//! ext4, read and write: the file system of most Linux installs.
//!
//! Supported: extents and old-style block maps, 32/64-bit block numbers,
//! flex_bg, htree directories (read linearly; flattened to linear before
//! the first change), fast and slow symbolic links, and metadata_csum
//! (crc32c checksums of the superblock, group descriptors, bitmaps,
//! inodes, extent blocks and directory blocks). Groups the formatter left
//! uninitialised (BLOCK_UNINIT, INODE_UNINIT) are initialised on first use.
//!
//! Changes are written in place, without the journal: the file system is
//! consistent between operations, not during one, as with ext2. A file
//! system whose journal needs recovery is mounted read-only. Not
//! supported: inline data, encryption, meta_bg, bigalloc, writes that would
//! grow an extent tree past depth 1.
//!
//! File data lives in a page cache per inode; `mmap` maps those pages, and
//! `write` updates them and writes through to the disk.

use super::{FileType, Inode, poll};
use crate::abi::{Errno, KResult};
use crate::block::BlockDevice;
use crate::mm::{PAGE_SIZE, frame, phys_to_virt};
use crate::sync::{Mutex, SpinLock};
use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::sync::{Arc, Weak};
use alloc::vec;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

const MAGIC: u16 = 0xef53;
const ROOT_INO: u32 = 2;
const INCOMPAT_FILETYPE: u32 = 0x2;
const INCOMPAT_RECOVER: u32 = 0x4;
const INCOMPAT_META_BG: u32 = 0x10;
const INCOMPAT_64BIT: u32 = 0x80;
const INCOMPAT_CSUM_SEED: u32 = 0x2000;
const INCOMPAT_INLINE_DATA: u32 = 0x8000;
const INCOMPAT_ENCRYPT: u32 = 0x10000;
const RO_SPARSE_SUPER: u32 = 0x1;
const RO_HUGE_FILE: u32 = 0x8;
const RO_METADATA_CSUM: u32 = 0x400;
const RO_BIGALLOC: u32 = 0x200;
const BG_INODE_UNINIT: u16 = 1;
const BG_BLOCK_UNINIT: u16 = 2;
const FL_INDEX: u32 = 0x1000;
const FL_HUGE_FILE: u32 = 0x40000;
const FL_EXTENTS: u32 = 0x80000;
const FL_INLINE: u32 = 0x1000_0000;
const EXT_MAGIC: u16 = 0xf30a;
const S_IFMT: u16 = 0o170000;

fn le16(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes([b[o], b[o + 1]])
}
fn le32(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes(b[o..o + 4].try_into().unwrap())
}
fn put16(b: &mut [u8], o: usize, v: u16) {
    b[o..o + 2].copy_from_slice(&v.to_le_bytes());
}
fn put32(b: &mut [u8], o: usize, v: u32) {
    b[o..o + 4].copy_from_slice(&v.to_le_bytes());
}

/// CRC-32C (Castagnoli), without the final inversion, as ext4 uses it.
fn crc32c(mut crc: u32, data: &[u8]) -> u32 {
    static TABLE: crate::sync::Once<[u32; 256]> = crate::sync::Once::new();
    let t = TABLE.call_once(|| {
        let mut t = [0u32; 256];
        for (i, e) in t.iter_mut().enumerate() {
            let mut c = i as u32;
            for _ in 0..8 {
                c = if c & 1 != 0 {
                    (c >> 1) ^ 0x82f6_3b78
                } else {
                    c >> 1
                };
            }
            *e = c;
        }
        t
    });
    for &b in data {
        crc = t[((crc ^ b as u32) & 0xff) as usize] ^ (crc >> 8);
    }
    crc
}

fn now() -> u32 {
    (crate::time::realtime_ns() / crate::time::NS_PER_SEC) as u32
}

static NEXT_DEV: AtomicU64 = AtomicU64::new(0x800);

pub struct Ext4 {
    dev: Arc<dyn BlockDevice>,
    pub dev_id: u64,
    bs: usize,
    sb: SpinLock<Vec<u8>>,
    gds: SpinLock<Vec<Vec<u8>>>,
    desc_size: usize,
    ipg: u32,
    bpg: u32,
    inode_size: usize,
    first_data_block: u64,
    blocks: u64,
    csum: bool,
    seed: u32,
    sparse_super: bool,
    huge_file: bool,
    readonly: bool,
    cache: SpinLock<BTreeMap<u64, Arc<Vec<u8>>>>,
    inodes: SpinLock<BTreeMap<u32, Weak<Ext4Inode>>>,
    /// Recently used inodes, kept alive (with their cached pages).
    recent: SpinLock<alloc::collections::VecDeque<Arc<Ext4Inode>>>,
    alloc: Mutex<()>,
    pub label: String,
}

/// Inodes kept in memory after their last user.
const RECENT_INODES: usize = 256;
/// Blocks kept in the metadata cache.
const CACHE_BLOCKS: usize = 2048;

impl Ext4 {
    /// Mounts the file system on `dev`; returns its root directory.
    pub fn mount(dev: Arc<dyn BlockDevice>) -> KResult<Arc<dyn Inode>> {
        let mut sb = vec![0u8; 1024];
        crate::block::read_bytes(&*dev, 1024, &mut sb)?;
        if le16(&sb, 0x38) != MAGIC {
            return Err(Errno::EINVAL);
        }
        let incompat = le32(&sb, 0x60);
        let ro = le32(&sb, 0x64);
        if incompat & (INCOMPAT_META_BG | INCOMPAT_ENCRYPT | INCOMPAT_INLINE_DATA) != 0
            || ro & RO_BIGALLOC != 0
        {
            crate::warn!("ext4: unsupported features (incompat {incompat:#x}, ro {ro:#x})");
            return Err(Errno::EINVAL);
        }
        let bs = 1024usize << le32(&sb, 0x18);
        let is64 = incompat & INCOMPAT_64BIT != 0;
        let desc_size = if is64 { le16(&sb, 0xfe) as usize } else { 32 };
        let blocks = le32(&sb, 0x04) as u64
            | if is64 {
                (le32(&sb, 0x150) as u64) << 32
            } else {
                0
            };
        let bpg = le32(&sb, 0x20);
        let ngroups = (blocks - le32(&sb, 0x14) as u64).div_ceil(bpg as u64) as usize;
        let csum = ro & RO_METADATA_CSUM != 0;
        let seed = if incompat & INCOMPAT_CSUM_SEED != 0 {
            le32(&sb, 0x270)
        } else {
            crc32c(!0, &sb[0x68..0x78])
        };
        let first_data_block = le32(&sb, 0x14) as u64;
        let gdt_off = (first_data_block + 1) * bs as u64;
        let mut gdt = vec![0u8; ngroups * desc_size];
        crate::block::read_bytes(&*dev, gdt_off, &mut gdt)?;
        let gds = gdt.chunks(desc_size).map(|c| c.to_vec()).collect();
        let label = String::from_utf8_lossy(&sb[0x78..0x88])
            .trim_end_matches('\0')
            .to_string();
        let readonly = incompat & INCOMPAT_RECOVER != 0;
        if readonly {
            crate::warn!("ext4: journal needs recovery; mounting read-only");
        }
        let fs = Arc::new(Ext4 {
            dev,
            dev_id: NEXT_DEV.fetch_add(1, Ordering::Relaxed),
            bs,
            sb: SpinLock::new(sb.clone()),
            gds: SpinLock::new(gds),
            desc_size,
            ipg: le32(&sb, 0x28),
            bpg,
            inode_size: le16(&sb, 0x58) as usize,
            first_data_block,
            blocks,
            csum,
            seed,
            sparse_super: ro & RO_SPARSE_SUPER != 0,
            huge_file: ro & RO_HUGE_FILE != 0,
            readonly,
            cache: SpinLock::new(BTreeMap::new()),
            inodes: SpinLock::new(BTreeMap::new()),
            recent: SpinLock::new(alloc::collections::VecDeque::new()),
            alloc: Mutex::new(()),
            label,
        });
        crate::info!(
            "ext4: \"{}\", {} MiB, {}-byte blocks, {} groups{}",
            fs.label,
            (blocks * bs as u64) >> 20,
            bs,
            ngroups,
            if csum { ", checksums" } else { "" }
        );
        let root = fs.inode(ROOT_INO)?;
        Ok(root)
    }

    // ---- Blocks -----------------------------------------------------------

    fn read_block(&self, n: u64) -> KResult<Arc<Vec<u8>>> {
        if let Some(b) = self.cache.lock().get(&n) {
            return Ok(b.clone());
        }
        if n >= self.blocks {
            return Err(Errno::EIO);
        }
        let mut buf = vec![0u8; self.bs];
        crate::block::read_bytes(&*self.dev, n * self.bs as u64, &mut buf)?;
        let b = Arc::new(buf);
        let mut c = self.cache.lock();
        if c.len() >= CACHE_BLOCKS {
            let k = *c.keys().next().unwrap();
            c.remove(&k);
        }
        c.insert(n, b.clone());
        Ok(b)
    }

    fn write_block(&self, n: u64, data: &[u8]) -> KResult<()> {
        if self.readonly {
            return Err(Errno::EROFS);
        }
        crate::block::write_bytes(&*self.dev, n * self.bs as u64, data)?;
        let mut c = self.cache.lock();
        if c.contains_key(&n) {
            c.insert(n, Arc::new(data.to_vec()));
        }
        Ok(())
    }

    // ---- Superblock and group descriptors ----------------------------------

    fn gd_u64(&self, g: usize, lo: usize, hi: usize) -> u64 {
        let gds = self.gds.lock();
        let d = &gds[g];
        le32(d, lo) as u64
            | if self.desc_size >= 64 {
                (le32(d, hi) as u64) << 32
            } else {
                0
            }
    }

    fn gd16x(d: &[u8], lo: usize, hi: usize, big: bool) -> u32 {
        le16(d, lo) as u32 | if big { (le16(d, hi) as u32) << 16 } else { 0 }
    }

    fn set_gd16x(d: &mut [u8], lo: usize, hi: usize, big: bool, v: u32) {
        put16(d, lo, v as u16);
        if big {
            put16(d, hi, (v >> 16) as u16);
        }
    }

    fn block_bitmap(&self, g: usize) -> u64 {
        self.gd_u64(g, 0x00, 0x20)
    }
    fn inode_bitmap(&self, g: usize) -> u64 {
        self.gd_u64(g, 0x04, 0x24)
    }
    fn inode_table(&self, g: usize) -> u64 {
        self.gd_u64(g, 0x08, 0x28)
    }

    /// Writes group descriptor `g` (with its checksum) to the disk.
    fn write_gd(&self, g: usize) -> KResult<()> {
        let mut d = self.gds.lock()[g].clone();
        if self.csum {
            put16(&mut d, 0x1e, 0);
            let mut c = crc32c(self.seed, &(g as u32).to_le_bytes());
            c = crc32c(c, &d);
            put16(&mut d, 0x1e, c as u16);
            self.gds.lock()[g] = d.clone();
        }
        let off = (self.first_data_block + 1) * self.bs as u64 + (g * self.desc_size) as u64;
        crate::block::write_bytes(&*self.dev, off, &d)?;
        let block = off / self.bs as u64;
        self.cache.lock().remove(&block);
        Ok(())
    }

    fn write_sb(&self, free_blocks_delta: i64, free_inodes_delta: i64) -> KResult<()> {
        let mut sb = self.sb.lock();
        let fb =
            (le32(&sb, 0x0c) as u64 | (le32(&sb, 0x158) as u64) << 32) as i64 + free_blocks_delta;
        put32(&mut sb, 0x0c, fb as u32);
        put32(&mut sb, 0x158, (fb as u64 >> 32) as u32);
        let fi = le32(&sb, 0x10) as i64 + free_inodes_delta;
        put32(&mut sb, 0x10, fi as u32);
        put32(&mut sb, 0x30, now());
        if self.csum {
            let c = crc32c(!0, &sb[..0x3fc]);
            put32(&mut sb, 0x3fc, c);
        }
        let copy = sb.clone();
        drop(sb);
        crate::block::write_bytes(&*self.dev, 1024, &copy)
    }

    fn groups(&self) -> usize {
        self.gds.lock().len()
    }

    /// Whether group `g` holds a superblock backup (sparse_super).
    fn has_super(&self, g: usize) -> bool {
        if !self.sparse_super || g <= 1 {
            return true;
        }
        for p in [3usize, 5, 7] {
            let mut x = p;
            while x < g {
                x *= p;
            }
            if x == g {
                return true;
            }
        }
        false
    }

    /// A block bitmap for a BLOCK_UNINIT group: its superblock backup and
    /// descriptor table blocks, and its own bitmaps and inode table if
    /// they lie inside it, are in use.
    fn init_block_bitmap(&self, g: usize) -> Vec<u8> {
        let mut bm = vec![0u8; self.bs];
        let start = self.first_data_block + g as u64 * self.bpg as u64;
        let mut mark = |b: u64| {
            if b >= start && b < start + self.bpg as u64 {
                let i = (b - start) as usize;
                bm[i / 8] |= 1 << (i % 8);
            }
        };
        if self.has_super(g) {
            let gdt_blocks = (self.groups() * self.desc_size).div_ceil(self.bs) as u64;
            let reserved = le16(&self.sb.lock(), 0xce) as u64;
            for b in 0..1 + gdt_blocks + reserved {
                mark(start + b);
            }
        }
        mark(self.block_bitmap(g));
        mark(self.inode_bitmap(g));
        let it_blocks = (self.ipg as usize * self.inode_size).div_ceil(self.bs) as u64;
        for b in 0..it_blocks {
            mark(self.inode_table(g) + b);
        }
        // Past the end of the file system (last group).
        let in_group = (self.blocks - start).min(self.bpg as u64) as usize;
        for i in in_group..self.bs * 8 {
            bm[i / 8] |= 1 << (i % 8);
        }
        bm
    }

    fn bitmap_csum(&self, g: usize, bm: &[u8], inode: bool) {
        if !self.csum {
            return;
        }
        let bits = if inode { self.ipg } else { self.bpg } as usize;
        let c = crc32c(self.seed, &bm[..bits / 8]);
        let mut gds = self.gds.lock();
        let big = self.desc_size >= 64;
        if inode {
            Self::set_gd16x(&mut gds[g], 0x1a, 0x3a, big, c);
        } else {
            Self::set_gd16x(&mut gds[g], 0x18, 0x38, big, c);
        }
    }

    /// Allocates a block, preferably `goal`.
    fn alloc_block(&self, goal: u64) -> KResult<u64> {
        let _g = self.alloc.lock();
        let ngroups = self.groups();
        let big = self.desc_size >= 64;
        let first = ((goal.max(self.first_data_block) - self.first_data_block) / self.bpg as u64)
            as usize
            % ngroups;
        for k in 0..ngroups {
            let g = (first + k) % ngroups;
            let (free, flags) = {
                let gds = self.gds.lock();
                (Self::gd16x(&gds[g], 0x0c, 0x2c, big), le16(&gds[g], 0x12))
            };
            if free == 0 {
                continue;
            }
            let bmb = self.block_bitmap(g);
            let mut bm = if flags & BG_BLOCK_UNINIT != 0 {
                self.init_block_bitmap(g)
            } else {
                (*self.read_block(bmb)?).clone()
            };
            let start = self.first_data_block + g as u64 * self.bpg as u64;
            let from = if g == first && goal > start {
                (goal - start) as usize
            } else {
                0
            };
            let n = (self.blocks - start).min(self.bpg as u64) as usize;
            let found = (from..n)
                .chain(0..from)
                .find(|&i| bm[i / 8] & (1 << (i % 8)) == 0);
            let Some(i) = found else { continue };
            bm[i / 8] |= 1 << (i % 8);
            {
                let mut gds = self.gds.lock();
                Self::set_gd16x(&mut gds[g], 0x0c, 0x2c, big, free - 1);
                put16(&mut gds[g], 0x12, flags & !BG_BLOCK_UNINIT);
            }
            self.bitmap_csum(g, &bm, false);
            self.write_block(bmb, &bm)?;
            self.write_gd(g)?;
            self.write_sb(-1, 0)?;
            return Ok(start + i as u64);
        }
        Err(Errno::ENOSPC)
    }

    fn free_block(&self, b: u64) -> KResult<()> {
        let _g = self.alloc.lock();
        let g = ((b - self.first_data_block) / self.bpg as u64) as usize;
        let i = ((b - self.first_data_block) % self.bpg as u64) as usize;
        let big = self.desc_size >= 64;
        let bmb = self.block_bitmap(g);
        let mut bm = (*self.read_block(bmb)?).clone();
        if bm[i / 8] & (1 << (i % 8)) == 0 {
            return Ok(());
        }
        bm[i / 8] &= !(1 << (i % 8));
        {
            let mut gds = self.gds.lock();
            let free = Self::gd16x(&gds[g], 0x0c, 0x2c, big);
            Self::set_gd16x(&mut gds[g], 0x0c, 0x2c, big, free + 1);
        }
        self.bitmap_csum(g, &bm, false);
        self.write_block(bmb, &bm)?;
        self.write_gd(g)?;
        self.write_sb(1, 0)
    }

    fn alloc_inode(&self, near: u32, dir: bool) -> KResult<u32> {
        let _g = self.alloc.lock();
        let ngroups = self.groups();
        let big = self.desc_size >= 64;
        let first = ((near.max(1) - 1) / self.ipg) as usize;
        let first_ino = le32(&self.sb.lock(), 0x54);
        for k in 0..ngroups {
            let g = (first + k) % ngroups;
            let (free, flags, unused) = {
                let gds = self.gds.lock();
                let d = &gds[g];
                (
                    Self::gd16x(d, 0x0e, 0x2e, big),
                    le16(d, 0x12),
                    Self::gd16x(d, 0x1c, 0x32, big),
                )
            };
            if free == 0 {
                continue;
            }
            let bmb = self.inode_bitmap(g);
            let mut bm = if flags & BG_INODE_UNINIT != 0 {
                let mut b = vec![0u8; self.bs];
                for i in self.ipg as usize..self.bs * 8 {
                    b[i / 8] |= 1 << (i % 8);
                }
                b
            } else {
                (*self.read_block(bmb)?).clone()
            };
            let found = (0..self.ipg as usize).find(|&i| {
                let ino = g as u32 * self.ipg + i as u32 + 1;
                ino >= first_ino && bm[i / 8] & (1 << (i % 8)) == 0
            });
            let Some(i) = found else { continue };
            bm[i / 8] |= 1 << (i % 8);
            {
                let mut gds = self.gds.lock();
                let d = &mut gds[g];
                Self::set_gd16x(d, 0x0e, 0x2e, big, free - 1);
                if dir {
                    let used = Self::gd16x(d, 0x10, 0x30, big);
                    Self::set_gd16x(d, 0x10, 0x30, big, used + 1);
                }
                let left = self.ipg - (i as u32 + 1);
                Self::set_gd16x(d, 0x1c, 0x32, big, unused.min(left));
                put16(d, 0x12, flags & !BG_INODE_UNINIT);
            }
            self.bitmap_csum(g, &bm, true);
            self.write_block(bmb, &bm)?;
            self.write_gd(g)?;
            self.write_sb(0, -1)?;
            return Ok(g as u32 * self.ipg + i as u32 + 1);
        }
        Err(Errno::ENOSPC)
    }

    fn free_inode(&self, ino: u32, dir: bool) -> KResult<()> {
        let _g = self.alloc.lock();
        let g = ((ino - 1) / self.ipg) as usize;
        let i = ((ino - 1) % self.ipg) as usize;
        let big = self.desc_size >= 64;
        let bmb = self.inode_bitmap(g);
        let mut bm = (*self.read_block(bmb)?).clone();
        bm[i / 8] &= !(1 << (i % 8));
        {
            let mut gds = self.gds.lock();
            let d = &mut gds[g];
            let free = Self::gd16x(d, 0x0e, 0x2e, big);
            Self::set_gd16x(d, 0x0e, 0x2e, big, free + 1);
            if dir {
                let used = Self::gd16x(d, 0x10, 0x30, big);
                Self::set_gd16x(d, 0x10, 0x30, big, used.saturating_sub(1));
            }
        }
        self.bitmap_csum(g, &bm, true);
        self.write_block(bmb, &bm)?;
        self.write_gd(g)?;
        self.write_sb(0, 1)
    }

    // ---- Inodes -------------------------------------------------------------

    fn inode_location(&self, ino: u32) -> (u64, usize) {
        let g = ((ino - 1) / self.ipg) as usize;
        let index = ((ino - 1) % self.ipg) as usize;
        let byte = index * self.inode_size;
        (
            self.inode_table(g) + (byte / self.bs) as u64,
            byte % self.bs,
        )
    }

    fn read_raw_inode(&self, ino: u32) -> KResult<Vec<u8>> {
        let (b, off) = self.inode_location(ino);
        let blk = self.read_block(b)?;
        Ok(blk[off..off + self.inode_size].to_vec())
    }

    fn inode_seed(&self, ino: u32, raw: &[u8]) -> u32 {
        let c = crc32c(self.seed, &ino.to_le_bytes());
        crc32c(c, &raw[0x64..0x68])
    }

    fn write_raw_inode(&self, ino: u32, raw: &mut [u8]) -> KResult<()> {
        if self.csum {
            let has_hi = self.inode_size > 128 && le16(raw, 0x80) >= 4;
            put16(raw, 0x7c, 0);
            if has_hi {
                put16(raw, 0x82, 0);
            }
            let c = crc32c(self.inode_seed(ino, raw), raw);
            put16(raw, 0x7c, c as u16);
            if has_hi {
                put16(raw, 0x82, (c >> 16) as u16);
            }
        }
        let (b, off) = self.inode_location(ino);
        let mut blk = (*self.read_block(b)?).clone();
        blk[off..off + self.inode_size].copy_from_slice(raw);
        self.write_block(b, &blk)
    }

    /// The (cached) inode `ino`.
    fn inode(self: &Arc<Self>, ino: u32) -> KResult<Arc<dyn Inode>> {
        Ok(self.inode_arc(ino)?)
    }

    fn inode_arc(self: &Arc<Self>, ino: u32) -> KResult<Arc<Ext4Inode>> {
        if let Some(i) = self.inodes.lock().get(&ino).and_then(|w| w.upgrade()) {
            return Ok(i);
        }
        let i = self.load_inode(ino)?;
        let mut recent = self.recent.lock();
        if recent.len() >= RECENT_INODES {
            let old = recent.pop_front();
            drop(recent);
            drop(old);
            recent = self.recent.lock();
        }
        recent.push_back(i.clone());
        Ok(i)
    }

    /// Forgets `ino` in the recently-used list (it lost its last name).
    fn forget(&self, ino: u32) {
        let gone: alloc::collections::VecDeque<Arc<Ext4Inode>> = {
            let mut recent = self.recent.lock();
            let (keep, gone) = core::mem::take(&mut *recent)
                .into_iter()
                .partition(|i| i.ino != ino);
            *recent = keep;
            gone
        };
        drop(gone);
    }

    fn load_inode(self: &Arc<Self>, ino: u32) -> KResult<Arc<Ext4Inode>> {
        let raw = self.read_raw_inode(ino)?;
        let i = Arc::new_cyclic(|me| Ext4Inode {
            fs: self.clone(),
            ino,
            raw: Mutex::new(raw),
            pages: SpinLock::new(BTreeMap::new()),
            me: me.clone(),
        });
        self.inodes.lock().insert(ino, Arc::downgrade(&i));
        Ok(i)
    }

    fn csum_extent_block(&self, seed: u32, blk: &mut [u8]) {
        if !self.csum {
            return;
        }
        let max = le16(blk, 4) as usize;
        let tail = 12 + 12 * max;
        if tail + 4 <= blk.len() {
            let c = crc32c(seed, &blk[..tail]);
            put32(blk, tail, c);
        }
    }

    fn csum_dir_block(&self, seed: u32, blk: &mut [u8]) {
        if !self.csum {
            return;
        }
        let t = self.bs - 12;
        put32(blk, t, 0);
        put16(blk, t + 4, 12);
        blk[t + 6] = 0;
        blk[t + 7] = 0xde;
        let c = crc32c(seed, &blk[..t]);
        put32(blk, t + 8, c);
    }

    /// Room in a directory block for entries (the checksum tail excluded).
    fn dir_space(&self) -> usize {
        if self.csum { self.bs - 12 } else { self.bs }
    }
}

pub struct Ext4Inode {
    fs: Arc<Ext4>,
    ino: u32,
    raw: Mutex<Vec<u8>>,
    /// Page cache: page index -> frame (holding one reference).
    pages: SpinLock<BTreeMap<u64, u64>>,
    #[allow(dead_code)]
    me: Weak<Ext4Inode>,
}

fn mode_type(mode: u16) -> FileType {
    match mode & S_IFMT {
        0o040000 => FileType::Directory,
        0o120000 => FileType::Symlink,
        0o020000 => FileType::CharDevice,
        0o060000 => FileType::BlockDevice,
        0o010000 => FileType::Fifo,
        _ => FileType::Regular,
    }
}

fn dirent_type(t: FileType) -> u8 {
    match t {
        FileType::Regular => 1,
        FileType::Directory => 2,
        FileType::CharDevice => 3,
        FileType::BlockDevice => 4,
        FileType::Fifo => 5,
        FileType::Symlink => 7,
    }
}

impl Ext4Inode {
    fn mode(&self) -> u16 {
        le16(&self.raw.lock(), 0)
    }

    fn flags(raw: &[u8]) -> u32 {
        le32(raw, 0x20)
    }

    fn size_of(raw: &[u8]) -> u64 {
        le32(raw, 0x04) as u64 | (le32(raw, 0x6c) as u64) << 32
    }

    fn set_size(raw: &mut [u8], size: u64) {
        put32(raw, 0x04, size as u32);
        put32(raw, 0x6c, (size >> 32) as u32);
    }

    fn links(raw: &[u8]) -> u16 {
        le16(raw, 0x1a)
    }

    fn seed(&self, raw: &[u8]) -> u32 {
        self.fs.inode_seed(self.ino, raw)
    }

    fn save(&self, raw: &mut [u8]) -> KResult<()> {
        self.fs.write_raw_inode(self.ino, raw)
    }

    fn add_blocks(&self, raw: &mut [u8], n: i64) {
        let sectors = (self.fs.bs / 512) as i64 * n;
        let cur = le32(raw, 0x1c) as u64 | (le16(raw, 0x74) as u64) << 32;
        let huge = self.fs.huge_file && Self::flags(raw) & FL_HUGE_FILE != 0;
        let delta = if huge { n } else { sectors };
        let v = (cur as i64 + delta).max(0) as u64;
        put32(raw, 0x1c, v as u32);
        put16(raw, 0x74, (v >> 32) as u16);
    }

    // ---- Block mapping ------------------------------------------------------

    /// The physical block of logical block `lb`; None for a hole. The bool
    /// is true for an unwritten (preallocated) extent, which reads as zeros.
    fn bmap(&self, raw: &[u8], lb: u64) -> KResult<Option<(u64, bool)>> {
        if Self::flags(raw) & FL_EXTENTS != 0 {
            let mut node = raw[0x28..0x28 + 60].to_vec();
            loop {
                if le16(&node, 0) != EXT_MAGIC {
                    return Err(Errno::EIO);
                }
                let (entries, depth) = (le16(&node, 2) as usize, le16(&node, 6));
                if depth == 0 {
                    for e in 0..entries {
                        let o = 12 + e * 12;
                        let start = le32(&node, o) as u64;
                        let mut len = le16(&node, o + 4) as u64;
                        let uninit = len > 32768;
                        if uninit {
                            len -= 32768;
                        }
                        if lb >= start && lb < start + len {
                            let phys =
                                (le16(&node, o + 6) as u64) << 32 | le32(&node, o + 8) as u64;
                            return Ok(Some((phys + lb - start, uninit)));
                        }
                    }
                    return Ok(None);
                }
                let mut child = None;
                for e in 0..entries {
                    let o = 12 + e * 12;
                    if le32(&node, o) as u64 <= lb {
                        child = Some(le32(&node, o + 4) as u64 | (le16(&node, o + 8) as u64) << 32);
                    }
                }
                let Some(c) = child else { return Ok(None) };
                node = (*self.fs.read_block(c)?).clone();
            }
        }
        // Old block map: 12 direct, then single, double, triple indirect.
        let per = (self.fs.bs / 4) as u64;
        let word = |blk: &[u8], i: u64| le32(blk, i as usize * 4) as u64;
        let direct = |i: usize| le32(raw, 0x28 + i * 4) as u64;
        let mut idx = lb;
        if idx < 12 {
            return Ok(Some(direct(idx as usize))
                .filter(|&p| p != 0)
                .map(|p| (p, false)));
        }
        idx -= 12;
        let (mut b, levels) = if idx < per {
            (direct(12), 1)
        } else if idx - per < per * per {
            idx -= per;
            (direct(13), 2)
        } else {
            idx -= per + per * per;
            (direct(14), 3)
        };
        for l in (0..levels).rev() {
            if b == 0 {
                return Ok(None);
            }
            let blk = self.fs.read_block(b)?;
            b = word(&blk, (idx / per.pow(l)) % per);
        }
        Ok(Some(b).filter(|&p| p != 0).map(|p| (p, false)))
    }

    /// Maps logical block `lb` to a new physical block `pb` (extents only,
    /// depth 0 or 1).
    fn map_new(&self, raw: &mut [u8], lb: u64, pb: u64) -> KResult<()> {
        if Self::flags(raw) & FL_EXTENTS == 0 {
            return Err(Errno::EOPNOTSUPP);
        }
        let seed = self.seed(raw);
        let depth = le16(raw, 0x28 + 6);
        if depth == 0 {
            let mut root = raw[0x28..0x28 + 60].to_vec();
            if Self::leaf_insert(&mut root, lb, pb) {
                raw[0x28..0x28 + 60].copy_from_slice(&root);
                return Ok(());
            }
            // Root full: move its extents to a new leaf block.
            let leaf_b = self.fs.alloc_block(pb + 1)?;
            self.add_blocks(raw, 1);
            let mut leaf = vec![0u8; self.fs.bs];
            put16(&mut leaf, 0, EXT_MAGIC);
            put16(&mut leaf, 2, le16(&root, 2));
            put16(&mut leaf, 4, ((self.fs.bs - 12) / 12) as u16);
            leaf[12..12 + 48].copy_from_slice(&root[12..60]);
            let first = le32(&root, 12);
            let mut new_root = vec![0u8; 60];
            put16(&mut new_root, 0, EXT_MAGIC);
            put16(&mut new_root, 2, 1);
            put16(&mut new_root, 4, 4);
            put16(&mut new_root, 6, 1);
            put32(&mut new_root, 12, first);
            put32(&mut new_root, 16, leaf_b as u32);
            put16(&mut new_root, 20, (leaf_b >> 32) as u16);
            raw[0x28..0x28 + 60].copy_from_slice(&new_root);
            if !Self::leaf_insert(&mut leaf, lb, pb) {
                return Err(Errno::EFBIG);
            }
            self.fs.csum_extent_block(seed, &mut leaf);
            return self.fs.write_block(leaf_b, &leaf);
        }
        if depth != 1 {
            return Err(Errno::EFBIG);
        }
        let root = raw[0x28..0x28 + 60].to_vec();
        let entries = le16(&root, 2) as usize;
        let mut pick = 0;
        for e in 0..entries {
            if le32(&root, 12 + e * 12) as u64 <= lb {
                pick = e;
            }
        }
        let o = 12 + pick * 12;
        let leaf_b = le32(&root, o + 4) as u64 | (le16(&root, o + 8) as u64) << 32;
        let mut leaf = (*self.fs.read_block(leaf_b)?).clone();
        if Self::leaf_insert(&mut leaf, lb, pb) {
            self.fs.csum_extent_block(seed, &mut leaf);
            return self.fs.write_block(leaf_b, &leaf);
        }
        // Leaf full: a new leaf for blocks past it, if the root has room.
        if entries >= 4 || pick + 1 != entries {
            return Err(Errno::EFBIG);
        }
        let nb = self.fs.alloc_block(pb + 1)?;
        self.add_blocks(raw, 1);
        let mut nl = vec![0u8; self.fs.bs];
        put16(&mut nl, 0, EXT_MAGIC);
        put16(&mut nl, 4, ((self.fs.bs - 12) / 12) as u16);
        Self::leaf_insert(&mut nl, lb, pb);
        self.fs.csum_extent_block(seed, &mut nl);
        self.fs.write_block(nb, &nl)?;
        let o = 12 + entries * 12;
        put32(raw, 0x28 + o, lb as u32);
        put32(raw, 0x28 + o + 4, nb as u32);
        put16(raw, 0x28 + o + 8, (nb >> 32) as u16);
        put16(raw, 0x28 + 2, entries as u16 + 1);
        Ok(())
    }

    /// Adds lb->pb to an extent leaf node (extending the last extent if
    /// contiguous). False if the node is full.
    fn leaf_insert(node: &mut [u8], lb: u64, pb: u64) -> bool {
        let entries = le16(node, 2) as usize;
        let max = le16(node, 4) as usize;
        if entries > 0 {
            let o = 12 + (entries - 1) * 12;
            let start = le32(node, o) as u64;
            let len = le16(node, o + 4) as u64;
            let phys = (le16(node, o + 6) as u64) << 32 | le32(node, o + 8) as u64;
            if len < 32768 && start + len == lb && phys + len == pb {
                put16(node, o + 4, len as u16 + 1);
                return true;
            }
        }
        if entries >= max {
            return false;
        }
        // Keep entries sorted by logical block.
        let mut at = entries;
        while at > 0 && le32(node, 12 + (at - 1) * 12) as u64 > lb {
            at -= 1;
        }
        node.copy_within(12 + at * 12..12 + entries * 12, 12 + (at + 1) * 12);
        let o = 12 + at * 12;
        put32(node, o, lb as u32);
        put16(node, o + 4, 1);
        put16(node, o + 6, (pb >> 32) as u16);
        put32(node, o + 8, pb as u32);
        put16(node, 2, entries as u16 + 1);
        true
    }

    /// The physical block for writing logical block `lb`, allocating it.
    fn block_for_write(&self, raw: &mut [u8], lb: u64) -> KResult<u64> {
        match self.bmap(raw, lb)? {
            Some((b, false)) => return Ok(b),
            Some((_, true)) => return Err(Errno::EOPNOTSUPP),
            None => {}
        }
        let goal = if lb > 0 {
            self.bmap(raw, lb - 1)?.map_or(0, |(b, _)| b + 1)
        } else {
            self.fs.inode_table(((self.ino - 1) / self.fs.ipg) as usize)
        };
        let pb = self.fs.alloc_block(goal)?;
        self.add_blocks(raw, 1);
        if let Err(e) = self.map_new(raw, lb, pb) {
            let _ = self.fs.free_block(pb);
            self.add_blocks(raw, -1);
            return Err(e);
        }
        Ok(pb)
    }

    /// Frees every block of an extent-mapped inode from logical block
    /// `from` on (and the tree's own blocks when emptied).
    fn free_from(&self, raw: &mut [u8], from: u64) -> KResult<()> {
        if Self::flags(raw) & FL_EXTENTS == 0 {
            if from == 0 {
                // Old block maps: free the data blocks we can find.
                let blocks = Self::size_of(raw).div_ceil(self.fs.bs as u64);
                for lb in 0..blocks {
                    if let Some((b, _)) = self.bmap(raw, lb)? {
                        self.fs.free_block(b)?;
                    }
                }
                raw[0x28..0x28 + 60].fill(0);
                put32(raw, 0x1c, 0);
            }
            return Ok(());
        }
        let seed = self.seed(raw);
        let depth = le16(raw, 0x28 + 6);
        let mut freed = 0i64;
        let trim = |fs: &Ext4, node: &mut [u8], freed: &mut i64| -> KResult<()> {
            let mut entries = le16(node, 2) as usize;
            let mut e = 0;
            while e < entries {
                let o = 12 + e * 12;
                let start = le32(node, o) as u64;
                let raw_len = le16(node, o + 4) as u64;
                let len = if raw_len > 32768 {
                    raw_len - 32768
                } else {
                    raw_len
                };
                let phys = (le16(node, o + 6) as u64) << 32 | le32(node, o + 8) as u64;
                if start + len <= from {
                    e += 1;
                    continue;
                }
                let keep = from.saturating_sub(start);
                for b in keep..len {
                    fs.free_block(phys + b)?;
                    *freed += 1;
                }
                if keep > 0 {
                    put16(
                        node,
                        o + 4,
                        (keep + if raw_len > 32768 { 32768 } else { 0 }) as u16,
                    );
                    e += 1;
                } else {
                    node.copy_within(o + 12..12 + entries * 12, o);
                    entries -= 1;
                    put16(node, 2, entries as u16);
                }
            }
            Ok(())
        };
        if depth == 0 {
            let mut root = raw[0x28..0x28 + 60].to_vec();
            trim(&self.fs, &mut root, &mut freed)?;
            raw[0x28..0x28 + 60].copy_from_slice(&root);
        } else if depth == 1 {
            let mut root = raw[0x28..0x28 + 60].to_vec();
            let entries = le16(&root, 2) as usize;
            let mut kept = 0;
            for e in 0..entries {
                let o = 12 + e * 12;
                let leaf_b = le32(&root, o + 4) as u64 | (le16(&root, o + 8) as u64) << 32;
                let mut leaf = (*self.fs.read_block(leaf_b)?).clone();
                trim(&self.fs, &mut leaf, &mut freed)?;
                if le16(&leaf, 2) == 0 {
                    self.fs.free_block(leaf_b)?;
                    freed += 1;
                } else {
                    self.fs.csum_extent_block(seed, &mut leaf);
                    self.fs.write_block(leaf_b, &leaf)?;
                    let dst = 12 + kept * 12;
                    root.copy_within(o..o + 12, dst);
                    kept += 1;
                }
            }
            put16(&mut root, 2, kept as u16);
            if kept == 0 {
                put16(&mut root, 6, 0);
            }
            raw[0x28..0x28 + 60].copy_from_slice(&root);
        } else if from == 0 {
            return Err(Errno::EFBIG);
        }
        self.add_blocks(raw, -freed);
        Ok(())
    }

    // ---- Data and page cache -------------------------------------------------

    /// Reads logical block `lb` (zeros for holes).
    fn read_lblock(&self, raw: &[u8], lb: u64, out: &mut [u8]) -> KResult<()> {
        match self.bmap(raw, lb)? {
            Some((b, false)) => out.copy_from_slice(&self.fs.read_block_uncached(b)?),
            _ => out.fill(0),
        }
        Ok(())
    }

    /// The frame caching file page `idx` (one reference stays with the
    /// cache).
    fn cached_page(&self, idx: u64) -> KResult<u64> {
        if let Some(&p) = self.pages.lock().get(&idx) {
            return Ok(p);
        }
        let raw = self.raw.lock().clone();
        let phys = frame::alloc_zeroed().ok_or(Errno::ENOMEM)?;
        let page =
            unsafe { core::slice::from_raw_parts_mut(phys_to_virt(phys), PAGE_SIZE as usize) };
        let size = Self::size_of(&raw);
        let per = PAGE_SIZE as usize / self.fs.bs;
        for k in 0..per {
            let lb = idx * per as u64 + k as u64;
            if lb * self.fs.bs as u64 >= size {
                break;
            }
            if let Err(e) =
                self.read_lblock(&raw, lb, &mut page[k * self.fs.bs..(k + 1) * self.fs.bs])
            {
                frame::free(phys);
                return Err(e);
            }
        }
        // Bytes past the end of file read as zero.
        let end = size.saturating_sub(idx * PAGE_SIZE);
        if end < PAGE_SIZE {
            page[end as usize..].fill(0);
        }
        let mut pages = self.pages.lock();
        if let Some(&p) = pages.get(&idx) {
            frame::free(phys);
            return Ok(p);
        }
        pages.insert(idx, phys);
        Ok(phys)
    }

    fn drop_pages_from(&self, idx: u64) {
        let mut pages = self.pages.lock();
        let gone: Vec<u64> = pages.range(idx..).map(|(&k, _)| k).collect();
        for k in gone {
            frame::free(pages.remove(&k).unwrap());
        }
    }

    // ---- Directories ------------------------------------------------------------

    /// Calls `f(block index, offset, inode, name, type)` for each entry
    /// until it returns true.
    fn scan_dir(&self, mut f: impl FnMut(u64, usize, u32, &[u8], u8) -> bool) -> KResult<()> {
        let raw = self.raw.lock().clone();
        let size = Self::size_of(&raw);
        let bs = self.fs.bs;
        let mut blk = vec![0u8; bs];
        for lb in 0..size.div_ceil(bs as u64) {
            self.read_lblock(&raw, lb, &mut blk)?;
            let mut off = 0;
            while off + 8 <= bs {
                let ino = le32(&blk, off);
                let rec = le16(&blk, off + 4) as usize;
                let nlen = blk[off + 6] as usize;
                if rec < 8 || off + rec > bs {
                    break;
                }
                if ino != 0
                    && nlen > 0
                    && off + 8 + nlen <= bs
                    && f(lb, off, ino, &blk[off + 8..off + 8 + nlen], blk[off + 7])
                {
                    return Ok(());
                }
                off += rec;
            }
        }
        Ok(())
    }

    fn find(&self, name: &str) -> KResult<Option<u32>> {
        let mut found = None;
        self.scan_dir(|_, _, ino, n, _| {
            if n == name.as_bytes() {
                found = Some(ino);
                true
            } else {
                false
            }
        })?;
        Ok(found)
    }

    /// Rewrites a hashed (htree) directory as a plain one before changing
    /// it: index blocks become empty entry blocks, and the index flag goes.
    fn unindex(&self, raw: &mut [u8]) -> KResult<()> {
        if Self::flags(raw) & FL_INDEX == 0 {
            return Ok(());
        }
        let bs = self.fs.bs;
        let seed = self.seed(raw);
        let space = self.fs.dir_space();
        for lb in 0..Self::size_of(raw).div_ceil(bs as u64) {
            let Some((b, _)) = self.bmap(raw, lb)? else {
                continue;
            };
            let mut blk = (*self.fs.read_block(b)?).clone();
            let first_rec = le16(&blk, 4) as usize;
            let rewrite = if lb == 0 {
                // "." then ".." whose record hid the index root.
                let dot_rec = first_rec;
                put16(&mut blk, dot_rec + 4, (space - dot_rec) as u16);
                blk[space..].fill(0);
                true
            } else if le32(&blk, 0) == 0 && first_rec == bs {
                put16(&mut blk, 4, space as u16);
                blk[8..].fill(0);
                true
            } else {
                false
            };
            if rewrite {
                self.fs.csum_dir_block(seed, &mut blk);
                self.fs.write_block(b, &blk)?;
            }
        }
        let fl = Self::flags(raw) & !FL_INDEX;
        put32(raw, 0x20, fl);
        Ok(())
    }

    /// Adds `name` -> `ino` to this directory.
    fn add_entry(&self, name: &str, ino: u32, t: FileType) -> KResult<()> {
        let fs = &self.fs;
        let bs = fs.bs;
        let need = (8 + name.len()).next_multiple_of(4);
        let mut raw = self.raw.lock();
        self.unindex(&mut raw)?;
        let seed = self.seed(&raw);
        let space = fs.dir_space();
        let write_entry = |blk: &mut [u8], off: usize, rec: usize| {
            put32(blk, off, ino);
            put16(blk, off + 4, rec as u16);
            blk[off + 6] = name.len() as u8;
            blk[off + 7] = dirent_type(t);
            blk[off + 8..off + 8 + name.len()].copy_from_slice(name.as_bytes());
        };
        let blocks = Self::size_of(&raw).div_ceil(bs as u64);
        for lb in 0..blocks {
            let Some((b, _)) = self.bmap(&raw, lb)? else {
                continue;
            };
            let mut blk = (*fs.read_block(b)?).clone();
            let mut off = 0;
            while off < space {
                let e_ino = le32(&blk, off);
                let rec = le16(&blk, off + 4) as usize;
                if rec < 8 {
                    break;
                }
                let used = if e_ino == 0 {
                    0
                } else {
                    (8 + blk[off + 6] as usize).next_multiple_of(4)
                };
                if rec - used >= need {
                    if e_ino == 0 {
                        write_entry(&mut blk, off, rec);
                    } else {
                        put16(&mut blk, off + 4, used as u16);
                        write_entry(&mut blk, off + used, rec - used);
                    }
                    fs.csum_dir_block(seed, &mut blk);
                    fs.write_block(b, &blk)?;
                    let mut r = raw.clone();
                    put32(&mut r, 0x10, now());
                    put32(&mut r, 0x0c, now());
                    self.save(&mut r)?;
                    *raw = r;
                    return Ok(());
                }
                off += rec;
            }
        }
        // A new block.
        let mut r = raw.clone();
        let b = self.block_for_write(&mut r, blocks)?;
        let mut blk = vec![0u8; bs];
        write_entry(&mut blk, 0, space);
        fs.csum_dir_block(seed, &mut blk);
        fs.write_block(b, &blk)?;
        Self::set_size(&mut r, (blocks + 1) * bs as u64);
        put32(&mut r, 0x10, now());
        self.save(&mut r)?;
        *raw = r;
        drop(raw);
        self.drop_pages_from(0);
        Ok(())
    }

    /// Removes the entry `name`; returns its inode number.
    fn remove_entry(&self, name: &str) -> KResult<u32> {
        let fs = &self.fs;
        let mut raw = self.raw.lock();
        self.unindex(&mut raw)?;
        let seed = self.seed(&raw);
        let blocks = Self::size_of(&raw).div_ceil(fs.bs as u64);
        for lb in 0..blocks {
            let Some((b, _)) = self.bmap(&raw, lb)? else {
                continue;
            };
            let mut blk = (*fs.read_block(b)?).clone();
            let (mut off, mut prev) = (0, None);
            while off < fs.dir_space() {
                let e_ino = le32(&blk, off);
                let rec = le16(&blk, off + 4) as usize;
                if rec < 8 {
                    break;
                }
                let nlen = blk[off + 6] as usize;
                if e_ino != 0 && &blk[off + 8..off + 8 + nlen] == name.as_bytes() {
                    match prev {
                        Some(p) => {
                            let prec = le16(&blk, p + 4) as usize;
                            put16(&mut blk, p + 4, (prec + rec) as u16);
                        }
                        None => put32(&mut blk, off, 0),
                    }
                    fs.csum_dir_block(seed, &mut blk);
                    fs.write_block(b, &blk)?;
                    let mut r = raw.clone();
                    put32(&mut r, 0x10, now());
                    self.save(&mut r)?;
                    *raw = r;
                    drop(raw);
                    self.drop_pages_from(0);
                    return Ok(e_ino);
                }
                prev = Some(off);
                off += rec;
            }
        }
        Err(Errno::ENOENT)
    }

    fn change_links(&self, delta: i32) -> KResult<()> {
        let mut raw = self.raw.lock();
        let mut r = raw.clone();
        let l = (Self::links(&r) as i32 + delta).max(0) as u16;
        put16(&mut r, 0x1a, l);
        put32(&mut r, 0x0c, now());
        self.save(&mut r)?;
        *raw = r;
        Ok(())
    }

    /// A fresh inode of type `t` in this directory's group.
    fn new_inode(&self, t: FileType, perm: u32) -> KResult<Arc<Ext4Inode>> {
        let fs = &self.fs;
        let ino = fs.alloc_inode(self.ino, t == FileType::Directory)?;
        let mut raw = vec![0u8; fs.inode_size];
        let type_bits: u16 = match t {
            FileType::Directory => 0o040000,
            FileType::Symlink => 0o120000,
            FileType::Fifo => 0o010000,
            _ => 0o100000,
        };
        put16(&mut raw, 0, type_bits | (perm & 0o7777) as u16);
        let t_now = now();
        for o in [0x08, 0x0c, 0x10] {
            put32(&mut raw, o, t_now);
        }
        put16(&mut raw, 0x1a, 1);
        let mut generation = [0u8; 4];
        crate::random::fill(&mut generation);
        raw[0x64..0x68].copy_from_slice(&generation);
        if fs.inode_size > 128 {
            put16(&mut raw, 0x80, 32);
        }
        if t != FileType::Symlink {
            put32(&mut raw, 0x20, FL_EXTENTS);
            put16(&mut raw, 0x28, EXT_MAGIC);
            put16(&mut raw, 0x28 + 4, 4);
        }
        fs.write_raw_inode(ino, &mut raw)?;
        fs.inodes.lock().remove(&ino);
        fs.inode_arc(ino)
    }

    fn create_child(&self, name: &str, t: FileType, perm: u32) -> KResult<Arc<Ext4Inode>> {
        if self.fs.readonly {
            return Err(Errno::EROFS);
        }
        if name.len() > 255 {
            return Err(Errno::ENAMETOOLONG);
        }
        if matches!(name, "." | "..") || self.find(name)?.is_some() {
            return Err(Errno::EEXIST);
        }
        let child = self.new_inode(t, perm)?;
        if t == FileType::Directory {
            let fs = &self.fs;
            let mut raw = child.raw.lock();
            let mut r = raw.clone();
            let b = child.block_for_write(&mut r, 0)?;
            let mut blk = vec![0u8; fs.bs];
            put32(&mut blk, 0, child.ino);
            put16(&mut blk, 4, 12);
            blk[6] = 1;
            blk[7] = 2;
            blk[8] = b'.';
            put32(&mut blk, 12, self.ino);
            put16(&mut blk, 16, (fs.dir_space() - 12) as u16);
            blk[18] = 2;
            blk[19] = 2;
            blk[20..22].copy_from_slice(b"..");
            fs.csum_dir_block(child.seed(&r), &mut blk);
            fs.write_block(b, &blk)?;
            Self::set_size(&mut r, fs.bs as u64);
            put16(&mut r, 0x1a, 2);
            child.save(&mut r)?;
            *raw = r;
            drop(raw);
            self.change_links(1)?;
        }
        if let Err(e) = self.add_entry(name, child.ino, t) {
            child.change_links(-(Self::links(&child.raw.lock()) as i32))?;
            return Err(e);
        }
        Ok(child)
    }

    /// Frees the inode and its blocks (no names left, no users left).
    fn release(&self) {
        let mut raw = self.raw.lock();
        if self.fs.readonly || Self::links(&raw) != 0 {
            return;
        }
        let dir = mode_type(le16(&raw, 0)) == FileType::Directory;
        let mut r = raw.clone();
        let fast_link = mode_type(le16(&r, 0)) == FileType::Symlink
            && Self::flags(&r) & FL_EXTENTS == 0
            && Self::size_of(&r) < 60;
        if !fast_link {
            let _ = self.free_from(&mut r, 0);
        }
        Self::set_size(&mut r, 0);
        put32(&mut r, 0x14, now()); // dtime
        let _ = self.save(&mut r);
        *raw = r;
        let _ = self.fs.free_inode(self.ino, dir);
    }
}

impl Ext4 {
    fn read_block_uncached(&self, n: u64) -> KResult<Vec<u8>> {
        if let Some(b) = self.cache.lock().get(&n) {
            return Ok((**b).clone());
        }
        let mut buf = vec![0u8; self.bs];
        crate::block::read_bytes(&*self.dev, n * self.bs as u64, &mut buf)?;
        Ok(buf)
    }
}

impl Drop for Ext4Inode {
    fn drop(&mut self) {
        for (_, p) in core::mem::take(&mut *self.pages.lock()) {
            frame::free(p);
        }
        {
            let mut m = self.fs.inodes.lock();
            if m.get(&self.ino).is_some_and(|w| w.strong_count() == 0) {
                m.remove(&self.ino);
            }
        }
        self.release();
    }
}

impl Inode for Ext4Inode {
    fn file_type(&self) -> FileType {
        mode_type(self.mode())
    }
    fn ino(&self) -> u64 {
        self.ino as u64
    }
    fn dev(&self) -> u64 {
        self.fs.dev_id
    }
    fn perm(&self) -> u32 {
        (self.mode() & 0o7777) as u32
    }
    fn set_perm(&self, perm: u32) -> KResult<()> {
        let mut raw = self.raw.lock();
        let mut r = raw.clone();
        let m = (le16(&r, 0) & S_IFMT) | (perm & 0o7777) as u16;
        put16(&mut r, 0, m);
        put32(&mut r, 0x0c, now());
        self.save(&mut r)?;
        *raw = r;
        Ok(())
    }
    fn size(&self) -> u64 {
        Self::size_of(&self.raw.lock())
    }
    fn mtime(&self) -> u64 {
        le32(&self.raw.lock(), 0x10) as u64
    }
    fn set_mtime(&self, secs: u64) {
        let mut raw = self.raw.lock();
        let mut r = raw.clone();
        put32(&mut r, 0x10, secs as u32);
        if self.save(&mut r).is_ok() {
            *raw = r;
        }
    }
    fn nlink(&self) -> u64 {
        Self::links(&self.raw.lock()) as u64
    }
    fn link_added(&self) {
        let _ = self.change_links(1);
    }
    fn link_removed(&self) {
        let _ = self.change_links(-1);
    }
    fn stat(&self) -> crate::abi::Stat {
        let raw = self.raw.lock();
        let size = Self::size_of(&raw);
        let blocks = le32(&raw, 0x1c) as u64 | (le16(&raw, 0x74) as u64) << 32;
        let (t_a, t_m, t_c) = (le32(&raw, 0x08), le32(&raw, 0x10), le32(&raw, 0x0c));
        let uid = le16(&raw, 0x02) as u32 | (le16(&raw, 0x78) as u32) << 16;
        let gid = le16(&raw, 0x18) as u32 | (le16(&raw, 0x7a) as u32) << 16;
        crate::abi::Stat {
            st_dev: self.fs.dev_id,
            st_ino: self.ino as u64,
            st_nlink: Self::links(&raw) as u64,
            st_mode: le16(&raw, 0) as u32,
            st_uid: uid,
            st_gid: gid,
            st_size: size as i64,
            st_blksize: self.fs.bs as i64,
            st_blocks: blocks as i64,
            st_atime: t_a as i64,
            st_mtime: t_m as i64,
            st_ctime: t_c as i64,
            ..Default::default()
        }
    }

    fn read_at(&self, off: u64, buf: &mut [u8]) -> KResult<usize> {
        if self.file_type() == FileType::Directory {
            return Err(Errno::EISDIR);
        }
        let size = self.size();
        if off >= size {
            return Ok(0);
        }
        let n = buf.len().min((size - off) as usize);
        let mut done = 0;
        while done < n {
            let pos = off + done as u64;
            let idx = pos / PAGE_SIZE;
            let in_page = (pos % PAGE_SIZE) as usize;
            let len = (PAGE_SIZE as usize - in_page).min(n - done);
            let phys = self.cached_page(idx)?;
            let src = unsafe { core::slice::from_raw_parts(phys_to_virt(phys).add(in_page), len) };
            buf[done..done + len].copy_from_slice(src);
            done += len;
        }
        Ok(n)
    }

    fn write_at(&self, off: u64, data: &[u8]) -> KResult<usize> {
        if self.fs.readonly {
            return Err(Errno::EROFS);
        }
        if self.file_type() == FileType::Directory {
            return Err(Errno::EISDIR);
        }
        let bs = self.fs.bs;
        let mut done = 0;
        while done < data.len() {
            let pos = off + done as u64;
            let idx = pos / PAGE_SIZE;
            let in_page = (pos % PAGE_SIZE) as usize;
            let len = (PAGE_SIZE as usize - in_page).min(data.len() - done);
            let phys = self.cached_page(idx)?;
            let page =
                unsafe { core::slice::from_raw_parts_mut(phys_to_virt(phys), PAGE_SIZE as usize) };
            page[in_page..in_page + len].copy_from_slice(&data[done..done + len]);
            // Write the touched blocks through.
            let mut raw = self.raw.lock();
            let mut r = raw.clone();
            let first = (in_page / bs) as u64;
            let last = ((in_page + len - 1) / bs) as u64;
            let per = (PAGE_SIZE as usize / bs) as u64;
            for k in first..=last {
                let lb = idx * per + k;
                let b = self.block_for_write(&mut r, lb)?;
                self.fs
                    .write_block(b, &page[k as usize * bs..(k as usize + 1) * bs])?;
            }
            let end = pos + len as u64;
            if end > Self::size_of(&r) {
                Self::set_size(&mut r, end);
            }
            put32(&mut r, 0x10, now());
            self.save(&mut r)?;
            *raw = r;
            done += len;
        }
        Ok(done)
    }

    fn truncate(&self, len: u64) -> KResult<()> {
        if self.fs.readonly {
            return Err(Errno::EROFS);
        }
        let mut raw = self.raw.lock();
        let mut r = raw.clone();
        let old = Self::size_of(&r);
        if len < old {
            let bs = self.fs.bs as u64;
            self.free_from(&mut r, len.div_ceil(bs))?;
            // Zero the tail of the last block (later growth must read 0s).
            if !len.is_multiple_of(bs)
                && let Some((b, false)) = self.bmap(&r, len / bs)?
            {
                let mut blk = self.fs.read_block_uncached(b)?;
                blk[(len % bs) as usize..].fill(0);
                self.fs.write_block(b, &blk)?;
            }
        }
        Self::set_size(&mut r, len);
        put32(&mut r, 0x10, now());
        self.save(&mut r)?;
        *raw = r;
        drop(raw);
        self.drop_pages_from(len / PAGE_SIZE);
        Ok(())
    }

    fn page(&self, idx: u64) -> KResult<u64> {
        let p = self.cached_page(idx)?;
        frame::get(p);
        Ok(p)
    }

    fn readlink(&self) -> KResult<String> {
        if self.file_type() != FileType::Symlink {
            return Err(Errno::EINVAL);
        }
        let raw = self.raw.lock().clone();
        let size = Self::size_of(&raw) as usize;
        if Self::flags(&raw) & (FL_EXTENTS | FL_INLINE) == 0 && size < 60 {
            return Ok(String::from_utf8_lossy(&raw[0x28..0x28 + size]).into_owned());
        }
        let mut buf = vec![0u8; size];
        self.read_at(0, &mut buf)?;
        Ok(String::from_utf8_lossy(&buf).into_owned())
    }

    fn lookup(&self, name: &str) -> KResult<Arc<dyn Inode>> {
        if self.file_type() != FileType::Directory {
            return Err(Errno::ENOTDIR);
        }
        match self.find(name)? {
            Some(ino) => self.fs.inode(ino),
            None => Err(Errno::ENOENT),
        }
    }

    fn parent(&self) -> Option<Arc<dyn Inode>> {
        let ino = self.find("..").ok().flatten()?;
        self.fs.inode(ino).ok()
    }

    fn create(&self, name: &str, ty: FileType, perm: u32) -> KResult<Arc<dyn Inode>> {
        if self.file_type() != FileType::Directory {
            return Err(Errno::ENOTDIR);
        }
        match ty {
            FileType::Regular | FileType::Directory | FileType::Fifo => {
                Ok(self.create_child(name, ty, perm)?)
            }
            _ => Err(Errno::EPERM),
        }
    }

    fn symlink(&self, name: &str, target: &str) -> KResult<()> {
        let child = self.create_child(name, FileType::Symlink, 0o777)?;
        if target.len() < 60 {
            let mut raw = child.raw.lock();
            let mut r = raw.clone();
            r[0x28..0x28 + 60].fill(0);
            r[0x28..0x28 + target.len()].copy_from_slice(target.as_bytes());
            Self::set_size(&mut r, target.len() as u64);
            child.save(&mut r)?;
            *raw = r;
        } else {
            {
                let mut raw = child.raw.lock();
                let mut r = raw.clone();
                put32(&mut r, 0x20, FL_EXTENTS);
                put16(&mut r, 0x28, EXT_MAGIC);
                put16(&mut r, 0x28 + 4, 4);
                child.save(&mut r)?;
                *raw = r;
            }
            child.write_at(0, target.as_bytes())?;
        }
        Ok(())
    }

    fn insert(&self, name: &str, inode: Arc<dyn Inode>) -> KResult<()> {
        if inode.dev() != self.fs.dev_id {
            return Err(Errno::EXDEV);
        }
        if self.find(name)?.is_some() {
            return Err(Errno::EEXIST);
        }
        self.add_entry(name, inode.ino() as u32, inode.file_type())
    }

    fn remove(&self, name: &str, dir: bool) -> KResult<()> {
        if self.fs.readonly {
            return Err(Errno::EROFS);
        }
        if name == "." {
            return Err(Errno::EINVAL);
        }
        if name == ".." {
            return Err(Errno::ENOTEMPTY);
        }
        let ino = self.find(name)?.ok_or(Errno::ENOENT)?;
        let child = self.fs.inode_arc(ino)?;
        let is_dir = child.file_type() == FileType::Directory;
        match (dir, is_dir) {
            (true, false) => return Err(Errno::ENOTDIR),
            (false, true) => return Err(Errno::EISDIR),
            (true, true) if !child.is_empty_dir() => return Err(Errno::ENOTEMPTY),
            _ => {}
        }
        self.remove_entry(name)?;
        if is_dir {
            child.change_links(-2)?;
            self.change_links(-1)?;
        } else {
            child.change_links(-1)?;
        }
        if Self::links(&child.raw.lock()) == 0 {
            self.fs.forget(ino);
        }
        Ok(())
    }

    fn take(&self, name: &str) -> KResult<Arc<dyn Inode>> {
        let ino = self.remove_entry(name)?;
        let child = self.fs.inode_arc(ino)?;
        if child.file_type() == FileType::Directory {
            self.change_links(-1)?;
        }
        // The caller re-inserts it: undo insert's effect on the count.
        Ok(child)
    }

    fn set_parent(&self, parent: &Arc<dyn Inode>) {
        // Point ".." at the new parent, which gains a link.
        let Ok(Some(_)) = self.find("..") else { return };
        let fs = &self.fs;
        let raw = self.raw.lock().clone();
        if let Ok(Some((b, _))) = self.bmap(&raw, 0)
            && let Ok(blk) = fs.read_block(b)
        {
            let mut blk = (*blk).clone();
            let dot_rec = le16(&blk, 4) as usize;
            put32(&mut blk, dot_rec, parent.ino() as u32);
            fs.csum_dir_block(self.seed(&raw), &mut blk);
            let _ = fs.write_block(b, &blk);
        }
        parent.link_added();
    }

    fn entries(&self) -> KResult<Vec<(String, Arc<dyn Inode>)>> {
        let mut names = Vec::new();
        self.scan_dir(|_, _, ino, n, _| {
            if n != b"." && n != b".." {
                names.push((String::from_utf8_lossy(n).into_owned(), ino));
            }
            false
        })?;
        let mut out = Vec::with_capacity(names.len());
        for (n, ino) in names {
            if let Ok(i) = self.fs.inode(ino) {
                out.push((n, i));
            }
        }
        Ok(out)
    }

    fn is_empty_dir(&self) -> bool {
        let mut empty = true;
        let _ = self.scan_dir(|_, _, _, n, _| {
            if n != b"." && n != b".." {
                empty = false;
                true
            } else {
                false
            }
        });
        empty
    }

    fn poll(&self) -> u16 {
        poll::POLLIN | poll::POLLOUT
    }

    fn name_of(&self, child: &Arc<dyn Inode>) -> Option<String> {
        if child.dev() != self.fs.dev_id {
            return None;
        }
        let want = child.ino() as u32;
        let mut name = None;
        let _ = self.scan_dir(|_, _, ino, n, _| {
            if ino == want && n != b"." && n != b".." {
                name = Some(String::from_utf8_lossy(n).into_owned());
                true
            } else {
                false
            }
        });
        name
    }

    fn shares_pages(&self) -> bool {
        true
    }

    fn write_page(&self, idx: u64) -> KResult<()> {
        let Some(&phys) = self.pages.lock().get(&idx) else {
            return Ok(());
        };
        let bs = self.fs.bs;
        let mut raw = self.raw.lock();
        let mut r = raw.clone();
        let size = Self::size_of(&r);
        let per = (PAGE_SIZE as usize / bs) as u64;
        let page = unsafe { core::slice::from_raw_parts(phys_to_virt(phys), PAGE_SIZE as usize) };
        for k in 0..per {
            let lb = idx * per + k;
            if lb * bs as u64 >= size {
                break;
            }
            let b = self.block_for_write(&mut r, lb)?;
            self.fs
                .write_block(b, &page[k as usize * bs..(k as usize + 1) * bs])?;
        }
        self.save(&mut r)?;
        *raw = r;
        Ok(())
    }

    fn fs_stats(&self) -> Option<(u64, u64, u64, u64, u64, u64)> {
        let sb = self.fs.sb.lock();
        let free = le32(&sb, 0x0c) as u64 | (le32(&sb, 0x158) as u64) << 32;
        Some((
            0xef53,
            self.fs.bs as u64,
            self.fs.blocks,
            free,
            le32(&sb, 0x00) as u64,
            le32(&sb, 0x10) as u64,
        ))
    }
}
