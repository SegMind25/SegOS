//! ext4 (and ext2/ext3).
//!
//! Reads the superblock and group descriptors (32- or 64-bit, with or
//! without `meta_bg`), inodes of any size, file data through extent trees
//! or classic indirect block maps (holes read as zeros), inline data,
//! directories by a linear scan of their entries (htree directories are
//! ordinary entry blocks to such a scan), and fast and slow symbolic
//! links.
//!
//! Writes go in place, without the journal: every operation updates the
//! bitmaps, group descriptors, inodes, extent trees and directory blocks
//! it touches (with their checksums under `metadata_csum` or `gdt_csum`)
//! and leaves the file system consistent when it returns. The journal is
//! kept empty and clean; one left by a crash is replayed at mount
//! (see [`journal`]). A file system with a feature the writer does not
//! handle is mounted read-only ([`Ext4Fs::writable`]).
//!
//! All operations of one file system are serialised by one sleeping lock
//! (the "big lock", [`Ext4Fs::state`]).
//!
//! Layout references: the ext4 on-disk format as documented in the Linux
//! kernel's `Documentation/filesystems/ext4/` pages, and jbd2's in
//! `Documentation/filesystems/ext4/journal.rst`.

mod alloc_bits;
mod crc;
mod dir;
mod extent;
mod inode;
mod journal;
mod node;

use crate::abi::{Errno, KResult};
use crate::block::{BlockDevice, read_bytes, write_bytes};
use crate::fs::Inode;
use crate::sync::{Mutex, SpinLock};
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::{Arc, Weak};
use alloc::vec;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use inode::RawInode;
use node::Ext4Inode;

/// Byte offset of the superblock on the device.
const SUPERBLOCK_OFFSET: u64 = 1024;
const SUPERBLOCK_SIZE: usize = 1024;
const MAGIC: u16 = 0xef53;
const ROOT_INO: u32 = 2;

// s_feature_compat
const COMPAT_SPARSE_SUPER2: u32 = 0x200;

// s_feature_incompat
const INCOMPAT_COMPRESSION: u32 = 0x1;
const INCOMPAT_FILETYPE: u32 = 0x2;
const INCOMPAT_RECOVER: u32 = 0x4;
const INCOMPAT_JOURNAL_DEV: u32 = 0x8;
const INCOMPAT_META_BG: u32 = 0x10;
const INCOMPAT_EXTENTS: u32 = 0x40;
const INCOMPAT_64BIT: u32 = 0x80;
const INCOMPAT_MMP: u32 = 0x100;
const INCOMPAT_FLEX_BG: u32 = 0x200;
const INCOMPAT_EA_INODE: u32 = 0x400;
const INCOMPAT_DIRDATA: u32 = 0x1000;
const INCOMPAT_CSUM_SEED: u32 = 0x2000;
const INCOMPAT_LARGEDIR: u32 = 0x4000;
const INCOMPAT_INLINE_DATA: u32 = 0x8000;
const INCOMPAT_ENCRYPT: u32 = 0x10000;
const INCOMPAT_CASEFOLD: u32 = 0x20000;

/// Incompatible features this reader understands (or that do not change
/// how existing data is read).
const INCOMPAT_SUPPORTED: u32 = INCOMPAT_FILETYPE
    | INCOMPAT_RECOVER
    | INCOMPAT_META_BG
    | INCOMPAT_EXTENTS
    | INCOMPAT_64BIT
    | INCOMPAT_MMP
    | INCOMPAT_FLEX_BG
    | INCOMPAT_EA_INODE
    | INCOMPAT_CSUM_SEED
    | INCOMPAT_LARGEDIR
    | INCOMPAT_INLINE_DATA
    | INCOMPAT_CASEFOLD;

/// Incompatible features the writer handles. Inline-data inodes are
/// read-only (EROFS), new ones are never inline.
const INCOMPAT_WRITABLE: u32 = INCOMPAT_FILETYPE
    | INCOMPAT_META_BG
    | INCOMPAT_EXTENTS
    | INCOMPAT_64BIT
    | INCOMPAT_FLEX_BG
    | INCOMPAT_CSUM_SEED
    | INCOMPAT_LARGEDIR
    | INCOMPAT_INLINE_DATA;

// s_feature_ro_compat
const RO_COMPAT_SPARSE_SUPER: u32 = 0x1;
const RO_COMPAT_LARGE_FILE: u32 = 0x2;
const RO_COMPAT_BTREE_DIR: u32 = 0x4;
const RO_COMPAT_HUGE_FILE: u32 = 0x8;
const RO_COMPAT_GDT_CSUM: u32 = 0x10;
const RO_COMPAT_DIR_NLINK: u32 = 0x20;
const RO_COMPAT_EXTRA_ISIZE: u32 = 0x40;
const RO_COMPAT_METADATA_CSUM: u32 = 0x400;
const RO_COMPAT_PROJECT: u32 = 0x2000;
const RO_COMPAT_VERITY: u32 = 0x8000;

/// Read-only-compatible features the writer keeps consistent (others,
/// such as quota, bigalloc or snapshots, make the mount read-only).
const RO_COMPAT_WRITABLE: u32 = RO_COMPAT_SPARSE_SUPER
    | RO_COMPAT_LARGE_FILE
    | RO_COMPAT_BTREE_DIR
    | RO_COMPAT_HUGE_FILE
    | RO_COMPAT_GDT_CSUM
    | RO_COMPAT_DIR_NLINK
    | RO_COMPAT_EXTRA_ISIZE
    | RO_COMPAT_METADATA_CSUM
    | RO_COMPAT_PROJECT
    | RO_COMPAT_VERITY;

// s_state
const STATE_VALID: u16 = 1;
const STATE_ERROR: u16 = 2;

// bg_flags
const BG_INODE_UNINIT: u16 = 1;
const BG_BLOCK_UNINIT: u16 = 2;

/// Metadata blocks kept in memory.
const BLOCK_CACHE_SIZE: usize = 128;

pub(crate) fn le16(b: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([b[off], b[off + 1]])
}

pub(crate) fn le32(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}

pub(crate) fn put16(b: &mut [u8], off: usize, v: u16) {
    b[off..off + 2].copy_from_slice(&v.to_le_bytes());
}

pub(crate) fn put32(b: &mut [u8], off: usize, v: u32) {
    b[off..off + 4].copy_from_slice(&v.to_le_bytes());
}

/// Seconds and nanoseconds since 1970.
pub(crate) fn now() -> (i64, u32) {
    let ns = crate::time::realtime_ns();
    ((ns / 1_000_000_000) as i64, (ns % 1_000_000_000) as u32)
}

/// Which metadata checksums the file system keeps.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Csum {
    None,
    /// gdt_csum: CRC16 of the group descriptors only.
    Crc16,
    /// metadata_csum: CRC32C of everything.
    Crc32c,
}

/// The superblock fields the reader uses (the geometry, fixed while
/// mounted).
struct Superblock {
    inodes_count: u32,
    blocks_count: u64,
    free_blocks: u64,
    free_inodes: u32,
    first_data_block: u32,
    block_size: u64,
    blocks_per_group: u32,
    inodes_per_group: u32,
    inode_size: u32,
    rev: u32,
    first_ino: u32,
    compat: u32,
    incompat: u32,
    ro_compat: u32,
    desc_size: u32,
    first_meta_bg: u32,
    reserved_gdt: u32,
    backup_bgs: [u32; 2],
    volume_name: [u8; 16],
    uuid: [u8; 16],
    csum_seed: u32,
    journal_inum: u32,
    last_orphan: u32,
    state: u16,
    want_extra_isize: u16,
}

impl Superblock {
    fn parse(b: &[u8]) -> KResult<Self> {
        if le16(b, 0x38) != MAGIC {
            return Err(Errno::EINVAL);
        }
        let log = le32(b, 0x18);
        if log > 6 {
            return Err(Errno::EINVAL); // larger than 64 KiB
        }
        let rev = le32(b, 0x4c);
        let (compat, incompat, ro_compat) = if rev == 0 {
            (0, 0, 0)
        } else {
            (le32(b, 0x5c), le32(b, 0x60), le32(b, 0x64))
        };
        let is64 = incompat & INCOMPAT_64BIT != 0;
        let hi = |off: usize| if is64 { (le32(b, off) as u64) << 32 } else { 0 };
        let mut volume_name = [0u8; 16];
        volume_name.copy_from_slice(&b[0x78..0x88]);
        let mut uuid = [0u8; 16];
        uuid.copy_from_slice(&b[0x68..0x78]);
        let sb = Self {
            inodes_count: le32(b, 0x0),
            blocks_count: le32(b, 0x4) as u64 | hi(0x150),
            free_blocks: le32(b, 0xc) as u64 | hi(0x158),
            free_inodes: le32(b, 0x10),
            first_data_block: le32(b, 0x14),
            block_size: 1024 << log,
            blocks_per_group: le32(b, 0x20),
            inodes_per_group: le32(b, 0x28),
            inode_size: if rev == 0 { 128 } else { le16(b, 0x58) as u32 },
            rev,
            first_ino: if rev == 0 { 11 } else { le32(b, 0x54) },
            compat,
            incompat,
            ro_compat,
            desc_size: if is64 { le16(b, 0xfe) as u32 } else { 32 },
            first_meta_bg: le32(b, 0x104),
            reserved_gdt: le16(b, 0xce) as u32,
            backup_bgs: [le32(b, 0x24c), le32(b, 0x250)],
            volume_name,
            uuid,
            csum_seed: le32(b, 0x270),
            journal_inum: le32(b, 0xe0),
            last_orphan: le32(b, 0xe8),
            state: le16(b, 0x3a),
            want_extra_isize: le16(b, 0x15e),
        };
        let bs = sb.block_size as u32;
        if sb.blocks_per_group == 0
            || sb.inodes_per_group == 0
            || sb.inode_size < 128
            || !sb.inode_size.is_power_of_two()
            || sb.inode_size > bs
            || sb.desc_size < 32
            || sb.desc_size > bs
            || !sb.desc_size.is_power_of_two()
            || (is64 && sb.desc_size < 64)
            || sb.blocks_count <= sb.first_data_block as u64
            || sb.inodes_per_group > bs * 8
        {
            return Err(Errno::EINVAL);
        }
        Ok(sb)
    }

    fn group_count(&self) -> u64 {
        (self.blocks_count - self.first_data_block as u64).div_ceil(self.blocks_per_group as u64)
    }

    /// Whether block group `g` holds a superblock backup (and so its
    /// first block is not data).
    fn group_has_super(&self, g: u64) -> bool {
        if g == 0 {
            return true;
        }
        if self.compat & COMPAT_SPARSE_SUPER2 != 0 {
            return g == self.backup_bgs[0] as u64 || g == self.backup_bgs[1] as u64;
        }
        if self.ro_compat & RO_COMPAT_SPARSE_SUPER == 0 || g == 1 {
            return true;
        }
        let power_of = |base: u64| {
            let mut n = g;
            while n.is_multiple_of(base) {
                n /= base;
            }
            n == 1
        };
        power_of(3) || power_of(5) || power_of(7)
    }
}

/// A small cache of metadata blocks (descriptors, bitmaps, inode tables,
/// extent tree nodes, indirect blocks). Every write updates it.
struct BlockCache {
    blocks: BTreeMap<u64, (Arc<Vec<u8>>, u64)>,
    tick: u64,
}

/// What the big lock protects.
struct FsState {
    /// The superblock as on disk.
    sb: Vec<u8>,
    sb_dirty: bool,
    /// Where the last block search ended (the next one starts there).
    last_group: u64,
}

/// A mounted ext2/3/4 file system.
pub struct Ext4Fs {
    dev: Arc<dyn BlockDevice>,
    dev_id: u64,
    sb: Superblock,
    group_count: u64,
    /// Group descriptor blocks (not meta_bg).
    gdb_count: u64,
    csum: Csum,
    /// metadata_csum seed (CRC32C of the UUID, or s_checksum_seed).
    seed: u32,
    writable: bool,
    free_blocks: AtomicU64,
    free_inodes: AtomicU64,
    root_raw: RawInode,
    state: Mutex<FsState>,
    cache: SpinLock<BlockCache>,
    inodes: SpinLock<BTreeMap<u32, Weak<Ext4Inode>>>,
}

impl Ext4Fs {
    /// Reads and checks the superblock; refuses (EINVAL) if not ext2/3/4 or
    /// if it needs an incompat feature we do not support. `dev_id` is the
    /// st_dev to report. A journal left by a crash is replayed first; the
    /// file system is writable if [`Ext4Fs::writable`] says so.
    pub fn mount(dev: Arc<dyn BlockDevice>, dev_id: u64) -> KResult<Arc<Ext4Fs>> {
        let fs = Self::open(dev.clone(), dev_id, true)?;
        if fs.sb.incompat & INCOMPAT_RECOVER == 0 || !fs.writable {
            fs.mounted()?;
            return Ok(fs);
        }
        match journal::replay(&fs) {
            Ok(()) => {
                crate::info!("ext4: {}: journal replayed", dev.name());
                drop(fs);
                let fs = Self::open(dev, dev_id, true)?;
                fs.mounted()?;
                Ok(fs)
            }
            Err(e) => {
                crate::warn!(
                    "ext4: {}: cannot replay the journal ({e:?}); mounting read-only",
                    dev.name()
                );
                drop(fs);
                Self::open(dev, dev_id, false)
            }
        }
    }

    /// Whether writes are possible (the device is writable and every
    /// feature of the file system is one the writer handles).
    pub fn writable(&self) -> bool {
        self.writable
    }

    fn open(dev: Arc<dyn BlockDevice>, dev_id: u64, may_write: bool) -> KResult<Arc<Ext4Fs>> {
        if dev.size_bytes() < SUPERBLOCK_OFFSET + SUPERBLOCK_SIZE as u64 {
            return Err(Errno::EINVAL);
        }
        let mut b = vec![0u8; SUPERBLOCK_SIZE];
        read_bytes(dev.as_ref(), SUPERBLOCK_OFFSET, &mut b)?;
        let sb = Superblock::parse(&b)?;
        let name = dev.name();
        let unsupported = sb.incompat & !INCOMPAT_SUPPORTED;
        if unsupported != 0 {
            let known = [
                (INCOMPAT_COMPRESSION, "compression"),
                (INCOMPAT_JOURNAL_DEV, "journal_dev"),
                (INCOMPAT_DIRDATA, "dirdata"),
                (INCOMPAT_ENCRYPT, "encrypt"),
            ];
            let what = known
                .iter()
                .find(|(f, _)| unsupported & f != 0)
                .map_or("unknown", |(_, n)| *n);
            crate::warn!("ext4: {name}: unsupported feature {what} ({unsupported:#x})");
            return Err(Errno::EINVAL);
        }
        if sb.blocks_count.saturating_mul(sb.block_size) > dev.size_bytes() {
            crate::warn!("ext4: {name}: file system larger than the device");
            return Err(Errno::EINVAL);
        }
        let group_count = sb.group_count();
        if (sb.inodes_count as u64) > group_count * sb.inodes_per_group as u64 {
            return Err(Errno::EINVAL);
        }
        let csum = if sb.ro_compat & RO_COMPAT_METADATA_CSUM != 0 {
            Csum::Crc32c
        } else if sb.ro_compat & RO_COMPAT_GDT_CSUM != 0 {
            Csum::Crc16
        } else {
            Csum::None
        };
        let seed = if sb.incompat & INCOMPAT_CSUM_SEED != 0 {
            sb.csum_seed
        } else {
            crc::crc32c(!0, &sb.uuid)
        };
        let mut writable = may_write && !dev.read_only();
        let ro_reason = if sb.rev == 0 {
            Some("revision 0")
        } else if sb.incompat & !INCOMPAT_WRITABLE & !INCOMPAT_RECOVER != 0 {
            Some("incompatible features")
        } else if sb.ro_compat & !RO_COMPAT_WRITABLE != 0 {
            Some("read-only-compatible features")
        } else if sb.state & STATE_ERROR != 0 {
            Some("errors recorded")
        } else if sb.desc_size > 64 && csum == Csum::Crc16 {
            Some("descriptor size")
        } else {
            None
        };
        if writable && let Some(r) = ro_reason {
            crate::warn!("ext4: {name}: read-only ({r})");
            writable = false;
        }
        if sb.incompat & INCOMPAT_RECOVER != 0 && !writable {
            crate::warn!("ext4: {name}: needs journal recovery; read-only without replaying it");
        }
        let per_block = sb.block_size / sb.desc_size as u64;
        let mut fs = Ext4Fs {
            dev,
            dev_id,
            group_count,
            gdb_count: group_count.div_ceil(per_block),
            csum,
            seed,
            writable,
            free_blocks: AtomicU64::new(sb.free_blocks),
            free_inodes: AtomicU64::new(sb.free_inodes as u64),
            sb,
            root_raw: RawInode::empty(),
            state: Mutex::new(FsState {
                sb: b,
                sb_dirty: false,
                last_group: 0,
            }),
            cache: SpinLock::new(BlockCache {
                blocks: BTreeMap::new(),
                tick: 0,
            }),
            inodes: SpinLock::new(BTreeMap::new()),
        };
        // The superblock's free counts are only updated now and then; the
        // group descriptors are exact.
        if let Ok((fb, fi)) = fs.sum_free_counts() {
            fs.free_blocks.store(fb, Ordering::Relaxed);
            fs.free_inodes.store(fi, Ordering::Relaxed);
        }
        let root = fs.read_raw_inode(ROOT_INO)?;
        if root.file_type() != Some(crate::fs::FileType::Directory) {
            crate::warn!("ext4: {}: root is not a directory", fs.dev.name());
            return Err(Errno::EINVAL);
        }
        fs.root_raw = root;
        Ok(Arc::new(fs))
    }

    /// A writable mount begins: orphans left by a crash are finished off,
    /// the mount is counted in the superblock.
    fn mounted(self: &Arc<Self>) -> KResult<()> {
        if !self.writable {
            return Ok(());
        }
        if self.sb.last_orphan != 0 {
            self.clean_orphans();
        }
        let mut st = self.state.lock();
        let (t, _) = now();
        let count = le16(&st.sb, 0x34).wrapping_add(1);
        put16(&mut st.sb, 0x34, count);
        put32(&mut st.sb, 0x2c, t as u32); // s_mtime
        let state = le16(&st.sb, 0x3a) | STATE_VALID;
        put16(&mut st.sb, 0x3a, state);
        st.sb_dirty = true;
        self.flush_sb(&mut st)
    }

    pub fn root(self: &Arc<Self>) -> Arc<dyn Inode> {
        self.inode_from_raw(ROOT_INO, self.root_raw.clone())
    }

    pub fn volume_name(&self) -> String {
        let n = &self.sb.volume_name;
        let len = n.iter().position(|&c| c == 0).unwrap_or(n.len());
        String::from_utf8_lossy(&n[..len]).into_owned()
    }

    /// (block size, total blocks, free blocks, total inodes, free inodes)
    /// for statfs/df.
    pub fn stats(&self) -> (u64, u64, u64, u64, u64) {
        (
            self.sb.block_size,
            self.sb.blocks_count,
            self.free_blocks.load(Ordering::Relaxed),
            self.sb.inodes_count as u64,
            self.free_inodes.load(Ordering::Relaxed),
        )
    }

    fn block_size(&self) -> u64 {
        self.sb.block_size
    }

    fn has_incompat(&self, f: u32) -> bool {
        self.sb.incompat & f != 0
    }

    fn huge_file(&self) -> bool {
        self.sb.ro_compat & RO_COMPAT_HUGE_FILE != 0
    }

    fn metadata_csum(&self) -> bool {
        self.csum == Csum::Crc32c
    }

    /// Group descriptors carry a checksum, and the uninit flags mean
    /// something.
    fn group_csum(&self) -> bool {
        self.csum != Csum::None
    }

    fn check_range(&self, blk: u64, off: u64, len: usize) -> KResult<u64> {
        let bs = self.block_size();
        let start = blk
            .checked_mul(bs)
            .and_then(|b| b.checked_add(off))
            .ok_or(Errno::EIO)?;
        let end = start.checked_add(len as u64).ok_or(Errno::EIO)?;
        if end > self.sb.blocks_count * bs {
            return Err(Errno::EIO);
        }
        Ok(start)
    }

    /// Reads `buf.len()` bytes of the device starting at byte `off` of
    /// block `blk`, bypassing the cache (file data).
    fn read_direct(&self, blk: u64, off: u64, buf: &mut [u8]) -> KResult<()> {
        let at = self.check_range(blk, off, buf.len())?;
        read_bytes(self.dev.as_ref(), at, buf)
    }

    /// Writes `data` at byte `off` of block `blk` (and onwards), keeping
    /// cached copies of the blocks it covers up to date.
    fn write_at(&self, blk: u64, off: u64, data: &[u8]) -> KResult<()> {
        if !self.writable {
            return Err(Errno::EROFS);
        }
        let at = self.check_range(blk, off, data.len())?;
        let bs = self.block_size();
        {
            let mut c = self.cache.lock();
            let first = at / bs;
            let last = (at + data.len() as u64).div_ceil(bs);
            for b in first..last {
                if let Some(e) = c.blocks.get_mut(&b) {
                    let bstart = b * bs;
                    let s = at.max(bstart);
                    let e_end = (at + data.len() as u64).min(bstart + bs);
                    let mut copy = (*e.0).clone();
                    copy[(s - bstart) as usize..(e_end - bstart) as usize]
                        .copy_from_slice(&data[(s - at) as usize..(e_end - at) as usize]);
                    e.0 = Arc::new(copy);
                }
            }
        }
        write_bytes(self.dev.as_ref(), at, data)
    }

    /// One metadata block, through the cache. The lock is never held
    /// while the device is read.
    fn block(&self, blk: u64) -> KResult<Arc<Vec<u8>>> {
        if blk >= self.sb.blocks_count {
            return Err(Errno::EIO);
        }
        {
            let mut c = self.cache.lock();
            c.tick += 1;
            let tick = c.tick;
            if let Some(e) = c.blocks.get_mut(&blk) {
                e.1 = tick;
                return Ok(e.0.clone());
            }
        }
        let bs = self.block_size();
        let mut data = vec![0u8; bs as usize];
        read_bytes(self.dev.as_ref(), blk * bs, &mut data)?;
        let data = Arc::new(data);
        let mut c = self.cache.lock();
        c.tick += 1;
        let tick = c.tick;
        if let Some(e) = c.blocks.get(&blk) {
            return Ok(e.0.clone()); // someone was faster (and maybe wrote)
        }
        if c.blocks.len() >= BLOCK_CACHE_SIZE {
            let oldest = c.blocks.iter().min_by_key(|(_, e)| e.1).map(|(k, _)| *k);
            if let Some(k) = oldest {
                c.blocks.remove(&k);
            }
        }
        c.blocks.insert(blk, (data.clone(), tick));
        Ok(data)
    }

    /// Forgets every cached block (after the journal wrote behind its back).
    fn drop_cache(&self) {
        self.cache.lock().blocks.clear();
    }

    /// Where group descriptor `g` is: (block, byte offset in it).
    fn desc_location(&self, g: u64) -> (u64, usize) {
        let bs = self.block_size();
        let per_block = bs / self.sb.desc_size as u64;
        let desc_blk = g / per_block;
        let off = ((g % per_block) * self.sb.desc_size as u64) as usize;
        let first = self.sb.first_data_block as u64;
        if !self.has_incompat(INCOMPAT_META_BG) || desc_blk < self.sb.first_meta_bg as u64 {
            return (first + 1 + desc_blk, off);
        }
        // meta_bg: each descriptor block lives in the first group of the
        // run of groups it describes.
        let group = desc_blk * per_block;
        let start = first + group * self.sb.blocks_per_group as u64;
        let has_super = self.sb.group_has_super(group) as u64;
        (start + has_super, off)
    }

    /// The raw descriptor of group `g` (32 or 64+ bytes).
    fn group_desc(&self, g: u64) -> KResult<Vec<u8>> {
        if g >= self.group_count {
            return Err(Errno::EIO);
        }
        let (blk, off) = self.desc_location(g);
        let b = self.block(blk)?;
        Ok(b[off..off + self.sb.desc_size as usize].to_vec())
    }

    /// Writes group descriptor `g` back, with its checksum.
    fn put_group_desc(&self, g: u64, d: &mut [u8]) -> KResult<()> {
        if self.group_csum() {
            let c = self.desc_csum(g, d);
            put16(d, 0x1e, c);
        }
        let (blk, off) = self.desc_location(g);
        self.write_at(blk, off as u64, d)
    }

    fn desc_csum(&self, g: u64, d: &[u8]) -> u16 {
        let ds = self.sb.desc_size as usize;
        let le_group = (g as u32).to_le_bytes();
        match self.csum {
            Csum::Crc32c => {
                let mut c = crc::crc32c(self.seed, &le_group);
                c = crc::crc32c(c, &d[..0x1e]);
                c = crc::crc32c(c, &[0, 0]);
                if ds > 0x20 {
                    c = crc::crc32c(c, &d[0x20..ds]);
                }
                c as u16
            }
            Csum::Crc16 => {
                let mut c = crc::crc16(!0, &self.sb.uuid);
                c = crc::crc16(c, &le_group);
                c = crc::crc16(c, &d[..0x1e]);
                if self.has_incompat(INCOMPAT_64BIT) && ds > 0x20 {
                    c = crc::crc16(c, &d[0x20..ds]);
                }
                c
            }
            Csum::None => 0,
        }
    }

    fn desc_field(&self, d: &[u8], lo32: usize, hi32: usize) -> u64 {
        let hi = if self.sb.desc_size >= 64 {
            (le32(d, hi32) as u64) << 32
        } else {
            0
        };
        le32(d, lo32) as u64 | hi
    }

    fn desc_field16(&self, d: &[u8], lo16: usize, hi16: usize) -> u64 {
        let hi = if self.sb.desc_size >= 64 {
            (le16(d, hi16) as u64) << 16
        } else {
            0
        };
        le16(d, lo16) as u64 | hi
    }

    fn set_desc_field16(&self, d: &mut [u8], lo16: usize, hi16: usize, v: u64) {
        put16(d, lo16, v as u16);
        if self.sb.desc_size >= 64 {
            put16(d, hi16, (v >> 16) as u16);
        }
    }

    fn sum_free_counts(&self) -> KResult<(u64, u64)> {
        let (mut fb, mut fi) = (0u64, 0u64);
        for g in 0..self.group_count {
            let d = self.group_desc(g)?;
            fb += self.desc_field16(&d, 0xc, 0x2c);
            fi += self.desc_field16(&d, 0xe, 0x2e);
        }
        Ok((fb, fi))
    }

    /// Where inode `ino` is: (block, byte offset in it).
    fn inode_location(&self, ino: u32) -> KResult<(u64, usize)> {
        if ino == 0 || ino > self.sb.inodes_count {
            return Err(Errno::EIO);
        }
        let idx = (ino - 1) as u64;
        let ipg = self.sb.inodes_per_group as u64;
        let d = self.group_desc(idx / ipg)?;
        let table = self.desc_field(&d, 0x8, 0x28);
        let byte = (idx % ipg) * self.sb.inode_size as u64;
        let bs = self.block_size();
        Ok((table + byte / bs, (byte % bs) as usize))
    }

    /// Reads inode `ino` from its group's inode table.
    fn read_raw_inode(&self, ino: u32) -> KResult<RawInode> {
        let (blk, off) = self.inode_location(ino)?;
        let b = self.block(blk)?;
        RawInode::parse(&b[off..off + self.sb.inode_size as usize])
    }

    /// Writes inode `ino` back (with its checksum).
    fn write_raw_inode(&self, ino: u32, raw: &RawInode) -> KResult<()> {
        let bytes = raw.serialize(self, ino);
        let (blk, off) = self.inode_location(ino)?;
        self.write_at(blk, off as u64, &bytes)
    }

    /// The inode `ino`, shared while anyone holds it.
    fn inode(self: &Arc<Self>, ino: u32) -> KResult<Arc<Ext4Inode>> {
        if let Some(i) = self.inodes.lock().get(&ino).and_then(Weak::upgrade) {
            return Ok(i);
        }
        let raw = self.read_raw_inode(ino)?;
        if raw.mode == 0 || raw.file_type().is_none() {
            return Err(Errno::EIO); // a free inode, or garbage
        }
        Ok(self.inode_from_raw(ino, raw))
    }

    fn inode_from_raw(self: &Arc<Self>, ino: u32, raw: RawInode) -> Arc<Ext4Inode> {
        let mut map = self.inodes.lock();
        if let Some(i) = map.get(&ino).and_then(Weak::upgrade) {
            return i;
        }
        if map.len() >= 256 && map.len().is_power_of_two() {
            map.retain(|_, w| w.strong_count() > 0);
        }
        let i = Arc::new(Ext4Inode::new(self.clone(), ino, raw));
        map.insert(ino, Arc::downgrade(&i));
        i
    }

    /// The in-memory inode `ino` if one exists.
    fn cached_inode(&self, ino: u32) -> Option<Arc<Ext4Inode>> {
        self.inodes.lock().get(&ino).and_then(Weak::upgrade)
    }

    /// Writes the superblock if anything in it changed: free counts,
    /// write time, checksum.
    fn flush_sb(&self, st: &mut FsState) -> KResult<()> {
        if !st.sb_dirty {
            return Ok(());
        }
        st.sb_dirty = false;
        let fb = self.free_blocks.load(Ordering::Relaxed);
        let fi = self.free_inodes.load(Ordering::Relaxed);
        put32(&mut st.sb, 0xc, fb as u32);
        if self.has_incompat(INCOMPAT_64BIT) {
            put32(&mut st.sb, 0x158, (fb >> 32) as u32);
        }
        put32(&mut st.sb, 0x10, fi as u32);
        put32(&mut st.sb, 0x30, now().0 as u32); // s_wtime
        if self.metadata_csum() {
            let c = crc::crc32c(!0, &st.sb[..0x3fc]);
            put32(&mut st.sb, 0x3fc, c);
        }
        if !self.writable {
            return Err(Errno::EROFS);
        }
        write_bytes(self.dev.as_ref(), SUPERBLOCK_OFFSET, &st.sb)?;
        // Block 0 of a 1 KiB file system is the boot block; the superblock
        // is block 1 there and in the cache.
        let bs = self.block_size();
        let (blk, off) = (SUPERBLOCK_OFFSET / bs, SUPERBLOCK_OFFSET % bs);
        let mut c = self.cache.lock();
        if let Some(e) = c.blocks.get_mut(&blk) {
            let mut copy = (*e.0).clone();
            copy[off as usize..off as usize + SUPERBLOCK_SIZE].copy_from_slice(&st.sb);
            e.0 = Arc::new(copy);
        }
        Ok(())
    }

    /// Runs `f` under the big lock (refused on a read-only file system),
    /// then writes the superblock if `f` changed it.
    fn modify<R>(&self, f: impl FnOnce(&mut FsState) -> KResult<R>) -> KResult<R> {
        if !self.writable {
            return Err(Errno::EROFS);
        }
        let mut st = self.state.lock();
        let r = f(&mut st);
        let w = self.flush_sb(&mut st);
        let r = r?;
        w?;
        Ok(r)
    }

    /// Sets a read-only-compatible feature (large_file when a file grows
    /// past 2 GiB).
    fn set_ro_compat(&self, st: &mut FsState, f: u32) {
        let cur = le32(&st.sb, 0x64);
        if cur & f == 0 {
            put32(&mut st.sb, 0x64, cur | f);
            st.sb_dirty = true;
        }
    }

    /// Frees the inodes on the orphan list (deleted while open, or being
    /// truncated, when the system went down).
    fn clean_orphans(self: &Arc<Self>) {
        let mut next = self.sb.last_orphan;
        let mut n = 0;
        while next != 0 && n < 100_000 {
            n += 1;
            let ino = next;
            let Ok(raw) = self.read_raw_inode(ino) else {
                break;
            };
            next = raw.dtime;
            let inode = self.inode_from_raw(ino, raw);
            if let Err(e) = inode.finish_orphan() {
                crate::warn!("ext4: orphan inode {ino}: {e:?}");
            }
        }
        let mut st = self.state.lock();
        put32(&mut st.sb, 0xe8, 0);
        st.sb_dirty = true;
        let _ = self.flush_sb(&mut st);
    }
}
