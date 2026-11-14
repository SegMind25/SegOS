//! ext4 (and ext2/ext3), read-only.
//!
//! Reads the superblock and group descriptors (32- or 64-bit, with or
//! without `meta_bg`), inodes of any size, file data through extent trees
//! or classic indirect block maps (holes read as zeros), inline data,
//! directories by a linear scan of their entries (htree directories are
//! ordinary entry blocks to such a scan), and fast and slow symbolic
//! links. Checksums are ignored and the journal is not replayed: a file
//! system that needs recovery is still mounted, with a warning, as it was
//! last written in place.
//!
//! Layout references: the ext4 on-disk format as documented in the Linux
//! kernel's `Documentation/filesystems/ext4/` pages.

mod dir;
mod inode;
mod node;

use crate::abi::{Errno, KResult};
use crate::block::{BlockDevice, read_bytes};
use crate::fs::Inode;
use crate::sync::SpinLock;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::{Arc, Weak};
use alloc::vec;
use alloc::vec::Vec;

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

// s_feature_ro_compat
const RO_COMPAT_SPARSE_SUPER: u32 = 0x1;
const RO_COMPAT_HUGE_FILE: u32 = 0x8;

/// Metadata blocks kept in memory.
const BLOCK_CACHE_SIZE: usize = 64;

pub(crate) fn le16(b: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([b[off], b[off + 1]])
}

pub(crate) fn le32(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}

/// The superblock fields the reader uses.
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
    compat: u32,
    incompat: u32,
    ro_compat: u32,
    desc_size: u32,
    first_meta_bg: u32,
    backup_bgs: [u32; 2],
    volume_name: [u8; 16],
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
            compat,
            incompat,
            ro_compat,
            desc_size: if is64 { le16(b, 0xfe) as u32 } else { 32 },
            first_meta_bg: le32(b, 0x104),
            backup_bgs: [le32(b, 0x24c), le32(b, 0x250)],
            volume_name,
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
            while n % base == 0 {
                n /= base;
            }
            n == 1
        };
        power_of(3) || power_of(5) || power_of(7)
    }
}

/// A small cache of metadata blocks (descriptors, inode tables, extent
/// tree nodes, indirect blocks, directory blocks).
struct BlockCache {
    blocks: BTreeMap<u64, (Arc<Vec<u8>>, u64)>,
    tick: u64,
}

/// A mounted ext2/3/4 file system.
pub struct Ext4Fs {
    dev: Arc<dyn BlockDevice>,
    dev_id: u64,
    sb: Superblock,
    group_count: u64,
    free_blocks: u64,
    free_inodes: u64,
    root_raw: RawInode,
    cache: SpinLock<BlockCache>,
    inodes: SpinLock<BTreeMap<u32, Weak<Ext4Inode>>>,
}

impl Ext4Fs {
    /// Reads and checks the superblock; refuses (EINVAL) if not ext2/3/4 or
    /// if it needs an incompat feature we do not support. `dev_id` is the
    /// st_dev to report.
    pub fn mount(dev: Arc<dyn BlockDevice>, dev_id: u64) -> KResult<Arc<Ext4Fs>> {
        if dev.size_bytes() < SUPERBLOCK_OFFSET + SUPERBLOCK_SIZE as u64 {
            return Err(Errno::EINVAL);
        }
        let mut b = vec![0u8; SUPERBLOCK_SIZE];
        read_bytes(dev.as_ref(), SUPERBLOCK_OFFSET, &mut b)?;
        let sb = Superblock::parse(&b)?;
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
            crate::warn!(
                "ext4: {}: unsupported feature {} ({:#x})",
                dev.name(),
                what,
                unsupported
            );
            return Err(Errno::EINVAL);
        }
        if sb.blocks_count.saturating_mul(sb.block_size) > dev.size_bytes() {
            crate::warn!("ext4: {}: file system larger than the device", dev.name());
            return Err(Errno::EINVAL);
        }
        if sb.incompat & INCOMPAT_RECOVER != 0 {
            crate::warn!(
                "ext4: {}: needs journal recovery; mounting read-only without replaying it",
                dev.name()
            );
        }
        let group_count = sb.group_count();
        if (sb.inodes_count as u64) > group_count * sb.inodes_per_group as u64 {
            return Err(Errno::EINVAL);
        }
        let mut fs = Ext4Fs {
            dev,
            dev_id,
            group_count,
            free_blocks: sb.free_blocks,
            free_inodes: sb.free_inodes as u64,
            sb,
            root_raw: RawInode::empty(),
            cache: SpinLock::new(BlockCache {
                blocks: BTreeMap::new(),
                tick: 0,
            }),
            inodes: SpinLock::new(BTreeMap::new()),
        };
        // The superblock's free counts are only updated now and then; the
        // group descriptors are exact.
        if let Ok((fb, fi)) = fs.sum_free_counts() {
            fs.free_blocks = fb;
            fs.free_inodes = fi;
        }
        let root = fs.read_raw_inode(ROOT_INO)?;
        if root.file_type() != Some(crate::fs::FileType::Directory) {
            crate::warn!("ext4: {}: root is not a directory", fs.dev.name());
            return Err(Errno::EINVAL);
        }
        fs.root_raw = root;
        Ok(Arc::new(fs))
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
            self.free_blocks,
            self.sb.inodes_count as u64,
            self.free_inodes,
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

    /// Reads `buf.len()` bytes of the device starting at block `blk`,
    /// bypassing the cache (file data).
    fn read_blocks_direct(&self, blk: u64, off_in_block: u64, buf: &mut [u8]) -> KResult<()> {
        let bs = self.block_size();
        let end_blk = blk
            .checked_mul(bs)
            .and_then(|b| b.checked_add(off_in_block + buf.len() as u64))
            .ok_or(Errno::EIO)?;
        if end_blk > self.sb.blocks_count * bs {
            return Err(Errno::EIO);
        }
        read_bytes(self.dev.as_ref(), blk * bs + off_in_block, buf)
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
        if c.blocks.len() >= BLOCK_CACHE_SIZE && !c.blocks.contains_key(&blk) {
            let oldest = c.blocks.iter().min_by_key(|(_, e)| e.1).map(|(k, _)| *k);
            if let Some(k) = oldest {
                c.blocks.remove(&k);
            }
        }
        c.blocks.insert(blk, (data.clone(), tick));
        Ok(data)
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

    fn sum_free_counts(&self) -> KResult<(u64, u64)> {
        let (mut fb, mut fi) = (0u64, 0u64);
        for g in 0..self.group_count {
            let d = self.group_desc(g)?;
            fb += self.desc_field16(&d, 0xc, 0x2c);
            fi += self.desc_field16(&d, 0xe, 0x2e);
        }
        Ok((fb, fi))
    }

    /// Reads inode `ino` from its group's inode table.
    fn read_raw_inode(&self, ino: u32) -> KResult<RawInode> {
        if ino == 0 || ino > self.sb.inodes_count {
            return Err(Errno::EIO);
        }
        let idx = (ino - 1) as u64;
        let ipg = self.sb.inodes_per_group as u64;
        let d = self.group_desc(idx / ipg)?;
        let table = self.desc_field(&d, 0x8, 0x28);
        let isz = self.sb.inode_size as u64;
        let byte = (idx % ipg) * isz;
        let bs = self.block_size();
        let b = self.block(table + byte / bs)?;
        let off = (byte % bs) as usize;
        RawInode::parse(&b[off..off + isz as usize])
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
}
