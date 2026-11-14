//! On-disk inodes, and classic indirect block maps (ext2/ext3 files).

use super::{Ext4Fs, FsState, crc, le16, le32, put16, put32};
use crate::abi::{Errno, KResult};
use crate::fs::FileType;
use alloc::vec;
use alloc::vec::Vec;

// i_mode file types
pub const S_IFMT: u16 = 0o170000;
pub const S_IFSOCK: u16 = 0o140000;
pub const S_IFLNK: u16 = 0o120000;
pub const S_IFREG: u16 = 0o100000;
pub const S_IFBLK: u16 = 0o060000;
pub const S_IFDIR: u16 = 0o040000;
pub const S_IFCHR: u16 = 0o020000;
pub const S_IFIFO: u16 = 0o010000;

// i_flags
pub const INDEX_FL: u32 = 0x1000;
pub const HUGE_FILE_FL: u32 = 0x40000;
pub const EXTENTS_FL: u32 = 0x80000;
const EA_INODE_FL: u32 = 0x200000;
pub const INLINE_DATA_FL: u32 = 0x10000000;

/// Size of i_block.
pub const IBLOCK_LEN: usize = 60;

/// Extended attribute name index of `system.*` (inline data lives in
/// `system.data`).
const XATTR_INDEX_SYSTEM: u8 = 7;
const XATTR_MAGIC: u32 = 0xea02_0000;

/// An inode as read from the inode table: the fields the file system
/// uses, and every byte (written back as they were, with these fields
/// put in).
#[derive(Clone)]
pub struct RawInode {
    pub mode: u16,
    pub size: u64,
    pub atime: i64,
    pub ctime: i64,
    pub mtime: i64,
    pub atime_nsec: u32,
    pub ctime_nsec: u32,
    pub mtime_nsec: u32,
    pub dtime: u32,
    pub links: u16,
    /// i_blocks as stored (units depend on HUGE_FILE_FL).
    pub blocks: u64,
    pub flags: u32,
    pub file_acl: u64,
    pub generation: u32,
    pub iblock: [u8; IBLOCK_LEN],
    /// i_extra_isize (0 for 128-byte inodes).
    pub extra_isize: usize,
    pub bytes: Vec<u8>,
}

fn time_with_extra(secs: u32, extra: Option<u32>) -> (i64, u32) {
    let mut t = secs as i32 as i64;
    let mut nsec = 0;
    if let Some(x) = extra {
        t += ((x & 3) as i64) << 32;
        nsec = x >> 2;
    }
    (t, nsec)
}

/// (seconds field, extra field) of a time.
fn encode_time(t: i64, nsec: u32) -> (u32, u32) {
    let epoch = ((t - (t as i32 as i64)) >> 32) as u32 & 3;
    (t as u32, epoch | (nsec << 2))
}

impl RawInode {
    pub fn empty() -> Self {
        Self {
            mode: 0,
            size: 0,
            atime: 0,
            ctime: 0,
            mtime: 0,
            atime_nsec: 0,
            ctime_nsec: 0,
            mtime_nsec: 0,
            dtime: 0,
            links: 0,
            blocks: 0,
            flags: 0,
            file_acl: 0,
            generation: 0,
            iblock: [0; IBLOCK_LEN],
            extra_isize: 0,
            bytes: Vec::new(),
        }
    }

    pub fn parse(b: &[u8]) -> KResult<Self> {
        let extra_isize = if b.len() > 128 {
            le16(b, 0x80) as usize
        } else {
            0
        };
        let extra_end = 128 + extra_isize;
        if extra_isize != 0 && (extra_end > b.len() || extra_isize % 4 != 0) {
            return Err(Errno::EIO);
        }
        // An extra field is present when it fits in i_extra_isize.
        let extra = |off: usize| (off + 4 <= extra_end).then(|| le32(b, off));
        let (ctime, ctime_nsec) = time_with_extra(le32(b, 0xc), extra(0x84));
        let (mtime, mtime_nsec) = time_with_extra(le32(b, 0x10), extra(0x88));
        let (atime, atime_nsec) = time_with_extra(le32(b, 0x8), extra(0x8c));
        let mut iblock = [0u8; IBLOCK_LEN];
        iblock.copy_from_slice(&b[0x28..0x28 + IBLOCK_LEN]);
        let size_high = le32(b, 0x6c) as u64;
        Ok(Self {
            mode: le16(b, 0x0),
            size: le32(b, 0x4) as u64 | (size_high << 32),
            atime,
            ctime,
            mtime,
            atime_nsec,
            ctime_nsec,
            mtime_nsec,
            dtime: le32(b, 0x14),
            links: le16(b, 0x1a),
            blocks: le32(b, 0x1c) as u64 | ((le16(b, 0x74) as u64) << 32),
            flags: le32(b, 0x20),
            file_acl: le32(b, 0x68) as u64 | ((le16(b, 0x76) as u64) << 32),
            generation: le32(b, 0x64),
            iblock,
            extra_isize,
            bytes: b.to_vec(),
        })
    }

    /// A fresh inode of `inode_size` bytes.
    pub fn new(fs: &Ext4Fs, mode: u16, generation: u32) -> Self {
        let isz = fs.sb.inode_size as usize;
        let mut r = Self::empty();
        r.bytes = vec![0u8; isz];
        if isz > 128 {
            let want = (fs.sb.want_extra_isize as usize).max(32);
            r.extra_isize = want.min(isz - 128) & !3;
            put16(&mut r.bytes, 0x80, r.extra_isize as u16);
        }
        r.mode = mode;
        r.generation = generation;
        let (t, ns) = super::now();
        (r.atime, r.ctime, r.mtime) = (t, t, t);
        (r.atime_nsec, r.ctime_nsec, r.mtime_nsec) = (ns, ns, ns);
        // i_crtime
        if r.extra_isize >= 24 {
            let (s, x) = encode_time(t, ns);
            put32(&mut r.bytes, 0x90, s);
            put32(&mut r.bytes, 0x94, x);
        }
        r
    }

    /// The bytes to write to the inode table, checksummed.
    pub fn serialize(&self, fs: &Ext4Fs, ino: u32) -> Vec<u8> {
        let mut b = self.bytes.clone();
        put16(&mut b, 0x0, self.mode);
        put32(&mut b, 0x4, self.size as u32);
        put32(&mut b, 0x6c, (self.size >> 32) as u32);
        let extra_end = 128 + self.extra_isize;
        let blen = b.len();
        let fits = |off: usize| off + 4 <= extra_end && extra_end <= blen;
        for (secs_off, extra_off, t, ns) in [
            (0x8, 0x8c, self.atime, self.atime_nsec),
            (0xc, 0x84, self.ctime, self.ctime_nsec),
            (0x10, 0x88, self.mtime, self.mtime_nsec),
        ] {
            let (s, x) = encode_time(t, ns);
            put32(&mut b, secs_off, s);
            if fits(extra_off) {
                put32(&mut b, extra_off, x);
            }
        }
        put32(&mut b, 0x14, self.dtime);
        put16(&mut b, 0x1a, self.links);
        put32(&mut b, 0x1c, self.blocks as u32);
        put16(&mut b, 0x74, (self.blocks >> 32) as u16);
        put32(&mut b, 0x20, self.flags);
        put32(&mut b, 0x64, self.generation);
        b[0x28..0x28 + IBLOCK_LEN].copy_from_slice(&self.iblock);
        if fs.metadata_csum() {
            let hi = b.len() > 128 && self.extra_isize >= 4;
            put16(&mut b, 0x7c, 0);
            if hi {
                put16(&mut b, 0x82, 0);
            }
            let c = crc::crc32c(self.csum_seed(fs, ino), &b);
            put16(&mut b, 0x7c, c as u16);
            if hi {
                put16(&mut b, 0x82, (c >> 16) as u16);
            }
        }
        b
    }

    /// The per-inode checksum seed (extent blocks and directory blocks are
    /// checksummed with it).
    pub fn csum_seed(&self, fs: &Ext4Fs, ino: u32) -> u32 {
        let c = crc::crc32c(fs.seed, &ino.to_le_bytes());
        crc::crc32c(c, &self.generation.to_le_bytes())
    }

    pub fn file_type(&self) -> Option<FileType> {
        Some(match self.mode & S_IFMT {
            S_IFREG | S_IFSOCK => FileType::Regular,
            S_IFDIR => FileType::Directory,
            S_IFLNK => FileType::Symlink,
            S_IFCHR => FileType::CharDevice,
            S_IFBLK => FileType::BlockDevice,
            S_IFIFO => FileType::Fifo,
            _ => return None,
        })
    }

    pub fn is_socket(&self) -> bool {
        self.mode & S_IFMT == S_IFSOCK
    }

    pub fn has_inline_data(&self) -> bool {
        self.flags & INLINE_DATA_FL != 0
    }

    pub fn has_extents(&self) -> bool {
        self.flags & EXTENTS_FL != 0
    }

    pub fn iblock32(&self, i: usize) -> u32 {
        le32(&self.iblock, i * 4)
    }

    fn set_iblock32(&mut self, i: usize, v: u32) {
        put32(&mut self.iblock, i * 4, v);
    }

    /// i_blocks in 512-byte units.
    pub fn sectors(&self, fs: &Ext4Fs) -> u64 {
        if fs.huge_file() {
            if self.flags & HUGE_FILE_FL != 0 {
                return self.blocks * (fs.block_size() / 512);
            }
            self.blocks
        } else {
            self.blocks & 0xffff_ffff
        }
    }

    /// Adds `n` file system blocks (negative: removes) to i_blocks.
    pub fn add_blocks(&mut self, fs: &Ext4Fs, n: i64) {
        let per = if self.flags & HUGE_FILE_FL != 0 {
            1
        } else {
            (fs.block_size() / 512) as i64
        };
        self.blocks = (self.blocks as i64 + n * per).max(0) as u64;
    }

    /// Device number of a device file: the old 16-bit encoding in
    /// i_block[0], or the new 32-bit one in i_block[1].
    pub fn rdev(&self) -> u64 {
        let (major, minor) = match self.iblock32(0) {
            0 => {
                let n = self.iblock32(1);
                ((n & 0xfff00) >> 8, (n & 0xff) | ((n >> 12) & 0xfff00))
            }
            o => ((o >> 8) & 0xff, o & 0xff),
        };
        let (ma, mi) = (major as u64, minor as u64);
        (mi & 0xff) | ((ma & 0xfff) << 8) | ((mi & !0xff) << 12) | ((ma & !0xfff) << 32)
    }

    /// Whether a symbolic link keeps its target in i_block.
    pub fn is_fast_symlink(&self, fs: &Ext4Fs) -> bool {
        if self.has_inline_data() {
            return false;
        }
        if self.flags & EA_INODE_FL != 0 || self.flags & EXTENTS_FL != 0 {
            return self.flags & EXTENTS_FL == 0 && self.size < IBLOCK_LEN as u64;
        }
        let ea = if self.file_acl != 0 {
            fs.block_size() / 512
        } else {
            0
        };
        self.size < IBLOCK_LEN as u64 && self.sectors(fs).saturating_sub(ea) == 0
    }

    /// The value of the in-inode extended attribute `system.data` (the
    /// part of inline data that does not fit in i_block).
    pub fn inline_xattr(&self) -> KResult<&[u8]> {
        let start = 128 + self.extra_isize;
        if start >= self.bytes.len() {
            return Ok(&[]);
        }
        let x = &self.bytes[start..];
        if x.len() < 4 || le32(x, 0) != XATTR_MAGIC {
            return Ok(&[]);
        }
        let base = 4; // value offsets count from the first entry
        let mut off = base;
        while off + 16 <= x.len() {
            if le32(x, off) == 0 {
                break; // end of entries
            }
            let name_len = x[off] as usize;
            let index = x[off + 1];
            let value_off = le16(x, off + 2) as usize;
            let value_inum = le32(x, off + 4);
            let value_size = le32(x, off + 8) as usize;
            let name_end = off + 16 + name_len;
            if name_end > x.len() {
                return Err(Errno::EIO);
            }
            if index == XATTR_INDEX_SYSTEM && &x[off + 16..name_end] == b"data" {
                if value_inum != 0 {
                    return Err(Errno::EIO); // value in an EA inode: not here
                }
                let start = base + value_off;
                return x.get(start..start + value_size).ok_or(Errno::EIO);
            }
            off = (name_end + 3) & !3;
        }
        Ok(&[])
    }

    /// Whether `system.data` is the only extended attribute kept in the
    /// inode (or there are none), so the area can simply be cleared when
    /// the data moves out to blocks.
    pub fn only_data_xattr(&self) -> bool {
        let start = 128 + self.extra_isize;
        if start + 4 > self.bytes.len() || le32(&self.bytes, start) != XATTR_MAGIC {
            return true;
        }
        let x = &self.bytes[start..];
        let mut off = 4;
        while off + 16 <= x.len() && le32(x, off) != 0 {
            let name_len = x[off] as usize;
            let name_end = off + 16 + name_len;
            if name_end > x.len()
                || x[off + 1] != XATTR_INDEX_SYSTEM
                || &x[off + 16..name_end] != b"data"
            {
                return false;
            }
            off = (name_end + 3) & !3;
        }
        true
    }

    /// Clears the in-inode extended attribute area.
    pub fn clear_xattrs(&mut self) {
        let start = 128 + self.extra_isize;
        if start < self.bytes.len() {
            self.bytes[start..].fill(0);
        }
    }

    /// Which indirect tree holds file block `lblk`, and the index of each
    /// level on the way: (tree level 0 = direct, path).
    fn indirect_path(fs: &Ext4Fs, lblk: u64) -> KResult<(usize, [usize; 3])> {
        let per = fs.block_size() / 4;
        if lblk < 12 {
            return Ok((0, [lblk as usize, 0, 0]));
        }
        let mut rel = lblk - 12;
        let mut span = per;
        let mut level = 1usize;
        while rel >= span {
            rel -= span;
            level += 1;
            if level > 3 {
                return Err(Errno::EFBIG);
            }
            span *= per;
        }
        let mut path = [0usize; 3];
        let mut covered = span;
        for p in path.iter_mut().take(level) {
            covered /= per;
            *p = (rel / covered) as usize;
            rel %= covered;
        }
        Ok((level, path))
    }

    /// Maps file block `lblk` through the indirect blocks: (device block or
    /// 0 for a hole, run of following blocks with the same state).
    pub fn map_indirect(&self, fs: &Ext4Fs, lblk: u64) -> KResult<(u64, u64)> {
        let per = fs.block_size() / 4;
        if lblk < 12 {
            return Ok((self.iblock32(lblk as usize) as u64, 1));
        }
        let mut rel = lblk - 12;
        let mut span = per;
        let mut level = 1usize;
        while rel >= span {
            rel -= span;
            level += 1;
            if level > 3 {
                return Ok((0, u64::MAX - lblk));
            }
            span *= per;
        }
        let mut ptr = self.iblock32(11 + level) as u64;
        // covered: file blocks mapped by `ptr`; rel: position in them.
        let mut covered = span;
        for _ in 0..level {
            if ptr == 0 {
                return Ok((0, covered - rel));
            }
            covered /= per;
            let idx = (rel / covered) as usize;
            rel %= covered;
            let b = fs.block(ptr)?;
            ptr = le32(&b, idx * 4) as u64;
            if covered == 1 {
                // Leaf level: extend over consecutive pointers.
                let per = per as usize;
                let mut n = 1;
                if ptr == 0 {
                    while idx + n < per && le32(&b, (idx + n) * 4) == 0 {
                        n += 1;
                    }
                } else {
                    while idx + n < per && le32(&b, (idx + n) * 4) as u64 == ptr + n as u64 {
                        n += 1;
                    }
                }
                return Ok((ptr, n as u64));
            }
        }
        Err(Errno::EIO)
    }

    /// Sets the device block of file block `lblk` in the indirect map,
    /// allocating indirect blocks on the way (counted in `allocated`, also
    /// when a later step fails).
    pub fn set_indirect(
        &mut self,
        fs: &Ext4Fs,
        st: &mut FsState,
        lblk: u64,
        pblk: u64,
        allocated: &mut i64,
    ) -> KResult<()> {
        if pblk > u32::MAX as u64 {
            return Err(Errno::EFBIG);
        }
        let (level, path) = Self::indirect_path(fs, lblk)?;
        if level == 0 {
            self.set_iblock32(lblk as usize, pblk as u32);
            return Ok(());
        }
        let mut ptr = self.iblock32(11 + level) as u64;
        if ptr == 0 {
            ptr = Self::new_indirect(fs, st, pblk)?;
            *allocated += 1;
            self.set_iblock32(11 + level, ptr as u32);
        }
        for (depth, &idx) in path.iter().take(level).enumerate() {
            let b = fs.block(ptr)?;
            if depth + 1 == level {
                fs.write_at(ptr, (idx * 4) as u64, &(pblk as u32).to_le_bytes())?;
                return Ok(());
            }
            let mut next = le32(&b, idx * 4) as u64;
            if next == 0 {
                next = Self::new_indirect(fs, st, ptr + 1)?;
                *allocated += 1;
                fs.write_at(ptr, (idx * 4) as u64, &(next as u32).to_le_bytes())?;
            }
            ptr = next;
        }
        Err(Errno::EIO)
    }

    fn new_indirect(fs: &Ext4Fs, st: &mut FsState, goal: u64) -> KResult<u64> {
        let (b, _) = fs.alloc_blocks(st, goal, 1)?;
        if b > u32::MAX as u64 {
            fs.free_blocks(st, b, 1)?;
            return Err(Errno::ENOSPC);
        }
        fs.write_at(b, 0, &vec![0u8; fs.block_size() as usize])?;
        Ok(b)
    }

    /// Removes every block at or after file block `from` from the
    /// indirect map; the freed blocks (data and indirect) are appended to
    /// `freed`.
    pub fn truncate_indirect(
        &mut self,
        fs: &Ext4Fs,
        from: u64,
        freed: &mut Vec<u64>,
    ) -> KResult<()> {
        for i in (from.min(12) as usize)..12 {
            let p = self.iblock32(i);
            if p != 0 {
                freed.push(p as u64);
                self.set_iblock32(i, 0);
            }
        }
        let per = fs.block_size() / 4;
        let mut base = 12u64;
        let mut span = per;
        for level in 1..=3usize {
            let root = self.iblock32(11 + level) as u64;
            if root != 0 && from < base + span {
                let start = from.saturating_sub(base);
                if Self::free_subtree(fs, root, level, start, freed)? {
                    freed.push(root);
                    self.set_iblock32(11 + level, 0);
                }
            }
            base += span;
            span = span.saturating_mul(per);
        }
        Ok(())
    }

    /// Frees blocks at or after `start` in the subtree of `blk` (which maps
    /// per^level blocks). Returns whether the subtree is now empty.
    fn free_subtree(
        fs: &Ext4Fs,
        blk: u64,
        level: usize,
        start: u64,
        freed: &mut Vec<u64>,
    ) -> KResult<bool> {
        let per = (fs.block_size() / 4) as usize;
        let child_span = (per as u64).pow(level as u32 - 1);
        let mut b = fs.block(blk)?.to_vec();
        let mut changed = false;
        for idx in 0..per {
            let p = le32(&b, idx * 4) as u64;
            if p == 0 {
                continue;
            }
            let lo = idx as u64 * child_span;
            let hi = lo + child_span;
            if start <= lo {
                if level > 1 {
                    Self::free_subtree(fs, p, level - 1, 0, freed)?;
                }
                freed.push(p);
                put32(&mut b, idx * 4, 0);
                changed = true;
            } else if start < hi
                && level > 1
                && Self::free_subtree(fs, p, level - 1, start - lo, freed)?
            {
                freed.push(p);
                put32(&mut b, idx * 4, 0);
                changed = true;
            }
        }
        let empty = b.iter().all(|&x| x == 0);
        if changed && !empty {
            fs.write_at(blk, 0, &b)?;
        }
        Ok(empty)
    }
}
