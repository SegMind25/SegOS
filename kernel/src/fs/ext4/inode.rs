//! On-disk inodes and the mapping of file blocks to device blocks
//! (extent trees, indirect block maps, inline data).

use super::{Ext4Fs, le16, le32};
use crate::abi::{Errno, KResult};
use crate::fs::FileType;
use alloc::vec::Vec;

// i_mode file types
const S_IFMT: u16 = 0o170000;
const S_IFSOCK: u16 = 0o140000;
const S_IFLNK: u16 = 0o120000;
const S_IFREG: u16 = 0o100000;
const S_IFBLK: u16 = 0o060000;
const S_IFDIR: u16 = 0o040000;
const S_IFCHR: u16 = 0o020000;
const S_IFIFO: u16 = 0o010000;

// i_flags
const HUGE_FILE_FL: u32 = 0x40000;
const EXTENTS_FL: u32 = 0x80000;
const EA_INODE_FL: u32 = 0x200000;
const INLINE_DATA_FL: u32 = 0x10000000;

const EXTENT_MAGIC: u16 = 0xf30a;
/// Extent tree depth limit (Linux: 5).
const MAX_EXTENT_DEPTH: u16 = 5;
/// Size of i_block.
pub const IBLOCK_LEN: usize = 60;

/// Extended attribute name index of `system.*` (inline data lives in
/// `system.data`).
const XATTR_INDEX_SYSTEM: u8 = 7;
const XATTR_MAGIC: u32 = 0xea02_0000;

/// An inode as read from the inode table.
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
    pub links: u16,
    /// i_blocks as stored (units depend on HUGE_FILE_FL).
    pub blocks: u64,
    pub flags: u32,
    pub file_acl: u64,
    pub iblock: [u8; IBLOCK_LEN],
    /// The in-inode extended attribute area (after i_extra_isize).
    pub xattrs: Vec<u8>,
}

/// A run of file blocks: mapped to consecutive device blocks starting at
/// `pblk`, or a hole (`None`, reads as zeros).
pub struct Mapping {
    pub pblk: Option<u64>,
    pub len: u64,
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
            links: 0,
            blocks: 0,
            flags: 0,
            file_acl: 0,
            iblock: [0; IBLOCK_LEN],
            xattrs: Vec::new(),
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
        let mode = le16(b, 0x0);
        let size_high = le32(b, 0x6c) as u64;
        Ok(Self {
            mode,
            size: le32(b, 0x4) as u64 | (size_high << 32),
            atime,
            ctime,
            mtime,
            atime_nsec,
            ctime_nsec,
            mtime_nsec,
            links: le16(b, 0x1a),
            blocks: le32(b, 0x1c) as u64 | ((le16(b, 0x74) as u64) << 32),
            flags: le32(b, 0x20),
            file_acl: le32(b, 0x68) as u64 | ((le16(b, 0x76) as u64) << 32),
            iblock,
            xattrs: if extra_end < b.len() {
                b[extra_end..].to_vec()
            } else {
                Vec::new()
            },
        })
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

    fn iblock32(&self, i: usize) -> u32 {
        le32(&self.iblock, i * 4)
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
        let x = &self.xattrs;
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

    /// Maps file block `lblk`.
    pub fn map(&self, fs: &Ext4Fs, lblk: u64) -> KResult<Mapping> {
        if self.flags & EXTENTS_FL != 0 {
            self.map_extent(fs, lblk)
        } else {
            self.map_indirect(fs, lblk)
        }
    }

    fn map_extent(&self, fs: &Ext4Fs, lblk: u64) -> KResult<Mapping> {
        if lblk > u32::MAX as u64 {
            return Ok(Mapping {
                pblk: None,
                len: u64::MAX - lblk,
            });
        }
        let lblk32 = lblk as u32;
        // The node being searched; `end` is the first file block past what
        // this subtree can map (the start of the next sibling).
        let mut node: Vec<u8> = self.iblock.to_vec();
        let mut end: u64 = 1 << 32;
        let mut depth_seen: Option<u16> = None;
        loop {
            if node.len() < 12 || le16(&node, 0) != EXTENT_MAGIC {
                return Err(Errno::EIO);
            }
            let entries = le16(&node, 2) as usize;
            let depth = le16(&node, 6);
            if depth > MAX_EXTENT_DEPTH
                || 12 + entries * 12 > node.len()
                || depth_seen.is_some_and(|d| depth + 1 != d)
            {
                return Err(Errno::EIO);
            }
            depth_seen = Some(depth);
            // Last entry starting at or before lblk.
            let first_of = |i: usize| le32(&node, 12 + i * 12);
            let mut lo = 0usize;
            let mut hi = entries; // entries[..lo] start <= lblk
            while lo < hi {
                let mid = (lo + hi) / 2;
                if first_of(mid) <= lblk32 {
                    lo = mid + 1;
                } else {
                    hi = mid;
                }
            }
            let next_start = if lo < entries {
                first_of(lo) as u64
            } else {
                end
            };
            if lo == 0 {
                // Before the first entry: a hole up to it.
                return Ok(Mapping {
                    pblk: None,
                    len: next_start.max(lblk + 1) - lblk,
                });
            }
            let e = 12 + (lo - 1) * 12;
            if depth == 0 {
                let start = le32(&node, e) as u64;
                let raw_len = le16(&node, e + 4) as u64;
                let (len, uninit) = if raw_len > 32768 {
                    (raw_len - 32768, true)
                } else {
                    (raw_len, false)
                };
                let pstart = ((le16(&node, e + 6) as u64) << 32) | le32(&node, e + 8) as u64;
                if lblk < start + len {
                    let off = lblk - start;
                    return Ok(Mapping {
                        pblk: (!uninit).then_some(pstart + off),
                        len: len - off,
                    });
                }
                return Ok(Mapping {
                    pblk: None,
                    len: next_start.max(lblk + 1) - lblk,
                });
            }
            let child = ((le16(&node, e + 8) as u64) << 32) | le32(&node, e + 4) as u64;
            end = next_start;
            node = fs.block(child)?.to_vec();
        }
    }

    fn map_indirect(&self, fs: &Ext4Fs, lblk: u64) -> KResult<Mapping> {
        let per = fs.block_size() / 4; // pointers per block
        if lblk < 12 {
            return Ok(match self.iblock32(lblk as usize) {
                0 => Mapping { pblk: None, len: 1 },
                p => Mapping {
                    pblk: Some(p as u64),
                    len: 1,
                },
            });
        }
        // Which tree, and the index path within it.
        let mut rel = lblk - 12;
        let mut span = per; // blocks one tree of this level maps
        let mut level = 1usize;
        while rel >= span {
            rel -= span;
            level += 1;
            if level > 3 {
                return Ok(Mapping {
                    pblk: None,
                    len: u64::MAX - lblk,
                });
            }
            span = span.saturating_mul(per);
        }
        let mut ptr = self.iblock32(11 + level) as u64;
        // span: file blocks covered by the current pointer.
        let mut covered = span;
        for _ in 0..level {
            if ptr == 0 {
                return Ok(Mapping {
                    pblk: None,
                    len: covered - rel,
                });
            }
            covered /= per;
            let idx = (rel / covered) as usize;
            rel %= covered;
            let b = fs.block(ptr)?;
            ptr = le32(&b, idx * 4) as u64;
            if covered == 1 {
                // Leaf level: extend over consecutive pointers.
                if ptr == 0 {
                    let mut n = 1;
                    while idx + n < per as usize && le32(&b, (idx + n) * 4) == 0 {
                        n += 1;
                    }
                    return Ok(Mapping {
                        pblk: None,
                        len: n as u64,
                    });
                }
                let mut n = 1;
                while idx + n < per as usize && le32(&b, (idx + n) * 4) as u64 == ptr + n as u64 {
                    n += 1;
                }
                return Ok(Mapping {
                    pblk: Some(ptr),
                    len: n as u64,
                });
            }
        }
        Err(Errno::EIO)
    }

    /// Reads file data at `off` (already clamped by the caller to the file
    /// size), into `buf`. Inline data is handled by the caller.
    pub fn read_blocks(&self, fs: &Ext4Fs, off: u64, buf: &mut [u8]) -> KResult<()> {
        let bs = fs.block_size();
        let mut done = 0usize;
        while done < buf.len() {
            let pos = off + done as u64;
            let lblk = pos / bs;
            let in_blk = pos % bs;
            let m = self.map(fs, lblk)?;
            let avail = m.len.max(1).saturating_mul(bs) - in_blk;
            // Bounded chunks: read_bytes may bounce through a buffer.
            let n = (buf.len() - done).min(avail.min(1 << 20) as usize);
            let dst = &mut buf[done..done + n];
            match m.pblk {
                None => dst.fill(0),
                Some(p) => fs.read_blocks_direct(p, in_blk, dst)?,
            }
            done += n;
        }
        Ok(())
    }
}
