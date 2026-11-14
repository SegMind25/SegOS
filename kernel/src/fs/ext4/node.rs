//! The VFS side: an ext4 inode as an [`Inode`].

use super::dir::{self, DirEntry};
use super::inode::{IBLOCK_LEN, RawInode};
use super::{Ext4Fs, INCOMPAT_FILETYPE, INCOMPAT_INLINE_DATA, le32};
use crate::abi::{Errno, KResult, Stat};
use crate::fs::{FileType, Inode};
use crate::sync::SpinLock;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;

/// Longest symbolic link target read (Linux: PATH_MAX).
const SYMLINK_MAX: u64 = 4096;

pub struct Ext4Inode {
    fs: Arc<Ext4Fs>,
    ino: u32,
    ty: FileType,
    raw: RawInode,
    /// A directory's entries, read on first use (the file system never
    /// changes under us).
    entries: SpinLock<Option<Arc<Vec<DirEntry>>>>,
}

impl Ext4Inode {
    pub(super) fn new(fs: Arc<Ext4Fs>, ino: u32, raw: RawInode) -> Self {
        Self {
            fs,
            ino,
            ty: raw.file_type().unwrap_or(FileType::Regular),
            raw,
            entries: SpinLock::new(None),
        }
    }

    fn inline(&self) -> bool {
        self.raw.has_inline_data() && self.fs.has_incompat(INCOMPAT_INLINE_DATA)
    }

    /// The whole content of an inline-data inode: i_block, then the
    /// `system.data` attribute.
    fn inline_content(&self) -> KResult<Vec<u8>> {
        let mut v = self.raw.iblock.to_vec();
        v.extend_from_slice(self.raw.inline_xattr()?);
        Ok(v)
    }

    /// Reads data at `off`, clamped to the file size.
    fn read_data(&self, off: u64, buf: &mut [u8]) -> KResult<usize> {
        let size = self.raw.size;
        if off >= size || buf.is_empty() {
            return Ok(0);
        }
        let n = buf.len().min((size - off).min(usize::MAX as u64) as usize);
        let buf = &mut buf[..n];
        if self.inline() {
            let data = self.inline_content()?;
            for (i, b) in buf.iter_mut().enumerate() {
                *b = data.get(off as usize + i).copied().unwrap_or(0);
            }
        } else {
            self.raw.read_blocks(&self.fs, off, buf)?;
        }
        Ok(n)
    }

    fn dir_entries(&self) -> KResult<Arc<Vec<DirEntry>>> {
        if self.ty != FileType::Directory {
            return Err(Errno::ENOTDIR);
        }
        if let Some(e) = self.entries.lock().as_ref() {
            return Ok(e.clone());
        }
        let filetype = self.fs.has_incompat(INCOMPAT_FILETYPE);
        let bs = self.fs.block_size();
        let big = bs >= 65536;
        let mut out = Vec::new();
        if self.inline() {
            let ib = &self.raw.iblock;
            out.push(DirEntry {
                name: b".".to_vec(),
                ino: self.ino,
            });
            out.push(DirEntry {
                name: b"..".to_vec(),
                ino: le32(ib, 0),
            });
            dir::parse_block(&ib[4..IBLOCK_LEN], filetype, false, &mut out);
            dir::parse_block(self.raw.inline_xattr()?, filetype, false, &mut out);
        } else {
            let mut block = vec![0u8; bs as usize];
            let nblocks = self.raw.size.div_ceil(bs);
            for lblk in 0..nblocks {
                let m = self.raw.map(&self.fs, lblk)?;
                if m.pblk.is_none() {
                    continue;
                }
                let len = (self.raw.size - lblk * bs).min(bs) as usize;
                self.raw.read_blocks(&self.fs, lblk * bs, &mut block[..len])?;
                dir::parse_block(&block[..len], filetype, big, &mut out);
            }
        }
        let out = Arc::new(out);
        *self.entries.lock() = Some(out.clone());
        Ok(out)
    }

    fn find(&self, name: &[u8]) -> KResult<u32> {
        self.dir_entries()?
            .iter()
            .find(|e| e.name == name)
            .map(|e| e.ino)
            .ok_or(Errno::ENOENT)
    }
}

impl Inode for Ext4Inode {
    fn file_type(&self) -> FileType {
        self.ty
    }
    fn ino(&self) -> u64 {
        self.ino as u64
    }
    fn perm(&self) -> u32 {
        (self.raw.mode & 0o7777) as u32
    }
    fn set_perm(&self, _perm: u32) -> KResult<()> {
        Err(Errno::EROFS)
    }
    fn size(&self) -> u64 {
        match self.ty {
            FileType::Regular if self.raw.is_socket() => 0,
            FileType::Regular | FileType::Directory | FileType::Symlink => self.raw.size,
            _ => 0,
        }
    }
    fn rdev(&self) -> u64 {
        match self.ty {
            FileType::CharDevice | FileType::BlockDevice => self.raw.rdev(),
            _ => 0,
        }
    }
    fn dev(&self) -> u64 {
        self.fs.dev_id
    }
    fn mtime(&self) -> u64 {
        self.raw.mtime.max(0) as u64
    }
    fn nlink(&self) -> u64 {
        self.raw.links as u64
    }

    fn read_at(&self, off: u64, buf: &mut [u8]) -> KResult<usize> {
        match self.ty {
            FileType::Regular if self.raw.is_socket() => Ok(0),
            FileType::Regular => self.read_data(off, buf),
            _ => Err(self.not_a_file()),
        }
    }
    fn write_at(&self, _off: u64, _data: &[u8]) -> KResult<usize> {
        Err(Errno::EROFS)
    }
    fn truncate(&self, _len: u64) -> KResult<()> {
        Err(Errno::EROFS)
    }

    fn readlink(&self) -> KResult<String> {
        if self.ty != FileType::Symlink {
            return Err(Errno::EINVAL);
        }
        let size = self.raw.size;
        if size > SYMLINK_MAX {
            return Err(Errno::ENAMETOOLONG);
        }
        let target = if !self.inline() && self.raw.is_fast_symlink(&self.fs) {
            self.raw.iblock[..size as usize].to_vec()
        } else {
            let mut v = vec![0u8; size as usize];
            let n = self.read_data(0, &mut v)?;
            v.truncate(n);
            v
        };
        Ok(String::from_utf8_lossy(&target).into_owned())
    }

    fn lookup(&self, name: &str) -> KResult<Arc<dyn Inode>> {
        let ino = self.find(name.as_bytes())?;
        let inode: Arc<dyn Inode> = self.fs.inode(ino)?;
        Ok(inode)
    }
    fn parent(&self) -> Option<Arc<dyn Inode>> {
        if self.ty != FileType::Directory {
            return None;
        }
        self.lookup("..").ok()
    }
    fn create(&self, _name: &str, _ty: FileType, _perm: u32) -> KResult<Arc<dyn Inode>> {
        Err(Errno::EROFS)
    }
    fn symlink(&self, _name: &str, _target: &str) -> KResult<()> {
        Err(Errno::EROFS)
    }
    fn insert(&self, _name: &str, _inode: Arc<dyn Inode>) -> KResult<()> {
        Err(Errno::EROFS)
    }
    fn remove(&self, _name: &str, _dir: bool) -> KResult<()> {
        Err(Errno::EROFS)
    }
    fn take(&self, _name: &str) -> KResult<Arc<dyn Inode>> {
        Err(Errno::EROFS)
    }
    fn entries(&self) -> KResult<Vec<(String, Arc<dyn Inode>)>> {
        let mut out: Vec<(String, Arc<dyn Inode>)> = Vec::new();
        for e in self.dir_entries()?.iter() {
            if e.name == b"." || e.name == b".." {
                continue;
            }
            let inode: Arc<dyn Inode> = self.fs.inode(e.ino)?;
            out.push((String::from_utf8_lossy(&e.name).into_owned(), inode));
        }
        Ok(out)
    }
    fn is_empty_dir(&self) -> bool {
        self.dir_entries()
            .map(|es| es.iter().all(|e| e.name == b"." || e.name == b".."))
            .unwrap_or(false)
    }
    fn writable_dir(&self) -> bool {
        false
    }

    fn stat(&self) -> Stat {
        let r = &self.raw;
        Stat {
            st_dev: self.dev(),
            st_ino: self.ino(),
            st_nlink: self.nlink(),
            st_mode: self.ty.mode_bits() | self.perm(),
            st_rdev: self.rdev(),
            st_size: self.size() as i64,
            st_blksize: self.fs.block_size() as i64,
            st_blocks: r.sectors(&self.fs) as i64,
            st_atime: r.atime,
            st_atime_nsec: r.atime_nsec as i64,
            st_mtime: r.mtime,
            st_mtime_nsec: r.mtime_nsec as i64,
            st_ctime: r.ctime,
            st_ctime_nsec: r.ctime_nsec as i64,
            ..Stat::default()
        }
    }
}
