//! Files: a small virtual file system.
//!
//! Everything is an [`Inode`]: tmpfs files and directories (the root file
//! system, filled from the initramfs at boot), and device files in `/dev`.
//! A [`File`] is an open file (Linux's "open file description": the inode,
//! the offset, the status flags), shared by every descriptor `dup` makes;
//! an [`FdTable`] maps a process's descriptors to them.
//!
//! Phase 2 needs no mount table: `/dev` is a tmpfs directory holding the
//! device inodes. Real file systems (ext4, FAT32) and mounts come in
//! Phase 4.

pub mod cpio;
pub mod dev;
pub mod tmpfs;

use crate::abi::{Errno, KResult, Stat, mode};
use crate::mm::vm::AddressSpace;
use crate::sync::{Mutex, Once, SpinLock};
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FileType {
    Regular,
    Directory,
    CharDevice,
}

impl FileType {
    pub fn mode_bits(self) -> u32 {
        match self {
            Self::Regular => mode::S_IFREG,
            Self::Directory => mode::S_IFDIR,
            Self::CharDevice => mode::S_IFCHR,
        }
    }
}

static NEXT_INO: AtomicU64 = AtomicU64::new(1);

pub fn new_ino() -> u64 {
    NEXT_INO.fetch_add(1, Ordering::Relaxed)
}

/// What every file system object can do. Defaults answer as Linux does for
/// an object that does not support the operation.
pub trait Inode: Send + Sync {
    fn file_type(&self) -> FileType;
    fn ino(&self) -> u64;
    /// Permission bits (the low 12 bits of `st_mode`).
    fn perm(&self) -> u32;
    fn size(&self) -> u64 {
        0
    }
    /// Device number for device files (`st_rdev`).
    fn rdev(&self) -> u64 {
        0
    }
    /// Seconds since 1970 of the last change.
    fn mtime(&self) -> u64 {
        0
    }

    fn read_at(&self, _off: u64, _buf: &mut [u8]) -> KResult<usize> {
        Err(self.not_a_file())
    }
    fn write_at(&self, _off: u64, _data: &[u8]) -> KResult<usize> {
        Err(self.not_a_file())
    }
    fn truncate(&self, _len: u64) -> KResult<()> {
        Err(self.not_a_file())
    }
    /// Whether reads and writes use the file offset (false for devices:
    /// `lseek` on them is allowed but meaningless, as on Linux).
    fn seekable(&self) -> bool {
        self.file_type() == FileType::Regular
    }
    fn ioctl(&self, _req: u32, _arg: u64, _mm: &AddressSpace) -> KResult<u64> {
        Err(Errno::ENOTTY)
    }

    // Directories.
    fn lookup(&self, _name: &str) -> KResult<Arc<dyn Inode>> {
        Err(Errno::ENOTDIR)
    }
    fn parent(&self) -> Option<Arc<dyn Inode>> {
        None
    }
    fn create(&self, _name: &str, _ty: FileType, _perm: u32) -> KResult<Arc<dyn Inode>> {
        Err(Errno::ENOTDIR)
    }
    /// Adds an existing inode (a device) under `name`.
    fn insert(&self, _name: &str, _inode: Arc<dyn Inode>) -> KResult<()> {
        Err(Errno::ENOTDIR)
    }
    /// Removes `name`; `dir` selects rmdir (only empty directories) or
    /// unlink (only non-directories).
    fn remove(&self, _name: &str, _dir: bool) -> KResult<()> {
        Err(Errno::ENOTDIR)
    }
    fn entries(&self) -> KResult<Vec<(String, Arc<dyn Inode>)>> {
        Err(Errno::ENOTDIR)
    }
    fn is_empty_dir(&self) -> bool {
        false
    }

    fn not_a_file(&self) -> Errno {
        if self.file_type() == FileType::Directory {
            Errno::EISDIR
        } else {
            Errno::EINVAL
        }
    }

    fn stat(&self) -> Stat {
        let size = self.size();
        let t = self.mtime() as i64;
        Stat {
            st_dev: 1,
            st_ino: self.ino(),
            st_nlink: if self.file_type() == FileType::Directory {
                2
            } else {
                1
            },
            st_mode: self.file_type().mode_bits() | self.perm(),
            st_rdev: self.rdev(),
            st_size: size as i64,
            st_blksize: 4096,
            st_blocks: size.div_ceil(512) as i64,
            st_atime: t,
            st_mtime: t,
            st_ctime: t,
            ..Stat::default()
        }
    }
}

static ROOT: Once<Arc<dyn Inode>> = Once::new();

/// The root directory. Created (empty, with `/dev`) on first use.
pub fn root() -> Arc<dyn Inode> {
    ROOT.call_once(|| {
        let root = tmpfs::Dir::new_root(0o755);
        let devdir = root.create("dev", FileType::Directory, 0o755).unwrap();
        dev::populate(&devdir);
        root
    })
    .clone()
}

/// Longest path accepted, as Linux's PATH_MAX.
pub const PATH_MAX: usize = 4096;
const NAME_MAX: usize = 255;

/// Resolves `path` from `cwd` (absolute paths from the root).
pub fn lookup(cwd: &Arc<dyn Inode>, path: &str) -> KResult<Arc<dyn Inode>> {
    if path.is_empty() {
        return Err(Errno::ENOENT);
    }
    let mut cur = if path.starts_with('/') {
        root()
    } else {
        cwd.clone()
    };
    for part in path.split('/').filter(|p| !p.is_empty()) {
        cur = step(&cur, part)?;
    }
    // "file/" names a directory.
    if path.ends_with('/') && cur.file_type() != FileType::Directory {
        return Err(Errno::ENOTDIR);
    }
    Ok(cur)
}

fn step(dir: &Arc<dyn Inode>, part: &str) -> KResult<Arc<dyn Inode>> {
    if dir.file_type() != FileType::Directory {
        return Err(Errno::ENOTDIR);
    }
    match part {
        "." => Ok(dir.clone()),
        ".." => Ok(dir.parent().unwrap_or_else(|| dir.clone())),
        name if name.len() > NAME_MAX => Err(Errno::ENAMETOOLONG),
        name => dir.lookup(name),
    }
}

/// Resolves everything but the last component: (directory, last name).
/// The last name is never "." or ".." (callers creating or removing
/// entries get EEXIST/EINVAL/ENOTEMPTY-like errors from those).
pub fn lookup_parent(cwd: &Arc<dyn Inode>, path: &str) -> KResult<(Arc<dyn Inode>, String)> {
    let trimmed = path.trim_end_matches('/');
    if path.is_empty() {
        return Err(Errno::ENOENT);
    }
    if trimmed.is_empty() {
        // "/" itself.
        return Err(Errno::EEXIST);
    }
    let (dir_path, name) = match trimmed.rfind('/') {
        Some(0) => ("/", &trimmed[1..]),
        Some(i) => (&trimmed[..i], &trimmed[i + 1..]),
        None => (".", trimmed),
    };
    if name.len() > NAME_MAX {
        return Err(Errno::ENAMETOOLONG);
    }
    let dir = lookup(cwd, dir_path)?;
    if dir.file_type() != FileType::Directory {
        return Err(Errno::ENOTDIR);
    }
    Ok((dir, name.to_string()))
}

/// Joins `path` onto the absolute directory `base` and removes ".", ".."
/// and repeated slashes (for the working directory's name).
pub fn normalize(base: &str, path: &str) -> String {
    let mut parts: Vec<&str> = Vec::new();
    let full = if path.starts_with('/') {
        [path, ""]
    } else {
        [base, path]
    };
    for piece in full {
        for p in piece.split('/') {
            match p {
                "" | "." => {}
                ".." => {
                    parts.pop();
                }
                p => parts.push(p),
            }
        }
    }
    let mut out = String::from("/");
    out.push_str(&parts.join("/"));
    out
}

/// An open file: shared by descriptors `dup` makes, and (from Phase 3) by
/// parent and child after `fork`.
pub struct File {
    pub inode: Arc<dyn Inode>,
    pub offset: Mutex<u64>,
    /// Access mode and status flags (O_APPEND, O_NONBLOCK, ...).
    pub flags: SpinLock<u32>,
}

impl File {
    pub fn new(inode: Arc<dyn Inode>, flags: u32) -> Arc<Self> {
        Arc::new(Self {
            inode,
            offset: Mutex::new(0),
            flags: SpinLock::new(flags),
        })
    }

    pub fn readable(&self) -> bool {
        use crate::abi::open::*;
        matches!(*self.flags.lock() & O_ACCMODE, O_RDONLY | O_RDWR)
    }

    pub fn writable(&self) -> bool {
        use crate::abi::open::*;
        matches!(*self.flags.lock() & O_ACCMODE, O_WRONLY | O_RDWR)
    }

    /// Reads at the file offset and advances it.
    pub fn read(&self, buf: &mut [u8]) -> KResult<usize> {
        if !self.readable() {
            return Err(Errno::EBADF);
        }
        if !self.inode.seekable() {
            return self.inode.read_at(0, buf);
        }
        let mut off = self.offset.lock();
        let n = self.inode.read_at(*off, buf)?;
        *off += n as u64;
        Ok(n)
    }

    /// Writes at the file offset (or the end, with O_APPEND) and advances it.
    pub fn write(&self, data: &[u8]) -> KResult<usize> {
        if !self.writable() {
            return Err(Errno::EBADF);
        }
        if !self.inode.seekable() {
            return self.inode.write_at(0, data);
        }
        let mut off = self.offset.lock();
        if *self.flags.lock() & crate::abi::open::O_APPEND != 0 {
            *off = self.inode.size();
        }
        let n = self.inode.write_at(*off, data)?;
        *off += n as u64;
        Ok(n)
    }
}

#[derive(Clone)]
pub struct FdEntry {
    pub file: Arc<File>,
    pub cloexec: bool,
}

/// A process's file descriptors.
#[derive(Clone, Default)]
pub struct FdTable {
    fds: Vec<Option<FdEntry>>,
}

/// Highest descriptor count (RLIMIT_NOFILE's usual soft limit).
pub const MAX_FDS: usize = 1024;

impl FdTable {
    pub fn get(&self, fd: i32) -> KResult<Arc<File>> {
        usize::try_from(fd)
            .ok()
            .and_then(|i| self.fds.get(i))
            .and_then(|e| e.as_ref())
            .map(|e| e.file.clone())
            .ok_or(Errno::EBADF)
    }

    /// The lowest free descriptor at or above `min`.
    pub fn alloc(&mut self, min: usize, file: Arc<File>, cloexec: bool) -> KResult<i32> {
        let i = (min..MAX_FDS)
            .find(|&i| self.fds.get(i).is_none_or(|e| e.is_none()))
            .ok_or(Errno::EMFILE)?;
        self.set(i, file, cloexec);
        Ok(i as i32)
    }

    /// Puts `file` at descriptor `i`, closing what was there.
    pub fn set(&mut self, i: usize, file: Arc<File>, cloexec: bool) {
        if self.fds.len() <= i {
            self.fds.resize(i + 1, None);
        }
        self.fds[i] = Some(FdEntry { file, cloexec });
    }

    pub fn close(&mut self, fd: i32) -> KResult<()> {
        let i = usize::try_from(fd).map_err(|_| Errno::EBADF)?;
        match self.fds.get_mut(i) {
            Some(e @ Some(_)) => {
                *e = None;
                Ok(())
            }
            _ => Err(Errno::EBADF),
        }
    }

    pub fn set_cloexec(&mut self, fd: i32, on: bool) -> KResult<()> {
        let i = usize::try_from(fd).map_err(|_| Errno::EBADF)?;
        match self.fds.get_mut(i) {
            Some(Some(e)) => {
                e.cloexec = on;
                Ok(())
            }
            _ => Err(Errno::EBADF),
        }
    }

    pub fn cloexec(&self, fd: i32) -> KResult<bool> {
        usize::try_from(fd)
            .ok()
            .and_then(|i| self.fds.get(i))
            .and_then(|e| e.as_ref())
            .map(|e| e.cloexec)
            .ok_or(Errno::EBADF)
    }

    pub fn clear(&mut self) {
        self.fds.clear();
    }
}
