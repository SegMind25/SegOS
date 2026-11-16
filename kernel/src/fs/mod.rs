//! Files: a small virtual file system.
//!
//! Everything is an [`Inode`]: tmpfs files, directories and symbolic links
//! (the root file system, filled from the initramfs at boot), device files
//! in `/dev`, pipes, and the generated files of `/proc`. A [`File`] is an
//! open file (Linux's "open file description": the inode, the offset, the
//! status flags), shared by every descriptor `dup` and `fork` make; an
//! [`FdTable`] maps a process's descriptors to them.
//!
//! There is no mount table yet: `/dev` and `/proc` are directories of the
//! root holding their own inodes. Real file systems and mounts come in
//! Phase 4.

pub mod cpio;
pub mod dev;
pub mod disk;
pub mod event;
pub mod ext4;
pub mod fat;
pub mod flock;
pub mod mount;
pub mod pagecache;
pub mod pipe;
pub mod procfs;
pub mod sysfs;
pub mod tmpfs;

use crate::abi::{Errno, KResult, Stat, mode};
use crate::mm::vm::AddressSpace;
use crate::sync::{Mutex, Once, SpinLock};
use crate::task::wait::WaitQueue;
use alloc::collections::VecDeque;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FileType {
    Regular,
    Directory,
    CharDevice,
    BlockDevice,
    Symlink,
    Socket,
    Fifo,
}

impl FileType {
    pub fn mode_bits(self) -> u32 {
        match self {
            Self::Regular => mode::S_IFREG,
            Self::Directory => mode::S_IFDIR,
            Self::CharDevice => mode::S_IFCHR,
            Self::BlockDevice => mode::S_IFBLK,
            Self::Socket => mode::S_IFSOCK,
            Self::Symlink => mode::S_IFLNK,
            Self::Fifo => mode::S_IFIFO,
        }
    }

    /// The `d_type` of a directory entry.
    pub fn dirent_type(self) -> u8 {
        match self {
            Self::Fifo => 1,
            Self::CharDevice => 2,
            Self::BlockDevice => 6,
            Self::Socket => 12,
            Self::Directory => 4,
            Self::Regular => 8,
            Self::Symlink => 10,
        }
    }
}

static NEXT_INO: AtomicU64 = AtomicU64::new(1);

/// `st_dev` of each file system (anonymous device numbers, as Linux gives
/// in-memory file systems).
pub const DEV_TMPFS: u64 = 0x1;
pub const DEV_PIPEFS: u64 = 0xc;
pub const DEV_PROC: u64 = 0x16;
pub const DEV_SOCKFS: u64 = 0x8;

pub fn new_ino() -> u64 {
    NEXT_INO.fetch_add(1, Ordering::Relaxed)
}

/// What `poll` reports.
pub mod poll {
    pub const POLLIN: u16 = 0x001;
    pub const POLLPRI: u16 = 0x002;
    pub const POLLOUT: u16 = 0x004;
    pub const POLLERR: u16 = 0x008;
    pub const POLLHUP: u16 = 0x010;
    pub const POLLNVAL: u16 = 0x020;
}

/// Woken whenever something a `poll` could be waiting for changes (pipe or
/// terminal data, a closed end). Pollers re-check their descriptors.
pub static POLL_WAIT: WaitQueue = WaitQueue::new();
pub static POLL_EVENTS: AtomicU64 = AtomicU64::new(0);

pub fn poll_notify() {
    POLL_EVENTS.fetch_add(1, Ordering::Release);
    POLL_WAIT.wake_all();
}

/// What every file system object can do. Defaults answer as Linux does for
/// an object that does not support the operation.
pub trait Inode: Send + Sync {
    fn file_type(&self) -> FileType;
    fn ino(&self) -> u64;
    /// Permission bits (the low 12 bits of `st_mode`).
    fn perm(&self) -> u32;
    fn set_perm(&self, _perm: u32) -> KResult<()> {
        Err(Errno::EPERM)
    }
    fn size(&self) -> u64 {
        0
    }
    /// Device number for device files (`st_rdev`).
    fn rdev(&self) -> u64 {
        0
    }
    /// The file system it is on (`st_dev`; one number per file system, so
    /// `df` and `find -xdev` can tell them apart).
    fn dev(&self) -> u64 {
        DEV_TMPFS
    }
    /// Seconds since 1970 of the last change.
    fn mtime(&self) -> u64 {
        0
    }
    fn set_mtime(&self, _secs: u64) {}
    /// Number of names (hard links) the inode has.
    fn nlink(&self) -> u64 {
        if self.file_type() == FileType::Directory {
            2
        } else {
            1
        }
    }
    fn link_added(&self) {}
    fn link_removed(&self) {}

    /// Data at an offset (regular files).
    fn read_at(&self, _off: u64, _buf: &mut [u8]) -> KResult<usize> {
        Err(self.not_a_file())
    }
    fn write_at(&self, _off: u64, _data: &[u8]) -> KResult<usize> {
        Err(self.not_a_file())
    }
    /// Data from a stream (devices, pipes, terminals): no offset, may
    /// block unless `nonblock`.
    fn read_stream(&self, buf: &mut [u8], _nonblock: bool) -> KResult<usize> {
        self.read_at(0, buf)
    }
    fn write_stream(&self, data: &[u8], _nonblock: bool) -> KResult<usize> {
        self.write_at(0, data)
    }
    fn truncate(&self, _len: u64) -> KResult<()> {
        Err(self.not_a_file())
    }
    /// Whether reads and writes use the file offset (false for devices,
    /// pipes and terminals).
    fn seekable(&self) -> bool {
        matches!(self.file_type(), FileType::Regular | FileType::BlockDevice)
    }
    fn ioctl(&self, _req: u32, _arg: u64, _mm: &AddressSpace) -> KResult<u64> {
        Err(Errno::ENOTTY)
    }
    /// Which of POLLIN/POLLOUT/POLLHUP/POLLERR hold now.
    fn poll(&self) -> u16 {
        poll::POLLIN | poll::POLLOUT
    }
    /// A counter bumped whenever the object's readiness may have changed
    /// (new data, a closed end), for edge-triggered epoll; 0 for objects
    /// that do not keep one.
    fn poll_generation(&self) -> u64 {
        0
    }
    /// For anonymous inodes: the name `/proc/<pid>/fd` shows
    /// ("anon_inode:[eventfd]").
    fn anon_name(&self) -> Option<&'static str> {
        None
    }
    /// The object itself, for system calls that work on one kind of file
    /// (epoll_ctl, signalfd4, timerfd_settime).
    fn as_any(&self) -> Option<&dyn core::any::Any> {
        None
    }
    /// Called when the inode is opened (terminals take a controlling
    /// terminal here).
    fn opened(&self, _flags: u32) -> KResult<()> {
        Ok(())
    }
    /// A named pipe: the pipe end an open with `flags` gets.
    fn open_fifo(&self, _flags: u32) -> Option<Arc<dyn Inode>> {
        None
    }
    /// Device memory for `mmap(MAP_SHARED)` at offset `off`: the frames
    /// of `pages` pages (the device keeps its own references). None: not
    /// a device with memory of its own.
    fn mmap_frames(&self, _off: u64, _pages: u64) -> Option<KResult<Vec<u64>>> {
        None
    }

    // Symbolic links.
    fn readlink(&self) -> KResult<String> {
        Err(Errno::EINVAL)
    }
    /// A "magic" link (`/proc/<pid>/fd/<n>`): following it reaches this
    /// inode directly instead of looking its target's name up.
    fn magic_target(&self) -> Option<Arc<dyn Inode>> {
        None
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
    fn symlink(&self, _name: &str, _target: &str) -> KResult<()> {
        Err(Errno::ENOTDIR)
    }
    /// Adds an existing inode under `name` (devices, hard links).
    fn insert(&self, _name: &str, _inode: Arc<dyn Inode>) -> KResult<()> {
        Err(Errno::ENOTDIR)
    }
    /// Removes `name`; `dir` selects rmdir (only empty directories) or
    /// unlink (only non-directories).
    fn remove(&self, _name: &str, _dir: bool) -> KResult<()> {
        Err(Errno::ENOTDIR)
    }
    /// Takes `name` out of this directory (for rename); no checks.
    fn take(&self, _name: &str) -> KResult<Arc<dyn Inode>> {
        Err(Errno::ENOTDIR)
    }
    /// For rename: the directory `self` was moved into.
    fn set_parent(&self, _parent: &Arc<dyn Inode>) {}
    fn entries(&self) -> KResult<Vec<(String, Arc<dyn Inode>)>> {
        Err(Errno::ENOTDIR)
    }
    fn is_empty_dir(&self) -> bool {
        false
    }
    /// Whether this directory can change (false for /proc).
    fn writable_dir(&self) -> bool {
        true
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
            st_dev: self.dev(),
            st_ino: self.ino(),
            st_nlink: self.nlink(),
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

/// The root directory. Created (empty, with `/dev` and `/proc`) on first
/// use.
pub fn root() -> Arc<dyn Inode> {
    mount::cross_down(base_root())
}

/// The kernel's `/dev` directory (for devtmpfs mounts).
pub fn dev_dir() -> Arc<dyn Inode> {
    base_root().lookup("dev").expect("/dev exists")
}

/// The boot root file system (the initramfs), under any mount on "/".
fn base_root() -> Arc<dyn Inode> {
    ROOT.call_once(|| {
        let root = tmpfs::Dir::new_root(0o755);
        let devdir = root.create("dev", FileType::Directory, 0o755).unwrap();
        dev::populate(&devdir);
        root.insert("proc", procfs::root(&root)).unwrap();
        root
    })
    .clone()
}

/// Longest path accepted, as Linux's PATH_MAX.
pub const PATH_MAX: usize = 4096;
const NAME_MAX: usize = 255;
/// Symbolic links followed in one lookup before ELOOP (Linux: 40).
const MAX_SYMLINKS: usize = 40;

/// The absolute path of a directory (or other inode), found by walking up
/// the tree and looking each step's name up in its parent.
pub fn path_of(inode: &Arc<dyn Inode>) -> String {
    let mut parts = Vec::new();
    let mut cur = inode.clone();
    for _ in 0..256 {
        cur = mount::cross_up(cur);
        let Some(parent) = cur.parent() else { break };
        if parent.ino() == cur.ino() && parent.dev() == cur.dev() {
            break; // the root
        }
        let Ok(entries) = parent.entries() else { break };
        match entries
            .into_iter()
            .find(|(_, i)| i.ino() == cur.ino() && i.dev() == cur.dev())
        {
            Some((name, _)) => parts.push(name),
            None => break,
        }
        cur = parent;
    }
    let mut out = String::new();
    for p in parts.iter().rev() {
        out.push('/');
        out.push_str(p);
    }
    if out.is_empty() {
        out.push('/');
    }
    out
}

/// Resolves `path` from `cwd` (absolute paths from the root), following
/// symbolic links (the last one only if `follow_last`). Returns the inode
/// and its canonical absolute path.
pub fn resolve(
    cwd: &Arc<dyn Inode>,
    path: &str,
    follow_last: bool,
) -> KResult<(Arc<dyn Inode>, String)> {
    if path.is_empty() {
        return Err(Errno::ENOENT);
    }
    if path.len() > PATH_MAX {
        return Err(Errno::ENAMETOOLONG);
    }
    let trailing_slash = path.ends_with('/');
    let mut todo: VecDeque<String> = path
        .split('/')
        .filter(|p| !p.is_empty())
        .map(|p| p.to_string())
        .collect();
    let (mut cur, mut canon): (Arc<dyn Inode>, Vec<String>) = if path.starts_with('/') {
        (root(), Vec::new())
    } else {
        let p = path_of(cwd);
        (
            cwd.clone(),
            p.split('/')
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string())
                .collect(),
        )
    };
    let mut links = 0;
    while let Some(part) = todo.pop_front() {
        if cur.file_type() != FileType::Directory {
            return Err(Errno::ENOTDIR);
        }
        match part.as_str() {
            "." => continue,
            ".." => {
                let up = mount::cross_up(cur.clone());
                // "/.." is "/": the file system mounted there, not what
                // that mount covers.
                let top = base_root();
                cur = if up.dev() == top.dev() && up.ino() == top.ino() {
                    root()
                } else {
                    up.parent().unwrap_or(up)
                };
                canon.pop();
                continue;
            }
            p if p.len() > NAME_MAX => return Err(Errno::ENAMETOOLONG),
            _ => {}
        }
        let next = mount::cross_down(cur.lookup(&part)?);
        let last = todo.is_empty();
        if next.file_type() == FileType::Symlink && (!last || follow_last || trailing_slash) {
            links += 1;
            if links > MAX_SYMLINKS {
                return Err(Errno::ELOOP);
            }
            let target = next.readlink()?;
            if let Some(inode) = next.magic_target() {
                cur = inode;
                canon = target
                    .split('/')
                    .filter(|s| !s.is_empty())
                    .map(|s| s.to_string())
                    .collect();
                continue;
            }
            if target.starts_with('/') {
                cur = root();
                canon.clear();
            }
            for p in target.split('/').filter(|p| !p.is_empty()).rev() {
                todo.push_front(p.to_string());
            }
            continue;
        }
        cur = next;
        canon.push(part);
    }
    if trailing_slash && cur.file_type() != FileType::Directory {
        return Err(Errno::ENOTDIR);
    }
    let mut path = String::from("/");
    path.push_str(&canon.join("/"));
    Ok((cur, path))
}

/// Resolves `path` from `cwd`, following every symbolic link.
pub fn lookup(cwd: &Arc<dyn Inode>, path: &str) -> KResult<Arc<dyn Inode>> {
    resolve(cwd, path, true).map(|(i, _)| i)
}

/// Resolves `path` without following a symbolic link at the end.
pub fn lookup_nofollow(cwd: &Arc<dyn Inode>, path: &str) -> KResult<Arc<dyn Inode>> {
    resolve(cwd, path, false).map(|(i, _)| i)
}

/// Resolves everything but the last component: (directory, last name).
/// "path/." and "path/.." have no usable last name: EEXIST-style errors
/// come from the directory operations themselves.
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
/// and repeated slashes, lexically.
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

/// Whether `dir` is `ancestor` or below it (rename must not move a
/// directory into itself).
pub fn is_within(dir: &Arc<dyn Inode>, ancestor: &Arc<dyn Inode>) -> bool {
    let mut cur = dir.clone();
    for _ in 0..4096 {
        if cur.ino() == ancestor.ino() {
            return true;
        }
        match cur.parent() {
            Some(p) if p.ino() != cur.ino() => cur = p,
            _ => return false,
        }
    }
    false
}

/// An open file: shared by descriptors `dup` makes, and by parent and
/// child after `fork`.
pub struct File {
    pub inode: Arc<dyn Inode>,
    pub offset: Mutex<u64>,
    /// Access mode and status flags (O_APPEND, O_NONBLOCK, ...).
    pub flags: SpinLock<u32>,
    /// Whether it has held a `flock` lock (to release on the last close).
    pub locked: core::sync::atomic::AtomicBool,
    /// The absolute path it was opened by, if known (for /proc/<pid>/fd
    /// and /proc/<pid>/maps: a regular file's inode knows no name).
    path: SpinLock<Option<Arc<str>>>,
    /// `getdents64`: the name of the last entry returned (entries come in
    /// name order, so a listing resumes correctly after entries before it
    /// were removed, as `rm -r` and closing every fd in /proc/self/fd do).
    pub dir_cursor: SpinLock<Option<String>>,
}

impl Drop for File {
    fn drop(&mut self) {
        if self.locked.load(Ordering::Relaxed) {
            flock::release(self as *const File as usize);
        }
    }
}

impl File {
    pub fn new(inode: Arc<dyn Inode>, flags: u32) -> Arc<Self> {
        Arc::new(Self {
            inode,
            offset: Mutex::new(0),
            flags: SpinLock::new(flags),
            locked: core::sync::atomic::AtomicBool::new(false),
            path: SpinLock::new(None),
            dir_cursor: SpinLock::new(None),
        })
    }

    pub fn set_path(&self, path: &str) {
        *self.path.lock() = Some(Arc::from(path));
    }

    pub fn path(&self) -> Option<Arc<str>> {
        self.path.lock().clone()
    }

    pub fn readable(&self) -> bool {
        use crate::abi::open::*;
        matches!(*self.flags.lock() & O_ACCMODE, O_RDONLY | O_RDWR)
    }

    pub fn writable(&self) -> bool {
        use crate::abi::open::*;
        matches!(*self.flags.lock() & O_ACCMODE, O_WRONLY | O_RDWR)
    }

    pub fn nonblock(&self) -> bool {
        *self.flags.lock() & crate::abi::open::O_NONBLOCK != 0
    }

    /// Reads at the file offset and advances it.
    pub fn read(&self, buf: &mut [u8]) -> KResult<usize> {
        if !self.readable() {
            return Err(Errno::EBADF);
        }
        if !self.inode.seekable() {
            return self.inode.read_stream(buf, self.nonblock());
        }
        let mut off = self.offset.lock();
        let n = pagecache::read_at(&self.inode, *off, buf)?;
        *off += n as u64;
        Ok(n)
    }

    /// Writes at the file offset (or the end, with O_APPEND) and advances it.
    pub fn write(&self, data: &[u8]) -> KResult<usize> {
        if !self.writable() {
            return Err(Errno::EBADF);
        }
        if !self.inode.seekable() {
            return self.inode.write_stream(data, self.nonblock());
        }
        let mut off = self.offset.lock();
        if *self.flags.lock() & crate::abi::open::O_APPEND != 0 {
            *off = self.inode.size();
        }
        let n = pagecache::write_at(&self.inode, *off, data)?;
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

    /// Closes every descriptor marked close-on-exec.
    pub fn close_on_exec(&mut self) {
        for e in self.fds.iter_mut() {
            if e.as_ref().is_some_and(|e| e.cloexec) {
                *e = None;
            }
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

    /// The open descriptors, for /proc/<pid>/fd.
    pub fn list(&self) -> Vec<(i32, Arc<File>)> {
        self.fds
            .iter()
            .enumerate()
            .filter_map(|(i, e)| e.as_ref().map(|e| (i as i32, e.file.clone())))
            .collect()
    }

    pub fn clear(&mut self) {
        self.fds.clear();
    }
}
