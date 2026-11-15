//! File and directory system calls.

use super::{Ctx, path_arg};
use crate::abi::open::*;
use crate::abi::{
    AT_EMPTY_PATH, AT_FDCWD, AT_REMOVEDIR, AT_SYMLINK_NOFOLLOW, Errno, Iovec, KResult,
};
use crate::fs::{self, File, FileType, Inode, poll as pollbits};
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::sync::atomic::Ordering;

/// Largest single read or write; a bigger request returns a short count,
/// which POSIX allows and every program handles.
const IO_CHUNK: u64 = 1 << 20;
/// Linux's UIO_MAXIOV.
const IOV_MAX: u64 = 1024;

fn file(ctx: &Ctx, fd: i32) -> KResult<Arc<File>> {
    ctx.process().files.lock().get(fd)
}

pub fn read(ctx: &Ctx, fd: i32, buf: u64, count: u64) -> KResult<u64> {
    let f = file(ctx, fd)?;
    if f.inode.file_type() == FileType::Directory {
        return Err(Errno::EISDIR);
    }
    let mut kbuf = vec![0u8; count.min(IO_CHUNK) as usize];
    let n = f.read(&mut kbuf)?;
    ctx.mm().copy_to(buf, &kbuf[..n])?;
    Ok(n as u64)
}

pub fn write(ctx: &Ctx, fd: i32, buf: u64, count: u64) -> KResult<u64> {
    let f = file(ctx, fd)?;
    let mut kbuf = vec![0u8; count.min(IO_CHUNK) as usize];
    ctx.mm().copy_from(buf, &mut kbuf)?;
    Ok(f.write(&kbuf)? as u64)
}

pub(super) fn iovecs(ctx: &Ctx, iov: u64, count: u64) -> KResult<Vec<Iovec>> {
    if count > IOV_MAX {
        return Err(Errno::EINVAL);
    }
    let mut v = Vec::with_capacity(count as usize);
    for i in 0..count {
        let e: Iovec = ctx.mm().read(iov + i * 16)?;
        if e.len > isize::MAX as u64 {
            return Err(Errno::EINVAL);
        }
        v.push(e);
    }
    Ok(v)
}

pub fn readv(ctx: &Ctx, fd: i32, iov: u64, count: u64) -> KResult<u64> {
    let f = file(ctx, fd)?;
    let mut total = 0u64;
    for e in iovecs(ctx, iov, count)? {
        if e.len == 0 {
            continue;
        }
        let mut kbuf = vec![0u8; e.len.min(IO_CHUNK) as usize];
        let n = match f.read(&mut kbuf) {
            Ok(n) => n,
            Err(e) if total > 0 => {
                let _ = e;
                break;
            }
            Err(e) => return Err(e),
        };
        ctx.mm().copy_to(e.base, &kbuf[..n])?;
        total += n as u64;
        if (n as u64) < e.len {
            break;
        }
    }
    Ok(total)
}

pub fn writev(ctx: &Ctx, fd: i32, iov: u64, count: u64) -> KResult<u64> {
    let f = file(ctx, fd)?;
    // Gather first, then write once: a console line or a small pipe write
    // is not split.
    let mut data = Vec::new();
    for e in iovecs(ctx, iov, count)? {
        let start = data.len();
        let len = e.len.min(IO_CHUNK.saturating_sub(start as u64)) as usize;
        data.resize(start + len, 0);
        ctx.mm().copy_from(e.base, &mut data[start..])?;
    }
    Ok(f.write(&data)? as u64)
}

pub fn pread(ctx: &Ctx, fd: i32, buf: u64, count: u64, off: i64) -> KResult<u64> {
    let f = file(ctx, fd)?;
    if off < 0 {
        return Err(Errno::EINVAL);
    }
    if !f.inode.seekable() {
        return Err(Errno::ESPIPE);
    }
    if !f.readable() {
        return Err(Errno::EBADF);
    }
    let mut kbuf = vec![0u8; count.min(IO_CHUNK) as usize];
    let n = fs::pagecache::read_at(&f.inode, off as u64, &mut kbuf)?;
    ctx.mm().copy_to(buf, &kbuf[..n])?;
    Ok(n as u64)
}

pub fn pwrite(ctx: &Ctx, fd: i32, buf: u64, count: u64, off: i64) -> KResult<u64> {
    let f = file(ctx, fd)?;
    if off < 0 {
        return Err(Errno::EINVAL);
    }
    if !f.inode.seekable() {
        return Err(Errno::ESPIPE);
    }
    if !f.writable() {
        return Err(Errno::EBADF);
    }
    let mut kbuf = vec![0u8; count.min(IO_CHUNK) as usize];
    ctx.mm().copy_from(buf, &mut kbuf)?;
    Ok(fs::pagecache::write_at(&f.inode, off as u64, &kbuf)? as u64)
}

pub fn lseek(ctx: &Ctx, fd: i32, off: i64, whence: u32) -> KResult<u64> {
    let f = file(ctx, fd)?;
    match f.inode.file_type() {
        FileType::Fifo => return Err(Errno::ESPIPE),
        // Character devices: seeking succeeds and means nothing.
        FileType::CharDevice => return Ok(0),
        _ => {}
    }
    let mut pos = f.offset.lock();
    let base = match whence {
        0 => 0,
        1 => *pos as i64,
        2 => f.inode.size() as i64,
        _ => return Err(Errno::EINVAL),
    };
    let new = base.checked_add(off).ok_or(Errno::EINVAL)?;
    if new < 0 {
        return Err(Errno::EINVAL);
    }
    *pos = new as u64;
    Ok(new as u64)
}

fn cwd(ctx: &Ctx) -> Arc<dyn Inode> {
    ctx.process().cwd.lock().clone()
}

/// The directory a `*at` call's relative path starts from.
fn dir_of(ctx: &Ctx, dirfd: i32, path: &str) -> KResult<Arc<dyn Inode>> {
    if path.starts_with('/') {
        return Ok(fs::root());
    }
    if dirfd == AT_FDCWD {
        return Ok(cwd(ctx));
    }
    let f = file(ctx, dirfd)?;
    if f.inode.file_type() != FileType::Directory {
        return Err(Errno::ENOTDIR);
    }
    Ok(f.inode.clone())
}

fn resolve(ctx: &Ctx, dirfd: i32, path: &str, follow: bool) -> KResult<Arc<dyn Inode>> {
    let base = dir_of(ctx, dirfd, path)?;
    fs::resolve(&base, path, follow).map(|(i, _)| i)
}

fn resolve_parent(ctx: &Ctx, dirfd: i32, path: &str) -> KResult<(Arc<dyn Inode>, String)> {
    let base = dir_of(ctx, dirfd, path)?;
    let (dir, name) = fs::lookup_parent(&base, path)?;
    // A name that exists gets the operation's own error (EEXIST from
    // mkdir, EROFS from the file system on unlink), as on Linux.
    if fs::mount::is_read_only(dir.dev()) {
        return match dir.lookup(&name) {
            Ok(_) => Ok((dir, name)),
            Err(_) => Err(Errno::EROFS),
        };
    }
    if !dir.writable_dir() {
        return Err(Errno::EACCES);
    }
    Ok((dir, name))
}

fn umask(ctx: &Ctx) -> u32 {
    ctx.process().umask.load(Ordering::Relaxed)
}

pub fn openat(ctx: &Ctx, dirfd: i32, path: u64, flags: u32, mode: u32) -> KResult<u64> {
    let path = path_arg(ctx, path)?;
    let follow = flags & O_NOFOLLOW == 0;
    let inode = if flags & O_CREAT != 0 {
        match resolve(ctx, dirfd, &path, follow) {
            Ok(existing) => {
                if flags & O_EXCL != 0 {
                    return Err(Errno::EEXIST);
                }
                existing
            }
            Err(Errno::ENOENT) => {
                if path.ends_with('/') {
                    return Err(Errno::EISDIR);
                }
                let (dir, name) = resolve_parent(ctx, dirfd, &path)?;
                match dir.create(&name, FileType::Regular, mode & 0o7777 & !umask(ctx)) {
                    Ok(i) => i,
                    // A dangling symbolic link in the way.
                    Err(Errno::EEXIST) => return Err(Errno::ENOENT),
                    Err(e) => return Err(e),
                }
            }
            Err(e) => return Err(e),
        }
    } else {
        resolve(ctx, dirfd, &path, follow)?
    };
    let ty = inode.file_type();
    let acc = flags & O_ACCMODE;
    if ty == FileType::Symlink {
        // O_NOFOLLOW on a symbolic link.
        return Err(Errno::ELOOP);
    }
    if flags & O_DIRECTORY != 0 && ty != FileType::Directory {
        return Err(Errno::ENOTDIR);
    }
    if ty == FileType::Directory && (acc != O_RDONLY || flags & O_CREAT != 0) {
        return Err(Errno::EISDIR);
    }
    if flags & O_TRUNC != 0 && ty == FileType::Regular && acc != O_RDONLY {
        inode.truncate(0)?;
    }
    inode.opened(flags)?;
    let inode = inode.open_fifo(flags).unwrap_or(inode);
    let status = flags & (O_ACCMODE | O_APPEND | O_NONBLOCK | O_DIRECTORY | O_PATH);
    let f = File::new(inode, status);
    let fd = ctx
        .process()
        .files
        .lock()
        .alloc(0, f, flags & O_CLOEXEC != 0)?;
    Ok(fd as u64)
}

pub fn close(ctx: &Ctx, fd: i32) -> KResult<u64> {
    let f = {
        let mut files = ctx.process().files.lock();
        let f = files.get(fd)?;
        files.close(fd)?;
        f
    };
    // The last reference may close a pipe end: drop it outside the lock.
    drop(f);
    Ok(0)
}

pub fn fstat(ctx: &Ctx, fd: i32, buf: u64) -> KResult<u64> {
    let st = file(ctx, fd)?.inode.stat();
    ctx.mm().write(buf, &st)?;
    Ok(0)
}

pub fn stat_path(ctx: &Ctx, dirfd: i32, path: u64, buf: u64, flags: u32) -> KResult<u64> {
    let p = ctx.mm().read_cstr(path, fs::PATH_MAX)?;
    let inode = if p.is_empty() {
        if flags & AT_EMPTY_PATH == 0 {
            return Err(Errno::ENOENT);
        }
        if dirfd == AT_FDCWD {
            cwd(ctx)
        } else {
            file(ctx, dirfd)?.inode.clone()
        }
    } else {
        resolve(ctx, dirfd, &p, flags & AT_SYMLINK_NOFOLLOW == 0)?
    };
    ctx.mm().write(buf, &inode.stat())?;
    Ok(0)
}

/// `statx(dirfd, path, flags, mask, buf)`: the same facts as `stat`, in
/// the newer layout (coreutils and glibc's `stat` use it).
pub fn statx(ctx: &Ctx, dirfd: i32, path: u64, flags: u32, buf: u64) -> KResult<u64> {
    const STATX_BASIC_STATS: u32 = 0x7ff;
    let p = ctx.mm().read_cstr(path, fs::PATH_MAX)?;
    let inode = if p.is_empty() {
        if flags & AT_EMPTY_PATH == 0 {
            return Err(Errno::ENOENT);
        }
        if dirfd == AT_FDCWD {
            cwd(ctx)
        } else {
            file(ctx, dirfd)?.inode.clone()
        }
    } else {
        resolve(ctx, dirfd, &p, flags & AT_SYMLINK_NOFOLLOW == 0)?
    };
    let st = inode.stat();
    let mut b = [0u8; 256];
    let mut put = |off: usize, bytes: &[u8]| b[off..off + bytes.len()].copy_from_slice(bytes);
    put(0, &STATX_BASIC_STATS.to_le_bytes());
    put(4, &(st.st_blksize as u32).to_le_bytes());
    put(16, &(st.st_nlink as u32).to_le_bytes());
    put(20, &st.st_uid.to_le_bytes());
    put(24, &st.st_gid.to_le_bytes());
    put(28, &(st.st_mode as u16).to_le_bytes());
    put(32, &st.st_ino.to_le_bytes());
    put(40, &st.st_size.to_le_bytes());
    put(48, &st.st_blocks.to_le_bytes());
    for (off, sec, nsec) in [
        (64, st.st_atime, st.st_atime_nsec),
        (96, st.st_ctime, st.st_ctime_nsec),
        (112, st.st_mtime, st.st_mtime_nsec),
    ] {
        put(off, &sec.to_le_bytes());
        put(off + 8, &(nsec as u32).to_le_bytes());
    }
    // Device numbers split into major and minor (Linux's encoding).
    let split = |d: u64| {
        (
            ((d >> 8) & 0xfff) | ((d >> 32) & !0xfff),
            (d & 0xff) | ((d >> 12) & !0xff),
        )
    };
    let (rmaj, rmin) = split(st.st_rdev);
    let (dmaj, dmin) = split(st.st_dev);
    put(128, &(rmaj as u32).to_le_bytes());
    put(132, &(rmin as u32).to_le_bytes());
    put(136, &(dmaj as u32).to_le_bytes());
    put(140, &(dmin as u32).to_le_bytes());
    ctx.mm().copy_to(buf, &b)?;
    Ok(0)
}

pub fn faccessat(ctx: &Ctx, dirfd: i32, path: u64, mode: u32) -> KResult<u64> {
    let path = path_arg(ctx, path)?;
    let inode = resolve(ctx, dirfd, &path, true)?;
    // Everything runs as root: only "execute" needs an x bit somewhere.
    if mode & 1 != 0 && inode.file_type() != FileType::Directory && inode.perm() & 0o111 == 0 {
        return Err(Errno::EACCES);
    }
    Ok(0)
}

pub fn ioctl(ctx: &Ctx, fd: i32, req: u32, arg: u64) -> KResult<u64> {
    const FIONCLEX: u32 = 0x5450;
    const FIOCLEX: u32 = 0x5451;
    const FIONBIO: u32 = 0x5421;
    let f = file(ctx, fd)?;
    match req {
        FIOCLEX | FIONCLEX => {
            ctx.process().files.lock().set_cloexec(fd, req == FIOCLEX)?;
            Ok(0)
        }
        FIONBIO => {
            let on: i32 = ctx.mm().read(arg)?;
            let mut fl = f.flags.lock();
            if on != 0 {
                *fl |= O_NONBLOCK;
            } else {
                *fl &= !O_NONBLOCK;
            }
            Ok(0)
        }
        _ => f.inode.ioctl(req, arg, ctx.mm()),
    }
}

pub fn dup(ctx: &Ctx, fd: i32) -> KResult<u64> {
    let mut files = ctx.process().files.lock();
    let f = files.get(fd)?;
    Ok(files.alloc(0, f, false)? as u64)
}

/// `dup2` (`is_dup2`: same descriptor is fine) and `dup3`.
pub fn dup3(ctx: &Ctx, old: i32, new: i32, flags: u32, is_dup2: bool) -> KResult<u64> {
    let replaced;
    {
        let mut files = ctx.process().files.lock();
        let f = files.get(old)?;
        if new < 0 || new as usize >= fs::MAX_FDS {
            return Err(Errno::EBADF);
        }
        if old == new {
            return if is_dup2 {
                Ok(new as u64)
            } else {
                Err(Errno::EINVAL)
            };
        }
        if flags & !O_CLOEXEC != 0 {
            return Err(Errno::EINVAL);
        }
        replaced = files.get(new).ok();
        files.set(new as usize, f, flags & O_CLOEXEC != 0);
    }
    drop(replaced);
    Ok(new as u64)
}

pub fn fcntl(ctx: &Ctx, fd: i32, cmd: u32, arg: u64) -> KResult<u64> {
    const F_DUPFD: u32 = 0;
    const F_GETFD: u32 = 1;
    const F_SETFD: u32 = 2;
    const F_GETFL: u32 = 3;
    const F_SETFL: u32 = 4;
    const F_GETLK: u32 = 5;
    const F_SETLK: u32 = 6;
    const F_SETLKW: u32 = 7;
    const F_DUPFD_CLOEXEC: u32 = 1030;
    const F_GETPIPE_SZ: u32 = 1032;
    const F_ADD_SEALS: u32 = 1033;
    const F_GET_SEALS: u32 = 1034;
    const FD_CLOEXEC: u64 = 1;
    let mut files = ctx.process().files.lock();
    let f = files.get(fd)?;
    match cmd {
        F_ADD_SEALS | F_GET_SEALS => {
            let mut seals = SEALS.lock();
            let s = seals.get_mut(&f.inode.ino()).ok_or(Errno::EINVAL)?;
            if cmd == F_GET_SEALS {
                return Ok(*s as u64);
            }
            if *s & 1 != 0 {
                return Err(Errno::EPERM); // F_SEAL_SEAL
            }
            *s |= arg as u32 & 0x3f;
            Ok(0)
        }
        F_DUPFD | F_DUPFD_CLOEXEC => {
            let min = usize::try_from(arg).map_err(|_| Errno::EINVAL)?;
            if min >= fs::MAX_FDS {
                return Err(Errno::EINVAL);
            }
            Ok(files.alloc(min, f, cmd == F_DUPFD_CLOEXEC)? as u64)
        }
        F_GETFD => Ok(files.cloexec(fd)? as u64),
        F_SETFD => {
            files.set_cloexec(fd, arg & FD_CLOEXEC != 0)?;
            Ok(0)
        }
        F_GETFL => Ok(*f.flags.lock() as u64),
        F_SETFL => {
            let mut fl = f.flags.lock();
            let changeable = O_APPEND | O_NONBLOCK;
            *fl = (*fl & !changeable) | (arg as u32 & changeable);
            Ok(0)
        }
        // Record locks: one process at a time uses a file so far; grant.
        F_SETLK | F_SETLKW => Ok(0),
        F_GETLK => {
            // struct flock: l_type F_UNLCK (2) means "would succeed".
            drop(files);
            ctx.mm().write(arg, &2u16)?;
            Ok(0)
        }
        F_GETPIPE_SZ if f.inode.file_type() == FileType::Fifo => Ok(64 * 1024),
        _ => Err(Errno::EINVAL),
    }
}

pub fn fsync(ctx: &Ctx, fd: i32) -> KResult<u64> {
    let f = file(ctx, fd)?;
    fs::pagecache::sync_inode(&f.inode)?;
    if f.inode.dev() != fs::DEV_TMPFS {
        crate::block::sync_all();
    }
    Ok(0)
}

pub fn ftruncate(ctx: &Ctx, fd: i32, len: i64) -> KResult<u64> {
    let f = file(ctx, fd)?;
    if len < 0 {
        return Err(Errno::EINVAL);
    }
    if !f.writable() || f.inode.file_type() != FileType::Regular {
        return Err(Errno::EINVAL);
    }
    f.inode.truncate(len as u64)?;
    Ok(0)
}

pub fn truncate(ctx: &Ctx, path: u64, len: i64) -> KResult<u64> {
    let path = path_arg(ctx, path)?;
    let inode = resolve(ctx, AT_FDCWD, &path, true)?;
    if len < 0 {
        return Err(Errno::EINVAL);
    }
    match inode.file_type() {
        FileType::Directory => Err(Errno::EISDIR),
        FileType::Regular => inode.truncate(len as u64).map(|()| 0),
        _ => Err(Errno::EINVAL),
    }
}

pub fn getcwd(ctx: &Ctx, buf: u64, size: u64) -> KResult<u64> {
    let path = fs::path_of(&cwd(ctx));
    let len = path.len() as u64 + 1;
    if size < len {
        return Err(Errno::ERANGE);
    }
    let mut bytes = path.into_bytes();
    bytes.push(0);
    ctx.mm().copy_to(buf, &bytes)?;
    Ok(len)
}

fn set_cwd(ctx: &Ctx, inode: Arc<dyn Inode>) -> KResult<u64> {
    if inode.file_type() != FileType::Directory {
        return Err(Errno::ENOTDIR);
    }
    *ctx.process().cwd.lock() = inode;
    Ok(0)
}

pub fn chdir(ctx: &Ctx, path: u64) -> KResult<u64> {
    let path = path_arg(ctx, path)?;
    let inode = resolve(ctx, AT_FDCWD, &path, true)?;
    set_cwd(ctx, inode)
}

pub fn fchdir(ctx: &Ctx, fd: i32) -> KResult<u64> {
    let inode = file(ctx, fd)?.inode.clone();
    set_cwd(ctx, inode)
}

pub fn mkdirat(ctx: &Ctx, dirfd: i32, path: u64, mode: u32) -> KResult<u64> {
    let path = path_arg(ctx, path)?;
    let (dir, name) = resolve_parent(ctx, dirfd, &path)?;
    if dir.lookup(&name).is_ok() {
        return Err(Errno::EEXIST);
    }
    dir.create(&name, FileType::Directory, mode & 0o7777 & !umask(ctx))?;
    Ok(0)
}

/// `mknod`/`mknodat`: FIFOs and regular files (no device nodes: /dev is
/// the kernel's).
pub fn mknodat(ctx: &Ctx, dirfd: i32, path: u64, mode: u32) -> KResult<u64> {
    use crate::abi::mode::*;
    let path = path_arg(ctx, path)?;
    let (dir, name) = resolve_parent(ctx, dirfd, &path)?;
    let perm = mode & 0o7777 & !umask(ctx);
    let ty = match mode & S_IFMT {
        S_IFIFO => FileType::Fifo,
        0 | S_IFREG => FileType::Regular,
        _ => return Err(Errno::EPERM),
    };
    dir.create(&name, ty, perm)?;
    Ok(0)
}

pub fn unlinkat(ctx: &Ctx, dirfd: i32, path: u64, flags: u32) -> KResult<u64> {
    let path = path_arg(ctx, path)?;
    if flags & !AT_REMOVEDIR != 0 {
        return Err(Errno::EINVAL);
    }
    let dir_wanted = flags & AT_REMOVEDIR != 0;
    if !dir_wanted && path.ends_with('/') {
        // unlink("dir/") names a directory.
        let target = resolve(ctx, dirfd, &path, true)?;
        return Err(if target.file_type() == FileType::Directory {
            Errno::EISDIR
        } else {
            Errno::ENOTDIR
        });
    }
    let (dir, name) = resolve_parent(ctx, dirfd, &path)?;
    if dir_wanted && name == "." {
        return Err(Errno::EINVAL);
    }
    dir.remove(&name, dir_wanted)?;
    Ok(0)
}

pub fn renameat(
    ctx: &Ctx,
    olddir: i32,
    old: u64,
    newdir: i32,
    new: u64,
    flags: u32,
) -> KResult<u64> {
    const RENAME_NOREPLACE: u32 = 1;
    if flags & !RENAME_NOREPLACE != 0 {
        return Err(Errno::EINVAL);
    }
    let old = path_arg(ctx, old)?;
    let new = path_arg(ctx, new)?;
    let (from_dir, from) = resolve_parent(ctx, olddir, &old)?;
    let (to_dir, to) = resolve_parent(ctx, newdir, &new)?;
    if matches!(from.as_str(), "." | "..") || matches!(to.as_str(), "." | "..") {
        return Err(Errno::EBUSY);
    }
    let inode = from_dir.lookup(&from)?;
    let is_dir = inode.file_type() == FileType::Directory;
    if from_dir.dev() != to_dir.dev() {
        return Err(Errno::EXDEV);
    }
    if is_dir && fs::is_within(&to_dir, &inode) {
        return Err(Errno::EINVAL); // into itself
    }
    match to_dir.lookup(&to) {
        Ok(existing) => {
            if existing.ino() == inode.ino() {
                return Ok(0); // the same file: nothing to do
            }
            if flags & RENAME_NOREPLACE != 0 {
                return Err(Errno::EEXIST);
            }
            let target_dir = existing.file_type() == FileType::Directory;
            match (is_dir, target_dir) {
                (true, false) => return Err(Errno::ENOTDIR),
                (false, true) => return Err(Errno::EISDIR),
                _ => {}
            }
            to_dir.remove(&to, target_dir)?;
        }
        Err(Errno::ENOENT) => {}
        Err(e) => return Err(e),
    }
    let inode = from_dir.take(&from)?;
    if let Err(e) = to_dir.insert(&to, inode.clone()) {
        let _ = from_dir.insert(&from, inode);
        return Err(e);
    }
    if is_dir {
        inode.set_parent(&to_dir);
    }
    Ok(0)
}

pub fn linkat(ctx: &Ctx, olddir: i32, old: u64, newdir: i32, new: u64) -> KResult<u64> {
    let old = path_arg(ctx, old)?;
    let new = path_arg(ctx, new)?;
    let inode = resolve(ctx, olddir, &old, false)?;
    if inode.file_type() == FileType::Directory {
        return Err(Errno::EPERM);
    }
    let (dir, name) = resolve_parent(ctx, newdir, &new)?;
    dir.insert(&name, inode.clone())?;
    inode.link_added();
    Ok(0)
}

pub fn symlinkat(ctx: &Ctx, target: u64, newdir: i32, path: u64) -> KResult<u64> {
    let target = path_arg(ctx, target)?;
    let path = path_arg(ctx, path)?;
    let (dir, name) = resolve_parent(ctx, newdir, &path)?;
    dir.symlink(&name, &target)?;
    Ok(0)
}

pub fn readlinkat(ctx: &Ctx, dirfd: i32, path: u64, buf: u64, size: u64) -> KResult<u64> {
    let path = path_arg(ctx, path)?;
    if size as i64 <= 0 {
        return Err(Errno::EINVAL);
    }
    let inode = resolve(ctx, dirfd, &path, false)?;
    let target = inode.readlink()?;
    let n = target.len().min(size as usize);
    ctx.mm().copy_to(buf, &target.as_bytes()[..n])?;
    Ok(n as u64)
}

pub fn fchmodat(ctx: &Ctx, dirfd: i32, path: u64, mode: u32) -> KResult<u64> {
    let path = path_arg(ctx, path)?;
    resolve(ctx, dirfd, &path, true)?.set_perm(mode & 0o7777)?;
    Ok(0)
}

pub fn fchmod(ctx: &Ctx, fd: i32, mode: u32) -> KResult<u64> {
    file(ctx, fd)?.inode.set_perm(mode & 0o7777)?;
    Ok(0)
}

/// `utime` (132), `utimes` (235), `utimensat` (280): only the modification
/// time is kept.
pub fn utimes(ctx: &Ctx, nr: u64, a: [u64; 6]) -> KResult<u64> {
    const UTIME_NOW: i64 = (1 << 30) - 1;
    const UTIME_OMIT: i64 = (1 << 30) - 2;
    let now = crate::time::realtime_ns() / crate::time::NS_PER_SEC;
    let (inode, mtime) = match nr {
        280 => {
            let (dirfd, path, times, flags) = (a[0] as i32, a[1], a[2], a[3] as u32);
            let inode = if path == 0 {
                file(ctx, dirfd)?.inode.clone()
            } else {
                let p = path_arg(ctx, path)?;
                resolve(ctx, dirfd, &p, flags & AT_SYMLINK_NOFOLLOW == 0)?
            };
            let mtime = if times == 0 {
                Some(now)
            } else {
                let t: crate::abi::Timespec = ctx.mm().read(times + 16)?;
                match t.tv_nsec {
                    UTIME_OMIT => None,
                    UTIME_NOW => Some(now),
                    _ => Some(t.tv_sec.max(0) as u64),
                }
            };
            (inode, mtime)
        }
        _ => {
            let p = path_arg(ctx, a[0])?;
            let inode = resolve(ctx, AT_FDCWD, &p, true)?;
            let mtime = if a[1] == 0 {
                Some(now)
            } else {
                // utime: {actime, modtime}; utimes: two timevals.
                let off = if nr == 132 { 8 } else { 16 };
                Some(ctx.mm().read::<i64>(a[1] + off)?.max(0) as u64)
            };
            (inode, mtime)
        }
    };
    if let Some(t) = mtime {
        inode.set_mtime(t);
    }
    Ok(0)
}

/// `statfs` (path) and `fstatfs` (descriptor): tmpfs numbers come from
/// free memory; /proc has none.
pub fn statfs(ctx: &Ctx, target: u64, buf: u64, by_fd: bool) -> KResult<u64> {
    const TMPFS_MAGIC: u64 = 0x0102_1994;
    const PROC_SUPER_MAGIC: u64 = 0x9fa0;
    const PIPEFS_MAGIC: u64 = 0x5049_5045;
    let inode = if by_fd {
        file(ctx, target as i32)?.inode.clone()
    } else {
        let p = path_arg(ctx, target)?;
        resolve(ctx, AT_FDCWD, &p, true)?
    };
    let disk = fs::mount::mount_of_dev(inode.dev()).and_then(|m| m.info.clone().map(|i| (m, i)));
    let (magic, bsize, total, free, files, ffree, flags) = match (inode.dev(), disk) {
        (_, Some((m, info))) => {
            let (bsize, blocks, bfree, files, ffree) = info.stats();
            (
                info.magic(),
                bsize,
                blocks,
                bfree,
                files,
                ffree,
                if m.read_only { 1 } else { 0 },
            )
        }
        (fs::DEV_PROC, None) => (PROC_SUPER_MAGIC, 4096, 0, 0, 0, 0, 0),
        (fs::DEV_PIPEFS, None) => (PIPEFS_MAGIC, 4096, 0, 0, 0, 0, 0),
        _ => (
            TMPFS_MAGIC,
            4096,
            crate::mm::frame::total_count(),
            crate::mm::frame::free_count(),
            1 << 20,
            1 << 20,
            0,
        ),
    };
    let words: [u64; 12] = [
        magic,       // f_type
        bsize,       // f_bsize
        total,       // f_blocks
        free,        // f_bfree
        free,        // f_bavail
        files,       // f_files
        ffree,       // f_ffree
        inode.dev(), // f_fsid
        255,         // f_namelen
        bsize,       // f_frsize
        flags,       // f_flags (ST_RDONLY)
        0,
    ];
    let mut bytes: Vec<u8> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
    bytes.resize(120, 0);
    ctx.mm().copy_to(buf, &bytes)?;
    Ok(0)
}

pub fn pipe2(ctx: &Ctx, fds: u64, flags: u32) -> KResult<u64> {
    if flags & !(O_CLOEXEC | O_NONBLOCK | O_DIRECT) != 0 {
        return Err(Errno::EINVAL);
    }
    let (r, w) = fs::pipe::pipe();
    let status = flags & O_NONBLOCK;
    let cloexec = flags & O_CLOEXEC != 0;
    let (rfd, wfd) = {
        let mut files = ctx.process().files.lock();
        let rfd = files.alloc(0, File::new(r, O_RDONLY | status), cloexec)?;
        match files.alloc(0, File::new(w, O_WRONLY | status), cloexec) {
            Ok(wfd) => (rfd, wfd),
            Err(e) => {
                let _ = files.close(rfd);
                return Err(e);
            }
        }
    };
    let pair = [rfd, wfd];
    if let Err(e) = ctx.mm().write(fds, &pair) {
        let mut files = ctx.process().files.lock();
        let _ = files.close(rfd);
        let _ = files.close(wfd);
        return Err(e);
    }
    Ok(0)
}

/// Waits until one of `fds` (descriptor, wanted events) is ready, a signal
/// arrives, or `timeout` (ns, None for ever) passes. Returns the events.
fn wait_ready(ctx: &Ctx, fds: &[(i32, u16)], timeout: Option<u64>) -> KResult<Vec<u16>> {
    let deadline = timeout.map(|t| crate::time::monotonic_ns().saturating_add(t));
    let _timer = deadline
        .filter(|_| timeout != Some(0))
        .map(crate::time::wake_at);
    loop {
        let seen = fs::POLL_EVENTS.load(Ordering::Acquire);
        let mut ready = 0;
        let files = ctx.process().files.lock();
        let events: Vec<u16> = fds
            .iter()
            .map(|&(fd, want)| {
                if fd < 0 {
                    return 0;
                }
                let r = match files.get(fd) {
                    Ok(f) => f.inode.poll() & (want | pollbits::POLLERR | pollbits::POLLHUP),
                    Err(_) => pollbits::POLLNVAL,
                };
                if r != 0 {
                    ready += 1;
                }
                r
            })
            .collect();
        drop(files);
        if ready > 0 || deadline.is_some_and(|d| crate::time::monotonic_ns() >= d) {
            return Ok(events);
        }
        let timed_out = || deadline.is_some_and(|d| crate::time::monotonic_ns() >= d);
        match fs::POLL_WAIT
            .wait_interruptible(|| fs::POLL_EVENTS.load(Ordering::Acquire) != seen || timed_out())
        {
            Ok(()) => {}
            // poll and select are not restarted after a handler (Linux).
            Err(_) => return Err(Errno::EINTR),
        }
    }
}

fn do_poll(ctx: &Ctx, ufds: u64, nfds: u64, timeout: Option<u64>) -> KResult<u64> {
    if nfds > fs::MAX_FDS as u64 {
        return Err(Errno::EINVAL);
    }
    let mut fds = Vec::with_capacity(nfds as usize);
    for i in 0..nfds {
        let fd: i32 = ctx.mm().read(ufds + i * 8)?;
        let events: u16 = ctx.mm().read(ufds + i * 8 + 4)?;
        fds.push((fd, events));
    }
    let revents = wait_ready(ctx, &fds, timeout)?;
    for (i, r) in revents.iter().enumerate() {
        ctx.mm().write(ufds + i as u64 * 8 + 6, r)?;
    }
    Ok(revents.iter().filter(|&&r| r != 0).count() as u64)
}

pub fn poll(ctx: &Ctx, ufds: u64, nfds: u64, timeout_ms: i64) -> KResult<u64> {
    let timeout = (timeout_ms >= 0).then(|| timeout_ms as u64 * 1_000_000);
    do_poll(ctx, ufds, nfds, timeout)
}

fn timespec_ns(ctx: &Ctx, addr: u64) -> KResult<Option<u64>> {
    if addr == 0 {
        return Ok(None);
    }
    let t: crate::abi::Timespec = ctx.mm().read(addr)?;
    if t.tv_sec < 0 || !(0..1_000_000_000).contains(&t.tv_nsec) {
        return Err(Errno::EINVAL);
    }
    Ok(Some(
        (t.tv_sec as u64)
            .saturating_mul(crate::time::NS_PER_SEC)
            .saturating_add(t.tv_nsec as u64),
    ))
}

/// ppoll and pselect6 run with a temporary signal mask, restored on the
/// way back to user mode (or from the signal frame if a handler runs), as
/// with sigsuspend.
fn apply_sigmask(ctx: &Ctx, mask: u64) -> KResult<()> {
    if mask != 0 {
        let m: u64 = ctx.mm().read(mask)?;
        ctx.thread().sig.suspend_mask(m);
    }
    Ok(())
}

pub fn ppoll(ctx: &Ctx, ufds: u64, nfds: u64, tsp: u64, sigmask: u64) -> KResult<u64> {
    let timeout = timespec_ns(ctx, tsp)?;
    apply_sigmask(ctx, sigmask)?;
    do_poll(ctx, ufds, nfds, timeout)
}

/// `select`, and `pselect6` (with `sigmask`: a pointer to {mask pointer,
/// size}).
pub fn select(ctx: &Ctx, nfds: i32, sets: [u64; 3], tv: u64, sigmask: Option<u64>) -> KResult<u64> {
    let pselect = sigmask.is_some();
    if !(0..=fs::MAX_FDS as i32).contains(&nfds) {
        return Err(Errno::EINVAL);
    }
    let words = (nfds as usize).div_ceil(64);
    let mut bits = [vec![0u64; words], vec![0u64; words], vec![0u64; words]];
    for (set, &addr) in bits.iter_mut().zip(&sets) {
        if addr != 0 {
            for (w, word) in set.iter_mut().enumerate() {
                *word = ctx.mm().read(addr + w as u64 * 8)?;
            }
        }
    }
    let timeout = if tv == 0 {
        None
    } else if pselect {
        timespec_ns(ctx, tv)?
    } else {
        let s: i64 = ctx.mm().read(tv)?;
        let us: i64 = ctx.mm().read(tv + 8)?;
        if s < 0 || !(0..1_000_000).contains(&us) {
            return Err(Errno::EINVAL);
        }
        Some(s as u64 * crate::time::NS_PER_SEC + us as u64 * 1000)
    };
    let mut fds = Vec::new();
    for fd in 0..nfds as usize {
        let (w, b) = (fd / 64, 1u64 << (fd % 64));
        let mut want = 0;
        if bits[0][w] & b != 0 {
            want |= pollbits::POLLIN;
        }
        if bits[1][w] & b != 0 {
            want |= pollbits::POLLOUT;
        }
        if bits[2][w] & b != 0 {
            want |= pollbits::POLLPRI;
        }
        if want != 0 {
            if file(ctx, fd as i32).is_err() {
                return Err(Errno::EBADF);
            }
            fds.push((fd as i32, want));
        }
    }
    if let Some(m) = sigmask.filter(|&m| m != 0) {
        let mask_ptr: u64 = ctx.mm().read(m)?;
        apply_sigmask(ctx, mask_ptr)?;
    }
    let revents = wait_ready(ctx, &fds, timeout)?;
    let mut out = [vec![0u64; words], vec![0u64; words], vec![0u64; words]];
    let mut count = 0;
    for (&(fd, want), &r) in fds.iter().zip(&revents) {
        let (w, b) = (fd as usize / 64, 1u64 << (fd % 64));
        if want & pollbits::POLLIN != 0
            && r & (pollbits::POLLIN | pollbits::POLLHUP | pollbits::POLLERR) != 0
        {
            out[0][w] |= b;
            count += 1;
        }
        if want & pollbits::POLLOUT != 0 && r & (pollbits::POLLOUT | pollbits::POLLERR) != 0 {
            out[1][w] |= b;
            count += 1;
        }
        if want & pollbits::POLLPRI != 0 && r & pollbits::POLLPRI != 0 {
            out[2][w] |= b;
            count += 1;
        }
    }
    for (set, &addr) in out.iter().zip(&sets) {
        if addr != 0 {
            for (w, word) in set.iter().enumerate() {
                ctx.mm().write(addr + w as u64 * 8, word)?;
            }
        }
    }
    Ok(count)
}

/// `getdents64`: the file offset counts entries already returned
/// ("." and ".." first).
pub fn getdents64(ctx: &Ctx, fd: i32, buf: u64, count: u64) -> KResult<u64> {
    let f = file(ctx, fd)?;
    let dir = &f.inode;
    if dir.file_type() != FileType::Directory {
        return Err(Errno::ENOTDIR);
    }
    let mut list: Vec<(String, u64, u8)> = vec![
        (".".into(), dir.ino(), 4),
        ("..".into(), dir.parent().map_or(dir.ino(), |p| p.ino()), 4),
    ];
    for (name, inode) in dir.entries()? {
        list.push((name, inode.ino(), inode.file_type().dirent_type()));
    }
    let mut pos = f.offset.lock();
    let mut out = Vec::new();
    let mut i = *pos as usize;
    while let Some((name, ino, t)) = list.get(i) {
        let reclen = (19 + name.len() + 1).next_multiple_of(8);
        if (out.len() + reclen) as u64 > count {
            break;
        }
        out.extend_from_slice(&ino.to_le_bytes());
        out.extend_from_slice(&((i + 1) as i64).to_le_bytes());
        out.extend_from_slice(&(reclen as u16).to_le_bytes());
        out.push(*t);
        out.extend_from_slice(name.as_bytes());
        out.resize(out.len() + reclen - 19 - name.len(), 0);
        i += 1;
    }
    if out.is_empty() && i < list.len() {
        return Err(Errno::EINVAL); // buffer too small for one entry
    }
    ctx.mm().copy_to(buf, &out)?;
    *pos = i as u64;
    Ok(out.len() as u64)
}

/// `sendfile(out, in, offset, count)`: copies between files in the kernel.
pub fn sendfile(ctx: &Ctx, out_fd: i32, in_fd: i32, offset: u64, count: u64) -> KResult<u64> {
    let input = file(ctx, in_fd)?;
    let output = file(ctx, out_fd)?;
    if !input.readable() || !output.writable() {
        return Err(Errno::EBADF);
    }
    let mut buf = vec![0u8; count.min(64 * 1024) as usize];
    let n = if offset != 0 {
        if !input.inode.seekable() {
            return Err(Errno::ESPIPE);
        }
        let mut pos: i64 = ctx.mm().read(offset)?;
        if pos < 0 {
            return Err(Errno::EINVAL);
        }
        let n = fs::pagecache::read_at(&input.inode, pos as u64, &mut buf)?;
        let w = output.write(&buf[..n])?;
        pos += w as i64;
        ctx.mm().write(offset, &pos)?;
        return Ok(w as u64);
    } else {
        input.read(&mut buf)?
    };
    let mut done = 0;
    while done < n {
        match output.write(&buf[done..n]) {
            Ok(w) => done += w,
            Err(e) if done == 0 => return Err(e),
            Err(_) => break,
        }
    }
    Ok(done as u64)
}

/// Mounts a file system of type `fstype` on `point`: (root, info).
fn make_fs(
    ctx: &Ctx,
    fstype: &str,
    source: &str,
    point: &Arc<dyn Inode>,
) -> KResult<fs::mount::Mounted> {
    match fstype {
        "tmpfs" | "ramfs" => Ok((fs::tmpfs::Dir::new_root(0o1777), None)),
        "proc" => Ok((fs::procfs::root(point), None)),
        "sysfs" => Ok((fs::sysfs::create(), None)),
        // The kernel's own /dev, wherever it is asked for.
        "devtmpfs" => Ok((fs::dev_dir(), None)),
        "ext4" | "ext3" | "ext2" => {
            let node = resolve(ctx, AT_FDCWD, source, true)?;
            let dev = crate::block::device_of(&node).ok_or(Errno::ENOTBLK)?;
            fs::disk::mount_ext4(dev)
        }
        "vfat" | "msdos" | "fat" => {
            let node = resolve(ctx, AT_FDCWD, source, true)?;
            let dev = crate::block::device_of(&node).ok_or(Errno::ENOTBLK)?;
            fs::disk::mount_fat(dev)
        }
        _ => Err(Errno::ENODEV),
    }
}

/// `mount(source, target, fstype, flags, data)`: new mounts of tmpfs,
/// proc, devtmpfs and ext2/3/4 (read-only for now), bind mounts,
/// read-only remounts. Propagation changes are accepted and mean nothing
/// (there is one mount namespace).
pub fn mount(ctx: &Ctx, source: u64, target: u64, fstype: u64, flags: u64) -> KResult<u64> {
    const MS_RDONLY: u64 = 1;
    const MS_REMOUNT: u64 = 32;
    const MS_BIND: u64 = 4096;
    const MS_MOVE: u64 = 8192;
    const PROPAGATION: u64 = 1 << 17 | 1 << 18 | 1 << 19 | 1 << 20;
    let target = path_arg(ctx, target)?;
    let point = resolve(ctx, AT_FDCWD, &target, true)?;
    if point.file_type() != FileType::Directory {
        return Err(Errno::ENOTDIR);
    }
    if flags & MS_REMOUNT != 0 {
        fs::mount::set_read_only(&point, flags & MS_RDONLY != 0)?;
        return Ok(0);
    }
    if flags & PROPAGATION != 0 && flags & (MS_BIND | MS_MOVE) == 0 {
        return Ok(0);
    }
    let source = if source == 0 {
        String::from("none")
    } else {
        ctx.mm().read_cstr(source, fs::PATH_MAX)?
    };
    let path = fs::path_of(&point);
    if flags & MS_MOVE != 0 {
        let src = resolve(ctx, AT_FDCWD, &source, true)?;
        fs::mount::move_to(&src, point, &path)?;
        return Ok(0);
    }
    if flags & MS_BIND != 0 {
        let src = resolve(ctx, AT_FDCWD, &source, true)?;
        fs::mount::add(
            point,
            src,
            &source,
            "none",
            &path,
            flags & MS_RDONLY != 0,
            None,
        )?;
        return Ok(0);
    }
    let fstype = ctx.mm().read_cstr(fstype, 64)?;
    let (root, info) = make_fs(ctx, &fstype, &source, &point)?;
    let ro = flags & MS_RDONLY != 0 || info.as_ref().is_some_and(|i| i.read_only());
    fs::mount::add(point, root, &source, &fstype, &path, ro, info)?;
    Ok(0)
}

/// `umount2(target, flags)`.
pub fn umount2(ctx: &Ctx, target: u64, _flags: u64) -> KResult<u64> {
    let target = path_arg(ctx, target)?;
    let root = resolve(ctx, AT_FDCWD, &target, true)?;
    fs::mount::remove(&root)?;
    crate::block::sync_all();
    Ok(0)
}

/// `close_range`: closes (or, with CLOSE_RANGE_CLOEXEC, marks
/// close-on-exec) every descriptor from `first` to `last`.
pub fn close_range(ctx: &Ctx, first: u32, last: u32, flags: u32) -> KResult<u64> {
    const UNSHARE: u32 = 2;
    const CLOEXEC: u32 = 4;
    if flags & !(UNSHARE | CLOEXEC) != 0 || first > last {
        return Err(Errno::EINVAL);
    }
    let mut files = ctx.process().files.lock();
    let fds: alloc::vec::Vec<i32> = files
        .list()
        .into_iter()
        .map(|(fd, _)| fd)
        .filter(|&fd| fd as u32 >= first && fd as u32 <= last)
        .collect();
    for fd in fds {
        if flags & CLOEXEC != 0 {
            let _ = files.set_cloexec(fd, true);
        } else {
            let _ = files.close(fd);
        }
    }
    Ok(0)
}

/// Seals of memfd files, by inode number (F_ADD_SEALS / F_GET_SEALS).
static SEALS: crate::sync::SpinLock<alloc::collections::BTreeMap<u64, u32>> =
    crate::sync::SpinLock::new(alloc::collections::BTreeMap::new());

/// `memfd_create`: a tmpfs file with no name, for sharing memory (Wayland
/// clients hand their buffers to the compositor this way).
pub fn memfd_create(ctx: &Ctx, name: u64, flags: u32) -> KResult<u64> {
    const MFD_CLOEXEC: u32 = 1;
    const MFD_ALLOW_SEALING: u32 = 2;
    const MFD_NOEXEC_SEAL: u32 = 8;
    const MFD_EXEC: u32 = 0x10;
    if flags & !(MFD_CLOEXEC | MFD_ALLOW_SEALING | MFD_NOEXEC_SEAL | MFD_EXEC | 4) != 0 {
        return Err(Errno::EINVAL);
    }
    let name = ctx.mm().read_cstr(name, 249)?;
    let dir = fs::tmpfs::Dir::new_root(0o700);
    let file_name = alloc::format!("memfd:{name}");
    let inode = dir.create(&file_name, FileType::Regular, 0o777)?;
    dir.remove(&file_name, false)?;
    let sealing = flags & (MFD_ALLOW_SEALING | MFD_NOEXEC_SEAL) != 0;
    {
        let mut seals = SEALS.lock();
        if seals.len() > 4096 {
            seals.clear(); // a bound, not a policy: old memfds lose their seals
        }
        seals.insert(inode.ino(), if sealing { 0 } else { 1 });
    }
    let file = fs::File::new(inode, crate::abi::open::O_RDWR);
    let fd = ctx
        .process()
        .files
        .lock()
        .alloc(0, file, flags & MFD_CLOEXEC != 0)?;
    Ok(fd as u64)
}
