//! File and directory system calls.

use super::{Ctx, path_arg};
use crate::abi::open::*;
use crate::abi::{AT_EMPTY_PATH, AT_FDCWD, AT_REMOVEDIR, Errno, Iovec, KResult};
use crate::fs::{self, File, FileType, Inode};
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;

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

fn iovecs(ctx: &Ctx, iov: u64, count: u64) -> KResult<Vec<Iovec>> {
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
        let mut kbuf = vec![0u8; e.len.min(IO_CHUNK) as usize];
        let n = f.read(&mut kbuf)?;
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
    // Gather first, then write once: a console line is not split.
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
    let n = f.inode.read_at(off as u64, &mut kbuf)?;
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
    Ok(f.inode.write_at(off as u64, &kbuf)? as u64)
}

pub fn lseek(ctx: &Ctx, fd: i32, off: i64, whence: u32) -> KResult<u64> {
    let f = file(ctx, fd)?;
    if !f.inode.seekable() && f.inode.file_type() != FileType::Directory {
        // Character devices: seeking succeeds and means nothing.
        return Ok(0);
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

/// The directory a `*at` call's relative path starts from.
fn dir_of(ctx: &Ctx, dirfd: i32) -> KResult<Arc<dyn Inode>> {
    if dirfd == AT_FDCWD {
        return Ok(ctx.process().cwd.lock().inode.clone());
    }
    let f = file(ctx, dirfd)?;
    if f.inode.file_type() != FileType::Directory {
        return Err(Errno::ENOTDIR);
    }
    Ok(f.inode.clone())
}

fn resolve(ctx: &Ctx, dirfd: i32, path: &str) -> KResult<Arc<dyn Inode>> {
    let base = if path.starts_with('/') {
        fs::root()
    } else {
        dir_of(ctx, dirfd)?
    };
    fs::lookup(&base, path)
}

fn resolve_parent(
    ctx: &Ctx,
    dirfd: i32,
    path: &str,
) -> KResult<(Arc<dyn Inode>, alloc::string::String)> {
    let base = if path.starts_with('/') {
        fs::root()
    } else {
        dir_of(ctx, dirfd)?
    };
    fs::lookup_parent(&base, path)
}

pub fn openat(ctx: &Ctx, dirfd: i32, path: u64, flags: u32, mode: u32) -> KResult<u64> {
    let path = path_arg(ctx, path)?;
    let inode = if flags & O_CREAT != 0 {
        let (dir, name) = resolve_parent(ctx, dirfd, &path)?;
        match dir.lookup(&name) {
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
                let umask = ctx
                    .process()
                    .umask
                    .load(core::sync::atomic::Ordering::Relaxed);
                dir.create(&name, FileType::Regular, mode & 0o7777 & !umask)?
            }
            Err(e) => return Err(e),
        }
    } else {
        resolve(ctx, dirfd, &path)?
    };
    let ty = inode.file_type();
    let acc = flags & O_ACCMODE;
    if flags & O_DIRECTORY != 0 && ty != FileType::Directory {
        return Err(Errno::ENOTDIR);
    }
    if ty == FileType::Directory && (acc != O_RDONLY || flags & O_CREAT != 0) {
        return Err(Errno::EISDIR);
    }
    if flags & O_TRUNC != 0 && ty == FileType::Regular && acc != O_RDONLY {
        inode.truncate(0)?;
    }
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
    ctx.process().files.lock().close(fd)?;
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
            ctx.process().cwd.lock().inode.clone()
        } else {
            file(ctx, dirfd)?.inode.clone()
        }
    } else {
        // No symbolic links yet, so AT_SYMLINK_NOFOLLOW changes nothing.
        resolve(ctx, dirfd, &p)?
    };
    ctx.mm().write(buf, &inode.stat())?;
    Ok(0)
}

pub fn faccessat(ctx: &Ctx, dirfd: i32, path: u64, mode: u32) -> KResult<u64> {
    let path = path_arg(ctx, path)?;
    let inode = resolve(ctx, dirfd, &path)?;
    // Everything runs as root: only "execute" needs an x bit somewhere.
    if mode & 1 != 0 && inode.file_type() != FileType::Directory && inode.perm() & 0o111 == 0 {
        return Err(Errno::EACCES);
    }
    Ok(0)
}

pub fn ioctl(ctx: &Ctx, fd: i32, req: u32, arg: u64) -> KResult<u64> {
    const FIOCLEX: u32 = 0x5451;
    const FIONCLEX: u32 = 0x5450;
    let f = file(ctx, fd)?;
    match req {
        FIOCLEX | FIONCLEX => {
            ctx.process().files.lock().set_cloexec(fd, req == FIOCLEX)?;
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
    files.set(new as usize, f, flags & O_CLOEXEC != 0);
    Ok(new as u64)
}

pub fn fcntl(ctx: &Ctx, fd: i32, cmd: u32, arg: u64) -> KResult<u64> {
    const F_DUPFD: u32 = 0;
    const F_GETFD: u32 = 1;
    const F_SETFD: u32 = 2;
    const F_GETFL: u32 = 3;
    const F_SETFL: u32 = 4;
    const F_DUPFD_CLOEXEC: u32 = 1030;
    const FD_CLOEXEC: u64 = 1;
    let mut files = ctx.process().files.lock();
    let f = files.get(fd)?;
    match cmd {
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
        _ => Err(Errno::EINVAL),
    }
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
    let inode = resolve(ctx, AT_FDCWD, &path)?;
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
    let path = ctx.process().cwd.lock().path.clone();
    let len = path.len() as u64 + 1;
    if size < len {
        return Err(Errno::ERANGE);
    }
    let mut bytes = path.into_bytes();
    bytes.push(0);
    ctx.mm().copy_to(buf, &bytes)?;
    Ok(len)
}

fn set_cwd(ctx: &Ctx, inode: Arc<dyn Inode>, path: alloc::string::String) -> KResult<u64> {
    if inode.file_type() != FileType::Directory {
        return Err(Errno::ENOTDIR);
    }
    let mut cwd = ctx.process().cwd.lock();
    cwd.inode = inode;
    cwd.path = path;
    Ok(0)
}

pub fn chdir(ctx: &Ctx, path: u64) -> KResult<u64> {
    let path = path_arg(ctx, path)?;
    let inode = resolve(ctx, AT_FDCWD, &path)?;
    let base = ctx.process().cwd.lock().path.clone();
    set_cwd(ctx, inode, fs::normalize(&base, &path))
}

pub fn fchdir(ctx: &Ctx, fd: i32) -> KResult<u64> {
    let _ = (ctx, fd);
    // Needs a path per open directory: Phase 3, with getdents users.
    Err(Errno::ENOSYS)
}

pub fn mkdirat(ctx: &Ctx, dirfd: i32, path: u64, mode: u32) -> KResult<u64> {
    let path = path_arg(ctx, path)?;
    let (dir, name) = resolve_parent(ctx, dirfd, &path)?;
    let umask = ctx
        .process()
        .umask
        .load(core::sync::atomic::Ordering::Relaxed);
    dir.create(&name, FileType::Directory, mode & 0o7777 & !umask)?;
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
        let target = resolve(ctx, dirfd, &path)?;
        return Err(if target.file_type() == FileType::Directory {
            Errno::EISDIR
        } else {
            Errno::ENOTDIR
        });
    }
    let (dir, name) = resolve_parent(ctx, dirfd, &path)?;
    dir.remove(&name, dir_wanted)?;
    Ok(0)
}

pub fn readlinkat(ctx: &Ctx, dirfd: i32, path: u64) -> KResult<u64> {
    let path = path_arg(ctx, path)?;
    // There are no symbolic links yet: anything that exists is "not one".
    resolve(ctx, dirfd, &path)?;
    Err(Errno::EINVAL)
}

/// `getdents64`: the file offset counts entries already returned
/// ("." and ".." first).
pub fn getdents64(ctx: &Ctx, fd: i32, buf: u64, count: u64) -> KResult<u64> {
    const DT_CHR: u8 = 2;
    const DT_DIR: u8 = 4;
    const DT_REG: u8 = 8;
    let f = file(ctx, fd)?;
    let dir = &f.inode;
    let mut list: Vec<(alloc::string::String, u64, u8)> = vec![
        (".".into(), dir.ino(), DT_DIR),
        (
            "..".into(),
            dir.parent().map_or(dir.ino(), |p| p.ino()),
            DT_DIR,
        ),
    ];
    for (name, inode) in dir.entries()? {
        let t = match inode.file_type() {
            FileType::Directory => DT_DIR,
            FileType::Regular => DT_REG,
            FileType::CharDevice => DT_CHR,
        };
        list.push((name, inode.ino(), t));
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
