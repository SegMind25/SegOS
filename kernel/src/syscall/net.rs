//! Socket system calls: they find the socket behind a descriptor and pass
//! the call to its address family (`net/`).

use super::Ctx;
use crate::abi::{Errno, KResult};
use crate::fs::File;
use crate::net::socket::*;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;

const SOCKADDR_MAX: u64 = 128;
const MSG_CMSG_CLOEXEC: u32 = 0x4000_0000;
const SCM_RIGHTS: u32 = 1;
const SCM_CREDENTIALS: u32 = 2;

fn sock(ctx: &Ctx, fd: i32) -> KResult<(Arc<File>, Arc<dyn Socket>)> {
    let f = ctx.process().files.lock().get(fd)?;
    let s = socket_of(&f.inode)?;
    Ok((f, s))
}

fn read_addr(ctx: &Ctx, addr: u64, len: u64) -> KResult<Vec<u8>> {
    if !(2..=SOCKADDR_MAX).contains(&len) {
        return Err(Errno::EINVAL);
    }
    let mut b = vec![0u8; len as usize];
    ctx.mm().copy_from(addr, &mut b)?;
    Ok(b)
}

/// Writes an address back the way Linux does: truncated to the caller's
/// buffer, with the full length in `*len`.
fn write_addr(ctx: &Ctx, addr: u64, len_ptr: u64, a: &[u8]) -> KResult<()> {
    if addr == 0 || len_ptr == 0 {
        return Ok(());
    }
    let cap: u32 = ctx.mm().read(len_ptr)?;
    let n = a.len().min(cap as usize);
    ctx.mm().copy_to(addr, &a[..n])?;
    ctx.mm().write(len_ptr, &(a.len() as u32))
}

fn new_fd(ctx: &Ctx, s: Arc<dyn Socket>, flags: u32) -> KResult<u64> {
    use crate::abi::open::*;
    let status = O_RDWR
        | if flags & SOCK_NONBLOCK != 0 {
            O_NONBLOCK
        } else {
            0
        };
    let file = File::new(SocketFile::inode(s), status);
    let fd = ctx
        .process()
        .files
        .lock()
        .alloc(0, file, flags & SOCK_CLOEXEC != 0)?;
    Ok(fd as u64)
}

fn create(domain: u32, ty: u32, protocol: u32) -> KResult<Arc<dyn Socket>> {
    match domain as u16 {
        AF_UNIX => crate::net::unix::new_socket(ty),
        AF_INET if !crate::proc::ns::current_net().is_initial() => {
            crate::net::isolated::new(ty, protocol)
        }
        AF_INET => crate::net::inet_socket(ty, protocol),
        AF_NETLINK => crate::net::netlink_socket(ty, protocol),
        AF_INET6 => Err(Errno::EAFNOSUPPORT),
        _ => Err(Errno::EAFNOSUPPORT),
    }
}

pub fn socket(ctx: &Ctx, domain: u32, ty: u32, protocol: u32) -> KResult<u64> {
    let flags = ty & (SOCK_NONBLOCK | SOCK_CLOEXEC);
    let s = create(domain, ty & !flags, protocol)?;
    new_fd(ctx, s, flags)
}

pub fn socketpair(ctx: &Ctx, domain: u32, ty: u32, _protocol: u32, sv: u64) -> KResult<u64> {
    if domain as u16 != AF_UNIX {
        return Err(Errno::EOPNOTSUPP);
    }
    let flags = ty & (SOCK_NONBLOCK | SOCK_CLOEXEC);
    let (a, b) = crate::net::unix::pair(ty & !flags)?;
    let fa = new_fd(ctx, a, flags)?;
    let fb = match new_fd(ctx, b, flags) {
        Ok(f) => f,
        Err(e) => {
            let _ = ctx.process().files.lock().close(fa as i32);
            return Err(e);
        }
    };
    ctx.mm().write(sv, &[fa as i32, fb as i32])?;
    Ok(0)
}

pub fn bind(ctx: &Ctx, fd: i32, addr: u64, len: u64) -> KResult<u64> {
    let (_, s) = sock(ctx, fd)?;
    s.bind(&read_addr(ctx, addr, len)?)?;
    Ok(0)
}

pub fn listen(ctx: &Ctx, fd: i32, backlog: u32) -> KResult<u64> {
    sock(ctx, fd)?.1.listen(backlog.min(4096))?;
    Ok(0)
}

pub fn accept4(ctx: &Ctx, fd: i32, addr: u64, len: u64, flags: u32) -> KResult<u64> {
    if flags & !(SOCK_NONBLOCK | SOCK_CLOEXEC) != 0 {
        return Err(Errno::EINVAL);
    }
    let (f, s) = sock(ctx, fd)?;
    let (conn, peer) = s.accept(f.nonblock())?;
    write_addr(ctx, addr, len, &peer)?;
    new_fd(ctx, conn, flags)
}

pub fn connect(ctx: &Ctx, fd: i32, addr: u64, len: u64) -> KResult<u64> {
    let (f, s) = sock(ctx, fd)?;
    s.connect(&read_addr(ctx, addr, len)?, f.nonblock())?;
    Ok(0)
}

pub fn getsockname(ctx: &Ctx, fd: i32, addr: u64, len: u64) -> KResult<u64> {
    let a = sock(ctx, fd)?.1.local_addr()?;
    write_addr(ctx, addr, len, &a)?;
    Ok(0)
}

pub fn getpeername(ctx: &Ctx, fd: i32, addr: u64, len: u64) -> KResult<u64> {
    let a = sock(ctx, fd)?.1.peer_addr()?;
    write_addr(ctx, addr, len, &a)?;
    Ok(0)
}

pub fn shutdown(ctx: &Ctx, fd: i32, how: u32) -> KResult<u64> {
    sock(ctx, fd)?.1.shutdown(how)?;
    Ok(0)
}

pub fn setsockopt(ctx: &Ctx, fd: i32, level: u32, name: u32, val: u64, len: u64) -> KResult<u64> {
    let s = sock(ctx, fd)?.1;
    if len > 4096 {
        return Err(Errno::EINVAL);
    }
    let mut v = vec![0u8; len as usize];
    ctx.mm().copy_from(val, &mut v)?;
    s.set_option(level, name, &v)?;
    Ok(0)
}

pub fn getsockopt(
    ctx: &Ctx,
    fd: i32,
    level: u32,
    name: u32,
    val: u64,
    len_ptr: u64,
) -> KResult<u64> {
    let s = sock(ctx, fd)?.1;
    let v = s.get_option(level, name)?;
    let cap: u32 = ctx.mm().read(len_ptr)?;
    let n = v.len().min(cap as usize);
    ctx.mm().copy_to(val, &v[..n])?;
    ctx.mm().write(len_ptr, &(n as u32))?;
    Ok(0)
}

fn sigpipe(flags: u32, r: KResult<usize>) -> KResult<usize> {
    if r == Err(Errno::EPIPE) && flags & MSG_NOSIGNAL == 0 {
        let task = crate::task::current();
        if let Some(u) = task.user() {
            crate::proc::signal::send(
                &u.process,
                crate::proc::signo::SIGPIPE,
                crate::proc::signal::SigInfo::kernel(),
            );
        }
    }
    r
}

pub fn sendto(
    ctx: &Ctx,
    fd: i32,
    buf: u64,
    len: u64,
    flags: u32,
    addr: u64,
    alen: u64,
) -> KResult<u64> {
    let (f, s) = sock(ctx, fd)?;
    let mut data = vec![0u8; len.min(1 << 20) as usize];
    ctx.mm().copy_from(buf, &mut data)?;
    let to = if addr != 0 {
        Some(read_addr(ctx, addr, alen)?)
    } else {
        None
    };
    let nonblock = f.nonblock() || flags & MSG_DONTWAIT != 0;
    let r = s.send(&data, to.as_deref(), flags, nonblock, Vec::new());
    sigpipe(flags, r).map(|n| n as u64)
}

pub fn recvfrom(
    ctx: &Ctx,
    fd: i32,
    buf: u64,
    len: u64,
    flags: u32,
    addr: u64,
    alen: u64,
) -> KResult<u64> {
    let (f, s) = sock(ctx, fd)?;
    let mut data = vec![0u8; len.min(1 << 20) as usize];
    let nonblock = f.nonblock() || flags & MSG_DONTWAIT != 0;
    let r = s.recv(&mut data, flags, nonblock)?;
    ctx.mm().copy_to(buf, &data[..r.len])?;
    if let Some(from) = &r.from {
        write_addr(ctx, addr, alen, from)?;
    } else if addr != 0 && alen != 0 {
        ctx.mm().write(alen, &0u32)?;
    }
    Ok(if flags & MSG_TRUNC != 0 {
        r.full_len
    } else {
        r.len
    } as u64)
}

/// The fields of a `struct msghdr`.
struct MsgHdr {
    name: u64,
    namelen: u32,
    iov: u64,
    iovlen: u64,
    control: u64,
    controllen: u64,
}

fn read_msghdr(ctx: &Ctx, msg: u64) -> KResult<MsgHdr> {
    let mut b = [0u8; 56];
    ctx.mm().copy_from(msg, &mut b)?;
    let u64_at = |o: usize| u64::from_le_bytes(b[o..o + 8].try_into().unwrap());
    Ok(MsgHdr {
        name: u64_at(0),
        namelen: u64_at(8) as u32,
        iov: u64_at(16),
        iovlen: u64_at(24),
        control: u64_at(32),
        controllen: u64_at(40),
    })
}

pub fn sendmsg(ctx: &Ctx, fd: i32, msg: u64, flags: u32) -> KResult<u64> {
    let (f, s) = sock(ctx, fd)?;
    let h = read_msghdr(ctx, msg)?;
    let mut data = Vec::new();
    for v in super::fs::iovecs(ctx, h.iov, h.iovlen)? {
        let start = data.len();
        data.resize(start + v.len.min(1 << 20) as usize, 0);
        ctx.mm().copy_from(v.base, &mut data[start..])?;
    }
    // Control messages: descriptors to pass (SCM_RIGHTS).
    let mut rights = Vec::new();
    if h.control != 0 && h.controllen >= 16 {
        let mut c = vec![0u8; h.controllen.min(4096) as usize];
        ctx.mm().copy_from(h.control, &mut c)?;
        let mut o = 0;
        while o + 16 <= c.len() {
            let clen = u64::from_le_bytes(c[o..o + 8].try_into().unwrap()) as usize;
            let level = u32::from_le_bytes(c[o + 8..o + 12].try_into().unwrap());
            let ty = u32::from_le_bytes(c[o + 12..o + 16].try_into().unwrap());
            if clen < 16 || o + clen > c.len() {
                return Err(Errno::EINVAL);
            }
            if level == SOL_SOCKET && ty == SCM_RIGHTS {
                let files = ctx.process().files.lock();
                for fdb in c[o + 16..o + clen].chunks_exact(4) {
                    rights.push(files.get(i32::from_le_bytes(fdb.try_into().unwrap()))?);
                }
            }
            o += clen.next_multiple_of(8);
        }
    }
    let to = if h.name != 0 && h.namelen != 0 {
        Some(read_addr(ctx, h.name, h.namelen as u64)?)
    } else {
        None
    };
    let nonblock = f.nonblock() || flags & MSG_DONTWAIT != 0;
    let r = s.send(&data, to.as_deref(), flags, nonblock, rights);
    sigpipe(flags, r).map(|n| n as u64)
}

pub fn recvmsg(ctx: &Ctx, fd: i32, msg: u64, flags: u32) -> KResult<u64> {
    let (f, s) = sock(ctx, fd)?;
    let h = read_msghdr(ctx, msg)?;
    let iovs = super::fs::iovecs(ctx, h.iov, h.iovlen)?;
    let total: u64 = iovs.iter().map(|v| v.len).sum();
    let mut data = vec![0u8; total.min(1 << 20) as usize];
    let nonblock = f.nonblock() || flags & MSG_DONTWAIT != 0;
    let r = s.recv(&mut data, flags, nonblock)?;
    let mut done = 0;
    for v in &iovs {
        if done >= r.len {
            break;
        }
        let n = (v.len as usize).min(r.len - done);
        ctx.mm().copy_to(v.base, &data[done..done + n])?;
        done += n;
    }
    let mut out_flags = 0u32;
    if r.full_len > r.len {
        out_flags |= MSG_TRUNC;
    }
    // The sender's address.
    if h.name != 0 {
        let a = r.from.clone().unwrap_or_default();
        let n = a.len().min(h.namelen as usize);
        ctx.mm().copy_to(h.name, &a[..n])?;
        ctx.mm().write(msg + 8, &(a.len() as u32))?;
    }
    // Control messages: received descriptors become new ones here.
    let mut control = Vec::new();
    if !r.rights.is_empty() {
        let mut fds = Vec::new();
        let cloexec = flags & MSG_CMSG_CLOEXEC != 0;
        let mut files = ctx.process().files.lock();
        for file in r.rights {
            fds.push(files.alloc(0, file, cloexec)?);
        }
        drop(files);
        let len = 16 + 4 * fds.len();
        control.extend_from_slice(&(len as u64).to_le_bytes());
        control.extend_from_slice(&SOL_SOCKET.to_le_bytes());
        control.extend_from_slice(&SCM_RIGHTS.to_le_bytes());
        for fd in fds {
            control.extend_from_slice(&fd.to_le_bytes());
        }
        control.resize(len.next_multiple_of(8), 0);
    }
    if let Some((pid, uid, gid)) = r.creds
        && passcred(&s)
    {
        control.extend_from_slice(&28u64.to_le_bytes());
        control.extend_from_slice(&SOL_SOCKET.to_le_bytes());
        control.extend_from_slice(&SCM_CREDENTIALS.to_le_bytes());
        for v in [pid, uid, gid] {
            control.extend_from_slice(&v.to_le_bytes());
        }
        control.resize(control.len().next_multiple_of(8), 0);
    }
    let n = control.len().min(h.controllen as usize);
    if n < control.len() {
        out_flags |= MSG_CTRUNC;
    }
    if n > 0 {
        ctx.mm().copy_to(h.control, &control[..n])?;
    }
    ctx.mm().write(msg + 40, &(n as u64))?;
    ctx.mm().write(msg + 48, &out_flags)?;
    Ok(if flags & MSG_TRUNC != 0 {
        r.full_len
    } else {
        r.len
    } as u64)
}

fn passcred(s: &Arc<dyn Socket>) -> bool {
    const SO_PASSCRED: u32 = 16;
    s.get_option(SOL_SOCKET, SO_PASSCRED)
        .ok()
        .and_then(|v| v.first().copied())
        .is_some_and(|b| b != 0)
}

/// `sendmmsg`: `sendmsg` for each `struct mmsghdr` (64 bytes: the msghdr,
/// then the byte count written back). Stops at the first error after at
/// least one message went.
pub fn sendmmsg(ctx: &Ctx, fd: i32, vec: u64, n: u32, flags: u32) -> KResult<u64> {
    let mut done = 0u64;
    for i in 0..n.min(1024) as u64 {
        let at = vec + i * 64;
        match sendmsg(ctx, fd, at, flags) {
            Ok(len) => {
                ctx.mm().write(at + 56, &(len as u32))?;
                done += 1;
            }
            Err(e) if done == 0 => return Err(e),
            Err(_) => break,
        }
    }
    Ok(done)
}

/// `recvmmsg` (the timeout is not supported; MSG_WAITFORONE is how C
/// libraries use it): after the first message, the rest only if ready.
pub fn recvmmsg(ctx: &Ctx, fd: i32, vec: u64, n: u32, flags: u32) -> KResult<u64> {
    const MSG_WAITFORONE: u32 = 0x10000;
    let mut done = 0u64;
    for i in 0..n.min(1024) as u64 {
        let at = vec + i * 64;
        let f = if done > 0 && flags & MSG_WAITFORONE != 0 {
            (flags & !MSG_WAITFORONE) | MSG_DONTWAIT
        } else {
            flags & !MSG_WAITFORONE
        };
        match recvmsg(ctx, fd, at, f) {
            Ok(len) => {
                ctx.mm().write(at + 56, &(len as u32))?;
                done += 1;
            }
            Err(e) if done == 0 => return Err(e),
            Err(_) => break,
        }
    }
    Ok(done)
}
