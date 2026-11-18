//! Event descriptor system calls: eventfd, timerfd, signalfd, epoll,
//! inotify and fanotify (see `fs::event`).

use super::Ctx;
use crate::abi::open::{O_CLOEXEC, O_NONBLOCK, O_RDONLY, O_RDWR};
use crate::abi::{Errno, KResult, Timespec};
use crate::fs::event::{self, Epoll, EventFd, Fanotify, Inotify, SignalFd, TimerFd};
use crate::fs::{self, File, FileType, Inode};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::Ordering;

fn install(ctx: &Ctx, inode: Arc<dyn Inode>, access: u32, flags: u32) -> KResult<u64> {
    let file = File::new(inode, access | (flags & O_NONBLOCK));
    let fd = ctx
        .process()
        .files
        .lock()
        .alloc(0, file, flags & O_CLOEXEC != 0)?;
    Ok(fd as u64)
}

fn file(ctx: &Ctx, fd: i32) -> KResult<Arc<File>> {
    ctx.process().files.lock().get(fd)
}

/// The object of kind `T` behind descriptor `fd`.
fn object<T: 'static>(f: &Arc<File>) -> KResult<&T> {
    f.inode
        .as_any()
        .and_then(|a| a.downcast_ref::<T>())
        .ok_or(Errno::EINVAL)
}

/// `eventfd(initval)` (flags 0) and `eventfd2(initval, flags)`.
pub fn eventfd(ctx: &Ctx, initval: u32, flags: u32) -> KResult<u64> {
    if flags & !(event::EFD_SEMAPHORE | O_CLOEXEC | O_NONBLOCK) != 0 {
        return Err(Errno::EINVAL);
    }
    install(ctx, EventFd::create(initval, flags), O_RDWR, flags)
}

pub fn timerfd_create(ctx: &Ctx, clock: u32, flags: u32) -> KResult<u64> {
    if flags & !(O_CLOEXEC | O_NONBLOCK) != 0 {
        return Err(Errno::EINVAL);
    }
    install(ctx, TimerFd::create(clock)?, O_RDWR, flags)
}

fn write_itimerspec(ctx: &Ctx, addr: u64, (interval, value): event::ITimerSpec) -> KResult<()> {
    let ns = crate::time::NS_PER_SEC;
    let words: [i64; 4] = [
        (interval / ns) as i64,
        (interval % ns) as i64,
        (value / ns) as i64,
        (value % ns) as i64,
    ];
    ctx.mm().write(addr, &words)
}

pub fn timerfd_settime(ctx: &Ctx, fd: i32, flags: u32, new: u64, old: u64) -> KResult<u64> {
    if flags & !(event::TFD_TIMER_ABSTIME | event::TFD_TIMER_CANCEL_ON_SET) != 0 {
        return Err(Errno::EINVAL);
    }
    let f = file(ctx, fd)?;
    let t = object::<TimerFd>(&f)?;
    let interval: Timespec = ctx.mm().read(new)?;
    let value: Timespec = ctx.mm().read(new + 16)?;
    let interval = event::ns_of_timespec(interval.tv_sec, interval.tv_nsec)?;
    let value = event::ns_of_timespec(value.tv_sec, value.tv_nsec)?;
    let prev = t.set(flags, interval, value);
    if old != 0 {
        write_itimerspec(ctx, old, prev)?;
    }
    Ok(0)
}

pub fn timerfd_gettime(ctx: &Ctx, fd: i32, cur: u64) -> KResult<u64> {
    let f = file(ctx, fd)?;
    let t = object::<TimerFd>(&f)?;
    write_itimerspec(ctx, cur, t.get())?;
    Ok(0)
}

/// `signalfd(fd, mask, size)` (flags 0) and `signalfd4`.
pub fn signalfd(ctx: &Ctx, fd: i32, mask: u64, size: u64, flags: u32) -> KResult<u64> {
    if size != 8 || flags & !(O_CLOEXEC | O_NONBLOCK) != 0 {
        return Err(Errno::EINVAL);
    }
    let m: u64 = ctx.mm().read(mask)?;
    if fd == -1 {
        return install(ctx, SignalFd::create(m), O_RDONLY, flags);
    }
    let f = file(ctx, fd)?;
    object::<SignalFd>(&f)?.mask.store(m, Ordering::Relaxed);
    Ok(fd as u64)
}

pub fn epoll_create(ctx: &Ctx, size: i32) -> KResult<u64> {
    if size <= 0 {
        return Err(Errno::EINVAL);
    }
    install(ctx, Epoll::create(), O_RDWR, 0)
}

pub fn epoll_create1(ctx: &Ctx, flags: u32) -> KResult<u64> {
    if flags & !O_CLOEXEC != 0 {
        return Err(Errno::EINVAL);
    }
    install(ctx, Epoll::create(), O_RDWR, flags)
}

pub fn epoll_ctl(ctx: &Ctx, epfd: i32, op: u32, fd: i32, event: u64) -> KResult<u64> {
    let ep_file = file(ctx, epfd)?;
    let target = file(ctx, fd)?;
    let ep = object::<Epoll>(&ep_file)?;
    let (events, data) = if op == event::EPOLL_CTL_DEL {
        (0, 0)
    } else {
        // struct epoll_event is packed: u32 events, u64 data.
        let mut b = [0u8; 12];
        ctx.mm().copy_from(event, &mut b)?;
        (
            u32::from_le_bytes(b[0..4].try_into().unwrap()),
            u64::from_le_bytes(b[4..12].try_into().unwrap()),
        )
    };
    ep.ctl(op, fd, &target, events, data)?;
    Ok(0)
}

/// `epoll_wait`, `epoll_pwait` and `epoll_pwait2`: `timeout` in ns (None
/// for ever), `sigmask` a pointer to a temporary signal mask.
pub fn epoll_wait(
    ctx: &Ctx,
    epfd: i32,
    events: u64,
    max: i32,
    timeout: Option<u64>,
    sigmask: u64,
) -> KResult<u64> {
    if max <= 0 || max > i32::MAX / 12 {
        return Err(Errno::EINVAL);
    }
    let ep_file = file(ctx, epfd)?;
    let ep = object::<Epoll>(&ep_file)?;
    if sigmask != 0 {
        let m: u64 = ctx.mm().read(sigmask)?;
        ctx.thread().sig.suspend_mask(m);
    }
    let deadline = timeout.map(|t| crate::time::monotonic_ns().saturating_add(t));
    let _timer = deadline
        .filter(|_| timeout != Some(0))
        .map(crate::time::wake_at);
    let timed_out = || deadline.is_some_and(|d| crate::time::monotonic_ns() >= d);
    let ready = loop {
        let seen = fs::POLL_EVENTS.load(Ordering::Acquire);
        let ready = ep.collect(max as usize);
        if !ready.is_empty() || timed_out() {
            break ready;
        }
        // epoll_wait is never restarted after a handler (Linux).
        fs::POLL_WAIT
            .wait_interruptible(|| fs::POLL_EVENTS.load(Ordering::Acquire) != seen || timed_out())
            .map_err(|_| Errno::EINTR)?;
    };
    let mut out = Vec::with_capacity(ready.len() * 12);
    for (ev, data) in &ready {
        out.extend_from_slice(&ev.to_le_bytes());
        out.extend_from_slice(&data.to_le_bytes());
    }
    ctx.mm().copy_to(events, &out)?;
    Ok(ready.len() as u64)
}

/// The timeout of epoll_wait/epoll_pwait (ms, negative for ever).
pub fn ms_timeout(ms: i32) -> Option<u64> {
    (ms >= 0).then(|| ms as u64 * 1_000_000)
}

/// The timeout of epoll_pwait2 (a timespec pointer, NULL for ever).
pub fn ts_timeout(ctx: &Ctx, ts: u64) -> KResult<Option<u64>> {
    if ts == 0 {
        return Ok(None);
    }
    let t: Timespec = ctx.mm().read(ts)?;
    event::ns_of_timespec(t.tv_sec, t.tv_nsec).map(Some)
}

pub fn inotify_init(ctx: &Ctx, flags: u32) -> KResult<u64> {
    if flags & !(O_CLOEXEC | O_NONBLOCK) != 0 {
        return Err(Errno::EINVAL);
    }
    install(ctx, Inotify::create(), O_RDONLY, flags)
}

pub fn inotify_add_watch(ctx: &Ctx, fd: i32, path: u64, mask: u32) -> KResult<u64> {
    let f = file(ctx, fd)?;
    let ino = object::<Inotify>(&f)?;
    let path = super::path_arg(ctx, path)?;
    let cwd = ctx.process().cwd();
    let target = if mask & event::in_mask::IN_DONT_FOLLOW != 0 {
        fs::lookup_nofollow(&cwd, &path)?
    } else {
        fs::lookup(&cwd, &path)?
    };
    Ok(ino.add_watch(&target, mask)? as u64)
}

pub fn inotify_rm_watch(ctx: &Ctx, fd: i32, wd: i32) -> KResult<u64> {
    let f = file(ctx, fd)?;
    object::<Inotify>(&f)?.rm_watch(wd)?;
    Ok(0)
}

/// `fanotify_init`: creates a notification group. Only FAN_CLASS_NOTIF is
/// meaningful here — permission events are never generated, so a CONTENT or
/// PRE_CONTENT group behaves exactly like a NOTIF one.
pub fn fanotify_init(ctx: &Ctx, flags: u32, event_f_flags: u32) -> KResult<u64> {
    use event::fan_init::*;
    if flags & !ALL != 0 {
        return Err(Errno::EINVAL);
    }
    // The two class bits are mutually exclusive; NOTIF is zero.
    if flags & CLASS_MASK == CLASS_MASK {
        return Err(Errno::EINVAL);
    }
    let access = event_f_flags & 3;
    if access > 2 {
        return Err(Errno::EINVAL);
    }
    let mut oflags = if flags & FAN_NONBLOCK != 0 {
        O_NONBLOCK
    } else {
        0
    };
    if flags & FAN_CLOEXEC != 0 || event_f_flags & O_CLOEXEC != 0 {
        oflags |= O_CLOEXEC;
    }
    install(ctx, Fanotify::create(), access, oflags)
}

/// `fanotify_mark`: adds or removes a mark on the file at `dirfd`/`path`.
pub fn fanotify_mark(
    ctx: &Ctx,
    fd: i32,
    flags: u32,
    mask: u64,
    dirfd: i32,
    path: u64,
) -> KResult<u64> {
    use event::fan_mark::*;
    let f = file(ctx, fd)?;
    let fan = object::<Fanotify>(&f)?;
    if flags & !ALL != 0 {
        return Err(Errno::EINVAL);
    }
    if flags & FLUSH != 0 {
        // A flush needs no path; the type bits are the only other flags
        // Linux accepts with it.
        if flags & !(FLUSH | MOUNT | FILESYSTEM) != 0 {
            return Err(Errno::EINVAL);
        }
        if mask != 0 {
            return Err(Errno::EINVAL);
        }
        fan.flush();
        return Ok(0);
    }
    let add = flags & ADD != 0;
    let remove = flags & REMOVE != 0;
    if add == remove {
        return Err(Errno::EINVAL);
    }
    if mask == 0 || mask & !event::fan_mask::FAN_ALL != 0 {
        return Err(Errno::EINVAL);
    }
    let path = super::path_arg(ctx, path)?;
    let base = super::fs::dir_of(ctx, dirfd, &path)?;
    let (target, _) = fs::resolve(&base, &path, flags & DONT_FOLLOW == 0)?;
    if flags & ONLYDIR != 0 && target.file_type() != FileType::Directory {
        return Err(Errno::ENOTDIR);
    }
    if add {
        fan.add_mark(&target, flags, mask)?;
    } else {
        fan.rm_mark(&target, flags, mask)?;
    }
    Ok(0)
}
