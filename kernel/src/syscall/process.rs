//! Process, thread and signal system calls.

use super::{Ctx, path_arg};
use crate::abi::{Errno, KResult};
use crate::hal::idt::TrapFrame;
use crate::hal::x86;
use crate::proc::signal::{self, SigAction, SigInfo, UNBLOCKABLE, signo};
use crate::proc::{self, wait_flags};
use crate::task::wait::WaitQueue;
use alloc::sync::Arc;
use core::sync::atomic::Ordering;

/// `exit`: ends the calling thread (the process ends with its last one).
pub fn exit(ctx: &Ctx, code: i32) -> KResult<u64> {
    ctx.thread().request_thread_exit((code & 0xff) << 8);
    Ok(0)
}

/// `exit_group`: ends every thread of the process.
pub fn exit_group(ctx: &Ctx, code: i32) -> KResult<u64> {
    ctx.thread().request_exit((code & 0xff) << 8);
    Ok(0)
}

pub fn clone(
    ctx: &Ctx,
    frame: &TrapFrame,
    flags: u64,
    stack: u64,
    ptid: u64,
    ctid: u64,
    tls: u64,
) -> KResult<u64> {
    proc::clone(ctx.thread(), frame, flags, stack, ptid, ctid, tls).map(|pid| pid as u64)
}

pub fn execve(ctx: &Ctx, frame: &mut TrapFrame, path: u64, argv: u64, envp: u64) -> KResult<u64> {
    let path = path_arg(ctx, path)?;
    let argv = proc::read_string_array(ctx.mm(), argv)?;
    let envp = proc::read_string_array(ctx.mm(), envp)?;
    if ctx.process().thread_count() > 1 {
        // The other threads go first, unless the program obviously cannot
        // be run (a failed execve must leave the process as it was).
        let cwd = ctx.process().cwd.lock().clone();
        let inode = crate::fs::lookup(&cwd, &path)?;
        if inode.file_type() != crate::fs::FileType::Regular || inode.perm() & 0o111 == 0 {
            return Err(Errno::EACCES);
        }
        proc::kill_other_threads()?;
    }
    proc::exec::execve(ctx.thread(), frame, &path, argv, envp)?;
    Ok(0)
}

pub fn wait4(ctx: &Ctx, pid: i32, status: u64, options: u32, rusage: u64) -> KResult<u64> {
    use wait_flags::*;
    if options & !(WNOHANG | WUNTRACED | WCONTINUED | 0xe000_0000) != 0 {
        return Err(Errno::EINVAL);
    }
    match proc::wait(ctx.process(), pid, options)? {
        Some((pid, st)) => {
            if status != 0 {
                ctx.mm().write(status, &st)?;
            }
            if rusage != 0 {
                ctx.mm().copy_to(rusage, &[0u8; 144])?;
            }
            Ok(pid as u64)
        }
        None => Ok(0),
    }
}

/// `waitid(idtype, id, infop, options)`.
pub fn waitid(ctx: &Ctx, idtype: u32, id: u32, infop: u64, options: u32) -> KResult<u64> {
    const P_ALL: u32 = 0;
    const P_PID: u32 = 1;
    const P_PGID: u32 = 2;
    const WSTOPPED: u32 = 2;
    const WEXITED: u32 = 4;
    let pid = match idtype {
        P_ALL => -1,
        P_PID => id as i32,
        P_PGID => -(id as i32),
        _ => return Err(Errno::EINVAL),
    };
    if options & (WEXITED | WSTOPPED | wait_flags::WCONTINUED) == 0 {
        return Err(Errno::EINVAL);
    }
    let mut opts = options & (wait_flags::WNOHANG | wait_flags::WCONTINUED);
    if options & WSTOPPED != 0 {
        opts |= wait_flags::WUNTRACED;
    }
    let mut info = [0u8; 128];
    if let Some((cpid, st)) = proc::wait(ctx.process(), pid, opts)? {
        let (code, value): (i32, i32) = match st {
            0xffff => (6, signo::SIGCONT),                 // CLD_CONTINUED
            s if s & 0xff == 0x7f => (5, (s >> 8) & 0xff), // CLD_STOPPED
            s if s & 0x7f == 0 => (1, (s >> 8) & 0xff),    // CLD_EXITED
            s => (2, s & 0x7f),                            // CLD_KILLED
        };
        info[0..4].copy_from_slice(&signo::SIGCHLD.to_le_bytes());
        info[8..12].copy_from_slice(&code.to_le_bytes());
        info[16..20].copy_from_slice(&cpid.to_le_bytes());
        info[24..28].copy_from_slice(&value.to_le_bytes());
    }
    if infop != 0 {
        ctx.mm().copy_to(infop, &info)?;
    }
    Ok(0)
}

/// kill(pid, sig), tkill(tid, sig), tgkill(tgid, tid, sig).
pub fn kill(ctx: &Ctx, a: [u64; 6], nr: u64) -> KResult<u64> {
    let me = ctx.process();
    if nr != 62 {
        // tkill(tid, sig), tgkill(tgid, tid, sig): one thread.
        let (tgid, tid, sig) = if nr == 200 {
            (None, a[0] as i32, a[1] as i32)
        } else {
            (Some(a[0] as i32), a[1] as i32, a[2] as i32)
        };
        if tid <= 0 || tgid.is_some_and(|g| g <= 0) || !(0..=signal::NSIG as i32).contains(&sig) {
            return Err(Errno::EINVAL);
        }
        let t = proc::find_thread(tid as u32).ok_or(Errno::ESRCH)?;
        if let Some(g) = tgid
            && t.user().is_none_or(|u| u.process.pid != g as u32)
        {
            return Err(Errno::ESRCH);
        }
        if sig != 0 {
            signal::send_thread(&t, sig, SigInfo::tkill(me.pid));
        }
        return Ok(0);
    }
    let (target, sig, info) = (a[0] as i32, a[1] as i32, SigInfo::user(me.pid));
    if !(0..=signal::NSIG as i32).contains(&sig) {
        return Err(Errno::EINVAL);
    }
    let send = |p: &Arc<proc::Process>| {
        if sig != 0 {
            signal::send(p, sig, info);
        }
    };
    match target {
        t if t > 0 => {
            let p = proc::lookup(t as u32).ok_or(Errno::ESRCH)?;
            send(&p);
        }
        0 => {
            if sig != 0 {
                signal::send_to_group(me.pgid(), sig, info)?;
            }
        }
        -1 => {
            let all: alloc::vec::Vec<_> = proc::all().into_iter().filter(|p| p.pid != 1).collect();
            if all.is_empty() {
                return Err(Errno::ESRCH);
            }
            all.iter().for_each(send);
        }
        t => {
            let pg = t.unsigned_abs();
            if sig == 0 {
                if !proc::all().iter().any(|p| p.pgid() == pg) {
                    return Err(Errno::ESRCH);
                }
            } else {
                signal::send_to_group(pg, sig, info)?;
            }
        }
    }
    Ok(0)
}

pub fn rt_sigaction(ctx: &Ctx, sig: i32, act: u64, old: u64, setsize: u64) -> KResult<u64> {
    if setsize != 8 || !(1..=signal::NSIG as i32).contains(&sig) {
        return Err(Errno::EINVAL);
    }
    let new = if act != 0 {
        if sig == signo::SIGKILL || sig == signo::SIGSTOP {
            return Err(Errno::EINVAL);
        }
        let mut a: SigAction = ctx.mm().read(act)?;
        a.mask &= !UNBLOCKABLE;
        Some(a)
    } else {
        None
    };
    let prev = {
        let mut table = ctx.process().sigactions.lock();
        let prev = table[sig as usize - 1];
        if let Some(n) = new {
            table[sig as usize - 1] = n;
        }
        prev
    };
    // Setting a signal to "ignore" discards it if pending (POSIX).
    if let Some(n) = new
        && (n.handler == signal::SIG_IGN || (n.handler == signal::SIG_DFL && sig == signo::SIGCHLD))
    {
        signal::discard(ctx.process(), sig);
    }
    if old != 0 {
        ctx.mm().write(old, &prev)?;
    }
    Ok(0)
}

pub fn rt_sigprocmask(ctx: &Ctx, how: i32, set: u64, old: u64, setsize: u64) -> KResult<u64> {
    const SIG_BLOCK: i32 = 0;
    const SIG_UNBLOCK: i32 = 1;
    const SIG_SETMASK: i32 = 2;
    if setsize != 8 {
        return Err(Errno::EINVAL);
    }
    let s = &ctx.thread().sig;
    let prev = s.mask.load(Ordering::Relaxed);
    if set != 0 {
        let v: u64 = ctx.mm().read(set)?;
        let new = match how {
            SIG_BLOCK => prev | v,
            SIG_UNBLOCK => prev & !v,
            SIG_SETMASK => v,
            _ => return Err(Errno::EINVAL),
        };
        // Signals unblocked here are delivered on the way back to user mode.
        s.set_mask(new);
    }
    if old != 0 {
        ctx.mm().write(old, &prev)?;
    }
    Ok(0)
}

pub fn rt_sigpending(ctx: &Ctx, set: u64, size: u64) -> KResult<u64> {
    if size > 8 {
        return Err(Errno::EINVAL);
    }
    let pending = ctx.thread().pending_signals();
    ctx.mm()
        .copy_to(set, &pending.to_le_bytes()[..size as usize])?;
    Ok(0)
}

/// Sleeps until a signal arrives (`pause`, `sigsuspend`).
fn sleep_for_signal() -> Errno {
    static NOBODY: WaitQueue = WaitQueue::new();
    match NOBODY.wait_interruptible(|| false) {
        Ok(()) => Errno::EINTR,
        Err(_) => Errno::EINTR,
    }
}

pub fn rt_sigsuspend(ctx: &Ctx, mask: u64, size: u64) -> KResult<u64> {
    if size != 8 {
        return Err(Errno::EINVAL);
    }
    let m: u64 = ctx.mm().read(mask)?;
    ctx.thread().sig.suspend_mask(m);
    Err(sleep_for_signal())
}

pub fn pause(_ctx: &Ctx) -> KResult<u64> {
    Err(sleep_for_signal())
}

pub fn sigaltstack(ctx: &Ctx, frame: &TrapFrame, new: u64, old: u64) -> KResult<u64> {
    signal::altstack(ctx.thread(), frame, new, old)?;
    Ok(0)
}

pub fn setpgid(ctx: &Ctx, pid: u32, pgid: u32) -> KResult<u64> {
    proc::setpgid(ctx.process(), pid, pgid)?;
    Ok(0)
}

pub fn getpgid(ctx: &Ctx, pid: u32) -> KResult<u64> {
    if pid == 0 {
        return Ok(ctx.process().pgid() as u64);
    }
    Ok(proc::lookup(pid).ok_or(Errno::ESRCH)?.pgid() as u64)
}

pub fn setsid(ctx: &Ctx) -> KResult<u64> {
    proc::setsid(ctx.process()).map(|s| s as u64)
}

pub fn getsid(ctx: &Ctx, pid: u32) -> KResult<u64> {
    if pid == 0 {
        return Ok(ctx.process().sid() as u64);
    }
    Ok(proc::lookup(pid).ok_or(Errno::ESRCH)?.sid() as u64)
}

pub fn arch_prctl(ctx: &Ctx, code: u32, addr: u64) -> KResult<u64> {
    const ARCH_SET_GS: u32 = 0x1001;
    const ARCH_SET_FS: u32 = 0x1002;
    const ARCH_GET_FS: u32 = 0x1003;
    const ARCH_GET_GS: u32 = 0x1004;
    let t = ctx.thread();
    let canonical = addr < 0x0000_8000_0000_0000;
    match code {
        ARCH_SET_FS | ARCH_SET_GS if !canonical => Err(Errno::EPERM),
        ARCH_SET_FS => {
            x86::without_interrupts(|| {
                t.fs_base.store(addr, Ordering::Relaxed);
                unsafe { x86::wrmsr(x86::msr::FS_BASE, addr) };
            });
            Ok(0)
        }
        ARCH_SET_GS => {
            x86::without_interrupts(|| {
                t.gs_base.store(addr, Ordering::Relaxed);
                // In the kernel, the user's GS base is in KERNEL_GS_BASE.
                unsafe { x86::wrmsr(x86::msr::KERNEL_GS_BASE, addr) };
            });
            Ok(0)
        }
        ARCH_GET_FS => {
            ctx.mm().write(addr, &t.fs_base.load(Ordering::Relaxed))?;
            Ok(0)
        }
        ARCH_GET_GS => {
            ctx.mm().write(addr, &t.gs_base.load(Ordering::Relaxed))?;
            Ok(0)
        }
        _ => Err(Errno::EINVAL),
    }
}

pub fn futex(ctx: &Ctx, a: [u64; 6]) -> KResult<u64> {
    proc::futex::futex(ctx.mm(), a)
}

/// `set_robust_list(head, len)`.
pub fn set_robust_list(ctx: &Ctx, head: u64, len: u64) -> KResult<u64> {
    if len != 24 {
        return Err(Errno::EINVAL);
    }
    ctx.thread().robust_list.store(head, Ordering::Relaxed);
    Ok(0)
}

/// `get_robust_list(tid, head_ptr, len_ptr)`.
pub fn get_robust_list(ctx: &Ctx, tid: u32, head: u64, len: u64) -> KResult<u64> {
    let t = if tid == 0 {
        crate::task::current()
    } else {
        proc::find_thread(tid).ok_or(Errno::ESRCH)?
    };
    let u = t.user().ok_or(Errno::ESRCH)?;
    ctx.mm()
        .write(head, &u.robust_list.load(Ordering::Relaxed))?;
    ctx.mm().write(len, &24u64)?;
    Ok(0)
}

/// `rt_sigtimedwait(set, info, timeout, setsize)`: takes a pending signal
/// of `set` (normally blocked ones), waiting for one up to `timeout`.
pub fn rt_sigtimedwait(ctx: &Ctx, set: u64, info: u64, timeout: u64, size: u64) -> KResult<u64> {
    if size != 8 {
        return Err(Errno::EINVAL);
    }
    let want: u64 = ctx.mm().read::<u64>(set)? & !UNBLOCKABLE;
    let deadline = if timeout != 0 {
        let ts: crate::abi::Timespec = ctx.mm().read(timeout)?;
        if ts.tv_sec < 0 || !(0..1_000_000_000).contains(&ts.tv_nsec) {
            return Err(Errno::EINVAL);
        }
        let ns = (ts.tv_sec as u64)
            .saturating_mul(crate::time::NS_PER_SEC)
            .saturating_add(ts.tv_nsec as u64);
        Some(crate::time::monotonic_ns().saturating_add(ns))
    } else {
        None
    };
    let u = ctx.thread();
    let _timer = deadline.map(crate::time::wake_at);
    let timed_out = || deadline.is_some_and(|d| crate::time::monotonic_ns() >= d);
    loop {
        if let Some((sig, si)) = u.dequeue_signal(want) {
            if info != 0 {
                ctx.mm().copy_to(info, &si.to_bytes(sig))?;
            }
            return Ok(sig as u64);
        }
        if timed_out() {
            return Err(Errno::EAGAIN);
        }
        let seen = crate::fs::POLL_EVENTS.load(Ordering::Acquire);
        crate::fs::POLL_WAIT
            .wait_interruptible(|| {
                crate::fs::POLL_EVENTS.load(Ordering::Acquire) != seen
                    || u.pending_signals() & want != 0
                    || timed_out()
            })
            .map_err(|_| Errno::EINTR)?;
    }
}
