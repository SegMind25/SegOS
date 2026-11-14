//! Process, thread and signal system calls.

use super::{Ctx, path_arg};
use crate::abi::{Errno, KResult};
use crate::hal::idt::TrapFrame;
use crate::hal::x86;
use crate::proc::signal::{self, SigAction, SigInfo, UNBLOCKABLE, signo};
use crate::proc::{self, wait_flags};
use crate::sync::SpinLock;
use crate::task::wait::WaitQueue;
use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicU64, Ordering};

pub fn exit(ctx: &Ctx, code: i32) -> KResult<u64> {
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
    let (target, sig, info) = match nr {
        62 => (a[0] as i32, a[1] as i32, SigInfo::user(me.pid)),
        200 => (a[0] as i32, a[1] as i32, SigInfo::tkill(me.pid)),
        _ => {
            if a[0] as i32 != a[1] as i32 {
                return Err(Errno::ESRCH); // threads come in Phase 5
            }
            (a[1] as i32, a[2] as i32, SigInfo::tkill(me.pid))
        }
    };
    if !(0..=signal::NSIG as i32).contains(&sig) {
        return Err(Errno::EINVAL);
    }
    let send = |p: &Arc<proc::Process>| {
        if sig != 0 {
            signal::send(p, sig, info);
        }
    };
    if nr != 62 && target <= 0 {
        return Err(Errno::EINVAL);
    }
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
        ctx.thread()
            .sig
            .pending
            .fetch_and(!(1 << (sig - 1)), Ordering::Relaxed);
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
    let pending = ctx.thread().sig.pending.load(Ordering::Relaxed);
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

/// One futex word's waiters.
struct FutexQueue {
    queue: WaitQueue,
    wakes: AtomicU64,
}

/// Futexes by (address space, address). Waiters on a shared address space
/// (a vfork child) find each other; real thread support comes in Phase 5.
static FUTEXES: SpinLock<BTreeMap<(usize, u64), Arc<FutexQueue>>> = SpinLock::new(BTreeMap::new());

pub fn futex(ctx: &Ctx, a: [u64; 6]) -> KResult<u64> {
    const FUTEX_WAIT: u64 = 0;
    const FUTEX_WAKE: u64 = 1;
    const FUTEX_WAIT_BITSET: u64 = 9;
    const FUTEX_WAKE_BITSET: u64 = 10;
    let (addr, op, val) = (a[0], a[1] & 0x7f, a[2] as u32);
    if addr % 4 != 0 {
        return Err(Errno::EINVAL);
    }
    let key = (ctx.mm() as *const _ as usize, addr);
    let q = FUTEXES
        .lock()
        .entry(key)
        .or_insert_with(|| {
            Arc::new(FutexQueue {
                queue: WaitQueue::new(),
                wakes: AtomicU64::new(0),
            })
        })
        .clone();
    match op {
        FUTEX_WAIT | FUTEX_WAIT_BITSET => {
            let seen = q.wakes.load(Ordering::Acquire);
            let cur: u32 = ctx.mm().read(addr)?;
            if cur != val {
                return Err(Errno::EAGAIN);
            }
            let deadline = if a[3] != 0 {
                let ts: crate::abi::Timespec = ctx.mm().read(a[3])?;
                let ns = (ts.tv_sec.max(0) as u64)
                    .saturating_mul(crate::time::NS_PER_SEC)
                    .saturating_add(ts.tv_nsec.max(0) as u64);
                Some(if op == FUTEX_WAIT {
                    crate::time::monotonic_ns().saturating_add(ns)
                } else {
                    ns // WAIT_BITSET takes an absolute time
                })
            } else {
                None
            };
            let _timer = deadline.map(crate::time::wake_at);
            let timed_out = || deadline.is_some_and(|d| crate::time::monotonic_ns() >= d);
            q.queue
                .wait_interruptible(|| q.wakes.load(Ordering::Acquire) != seen || timed_out())?;
            if q.wakes.load(Ordering::Acquire) == seen {
                return Err(Errno::ETIMEDOUT);
            }
            Ok(0)
        }
        FUTEX_WAKE | FUTEX_WAKE_BITSET => {
            q.wakes.fetch_add(1, Ordering::Release);
            q.queue.wake_all();
            Ok(val.min(1) as u64)
        }
        _ => Err(Errno::ENOSYS),
    }
}
