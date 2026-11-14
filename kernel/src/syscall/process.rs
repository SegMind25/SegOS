//! Process and thread system calls, and signal bookkeeping.
//!
//! Signal *delivery* (running a handler) comes with Phase 3; until then
//! handlers and masks are recorded and returned faithfully, and a fatal
//! signal a process sends itself (`abort`) ends it.

use super::Ctx;
use crate::abi::{Errno, KResult};
use crate::hal::x86;
use crate::proc::{SigAction, signal};
use core::sync::atomic::Ordering;

pub fn exit(ctx: &Ctx, code: i32) -> KResult<u64> {
    ctx.thread().request_exit((code & 0xff) << 8);
    Ok(0)
}

const SIG_DFL: u64 = 0;
const SIG_IGN: u64 = 1;

/// Signals whose default action is to be ignored (SIGCHLD, SIGURG,
/// SIGWINCH); SIGCONT continues. All others terminate.
fn ignored_by_default(sig: i32) -> bool {
    matches!(sig, 17 | 18 | 23 | 28)
}

/// kill(pid, sig), tkill(tid, sig), tgkill(tgid, tid, sig).
pub fn kill(ctx: &Ctx, a: [u64; 6], nr: u64) -> KResult<u64> {
    let p = ctx.process();
    let (target, sig) = match nr {
        62 => (a[0] as i32, a[1] as i32),  // kill
        200 => (a[0] as i32, a[1] as i32), // tkill
        _ => {
            // tgkill
            if a[0] as i32 != p.pid as i32 {
                return Err(Errno::ESRCH);
            }
            (a[1] as i32, a[2] as i32)
        }
    };
    if !(0..=signal::NSIG as i32).contains(&sig) {
        return Err(Errno::EINVAL);
    }
    // Only this process exists for it to signal (0 and -1 include it).
    if target != p.pid as i32 && target != 0 && target != -1 {
        return Err(Errno::ESRCH);
    }
    if sig == 0 {
        return Ok(0);
    }
    let blocked = ctx.thread().sigmask.load(Ordering::Relaxed) & (1 << (sig - 1)) != 0;
    if blocked && sig != signal::SIGKILL {
        ctx.thread()
            .sigpending
            .fetch_or(1 << (sig - 1), Ordering::Relaxed);
        return Ok(0);
    }
    deliver(ctx, sig);
    Ok(0)
}

/// Acts on an unblocked signal: the default action, or (not yet) a handler.
fn deliver(ctx: &Ctx, sig: i32) {
    let p = ctx.process();
    let act = p.sigactions.lock()[sig as usize - 1];
    let fatal = sig == signal::SIGKILL || (act.handler == SIG_DFL && !ignored_by_default(sig));
    if fatal {
        ctx.thread().request_exit(sig);
    } else if act.handler != SIG_IGN && act.handler != SIG_DFL {
        crate::warn!(
            "{}[{}]: signal {sig} has a handler; delivery is not implemented yet",
            p.name.lock().as_str(),
            p.pid
        );
    }
}

pub fn rt_sigaction(ctx: &Ctx, sig: i32, act: u64, old: u64, setsize: u64) -> KResult<u64> {
    if setsize != 8 || !(1..=signal::NSIG as i32).contains(&sig) {
        return Err(Errno::EINVAL);
    }
    let new = if act != 0 {
        if sig == signal::SIGKILL || sig == signal::SIGSTOP {
            return Err(Errno::EINVAL);
        }
        Some(ctx.mm().read::<SigAction>(act)?)
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
    let mask = &ctx.thread().sigmask;
    let prev = mask.load(Ordering::Relaxed);
    if set != 0 {
        let s: u64 = ctx.mm().read(set)?;
        // SIGKILL and SIGSTOP cannot be blocked.
        let s = s & !(1 << (signal::SIGKILL - 1) | 1 << (signal::SIGSTOP - 1));
        let new = match how {
            SIG_BLOCK => prev | s,
            SIG_UNBLOCK => prev & !s,
            SIG_SETMASK => s,
            _ => return Err(Errno::EINVAL),
        };
        mask.store(new, Ordering::Relaxed);
        // Pending signals just unblocked happen now.
        let ready = ctx.thread().sigpending.fetch_and(new, Ordering::Relaxed) & !new;
        for sig in 1..=signal::NSIG as i32 {
            if ready & (1 << (sig - 1)) != 0 {
                deliver(ctx, sig);
            }
        }
    }
    if old != 0 {
        ctx.mm().write(old, &prev)?;
    }
    Ok(0)
}

pub fn sigaltstack(ctx: &Ctx, _new: u64, old: u64) -> KResult<u64> {
    if old != 0 {
        // stack_t { ss_sp, ss_flags (SS_DISABLE = 2), ss_size }
        let disabled: [u64; 3] = [0, 2, 0];
        let bytes: alloc::vec::Vec<u8> = disabled.iter().flat_map(|w| w.to_le_bytes()).collect();
        ctx.mm().copy_to(old, &bytes)?;
    }
    Ok(0)
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
