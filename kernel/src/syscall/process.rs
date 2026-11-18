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
        let cwd = ctx.process().cwd();
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
        let t = proc::find_thread_in(me, tid as u32).ok_or(Errno::ESRCH)?;
        let target = t.user().ok_or(Errno::ESRCH)?.process.clone();
        if let Some(g) = tgid
            && me.pid_ns.kid(g as u32) != Some(target.pid)
        {
            return Err(Errno::ESRCH);
        }
        if sig != 0 && !ns_init_ignores(&target, me, sig) {
            let info = SigInfo::tkill(target.pid_ns.nr(me.pid));
            signal::send_thread(&t, sig, info);
        }
        return Ok(0);
    }
    let (target, sig) = (a[0] as i32, a[1] as i32);
    let info = SigInfo::user(me.ns_pid);
    if !(0..=signal::NSIG as i32).contains(&sig) {
        return Err(Errno::EINVAL);
    }
    let send = |p: &Arc<proc::Process>| {
        if sig != 0 && !ns_init_ignores(p, me, sig) {
            signal::send(p, sig, SigInfo::user(p.pid_ns.nr(me.pid)));
        }
    };
    match target {
        t if t > 0 => {
            let p = proc::lookup_in(me, t as u32).ok_or(Errno::ESRCH)?;
            send(&p);
        }
        0 => {
            if sig != 0 {
                signal::send_to_group(me.pgid(), sig, info)?;
            }
        }
        -1 => {
            let all: alloc::vec::Vec<_> = proc::all()
                .into_iter()
                .filter(|p| me.pid_ns.nr(p.pid) > 1)
                .collect();
            if all.is_empty() {
                return Err(Errno::ESRCH);
            }
            all.iter().for_each(send);
        }
        t => {
            let pg = me.pid_ns.kid(t.unsigned_abs()).ok_or(Errno::ESRCH)?;
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

/// `unshare(flags)`: a new user, mount or network namespace for the
/// caller, or a new PID namespace for its children; CLONE_FS stops
/// sharing the filesystem state; CLONE_FILES and CLONE_SYSVSEM change
/// nothing (descriptor tables are never shared); CLONE_THREAD,
/// CLONE_SIGHAND and CLONE_VM only for a single-threaded caller.
pub fn unshare(ctx: &Ctx, flags: u64) -> KResult<u64> {
    use proc::clone_flags::*;
    use proc::ns::{MntNs, PidNs, UserNs};
    let known = CLONE_NEWUSER
        | CLONE_NEWPID
        | CLONE_NEWNET
        | CLONE_NEWNS
        | CLONE_FILES
        | CLONE_FS
        | CLONE_SYSVSEM
        | CLONE_THREAD
        | CLONE_SIGHAND
        | CLONE_VM;
    if flags & !known != 0 {
        return Err(Errno::EINVAL);
    }
    let p = ctx.process();
    let mut flags = flags;
    if flags & CLONE_NEWUSER != 0 {
        flags |= CLONE_THREAD | CLONE_FS;
    }
    if flags & (CLONE_THREAD | CLONE_SIGHAND | CLONE_VM) != 0 && p.thread_count() > 1 {
        return Err(Errno::EINVAL);
    }
    let user = if flags & CLONE_NEWUSER != 0 {
        Some(UserNs::new(&p.user_ns.lock())?)
    } else {
        None
    };
    let pid = if flags & CLONE_NEWPID != 0 {
        // Once only: until then children go to the caller's own namespace.
        let base = p.child_pid_ns.lock().clone();
        if !Arc::ptr_eq(&base, &p.pid_ns) {
            return Err(Errno::EINVAL);
        }
        Some(PidNs::new(&base)?)
    } else {
        None
    };
    if let Some(u) = user {
        *p.user_ns.lock() = u;
    }
    if flags & CLONE_FS != 0 {
        let own = p.fs().copy();
        *p.fs.lock() = own;
    }
    if flags & CLONE_NEWNET != 0 {
        *p.net_ns.lock() = proc::ns::NetNs::new();
    }
    if flags & CLONE_NEWNS != 0 {
        let own = {
            let current = p.mnt_ns.lock();
            MntNs::copy_of(&current)
        };
        *p.mnt_ns.lock() = own;
    }
    if let Some(n) = pid {
        *p.child_pid_ns.lock() = n;
    }
    Ok(0)
}

/// Signals with the default action do not reach the init of a PID
/// namespace, except SIGKILL and SIGSTOP from a namespace above it.
fn ns_init_ignores(target: &proc::Process, sender: &proc::Process, sig: i32) -> bool {
    let ns = &target.pid_ns;
    if !signal::is_ns_init(target) {
        return false;
    }
    if target.sigactions.lock()[sig as usize - 1].handler != signal::SIG_DFL {
        return false;
    }
    let from_above = !Arc::ptr_eq(&sender.pid_ns, ns) && sender.pid_ns.contains(ns);
    !(from_above && (sig == signo::SIGKILL || sig == signo::SIGSTOP))
}

pub fn setpgid(ctx: &Ctx, pid: u32, pgid: u32) -> KResult<u64> {
    let me = ctx.process();
    let pid = match pid {
        0 => 0,
        n => me.pid_ns.kid(n).ok_or(Errno::ESRCH)?,
    };
    let pgid = match pgid {
        0 => 0,
        n => me.pid_ns.kid(n).ok_or(Errno::EPERM)?,
    };
    proc::setpgid(me, pid, pgid)?;
    Ok(0)
}

pub fn getpgid(ctx: &Ctx, pid: u32) -> KResult<u64> {
    let me = ctx.process();
    let p = match pid {
        0 => me.clone(),
        n => proc::lookup_in(me, n).ok_or(Errno::ESRCH)?,
    };
    Ok(me.pid_ns.nr(p.pgid()) as u64)
}

pub fn setsid(ctx: &Ctx) -> KResult<u64> {
    let me = ctx.process();
    proc::setsid(me).map(|s| me.pid_ns.nr(s) as u64)
}

pub fn getsid(ctx: &Ctx, pid: u32) -> KResult<u64> {
    let me = ctx.process();
    let p = match pid {
        0 => me.clone(),
        n => proc::lookup_in(me, n).ok_or(Errno::ESRCH)?,
    };
    Ok(me.pid_ns.nr(p.sid()) as u64)
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
        proc::find_thread_in(ctx.process(), tid).ok_or(Errno::ESRCH)?
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

/// `seccomp(op, flags, args)`.
pub fn seccomp(ctx: &Ctx, op: u32, flags: u32, args: u64) -> KResult<u64> {
    use crate::proc::seccomp as sc;
    const SET_MODE_STRICT: u32 = 0;
    const SET_MODE_FILTER: u32 = 1;
    const GET_ACTION_AVAIL: u32 = 2;
    const GET_NOTIF_SIZES: u32 = 3;
    const FLAG_TSYNC: u32 = 1;
    const FLAG_LOG: u32 = 2;
    const FLAG_SPEC_ALLOW: u32 = 4;
    const FLAG_TSYNC_ESRCH: u32 = 16;
    match op {
        SET_MODE_STRICT if flags == 0 && args == 0 => set_strict(ctx),
        SET_MODE_FILTER => {
            if flags & !(FLAG_TSYNC | FLAG_LOG | FLAG_SPEC_ALLOW | FLAG_TSYNC_ESRCH) != 0 {
                // No user-space notification (NEW_LISTENER) here.
                return Err(Errno::EINVAL);
            }
            set_filter(
                ctx,
                args,
                flags & FLAG_TSYNC != 0,
                flags & FLAG_LOG != 0,
                flags & FLAG_TSYNC_ESRCH != 0,
            )
        }
        GET_ACTION_AVAIL if flags == 0 => {
            let action: u32 = ctx.mm().read(args)?;
            if sc::action_available(action) {
                Ok(0)
            } else {
                Err(Errno::EOPNOTSUPP)
            }
        }
        // struct seccomp_notif_sizes: notif, notif_resp, data.
        GET_NOTIF_SIZES if flags == 0 => {
            ctx.mm().write(args, &[80u16, 24, 64])?;
            Ok(0)
        }
        _ => Err(Errno::EINVAL),
    }
}

/// `SECCOMP_MODE_STRICT` for the calling thread.
pub fn set_strict(ctx: &Ctx) -> KResult<u64> {
    use crate::proc::seccomp as sc;
    let t = ctx.thread();
    match t.seccomp_mode.load(Ordering::Relaxed) {
        sc::MODE_DISABLED => {
            t.seccomp_mode.store(sc::MODE_STRICT, Ordering::Relaxed);
            Ok(0)
        }
        _ => Err(Errno::EINVAL),
    }
}

/// Installs the filter at `prog` (a `struct sock_fprog`) for the calling
/// thread, or (`tsync`) for every thread of its process. Root may always
/// install one (no `no_new_privs` needed).
pub fn set_filter(ctx: &Ctx, prog: u64, tsync: bool, log: bool, esrch: bool) -> KResult<u64> {
    use crate::proc::seccomp as sc;
    let t = ctx.thread();
    if t.seccomp_mode.load(Ordering::Relaxed) == sc::MODE_STRICT {
        return Err(Errno::EINVAL);
    }
    let current = t.seccomp.lock().clone();
    let filter = sc::load(ctx.mm(), prog, current.clone(), log)?;
    let threads = if tsync {
        ctx.process().threads()
    } else {
        alloc::vec![crate::task::current()]
    };
    if tsync {
        // Every other thread must be at an ancestor of ours (or have
        // none); otherwise the first one that is not is the answer.
        for task in &threads {
            let Some(u) = task.user() else { continue };
            let theirs = u.seccomp.lock().clone();
            let ok = u.seccomp_mode.load(Ordering::Relaxed) != sc::MODE_STRICT
                && match (&theirs, &current) {
                    (None, _) => true,
                    (Some(f), Some(c)) => c.descends_from(f),
                    (Some(_), None) => false,
                };
            if !ok {
                return if esrch {
                    Err(Errno::ESRCH)
                } else {
                    Ok(u.ns_tid as u64)
                };
            }
        }
    }
    for task in &threads {
        let Some(u) = task.user() else { continue };
        *u.seccomp.lock() = Some(filter.clone());
        u.seccomp_mode.store(sc::MODE_FILTER, Ordering::Relaxed);
        if tsync {
            u.no_new_privs
                .store(t.no_new_privs.load(Ordering::Relaxed), Ordering::Relaxed);
        }
    }
    Ok(0)
}
