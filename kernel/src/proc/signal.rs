//! Signals: sending, and delivering them on the way back to user mode.
//!
//! A signal is a bit in the thread's pending set (standard signals do not
//! queue). Whenever the kernel is about to return to user mode it calls
//! [`on_return_to_user`], which takes the lowest pending, unblocked signal
//! and acts on it: ignore it, stop or kill the process (the default
//! actions), or run the program's handler by building Linux's
//! `rt_sigframe` on the user stack, exactly as Linux lays it out, so the C
//! library's `sa_restorer` and `rt_sigreturn` find everything where they
//! expect it.
//!
//! A blocking system call that a signal interrupts returns `ERESTARTSYS`
//! internally: it is restarted transparently if no handler runs or the
//! handler has SA_RESTART, and fails with EINTR otherwise.

use super::{Process, UserThread, continue_process, stop_self};
use crate::abi::{Errno, KResult};
use crate::hal::idt::TrapFrame;
use crate::hal::x86::{self, FxArea};
use crate::sync::SpinLock;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering, fence};

pub const NSIG: usize = 64;

/// Signal numbers (x86-64 Linux).
pub mod signo {
    pub const SIGHUP: i32 = 1;
    pub const SIGINT: i32 = 2;
    pub const SIGQUIT: i32 = 3;
    pub const SIGILL: i32 = 4;
    pub const SIGTRAP: i32 = 5;
    pub const SIGABRT: i32 = 6;
    pub const SIGBUS: i32 = 7;
    pub const SIGFPE: i32 = 8;
    pub const SIGKILL: i32 = 9;
    pub const SIGSEGV: i32 = 11;
    pub const SIGPIPE: i32 = 13;
    pub const SIGALRM: i32 = 14;
    pub const SIGTERM: i32 = 15;
    pub const SIGCHLD: i32 = 17;
    pub const SIGCONT: i32 = 18;
    pub const SIGSTOP: i32 = 19;
    pub const SIGTSTP: i32 = 20;
    pub const SIGTTIN: i32 = 21;
    pub const SIGTTOU: i32 = 22;
    pub const SIGURG: i32 = 23;
    pub const SIGWINCH: i32 = 28;
    pub const SIGSYS: i32 = 31;
}
use signo::*;

pub const SIG_DFL: u64 = 0;
pub const SIG_IGN: u64 = 1;

/// `sa_flags`.
pub mod sa {
    pub const SA_NOCLDSTOP: u64 = 1;
    pub const SA_NOCLDWAIT: u64 = 2;
    pub const SA_SIGINFO: u64 = 4;
    pub const SA_RESTORER: u64 = 0x0400_0000;
    pub const SA_ONSTACK: u64 = 0x0800_0000;
    pub const SA_RESTART: u64 = 0x1000_0000;
    pub const SA_NODEFER: u64 = 0x4000_0000;
    pub const SA_RESETHAND: u64 = 0x8000_0000;
}
use sa::*;

fn bit(sig: i32) -> u64 {
    1 << (sig - 1)
}

/// SIGKILL and SIGSTOP can be neither blocked, caught nor ignored.
pub const UNBLOCKABLE: u64 = 1 << (SIGKILL - 1) | 1 << (SIGSTOP - 1);
const STOP_SIGNALS: u64 =
    1 << (SIGSTOP - 1) | 1 << (SIGTSTP - 1) | 1 << (SIGTTIN - 1) | 1 << (SIGTTOU - 1);

/// `struct sigaction` as the kernel's interface has it (handler, flags,
/// restorer, mask).
#[derive(Clone, Copy, Default)]
#[repr(C)]
pub struct SigAction {
    pub handler: u64,
    pub flags: u64,
    pub restorer: u64,
    pub mask: u64,
}

unsafe impl crate::abi::Pod for SigAction {}

enum Default {
    Ignore,
    Stop,
    Terminate,
}

fn default_action(sig: i32) -> Default {
    match sig {
        SIGCHLD | SIGCONT | SIGURG | SIGWINCH => Default::Ignore,
        SIGSTOP | SIGTSTP | SIGTTIN | SIGTTOU => Default::Stop,
        // Core-dumping signals terminate too; no core file is written
        // (RLIMIT_CORE is 0), so the status has no core flag, as on Linux.
        _ => Default::Terminate,
    }
}

fn ignored(sig: i32, act: &SigAction) -> bool {
    act.handler == SIG_IGN
        || (act.handler == SIG_DFL && matches!(default_action(sig), Default::Ignore))
}

/// What `siginfo_t` says about a signal (128 bytes in user memory).
/// Whether `p` is the init of a PID namespace below the initial one.
pub fn is_ns_init(p: &Process) -> bool {
    p.pid_ns.level > 0 && p.pid_ns.reaper() == p.pid
}

/// `p`'s pid as its parent's PID namespace numbers it.
fn seen_by_parent(p: &Process) -> u32 {
    super::lookup(p.ppid.load(core::sync::atomic::Ordering::Relaxed))
        .map_or(p.pid, |q| q.pid_ns.nr(p.pid))
}

#[derive(Clone, Copy, Default)]
pub struct SigInfo {
    /// si_errno (SIGSYS from seccomp: the filter's data).
    pub errno: i32,
    pub code: i32,
    /// The first union words: si_pid/si_uid, or si_addr.
    pub a: u64,
    /// si_status (SIGCHLD).
    pub b: u64,
}

impl SigInfo {
    const SI_USER: i32 = 0;
    const SI_KERNEL: i32 = 0x80;
    const SI_TKILL: i32 = -6;
    const CLD_EXITED: i32 = 1;
    const CLD_KILLED: i32 = 2;
    const CLD_STOPPED: i32 = 5;

    pub fn user(sender: u32) -> Self {
        Self {
            errno: 0,
            code: Self::SI_USER,
            a: sender as u64,
            b: 0,
        }
    }

    pub fn tkill(sender: u32) -> Self {
        Self {
            errno: 0,
            code: Self::SI_TKILL,
            a: sender as u64,
            b: 0,
        }
    }

    pub fn kernel() -> Self {
        Self {
            errno: 0,
            code: Self::SI_KERNEL,
            a: 0,
            b: 0,
        }
    }

    /// A fault at `addr` (SIGSEGV, SIGBUS...), with its si_code.
    pub fn fault(code: i32, addr: u64) -> Self {
        Self {
            errno: 0,
            code,
            a: addr,
            b: 0,
        }
    }

    pub fn child(p: &Process, status: i32) -> Self {
        let (code, value) = if status & 0x7f == 0 {
            (Self::CLD_EXITED, (status >> 8) & 0xff)
        } else {
            (Self::CLD_KILLED, status & 0x7f)
        };
        Self {
            errno: 0,
            code,
            a: seen_by_parent(p) as u64,
            b: value as u64,
        }
    }

    pub fn child_stopped(p: &Process, sig: i32) -> Self {
        Self {
            errno: 0,
            code: Self::CLD_STOPPED,
            a: seen_by_parent(p) as u64,
            b: sig as u64,
        }
    }

    /// SIGSYS from a seccomp filter's `SECCOMP_RET_TRAP`: the system call
    /// `nr` made at `ip` (the address after the instruction), `data`
    /// from the filter.
    pub fn seccomp(ip: u64, nr: u64, data: i32) -> Self {
        const SYS_SECCOMP: i32 = 1;
        const AUDIT_ARCH_X86_64: u64 = 0xc000_003e;
        Self {
            errno: data,
            code: SYS_SECCOMP,
            a: ip,
            b: (nr & 0xffff_ffff) | AUDIT_ARCH_X86_64 << 32,
        }
    }

    pub fn to_bytes(self, sig: i32) -> [u8; 128] {
        let mut b = [0u8; 128];
        b[0..4].copy_from_slice(&sig.to_le_bytes());
        b[4..8].copy_from_slice(&self.errno.to_le_bytes());
        b[8..12].copy_from_slice(&self.code.to_le_bytes());
        b[16..24].copy_from_slice(&self.a.to_le_bytes());
        b[24..32].copy_from_slice(&self.b.to_le_bytes());
        b
    }
}

/// Pending signals with their `siginfo`: a thread's own, or its
/// process's shared set (process-directed signals, which whichever thread
/// does not block them takes).
#[derive(Default)]
pub struct SigQueue {
    pub pending: AtomicU64,
    info: SpinLock<Vec<(i32, SigInfo)>>,
}

impl SigQueue {
    /// Marks `sig` pending (standard signals do not queue: a second one
    /// while the first is pending is merged into it).
    pub fn post(&self, sig: i32, info: SigInfo) {
        if self.pending.load(Ordering::Relaxed) & bit(sig) == 0 {
            let mut infos = self.info.lock();
            infos.retain(|(x, _)| *x != sig);
            infos.push((sig, info));
        }
        self.pending.fetch_or(bit(sig), Ordering::SeqCst);
    }

    /// Takes `sig` if it is pending.
    pub fn take(&self, sig: i32) -> Option<SigInfo> {
        if self.pending.fetch_and(!bit(sig), Ordering::AcqRel) & bit(sig) == 0 {
            return None;
        }
        let mut v = self.info.lock();
        Some(match v.iter().position(|(s, _)| *s == sig) {
            Some(i) => v.swap_remove(i).1,
            None => SigInfo::kernel(),
        })
    }

    /// Forgets the signals in `set`.
    pub fn discard(&self, set: u64) {
        self.pending.fetch_and(!set, Ordering::AcqRel);
        self.info.lock().retain(|(s, _)| set & bit(*s) == 0);
    }
}

/// A thread's signal state.
#[derive(Default)]
pub struct ThreadSignals {
    /// Signals sent to this thread (tgkill, faults).
    pub q: SigQueue,
    pub mask: AtomicU64,
    /// The mask to restore after `sigsuspend`, if one is in progress.
    saved_mask: AtomicU64,
    has_saved: AtomicBool,
    /// sigaltstack: (sp, size, flags).
    pub altstack: SpinLock<(u64, u64, u32)>,
}

impl ThreadSignals {
    /// What a `fork` child starts with: the mask and alternate stack, no
    /// pending signals.
    pub fn inherit(&self, from: &ThreadSignals) {
        self.mask
            .store(from.mask.load(Ordering::Relaxed), Ordering::Relaxed);
        *self.altstack.lock() = *from.altstack.lock();
    }

    pub fn set_mask(&self, mask: u64) {
        self.mask.store(mask & !UNBLOCKABLE, Ordering::Relaxed);
    }

    /// For `sigsuspend`: install `mask` until a handler has run.
    pub fn suspend_mask(&self, mask: u64) {
        self.saved_mask
            .store(self.mask.load(Ordering::Relaxed), Ordering::Relaxed);
        self.has_saved.store(true, Ordering::Relaxed);
        self.set_mask(mask);
    }

    fn blocks(&self, sig: i32) -> bool {
        self.mask.load(Ordering::Relaxed) & bit(sig) & !UNBLOCKABLE != 0
    }
}

impl UserThread {
    /// Signals pending for this thread: its own and its process's.
    pub fn pending_signals(&self) -> u64 {
        self.sig.q.pending.load(Ordering::Acquire)
            | self.process.shared_sig.pending.load(Ordering::Acquire)
    }

    fn deliverable(&self) -> u64 {
        self.pending_signals() & (!self.sig.mask.load(Ordering::Relaxed) | UNBLOCKABLE)
    }

    /// Takes the lowest pending signal in `set` (the thread's own first),
    /// for delivery or `signalfd`.
    pub fn dequeue_signal(&self, set: u64) -> Option<(i32, SigInfo)> {
        loop {
            let ready = self.pending_signals() & set;
            if ready == 0 {
                return None;
            }
            let sig = if ready & bit(SIGKILL) != 0 {
                SIGKILL
            } else {
                ready.trailing_zeros() as i32 + 1
            };
            if let Some(i) = self.sig.q.take(sig) {
                return Some((sig, i));
            }
            if let Some(i) = self.process.shared_sig.take(sig) {
                return Some((sig, i));
            }
            // Another thread took a shared signal meanwhile: look again.
        }
    }
}

/// Whether the current thread has a signal to act on (blocking waits end
/// early when it does).
pub fn pending() -> bool {
    let t = crate::task::current();
    t.user().is_some_and(|u| u.deliverable() != 0)
}

/// Whether SIGKILL is pending for the current thread.
pub fn kill_pending() -> bool {
    let t = crate::task::current();
    t.user()
        .is_some_and(|u| u.sig.q.pending.load(Ordering::Acquire) & bit(SIGKILL) != 0)
}

pub fn parent_ignores_children(parent: &Process) -> bool {
    let act = parent.sigactions.lock()[SIGCHLD as usize - 1];
    act.handler == SIG_IGN || act.flags & SA_NOCLDWAIT != 0
}

pub fn parent_ignores_stops(parent: &Process) -> bool {
    parent.sigactions.lock()[SIGCHLD as usize - 1].flags & SA_NOCLDSTOP != 0
}

/// Sends `sig` to process `p` (any of its threads that does not block it
/// takes it). Safe from interrupt handlers (the terminal sends SIGINT from
/// the keyboard interrupt): only spinlocks are taken.
pub fn send(p: &Arc<Process>, sig: i32, info: SigInfo) {
    if sig <= 0 || sig as usize > NSIG {
        return;
    }
    let threads = p.threads();
    if threads.is_empty() {
        return; // a zombie
    }
    let users = || threads.iter().filter_map(|t| t.user());
    if sig == SIGCONT {
        p.shared_sig.discard(STOP_SIGNALS);
        users().for_each(|u| u.sig.q.discard(STOP_SIGNALS));
        continue_process(p);
    } else if bit(sig) & STOP_SIGNALS != 0 {
        p.shared_sig.discard(bit(SIGCONT));
        users().for_each(|u| u.sig.q.discard(bit(SIGCONT)));
    }
    if sig == SIGKILL {
        // Every thread dies.
        users().for_each(|u| u.sig.q.post(SIGKILL, info));
        fence(Ordering::SeqCst);
        continue_process(p);
        threads.iter().for_each(crate::task::kick);
        return;
    }
    let act = p.sigactions.lock()[sig as usize - 1];
    let blocked = users().all(|u| u.sig.blocks(sig));
    if !blocked && sig != SIGSTOP && ignored(sig, &act) {
        return;
    }
    p.shared_sig.post(sig, info);
    // Pairs with the fence in WaitQueue::wait: the thread either sees the
    // signal before sleeping or is Blocked when we kick it.
    fence(Ordering::SeqCst);
    for t in &threads {
        if t.user().is_some_and(|u| !u.sig.blocks(sig)) {
            crate::task::kick(t);
        }
    }
    // A signalfd may be waiting for it.
    crate::fs::poll_notify();
}

/// Sends `sig` to one thread (`tgkill`, `pthread_kill`). Signals whose
/// effect is on the whole process (kill, stop, continue) go to it.
pub fn send_thread(task: &Arc<crate::task::Task>, sig: i32, info: SigInfo) {
    if sig <= 0 || sig as usize > NSIG {
        return;
    }
    let Some(u) = task.user() else {
        return;
    };
    if matches!(sig, SIGKILL | SIGSTOP | SIGCONT) {
        return send(&u.process, sig, info);
    }
    let act = u.process.sigactions.lock()[sig as usize - 1];
    if !u.sig.blocks(sig) && ignored(sig, &act) {
        return;
    }
    if bit(sig) & STOP_SIGNALS != 0 {
        u.process.shared_sig.discard(bit(SIGCONT));
    }
    u.sig.q.post(sig, info);
    fence(Ordering::SeqCst);
    crate::task::kick(task);
    crate::fs::poll_notify();
}

/// Discards `sig` wherever it is pending in `p` (it became ignored).
pub fn discard(p: &Process, sig: i32) {
    p.shared_sig.discard(bit(sig));
    for t in p.threads() {
        if let Some(u) = t.user() {
            u.sig.q.discard(bit(sig));
        }
    }
}

/// Sends `sig` to every process in group `pgid`.
pub fn send_to_group(pgid: u32, sig: i32, info: SigInfo) -> KResult<()> {
    let members: Vec<_> = super::all()
        .into_iter()
        .filter(|p| p.pgid() == pgid && p.exit_status().is_none())
        .collect();
    if members.is_empty() {
        return Err(Errno::ESRCH);
    }
    for p in members {
        send(&p, sig, info);
    }
    Ok(())
}

/// A signal caused by the program itself (a fault): if it is blocked or
/// ignored, the default action applies, as Linux's `force_sig` does.
pub fn force(t: &UserThread, sig: i32, info: SigInfo) {
    {
        let mut acts = t.process.sigactions.lock();
        let act = &mut acts[sig as usize - 1];
        let blocked = t.sig.mask.load(Ordering::Relaxed) & bit(sig) != 0;
        if blocked || act.handler == SIG_IGN {
            act.handler = SIG_DFL;
            t.sig.mask.fetch_and(!bit(sig), Ordering::Relaxed);
        }
    }
    t.sig.q.post(sig, info);
}

const EFLAGS_DF: u64 = 1 << 10;
const EFLAGS_TF: u64 = 1 << 8;
/// RFLAGS bits a program may change through its signal frame (Linux's
/// FIX_EFLAGS: CF PF AF ZF SF TF DF OF AC RF).
const FIX_EFLAGS: u64 = 0x50dd5;
const SS_ONSTACK: u32 = 1;
const SS_DISABLE: u32 = 2;

/// Layout of the frame (struct rt_sigframe): the return address (the
/// handler's `ret` goes to `sa_restorer`), `struct ucontext`, `siginfo`.
const UC_SIZE: u64 = 8 + 8 + 24 + SIGCONTEXT_SIZE + 8;
const SIGCONTEXT_SIZE: u64 = 256;
const UC_MCONTEXT: u64 = 40;
const UC_SIGMASK: u64 = UC_MCONTEXT + SIGCONTEXT_SIZE;
const FRAME_SIZE: u64 = 8 + UC_SIZE + 128;

/// The `struct sigcontext` image of `f`.
fn sigcontext(f: &TrapFrame, mask: u64, fpstate: u64) -> [u8; SIGCONTEXT_SIZE as usize] {
    let regs = [
        f.r8, f.r9, f.r10, f.r11, f.r12, f.r13, f.r14, f.r15, f.rdi, f.rsi, f.rbp, f.rbx, f.rdx,
        f.rax, f.rcx, f.rsp, f.rip, f.rflags,
    ];
    let mut b = [0u8; SIGCONTEXT_SIZE as usize];
    for (i, r) in regs.iter().enumerate() {
        b[i * 8..i * 8 + 8].copy_from_slice(&r.to_le_bytes());
    }
    b[144..146].copy_from_slice(&(f.cs as u16).to_le_bytes());
    // gs, fs: 0; ss
    b[150..152].copy_from_slice(&(f.ss as u16).to_le_bytes());
    b[152..160].copy_from_slice(&f.error_code.to_le_bytes()); // err
    b[160..168].copy_from_slice(&f.vector.min(255).to_le_bytes()); // trapno
    b[168..176].copy_from_slice(&mask.to_le_bytes()); // oldmask
    b[176..184].copy_from_slice(&x86::read_cr2().to_le_bytes()); // cr2
    b[184..192].copy_from_slice(&fpstate.to_le_bytes());
    b
}

/// Builds the signal frame and points the thread at the handler.
fn setup_frame(
    u: &UserThread,
    frame: &mut TrapFrame,
    sig: i32,
    info: SigInfo,
    act: &SigAction,
) -> KResult<()> {
    if act.flags & SA_RESTORER == 0 {
        // x86-64 Linux needs the C library's restorer to return.
        return Err(Errno::EFAULT);
    }
    let mm = u.mm();
    let (ss_sp, ss_size, ss_flags) = *u.sig.altstack.lock();
    let on_alt = ss_flags & SS_DISABLE == 0
        && ss_size != 0
        && frame.rsp > ss_sp
        && frame.rsp <= ss_sp + ss_size;
    let mut sp =
        if act.flags & SA_ONSTACK != 0 && ss_flags & SS_DISABLE == 0 && ss_size != 0 && !on_alt {
            ss_sp + ss_size
        } else {
            frame.rsp - 128 // the red zone below rsp belongs to the interrupted code
        };
    // FPU state (the thread's registers are live in the CPU).
    let mut fx = FxArea::initial();
    x86::fxsave(&mut fx);
    sp = (sp - 512) & !63;
    let fpstate = sp;
    mm.copy_to(fpstate, &fx.0)?;
    // The frame: at handler entry, rsp + 8 is 16-byte aligned, as if the
    // handler had been called.
    sp = ((sp - FRAME_SIZE) & !15) - 8;
    let old_mask = if u.sig.has_saved.swap(false, Ordering::Relaxed) {
        u.sig.saved_mask.load(Ordering::Relaxed)
    } else {
        u.sig.mask.load(Ordering::Relaxed)
    };
    let mut bytes = Vec::with_capacity(FRAME_SIZE as usize);
    bytes.extend_from_slice(&act.restorer.to_le_bytes());
    bytes.extend_from_slice(&0u64.to_le_bytes()); // uc_flags
    bytes.extend_from_slice(&0u64.to_le_bytes()); // uc_link
    bytes.extend_from_slice(&ss_sp.to_le_bytes()); // uc_stack
    let cur_flags = if on_alt { SS_ONSTACK } else { ss_flags };
    bytes.extend_from_slice(&(cur_flags as u64).to_le_bytes());
    bytes.extend_from_slice(&ss_size.to_le_bytes());
    bytes.extend_from_slice(&sigcontext(frame, old_mask, fpstate));
    bytes.extend_from_slice(&old_mask.to_le_bytes()); // uc_sigmask
    bytes.extend_from_slice(&info.to_bytes(sig));
    debug_assert_eq!(bytes.len() as u64, FRAME_SIZE);
    mm.copy_to(sp, &bytes)?;

    frame.rip = act.handler;
    frame.rsp = sp;
    frame.rdi = sig as u64;
    frame.rsi = sp + 8 + UC_SIZE;
    frame.rdx = sp + 8;
    frame.rax = 0;
    frame.rflags &= !(EFLAGS_DF | EFLAGS_TF);
    let mut mask = u.sig.mask.load(Ordering::Relaxed) | act.mask;
    if act.flags & SA_NODEFER == 0 {
        mask |= bit(sig);
    }
    u.sig.set_mask(mask);
    if act.flags & SA_RESETHAND != 0 {
        u.process.sigactions.lock()[sig as usize - 1].handler = SIG_DFL;
    }
    Ok(())
}

/// `rt_sigreturn`: restores what `setup_frame` saved. Returns the restored
/// RAX (the system call's result is what the program sees in RAX).
pub fn sigreturn(u: &UserThread, frame: &mut TrapFrame) -> KResult<u64> {
    let mm = u.mm();
    let uc = frame.rsp; // the handler's `ret` popped the return address
    let mut sc = [0u8; SIGCONTEXT_SIZE as usize];
    mm.copy_from(uc + UC_MCONTEXT, &mut sc)?;
    let mask: u64 = mm.read(uc + UC_SIGMASK)?;
    let r = |i: usize| u64::from_le_bytes(sc[i * 8..i * 8 + 8].try_into().unwrap());
    frame.r8 = r(0);
    frame.r9 = r(1);
    frame.r10 = r(2);
    frame.r11 = r(3);
    frame.r12 = r(4);
    frame.r13 = r(5);
    frame.r14 = r(6);
    frame.r15 = r(7);
    frame.rdi = r(8);
    frame.rsi = r(9);
    frame.rbp = r(10);
    frame.rbx = r(11);
    frame.rdx = r(12);
    frame.rax = r(13);
    frame.rcx = r(14);
    frame.rsp = r(15);
    frame.rip = r(16);
    frame.rflags = (frame.rflags & !FIX_EFLAGS) | (r(17) & FIX_EFLAGS) | 0x202;
    let fpstate = r(23);
    // CS and SS stay the user selectors whatever the frame says.
    u.sig.set_mask(mask);
    if fpstate != 0 {
        let mut fx = FxArea::initial();
        mm.copy_from(fpstate, &mut fx.0)?;
        // A reserved MXCSR bit would make fxrstor fault in the kernel.
        let mxcsr = u32::from_le_bytes(fx.0[24..28].try_into().unwrap()) & x86::mxcsr_mask();
        fx.0[24..28].copy_from_slice(&mxcsr.to_le_bytes());
        x86::fxrstor(&fx);
    }
    Ok(frame.rax)
}

/// Called just before returning to user mode, interrupts on: acts on
/// pending signals. `syscall` is the number of the system call returning,
/// for restarting it.
pub fn on_return_to_user(frame: &mut TrapFrame, syscall: Option<u64>) {
    let restart_code = (-(Errno::ERESTARTSYS.0 as i64)) as u64;
    loop {
        enum Action {
            Done,
            Exit(i32),
            Stop(Arc<Process>, i32),
            Wait(Arc<Process>),
            Again,
        }
        let action = {
            let task = crate::task::current();
            let Some(u) = task.user() else {
                return;
            };
            let stopped = matches!(u.process.state(), super::RunState::Stopped { .. });
            let allowed = !u.sig.mask.load(Ordering::Relaxed) | UNBLOCKABLE;
            if stopped && !kill_pending() {
                // Another thread stopped the process: stop here too.
                Action::Wait(u.process.clone())
            } else if let Some((sig, info)) = u.dequeue_signal(allowed) {
                let act = u.process.sigactions.lock()[sig as usize - 1];
                if sig == SIGKILL {
                    Action::Exit(SIGKILL)
                } else if sig == SIGSTOP {
                    Action::Stop(u.process.clone(), sig)
                } else if act.handler == SIG_IGN {
                    Action::Again
                } else if act.handler == SIG_DFL && is_ns_init(&u.process) {
                    // The init of a PID namespace takes only signals it
                    // handles (SIGKILL and SIGSTOP came from above).
                    Action::Again
                } else if act.handler == SIG_DFL {
                    match default_action(sig) {
                        Default::Ignore => Action::Again,
                        Default::Stop => Action::Stop(u.process.clone(), sig),
                        Default::Terminate => Action::Exit(sig),
                    }
                } else {
                    // A handler. An interrupted system call is restarted
                    // after it if the handler asked for that.
                    if let Some(nr) = syscall
                        && frame.rax == restart_code
                    {
                        if act.flags & SA_RESTART != 0 {
                            frame.rax = nr;
                            frame.rip -= 2;
                        } else {
                            frame.rax = (-(Errno::EINTR.0 as i64)) as u64;
                        }
                    }
                    match setup_frame(u, frame, sig, info, &act) {
                        Ok(()) => Action::Done,
                        Err(_) => Action::Exit(SIGSEGV),
                    }
                }
            } else {
                Action::Done
            }
        };
        match action {
            Action::Done => break,
            Action::Again => continue,
            Action::Exit(status) => super::exit(status),
            Action::Stop(p, sig) => stop_self(&p, sig),
            Action::Wait(p) => p.stop_wait.wait_until(|| {
                !matches!(p.state(), super::RunState::Stopped { .. }) || kill_pending()
            }),
        }
    }
    // No handler ran: an interrupted system call starts again.
    if let Some(nr) = syscall
        && frame.rax == restart_code
    {
        frame.rax = nr;
        frame.rip -= 2;
    }
    // A sigsuspend whose signal did not run a handler: its mask ends here.
    let task = crate::task::current();
    if let Some(u) = task.user()
        && u.sig.has_saved.swap(false, Ordering::Relaxed)
    {
        u.sig.set_mask(u.sig.saved_mask.load(Ordering::Relaxed));
    }
}

/// `sigaltstack`.
pub fn altstack(u: &UserThread, frame: &TrapFrame, new: u64, old: u64) -> KResult<()> {
    let mm = u.mm();
    let (sp, size, flags) = *u.sig.altstack.lock();
    let on = flags & SS_DISABLE == 0 && size != 0 && frame.rsp > sp && frame.rsp <= sp + size;
    if old != 0 {
        let cur = if on { SS_ONSTACK } else { flags & SS_DISABLE };
        let words: [u64; 3] = [sp, cur as u64, size];
        let bytes: Vec<u8> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
        mm.copy_to(old, &bytes)?;
    }
    if new != 0 {
        if on {
            return Err(Errno::EPERM);
        }
        let nsp: u64 = mm.read(new)?;
        let nflags: u32 = mm.read(new + 8)?;
        let nsize: u64 = mm.read(new + 16)?;
        if nflags & !(SS_DISABLE | 0x8000_0000) != 0 {
            return Err(Errno::EINVAL);
        }
        if nflags & SS_DISABLE == 0 && nsize < 2048 {
            return Err(Errno::ENOMEM);
        }
        *u.sig.altstack.lock() = (nsp, nsize, nflags & SS_DISABLE);
    }
    Ok(())
}
