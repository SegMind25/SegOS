//! User processes.
//!
//! A user thread is a kernel [`Task`] with a [`UserThread`] attached: its
//! process, its address space, and the CPU state that is per thread but
//! not saved by the kernel's own context switch (FS/GS base, x87/SSE
//! registers). The scheduler is unchanged; [`switch_hook`] swaps that extra
//! state on every switch.
//!
//! A process is a thread group: `clone(CLONE_THREAD)` adds threads that
//! share its address space, descriptors, working directory and signal
//! handlers. `getpid` is the group's id (the first thread's tid). `exit`
//! ends one thread; the process ends, a zombie for its parent, when its
//! last thread has gone. `exit_group` and fatal signals end every thread.
//!
//! Processes form the usual Unix tree: `fork` makes a child, `exit` leaves
//! a zombie holding the wait status until the parent reaps it with
//! `wait4`, and orphans are handed to init (pid 1). Process groups and
//! sessions are what job control and the terminal use.

pub mod elf;
pub mod exec;
pub mod faults;
pub mod futex;
pub mod itimer;
pub mod ns;
pub mod seccomp;
pub mod signal;

use crate::abi::{Errno, KResult};
use crate::fs::{self, FdTable, File, Inode};
use crate::hal::idt::TrapFrame;
use crate::hal::percpu::this_cpu;
use crate::hal::x86::{self, FxArea};
use crate::mm::paging;
use crate::mm::vm::AddressSpace;
use crate::sync::{Mutex, SpinLock};
use crate::task::wait::{Completion, WaitQueue};
use crate::task::{self, Task};
use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, AtomicI32, AtomicU32, AtomicU64, Ordering};
pub use signal::{SigAction, signo};

/// Where a process is in its life, as `wait4` reports it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RunState {
    Running,
    /// Stopped by `sig`; `reported` once a `wait4(WUNTRACED)` saw it.
    Stopped {
        sig: i32,
        reported: bool,
    },
    /// Exited; the wait status, until the parent reaps it.
    Zombie(i32),
}

pub struct Process {
    /// The kernel's pid (the number in the initial PID namespace).
    pub pid: u32,
    /// The PID namespace the process is in, and its pid there.
    pub pid_ns: Arc<ns::PidNs>,
    pub ns_pid: u32,
    /// Where its children go (`unshare(CLONE_NEWPID)` changes it).
    pub child_pid_ns: SpinLock<Arc<ns::PidNs>>,
    pub user_ns: SpinLock<Arc<ns::UserNs>>,
    pub ppid: AtomicU32,
    pub pgid: AtomicU32,
    pub sid: AtomicU32,
    /// `comm`: the executable's name, at most 15 bytes.
    pub name: SpinLock<String>,
    /// Absolute path of the executable (`/proc/<pid>/exe`).
    pub exe: SpinLock<String>,
    pub cmdline: SpinLock<Vec<String>>,
    pub files: Mutex<FdTable>,
    /// Root, working directory and umask (shared after CLONE_FS).
    pub fs: SpinLock<Arc<FsState>>,
    pub net_ns: SpinLock<Arc<ns::NetNs>>,
    /// The mount table this process sees (a private copy after CLONE_NEWNS).
    pub mnt_ns: SpinLock<Arc<ns::MntNs>>,
    pub sigactions: SpinLock<[SigAction; signal::NSIG]>,
    pub children: SpinLock<Vec<Arc<Process>>>,
    /// Bumped and woken whenever a child changes state.
    pub child_events: AtomicU64,
    pub child_wait: WaitQueue,
    state: SpinLock<RunState>,
    /// A SIGCONT not yet reported to a `wait4(WCONTINUED)`.
    continued: AtomicBool,
    /// Woken when a stopped process is continued (or killed).
    pub(crate) stop_wait: WaitQueue,
    /// Signal sent to the parent on exit (normally SIGCHLD).
    exit_signal: i32,
    /// Whether the process has the console as its controlling terminal.
    pub has_ctty: AtomicBool,
    /// The live threads (the first is the oldest).
    threads: SpinLock<Vec<Weak<Task>>>,
    /// Woken whenever a thread of the group exits.
    thread_exit_wait: WaitQueue,
    /// The exit status `exit_group` or a fatal signal set for the group.
    group_exit: AtomicI32,
    /// Process-directed signals not yet taken by a thread.
    pub(crate) shared_sig: signal::SigQueue,
    /// Monotonic ns at creation (for /proc).
    pub start_ns: u64,
    /// A debugging aid: log this process's failing system calls (1) or
    /// all of them (2). Set by `SEGOS_STRACE=1` or `=2` in the
    /// environment of `execve`; children inherit it.
    pub trace: AtomicU32,
}

impl Process {
    pub fn state(&self) -> RunState {
        *self.state.lock()
    }

    pub fn exit_status(&self) -> Option<i32> {
        match self.state() {
            RunState::Zombie(s) => Some(s),
            _ => None,
        }
    }

    /// A live thread of the process (the oldest), if any.
    pub fn thread(&self) -> Option<Arc<Task>> {
        self.threads.lock().iter().find_map(|w| w.upgrade())
    }

    /// Every live thread.
    pub fn threads(&self) -> Vec<Arc<Task>> {
        self.threads
            .lock()
            .iter()
            .filter_map(|w| w.upgrade())
            .collect()
    }

    pub fn thread_count(&self) -> usize {
        self.threads.lock().len()
    }

    pub fn pgid(&self) -> u32 {
        self.pgid.load(Ordering::Relaxed)
    }

    pub fn sid(&self) -> u32 {
        self.sid.load(Ordering::Relaxed)
    }

    /// Tells the parent (and its `wait4`) that this process changed state.
    fn notify_parent(&self) {
        if let Some(parent) = lookup(self.ppid.load(Ordering::Relaxed)) {
            parent.child_events.fetch_add(1, Ordering::Release);
            parent.child_wait.wake_all();
        }
    }
}

/// Every process by pid, until it is reaped.
static TABLE: SpinLock<BTreeMap<u32, Arc<Process>>> = SpinLock::new(BTreeMap::new());
static NEXT_PID: AtomicU32 = AtomicU32::new(1);

pub fn lookup(pid: u32) -> Option<Arc<Process>> {
    TABLE.lock().get(&pid).cloned()
}

/// All processes, in pid order.
pub fn all() -> Vec<Arc<Process>> {
    TABLE.lock().values().cloned().collect()
}

/// The process numbered `nr` in `me`'s PID namespace.
pub fn lookup_in(me: &Process, nr: u32) -> Option<Arc<Process>> {
    me.pid_ns.kid(nr).and_then(lookup)
}

/// The thread numbered `nr` in `me`'s PID namespace.
pub fn find_thread_in(me: &Process, nr: u32) -> Option<Arc<Task>> {
    me.pid_ns.kid(nr).and_then(find_thread)
}

/// The thread with id `tid`, in any process.
pub fn find_thread(tid: u32) -> Option<Arc<Task>> {
    all().iter().find_map(|p| {
        p.threads()
            .into_iter()
            .find(|t| t.user().is_some_and(|u| u.tid == tid))
    })
}

/// The per-thread state of a user thread.
pub struct UserThread {
    pub process: Arc<Process>,
    pub tid: u32,
    /// The tid in the process's PID namespace.
    pub ns_tid: u32,
    /// Dropped (set to None) when the thread exits.
    mm: SpinLock<Option<Arc<AddressSpace>>>,
    /// What CR3 should be while this thread runs.
    pml4: AtomicU64,
    pub fs_base: AtomicU64,
    pub gs_base: AtomicU64,
    pub clear_child_tid: AtomicU64,
    pub robust_list: AtomicU64,
    pub(crate) sig: signal::ThreadSignals,
    /// Saved x87/SSE state; only the CPU switching the thread touches it.
    fpu: UnsafeCell<FxArea>,
    /// A wait status to exit with on the way back to user mode.
    pending_exit: AtomicI32,
    /// Completed when a `vfork` child execs or exits.
    vfork_done: SpinLock<Option<Arc<Completion>>>,
    /// Exiting ends only this thread (`exit`, or killed by another
    /// thread's `exit_group` or `execve`), not the whole group.
    thread_only: AtomicBool,
    /// Scheduling policy (low 32 bits) and real-time priority (high 32),
    /// as `sched_setscheduler` set them. (The scheduler treats every
    /// thread alike; programs read back what they set.)
    pub sched: AtomicU64,
    /// A thread's own name (`PR_SET_NAME` in a thread other than the
    /// main one); None: the process's.
    pub comm: SpinLock<Option<String>>,
    /// seccomp mode (`seccomp::MODE_*`) and the newest filter.
    pub seccomp_mode: AtomicU32,
    pub seccomp: SpinLock<Option<Arc<seccomp::Filter>>>,
    /// `PR_SET_NO_NEW_PRIVS` (inherited, never cleared).
    pub no_new_privs: AtomicBool,
}

unsafe impl Sync for UserThread {}

const NO_EXIT: i32 = i32::MIN;

impl UserThread {
    pub fn mm(&self) -> Arc<AddressSpace> {
        self.mm
            .lock()
            .clone()
            .expect("user thread without an address space")
    }

    /// Makes the thread exit with wait status `status` when the current
    /// system call returns.
    pub fn request_exit(&self, status: i32) {
        let _ = self.pending_exit.compare_exchange(
            NO_EXIT,
            status,
            Ordering::Relaxed,
            Ordering::Relaxed,
        );
    }

    /// Makes the thread (alone) exit when the current system call returns.
    pub fn request_thread_exit(&self, status: i32) {
        self.thread_only.store(true, Ordering::Relaxed);
        self.request_exit(status);
    }

    pub fn take_pending_exit(&self) -> Option<i32> {
        let s = self.pending_exit.swap(NO_EXIT, Ordering::Relaxed);
        (s != NO_EXIT).then_some(s)
    }

    /// Switches this (running) thread to `mm`, returning the old one. The
    /// caller drops it once nothing on this CPU uses it.
    pub(crate) fn replace_mm(&self, mm: Arc<AddressSpace>) -> Option<Arc<AddressSpace>> {
        x86::without_interrupts(|| {
            self.pml4.store(mm.pml4(), Ordering::Relaxed);
            unsafe { x86::write_cr3(mm.pml4()) };
            self.mm.lock().replace(mm)
        })
    }

    /// Loads a fresh FPU state (for execve) into the CPU.
    pub(crate) fn reset_fpu(&self) {
        x86::fxrstor(&FxArea::initial());
    }

    /// Wakes a parent waiting in `vfork`.
    pub(crate) fn release_vfork_parent(&self) {
        if let Some(c) = self.vfork_done.lock().take() {
            c.complete();
        }
    }
}

/// What a new process gets as descriptors 0, 1 and 2.
pub fn console_stdio() -> KResult<[Arc<File>; 3]> {
    use crate::abi::open::O_RDWR;
    let console = fs::lookup(&fs::root(), "/dev/console")?;
    let f = File::new(console, O_RDWR);
    Ok([f.clone(), f.clone(), f])
}

/// A user-mode register frame starting at `rip` with stack `rsp`, every
/// general register zero.
pub fn initial_frame(rip: u64, rsp: u64) -> TrapFrame {
    use crate::hal::gdt::{USER_CODE, USER_DATA};
    TrapFrame {
        r15: 0,
        r14: 0,
        r13: 0,
        r12: 0,
        r11: 0,
        r10: 0,
        r9: 0,
        r8: 0,
        rbp: 0,
        rdi: 0,
        rsi: 0,
        rdx: 0,
        rcx: 0,
        rbx: 0,
        rax: 0,
        vector: 0,
        error_code: 0,
        rip,
        cs: USER_CODE as u64,
        rflags: 0x202,
        rsp,
        ss: USER_DATA as u64,
    }
}

/// What CLONE_FS shares: the root directory (`chroot`; None: the
/// system's), the working directory and the umask.
pub struct FsState {
    pub root: SpinLock<Option<Arc<dyn Inode>>>,
    pub cwd: SpinLock<Arc<dyn Inode>>,
    pub umask: AtomicU32,
}

impl FsState {
    fn new(cwd: Arc<dyn Inode>) -> Arc<FsState> {
        Arc::new(FsState {
            root: SpinLock::new(None),
            cwd: SpinLock::new(cwd),
            umask: AtomicU32::new(0o022),
        })
    }

    /// A copy that is no longer shared.
    pub fn copy(&self) -> Arc<FsState> {
        Arc::new(FsState {
            root: SpinLock::new(self.root.lock().clone()),
            cwd: SpinLock::new(self.cwd.lock().clone()),
            umask: AtomicU32::new(self.umask.load(Ordering::Relaxed)),
        })
    }
}

impl Process {
    pub fn fs(&self) -> Arc<FsState> {
        self.fs.lock().clone()
    }

    pub fn cwd(&self) -> Arc<dyn Inode> {
        self.fs().cwd.lock().clone()
    }

    /// The root directory as this process sees it.
    pub fn root(&self) -> Option<Arc<dyn Inode>> {
        self.fs().root.lock().clone()
    }
}

#[allow(clippy::too_many_arguments)]
fn new_process(
    pid: u32,
    pid_ns: Arc<ns::PidNs>,
    ns_pid: u32,
    user_ns: Arc<ns::UserNs>,
    ppid: u32,
    pgid: u32,
    sid: u32,
    files: FdTable,
    cwd: Arc<dyn Inode>,
) -> Process {
    Process {
        pid,
        child_pid_ns: SpinLock::new(pid_ns.clone()),
        pid_ns,
        ns_pid,
        user_ns: SpinLock::new(user_ns),
        ppid: AtomicU32::new(ppid),
        pgid: AtomicU32::new(pgid),
        sid: AtomicU32::new(sid),
        name: SpinLock::new(String::new()),
        exe: SpinLock::new(String::new()),
        cmdline: SpinLock::new(Vec::new()),
        files: Mutex::new(files),
        fs: SpinLock::new(FsState::new(cwd)),
        net_ns: SpinLock::new(ns::NetNs::initial()),
        mnt_ns: SpinLock::new(ns::MntNs::initial()),
        sigactions: SpinLock::new([SigAction::default(); signal::NSIG]),
        children: SpinLock::new(Vec::new()),
        child_events: AtomicU64::new(0),
        child_wait: WaitQueue::new(),
        state: SpinLock::new(RunState::Running),
        continued: AtomicBool::new(false),
        stop_wait: WaitQueue::new(),
        exit_signal: signo::SIGCHLD,
        has_ctty: AtomicBool::new(false),
        threads: SpinLock::new(Vec::new()),
        thread_exit_wait: WaitQueue::new(),
        group_exit: AtomicI32::new(NO_EXIT),
        shared_sig: signal::SigQueue::default(),
        start_ns: crate::time::monotonic_ns(),
        trace: AtomicU32::new(0),
    }
}

fn new_thread(process: Arc<Process>, mm: Arc<AddressSpace>) -> UserThread {
    UserThread {
        tid: process.pid,
        ns_tid: process.ns_pid,
        process,
        pml4: AtomicU64::new(mm.pml4()),
        mm: SpinLock::new(Some(mm)),
        fs_base: AtomicU64::new(0),
        gs_base: AtomicU64::new(0),
        clear_child_tid: AtomicU64::new(0),
        robust_list: AtomicU64::new(0),
        sig: signal::ThreadSignals::default(),
        fpu: UnsafeCell::new(FxArea::initial()),
        pending_exit: AtomicI32::new(NO_EXIT),
        vfork_done: SpinLock::new(None),
        thread_only: AtomicBool::new(false),
        sched: AtomicU64::new(0),
        comm: SpinLock::new(None),
        seccomp_mode: AtomicU32::new(seccomp::MODE_DISABLED),
        seccomp: SpinLock::new(None),
        no_new_privs: AtomicBool::new(false),
    }
}

/// What a new thread inherits from its creator `t`: seccomp filters and
/// `no_new_privs`.
fn inherit_restrictions(thread: &UserThread, t: &UserThread) {
    thread
        .seccomp_mode
        .store(t.seccomp_mode.load(Ordering::Relaxed), Ordering::Relaxed);
    *thread.seccomp.lock() = t.seccomp.lock().clone();
    thread
        .no_new_privs
        .store(t.no_new_privs.load(Ordering::Relaxed), Ordering::Relaxed);
}

/// Starts `thread` (of `p`) with `frame`, adding it to the process's
/// threads first. Fails if the group is exiting.
fn start_thread(p: &Arc<Process>, thread: UserThread, frame: TrapFrame) -> KResult<Arc<Task>> {
    let task = task::new_user(thread, frame);
    {
        let mut threads = p.threads.lock();
        if p.group_exit.load(Ordering::Relaxed) != NO_EXIT {
            return Err(Errno::EAGAIN);
        }
        threads.push(Arc::downgrade(&task));
    }
    task::start(task.clone());
    Ok(task)
}

/// Starts the program at `path` as a new process (a new session and
/// process group, child of nobody: the kernel starts it), with `stdio` as
/// descriptors 0 to 2 and, with `controlling_tty`, the console as its
/// terminal. Returns its thread (join it to wait for the exit).
pub fn spawn(
    path: &str,
    argv: &[&str],
    envp: &[&str],
    stdio: [Arc<File>; 3],
    controlling_tty: bool,
) -> KResult<Arc<Task>> {
    let root = fs::root();
    let argv: Vec<String> = argv.iter().map(|s| s.to_string()).collect();
    let envp: Vec<String> = envp.iter().map(|s| s.to_string()).collect();
    let image = exec::prepare(&root, path, argv, envp)?;

    let mut files = FdTable::default();
    for (fd, f) in stdio.into_iter().enumerate() {
        files.set(fd, f, false);
    }
    let pid = NEXT_PID.fetch_add(1, Ordering::Relaxed);
    let process = Arc::new(new_process(
        pid,
        ns::PidNs::initial(),
        pid,
        ns::UserNs::initial(),
        0,
        pid,
        pid,
        files,
        root,
    ));
    exec::set_identity(&process, &image);
    if controlling_tty {
        crate::tty::console().make_controlling(&process);
    }
    let mm = image.mm.clone();
    let frame = initial_frame(image.entry, image.rsp);
    let thread = new_thread(process.clone(), mm);
    TABLE.lock().insert(pid, process.clone());
    start_thread(&process, thread, frame)
}

/// `clone` flags (sched.h).
pub mod clone_flags {
    pub const CSIGNAL: u64 = 0xff;
    pub const CLONE_VM: u64 = 0x100;
    pub const CLONE_FS: u64 = 0x200;
    pub const CLONE_NEWNS: u64 = 0x2_0000;
    pub const CLONE_FILES: u64 = 0x400;
    pub const CLONE_SIGHAND: u64 = 0x800;
    pub const CLONE_VFORK: u64 = 0x4000;
    pub const CLONE_PARENT: u64 = 0x8000;
    pub const CLONE_THREAD: u64 = 0x10000;
    pub const CLONE_SYSVSEM: u64 = 0x40000;
    pub const CLONE_SETTLS: u64 = 0x80000;
    pub const CLONE_PARENT_SETTID: u64 = 0x100000;
    pub const CLONE_CHILD_CLEARTID: u64 = 0x200000;
    pub const CLONE_CHILD_SETTID: u64 = 0x1000000;
    pub const CLONE_NEWUSER: u64 = 0x1000_0000;
    pub const CLONE_NEWPID: u64 = 0x2000_0000;
    pub const CLONE_NEWNET: u64 = 0x4000_0000;
    /// UTS, IPC and cgroup namespaces: not yet.
    pub const UNSUPPORTED: u64 = 0x0e00_0000;
}

/// `fork`, `vfork` and `clone`. `frame` is the parent's saved user state;
/// the child resumes from a copy of it with RAX = 0. Returns the child's
/// pid (or tid, for a thread).
pub fn clone(
    t: &UserThread,
    frame: &TrapFrame,
    flags: u64,
    stack: u64,
    ptid: u64,
    ctid: u64,
    tls: u64,
) -> KResult<u32> {
    use clone_flags::*;
    if flags & UNSUPPORTED != 0 || (flags & CLONE_SIGHAND != 0 && flags & CLONE_VM == 0) {
        return Err(Errno::EINVAL);
    }
    // A new namespace cannot share the caller's thread group, and a new
    // user or mount namespace cannot share its filesystem state; the init
    // of a PID namespace cannot give itself siblings.
    let me = &t.process;
    if (flags & (CLONE_NEWUSER | CLONE_NEWPID | CLONE_NEWNS) != 0 && flags & CLONE_THREAD != 0)
        || (flags & (CLONE_NEWUSER | CLONE_NEWNS) != 0 && flags & CLONE_FS != 0)
        || (flags & CLONE_PARENT != 0 && me.pid_ns.level > 0 && me.pid_ns.reaper() == me.pid)
    {
        return Err(Errno::EINVAL);
    }
    if flags & CLONE_THREAD != 0 {
        if flags & CLONE_SIGHAND == 0 {
            return Err(Errno::EINVAL);
        }
        return clone_thread(t, frame, flags, stack, ptid, ctid, tls);
    }
    let parent = &t.process;
    let user_ns = {
        let own = parent.user_ns.lock().clone();
        if flags & CLONE_NEWUSER != 0 {
            ns::UserNs::new(&own)?
        } else {
            own
        }
    };
    let pid_ns = {
        let base = parent.child_pid_ns.lock().clone();
        if flags & CLONE_NEWPID != 0 {
            ns::PidNs::new(&base)?
        } else {
            base
        }
    };
    let pid = NEXT_PID.fetch_add(1, Ordering::Relaxed);
    let ns_pid = pid_ns.attach(pid)?;
    let parent_mm = t.mm();
    let mm = if flags & CLONE_VM != 0 {
        parent_mm.clone()
    } else {
        match parent_mm.fork() {
            Ok(mm) => mm,
            Err(e) => {
                pid_ns.detach(pid);
                return Err(e);
            }
        }
    };
    let ppid = if flags & CLONE_PARENT != 0 {
        parent.ppid.load(Ordering::Relaxed)
    } else {
        parent.pid
    };
    let files = parent.files.lock().clone();
    let cwd = parent.cwd();
    let mut child = new_process(
        pid,
        pid_ns,
        ns_pid,
        user_ns,
        ppid,
        parent.pgid(),
        parent.sid(),
        files,
        cwd,
    );
    child.exit_signal = (flags & CSIGNAL) as i32;
    *child.name.get_mut() = parent.name.lock().clone();
    *child.exe.get_mut() = parent.exe.lock().clone();
    *child.cmdline.get_mut() = parent.cmdline.lock().clone();
    *child.fs.get_mut() = if flags & CLONE_FS != 0 {
        parent.fs()
    } else {
        parent.fs().copy()
    };
    *child.net_ns.get_mut() = if flags & CLONE_NEWNET != 0 {
        ns::NetNs::new()
    } else {
        parent.net_ns.lock().clone()
    };
    *child.mnt_ns.get_mut() = if flags & CLONE_NEWNS != 0 {
        ns::MntNs::copy_of(&parent.mnt_ns.lock())
    } else {
        parent.mnt_ns.lock().clone()
    };
    child.trace = AtomicU32::new(parent.trace.load(Ordering::Relaxed));
    *child.sigactions.get_mut() = *parent.sigactions.lock();
    child
        .has_ctty
        .store(parent.has_ctty.load(Ordering::Relaxed), Ordering::Relaxed);
    let child = Arc::new(child);

    let thread = new_thread(child.clone(), mm.clone());
    thread.fs_base.store(
        if flags & CLONE_SETTLS != 0 {
            tls
        } else {
            t.fs_base.load(Ordering::Relaxed)
        },
        Ordering::Relaxed,
    );
    thread
        .gs_base
        .store(t.gs_base.load(Ordering::Relaxed), Ordering::Relaxed);
    thread.sig.inherit(&t.sig);
    inherit_restrictions(&thread, t);
    // The parent's FPU registers are live in the CPU (the kernel never
    // touches them): copy them.
    x86::fxsave(unsafe { &mut *thread.fpu.get() });
    if flags & CLONE_CHILD_CLEARTID != 0 {
        thread.clear_child_tid.store(ctid, Ordering::Relaxed);
    }
    // The parent sees the child's pid in its own namespace.
    let seen = parent.pid_ns.nr(pid);
    if flags & CLONE_CHILD_SETTID != 0 {
        mm.write(ctid, &child.ns_pid)?;
    }
    if flags & CLONE_PARENT_SETTID != 0 {
        parent_mm.write(ptid, &seen)?;
    }
    let vfork = (flags & CLONE_VFORK != 0).then(|| Arc::new(Completion::default()));
    *thread.vfork_done.lock() = vfork.clone();

    let mut child_frame = *frame;
    child_frame.rax = 0;
    if stack != 0 {
        child_frame.rsp = stack;
    }
    if let Some(p) = lookup(ppid) {
        p.children.lock().push(child.clone());
    }
    TABLE.lock().insert(pid, child.clone());
    let task = start_thread(&child, thread, child_frame)?;
    drop(task);
    if let Some(done) = vfork {
        // The child borrows our memory until it execs or exits.
        done.wait();
    }
    Ok(seen)
}

/// `clone(CLONE_THREAD | CLONE_VM | CLONE_SIGHAND ...)`: a new thread of
/// the caller's process.
fn clone_thread(
    t: &UserThread,
    frame: &TrapFrame,
    flags: u64,
    stack: u64,
    ptid: u64,
    ctid: u64,
    tls: u64,
) -> KResult<u32> {
    use clone_flags::*;
    let p = &t.process;
    // A thread must be in its process's PID namespace.
    if !Arc::ptr_eq(&p.child_pid_ns.lock(), &p.pid_ns) {
        return Err(Errno::EINVAL);
    }
    let mm = t.mm();
    let tid = NEXT_PID.fetch_add(1, Ordering::Relaxed);
    let ns_tid = p.pid_ns.attach(tid)?;
    let mut thread = new_thread(p.clone(), mm.clone());
    thread.tid = tid;
    thread.ns_tid = ns_tid;
    thread.fs_base.store(
        if flags & CLONE_SETTLS != 0 {
            tls
        } else {
            t.fs_base.load(Ordering::Relaxed)
        },
        Ordering::Relaxed,
    );
    thread
        .gs_base
        .store(t.gs_base.load(Ordering::Relaxed), Ordering::Relaxed);
    // The signal mask is inherited; the alternate stack is not.
    thread.sig.set_mask(t.sig.mask.load(Ordering::Relaxed));
    inherit_restrictions(&thread, t);
    x86::fxsave(unsafe { &mut *thread.fpu.get() });
    if flags & CLONE_CHILD_CLEARTID != 0 {
        thread.clear_child_tid.store(ctid, Ordering::Relaxed);
    }
    if flags & CLONE_CHILD_SETTID != 0 {
        mm.write(ctid, &ns_tid)?;
    }
    if flags & CLONE_PARENT_SETTID != 0 {
        mm.write(ptid, &ns_tid)?;
    }
    let mut child_frame = *frame;
    child_frame.rax = 0;
    if stack != 0 {
        child_frame.rsp = stack;
    }
    if let Err(e) = start_thread(p, thread, child_frame) {
        p.pid_ns.detach(tid);
        return Err(e);
    }
    Ok(ns_tid)
}

/// Kills every thread of the current process but the caller and waits
/// until they are gone (`execve` from a multithreaded program). Fails if
/// the caller itself is killed meanwhile (another thread's `exit_group`).
pub fn kill_other_threads() -> KResult<()> {
    let me = current();
    let p = me.user().unwrap().process.clone();
    let others: Vec<_> = p
        .threads()
        .into_iter()
        .filter(|t| !Arc::ptr_eq(t, &me))
        .collect();
    if others.is_empty() {
        return Ok(());
    }
    others.iter().for_each(kill_thread);
    drop(others);
    p.thread_exit_wait.wait_until(|| {
        signal::kill_pending()
            || p.threads
                .lock()
                .iter()
                .all(|w| core::ptr::eq(w.as_ptr(), Arc::as_ptr(&me)))
    });
    if signal::kill_pending() {
        return Err(Errno::EINTR);
    }
    Ok(())
}

/// Makes thread `t` exit (alone) as soon as it can.
fn kill_thread(t: &Arc<Task>) {
    if let Some(u) = t.user() {
        u.thread_only.store(true, Ordering::Relaxed);
        u.sig.q.post(signo::SIGKILL, signal::SigInfo::kernel());
        core::sync::atomic::fence(Ordering::SeqCst);
        task::kick(t);
    }
}

/// Swaps the per-thread CPU state that `switch_context` does not: the
/// address space, the kernel stack for traps from ring 3, FS/GS bases and
/// the FPU registers. Interrupts are off.
pub fn switch_hook(prev: &Task, next: &Task) {
    if let Some(u) = prev.user() {
        x86::fxsave(unsafe { &mut *u.fpu.get() });
    }
    let cr3 = x86::read_cr3() & !0xfff;
    match next.user() {
        Some(u) => {
            this_cpu().set_kernel_stack(next.kernel_stack_top());
            let pml4 = u.pml4.load(Ordering::Relaxed);
            if cr3 != pml4 {
                unsafe { x86::write_cr3(pml4) };
            }
            unsafe {
                x86::wrmsr(x86::msr::FS_BASE, u.fs_base.load(Ordering::Relaxed));
                // The user's GS base waits in KERNEL_GS_BASE until swapgs.
                x86::wrmsr(x86::msr::KERNEL_GS_BASE, u.gs_base.load(Ordering::Relaxed));
            }
            x86::fxrstor(unsafe { &*u.fpu.get() });
        }
        None => {
            // Kernel threads run on the kernel's table, so a dead process's
            // table is never left loaded on some CPU.
            let kernel = paging::kernel_pml4();
            if cr3 != kernel {
                unsafe { x86::write_cr3(kernel) };
            }
        }
    }
}

/// The current task, which must be a user thread.
pub fn current() -> Arc<Task> {
    let t = task::current();
    assert!(t.user().is_some(), "not a user thread");
    t
}

/// Ends the current thread's process with wait status `status` (exit code
/// << 8, or the signal number): every thread exits (`exit_group`, fatal
/// signals). A thread asked to exit alone (`exit`, or killed by another
/// thread) ends only itself.
pub fn exit(status: i32) -> ! {
    {
        let task = current();
        let u = task.user().unwrap();
        let p = &u.process;
        if !u.thread_only.load(Ordering::Relaxed)
            && p.group_exit
                .compare_exchange(NO_EXIT, status, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
        {
            for t in p.threads() {
                if !Arc::ptr_eq(&t, &task) {
                    kill_thread(&t);
                }
            }
        }
    }
    exit_thread(status)
}

/// Ends the current thread. The last thread of a process ends the process.
fn exit_thread(status: i32) -> ! {
    {
        let task = current();
        let u = task.user().unwrap();
        let p = u.process.clone();
        let mm = u.mm.lock().clone();
        if let Some(mm) = &mm {
            futex::exit_robust_list(mm, u.robust_list.load(Ordering::Relaxed), u.ns_tid);
            // pthread_join waits for this word to become 0.
            let ctid = u.clear_child_tid.swap(0, Ordering::Relaxed);
            if ctid != 0 && mm.write(ctid, &0u32).is_ok() {
                futex::wake_address(mm, ctid, 1);
            }
        }
        drop(mm);
        u.release_vfork_parent();
        let last = {
            let mut threads = p.threads.lock();
            threads.retain(|w| !core::ptr::eq(w.as_ptr(), Arc::as_ptr(&task)));
            threads.is_empty()
        };
        if last {
            // Close every file.
            let files = core::mem::take(&mut *p.files.lock());
            drop(files);
        }
        // Leave the address space before dropping it.
        x86::without_interrupts(|| {
            let kernel = paging::kernel_pml4();
            u.pml4.store(kernel, Ordering::Relaxed);
            unsafe { x86::write_cr3(kernel) };
        });
        let mm = u.mm.lock().take();
        drop(mm);
        p.thread_exit_wait.wake_all();
        if u.tid != p.pid {
            p.pid_ns.detach(u.tid);
        }
        if last {
            let group = p.group_exit.load(Ordering::Acquire);
            end_process(&p, if group != NO_EXIT { group } else { status });
        } else if u.tid == p.pid {
            // The group leader stays until the whole group has gone (a
            // parent, or the kernel's `join`, waits for the process).
            p.thread_exit_wait
                .wait_until(|| matches!(p.state(), RunState::Zombie(_)));
        }
    }
    task::exit()
}

/// The last thread of `p` has exited: it becomes a zombie for its parent.
fn end_process(p: &Arc<Process>, status: i32) {
    // The init of a PID namespace takes the rest of it along.
    let mut ns = p.pid_ns.clone();
    if ns.level > 0 && ns.reaper() == p.pid {
        for kid in ns.shut_down() {
            if let Some(q) = lookup(kid).filter(|q| q.pid != p.pid) {
                signal::send(&q, signo::SIGKILL, signal::SigInfo::kernel());
            }
        }
    }
    // Orphans go to the init of the namespace (or of the nearest one
    // above whose init is not this process).
    while ns.reaper() == p.pid
        && let Some(up) = ns.parent.clone()
    {
        ns = up;
    }
    let reaper = ns.reaper();
    let orphans = core::mem::take(&mut *p.children.lock());
    if !orphans.is_empty() {
        if let Some(init) = lookup(reaper).filter(|i| i.pid != p.pid) {
            let mut any_zombie = false;
            for c in &orphans {
                c.ppid.store(init.pid, Ordering::Relaxed);
                any_zombie |= c.exit_status().is_some();
            }
            init.children.lock().extend(orphans);
            if any_zombie {
                init.child_events.fetch_add(1, Ordering::Release);
                init.child_wait.wake_all();
            }
        } else {
            for c in orphans {
                c.ppid.store(0, Ordering::Relaxed);
                if c.exit_status().is_some() {
                    forget(&c);
                }
            }
        }
    }
    *p.state.lock() = RunState::Zombie(status);
    p.thread_exit_wait.wake_all();
    let parent = lookup(p.ppid.load(Ordering::Relaxed));
    match parent {
        Some(parent) => {
            let auto_reap = signal::parent_ignores_children(&parent);
            if p.exit_signal != 0 {
                signal::send(&parent, p.exit_signal, signal::SigInfo::child(p, status));
            }
            if auto_reap {
                parent.children.lock().retain(|c| c.pid != p.pid);
                forget(p);
            }
            p.notify_parent();
        }
        // Started by the kernel: nobody will reap it but the kernel's
        // `join`; keep the status readable through the Arc.
        None => forget(p),
    }
}

/// `p` has been reaped: its pid is free.
fn forget(p: &Process) {
    TABLE.lock().remove(&p.pid);
    p.pid_ns.detach(p.pid);
}

/// `wait4` options.
pub mod wait_flags {
    pub const WNOHANG: u32 = 1;
    pub const WUNTRACED: u32 = 2;
    pub const WCONTINUED: u32 = 8;
}

/// What `wait4` found: (pid, wait status). Both pids are numbers in the
/// caller's PID namespace.
pub fn wait(me: &Arc<Process>, pid: i32, options: u32) -> KResult<Option<(u32, i32)>> {
    use wait_flags::*;
    let target = match pid {
        -1 | 0 => 0,
        p => me.pid_ns.kid(p.unsigned_abs()).unwrap_or(u32::MAX),
    };
    let matches = |c: &Process| match pid {
        -1 => true,
        0 => c.pgid() == me.pgid(),
        p if p > 0 => c.pid == target,
        _ => c.pgid() == target,
    };
    loop {
        let seen = me.child_events.load(Ordering::Acquire);
        let mut found = false;
        {
            let mut children = me.children.lock();
            let mut reap = None;
            for (i, c) in children.iter().enumerate() {
                if !matches(c) {
                    continue;
                }
                found = true;
                let mut st = c.state.lock();
                match *st {
                    RunState::Zombie(status) => {
                        reap = Some((i, me.pid_ns.nr(c.pid), status));
                        break;
                    }
                    RunState::Stopped { sig, reported }
                        if options & WUNTRACED != 0 && !reported =>
                    {
                        *st = RunState::Stopped {
                            sig,
                            reported: true,
                        };
                        return Ok(Some((me.pid_ns.nr(c.pid), (sig << 8) | 0x7f)));
                    }
                    RunState::Running
                        if options & WCONTINUED != 0
                            && c.continued.swap(false, Ordering::Relaxed) =>
                    {
                        return Ok(Some((me.pid_ns.nr(c.pid), 0xffff)));
                    }
                    _ => {}
                }
            }
            if let Some((i, pid, status)) = reap {
                let c = children.remove(i);
                drop(children);
                forget(&c);
                return Ok(Some((pid, status)));
            }
        }
        if !found {
            return Err(Errno::ECHILD);
        }
        if options & WNOHANG != 0 {
            return Ok(None);
        }
        me.child_wait
            .wait_interruptible(|| me.child_events.load(Ordering::Acquire) != seen)?;
    }
}

/// Stops the current process (the default action of SIGSTOP and friends)
/// until SIGCONT or SIGKILL.
pub(crate) fn stop_self(p: &Arc<Process>, sig: i32) {
    *p.state.lock() = RunState::Stopped {
        sig,
        reported: false,
    };
    if let Some(parent) = lookup(p.ppid.load(Ordering::Relaxed))
        && !signal::parent_ignores_stops(&parent)
    {
        signal::send(
            &parent,
            signo::SIGCHLD,
            signal::SigInfo::child_stopped(p, sig),
        );
    }
    p.notify_parent();
    p.stop_wait.wait_until(|| {
        !matches!(*p.state.lock(), RunState::Stopped { .. }) || signal::kill_pending()
    });
}

/// SIGCONT: lets a stopped process run again.
pub(crate) fn continue_process(p: &Arc<Process>) {
    let was_stopped = {
        let mut st = p.state.lock();
        if matches!(*st, RunState::Stopped { .. }) {
            *st = RunState::Running;
            true
        } else {
            false
        }
    };
    if was_stopped {
        p.continued.store(true, Ordering::Relaxed);
        p.stop_wait.wake_all();
        p.notify_parent();
    }
}

/// Process groups and sessions.
pub fn setpgid(me: &Arc<Process>, pid: u32, pgid: u32) -> KResult<()> {
    let target = if pid == 0 || pid == me.pid {
        me.clone()
    } else {
        let t = lookup(pid).ok_or(Errno::ESRCH)?;
        if t.ppid.load(Ordering::Relaxed) != me.pid {
            return Err(Errno::ESRCH);
        }
        t
    };
    let pgid = if pgid == 0 { target.pid } else { pgid };
    if target.sid() != me.sid() || target.sid() == target.pid {
        // Another session's process, or a session leader.
        return Err(Errno::EPERM);
    }
    if pgid != target.pid
        && !all()
            .iter()
            .any(|p| p.pgid() == pgid && p.sid() == me.sid())
    {
        return Err(Errno::EPERM);
    }
    target.pgid.store(pgid, Ordering::Relaxed);
    Ok(())
}

pub fn setsid(me: &Arc<Process>) -> KResult<u32> {
    if all().iter().any(|p| p.pgid() == me.pid) {
        return Err(Errno::EPERM);
    }
    me.sid.store(me.pid, Ordering::Relaxed);
    me.pgid.store(me.pid, Ordering::Relaxed);
    me.has_ctty.store(false, Ordering::Relaxed);
    Ok(me.pid)
}

/// Reads a NULL-terminated array of string pointers (argv, envp).
pub fn read_string_array(mm: &AddressSpace, mut addr: u64) -> KResult<Vec<String>> {
    let mut out = Vec::new();
    if addr == 0 {
        return Ok(out);
    }
    loop {
        let p: u64 = mm.read(addr)?;
        if p == 0 {
            return Ok(out);
        }
        out.push(mm.read_cstr(p, fs::PATH_MAX)?);
        if out.len() > 4096 {
            return Err(Errno::E2BIG);
        }
        addr += 8;
    }
}
