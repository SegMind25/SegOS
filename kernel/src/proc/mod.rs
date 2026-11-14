//! User processes.
//!
//! A user thread is a kernel [`Task`] with a [`UserThread`] attached: its
//! process, its address space, and the CPU state that is per thread but
//! not saved by the kernel's own context switch (FS/GS base, x87/SSE
//! registers). The scheduler is unchanged; [`switch_hook`] swaps that extra
//! state on every switch. In Phase 2 every process has one thread; `clone`
//! with threads comes in Phase 5.

pub mod elf;

use crate::abi::{Errno, KResult};
use crate::fs::{self, FdTable, File, Inode};
use crate::hal::idt::{TrapFrame, vector};
use crate::hal::percpu::this_cpu;
use crate::hal::x86::{self, FxArea};
use crate::mm::paging;
use crate::mm::vm::AddressSpace;
use crate::sync::{Mutex, SpinLock};
use crate::task::{self, Task};
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, AtomicI32, AtomicU32, AtomicU64, Ordering};

/// Signal numbers used by the kernel itself.
pub mod signal {
    pub const SIGILL: i32 = 4;
    pub const SIGTRAP: i32 = 5;
    pub const SIGABRT: i32 = 6;
    pub const SIGBUS: i32 = 7;
    pub const SIGFPE: i32 = 8;
    pub const SIGKILL: i32 = 9;
    pub const SIGSEGV: i32 = 11;
    pub const SIGSTOP: i32 = 19;
    pub const NSIG: usize = 64;
}

pub struct Cwd {
    pub inode: Arc<dyn Inode>,
    /// Absolute, normalised: what `getcwd` returns.
    pub path: String,
}

/// `struct sigaction` as the kernel sees it (handler, flags, restorer,
/// mask). Stored and returned; delivery comes with Phase 3.
#[derive(Clone, Copy, Default)]
#[repr(C)]
pub struct SigAction {
    pub handler: u64,
    pub flags: u64,
    pub restorer: u64,
    pub mask: u64,
}

unsafe impl crate::abi::Pod for SigAction {}

pub struct Process {
    pub pid: u32,
    pub ppid: u32,
    pub name: SpinLock<String>,
    pub files: Mutex<FdTable>,
    pub cwd: Mutex<Cwd>,
    pub umask: AtomicU32,
    pub sigactions: SpinLock<[SigAction; signal::NSIG]>,
    exited: AtomicBool,
    /// The wait status (as `wait4` reports it) once exited.
    status: AtomicI32,
}

impl Process {
    pub fn exit_status(&self) -> Option<i32> {
        self.exited
            .load(Ordering::Acquire)
            .then(|| self.status.load(Ordering::Relaxed))
    }
}

/// The per-thread state of a user thread.
pub struct UserThread {
    pub process: Arc<Process>,
    pub tid: u32,
    /// Dropped (set to None) when the thread exits.
    mm: SpinLock<Option<Arc<AddressSpace>>>,
    /// What CR3 should be while this thread runs.
    pml4: AtomicU64,
    pub fs_base: AtomicU64,
    pub gs_base: AtomicU64,
    pub clear_child_tid: AtomicU64,
    pub robust_list: AtomicU64,
    pub sigmask: AtomicU64,
    /// Signals sent while blocked (bit n-1 for signal n).
    pub sigpending: AtomicU64,
    /// Saved x87/SSE state; only the CPU switching the thread touches it.
    fpu: UnsafeCell<FxArea>,
    /// Where the thread starts in user mode: (rip, rsp).
    start: (u64, u64),
    /// A wait status to exit with on the way back to user mode.
    pending_exit: AtomicI32,
}

const NO_EXIT: i32 = i32::MIN;

unsafe impl Sync for UserThread {}

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

    pub fn take_pending_exit(&self) -> Option<i32> {
        let s = self.pending_exit.swap(NO_EXIT, Ordering::Relaxed);
        (s != NO_EXIT).then_some(s)
    }
}

static NEXT_PID: AtomicU32 = AtomicU32::new(1);

/// What a new process gets as descriptors 0, 1 and 2.
pub fn console_stdio() -> KResult<[Arc<File>; 3]> {
    use crate::abi::open::O_RDWR;
    let console = fs::lookup(&fs::root(), "/dev/console")?;
    let f = File::new(console, O_RDWR);
    Ok([f.clone(), f.clone(), f])
}

/// Starts the program at `path` as a new process, with `stdio` as
/// descriptors 0 to 2. Returns its thread (join it to wait for the exit).
pub fn spawn(
    path: &str,
    argv: &[&str],
    envp: &[&str],
    stdio: [Arc<File>; 3],
) -> KResult<Arc<Task>> {
    let root = fs::root();
    let inode = fs::lookup(&root, path)?;
    if inode.file_type() != fs::FileType::Regular {
        return Err(Errno::EACCES);
    }
    let mut bytes = alloc::vec![0u8; inode.size() as usize];
    let n = inode.read_at(0, &mut bytes)?;
    bytes.truncate(n);

    let mm = AddressSpace::new()?;
    let image = elf::load(&mm, &bytes)?;
    drop(bytes);
    mm.init_brk(image.end);
    let rsp = elf::build_stack(&mm, &image, path, argv, envp)?;

    let mut files = FdTable::default();
    for (fd, f) in stdio.into_iter().enumerate() {
        files.set(fd, f, false);
    }
    let pid = NEXT_PID.fetch_add(1, Ordering::Relaxed);
    let name = path.rsplit('/').next().unwrap_or(path);
    let process = Arc::new(Process {
        pid,
        ppid: 0,
        name: SpinLock::new(name.to_string()),
        files: Mutex::new(files),
        cwd: Mutex::new(Cwd {
            inode: root,
            path: "/".to_string(),
        }),
        umask: AtomicU32::new(0o022),
        sigactions: SpinLock::new([SigAction::default(); signal::NSIG]),
        exited: AtomicBool::new(false),
        status: AtomicI32::new(0),
    });
    let thread = UserThread {
        process,
        tid: pid,
        pml4: AtomicU64::new(mm.pml4()),
        mm: SpinLock::new(Some(mm)),
        fs_base: AtomicU64::new(0),
        gs_base: AtomicU64::new(0),
        clear_child_tid: AtomicU64::new(0),
        robust_list: AtomicU64::new(0),
        sigmask: AtomicU64::new(0),
        sigpending: AtomicU64::new(0),
        fpu: UnsafeCell::new(FxArea::initial()),
        start: (image.entry, rsp),
        pending_exit: AtomicI32::new(NO_EXIT),
    };
    Ok(task::spawn_user(thread))
}

/// First run of a user thread, on its kernel stack (called by the
/// scheduler's task start-up, with the thread's state already loaded).
pub fn start_user(t: &UserThread) -> ! {
    let (rip, rsp) = t.start;
    crate::hal::user::enter_user(rip, rsp)
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

/// Ends the current process with wait status `status` (exit code << 8, or
/// the signal number).
pub fn exit(status: i32) -> ! {
    {
        let task = current();
        let u = task.user().unwrap();
        let p = &u.process;
        // Close every file.
        let files = core::mem::take(&mut *p.files.lock());
        drop(files);
        // Leave the address space before dropping it.
        x86::without_interrupts(|| {
            let kernel = paging::kernel_pml4();
            u.pml4.store(kernel, Ordering::Relaxed);
            unsafe { x86::write_cr3(kernel) };
        });
        let mm = u.mm.lock().take();
        drop(mm);
        p.status.store(status, Ordering::Relaxed);
        p.exited.store(true, Ordering::Release);
        crate::debug!(
            "process {} ({}) exited, status {:#x}",
            p.pid,
            p.name.lock().as_str(),
            status
        );
    }
    task::exit()
}

/// Terminates the current process by signal `sig`, as the default action
/// of a fatal signal does.
pub fn kill_self(sig: i32) -> ! {
    exit(sig & 0x7f)
}

/// An exception in user mode: a page fault to resolve, or a fatal signal.
pub fn user_exception(frame: &mut TrapFrame) {
    // CR2 first: a page fault elsewhere would overwrite it once interrupts
    // are on and another thread runs.
    let cr2 = x86::read_cr2();
    x86::enable_interrupts();
    let task = current();
    let u = task.user().unwrap();
    let sig = match frame.vector {
        vector::PAGE_FAULT => {
            let write = frame.error_code & 2 != 0;
            let exec = frame.error_code & 16 != 0;
            if u.mm().handle_fault(cr2, write, exec) {
                x86::disable_interrupts();
                return;
            }
            signal::SIGSEGV
        }
        vector::DIVIDE_ERROR | 16 | 19 => signal::SIGFPE,
        vector::INVALID_OPCODE => signal::SIGILL,
        vector::BREAKPOINT | 1 => signal::SIGTRAP,
        17 => signal::SIGBUS,
        _ => signal::SIGSEGV,
    };
    let p = &u.process;
    crate::info!(
        "{}[{}]: {} at rip {:#x}{} (vector {}, error {:#x}): killed by signal {}",
        p.name.lock().as_str(),
        p.pid,
        crate::hal::idt::exception_name(frame.vector),
        frame.rip,
        if frame.vector == vector::PAGE_FAULT {
            alloc::format!(", address {cr2:#x}")
        } else {
            String::new()
        },
        frame.vector,
        frame.error_code,
        sig
    );
    drop(task);
    kill_self(sig)
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
