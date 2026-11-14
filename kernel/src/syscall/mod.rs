//! Linux system calls: numbers, dispatch, and the calls themselves.
//!
//! The numbers are Linux's x86-64 ones (`arch/x86/entry/syscalls`). Each
//! handler returns `Ok(value)` or `Err(errno)`; the program sees `-errno`
//! in RAX, exactly as on Linux. An unknown call returns `ENOSYS` and is
//! logged once per number: that log is the to-do list.

mod fs;
mod info;
mod mem;
mod process;

use crate::abi::{Errno, KResult};
use crate::hal::idt::TrapFrame;
use crate::hal::x86;
use crate::mm::vm::AddressSpace;
use crate::proc::{Process, UserThread};
use crate::task::Task;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicU64, Ordering};

/// What a handler works with: the calling thread.
pub struct Ctx {
    task: Arc<Task>,
    mm: Arc<AddressSpace>,
}

impl Ctx {
    pub fn thread(&self) -> &UserThread {
        self.task.user().unwrap()
    }
    pub fn process(&self) -> &Arc<Process> {
        &self.thread().process
    }
    pub fn mm(&self) -> &AddressSpace {
        &self.mm
    }
}

/// Called by the `syscall` entry (hal::syscall) with interrupts off.
#[unsafe(no_mangle)]
extern "C" fn syscall_dispatch(frame: &mut TrapFrame) {
    x86::enable_interrupts();
    let nr = frame.rax;
    let a = [
        frame.rdi, frame.rsi, frame.rdx, frame.r10, frame.r8, frame.r9,
    ];
    let result = {
        let task = crate::proc::current();
        let mm = task.user().unwrap().mm();
        let ctx = Ctx { task, mm };
        dispatch(&ctx, nr, a)
    };
    frame.rax = match result {
        Ok(v) => v,
        Err(e) => (-(e.0 as i64)) as u64,
    };
    // exit, exit_group or a fatal signal to itself: leave now that no
    // reference to the thread or its memory is held on this stack.
    let pending = crate::task::current()
        .user()
        .and_then(|u| u.take_pending_exit());
    if let Some(status) = pending {
        crate::proc::exit(status);
    }
    x86::disable_interrupts();
}

/// Unknown system calls already reported (bit n: number n, below 512).
static REPORTED: [AtomicU64; 8] = [const { AtomicU64::new(0) }; 8];

fn report_unknown(ctx: &Ctx, nr: u64) {
    if nr < 512 {
        let bit = 1u64 << (nr % 64);
        if REPORTED[nr as usize / 64].fetch_or(bit, Ordering::Relaxed) & bit != 0 {
            return;
        }
    }
    let p = ctx.process();
    crate::warn!(
        "{}[{}]: system call {nr} is not implemented (ENOSYS)",
        p.name.lock().as_str(),
        p.pid
    );
}

fn dispatch(ctx: &Ctx, nr: u64, a: [u64; 6]) -> KResult<u64> {
    let fd = a[0] as i32;
    match nr {
        0 => fs::read(ctx, fd, a[1], a[2]),
        1 => fs::write(ctx, fd, a[1], a[2]),
        2 => fs::openat(ctx, crate::abi::AT_FDCWD, a[0], a[1] as u32, a[2] as u32),
        3 => fs::close(ctx, fd),
        4 => fs::stat_path(ctx, crate::abi::AT_FDCWD, a[0], a[1], 0),
        5 => fs::fstat(ctx, fd, a[1]),
        6 => fs::stat_path(
            ctx,
            crate::abi::AT_FDCWD,
            a[0],
            a[1],
            crate::abi::AT_SYMLINK_NOFOLLOW,
        ),
        8 => fs::lseek(ctx, fd, a[1] as i64, a[2] as u32),
        9 => mem::mmap(ctx, a[0], a[1], a[2] as u32, a[3] as u32, a[4] as i32, a[5]),
        10 => mem::mprotect(ctx, a[0], a[1], a[2] as u32),
        11 => mem::munmap(ctx, a[0], a[1]),
        12 => Ok(ctx.mm().brk(a[0])),
        13 => process::rt_sigaction(ctx, a[0] as i32, a[1], a[2], a[3]),
        14 => process::rt_sigprocmask(ctx, a[0] as i32, a[1], a[2], a[3]),
        16 => fs::ioctl(ctx, fd, a[1] as u32, a[2]),
        17 => fs::pread(ctx, fd, a[1], a[2], a[3] as i64),
        18 => fs::pwrite(ctx, fd, a[1], a[2], a[3] as i64),
        19 => fs::readv(ctx, fd, a[1], a[2]),
        20 => fs::writev(ctx, fd, a[1], a[2]),
        21 => fs::faccessat(ctx, crate::abi::AT_FDCWD, a[0], a[1] as u32),
        24 => {
            crate::task::yield_now();
            Ok(0)
        }
        25 => mem::mremap(),
        28 => Ok(0), // madvise: advice may be ignored
        32 => fs::dup(ctx, fd),
        33 => fs::dup3(ctx, fd, a[1] as i32, 0, true),
        35 => info::nanosleep(ctx, a[0], a[1]),
        39 => Ok(ctx.process().pid as u64),
        60 | 231 => process::exit(ctx, a[0] as i32),
        61 => Err(Errno::ECHILD), // wait4: no children before fork (Phase 3)
        62 | 200 | 234 => process::kill(ctx, a, nr),
        63 => info::uname(ctx, a[0]),
        72 => fs::fcntl(ctx, fd, a[1] as u32, a[2]),
        76 => fs::truncate(ctx, a[0], a[1] as i64),
        77 => fs::ftruncate(ctx, fd, a[1] as i64),
        79 => fs::getcwd(ctx, a[0], a[1]),
        80 => fs::chdir(ctx, a[0]),
        81 => fs::fchdir(ctx, fd),
        83 => fs::mkdirat(ctx, crate::abi::AT_FDCWD, a[0], a[1] as u32),
        84 => fs::unlinkat(ctx, crate::abi::AT_FDCWD, a[0], crate::abi::AT_REMOVEDIR),
        87 => fs::unlinkat(ctx, crate::abi::AT_FDCWD, a[0], 0),
        89 => fs::readlinkat(ctx, crate::abi::AT_FDCWD, a[0]),
        95 => Ok(ctx
            .process()
            .umask
            .swap(a[0] as u32 & 0o777, Ordering::Relaxed) as u64),
        96 => info::gettimeofday(ctx, a[0]),
        97 => info::getrlimit(ctx, a[0] as u32, a[1]),
        98 => info::getrusage(ctx, a[1]),
        102 | 104 | 107 | 108 => Ok(0), // getuid, getgid, geteuid, getegid: root
        105 | 106 => Ok(0),             // setuid, setgid to root
        110 => Ok(ctx.process().ppid as u64),
        118 | 120 => info::getres_ids(ctx, a),
        131 => process::sigaltstack(ctx, a[0], a[1]),
        158 => process::arch_prctl(ctx, a[0] as u32, a[1]),
        186 => Ok(ctx.thread().tid as u64),
        201 => info::time(ctx, a[0]),
        204 => info::sched_getaffinity(ctx, a[1], a[2]),
        217 => fs::getdents64(ctx, fd, a[1], a[2]),
        218 => {
            ctx.thread().clear_child_tid.store(a[0], Ordering::Relaxed);
            Ok(ctx.thread().tid as u64)
        }
        228 => info::clock_gettime(ctx, a[0] as u32, a[1]),
        229 => info::clock_getres(ctx, a[0] as u32, a[1]),
        230 => info::clock_nanosleep(ctx, a[0] as u32, a[1] as u32, a[2], a[3]),
        257 => fs::openat(ctx, fd, a[1], a[2] as u32, a[3] as u32),
        258 => fs::mkdirat(ctx, fd, a[1], a[2] as u32),
        262 => fs::stat_path(ctx, fd, a[1], a[2], a[3] as u32),
        263 => fs::unlinkat(ctx, fd, a[1], a[2] as u32),
        267 => fs::readlinkat(ctx, fd, a[1]),
        269 | 439 => fs::faccessat(ctx, fd, a[1], a[2] as u32),
        273 => {
            ctx.thread().robust_list.store(a[0], Ordering::Relaxed);
            Ok(0)
        }
        292 => fs::dup3(ctx, fd, a[1] as i32, a[2] as u32, false),
        302 => info::prlimit64(ctx, a[0] as u32, a[1] as u32, a[2], a[3]),
        318 => info::getrandom(ctx, a[0], a[1]),
        // rseq: glibc probes it and copes without; no log line.
        334 => Err(Errno::ENOSYS),
        _ => {
            report_unknown(ctx, nr);
            Err(Errno::ENOSYS)
        }
    }
}

/// Reads a path argument.
fn path_arg(ctx: &Ctx, addr: u64) -> KResult<alloc::string::String> {
    let p = ctx.mm().read_cstr(addr, crate::fs::PATH_MAX)?;
    if p.is_empty() {
        return Err(Errno::ENOENT);
    }
    Ok(p)
}
