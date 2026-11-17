//! Linux system calls: numbers, dispatch, and the calls themselves.
//!
//! The numbers are Linux's x86-64 ones (`arch/x86/entry/syscalls`). Each
//! handler returns `Ok(value)` or `Err(errno)`; the program sees `-errno`
//! in RAX, exactly as on Linux. An unknown call returns `ENOSYS` and is
//! logged once per number: that log is the to-do list.

mod event;
mod fs;
mod info;
mod mem;
mod net;
mod process;

use crate::abi::{AT_FDCWD, AT_REMOVEDIR, AT_SYMLINK_NOFOLLOW, Errno, KResult};
use crate::hal::idt::TrapFrame;
use crate::hal::x86;
use crate::mm::vm::AddressSpace;
use crate::proc::ns::Ids;
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

/// `rt_sigreturn`: its result is the restored RAX, not a status.
const SYS_RT_SIGRETURN: u64 = 15;

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
        let r = match filter(&ctx, frame, nr, a) {
            None => dispatch(&ctx, frame, nr, a),
            Some(r) => r,
        };
        trace(&ctx, nr, a, &r);
        r
    };
    frame.rax = match result {
        Ok(v) => v,
        Err(e) => (-(e.0 as i64)) as u64,
    };
    // exit, exit_group or a fatal signal: leave now that no reference to
    // the thread or its memory is held on this stack.
    let pending = crate::task::current()
        .user()
        .and_then(|u| u.take_pending_exit());
    if let Some(status) = pending {
        crate::proc::exit(status);
    }
    let restartable = (nr != SYS_RT_SIGRETURN).then_some(nr);
    crate::proc::signal::on_return_to_user(frame, restartable);
    x86::disable_interrupts();
}

/// seccomp: what the thread's filters say about the call. None: run it;
/// otherwise its result without running it.
fn filter(ctx: &Ctx, frame: &TrapFrame, nr: u64, a: [u64; 6]) -> Option<KResult<u64>> {
    use crate::proc::seccomp::{self, Verdict};
    let t = ctx.thread();
    let verdict = match t.seccomp_mode.load(Ordering::Relaxed) {
        seccomp::MODE_DISABLED => return None,
        seccomp::MODE_STRICT if seccomp::strict_allows(nr) => return None,
        seccomp::MODE_STRICT => {
            t.request_exit(crate::proc::signo::SIGKILL);
            return Some(Err(Errno::EPERM));
        }
        _ => {
            let f = t.seccomp.lock().clone()?;
            seccomp::evaluate(&f, nr, &a, frame.rip)
        }
    };
    match verdict {
        Verdict::Allow => None,
        Verdict::Errno(e) => Some(Err(e)),
        Verdict::Trap(data) => {
            // As Linux: the handler sees RAX holding the call's number.
            crate::proc::signal::force(
                t,
                crate::proc::signo::SIGSYS,
                crate::proc::signal::SigInfo::seccomp(frame.rip, nr, data as i32),
            );
            Some(Ok(nr))
        }
        Verdict::Kill { process } => {
            let status = crate::proc::signo::SIGSYS;
            if process {
                t.request_exit(status);
            } else {
                t.request_thread_exit(status);
            }
            Some(Err(Errno::ENOSYS))
        }
    }
}

/// `SEGOS_STRACE`: logs the call if the process asked for it.
fn trace(ctx: &Ctx, nr: u64, a: [u64; 6], r: &KResult<u64>) {
    let level = ctx.process().trace.load(Ordering::Relaxed);
    if level == 0 || (level == 1 && r.is_ok()) || nr == SYS_RT_SIGRETURN {
        return;
    }
    let p = ctx.process();
    let res = match r {
        Ok(v) => alloc::format!("{v:#x}"),
        Err(e) => alloc::format!("-{}", e.0),
    };
    let path_at = match nr {
        2 | 4 | 6 | 21 | 59 | 80 | 83 | 84 | 87 | 89 | 137 => Some(a[0]),
        257 | 258 | 262 | 263 | 267 | 269 | 332 | 439 => Some(a[1]),
        _ => None,
    };
    let path = path_at
        .and_then(|at| ctx.mm().read_cstr(at, 256).ok())
        .map(|s| alloc::format!(" \"{s}\""))
        .unwrap_or_default();
    let comm = ctx.thread().comm.lock().clone();
    let name = comm.unwrap_or_else(|| p.name.lock().clone());
    crate::debug!(
        "strace {}[{}/{}]: {nr}({:#x}, {:#x}, {:#x}, {:#x}, {:#x}){path} = {res}",
        name,
        p.pid,
        ctx.thread().tid,
        a[0],
        a[1],
        a[2],
        a[3],
        a[4]
    );
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

fn dispatch(ctx: &Ctx, frame: &mut TrapFrame, nr: u64, a: [u64; 6]) -> KResult<u64> {
    let fd = a[0] as i32;
    match nr {
        0 => fs::read(ctx, fd, a[1], a[2]),
        1 => fs::write(ctx, fd, a[1], a[2]),
        2 => fs::openat(ctx, AT_FDCWD, a[0], a[1] as u32, a[2] as u32),
        3 => fs::close(ctx, fd),
        4 => fs::stat_path(ctx, AT_FDCWD, a[0], a[1], 0),
        5 => fs::fstat(ctx, fd, a[1]),
        6 => fs::stat_path(ctx, AT_FDCWD, a[0], a[1], AT_SYMLINK_NOFOLLOW),
        7 => fs::poll(ctx, a[0], a[1], a[2] as i32 as i64),
        8 => fs::lseek(ctx, fd, a[1] as i64, a[2] as u32),
        9 => mem::mmap(ctx, a[0], a[1], a[2] as u32, a[3] as u32, a[4] as i32, a[5]),
        10 => mem::mprotect(ctx, a[0], a[1], a[2] as u32),
        11 => mem::munmap(ctx, a[0], a[1]),
        12 => Ok(ctx.mm().brk(a[0])),
        13 => process::rt_sigaction(ctx, a[0] as i32, a[1], a[2], a[3]),
        14 => process::rt_sigprocmask(ctx, a[0] as i32, a[1], a[2], a[3]),
        15 => crate::proc::signal::sigreturn(ctx.thread(), frame),
        16 => fs::ioctl(ctx, fd, a[1] as u32, a[2]),
        17 => fs::pread(ctx, fd, a[1], a[2], a[3] as i64),
        18 => fs::pwrite(ctx, fd, a[1], a[2], a[3] as i64),
        19 => fs::readv(ctx, fd, a[1], a[2]),
        20 => fs::writev(ctx, fd, a[1], a[2]),
        21 => fs::faccessat(ctx, AT_FDCWD, a[0], a[1] as u32),
        22 => fs::pipe2(ctx, a[0], 0),
        23 => fs::select(ctx, a[0] as i32, [a[1], a[2], a[3]], a[4], None),
        24 => {
            crate::task::yield_now();
            Ok(0)
        }
        25 => mem::mremap(ctx, a[0], a[1], a[2], a[3] as u32),
        26 => {
            // msync: write back shared file mappings.
            crate::fs::pagecache::sync_all();
            Ok(0)
        }
        28 => Ok(0),  // madvise: advice may be ignored
        221 => Ok(0), // fadvise64: likewise
        32 => fs::dup(ctx, fd),
        33 => fs::dup3(ctx, fd, a[1] as i32, 0, true),
        34 => process::pause(ctx),
        35 => info::nanosleep(ctx, a[0], a[1]),
        36 => info::getitimer(ctx, a[0] as u32, a[1]),
        37 => info::alarm(ctx, a[0]),
        38 => info::setitimer(ctx, a[0] as u32, a[1], a[2]),
        39 => Ok(ctx.process().ns_pid as u64),
        40 => fs::sendfile(ctx, fd, a[1] as i32, a[2], a[3]),
        56 => process::clone(ctx, frame, a[0], a[1], a[2], a[3], a[4]),
        57 => process::clone(ctx, frame, crate::proc::signo::SIGCHLD as u64, 0, 0, 0, 0),
        58 => {
            use crate::proc::clone_flags::{CLONE_VFORK, CLONE_VM};
            let flags = CLONE_VM | CLONE_VFORK | crate::proc::signo::SIGCHLD as u64;
            process::clone(ctx, frame, flags, 0, 0, 0, 0)
        }
        59 => process::execve(ctx, frame, a[0], a[1], a[2]),
        60 => process::exit(ctx, a[0] as i32),
        231 => process::exit_group(ctx, a[0] as i32),
        61 => process::wait4(ctx, a[0] as i32, a[1], a[2] as u32, a[3]),
        62 | 200 | 234 => process::kill(ctx, a, nr),
        63 => info::uname(ctx, a[0]),
        72 => fs::fcntl(ctx, fd, a[1] as u32, a[2]),
        74 | 75 => fs::fsync(ctx, fd),
        76 => fs::truncate(ctx, a[0], a[1] as i64),
        73 => fs::flock(ctx, fd, a[1] as u32),
        77 => fs::ftruncate(ctx, fd, a[1] as i64),
        285 => fs::fallocate(ctx, fd, a[1] as u32, a[2] as i64, a[3] as i64),
        79 => fs::getcwd(ctx, a[0], a[1]),
        80 => fs::chdir(ctx, a[0]),
        81 => fs::fchdir(ctx, fd),
        82 => fs::renameat(ctx, AT_FDCWD, a[0], AT_FDCWD, a[1], 0),
        83 => fs::mkdirat(ctx, AT_FDCWD, a[0], a[1] as u32),
        84 => fs::unlinkat(ctx, AT_FDCWD, a[0], AT_REMOVEDIR),
        86 => fs::linkat(ctx, AT_FDCWD, a[0], AT_FDCWD, a[1]),
        87 => fs::unlinkat(ctx, AT_FDCWD, a[0], 0),
        88 => fs::symlinkat(ctx, a[0], AT_FDCWD, a[1]),
        89 => fs::readlinkat(ctx, AT_FDCWD, a[0], a[1], a[2]),
        90 => fs::fchmodat(ctx, AT_FDCWD, a[0], a[1] as u32),
        91 => fs::fchmod(ctx, fd, a[1] as u32),
        // chown, fchown, lchown, fchownat: everything is root's; the ids
        // must be mapped in the caller's user namespace.
        92..=94 => info::check_owner(ctx, a[1], a[2]),
        260 => info::check_owner(ctx, a[2], a[3]),
        95 => Ok(ctx
            .process()
            .fs()
            .umask
            .swap(a[0] as u32 & 0o777, Ordering::Relaxed) as u64),
        161 => fs::chroot(ctx, a[0]),
        96 => info::gettimeofday(ctx, a[0]),
        97 => info::getrlimit(ctx, a[0] as u32, a[1]),
        98 => info::getrusage(ctx, a[1]),
        99 => info::sysinfo(ctx, a[0]),
        100 => info::times(ctx, a[0]),
        // getuid, geteuid, getgid, getegid: root, as the caller's user
        // namespace sees it.
        102 | 107 => Ok(ctx.process().user_ns.lock().view(Ids::Uid, 0) as u64),
        104 | 108 => Ok(ctx.process().user_ns.lock().view(Ids::Gid, 0) as u64),
        // setuid, setgid, setreuid, setregid, setresuid, setresgid,
        // setfsuid, setfsgid, setgroups: everything runs as root; an id
        // must be mapped in the caller's user namespace.
        105 | 106 | 113 | 114 | 117 | 119 | 122 | 123 => info::set_ids(ctx, nr, a),
        116 => info::setgroups(ctx, a[0], a[1]),
        109 => process::setpgid(ctx, a[0] as u32, a[1] as u32),
        110 => {
            let p = ctx.process();
            Ok(p.pid_ns.nr(p.ppid.load(Ordering::Relaxed)) as u64)
        }
        111 => Ok(ctx.process().pid_ns.nr(ctx.process().pgid()) as u64),
        112 => process::setsid(ctx),
        115 => info::getgroups(ctx, a[0], a[1]),
        118 => info::getres_ids(ctx, a, Ids::Uid),
        120 => info::getres_ids(ctx, a, Ids::Gid),
        121 => process::getpgid(ctx, a[0] as u32),
        124 => process::getsid(ctx, a[0] as u32),
        127 => process::rt_sigpending(ctx, a[0], a[1]),
        128 => process::rt_sigtimedwait(ctx, a[0], a[1], a[2], a[3]),
        130 => process::rt_sigsuspend(ctx, a[0], a[1]),
        131 => process::sigaltstack(ctx, frame, a[0], a[1]),
        132 | 235 | 280 => fs::utimes(ctx, nr, a),
        133 => fs::mknodat(ctx, AT_FDCWD, a[0], a[1] as u32),
        259 => fs::mknodat(ctx, fd, a[1], a[2] as u32),
        165 => fs::mount(ctx, a[0], a[1], a[2], a[3]),
        // Extended attributes: none exist; setting them is unsupported.
        188..=190 => Err(Errno::EOPNOTSUPP),
        191..=193 | 197..=199 => Err(Errno::ENODATA),
        194..=196 => Ok(0), // listxattr: an empty list
        332 => fs::statx(ctx, a[0] as i32, a[1], a[2] as u32, a[4]),
        41 => net::socket(ctx, a[0] as u32, a[1] as u32, a[2] as u32),
        42 => net::connect(ctx, fd, a[1], a[2]),
        43 => net::accept4(ctx, fd, a[1], a[2], 0),
        288 => net::accept4(ctx, fd, a[1], a[2], a[3] as u32),
        44 => net::sendto(ctx, fd, a[1], a[2], a[3] as u32, a[4], a[5]),
        45 => net::recvfrom(ctx, fd, a[1], a[2], a[3] as u32, a[4], a[5]),
        46 => net::sendmsg(ctx, fd, a[1], a[2] as u32),
        47 => net::recvmsg(ctx, fd, a[1], a[2] as u32),
        299 => net::recvmmsg(ctx, fd, a[1], a[2] as u32, a[3] as u32),
        307 => net::sendmmsg(ctx, fd, a[1], a[2] as u32, a[3] as u32),
        48 => net::shutdown(ctx, fd, a[1] as u32),
        49 => net::bind(ctx, fd, a[1], a[2]),
        50 => net::listen(ctx, fd, a[1] as u32),
        51 => net::getsockname(ctx, fd, a[1], a[2]),
        52 => net::getpeername(ctx, fd, a[1], a[2]),
        53 => net::socketpair(ctx, a[0] as u32, a[1] as u32, a[2] as u32, a[3]),
        54 => net::setsockopt(ctx, fd, a[1] as u32, a[2] as u32, a[3], a[4]),
        55 => net::getsockopt(ctx, fd, a[1] as u32, a[2] as u32, a[3], a[4]),
        166 => fs::umount2(ctx, a[0], a[1]),
        137 => fs::statfs(ctx, a[0], a[1], false),
        138 => fs::statfs(ctx, a[0], a[1], true),
        140 | 141 => Ok(0), // getpriority, setpriority: everyone at nice 0
        157 => info::prctl(ctx, a),
        317 => process::seccomp(ctx, a[0] as u32, a[1] as u32, a[2]),
        158 => process::arch_prctl(ctx, a[0] as u32, a[1]),
        162 => {
            crate::fs::pagecache::sync_all();
            crate::block::sync_all();
            Ok(0)
        }
        169 => info::reboot(a[0] as u32, a[1] as u32, a[2] as u32),
        186 => Ok(ctx.thread().ns_tid as u64),
        201 => info::time(ctx, a[0]),
        202 => process::futex(ctx, a),
        204 => info::sched_getaffinity(ctx, a[1], a[2]),
        203 => info::sched_setaffinity(ctx, a[0] as u32, a[1], a[2]),
        142 => info::sched_setparam(ctx, a[0] as u32, a[1]),
        143 => info::sched_getparam(ctx, a[0] as u32, a[1]),
        144 => info::sched_setscheduler(ctx, a[0] as u32, a[1] as u32, a[2]),
        145 => info::sched_getscheduler(ctx, a[0] as u32),
        146 => info::sched_priority_limit(a[0] as u32, true),
        147 => info::sched_priority_limit(a[0] as u32, false),
        148 => info::sched_rr_get_interval(ctx, a[0] as u32, a[1]),
        314 => info::sched_setattr(ctx, a[0] as u32, a[1], a[2] as u32),
        315 => info::sched_getattr(ctx, a[0] as u32, a[1], a[2] as u32, a[3] as u32),
        // mbind, set_mempolicy: one node, nothing to choose between.
        237 | 238 => Ok(0),
        239 => info::get_mempolicy(ctx, a[0], a[1], a[2]),
        217 => fs::getdents64(ctx, fd, a[1], a[2]),
        218 => {
            ctx.thread().clear_child_tid.store(a[0], Ordering::Relaxed);
            Ok(ctx.thread().ns_tid as u64)
        }
        228 => info::clock_gettime(ctx, a[0] as u32, a[1]),
        229 => info::clock_getres(ctx, a[0] as u32, a[1]),
        230 => info::clock_nanosleep(ctx, a[0] as u32, a[1] as u32, a[2], a[3]),
        247 => process::waitid(ctx, a[0] as u32, a[1] as u32, a[2], a[3] as u32),
        257 => fs::openat(ctx, fd, a[1], a[2] as u32, a[3] as u32),
        258 => fs::mkdirat(ctx, fd, a[1], a[2] as u32),
        262 => fs::stat_path(ctx, fd, a[1], a[2], a[3] as u32),
        263 => fs::unlinkat(ctx, fd, a[1], a[2] as u32),
        264 => fs::renameat(ctx, fd, a[1], a[2] as i32, a[3], 0),
        265 => fs::linkat(ctx, fd, a[1], a[2] as i32, a[3]),
        266 => fs::symlinkat(ctx, a[0], a[1] as i32, a[2]),
        267 => fs::readlinkat(ctx, fd, a[1], a[2], a[3]),
        268 => fs::fchmodat(ctx, fd, a[1], a[2] as u32),
        269 | 439 => fs::faccessat(ctx, fd, a[1], a[2] as u32),
        436 => fs::close_range(ctx, a[0] as u32, a[1] as u32, a[2] as u32),
        270 => fs::select(ctx, a[0] as i32, [a[1], a[2], a[3]], a[4], Some(a[5])),
        271 => fs::ppoll(ctx, a[0], a[1], a[2], a[3]),
        272 => process::unshare(ctx, a[0]),
        273 => process::set_robust_list(ctx, a[0], a[1]),
        274 => process::get_robust_list(ctx, a[0] as u32, a[1], a[2]),
        // Event descriptors.
        213 => event::epoll_create(ctx, a[0] as i32),
        291 => event::epoll_create1(ctx, a[0] as u32),
        233 => event::epoll_ctl(ctx, fd, a[1] as u32, a[2] as i32, a[3]),
        232 => event::epoll_wait(
            ctx,
            fd,
            a[1],
            a[2] as i32,
            event::ms_timeout(a[3] as i32),
            0,
        ),
        281 => event::epoll_wait(
            ctx,
            fd,
            a[1],
            a[2] as i32,
            event::ms_timeout(a[3] as i32),
            a[4],
        ),
        441 => {
            let timeout = event::ts_timeout(ctx, a[3])?;
            event::epoll_wait(ctx, fd, a[1], a[2] as i32, timeout, a[4])
        }
        284 => event::eventfd(ctx, a[0] as u32, 0),
        290 => event::eventfd(ctx, a[0] as u32, a[1] as u32),
        283 => event::timerfd_create(ctx, a[0] as u32, a[1] as u32),
        286 => event::timerfd_settime(ctx, fd, a[1] as u32, a[2], a[3]),
        287 => event::timerfd_gettime(ctx, fd, a[1]),
        282 => event::signalfd(ctx, fd, a[1], a[2], 0),
        289 => event::signalfd(ctx, fd, a[1], a[2], a[3] as u32),
        253 => event::inotify_init(ctx, 0),
        294 => event::inotify_init(ctx, a[0] as u32),
        254 => event::inotify_add_watch(ctx, fd, a[1], a[2] as u32),
        255 => event::inotify_rm_watch(ctx, fd, a[1] as i32),
        309 => info::getcpu(ctx, a[0], a[1]),
        292 => fs::dup3(ctx, fd, a[1] as i32, a[2] as u32, false),
        293 => fs::pipe2(ctx, a[0], a[1] as u32),
        302 => info::prlimit64(ctx, a[0] as u32, a[1] as u32, a[2], a[3]),
        316 => fs::renameat(ctx, fd, a[1], a[2] as i32, a[3], a[4] as u32),
        318 => info::getrandom(ctx, a[0], a[1]),
        319 => fs::memfd_create(ctx, a[0], a[1] as u32),
        // rseq, clone3, membarrier: the C libraries probe these and fall
        // back without them; no log line.
        334 | 435 | 324 => Err(Errno::ENOSYS),
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
