//! Information and time: uname, clocks, sleeping, limits, randomness.

use super::Ctx;
use crate::abi::{Errno, KResult, Timespec, Utsname};
use crate::time::{self, NS_PER_SEC};
use alloc::vec;

fn put(field: &mut [u8; 65], s: &str) {
    let n = s.len().min(64);
    field[..n].copy_from_slice(&s.as_bytes()[..n]);
}

/// What `uname` reports. Programs compare `sysname` with "Linux" and parse
/// `release` for a minimum kernel version (glibc wants 3.2), so SegOS
/// answers as the Linux version whose interface it targets, and says what
/// it really is after the dash.
pub fn uname(ctx: &Ctx, buf: u64) -> KResult<u64> {
    let mut u = Utsname {
        sysname: [0; 65],
        nodename: [0; 65],
        release: [0; 65],
        version: [0; 65],
        machine: [0; 65],
        domainname: [0; 65],
    };
    put(&mut u.sysname, "Linux");
    put(&mut u.nodename, "segos");
    put(
        &mut u.release,
        concat!("6.6.0-segos-", env!("CARGO_PKG_VERSION")),
    );
    put(
        &mut u.version,
        concat!("#1 SegOS ", env!("CARGO_PKG_VERSION")),
    );
    put(&mut u.machine, "x86_64");
    put(&mut u.domainname, "(none)");
    let bytes = unsafe {
        core::slice::from_raw_parts(&u as *const Utsname as *const u8, size_of::<Utsname>())
    };
    ctx.mm().copy_to(buf, bytes)?;
    Ok(0)
}

const CLOCK_REALTIME: u32 = 0;
const CLOCK_MONOTONIC: u32 = 1;
const CLOCK_PROCESS_CPUTIME_ID: u32 = 2;
const CLOCK_THREAD_CPUTIME_ID: u32 = 3;
const CLOCK_MONOTONIC_RAW: u32 = 4;
const CLOCK_REALTIME_COARSE: u32 = 5;
const CLOCK_MONOTONIC_COARSE: u32 = 6;
const CLOCK_BOOTTIME: u32 = 7;

fn now(clock: u32) -> KResult<u64> {
    match clock {
        CLOCK_REALTIME | CLOCK_REALTIME_COARSE => Ok(time::realtime_ns()),
        CLOCK_MONOTONIC | CLOCK_MONOTONIC_RAW | CLOCK_MONOTONIC_COARSE | CLOCK_BOOTTIME => {
            Ok(time::monotonic_ns())
        }
        // No per-thread CPU accounting yet: wall time since boot is an
        // upper bound.
        CLOCK_PROCESS_CPUTIME_ID | CLOCK_THREAD_CPUTIME_ID => Ok(time::monotonic_ns()),
        _ => Err(Errno::EINVAL),
    }
}

fn timespec(ns: u64) -> Timespec {
    Timespec {
        tv_sec: (ns / NS_PER_SEC) as i64,
        tv_nsec: (ns % NS_PER_SEC) as i64,
    }
}

fn read_timespec(ctx: &Ctx, addr: u64) -> KResult<u64> {
    let t: Timespec = ctx.mm().read(addr)?;
    if t.tv_sec < 0 || !(0..NS_PER_SEC as i64).contains(&t.tv_nsec) {
        return Err(Errno::EINVAL);
    }
    Ok((t.tv_sec as u64)
        .saturating_mul(NS_PER_SEC)
        .saturating_add(t.tv_nsec as u64))
}

pub fn clock_gettime(ctx: &Ctx, clock: u32, ts: u64) -> KResult<u64> {
    let ns = now(clock)?;
    ctx.mm().write(ts, &timespec(ns))?;
    Ok(0)
}

pub fn clock_getres(ctx: &Ctx, clock: u32, ts: u64) -> KResult<u64> {
    now(clock)?;
    if ts != 0 {
        ctx.mm().write(ts, &timespec(1))?;
    }
    Ok(0)
}

pub fn gettimeofday(ctx: &Ctx, tv: u64) -> KResult<u64> {
    if tv != 0 {
        let ns = time::realtime_ns();
        let v: [i64; 2] = [(ns / NS_PER_SEC) as i64, ((ns % NS_PER_SEC) / 1000) as i64];
        ctx.mm().write(tv, &v[0])?;
        ctx.mm().write(tv + 8, &v[1])?;
    }
    Ok(0)
}

pub fn time(ctx: &Ctx, tloc: u64) -> KResult<u64> {
    let secs = time::realtime_ns() / NS_PER_SEC;
    if tloc != 0 {
        ctx.mm().write(tloc, &secs)?;
    }
    Ok(secs)
}

fn write_remaining(ctx: &Ctx, rem: u64, deadline: u64) {
    if rem != 0 {
        let left = deadline.saturating_sub(time::monotonic_ns());
        let _ = ctx.mm().write(rem, &timespec(left));
    }
}

pub fn nanosleep(ctx: &Ctx, req: u64, rem: u64) -> KResult<u64> {
    let ns = read_timespec(ctx, req)?;
    let deadline = time::monotonic_ns().saturating_add(ns);
    if time::sleep_until(deadline, true).is_err() {
        write_remaining(ctx, rem, deadline);
        return Err(Errno::EINTR);
    }
    Ok(0)
}

pub fn clock_nanosleep(ctx: &Ctx, clock: u32, flags: u32, req: u64, rem: u64) -> KResult<u64> {
    const TIMER_ABSTIME: u32 = 1;
    if matches!(clock, CLOCK_THREAD_CPUTIME_ID) {
        return Err(Errno::EINVAL);
    }
    let ns = read_timespec(ctx, req)?;
    let current = now(clock)?;
    let wait = if flags & TIMER_ABSTIME != 0 {
        ns.saturating_sub(current)
    } else {
        ns
    };
    let deadline = time::monotonic_ns().saturating_add(wait);
    if time::sleep_until(deadline, true).is_err() {
        if flags & TIMER_ABSTIME == 0 {
            write_remaining(ctx, rem, deadline);
        }
        return Err(Errno::EINTR);
    }
    Ok(0)
}

pub fn getrandom(ctx: &Ctx, buf: u64, len: u64) -> KResult<u64> {
    let n = len.min(1 << 20) as usize;
    let mut bytes = vec![0u8; n];
    crate::random::fill(&mut bytes);
    ctx.mm().copy_to(buf, &bytes)?;
    Ok(n as u64)
}

const RLIM_INFINITY: u64 = u64::MAX;

/// Default limits, as a typical Linux system sets them.
fn rlimit(resource: u32) -> KResult<[u64; 2]> {
    const RLIMIT_STACK: u32 = 3;
    const RLIMIT_CORE: u32 = 4;
    const RLIMIT_NPROC: u32 = 6;
    const RLIMIT_NOFILE: u32 = 7;
    const RLIMIT_MEMLOCK: u32 = 8;
    const RLIM_NLIMITS: u32 = 16;
    Ok(match resource {
        RLIMIT_STACK => [crate::mm::vm::STACK_SIZE, RLIM_INFINITY],
        RLIMIT_CORE => [0, RLIM_INFINITY],
        RLIMIT_NPROC => [4096, 4096],
        RLIMIT_NOFILE => [crate::fs::MAX_FDS as u64, crate::fs::MAX_FDS as u64],
        RLIMIT_MEMLOCK => [8 << 20, 8 << 20],
        r if r < RLIM_NLIMITS => [RLIM_INFINITY, RLIM_INFINITY],
        _ => return Err(Errno::EINVAL),
    })
}

pub fn getrlimit(ctx: &Ctx, resource: u32, out: u64) -> KResult<u64> {
    let l = rlimit(resource)?;
    ctx.mm().write(out, &l[0])?;
    ctx.mm().write(out + 8, &l[1])?;
    Ok(0)
}

pub fn prlimit64(ctx: &Ctx, pid: u32, resource: u32, _new: u64, old: u64) -> KResult<u64> {
    if pid != 0 && crate::proc::lookup(pid).is_none() {
        return Err(Errno::ESRCH);
    }
    let l = rlimit(resource)?;
    // Setting limits is accepted and not enforced yet.
    if old != 0 {
        ctx.mm().write(old, &l[0])?;
        ctx.mm().write(old + 8, &l[1])?;
    }
    Ok(0)
}

pub fn getrusage(ctx: &Ctx, out: u64) -> KResult<u64> {
    // struct rusage: 2 timevals and 14 longs, all zero for now.
    ctx.mm().copy_to(out, &[0u8; 144])?;
    Ok(0)
}

/// getresuid / getresgid: everything runs as root.
pub fn getres_ids(ctx: &Ctx, a: [u64; 6]) -> KResult<u64> {
    for &p in &a[..3] {
        ctx.mm().write(p, &0u32)?;
    }
    Ok(0)
}

/// The CPUs a thread may run on: all of them.
pub fn sched_getaffinity(ctx: &Ctx, len: u64, mask: u64) -> KResult<u64> {
    let cpus = crate::hal::percpu::count();
    let bytes = cpus.div_ceil(64) * 8;
    if (len as usize) < bytes || !len.is_multiple_of(8) {
        return Err(Errno::EINVAL);
    }
    let mut out = vec![0u8; bytes];
    for c in 0..cpus {
        out[c / 8] |= 1 << (c % 8);
    }
    ctx.mm().copy_to(mask, &out)?;
    Ok(bytes as u64)
}

/// `sysinfo`: uptime, memory and process count.
pub fn sysinfo(ctx: &Ctx, buf: u64) -> KResult<u64> {
    let mut b = [0u8; 112];
    let put =
        |b: &mut [u8; 112], off: usize, v: u64| b[off..off + 8].copy_from_slice(&v.to_le_bytes());
    put(&mut b, 0, time::monotonic_ns() / NS_PER_SEC);
    put(&mut b, 32, crate::mm::frame::total_count() * 4096);
    put(&mut b, 40, crate::mm::frame::free_count() * 4096);
    let procs = crate::proc::all().len() as u16;
    b[80..82].copy_from_slice(&procs.to_le_bytes());
    b[104..108].copy_from_slice(&1u32.to_le_bytes()); // mem_unit
    ctx.mm().copy_to(buf, &b)?;
    Ok(0)
}

/// `times`: CPU times are not accounted yet (zeros); returns clock ticks
/// since boot.
pub fn times(ctx: &Ctx, buf: u64) -> KResult<u64> {
    if buf != 0 {
        ctx.mm().copy_to(buf, &[0u8; 32])?;
    }
    Ok(time::monotonic_ns() / (NS_PER_SEC / crate::hal::apic::HZ))
}

/// `getgroups`: no supplementary groups.
pub fn getgroups(_ctx: &Ctx, _size: u64, _list: u64) -> KResult<u64> {
    Ok(0)
}

pub fn prctl(ctx: &Ctx, a: [u64; 6]) -> KResult<u64> {
    const PR_SET_PDEATHSIG: u64 = 1;
    const PR_GET_DUMPABLE: u64 = 3;
    const PR_SET_DUMPABLE: u64 = 4;
    const PR_SET_NAME: u64 = 15;
    const PR_GET_NAME: u64 = 16;
    const PR_SET_CHILD_SUBREAPER: u64 = 36;
    const PR_SET_NO_NEW_PRIVS: u64 = 38;
    const PR_GET_NO_NEW_PRIVS: u64 = 39;
    const PR_CAPBSET_READ: u64 = 23;
    const PR_GET_SECCOMP: u64 = 21;
    const PR_SET_SECCOMP: u64 = 22;
    const PR_SET_PTRACER: u64 = 0x5961_6d61;
    match a[0] {
        PR_SET_NAME => {
            let mut raw = [0u8; 16];
            // The name may end anywhere in the 16 bytes; read what is there.
            for (i, b) in raw.iter_mut().enumerate() {
                *b = ctx.mm().read(a[1] + i as u64)?;
                if *b == 0 {
                    break;
                }
            }
            raw[15] = 0;
            let end = raw.iter().position(|&b| b == 0).unwrap_or(15);
            let name = alloc::string::String::from_utf8_lossy(&raw[..end]).into_owned();
            // The main thread's name is the process's (/proc/<pid>/comm).
            if ctx.thread().tid == ctx.process().pid {
                *ctx.process().name.lock() = name;
            } else {
                *ctx.thread().comm.lock() = Some(name);
            }
            Ok(0)
        }
        PR_GET_NAME => {
            let mut raw = [0u8; 16];
            let own = ctx.thread().comm.lock().clone();
            let name = own.unwrap_or_else(|| ctx.process().name.lock().clone());
            let n = name.len().min(15);
            raw[..n].copy_from_slice(&name.as_bytes()[..n]);
            ctx.mm().copy_to(a[1], &raw)?;
            Ok(0)
        }
        PR_GET_DUMPABLE => Ok(1),
        // Every capability is in the bounding set (CAP_LAST_CAP is 40).
        PR_CAPBSET_READ if a[1] <= 40 => Ok(1),
        PR_SET_PTRACER => Ok(0),
        PR_SET_PDEATHSIG | PR_SET_DUMPABLE | PR_SET_CHILD_SUBREAPER => Ok(0),
        PR_SET_NO_NEW_PRIVS if a[1] == 1 && a[2..5] == [0, 0, 0] => {
            ctx.thread()
                .no_new_privs
                .store(true, core::sync::atomic::Ordering::Relaxed);
            Ok(0)
        }
        PR_GET_NO_NEW_PRIVS => Ok(ctx
            .thread()
            .no_new_privs
            .load(core::sync::atomic::Ordering::Relaxed) as u64),
        PR_GET_SECCOMP => Ok(ctx
            .thread()
            .seccomp_mode
            .load(core::sync::atomic::Ordering::Relaxed) as u64),
        PR_SET_SECCOMP => match a[1] {
            1 => super::process::set_strict(ctx),
            2 => super::process::set_filter(ctx, a[2], false, false, false),
            _ => Err(Errno::EINVAL),
        },
        _ => Err(Errno::EINVAL),
    }
}

/// `reboot`: restart, power off, or halt the machine.
pub fn reboot(magic1: u32, magic2: u32, cmd: u32) -> KResult<u64> {
    const MAGIC1: u32 = 0xfee1_dead;
    const MAGIC2: [u32; 4] = [672_274_793, 85_072_278, 369_367_448, 537_993_216];
    const RESTART: u32 = 0x0123_4567;
    const HALT: u32 = 0xcdef_0123;
    const POWER_OFF: u32 = 0x4321_fedc;
    const CAD_ON: u32 = 0x89ab_cdef;
    const CAD_OFF: u32 = 0;
    if magic1 != MAGIC1 || !MAGIC2.contains(&magic2) {
        return Err(Errno::EINVAL);
    }
    if matches!(cmd, RESTART | POWER_OFF | HALT) {
        // Nothing cached may be lost (Linux leaves this to user space; a
        // forced power-off from BusyBox skips it, so the kernel does it).
        crate::fs::pagecache::sync_all();
        crate::block::sync_all();
    }
    match cmd {
        CAD_ON | CAD_OFF => Ok(0),
        RESTART => {
            crate::info!("reboot: restarting");
            crate::hal::cpu::restart()
        }
        POWER_OFF => {
            crate::info!("reboot: power off");
            crate::hal::acpi::power_off();
            crate::info!("reboot: power off failed; system halted");
            crate::hal::cpu::halt_forever()
        }
        HALT => {
            crate::info!("reboot: system halted");
            crate::hal::cpu::halt_forever()
        }
        _ => Err(Errno::EINVAL),
    }
}

/// `getcpu(cpu, node, cache)`: the CPU the caller runs on; one NUMA node.
pub fn getcpu(ctx: &Ctx, cpu: u64, node: u64) -> KResult<u64> {
    let index = crate::hal::x86::without_interrupts(|| crate::hal::percpu::this_cpu().index);
    if cpu != 0 {
        ctx.mm().write(cpu, &index)?;
    }
    if node != 0 {
        ctx.mm().write(node, &0u32)?;
    }
    Ok(0)
}

/// `struct itimerval` from user memory: (interval, value) in ns.
fn read_itimerval(ctx: &Ctx, at: u64) -> KResult<(u64, u64)> {
    let v: [i64; 4] = ctx.mm().read(at)?;
    if v.iter().any(|&x| x < 0) || v[1] >= 1_000_000 || v[3] >= 1_000_000 {
        return Err(Errno::EINVAL);
    }
    let ns = |s: i64, us: i64| s as u64 * 1_000_000_000 + us as u64 * 1000;
    Ok((ns(v[0], v[1]), ns(v[2], v[3])))
}

fn write_itimerval(ctx: &Ctx, at: u64, (left, interval): (u64, u64)) -> KResult<()> {
    if at == 0 {
        return Ok(());
    }
    let tv = |ns: u64| {
        [
            (ns / 1_000_000_000) as i64,
            (ns % 1_000_000_000).div_ceil(1000) as i64,
        ]
    };
    let (i, v) = (tv(interval), tv(left));
    ctx.mm().write(at, &[i[0], i[1], v[0], v[1]])
}

pub fn setitimer(ctx: &Ctx, which: u32, new: u64, old: u64) -> KResult<u64> {
    if which > 2 {
        return Err(Errno::EINVAL);
    }
    let (interval, value) = if new == 0 {
        (0, 0)
    } else {
        read_itimerval(ctx, new)?
    };
    if which != 0 {
        // ITIMER_VIRTUAL and ITIMER_PROF: accepted, never fire.
        return write_itimerval(ctx, old, (0, 0)).map(|()| 0);
    }
    let prev = crate::proc::itimer::set(ctx.process(), value, interval);
    write_itimerval(ctx, old, prev)?;
    Ok(0)
}

pub fn getitimer(ctx: &Ctx, which: u32, cur: u64) -> KResult<u64> {
    if which > 2 {
        return Err(Errno::EINVAL);
    }
    let v = if which == 0 {
        crate::proc::itimer::get(ctx.process())
    } else {
        (0, 0)
    };
    write_itimerval(ctx, cur, v)?;
    Ok(0)
}

pub fn alarm(ctx: &Ctx, secs: u64) -> KResult<u64> {
    let (left, _) = crate::proc::itimer::set(ctx.process(), secs * 1_000_000_000, 0);
    Ok(left.div_ceil(1_000_000_000))
}

// ---------------------------------------------------------------- sched_*

const SCHED_OTHER: u32 = 0;
const SCHED_FIFO: u32 = 1;
const SCHED_RR: u32 = 2;
const SCHED_BATCH: u32 = 3;
const SCHED_IDLE: u32 = 5;
const SCHED_RESET_ON_FORK: u32 = 0x4000_0000;

/// The thread `tid` names (0: the caller).
fn sched_target(ctx: &Ctx, tid: u32) -> KResult<alloc::sync::Arc<crate::task::Task>> {
    if (tid as i32) < 0 {
        return Err(Errno::EINVAL);
    }
    if tid == 0 {
        return Ok(crate::task::current());
    }
    let _ = ctx;
    crate::proc::find_thread(tid).ok_or(Errno::ESRCH)
}

fn sched_state(t: &crate::task::Task) -> (u32, u32) {
    let v = t
        .user()
        .map_or(0, |u| u.sched.load(core::sync::atomic::Ordering::Relaxed));
    (v as u32, (v >> 32) as u32)
}

fn sched_store(t: &crate::task::Task, policy: u32, prio: u32) -> KResult<()> {
    let base = policy & !SCHED_RESET_ON_FORK;
    let valid = match base {
        SCHED_FIFO | SCHED_RR => (1..=99).contains(&prio),
        SCHED_OTHER | SCHED_BATCH | SCHED_IDLE => prio == 0,
        _ => return Err(Errno::EINVAL),
    };
    if !valid {
        return Err(Errno::EINVAL);
    }
    if let Some(u) = t.user() {
        u.sched.store(
            policy as u64 | (prio as u64) << 32,
            core::sync::atomic::Ordering::Relaxed,
        );
    }
    Ok(())
}

/// `sched_setscheduler(tid, policy, param)`.
pub fn sched_setscheduler(ctx: &Ctx, tid: u32, policy: u32, param: u64) -> KResult<u64> {
    let t = sched_target(ctx, tid)?;
    let prio: i32 = ctx.mm().read(param)?;
    sched_store(&t, policy, prio as u32)?;
    Ok(0)
}

/// `sched_getscheduler(tid)`.
pub fn sched_getscheduler(ctx: &Ctx, tid: u32) -> KResult<u64> {
    Ok(sched_state(&*sched_target(ctx, tid)?).0 as u64)
}

/// `sched_setparam(tid, param)`: a new priority, the same policy.
pub fn sched_setparam(ctx: &Ctx, tid: u32, param: u64) -> KResult<u64> {
    let t = sched_target(ctx, tid)?;
    let prio: i32 = ctx.mm().read(param)?;
    sched_store(&t, sched_state(&t).0, prio as u32)?;
    Ok(0)
}

/// `sched_getparam(tid, param)`.
pub fn sched_getparam(ctx: &Ctx, tid: u32, param: u64) -> KResult<u64> {
    let (_, prio) = sched_state(&*sched_target(ctx, tid)?);
    ctx.mm().write(param, &(prio as i32))?;
    Ok(0)
}

/// `sched_get_priority_max` (`max`) and `_min`.
pub fn sched_priority_limit(policy: u32, max: bool) -> KResult<u64> {
    match policy {
        SCHED_FIFO | SCHED_RR => Ok(if max { 99 } else { 1 }),
        SCHED_OTHER | SCHED_BATCH | SCHED_IDLE => Ok(0),
        _ => Err(Errno::EINVAL),
    }
}

/// `sched_rr_get_interval(tid, ts)`: the scheduler's 10 ms tick.
pub fn sched_rr_get_interval(ctx: &Ctx, tid: u32, ts: u64) -> KResult<u64> {
    sched_target(ctx, tid)?;
    ctx.mm().write(ts, &[0i64, 10_000_000])?;
    Ok(0)
}

/// `sched_setaffinity(tid, len, mask)`: every thread may run on every
/// CPU; a mask with none of them is EINVAL, as on Linux.
pub fn sched_setaffinity(ctx: &Ctx, tid: u32, len: u64, mask: u64) -> KResult<u64> {
    sched_target(ctx, tid)?;
    let cpus = crate::hal::percpu::count();
    let mut buf = vec![0u8; (len as usize).min(cpus.div_ceil(8))];
    ctx.mm().copy_from(mask, &mut buf)?;
    if (0..cpus).all(|c| buf.get(c / 8).is_none_or(|b| b & (1 << (c % 8)) == 0)) {
        return Err(Errno::EINVAL);
    }
    Ok(0)
}

/// `sched_setattr(tid, attr, flags)`.
pub fn sched_setattr(ctx: &Ctx, tid: u32, attr: u64, flags: u32) -> KResult<u64> {
    if flags != 0 {
        return Err(Errno::EINVAL);
    }
    let t = sched_target(ctx, tid)?;
    // struct sched_attr: size, policy, flags, nice, priority, ...
    let head: [u32; 7] = ctx.mm().read(attr)?;
    let (policy, prio) = (head[1], head[6]);
    sched_store(&t, policy, prio)?;
    Ok(0)
}

/// `sched_getattr(tid, attr, size, flags)`.
pub fn sched_getattr(ctx: &Ctx, tid: u32, attr: u64, size: u32, flags: u32) -> KResult<u64> {
    const SCHED_ATTR_SIZE: u32 = 56;
    if flags != 0 || size < 48 {
        return Err(Errno::EINVAL);
    }
    let (policy, prio) = sched_state(&*sched_target(ctx, tid)?);
    let mut out = [0u8; SCHED_ATTR_SIZE as usize];
    let n = SCHED_ATTR_SIZE.min(size);
    out[0..4].copy_from_slice(&n.to_le_bytes());
    out[4..8].copy_from_slice(&(policy & !SCHED_RESET_ON_FORK).to_le_bytes());
    out[24..28].copy_from_slice(&prio.to_le_bytes());
    ctx.mm().copy_to(attr, &out[..n as usize])?;
    Ok(0)
}

/// `get_mempolicy(mode, nodemask, maxnode, addr, flags)`: one NUMA node,
/// the default policy.
pub fn get_mempolicy(ctx: &Ctx, mode: u64, nodemask: u64, maxnode: u64) -> KResult<u64> {
    if mode != 0 {
        ctx.mm().write(mode, &0i32)?;
    }
    if nodemask != 0 && maxnode > 0 {
        ctx.mm().write(nodemask, &1u64)?;
    }
    Ok(0)
}
