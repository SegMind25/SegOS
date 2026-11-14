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

pub fn nanosleep(ctx: &Ctx, req: u64, _rem: u64) -> KResult<u64> {
    let ns = read_timespec(ctx, req)?;
    time::sleep_ns(ns);
    Ok(0)
}

pub fn clock_nanosleep(ctx: &Ctx, clock: u32, flags: u32, req: u64, _rem: u64) -> KResult<u64> {
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
    time::sleep_ns(wait);
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
    if pid != 0 && pid != ctx.process().pid {
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
