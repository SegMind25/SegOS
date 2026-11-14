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
            *ctx.process().name.lock() =
                alloc::string::String::from_utf8_lossy(&raw[..end]).into_owned();
            Ok(0)
        }
        PR_GET_NAME => {
            let mut raw = [0u8; 16];
            let name = ctx.process().name.lock().clone();
            let n = name.len().min(15);
            raw[..n].copy_from_slice(&name.as_bytes()[..n]);
            ctx.mm().copy_to(a[1], &raw)?;
            Ok(0)
        }
        PR_GET_DUMPABLE => Ok(1),
        PR_SET_PDEATHSIG | PR_SET_DUMPABLE | PR_SET_CHILD_SUBREAPER | PR_SET_NO_NEW_PRIVS => Ok(0),
        PR_GET_NO_NEW_PRIVS => Ok(0),
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
