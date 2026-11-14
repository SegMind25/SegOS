//! Time: uptime from the TSC (nanoseconds), wall-clock time from the RTC
//! read at boot, the scheduler tick, and sleeping threads woken by it.
//!
//! The TSC frequency is measured against the PIT at boot (in
//! `apic::calibrate_10ms`). Modern CPUs keep the TSC constant-rate and in
//! step across cores; older ones would need the HPET instead.

use crate::abi::KResult;
use crate::hal::apic::HZ;
use crate::sync::SpinLock;
use crate::task::Task;
use crate::task::wait::WaitQueue;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

static TICKS: AtomicU64 = AtomicU64::new(0);
static TSC_HZ: AtomicU64 = AtomicU64::new(0);
static TSC_BOOT: AtomicU64 = AtomicU64::new(0);
/// Unix time (seconds) at the moment `TSC_BOOT` was taken.
static REALTIME_BOOT: AtomicU64 = AtomicU64::new(0);

pub const NS_PER_SEC: u64 = 1_000_000_000;

/// Sleeping threads and when to wake them (a list: there are few).
static TIMERS: SpinLock<Vec<(u64, Arc<Task>)>> = SpinLock::new(Vec::new());

/// Called by the bootstrap CPU's timer interrupt.
pub fn tick() {
    TICKS.fetch_add(1, Ordering::Relaxed);
    let now = monotonic_ns();
    let mut due = Vec::new();
    {
        let mut timers = TIMERS.lock();
        let mut i = 0;
        while i < timers.len() {
            if timers[i].0 <= now {
                due.push(timers.swap_remove(i).1);
            } else {
                i += 1;
            }
        }
    }
    for t in due {
        crate::task::kick(&t);
    }
}

/// Wakes the calling thread at `deadline` (monotonic ns) if it is asleep
/// then; the caller sleeps on some wait queue meanwhile.
pub fn wake_at(deadline: u64) -> TimerGuard {
    let me = crate::task::current();
    TIMERS.lock().push((deadline, me.clone()));
    TimerGuard(me)
}

/// Removes the timer `wake_at` set, if it has not fired.
pub struct TimerGuard(Arc<Task>);

impl Drop for TimerGuard {
    fn drop(&mut self) {
        TIMERS.lock().retain(|(_, t)| !Arc::ptr_eq(t, &self.0));
    }
}

/// Sleeps until `deadline` (monotonic ns). With `interruptible`, a signal
/// ends the sleep early with `ERESTARTSYS`.
pub fn sleep_until(deadline: u64, interruptible: bool) -> KResult<()> {
    static NOBODY: WaitQueue = WaitQueue::new();
    if monotonic_ns() >= deadline {
        return Ok(());
    }
    let _timer = wake_at(deadline);
    let done = || monotonic_ns() >= deadline;
    if interruptible {
        NOBODY.wait_interruptible(done)
    } else {
        NOBODY.wait_until(done);
        Ok(())
    }
}

pub(crate) fn set_tsc_hz(hz: u64, now: u64) {
    TSC_HZ.store(hz.max(1), Ordering::Relaxed);
    TSC_BOOT.store(now, Ordering::Relaxed);
    REALTIME_BOOT.store(crate::hal::rtc::unix_time(), Ordering::Relaxed);
}

/// Nanoseconds since the clock was calibrated (early in boot).
pub fn monotonic_ns() -> u64 {
    let hz = TSC_HZ.load(Ordering::Relaxed);
    if hz == 0 {
        return TICKS.load(Ordering::Relaxed) * (NS_PER_SEC / HZ);
    }
    let delta = crate::hal::x86::rdtsc().saturating_sub(TSC_BOOT.load(Ordering::Relaxed));
    (delta as u128 * NS_PER_SEC as u128 / hz as u128) as u64
}

/// Nanoseconds since 1970-01-01 UTC.
pub fn realtime_ns() -> u64 {
    REALTIME_BOOT.load(Ordering::Relaxed) * NS_PER_SEC + monotonic_ns()
}

pub fn uptime_ms() -> u64 {
    monotonic_ns() / 1_000_000
}

pub fn tsc_hz() -> u64 {
    TSC_HZ.load(Ordering::Relaxed)
}

/// Sleeps at least `ms` milliseconds.
pub fn sleep_ms(ms: u64) {
    sleep_ns(ms * 1_000_000)
}

/// Sleeps at least `ns` nanoseconds (to the next timer tick after it).
pub fn sleep_ns(ns: u64) {
    let _ = sleep_until(monotonic_ns().saturating_add(ns), false);
}
