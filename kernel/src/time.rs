//! Time: uptime from the TSC (nanoseconds), wall-clock time from the RTC
//! read at boot, and the scheduler tick.
//!
//! The TSC frequency is measured against the PIT at boot (in
//! `apic::calibrate_10ms`). Modern CPUs keep the TSC constant-rate and in
//! step across cores; older ones would need the HPET instead.

use crate::hal::apic::HZ;
use core::sync::atomic::{AtomicU64, Ordering};

static TICKS: AtomicU64 = AtomicU64::new(0);
static TSC_HZ: AtomicU64 = AtomicU64::new(0);
static TSC_BOOT: AtomicU64 = AtomicU64::new(0);
/// Unix time (seconds) at the moment `TSC_BOOT` was taken.
static REALTIME_BOOT: AtomicU64 = AtomicU64::new(0);

pub const NS_PER_SEC: u64 = 1_000_000_000;

pub fn tick() {
    TICKS.fetch_add(1, Ordering::Relaxed);
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

/// Sleeps at least `ns` nanoseconds, yielding the CPU meanwhile.
/// (Yields in a loop; a timer wheel that blocks the thread comes later.)
pub fn sleep_ns(ns: u64) {
    let until = monotonic_ns() + ns;
    while monotonic_ns() < until {
        crate::task::yield_now();
        core::hint::spin_loop();
    }
}
