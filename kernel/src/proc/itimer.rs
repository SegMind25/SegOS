//! `alarm` and `setitimer(ITIMER_REAL)`: SIGALRM after a delay, once or
//! periodically. One kernel thread sleeps until the earliest timer.

use super::Process;
use crate::sync::{Once, SpinLock};
use crate::task::wait::WaitQueue;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

struct Timer {
    pid: u32,
    process: Weak<Process>,
    deadline: u64,
    interval: u64,
}

static TIMERS: SpinLock<Vec<Timer>> = SpinLock::new(Vec::new());
static CHANGED: AtomicU64 = AtomicU64::new(0);
static WAKE: WaitQueue = WaitQueue::new();
static THREAD: Once<()> = Once::new();

/// (time left, interval) of `p`'s timer, in ns; (0, 0) if none.
pub fn get(p: &Process) -> (u64, u64) {
    let now = crate::time::monotonic_ns();
    TIMERS
        .lock()
        .iter()
        .find(|t| t.pid == p.pid)
        .map_or((0, 0), |t| {
            (t.deadline.saturating_sub(now).max(1), t.interval)
        })
}

/// Sets `p`'s timer (`value` 0 disarms); returns the old (left, interval).
pub fn set(p: &Arc<Process>, value: u64, interval: u64) -> (u64, u64) {
    THREAD.call_once(|| {
        crate::task::spawn_named("itimer", run);
    });
    let old = get(p);
    let mut t = TIMERS.lock();
    t.retain(|x| x.pid != p.pid && x.process.strong_count() > 0);
    if value > 0 {
        t.push(Timer {
            pid: p.pid,
            process: Arc::downgrade(p),
            deadline: crate::time::monotonic_ns() + value,
            interval,
        });
    }
    drop(t);
    CHANGED.fetch_add(1, Ordering::Release);
    WAKE.wake_all();
    old
}

fn run() {
    loop {
        let now = crate::time::monotonic_ns();
        let mut due = Vec::new();
        let mut next = now + 1_000_000_000;
        TIMERS.lock().retain_mut(|t| {
            if t.process.strong_count() == 0 {
                return false;
            }
            if t.deadline <= now {
                due.push(t.process.clone());
                if t.interval == 0 {
                    return false;
                }
                t.deadline = now + t.interval;
            }
            next = next.min(t.deadline);
            true
        });
        for p in due.into_iter().filter_map(|w| w.upgrade()) {
            super::signal::send(&p, super::signo::SIGALRM, super::signal::SigInfo::kernel());
        }
        let seen = CHANGED.load(Ordering::Acquire);
        let _timer = crate::time::wake_at(next);
        WAKE.wait_until(|| {
            CHANGED.load(Ordering::Acquire) != seen || crate::time::monotonic_ns() >= next
        });
    }
}
