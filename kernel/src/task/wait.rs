//! Wait queues: threads sleep here until another thread wakes them.
//!
//! A sleeping thread can also be woken by [`super::kick`] (a signal, a
//! timer): it then re-checks its condition, and removes itself from the
//! queue before deciding what to do, so no stale entry is ever left
//! behind to swallow another thread's wake-up.

use super::{State, Task, sched};
use crate::abi::{Errno, KResult};
use crate::sync::SpinLock;
use alloc::collections::VecDeque;
use alloc::sync::Arc;
use core::sync::atomic::{Ordering, fence};

pub struct WaitQueue {
    waiters: SpinLock<VecDeque<Arc<Task>>>,
}

impl Default for WaitQueue {
    fn default() -> Self {
        Self::new()
    }
}

impl WaitQueue {
    pub const fn new() -> Self {
        Self {
            waiters: SpinLock::new(VecDeque::new()),
        }
    }

    /// Sleeps until `cond` is true. `cond` is checked under the queue lock,
    /// and wakers take the same lock, so a wake-up cannot be lost between
    /// the check and going to sleep.
    pub fn wait_until(&self, mut cond: impl FnMut() -> bool) {
        let _ = self.wait(&mut cond, false);
    }

    /// Like [`wait_until`](Self::wait_until), but a signal for the calling
    /// thread ends the wait with `ERESTARTSYS` (the system call is then
    /// restarted or fails with `EINTR`, see `proc::signal`).
    pub fn wait_interruptible(&self, mut cond: impl FnMut() -> bool) -> KResult<()> {
        self.wait(&mut cond, true)
    }

    fn wait(&self, cond: &mut dyn FnMut() -> bool, interruptible: bool) -> KResult<()> {
        let me = sched::current();
        loop {
            let mut q = self.waiters.lock();
            // Blocked *before* looking at the condition: a waker or kick
            // that comes after the check then finds us Blocked and wakes
            // us. The fence pairs with the one in signal sending.
            me.set_state(State::Blocked);
            fence(Ordering::SeqCst);
            let result = if cond() {
                Some(Ok(()))
            } else if interruptible && crate::proc::signal::pending() {
                Some(Err(Errno::ERESTARTSYS))
            } else {
                None
            };
            if let Some(r) = result {
                if !me.cas_state(State::Blocked, State::Running) {
                    // Kicked meanwhile: we are on the run queue already;
                    // let the scheduler take us off it.
                    drop(q);
                    sched::schedule();
                }
                return r;
            }
            q.push_back(me.clone());
            drop(q);
            sched::schedule();
            self.forget(&me);
        }
    }

    /// Removes `me` if a kick (not a wake) ended the sleep.
    fn forget(&self, me: &Arc<Task>) {
        self.waiters.lock().retain(|t| !Arc::ptr_eq(t, me));
    }

    pub fn wake_one(&self) {
        let mut q = self.waiters.lock();
        while let Some(t) = q.pop_front() {
            if wake(t) {
                return;
            }
        }
    }

    pub fn wake_all(&self) {
        let mut q = self.waiters.lock();
        while let Some(t) = q.pop_front() {
            wake(t);
        }
    }
}

fn wake(t: Arc<Task>) -> bool {
    if t.cas_state(State::Blocked, State::Ready) {
        sched::make_ready(t);
        true
    } else {
        false
    }
}

/// Makes a blocked task runnable without going through its wait queue: it
/// wakes, re-checks why it slept, and sleeps again if nothing changed.
pub fn kick(t: &Arc<Task>) {
    wake(t.clone());
}

/// A one-shot event: `vfork` waits for the child to exec or exit.
#[derive(Default)]
pub struct Completion {
    done: core::sync::atomic::AtomicBool,
    queue: WaitQueue,
}

impl Completion {
    pub fn complete(&self) {
        self.done.store(true, Ordering::Release);
        self.queue.wake_all();
    }

    pub fn wait(&self) {
        self.queue.wait_until(|| self.done.load(Ordering::Acquire));
    }
}
