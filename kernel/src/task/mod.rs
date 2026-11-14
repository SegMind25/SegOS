//! Kernel threads.
//!
//! A [`Task`] is a kernel thread with its own stack. A user thread is a
//! task with a [`UserThread`] attached (see `proc`); the scheduler treats
//! both the same.

pub mod sched;
pub mod wait;

use crate::mm::{PAGE_SIZE, paging};
use crate::proc::UserThread;
use alloc::boxed::Box;
use alloc::sync::Arc;
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, AtomicU8, AtomicU32, AtomicU64, Ordering};
use wait::WaitQueue;

#[allow(unused_imports)]
pub use sched::{current, exit, schedule as yield_now, spawn};
pub use wait::kick;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum State {
    Running = 0,
    Ready = 1,
    Blocked = 2,
    Dead = 3,
}

pub struct Task {
    pub id: u64,
    pub name: &'static str,
    /// Saved stack pointer while switched out.
    pub(crate) rsp: UnsafeCell<u64>,
    state: AtomicU8,
    /// Set while a CPU is running on this task's stack; another CPU must not
    /// switch to the task until the switch away from it has completed.
    pub(crate) on_cpu: AtomicBool,
    pub last_cpu: AtomicU32,
    pub(crate) entry: UnsafeCell<Option<Box<dyn FnOnce() + Send>>>,
    pub(crate) exited: WaitQueue,
    stack: Option<KernelStack>,
    user: Option<Box<UserThread>>,
}

unsafe impl Send for Task {}
unsafe impl Sync for Task {}

static NEXT_ID: AtomicU64 = AtomicU64::new(0);

impl Task {
    pub fn state(&self) -> State {
        match self.state.load(Ordering::Acquire) {
            0 => State::Running,
            1 => State::Ready,
            2 => State::Blocked,
            _ => State::Dead,
        }
    }

    pub(crate) fn set_state(&self, s: State) {
        self.state.store(s as u8, Ordering::Release);
    }

    pub(crate) fn cas_state(&self, from: State, to: State) -> bool {
        self.state
            .compare_exchange(from as u8, to as u8, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }

    /// The context a CPU booted on, which becomes its idle task.
    pub(crate) fn boot(name: &'static str) -> Self {
        Self::build(name, None, 0, None, None)
    }

    pub(crate) fn new(name: &'static str, f: Box<dyn FnOnce() + Send>) -> Self {
        let stack = KernelStack::new().expect("out of memory for a kernel stack");
        let rsp = sched::initial_stack(stack.top);
        Self::build(name, Some(stack), rsp, Some(f), None)
    }

    /// A user thread: its first run returns to user mode with `frame`.
    pub(crate) fn new_user(user: UserThread, frame: &crate::hal::idt::TrapFrame) -> Self {
        let stack = KernelStack::new().expect("out of memory for a kernel stack");
        let rsp = sched::initial_user_stack(stack.top, frame);
        Self::build("user", Some(stack), rsp, None, Some(Box::new(user)))
    }

    fn build(
        name: &'static str,
        stack: Option<KernelStack>,
        rsp: u64,
        entry: Option<Box<dyn FnOnce() + Send>>,
        user: Option<Box<UserThread>>,
    ) -> Self {
        Self {
            id: NEXT_ID.fetch_add(1, Ordering::Relaxed),
            name,
            rsp: UnsafeCell::new(rsp),
            state: AtomicU8::new(if stack.is_some() {
                State::Ready
            } else {
                State::Running
            } as u8),
            on_cpu: AtomicBool::new(stack.is_none()),
            last_cpu: AtomicU32::new(0),
            entry: UnsafeCell::new(entry),
            exited: WaitQueue::new(),
            stack,
            user,
        }
    }

    /// The user-mode side of the thread, if it has one.
    pub fn user(&self) -> Option<&UserThread> {
        self.user.as_deref()
    }

    /// Top of the kernel stack (0 for a CPU's boot/idle context).
    pub fn kernel_stack_top(&self) -> u64 {
        self.stack.as_ref().map_or(0, |s| s.top)
    }

    /// Waits until the task has exited.
    pub fn join(&self) {
        self.exited.wait_until(|| self.state() == State::Dead);
    }
}

/// A kernel stack with an unmapped guard page below it: an overflow faults
/// (and reaches the double-fault handler on its own stack) instead of
/// silently corrupting memory.
pub struct KernelStack {
    base: u64,
    top: u64,
}

pub const STACK_PAGES: u64 = 16; // 64 KiB
const STACK_REGION: u64 = 0xffff_d800_0000_0000;
static NEXT_SLOT: AtomicU64 = AtomicU64::new(0);

impl KernelStack {
    pub fn top(&self) -> u64 {
        self.top
    }

    pub fn new() -> Option<Self> {
        let slot = NEXT_SLOT.fetch_add(1, Ordering::Relaxed);
        let guard = STACK_REGION + slot * (STACK_PAGES + 1) * PAGE_SIZE;
        let base = guard + PAGE_SIZE;
        paging::map_new(base, STACK_PAGES).ok()?;
        Some(Self {
            base,
            top: base + STACK_PAGES * PAGE_SIZE,
        })
    }
}

impl Drop for KernelStack {
    fn drop(&mut self) {
        for i in 0..STACK_PAGES {
            paging::unmap(self.base + i * PAGE_SIZE);
        }
    }
}

pub fn spawn_named(name: &'static str, f: impl FnOnce() + Send + 'static) -> Arc<Task> {
    sched::spawn_task(Task::new(name, Box::new(f)))
}

/// A user thread that starts in user mode with `frame` once [`start`]ed.
pub fn new_user(user: UserThread, frame: crate::hal::idt::TrapFrame) -> Arc<Task> {
    Arc::new(Task::new_user(user, &frame))
}

/// Makes a task from [`new_user`] runnable.
pub fn start(task: Arc<Task>) {
    sched::make_ready(task);
}
