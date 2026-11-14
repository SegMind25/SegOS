//! Per-CPU data, reached through the GS base register.

use super::gdt::TaskStateSegment;
use super::x86;
use crate::sync::Once;
use crate::task::Task;
use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicU64, Ordering};

#[repr(C)]
pub struct PerCpu {
    /// Must stay first: `this_cpu` reads it from `gs:0`.
    self_ptr: *const PerCpu,
    /// Top of the running thread's kernel stack; the `syscall` entry
    /// switches to it (`gs:[KERNEL_RSP]`).
    pub(crate) kernel_rsp: UnsafeCell<u64>,
    /// The user stack pointer, saved by the `syscall` entry.
    pub(crate) user_rsp: UnsafeCell<u64>,
    /// This CPU's TSS: `rsp0` is the stack interrupts from ring 3 use.
    tss: *mut TaskStateSegment,
    pub index: u32,
    pub lapic_id: u32,
    pub ticks: AtomicU64,
    /// Touched only by this CPU, with interrupts disabled.
    pub(crate) current: UnsafeCell<Option<Arc<Task>>>,
    pub(crate) idle: Once<Arc<Task>>,
}

unsafe impl Sync for PerCpu {}

static CPUS: crate::sync::SpinLock<Vec<&'static PerCpu>> = crate::sync::SpinLock::new(Vec::new());

/// Offsets the `syscall` entry uses.
pub const KERNEL_RSP: usize = core::mem::offset_of!(PerCpu, kernel_rsp);
pub const USER_RSP: usize = core::mem::offset_of!(PerCpu, user_rsp);

/// Creates this CPU's block and points GS at it. `tss` is the TSS loaded
/// on this CPU.
pub fn init(index: u32, lapic_id: u32, tss: *mut TaskStateSegment) {
    let cpu: &'static mut PerCpu = Box::leak(Box::new(PerCpu {
        self_ptr: core::ptr::null(),
        kernel_rsp: UnsafeCell::new(0),
        user_rsp: UnsafeCell::new(0),
        tss,
        index,
        lapic_id,
        ticks: AtomicU64::new(0),
        current: UnsafeCell::new(None),
        idle: Once::new(),
    }));
    cpu.self_ptr = cpu;
    unsafe {
        x86::wrmsr(x86::msr::GS_BASE, cpu as *const PerCpu as u64);
        // The user's GS base, swapped in by `swapgs` on the way to ring 3.
        x86::wrmsr(x86::msr::KERNEL_GS_BASE, 0);
    }
    CPUS.lock().push(cpu);
}

impl PerCpu {
    /// Sets the kernel stack that traps and system calls from user mode
    /// land on. Called on every switch to a user thread, interrupts off.
    pub fn set_kernel_stack(&self, top: u64) {
        unsafe {
            *self.kernel_rsp.get() = top;
            // The TSS is packed: rsp[0] is not 8-byte aligned.
            core::ptr::addr_of_mut!((*self.tss).rsp)
                .cast::<u64>()
                .write_unaligned(top);
        }
    }
}

pub fn this_cpu() -> &'static PerCpu {
    let ptr: *const PerCpu;
    unsafe {
        core::arch::asm!("mov {}, gs:[0]", out(reg) ptr, options(nostack, readonly, preserves_flags))
    };
    unsafe { &*ptr }
}

pub fn count() -> usize {
    CPUS.lock().len()
}

/// Timer ticks each CPU has handled, in CPU index order.
pub fn ticks() -> Vec<(u32, u64)> {
    let mut v: Vec<_> = CPUS
        .lock()
        .iter()
        .map(|c| (c.index, c.ticks.load(Ordering::Relaxed)))
        .collect();
    v.sort_unstable();
    v
}
