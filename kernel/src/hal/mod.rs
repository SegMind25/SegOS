//! Hardware abstraction for x86-64. Most of the kernel's `unsafe` lives here.

pub mod acpi;
pub mod apic;
pub mod cpu;
pub mod gdt;
pub mod idt;
pub mod percpu;
pub mod rtc;
pub mod serial;
pub mod smp;
pub mod syscall;
pub mod user;
pub mod x86;

/// Brings the CPU into a known state: segments, TSS, exception handlers,
/// SSE for user code, `syscall`; legacy PIC masked (the APIC takes over).
pub fn init() {
    gdt::init_bsp();
    idt::init();
    cpu::init_this_cpu();
    cpu::mask_legacy_pic();
}
