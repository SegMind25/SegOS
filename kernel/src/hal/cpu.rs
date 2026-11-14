//! Small CPU helpers.

use super::x86;

pub fn halt_forever() -> ! {
    loop {
        x86::disable_interrupts();
        x86::halt();
    }
}

/// Per-CPU feature setup, on every CPU before it runs user code:
/// x87/SSE usable from ring 3 (the kernel itself is built without SSE, so
/// only user threads' FPU state needs saving), SMEP and SMAP where the CPU
/// has them (the kernel reaches user memory only through the direct map,
/// so any direct access is a bug and faults), and `syscall`.
pub fn init_this_cpu() {
    let ebx7 = if x86::cpuid(0, 0).0 >= 7 {
        x86::cpuid(7, 0).1
    } else {
        0
    };
    let mut cr4 = x86::read_cr4() | x86::cr4::OSFXSR | x86::cr4::OSXMMEXCPT;
    if ebx7 & (1 << 7) != 0 {
        cr4 |= x86::cr4::SMEP;
    }
    if ebx7 & (1 << 20) != 0 {
        cr4 |= x86::cr4::SMAP;
    }
    unsafe {
        let cr0 = x86::read_cr0();
        x86::write_cr0((cr0 | x86::cr0::MP) & !(x86::cr0::EM | x86::cr0::TS));
        x86::write_cr4(cr4);
        core::arch::asm!("fninit", options(nomem, nostack));
    }
    static LOGGED: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);
    if !LOGGED.swap(true, core::sync::atomic::Ordering::Relaxed) {
        let on = |bit| {
            if cr4 & bit != 0 {
                "on"
            } else {
                "not available"
            }
        };
        crate::info!(
            "cpu: SMEP {}, SMAP {}",
            on(x86::cr4::SMEP),
            on(x86::cr4::SMAP)
        );
    }
    super::syscall::init_this_cpu();
}

/// Masks every line of the two 8259 PICs so they never fire.
pub fn mask_legacy_pic() {
    unsafe {
        x86::outb(0x21, 0xff);
        x86::outb(0xa1, 0xff);
    }
}

/// Exit codes for QEMU's `isa-debug-exit` device (iobase 0xf4).
/// QEMU exits with `(code << 1) | 1`: 33 for success, 35 for failure.
#[derive(Clone, Copy)]
#[repr(u32)]
pub enum QemuExit {
    Success = 0x10,
    Failure = 0x11,
}

pub fn exit_qemu(code: QemuExit) -> ! {
    unsafe { x86::outl(0xf4, code as u32) };
    // Not running under QEMU with the device: stop here.
    halt_forever()
}

/// Walks the frame-pointer chain (the kernel is built with frame pointers)
/// and calls `f` with each return address.
pub fn backtrace(mut f: impl FnMut(usize, u64)) {
    let mut rbp: u64;
    unsafe { core::arch::asm!("mov {}, rbp", out(reg) rbp) };
    for depth in 0..24 {
        // Only follow frames on kernel stacks (higher half), aligned.
        if rbp < 0xffff_8000_0000_0000 || !rbp.is_multiple_of(8) {
            break;
        }
        let ret = unsafe { *((rbp + 8) as *const u64) };
        if ret == 0 {
            break;
        }
        f(depth, ret);
        rbp = unsafe { *(rbp as *const u64) };
    }
}

/// Resets the machine: the keyboard controller's reset line, then a triple
/// fault if that did nothing.
pub fn restart() -> ! {
    x86::disable_interrupts();
    unsafe {
        for _ in 0..1000 {
            if x86::inb(0x64) & 2 == 0 {
                break;
            }
        }
        x86::outb(0x64, 0xfe);
        // An empty IDT and an exception: the CPU resets.
        let empty = x86::DescriptorPointer { limit: 0, base: 0 };
        x86::lidt(&empty);
        core::arch::asm!("int3", options(nomem, nostack));
    }
    halt_forever()
}
