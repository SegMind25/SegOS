//! Entering user mode for the first time.

use super::gdt::{USER_CODE, USER_DATA};

core::arch::global_asm!(
    ".section .text",
    ".global enter_user_mode",
    // rdi: user RIP, rsi: user RSP. Builds an interrupt return frame and
    // drops to ring 3 with every general register zero (no kernel values
    // leak; rdx = 0 also tells the C library there is no exit hook).
    "enter_user_mode:",
    "    cli",
    "    push {ss}",
    "    push rsi",
    "    push 0x202", // IF, and the always-one bit
    "    push {cs}",
    "    push rdi",
    "    swapgs",
    "    xor eax, eax",
    "    xor ebx, ebx",
    "    xor ecx, ecx",
    "    xor edx, edx",
    "    xor esi, esi",
    "    xor edi, edi",
    "    xor ebp, ebp",
    "    xor r8d, r8d",
    "    xor r9d, r9d",
    "    xor r10d, r10d",
    "    xor r11d, r11d",
    "    xor r12d, r12d",
    "    xor r13d, r13d",
    "    xor r14d, r14d",
    "    xor r15d, r15d",
    "    iretq",
    ss = const USER_DATA,
    cs = const USER_CODE,
);

unsafe extern "C" {
    fn enter_user_mode(rip: u64, rsp: u64) -> !;
}

/// Starts executing user code at `rip` with stack `rsp`, on the current
/// thread. The caller must have set up the address space, the thread's
/// kernel stack (TSS and per-CPU), its FS base and FPU state.
pub fn enter_user(rip: u64, rsp: u64) -> ! {
    unsafe { enter_user_mode(rip, rsp) }
}
