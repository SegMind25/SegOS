//! The `syscall` instruction: how user programs enter the kernel.
//!
//! `syscall` jumps to [`syscall_entry`] in ring 0 with the user's RIP in
//! RCX and RFLAGS in R11, interrupts off (FMASK), and the user's stack
//! still in RSP. The entry swaps GS to the per-CPU block, switches to the
//! thread's kernel stack, and saves a [`TrapFrame`] laid out exactly as the
//! interrupt path does, so both leave through `trap_return` (`iretq`). The
//! Rust side, `syscall_dispatch`, may change the frame: `rax` is the
//! result.
//!
//! [`TrapFrame`]: super::idt::TrapFrame

use super::gdt::{KERNEL_CODE, USER_CODE, USER_DATA};
use super::percpu;
use super::x86;

/// `TrapFrame::vector` of a frame built by the system call entry.
pub const SYSCALL_VECTOR: u64 = 0x100;

core::arch::global_asm!(
    ".section .text",
    ".global syscall_entry",
    "syscall_entry:",
    "    swapgs",
    "    mov gs:[{user_rsp}], rsp",
    "    mov rsp, gs:[{kernel_rsp}]",
    // The part of the frame the CPU pushes on an interrupt from ring 3.
    "    push {user_ss}",
    "    push qword ptr gs:[{user_rsp}]",
    "    push r11",
    "    push {user_cs}",
    "    push rcx",
    "    push 0",
    "    push {vector}",
    // The rest, as isr_common saves it.
    "    push rax",
    "    push rbx",
    "    push rcx",
    "    push rdx",
    "    push rsi",
    "    push rdi",
    "    push rbp",
    "    push r8",
    "    push r9",
    "    push r10",
    "    push r11",
    "    push r12",
    "    push r13",
    "    push r14",
    "    push r15",
    "    xor ebp, ebp", // backtraces stop here
    "    mov rdi, rsp",
    "    cld",
    "    call syscall_dispatch",
    "    jmp trap_return",
    user_rsp = const percpu::USER_RSP,
    kernel_rsp = const percpu::KERNEL_RSP,
    user_ss = const USER_DATA,
    user_cs = const USER_CODE,
    vector = const SYSCALL_VECTOR,
);

unsafe extern "C" {
    fn syscall_entry();
}

/// Enables `syscall` on this CPU.
pub fn init_this_cpu() {
    // sysret would load CS = STAR[63:48] + 16 and SS = STAR[63:48] + 8 (user
    // code and data, RPL 3); syscall loads CS = STAR[47:32], SS = CS + 8.
    let star = ((USER_DATA as u64 - 8) << 48) | ((KERNEL_CODE as u64) << 32);
    // Cleared on entry: TF, IF, DF, IOPL, NT, AC.
    const FMASK: u64 = 0x4_7700;
    unsafe {
        x86::wrmsr(x86::msr::EFER, x86::rdmsr(x86::msr::EFER) | x86::efer::SCE);
        x86::wrmsr(x86::msr::STAR, star);
        x86::wrmsr(x86::msr::LSTAR, syscall_entry as *const () as u64);
        x86::wrmsr(x86::msr::FMASK, FMASK);
    }
}
