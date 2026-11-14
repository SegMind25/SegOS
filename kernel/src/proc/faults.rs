//! Exceptions in user mode become signals for the program, as on Linux:
//! a page fault the address space cannot resolve is SIGSEGV, an invalid
//! instruction SIGILL, a division by zero SIGFPE.

use super::signal::{self, SigInfo, signo};
use crate::hal::idt::{TrapFrame, vector};
use crate::hal::x86;

/// si_code values (siginfo.h).
const SEGV_MAPERR: i32 = 1;
const SEGV_ACCERR: i32 = 2;
const ILL_ILLOPN: i32 = 2;
const FPE_INTDIV: i32 = 1;
const TRAP_BRKPT: i32 = 1;
const BUS_ADRALN: i32 = 1;
const SI_KERNEL: i32 = 0x80;

pub fn user_exception(frame: &mut TrapFrame) {
    // CR2 first: a page fault elsewhere would overwrite it once interrupts
    // are on and another thread runs.
    let cr2 = x86::read_cr2();
    x86::enable_interrupts();
    let task = super::current();
    let u = task.user().unwrap();
    let (sig, info) = match frame.vector {
        vector::PAGE_FAULT => {
            let write = frame.error_code & 2 != 0;
            let exec = frame.error_code & 16 != 0;
            if u.mm().handle_fault(cr2, write, exec) {
                x86::disable_interrupts();
                return;
            }
            let code = if frame.error_code & 1 != 0 {
                SEGV_ACCERR
            } else {
                SEGV_MAPERR
            };
            (signo::SIGSEGV, SigInfo::fault(code, cr2))
        }
        vector::DIVIDE_ERROR => (signo::SIGFPE, SigInfo::fault(FPE_INTDIV, frame.rip)),
        16 | 19 => (signo::SIGFPE, SigInfo::fault(0, frame.rip)),
        vector::INVALID_OPCODE => (signo::SIGILL, SigInfo::fault(ILL_ILLOPN, frame.rip)),
        vector::BREAKPOINT | 1 => (signo::SIGTRAP, SigInfo::fault(TRAP_BRKPT, frame.rip)),
        17 => (signo::SIGBUS, SigInfo::fault(BUS_ADRALN, frame.rip)),
        _ => (signo::SIGSEGV, SigInfo::fault(SI_KERNEL, 0)),
    };
    let p = &u.process;
    let handled = {
        let act = p.sigactions.lock()[sig as usize - 1];
        act.handler > signal::SIG_IGN
            && u.sig.mask.load(core::sync::atomic::Ordering::Relaxed) & (1 << (sig - 1)) == 0
    };
    if !handled {
        crate::info!(
            "{}[{}]: {} at rip {:#x}{} (vector {}, error {:#x}): killed by signal {}",
            p.name.lock().as_str(),
            p.pid,
            crate::hal::idt::exception_name(frame.vector),
            frame.rip,
            if frame.vector == vector::PAGE_FAULT {
                alloc::format!(", address {cr2:#x}")
            } else {
                alloc::string::String::new()
            },
            frame.vector,
            frame.error_code,
            sig
        );
    }
    signal::force(u, sig, info);
    drop(task);
    x86::disable_interrupts();
}
