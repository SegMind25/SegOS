//! seccomp: a thread's system calls filtered by classic BPF programs, as
//! Linux's `seccomp(2)` and `prctl(PR_SET_SECCOMP)` install them (Firefox
//! and Chromium sandbox their content processes with these).
//!
//! A filter is a classic BPF program (`struct sock_filter`) run over
//! `struct seccomp_data` (the call's number, architecture, address and six
//! arguments) before every system call. Filters stack: a thread runs all
//! of the ones it installed or inherited, newest first, and the action
//! with the highest precedence wins (KILL > TRAP > ERRNO > TRACE > LOG >
//! ALLOW). Threads inherit their creator's filters, `execve` keeps them,
//! and nothing removes one.
//!
//! Strict mode (`SECCOMP_MODE_STRICT`) allows read, write, exit and
//! rt_sigreturn and kills on anything else.

use crate::abi::{Errno, KResult};
use crate::mm::vm::AddressSpace;
use alloc::sync::Arc;
use alloc::vec::Vec;

/// `struct sock_filter`.
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct Insn {
    pub code: u16,
    pub jt: u8,
    pub jf: u8,
    pub k: u32,
}

unsafe impl crate::abi::Pod for Insn {}

pub const MODE_DISABLED: u32 = 0;
pub const MODE_STRICT: u32 = 1;
pub const MODE_FILTER: u32 = 2;

pub const RET_KILL_PROCESS: u32 = 0x8000_0000;
pub const RET_KILL_THREAD: u32 = 0;
pub const RET_TRAP: u32 = 0x0003_0000;
pub const RET_ERRNO: u32 = 0x0005_0000;
pub const RET_USER_NOTIF: u32 = 0x7fc0_0000;
pub const RET_TRACE: u32 = 0x7ff0_0000;
pub const RET_LOG: u32 = 0x7ffc_0000;
pub const RET_ALLOW: u32 = 0x7fff_0000;
const RET_ACTION_FULL: u32 = 0xffff_0000;
const RET_DATA: u32 = 0x0000_ffff;

/// Linux's limits: instructions per program, and per thread over all of
/// its filters (each counting 4 more).
const MAX_INSNS: usize = 4096;
const MAX_INSNS_PER_PATH: usize = 32768;
/// `sizeof(struct seccomp_data)`.
const DATA_SIZE: u32 = 64;
const AUDIT_ARCH_X86_64: u32 = 0xc000_003e;

/// One installed program, and the filters installed before it.
pub struct Filter {
    prog: Vec<Insn>,
    prev: Option<Arc<Filter>>,
    /// `SECCOMP_FILTER_FLAG_LOG`: log actions other than ALLOW.
    log: bool,
}

impl Filter {
    /// Whether `other` is this filter or one installed before it.
    pub fn descends_from(self: &Arc<Self>, other: &Arc<Filter>) -> bool {
        let mut f = Some(self);
        while let Some(cur) = f {
            if Arc::ptr_eq(cur, other) {
                return true;
            }
            f = cur.prev.as_ref();
        }
        false
    }

    fn path_len(&self) -> usize {
        self.prog.len() + 4 + self.prev.as_ref().map_or(0, |p| p.path_len())
    }
}

// Classic BPF opcodes (linux/bpf_common.h).
const LD: u16 = 0x00;
const LDX: u16 = 0x01;
const ST: u16 = 0x02;
const STX: u16 = 0x03;
const ALU: u16 = 0x04;
const JMP: u16 = 0x05;
const RET: u16 = 0x06;
const MISC: u16 = 0x07;
const W: u16 = 0x00;
const IMM: u16 = 0x00;
const ABS: u16 = 0x20;
const MEM: u16 = 0x60;
const LEN: u16 = 0x80;
const X: u16 = 0x08;
const A: u16 = 0x10;
const SCRATCH: u32 = 16;

fn class(code: u16) -> u16 {
    code & 0x07
}

/// Checks a program as Linux's `seccomp_check_filter` and
/// `bpf_check_classic` do: only loads of aligned words of
/// `seccomp_data`, jumps inside the program, no division by a constant
/// zero, and a return at the end.
fn check(prog: &[Insn]) -> KResult<()> {
    if prog.is_empty() || prog.len() > MAX_INSNS {
        return Err(Errno::EINVAL);
    }
    let len = prog.len();
    for (pc, i) in prog.iter().enumerate() {
        let left = (len - pc - 1) as u32;
        let ok = match class(i.code) {
            LD => match i.code {
                c if c == LD | W | ABS => i.k < DATA_SIZE && i.k % 4 == 0,
                c if c == LD | W | LEN || c == LD | IMM => true,
                c if c == LD | MEM => i.k < SCRATCH,
                _ => false,
            },
            LDX => match i.code {
                c if c == LDX | W | LEN || c == LDX | IMM => true,
                c if c == LDX | MEM => i.k < SCRATCH,
                _ => false,
            },
            ST | STX => i.code & !0x07 == 0 && i.k < SCRATCH,
            ALU => {
                let op = i.code & 0xf0;
                let by_k = i.code & X == 0;
                match op {
                    0x00..=0x20 | 0x40 | 0x50 | 0xa0 => true,
                    0x30 | 0x90 => !by_k || i.k != 0, // DIV, MOD
                    0x60 | 0x70 => !by_k || i.k < 32, // LSH, RSH
                    0x80 => true,                     // NEG
                    _ => false,
                }
            }
            JMP => match i.code & 0xf0 {
                0x00 => i.code & X == 0 && i.k < left, // JA
                0x10..=0x40 => (i.jt as u32) < left && (i.jf as u32) < left,
                _ => false,
            },
            RET => matches!(i.code & 0x18, 0x00 | A),
            MISC => matches!(i.code & 0xf8, 0x00 | 0x80),
            _ => false,
        };
        if !ok {
            return Err(Errno::EINVAL);
        }
    }
    if class(prog[len - 1].code) != RET {
        return Err(Errno::EINVAL);
    }
    Ok(())
}

/// Runs one checked program over `data` (`seccomp_data` as words).
fn run(prog: &[Insn], data: &[u32; 16]) -> u32 {
    let (mut a, mut x) = (0u32, 0u32);
    let mut mem = [0u32; SCRATCH as usize];
    let mut pc = 0usize;
    // `check` makes every jump go forwards and the last instruction a
    // return, so this ends.
    while let Some(i) = prog.get(pc) {
        pc += 1;
        match class(i.code) {
            LD => {
                a = match i.code & 0xe0 {
                    ABS => data[(i.k / 4) as usize],
                    LEN => DATA_SIZE,
                    MEM => mem[i.k as usize],
                    _ => i.k,
                }
            }
            LDX => {
                x = match i.code & 0xe0 {
                    LEN => DATA_SIZE,
                    MEM => mem[i.k as usize],
                    _ => i.k,
                }
            }
            ST => mem[i.k as usize] = a,
            STX => mem[i.k as usize] = x,
            ALU => {
                let v = if i.code & X != 0 { x } else { i.k };
                a = match i.code & 0xf0 {
                    0x00 => a.wrapping_add(v),
                    0x10 => a.wrapping_sub(v),
                    0x20 => a.wrapping_mul(v),
                    0x30 => match a.checked_div(v) {
                        Some(q) => q,
                        None => return 0,
                    },
                    0x90 => match a.checked_rem(v) {
                        Some(r) => r,
                        None => return 0,
                    },
                    0x40 => a | v,
                    0x50 => a & v,
                    0x60 => a.checked_shl(v).unwrap_or(0),
                    0x70 => a.checked_shr(v).unwrap_or(0),
                    0x80 => a.wrapping_neg(),
                    _ => a ^ v,
                }
            }
            JMP => {
                let v = if i.code & X != 0 { x } else { i.k };
                let taken = match i.code & 0xf0 {
                    0x00 => {
                        pc += i.k as usize;
                        continue;
                    }
                    0x10 => a == v,
                    0x20 => a > v,
                    0x30 => a >= v,
                    _ => a & v != 0,
                };
                pc += if taken { i.jt } else { i.jf } as usize;
            }
            RET => {
                return if i.code & 0x18 == A { a } else { i.k };
            }
            _ => {
                if i.code & 0x80 != 0 {
                    a = x; // TXA
                } else {
                    x = a; // TAX
                }
            }
        }
    }
    RET_KILL_THREAD
}

/// What happens to a system call.
pub enum Verdict {
    Allow,
    /// Fail with this error without running it.
    Errno(Errno),
    /// SIGSYS for the thread (`SECCOMP_RET_TRAP`), with the filter's data.
    Trap(u16),
    /// Kill the thread, or (`process`) the whole process, by SIGSYS.
    Kill {
        process: bool,
    },
}

/// Runs `filter` (and those before it) for system call `nr` with `args`,
/// made at `ip`.
pub fn evaluate(filter: &Arc<Filter>, nr: u64, args: &[u64; 6], ip: u64) -> Verdict {
    let mut data = [0u32; 16];
    data[0] = nr as u32;
    data[1] = AUDIT_ARCH_X86_64;
    data[2] = ip as u32;
    data[3] = (ip >> 32) as u32;
    for (n, &arg) in args.iter().enumerate() {
        data[4 + 2 * n] = arg as u32;
        data[5 + 2 * n] = (arg >> 32) as u32;
    }
    let mut ret = RET_ALLOW;
    let mut log = false;
    let mut f = Some(filter);
    while let Some(cur) = f {
        let r = run(&cur.prog, &data);
        if ((r & RET_ACTION_FULL) as i32) < ((ret & RET_ACTION_FULL) as i32) {
            ret = r;
            log = cur.log;
        }
        f = cur.prev.as_ref();
    }
    let data16 = (ret & RET_DATA) as u16;
    let verdict = match ret & RET_ACTION_FULL {
        RET_KILL_PROCESS => Verdict::Kill { process: true },
        RET_KILL_THREAD => Verdict::Kill { process: false },
        RET_TRAP => Verdict::Trap(data16),
        // Linux caps the error at MAX_ERRNO.
        RET_ERRNO => Verdict::Errno(Errno(data16.min(4095) as i32)),
        // No tracer, no listener: the call fails as Linux has it.
        RET_TRACE | RET_USER_NOTIF => Verdict::Errno(Errno::ENOSYS),
        RET_LOG | RET_ALLOW => Verdict::Allow,
        // Unknown actions are KILL_PROCESS (Linux 4.14 and later).
        _ => Verdict::Kill { process: true },
    };
    if log && ret & RET_ACTION_FULL != RET_ALLOW {
        crate::info!("seccomp: system call {nr} at {ip:#x}: action {ret:#x}");
    }
    verdict
}

/// Strict mode: read, write, exit, rt_sigreturn.
pub fn strict_allows(nr: u64) -> bool {
    matches!(nr, 0 | 1 | 15 | 60)
}

/// Reads a `struct sock_fprog` at `addr` and checks the program; `prev`
/// is the thread's current filter.
pub fn load(
    mm: &AddressSpace,
    addr: u64,
    prev: Option<Arc<Filter>>,
    log: bool,
) -> KResult<Arc<Filter>> {
    if addr == 0 {
        return Err(Errno::EFAULT);
    }
    let len: u16 = mm.read(addr)?;
    let at: u64 = mm.read(addr + 8)?;
    let len = len as usize;
    if len == 0 || len > MAX_INSNS {
        return Err(Errno::EINVAL);
    }
    let mut prog = Vec::with_capacity(len);
    for n in 0..len {
        prog.push(mm.read::<Insn>(at + (n * 8) as u64)?);
    }
    check(&prog)?;
    let f = Filter { prog, prev, log };
    if f.path_len() > MAX_INSNS_PER_PATH {
        return Err(Errno::ENOMEM);
    }
    Ok(Arc::new(f))
}

/// `SECCOMP_GET_ACTION_AVAIL`: whether an action is known.
pub fn action_available(action: u32) -> bool {
    matches!(
        action,
        RET_KILL_PROCESS
            | RET_KILL_THREAD
            | RET_TRAP
            | RET_ERRNO
            | RET_USER_NOTIF
            | RET_TRACE
            | RET_LOG
            | RET_ALLOW
    )
}

#[cfg(feature = "ktest")]
pub fn run_for_test(prog: &[Insn], nr: u64, args: &[u64; 6]) -> KResult<u32> {
    check(prog)?;
    let f = Arc::new(Filter {
        prog: prog.to_vec(),
        prev: None,
        log: false,
    });
    let mut data = [0u32; 16];
    data[0] = nr as u32;
    data[1] = AUDIT_ARCH_X86_64;
    for (n, &arg) in args.iter().enumerate() {
        data[4 + 2 * n] = arg as u32;
        data[5 + 2 * n] = (arg >> 32) as u32;
    }
    Ok(run(&f.prog, &data))
}
