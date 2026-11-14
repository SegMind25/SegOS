//! x86-64 instructions and registers the kernel uses: port I/O, MSRs,
//! control registers, interrupts, descriptor tables, TLB.

use core::arch::asm;

pub unsafe fn outb(port: u16, value: u8) {
    unsafe {
        asm!("out dx, al", in("dx") port, in("al") value, options(nomem, nostack, preserves_flags))
    }
}

pub unsafe fn inb(port: u16) -> u8 {
    let v: u8;
    unsafe {
        asm!("in al, dx", out("al") v, in("dx") port, options(nomem, nostack, preserves_flags))
    };
    v
}

pub unsafe fn inw(port: u16) -> u16 {
    let v: u16;
    unsafe {
        asm!("in ax, dx", out("ax") v, in("dx") port, options(nomem, nostack, preserves_flags))
    };
    v
}

pub unsafe fn outw(port: u16, value: u16) {
    unsafe {
        asm!("out dx, ax", in("dx") port, in("ax") value, options(nomem, nostack, preserves_flags))
    }
}

pub unsafe fn outl(port: u16, value: u32) {
    unsafe {
        asm!("out dx, eax", in("dx") port, in("eax") value, options(nomem, nostack, preserves_flags))
    }
}

pub unsafe fn inl(port: u16) -> u32 {
    let v: u32;
    unsafe {
        asm!("in eax, dx", out("eax") v, in("dx") port, options(nomem, nostack, preserves_flags))
    };
    v
}

pub unsafe fn rdmsr(msr: u32) -> u64 {
    let (lo, hi): (u32, u32);
    unsafe {
        asm!("rdmsr", in("ecx") msr, out("eax") lo, out("edx") hi, options(nomem, nostack, preserves_flags))
    };
    (hi as u64) << 32 | lo as u64
}

pub unsafe fn wrmsr(msr: u32, value: u64) {
    unsafe {
        asm!("wrmsr", in("ecx") msr, in("eax") value as u32, in("edx") (value >> 32) as u32,
             options(nostack, preserves_flags))
    }
}

pub mod msr {
    pub const APIC_BASE: u32 = 0x1b;
    pub const EFER: u32 = 0xc000_0080;
    /// `syscall`/`sysret` segment selectors.
    pub const STAR: u32 = 0xc000_0081;
    /// `syscall` entry point.
    pub const LSTAR: u32 = 0xc000_0082;
    /// RFLAGS bits cleared on `syscall`.
    pub const FMASK: u32 = 0xc000_0084;
    pub const FS_BASE: u32 = 0xc000_0100;
    pub const GS_BASE: u32 = 0xc000_0101;
    /// Swapped with GS_BASE by `swapgs`: holds the user's GS base while the
    /// kernel runs, and the per-CPU block while user code runs.
    pub const KERNEL_GS_BASE: u32 = 0xc000_0102;
}

pub mod efer {
    /// `syscall`/`sysret` enabled.
    pub const SCE: u64 = 1 << 0;
}

pub fn read_cr2() -> u64 {
    let v: u64;
    unsafe { asm!("mov {}, cr2", out(reg) v, options(nomem, nostack, preserves_flags)) };
    v
}

pub fn read_cr3() -> u64 {
    let v: u64;
    unsafe { asm!("mov {}, cr3", out(reg) v, options(nomem, nostack, preserves_flags)) };
    v
}

/// Switches address space (and flushes non-global TLB entries).
///
/// # Safety
/// `pml4` must be a top-level table that maps the kernel as the current one
/// does.
pub unsafe fn write_cr3(pml4: u64) {
    unsafe { asm!("mov cr3, {}", in(reg) pml4, options(nostack, preserves_flags)) }
}

pub fn read_cr0() -> u64 {
    let v: u64;
    unsafe { asm!("mov {}, cr0", out(reg) v, options(nomem, nostack, preserves_flags)) };
    v
}

pub unsafe fn write_cr0(v: u64) {
    unsafe { asm!("mov cr0, {}", in(reg) v, options(nostack, preserves_flags)) }
}

pub fn read_cr4() -> u64 {
    let v: u64;
    unsafe { asm!("mov {}, cr4", out(reg) v, options(nomem, nostack, preserves_flags)) };
    v
}

pub unsafe fn write_cr4(v: u64) {
    unsafe { asm!("mov cr4, {}", in(reg) v, options(nostack, preserves_flags)) }
}

pub mod cr0 {
    pub const MP: u64 = 1 << 1;
    pub const EM: u64 = 1 << 2;
    pub const TS: u64 = 1 << 3;
}

pub mod cr4 {
    pub const OSFXSR: u64 = 1 << 9;
    pub const OSXMMEXCPT: u64 = 1 << 10;
    /// Supervisor-mode execution prevention: the kernel cannot run user pages.
    pub const SMEP: u64 = 1 << 20;
    /// Supervisor-mode access prevention: the kernel cannot read or write
    /// user pages (it uses the direct map instead).
    pub const SMAP: u64 = 1 << 21;
}

/// The time-stamp counter.
pub fn rdtsc() -> u64 {
    let (lo, hi): (u32, u32);
    unsafe {
        asm!("rdtsc", out("eax") lo, out("edx") hi, options(nomem, nostack, preserves_flags))
    };
    (hi as u64) << 32 | lo as u64
}

/// CPUID leaf `leaf`, subleaf `sub`: (eax, ebx, ecx, edx).
pub fn cpuid(leaf: u32, sub: u32) -> (u32, u32, u32, u32) {
    let r = core::arch::x86_64::__cpuid_count(leaf, sub);
    (r.eax, r.ebx, r.ecx, r.edx)
}

/// A hardware random number, if the CPU has RDRAND and it delivers.
pub fn rdrand() -> Option<u64> {
    if cpuid(1, 0).2 & (1 << 30) == 0 {
        return None;
    }
    for _ in 0..10 {
        let (v, ok): (u64, u8);
        unsafe {
            asm!("rdrand {}", "setc {}", out(reg) v, out(reg_byte) ok, options(nomem, nostack))
        };
        if ok != 0 {
            return Some(v);
        }
    }
    None
}

/// 512-byte `fxsave` area: x87, MMX and SSE state of a user thread.
#[repr(C, align(16))]
pub struct FxArea(pub [u8; 512]);

impl FxArea {
    /// The state after `fninit` with SSE exceptions masked, as Linux gives a
    /// new program: FCW 0x37f, MXCSR 0x1f80, everything else zero.
    pub fn initial() -> Self {
        let mut a = [0u8; 512];
        a[0..2].copy_from_slice(&0x37fu16.to_le_bytes());
        a[24..28].copy_from_slice(&0x1f80u32.to_le_bytes());
        // MXCSR_MASK 0: the CPU's default mask applies on fxrstor.
        FxArea(a)
    }
}

/// The MXCSR bits this CPU supports (from fxsave's MXCSR_MASK field;
/// 0xffbf when the CPU reports 0).
pub fn mxcsr_mask() -> u32 {
    static MASK: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
    let m = MASK.load(core::sync::atomic::Ordering::Relaxed);
    if m != 0 {
        return m;
    }
    let mut a = FxArea::initial();
    fxsave(&mut a);
    let mut m = u32::from_le_bytes(a.0[28..32].try_into().unwrap());
    if m == 0 {
        m = 0xffbf;
    }
    MASK.store(m, core::sync::atomic::Ordering::Relaxed);
    m
}

pub fn fxsave(area: &mut FxArea) {
    unsafe { asm!("fxsave64 [{}]", in(reg) area.0.as_mut_ptr(), options(nostack, preserves_flags)) }
}

pub fn fxrstor(area: &FxArea) {
    unsafe {
        asm!("fxrstor64 [{}]", in(reg) area.0.as_ptr(), options(nostack, preserves_flags, readonly))
    }
}

pub unsafe fn invlpg(addr: u64) {
    unsafe { asm!("invlpg [{}]", in(reg) addr, options(nostack, preserves_flags)) }
}

pub fn interrupts_enabled() -> bool {
    let flags: u64;
    unsafe { asm!("pushfq", "pop {}", out(reg) flags, options(nomem, preserves_flags)) };
    flags & (1 << 9) != 0
}

pub fn enable_interrupts() {
    unsafe { asm!("sti", options(nomem, nostack)) }
}

pub fn disable_interrupts() {
    unsafe { asm!("cli", options(nomem, nostack)) }
}

/// `sti; hlt` as one step: an interrupt arriving between them still wakes
/// the CPU (sti takes effect after the next instruction).
pub fn enable_interrupts_and_halt() {
    unsafe { asm!("sti", "hlt", options(nomem, nostack)) }
}

pub fn halt() {
    unsafe { asm!("hlt", options(nomem, nostack, preserves_flags)) }
}

pub fn breakpoint() {
    unsafe { asm!("int3", options(nomem, nostack)) }
}

pub fn without_interrupts<R>(f: impl FnOnce() -> R) -> R {
    let was = interrupts_enabled();
    disable_interrupts();
    let r = f();
    if was {
        enable_interrupts();
    }
    r
}

/// Operand of `lgdt`/`lidt`.
#[repr(C, packed)]
pub struct DescriptorPointer {
    pub limit: u16,
    pub base: u64,
}

pub unsafe fn lgdt(p: &DescriptorPointer) {
    unsafe { asm!("lgdt [{}]", in(reg) p, options(readonly, nostack, preserves_flags)) }
}

pub unsafe fn lidt(p: &DescriptorPointer) {
    unsafe { asm!("lidt [{}]", in(reg) p, options(readonly, nostack, preserves_flags)) }
}

pub unsafe fn ltr(selector: u16) {
    unsafe { asm!("ltr {:x}", in(reg) selector, options(nostack, preserves_flags)) }
}

/// Reloads CS with a far return, and the data segment registers.
pub unsafe fn load_segments(code: u16, data: u16) {
    unsafe {
        asm!(
            "push {code}",
            "lea {tmp}, [rip + 2f]",
            "push {tmp}",
            "retfq",
            "2:",
            "mov ds, {data:x}",
            "mov es, {data:x}",
            "mov ss, {data:x}",
            code = in(reg) code as u64,
            data = in(reg) data,
            tmp = out(reg) _,
            options(preserves_flags),
        )
    }
}
