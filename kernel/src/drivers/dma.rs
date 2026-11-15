//! Memory devices read and write directly (DMA): whole pages, physically
//! contiguous by construction, reached by the kernel through the direct
//! map (x86 DMA is cache coherent).

use crate::mm::{frame, phys_to_virt};

pub struct DmaPage {
    pub phys: u64,
    pub virt: *mut u8,
}

unsafe impl Send for DmaPage {}
unsafe impl Sync for DmaPage {}

impl DmaPage {
    pub fn new() -> Self {
        let phys = frame::alloc_zeroed().expect("out of memory for DMA");
        Self {
            phys,
            virt: phys_to_virt(phys),
        }
    }

    pub fn read<T: Copy>(&self, off: usize) -> T {
        unsafe { (self.virt.add(off) as *const T).read_volatile() }
    }

    pub fn write<T: Copy>(&self, off: usize, v: T) {
        unsafe { (self.virt.add(off) as *mut T).write_volatile(v) }
    }

    #[allow(clippy::mut_from_ref)]
    pub fn bytes(&self) -> &mut [u8] {
        unsafe { core::slice::from_raw_parts_mut(self.virt, 4096) }
    }

    pub fn zero(&self) {
        self.bytes().fill(0);
    }
}

impl Drop for DmaPage {
    fn drop(&mut self) {
        frame::free(self.phys);
    }
}

/// Registers of a memory-mapped device.
#[derive(Clone, Copy)]
pub struct Mmio(pub u64);

impl Mmio {
    pub fn r32(&self, off: u64) -> u32 {
        unsafe { ((self.0 + off) as *const u32).read_volatile() }
    }
    pub fn w32(&self, off: u64, v: u32) {
        unsafe { ((self.0 + off) as *mut u32).write_volatile(v) }
    }
    pub fn r64(&self, off: u64) -> u64 {
        self.r32(off) as u64 | (self.r32(off + 4) as u64) << 32
    }
    pub fn w64(&self, off: u64, v: u64) {
        self.w32(off, v as u32);
        self.w32(off + 4, (v >> 32) as u32);
    }
    pub fn r16(&self, off: u64) -> u16 {
        unsafe { ((self.0 + off) as *const u16).read_volatile() }
    }
    pub fn w16(&self, off: u64, v: u16) {
        unsafe { ((self.0 + off) as *mut u16).write_volatile(v) }
    }
    pub fn r8(&self, off: u64) -> u8 {
        unsafe { ((self.0 + off) as *const u8).read_volatile() }
    }
    pub fn w8(&self, off: u64, v: u8) {
        unsafe { ((self.0 + off) as *mut u8).write_volatile(v) }
    }
}

/// Waits (yielding the CPU) until `done`, at most `ms` milliseconds.
pub fn poll(ms: u64, mut done: impl FnMut() -> bool) -> bool {
    let until = crate::time::monotonic_ns() + ms * 1_000_000;
    let mut spins = 0u32;
    loop {
        if done() {
            return true;
        }
        if crate::time::monotonic_ns() > until {
            return false;
        }
        spins += 1;
        if spins > 64 {
            crate::task::yield_now();
        } else {
            core::hint::spin_loop();
        }
    }
}
