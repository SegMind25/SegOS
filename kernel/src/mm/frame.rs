//! Physical frame allocator: one bit per 4 KiB frame.
//!
//! Simple and good enough until SMP and NUMA (a buddy allocator with
//! per-CPU caches replaces it in Phase 1/4). The bitmap itself lives in the
//! first usable region above 1 MiB large enough, reached through the direct
//! map.
//!
//! Memory below 1 MiB is kept back from [`alloc_zeroed`]: it is scarce and
//! some things need it (the real-mode trampoline that starts the other
//! CPUs, old DMA). Only [`alloc_below`] hands it out.
//!
//! Every frame also has a reference count (4 bytes per 4 KiB frame, 0.1%
//! of memory, next to the bitmap): copy-on-write `fork` shares one frame
//! between address spaces, and the frame is freed when the last one lets
//! go ([`free`] drops one reference).

use super::{PAGE_SIZE, phys_to_virt};
use crate::sync::{Once, SpinLock};
use bootinfo::{MemoryKind, MemoryRegion};
use core::sync::atomic::{AtomicU32, Ordering};

/// First frame [`FrameAllocator::alloc`] may return (1 MiB).
const LOW_FRAMES: u64 = 0x10_0000 / PAGE_SIZE;

pub struct FrameAllocator {
    bitmap: &'static mut [u64],
    frames: u64,
    free: u64,
    /// Search hint: no free frame in `LOW_FRAMES..next`.
    next: u64,
}

static ALLOCATOR: SpinLock<Option<FrameAllocator>> = SpinLock::new(None);
/// Frames of usable memory at boot.
static TOTAL: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

pub fn total_count() -> u64 {
    TOTAL.load(Ordering::Relaxed)
}

/// Reference count of every frame, indexed by frame number.
static REFS: Once<&'static [AtomicU32]> = Once::new();

fn refs(phys: u64) -> &'static AtomicU32 {
    &REFS.get().expect("frame allocator not ready")[(phys / PAGE_SIZE) as usize]
}

impl FrameAllocator {
    fn is_used(&self, i: u64) -> bool {
        self.bitmap[(i / 64) as usize] & (1 << (i % 64)) != 0
    }

    fn set(&mut self, i: u64, used: bool) {
        let word = &mut self.bitmap[(i / 64) as usize];
        if used {
            *word |= 1 << (i % 64);
        } else {
            *word &= !(1 << (i % 64));
        }
    }

    fn alloc(&mut self) -> Option<u64> {
        let words = self.bitmap.len() as u64;
        let mut w = self.next / 64;
        while w < words {
            let word = self.bitmap[w as usize];
            if word != u64::MAX {
                let i = w * 64 + (!word).trailing_zeros() as u64;
                if i >= self.frames {
                    return None;
                }
                self.set(i, true);
                self.free -= 1;
                self.next = i + 1;
                return Some(i * PAGE_SIZE);
            }
            w += 1;
        }
        None
    }

    fn dealloc(&mut self, phys: u64) {
        let i = phys / PAGE_SIZE;
        assert!(
            i < self.frames && self.is_used(i),
            "double free of frame {phys:#x}"
        );
        self.set(i, false);
        self.free += 1;
        self.next = self.next.min(i).max(LOW_FRAMES);
    }
}

pub fn init(entries: &[MemoryRegion]) {
    let top = entries
        .iter()
        .filter(|e| e.kind == MemoryKind::Usable)
        .map(|e| e.base + e.length)
        .max()
        .expect("no usable memory");
    let frames = top / PAGE_SIZE;
    let words = frames.div_ceil(64);
    let bitmap_bytes = words * 8;
    let bytes = bitmap_bytes + frames * 4;

    let home = entries
        .iter()
        .find(|e| e.kind == MemoryKind::Usable && e.base >= 0x10_0000 && e.length >= bytes)
        .expect("no region large enough for the frame bitmap");
    let bitmap = unsafe {
        core::slice::from_raw_parts_mut(phys_to_virt(home.base).cast::<u64>(), words as usize)
    };
    bitmap.fill(u64::MAX);
    let counts = unsafe {
        let p = phys_to_virt(home.base + bitmap_bytes).cast::<AtomicU32>();
        core::ptr::write_bytes(p, 0, frames as usize);
        core::slice::from_raw_parts(p, frames as usize)
    };
    REFS.call_once(|| counts);

    let mut fa = FrameAllocator {
        bitmap,
        frames,
        free: 0,
        next: LOW_FRAMES,
    };
    for e in entries.iter().filter(|e| e.kind == MemoryKind::Usable) {
        // Usable regions are page aligned by the protocol.
        for i in e.base / PAGE_SIZE..(e.base + e.length) / PAGE_SIZE {
            fa.set(i, false);
            fa.free += 1;
        }
    }
    // The bitmap's own frames, and frame 0 (keeps null physical addresses invalid).
    for i in home.base / PAGE_SIZE..(home.base + bytes).div_ceil(PAGE_SIZE) {
        fa.set(i, true);
        fa.free -= 1;
    }
    if !fa.is_used(0) {
        fa.set(0, true);
        fa.free -= 1;
    }
    TOTAL.store(fa.free, Ordering::Relaxed);
    crate::info!(
        "frames: {} free of {} ({} KiB bitmap and reference counts)",
        fa.free,
        frames,
        bytes / 1024
    );
    *ALLOCATOR.lock() = Some(fa);
}

/// Allocates one zeroed 4 KiB frame with one reference; returns its
/// physical address.
pub fn alloc_zeroed() -> Option<u64> {
    let phys = ALLOCATOR.lock().as_mut()?.alloc()?;
    refs(phys).store(1, Ordering::Relaxed);
    unsafe { core::ptr::write_bytes(phys_to_virt(phys), 0, PAGE_SIZE as usize) };
    Some(phys)
}

/// Adds a reference to an allocated frame (it is now shared).
pub fn get(phys: u64) {
    let old = refs(phys).fetch_add(1, Ordering::Relaxed);
    assert!(old > 0, "reference to free frame {phys:#x}");
}

/// How many address spaces (or other owners) hold the frame.
pub fn ref_count(phys: u64) -> u32 {
    refs(phys).load(Ordering::Acquire)
}

/// Allocates one zeroed frame below `limit` (for real-mode code, DMA).
pub fn alloc_below(limit: u64) -> Option<u64> {
    let mut guard = ALLOCATOR.lock();
    let fa = guard.as_mut()?;
    let i = (1..(limit / PAGE_SIZE).min(fa.frames)).find(|&i| !fa.is_used(i))?;
    fa.set(i, true);
    fa.free -= 1;
    drop(guard);
    let phys = i * PAGE_SIZE;
    refs(phys).store(1, Ordering::Relaxed);
    unsafe { core::ptr::write_bytes(phys_to_virt(phys), 0, PAGE_SIZE as usize) };
    Some(phys)
}

/// Drops one reference; the frame is freed with the last one.
pub fn free(phys: u64) {
    let old = refs(phys).fetch_sub(1, Ordering::AcqRel);
    assert!(old > 0, "double free of frame {phys:#x}");
    if old == 1 {
        ALLOCATOR
            .lock()
            .as_mut()
            .expect("frame allocator not ready")
            .dealloc(phys);
    }
}

pub fn free_count() -> u64 {
    ALLOCATOR.lock().as_ref().map_or(0, |a| a.free)
}
