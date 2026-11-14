//! Process address spaces: the lower half of a page table, described by
//! regions (VMAs, as Linux calls them).
//!
//! A region says what a range of addresses is for and what access is
//! allowed. Pages are mapped lazily: the first touch of a page in an
//! anonymous region page-faults, and [`AddressSpace::handle_fault`] maps a
//! zeroed frame. A touch outside every region, or one the region's
//! protection forbids, is the program's bug (SIGSEGV).
//!
//! The kernel reads and writes user memory through the direct map, after
//! looking each page up here ([`AddressSpace::copy_from`] and friends), so
//! a bad pointer from a program becomes `EFAULT`, never a kernel fault.
//!
//! `fork` shares every page between parent and child, read-only and marked
//! copy-on-write; the first write to such a page copies it. Frames are
//! reference counted, so the last address space to let go frees them.

use super::paging::{self, flags};
use super::{PAGE_SIZE, frame, phys_to_virt};
use crate::abi::mman::{PROT_EXEC, PROT_READ, PROT_WRITE};
use crate::abi::{Errno, KResult, Pod};
use crate::sync::Mutex;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

/// One past the highest user address (as Linux: 128 TiB minus a page).
pub const USER_END: u64 = 0x0000_7fff_ffff_f000;
/// The main thread's stack: the top 8 MiB below `USER_END`.
pub const STACK_END: u64 = USER_END;
pub const STACK_SIZE: u64 = 8 << 20;
/// `mmap` without an address searches downwards from here.
pub const MMAP_END: u64 = 0x0000_7f00_0000_0000;
/// Lowest address `mmap` hands out (Linux's default `mmap_min_addr`).
pub const MMAP_MIN: u64 = 0x1_0000;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Kind {
    /// Loaded from the executable.
    Image,
    /// `brk` heap.
    Heap,
    Stack,
    /// Anonymous `mmap`.
    Anon,
}

#[derive(Clone, Copy, Debug)]
pub struct Vma {
    pub start: u64,
    pub end: u64,
    /// PROT_* bits.
    pub prot: u32,
    pub kind: Kind,
}

impl Vma {
    /// Page-table flags for the region's pages. x86 cannot express "no
    /// access" for a present page, so PROT_NONE pages are present but
    /// kernel-only: user access faults, and the contents survive a later
    /// mprotect.
    fn page_flags(&self) -> u64 {
        if self.prot & (PROT_READ | PROT_WRITE | PROT_EXEC) == 0 {
            return flags::NO_EXECUTE;
        }
        flags::USER
            | if self.prot & PROT_WRITE != 0 {
                flags::WRITABLE
            } else {
                0
            }
            | if self.prot & PROT_EXEC != 0 {
                0
            } else {
                flags::NO_EXECUTE
            }
    }

    fn allows(&self, write: bool, exec: bool) -> bool {
        if write {
            self.prot & PROT_WRITE != 0
        } else if exec {
            self.prot & PROT_EXEC != 0
        } else {
            self.prot & (PROT_READ | PROT_WRITE | PROT_EXEC) != 0
        }
    }
}

struct Regions {
    /// Keyed by start address; never overlapping.
    vmas: BTreeMap<u64, Vma>,
    brk_start: u64,
    brk: u64,
}

pub struct AddressSpace {
    pml4: u64,
    inner: Mutex<Regions>,
}

fn page_down(a: u64) -> u64 {
    a & !(PAGE_SIZE - 1)
}

fn page_up(a: u64) -> u64 {
    a.next_multiple_of(PAGE_SIZE)
}

impl Regions {
    fn find(&self, addr: u64) -> Option<&Vma> {
        self.vmas
            .range(..=addr)
            .next_back()
            .map(|(_, v)| v)
            .filter(|v| addr < v.end)
    }

    fn overlaps(&self, start: u64, end: u64) -> bool {
        self.vmas
            .range(..end)
            .next_back()
            .is_some_and(|(_, v)| v.end > start)
    }

    /// Splits the region containing `addr` (if any) so that a region
    /// starts exactly at `addr`.
    fn split_at(&mut self, addr: u64) {
        let Some(v) = self.find(addr).copied() else {
            return;
        };
        if v.start == addr {
            return;
        }
        self.vmas.insert(v.start, Vma { end: addr, ..v });
        self.vmas.insert(addr, Vma { start: addr, ..v });
    }

    /// Start addresses of the regions inside `[start, end)`, after splitting
    /// at both ends.
    fn isolate(&mut self, start: u64, end: u64) -> Vec<u64> {
        self.split_at(start);
        self.split_at(end);
        self.vmas.range(start..end).map(|(&s, _)| s).collect()
    }

    /// Highest free gap of `len` bytes ending at or below `below`.
    fn find_free(&self, len: u64, below: u64) -> Option<u64> {
        let mut top = below;
        for v in self.vmas.values().rev() {
            if v.start >= top {
                continue;
            }
            if v.end <= top && top - v.end >= len {
                return Some(top - len);
            }
            top = top.min(v.start);
        }
        (top >= MMAP_MIN + len).then(|| top - len)
    }
}

impl AddressSpace {
    pub fn new() -> KResult<Arc<Self>> {
        let pml4 = paging::new_user_pml4().ok_or(Errno::ENOMEM)?;
        Ok(Arc::new(Self {
            pml4,
            inner: Mutex::new(Regions {
                vmas: BTreeMap::new(),
                brk_start: 0,
                brk: 0,
            }),
        }))
    }

    /// Physical address of the top-level table, for CR3.
    pub fn pml4(&self) -> u64 {
        self.pml4
    }

    /// Unmaps every page in `[start, end)` and frees the frames.
    fn unmap_pages(&self, start: u64, end: u64) {
        let mut a = start;
        while a < end {
            if let Some(phys) = paging::unmap_user(self.pml4, a) {
                frame::free(phys);
            }
            a += PAGE_SIZE;
        }
    }

    /// Adds a region. With `fixed`, whatever was there is unmapped first;
    /// otherwise the range must be free.
    pub fn map(&self, start: u64, len: u64, prot: u32, kind: Kind, fixed: bool) -> KResult<()> {
        let end = start.checked_add(len).ok_or(Errno::ENOMEM)?;
        if !start.is_multiple_of(PAGE_SIZE) || len == 0 || end > USER_END || start < PAGE_SIZE {
            return Err(Errno::EINVAL);
        }
        let end = page_up(end);
        let mut r = self.inner.lock();
        if r.overlaps(start, end) {
            if !fixed {
                return Err(Errno::EEXIST);
            }
            for s in r.isolate(start, end) {
                r.vmas.remove(&s);
            }
            self.unmap_pages(start, end);
        }
        r.vmas.insert(
            start,
            Vma {
                start,
                end,
                prot,
                kind,
            },
        );
        Ok(())
    }

    /// A free range of `len` bytes for `mmap` without an address.
    pub fn find_free(&self, len: u64) -> KResult<u64> {
        self.inner
            .lock()
            .find_free(page_up(len), MMAP_END)
            .ok_or(Errno::ENOMEM)
    }

    /// `munmap`: removes every region (or part of one) in the range.
    pub fn unmap(&self, start: u64, len: u64) -> KResult<()> {
        if !start.is_multiple_of(PAGE_SIZE) || len == 0 || start >= USER_END {
            return Err(Errno::EINVAL);
        }
        let end = page_up(start.saturating_add(len)).min(USER_END);
        let mut r = self.inner.lock();
        for s in r.isolate(start, end) {
            r.vmas.remove(&s);
        }
        self.unmap_pages(start, end);
        Ok(())
    }

    /// `mprotect`: every page in the range must be in some region.
    pub fn protect(&self, start: u64, len: u64, prot: u32) -> KResult<()> {
        if !start.is_multiple_of(PAGE_SIZE) {
            return Err(Errno::EINVAL);
        }
        let end = page_up(start.checked_add(len).ok_or(Errno::ENOMEM)?);
        if end > USER_END {
            return Err(Errno::ENOMEM);
        }
        let mut r = self.inner.lock();
        // Linux: ENOMEM if part of the range is not mapped.
        let mut a = start;
        while a < end {
            let v = r.find(a).ok_or(Errno::ENOMEM)?;
            a = v.end;
        }
        for s in r.isolate(start, end) {
            let v = r.vmas.get_mut(&s).unwrap();
            v.prot = prot;
            let (vs, ve, fl) = (v.start, v.end, v.page_flags());
            let mut p = vs;
            while p < ve {
                paging::protect_user(self.pml4, p, fl);
                p += PAGE_SIZE;
            }
        }
        Ok(())
    }

    /// Sets where the `brk` heap starts (just after the executable).
    pub fn init_brk(&self, at: u64) {
        let mut r = self.inner.lock();
        r.brk_start = page_up(at);
        r.brk = r.brk_start;
    }

    /// `brk`: moves the end of the heap; returns the (possibly unchanged)
    /// end, as Linux does.
    pub fn brk(&self, new: u64) -> u64 {
        let mut r = self.inner.lock();
        let (start, old) = (r.brk_start, r.brk);
        if new < start || new > MMAP_END {
            return old;
        }
        let (old_top, new_top) = (page_up(old), page_up(new));
        if new_top > old_top {
            if r.overlaps(old_top, new_top) {
                return old;
            }
            // Extend the heap region (or create it).
            let prev = r.find(old_top - 1).copied();
            match prev {
                Some(v) if v.kind == Kind::Heap && v.end == old_top => {
                    r.vmas.get_mut(&v.start).unwrap().end = new_top;
                }
                _ => {
                    r.vmas.insert(
                        old_top,
                        Vma {
                            start: old_top,
                            end: new_top,
                            prot: PROT_READ | PROT_WRITE,
                            kind: Kind::Heap,
                        },
                    );
                }
            }
        } else if new_top < old_top {
            for s in r.isolate(new_top, old_top) {
                r.vmas.remove(&s);
            }
            self.unmap_pages(new_top, old_top);
        }
        r.brk = new;
        new
    }

    /// Maps the page holding `addr` if a region allows the access. Returns
    /// the page's frame. `force` ignores the protection (for the kernel
    /// filling in a read-only executable segment).
    fn fault_in(
        r: &Regions,
        pml4: u64,
        addr: u64,
        write: bool,
        exec: bool,
        force: bool,
    ) -> KResult<u64> {
        let page = page_down(addr);
        let vma = r.find(addr).ok_or(Errno::EFAULT)?;
        if !force && !vma.allows(write, exec) {
            return Err(Errno::EFAULT);
        }
        if let Some(e) = paging::user_entry(pml4, page) {
            if write && e & flags::COW != 0 {
                return Self::break_cow(pml4, page, e, vma.page_flags());
            }
            return Ok(paging::entry_phys(e));
        }
        let phys = frame::alloc_zeroed().ok_or(Errno::ENOMEM)?;
        if paging::map_user(pml4, page, phys, vma.page_flags()).is_err() {
            frame::free(phys);
            return Err(Errno::ENOMEM);
        }
        Ok(phys)
    }

    /// The first write to a copy-on-write page: copy it, unless this
    /// address space is the last one holding the frame, which can simply
    /// take it over. Returns the frame now mapped.
    fn break_cow(pml4: u64, page: u64, entry: u64, page_flags: u64) -> KResult<u64> {
        let old = paging::entry_phys(entry);
        if frame::ref_count(old) == 1 {
            paging::set_user_entry(pml4, page, old | page_flags | flags::PRESENT);
            return Ok(old);
        }
        let new = frame::alloc_zeroed().ok_or(Errno::ENOMEM)?;
        unsafe {
            core::ptr::copy_nonoverlapping(phys_to_virt(old), phys_to_virt(new), PAGE_SIZE as usize)
        };
        paging::set_user_entry(pml4, page, new | page_flags | flags::PRESENT);
        frame::free(old);
        Ok(new)
    }

    /// A copy of this address space for `fork`: the same regions, every
    /// page shared copy-on-write.
    pub fn fork(&self) -> KResult<Arc<Self>> {
        let r = self.inner.lock();
        let pml4 = paging::new_user_pml4().ok_or(Errno::ENOMEM)?;
        let child = Arc::new(Self {
            pml4,
            inner: Mutex::new(Regions {
                vmas: r.vmas.clone(),
                brk_start: r.brk_start,
                brk: r.brk,
            }),
        });
        let result = paging::fork_user(self.pml4, pml4);
        // Our writable pages just became read-only: drop stale TLB entries.
        if crate::hal::x86::read_cr3() & !0xfff == self.pml4 {
            unsafe { crate::hal::x86::write_cr3(self.pml4) };
        }
        result.map_err(|_| Errno::ENOMEM)?;
        Ok(child)
    }

    /// Resolves a user page fault. Returns false if the access is invalid
    /// (the program gets SIGSEGV).
    pub fn handle_fault(&self, addr: u64, write: bool, exec: bool) -> bool {
        if addr >= USER_END {
            return false;
        }
        let r = self.inner.lock();
        let Some(vma) = r.find(addr) else {
            return false;
        };
        if !vma.allows(write, exec) {
            return false;
        }
        if let Some(e) = paging::user_entry(self.pml4, page_down(addr)) {
            if write && e & flags::COW != 0 {
                return Self::break_cow(self.pml4, page_down(addr), e, vma.page_flags()).is_ok();
            }
            // Present, and the region allows the access: the entry's flags
            // are stale (they should not be). Make them match and retry.
            paging::protect_user(self.pml4, page_down(addr), vma.page_flags());
            return true;
        }
        Self::fault_in(&r, self.pml4, addr, write, exec, false).is_ok()
    }

    /// Walks `[addr, addr + len)` page by page, giving `f` each piece's
    /// kernel pointer and its offset in the range.
    fn each_page(
        &self,
        addr: u64,
        len: usize,
        write: bool,
        force: bool,
        mut f: impl FnMut(*mut u8, usize, usize),
    ) -> KResult<()> {
        if len == 0 {
            return Ok(());
        }
        let end = addr.checked_add(len as u64).ok_or(Errno::EFAULT)?;
        if end > USER_END {
            return Err(Errno::EFAULT);
        }
        let r = self.inner.lock();
        let mut done = 0usize;
        while done < len {
            let a = addr + done as u64;
            let in_page = (PAGE_SIZE - a % PAGE_SIZE).min((len - done) as u64) as usize;
            let phys = Self::fault_in(&r, self.pml4, a, write, false, force)?;
            f(
                unsafe { phys_to_virt(phys).add((a % PAGE_SIZE) as usize) },
                done,
                in_page,
            );
            done += in_page;
        }
        Ok(())
    }

    /// Copies from user memory into `buf`.
    pub fn copy_from(&self, addr: u64, buf: &mut [u8]) -> KResult<()> {
        self.each_page(addr, buf.len(), false, false, |p, off, n| unsafe {
            core::ptr::copy_nonoverlapping(p, buf.as_mut_ptr().add(off), n)
        })
    }

    /// Copies `data` into user memory.
    pub fn copy_to(&self, addr: u64, data: &[u8]) -> KResult<()> {
        self.each_page(addr, data.len(), true, false, |p, off, n| unsafe {
            core::ptr::copy_nonoverlapping(data.as_ptr().add(off), p, n)
        })
    }

    /// Writes `data` whatever the region's protection (loading executables).
    pub fn fill(&self, addr: u64, data: &[u8]) -> KResult<()> {
        self.each_page(addr, data.len(), true, true, |p, off, n| unsafe {
            core::ptr::copy_nonoverlapping(data.as_ptr().add(off), p, n)
        })
    }

    pub fn read<T: Pod>(&self, addr: u64) -> KResult<T> {
        let mut v = core::mem::MaybeUninit::<T>::zeroed();
        let bytes =
            unsafe { core::slice::from_raw_parts_mut(v.as_mut_ptr() as *mut u8, size_of::<T>()) };
        self.copy_from(addr, bytes)?;
        Ok(unsafe { v.assume_init() })
    }

    pub fn write<T: Pod>(&self, addr: u64, v: &T) -> KResult<()> {
        self.copy_to(addr, crate::abi::as_bytes(v))
    }

    /// A NUL-terminated string from user memory, at most `max` bytes.
    pub fn read_cstr(&self, addr: u64, max: usize) -> KResult<String> {
        let mut out = Vec::new();
        let mut a = addr;
        loop {
            let mut chunk = [0u8; 64];
            let n = (PAGE_SIZE - a % PAGE_SIZE).min(64) as usize;
            self.copy_from(a, &mut chunk[..n])?;
            if let Some(i) = chunk[..n].iter().position(|&b| b == 0) {
                out.extend_from_slice(&chunk[..i]);
                break;
            }
            out.extend_from_slice(&chunk[..n]);
            if out.len() > max {
                return Err(Errno::ENAMETOOLONG);
            }
            a += n as u64;
        }
        String::from_utf8(out).map_err(|_| Errno::EINVAL)
    }

    /// The regions, for diagnostics and tests.
    pub fn regions(&self) -> Vec<Vma> {
        self.inner.lock().vmas.values().copied().collect()
    }
}

impl Drop for AddressSpace {
    fn drop(&mut self) {
        paging::free_user_pml4(self.pml4);
    }
}
