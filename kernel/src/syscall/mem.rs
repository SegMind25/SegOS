//! Memory system calls: mmap, munmap, mprotect, mremap.

use super::Ctx;
use crate::abi::mman::*;
use crate::abi::{Errno, KResult};
use crate::fs::FileType;
use crate::mm::PAGE_SIZE;
use crate::mm::vm::{Kind, MMAP_MIN, USER_END};
use alloc::vec;

const MAP_TYPE: u32 = 0x0f;
const MAP_SHARED_VALIDATE: u32 = 0x03;

pub fn mmap(
    ctx: &Ctx,
    addr: u64,
    len: u64,
    prot: u32,
    flags: u32,
    fd: i32,
    off: u64,
) -> KResult<u64> {
    if len == 0 || !off.is_multiple_of(PAGE_SIZE) {
        return Err(Errno::EINVAL);
    }
    match flags & MAP_TYPE {
        MAP_PRIVATE | MAP_SHARED | MAP_SHARED_VALIDATE => {}
        _ => return Err(Errno::EINVAL),
    }
    let len = len
        .checked_next_multiple_of(PAGE_SIZE)
        .ok_or(Errno::ENOMEM)?;
    if len > USER_END {
        return Err(Errno::ENOMEM);
    }
    let anonymous = flags & MAP_ANONYMOUS != 0;
    let file = if anonymous {
        None
    } else {
        let f = ctx.process().files.lock().get(fd)?;
        match f.inode.file_type() {
            FileType::Regular => {}
            FileType::Directory => return Err(Errno::ENODEV),
            // Device memory (/dev/zero is the common case): anonymous.
            FileType::CharDevice => {}
        }
        if !f.readable() {
            return Err(Errno::EACCES);
        }
        if flags & MAP_TYPE != MAP_PRIVATE && prot & PROT_WRITE != 0 && !f.writable() {
            return Err(Errno::EACCES);
        }
        (f.inode.file_type() == FileType::Regular).then_some(f)
    };
    if flags & MAP_TYPE != MAP_PRIVATE && file.is_some() {
        // Shared file mappings need the page cache (Phase 4): a private
        // copy would silently lose writes.
        return Err(Errno::ENODEV);
    }

    let mm = ctx.mm();
    let fixed = flags & (MAP_FIXED | MAP_FIXED_NOREPLACE) != 0;
    let start = if fixed {
        if !addr.is_multiple_of(PAGE_SIZE) {
            return Err(Errno::EINVAL);
        }
        if addr < MMAP_MIN {
            return Err(Errno::EPERM);
        }
        addr
    } else {
        // A hint is used if that range is free.
        let hint = addr & !(PAGE_SIZE - 1);
        if hint >= MMAP_MIN
            && hint.checked_add(len).is_some_and(|e| e <= USER_END)
            && mm.map(hint, len, prot, Kind::Anon, false).is_ok()
        {
            return fill(ctx, hint, len, file.as_deref(), off);
        }
        mm.find_free(len)?
    };
    let replace = flags & MAP_FIXED_NOREPLACE == 0 && fixed;
    mm.map(start, len, prot, Kind::Anon, replace)?;
    fill(ctx, start, len, file.as_deref(), off)
}

/// Copies a file's contents into a fresh private mapping. (Read now, not
/// on fault: tmpfs files are in memory already. Demand paging from the
/// page cache comes with real disks.)
fn fill(ctx: &Ctx, start: u64, len: u64, file: Option<&crate::fs::File>, off: u64) -> KResult<u64> {
    let Some(f) = file else {
        return Ok(start);
    };
    let size = f.inode.size();
    if off < size {
        let n = (size - off).min(len) as usize;
        let mut buf = vec![0u8; n];
        let got = f.inode.read_at(off, &mut buf)?;
        ctx.mm().fill(start, &buf[..got])?;
    }
    Ok(start)
}

pub fn munmap(ctx: &Ctx, addr: u64, len: u64) -> KResult<u64> {
    ctx.mm().unmap(addr, len)?;
    Ok(0)
}

pub fn mprotect(ctx: &Ctx, addr: u64, len: u64, prot: u32) -> KResult<u64> {
    if prot & !(PROT_READ | PROT_WRITE | PROT_EXEC) != 0 {
        return Err(Errno::EINVAL);
    }
    if len == 0 {
        return if addr.is_multiple_of(PAGE_SIZE) {
            Ok(0)
        } else {
            Err(Errno::EINVAL)
        };
    }
    ctx.mm().protect(addr, len, prot)?;
    Ok(0)
}

/// Not supported yet; C libraries fall back to allocate, copy, free.
pub fn mremap() -> KResult<u64> {
    Err(Errno::ENOMEM)
}
