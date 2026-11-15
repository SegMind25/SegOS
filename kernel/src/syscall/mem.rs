//! Memory system calls: mmap, munmap, mprotect, mremap.

use super::Ctx;
use crate::abi::mman::*;
use crate::abi::{Errno, KResult};
use crate::fs::FileType;
use crate::mm::PAGE_SIZE;
use crate::mm::vm::{Kind, MMAP_MIN, USER_END};
use alloc::vec::Vec;

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
            FileType::Directory
            | FileType::Fifo
            | FileType::Symlink
            | FileType::BlockDevice
            | FileType::Socket => {
                return Err(Errno::ENODEV);
            }
            // Device memory (/dev/zero is the common case): anonymous.
            FileType::CharDevice => {}
        }
        if !f.readable() {
            return Err(Errno::EACCES);
        }
        if flags & MAP_TYPE != MAP_PRIVATE && prot & PROT_WRITE != 0 && !f.writable() {
            return Err(Errno::EACCES);
        }
        // Devices map their own memory (DRM buffers) only when shared.
        let device_memory = f.inode.file_type() == FileType::CharDevice
            && flags & MAP_TYPE != MAP_PRIVATE
            && f.inode.mmap_frames(off, 0).is_some();
        (f.inode.file_type() == FileType::Regular || device_memory).then_some(f)
    };
    let mm = ctx.mm();
    if flags & MAP_TYPE != MAP_PRIVATE {
        return map_shared(ctx, addr, len, prot, flags, file.as_deref(), off);
    }
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

/// `MAP_SHARED`: the file's page-cache pages, or (anonymous) fresh pages
/// that `fork` shares rather than copies.
fn map_shared(
    ctx: &Ctx,
    addr: u64,
    len: u64,
    prot: u32,
    flags: u32,
    file: Option<&crate::fs::File>,
    off: u64,
) -> KResult<u64> {
    let mm = ctx.mm();
    let start = if flags & (MAP_FIXED | MAP_FIXED_NOREPLACE) != 0 {
        if !addr.is_multiple_of(PAGE_SIZE) {
            return Err(Errno::EINVAL);
        }
        if addr < MMAP_MIN {
            return Err(Errno::EPERM);
        }
        mm.map(
            addr,
            len,
            prot,
            Kind::Shared,
            flags & MAP_FIXED_NOREPLACE == 0,
        )?;
        addr
    } else {
        let s = mm.find_free(len)?;
        mm.map(s, len, prot, Kind::Shared, false)?;
        s
    };
    let pages = len / PAGE_SIZE;
    let mut frames = Vec::with_capacity(pages as usize);
    let result = (|| -> KResult<()> {
        match file {
            Some(f) if f.inode.file_type() == FileType::CharDevice => {
                frames = f.inode.mmap_frames(off, pages).unwrap()?;
                mm.map_shared(start, &frames)
            }
            Some(f) => {
                let cache = crate::fs::pagecache::get(&f.inode);
                if prot & PROT_WRITE != 0 {
                    cache.mark_writable();
                }
                // `page` hands out a reference each; the mappings take
                // their own.
                let r = (0..pages)
                    .try_for_each(|i| cache.page(off / PAGE_SIZE + i).map(|p| frames.push(p)))
                    .and_then(|()| {
                        mm.set_file(start, f.inode.clone(), off, f.path());
                        mm.map_shared(start, &frames)
                    });
                for &p in &frames {
                    crate::mm::frame::free(p);
                }
                r
            }
            None => {
                for _ in 0..pages {
                    frames.push(crate::mm::frame::alloc_zeroed().ok_or(Errno::ENOMEM)?);
                }
                let r = mm.map_shared(start, &frames);
                // The mappings hold the only references now.
                for &p in &frames {
                    crate::mm::frame::free(p);
                }
                r
            }
        }
    })();
    if let Err(e) = result {
        let _ = mm.unmap(start, len);
        return Err(e);
    }
    Ok(start)
}

/// A fresh private mapping of a file: its pages fault in from the file's
/// page cache, shared copy-on-write until written.
fn fill(
    ctx: &Ctx,
    start: u64,
    _len: u64,
    file: Option<&crate::fs::File>,
    off: u64,
) -> KResult<u64> {
    if let Some(f) = file {
        ctx.mm().set_file(start, f.inode.clone(), off, f.path());
    }
    Ok(start)
}

pub fn munmap(ctx: &Ctx, addr: u64, len: u64) -> KResult<u64> {
    let shared = ctx
        .mm()
        .regions()
        .iter()
        .any(|v| v.kind == Kind::Shared && v.start < addr.saturating_add(len) && addr < v.end);
    ctx.mm().unmap(addr, len)?;
    if shared {
        crate::fs::pagecache::sync_all();
    }
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

/// `mremap(old, old_len, new_len, flags)`: shrinks, grows or (with
/// MREMAP_MAYMOVE) moves a mapping. A grown shared file mapping shows more
/// of the file (Wayland compositors grow clients' wl_shm pools this way).
pub fn mremap(ctx: &Ctx, old: u64, old_len: u64, new_len: u64, flags: u32) -> KResult<u64> {
    const MREMAP_MAYMOVE: u32 = 1;
    if flags & !MREMAP_MAYMOVE != 0 {
        return Err(Errno::EINVAL);
    }
    let mm = ctx.mm();
    let (addr, tail) = mm.remap(old, old_len, new_len, flags & MREMAP_MAYMOVE != 0)?;
    if let Some((start, inode, off)) = tail {
        let end = addr + new_len.next_multiple_of(PAGE_SIZE);
        let cache = crate::fs::pagecache::get(&inode);
        cache.mark_writable();
        let mut frames = Vec::new();
        let r = (0..(end - start) / PAGE_SIZE)
            .try_for_each(|i| cache.page(off / PAGE_SIZE + i).map(|p| frames.push(p)))
            .and_then(|()| mm.map_shared(start, &frames));
        for &p in &frames {
            crate::mm::frame::free(p);
        }
        r?;
    }
    Ok(addr)
}
