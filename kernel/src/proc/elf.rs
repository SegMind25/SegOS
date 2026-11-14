//! Loading ELF executables, and the initial stack Linux gives a program.
//!
//! Static executables only in Phase 2: `ET_EXEC` (loaded at its link
//! addresses) and static-PIE `ET_DYN` (loaded at Linux's usual base). A
//! program with `PT_INTERP` needs the dynamic linker, which arrives with
//! glibc in Phase 5.

use crate::abi::mman::{PROT_EXEC, PROT_READ, PROT_WRITE};
use crate::abi::{Errno, KResult};
use crate::mm::PAGE_SIZE;
use crate::mm::vm::{self, AddressSpace, Kind};
use alloc::vec::Vec;

const PT_LOAD: u32 = 1;
const PT_INTERP: u32 = 3;
const PT_PHDR: u32 = 6;
const PF_X: u32 = 1;
const PF_W: u32 = 2;
const PF_R: u32 = 4;
const ET_EXEC: u16 = 2;
const ET_DYN: u16 = 3;
const EM_X86_64: u16 = 62;
/// Where Linux puts a position-independent executable (2/3 of the
/// 47-bit user space, page aligned).
const PIE_BASE: u64 = 0x5555_5555_4000;

/// What the loader learned, for the auxiliary vector and `brk`.
pub struct Image {
    pub entry: u64,
    pub phdr: u64,
    pub phent: u64,
    pub phnum: u64,
    /// End of the highest segment: where the heap starts.
    pub end: u64,
}

struct Phdr {
    ty: u32,
    flags: u32,
    offset: u64,
    vaddr: u64,
    filesz: u64,
    memsz: u64,
}

fn u16_at(b: &[u8], o: usize) -> KResult<u16> {
    b.get(o..o + 2)
        .map(|s| u16::from_le_bytes(s.try_into().unwrap()))
        .ok_or(Errno::ENOEXEC)
}

fn u32_at(b: &[u8], o: usize) -> KResult<u32> {
    b.get(o..o + 4)
        .map(|s| u32::from_le_bytes(s.try_into().unwrap()))
        .ok_or(Errno::ENOEXEC)
}

fn u64_at(b: &[u8], o: usize) -> KResult<u64> {
    b.get(o..o + 8)
        .map(|s| u64::from_le_bytes(s.try_into().unwrap()))
        .ok_or(Errno::ENOEXEC)
}

fn prot(flags: u32) -> u32 {
    (if flags & PF_R != 0 { PROT_READ } else { 0 })
        | (if flags & PF_W != 0 { PROT_WRITE } else { 0 })
        | (if flags & PF_X != 0 { PROT_EXEC } else { 0 })
}

/// Maps the program's segments into `mm`.
pub fn load(mm: &AddressSpace, file: &[u8]) -> KResult<Image> {
    if file.len() < 64 || &file[..4] != b"\x7fELF" {
        return Err(Errno::ENOEXEC);
    }
    // 64-bit, little-endian, version 1, x86-64.
    if file[4] != 2 || file[5] != 1 || file[6] != 1 || u16_at(file, 18)? != EM_X86_64 {
        return Err(Errno::ENOEXEC);
    }
    let ty = u16_at(file, 16)?;
    let entry = u64_at(file, 24)?;
    let phoff = u64_at(file, 32)? as usize;
    let phentsize = u16_at(file, 54)? as usize;
    let phnum = u16_at(file, 56)? as usize;
    if phentsize < 56 || phnum == 0 || phnum > 128 {
        return Err(Errno::ENOEXEC);
    }
    let mut phdrs = Vec::with_capacity(phnum);
    for i in 0..phnum {
        let o = phoff + i * phentsize;
        phdrs.push(Phdr {
            ty: u32_at(file, o)?,
            flags: u32_at(file, o + 4)?,
            offset: u64_at(file, o + 8)?,
            vaddr: u64_at(file, o + 16)?,
            filesz: u64_at(file, o + 32)?,
            memsz: u64_at(file, o + 40)?,
        });
    }
    if phdrs.iter().any(|p| p.ty == PT_INTERP) {
        // Dynamically linked: needs ld.so (Phase 5).
        return Err(Errno::ENOEXEC);
    }
    let bias = match ty {
        ET_EXEC => 0,
        ET_DYN => PIE_BASE,
        _ => return Err(Errno::ENOEXEC),
    };

    let mut prev_end = 0u64; // end (page aligned) of the last region mapped
    let mut prev_prot = 0u32;
    let mut end = 0u64;
    for p in phdrs.iter().filter(|p| p.ty == PT_LOAD && p.memsz > 0) {
        if p.filesz > p.memsz
            || p.offset
                .checked_add(p.filesz)
                .is_none_or(|e| e > file.len() as u64)
        {
            return Err(Errno::ENOEXEC);
        }
        let start = p.vaddr.checked_add(bias).ok_or(Errno::ENOEXEC)?;
        let seg_end = start.checked_add(p.memsz).ok_or(Errno::ENOEXEC)?;
        if seg_end > vm::MMAP_END || start < PAGE_SIZE {
            return Err(Errno::ENOEXEC);
        }
        let mut ps = start & !(PAGE_SIZE - 1);
        let pe = seg_end.next_multiple_of(PAGE_SIZE);
        let pr = prot(p.flags);
        if ps < prev_end {
            // This segment starts in the last page of the previous one:
            // that page gets both segments' permissions.
            mm.protect(ps, PAGE_SIZE, prev_prot | pr)?;
            ps = prev_end;
        }
        if pe > ps {
            mm.map(ps, pe - ps, pr, Kind::Image, false)
                .map_err(|_| Errno::ENOEXEC)?;
        }
        let data = &file[p.offset as usize..(p.offset + p.filesz) as usize];
        mm.fill(start, data)?;
        prev_end = prev_end.max(pe);
        prev_prot = pr;
        end = end.max(seg_end);
    }
    if end == 0 {
        return Err(Errno::ENOEXEC);
    }

    // Where the program headers are in memory, for AT_PHDR.
    let phdr = match phdrs.iter().find(|p| p.ty == PT_PHDR) {
        Some(p) => p.vaddr + bias,
        None => phdrs
            .iter()
            .find(|p| {
                p.ty == PT_LOAD && p.offset <= phoff as u64 && (phoff as u64) < p.offset + p.filesz
            })
            .map(|p| p.vaddr + bias + (phoff as u64 - p.offset))
            .unwrap_or(0),
    };
    Ok(Image {
        entry: entry + bias,
        phdr,
        phent: phentsize as u64,
        phnum: phnum as u64,
        end,
    })
}

// Auxiliary vector keys (elf.h).
const AT_NULL: u64 = 0;
const AT_PHDR: u64 = 3;
const AT_PHENT: u64 = 4;
const AT_PHNUM: u64 = 5;
const AT_PAGESZ: u64 = 6;
const AT_BASE: u64 = 7;
const AT_FLAGS: u64 = 8;
const AT_ENTRY: u64 = 9;
const AT_UID: u64 = 11;
const AT_EUID: u64 = 12;
const AT_GID: u64 = 13;
const AT_EGID: u64 = 14;
const AT_PLATFORM: u64 = 15;
const AT_HWCAP: u64 = 16;
const AT_CLKTCK: u64 = 17;
const AT_SECURE: u64 = 23;
const AT_RANDOM: u64 = 25;
const AT_HWCAP2: u64 = 26;
const AT_EXECFN: u64 = 31;

/// Maps the main thread's stack and writes what a Linux program finds on
/// it at `_start`, from `rsp` upwards: argc, argv[], NULL, envp[], NULL,
/// the auxiliary vector, then the strings. Returns `rsp` (16-byte aligned).
pub fn build_stack(
    mm: &AddressSpace,
    image: &Image,
    path: &str,
    argv: &[&str],
    envp: &[&str],
) -> KResult<u64> {
    let bottom = vm::STACK_END - vm::STACK_SIZE;
    mm.map(
        bottom,
        vm::STACK_SIZE,
        PROT_READ | PROT_WRITE,
        Kind::Stack,
        false,
    )?;

    let mut sp = vm::STACK_END;
    let push_bytes = |bytes: &[u8], sp: &mut u64| -> KResult<u64> {
        *sp -= bytes.len() as u64;
        mm.copy_to(*sp, bytes)?;
        Ok(*sp)
    };
    // Strings, with their NUL terminators; Linux puts the executable's
    // name highest.
    let cstr = |s: &str, sp: &mut u64| -> KResult<u64> {
        let mut v = Vec::with_capacity(s.len() + 1);
        v.extend_from_slice(s.as_bytes());
        v.push(0);
        push_bytes(&v, sp)
    };
    sp -= 8; // an empty word at the very top, as Linux leaves
    let execfn = cstr(path, &mut sp)?;
    let mut env_ptrs = Vec::with_capacity(envp.len());
    for e in envp.iter().rev() {
        env_ptrs.push(cstr(e, &mut sp)?);
    }
    env_ptrs.reverse();
    let mut arg_ptrs = Vec::with_capacity(argv.len());
    for a in argv.iter().rev() {
        arg_ptrs.push(cstr(a, &mut sp)?);
    }
    arg_ptrs.reverse();
    let platform = cstr("x86_64", &mut sp)?;
    let mut random = [0u8; 16];
    crate::random::fill(&mut random);
    sp &= !15;
    sp -= 16;
    mm.copy_to(sp, &random)?;
    let random_at = sp;

    let hwcap = crate::hal::x86::cpuid(1, 0).3 as u64;
    let auxv: [(u64, u64); 19] = [
        (AT_PHDR, image.phdr),
        (AT_PHENT, image.phent),
        (AT_PHNUM, image.phnum),
        (AT_PAGESZ, PAGE_SIZE),
        (AT_BASE, 0),
        (AT_FLAGS, 0),
        (AT_ENTRY, image.entry),
        (AT_UID, 0),
        (AT_EUID, 0),
        (AT_GID, 0),
        (AT_EGID, 0),
        (AT_PLATFORM, platform),
        (AT_HWCAP, hwcap),
        (AT_CLKTCK, crate::hal::apic::HZ),
        (AT_SECURE, 0),
        (AT_RANDOM, random_at),
        (AT_HWCAP2, 0),
        (AT_EXECFN, execfn),
        (AT_NULL, 0),
    ];
    let mut words: Vec<u64> = Vec::new();
    words.push(argv.len() as u64);
    words.extend(&arg_ptrs);
    words.push(0);
    words.extend(&env_ptrs);
    words.push(0);
    for (k, v) in auxv {
        words.push(k);
        words.push(v);
    }
    // rsp must be 16-byte aligned with argc at [rsp].
    sp &= !15;
    if words.len() % 2 == 1 {
        sp -= 8;
    }
    sp -= words.len() as u64 * 8;
    let bytes: Vec<u8> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
    mm.copy_to(sp, &bytes)?;
    if sp < bottom + PAGE_SIZE {
        return Err(Errno::E2BIG);
    }
    Ok(sp)
}
