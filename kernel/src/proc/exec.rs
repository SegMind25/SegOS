//! `execve`: replacing a process's program.
//!
//! Everything that can fail (finding the file, `#!` interpreters, loading
//! the ELF, building the stack) happens in a fresh address space first;
//! only then is the process changed, so a failed `execve` returns an error
//! to an untouched program.

use super::{Process, UserThread, elf, initial_frame, signal};
use crate::abi::{Errno, KResult};
use crate::fs::{self, FileType, Inode};
use crate::hal::idt::TrapFrame;
use crate::hal::x86;
use crate::mm::vm::AddressSpace;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::Ordering;

/// A program ready to run.
pub struct Prepared {
    pub mm: Arc<AddressSpace>,
    pub entry: u64,
    pub rsp: u64,
    /// The executable's canonical absolute path.
    pub exe: String,
    /// The path the program was started by (its name comes from this, as
    /// on Linux: `execve("/proc/self/exe")` makes a process named "exe").
    pub invoked: String,
    pub argv: Vec<String>,
}

/// Interpreters may themselves be scripts this many times (Linux: 4).
const MAX_INTERP_DEPTH: usize = 4;
/// Longest `#!` line read (Linux: BINPRM_BUF_SIZE).
const MAX_SHEBANG: usize = 256;

fn read_all(inode: &Arc<dyn Inode>) -> KResult<Vec<u8>> {
    let mut bytes = alloc::vec![0u8; inode.size() as usize];
    let mut got = 0;
    while got < bytes.len() {
        match fs::pagecache::read_at(inode, got as u64, &mut bytes[got..])? {
            0 => break,
            n => got += n,
        }
    }
    bytes.truncate(got);
    Ok(bytes)
}

/// Parses a `#!interpreter [arg]` line.
fn shebang(bytes: &[u8]) -> Option<(String, Option<String>)> {
    let line = bytes.strip_prefix(b"#!")?;
    let end = line
        .iter()
        .position(|&b| b == b'\n')
        .unwrap_or(line.len())
        .min(MAX_SHEBANG);
    let line = core::str::from_utf8(&line[..end]).ok()?.trim();
    let (interp, arg) = match line.split_once([' ', '\t']) {
        Some((i, a)) => (i, Some(a.trim().to_string()).filter(|a| !a.is_empty())),
        None => (line, None),
    };
    (!interp.is_empty()).then(|| (interp.to_string(), arg))
}

/// Finds and loads the program at `path` (from `cwd`), following `#!`.
pub fn prepare(
    cwd: &Arc<dyn Inode>,
    path: &str,
    mut argv: Vec<String>,
    envp: Vec<String>,
) -> KResult<Prepared> {
    let execfn = path.to_string();
    let mut path = path.to_string();
    for _ in 0..=MAX_INTERP_DEPTH {
        let (inode, canonical) = fs::resolve(cwd, &path, true)?;
        match inode.file_type() {
            FileType::Regular => {}
            FileType::Directory => return Err(Errno::EACCES),
            _ => return Err(Errno::EACCES),
        }
        if inode.perm() & 0o111 == 0 {
            return Err(Errno::EACCES);
        }
        let bytes = read_all(&inode)?;
        if let Some((interp, arg)) = shebang(&bytes) {
            // argv becomes: interpreter [arg] script original-args...
            let mut new = alloc::vec![interp.clone()];
            new.extend(arg);
            new.push(path.clone());
            new.extend(argv.into_iter().skip(1));
            argv = new;
            path = interp;
            continue;
        }
        let mm = AddressSpace::new()?;
        let mut image = elf::load(&mm, &bytes)?;
        drop(bytes);
        if let Some(interp) = image.interp.take() {
            // The dynamic linker: found from the root, a regular file.
            let ld = fs::lookup(&fs::root(), &interp).map_err(|e| match e {
                Errno::ENOENT => Errno::ENOENT,
                _ => Errno::ELIBBAD,
            })?;
            if ld.file_type() != FileType::Regular {
                return Err(Errno::ELIBBAD);
            }
            let (base, entry) = elf::load_interp(&mm, &read_all(&ld)?)?;
            image.interp_base = base;
            image.start = entry;
        }
        mm.init_brk(image.end);
        let argv_refs: Vec<&str> = argv.iter().map(|s| s.as_str()).collect();
        let envp_refs: Vec<&str> = envp.iter().map(|s| s.as_str()).collect();
        let rsp = elf::build_stack(&mm, &image, &execfn, &argv_refs, &envp_refs)?;
        return Ok(Prepared {
            mm,
            entry: image.start,
            rsp,
            exe: canonical,
            invoked: execfn,
            argv,
        });
    }
    Err(Errno::ELOOP)
}

/// Names the process after its new program.
pub fn set_identity(p: &Process, img: &Prepared) {
    let base = img.invoked.rsplit('/').next().unwrap_or(&img.invoked);
    let mut name = base.to_string();
    name.truncate(15);
    *p.name.lock() = name;
    *p.exe.lock() = img.exe.clone();
    *p.cmdline.lock() = img.argv.clone();
}

/// `execve` for the calling thread: on success the thread returns to user
/// mode at the new program's entry point through `frame`.
pub fn execve(
    t: &UserThread,
    frame: &mut TrapFrame,
    path: &str,
    argv: Vec<String>,
    envp: Vec<String>,
) -> KResult<()> {
    let cwd = t.process.cwd.lock().clone();
    let img = prepare(&cwd, path, argv, envp)?;

    // Point of no return.
    let old = t.replace_mm(img.mm.clone());
    drop(old);
    t.process.files.lock().close_on_exec();
    {
        // Handlers do not survive (their code is gone); ignored stays
        // ignored. The mask and pending signals are kept.
        let mut acts = t.process.sigactions.lock();
        for a in acts.iter_mut() {
            if a.handler != signal::SIG_IGN {
                *a = signal::SigAction::default();
            }
        }
    }
    *t.sig.altstack.lock() = (0, 0, 2);
    t.fs_base.store(0, Ordering::Relaxed);
    t.gs_base.store(0, Ordering::Relaxed);
    t.clear_child_tid.store(0, Ordering::Relaxed);
    x86::without_interrupts(|| unsafe {
        x86::wrmsr(x86::msr::FS_BASE, 0);
        x86::wrmsr(x86::msr::KERNEL_GS_BASE, 0);
    });
    t.reset_fpu();
    set_identity(&t.process, &img);
    t.release_vfork_parent();
    *frame = initial_frame(img.entry, img.rsp);
    Ok(())
}
