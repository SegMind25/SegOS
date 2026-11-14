//! Unpacks a `newc` cpio archive (Linux's initramfs format) into the root
//! file system.

use super::{FileType, Inode, lookup_parent, root};
use crate::abi::{Errno, KResult, mode};
use alloc::string::String;
use alloc::sync::Arc;

const HEADER: usize = 110;

fn hex(field: &[u8]) -> Option<u32> {
    u32::from_str_radix(core::str::from_utf8(field).ok()?, 16).ok()
}

fn align4(n: usize) -> usize {
    n.next_multiple_of(4)
}

/// Counts of what was unpacked.
#[derive(Default, Debug)]
pub struct Summary {
    pub files: usize,
    pub dirs: usize,
    pub bytes: usize,
    pub skipped: usize,
}

/// Unpacks `archive` into the root. Directories must come before their
/// contents (as every cpio writer emits them).
pub fn unpack(archive: &[u8]) -> KResult<Summary> {
    let root: Arc<dyn Inode> = root();
    let mut s = Summary::default();
    let mut pos = 0;
    loop {
        let h = archive.get(pos..pos + HEADER).ok_or(Errno::EINVAL)?;
        if &h[..6] != b"070701" && &h[..6] != b"070702" {
            return Err(Errno::EINVAL);
        }
        let field = |i: usize| hex(&h[6 + i * 8..14 + i * 8]).ok_or(Errno::EINVAL);
        let (m, size, namesize) = (field(1)?, field(6)? as usize, field(11)? as usize);
        let name_start = pos + HEADER;
        let name = archive
            .get(name_start..name_start + namesize.saturating_sub(1))
            .ok_or(Errno::EINVAL)?;
        let name = String::from_utf8_lossy(name);
        let data_start = align4(name_start + namesize);
        let data = archive
            .get(data_start..data_start + size)
            .ok_or(Errno::EINVAL)?;
        pos = align4(data_start + size);
        if name == "TRAILER!!!" {
            return Ok(s);
        }
        let path = name.trim_start_matches("./").trim_start_matches('/');
        if path.is_empty() || path == "." {
            continue;
        }
        let perm = m & 0o7777;
        let (dir, last) = lookup_parent(&root, path)?;
        match m & mode::S_IFMT {
            mode::S_IFDIR => {
                match dir.create(&last, FileType::Directory, perm) {
                    Ok(_) | Err(Errno::EEXIST) => {}
                    Err(e) => return Err(e),
                }
                s.dirs += 1;
            }
            mode::S_IFREG => {
                let f = dir.create(&last, FileType::Regular, perm)?;
                f.write_at(0, data)?;
                s.files += 1;
                s.bytes += data.len();
            }
            // Symbolic links, device nodes, FIFOs: Phase 3.
            _ => {
                crate::warn!("initramfs: skipping {path} (mode {m:o})");
                s.skipped += 1;
            }
        }
    }
}
