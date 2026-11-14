//! `newc` cpio archive writer: the format Linux uses for its initramfs
//! (see the kernel's Documentation/driver-api/early-userspace), so the same
//! archive would also boot Linux.
//!
//! Every entry: a 110-byte ASCII header ("070701" and 13 eight-digit hex
//! fields), the NUL-terminated name, padding to 4 bytes, the data, padding
//! to 4 bytes. The archive ends with an entry named `TRAILER!!!`.

use std::collections::BTreeSet;

pub const MODE_DIR: u32 = 0o040_000;
pub const MODE_FILE: u32 = 0o100_000;

pub struct Entry {
    /// Path inside the archive, without a leading slash ("tests/basics").
    pub path: String,
    /// File type and permission bits, as in `st_mode`.
    pub mode: u32,
    pub data: Vec<u8>,
}

/// Writes `files` (regular files), the (possibly empty) directories
/// `dirs`, and every directory above them, parents first. Timestamps are 0
/// so archives are reproducible.
pub fn write(files: &[Entry], dirs: &[&str]) -> Vec<u8> {
    let mut all: Vec<String> = files.iter().map(|f| f.path.clone()).collect();
    all.extend(dirs.iter().map(|d| format!("{d}/")));
    let mut dirs = BTreeSet::new();
    for path in &all {
        let mut p = path.as_str();
        while let Some(i) = p.rfind('/') {
            p = &p[..i];
            dirs.insert(p.to_string());
        }
    }
    let mut out = Vec::new();
    let mut ino = 1;
    // BTreeSet order puts "a" before "a/b": parents first.
    for d in &dirs {
        entry(&mut out, ino, d, MODE_DIR | 0o755, &[]);
        ino += 1;
    }
    for f in files {
        entry(&mut out, ino, &f.path, f.mode, &f.data);
        ino += 1;
    }
    entry(&mut out, 0, "TRAILER!!!", 0, &[]);
    out
}

fn entry(out: &mut Vec<u8>, ino: u32, name: &str, mode: u32, data: &[u8]) {
    let nlink = if mode & MODE_DIR != 0 { 2 } else { 1 };
    let fields = [
        ino,
        mode,
        0, // uid
        0, // gid
        nlink,
        0, // mtime
        data.len() as u32,
        0, // devmajor
        0, // devminor
        0, // rdevmajor
        0, // rdevminor
        name.len() as u32 + 1,
        0, // check
    ];
    out.extend_from_slice(b"070701");
    for f in fields {
        out.extend_from_slice(format!("{f:08x}").as_bytes());
    }
    out.extend_from_slice(name.as_bytes());
    out.push(0);
    pad4(out);
    out.extend_from_slice(data);
    pad4(out);
}

fn pad4(out: &mut Vec<u8>) {
    while !out.len().is_multiple_of(4) {
        out.push(0);
    }
}
