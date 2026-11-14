//! `/sys`: the few files glibc and Python read at start-up, generated once
//! at boot (CPU counts for `sysconf(_SC_NPROCESSORS_ONLN)` and
//! `os.cpu_count()`). A real sysfs, with devices, arrives with the
//! drivers that need it.

use super::{FileType, Inode};
use alloc::format;
use alloc::sync::Arc;

/// Builds the tree (read-only files on a tmpfs).
pub fn create() -> Arc<dyn Inode> {
    let root = super::tmpfs::Dir::new_root(0o555);
    let cpus = crate::hal::percpu::count();
    let range = if cpus > 1 {
        format!("0-{}\n", cpus - 1)
    } else {
        "0\n".into()
    };
    let mut dir = root.clone();
    for part in ["devices", "system", "cpu"] {
        dir = dir.create(part, FileType::Directory, 0o755).expect("sysfs");
    }
    for name in ["online", "possible", "present"] {
        let f = dir.create(name, FileType::Regular, 0o444).expect("sysfs");
        let _ = f.write_at(0, range.as_bytes());
    }
    for i in 0..cpus {
        let _ = dir.create(&format!("cpu{i}"), FileType::Directory, 0o755);
    }
    for part in ["kernel", "fs", "block", "class", "bus", "dev"] {
        let _ = root.create(part, FileType::Directory, 0o755);
    }
    root
}
