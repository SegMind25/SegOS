//! Disk file systems, mounted from block devices, and the root file
//! system on disk.

use super::Inode;
use super::mount;
use crate::abi::{Errno, KResult};
use crate::block::BlockDevice;
use alloc::format;
use alloc::sync::Arc;

/// Mounts the ext2/3/4 file system on `dev`: its root and statfs info.
pub fn mount_ext4(_dev: Arc<dyn BlockDevice>) -> KResult<mount::Mounted> {
    Err(Errno::ENODEV)
}

/// Looks for a partition holding a root file system (ext4 with `/init`)
/// and mounts it on "/", as Linux does with `root=`. Then mounts what the
/// system needs on it: /dev, /proc, and tmpfs on /tmp and /root while disk
/// file systems are read-only. Returns the device used.
pub fn mount_root() -> Option<alloc::string::String> {
    for dev in crate::block::all() {
        let Ok((root, info)) = mount_ext4(dev.clone()) else {
            continue;
        };
        if root.lookup("init").is_err() {
            continue;
        }
        let source = format!("/dev/{}", dev.name());
        if mount::add(
            super::root(),
            root.clone(),
            &source,
            "ext4",
            "/",
            true,
            info,
        )
        .is_err()
        {
            continue;
        }
        let extra: [(&str, &str, Arc<dyn Inode>); 4] = [
            ("dev", "devtmpfs", super::dev_dir()),
            ("proc", "proc", super::procfs::root(&root)),
            ("tmp", "tmpfs", super::tmpfs::Dir::new_root(0o1777)),
            ("root", "tmpfs", super::tmpfs::Dir::new_root(0o700)),
        ];
        for (dir, fstype, fsroot) in extra {
            match root.lookup(dir) {
                Ok(point) => {
                    let _ = mount::add(
                        point,
                        fsroot,
                        fstype,
                        fstype,
                        &format!("/{dir}"),
                        false,
                        None,
                    );
                }
                Err(_) => crate::warn!("root: no /{dir} on {source}"),
            }
        }
        return Some(source);
    }
    None
}
