//! Disk file systems, mounted from block devices, and the root file
//! system on disk.

use super::Inode;
use super::mount;
use crate::abi::KResult;
use crate::block::BlockDevice;
use alloc::format;
use alloc::sync::Arc;

/// Mounts the ext2/3/4 file system on `dev`: its root and statfs info.
pub fn mount_ext4(dev: Arc<dyn BlockDevice>) -> KResult<mount::Mounted> {
    let id = dev.rdev();
    let fs = super::ext4::Ext4Fs::mount(dev, id)?;
    Ok((fs.root(), Some(Arc::new(Ext4Info(fs)))))
}

struct Ext4Info(Arc<super::ext4::Ext4Fs>);

impl mount::FsInfo for Ext4Info {
    fn magic(&self) -> u64 {
        0xef53
    }
    fn stats(&self) -> (u64, u64, u64, u64, u64) {
        self.0.stats()
    }
    fn read_only(&self) -> bool {
        !self.0.writable()
    }
}

/// Mounts the FAT12/16/32 file system on `dev`.
pub fn mount_fat(dev: Arc<dyn BlockDevice>) -> KResult<mount::Mounted> {
    let id = dev.rdev();
    let fs = super::fat::FatFs::mount(dev, id)?;
    Ok((fs.root(), Some(fs)))
}

/// Looks for a partition holding a root file system (ext4 with `/init`)
/// and mounts it on "/", as Linux does with `root=`. Then mounts what the
/// system needs on it: /dev, /proc, /sys, tmpfs on /tmp and /run, and on /root while disk
/// file systems are read-only. Returns the device used.
pub fn mount_root() -> Option<alloc::string::String> {
    for dev in crate::block::all() {
        let Ok((root, info)) = mount_ext4(dev.clone()) else {
            continue;
        };
        let read_only = info.as_ref().is_none_or(|i| i.read_only());
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
            read_only,
            info,
        )
        .is_err()
        {
            continue;
        }
        let mut extra: alloc::vec::Vec<(&str, &str, Arc<dyn Inode>)> = alloc::vec![
            ("dev", "devtmpfs", super::dev_dir()),
            ("proc", "proc", super::procfs::root(&root)),
            ("tmp", "tmpfs", super::tmpfs::Dir::new_root(0o1777)),
            ("run", "tmpfs", super::tmpfs::Dir::new_root(0o755)),
            ("sys", "sysfs", super::sysfs::create()),
        ];
        if read_only {
            // Somewhere to write a shell history and the like.
            extra.push(("root", "tmpfs", super::tmpfs::Dir::new_root(0o700)));
        }
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
