//! Booting from a disk: `root=` on the command line names the file
//! system to mount on `/` (`/dev/sda2`, `PARTLABEL=<GPT name>` or
//! `LABEL=<file system label>`). `/dev`, `/proc`, `/sys`, `/tmp` and
//! `/run` are mounted on it where it has those directories.

use super::{FileType, Inode, ext4::Ext4, mount};
use crate::abi::{Errno, KResult};
use crate::block::{self, BlockDevice};
use alloc::format;
use alloc::sync::Arc;

/// The block device `spec` names.
fn device(spec: &str) -> Option<Arc<dyn BlockDevice>> {
    if let Some(l) = spec.strip_prefix("PARTLABEL=") {
        return block::find_label(l);
    }
    if let Some(l) = spec.strip_prefix("LABEL=") {
        // The ext4 volume label, at offset 0x78 of the superblock.
        return block::all().into_iter().map(|(d, _)| d).find(|d| {
            let mut sb = [0u8; 0x100];
            block::read_bytes(&**d, 1024, &mut sb).is_ok()
                && sb[0x38..0x3a] == [0x53, 0xef]
                && sb[0x78..0x88].split(|&b| b == 0).next() == Some(l.as_bytes())
        });
    }
    block::find(spec.strip_prefix("/dev/").unwrap_or(spec))
}

pub fn mount_root(spec: &str) -> KResult<()> {
    let dev = device(spec).ok_or(Errno::ENODEV)?;
    let name = format!("/dev/{}", dev.name());
    let root = Ext4::mount(dev)?;
    mount::mount(None, root.clone(), &name, "ext4", false)?;
    super::set_root(root.clone());
    let dir = |p: &str| -> Option<Arc<dyn Inode>> {
        root.lookup(p)
            .ok()
            .filter(|d| d.file_type() == FileType::Directory)
    };
    let initial = super::initial_root();
    if let (Some(p), Ok(d)) = (dir("dev"), initial.lookup("dev")) {
        mount::mount(Some(p), d, "devtmpfs", "devtmpfs", false)?;
    }
    if let Some(p) = dir("proc") {
        mount::mount(Some(p), super::procfs::root(&root), "proc", "proc", false)?;
    }
    if let Some(p) = dir("sys") {
        mount::mount(Some(p), super::procfs::sysfs(), "sysfs", "sysfs", false)?;
    }
    for t in ["tmp", "run"] {
        if let Some(p) = dir(t) {
            mount::mount(
                Some(p),
                super::tmpfs::Dir::new_root(0o1777),
                "tmpfs",
                "tmpfs",
                false,
            )?;
        }
    }
    Ok(())
}
