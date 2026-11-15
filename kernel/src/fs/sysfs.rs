//! `/sys`: what programs read at start-up, generated once at boot: CPU
//! counts (for `sysconf(_SC_NPROCESSORS_ONLN)`, `os.cpu_count()`), and
//! the display and input devices laid out as udev expects them (device
//! directories with `uevent` and `dev`, `subsystem` links, `/sys/class`
//! and `/sys/dev/char` links), so libudev, libinput and Wayland
//! compositors find `/dev/dri/card0` and `/dev/input/event*`.

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
    devices(&root);
    root
}

fn mkdir(root: &Arc<dyn Inode>, path: &str) -> Arc<dyn Inode> {
    let mut d = root.clone();
    for p in path.split('/').filter(|p| !p.is_empty()) {
        d = match d.lookup(p) {
            Ok(x) => x,
            Err(_) => d.create(p, FileType::Directory, 0o755).expect("sysfs"),
        };
    }
    d
}

fn put(root: &Arc<dyn Inode>, path: &str, text: &str) {
    let (dir, name) = path.rsplit_once('/').unwrap();
    if let Ok(f) = mkdir(root, dir).create(name, FileType::Regular, 0o444) {
        let _ = f.write_at(0, text.as_bytes());
    }
}

fn link(root: &Arc<dyn Inode>, path: &str, target: &str) {
    let (dir, name) = path.rsplit_once('/').unwrap();
    let _ = mkdir(root, dir).symlink(name, target);
}

/// A device directory `dev` (under /sys/devices) of `subsystem`, with its
/// device node `(major, minor, name under /dev)` if it has one.
fn device(
    root: &Arc<dyn Inode>,
    dev: &str,
    subsystem: &str,
    node: Option<(u32, u32, &str)>,
    extra: &str,
) {
    let depth = dev.split('/').count() + 1; // "devices/" plus the path
    let up = "../".repeat(depth);
    let name = dev.rsplit('/').next().unwrap();
    let mut uevent = alloc::string::String::new();
    if let Some((ma, mi, n)) = node {
        uevent.push_str(&format!("MAJOR={ma}\nMINOR={mi}\nDEVNAME={n}\n"));
        put(root, &format!("devices/{dev}/dev"), &format!("{ma}:{mi}\n"));
        link(
            root,
            &format!("dev/char/{ma}:{mi}"),
            &format!("../../devices/{dev}"),
        );
    }
    uevent.push_str(extra);
    put(root, &format!("devices/{dev}/uevent"), &uevent);
    link(
        root,
        &format!("devices/{dev}/subsystem"),
        &format!("{up}class/{subsystem}"),
    );
    link(
        root,
        &format!("class/{subsystem}/{name}"),
        &format!("../../devices/{dev}"),
    );
}

fn devices(root: &Arc<dyn Inode>) {
    if crate::drm::present() {
        put(
            root,
            "devices/platform/simple-framebuffer.0/uevent",
            "DRIVER=simple-framebuffer\n",
        );
        device(
            root,
            "platform/simple-framebuffer.0/drm/card0",
            "drm",
            Some((226, 0, "dri/card0")),
            "DEVTYPE=drm_minor\n",
        );
    }
    for (i, name, keyboard) in crate::input::devices() {
        let serio = format!("platform/i8042/serio{i}");
        let input = format!("{serio}/input/input{i}");
        let ev = if keyboard { "120013" } else { "7" };
        put(root, &format!("devices/{input}/name"), &format!("{name}\n"));
        put(
            root,
            &format!("devices/{input}/phys"),
            &format!("isa0060/serio{i}/input0\n"),
        );
        put(
            root,
            &format!("devices/{input}/capabilities/ev"),
            &format!("{ev}\n"),
        );
        put(root, &format!("devices/{input}/id/bustype"), "0011\n");
        device(
            root,
            &input,
            "input",
            None,
            &format!(
                "PRODUCT=11/1/{}/ab41\nNAME=\"{name}\"\nPHYS=\"isa0060/serio{i}/input0\"\nPROP={}\nEV={ev}\n",
                if keyboard { 1 } else { 2 },
                if keyboard { 0 } else { 1 }
            ),
        );
        device(
            root,
            &format!("{input}/event{i}"),
            "input",
            Some((13, 64 + i, &format!("input/event{i}"))),
            "",
        );
    }
}
