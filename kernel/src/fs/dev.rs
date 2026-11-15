//! Device files in `/dev`, with Linux's device numbers.

use super::{FileType, Inode, new_ino};
use crate::abi::{Errno, KResult};
use crate::mm::vm::AddressSpace;
use alloc::sync::Arc;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Null,
    Zero,
    Full,
    Random,
    Console,
    /// `/dev/tty`: the caller's controlling terminal.
    Tty,
}

pub struct Device {
    ino: u64,
    kind: Kind,
    /// (major, minor) as Linux numbers them (Documentation/admin-guide/devices.txt).
    major: u32,
    minor: u32,
}

/// Linux's `makedev` encoding of a device number.
pub fn makedev(major: u32, minor: u32) -> u64 {
    let (ma, mi) = (major as u64, minor as u64);
    (mi & 0xff) | ((ma & 0xfff) << 8) | ((mi & !0xff) << 12) | ((ma & !0xfff) << 32)
}

/// Fills `dir` (the root's `/dev`).
pub fn populate(dir: &Arc<dyn Inode>) {
    let devices = [
        ("null", Kind::Null, 1, 3),
        ("zero", Kind::Zero, 1, 5),
        ("full", Kind::Full, 1, 7),
        ("random", Kind::Random, 1, 8),
        ("urandom", Kind::Random, 1, 9),
        ("tty", Kind::Tty, 5, 0),
        ("console", Kind::Console, 5, 1),
        ("tty0", Kind::Console, 4, 0),
        ("tty1", Kind::Console, 4, 1),
        ("ttyS0", Kind::Console, 4, 64),
    ];
    if crate::drm::present()
        && let Ok(dri) = dir.create("dri", FileType::Directory, 0o755)
    {
        let _ = dri.insert("card0", crate::drm::node());
    }
    if let Ok(input) = dir.create("input", FileType::Directory, 0o755) {
        for (name, node) in crate::input::nodes() {
            let _ = input.insert(&name, node);
        }
    }
    for (name, kind, major, minor) in devices {
        dir.insert(
            name,
            Arc::new(Device {
                ino: new_ino(),
                kind,
                major,
                minor,
            }),
        )
        .unwrap();
    }
}

impl Device {
    fn is_terminal(&self) -> bool {
        matches!(self.kind, Kind::Console | Kind::Tty)
    }
}

impl Inode for Device {
    fn file_type(&self) -> FileType {
        FileType::CharDevice
    }
    fn ino(&self) -> u64 {
        self.ino
    }
    fn perm(&self) -> u32 {
        if self.is_terminal() { 0o620 } else { 0o666 }
    }
    fn rdev(&self) -> u64 {
        makedev(self.major, self.minor)
    }

    fn opened(&self, flags: u32) -> KResult<()> {
        match self.kind {
            Kind::Tty => {
                let t = crate::task::current();
                let has = t.user().is_some_and(|u| {
                    u.process
                        .has_ctty
                        .load(core::sync::atomic::Ordering::Relaxed)
                });
                if has { Ok(()) } else { Err(Errno::ENXIO) }
            }
            Kind::Console => {
                crate::tty::console().opened(flags);
                Ok(())
            }
            _ => Ok(()),
        }
    }

    fn read_at(&self, _off: u64, buf: &mut [u8]) -> KResult<usize> {
        self.read_stream(buf, false)
    }

    fn write_at(&self, _off: u64, data: &[u8]) -> KResult<usize> {
        self.write_stream(data, false)
    }

    fn read_stream(&self, buf: &mut [u8], nonblock: bool) -> KResult<usize> {
        match self.kind {
            Kind::Null => Ok(0),
            Kind::Zero | Kind::Full => {
                buf.fill(0);
                Ok(buf.len())
            }
            Kind::Random => {
                crate::random::fill(buf);
                Ok(buf.len())
            }
            Kind::Console | Kind::Tty => crate::tty::console().read(buf, nonblock),
        }
    }

    fn write_stream(&self, data: &[u8], _nonblock: bool) -> KResult<usize> {
        match self.kind {
            Kind::Full => Err(Errno::ENOSPC),
            Kind::Console | Kind::Tty => crate::tty::console().write(data),
            _ => Ok(data.len()),
        }
    }

    fn truncate(&self, _len: u64) -> KResult<()> {
        Ok(())
    }

    fn poll(&self) -> u16 {
        if self.is_terminal() {
            crate::tty::console().poll()
        } else {
            crate::fs::poll::POLLIN | crate::fs::poll::POLLOUT
        }
    }

    fn ioctl(&self, req: u32, arg: u64, mm: &AddressSpace) -> KResult<u64> {
        if !self.is_terminal() {
            return Err(Errno::ENOTTY);
        }
        crate::tty::console().ioctl(req, arg, mm)
    }
}
