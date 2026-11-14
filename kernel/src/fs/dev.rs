//! Device files in `/dev`, with Linux's device numbers.

use super::{FileType, Inode, new_ino};
use crate::abi::{Errno, KResult, Winsize, ioctl};
use crate::mm::vm::AddressSpace;
use alloc::sync::Arc;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Null,
    Zero,
    Full,
    Random,
    Console,
}

pub struct Device {
    ino: u64,
    kind: Kind,
    /// (major, minor) as Linux numbers them (Documentation/admin-guide/devices.txt).
    major: u32,
    minor: u32,
}

/// Linux's `makedev` encoding of a device number.
fn makedev(major: u32, minor: u32) -> u64 {
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
        ("tty", Kind::Console, 5, 0),
        ("console", Kind::Console, 5, 1),
    ];
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

/// The terminal settings Linux's console starts with (`stty -a`: icrnl
/// ixon opost onlcr, 38400 baud cs8 cread hupcl, isig icanon echo echoe
/// echok iexten echoctl echoke), so programs that ask see a sane terminal.
/// Applying changes comes with the line discipline in Phase 3.
fn default_termios() -> [u8; 60] {
    let mut t = [0u8; 60];
    let words: [u32; 4] = [0x0500, 0x0005, 0x00bf, 0x8a3b];
    for (i, w) in words.iter().enumerate() {
        t[i * 4..i * 4 + 4].copy_from_slice(&w.to_le_bytes());
    }
    // c_line = 0 at 16; c_cc[19] from 17: INTR QUIT ERASE KILL EOF TIME MIN
    // SWTC START STOP SUSP EOL REPRINT DISCARD WERASE LNEXT EOL2.
    let cc: [u8; 17] = [3, 28, 127, 21, 4, 0, 1, 0, 17, 19, 26, 0, 18, 15, 23, 22, 0];
    t[17..17 + cc.len()].copy_from_slice(&cc);
    t
}

impl Inode for Device {
    fn file_type(&self) -> FileType {
        FileType::CharDevice
    }
    fn ino(&self) -> u64 {
        self.ino
    }
    fn perm(&self) -> u32 {
        if self.kind == Kind::Console {
            0o620
        } else {
            0o666
        }
    }
    fn rdev(&self) -> u64 {
        makedev(self.major, self.minor)
    }

    fn read_at(&self, _off: u64, buf: &mut [u8]) -> KResult<usize> {
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
            // No keyboard driver yet: the console reads as end of file.
            Kind::Console => Ok(0),
        }
    }

    fn write_at(&self, _off: u64, data: &[u8]) -> KResult<usize> {
        match self.kind {
            Kind::Full => Err(Errno::ENOSPC),
            Kind::Console => {
                crate::console::write_bytes(data);
                Ok(data.len())
            }
            _ => Ok(data.len()),
        }
    }

    fn truncate(&self, _len: u64) -> KResult<()> {
        Ok(())
    }

    fn ioctl(&self, req: u32, arg: u64, mm: &AddressSpace) -> KResult<u64> {
        if self.kind != Kind::Console {
            return Err(Errno::ENOTTY);
        }
        match req {
            ioctl::TIOCGWINSZ => {
                let (cols, rows) = crate::console::size();
                mm.write(
                    arg,
                    &Winsize {
                        rows: rows as u16,
                        cols: cols as u16,
                        xpixel: 0,
                        ypixel: 0,
                    },
                )?;
                Ok(0)
            }
            ioctl::TCGETS => {
                mm.copy_to(arg, &default_termios())?;
                Ok(0)
            }
            ioctl::TCSETS | ioctl::TCSETSW | ioctl::TCSETSF | ioctl::TIOCSWINSZ => Ok(0),
            ioctl::TIOCGPGRP => {
                mm.write(arg, &1i32)?;
                Ok(0)
            }
            ioctl::TIOCSPGRP => Ok(0),
            _ => Err(Errno::EINVAL),
        }
    }
}
