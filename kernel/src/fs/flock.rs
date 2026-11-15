//! `flock`: whole-file advisory locks. A lock belongs to an open file
//! (shared by the descriptors `dup` and `fork` make), and goes with
//! `LOCK_UN` or when the last of those descriptors is closed. Wayland
//! compositors lock `$XDG_RUNTIME_DIR/wayland-N.lock` this way.

use super::File;
use crate::abi::{Errno, KResult};
use crate::sync::SpinLock;
use alloc::vec::Vec;
use core::sync::atomic::Ordering;

const LOCK_SH: u32 = 1;
const LOCK_EX: u32 = 2;
const LOCK_NB: u32 = 4;
const LOCK_UN: u32 = 8;

struct Lock {
    dev: u64,
    ino: u64,
    /// The open file holding it (its address; released before it is freed).
    owner: usize,
    exclusive: bool,
}

static LOCKS: SpinLock<Vec<Lock>> = SpinLock::new(Vec::new());

pub fn flock(file: &File, op: u32) -> KResult<()> {
    let owner = file as *const File as usize;
    let (dev, ino) = (file.inode.dev(), file.inode.ino());
    let exclusive = match op & !LOCK_NB {
        LOCK_SH => false,
        LOCK_EX => true,
        LOCK_UN => {
            release(owner);
            return Ok(());
        }
        _ => return Err(Errno::EINVAL),
    };
    loop {
        {
            let mut locks = LOCKS.lock();
            let conflict = locks.iter().any(|l| {
                l.dev == dev && l.ino == ino && l.owner != owner && (exclusive || l.exclusive)
            });
            if !conflict {
                match locks.iter_mut().find(|l| l.owner == owner) {
                    Some(l) => l.exclusive = exclusive,
                    None => locks.push(Lock {
                        dev,
                        ino,
                        owner,
                        exclusive,
                    }),
                }
                file.locked.store(true, Ordering::Relaxed);
                return Ok(());
            }
        }
        if op & LOCK_NB != 0 {
            return Err(Errno::EAGAIN);
        }
        // Wait for the holder to let go (rare: poll every 10 ms).
        let deadline = crate::time::monotonic_ns() + 10_000_000;
        crate::time::sleep_until(deadline, true).map_err(|_| Errno::EINTR)?;
    }
}

/// Drops the lock `owner` (an open file's address) holds, if any.
pub fn release(owner: usize) {
    LOCKS.lock().retain(|l| l.owner != owner);
}
