//! Pipes: `pipe2` and named FIFOs.
//!
//! A pipe is a 64 KiB buffer with a read end and a write end. Reading an
//! empty pipe sleeps until data arrives or every writer has closed (then
//! it reads end-of-file); writing a full one sleeps until a reader makes
//! room. Writes of up to PIPE_BUF bytes are never interleaved with other
//! writers'. Writing with no reader left gets SIGPIPE and EPIPE.

use super::{FileType, Inode, new_ino, poll, poll_notify};
use crate::abi::{Errno, KResult};
use crate::sync::SpinLock;
use crate::task::wait::WaitQueue;
use alloc::collections::VecDeque;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

/// Capacity (Linux's default: 16 pages).
const CAPACITY: usize = 64 * 1024;
/// Writes up to this size are atomic (POSIX PIPE_BUF).
pub const PIPE_BUF: usize = 4096;

pub struct Pipe {
    ino: u64,
    buf: SpinLock<VecDeque<u8>>,
    readers: AtomicUsize,
    writers: AtomicUsize,
    read_wait: WaitQueue,
    write_wait: WaitQueue,
    /// Bumped on every change (edge-triggered epoll).
    generation: AtomicU64,
}

impl Pipe {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            ino: new_ino(),
            buf: SpinLock::new(VecDeque::new()),
            readers: AtomicUsize::new(0),
            writers: AtomicUsize::new(0),
            read_wait: WaitQueue::new(),
            write_wait: WaitQueue::new(),
            generation: AtomicU64::new(0),
        })
    }

    fn end(self: &Arc<Self>, write: bool) -> Arc<dyn Inode> {
        if write {
            self.writers.fetch_add(1, Ordering::AcqRel);
        } else {
            self.readers.fetch_add(1, Ordering::AcqRel);
        }
        Arc::new(PipeEnd {
            pipe: self.clone(),
            write,
        })
    }

    fn changed(&self) {
        self.generation.fetch_add(1, Ordering::Release);
        self.read_wait.wake_all();
        self.write_wait.wake_all();
        poll_notify();
    }
}

/// A new pipe: (read end, write end).
pub fn pipe() -> (Arc<dyn Inode>, Arc<dyn Inode>) {
    let p = Pipe::new();
    (p.end(false), p.end(true))
}

/// One end of a pipe. Dropping the last open file of an end closes it.
pub struct PipeEnd {
    pipe: Arc<Pipe>,
    write: bool,
}

impl Drop for PipeEnd {
    fn drop(&mut self) {
        let count = if self.write {
            &self.pipe.writers
        } else {
            &self.pipe.readers
        };
        count.fetch_sub(1, Ordering::AcqRel);
        self.pipe.changed();
    }
}

fn sigpipe() {
    let task = crate::task::current();
    if let Some(u) = task.user() {
        crate::proc::signal::send(
            &u.process,
            crate::proc::signo::SIGPIPE,
            crate::proc::signal::SigInfo::kernel(),
        );
    }
}

impl Inode for PipeEnd {
    fn file_type(&self) -> FileType {
        FileType::Fifo
    }
    fn ino(&self) -> u64 {
        self.pipe.ino
    }
    fn dev(&self) -> u64 {
        super::DEV_PIPEFS
    }
    fn perm(&self) -> u32 {
        0o600
    }
    fn seekable(&self) -> bool {
        false
    }
    fn size(&self) -> u64 {
        if self.write {
            0
        } else {
            self.pipe.buf.lock().len() as u64
        }
    }

    fn read_at(&self, _off: u64, _buf: &mut [u8]) -> KResult<usize> {
        Err(Errno::ESPIPE)
    }
    fn write_at(&self, _off: u64, _data: &[u8]) -> KResult<usize> {
        Err(Errno::ESPIPE)
    }

    fn read_stream(&self, out: &mut [u8], nonblock: bool) -> KResult<usize> {
        if self.write {
            return Err(Errno::EBADF);
        }
        if out.is_empty() {
            return Ok(0);
        }
        let p = &self.pipe;
        loop {
            {
                let mut buf = p.buf.lock();
                if !buf.is_empty() {
                    let n = out.len().min(buf.len());
                    for (o, b) in out.iter_mut().zip(buf.drain(..n)) {
                        *o = b;
                    }
                    drop(buf);
                    p.changed();
                    return Ok(n);
                }
            }
            if p.writers.load(Ordering::Acquire) == 0 {
                return Ok(0);
            }
            if nonblock {
                return Err(Errno::EAGAIN);
            }
            p.read_wait.wait_interruptible(|| {
                !p.buf.lock().is_empty() || p.writers.load(Ordering::Acquire) == 0
            })?;
        }
    }

    fn write_stream(&self, data: &[u8], nonblock: bool) -> KResult<usize> {
        if !self.write {
            return Err(Errno::EBADF);
        }
        let p = &self.pipe;
        let mut done = 0;
        loop {
            if p.readers.load(Ordering::Acquire) == 0 {
                if done > 0 {
                    return Ok(done);
                }
                sigpipe();
                return Err(Errno::EPIPE);
            }
            let left = data.len() - done;
            // A small write goes in whole or not at all.
            let need = if left <= PIPE_BUF { left } else { 1 };
            {
                let mut buf = p.buf.lock();
                let space = CAPACITY - buf.len();
                if space >= need {
                    let n = left.min(space);
                    buf.extend(&data[done..done + n]);
                    done += n;
                }
            }
            p.changed();
            if done == data.len() {
                return Ok(done);
            }
            if nonblock {
                return if done > 0 {
                    Ok(done)
                } else {
                    Err(Errno::EAGAIN)
                };
            }
            let waited = p.write_wait.wait_interruptible(|| {
                CAPACITY - p.buf.lock().len() >= need || p.readers.load(Ordering::Acquire) == 0
            });
            if let Err(e) = waited {
                return if done > 0 { Ok(done) } else { Err(e) };
            }
        }
    }

    fn poll_generation(&self) -> u64 {
        self.pipe.generation.load(Ordering::Acquire)
    }

    fn poll(&self) -> u16 {
        let p = &self.pipe;
        if self.write {
            if p.readers.load(Ordering::Acquire) == 0 {
                return poll::POLLOUT | poll::POLLERR;
            }
            if CAPACITY - p.buf.lock().len() >= PIPE_BUF {
                poll::POLLOUT
            } else {
                0
            }
        } else {
            let mut r = 0;
            if !p.buf.lock().is_empty() {
                r |= poll::POLLIN;
            }
            if p.writers.load(Ordering::Acquire) == 0 {
                r |= poll::POLLHUP;
            }
            r
        }
    }

    fn ioctl(&self, req: u32, arg: u64, mm: &crate::mm::vm::AddressSpace) -> KResult<u64> {
        const FIONREAD: u32 = 0x541b;
        match req {
            FIONREAD => {
                mm.write(arg, &(self.pipe.buf.lock().len() as i32))?;
                Ok(0)
            }
            _ => Err(Errno::ENOTTY),
        }
    }
}

/// A named pipe in tmpfs (`mkfifo`): every open gets an end of one shared
/// pipe.
pub struct Fifo {
    ino: u64,
    perm: core::sync::atomic::AtomicU32,
    pipe: Arc<Pipe>,
}

impl Fifo {
    pub fn create(perm: u32) -> Arc<dyn Inode> {
        Arc::new(Self {
            ino: new_ino(),
            perm: core::sync::atomic::AtomicU32::new(perm & 0o7777),
            pipe: Pipe::new(),
        })
    }

    /// The end an `open` with `flags` gets.
    pub fn open_end(&self, flags: u32) -> Arc<dyn Inode> {
        let write = flags & crate::abi::open::O_ACCMODE != crate::abi::open::O_RDONLY;
        self.pipe.end(write)
    }
}

impl Inode for Fifo {
    fn file_type(&self) -> FileType {
        FileType::Fifo
    }
    fn ino(&self) -> u64 {
        self.ino
    }
    fn perm(&self) -> u32 {
        self.perm.load(Ordering::Relaxed)
    }
    fn set_perm(&self, perm: u32) -> KResult<()> {
        self.perm.store(perm & 0o7777, Ordering::Relaxed);
        Ok(())
    }
    fn seekable(&self) -> bool {
        false
    }
    fn open_fifo(&self, flags: u32) -> Option<Arc<dyn Inode>> {
        Some(self.open_end(flags))
    }
}
