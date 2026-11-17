//! AF_INET in a network namespace of its own (`unshare(CLONE_NEWNET)`),
//! which has only a loopback interface, down, and no routes: a socket can
//! be bound (each namespace has its own ports) and can listen, but
//! nothing reaches it and every destination is unreachable, as on Linux.

use super::socket::*;
use crate::abi::{Errno, KResult};
use crate::fs::File;
use crate::sync::SpinLock;
use crate::task::wait::WaitQueue;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU16, Ordering};

static NEXT_PORT: AtomicU16 = AtomicU16::new(32768);

pub struct IsolatedInet {
    ty: u32,
    local: SpinLock<Option<(u32, u16)>>,
    listening: AtomicBool,
    wait: WaitQueue,
}

pub fn new(ty: u32, protocol: u32) -> KResult<Arc<dyn Socket>> {
    match (ty, protocol) {
        (SOCK_STREAM, 0 | 6) | (SOCK_DGRAM, 0 | 1 | 17) | (SOCK_RAW, 1) => {}
        (SOCK_STREAM | SOCK_DGRAM | SOCK_RAW, _) => return Err(Errno::EPROTONOSUPPORT),
        _ => return Err(Errno::ESOCKTNOSUPPORT),
    }
    Ok(Arc::new(IsolatedInet {
        ty,
        local: SpinLock::new(None),
        listening: AtomicBool::new(false),
        wait: WaitQueue::new(),
    }))
}

fn sockaddr((ip, port): (u32, u16)) -> Vec<u8> {
    let mut a = alloc::vec![0u8; 16];
    a[0..2].copy_from_slice(&AF_INET.to_le_bytes());
    a[2..4].copy_from_slice(&port.to_be_bytes());
    a[4..8].copy_from_slice(&ip.to_be_bytes());
    a
}

impl IsolatedInet {
    fn autobind(&self) {
        let mut l = self.local.lock();
        if l.is_none() {
            *l = Some((0, NEXT_PORT.fetch_add(1, Ordering::Relaxed).max(32768)));
        }
    }

    /// Nothing ever arrives: wait for a signal (or EAGAIN).
    fn never(&self, nonblock: bool) -> Errno {
        if nonblock {
            return Errno::EAGAIN;
        }
        match self.wait.wait_interruptible(|| false) {
            Err(e) => e,
            Ok(()) => Errno::EINTR,
        }
    }
}

impl Socket for IsolatedInet {
    fn kind(&self) -> (u16, u32) {
        (AF_INET, self.ty)
    }
    fn bind(&self, addr: &[u8]) -> KResult<()> {
        let (ip, port) = super::ip::parse_sockaddr(addr)?;
        let mut l = self.local.lock();
        if l.is_some() {
            return Err(Errno::EINVAL);
        }
        let port = if port == 0 {
            NEXT_PORT.fetch_add(1, Ordering::Relaxed).max(32768)
        } else {
            port
        };
        *l = Some((ip, port));
        Ok(())
    }
    fn listen(&self, _backlog: u32) -> KResult<()> {
        if self.ty != SOCK_STREAM {
            return Err(Errno::EOPNOTSUPP);
        }
        self.autobind();
        self.listening.store(true, Ordering::Relaxed);
        Ok(())
    }
    fn accept(&self, nonblock: bool) -> KResult<(Arc<dyn Socket>, Vec<u8>)> {
        if !self.listening.load(Ordering::Relaxed) {
            return Err(Errno::EINVAL);
        }
        Err(self.never(nonblock))
    }
    fn connect(&self, addr: &[u8], _nonblock: bool) -> KResult<()> {
        super::ip::parse_sockaddr(addr)?;
        Err(Errno::ENETUNREACH)
    }
    fn send(
        &self,
        _data: &[u8],
        to: Option<&[u8]>,
        _flags: u32,
        _nonblock: bool,
        _rights: Vec<Arc<File>>,
    ) -> KResult<usize> {
        match to {
            Some(_) if self.ty != SOCK_STREAM => {
                self.autobind();
                Err(Errno::ENETUNREACH)
            }
            _ if self.ty == SOCK_STREAM => Err(Errno::EPIPE),
            _ => Err(Errno::EDESTADDRREQ),
        }
    }
    fn recv(&self, _buf: &mut [u8], _flags: u32, nonblock: bool) -> KResult<Received> {
        if self.ty == SOCK_STREAM && !self.listening.load(Ordering::Relaxed) {
            return Err(Errno::ENOTCONN);
        }
        Err(self.never(nonblock))
    }
    fn shutdown(&self, _how: u32) -> KResult<()> {
        Err(Errno::ENOTCONN)
    }
    fn local_addr(&self) -> KResult<Vec<u8>> {
        Ok(sockaddr(self.local.lock().unwrap_or((0, 0))))
    }
    fn set_option(&self, _level: u32, _name: u32, _value: &[u8]) -> KResult<()> {
        Ok(())
    }
    fn get_option(&self, _level: u32, _name: u32) -> KResult<Vec<u8>> {
        Ok(alloc::vec![0u8; 4])
    }
    fn poll(&self) -> u16 {
        0
    }
    fn as_any(&self) -> &dyn core::any::Any {
        self
    }
}
