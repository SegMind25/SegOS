//! AF_UNIX sockets: stream, datagram and seqpacket, named in the file
//! system or in the abstract namespace (a leading NUL), or unnamed pairs
//! from `socketpair`. Data may carry open descriptors (SCM_RIGHTS) and
//! the sender's credentials; `SO_PEERCRED` tells who is on the other end.
//!
//! A connection is two one-way [`Queue`]s of messages. Stream sockets read
//! across message boundaries, except that a message carrying descriptors
//! is delivered on its own (as Linux does).

use super::socket::*;
use crate::abi::{Errno, KResult};
use crate::fs::{self, File, FileType, Inode};
use crate::sync::SpinLock;
use crate::task::wait::WaitQueue;
use alloc::collections::{BTreeMap, VecDeque};
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

/// Bytes a queue holds before writers wait (Linux's default socket buffer).
const CAPACITY: usize = 212_992;

struct Msg {
    data: Vec<u8>,
    /// Bytes already read (streams read messages in pieces).
    read: usize,
    from: Option<Vec<u8>>,
    rights: Vec<Arc<File>>,
    creds: (u32, u32, u32),
}

/// One direction of a connection, or a datagram socket's inbox.
struct Queue {
    msgs: SpinLock<VecDeque<Msg>>,
    bytes: AtomicU64,
    /// No more data will come (the writer shut down or closed).
    eof: core::sync::atomic::AtomicBool,
    /// Nobody will read (the reader shut down or closed).
    gone: core::sync::atomic::AtomicBool,
    wait: WaitQueue,
}

impl Queue {
    fn new() -> Arc<Queue> {
        Arc::new(Queue {
            msgs: SpinLock::new(VecDeque::new()),
            bytes: AtomicU64::new(0),
            eof: Default::default(),
            gone: Default::default(),
            wait: WaitQueue::new(),
        })
    }

    fn changed(&self) {
        GENERATION.fetch_add(1, Ordering::Relaxed);
        self.wait.wake_all();
        fs::poll_notify();
    }

    fn room(&self) -> bool {
        (self.bytes.load(Ordering::Acquire) as usize) < CAPACITY
    }

    fn readable(&self) -> bool {
        !self.msgs.lock().is_empty()
    }
}

static GENERATION: AtomicU64 = AtomicU64::new(0);

enum State {
    Unbound,
    Listening {
        backlog: usize,
        pending: VecDeque<Arc<UnixSocket>>,
    },
    Connected {
        rx: Arc<Queue>,
        tx: Arc<Queue>,
        peer: Weak<UnixSocket>,
    },
    /// A datagram socket: its own inbox, and a default destination.
    Datagram {
        inbox: Arc<Queue>,
        peer: Option<Weak<UnixSocket>>,
    },
    Closed,
}

pub struct UnixSocket {
    ty: u32,
    me: Weak<UnixSocket>,
    /// Its name: a path or "\0abstract" (raw sockaddr_un bytes), if bound.
    name: SpinLock<Option<Vec<u8>>>,
    state: SpinLock<State>,
    /// Wakes `accept` and `connect`.
    wait: WaitQueue,
    /// Who created it: (pid, uid, gid) for SO_PEERCRED.
    creds: (u32, u32, u32),
    peer_creds: SpinLock<Option<(u32, u32, u32)>>,
    shut_rd: core::sync::atomic::AtomicBool,
    shut_wr: core::sync::atomic::AtomicBool,
    passcred: core::sync::atomic::AtomicBool,
}

/// Abstract-namespace names.
static ABSTRACT: SpinLock<BTreeMap<Vec<u8>, Weak<UnixSocket>>> = SpinLock::new(BTreeMap::new());

fn my_creds() -> (u32, u32, u32) {
    let pid = crate::task::current().user().map_or(0, |u| u.process.pid);
    (pid, 0, 0)
}

pub fn new_socket(ty: u32) -> KResult<Arc<dyn Socket>> {
    if !matches!(ty, SOCK_STREAM | SOCK_DGRAM | SOCK_SEQPACKET) {
        return Err(Errno::ESOCKTNOSUPPORT);
    }
    Ok(make(ty))
}

fn make(ty: u32) -> Arc<UnixSocket> {
    Arc::new_cyclic(|me| UnixSocket {
        ty,
        me: me.clone(),
        name: SpinLock::new(None),
        state: SpinLock::new(if ty == SOCK_DGRAM {
            State::Datagram {
                inbox: Queue::new(),
                peer: None,
            }
        } else {
            State::Unbound
        }),
        wait: WaitQueue::new(),
        creds: my_creds(),
        peer_creds: SpinLock::new(None),
        shut_rd: Default::default(),
        shut_wr: Default::default(),
        passcred: Default::default(),
    })
}

/// `socketpair`: two connected sockets.
pub fn pair(ty: u32) -> KResult<(Arc<dyn Socket>, Arc<dyn Socket>)> {
    if !matches!(ty, SOCK_STREAM | SOCK_DGRAM | SOCK_SEQPACKET) {
        return Err(Errno::ESOCKTNOSUPPORT);
    }
    let (a, b) = (make(ty), make(ty));
    connect_pair(&a, &b);
    let c = my_creds();
    *a.peer_creds.lock() = Some(c);
    *b.peer_creds.lock() = Some(c);
    Ok((a, b))
}

fn connect_pair(a: &Arc<UnixSocket>, b: &Arc<UnixSocket>) {
    if a.ty == SOCK_DGRAM {
        for (x, y) in [(a, b), (b, a)] {
            if let State::Datagram { peer, .. } = &mut *x.state.lock() {
                *peer = Some(Arc::downgrade(y));
            }
        }
        return;
    }
    let (ab, ba) = (Queue::new(), Queue::new());
    *a.state.lock() = State::Connected {
        rx: ba.clone(),
        tx: ab.clone(),
        peer: Arc::downgrade(b),
    };
    *b.state.lock() = State::Connected {
        rx: ab,
        tx: ba,
        peer: Arc::downgrade(a),
    };
}

/// The path or abstract name in a sockaddr_un.
fn parse_name(addr: &[u8]) -> KResult<Vec<u8>> {
    if addr.len() < 2 || u16::from_le_bytes([addr[0], addr[1]]) != AF_UNIX {
        return Err(Errno::EINVAL);
    }
    let path = &addr[2..addr.len().min(110)];
    if path.is_empty() {
        return Err(Errno::EINVAL);
    }
    if path[0] == 0 {
        return Ok(path.to_vec()); // abstract: every byte counts
    }
    let end = path.iter().position(|&b| b == 0).unwrap_or(path.len());
    Ok(path[..end].to_vec())
}

fn sockaddr(name: Option<&[u8]>) -> Vec<u8> {
    let mut v = AF_UNIX.to_le_bytes().to_vec();
    if let Some(n) = name {
        v.extend_from_slice(n);
        if n.first() != Some(&0) {
            v.push(0);
        }
    }
    v
}

/// What a socket's file-system name is: a node that leads to it.
struct NameNode {
    sock: Weak<UnixSocket>,
    ino: u64,
}

impl Inode for NameNode {
    fn file_type(&self) -> FileType {
        FileType::Socket
    }
    fn ino(&self) -> u64 {
        self.ino
    }
    fn perm(&self) -> u32 {
        0o755
    }
    fn as_any(&self) -> Option<&dyn core::any::Any> {
        Some(self)
    }
}

fn cwd() -> Arc<dyn Inode> {
    crate::task::current()
        .user()
        .map(|u| u.process.cwd.lock().clone())
        .unwrap_or_else(fs::root)
}

/// The socket a name refers to.
fn lookup(name: &[u8]) -> KResult<Arc<UnixSocket>> {
    if name.first() == Some(&0) {
        return ABSTRACT
            .lock()
            .get(name)
            .and_then(Weak::upgrade)
            .ok_or(Errno::ECONNREFUSED);
    }
    let path = core::str::from_utf8(name).map_err(|_| Errno::ENOENT)?;
    let inode = fs::lookup(&cwd(), path)?;
    if inode.file_type() != FileType::Socket {
        return Err(Errno::ECONNREFUSED);
    }
    inode
        .as_any()
        .and_then(|a| a.downcast_ref::<NameNode>())
        .and_then(|n| n.sock.upgrade())
        .ok_or(Errno::ECONNREFUSED)
}

impl UnixSocket {
    fn this(&self) -> Arc<UnixSocket> {
        self.me.upgrade().expect("live socket")
    }

    fn queues(&self) -> Option<(Arc<Queue>, Arc<Queue>)> {
        match &*self.state.lock() {
            State::Connected { rx, tx, .. } => Some((rx.clone(), tx.clone())),
            _ => None,
        }
    }

    fn inbox(&self) -> Option<Arc<Queue>> {
        match &*self.state.lock() {
            State::Datagram { inbox, .. } => Some(inbox.clone()),
            State::Connected { rx, .. } => Some(rx.clone()),
            _ => None,
        }
    }

    fn boundaries(&self) -> bool {
        self.ty != SOCK_STREAM
    }
}

impl Socket for UnixSocket {
    fn kind(&self) -> (u16, u32) {
        (AF_UNIX, self.ty)
    }

    fn bind(&self, addr: &[u8]) -> KResult<()> {
        let name = parse_name(addr)?;
        if self.name.lock().is_some() {
            return Err(Errno::EINVAL);
        }
        if name[0] == 0 {
            let mut names = ABSTRACT.lock();
            if names.get(&name).is_some_and(|w| w.strong_count() > 0) {
                return Err(Errno::EADDRINUSE);
            }
            names.insert(name.clone(), self.me.clone());
        } else {
            let path = core::str::from_utf8(&name).map_err(|_| Errno::EINVAL)?;
            let (dir, file) = fs::lookup_parent(&cwd(), path)?;
            if dir.lookup(&file).is_ok() {
                return Err(Errno::EADDRINUSE);
            }
            dir.insert(
                &file,
                Arc::new(NameNode {
                    sock: self.me.clone(),
                    ino: fs::new_ino(),
                }),
            )?;
        }
        *self.name.lock() = Some(name);
        Ok(())
    }

    fn listen(&self, backlog: u32) -> KResult<()> {
        if self.ty == SOCK_DGRAM {
            return Err(Errno::EOPNOTSUPP);
        }
        if self.name.lock().is_none() {
            return Err(Errno::EINVAL);
        }
        let mut st = self.state.lock();
        match &mut *st {
            State::Unbound => {
                *st = State::Listening {
                    backlog: (backlog as usize).clamp(1, 4096),
                    pending: VecDeque::new(),
                };
            }
            State::Listening { backlog: b, .. } => *b = (backlog as usize).clamp(1, 4096),
            _ => return Err(Errno::EINVAL),
        }
        Ok(())
    }

    fn accept(&self, nonblock: bool) -> KResult<(Arc<dyn Socket>, Vec<u8>)> {
        loop {
            {
                let mut st = self.state.lock();
                let State::Listening { pending, .. } = &mut *st else {
                    return Err(Errno::EINVAL);
                };
                if let Some(s) = pending.pop_front() {
                    drop(st);
                    fs::poll_notify();
                    return Ok((s, sockaddr(None)));
                }
            }
            if nonblock {
                return Err(Errno::EAGAIN);
            }
            self.wait.wait_interruptible(|| {
                matches!(&*self.state.lock(), State::Listening { pending, .. } if !pending.is_empty())
            })?;
        }
    }

    fn connect(&self, addr: &[u8], _nonblock: bool) -> KResult<()> {
        let target = lookup(&parse_name(addr)?)?;
        if self.ty == SOCK_DGRAM {
            if let State::Datagram { peer, .. } = &mut *self.state.lock() {
                *peer = Some(Arc::downgrade(&target));
            }
            return Ok(());
        }
        if target.ty != self.ty {
            return Err(Errno::EPROTOTYPE);
        }
        if matches!(&*self.state.lock(), State::Connected { .. }) {
            return Err(Errno::EISCONN);
        }
        // The server's end of the new connection.
        let server = make(self.ty);
        *server.name.lock() = target.name.lock().clone();
        {
            let mut st = target.state.lock();
            let State::Listening { backlog, pending } = &mut *st else {
                return Err(Errno::ECONNREFUSED);
            };
            if pending.len() >= *backlog {
                return Err(Errno::EAGAIN);
            }
            let me = self.this();
            connect_pair(&me, &server);
            *server.peer_creds.lock() = Some(self.creds);
            *me.peer_creds.lock() = Some(target.creds);
            pending.push_back(server);
        }
        target.wait.wake_all();
        fs::poll_notify();
        Ok(())
    }

    fn send(
        &self,
        data: &[u8],
        to: Option<&[u8]>,
        _flags: u32,
        nonblock: bool,
        rights: Vec<Arc<File>>,
    ) -> KResult<usize> {
        if self.shut_wr.load(Ordering::Acquire) {
            return Err(Errno::EPIPE);
        }
        let from = self.name.lock().as_deref().map(|n| sockaddr(Some(n)));
        let q = if self.ty == SOCK_DGRAM {
            let target = match to {
                Some(a) => lookup(&parse_name(a)?)?,
                None => match &*self.state.lock() {
                    State::Datagram { peer: Some(p), .. } => {
                        p.upgrade().ok_or(Errno::ECONNREFUSED)?
                    }
                    _ => return Err(Errno::ENOTCONN),
                },
            };
            target.inbox().ok_or(Errno::ECONNREFUSED)?
        } else {
            if to.is_some() && self.queues().is_some() {
                return Err(Errno::EISCONN);
            }
            self.queues().ok_or(Errno::ENOTCONN)?.1
        };
        if self.boundaries() && data.len() > CAPACITY {
            return Err(Errno::EMSGSIZE);
        }
        q.wait
            .wait_interruptible(|| q.room() || q.gone.load(Ordering::Acquire) || nonblock)?;
        if q.gone.load(Ordering::Acquire) {
            return Err(if self.ty == SOCK_DGRAM {
                Errno::ECONNREFUSED
            } else {
                Errno::EPIPE
            });
        }
        if !q.room() {
            return Err(Errno::EAGAIN);
        }
        // Streams take what fits; message sockets take all or wait.
        let n = if self.boundaries() {
            data.len()
        } else {
            data.len()
                .min(CAPACITY - q.bytes.load(Ordering::Acquire) as usize)
                .max(1)
                .min(data.len())
        };
        q.msgs.lock().push_back(Msg {
            data: data[..n].to_vec(),
            read: 0,
            from,
            rights,
            creds: self.creds,
        });
        q.bytes.fetch_add(n as u64, Ordering::AcqRel);
        q.changed();
        Ok(n)
    }

    fn recv(&self, buf: &mut [u8], flags: u32, nonblock: bool) -> KResult<Received> {
        let q = self.inbox().ok_or(if self.ty == SOCK_STREAM {
            Errno::ENOTCONN
        } else {
            Errno::EINVAL
        })?;
        let peek = flags & MSG_PEEK != 0;
        loop {
            {
                let mut msgs = q.msgs.lock();
                if !msgs.is_empty() {
                    let mut out = Received::default();
                    if self.boundaries() {
                        let m = if peek {
                            msgs.front().unwrap()
                        } else {
                            &msgs[0]
                        };
                        let n = m.data.len().min(buf.len());
                        buf[..n].copy_from_slice(&m.data[..n]);
                        out.len = n;
                        out.full_len = m.data.len();
                        out.from = m.from.clone();
                        out.creds = Some(m.creds);
                        if !peek {
                            let m = msgs.pop_front().unwrap();
                            out.rights = m.rights;
                            q.bytes.fetch_sub(m.data.len() as u64, Ordering::AcqRel);
                        } else {
                            out.rights = m.rights.clone();
                        }
                    } else {
                        // Streams: across messages, stopping before one
                        // that carries descriptors (unless it is first).
                        let mut done = 0;
                        let mut i = 0;
                        while done < buf.len() && i < msgs.len() {
                            if i > 0 && !msgs[i].rights.is_empty() {
                                break;
                            }
                            let m = &mut msgs[i];
                            let n = (m.data.len() - m.read).min(buf.len() - done);
                            buf[done..done + n].copy_from_slice(&m.data[m.read..m.read + n]);
                            done += n;
                            if i == 0 {
                                out.creds = Some(m.creds);
                                out.rights = if peek {
                                    m.rights.clone()
                                } else {
                                    core::mem::take(&mut m.rights)
                                };
                            }
                            if !peek {
                                m.read += n;
                            }
                            i += 1;
                        }
                        if !peek {
                            while msgs.front().is_some_and(|m| m.read == m.data.len()) {
                                msgs.pop_front();
                            }
                            q.bytes.fetch_sub(done as u64, Ordering::AcqRel);
                        }
                        out.len = done;
                        out.full_len = done;
                    }
                    drop(msgs);
                    if !peek {
                        q.changed();
                    }
                    return Ok(out);
                }
            }
            if q.eof.load(Ordering::Acquire) || self.shut_rd.load(Ordering::Acquire) {
                return Ok(Received::default()); // end of file
            }
            if nonblock {
                return Err(Errno::EAGAIN);
            }
            q.wait
                .wait_interruptible(|| q.readable() || q.eof.load(Ordering::Acquire))?;
        }
    }

    fn shutdown(&self, how: u32) -> KResult<()> {
        if how > 2 {
            return Err(Errno::EINVAL);
        }
        let Some((rx, tx)) = self.queues() else {
            return if self.ty == SOCK_DGRAM {
                Ok(())
            } else {
                Err(Errno::ENOTCONN)
            };
        };
        if how != 1 {
            self.shut_rd.store(true, Ordering::Release);
            rx.gone.store(true, Ordering::Release);
            rx.changed();
        }
        if how != 0 {
            self.shut_wr.store(true, Ordering::Release);
            tx.eof.store(true, Ordering::Release);
            tx.changed();
        }
        Ok(())
    }

    fn local_addr(&self) -> KResult<Vec<u8>> {
        Ok(sockaddr(self.name.lock().as_deref()))
    }

    fn peer_addr(&self) -> KResult<Vec<u8>> {
        let peer = match &*self.state.lock() {
            State::Connected { peer, .. } => peer.upgrade(),
            State::Datagram { peer: Some(p), .. } => p.upgrade(),
            _ => return Err(Errno::ENOTCONN),
        };
        Ok(sockaddr(
            peer.and_then(|p| p.name.lock().clone()).as_deref(),
        ))
    }

    fn set_option(&self, level: u32, name: u32, value: &[u8]) -> KResult<()> {
        const SO_PASSCRED: u32 = 16;
        if level == SOL_SOCKET && name == SO_PASSCRED {
            self.passcred.store(int_opt(value)? != 0, Ordering::Relaxed);
        }
        Ok(()) // buffer sizes, timeouts: accepted
    }

    fn get_option(&self, level: u32, name: u32) -> KResult<Vec<u8>> {
        const SO_TYPE: u32 = 3;
        const SO_ERROR: u32 = 4;
        const SO_SNDBUF: u32 = 7;
        const SO_RCVBUF: u32 = 8;
        const SO_PASSCRED: u32 = 16;
        const SO_PEERCRED: u32 = 17;
        const SO_ACCEPTCONN: u32 = 30;
        const SO_DOMAIN: u32 = 39;
        if level != SOL_SOCKET {
            return Err(Errno::ENOPROTOOPT);
        }
        let int = |v: u32| v.to_le_bytes().to_vec();
        Ok(match name {
            SO_TYPE => int(self.ty),
            SO_ERROR => int(0),
            SO_SNDBUF | SO_RCVBUF => int(CAPACITY as u32),
            SO_PASSCRED => int(self.passcred.load(Ordering::Relaxed) as u32),
            SO_ACCEPTCONN => int(matches!(&*self.state.lock(), State::Listening { .. }) as u32),
            SO_DOMAIN => int(AF_UNIX as u32),
            SO_PEERCRED => {
                let (pid, uid, gid) = self.peer_creds.lock().unwrap_or((0, u32::MAX, u32::MAX));
                [pid, uid, gid]
                    .iter()
                    .flat_map(|v| v.to_le_bytes())
                    .collect()
            }
            _ => return Err(Errno::ENOPROTOOPT),
        })
    }

    fn poll(&self) -> u16 {
        use crate::fs::poll::*;
        const POLLRDHUP: u16 = 0x2000;
        match &*self.state.lock() {
            State::Listening { pending, .. } => {
                if pending.is_empty() {
                    0
                } else {
                    POLLIN
                }
            }
            State::Connected { rx, tx, .. } => {
                let mut r = 0;
                if rx.readable() || rx.eof.load(Ordering::Acquire) {
                    r |= POLLIN;
                }
                if rx.eof.load(Ordering::Acquire) {
                    r |= POLLRDHUP;
                }
                if tx.room() && !tx.gone.load(Ordering::Acquire) {
                    r |= POLLOUT;
                }
                if rx.eof.load(Ordering::Acquire) && tx.gone.load(Ordering::Acquire) {
                    r |= POLLHUP;
                }
                r
            }
            State::Datagram { inbox, .. } => (if inbox.readable() { POLLIN } else { 0 }) | POLLOUT,
            State::Unbound => POLLOUT,
            State::Closed => POLLHUP,
        }
    }

    fn poll_generation(&self) -> u64 {
        GENERATION.load(Ordering::Relaxed)
    }

    fn bytes_ready(&self) -> usize {
        self.inbox()
            .map_or(0, |q| q.bytes.load(Ordering::Acquire) as usize)
    }

    fn close(&self) {
        let old = core::mem::replace(&mut *self.state.lock(), State::Closed);
        match old {
            State::Connected { rx, tx, .. } => {
                rx.gone.store(true, Ordering::Release);
                tx.eof.store(true, Ordering::Release);
                rx.msgs.lock().clear();
                rx.changed();
                tx.changed();
            }
            State::Listening { pending, .. } => {
                for s in pending {
                    s.close();
                }
            }
            State::Datagram { inbox, .. } => {
                inbox.gone.store(true, Ordering::Release);
                inbox.msgs.lock().clear();
                inbox.changed();
            }
            _ => {}
        }
        if let Some(name) = self.name.lock().as_ref()
            && name.first() == Some(&0)
        {
            ABSTRACT.lock().remove(name);
        }
        self.wait.wake_all();
    }

    fn as_any(&self) -> &dyn core::any::Any {
        self
    }
}
