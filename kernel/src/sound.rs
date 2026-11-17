//! Sound: Linux's ALSA interface on the HD Audio controller
//! (`drivers/hda.rs`), as libasound (and so `aplay`, Firefox, ...) uses
//! it: `/dev/snd/controlC0` (card and PCM information) and
//! `/dev/snd/pcmC0D0p`, one playback PCM: interleaved S16_LE, stereo,
//! 48 kHz, written with SNDRV_PCM_IOCTL_WRITEI_FRAMES. Pointers are kept
//! as the kernel keeps them (modulo the boundary); status and control
//! are exchanged with SYNC_PTR (mapping them is refused, which libasound
//! expects). A kernel thread follows the hardware position while the
//! stream runs, silences what has been played and wakes poll().

use crate::abi::{Errno, KResult};
use crate::drivers::hda;
use crate::fs::{FileType, Inode, new_ino, poll};
use crate::mm::vm::AddressSpace;
use crate::sync::SpinLock;
use crate::task::wait::WaitQueue;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

const RATE: u32 = 48000;
const CHANNELS: u32 = 2;
const FRAME: u64 = 4;
const PCM_VERSION: u32 = 0x0002_000f;
const CTL_VERSION: u32 = 0x0002_0008;

// States.
const OPEN: i32 = 0;
const SETUP: i32 = 1;
const PREPARED: i32 = 2;
const RUNNING: i32 = 3;
const XRUN: i32 = 4;
const DRAINING: i32 = 5;

// hw_params: masks 0..=2, intervals 8..=19.
const ACCESS: usize = 0;
const FORMAT: usize = 1;
const SUBFORMAT: usize = 2;
const SAMPLE_BITS: usize = 8;
const FRAME_BITS: usize = 9;
const CHANNELS_P: usize = 10;
const RATE_P: usize = 11;
const PERIOD_TIME: usize = 12;
const PERIOD_SIZE: usize = 13;
const PERIOD_BYTES: usize = 14;
const PERIODS: usize = 15;
const BUFFER_TIME: usize = 16;
const BUFFER_SIZE: usize = 17;
const BUFFER_BYTES: usize = 18;
const ACCESS_RW_INTERLEAVED: u32 = 3;
const FORMAT_S16_LE: u32 = 2;
/// SNDRV_PCM_INFO_INTERLEAVED | BLOCK_TRANSFER | BATCH-free.
const INFO: u32 = 0x100 | 0x10000;

struct Stream {
    state: i32,
    buffer_size: u64,
    period_size: u64,
    boundary: u64,
    hw_ptr: u64,
    appl_ptr: u64,
    avail_min: u64,
    start_threshold: u64,
    stop_threshold: u64,
    /// The hardware position (bytes) at the last update.
    last_pos: usize,
    trigger_ns: u64,
}

static STREAM: SpinLock<Stream> = SpinLock::new(Stream {
    state: OPEN,
    buffer_size: 0,
    period_size: 0,
    boundary: 0,
    hw_ptr: 0,
    appl_ptr: 0,
    avail_min: 1,
    start_threshold: 1,
    stop_threshold: 0,
    last_pos: 0,
    trigger_ns: 0,
});
static BUSY: AtomicBool = AtomicBool::new(false);
static GENERATION: AtomicU64 = AtomicU64::new(0);
static WAIT: WaitQueue = WaitQueue::new();

impl Stream {
    fn avail(&self) -> u64 {
        let a = self.hw_ptr as i64 + self.buffer_size as i64 - self.appl_ptr as i64;
        let b = self.boundary as i64;
        (if a < 0 {
            a + b
        } else if a >= b {
            a - b
        } else {
            a
        }) as u64
    }

    fn queued(&self) -> u64 {
        self.buffer_size.saturating_sub(self.avail())
    }

    /// Follows the hardware: advances hw_ptr, silences what was played,
    /// and ends the stream on an underrun or when draining is done.
    fn update(&mut self) {
        if !matches!(self.state, RUNNING | DRAINING) {
            return;
        }
        let Some(pos) = hda::with(|h| h.position()) else {
            return;
        };
        let bytes = self.buffer_size * FRAME;
        let delta = (pos + bytes as usize - self.last_pos) % bytes as usize;
        let frames = (delta as u64 / FRAME).min(self.queued());
        if frames > 0 {
            let at = (self.hw_ptr % self.buffer_size) * FRAME;
            hda::with(|h| h.silence(at as usize, (frames * FRAME) as usize));
            self.hw_ptr = (self.hw_ptr + frames) % self.boundary;
            self.last_pos = (self.last_pos + (frames * FRAME) as usize) % bytes as usize;
            GENERATION.fetch_add(1, Ordering::Relaxed);
        }
        let avail = self.avail();
        if self.state == DRAINING && avail >= self.buffer_size {
            self.stop(SETUP);
        } else if self.state == RUNNING && avail >= self.stop_threshold {
            self.stop(XRUN);
        }
    }

    fn start(&mut self) {
        self.state = RUNNING;
        self.trigger_ns = crate::time::monotonic_ns();
        hda::with(|h| h.start());
        GENERATION.fetch_add(1, Ordering::Relaxed);
        crate::task::spawn(follow);
    }

    fn stop(&mut self, state: i32) {
        hda::with(|h| h.stop());
        self.state = state;
        GENERATION.fetch_add(1, Ordering::Relaxed);
        WAIT.wake_all();
        crate::fs::poll_notify();
    }

    fn prepare(&mut self) -> KResult<()> {
        if self.state == OPEN {
            return Err(Errno::EBADFD);
        }
        let bytes = (self.buffer_size * FRAME) as usize;
        if !hda::with(|h| h.setup(bytes)).unwrap_or(false) {
            return Err(Errno::EIO);
        }
        self.hw_ptr = 0;
        self.appl_ptr = 0;
        self.last_pos = 0;
        self.state = PREPARED;
        Ok(())
    }
}

/// While the stream runs: follow the hardware every few milliseconds.
fn follow() {
    loop {
        crate::time::sleep_ms(4);
        let mut s = STREAM.lock();
        s.update();
        let running = matches!(s.state, RUNNING | DRAINING);
        drop(s);
        WAIT.wake_all();
        crate::fs::poll_notify();
        if !running {
            return;
        }
    }
}

/// Puts `/dev/snd/` into `dev` when there is a sound card.
pub fn populate(dev: &Arc<dyn Inode>) {
    if !hda::present() {
        return;
    }
    if let Ok(snd) = dev.create("snd", FileType::Directory, 0o755) {
        let _ = snd.insert(
            "controlC0",
            Arc::new(Node {
                ino: new_ino(),
                minor: 0,
            }),
        );
        let _ = snd.insert(
            "pcmC0D0p",
            Arc::new(Node {
                ino: new_ino(),
                minor: 16,
            }),
        );
    }
}

/// `/dev/snd/controlC0` (minor 0) or `/dev/snd/pcmC0D0p` (minor 16).
struct Node {
    ino: u64,
    minor: u32,
}

impl Inode for Node {
    fn file_type(&self) -> FileType {
        FileType::CharDevice
    }
    fn ino(&self) -> u64 {
        self.ino
    }
    fn perm(&self) -> u32 {
        0o666
    }
    fn rdev(&self) -> u64 {
        crate::fs::dev::makedev(116, self.minor)
    }
    fn seekable(&self) -> bool {
        false
    }
    fn open_fifo(&self, _flags: u32) -> Option<Arc<dyn Inode>> {
        if self.minor == 0 {
            return Some(Arc::new(Control { ino: self.ino }));
        }
        Some(Arc::new(Pcm {
            ino: self.ino,
            owner: AtomicBool::new(false),
        }))
    }
}

fn put_str(buf: &mut [u8], off: usize, len: usize, s: &str) {
    let n = s.len().min(len - 1);
    buf[off..off + n].copy_from_slice(&s.as_bytes()[..n]);
}

fn put32(buf: &mut [u8], off: usize, v: u32) {
    buf[off..off + 4].copy_from_slice(&v.to_le_bytes());
}

fn put64(buf: &mut [u8], off: usize, v: u64) {
    buf[off..off + 8].copy_from_slice(&v.to_le_bytes());
}

fn get32(buf: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(buf[off..off + 4].try_into().unwrap())
}

fn get64(buf: &[u8], off: usize) -> u64 {
    u64::from_le_bytes(buf[off..off + 8].try_into().unwrap())
}

/// struct snd_pcm_info for the playback PCM.
fn pcm_info(size: usize) -> Vec<u8> {
    let mut b = vec![0u8; size.max(288)];
    put32(&mut b, 8, 0); // SNDRV_PCM_STREAM_PLAYBACK
    put_str(&mut b, 16, 64, "HDA Generic");
    put_str(&mut b, 80, 80, "HDA Generic Analog");
    put_str(&mut b, 160, 32, "subdevice #0");
    put32(&mut b, 200, 1);
    put32(
        &mut b,
        204,
        if BUSY.load(Ordering::Relaxed) { 0 } else { 1 },
    );
    b.truncate(size);
    b
}

fn ioctl_size(req: u32) -> usize {
    ((req >> 16) & 0x3fff) as usize
}

fn read_arg(mm: &AddressSpace, arg: u64, size: usize) -> KResult<Vec<u8>> {
    let mut b = vec![0u8; size];
    mm.copy_from(arg, &mut b)?;
    Ok(b)
}

struct Control {
    ino: u64,
}

impl Inode for Control {
    fn file_type(&self) -> FileType {
        FileType::CharDevice
    }
    fn ino(&self) -> u64 {
        self.ino
    }
    fn perm(&self) -> u32 {
        0o666
    }
    fn rdev(&self) -> u64 {
        crate::fs::dev::makedev(116, 0)
    }
    fn seekable(&self) -> bool {
        false
    }
    fn poll(&self) -> u16 {
        0
    }
    fn ioctl(&self, req: u32, arg: u64, mm: &AddressSpace) -> KResult<u64> {
        if (req >> 8) & 0xff != b'U' as u32 {
            return Err(Errno::ENOTTY);
        }
        let size = ioctl_size(req);
        match req & 0xff {
            0x00 => mm.write(arg, &CTL_VERSION)?,
            0x01 => {
                // struct snd_ctl_card_info
                let mut b = vec![0u8; size];
                let base = hda::with(|h| h.base).unwrap_or(0);
                put_str(&mut b, 8, 16, "Intel");
                put_str(&mut b, 24, 16, "HDA-Intel");
                put_str(&mut b, 40, 32, "HDA Intel");
                put_str(&mut b, 72, 80, &alloc::format!("HDA Intel at {base:#x}"));
                put_str(&mut b, 168, 80, "HDA Generic");
                mm.copy_to(arg, &b)?;
            }
            0x10 => {
                // ELEM_LIST: no mixer controls yet.
                let mut b = read_arg(mm, arg, size)?;
                put32(&mut b, 8, 0);
                put32(&mut b, 12, 0);
                mm.copy_to(arg, &b)?;
            }
            0x16 | 0x32 | 0x40 | 0x41 => {} // SUBSCRIBE_EVENTS, PREFER_SUBDEVICE, *_PREFER_SUBDEVICE
            0x30 => {
                // PCM_NEXT_DEVICE: device 0 after -1, then none.
                let cur: i32 = mm.read(arg)?;
                mm.write(arg, &(if cur < 0 { 0i32 } else { -1 }))?;
            }
            0x31 => {
                let b = read_arg(mm, arg, size)?;
                let (dev, sub, stream) = (get32(&b, 0), get32(&b, 4), get32(&b, 8));
                if dev != 0 || sub != 0 {
                    return Err(Errno::ENXIO);
                }
                if stream != 0 {
                    return Err(Errno::ENOENT);
                }
                mm.copy_to(arg, &pcm_info(size))?;
            }
            0xd1 => mm.write(arg, &0u32)?, // POWER_STATE: D0
            _ => return Err(Errno::ENOTTY),
        }
        Ok(0)
    }
}

/// One open of the playback PCM (only one at a time: EBUSY).
struct Pcm {
    ino: u64,
    owner: AtomicBool,
}

impl Drop for Pcm {
    fn drop(&mut self) {
        if self.owner.load(Ordering::Relaxed) {
            let mut s = STREAM.lock();
            if s.state != OPEN {
                hda::with(|h| h.stop());
            }
            s.state = OPEN;
            BUSY.store(false, Ordering::Relaxed);
        }
    }
}

/// An interval of hw_params: [min, max] with its flag bits.
#[derive(Clone, Copy, PartialEq)]
struct Iv {
    min: u64,
    max: u64,
}

impl Iv {
    fn read(b: &[u8], i: usize) -> Iv {
        let off = interval_off(i);
        let (mut min, mut max) = (get32(b, off) as u64, get32(b, off + 4) as u64);
        let flags = get32(b, off + 8);
        if flags & 1 != 0 {
            min += 1;
        }
        if flags & 2 != 0 && max > 0 {
            max -= 1;
        }
        Iv { min, max }
    }
    fn write(self, b: &mut [u8], i: usize) {
        let off = interval_off(i);
        put32(b, off, self.min.min(u32::MAX as u64) as u32);
        put32(b, off + 4, self.max.min(u32::MAX as u64) as u32);
        // integer, closed at both ends
        put32(b, off + 8, 1 << 2);
    }
    fn and(self, o: Iv) -> Iv {
        Iv {
            min: self.min.max(o.min),
            max: self.max.min(o.max),
        }
    }
    fn empty(self) -> bool {
        self.min > self.max
    }
}

fn interval_off(i: usize) -> usize {
    // flags, then 3 + 5 masks of 32 bytes, then 12-byte intervals.
    4 + 8 * 32 + (i - 8) * 12
}

fn mask_off(i: usize) -> usize {
    4 + i * 32
}

/// Refines hw_params `b` to what the PCM supports (SNDRV_PCM_IOCTL_HW_REFINE).
fn refine(b: &mut [u8]) -> KResult<()> {
    for (m, bit) in [
        (ACCESS, ACCESS_RW_INTERLEAVED),
        (FORMAT, FORMAT_S16_LE),
        (SUBFORMAT, 0),
    ] {
        let off = mask_off(m);
        let word = get32(b, off + (bit as usize / 32) * 4);
        if word & 1 << (bit % 32) == 0 {
            return Err(Errno::EINVAL);
        }
        for w in 0..8 {
            put32(b, off + w * 4, 0);
        }
        put32(b, off + (bit as usize / 32) * 4, 1 << (bit % 32));
    }
    let fixed = |v: u64| Iv { min: v, max: v };
    let mut iv: [Iv; 20] = [Iv {
        min: 0,
        max: u32::MAX as u64,
    }; 20];
    for (i, slot) in iv.iter_mut().enumerate().take(19).skip(8) {
        *slot = Iv::read(b, i);
    }
    let limits = [
        (SAMPLE_BITS, fixed(16)),
        (FRAME_BITS, fixed(32)),
        (CHANNELS_P, fixed(CHANNELS as u64)),
        (RATE_P, fixed(RATE as u64)),
        (
            PERIOD_SIZE,
            Iv {
                min: 32,
                max: 16384,
            },
        ),
        (PERIODS, Iv { min: 2, max: 64 }),
        (
            BUFFER_SIZE,
            Iv {
                min: 64,
                max: (hda::MAX_PAGES as u64 * 4096) / FRAME,
            },
        ),
    ];
    for (i, l) in limits {
        iv[i] = iv[i].and(l);
    }
    let us = |frames: u64| frames * 1_000_000 / RATE as u64;
    let frames_of = |t: u64| t * RATE as u64 / 1_000_000;
    for _ in 0..16 {
        let before = iv;
        let ps = iv[PERIOD_SIZE];
        let bs = iv[BUFFER_SIZE];
        let pe = iv[PERIODS];
        iv[PERIOD_BYTES] = iv[PERIOD_BYTES].and(Iv {
            min: ps.min * FRAME,
            max: ps.max * FRAME,
        });
        iv[BUFFER_BYTES] = iv[BUFFER_BYTES].and(Iv {
            min: bs.min * FRAME,
            max: bs.max * FRAME,
        });
        iv[PERIOD_SIZE] = iv[PERIOD_SIZE]
            .and(Iv {
                min: iv[PERIOD_BYTES].min.div_ceil(FRAME),
                max: iv[PERIOD_BYTES].max / FRAME,
            })
            .and(Iv {
                min: bs.min.div_ceil(pe.max.max(1)),
                max: bs.max / pe.min.max(1),
            })
            .and(Iv {
                min: frames_of(iv[PERIOD_TIME].min),
                max: frames_of(iv[PERIOD_TIME].max).max(1) + 1,
            });
        iv[BUFFER_SIZE] = iv[BUFFER_SIZE]
            .and(Iv {
                min: iv[BUFFER_BYTES].min.div_ceil(FRAME),
                max: iv[BUFFER_BYTES].max / FRAME,
            })
            .and(Iv {
                min: ps.min * pe.min,
                max: ps.max.saturating_mul(pe.max),
            })
            .and(Iv {
                min: frames_of(iv[BUFFER_TIME].min),
                max: frames_of(iv[BUFFER_TIME].max).max(1) + 1,
            });
        let (ps, bs) = (iv[PERIOD_SIZE], iv[BUFFER_SIZE]);
        iv[PERIODS] = iv[PERIODS].and(Iv {
            min: bs.min.div_ceil(ps.max.max(1)),
            max: bs.max / ps.min.max(1),
        });
        iv[PERIOD_TIME] = iv[PERIOD_TIME].and(Iv {
            min: us(ps.min),
            max: us(ps.max) + 1,
        });
        iv[BUFFER_TIME] = iv[BUFFER_TIME].and(Iv {
            min: us(bs.min),
            max: us(bs.max) + 1,
        });
        if iv.iter().skip(8).take(11).any(|i| i.empty()) {
            return Err(Errno::EINVAL);
        }
        if iv == before {
            break;
        }
    }
    for (i, v) in iv.iter().enumerate().take(19).skip(8) {
        v.write(b, i);
    }
    // Times are not whole numbers of µs: leave them open-ended.
    for i in [PERIOD_TIME, BUFFER_TIME] {
        put32(b, interval_off(i) + 8, 0);
    }
    let tail = 4 + 8 * 32 + 21 * 12;
    put32(b, tail, 0); // rmask
    put32(b, tail + 4, !0); // cmask: everything may have changed
    put32(b, tail + 8, INFO);
    put32(b, tail + 12, 16); // msbits
    put32(b, tail + 16, RATE); // rate_num
    put32(b, tail + 20, 1); // rate_den
    Ok(())
}

fn chosen(b: &mut [u8], i: usize, last: bool) -> u64 {
    let v = Iv::read(b, i);
    let x = if last { v.max } else { v.min };
    Iv { min: x, max: x }.write(b, i);
    x
}

impl Pcm {
    fn claim(&self) -> KResult<()> {
        if self.owner.load(Ordering::Relaxed) {
            return Ok(());
        }
        if BUSY.swap(true, Ordering::Relaxed) {
            return Err(Errno::EBUSY);
        }
        self.owner.store(true, Ordering::Relaxed);
        Ok(())
    }

    fn hw_params(&self, b: &mut [u8]) -> KResult<()> {
        refine(b)?;
        let ps = chosen(b, PERIOD_SIZE, false);
        refine(b)?;
        let bs = chosen(b, BUFFER_SIZE, true);
        refine(b)?;
        let mut s = STREAM.lock();
        if matches!(s.state, RUNNING | DRAINING) {
            return Err(Errno::EBUSY);
        }
        s.period_size = ps;
        s.buffer_size = bs;
        let mut boundary = bs;
        while boundary * 2 <= (i64::MAX as u64) - bs {
            boundary *= 2;
        }
        s.boundary = boundary;
        s.avail_min = ps;
        s.start_threshold = 1;
        s.stop_threshold = bs;
        s.state = SETUP;
        s.prepare()?;
        s.state = SETUP;
        Ok(())
    }

    fn sw_params(&self, b: &mut [u8]) -> KResult<()> {
        let mut s = STREAM.lock();
        if s.state == OPEN {
            return Err(Errno::EBADFD);
        }
        s.avail_min = get64(b, 16).max(1);
        s.start_threshold = get64(b, 32);
        s.stop_threshold = get64(b, 40);
        let boundary = get64(b, 64);
        if boundary >= s.buffer_size && boundary.is_multiple_of(s.buffer_size.max(1)) {
            s.boundary = boundary;
        }
        put64(b, 64, s.boundary);
        Ok(())
    }

    /// Writes `frames` frames from `buf`; returns how many were written.
    fn write_frames(
        &self,
        mm: &AddressSpace,
        buf: u64,
        frames: u64,
        nonblock: bool,
    ) -> KResult<u64> {
        let mut done = 0u64;
        while done < frames {
            let mut s = STREAM.lock();
            s.update();
            match s.state {
                XRUN => {
                    return if done > 0 {
                        Ok(done)
                    } else {
                        Err(Errno::EPIPE)
                    };
                }
                PREPARED | RUNNING => {}
                _ => return Err(Errno::EBADFD),
            }
            let room = s.avail().min(frames - done).min(16384);
            if room == 0 {
                drop(s);
                if nonblock {
                    return if done > 0 {
                        Ok(done)
                    } else {
                        Err(Errno::EAGAIN)
                    };
                }
                let g = GENERATION.load(Ordering::Relaxed);
                if let Err(e) = WAIT.wait_interruptible(|| GENERATION.load(Ordering::Relaxed) != g)
                {
                    return if done > 0 { Ok(done) } else { Err(e) };
                }
                continue;
            }
            // Copy from the caller without holding the lock (it may fault).
            drop(s);
            let mut data = vec![0u8; (room * FRAME) as usize];
            mm.copy_from(buf + done * FRAME, &mut data)?;
            let mut s = STREAM.lock();
            if !matches!(s.state, PREPARED | RUNNING) {
                continue;
            }
            let at = (s.appl_ptr % s.buffer_size) * FRAME;
            hda::with(|h| h.write(at as usize, &data));
            s.appl_ptr = (s.appl_ptr + room) % s.boundary;
            done += room;
            if s.state == PREPARED && s.queued() >= s.start_threshold {
                s.start();
            }
        }
        Ok(done)
    }

    fn drain(&self, nonblock: bool) -> KResult<()> {
        {
            let mut s = STREAM.lock();
            match s.state {
                PREPARED if s.queued() > 0 => {
                    s.start();
                    s.state = DRAINING;
                }
                PREPARED | XRUN => {
                    s.state = SETUP;
                    return Ok(());
                }
                RUNNING => s.state = DRAINING,
                DRAINING => {}
                _ => return Err(Errno::EBADFD),
            }
        }
        if nonblock {
            return Err(Errno::EAGAIN);
        }
        loop {
            let g = GENERATION.load(Ordering::Relaxed);
            if STREAM.lock().state != DRAINING {
                return Ok(());
            }
            WAIT.wait_interruptible(|| GENERATION.load(Ordering::Relaxed) != g)?;
        }
    }

    /// struct snd_pcm_status.
    fn status(&self, size: usize) -> Vec<u8> {
        let mut s = STREAM.lock();
        s.update();
        let mut b = vec![0u8; size];
        let now = crate::time::monotonic_ns();
        put32(&mut b, 0, s.state as u32);
        put64(&mut b, 8, s.trigger_ns / 1_000_000_000);
        put64(&mut b, 16, s.trigger_ns % 1_000_000_000);
        put64(&mut b, 24, now / 1_000_000_000);
        put64(&mut b, 32, now % 1_000_000_000);
        put64(&mut b, 40, s.appl_ptr);
        put64(&mut b, 48, s.hw_ptr);
        put64(&mut b, 56, s.queued());
        put64(&mut b, 64, s.avail());
        put64(&mut b, 72, s.avail());
        b
    }

    /// SNDRV_PCM_IOCTL_SYNC_PTR: struct snd_pcm_sync_ptr.
    fn sync_ptr(&self, b: &mut [u8]) {
        let flags = get32(b, 0);
        let mut s = STREAM.lock();
        if flags & 1 != 0 {
            s.update();
        }
        if flags & 2 == 0 {
            let appl = get64(b, 72);
            if s.boundary > 0 {
                s.appl_ptr = appl % s.boundary;
            }
        }
        if flags & 4 == 0 {
            s.avail_min = get64(b, 80).max(1);
        }
        let now = crate::time::monotonic_ns();
        put32(b, 8, s.state as u32);
        put64(b, 16, s.hw_ptr);
        put64(b, 24, now / 1_000_000_000);
        put64(b, 32, now % 1_000_000_000);
        put64(b, 72, s.appl_ptr);
        put64(b, 80, s.avail_min);
    }
}

impl Inode for Pcm {
    fn file_type(&self) -> FileType {
        FileType::CharDevice
    }
    fn ino(&self) -> u64 {
        self.ino
    }
    fn perm(&self) -> u32 {
        0o666
    }
    fn rdev(&self) -> u64 {
        crate::fs::dev::makedev(116, 16)
    }
    fn seekable(&self) -> bool {
        false
    }
    fn opened(&self, _flags: u32) -> KResult<()> {
        self.claim()
    }
    fn poll(&self) -> u16 {
        let mut s = STREAM.lock();
        s.update();
        match s.state {
            PREPARED | RUNNING if s.avail() >= s.avail_min => poll::POLLOUT,
            PREPARED | RUNNING | DRAINING => 0,
            _ => poll::POLLOUT | poll::POLLERR,
        }
    }
    fn poll_generation(&self) -> u64 {
        GENERATION.load(Ordering::Relaxed)
    }
    fn mmap_frames(&self, _off: u64, _pages: u64) -> Option<KResult<Vec<u64>>> {
        // No mapped status, control or buffer: libasound uses SYNC_PTR
        // and read/write transfers instead.
        Some(Err(Errno::ENXIO))
    }
    fn ioctl(&self, req: u32, arg: u64, mm: &AddressSpace) -> KResult<u64> {
        self.ioctl_nb(req, arg, mm, false)
    }
    fn ioctl_nb(&self, req: u32, arg: u64, mm: &AddressSpace, nonblock: bool) -> KResult<u64> {
        if (req >> 8) & 0xff != b'A' as u32 {
            return Err(Errno::ENOTTY);
        }
        self.claim()?;
        let size = ioctl_size(req);
        match req & 0xff {
            0x00 => mm.write(arg, &PCM_VERSION)?,
            0x01 => mm.copy_to(arg, &pcm_info(size))?,
            0x02..=0x04 => {} // TSTAMP, TTSTAMP, USER_PVERSION
            0x10 | 0x11 => {
                let mut b = read_arg(mm, arg, size)?;
                if req & 0xff == 0x10 {
                    refine(&mut b)?;
                } else {
                    self.hw_params(&mut b)?;
                }
                mm.copy_to(arg, &b)?;
            }
            0x12 => {
                let mut s = STREAM.lock();
                if matches!(s.state, RUNNING | DRAINING) {
                    return Err(Errno::EBADFD);
                }
                s.state = OPEN;
            }
            0x13 => {
                let mut b = read_arg(mm, arg, size)?;
                self.sw_params(&mut b)?;
                mm.copy_to(arg, &b)?;
            }
            0x20 | 0x24 => mm.copy_to(arg, &self.status(size))?,
            0x21 => {
                let mut s = STREAM.lock();
                s.update();
                mm.write(arg, &(s.queued() as i64))?;
            }
            0x22 => STREAM.lock().update(),
            0x23 => {
                let mut b = read_arg(mm, arg, size)?;
                self.sync_ptr(&mut b);
                mm.copy_to(arg, &b)?;
            }
            0x40 => {
                let mut s = STREAM.lock();
                if matches!(s.state, RUNNING | DRAINING) {
                    s.stop(SETUP);
                }
                s.prepare()?;
            }
            0x41 => {
                let mut s = STREAM.lock();
                s.appl_ptr = s.hw_ptr;
            }
            0x42 => {
                let mut s = STREAM.lock();
                if s.state != PREPARED {
                    return Err(Errno::EBADFD);
                }
                s.start();
            }
            0x43 => {
                let mut s = STREAM.lock();
                if s.state == OPEN {
                    return Err(Errno::EBADFD);
                }
                if s.state != SETUP {
                    s.stop(SETUP);
                }
            }
            0x44 => self.drain(nonblock)?,
            0x46 | 0x49 => return Ok(0), // REWIND, FORWARD: nothing moved
            0x50 => {
                // struct snd_xferi { result, buf, frames }
                let b = read_arg(mm, arg, 24)?;
                let n = self.write_frames(mm, get64(&b, 8), get64(&b, 16), nonblock)?;
                mm.write(arg, &(n as i64))?;
            }
            _ => return Err(Errno::ENOTTY),
        }
        Ok(0)
    }
}
