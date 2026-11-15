//! DRM/KMS on the framebuffer the firmware set up: `/dev/dri/card0`, as
//! Linux's simpledrm offers it, for Wayland compositors and other KMS
//! programs.
//!
//! One CRTC, one primary plane, one encoder and one connected connector
//! with one mode (the firmware's resolution). Programs draw into dumb
//! buffers (ordinary memory they `mmap`), wrap them in framebuffers, and
//! show one with SETCRTC or PAGE_FLIP; the kernel then copies it to the
//! screen (and again on DIRTYFB). Page flips complete at once and send
//! their event. While a program shows its own picture the text console
//! stays off the screen; when its last file closes, the console returns.
//! Legacy KMS only (no atomic), no GPU rendering, no PRIME.

use crate::abi::{Errno, KResult};
use crate::fs::{FileType, Inode, new_ino, poll};
use crate::mm::vm::AddressSpace;
use crate::mm::{PAGE_SIZE, frame, phys_to_virt};
use crate::sync::{Once, SpinLock};
use crate::task::wait::WaitQueue;
use alloc::collections::{BTreeMap, VecDeque};
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

const CRTC: u32 = 0x20;
const ENCODER: u32 = 0x21;
const CONNECTOR: u32 = 0x22;
const PLANE: u32 = 0x23;
const PROP_TYPE: u32 = 0x30;
const PROP_DPMS: u32 = 0x31;
const OBJ_CRTC: u32 = 0xcccc_cccc;
const OBJ_CONNECTOR: u32 = 0xc0c0_c0c0;
const OBJ_PLANE: u32 = 0xeeee_eeee;
const XR24: u32 = 0x3432_5258;
const AR24: u32 = 0x3432_5241;

struct Screen {
    base: u64,
    width: u32,
    height: u32,
    /// Bytes per line.
    pitch: u32,
    /// The firmware's pixels are R, G, B (not B, G, R) in memory.
    rgb: bool,
}

static SCREEN: Once<Screen> = Once::new();
static NEXT_ID: AtomicU32 = AtomicU32::new(0x100);
static SEQUENCE: AtomicU64 = AtomicU64::new(0);
static GENERATION: AtomicU64 = AtomicU64::new(0);

/// A dumb buffer: pages the program draws into.
struct Buffer {
    width: u32,
    height: u32,
    pitch: u32,
    frames: Vec<u64>,
}

impl Drop for Buffer {
    fn drop(&mut self) {
        for &f in &self.frames {
            frame::free(f);
        }
    }
}

struct Fb {
    buffer: Arc<Buffer>,
    width: u32,
    height: u32,
    pitch: u32,
    offset: u32,
    format: u32,
}

/// What the screen shows: (file id, framebuffer).
static SCANOUT: SpinLock<Option<(u64, Arc<Fb>)>> = SpinLock::new(None);
static NEXT_FILE: AtomicU64 = AtomicU64::new(1);

pub fn init(fb: &bootinfo::Framebuffer) {
    if fb.address == 0 || fb.bpp != 32 {
        return;
    }
    SCREEN.call_once(|| Screen {
        base: fb.address,
        width: fb.width,
        height: fb.height,
        pitch: fb.pitch,
        rgb: fb.format == bootinfo::PixelFormat::Rgbx,
    });
    crate::info!(
        "drm: card0, {}x{} on the firmware framebuffer",
        fb.width,
        fb.height
    );
}

pub fn present() -> bool {
    SCREEN.get().is_some()
}

/// Copies `fb` to the screen.
fn show(fb: &Fb) {
    let Some(s) = SCREEN.get() else { return };
    let w = fb.width.min(s.width) as usize;
    let h = fb.height.min(s.height) as usize;
    let mut row = vec![0u8; w * 4];
    for y in 0..h {
        let mut off = fb.offset as usize + y * fb.pitch as usize;
        let mut done = 0;
        while done < row.len() {
            let page = off / PAGE_SIZE as usize;
            let in_page = off % PAGE_SIZE as usize;
            let n = (PAGE_SIZE as usize - in_page).min(row.len() - done);
            let Some(&phys) = fb.buffer.frames.get(page) else {
                return;
            };
            let src = unsafe { core::slice::from_raw_parts(phys_to_virt(phys).add(in_page), n) };
            row[done..done + n].copy_from_slice(src);
            done += n;
            off += n;
        }
        if s.rgb {
            for p in row.chunks_exact_mut(4) {
                p.swap(0, 2);
            }
        }
        let dst = phys_to_virt(s.base + (y * s.pitch as usize) as u64);
        unsafe { core::ptr::copy_nonoverlapping(row.as_ptr(), dst, row.len()) };
    }
}

fn set_scanout(file: u64, fb: Option<Arc<Fb>>) {
    let mut sc = SCANOUT.lock();
    match fb {
        Some(fb) => {
            crate::console::set_graphics(true);
            show(&fb);
            *sc = Some((file, fb));
        }
        None => {
            if sc.take().is_some() {
                crate::console::set_graphics(false);
            }
        }
    }
}

/// `/dev/dri/card0`.
pub struct CardNode {
    ino: u64,
}

pub fn node() -> Arc<dyn Inode> {
    Arc::new(CardNode { ino: new_ino() })
}

impl Inode for CardNode {
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
        crate::fs::dev::makedev(226, 0)
    }
    fn seekable(&self) -> bool {
        false
    }
    fn open_fifo(&self, _flags: u32) -> Option<Arc<dyn Inode>> {
        Some(Arc::new(DrmFile {
            id: NEXT_FILE.fetch_add(1, Ordering::Relaxed),
            ino: self.ino,
            st: SpinLock::new(State::default()),
            events: SpinLock::new(VecDeque::new()),
            wait: WaitQueue::new(),
        }))
    }
}

#[derive(Default)]
struct State {
    buffers: BTreeMap<u32, Arc<Buffer>>,
    fbs: BTreeMap<u32, Arc<Fb>>,
    next_handle: u32,
    universal: bool,
}

/// One open file of the card: its buffers, framebuffers and events.
pub struct DrmFile {
    id: u64,
    ino: u64,
    st: SpinLock<State>,
    events: SpinLock<VecDeque<[u8; 32]>>,
    wait: WaitQueue,
}

impl Drop for DrmFile {
    fn drop(&mut self) {
        let mine = SCANOUT.lock().as_ref().is_some_and(|(f, _)| *f == self.id);
        if mine {
            set_scanout(self.id, None);
        }
    }
}

fn mode_info(s: &Screen) -> [u8; 68] {
    let mut m = [0u8; 68];
    let (w, h) = (s.width as u16, s.height as u16);
    let (ht, vt) = (w + 48, h + 9);
    let clock = ht as u32 * vt as u32 * 60 / 1000;
    m[0..4].copy_from_slice(&clock.to_le_bytes());
    for (i, v) in [w, w + 16, w + 32, ht, 0, h, h + 3, h + 6, vt, 0]
        .iter()
        .enumerate()
    {
        m[4 + i * 2..6 + i * 2].copy_from_slice(&v.to_le_bytes());
    }
    m[24..28].copy_from_slice(&60u32.to_le_bytes());
    m[28..32].copy_from_slice(&0xau32.to_le_bytes()); // -hsync, -vsync
    m[32..36].copy_from_slice(&0x48u32.to_le_bytes()); // preferred | driver
    let name = alloc::format!("{w}x{h}");
    m[36..36 + name.len()].copy_from_slice(name.as_bytes());
    m
}

fn r32(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes(b[o..o + 4].try_into().unwrap())
}
fn r64(b: &[u8], o: usize) -> u64 {
    u64::from_le_bytes(b[o..o + 8].try_into().unwrap())
}
fn w32(b: &mut [u8], o: usize, v: u32) {
    b[o..o + 4].copy_from_slice(&v.to_le_bytes());
}
fn w64(b: &mut [u8], o: usize, v: u64) {
    b[o..o + 8].copy_from_slice(&v.to_le_bytes());
}

/// Copies `ids` to the user array at `ptr` if it has room for them all
/// (`cap` entries); returns how many there are, as the ioctls report.
fn put_ids(mm: &AddressSpace, ptr: u64, cap: u32, ids: &[u32]) -> KResult<u32> {
    if ptr != 0 && cap as usize >= ids.len() {
        let b: Vec<u8> = ids.iter().flat_map(|i| i.to_le_bytes()).collect();
        mm.copy_to(ptr, &b)?;
    }
    Ok(ids.len() as u32)
}

fn put_u64s(mm: &AddressSpace, ptr: u64, cap: u32, v: &[u64]) -> KResult<u32> {
    if ptr != 0 && cap as usize >= v.len() {
        let b: Vec<u8> = v.iter().flat_map(|i| i.to_le_bytes()).collect();
        mm.copy_to(ptr, &b)?;
    }
    Ok(v.len() as u32)
}

impl DrmFile {
    fn queue_event(&self, ty: u32, user_data: u64) {
        let now = crate::time::monotonic_ns();
        let seq = SEQUENCE.fetch_add(1, Ordering::Relaxed) as u32;
        let mut e = [0u8; 32];
        w32(&mut e, 0, ty);
        w32(&mut e, 4, 32);
        w64(&mut e, 8, user_data);
        w32(&mut e, 16, (now / 1_000_000_000) as u32);
        w32(&mut e, 20, (now % 1_000_000_000 / 1000) as u32);
        w32(&mut e, 24, seq);
        w32(&mut e, 28, CRTC);
        self.events.lock().push_back(e);
        GENERATION.fetch_add(1, Ordering::Relaxed);
        self.wait.wake_all();
        crate::fs::poll_notify();
    }

    fn fb(&self, id: u32) -> KResult<Arc<Fb>> {
        self.st.lock().fbs.get(&id).cloned().ok_or(Errno::ENOENT)
    }

    fn add_fb(
        &self,
        handle: u32,
        width: u32,
        height: u32,
        pitch: u32,
        offset: u32,
        format: u32,
    ) -> KResult<u32> {
        let mut st = self.st.lock();
        let buffer = st.buffers.get(&handle).cloned().ok_or(Errno::ENOENT)?;
        let need = offset as u64 + pitch as u64 * height as u64;
        if width == 0
            || height == 0
            || pitch < width * 4
            || need > buffer.frames.len() as u64 * PAGE_SIZE
        {
            return Err(Errno::EINVAL);
        }
        let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        st.fbs.insert(
            id,
            Arc::new(Fb {
                buffer,
                width,
                height,
                pitch,
                offset,
                format,
            }),
        );
        Ok(id)
    }

    fn handle(&self, nr: u32, b: &mut [u8], mm: &AddressSpace) -> KResult<()> {
        let s = SCREEN.get().ok_or(Errno::ENODEV)?;
        match nr {
            0x00 => {
                // VERSION
                w32(b, 0, 1);
                w32(b, 4, 0);
                w32(b, 8, 0);
                for (i, text) in [
                    &b"simpledrm"[..],
                    b"20200625",
                    b"DRM over the firmware framebuffer",
                ]
                .iter()
                .enumerate()
                {
                    let o = 16 + i * 16;
                    let cap = r64(b, o) as usize;
                    let ptr = r64(b, o + 8);
                    if ptr != 0 && cap > 0 {
                        mm.copy_to(ptr, &text[..text.len().min(cap)])?;
                    }
                    w64(b, o, text.len() as u64);
                }
            }
            0x01 | 0x02 => {
                // GET_UNIQUE / GET_MAGIC: empty.
                if nr == 0x02 {
                    w32(b, 0, 1);
                } else {
                    w64(b, 0, 0);
                }
            }
            0x09 => {
                // GEM_CLOSE
                self.st
                    .lock()
                    .buffers
                    .remove(&r32(b, 0))
                    .ok_or(Errno::EINVAL)?;
            }
            0x0c => {
                let v = match r64(b, 0) {
                    0x1 => 1,        // DUMB_BUFFER
                    0x3 => 24,       // DUMB_PREFERRED_DEPTH
                    0x6 => 1,        // TIMESTAMP_MONOTONIC
                    0x8 | 0x9 => 64, // CURSOR_WIDTH/HEIGHT
                    0x12 => 1,       // CRTC_IN_VBLANK_EVENT
                    0x2 | 0x4 | 0x5 | 0x7 | 0x10 | 0x11 | 0x13 | 0x14 | 0x15 => 0,
                    _ => return Err(Errno::EINVAL),
                };
                w64(b, 8, v);
            }
            0x0d => match r64(b, 0) {
                1 | 4 => {}
                2 => self.st.lock().universal = r64(b, 8) != 0,
                3 => return Err(Errno::EOPNOTSUPP), // atomic: not offered
                _ => return Err(Errno::EINVAL),
            },
            0x11 | 0x1e | 0x1f => {} // AUTH_MAGIC, SET_MASTER, DROP_MASTER
            0x3a => {
                // WAIT_VBLANK: answer with the current count and time.
                let ty = r32(b, 0);
                let now = crate::time::monotonic_ns();
                if ty & 0x0400_0000 != 0 {
                    self.queue_event(1, r64(b, 8));
                }
                w32(b, 4, SEQUENCE.load(Ordering::Relaxed) as u32);
                w64(b, 8, now / 1_000_000_000);
                w64(b, 16, now % 1_000_000_000 / 1000);
            }
            0x3b => {
                // CRTC_GET_SEQUENCE
                w32(b, 4, 1);
                w64(b, 8, SEQUENCE.load(Ordering::Relaxed));
                w64(b, 16, crate::time::monotonic_ns());
            }
            0xa0 => {
                // GETRESOURCES
                let fbs: Vec<u32> = self.st.lock().fbs.keys().copied().collect();
                let n = put_ids(mm, r64(b, 0), r32(b, 32), &fbs)?;
                w32(b, 32, n);
                let n = put_ids(mm, r64(b, 8), r32(b, 36), &[CRTC])?;
                w32(b, 36, n);
                let n = put_ids(mm, r64(b, 16), r32(b, 40), &[CONNECTOR])?;
                w32(b, 40, n);
                let n = put_ids(mm, r64(b, 24), r32(b, 44), &[ENCODER])?;
                w32(b, 44, n);
                for (i, v) in [1, s.width, 1, s.height].iter().enumerate() {
                    w32(b, 48 + i * 4, *v);
                }
            }
            0xa1 => {
                // GETCRTC
                if r32(b, 12) != CRTC {
                    return Err(Errno::ENOENT);
                }
                let sc = SCANOUT.lock();
                let fb_id = match &*sc {
                    Some((f, fb)) if *f == self.id => self
                        .st
                        .lock()
                        .fbs
                        .iter()
                        .find(|(_, x)| Arc::ptr_eq(x, fb))
                        .map_or(0, |(id, _)| *id),
                    _ => 0,
                };
                w32(b, 16, fb_id);
                w32(b, 20, 0);
                w32(b, 24, 0);
                w32(b, 28, 0);
                w32(b, 32, sc.is_some() as u32);
                b[36..104].copy_from_slice(&mode_info(s));
            }
            0xa2 => {
                // SETCRTC
                if r32(b, 12) != CRTC {
                    return Err(Errno::ENOENT);
                }
                let fb_id = r32(b, 16);
                if fb_id == 0 || r32(b, 32) == 0 {
                    set_scanout(self.id, None);
                } else {
                    let fb = self.fb(fb_id)?;
                    set_scanout(self.id, Some(fb));
                }
            }
            0xa3 | 0xbb => return Err(Errno::ENXIO), // no cursor plane
            0xa4 | 0xa5 => {}                        // gamma: size 0
            0xa6 => {
                if r32(b, 0) != ENCODER {
                    return Err(Errno::ENOENT);
                }
                w32(b, 4, 0); // DRM_MODE_ENCODER_NONE
                w32(b, 8, CRTC);
                w32(b, 12, 1);
                w32(b, 16, 0);
            }
            0xa7 => {
                // GETCONNECTOR
                if r32(b, 48) != CONNECTOR {
                    return Err(Errno::ENOENT);
                }
                let n = put_ids(mm, r64(b, 0), r32(b, 40), &[ENCODER])?;
                w32(b, 40, n);
                if r64(b, 8) != 0 && r32(b, 32) >= 1 {
                    mm.copy_to(r64(b, 8), &mode_info(s))?;
                }
                w32(b, 32, 1);
                let n = put_ids(mm, r64(b, 16), r32(b, 36), &[PROP_DPMS])?;
                put_u64s(mm, r64(b, 24), r32(b, 36), &[0])?;
                w32(b, 36, n);
                w32(b, 44, ENCODER);
                w32(b, 52, 15); // DRM_MODE_CONNECTOR_VIRTUAL
                w32(b, 56, 1);
                w32(b, 60, 1); // connected
                w32(b, 64, s.width * 254 / 960);
                w32(b, 68, s.height * 254 / 960);
                w32(b, 72, 1); // subpixel unknown
            }
            0xaa => {
                // GETPROPERTY
                let (name, flags, enums): (&str, u32, &[(u64, &str)]) = match r32(b, 16) {
                    PROP_TYPE => (
                        "type",
                        (1 << 3) | (1 << 2),
                        &[(0, "Overlay"), (1, "Primary"), (2, "Cursor")],
                    ),
                    PROP_DPMS => (
                        "DPMS",
                        1 << 3,
                        &[(0, "On"), (1, "Standby"), (2, "Suspend"), (3, "Off")],
                    ),
                    _ => return Err(Errno::ENOENT),
                };
                w32(b, 20, flags);
                b[24..56].fill(0);
                b[24..24 + name.len()].copy_from_slice(name.as_bytes());
                let values: Vec<u64> = enums.iter().map(|e| e.0).collect();
                let n = put_u64s(mm, r64(b, 0), r32(b, 56), &values)?;
                w32(b, 56, n);
                if r64(b, 8) != 0 && r32(b, 60) as usize >= enums.len() {
                    let mut blob = Vec::new();
                    for (v, n) in enums {
                        blob.extend_from_slice(&v.to_le_bytes());
                        let mut nm = [0u8; 32];
                        nm[..n.len()].copy_from_slice(n.as_bytes());
                        blob.extend_from_slice(&nm);
                    }
                    mm.copy_to(r64(b, 8), &blob)?;
                }
                w32(b, 60, enums.len() as u32);
            }
            0xab | 0xba => {} // SETPROPERTY, OBJ_SETPROPERTY
            0xad => {
                // GETFB
                let fb = self.fb(r32(b, 0))?;
                w32(b, 4, fb.width);
                w32(b, 8, fb.height);
                w32(b, 12, fb.pitch);
                w32(b, 16, 32);
                w32(b, 20, 24);
                w32(b, 24, 0);
            }
            0xae => {
                // ADDFB
                if r32(b, 16) != 32 {
                    return Err(Errno::EINVAL);
                }
                let id = self.add_fb(r32(b, 24), r32(b, 4), r32(b, 8), r32(b, 12), 0, XR24)?;
                w32(b, 0, id);
            }
            0xaf | 0xd0 => {
                // RMFB, CLOSEFB
                let id = r32(b, 0);
                let fb = self.st.lock().fbs.remove(&id).ok_or(Errno::ENOENT)?;
                let showing = SCANOUT
                    .lock()
                    .as_ref()
                    .is_some_and(|(f, x)| *f == self.id && Arc::ptr_eq(x, &fb));
                if showing && nr == 0xaf {
                    set_scanout(self.id, None);
                }
            }
            0xb0 => {
                // PAGE_FLIP
                if r32(b, 0) != CRTC {
                    return Err(Errno::ENOENT);
                }
                let fb = self.fb(r32(b, 4))?;
                set_scanout(self.id, Some(fb));
                if r32(b, 8) & 1 != 0 {
                    self.queue_event(2, r64(b, 16));
                }
            }
            0xb1 => {
                // DIRTYFB
                let fb = self.fb(r32(b, 0))?;
                if let Some((_, x)) = &*SCANOUT.lock()
                    && Arc::ptr_eq(x, &fb)
                {
                    show(&fb);
                }
            }
            0xb2 => {
                // CREATE_DUMB
                let (h, w, bpp) = (r32(b, 0), r32(b, 4), r32(b, 8));
                if w == 0 || h == 0 || w > 16384 || h > 16384 || bpp == 0 || bpp > 32 {
                    return Err(Errno::EINVAL);
                }
                let pitch = (w * bpp.div_ceil(8)).next_multiple_of(64);
                let size = (pitch as u64 * h as u64).next_multiple_of(PAGE_SIZE);
                let mut frames = Vec::with_capacity((size / PAGE_SIZE) as usize);
                for _ in 0..size / PAGE_SIZE {
                    match frame::alloc_zeroed() {
                        Some(f) => frames.push(f),
                        None => {
                            frames.into_iter().for_each(frame::free);
                            return Err(Errno::ENOMEM);
                        }
                    }
                }
                let mut st = self.st.lock();
                st.next_handle += 1;
                let handle = st.next_handle;
                st.buffers.insert(
                    handle,
                    Arc::new(Buffer {
                        width: w,
                        height: h,
                        pitch,
                        frames,
                    }),
                );
                w32(b, 16, handle);
                w32(b, 20, pitch);
                w64(b, 24, size);
            }
            0xb3 => {
                // MAP_DUMB: the mmap offset names the buffer.
                let h = r32(b, 0);
                if !self.st.lock().buffers.contains_key(&h) {
                    return Err(Errno::ENOENT);
                }
                w64(b, 8, (h as u64) << 32);
            }
            0xb4 => {
                self.st
                    .lock()
                    .buffers
                    .remove(&r32(b, 0))
                    .ok_or(Errno::ENOENT)?;
            }
            0xb5 => {
                // GETPLANERESOURCES
                let planes: &[u32] = if self.st.lock().universal {
                    &[PLANE]
                } else {
                    &[]
                };
                let n = put_ids(mm, r64(b, 0), r32(b, 8), planes)?;
                w32(b, 8, n);
            }
            0xb6 => {
                // GETPLANE
                if r32(b, 0) != PLANE {
                    return Err(Errno::ENOENT);
                }
                let showing = SCANOUT.lock().as_ref().is_some_and(|(f, _)| *f == self.id);
                w32(b, 4, if showing { CRTC } else { 0 });
                w32(b, 8, 0);
                w32(b, 12, 1);
                w32(b, 16, 0);
                let n = put_ids(mm, r64(b, 24), r32(b, 20), &[XR24, AR24])?;
                w32(b, 20, n);
            }
            0xb7 => {
                // SETPLANE on the primary plane: show that framebuffer.
                if r32(b, 0) != PLANE {
                    return Err(Errno::EINVAL);
                }
                match r32(b, 8) {
                    0 => set_scanout(self.id, None),
                    id => {
                        let fb = self.fb(id)?;
                        set_scanout(self.id, Some(fb));
                    }
                }
            }
            0xb8 => {
                // ADDFB2
                let format = r32(b, 12);
                if !matches!(format, XR24 | AR24) || r32(b, 16) & 2 != 0 && r64(b, 72) != 0 {
                    return Err(Errno::EINVAL);
                }
                let id = self.add_fb(
                    r32(b, 20),
                    r32(b, 4),
                    r32(b, 8),
                    r32(b, 36),
                    r32(b, 52),
                    format,
                )?;
                w32(b, 0, id);
            }
            0xb9 => {
                // OBJ_GETPROPERTIES
                let (ids, vals): (&[u32], &[u64]) = match r32(b, 24) {
                    OBJ_PLANE => (&[PROP_TYPE], &[1]),
                    OBJ_CONNECTOR => (&[PROP_DPMS], &[0]),
                    OBJ_CRTC => (&[], &[]),
                    _ => return Err(Errno::ENOENT),
                };
                let n = put_ids(mm, r64(b, 0), r32(b, 16), ids)?;
                put_u64s(mm, r64(b, 8), r32(b, 16), vals)?;
                w32(b, 16, n);
            }
            0xce => {
                // GETFB2
                let fb = self.fb(r32(b, 0))?;
                w32(b, 4, fb.width);
                w32(b, 8, fb.height);
                w32(b, 12, fb.format);
                w32(b, 36, fb.pitch);
            }
            _ => return Err(Errno::EINVAL),
        }
        Ok(())
    }

    fn buffer_frames(&self, off: u64, pages: u64) -> KResult<Vec<u64>> {
        let st = self.st.lock();
        let buf = st.buffers.get(&((off >> 32) as u32)).ok_or(Errno::EINVAL)?;
        let first = ((off & 0xffff_ffff) / PAGE_SIZE) as usize;
        let end = first + pages as usize;
        if end > buf.frames.len() {
            return Err(Errno::EINVAL);
        }
        let _ = (buf.width, buf.height, buf.pitch);
        Ok(buf.frames[first..end].to_vec())
    }
}

impl Inode for DrmFile {
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
        crate::fs::dev::makedev(226, 0)
    }
    fn seekable(&self) -> bool {
        false
    }
    fn read_stream(&self, buf: &mut [u8], nonblock: bool) -> KResult<usize> {
        loop {
            {
                let mut q = self.events.lock();
                let mut n = 0;
                while n + 32 <= buf.len() {
                    let Some(e) = q.pop_front() else { break };
                    buf[n..n + 32].copy_from_slice(&e);
                    n += 32;
                }
                if n > 0 {
                    return Ok(n);
                }
            }
            if nonblock {
                return Err(Errno::EAGAIN);
            }
            self.wait
                .wait_interruptible(|| !self.events.lock().is_empty())?;
        }
    }
    fn poll(&self) -> u16 {
        poll::POLLOUT
            | if self.events.lock().is_empty() {
                0
            } else {
                poll::POLLIN
            }
    }
    fn poll_generation(&self) -> u64 {
        GENERATION.load(Ordering::Relaxed)
    }
    fn ioctl(&self, req: u32, arg: u64, mm: &AddressSpace) -> KResult<u64> {
        if (req >> 8) & 0xff != b'd' as u32 {
            return Err(Errno::ENOTTY);
        }
        let size = ((req >> 16) & 0x3fff) as usize;
        let mut b = vec![0u8; size.max(128)];
        if size > 0 {
            mm.copy_from(arg, &mut b[..size])?;
        }
        self.handle(req & 0xff, &mut b, mm)?;
        if size > 0 && req >> 30 & 2 != 0 {
            mm.copy_to(arg, &b[..size])?;
        }
        Ok(0)
    }
    fn mmap_frames(&self, off: u64, pages: u64) -> Option<KResult<Vec<u64>>> {
        Some(self.buffer_frames(off, pages))
    }
}
