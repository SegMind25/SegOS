//! virtio-blk: QEMU's (and most clouds') paravirtual disk.

use super::dma::{DmaPage, poll};
use super::virtio::{Queue, Transport};
use crate::abi::{Errno, KResult};
use crate::block::BlockDevice;
use crate::sync::Mutex;
use alloc::string::String;
use alloc::sync::Arc;

struct State {
    q: Queue,
    page: DmaPage,
}

pub struct VirtioBlk {
    name: String,
    sectors: u64,
    state: Mutex<State>,
}

pub fn probe(pci: super::pci::Device, n: usize) -> Option<Arc<dyn BlockDevice>> {
    let Some(t) = Transport::new(pci) else {
        crate::warn!("virtio-blk: no virtio capabilities");
        return None;
    };
    if t.negotiate(0).is_none() {
        crate::warn!("virtio-blk: feature negotiation failed");
        return None;
    }
    let q = t.queue(0, 0xffff)?;
    t.driver_ok();
    let sectors = t.device_cfg.r64(0);
    let name = alloc::format!("vd{}", (b'a' + n as u8) as char);
    crate::info!("virtio-blk: {name}, {} MiB", sectors / 2048);
    Some(Arc::new(VirtioBlk {
        name,
        sectors,
        state: Mutex::new(State {
            q,
            page: DmaPage::new(),
        }),
    }))
}

impl VirtioBlk {
    /// One request of at most 3 KiB of data (header and status share the
    /// page with the data).
    fn request(&self, write: bool, sector: u64, buf: &mut [u8]) -> KResult<()> {
        let mut s = self.state.lock();
        let p = s.page.phys;
        // Header at 0, status at 16, data from 512.
        s.page.write::<u32>(0, write as u32);
        s.page.write::<u32>(4, 0);
        s.page.write::<u64>(8, sector);
        s.page.write::<u8>(16, 0xff);
        if write {
            s.page.bytes()[512..512 + buf.len()].copy_from_slice(buf);
        }
        let n = buf.len() as u32;
        s.q.submit(&[(p, 16, false), (p + 512, n, !write), (p + 16, 1, true)])
            .ok_or(Errno::EIO)?;
        s.q.kick();
        let st = &mut *s;
        if !poll(10_000, || st.q.pop_used().is_some()) {
            return Err(Errno::EIO);
        }
        if s.page.read::<u8>(16) != 0 {
            return Err(Errno::EIO);
        }
        if !write {
            buf.copy_from_slice(&s.page.bytes()[512..512 + buf.len()]);
        }
        Ok(())
    }
}

impl BlockDevice for VirtioBlk {
    fn name(&self) -> &str {
        &self.name
    }
    fn sectors(&self) -> u64 {
        self.sectors
    }
    fn read(&self, sector: u64, buf: &mut [u8]) -> KResult<()> {
        for (i, chunk) in buf.chunks_mut(2048).enumerate() {
            self.request(false, sector + i as u64 * 4, chunk)?;
        }
        Ok(())
    }
    fn write(&self, sector: u64, buf: &[u8]) -> KResult<()> {
        for (i, chunk) in buf.chunks(2048).enumerate() {
            let mut tmp = alloc::vec::Vec::from(chunk);
            self.request(true, sector + i as u64 * 4, &mut tmp)?;
        }
        Ok(())
    }
}
