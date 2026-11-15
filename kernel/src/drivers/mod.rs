//! Device drivers. Each speaks to one kind of hardware and hands what it
//! gets to the rest of the kernel (input to the terminal, for now).

pub mod ahci;
pub mod dma;
pub mod nvme;
pub mod pci;
pub mod ps2kbd;
pub mod virtio;
pub mod virtio_blk;

/// Interrupt vectors of the devices routed through the I/O APIC.
pub const KEYBOARD_VECTOR: u8 = 0x21;
pub const SERIAL_VECTOR: u8 = 0x24;

/// Sets up input devices and routes their interrupts to this CPU.
pub fn init(rsdp: u64) {
    crate::hal::ioapic::init(rsdp);
    let me = crate::hal::apic::id();
    if ps2kbd::init() && crate::hal::ioapic::route_isa(1, KEYBOARD_VECTOR, me) {
        crate::info!("keyboard: PS/2");
    }
    if crate::hal::ioapic::route_isa(4, SERIAL_VECTOR, me) {
        crate::hal::serial::enable_rx_interrupt();
    }
    crate::tty::init();
    pci::init();
    storage();
}

/// Finds disks (SATA, NVMe, virtio) and registers them and their
/// partitions.
fn storage() {
    let (mut sd, mut nvme, mut vd) = (b'a', 0, 0);
    for d in pci::devices() {
        let found: alloc::vec::Vec<_> = match (d.class, d.subclass, d.prog_if) {
            (0x01, 0x06, 0x01) => ahci::probe(d, &mut sd),
            (0x01, 0x08, 0x02) => {
                nvme += 1;
                nvme::probe(d, nvme - 1).into_iter().collect()
            }
            _ if d.vendor == 0x1af4 && (d.device == 0x1001 || d.device == 0x1042) => {
                vd += 1;
                virtio_blk::probe(d, vd - 1).into_iter().collect()
            }
            _ => continue,
        };
        for disk in found {
            crate::block::register(disk);
        }
    }
    if let Ok(dev) = crate::fs::lookup(&crate::fs::root(), "/dev") {
        for (b, rdev) in crate::block::all() {
            let name = alloc::string::String::from(b.name());
            let _ = dev.insert(&name, crate::block::BlockNode::create(b, rdev));
        }
    }
}
