//! I/O APIC: routes device interrupts (the keyboard's, the serial port's)
//! to a CPU's local APIC as an interrupt vector.
//!
//! ISA devices use IRQs 0-15; the firmware may wire them to other global
//! system interrupts ("interrupt source overrides" in the MADT), with
//! their own polarity and trigger mode.

use super::acpi;
use crate::sync::SpinLock;
use alloc::vec::Vec;

/// Mapped after the local APIC's page.
const MMIO_VIRT: u64 = 0xffff_e000_0001_0000;

struct IoApic {
    base: u64,
    gsi_base: u32,
    entries: u32,
}

impl IoApic {
    fn write(&self, reg: u32, value: u32) {
        unsafe {
            (self.base as *mut u32).write_volatile(reg);
            ((self.base + 0x10) as *mut u32).write_volatile(value);
        }
    }

    fn read(&self, reg: u32) -> u32 {
        unsafe {
            (self.base as *mut u32).write_volatile(reg);
            ((self.base + 0x10) as *const u32).read_volatile()
        }
    }
}

struct State {
    apics: Vec<IoApic>,
    overrides: Vec<acpi::Override>,
}

static STATE: SpinLock<Option<State>> = SpinLock::new(None);

/// Finds and maps the I/O APICs; every input starts masked.
pub fn init(rsdp: u64) {
    let (infos, overrides) = acpi::io_apics(rsdp);
    let mut apics = Vec::new();
    for (i, info) in infos.iter().enumerate() {
        let virt = MMIO_VIRT + i as u64 * 0x1000;
        if crate::mm::paging::map_mmio(virt, info.address & !0xfff, 1).is_err() {
            continue;
        }
        let apic = IoApic {
            base: virt + (info.address & 0xfff),
            gsi_base: info.gsi_base,
            entries: 0,
        };
        let entries = ((apic.read(1) >> 16) & 0xff) + 1;
        let apic = IoApic { entries, ..apic };
        for e in 0..entries {
            apic.write(0x10 + 2 * e, 1 << 16); // masked
        }
        apics.push(apic);
    }
    if apics.is_empty() {
        crate::warn!("ioapic: none found; no keyboard or serial input");
    } else {
        crate::info!(
            "ioapic: {} found, {} inputs",
            apics.len(),
            apics.iter().map(|a| a.entries).sum::<u32>()
        );
    }
    *STATE.lock() = Some(State { apics, overrides });
}

/// Routes ISA interrupt `irq` to `vector` on the CPU with local APIC ID
/// `apic_id`.
pub fn route_isa(irq: u8, vector: u8, apic_id: u32) -> bool {
    let guard = STATE.lock();
    let Some(state) = guard.as_ref() else {
        return false;
    };
    // ISA defaults: edge triggered, active high.
    let (gsi, flags) = state
        .overrides
        .iter()
        .find(|o| o.irq == irq)
        .map_or((irq as u32, 0), |o| (o.gsi, o.flags));
    let active_low = flags & 0b11 == 0b11;
    let level = (flags >> 2) & 0b11 == 0b11;
    let Some(apic) = state
        .apics
        .iter()
        .find(|a| gsi >= a.gsi_base && gsi < a.gsi_base + a.entries)
    else {
        return false;
    };
    let entry = 0x10 + 2 * (gsi - apic.gsi_base);
    let low = vector as u32 | (active_low as u32) << 13 | (level as u32) << 15;
    apic.write(entry + 1, apic_id << 24);
    apic.write(entry, low);
    true
}
