//! Just enough ACPI to find the CPUs and interrupt controllers: RSDP →
//! XSDT (or RSDT) → MADT.

use crate::mm::phys_to_virt;
use alloc::vec::Vec;

fn read<T: Copy>(phys: u64) -> T {
    unsafe { phys_to_virt(phys).cast::<T>().read_unaligned() }
}

fn checksum_ok(phys: u64, len: usize) -> bool {
    let bytes = unsafe { core::slice::from_raw_parts(phys_to_virt(phys), len) };
    bytes.iter().fold(0u8, |a, &b| a.wrapping_add(b)) == 0
}

#[derive(Clone, Copy)]
#[repr(C, packed)]
struct SdtHeader {
    signature: [u8; 4],
    length: u32,
    revision: u8,
    checksum: u8,
    oem_id: [u8; 6],
    oem_table_id: [u8; 8],
    oem_revision: u32,
    creator_id: u32,
    creator_revision: u32,
}

/// Physical addresses of every table the root table lists.
fn tables(rsdp: u64) -> Vec<u64> {
    let mut out = Vec::new();
    if rsdp == 0 || read::<[u8; 8]>(rsdp) != *b"RSD PTR " || !checksum_ok(rsdp, 20) {
        crate::warn!("acpi: no valid RSDP");
        return out;
    }
    let revision: u8 = read(rsdp + 15);
    let (root, entry_size) = if revision >= 2 && read::<u64>(rsdp + 24) != 0 {
        (read::<u64>(rsdp + 24), 8)
    } else {
        (read::<u32>(rsdp + 16) as u64, 4)
    };
    let header: SdtHeader = read(root);
    if !checksum_ok(root, header.length as usize) {
        crate::warn!("acpi: root table checksum is wrong");
        return out;
    }
    let count = (header.length as usize - size_of::<SdtHeader>()) / entry_size;
    for i in 0..count {
        let at = root + size_of::<SdtHeader>() as u64 + (i * entry_size) as u64;
        out.push(if entry_size == 8 {
            read::<u64>(at)
        } else {
            read::<u32>(at) as u64
        });
    }
    out
}

fn find(rsdp: u64, signature: &[u8; 4]) -> Option<u64> {
    tables(rsdp).into_iter().find(|&t| {
        let h: SdtHeader = read(t);
        h.signature == *signature && checksum_ok(t, h.length as usize)
    })
}

/// Local APIC IDs of the usable processors, from the MADT.
pub fn processor_apic_ids(rsdp: u64) -> Vec<u32> {
    let mut ids = Vec::new();
    let Some(madt) = find(rsdp, b"APIC") else {
        crate::warn!("acpi: no MADT");
        return ids;
    };
    let len = read::<SdtHeader>(madt).length as u64;
    let mut at = madt + size_of::<SdtHeader>() as u64 + 8; // local APIC address, flags
    while at + 2 <= madt + len {
        let (kind, entry_len): (u8, u8) = (read(at), read(at + 1));
        if entry_len < 2 {
            break;
        }
        match kind {
            // Processor local APIC: enabled, or can be brought online.
            0 if read::<u32>(at + 4) & 0b11 != 0 => ids.push(read::<u8>(at + 3) as u32),
            // Processor local x2APIC.
            9 if read::<u32>(at + 8) & 0b11 != 0 => ids.push(read::<u32>(at + 4)),
            _ => {}
        }
        at += entry_len as u64;
    }
    ids.dedup();
    ids
}

/// An I/O APIC: (physical address, first global system interrupt).
pub struct IoApicInfo {
    pub address: u64,
    pub gsi_base: u32,
}

/// An ISA interrupt the firmware wired differently: (ISA IRQ, global
/// system interrupt, MPS INTI flags: polarity in bits 0-1, trigger in 2-3).
pub struct Override {
    pub irq: u8,
    pub gsi: u32,
    pub flags: u16,
}

/// The I/O APICs and interrupt source overrides the MADT lists.
pub fn io_apics(rsdp: u64) -> (Vec<IoApicInfo>, Vec<Override>) {
    let (mut apics, mut overrides) = (Vec::new(), Vec::new());
    let Some(madt) = find(rsdp, b"APIC") else {
        return (apics, overrides);
    };
    let len = read::<SdtHeader>(madt).length as u64;
    let mut at = madt + size_of::<SdtHeader>() as u64 + 8;
    while at + 2 <= madt + len {
        let (kind, entry_len): (u8, u8) = (read(at), read(at + 1));
        if entry_len < 2 {
            break;
        }
        match kind {
            1 => apics.push(IoApicInfo {
                address: read::<u32>(at + 4) as u64,
                gsi_base: read(at + 8),
            }),
            2 => overrides.push(Override {
                irq: read(at + 3),
                gsi: read(at + 4),
                flags: read(at + 8),
            }),
            _ => {}
        }
        at += entry_len as u64;
    }
    (apics, overrides)
}

static RSDP: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// Remembers where the ACPI tables are (for power off).
pub fn set_rsdp(rsdp: u64) {
    RSDP.store(rsdp, core::sync::atomic::Ordering::Relaxed);
}

/// The sleep type values of `\_S5_` (soft off) from the DSDT's AML:
/// `Name(_S5_, Package(){a, b, ...})`. Returns (SLP_TYPa, SLP_TYPb).
fn s5_sleep_types(dsdt: u64) -> Option<(u16, u16)> {
    let len = read::<SdtHeader>(dsdt).length as usize;
    let aml = unsafe { core::slice::from_raw_parts(phys_to_virt(dsdt), len) };
    let at = aml.windows(4).position(|w| w == b"_S5_")?;
    let mut p = at + 4;
    if *aml.get(p)? != 0x12 {
        return None; // not a PackageOp
    }
    p += 1;
    p += 1 + (aml[p] >> 6) as usize; // PkgLength
    p += 1; // NumElements
    let mut value = || -> Option<u16> {
        let op = *aml.get(p)?;
        p += 1;
        Some(match op {
            0x0a => {
                p += 1;
                aml[p - 1] as u16 // BytePrefix
            }
            0x00 => 0, // ZeroOp
            0x01 => 1, // OneOp
            v => v as u16,
        })
    };
    let a = value()?;
    let b = value().unwrap_or(0);
    Some((a, b))
}

/// Turns the machine off through ACPI (sleep state S5). Returns only if
/// that is not possible.
pub fn power_off() {
    use super::x86;
    let rsdp = RSDP.load(core::sync::atomic::Ordering::Relaxed);
    let Some(fadt) = find(rsdp, b"FACP") else {
        return;
    };
    let flen = read::<SdtHeader>(fadt).length;
    let smi_cmd = read::<u32>(fadt + 48) as u16;
    let acpi_enable: u8 = read(fadt + 52);
    let pm1a = read::<u32>(fadt + 64) as u16;
    let pm1b = read::<u32>(fadt + 68) as u16;
    let dsdt = if flen >= 148 && read::<u64>(fadt + 140) != 0 {
        read::<u64>(fadt + 140)
    } else {
        read::<u32>(fadt + 40) as u64
    };
    let Some((typa, typb)) = s5_sleep_types(dsdt) else {
        crate::warn!("acpi: no \\_S5_ sleep state");
        return;
    };
    unsafe {
        // ACPI mode on (SCI_EN), if the firmware left it off.
        if x86::inw(pm1a) & 1 == 0 && smi_cmd != 0 && acpi_enable != 0 {
            x86::outb(smi_cmd, acpi_enable);
            for _ in 0..1_000_000 {
                if x86::inw(pm1a) & 1 != 0 {
                    break;
                }
            }
        }
        const SLP_EN: u16 = 1 << 13;
        x86::outw(pm1a, (typa << 10) | SLP_EN);
        if pm1b != 0 {
            x86::outw(pm1b, (typb << 10) | SLP_EN);
        }
    }
    // Give the chipset a moment.
    for _ in 0..100 {
        super::apic::delay_us(10_000);
    }
}
