//! GUID partition tables (UEFI specification, chapter 5).

use super::{BlockDevice, SECTOR_SIZE};
use crate::abi::{Errno, KResult};
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

pub struct GptPartition {
    /// 1-based, the entry's position in the table.
    pub number: u32,
    pub type_guid: [u8; 16],
    pub first_lba: u64,
    pub last_lba: u64,
    pub name: String,
}

/// The EFI system partition's type GUID, as stored on disk.
pub const ESP_TYPE: [u8; 16] = [
    0x28, 0x73, 0x2a, 0xc1, 0x1f, 0xf8, 0xd2, 0x11, 0xba, 0x4b, 0x00, 0xa0, 0xc9, 0x3e, 0xc9, 0x3b,
];

fn u32_at(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes(b[o..o + 4].try_into().unwrap())
}

fn u64_at(b: &[u8], o: usize) -> u64 {
    u64::from_le_bytes(b[o..o + 8].try_into().unwrap())
}

/// CRC-32 (IEEE 802.3, reflected), as GPT uses.
pub fn crc32(data: &[u8]) -> u32 {
    let mut crc = !0u32;
    for &b in data {
        crc ^= b as u32;
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0xedb8_8320
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

/// Reads the primary GPT (header at LBA 1), checking both CRCs.
pub fn read(disk: &dyn BlockDevice) -> KResult<Vec<GptPartition>> {
    let mut hdr = vec![0u8; SECTOR_SIZE];
    disk.read_sectors(1, &mut hdr)?;
    if &hdr[0..8] != b"EFI PART" {
        return Err(Errno::EINVAL);
    }
    let hdr_size = u32_at(&hdr, 12) as usize;
    if !(92..=SECTOR_SIZE).contains(&hdr_size) {
        return Err(Errno::EINVAL);
    }
    let mut check = hdr[..hdr_size].to_vec();
    check[16..20].fill(0);
    if crc32(&check) != u32_at(&hdr, 16) {
        return Err(Errno::EINVAL);
    }
    let entries_lba = u64_at(&hdr, 72);
    let count = u32_at(&hdr, 80) as usize;
    let entry_size = u32_at(&hdr, 84) as usize;
    if entry_size < 128 || count > 1024 {
        return Err(Errno::EINVAL);
    }
    let bytes = (count * entry_size).next_multiple_of(SECTOR_SIZE);
    let mut table = vec![0u8; bytes];
    disk.read_sectors(entries_lba, &mut table)?;
    if crc32(&table[..count * entry_size]) != u32_at(&hdr, 88) {
        return Err(Errno::EINVAL);
    }
    let mut out = Vec::new();
    for i in 0..count {
        let e = &table[i * entry_size..(i + 1) * entry_size];
        let type_guid: [u8; 16] = e[0..16].try_into().unwrap();
        if type_guid == [0; 16] {
            continue;
        }
        let (first_lba, last_lba) = (u64_at(e, 32), u64_at(e, 40));
        if first_lba > last_lba || last_lba >= disk.sector_count() {
            continue;
        }
        let name: String = char::decode_utf16(
            e[56..128]
                .chunks(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .take_while(|&c| c != 0),
        )
        .map(|c| c.unwrap_or('?'))
        .collect();
        out.push(GptPartition {
            number: i as u32 + 1,
            type_guid,
            first_lba,
            last_lba,
            name,
        });
    }
    Ok(out)
}
