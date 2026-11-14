//! The CMOS real-time clock: the date and time at boot, for
//! `CLOCK_REALTIME`. Read once; the TSC counts from there.

use super::x86;

const INDEX: u16 = 0x70;
const DATA: u16 = 0x71;

fn read(reg: u8) -> u8 {
    unsafe {
        // Bit 7 keeps NMIs disabled while we talk to the chip.
        x86::outb(INDEX, 0x80 | reg);
        x86::inb(DATA)
    }
}

fn updating() -> bool {
    read(0x0a) & 0x80 != 0
}

#[derive(PartialEq, Eq, Clone, Copy)]
struct Raw([u8; 7]);

fn raw() -> Raw {
    while updating() {
        core::hint::spin_loop();
    }
    Raw([
        read(0x00), // seconds
        read(0x02), // minutes
        read(0x04), // hours
        read(0x07), // day of month
        read(0x08), // month
        read(0x09), // year (two digits)
        read(0x32), // century, where present (ACPI FADT names it; 0x32 is usual)
    ])
}

fn bcd(v: u8) -> u8 {
    (v & 0x0f) + (v >> 4) * 10
}

/// Seconds since 1970-01-01 00:00:00 UTC (the RTC is assumed to keep UTC,
/// as Linux assumes by default), 0 if the clock reads as nonsense.
pub fn unix_time() -> u64 {
    // Read until two reads agree, so an update in between cannot tear it.
    let mut r = raw();
    loop {
        let again = raw();
        if again == r {
            break;
        }
        r = again;
    }
    let status_b = read(0x0b);
    let is_bcd = status_b & 0x04 == 0;
    let h24 = status_b & 0x02 != 0;
    let conv = |v: u8| if is_bcd { bcd(v) } else { v };
    let [s, m, h, d, mo, y, c] = r.0;
    let pm = h & 0x80 != 0;
    let mut hour = conv(h & 0x7f) as u64;
    if !h24 {
        hour %= 12;
        if pm {
            hour += 12;
        }
    }
    let century = match conv(c) {
        19..=21 => conv(c) as u64,
        _ => 20,
    };
    let year = century * 100 + conv(y) as u64;
    let (month, day) = (conv(mo) as u64, conv(d) as u64);
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) || year < 1970 {
        return 0;
    }
    days_from_civil(year, month, day) * 86400 + hour * 3600 + conv(m) as u64 * 60 + conv(s) as u64
}

/// Days from 1970-01-01 to the given date (proleptic Gregorian calendar;
/// Howard Hinnant's algorithm).
fn days_from_civil(y: u64, m: u64, d: u64) -> u64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y / 400;
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}
