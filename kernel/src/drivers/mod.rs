//! Device drivers. Each speaks to one kind of hardware and hands what it
//! gets to the rest of the kernel (input to the terminal, for now).

pub mod ps2kbd;

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
}
