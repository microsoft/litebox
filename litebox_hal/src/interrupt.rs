// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Interrupt controllers: the legacy 8259 PICs.

/// IRQ `n` of the legacy PICs is vector `LEGACY_PIC_VECTOR_BASE + n`.
pub const LEGACY_PIC_VECTOR_BASE: u8 = 0x20;

const MASTER_CMD: u16 = 0x20;
const MASTER_DATA: u16 = 0x21;
const SLAVE_CMD: u16 = 0xa0;
const SLAVE_DATA: u16 = 0xa1;
const EOI: u8 = 0x20;

/// PIC IRQ7/IRQ15 can arrive while masked; SeaBIOS leaves LAPIC SVR at 0xff.
pub const SPURIOUS_VECTORS: [u8; 3] = [
    LEGACY_PIC_VECTOR_BASE + 7,
    LEGACY_PIC_VECTOR_BASE + 15,
    0xff,
];

/// Must precede user entry (IF=1). PVH's PIC vectors overlap CPU exceptions.
pub fn init_legacy_pics() {
    use x86_64::instructions::port::Port;
    const ICW1_INIT_ICW4: u8 = 0x11; // edge-triggered, cascade, ICW4 follows
    const ICW4_8086: u8 = 0x01;
    // Safety: the standard 8259 initialization sequence; nothing else drives
    // the PICs, and interrupts are still disabled.
    unsafe {
        Port::<u8>::new(MASTER_CMD).write(ICW1_INIT_ICW4);
        Port::<u8>::new(SLAVE_CMD).write(ICW1_INIT_ICW4);
        Port::<u8>::new(MASTER_DATA).write(LEGACY_PIC_VECTOR_BASE); // ICW2: vector base
        Port::<u8>::new(SLAVE_DATA).write(LEGACY_PIC_VECTOR_BASE + 8);
        Port::<u8>::new(MASTER_DATA).write(1 << 2); // ICW3: slave on IRQ2
        Port::<u8>::new(SLAVE_DATA).write(2); // ICW3: cascade identity
        Port::<u8>::new(MASTER_DATA).write(ICW4_8086);
        Port::<u8>::new(SLAVE_DATA).write(ICW4_8086);
        Port::<u8>::new(MASTER_DATA).write(0xff);
        Port::<u8>::new(SLAVE_DATA).write(0xff);
    }
}

/// Unmasks legacy IRQ `irq` (0..16); for its sole driver. Unmasking a slave
/// IRQ also unmasks the cascade (IRQ2).
///
/// # Panics
///
/// If `irq` is not below 16.
pub fn unmask_legacy_irq(irq: u8) {
    use x86_64::instructions::port::Port;
    assert!(irq < 16, "no legacy IRQ {irq}");
    let unmask = |port: u16, bit: u8| {
        let mut data = Port::<u8>::new(port);
        // Safety: read-modify-write of a PIC's interrupt mask; interrupts are
        // disabled in the kernel, so nothing races it.
        unsafe {
            let mask = data.read();
            data.write(mask & !(1 << bit));
        }
    };
    if irq < 8 {
        unmask(MASTER_DATA, irq);
    } else {
        unmask(SLAVE_DATA, irq - 8);
        unmask(MASTER_DATA, 2);
    }
}

/// Acknowledges legacy IRQ `irq` (non-specific EOI).
pub fn end_of_legacy_irq(irq: u8) {
    use x86_64::instructions::port::Port;
    // Safety: an EOI only ends the PIC's in-service interrupt.
    unsafe {
        if irq >= 8 {
            Port::<u8>::new(SLAVE_CMD).write(EOI);
        }
        Port::<u8>::new(MASTER_CMD).write(EOI);
    }
}
