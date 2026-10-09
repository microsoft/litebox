// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Interrupt controllers: the legacy 8259 PICs.
//!
//! Handlers mask their IRQ ([`mask_and_acknowledge`]) until the device is
//! serviced ([`unmask`]), as a level-triggered (PCI) line stays asserted
//! until then. Call with interrupts disabled: masks are read-modify-write.

use x86_64::instructions::port::Port;

const LEGACY_PIC_VECTOR_BASE: u8 = 0x20;

const MASTER_CMD: u16 = 0x20;
const MASTER_DATA: u16 = 0x21;
const SLAVE_CMD: u16 = 0xa0;
const SLAVE_DATA: u16 = 0xa1;
const CASCADE_IRQ: u8 = 2;
const EOI: u8 = 0x20;

/// The vector of PIC IRQ `irq` (0..16).
pub const fn vector(irq: u8) -> u8 {
    LEGACY_PIC_VECTOR_BASE + irq
}

/// The PIC IRQ behind `vector`, if it is a PIC vector.
pub const fn irq(vector: u8) -> Option<u8> {
    if vector >= LEGACY_PIC_VECTOR_BASE && vector < LEGACY_PIC_VECTOR_BASE + 16 {
        Some(vector - LEGACY_PIC_VECTOR_BASE)
    } else {
        None
    }
}

/// PIC IRQ7/IRQ15 can arrive while masked; SeaBIOS leaves LAPIC SVR at 0xff.
pub const SPURIOUS_VECTORS: [u8; 3] = [
    LEGACY_PIC_VECTOR_BASE + 7,
    LEGACY_PIC_VECTOR_BASE + 15,
    0xff,
];

/// Must precede user entry (IF=1). PVH's PIC vectors overlap CPU exceptions.
pub fn init_legacy_pics() {
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

/// The mask register and bit of `irq`.
fn mask_register(irq: u8) -> (Port<u8>, u8) {
    assert!(irq < 16, "PIC IRQs are 0..16");
    if irq < 8 {
        (Port::new(MASTER_DATA), 1 << irq)
    } else {
        (Port::new(SLAVE_DATA), 1 << (irq - 8))
    }
}

/// Lets `irq` interrupt (when IF=1); an IRQ on the slave also needs the
/// cascade.
pub fn unmask(irq: u8) {
    let (mut port, bit) = mask_register(irq);
    // Safety: only the PICs' mask registers change; nothing else drives the
    // PICs, and the caller excludes interleaving (see the module docs).
    unsafe {
        let mask = port.read();
        port.write(mask & !bit);
    }
    if irq >= 8 {
        unmask(CASCADE_IRQ);
    }
}

/// For interrupt handlers: masks `irq` until it is serviced, then ends the
/// interrupt at the PICs (non-specific EOI, to both PICs for a slave IRQ).
pub fn mask_and_acknowledge(irq: u8) {
    let (mut port, bit) = mask_register(irq);
    // Safety: as in `unmask`; an EOI only clears the PIC's in-service bit.
    unsafe {
        let mask = port.read();
        port.write(mask | bit);
        if irq >= 8 {
            Port::<u8>::new(SLAVE_CMD).write(EOI);
        }
        Port::<u8>::new(MASTER_CMD).write(EOI);
    }
}
