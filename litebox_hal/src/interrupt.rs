// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Interrupt controllers: the legacy 8259 PICs.

const LEGACY_PIC_VECTOR_BASE: u8 = 0x20;

/// PIC IRQ7/IRQ15 can arrive while masked; SeaBIOS leaves LAPIC SVR at 0xff.
pub const SPURIOUS_VECTORS: [u8; 3] = [
    LEGACY_PIC_VECTOR_BASE + 7,
    LEGACY_PIC_VECTOR_BASE + 15,
    0xff,
];

/// Must precede user entry (IF=1). PVH's PIC vectors overlap CPU exceptions.
pub fn init_legacy_pics() {
    use x86_64::instructions::port::Port;
    const MASTER_CMD: u16 = 0x20;
    const MASTER_DATA: u16 = 0x21;
    const SLAVE_CMD: u16 = 0xa0;
    const SLAVE_DATA: u16 = 0xa1;
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
