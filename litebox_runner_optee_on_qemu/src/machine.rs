// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! QEMU machine control. Power-off needs
//! `-device isa-debug-exit,iobase=0xf4,iosize=0x04`.

const DEBUG_EXIT_PORT: u16 = 0xf4;

/// Written on success; QEMU exits with status 33.
const DEBUG_EXIT_SUCCESS: u32 = 0x10;
/// Written on failure; QEMU exits with status 65.
const DEBUG_EXIT_FAILURE: u32 = 0x20;

/// QEMU exits with status `(value << 1) | 1`. Without the device the machine
/// resets instead (use `-no-reboot` to make QEMU exit).
pub fn exit(success: bool) -> ! {
    let value = if success {
        DEBUG_EXIT_SUCCESS
    } else {
        DEBUG_EXIT_FAILURE
    };
    // Safety: a port write to the debug-exit device (or to nothing).
    unsafe {
        x86_64::instructions::port::Port::<u32>::new(DEBUG_EXIT_PORT).write(value);
    }
    reset()
}

/// Triple fault: with an empty IDT, the next exception shuts the machine down.
fn reset() -> ! {
    let empty = x86_64::structures::DescriptorTablePointer {
        limit: 0,
        base: x86_64::VirtAddr::zero(),
    };
    // Safety: deliberately unrecoverable; nothing runs after this.
    unsafe { x86_64::instructions::tables::lidt(&empty) };
    x86_64::instructions::interrupts::int3();
    loop {
        x86_64::instructions::hlt();
    }
}

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
