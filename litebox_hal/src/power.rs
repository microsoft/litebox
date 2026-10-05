// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Power: exit or reset the machine.

/// See [`exit`]; also written by boot stubs before Rust runs.
pub const DEBUG_EXIT_PORT: u16 = 0xf4;

const DEBUG_EXIT_SUCCESS: u32 = 0x10;
pub const DEBUG_EXIT_FAILURE: u32 = 0x20;

/// Through QEMU's `isa-debug-exit` device
/// (`-device isa-debug-exit,iobase=0xf4,iosize=0x04`): QEMU exits with status
/// `(value << 1) | 1`. Without the device, the machine resets instead (use
/// `-no-reboot` to make QEMU exit).
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
