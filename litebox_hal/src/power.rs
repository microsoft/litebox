// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Power: exit or reset the machine.

/// See [`exit`]; also written by boot stubs before Rust runs.
pub const DEBUG_EXIT_PORT: u16 = 0xf4;

const DEBUG_EXIT_SUCCESS: u32 = 0x10;
pub const DEBUG_EXIT_FAILURE: u32 = 0x20;

/// Printed by [`exit`], for VMMs whose exit status does not tell (e.g.,
/// Cloud Hypervisor).
pub const EXIT_SUCCESS_LINE: &str = "[litebox] exit: success";
pub const EXIT_FAILURE_LINE: &str = "[litebox] exit: failure";

/// About 0.3-1 s: a VMM may power off asynchronously (e.g., QEMU).
const SOFT_OFF_TIMEOUT_CYCLES: u64 = 1 << 30;

const PM1_SLP_TYP_SHIFT: u16 = 10;
const PM1_SLP_TYP: u16 = 0b111 << PM1_SLP_TYP_SHIFT;
const PM1_SLP_EN: u16 = 1 << 13;

/// How to enter ACPI's S5 sleep state (soft off): see
/// [`crate::acpi::soft_off`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SoftOff {
    /// Hardware-reduced ACPI (e.g., Cloud Hypervisor).
    SleepControl { port: u16, value: u8 },
    /// `(port, sleep type)` of PM1a and PM1b, if any (e.g., QEMU).
    Pm1 { a: (u16, u8), b: Option<(u16, u8)> },
}

impl SoftOff {
    /// As ACPICA: the sleep types first, then `SLP_EN`.
    fn enter(self) {
        use x86_64::instructions::port::Port;
        match self {
            // Safety: the firmware's sleep register, for this write.
            Self::SleepControl { port, value } => unsafe { Port::<u8>::new(port).write(value) },
            Self::Pm1 { a, b } => {
                let mut typed = [None; 2];
                for (block, typed) in [Some(a), b].into_iter().zip(&mut typed) {
                    let Some((port, sleep_type)) = block else {
                        continue;
                    };
                    let mut register = Port::<u16>::new(port);
                    // Safety: the firmware's PM1 control register, of which
                    // only the sleep type and enable bits change.
                    let value = (unsafe { register.read() } & !(PM1_SLP_TYP | PM1_SLP_EN))
                        | ((u16::from(sleep_type) << PM1_SLP_TYP_SHIFT) & PM1_SLP_TYP);
                    // Safety: as above.
                    unsafe { register.write(value) };
                    *typed = Some((port, value));
                }
                for (port, value) in typed.into_iter().flatten() {
                    // Safety: as above.
                    unsafe { Port::<u16>::new(port).write(value | PM1_SLP_EN) };
                }
            }
        }
    }
}

static SOFT_OFF: spin::Once<SoftOff> = spin::Once::new();

/// Has [`exit`] enter S5 this way; later calls are ignored.
pub fn set_soft_off(soft_off: SoftOff) {
    SOFT_OFF.call_once(|| soft_off);
}

/// Through QEMU's `isa-debug-exit` device
/// (`-device isa-debug-exit,iobase=0xf4,iosize=0x04`): QEMU exits with status
/// `(value << 1) | 1`. Without the device, enters S5 (see [`set_soft_off`]),
/// else resets the machine (use `-no-reboot` to make QEMU exit). Usable in
/// panic handlers.
pub fn exit(success: bool) -> ! {
    let (value, line) = if success {
        (DEBUG_EXIT_SUCCESS, EXIT_SUCCESS_LINE)
    } else {
        (DEBUG_EXIT_FAILURE, EXIT_FAILURE_LINE)
    };
    crate::serial::panic_print(format_args!("{line}\n"));
    // Safety: a port write to the debug-exit device (or to nothing).
    unsafe {
        x86_64::instructions::port::Port::<u32>::new(DEBUG_EXIT_PORT).write(value);
    }
    if let Some(soft_off) = SOFT_OFF.get() {
        soft_off.enter();
        let start = crate::clock::now();
        while crate::clock::now() - start < SOFT_OFF_TIMEOUT_CYCLES {
            core::hint::spin_loop();
        }
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
