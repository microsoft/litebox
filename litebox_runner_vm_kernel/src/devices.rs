// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Devices the kernel drives, from `litebox_hal`, for the broker
//! ([`litebox_broker_vm_kernel::Config`]):
//!
//! - [`Console`]: a virtio console if there is one, else output to the
//!   serial console and no input.
//! - [`Events`]: the console's interrupt (MSI-X), and the local APIC's timer
//!   for deadlines.
//!
//! The interrupt handler only ends the interrupt; the broker looks at the
//! devices when it next runs.

use alloc::boxed::Box;
use litebox_broker_vm_kernel::Events;
use litebox_broker_vm_kernel::stdio::Console;
use litebox_hal::interrupt::LocalApic;
use litebox_hal::virtio::console::VirtioConsole;
use litebox_platform_vm_kernel::VmKernel;
use spin::Mutex;

/// How long a console write may wait for the device to take output before
/// the rest is dropped.
const WRITE_TIMEOUT_NANOS: u64 = 100_000_000;

const TIMER_VECTOR: u8 = 0x30;
const CONSOLE_VECTOR: u8 = 0x31;

pub struct Devices {
    platform: &'static VmKernel,
    apic: LocalApic,
    tsc_khz: u64,
    console: Option<Mutex<VirtioConsole>>,
    /// Whether the console interrupts; else it is polled.
    console_interrupts: bool,
}

impl Devices {
    /// Brings up the devices and enables their interrupts. Call once.
    pub fn init(platform: &'static VmKernel, tsc_khz: u64) -> &'static Self {
        let apic = LocalApic::init(platform, TIMER_VECTOR, tsc_khz);
        let interrupt = apic.msi_message(CONSOLE_VECTOR);
        let console = match VirtioConsole::probe(platform, Some(interrupt)) {
            None => {
                litebox_util_log::info!(
                    "no virtio console: standard output goes to the serial console"
                );
                None
            }
            Some(Err(error)) => {
                litebox_util_log::warn!(
                    error:% = error;
                    "virtio console unusable: standard output goes to the serial console"
                );
                None
            }
            Some(Ok(device)) => {
                litebox_util_log::info!(
                    pci:% = device.transport().function(),
                    interrupts:% = device.transport().interrupts();
                    "virtio console: standard streams"
                );
                Some(device)
            }
        };
        let devices: &'static Self = Box::leak(Box::new(Self {
            platform,
            apic,
            tsc_khz,
            console_interrupts: console
                .as_ref()
                .is_some_and(|device| device.transport().interrupts()),
            console: console.map(Mutex::new),
        }));
        litebox_platform_vm_kernel::set_interrupt_handler(Box::leak(Box::new(|vector| {
            devices.on_interrupt(vector)
        })));
        devices
    }

    /// See `litebox_platform_vm_kernel::set_interrupt_handler`: no locks, no
    /// per-CPU data.
    fn on_interrupt(&self, vector: u8) -> bool {
        if !matches!(vector, TIMER_VECTOR | CONSOLE_VECTOR) {
            return false;
        }
        self.apic.end_of_interrupt();
        true
    }

    /// Halts until an interrupt, or until `deadline` (TSC).
    fn halt(&self, deadline: Option<u64>) {
        if let Some(deadline) = deadline {
            self.apic.arm_timer(deadline);
        }
        self.platform.halt_until_interrupt();
        if deadline.is_some() {
            self.apic.disarm_timer();
        }
    }
}

fn rdtsc() -> u64 {
    // Safety: RDTSC has no side effects.
    unsafe { core::arch::x86_64::_rdtsc() }
}

impl Events for Devices {
    fn wait(&self, deadline: Option<u64>) -> bool {
        if deadline.is_none() && !self.console_interrupts {
            return false;
        }
        self.halt(deadline);
        true
    }
}

/// Without a virtio console, input is at its end.
impl Console for Devices {
    fn read(&self, output: &mut [u8]) -> Option<usize> {
        Some(self.console.as_ref()?.lock().read(output))
    }

    fn has_input(&self) -> bool {
        self.console
            .as_ref()
            .is_none_or(|device| device.lock().has_input())
    }

    /// Waits (bounded) for the device to take all of `input`.
    fn write(&self, input: &[u8]) -> usize {
        let Some(device) = &self.console else {
            litebox_hal::console::print_bytes(input);
            return input.len();
        };
        let deadline = rdtsc() + WRITE_TIMEOUT_NANOS * self.tsc_khz / 1_000_000;
        let mut written = 0;
        loop {
            written += device.lock().write(&input[written..]);
            if written == input.len() || rdtsc() >= deadline {
                return written;
            }
            // Until the device returns a transmit buffer.
            self.halt(Some(deadline));
        }
    }
}
