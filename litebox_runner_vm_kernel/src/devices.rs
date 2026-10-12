// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Devices the kernel drives, from `litebox_hal`, for the broker
//! ([`litebox_broker_vm_kernel::Config`]):
//!
//! - [`Console`]: the VM's console device, else output to the serial port
//!   and no input.
//! - [`Events`]: the devices' interrupt, and the local APIC's timer for
//!   deadlines.
//!
//! The interrupt handler only ends the interrupt; the broker looks at the
//! devices when it next runs.

use alloc::boxed::Box;
use core::time::Duration;
use litebox_broker_core::stdio::StdioOutputStream;
use litebox_broker_vm_kernel::Events;
use litebox_broker_vm_kernel::stdio::Console;
use litebox_hal::clock::Clock;
use litebox_hal::devices::ConsoleDevice;
use litebox_hal::interrupt::LocalApic;
use litebox_platform::time::{Instant as _, TimeProvider as _};
use litebox_platform_vm_kernel::{Instant, VmKernel};
use spin::Mutex;

/// How long a console write may wait for the device to take output before
/// the rest is dropped.
const WRITE_TIMEOUT: Duration = Duration::from_millis(100);

const TIMER_VECTOR: u8 = 0x30;
/// Shared by every device: the broker looks at all of them when it runs.
const DEVICE_VECTOR: u8 = 0x31;

pub struct Devices {
    platform: &'static VmKernel,
    apic: LocalApic,
    clock: Clock,
    console: Mutex<ConsoleDevice>,
    /// Whether the console interrupts; else it is polled.
    console_interrupts: bool,
}

impl Devices {
    /// Brings up the devices and enables their interrupts. Call once.
    pub fn init(platform: &'static VmKernel, clock: Clock) -> &'static Self {
        let apic = LocalApic::init(platform, TIMER_VECTOR, clock);
        let console = match ConsoleDevice::probe(platform, apic.target(DEVICE_VECTOR)) {
            Ok(Some(device)) => device,
            Ok(None) => ConsoleDevice::serial(),
            Err(error) => {
                litebox_util_log::warn!(error:% = error; "console device unusable");
                ConsoleDevice::serial()
            }
        };
        litebox_util_log::info!(device:% = console; "standard streams");
        let devices: &'static Self = Box::leak(Box::new(Self {
            platform,
            apic,
            clock,
            console_interrupts: console.interrupts(),
            console: Mutex::new(console),
        }));
        litebox_platform_vm_kernel::set_interrupt_handler(Box::leak(Box::new(|vector| {
            devices.on_interrupt(vector)
        })));
        devices
    }

    /// See `litebox_platform_vm_kernel::set_interrupt_handler`: no locks, no
    /// per-CPU data.
    fn on_interrupt(&self, vector: u8) -> bool {
        if !matches!(vector, TIMER_VECTOR | DEVICE_VECTOR) {
            return false;
        }
        self.apic.end_of_interrupt();
        true
    }

    /// Halts until an interrupt, or until `deadline`.
    fn halt(&self, deadline: Option<Instant>) {
        if let Some(deadline) = deadline {
            self.apic
                .arm_timer(self.clock.ticks_at(deadline.as_nanos()));
        }
        self.platform.halt_until_interrupt();
        if deadline.is_some() {
            self.apic.disarm_timer();
        }
    }
}

impl Events for Devices {
    fn wait(&self, deadline: Option<Instant>) -> bool {
        if deadline.is_none() && !self.console_interrupts {
            return false;
        }
        self.halt(deadline);
        true
    }
}

/// A console that receives nothing is at the end of its input.
impl Console for Devices {
    fn read(&self, output: &mut [u8]) -> Option<usize> {
        let mut console = self.console.lock();
        console.receives().then(|| console.read(output))
    }

    fn has_input(&self) -> bool {
        let mut console = self.console.lock();
        !console.receives() || console.has_input()
    }

    /// Waits (bounded) for the device to take all of `input`; both streams
    /// share it.
    fn write(&self, _stream: StdioOutputStream, input: &[u8]) -> usize {
        let deadline = self
            .platform
            .now()
            .checked_add(WRITE_TIMEOUT)
            .expect("the clock is far from overflowing");
        let mut written = 0;
        loop {
            written += self.console.lock().write(&input[written..]);
            if written == input.len() || self.platform.now() >= deadline {
                return written;
            }
            // Until the device takes more output.
            self.halt(Some(deadline));
        }
    }
}
