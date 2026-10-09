// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Devices the kernel drives, from `litebox_hal`, for the broker
//! ([`litebox_broker_vm_kernel::Config`]):
//!
//! - Runner processes' standard streams: a virtio console if there is one,
//!   else output to the serial console and no input.
//! - Events: the console's interrupt, and the PIT for deadlines.
//!
//! The interrupt handler only masks the IRQ (the platform records the
//! vector); the kernel services the device and unmasks it when it next polls
//! or halts.

use alloc::boxed::Box;
use core::sync::atomic::{AtomicBool, Ordering};
use litebox_broker_core::readiness::{ReadinessRegistration, ReadinessWatchers};
use litebox_broker_core::stdio::{
    StdioOutputStream, StdioProvider, StdioProviderError, StdioStream,
};
use litebox_broker_protocol::readiness::ReadinessFlags;
use litebox_hal::virtio::console::VirtioConsole;
use litebox_hal::{interrupt, timer};
use litebox_platform_vm_kernel::VmKernel;
use spin::Mutex;

/// How long a console write may wait for the device to take output before
/// the rest is dropped.
const WRITE_TIMEOUT_NANOS: u64 = 100_000_000;

/// See `litebox_platform_vm_kernel::set_interrupt_handler`: no locks, no
/// per-CPU data. The IRQ stays masked until [`Devices::acknowledge`].
fn on_interrupt(vector: u8) -> bool {
    let Some(irq) = interrupt::irq(vector) else {
        return false;
    };
    interrupt::mask_and_acknowledge(irq);
    true
}

struct Console {
    device: Mutex<VirtioConsole>,
    irq: Option<u8>,
    /// Standard-input files, to wake when input arrives.
    stdin_watchers: Mutex<ReadinessWatchers>,
    /// Whether input was pending when last looked at; watchers are woken
    /// when it starts to be.
    stdin_readable: AtomicBool,
}

impl Console {
    fn readable(&self) -> bool {
        self.device.lock().has_input()
    }
}

pub struct Devices {
    platform: &'static VmKernel,
    tsc_khz: u64,
    console: Option<Console>,
}

impl Devices {
    /// Brings up the devices and enables their interrupts. Call once.
    pub fn init(platform: &'static VmKernel, tsc_khz: u64) -> &'static Self {
        litebox_platform_vm_kernel::set_interrupt_handler(on_interrupt);
        timer::disarm();
        interrupt::unmask(timer::IRQ);
        let console = match VirtioConsole::probe(platform) {
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
                let irq = device.transport().irq();
                litebox_util_log::info!(
                    pci:% = device.transport().function(),
                    irq:? = irq;
                    "virtio console: standard streams"
                );
                if let Some(irq) = irq {
                    interrupt::unmask(irq);
                }
                Some(Console {
                    device: Mutex::new(device),
                    irq,
                    stdin_watchers: Mutex::new(ReadinessWatchers::default()),
                    stdin_readable: AtomicBool::new(false),
                })
            }
        };
        Box::leak(Box::new(Self {
            platform,
            tsc_khz,
            console,
        }))
    }

    /// Acknowledges recorded interrupts at their devices and unmasks them.
    fn acknowledge(&self) {
        let pending = self.platform.take_pending_interrupts();
        if let Some(console) = &self.console
            && let Some(irq) = console.irq
            && pending.contains(interrupt::vector(irq))
        {
            // Before unmasking, or the line would still be asserted.
            console.device.lock().transport().acknowledge_interrupt();
        }
        for irq in pending.iter().filter_map(interrupt::irq) {
            interrupt::unmask(irq);
        }
    }

    /// Halts until an interrupt, or until `deadline` (TSC).
    fn halt(&self, deadline: Option<u64>) {
        if let Some(deadline) = deadline {
            let now = rdtsc();
            if now >= deadline {
                return;
            }
            let nanos = u128::from(deadline - now) * 1_000_000 / u128::from(self.tsc_khz);
            timer::arm_oneshot(u64::try_from(nanos).unwrap_or(u64::MAX));
        }
        self.platform.halt_until_interrupt();
        if deadline.is_some() {
            timer::disarm();
        }
        self.acknowledge();
    }
}

fn rdtsc() -> u64 {
    // Safety: RDTSC has no side effects.
    unsafe { core::arch::x86_64::_rdtsc() }
}

impl litebox_broker_vm_kernel::Events for Devices {
    fn poll(&self) {
        self.acknowledge();
        // Wake watchers when input starts to be pending.
        if let Some(console) = &self.console {
            let readable = console.readable();
            if readable && !console.stdin_readable.swap(true, Ordering::Relaxed) {
                console.stdin_watchers.lock().publish(ReadinessFlags::READ);
            } else if !readable {
                console.stdin_readable.store(false, Ordering::Relaxed);
            }
        }
    }

    fn wait(&self, deadline: Option<u64>) -> bool {
        let interrupts = self
            .console
            .as_ref()
            .is_some_and(|console| console.irq.is_some());
        if deadline.is_none() && !interrupts {
            return false;
        }
        self.halt(deadline);
        self.poll();
        true
    }
}

/// Standard streams over [`Devices`]. Never a terminal. Without a console,
/// standard input is at its end.
pub struct Stdio(pub &'static Devices);

impl StdioProvider for Stdio {
    fn read(&self, output: &mut [u8]) -> Result<usize, StdioProviderError> {
        let Some(console) = &self.0.console else {
            return Ok(0);
        };
        match console.device.lock().read(output) {
            0 => Err(StdioProviderError::WouldBlock),
            read => Ok(read),
        }
    }

    /// Waits (bounded) for the console to take all of `input`.
    fn write(&self, _stream: StdioOutputStream, input: &[u8]) -> Result<usize, StdioProviderError> {
        let Some(console) = &self.0.console else {
            litebox_hal::console::print_bytes(input);
            return Ok(input.len());
        };
        let deadline = rdtsc() + WRITE_TIMEOUT_NANOS * self.0.tsc_khz / 1_000_000;
        let mut written = 0;
        loop {
            written += console.device.lock().write(&input[written..]);
            if written == input.len() || rdtsc() >= deadline {
                break;
            }
            // Until the device returns a transmit buffer.
            self.0.halt(Some(deadline));
        }
        if written == 0 {
            return Err(StdioProviderError::WouldBlock);
        }
        Ok(written)
    }

    fn is_terminal(&self, _stream: StdioStream) -> bool {
        false
    }

    fn readiness(&self, stream: StdioStream) -> ReadinessFlags {
        match stream {
            StdioStream::Stdin => match &self.0.console {
                Some(console) if !console.readable() => ReadinessFlags(0),
                _ => ReadinessFlags::READ,
            },
            StdioStream::Stdout | StdioStream::Stderr => ReadinessFlags::WRITE,
        }
    }

    fn watch(
        &self,
        stream: StdioStream,
        registration: &ReadinessRegistration,
    ) -> litebox_broker_core::Result<()> {
        if let (StdioStream::Stdin, Some(console)) = (stream, &self.0.console) {
            console.stdin_watchers.lock().watch(registration)?;
            if console.readable() {
                registration.publish(ReadinessFlags::READ)?;
            }
        }
        Ok(())
    }
}
