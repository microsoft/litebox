// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Devices the kernel drives, from `litebox_hal`, for the broker
//! ([`litebox_broker_vm_kernel::Config`]) and processes:
//!
//! - [`Console`]: the VM's console device, else output to the serial port
//!   and no input.
//! - [`Link`]: the VM's network device, if any.
//! - [`Events`]: the devices' interrupt, and the local APIC's timer for
//!   deadlines.
//! - [`ProcessTimer`]: the same timer, while a process runs, for its
//!   `SetTimer` deadline.
//!
//! Also the wall clock ([`wall_clock`]), for runners.
//!
//! The interrupt handler only ends the interrupt; the broker looks at the
//! devices when it next runs. A device interrupt also fires the timer at
//! once, so that the shim of a process running meanwhile runs the broker
//! ([`Events::interrupted`]).

use alloc::boxed::Box;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use core::time::Duration;
use litebox_broker_core::stdio::StdioOutputStream;
use litebox_broker_vm_kernel::Events;
use litebox_broker_vm_kernel::Link;
use litebox_broker_vm_kernel::stdio::Console;
use litebox_hal::clock::Clock;
use litebox_hal::devices::{ConsoleDevice, NetworkDevice};
use litebox_hal::interrupt::LocalApic;
use litebox_platform::time::{Instant as _, TimeProvider as _};
use litebox_platform_vm_kernel::{Instant, VmKernel};
use litebox_shim_vm_kernel::ProcessTimer;
use spin::Mutex;

/// How long a console write may wait for the device to take output before
/// the rest is dropped.
const WRITE_TIMEOUT: Duration = Duration::from_millis(100);

/// Shared by every device: the broker looks at all of them when it runs.
const DEVICE_VECTOR: u8 = 0x31;

/// [`Devices::armed`]: the timer is in a state no deadline matches.
const ARMED_UNKNOWN: u64 = u64::MAX;

pub struct Devices {
    platform: &'static VmKernel,
    apic: LocalApic,
    clock: Clock,
    console: Mutex<ConsoleDevice>,
    /// Whether the console interrupts; else it is polled.
    console_interrupts: bool,
    /// A device interrupted since the broker last looked; see
    /// [`Events::interrupted`].
    interrupted: AtomicBool,
    network: Option<&'static Nic>,
    /// What [`ProcessTimer::arm`] last programmed into the timer (see
    /// [`armed`]), so it can skip rewriting it: under KVM each write is a VM
    /// exit, and it rearms before every resume of a process.
    armed: AtomicU64,
}

/// [`Devices::armed`]'s value for `deadline`: zero for none (the instant zero,
/// long passed, is the same as 1 ns).
fn armed(deadline: Option<Instant>) -> u64 {
    deadline.map_or(0, |deadline| deadline.as_nanos().max(1))
}

impl Devices {
    /// Brings up the devices and enables their interrupts. Call once.
    pub fn init(platform: &'static VmKernel, clock: Clock) -> &'static Self {
        // The platform's timer vector: a fire while a process runs also
        // reaches the shim (see `ProcessTimer::arm`).
        let apic = LocalApic::init(platform, litebox_platform_vm_kernel::TIMER_VECTOR, clock);
        let console = match ConsoleDevice::probe(platform, apic.target(DEVICE_VECTOR)) {
            Ok(Some(device)) => device,
            Ok(None) => ConsoleDevice::serial(),
            Err(error) => {
                litebox_util_log::warn!(error:% = error; "console device unusable");
                ConsoleDevice::serial()
            }
        };
        litebox_util_log::info!(device:% = console; "standard streams");
        let network = match NetworkDevice::probe(platform, apic.target(DEVICE_VECTOR)) {
            Ok(device) => device,
            Err(error) => {
                litebox_util_log::warn!(error:% = error; "network device unusable");
                None
            }
        };
        match &network {
            Some(device) => litebox_util_log::info!(device:% = device; "network"),
            None => litebox_util_log::info!("no network device: sockets stay in the guest"),
        }
        let network = network.map(|device| -> &'static Nic {
            Box::leak(Box::new(Nic {
                mac: device.mac(),
                interrupts: device.interrupts(),
                device: Mutex::new(device),
            }))
        });
        let devices: &'static Self = Box::leak(Box::new(Self {
            platform,
            apic,
            clock,
            console_interrupts: console.interrupts(),
            interrupted: AtomicBool::new(false),
            network,
            armed: AtomicU64::new(ARMED_UNKNOWN),
            console: Mutex::new(console),
        }));
        litebox_platform_vm_kernel::set_interrupt_handler(Box::leak(Box::new(|vector| {
            devices.on_interrupt(vector)
        })));
        devices
    }

    /// The network device, for the broker's sockets.
    pub fn network(&self) -> Option<&'static dyn Link> {
        self.network.map(|nic| -> &'static dyn Link { nic })
    }

    /// See `litebox_platform_vm_kernel::set_interrupt_handler`: no locks, no
    /// per-CPU data.
    fn on_interrupt(&self, vector: u8) -> bool {
        if !matches!(
            vector,
            litebox_platform_vm_kernel::TIMER_VECTOR | DEVICE_VECTOR
        ) {
            return false;
        }
        if vector == DEVICE_VECTOR {
            // For the broker, even while a process runs: firing the timer at
            // once enters the process's shim, which runs the broker (see
            // `Events::interrupted`). In a halt, it only ends the halt.
            self.interrupted.store(true, Ordering::Relaxed);
            self.apic.arm_timer(0);
        }
        // Fired, or replaced: arming the same deadline again (e.g., after an
        // early fire) must reprogram it.
        self.armed.store(ARMED_UNKNOWN, Ordering::Relaxed);
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
            self.armed.store(armed(None), Ordering::Relaxed);
        }
    }
}

impl Events for Devices {
    fn wait(&self, deadline: Option<Instant>) -> bool {
        let network_interrupts = self.network.is_some_and(|nic| nic.interrupts);
        if deadline.is_none() && !self.console_interrupts && !network_interrupts {
            return false;
        }
        self.halt(deadline);
        true
    }

    fn interrupted(&self) -> bool {
        self.interrupted.load(Ordering::Relaxed)
    }

    fn clear_interrupted(&self) {
        self.interrupted.store(false, Ordering::Relaxed);
    }
}

impl ProcessTimer for Devices {
    /// Shares the same one-shot timer as [`Self::halt`]: a bounded halt
    /// replaces the deadline and disarms the timer afterward (the process
    /// re-arms it as it resumes), and one without a deadline keeps it, so it
    /// may end such a halt early (harmless: waits recheck). Writes the timer
    /// only when the deadline changed, or it fired since.
    fn arm(&self, deadline: Option<Instant>) {
        if self.armed.swap(armed(deadline), Ordering::Relaxed) == armed(deadline) {
            return;
        }
        match deadline {
            Some(deadline) => self
                .apic
                .arm_timer(self.clock.ticks_at(deadline.as_nanos())),
            None => self.apic.disarm_timer(),
        }
    }
}

/// The wall clock from kvm-clock, else
/// [`WallClock::EPOCH_AT_BOOT`](litebox_common_vm_abi::WallClock::EPOCH_AT_BOOT).
pub fn wall_clock(platform: &'static VmKernel, clock: Clock) -> litebox_common_vm_abi::WallClock {
    let Some((unix_ns, ticks)) = litebox_hal::kvmclock::wall_clock(platform) else {
        litebox_util_log::info!("no kvm-clock: runners' wall clock starts at the Unix epoch");
        return litebox_common_vm_abi::WallClock::EPOCH_AT_BOOT;
    };
    litebox_util_log::info!(unix_seconds:% = unix_ns / 1_000_000_000; "wall clock");
    litebox_common_vm_abi::WallClock {
        unix_ns,
        at: clock.nanos_at(ticks),
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

/// The network device, shared by the broker's stack.
pub struct Nic {
    device: Mutex<NetworkDevice>,
    mac: [u8; 6],
    interrupts: bool,
}

impl Link for Nic {
    fn mac(&self) -> [u8; 6] {
        self.mac
    }

    fn receive(&self, frame: &mut [u8]) -> Option<usize> {
        self.device.lock().receive(frame)
    }

    fn can_transmit(&self) -> bool {
        self.device.lock().can_transmit()
    }

    fn transmit(&self, frame: &[u8]) -> bool {
        self.device.lock().transmit(frame)
    }

    fn interrupts(&self) -> bool {
        self.interrupts
    }
}
