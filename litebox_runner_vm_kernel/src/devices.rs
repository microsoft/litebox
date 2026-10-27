// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Devices the kernel drives, from `litebox_hal`, for the broker
//! ([`litebox_broker_vm_kernel::Config`]) and processes:
//!
//! - [`Console`]: the VM's console device, else output to the serial port
//!   and no input.
//! - [`Network`]: the VM's network device, if any.
//! - [`Events`]: the devices' interrupt, and the local APIC's timer for
//!   deadlines.
//! - [`ProcessTimer`]: the same timer, while a process runs, for its
//!   `SetTimer` deadline and time slice.
//! - [`Devices::shares`]: the VM's virtio-9p devices, each a host directory
//!   mounted at its tag.
//! - [`InterruptController`]: the local APICs, to start and wake the other
//!   CPUs, and to have them flush their TLBs.
//!
//! Also the wall clock ([`wall_clock`]), for runners.
//!
//! Each CPU has its own local APIC, so its own timer; devices interrupt the
//! boot CPU. The interrupt handler only ends the interrupt, waking the other
//! idle CPUs, and, for a device's, the broker tasks waiting for one
//! ([`worker::wake_blocked`]); the broker looks at the devices when it next
//! runs, which, if the interrupt stopped a process, the shim has it do at
//! once (see `litebox_platform_vm_kernel`). A wake IPI only ends a halt, or
//! has a CPU running a process enter the kernel. A TLB-flush IPI is only a
//! doorbell: the platform flushes before the handler runs, and a process it
//! interrupted resumes at once.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;
#[cfg(debug_assertions)]
use core::sync::atomic::AtomicBool;
use core::sync::atomic::{AtomicU64, Ordering};
use core::time::Duration;
use litebox_broker_core::stdio::StdioOutputStream;
use litebox_broker_smoltcp::Network;
use litebox_broker_vm_kernel::Events;
use litebox_broker_vm_kernel::share::{Share, Transport, TransportError};
use litebox_broker_vm_kernel::stdio::Console;
use litebox_hal::clock::Clock;
use litebox_hal::devices::{ConsoleDevice, NetworkDevice, NinePDevice};
use litebox_hal::interrupt::{LocalApic, SPURIOUS_VECTORS, StartupIpi};
use litebox_platform::time::{Instant as _, TimeProvider as _};
use litebox_platform_vm_kernel::cpu::{self, CpuId, InterruptController, Ipi, MAX_CPUS};
use litebox_platform_vm_kernel::{Handled, Instant, VmKernel, worker};
use litebox_shim_vm_kernel::ProcessTimer;
use spin::Mutex;

/// How long a console write may wait for the device to take output before
/// the rest is dropped.
const WRITE_TIMEOUT: Duration = Duration::from_millis(100);

/// How long a share's server may take to answer a request before the share
/// fails.
const SHARE_TIMEOUT: Duration = Duration::from_secs(30);
/// How often a device that may not interrupt is polled as something waits
/// for it (see [`ShareTransport`], and the console's writes).
const POLL_INTERVAL: Duration = Duration::from_millis(1);

/// The local APIC's timer.
const TIMER_VECTOR: u8 = 0x30;

/// Shared by every device: the broker looks at all of them when it runs.
const DEVICE_VECTOR: u8 = 0x31;

/// Ends a halt, or interrupts a process ([`Ipi::Wake`]).
const WAKE_VECTOR: u8 = 0x32;

/// Has a CPU flush its TLB ([`Ipi::FlushTlb`]): in the highest priority
/// class, below the spurious vector.
const FLUSH_VECTOR: u8 = 0xf0;

// So `send_fixed_ipi` cannot panic (it runs in interrupt handlers), and each
// vector is handled as one thing.
const _: () = {
    let vectors = [TIMER_VECTOR, DEVICE_VECTOR, WAKE_VECTOR, FLUSH_VECTOR];
    assert!(WAKE_VECTOR >= 32 && FLUSH_VECTOR >= 32);
    let mut i = 0;
    while i < SPURIOUS_VECTORS.len() {
        assert!(WAKE_VECTOR != SPURIOUS_VECTORS[i] && FLUSH_VECTOR != SPURIOUS_VECTORS[i]);
        i += 1;
    }
    let mut i = 0;
    while i < vectors.len() {
        let mut j = i + 1;
        while j < vectors.len() {
            assert!(vectors[i] != vectors[j]);
            j += 1;
        }
        i += 1;
    }
};

/// [`Devices::armed`]: the timer is in a state no deadline matches.
const ARMED_UNKNOWN: u64 = u64::MAX;

pub struct Devices {
    platform: &'static VmKernel,
    apic: LocalApic,
    clock: Clock,
    console: Mutex<ConsoleDevice>,
    /// Whether the console interrupts; else it is polled.
    console_interrupts: bool,
    network: Option<Mutex<NetworkDevice>>,
    /// Whether the network device interrupts; else it is polled.
    network_interrupts: bool,
    /// Per CPU, what [`ProcessTimer::arm`] last programmed into its timer
    /// (see [`armed`]), so it can skip rewriting it: under KVM each write is
    /// a VM exit, and it rearms before every resume of a process.
    armed: [AtomicU64; MAX_CPUS],
    /// Debug builds: whether the runtime began ([`Self::begin_runtime`]).
    #[cfg(debug_assertions)]
    runtime: AtomicBool,
}

/// [`Devices::armed`]'s value for `deadline`: zero for none (the instant zero,
/// long passed, is the same as 1 ns).
fn armed(deadline: Option<Instant>) -> u64 {
    deadline.map_or(0, |deadline| deadline.as_nanos().max(1))
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
        let devices: &'static Self = Box::leak(Box::new(Self {
            platform,
            apic,
            clock,
            console_interrupts: console.interrupts(),
            network_interrupts: network.as_ref().is_some_and(NetworkDevice::interrupts),
            network: network.map(Mutex::new),
            armed: [const { AtomicU64::new(ARMED_UNKNOWN) }; MAX_CPUS],
            #[cfg(debug_assertions)]
            runtime: AtomicBool::new(false),
            console: Mutex::new(console),
        }));
        litebox_platform_vm_kernel::set_interrupt_handler(Box::leak(Box::new(|vector| {
            devices.on_interrupt(vector)
        })));
        devices
    }

    /// The network device, if any, for the broker's sockets.
    pub fn network(&'static self) -> Option<&'static dyn Network> {
        self.network.is_some().then_some(self)
    }

    fn network_device(&self) -> spin::MutexGuard<'_, NetworkDevice> {
        self.network
            .as_ref()
            .expect("the broker has a network only with a device")
            .lock()
    }

    /// The VM's virtio-9p devices, brought up, as shares mounted at their
    /// tags (see [`mount_path`]). Devices that cannot be driven, or whose tag
    /// is not such a path or repeats another's, are skipped. Call once.
    pub fn shares(&'static self) -> Vec<Share> {
        let mut shares: Vec<Share> = Vec::new();
        for probed in NinePDevice::probe_all(self.platform, self.apic.target(DEVICE_VECTOR)) {
            let device = match probed {
                Ok(device) => device,
                Err(error) => {
                    litebox_util_log::warn!(error:% = error; "9P device unusable");
                    continue;
                }
            };
            let Some(path) = device.mount_tag().and_then(mount_path) else {
                litebox_util_log::warn!(
                    device:% = device,
                    tag:? = device.mount_tag().map(String::from_utf8_lossy);
                    "9P device's mount tag is not a path to mount at"
                );
                continue;
            };
            if shares.iter().any(|share| share.path == path) {
                litebox_util_log::warn!(
                    device:% = device,
                    path:% = path;
                    "9P device's mount tag repeats another's"
                );
                continue;
            }
            litebox_util_log::info!(device:% = device, path:% = path; "share");
            shares.push(Share {
                path,
                transport: Box::new(ShareTransport {
                    devices: self,
                    device,
                    failed: false,
                }),
            });
        }
        shares
    }

    /// Debug builds: begins the runtime, once the broker mounted the shares,
    /// before the first process is spawned. Processes may run from then on,
    /// so only tasks may make the shares' 9P round trips (see
    /// [`ShareTransport`]): checked from then on, for good (e.g., as the last
    /// processes' broker processes drop), on every CPU, which sees this before
    /// it runs a process, as the scheduler publishes processes under its lock.
    /// Call once.
    #[cfg(debug_assertions)]
    pub fn begin_runtime(&self) {
        assert!(
            !self.runtime.swap(true, Ordering::Release),
            "the runtime begins once"
        );
    }

    /// See `litebox_platform_vm_kernel::set_interrupt_handler`: no locks, no
    /// per-CPU data.
    fn on_interrupt(&self, vector: u8) -> Handled {
        match vector {
            // Fired: arming the same deadline again (e.g., after an early
            // fire) must reprogram it. Which CPU's timer it was is per-CPU
            // data: forget them all.
            TIMER_VECTOR => {
                for armed in &self.armed {
                    armed.store(ARMED_UNKNOWN, Ordering::Relaxed);
                }
            }
            // For whatever waits for it: the other idle CPUs step again
            // (e.g., for their threads' waits), and the broker tasks are due,
            // their busy CPUs interrupted (this one, the boot CPU, looks at
            // its own: see the shim's `sched`).
            DEVICE_VECTOR => {
                cpu::wake_idle(CpuId::BOOT);
                worker::wake_blocked(CpuId::BOOT);
            }
            WAKE_VECTOR => {}
            FLUSH_VECTOR => {
                self.apic.end_of_interrupt();
                return Handled::Doorbell;
            }
            _ => return Handled::Unexpected,
        }
        self.apic.end_of_interrupt();
        Handled::Event
    }

    /// The calling CPU's [`Self::armed`].
    fn armed(&self) -> &AtomicU64 {
        &self.armed[cpu::current().index()]
    }

    /// For drivers: waits until a device may have changed (an interrupt) or
    /// `deadline` (to poll one that does not interrupt); then look again.
    /// `seen` is [`worker::wakes`] as read before the last look. On a task
    /// (serving broker requests), suspends it, and processes run meanwhile;
    /// elsewhere, halts. Hold no spin lock meanwhile (see [`worker`]).
    pub fn block(&self, seen: u64, deadline: Option<Instant>) {
        if !worker::suspend(worker::Wait::event(seen, deadline)) {
            self.halt(deadline);
        }
    }

    /// Halts the calling CPU until an interrupt, or until `deadline`; while
    /// the CPU has a wakeup to acknowledge (see
    /// `litebox_platform_vm_kernel::cpu`), only takes the pending interrupts
    /// ([`cpu::relax`]), without arming the timer (a VM exit under KVM), as
    /// the caller polls meanwhile: until the scheduler acknowledges it, a
    /// driver's waits off a task (e.g., a 9P round trip's, as a share is
    /// mounted) busy-poll, which costs only CPU time.
    fn halt(&self, deadline: Option<Instant>) {
        if cpu::marked() {
            cpu::relax();
            return;
        }
        if let Some(deadline) = deadline {
            self.apic
                .arm_timer(self.clock.ticks_at(deadline.as_nanos()));
        }
        self.platform.halt_until_interrupt();
        if deadline.is_some() {
            self.apic.disarm_timer();
            self.armed().store(armed(None), Ordering::Relaxed);
        }
    }
}

// Safety: `send_ipi` sends `Init` and `Startup` as the HAL's, and `Wake` and
// `FlushTlb` as fixed interrupts, to the APIC ID it is given, or nothing
// (false); and `init_cpu` sets up the calling CPU's local APIC only.
unsafe impl InterruptController for Devices {
    fn init_cpu(&self) {
        self.apic.init_cpu();
    }

    unsafe fn send_ipi(&self, apic_id: u32, ipi: Ipi) -> bool {
        let startup = match ipi {
            Ipi::Init => StartupIpi::Init,
            Ipi::Startup { page } => StartupIpi::Startup { page },
            Ipi::Wake => return self.apic.send_fixed_ipi(apic_id, WAKE_VECTOR),
            Ipi::FlushTlb => return self.apic.send_fixed_ipi(apic_id, FLUSH_VECTOR),
        };
        // Safety: the caller's, as `send_ipi`'s.
        unsafe { self.apic.send_startup_ipi(apic_id, startup) }
    }
}

impl Events for Devices {
    fn wait(&self, deadline: Option<Instant>) -> bool {
        if deadline.is_none() && !self.console_interrupts && !self.network_interrupts {
            return false;
        }
        self.halt(deadline);
        true
    }
}

impl ProcessTimer for Devices {
    /// The calling CPU's timer, which its [`Self::halt`]s share: a bounded
    /// halt replaces the deadline and disarms the timer afterward (the process
    /// re-arms it as it resumes), and one without a deadline keeps it, so it
    /// may end such a halt early (harmless: waits recheck). Writes the timer
    /// only when the deadline changed, or it fired since.
    fn arm(&self, deadline: Option<Instant>) {
        if self.armed().swap(armed(deadline), Ordering::Relaxed) == armed(deadline) {
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
            // Before looking (see `worker::Wait`).
            let seen = worker::wakes();
            written += self.console.lock().write(&input[written..]);
            let now = self.platform.now();
            if written == input.len() || now >= deadline {
                return written;
            }
            // Until the device takes more output: it interrupts then, or is
            // polled.
            let wake = match now.checked_add(POLL_INTERVAL) {
                Some(poll) if !self.console_interrupts && poll < deadline => poll,
                _ => deadline,
            };
            self.block(seen, Some(wake));
        }
    }
}

impl Network for Devices {
    fn mac(&self) -> [u8; 6] {
        self.network_device().mac()
    }

    fn receive(&self, frame: &mut [u8]) -> Option<usize> {
        self.network_device().receive(frame)
    }

    fn can_transmit(&self) -> bool {
        self.network_device().can_transmit()
    }

    fn transmit(&self, frame: &[u8]) -> bool {
        self.network_device().transmit(frame)
    }

    fn interrupts(&self) -> bool {
        self.network_interrupts
    }
}

/// A share's virtio-9p device: a request at a time, waiting for its response
/// in [`Devices::block`], which, on a task (serving a request), suspends it:
/// the 9P client holds its lock across the round trip, which only tasks take
/// once processes run (see `litebox_broker_vm_kernel`; debug builds check it
/// from `Devices::begin_runtime` on), and suspend for; elsewhere (mounting
/// the share at boot), it halts the CPU. Polled even if it
/// interrupts: its interrupt goes to the boot CPU, which makes the tasks due
/// for it (see [`Devices::on_interrupt`]) only as it takes interrupts, which
/// it may not for a while, running kernel code (e.g., creating or freeing a
/// process's address space, or spinning for a spin lock).
struct ShareTransport {
    devices: &'static Devices,
    device: NinePDevice,
    /// A request timed out, and the device may still answer it: the share is
    /// no longer used.
    failed: bool,
}

impl Transport for ShareTransport {
    fn max_message_size(&self) -> usize {
        NinePDevice::MAX_MESSAGE_SIZE
    }

    fn round_trip(&mut self, request: &[u8], response: &mut [u8]) -> Result<usize, TransportError> {
        #[cfg(debug_assertions)]
        assert!(
            !self.devices.runtime.load(Ordering::Acquire) || worker::on_task(),
            "a 9P round trip off any task once processes may run (see `ShareTransport`)"
        );
        if self.failed || !self.device.transmit(request) {
            return Err(TransportError);
        }
        let platform = self.devices.platform;
        let deadline = platform
            .now()
            .checked_add(SHARE_TIMEOUT)
            .expect("the clock is far from overflowing");
        loop {
            // Before looking (see `worker::Wait`).
            let seen = worker::wakes();
            if let Some(len) = self.device.receive(response) {
                return Ok(len);
            }
            let now = platform.now();
            if now >= deadline {
                litebox_util_log::warn!(
                    device:% = self.device;
                    "9P server did not answer; share failed"
                );
                self.failed = true;
                return Err(TransportError);
            }
            // Until the device may have returned the request: it interrupts
            // then, or is polled.
            let wake = match now.checked_add(POLL_INTERVAL) {
                Some(poll) if poll < deadline => poll,
                _ => deadline,
            };
            self.devices.block(seen, Some(wake));
        }
    }
}

/// A mount tag as the path to mount its share at, if the broker can: its
/// `Composer` panics on paths that are not absolute and normalized, and `/`
/// and `/dev` (with what is under it) are reserved. Tags come from the host.
fn mount_path(tag: &[u8]) -> Option<String> {
    let path = core::str::from_utf8(tag).ok()?;
    let mut components = path.strip_prefix('/')?.split('/');
    let valid = components
        .clone()
        .all(|component| !matches!(component, "" | "." | ".."))
        && components.next() != Some("dev");
    valid.then(|| String::from(path))
}
