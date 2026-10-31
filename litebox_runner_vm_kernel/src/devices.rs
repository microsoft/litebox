// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Devices the kernel drives, from `litebox_hal`, for the broker
//! ([`litebox_broker_vm_kernel::Config`]) and processes:
//!
//! - [`Console`]: the VM's console device, else output to the serial port
//!   and no input.
//! - [`Network`]: the VM's network device, if any.
//! - [`Vsock`]: the VM's socket device (virtio-vsock), if any, for the
//!   broker's vsock sockets.
//! - [`Events`]: the devices' interrupt, and the local APIC's timer for
//!   deadlines.
//! - [`ProcessTimer`]: the same timer, while a process runs, for its
//!   `SetTimer` deadline and time slice.
//! - [`Devices::shares`]: the VM's virtio-9p devices, each a host directory
//!   mounted at its tag.
//! - [`InterruptController`]: the local APICs, to start and wake the other
//!   CPUs.
//!
//! Also the wall clock ([`wall_clock`]), for runners.
//!
//! Each CPU has its own local APIC, so its own timer; devices interrupt the
//! boot CPU. The interrupt handler only ends the interrupt, noting a
//! device's for every CPU, waking the other idle ones, and interrupting those
//! whose workers are suspended; the broker looks at the devices when it next
//! runs, which, if the interrupt stopped a process, the shim has it do at
//! once (see `litebox_platform_vm_kernel`). A wake IPI only ends a halt, or
//! has a CPU running a process enter the kernel.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use core::time::Duration;
use litebox_broker_core::stdio::StdioOutputStream;
use litebox_broker_core::vsock::device::{ConnectState, ConnectionId, ConnectionStatus, Vsock};
use litebox_broker_smoltcp::Network;
use litebox_broker_vm_kernel::Events;
use litebox_broker_vm_kernel::share::{Share, Transport, TransportError};
use litebox_broker_vm_kernel::stdio::Console;
use litebox_hal::clock::Clock;
use litebox_hal::devices::{self as hal, ConsoleDevice, NetworkDevice, NinePDevice, VsockDevice};
use litebox_hal::interrupt::{LocalApic, SPURIOUS_VECTORS, StartupIpi};
use litebox_platform::time::{Instant as _, TimeProvider as _};
use litebox_platform_vm_kernel::cpu::{self, CpuId, InterruptController, Ipi, MAX_CPUS};
use litebox_platform_vm_kernel::{Instant, VmKernel, worker};
use litebox_shim_vm_kernel::ProcessTimer;
use spin::Mutex;

/// How long a console write may wait for the device to take output before
/// the rest is dropped.
const WRITE_TIMEOUT: Duration = Duration::from_millis(100);

/// How long a share's server may take to answer a request before the share
/// fails.
const SHARE_TIMEOUT: Duration = Duration::from_secs(30);
/// How often a share waiting for its server is polled, whether or not it
/// interrupts (see [`ShareTransport`]).
const SHARE_POLL_INTERVAL: Duration = Duration::from_millis(1);

/// The local APIC's timer.
const TIMER_VECTOR: u8 = 0x30;

/// Shared by every device: the broker looks at all of them when it runs.
const DEVICE_VECTOR: u8 = 0x31;

/// Ends a halt, or interrupts a process ([`Ipi::Wake`]).
const WAKE_VECTOR: u8 = 0x32;

// So `send_fixed_ipi` cannot panic (it runs in interrupt handlers).
const _: () = {
    assert!(WAKE_VECTOR >= 32);
    let mut i = 0;
    while i < SPURIOUS_VECTORS.len() {
        assert!(WAKE_VECTOR != SPURIOUS_VECTORS[i]);
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
    vsock: Option<Mutex<VsockDevice>>,
    /// Whether the socket device interrupts; else it is polled.
    vsock_interrupts: bool,
    /// Per CPU, what [`ProcessTimer::arm`] last programmed into its timer
    /// (see [`armed`]), so it can skip rewriting it: under KVM each write is
    /// a VM exit, and it rearms before every resume of a process.
    armed: [AtomicU64; MAX_CPUS],
    /// Bit `i`: a device interrupted since CPU `i`'s last
    /// [`Events::take_device_interrupt`], so that each CPU's suspended worker
    /// sees each interrupt.
    device_interrupted: AtomicU64,
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
        let vsock = match VsockDevice::probe(platform, apic.target(DEVICE_VECTOR)) {
            Ok(device) => device,
            Err(error) => {
                litebox_util_log::warn!(error:% = error; "vsock device unusable");
                None
            }
        };
        match &vsock {
            Some(device) => litebox_util_log::info!(device:% = device; "vsock"),
            None => litebox_util_log::info!("no vsock device: no host AF_VSOCK connections"),
        }
        let devices: &'static Self = Box::leak(Box::new(Self {
            platform,
            apic,
            clock,
            console_interrupts: console.interrupts(),
            network_interrupts: network.as_ref().is_some_and(NetworkDevice::interrupts),
            network: network.map(Mutex::new),
            vsock_interrupts: vsock.as_ref().is_some_and(VsockDevice::interrupts),
            vsock: vsock.map(Mutex::new),
            armed: [const { AtomicU64::new(ARMED_UNKNOWN) }; MAX_CPUS],
            device_interrupted: AtomicU64::new(0),
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

    /// The socket device, if any, for the broker's vsock sockets.
    pub fn vsock(&'static self) -> Option<Arc<dyn Vsock>> {
        self.vsock
            .is_some()
            .then(|| Arc::new(VmVsock(self)) as Arc<dyn Vsock>)
    }

    fn vsock_device(&self) -> spin::MutexGuard<'_, VsockDevice> {
        self.vsock
            .as_ref()
            .expect("the broker has vsock sockets only with a device")
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

    /// See `litebox_platform_vm_kernel::set_interrupt_handler`: no locks, no
    /// per-CPU data.
    fn on_interrupt(&self, vector: u8) -> bool {
        match vector {
            // Fired: arming the same deadline again (e.g., after an early
            // fire) must reprogram it. Which CPU's timer it was is per-CPU
            // data: forget them all.
            TIMER_VECTOR => {
                for armed in &self.armed {
                    armed.store(ARMED_UNKNOWN, Ordering::Relaxed);
                }
            }
            // For whichever CPU's worker waits for it: the other idle CPUs
            // step again, and the busy ones whose workers are suspended enter
            // the kernel, to resume them (this one, the boot CPU, is already
            // in, and needs no mark: see the shim's `Inner::worker_due`).
            DEVICE_VECTOR => {
                self.device_interrupted.store(u64::MAX, Ordering::SeqCst);
                cpu::wake_idle(CpuId::BOOT);
                worker::interrupt_suspended(CpuId::BOOT);
            }
            WAKE_VECTOR => {}
            _ => return false,
        }
        self.apic.end_of_interrupt();
        true
    }

    /// The calling CPU's [`Self::armed`].
    fn armed(&self) -> &AtomicU64 {
        &self.armed[cpu::current().index()]
    }

    /// For drivers: waits until a device may have changed (an interrupt) or
    /// `deadline` (to poll one that does not interrupt); then look again. On
    /// the worker (serving broker requests), suspends it, and processes run
    /// meanwhile; elsewhere, halts. Hold no lock the kernel or another CPU
    /// may take meanwhile (see `litebox_platform_vm_kernel::worker`).
    pub fn block(&self, deadline: Option<Instant>) {
        if !litebox_platform_vm_kernel::worker::suspend(deadline) {
            self.halt(deadline);
        }
    }

    /// Halts the calling CPU until an interrupt, or until `deadline`; while
    /// the CPU has a wakeup to acknowledge (see
    /// `litebox_platform_vm_kernel::cpu`), only takes the pending interrupts
    /// ([`cpu::relax`]), without arming the timer (a VM exit under KVM), as
    /// the caller polls meanwhile: until the scheduler acknowledges it, a
    /// driver's waits (e.g., a 9P round trip's) busy-poll, which costs only
    /// CPU time.
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

// Safety: `send_ipi` sends `Init` and `Startup` as the HAL's, and `Wake` as
// a fixed interrupt, to the APIC ID it is given, or nothing (false); and
// `init_cpu` sets up the calling CPU's local APIC only.
unsafe impl InterruptController for Devices {
    fn init_cpu(&self) {
        self.apic.init_cpu();
    }

    unsafe fn send_ipi(&self, apic_id: u32, ipi: Ipi) -> bool {
        let startup = match ipi {
            Ipi::Init => StartupIpi::Init,
            Ipi::Startup { page } => StartupIpi::Startup { page },
            Ipi::Wake => return self.apic.send_fixed_ipi(apic_id, WAKE_VECTOR),
        };
        // Safety: the caller's, as `send_ipi`'s.
        unsafe { self.apic.send_startup_ipi(apic_id, startup) }
    }
}

impl Events for Devices {
    fn wait(&self, deadline: Option<Instant>) -> bool {
        if deadline.is_none()
            && !self.console_interrupts
            && !self.network_interrupts
            && !self.vsock_interrupts
        {
            return false;
        }
        self.halt(deadline);
        true
    }

    fn take_device_interrupt(&self) -> bool {
        let bit = 1 << cpu::current().index();
        // Sequentially consistent, as the handler's store, then load of the
        // suspended works, and this CPU's noting its own suspended before:
        // so either this sees the store, or the handler interrupts this CPU.
        self.device_interrupted.load(Ordering::SeqCst) & bit != 0
            && self.device_interrupted.fetch_and(!bit, Ordering::SeqCst) & bit != 0
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
            written += self.console.lock().write(&input[written..]);
            if written == input.len() || self.platform.now() >= deadline {
                return written;
            }
            // Until the device takes more output.
            self.block(Some(deadline));
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

/// The VM's socket device ([`VsockDevice`]), each call holding its lock only
/// for itself. The device holds at most the credit it gives the host of
/// unread data per connection, and sends as much as the host has credit for.
/// It refuses the guest's connects beyond
/// [`MAX_USER_CONNECTIONS`](litebox_hal::virtio::vsock::MAX_USER_CONNECTIONS),
/// keeping the rest of its connections for the host's requests. A transport
/// reset fails the connects in progress, ends the live connections, and may
/// change the guest's CID. A closed connection stays until the host resets
/// it.
struct VmVsock(&'static Devices);

impl Vsock for VmVsock {
    fn guest_cid(&self) -> u64 {
        self.0.vsock_device().guest_cid()
    }

    fn take_request(&self) -> Option<ConnectionId> {
        self.0.vsock_device().take_request().map(broker_id)
    }

    fn accept(&self, id: ConnectionId) -> bool {
        self.0.vsock_device().accept(device_id(id))
    }

    fn refuse(&self, id: ConnectionId) {
        self.0.vsock_device().refuse(device_id(id));
    }

    fn connect(&self, id: ConnectionId) -> bool {
        self.0.vsock_device().connect(device_id(id))
    }

    fn connect_state(&self, id: ConnectionId) -> ConnectState {
        match self.0.vsock_device().connect_state(device_id(id)) {
            hal::ConnectState::Connecting => ConnectState::Connecting,
            hal::ConnectState::Established => ConnectState::Established,
            hal::ConnectState::Failed => ConnectState::Failed,
        }
    }

    fn read(&self, id: ConnectionId, output: &mut [u8]) -> Option<usize> {
        self.0.vsock_device().read(device_id(id), output)
    }

    fn write(&self, id: ConnectionId, bytes: &[u8]) -> Option<usize> {
        self.0.vsock_device().write(device_id(id), bytes)
    }

    fn status(&self, id: ConnectionId) -> ConnectionStatus {
        let hal::ConnectionStatus {
            readable,
            host_sending_ended,
            writable,
        } = self.0.vsock_device().status(device_id(id));
        ConnectionStatus {
            readable,
            host_sending_ended,
            writable,
        }
    }

    fn shutdown_sending(&self, id: ConnectionId) {
        self.0.vsock_device().shutdown_sending(device_id(id));
    }

    fn shutdown_receiving(&self, id: ConnectionId) {
        self.0.vsock_device().shutdown_receiving(device_id(id));
    }

    fn close(&self, id: ConnectionId) {
        self.0.vsock_device().close(device_id(id));
    }

    fn is_closed(&self, id: ConnectionId) -> bool {
        self.0.vsock_device().is_closed(device_id(id))
    }

    fn forget(&self, id: ConnectionId) {
        self.0.vsock_device().forget(device_id(id));
    }

    fn take_backlog(&self) -> bool {
        self.0.vsock_device().take_backlog()
    }

    fn interrupts(&self) -> bool {
        self.0.vsock_interrupts
    }
}

fn device_id(id: ConnectionId) -> hal::ConnectionId {
    hal::ConnectionId {
        guest_port: id.guest_port,
        host_port: id.host_port,
    }
}

fn broker_id(id: hal::ConnectionId) -> ConnectionId {
    ConnectionId {
        guest_port: id.guest_port,
        host_port: id.host_port,
    }
}

/// A share's virtio-9p device: a request at a time, waiting for its response
/// in [`Devices::halt`], not [`Devices::block`]: the 9P client holds its lock
/// across the round trip, and while the worker is suspended, the kernel may
/// take it (e.g., ending another process's association closes its files),
/// which nothing on that CPU would release. Polled even if it interrupts:
/// its interrupt goes to the boot CPU, which wakes this one for it (see
/// [`Devices::on_interrupt`]) only as it takes interrupts, which it may not
/// for a while, running kernel code (e.g., creating or freeing a process's
/// address space, or spinning for a spin lock).
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
        if self.failed || !self.device.transmit(request) {
            return Err(TransportError);
        }
        let platform = self.devices.platform;
        let deadline = platform
            .now()
            .checked_add(SHARE_TIMEOUT)
            .expect("the clock is far from overflowing");
        loop {
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
            // Until the device returns the request; nothing else runs on this
            // CPU meanwhile (and, while the CPU has a wakeup to acknowledge,
            // this polls).
            let wake = match now.checked_add(SHARE_POLL_INTERVAL) {
                Some(poll) if poll < deadline => poll,
                _ => deadline,
            };
            self.devices.halt(Some(wake));
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
