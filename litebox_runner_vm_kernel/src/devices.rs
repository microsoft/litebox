// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Devices the kernel drives, from `litebox_hal`, for the broker
//! ([`litebox_broker_vm_kernel::Config`]) and processes:
//!
//! - [`Console`]: the VM's console device, else output to the serial port
//!   and no input.
//! - [`Network`]: the VM's network device, if any.
//! - [`VsockTransport`]: the VM's socket device (virtio-vsock), if any, for
//!   the broker's vsock sockets.
//! - [`Events`]: the devices' interrupt, and the local APIC's timer for
//!   deadlines.
//! - [`ProcessTimer`]: the same timer, while a process runs, for its
//!   `SetTimer` deadline and time slice.
//! - [`Devices::shares`]: the VM's virtio-fs devices, each a host directory
//!   mounted at its tag.
//! - [`InterruptController`]: the local APICs, to start and wake the other
//!   CPUs, and to have them flush their TLBs.
//!
//! Also the wall clock ([`wall_clock`]), for runners.
//!
//! Each CPU has its own local APIC, so its own timer; devices interrupt the
//! boot CPU. The interrupt handler only ends the interrupt, noting a device's
//! for every CPU and waking the other idle ones; the broker looks at the
//! devices when it next runs, which, if the interrupt stopped a process, the
//! shim has it do at once (see `litebox_platform_vm_kernel`). A wake IPI only
//! ends a halt, or has a CPU running a process enter the kernel. A TLB-flush
//! IPI is only a doorbell: the platform flushes before the handler runs, and a
//! process it interrupted resumes at once.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicU64, Ordering};
use core::time::Duration;
use litebox_broker_core::fs::fuse::transport as fuse;
use litebox_broker_core::stdio::StdioOutputStream;
use litebox_broker_core::vsock_socket::transport::{
    ConnectState, ConnectionId, ConnectionStatus, VsockTransport,
};
use litebox_broker_protocol::vsock_socket::VsockPort;
use litebox_broker_smoltcp::Network;
use litebox_broker_vm_kernel::Events;
use litebox_broker_vm_kernel::share::Share;
use litebox_broker_vm_kernel::stdio::Console;
use litebox_hal::clock::Clock;
use litebox_hal::devices::{self as hal, ConsoleDevice, FuseDevice, NetworkDevice, VsockDevice};
use litebox_hal::interrupt::{LocalApic, SPURIOUS_VECTORS, StartupIpi};
use litebox_hal::virtio::fs::Shared as FuseShared;
use litebox_platform::buffer::RawBytes;
use litebox_platform::time::{Instant as _, TimeProvider as _};
use litebox_platform_vm_kernel::cpu::{self, CpuId, InterruptController, Ipi, MAX_CPUS};
use litebox_platform_vm_kernel::preempt::{KernelMutex, KernelMutexGuard};
use litebox_platform_vm_kernel::{Handled, Instant, VmKernel};
use litebox_shim_vm_kernel::ProcessTimer;

/// How long a share's server may take to answer a request before the share
/// fails.
const SHARE_TIMEOUT: Duration = Duration::from_secs(30);
/// How often a share waiting for its server is polled, whether or not it
/// interrupts (see [`FuseShare`]).
const SHARE_POLL_INTERVAL: Duration = Duration::from_millis(1);

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

/// Printed once the vsock device runs, for host tools to connect only then: vhost-device-vsock
/// (0.3.0) stops serving the device on a connection made while QEMU starts it.
pub const VSOCK_STARTED: &str = "[litebox] vsock device started";

pub struct Devices {
    platform: &'static VmKernel,
    apic: LocalApic,
    clock: Clock,
    /// The devices' locks are kernel-grade: the broker drives them from code
    /// that runs with interrupts enabled.
    console: KernelMutex<ConsoleDevice>,
    /// Whether the console interrupts; else it is polled.
    console_interrupts: bool,
    network: Option<KernelMutex<NetworkDevice>>,
    /// Whether the network device interrupts; else it is polled.
    network_interrupts: bool,
    vsock: Option<KernelMutex<VsockDevice>>,
    /// Whether the socket device interrupts; else it is polled.
    vsock_interrupts: bool,
    /// Per CPU, what [`ProcessTimer::arm`] last programmed into its timer
    /// (see [`armed`]), so it can skip rewriting it: under KVM each write is
    /// a VM exit, and it rearms before every resume of a process.
    armed: [AtomicU64; MAX_CPUS],
    /// Bit `i`: a device interrupted since CPU `i`'s last
    /// [`Events::take_device_interrupt`].
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
            Some(device) => {
                litebox_util_log::info!(device:% = device; "vsock");
                litebox_hal::serial_println!("{VSOCK_STARTED}");
            }
            None => litebox_util_log::info!("no vsock device: no host AF_VSOCK connections"),
        }
        let devices: &'static Self = Box::leak(Box::new(Self {
            platform,
            apic,
            clock,
            console_interrupts: console.interrupts(),
            network_interrupts: network.as_ref().is_some_and(NetworkDevice::interrupts),
            network: network.map(KernelMutex::new),
            vsock_interrupts: vsock.as_ref().is_some_and(VsockDevice::interrupts),
            vsock: vsock.map(KernelMutex::new),
            armed: [const { AtomicU64::new(ARMED_UNKNOWN) }; MAX_CPUS],
            device_interrupted: AtomicU64::new(0),
            console: KernelMutex::new(console),
        }));
        litebox_platform_vm_kernel::set_interrupt_handler(Box::leak(Box::new(|cpu, vector| {
            devices.on_interrupt(cpu, vector)
        })));
        devices
    }

    /// Waits, up to a second, until the host took the console's output, lost at power-off.
    pub fn drain_console(&self) {
        const TIMEOUT: Duration = Duration::from_secs(1);
        let deadline = self
            .platform
            .now()
            .checked_add(TIMEOUT)
            .expect("the clock is far from overflowing");
        while !self.console.lock().is_drained() && self.platform.now() < deadline {
            cpu::relax();
        }
    }

    /// The network device, if any, for the broker's sockets.
    pub fn network(&'static self) -> Option<&'static dyn Network> {
        self.network.is_some().then_some(self)
    }

    fn network_device(&self) -> KernelMutexGuard<'_, NetworkDevice> {
        self.network
            .as_ref()
            .expect("the broker has a network only with a device")
            .lock()
    }

    /// The socket device, if any, for the broker's vsock sockets.
    pub fn vsock(&'static self) -> Option<Arc<dyn VsockTransport>> {
        self.vsock
            .is_some()
            .then(|| Arc::new(VmVsock(self)) as Arc<dyn VsockTransport>)
    }

    fn vsock_device(&self) -> KernelMutexGuard<'_, VsockDevice> {
        self.vsock
            .as_ref()
            .expect("the broker has vsock sockets only with a device")
            .lock()
    }

    /// The VM's virtio-fs devices, brought up, as shares mounted at their
    /// tags (see [`mount_path`]). Devices that cannot be driven, or whose tag
    /// is not such a path or repeats another's, are skipped. Call once.
    pub fn shares(&'static self) -> Vec<Share> {
        let target = self.apic.target(DEVICE_VECTOR);
        let mut shares: Vec<Share> = Vec::new();
        for probed in FuseDevice::probe_all(self.platform, target) {
            let device = match probed {
                Ok(device) => device,
                Err(error) => {
                    litebox_util_log::warn!(error:% = error; "virtio-fs device unusable");
                    continue;
                }
            };
            let Some(path) = mount_path(device.tag()) else {
                litebox_util_log::warn!(
                    device:% = device,
                    tag:? = String::from_utf8_lossy(device.tag());
                    "virtio-fs device's tag is not a path to mount at"
                );
                continue;
            };
            if shares.iter().any(|share| share.path == path) {
                litebox_util_log::warn!(
                    device:% = device,
                    path:% = path;
                    "virtio-fs device's tag repeats another's"
                );
                continue;
            }
            litebox_util_log::info!(device:% = device, path:% = path; "share");
            let transport = Box::new(FuseShare {
                devices: self,
                device,
                failed: false,
            });
            shares.push(Share { path, transport });
        }
        shares
    }

    /// Polls `done` until it has a result, for at most [`SHARE_TIMEOUT`]:
    /// `None` if it has none by then. Waits in [`Self::halt`] between polls.
    fn wait_for_share<R>(&self, mut done: impl FnMut() -> Option<R>) -> Option<R> {
        let platform = self.platform;
        let deadline = platform
            .now()
            .checked_add(SHARE_TIMEOUT)
            .expect("the clock is far from overflowing");
        loop {
            if let Some(result) = done() {
                return Some(result);
            }
            let now = platform.now();
            if now >= deadline {
                return None;
            }
            // Until the device answers; nothing else runs on this CPU
            // meanwhile (and, while the CPU has a wakeup to acknowledge, this
            // polls).
            let wake = match now.checked_add(SHARE_POLL_INTERVAL) {
                Some(poll) if poll < deadline => poll,
                _ => deadline,
            };
            self.halt(Some(wake));
        }
    }

    /// See `litebox_platform_vm_kernel::set_interrupt_handler`: no locks, no
    /// per-CPU data.
    fn on_interrupt(&self, cpu: CpuId, vector: u8) -> Handled {
        match vector {
            // Fired: arming the same deadline again (e.g., after an early
            // fire) must reprogram it. Only `cpu`'s: another CPU's timer may
            // still be armed for an earlier deadline.
            TIMER_VECTOR => self.armed[cpu.index()].store(ARMED_UNKNOWN, Ordering::Relaxed),
            // The other idle CPUs step again, to poll the devices (this one,
            // the boot CPU, is already in).
            DEVICE_VECTOR => {
                self.device_interrupted.store(u64::MAX, Ordering::SeqCst);
                cpu::wake_idle(CpuId::BOOT);
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

    /// Debug builds: whether the calling CPU's timer was last disarmed, and not
    /// armed or fired since.
    #[cfg(debug_assertions)]
    pub(crate) fn timer_disarmed(&self) -> bool {
        self.armed().load(Ordering::Relaxed) == armed(None)
    }

    /// Halts the calling CPU until an interrupt, or until `deadline`; while
    /// the CPU has a wakeup to acknowledge (see
    /// `litebox_platform_vm_kernel::cpu`), only takes the pending interrupts
    /// ([`cpu::relax`]), without arming the timer (a VM exit under KVM), as
    /// the caller polls meanwhile: until the scheduler acknowledges it, a
    /// driver's waits (e.g., a FUSE round trip's) busy-poll, which costs only
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

    /// `armed(None)` and [`ARMED_UNKNOWN`] both mean that none is armed.
    fn arm_if_earlier(&self, deadline: Instant) {
        let armed_now = self.armed().load(Ordering::Relaxed);
        if armed_now != armed(None)
            && armed_now != ARMED_UNKNOWN
            && armed_now <= armed(Some(deadline))
        {
            return;
        }
        self.arm(Some(deadline));
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

    /// One attempt; both streams share the device.
    fn write(&self, _stream: StdioOutputStream, input: &[u8]) -> usize {
        self.console.lock().write(input)
    }

    fn can_write(&self) -> bool {
        self.console.lock().can_write()
    }

    fn interrupts(&self) -> bool {
        self.console_interrupts
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

/// The VM's socket device ([`VsockDevice`]), locked per call; the driver
/// meets [`VsockTransport`]'s bounds, keeping all but
/// [`MAX_USER_CONNECTIONS`](litebox_hal::virtio::vsock::MAX_USER_CONNECTIONS)
/// connections for the host's requests.
struct VmVsock(&'static Devices);

impl VsockTransport for VmVsock {
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
        guest_port: id.guest_port.0,
        host_port: id.host_port.0,
    }
}

fn broker_id(id: hal::ConnectionId) -> ConnectionId {
    ConnectionId {
        guest_port: VsockPort(id.guest_port),
        host_port: VsockPort(id.host_port),
    }
}

// The FUSE client's messages fit the device's.
const _: () = {
    assert!(FuseDevice::MAX_REQUEST_SIZE >= fuse::MIN_REQUEST_SIZE);
    assert!(FuseDevice::MAX_PAYLOAD_SIZE >= fuse::MIN_PAYLOAD_SIZE);
    assert!(FuseDevice::MAX_SMALL_REPLY_SIZE >= fuse::SMALL_MESSAGE_SIZE);
    assert!(FuseDevice::MAX_ONEWAY_SIZE >= fuse::SMALL_MESSAGE_SIZE);
    assert!(FuseDevice::OUT_HEADER_SIZE == fuse::OUT_HEADER_SIZE);
};

/// A share's virtio-fs device: a request at a time, waiting for its reply in
/// [`Devices::halt`], not suspending the worker: the FUSE client holds its
/// lock across the round trip, and while the worker is suspended, the kernel
/// may take it (e.g., ending another process's association closes its files),
/// which nothing on that CPU would release. Polled even if it interrupts: its
/// interrupt goes to the boot CPU, which wakes this one for it (see
/// [`Devices::on_interrupt`]) only as it takes interrupts, which it may not
/// for a while, running kernel code (e.g., creating or freeing a process's
/// address space, or spinning for a spin lock).
struct FuseShare {
    devices: &'static Devices,
    device: FuseDevice,
    /// A request timed out, and the device may still answer it, or access
    /// its buffers: the share is no longer used.
    failed: bool,
}

impl FuseShare {
    /// Polls `done`, as [`Devices::wait_for_share`]; on a timeout, the share
    /// fails.
    fn wait<R>(
        &mut self,
        mut done: impl FnMut(&mut FuseDevice) -> Option<R>,
    ) -> Result<R, fuse::TransportError> {
        let device = &mut self.device;
        if let Some(result) = self.devices.wait_for_share(|| done(device)) {
            return Ok(result);
        }
        litebox_util_log::warn!(
            device:% = self.device;
            "FUSE server did not answer; share failed"
        );
        self.failed = true;
        Err(fuse::TransportError)
    }
}

/// Only ever copied by `RawBytes`, without references, as the device may
/// write them at any time.
fn raw_bytes(shared: FuseShared<'_>) -> RawBytes<'_> {
    let address = NonNull::new(shared.as_ptr()).expect("DMA memory is mapped");
    // Safety: DMA memory, valid for the borrow of `shared`; never
    // referenced, as above.
    unsafe { RawBytes::from_raw_parts(address, shared.len()) }
}

impl fuse::Transport for FuseShare {
    fn max_request_size(&self) -> usize {
        FuseDevice::MAX_REQUEST_SIZE
    }

    fn max_payload_size(&self) -> usize {
        FuseDevice::MAX_PAYLOAD_SIZE
    }

    fn payload(&mut self) -> Option<RawBytes<'_>> {
        if self.failed {
            return None;
        }
        self.device.payload().map(raw_bytes)
    }

    fn round_trip(
        &mut self,
        request: &[u8],
        payload: usize,
        room: usize,
    ) -> Result<fuse::Reply<'_>, fuse::TransportError> {
        if self.failed {
            return Err(fuse::TransportError);
        }
        let Some(buffer) = self.device.request() else {
            return Err(fuse::TransportError);
        };
        raw_bytes(buffer)
            .subrange(0..request.len())
            .copy_from_slice(request);
        if !self.device.transmit(request.len(), payload, room) {
            return Err(fuse::TransportError);
        }
        let len = self.wait(FuseDevice::receive)?;
        // As much of the header as the device reports; the rest reads as
        // zeros, as the client expects.
        let mut header = [0; fuse::OUT_HEADER_SIZE];
        let written = self
            .device
            .reply_header()
            .expect("the device just answered");
        raw_bytes(written).copy_to_slice(&mut header[..written.len()]);
        let body = self.device.reply_body().expect("the device just answered");
        Ok(fuse::Reply {
            len,
            header,
            body: raw_bytes(body),
        })
    }

    /// Waits for the device to take the last request without a reply, whose
    /// buffer this one needs, but not for it to take this one.
    fn send(&mut self, request: &[u8]) -> Result<(), fuse::TransportError> {
        if self.failed || request.len() > FuseDevice::MAX_ONEWAY_SIZE {
            return Err(fuse::TransportError);
        }
        self.wait(|device| device.oneway_done().then_some(()))?;
        let buffer = self.device.oneway().expect("the device took the last one");
        raw_bytes(buffer)
            .subrange(0..request.len())
            .copy_from_slice(request);
        if !self.device.transmit_oneway(request.len()) {
            return Err(fuse::TransportError);
        }
        Ok(())
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
