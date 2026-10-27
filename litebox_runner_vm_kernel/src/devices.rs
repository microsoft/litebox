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
//! - [`Devices::shares`]: the VM's virtio-9p devices, each a host directory
//!   mounted at its tag.
//! - [`InterruptController`]: the local APICs, to start and wake the other
//!   CPUs, and to have them flush their TLBs.
//!
//! Also the wall clock ([`wall_clock`]), for runners.
//!
//! Each CPU has its own local APIC, so its own timer; devices interrupt the
//! boot CPU. The interrupt handler only ends the interrupt, noting a device's
//! and waking the other idle CPUs; the first CPU to look at the devices then
//! ([`Events::poll`]) wakes the threads that wait for one. A wake IPI only
//! ends a halt, or has a CPU running a process enter the kernel. A TLB-flush
//! IPI is only a doorbell: the platform flushes before the handler runs, and a
//! process it interrupted resumes at once.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use core::time::Duration;
use litebox_broker_core::stdio::StdioOutputStream;
use litebox_broker_core::vsock_socket::transport::{
    ConnectState, ConnectionId, ConnectionStatus, VsockTransport,
};
use litebox_broker_protocol::vsock_socket::VsockPort;
use litebox_broker_smoltcp::Network;
use litebox_broker_vm_kernel::Events;
#[cfg(debug_assertions)]
use litebox_broker_vm_kernel::gate::Gate;
use litebox_broker_vm_kernel::share::{Share, Transport, TransportError};
use litebox_broker_vm_kernel::stdio::Console;
use litebox_hal::clock::Clock;
use litebox_hal::devices::{
    self as hal, ConsoleDevice, NetworkDevice, NinePDevice, Polled, VsockDevice,
};
use litebox_hal::interrupt::{LocalApic, SPURIOUS_VECTORS, StartupIpi};
use litebox_platform::time::{Instant as _, TimeProvider as _};
use litebox_platform_vm_kernel::cpu::{self, CpuId, InterruptController, Ipi, MAX_CPUS};
use litebox_platform_vm_kernel::kthread::{self, WaitQueue};
use litebox_platform_vm_kernel::preempt::{KernelMutex, KernelMutexGuard};
use litebox_platform_vm_kernel::{Handled, Instant, VmKernel};
use litebox_shim_vm_kernel::ProcessTimer;

/// How long a share's server may take to answer a request before the share
/// fails.
const SHARE_TIMEOUT: Duration = Duration::from_secs(30);
/// How often a share waiting for its server is polled (see [`ShareTransport`]).
const SHARE_POLL_INTERVAL: Duration = Duration::from_millis(1);
/// How long a kernel thread polls a share for its response before it sleeps:
/// longer than most of the server's round trips.
const SHARE_SPIN: Duration = Duration::from_micros(250);

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
    /// A device interrupted since the last [`Events::poll`].
    device_interrupted: AtomicBool,
    /// The kernel threads that wait for a device.
    waiters: WaitQueue,
    #[cfg(debug_assertions)]
    hold_waiters: HoldWaiters,
    #[cfg(debug_assertions)]
    gate: Gate,
    #[cfg(debug_assertions)]
    lose_share_response: AtomicBool,
    #[cfg(debug_assertions)]
    share_timeouts: AtomicU64,
}

#[cfg(debug_assertions)]
#[derive(Default)]
struct HoldWaiters {
    /// Until a CPU takes it.
    requested: AtomicBool,
    /// While the CPU that took it holds the lock.
    holding: AtomicBool,
    /// When it is to release it, in nanoseconds; zero until set.
    release_at: AtomicU64,
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
            network: network.map(KernelMutex::new),
            vsock_interrupts: vsock.as_ref().is_some_and(VsockDevice::interrupts),
            vsock: vsock.map(KernelMutex::new),
            armed: [const { AtomicU64::new(ARMED_UNKNOWN) }; MAX_CPUS],
            device_interrupted: AtomicBool::new(false),
            waiters: WaitQueue::new(),
            console: KernelMutex::new(console),
            #[cfg(debug_assertions)]
            hold_waiters: HoldWaiters::default(),
            #[cfg(debug_assertions)]
            gate: Gate::new(platform),
            #[cfg(debug_assertions)]
            lose_share_response: AtomicBool::new(false),
            #[cfg(debug_assertions)]
            share_timeouts: AtomicU64::new(0),
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
                #[cfg(debug_assertions)]
                gate: &self.gate,
            });
        }
        shares
    }

    /// See `litebox_platform_vm_kernel::set_interrupt_handler`: no locks, no
    /// per-CPU data; but, in debug builds, a test's hold of the device
    /// waiters' lock (see [`Self::hold_waiters`]).
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
            // The other idle CPUs step again, to look at the devices.
            DEVICE_VECTOR => {
                self.device_interrupted.store(true, Ordering::SeqCst);
                cpu::wake_idle(CpuId::BOOT);
            }
            WAKE_VECTOR => {
                #[cfg(debug_assertions)]
                self.hold_waiters_if_asked();
            }
            FLUSH_VECTOR => {
                self.apic.end_of_interrupt();
                return Handled::Doorbell;
            }
            _ => return Handled::Unexpected,
        }
        self.apic.end_of_interrupt();
        Handled::Event
    }

    /// Debug builds: the broker's gate.
    #[cfg(debug_assertions)]
    pub fn gate(&'static self) -> &'static Gate {
        &self.gate
    }

    /// The kernel threads that wait for a device (see [`Events::poll`]).
    #[cfg(debug_assertions)]
    pub(crate) fn waiters(&self) -> &WaitQueue {
        &self.waiters
    }

    /// Debug builds: the next round trip in a kernel thread loses its response,
    /// and times out, which fails its share.
    #[cfg(debug_assertions)]
    pub fn lose_share_response(&self) {
        self.lose_share_response.store(true, Ordering::SeqCst);
    }

    /// Debug builds: how many sleeps for a share's response ended at their
    /// deadline, for a device that interrupts: so the interrupt never came.
    #[cfg(debug_assertions)]
    pub fn share_timeouts(&self) -> u64 {
        self.share_timeouts.load(Ordering::SeqCst)
    }

    /// Debug builds: has another CPU, as it takes a wake, hold
    /// [`Self::waiters`]'s lock until [`Self::release_waiters`] sets when (or
    /// for a second); panics if none took the request within a second.
    #[cfg(debug_assertions)]
    pub(crate) fn hold_waiters(&self) {
        let start = self.platform.now();
        let hold = &self.hold_waiters;
        hold.release_at.store(0, Ordering::SeqCst);
        hold.requested.store(true, Ordering::SeqCst);
        while !hold.holding.load(Ordering::SeqCst) {
            assert!(
                self.platform.now().duration_since(&start) < Duration::from_secs(1),
                "another CPU holds the device waiters' lock"
            );
            // Again, for a CPU that was not idle yet.
            cpu::wake_idle(cpu::current());
            core::hint::spin_loop();
        }
    }

    /// Debug builds: see [`Self::hold_waiters`].
    #[cfg(debug_assertions)]
    pub(crate) fn release_waiters(&self, at: Instant) {
        self.hold_waiters
            .release_at
            .store(at.as_nanos().max(1), Ordering::SeqCst);
    }

    /// Debug builds: takes a request of [`Self::hold_waiters`], if any.
    #[cfg(debug_assertions)]
    fn hold_waiters_if_asked(&self) {
        let hold = &self.hold_waiters;
        // A load first: no write to the shared line on every wake.
        if !hold.requested.load(Ordering::Relaxed) || !hold.requested.swap(false, Ordering::SeqCst)
        {
            return;
        }
        let start = self.platform.now();
        self.waiters.hold_while(|| {
            hold.holding.store(true, Ordering::SeqCst);
            let now = self.platform.now();
            let release_at = hold.release_at.load(Ordering::SeqCst);
            (release_at == 0 || now.as_nanos() < release_at)
                && now.duration_since(&start) < Duration::from_secs(1)
        });
        hold.holding.store(false, Ordering::SeqCst);
    }

    /// Debug builds: sends the calling CPU a device interrupt.
    #[cfg(debug_assertions)]
    pub(crate) fn interrupt_self(&self) {
        assert!(
            self.apic
                .send_fixed_ipi(cpu::apic_id(cpu::current()), DEVICE_VECTOR),
            "a device interrupt sent"
        );
    }

    /// The calling CPU's [`Self::armed`].
    pub(crate) fn armed(&self) -> &AtomicU64 {
        &self.armed[cpu::current().index()]
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

    /// After the device wrote what it interrupted for: so a thread that
    /// registers after the wake, then looks, sees it.
    fn poll(&self) -> bool {
        // A load first: no write to the shared line on every look.
        let interrupted = self.device_interrupted.load(Ordering::Relaxed)
            && self.device_interrupted.swap(false, Ordering::SeqCst);
        if interrupted {
            self.waiters.wake(usize::MAX);
        }
        interrupted
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

/// A share's virtio-9p device: a request at a time. In a kernel thread, it
/// polls for the response for up to [`SHARE_SPIN`], then sleeps until the
/// devices' interrupt, or its next poll. Otherwise (at boot or shutdown), it
/// halts, polling every [`SHARE_POLL_INTERVAL`].
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
        if self.failed {
            return Err(TransportError);
        }
        let received = if kthread::in_kthread() {
            self.poll_then_sleep(request, response)
        } else {
            self.halt(request, response)
        };
        if received.is_err() {
            litebox_util_log::warn!(device:% = self.device; "9P server did not answer; share failed");
            self.failed = true;
        }
        received
    }
}

impl ShareTransport {
    /// [`Transport::round_trip`] in a kernel thread (see [`ShareTransport`]).
    fn poll_then_sleep(
        &mut self,
        request: &[u8],
        response: &mut [u8],
    ) -> Result<usize, TransportError> {
        let devices = self.devices;
        let platform = devices.platform;
        let start = platform.now();
        let spin_end = start.checked_add(SHARE_SPIN);
        #[cfg(debug_assertions)]
        let lose = devices.lose_share_response.load(Ordering::Relaxed)
            && devices.lose_share_response.swap(false, Ordering::SeqCst);
        #[cfg(not(debug_assertions))]
        let lose = false;
        let timeout = if lose {
            Duration::from_millis(100)
        } else {
            SHARE_TIMEOUT
        };
        let deadline = start
            .checked_add(timeout)
            .expect("the clock is far from overflowing");
        #[cfg(debug_assertions)]
        let mut transmitted = Some(&devices.gate);
        let polled = self.device.transmit_polled(
            request,
            response,
            || {
                #[cfg(debug_assertions)]
                if let Some(gate) = transmitted.take() {
                    gate.hold_at(litebox_broker_vm_kernel::gate::Point::Transmitted);
                }
                spin_end.is_some_and(|spin_end| platform.now() < spin_end) && !kthread::yield_due()
            },
            || devices.waiters.prepare(),
        );
        let mut prepared = match polled.ok_or(TransportError)? {
            Polled::Received(_) if lose => devices.waiters.prepare(),
            Polled::Received(len) => return Ok(len),
            Polled::Waiting(prepared) => prepared,
        };
        loop {
            let now = platform.now();
            if now >= deadline {
                return Err(TransportError);
            }
            let interrupts = self.device.interrupts();
            let wake = if interrupts {
                deadline
            } else {
                poll_at(now, deadline)
            };
            prepared.sleep(Some(wake));
            #[cfg(debug_assertions)]
            if interrupts && platform.now() >= deadline {
                devices.share_timeouts.fetch_add(1, Ordering::SeqCst);
            }
            // Before the look: an interrupt's wake after it ends the sleep.
            prepared = devices.waiters.prepare();
            match self.device.receive(response) {
                Some(len) if !lose => return Ok(len),
                _ => {}
            }
        }
    }

    /// [`Transport::round_trip`] outside kernel threads, halting.
    fn halt(&mut self, request: &[u8], response: &mut [u8]) -> Result<usize, TransportError> {
        if !self.device.transmit(request) {
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
                return Err(TransportError);
            }
            // Until the device returns the request; nothing else runs on this
            // CPU meanwhile (and, while the CPU has a wakeup to acknowledge,
            // this polls).
            self.devices.halt(Some(poll_at(now, deadline)));
        }
    }
}

/// A share's next poll after `now`, unless `deadline` is earlier.
fn poll_at(now: Instant, deadline: Instant) -> Instant {
    match now.checked_add(SHARE_POLL_INTERVAL) {
        Some(poll) if poll < deadline => poll,
        _ => deadline,
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
