// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use std::io::{Read as _, Write as _};
use std::net::Ipv4Addr;
use std::net::{Shutdown, TcpListener, UdpSocket};
use std::sync::Condvar;
use std::sync::atomic::AtomicUsize;
use std::sync::mpsc::{Receiver, RecvTimeoutError, Sender, channel};
use std::time::{Duration, Instant};

use super::*;
use litebox_broker_core::readiness::ReadinessSink;
use litebox_broker_core::socket::{GUEST_IPV4_ADDRESS, HOST_GATEWAY_IPV4_ADDRESS};
use litebox_broker_core::test_support::TestBrokerCoreBuilder;
use litebox_broker_core::{
    BrokerCore, BrokerCoreLimits, BrokerProcess, CallerCredential, DestinationPortRange,
    DestinationRule, Ipv4Cidr, ObjectRights, PolicyEngine, SocketPolicy,
};
use litebox_broker_protocol::ObjectHandle;
use litebox_broker_protocol::fs::FileOpenFlags;
use litebox_broker_protocol::socket::{
    Ipv4Address, MAX_SOCKET_TRANSFER_SIZE, Port, ReceiveSocketResponse,
};
use litebox_platform::buffer::{Fault, RawBytes};

use super::direct::MAX_RAW_PARTS;
use super::tcp::TcpPendingErrors;
use super::udp::{
    MAX_REJECTED_UDP_DATAGRAMS_PER_COMMAND, MAX_UDP_EXTERNAL_PEERS_PER_SOCKET,
    MAX_UDP_NATIVE_RECEIVE_BUFFER, MAX_UDP_QUEUE_DATAGRAMS_PER_SOURCE,
};

mod tcp;
mod udp;

const TEST_TIMEOUT: Duration = Duration::from_secs(30);

fn test_broker_core(
    policy: PolicyEngine,
    limits: BrokerCoreLimits,
    socket_provider: Arc<LinuxSocketProvider>,
) -> litebox_broker_core::Result<BrokerCore> {
    TestBrokerCoreBuilder::new(policy)
        .with_limits(limits)
        .with_socket_provider(socket_provider)
        .build()
}

type HookAction = Arc<dyn Fn(&TestHook, usize, HookPoint) + Send + Sync>;

/// The test's provider hook, which forces a chosen interleaving of a socket
/// call and the epoll thread.
///
/// Calls and the epoll thread can work on one socket at once, and their races
/// have windows too narrow for stress tests to hit reliably. A `TestHook`
/// records every [`HookPoint`] the provider reaches, so a test can wait for a
/// thread to reach a point instead of sleeping. It also runs the test's
/// action at each point, so the action can hold that thread there while
/// another thread makes its move.
struct TestHook {
    points: Mutex<Vec<HookPoint>>,
    changed: Condvar,
    action: Mutex<Option<HookAction>>,
}

impl TestHook {
    /// Creates a hook and installs it as `provider`'s, replacing any previous
    /// one.
    fn install(provider: &LinuxSocketProvider) -> Arc<Self> {
        let hook = Arc::new(Self {
            points: Mutex::new(Vec::new()),
            changed: Condvar::new(),
            action: Mutex::new(None),
        });
        let installed = Arc::clone(&hook);
        provider
            .core
            .set_hook(Some(Arc::new(move |point| installed.record(point))));
        hook
    }

    fn record(&self, point: HookPoint) {
        let index = {
            let mut points = self.points.lock().unwrap();
            points.push(point);
            points.len() - 1
        };
        self.changed.notify_all();
        let action = self.action.lock().unwrap().clone();
        if let Some(action) = action {
            action(self, index, point);
        }
    }

    /// Runs `action` with each later point and its index.
    fn act(&self, action: impl Fn(&TestHook, usize, HookPoint) + Send + Sync + 'static) {
        *self.action.lock().unwrap() = Some(Arc::new(action));
    }

    /// Stops running the action, releasing what it captured.
    fn stop(&self) {
        *self.action.lock().unwrap() = None;
    }

    fn len(&self) -> usize {
        self.points.lock().unwrap().len()
    }

    /// Waits for the first harvest at or after `start` of a token that
    /// `matches`, and returns how the epoll thread handled that event.
    ///
    /// An event harvested before `start` may still report `Handled` after
    /// it, so a wait for `Handled` alone could see that event.
    fn wait_for_harvest_handled(&self, start: usize, matches: impl Fn(u64) -> bool) -> Dispatch {
        let (harvested, point) = self.wait_for(
            start,
            |point| matches!(point, HookPoint::Harvested(token) if matches(token)),
        );
        let HookPoint::Harvested(token) = point else {
            unreachable!()
        };
        // A harvest merges any deferred flags for its token, so the next
        // `Handled` for the token is this event's.
        match self.wait_for(
            harvested,
            |point| matches!(point, HookPoint::Handled(handled, _) if handled == token),
        ) {
            (_, HookPoint::Handled(_, dispatch)) => dispatch,
            _ => unreachable!(),
        }
    }

    /// Waits for the first point at or after `start` that `matches`.
    fn wait_for(&self, start: usize, matches: impl Fn(HookPoint) -> bool) -> (usize, HookPoint) {
        let deadline = Instant::now() + TEST_TIMEOUT;
        let mut points = self.points.lock().unwrap();
        loop {
            if let Some((index, point)) = points
                .iter()
                .enumerate()
                .skip(start)
                .find(|(_, point)| matches(**point))
            {
                return (index, *point);
            }
            let remaining = deadline
                .checked_duration_since(Instant::now())
                .expect("timed out waiting for a provider hook point");
            points = self.changed.wait_timeout(points, remaining).unwrap().0;
        }
    }
}

/// Runs `operation` on another thread and waits for it, failing rather than
/// hanging if it blocks.
fn run_on_thread(operation: impl FnOnce() + Send + 'static) {
    let (done, finished) = channel();
    let worker = thread::spawn(move || {
        operation();
        let _ = done.send(());
    });
    match finished.recv_timeout(TEST_TIMEOUT) {
        Ok(()) | Err(RecvTimeoutError::Disconnected) => worker.join().unwrap(),
        Err(RecvTimeoutError::Timeout) => panic!("the operation did not finish"),
    }
}

/// Waits until `condition` holds, failing after [`TEST_TIMEOUT`].
fn wait_until(mut condition: impl FnMut() -> bool, what: &str) {
    let deadline = Instant::now() + TEST_TIMEOUT;
    while !condition() {
        assert!(Instant::now() < deadline, "timed out waiting until {what}");
        thread::yield_now();
    }
}

/// Waits for every socket's readiness to reflect its state; a lost wakeup
/// never settles.
fn wait_for_settled_readiness(provider: &LinuxSocketProvider) {
    let deadline = Instant::now() + TEST_TIMEOUT;
    while !provider.core.readiness_is_settled() {
        assert!(Instant::now() < deadline, "socket readiness did not settle");
        thread::sleep(Duration::from_millis(1));
    }
}

#[test]
fn tcp_pending_errors_preserve_order_and_source() {
    let mut errors = TcpPendingErrors::default();
    errors.append(TcpPendingError::Socket(SocketError::ConnectionReset));
    errors.append(TcpPendingError::GuestReset);
    errors.append(TcpPendingError::GuestReset);

    assert!(errors.contains_guest_reset());
    assert_eq!(
        errors.take(),
        Some(TcpPendingError::Socket(SocketError::ConnectionReset))
    );
    assert_eq!(errors.take(), Some(TcpPendingError::GuestReset));
    assert!(errors.is_empty());
}

fn gateway_tcp_policy() -> SocketPolicy {
    SocketPolicy::guest_network()
        .with_tcp_destination_rules(&[DestinationRule::new(
            CallerCredential::Unauthenticated,
            Ipv4Cidr::new(Ipv4Address(HOST_GATEWAY_IPV4_ADDRESS.octets()), 32).unwrap(),
            DestinationPortRange::new(Port(1), Port(u16::MAX)).unwrap(),
        )])
        .unwrap()
}

fn gateway_address(host_address: SocketAddrV4) -> SocketAddrV4 {
    SocketAddrV4::new(HOST_GATEWAY_IPV4_ADDRESS, host_address.port())
}

fn send_bytes(
    process: &BrokerProcess,
    handle: ObjectHandle,
    data: &[u8],
    flags: SendFlags,
) -> BrokerResult<SocketOutcome<usize>> {
    litebox_broker_core::socket::send(process, handle, &data, flags)
}

fn send_datagram(
    process: &BrokerProcess,
    handle: ObjectHandle,
    data: &[u8],
    flags: SendFlags,
    destination: Option<SocketAddrV4>,
) -> BrokerResult<SocketOutcome<usize>> {
    litebox_broker_core::socket::send_to(process, handle, &data, flags, destination)
}

fn receive_into(
    process: &BrokerProcess,
    handle: ObjectHandle,
    mut data: &mut [u8],
    flags: ReceiveFlags,
    peek_offset: u32,
    peek_length: u32,
) -> BrokerResult<SocketOutcome<ReceiveSocketResponse>> {
    match litebox_broker_core::socket::receive(
        process,
        handle,
        &mut data,
        flags,
        peek_offset,
        peek_length,
    )? {
        SocketOutcome::Completed(PlatformStreamReceive::Received(received)) => {
            Ok(SocketOutcome::Completed(ReceiveSocketResponse::Received(
                received.try_into().map_err(|_| BrokerError::Internal)?,
            )))
        }
        SocketOutcome::Completed(PlatformStreamReceive::EndOfStream) => {
            Ok(SocketOutcome::Completed(ReceiveSocketResponse::EndOfStream))
        }
        SocketOutcome::Failed(error) => Ok(SocketOutcome::Failed(error)),
    }
}

fn receive_datagram_into(
    process: &BrokerProcess,
    handle: ObjectHandle,
    mut data: &mut [u8],
    flags: ReceiveFromFlags,
) -> BrokerResult<SocketOutcome<PlatformDatagramReceive>> {
    litebox_broker_core::socket::receive_from(process, handle, &mut data, flags)
}

/// A message that [`TEST_BUFFER_LAYOUTS`] split variously.
const TEST_MESSAGE: [u8; 40] = *b"0123456789abcdefghijklmnopqrstuvwxyzABCD";

/// [`TestBuffer`] part lengths for [`TEST_MESSAGE`], or for its first
/// [`TEST_TRUNCATED_LENGTH`] bytes: few enough parts to transfer directly, too
/// many, and none.
const TEST_BUFFER_LAYOUTS: [Option<usize>; 3] = [Some(3), Some(1), None];

/// A length to which a datagram of [`TEST_MESSAGE`] is truncated.
const TEST_TRUNCATED_LENGTH: usize = 30;

const _: () = assert!(
    TEST_MESSAGE.len().div_ceil(3) <= MAX_RAW_PARTS && TEST_TRUNCATED_LENGTH > MAX_RAW_PARTS
);

/// A buffer over bytes that a socket must reach as `part_length` directs:
/// directly, in raw parts of at most that many bytes, or, if it is `None`,
/// only through copies, as a guest's memory.
///
/// Copying a buffer that has raw parts panics, so a socket that copies one
/// rather than using its raw parts fails the test.
struct TestBuffer<'a> {
    bytes: RawBytes<'a>,
    part_length: Option<usize>,
}

impl<'a> TestBuffer<'a> {
    fn new(bytes: &'a mut [u8], part_length: Option<usize>) -> Self {
        Self {
            bytes: RawBytes::from(bytes),
            part_length,
        }
    }

    /// Returns the `length` bytes at `offset` as raw parts, if the buffer
    /// has them.
    fn parts(&self, offset: usize, length: usize) -> Option<Vec<RawBytes<'a>>> {
        let part_length = self.part_length?;
        let bytes = self.bytes.subrange(offset..offset + length);
        Some(
            (0..length)
                .step_by(part_length)
                .map(|start| bytes.subrange(start..length.min(start + part_length)))
                .collect(),
        )
    }

    /// Returns the `length` bytes at `offset` to copy.
    ///
    /// # Panics
    ///
    /// Panics if the buffer has raw parts.
    fn copied(&self, offset: usize, length: usize) -> RawBytes<'a> {
        assert!(
            self.part_length.is_none(),
            "a socket copied a buffer it could use directly"
        );
        self.bytes.subrange(offset..offset + length)
    }
}

impl litebox_platform::buffer::Buffer for TestBuffer<'_> {
    fn len(&self) -> usize {
        self.bytes.len()
    }
}

impl ReadBuffer for TestBuffer<'_> {
    fn copy_from_slice_at(&mut self, offset: usize, source: &[u8]) -> Result<(), Fault> {
        self.copied(offset, source.len()).copy_from_slice(source);
        Ok(())
    }

    fn copy_from_raw_at(&mut self, offset: usize, source: RawBytes<'_>) -> Result<(), Fault> {
        let mut staged = vec![0; source.len()];
        source.copy_to_slice(&mut staged);
        self.copy_from_slice_at(offset, &staged)
    }

    fn read_direct_at(
        &mut self,
        offset: usize,
        length: usize,
        read: &mut dyn FnMut(&[RawBytes<'_>]) -> usize,
    ) -> Option<usize> {
        self.parts(offset, length).map(|parts| read(&parts))
    }
}

impl WriteBuffer for TestBuffer<'_> {
    fn copy_to_slice_at(&self, offset: usize, destination: &mut [u8]) -> Result<(), Fault> {
        self.copied(offset, destination.len())
            .copy_to_slice(destination);
        Ok(())
    }

    fn copy_to_raw_at(&self, offset: usize, destination: RawBytes<'_>) -> Result<(), Fault> {
        let mut staged = vec![0; destination.len()];
        self.copy_to_slice_at(offset, &mut staged)?;
        destination.copy_from_slice(&staged);
        Ok(())
    }

    fn write_direct_at(
        &self,
        offset: usize,
        length: usize,
        write: &mut dyn FnMut(&[RawBytes<'_>]) -> usize,
    ) -> Option<usize> {
        self.parts(offset, length).map(|parts| write(&parts))
    }
}

/// Peeks at the datagram at the head of `handle`, which must be
/// [`TEST_MESSAGE`] from `source`, into a [`TestBuffer`] that truncates it,
/// then receives it whole into another, both laid out as `part_length`
/// directs.
fn receive_test_message(
    process: &BrokerProcess,
    handle: ObjectHandle,
    publications: &Receiver<(ObjectHandle, ReadinessFlags)>,
    part_length: Option<usize>,
    source: SocketAddrV4,
) {
    for (flags, length) in [
        (ReceiveFromFlags::PEEK, TEST_TRUNCATED_LENGTH),
        (ReceiveFromFlags::NONE, TEST_MESSAGE.len()),
    ] {
        let mut received = vec![0; length];
        loop {
            match litebox_broker_core::socket::receive_from(
                process,
                handle,
                &mut TestBuffer::new(&mut received, part_length),
                flags,
            ) {
                Err(BrokerError::WouldBlock) => {
                    wait_until_ready(process, publications, handle, ReadinessFlags::READ);
                }
                outcome => {
                    assert_eq!(
                        outcome,
                        Ok(SocketOutcome::Completed(PlatformDatagramReceive {
                            received: length,
                            datagram_length: TEST_MESSAGE.len(),
                            source_address: source,
                        }))
                    );
                    break;
                }
            }
        }
        assert_eq!(received, TEST_MESSAGE[..length]);
    }
}

/// A socket call gets a buffer's own raw parts if it has at most
/// [`MAX_RAW_PARTS`] of them, and a staged copy otherwise.
#[test]
fn socket_calls_get_up_to_max_raw_parts_directly() {
    for (length, part_length, direct) in [
        (MAX_RAW_PARTS, Some(1), true),
        (MAX_RAW_PARTS + 1, Some(1), false),
        (MAX_RAW_PARTS, None, false),
    ] {
        let message = &TEST_MESSAGE[..length];
        // A call that writes to the bytes it gets changes the buffer only if
        // it gets the buffer's own; a receive copies none back as it reports
        // receiving none.
        let mut bytes = vec![0; length];
        let sent = super::direct::send_from(&TestBuffer::new(&mut bytes, part_length), |parts| {
            parts.copy_from_slice(message);
            Ok(SocketOutcome::Completed(length))
        });
        assert_eq!(sent, Ok(SocketOutcome::Completed(length)));
        assert_eq!(bytes == message, direct);
        let mut bytes = vec![0; length];
        super::direct::receive_into(
            &mut TestBuffer::new(&mut bytes, part_length),
            |()| 0,
            |parts| {
                parts.copy_from_slice(message);
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(bytes == message, direct);
    }
}

#[test]
fn synchronous_errors_do_not_consume_tcp_connect_status() {
    assert!(!can_consume_synchronous_error(
        SocketConnectionStatus::Connecting,
    ));
    assert!(can_consume_synchronous_error(
        SocketConnectionStatus::Connected
    ));
}

struct TestReadinessSink {
    published: Sender<(ObjectHandle, ReadinessFlags)>,
    retired: Sender<ObjectHandle>,
}

impl ReadinessSink for TestReadinessSink {
    fn max_tracked_objects(&self) -> usize {
        8
    }

    fn publish(&self, handle: ObjectHandle, readiness: ReadinessFlags) -> BrokerResult<()> {
        self.published
            .send((handle, readiness))
            .map_err(|_| BrokerError::Internal)
    }

    fn republish(&self, handle: ObjectHandle, readiness: ReadinessFlags) -> BrokerResult<()> {
        self.publish(handle, readiness)
    }

    fn retire(&self, handle: ObjectHandle) {
        let _ = self.retired.send(handle);
    }
}

fn socket_address_v4(address: std::net::SocketAddr) -> SocketAddrV4 {
    let std::net::SocketAddr::V4(address) = address else {
        panic!("loopback TCP test unexpectedly used IPv6");
    };
    address
}

fn non_loopback_local_ipv4() -> Option<Ipv4Addr> {
    let probe = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).ok()?;
    probe.connect((Ipv4Addr::new(192, 0, 2, 1), 9)).ok()?;
    let address = socket_address_v4(probe.local_addr().ok()?);
    (!address.ip().is_unspecified()
        && !address.ip().is_loopback()
        && *address.ip() != GUEST_IPV4_ADDRESS)
        .then_some(*address.ip())
}

fn create_socket(
    process: &litebox_broker_core::BrokerProcess,
    readiness: Arc<dyn ReadinessSink>,
) -> ObjectHandle {
    litebox_broker_core::socket::create(
        process,
        CreateSocketRequest {
            address_family: AddressFamily::Ipv4,
            socket_type: SocketType::Stream,
            protocol: IpProtocol::Tcp,
            flags: FileOpenFlags::NONE,
        },
        readiness,
    )
    .unwrap()
}

fn create_udp_socket(
    process: &litebox_broker_core::BrokerProcess,
    readiness: Arc<dyn ReadinessSink>,
) -> ObjectHandle {
    litebox_broker_core::socket::create(
        process,
        CreateSocketRequest {
            address_family: AddressFamily::Ipv4,
            socket_type: SocketType::Datagram,
            protocol: IpProtocol::Udp,
            flags: FileOpenFlags::NONE,
        },
        readiness,
    )
    .unwrap()
}

fn wait_until_connected(
    process: &litebox_broker_core::BrokerProcess,
    handle: ObjectHandle,
    publications: &Receiver<(ObjectHandle, ReadinessFlags)>,
) {
    let deadline = Instant::now() + TEST_TIMEOUT;
    loop {
        match litebox_broker_core::socket::status(process, handle)
            .unwrap()
            .status
        {
            SocketConnectionStatus::Connected => return,
            SocketConnectionStatus::Connecting => {
                wait_for_readiness_until(
                    publications,
                    handle,
                    ReadinessFlags::WRITE | ReadinessFlags::ERROR,
                    deadline,
                );
            }
            status => panic!("unexpected connect status: {status:?}"),
        }
    }
}

fn wait_until_failed(
    process: &litebox_broker_core::BrokerProcess,
    handle: ObjectHandle,
    publications: &Receiver<(ObjectHandle, ReadinessFlags)>,
) -> SocketError {
    // Like a guest, observe the failure through readiness, which queues it.
    // Readiness can show the transport's error before the broker has seen the
    // failure, so check once more to queue it before `status` consumes it.
    wait_until_ready(process, publications, handle, ReadinessFlags::ERROR);
    process.check_readiness(handle).unwrap();
    match litebox_broker_core::socket::status(process, handle)
        .unwrap()
        .status
    {
        SocketConnectionStatus::Failed(error) => error,
        status => panic!("unexpected connect status: {status:?}"),
    }
}

fn wait_for_end_of_stream(
    process: &litebox_broker_core::BrokerProcess,
    handle: ObjectHandle,
    publications: &Receiver<(ObjectHandle, ReadinessFlags)>,
) {
    let deadline = Instant::now() + TEST_TIMEOUT;
    loop {
        let mut byte = [0_u8; 1];
        match receive_into(process, handle, &mut byte, ReceiveFlags::NONE, 0, 0) {
            Ok(SocketOutcome::Completed(ReceiveSocketResponse::EndOfStream)) => return,
            Err(BrokerError::WouldBlock) => {
                wait_for_readiness_until(
                    publications,
                    handle,
                    ReadinessFlags::READ | ReadinessFlags::HANGUP,
                    deadline,
                );
            }
            outcome => panic!("unexpected receive outcome: {outcome:?}"),
        }
    }
}

fn wait_for_readiness(
    publications: &Receiver<(ObjectHandle, ReadinessFlags)>,
    handle: ObjectHandle,
    readiness: ReadinessFlags,
) {
    wait_for_readiness_until(
        publications,
        handle,
        readiness,
        Instant::now() + TEST_TIMEOUT,
    );
}

fn wait_for_readiness_publication(
    publications: &Receiver<(ObjectHandle, ReadinessFlags)>,
    handle: ObjectHandle,
    readiness: ReadinessFlags,
) {
    let deadline = Instant::now() + TEST_TIMEOUT;
    loop {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .expect("timed out waiting for socket readiness publication");
        let (published_handle, published) = publications.recv_timeout(remaining).unwrap();
        if published_handle == handle && published.contains(readiness) {
            return;
        }
    }
}

fn wait_until_ready(
    process: &litebox_broker_core::BrokerProcess,
    publications: &Receiver<(ObjectHandle, ReadinessFlags)>,
    handle: ObjectHandle,
    readiness: ReadinessFlags,
) {
    wait_until_ready_until(
        process,
        publications,
        handle,
        readiness,
        Instant::now() + TEST_TIMEOUT,
    );
}

fn wait_until_ready_until(
    process: &litebox_broker_core::BrokerProcess,
    publications: &Receiver<(ObjectHandle, ReadinessFlags)>,
    handle: ObjectHandle,
    readiness: ReadinessFlags,
    deadline: Instant,
) {
    loop {
        if process.check_readiness(handle).unwrap().contains(readiness) {
            return;
        }
        // Notifications are wake hints and may be stale by the time the
        // test receives them; readiness is authoritative.
        wait_for_readiness_until(publications, handle, readiness, deadline);
    }
}

fn wait_for_readiness_until(
    publications: &Receiver<(ObjectHandle, ReadinessFlags)>,
    handle: ObjectHandle,
    readiness: ReadinessFlags,
    deadline: Instant,
) {
    loop {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .expect("timed out waiting for socket readiness");
        let (published_handle, published) = publications.recv_timeout(remaining).unwrap();
        if published_handle == handle && published.0 & readiness.0 != 0 {
            return;
        }
    }
}
