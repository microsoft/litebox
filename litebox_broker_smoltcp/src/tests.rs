// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! The provider through the broker core, as runner processes use it. For
//! external traffic, the link is wired to a second smoltcp stack, the
//! "host" at [`HOST_GATEWAY_IPV4_ADDRESS`], with an echo server.

use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::net::{Ipv4Addr, SocketAddrV4};
use core::sync::atomic::AtomicU64;
use core::time::Duration;

use litebox_broker_core::readiness::ReadinessSink;
use litebox_broker_core::socket::{self as core_socket, PlatformStreamReceive};
use litebox_broker_core::test_support::TestBrokerCoreBuilder;
use litebox_broker_core::{
    BrokerError, BrokerProcess, CallerCredential, DestinationPortRange, DestinationRule, Ipv4Cidr,
    ObjectRights, PolicyEngine, Result as BrokerResult, SocketPolicy,
};
use litebox_broker_protocol::ObjectHandle;
use litebox_broker_protocol::socket::{
    AddressFamily, CreateSocketRequest, IpProtocol, Ipv4Address, Port, ReceiveFlags,
    ReceiveFromFlags, SendFlags, ShutdownMode, SocketConnectionStatus, SocketError, SocketOutcome,
    SocketType,
};
use smoltcp::iface::{Config, Interface, SocketSet};
use smoltcp::phy::{self, DeviceCapabilities, Medium};
use smoltcp::socket::tcp;
use smoltcp::storage::RingBuffer;
use smoltcp::wire::{EthernetAddress, HardwareAddress, IpCidr, IpListenEndpoint};
use spin::Mutex;

use super::*;

struct TestClock(AtomicU64);

impl TestClock {
    fn new() -> &'static Self {
        Box::leak(Box::new(Self(AtomicU64::new(1_000_000_000))))
    }

    fn advance(&self, by: Duration) {
        self.0
            .fetch_add(u64::try_from(by.as_nanos()).unwrap(), Ordering::Relaxed);
    }
}

impl Clock for TestClock {
    fn now(&self) -> Duration {
        Duration::from_nanos(self.0.load(Ordering::Relaxed))
    }
}

#[derive(Default)]
struct Sink(Mutex<Vec<(ObjectHandle, ReadinessFlags)>>);

impl ReadinessSink for Sink {
    fn max_tracked_objects(&self) -> usize {
        64
    }

    fn publish(&self, handle: ObjectHandle, readiness: ReadinessFlags) -> BrokerResult<()> {
        self.0.lock().push((handle, readiness));
        Ok(())
    }

    fn republish(&self, handle: ObjectHandle, readiness: ReadinessFlags) -> BrokerResult<()> {
        self.publish(handle, readiness)
    }

    fn retire(&self, _handle: ObjectHandle) {}
}

/// A wire between the guest's link and the host's device.
#[derive(Default)]
struct Wire {
    to_guest: Mutex<VecDeque<Vec<u8>>>,
    to_host: Mutex<VecDeque<Vec<u8>>>,
    /// Frames to the host are lost.
    cut: core::sync::atomic::AtomicBool,
    /// The link does not interrupt: the stack polls it.
    polled: bool,
}

impl Link for Wire {
    fn mac(&self) -> [u8; 6] {
        [0x02, 0, 0, 0, 0, 0x15]
    }

    fn receive(&self, frame: &mut [u8]) -> Option<usize> {
        let received = self.to_guest.lock().pop_front()?;
        let len = received.len().min(frame.len());
        frame[..len].copy_from_slice(&received[..len]);
        Some(received.len())
    }

    fn can_transmit(&self) -> bool {
        true
    }

    fn transmit(&self, frame: &[u8]) -> bool {
        assert!(frame.len() <= ETHERNET_MTU);
        if !self.cut.load(Ordering::Relaxed) {
            self.to_host.lock().push_back(frame.to_vec());
        }
        true
    }

    fn interrupts(&self) -> bool {
        !self.polled
    }
}

struct HostDevice(&'static Wire);

impl phy::Device for HostDevice {
    type RxToken<'a> = HostRx;
    type TxToken<'a> = HostTx;

    fn receive(&mut self, _now: smoltcp::time::Instant) -> Option<(HostRx, HostTx)> {
        let frame = self.0.to_host.lock().pop_front()?;
        Some((HostRx(frame), HostTx(self.0)))
    }

    fn transmit(&mut self, _now: smoltcp::time::Instant) -> Option<HostTx> {
        Some(HostTx(self.0))
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut capabilities = DeviceCapabilities::default();
        capabilities.medium = Medium::Ethernet;
        capabilities.max_transmission_unit = ETHERNET_MTU;
        capabilities
    }
}

struct HostRx(Vec<u8>);

impl phy::RxToken for HostRx {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(&self.0)
    }
}

struct HostTx(&'static Wire);

impl phy::TxToken for HostTx {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let mut frame = vec![0; len];
        let result = f(&mut frame);
        self.0.to_guest.lock().push_back(frame);
        result
    }
}

/// The host at the gateway address, echoing TCP on [`ECHO_PORT`].
struct Host {
    interface: Interface,
    device: HostDevice,
    sockets: SocketSet<'static>,
    echo: smoltcp::iface::SocketHandle,
    /// The echo server stops reading: its window closes.
    paused: bool,
}

const ECHO_PORT: u16 = 7;

impl Host {
    fn new(wire: &'static Wire, clock: &TestClock) -> Self {
        let mut device = HostDevice(wire);
        let config = Config::new(HardwareAddress::Ethernet(EthernetAddress([
            0x02, 0, 0, 0, 0, 0x01,
        ])));
        let mut interface = Interface::new(config, &mut device, timestamp(clock.now()));
        interface.update_ip_addrs(|addresses| {
            addresses
                .push(IpCidr::new(HOST_GATEWAY_IPV4_ADDRESS.into(), 24))
                .unwrap();
        });
        let mut sockets = SocketSet::new(vec![]);
        let mut echo = tcp::Socket::new(
            RingBuffer::new(vec![0; 64 * 1024]),
            RingBuffer::new(vec![0; 64 * 1024]),
        );
        echo.listen(ECHO_PORT).unwrap();
        let echo = sockets.add(echo);
        Self {
            interface,
            device,
            sockets,
            echo,
            paused: false,
        }
    }

    fn poll(&mut self, clock: &TestClock) {
        self.interface
            .poll(timestamp(clock.now()), &mut self.device, &mut self.sockets);
        let echo = self.sockets.get_mut::<tcp::Socket>(self.echo);
        let mut buffer = [0; 4096];
        while !self.paused
            && echo.can_recv()
            && echo.send_capacity() - echo.send_queue() >= buffer.len()
        {
            let n = echo.recv_slice(&mut buffer).unwrap();
            assert_eq!(echo.send_slice(&buffer[..n]).unwrap(), n);
        }
    }
}

struct Test {
    clock: &'static TestClock,
    network: Network,
    broker: litebox_broker_core::BrokerCore,
    sink: Arc<Sink>,
}

impl Test {
    fn new(link: Option<&'static dyn Link>) -> Self {
        Self::with_limits(link, &BrokerCoreLimits::DEFAULT)
    }

    /// `limits` for the stack; the broker core keeps its defaults.
    fn with_limits(link: Option<&'static dyn Link>, limits: &BrokerCoreLimits) -> Self {
        let clock = TestClock::new();
        let network = Network::new(clock, link, 0x1234_5678, limits);
        let anywhere = [DestinationRule::new(
            CallerCredential::Unauthenticated,
            Ipv4Cidr::new(Ipv4Address([0, 0, 0, 0]), 0).unwrap(),
            DestinationPortRange::new(Port(1), Port(u16::MAX)).unwrap(),
        )];
        let policy = SocketPolicy::guest_network()
            .with_tcp_destination_rules(&anywhere)
            .unwrap()
            .with_udp_destination_rules(&anywhere)
            .unwrap();
        let broker = TestBrokerCoreBuilder::new(
            PolicyEngine::with_unauthenticated_rights(ObjectRights::all())
                .with_socket_policy(policy),
        )
        .with_socket_provider(network.provider())
        .build()
        .unwrap();
        Self {
            clock,
            network,
            broker,
            sink: Arc::new(Sink::default()),
        }
    }

    fn process(&self) -> Arc<BrokerProcess> {
        self.broker
            .create_process(CallerCredential::Unauthenticated, None)
            .unwrap()
    }

    fn socket(&self, process: &BrokerProcess, socket_type: SocketType) -> ObjectHandle {
        let protocol = match socket_type {
            SocketType::Stream => IpProtocol::Tcp,
            _ => IpProtocol::Udp,
        };
        core_socket::create(
            process,
            CreateSocketRequest {
                address_family: AddressFamily::Ipv4,
                socket_type,
                protocol,
            },
            self.sink.clone(),
        )
        .unwrap()
    }

    /// The last readiness published for `handle`.
    fn published(&self, handle: ObjectHandle) -> Option<ReadinessFlags> {
        self.sink
            .0
            .lock()
            .iter()
            .rev()
            .find(|(published, _)| *published == handle)
            .map(|&(_, flags)| flags)
    }
}

fn address(ip: [u8; 4], port: u16) -> SocketAddrV4 {
    SocketAddrV4::new(Ipv4Addr::from(ip), port)
}

fn receive(
    process: &BrokerProcess,
    handle: ObjectHandle,
    length: usize,
) -> BrokerResult<SocketOutcome<PlatformStreamReceive>> {
    core_socket::receive(process, handle, length, ReceiveFlags::NONE, 0, 0)
}

#[expect(clippy::unnecessary_wraps, reason = "compared with receive results")]
fn received(data: &[u8]) -> BrokerResult<SocketOutcome<PlatformStreamReceive>> {
    Ok(SocketOutcome::Completed(PlatformStreamReceive::Received(
        data.to_vec(),
    )))
}

const END: BrokerResult<SocketOutcome<PlatformStreamReceive>> =
    Ok(SocketOutcome::Completed(PlatformStreamReceive::EndOfStream));

/// A listener in one process, a connection to it from another, accepted.
struct Pair {
    server: Arc<BrokerProcess>,
    client: Arc<BrokerProcess>,
    listener: ObjectHandle,
    connector: ObjectHandle,
    accepted: ObjectHandle,
}

fn pair(test: &Test, destination: [u8; 4]) -> Pair {
    let server = test.process();
    let client = test.process();
    let listener = test.socket(&server, SocketType::Stream);
    let bound = address([0, 0, 0, 0], 8080);
    assert_eq!(
        core_socket::bind(&server, listener, bound),
        Ok(SocketOutcome::Completed(bound))
    );
    assert_eq!(
        core_socket::listen(&server, listener, 4),
        Ok(SocketOutcome::Completed(bound))
    );
    assert_eq!(test.published(listener), None);
    let connector = test.socket(&client, SocketType::Stream);
    // Guest connections complete within the call.
    assert_eq!(
        core_socket::connect(&client, connector, address(destination, 8080)),
        Ok(SocketOutcome::Completed(SocketConnectionStatus::Connected))
    );
    assert_eq!(test.published(listener), Some(ReadinessFlags::READ));
    let SocketOutcome::Completed(accepted) =
        core_socket::accept(&server, listener, test.sink.clone()).unwrap()
    else {
        panic!("accept failed");
    };
    let local = core_socket::status(&client, connector)
        .unwrap()
        .local_address
        .unwrap();
    assert_eq!(accepted.remote_address, local);
    assert_eq!(accepted.local_address, address(destination, 8080));
    assert_eq!(*local.ip(), Ipv4Addr::from(destination));
    Pair {
        server,
        client,
        listener,
        connector,
        accepted: accepted.handle,
    }
}

#[test]
fn guest_tcp_connections_carry_data_and_half_close() {
    let test = Test::new(None);
    for destination in [[127, 0, 0, 1], GUEST_IPV4_ADDRESS.octets()] {
        let pair = pair(&test, destination);
        assert_eq!(
            core_socket::send(
                &pair.client,
                pair.connector,
                b"ping".to_vec(),
                SendFlags::NONE
            ),
            Ok(SocketOutcome::Completed(4))
        );
        assert!(
            test.published(pair.accepted)
                .unwrap()
                .contains(ReadinessFlags::READ | ReadinessFlags::WRITE)
        );
        // A peek at an offset leaves the data.
        assert_eq!(
            core_socket::receive(&pair.server, pair.accepted, 4, ReceiveFlags::PEEK, 0, 4),
            received(b"ping")
        );
        assert_eq!(receive(&pair.server, pair.accepted, 2), received(b"pi"));
        assert_eq!(receive(&pair.server, pair.accepted, 8), received(b"ng"));
        assert_eq!(
            receive(&pair.server, pair.accepted, 8),
            Err(BrokerError::WouldBlock)
        );

        assert_eq!(
            core_socket::shutdown(&pair.client, pair.connector, ShutdownMode::Write),
            Ok(SocketOutcome::Completed(()))
        );
        assert!(
            test.published(pair.accepted)
                .unwrap()
                .contains(ReadinessFlags::READ | ReadinessFlags::HANGUP)
        );
        assert_eq!(receive(&pair.server, pair.accepted, 8), END);
        // The other direction stays open.
        assert_eq!(
            core_socket::send(
                &pair.server,
                pair.accepted,
                b"pong".to_vec(),
                SendFlags::NONE
            ),
            Ok(SocketOutcome::Completed(4))
        );
        assert_eq!(receive(&pair.client, pair.connector, 8), received(b"pong"));

        pair.server.close_object_reference(pair.accepted).unwrap();
        assert_eq!(receive(&pair.client, pair.connector, 8), END);
        pair.client.close_object_reference(pair.connector).unwrap();
        pair.server.close_object_reference(pair.listener).unwrap();
        test.network.poll();
    }
}

#[test]
fn an_aborted_guest_connection_resets_its_peer_once() {
    let test = Test::new(None);
    let pair = pair(&test, [127, 0, 0, 1]);
    assert_eq!(
        core_socket::shutdown(&pair.server, pair.accepted, ShutdownMode::Abort),
        Ok(SocketOutcome::Completed(()))
    );
    pair.server.close_object_reference(pair.accepted).unwrap();
    assert!(
        test.published(pair.connector)
            .unwrap()
            .contains(ReadinessFlags::ERROR | ReadinessFlags::HANGUP)
    );
    assert_eq!(
        receive(&pair.client, pair.connector, 8),
        Ok(SocketOutcome::Failed(SocketError::ConnectionReset))
    );
    assert_eq!(receive(&pair.client, pair.connector, 8), END);
}

#[test]
fn a_guest_connection_without_a_listener_is_refused() {
    let test = Test::new(None);
    let process = test.process();
    let socket = test.socket(&process, SocketType::Stream);
    assert_eq!(
        core_socket::connect(&process, socket, address([127, 0, 0, 1], 9)),
        Ok(SocketOutcome::Completed(SocketConnectionStatus::Failed(
            SocketError::ConnectionRefused
        )))
    );
}

#[test]
fn a_listener_stops_and_frees_its_port() {
    let test = Test::new(None);
    let pair = pair(&test, [127, 0, 0, 1]);
    assert_eq!(
        core_socket::shutdown(&pair.server, pair.listener, ShutdownMode::StopListening),
        Ok(SocketOutcome::Completed(()))
    );
    let late = test.socket(&pair.client, SocketType::Stream);
    assert_eq!(
        core_socket::connect(&pair.client, late, address([127, 0, 0, 1], 8080)),
        Ok(SocketOutcome::Completed(SocketConnectionStatus::Failed(
            SocketError::ConnectionRefused
        )))
    );
    // The accepted connection outlives its listener.
    assert_eq!(
        core_socket::send(
            &pair.client,
            pair.connector,
            b"still".to_vec(),
            SendFlags::NONE
        ),
        Ok(SocketOutcome::Completed(5))
    );
    assert_eq!(receive(&pair.server, pair.accepted, 8), received(b"still"));
}

#[test]
fn guest_datagrams_carry_their_source_and_respect_the_peer() {
    let test = Test::new(None);
    let process = test.process();
    let a = test.socket(&process, SocketType::Datagram);
    let b = test.socket(&process, SocketType::Datagram);
    let c = test.socket(&process, SocketType::Datagram);
    let b_address = address([0, 0, 0, 0], 5000);
    assert_eq!(
        core_socket::bind(&process, b, b_address),
        Ok(SocketOutcome::Completed(b_address))
    );
    let to_b = address([127, 0, 0, 1], 5000);
    // Larger than an Ethernet frame: the loopback interface carries it whole.
    let big = vec![7; 8000];
    assert_eq!(
        core_socket::send_to(&process, a, big.clone(), SendFlags::NONE, Some(to_b)),
        Ok(SocketOutcome::Completed(big.len()))
    );
    let SocketOutcome::Completed(datagram) =
        core_socket::receive_from(&process, b, 100, ReceiveFromFlags::NONE).unwrap()
    else {
        panic!("receive failed");
    };
    assert_eq!(datagram.data, big[..100]);
    assert_eq!(datagram.datagram_length, big.len());
    assert_eq!(*datagram.source_address.ip(), Ipv4Addr::LOCALHOST);

    // Connected to `a`, `b` drops what `c` sends.
    assert_eq!(
        core_socket::connect(&process, b, datagram.source_address),
        Ok(SocketOutcome::Completed(SocketConnectionStatus::Connected))
    );
    for (from, data) in [(c, b"from c"), (a, b"from a")] {
        assert_eq!(
            core_socket::send_to(&process, from, data.to_vec(), SendFlags::NONE, Some(to_b)),
            Ok(SocketOutcome::Completed(6))
        );
    }
    let SocketOutcome::Completed(datagram) =
        core_socket::receive_from(&process, b, 100, ReceiveFromFlags::NONE).unwrap()
    else {
        panic!("receive failed");
    };
    assert_eq!(datagram.data, b"from a");
    assert_eq!(
        core_socket::receive_from(&process, b, 100, ReceiveFromFlags::NONE).map(|_| ()),
        Err(BrokerError::WouldBlock)
    );
}

#[test]
fn without_a_link_external_destinations_are_unreachable() {
    let test = Test::new(None);
    let process = test.process();
    let tcp = test.socket(&process, SocketType::Stream);
    assert_eq!(
        core_socket::connect(&process, tcp, address([192, 0, 2, 1], 80)),
        Ok(SocketOutcome::Completed(SocketConnectionStatus::Failed(
            SocketError::NetworkUnreachable
        )))
    );
    let udp = test.socket(&process, SocketType::Datagram);
    assert_eq!(
        core_socket::send_to(
            &process,
            udp,
            b"x".to_vec(),
            SendFlags::NONE,
            Some(address([192, 0, 2, 1], 53))
        ),
        Ok(SocketOutcome::Failed(SocketError::NetworkUnreachable))
    );
    assert_eq!(test.network.next_poll(), None);
}

/// Runs both stacks, a millisecond at a time, until `done`.
fn pump(test: &Test, host: &mut Host, mut done: impl FnMut(&mut Host) -> bool) {
    for _ in 0..10_000 {
        test.network.poll();
        host.poll(test.clock);
        if done(host) {
            return;
        }
        test.clock.advance(Duration::from_millis(1));
    }
    panic!("no progress");
}

#[test]
fn external_tcp_reaches_the_host_through_the_link() {
    let wire: &'static Wire = Box::leak(Box::default());
    let test = Test::new(Some(wire));
    let mut host = Host::new(wire, test.clock);
    let process = test.process();
    let socket = test.socket(&process, SocketType::Stream);
    let echo = SocketAddrV4::new(HOST_GATEWAY_IPV4_ADDRESS, ECHO_PORT);
    assert_eq!(
        core_socket::connect(&process, socket, echo),
        Ok(SocketOutcome::Completed(SocketConnectionStatus::Connecting))
    );
    pump(&test, &mut host, |_| {
        test.published(socket)
            .is_some_and(|flags| flags.contains(ReadinessFlags::WRITE))
    });
    let status = core_socket::status(&process, socket).unwrap();
    assert_eq!(status.status, SocketConnectionStatus::Connected);
    assert_eq!(*status.local_address.unwrap().ip(), GUEST_IPV4_ADDRESS);

    // Several windows' worth each way.
    let sent: Vec<u8> = (0..300_000u32).map(|i| (i * 13).to_le_bytes()[0]).collect();
    let mut written = 0;
    let mut echoed = Vec::new();
    pump(&test, &mut host, |_| {
        if written < sent.len() {
            let chunk = sent[written..].iter().take(32 * 1024).copied().collect();
            match core_socket::send(&process, socket, chunk, SendFlags::NONE) {
                Ok(SocketOutcome::Completed(n)) => written += n,
                Err(BrokerError::WouldBlock) => {}
                other => panic!("send: {other:?}"),
            }
        }
        match receive(&process, socket, 32 * 1024) {
            Ok(SocketOutcome::Completed(PlatformStreamReceive::Received(data))) => {
                echoed.extend(data);
            }
            Err(BrokerError::WouldBlock) => {}
            other => panic!("receive: {other:?}"),
        }
        echoed.len() == sent.len()
    });
    assert_eq!(echoed, sent);
}

#[test]
fn external_udp_goes_through_the_gateway() {
    let wire: &'static Wire = Box::leak(Box::default());
    let test = Test::new(Some(wire));
    let mut host = Host::new(wire, test.clock);
    let mut udp = smoltcp::socket::udp::Socket::new(
        smoltcp::socket::udp::PacketBuffer::new(
            vec![smoltcp::socket::udp::PacketMetadata::EMPTY; 4],
            vec![0; 4096],
        ),
        smoltcp::socket::udp::PacketBuffer::new(
            vec![smoltcp::socket::udp::PacketMetadata::EMPTY; 4],
            vec![0; 4096],
        ),
    );
    udp.bind(53).unwrap();
    let host_udp = host.sockets.add(udp);

    let process = test.process();
    let socket = test.socket(&process, SocketType::Datagram);
    let host_address = SocketAddrV4::new(HOST_GATEWAY_IPV4_ADDRESS, 53);
    assert_eq!(
        core_socket::send_to(
            &process,
            socket,
            b"query".to_vec(),
            SendFlags::NONE,
            Some(host_address)
        ),
        Ok(SocketOutcome::Completed(5))
    );
    let mut from = None;
    pump(&test, &mut host, |host| {
        let udp = host
            .sockets
            .get_mut::<smoltcp::socket::udp::Socket>(host_udp);
        if let Ok((data, meta)) = udp.recv() {
            assert_eq!(data, b"query");
            from = Some(meta.endpoint);
        }
        from.is_some()
    });
    let from = from.unwrap();
    assert_eq!(socket_address(from).ip(), &GUEST_IPV4_ADDRESS);
    host.sockets
        .get_mut::<smoltcp::socket::udp::Socket>(host_udp)
        .send_slice(b"answer", from)
        .unwrap();
    pump(&test, &mut host, |_| {
        test.published(socket)
            .is_some_and(|flags| flags.contains(ReadinessFlags::READ))
    });
    let SocketOutcome::Completed(datagram) =
        core_socket::receive_from(&process, socket, 100, ReceiveFromFlags::NONE).unwrap()
    else {
        panic!("receive failed");
    };
    assert_eq!(datagram.data, b"answer");
    assert_eq!(datagram.source_address, host_address);

    // Externally, datagrams must fit a frame.
    assert_eq!(
        core_socket::send_to(
            &process,
            socket,
            vec![0; MAX_EXTERNAL_DATAGRAM + 1],
            SendFlags::NONE,
            Some(host_address)
        ),
        Ok(SocketOutcome::Failed(SocketError::InvalidArgument))
    );
}

#[test]
fn an_unanswered_external_connection_times_out() {
    let wire: &'static Wire = Box::leak(Box::default());
    wire.cut.store(true, Ordering::Relaxed);
    let test = Test::new(Some(wire));
    let process = test.process();
    let socket = test.socket(&process, SocketType::Stream);
    assert_eq!(
        core_socket::connect(&process, socket, address([192, 0, 2, 1], 80)),
        Ok(SocketOutcome::Completed(SocketConnectionStatus::Connecting))
    );
    for _ in 0..200 {
        test.clock.advance(Duration::from_secs(1));
        test.network.poll();
        // The stack asks to run again while it is connecting.
        assert!(test.network.next_poll().is_some());
        if test.published(socket) == Some(ReadinessFlags::ERROR) {
            break;
        }
    }
    assert_eq!(
        core_socket::status(&process, socket).unwrap().status,
        SocketConnectionStatus::Failed(SocketError::TimedOut)
    );
}

/// A listening socket on `address`, in a new process.
fn listener(
    test: &Test,
    address: SocketAddrV4,
    backlog: u32,
) -> (Arc<BrokerProcess>, ObjectHandle) {
    let server = test.process();
    let listener = test.socket(&server, SocketType::Stream);
    assert_eq!(
        core_socket::bind(&server, listener, address),
        Ok(SocketOutcome::Completed(address))
    );
    assert_eq!(
        core_socket::listen(&server, listener, backlog),
        Ok(SocketOutcome::Completed(address))
    );
    (server, listener)
}

#[test]
fn unaccepted_guest_connections_count_against_the_connecting_process() {
    let test = Test::with_limits(None, &BrokerCoreLimits::new_with_all_limits(4096, 0, 64, 4));
    let (server, listener) = listener(&test, address([0, 0, 0, 0], 8080), 4096);
    let client = test.process();
    let destination = address([127, 0, 0, 1], 8080);
    // Until accepted, a connection costs its process two sockets: two fill
    // the client's four.
    for _ in 0..2 {
        let socket = test.socket(&client, SocketType::Stream);
        assert_eq!(
            core_socket::connect(&client, socket, destination),
            Ok(SocketOutcome::Completed(SocketConnectionStatus::Connected))
        );
    }
    let third = test.socket(&client, SocketType::Stream);
    assert_eq!(
        core_socket::connect(&client, third, destination),
        Err(BrokerError::ResourceExhausted)
    );
    // Accepted, they are the server's.
    for _ in 0..2 {
        let SocketOutcome::Completed(_) =
            core_socket::accept(&server, listener, test.sink.clone()).unwrap()
        else {
            panic!("accept failed");
        };
    }
    assert_eq!(
        core_socket::connect(&client, third, destination),
        Ok(SocketOutcome::Completed(SocketConnectionStatus::Connected))
    );
}

#[test]
fn close_process_discards_its_unaccepted_connections() {
    let test = Test::new(None);
    let (server, listener) = listener(&test, address([0, 0, 0, 0], 8080), 8);
    let client = test.process();
    let socket = test.socket(&client, SocketType::Stream);
    assert_eq!(
        core_socket::connect(&client, socket, address([127, 0, 0, 1], 8080)),
        Ok(SocketOutcome::Completed(SocketConnectionStatus::Connected))
    );
    let process = {
        let stack = test.network.0.stack.lock();
        assert_eq!(stack.leases.len(), 1);
        stack.leases[0].process
    };
    test.network.provider().close_process(process);
    assert!(test.network.0.stack.lock().leases.is_empty());
    assert_eq!(
        core_socket::accept(&server, listener, test.sink.clone()).map(|_| ()),
        Err(BrokerError::WouldBlock)
    );
}

#[test]
fn an_aborted_socket_that_cannot_send_its_reset_is_reaped() {
    let wire: &'static Wire = Box::leak(Box::default());
    wire.cut.store(true, Ordering::Relaxed);
    let test = Test::new(Some(wire));
    let process = test.process();
    let socket = test.socket(&process, SocketType::Stream);
    assert_eq!(
        core_socket::connect(&process, socket, address([10, 0, 2, 77], 80)),
        Ok(SocketOutcome::Completed(SocketConnectionStatus::Connecting))
    );
    // Retired while connecting: aborted, with a reset that never resolves
    // its neighbor.
    process.close_object_reference(socket).unwrap();
    assert_eq!(test.network.0.stack.lock().closing.len(), 1);
    test.clock.advance(CLOSE_TIMEOUT + Duration::from_secs(1));
    test.network.poll();
    let stack = test.network.0.stack.lock();
    assert!(stack.closing.is_empty());
    let tcp_sockets = stack
        .sockets
        .external
        .as_ref()
        .unwrap()
        .iter()
        .filter(|(_, socket)| tcp::Socket::downcast(socket).is_some())
        .count();
    assert_eq!(tcp_sockets, 0);
}

#[test]
fn retired_connections_finishing_are_bounded() {
    let test = Test::new(None);
    let (_server, _listener) = listener(&test, address([0, 0, 0, 0], 8080), 4096);
    let client = test.process();
    for _ in 0..MAX_CLOSING + 8 {
        let socket = test.socket(&client, SocketType::Stream);
        assert_eq!(
            core_socket::connect(&client, socket, address([127, 0, 0, 1], 8080)),
            Ok(SocketOutcome::Completed(SocketConnectionStatus::Connected))
        );
        // Unaccepted, the peer never closes: the connection lingers.
        client.close_object_reference(socket).unwrap();
    }
    assert!(test.network.0.stack.lock().closing.len() <= MAX_CLOSING);
}

#[test]
fn udp_is_not_writable_while_the_external_queue_is_full() {
    let wire: &'static Wire = Box::leak(Box::default());
    // The gateway never answers ARP: datagrams wait in the queue.
    wire.cut.store(true, Ordering::Relaxed);
    let test = Test::new(Some(wire));
    let process = test.process();
    let socket = test.socket(&process, SocketType::Datagram);
    let destination = address([192, 0, 2, 1], 53);
    let mut sent = 0;
    loop {
        match core_socket::send_to(
            &process,
            socket,
            b"x".to_vec(),
            SendFlags::NONE,
            Some(destination),
        ) {
            Ok(SocketOutcome::Completed(_)) => sent += 1,
            Err(BrokerError::WouldBlock) => break,
            other => panic!("send: {other:?}"),
        }
        assert!(sent < 1000, "the queue never filled");
    }
    assert!(
        !test
            .published(socket)
            .unwrap()
            .contains(ReadinessFlags::WRITE)
    );
    // Guest destinations are still reachable.
    let peer = test.socket(&process, SocketType::Datagram);
    let peer_address = address([0, 0, 0, 0], 6000);
    assert_eq!(
        core_socket::bind(&process, peer, peer_address),
        Ok(SocketOutcome::Completed(peer_address))
    );
    assert_eq!(
        core_socket::send_to(
            &process,
            socket,
            b"y".to_vec(),
            SendFlags::NONE,
            Some(address([127, 0, 0, 1], 6000))
        ),
        Ok(SocketOutcome::Completed(1))
    );
}

#[test]
fn every_loopback_address_reaches_the_guest() {
    let test = Test::new(None);
    let exact = address([127, 0, 0, 2], 8081);
    let (_server, _exact_listener) = listener(&test, exact, 4);
    let (_server, _wildcard_listener) = listener(&test, address([0, 0, 0, 0], 8082), 4);
    let client = test.process();
    for destination in [exact, address([127, 0, 0, 3], 8082)] {
        let socket = test.socket(&client, SocketType::Stream);
        assert_eq!(
            core_socket::connect(&client, socket, destination),
            Ok(SocketOutcome::Completed(SocketConnectionStatus::Connected)),
            "{destination}"
        );
    }
}

#[test]
fn a_network_deadline_comes_due_without_running_the_stack() {
    let wire: &'static Wire = Box::leak(Box::default());
    wire.cut.store(true, Ordering::Relaxed);
    let test = Test::new(Some(wire));
    let process = test.process();
    let socket = test.socket(&process, SocketType::Stream);
    assert_eq!(
        core_socket::connect(&process, socket, address([192, 0, 2, 1], 80)),
        Ok(SocketOutcome::Completed(SocketConnectionStatus::Connecting))
    );
    // A caller compares the deadline with its own reading of the clock,
    // taken before asking: once that passes it, it stays passed.
    let deadline = test.network.next_poll().unwrap();
    assert!(deadline > test.clock.now());
    test.clock
        .advance(deadline.checked_sub(test.clock.now()).unwrap());
    let observed = test.clock.now();
    test.clock.advance(Duration::from_micros(10));
    assert!(test.network.next_poll().unwrap() <= observed);
    // Running the stack moves it on.
    test.network.poll();
    assert!(test.network.next_poll().unwrap() > test.clock.now());
}

#[test]
fn a_polled_link_comes_due_at_its_interval() {
    let wire: &'static Wire = Box::leak(Box::new(Wire {
        polled: true,
        ..Wire::default()
    }));
    let test = Test::new(Some(wire));
    test.network.poll();
    let ran = test.clock.now();
    assert_eq!(test.network.next_poll(), Some(ran + LINK_POLL_INTERVAL));
    test.clock.advance(2 * LINK_POLL_INTERVAL);
    assert_eq!(test.network.next_poll(), Some(ran + LINK_POLL_INTERVAL));
}

#[test]
fn udp_waits_for_payload_room_and_is_woken_when_it_frees() {
    let wire: &'static Wire = Box::leak(Box::default());
    // Until the gateway answers ARP, datagrams wait in the queue.
    wire.cut.store(true, Ordering::Relaxed);
    let test = Test::new(Some(wire));
    let mut host = Host::new(wire, test.clock);
    let process = test.process();
    let socket = test.socket(&process, SocketType::Datagram);
    let destination = SocketAddrV4::new(HOST_GATEWAY_IPV4_ADDRESS, 9);
    let datagram = vec![0; MAX_EXTERNAL_DATAGRAM];
    let mut sent = 0;
    loop {
        match core_socket::send_to(
            &process,
            socket,
            datagram.clone(),
            SendFlags::NONE,
            Some(destination),
        ) {
            Ok(SocketOutcome::Completed(_)) => sent += 1,
            Err(BrokerError::WouldBlock) => break,
            other => panic!("send: {other:?}"),
        }
    }
    // The payload buffer filled before the packet slots did.
    assert!(sent < super::udp::PACKETS);
    assert!(
        !test
            .published(socket)
            .unwrap()
            .contains(ReadinessFlags::WRITE)
    );

    wire.cut.store(false, Ordering::Relaxed);
    pump(&test, &mut host, |_| {
        test.published(socket)
            .is_some_and(|flags| flags.contains(ReadinessFlags::WRITE))
    });
    assert_eq!(
        core_socket::send_to(
            &process,
            socket,
            datagram,
            SendFlags::NONE,
            Some(destination)
        ),
        Ok(SocketOutcome::Completed(MAX_EXTERNAL_DATAGRAM))
    );
}

#[test]
fn a_peeked_datagram_is_the_next_received() {
    let wire: &'static Wire = Box::leak(Box::default());
    let test = Test::new(Some(wire));
    let mut host = Host::new(wire, test.clock);
    let mut udp = smoltcp::socket::udp::Socket::new(
        smoltcp::socket::udp::PacketBuffer::new(
            vec![smoltcp::socket::udp::PacketMetadata::EMPTY; 4],
            vec![0; 4096],
        ),
        smoltcp::socket::udp::PacketBuffer::new(
            vec![smoltcp::socket::udp::PacketMetadata::EMPTY; 4],
            vec![0; 4096],
        ),
    );
    udp.bind(53).unwrap();
    let host_udp = host.sockets.add(udp);

    let process = test.process();
    let socket = test.socket(&process, SocketType::Datagram);
    let bound = address([0, 0, 0, 0], 5000);
    assert_eq!(
        core_socket::bind(&process, socket, bound),
        Ok(SocketOutcome::Completed(bound))
    );
    host.sockets
        .get_mut::<smoltcp::socket::udp::Socket>(host_udp)
        .send_slice(b"external", (GUEST_IPV4_ADDRESS, 5000))
        .unwrap();
    pump(&test, &mut host, |_| {
        test.published(socket)
            .is_some_and(|flags| flags.contains(ReadinessFlags::READ))
    });
    let receive = |flags| match core_socket::receive_from(&process, socket, 100, flags).unwrap() {
        SocketOutcome::Completed(datagram) => datagram.data,
        SocketOutcome::Failed(error) => panic!("receive: {error:?}"),
    };
    assert_eq!(receive(ReceiveFromFlags::PEEK), b"external");

    // A guest datagram arriving meanwhile waits its turn.
    let sender = test.socket(&process, SocketType::Datagram);
    assert_eq!(
        core_socket::send_to(
            &process,
            sender,
            b"guest".to_vec(),
            SendFlags::NONE,
            Some(address([127, 0, 0, 1], 5000))
        ),
        Ok(SocketOutcome::Completed(5))
    );
    assert_eq!(receive(ReceiveFromFlags::NONE), b"external");
    assert_eq!(receive(ReceiveFromFlags::NONE), b"guest");
}

#[test]
fn a_run_takes_a_bounded_number_of_frames() {
    let wire: &'static Wire = Box::leak(Box::default());
    let test = Test::new(Some(wire));
    test.network.poll();
    // Frames to the guest that it drops (an unknown EtherType): as many as
    // a flood might bring.
    let mut frame = vec![0; 60];
    frame[..6].copy_from_slice(&wire.mac());
    frame[12..14].copy_from_slice(&0x88b5_u16.to_be_bytes());
    let flood = 3 * MAX_FRAMES_PER_RUN + 10;
    wire.to_guest
        .lock()
        .extend(core::iter::repeat_n(frame, flood));
    test.clock.advance(Duration::from_millis(5));
    test.network.poll();
    assert_eq!(wire.to_guest.lock().len(), flood - MAX_FRAMES_PER_RUN);
    // The rest are due at the earliest next run.
    let ran = test.clock.now();
    assert_eq!(test.network.next_poll(), Some(ran + MIN_POLL_DELAY));
    test.clock.advance(MIN_POLL_DELAY);
    test.network.poll();
    assert_eq!(wire.to_guest.lock().len(), flood - 2 * MAX_FRAMES_PER_RUN);
}

#[test]
fn a_connected_udp_socket_drops_other_senders_as_they_arrive() {
    let test = Test::new(None);
    let process = test.process();
    let [peer, receiver, stranger] = [(); 3].map(|()| test.socket(&process, SocketType::Datagram));
    let peer_address = address([127, 0, 0, 1], 6000);
    let receiver_address = address([127, 0, 0, 1], 6001);
    for (socket, bound) in [(peer, peer_address), (receiver, receiver_address)] {
        assert_eq!(
            core_socket::bind(&process, socket, bound),
            Ok(SocketOutcome::Completed(bound))
        );
    }
    assert_eq!(
        core_socket::connect(&process, receiver, peer_address),
        Ok(SocketOutcome::Completed(SocketConnectionStatus::Connected))
    );
    // More than smoltcp's queue holds, from a stranger.
    for _ in 0..2 * super::udp::PACKETS {
        assert_eq!(
            core_socket::send_to(
                &process,
                stranger,
                b"junk".to_vec(),
                SendFlags::NONE,
                Some(receiver_address)
            ),
            Ok(SocketOutcome::Completed(4))
        );
    }
    assert_eq!(test.published(receiver), Some(ReadinessFlags::WRITE));
    assert_eq!(
        core_socket::send_to(
            &process,
            peer,
            b"reply".to_vec(),
            SendFlags::NONE,
            Some(receiver_address)
        ),
        Ok(SocketOutcome::Completed(5))
    );
    let SocketOutcome::Completed(datagram) =
        core_socket::receive_from(&process, receiver, 100, ReceiveFromFlags::NONE).unwrap()
    else {
        panic!("receive failed");
    };
    assert_eq!(datagram.data, b"reply");
    assert_eq!(datagram.source_address, peer_address);
}

#[test]
fn a_lingering_closed_connection_is_reaped_on_time() {
    let test = Test::new(None);
    let (_server, _listener) = listener(&test, address([0, 0, 0, 0], 8080), 4);
    let client = test.process();
    let socket = test.socket(&client, SocketType::Stream);
    assert_eq!(
        core_socket::connect(&client, socket, address([127, 0, 0, 1], 8080)),
        Ok(SocketOutcome::Completed(SocketConnectionStatus::Connected))
    );
    // Never accepted, the peer never closes: FIN-WAIT-2, with no timer.
    client.close_object_reference(socket).unwrap();
    assert_eq!(test.network.0.stack.lock().closing.len(), 1);
    let deadline = test.network.next_poll().unwrap();
    assert!(deadline <= test.clock.now() + CLOSE_TIMEOUT);
    test.clock
        .advance(deadline.checked_sub(test.clock.now()).unwrap());
    test.network.poll();
    assert!(test.network.0.stack.lock().closing.is_empty());
}

#[test]
fn a_connection_beyond_the_backlog_is_refused() {
    let test = Test::new(None);
    let (server, listener) = listener(&test, address([0, 0, 0, 0], 8080), 1);
    let client = test.process();
    let destination = address([127, 0, 0, 1], 8080);
    let first = test.socket(&client, SocketType::Stream);
    assert_eq!(
        core_socket::connect(&client, first, destination),
        Ok(SocketOutcome::Completed(SocketConnectionStatus::Connected))
    );
    // As on the userland broker.
    let full = test.socket(&client, SocketType::Stream);
    assert_eq!(
        core_socket::connect(&client, full, destination),
        Ok(SocketOutcome::Completed(SocketConnectionStatus::Failed(
            SocketError::ConnectionRefused
        )))
    );
    // Room again.
    let SocketOutcome::Completed(_) =
        core_socket::accept(&server, listener, test.sink.clone()).unwrap()
    else {
        panic!("accept failed");
    };
    let next = test.socket(&client, SocketType::Stream);
    assert_eq!(
        core_socket::connect(&client, next, destination),
        Ok(SocketOutcome::Completed(SocketConnectionStatus::Connected))
    );
}

/// A SYN to `destination`, as the loopback device carries it.
fn syn(destination: SocketAddrV4) -> Vec<u8> {
    use smoltcp::wire::{Ipv4Packet, TcpPacket};
    let mut packet = vec![0; 40];
    let mut ip = Ipv4Packet::new_unchecked(&mut packet);
    ip.set_version(4);
    ip.set_header_len(20);
    ip.set_total_len(40);
    ip.set_next_header(smoltcp::wire::IpProtocol::Tcp);
    ip.set_src_addr(Ipv4Addr::LOCALHOST);
    ip.set_dst_addr(*destination.ip());
    let mut tcp = TcpPacket::new_unchecked(&mut packet[20..]);
    tcp.set_header_len(20);
    tcp.set_src_port(40000);
    tcp.set_dst_port(destination.port());
    tcp.set_syn(true);
    packet
}

#[test]
fn syns_beyond_the_listening_sockets_wait_while_the_backlog_has_room() {
    use device::{ListenerRoom, Loopback};
    let destination = address([127, 0, 0, 1], 8080);
    let room = |idle, backlog| {
        let mut loopback = Loopback::new();
        loopback.set_listeners(vec![ListenerRoom {
            endpoint: IpListenEndpoint::from(8080),
            idle,
            backlog,
        }]);
        loopback
    };
    // A listening socket each, then none: dropped, for a retry.
    let mut loopback = room(2, 8);
    assert!(loopback.admits(&syn(destination)));
    assert!(loopback.admits(&syn(destination)));
    assert!(!loopback.admits(&syn(destination)));
    // A full backlog: to smoltcp, which refuses it.
    let mut loopback = room(0, 0);
    assert!(loopback.admits(&syn(destination)));
    // Other ports, and anything but a SYN, always pass.
    let mut loopback = room(0, 8);
    assert!(loopback.admits(&syn(address([127, 0, 0, 1], 8081))));
    let mut ack = syn(destination);
    TcpPacketMut::new_unchecked(&mut ack[20..]).set_ack(true);
    assert!(loopback.admits(&ack));
}

type TcpPacketMut<'a> = smoltcp::wire::TcpPacket<&'a mut [u8]>;

#[test]
fn port_unreachable_fails_a_connected_udp_socket() {
    let test = Test::new(None);
    let process = test.process();
    let unconnected = test.socket(&process, SocketType::Datagram);
    let connected = test.socket(&process, SocketType::Datagram);
    let closed = address([127, 0, 0, 1], 9);
    assert_eq!(
        core_socket::connect(&process, connected, closed),
        Ok(SocketOutcome::Completed(SocketConnectionStatus::Connected))
    );
    for socket in [unconnected, connected] {
        assert_eq!(
            core_socket::send_to(
                &process,
                socket,
                b"x".to_vec(),
                SendFlags::NONE,
                Some(closed)
            ),
            Ok(SocketOutcome::Completed(1))
        );
    }
    // As on Linux, only the connected socket learns of it.
    assert!(
        test.published(connected)
            .unwrap()
            .contains(ReadinessFlags::ERROR)
    );
    assert!(
        !test
            .published(unconnected)
            .unwrap()
            .contains(ReadinessFlags::ERROR)
    );
    assert_eq!(
        core_socket::receive_from(&process, connected, 100, ReceiveFromFlags::NONE),
        Ok(SocketOutcome::Failed(SocketError::ConnectionRefused))
    );
    // Consumed.
    assert_eq!(
        core_socket::receive_from(&process, connected, 100, ReceiveFromFlags::NONE).map(|_| ()),
        Err(BrokerError::WouldBlock)
    );
}

#[test]
fn port_unreachable_from_the_host_reaches_a_connected_udp_socket() {
    let wire: &'static Wire = Box::leak(Box::default());
    let test = Test::new(Some(wire));
    let mut host = Host::new(wire, test.clock);
    let process = test.process();
    let socket = test.socket(&process, SocketType::Datagram);
    let closed = SocketAddrV4::new(HOST_GATEWAY_IPV4_ADDRESS, 9);
    assert_eq!(
        core_socket::connect(&process, socket, closed),
        Ok(SocketOutcome::Completed(SocketConnectionStatus::Connected))
    );
    // A datagram longer than an ICMP error quotes.
    assert_eq!(
        core_socket::send_to(&process, socket, vec![0; 1000], SendFlags::NONE, None),
        Ok(SocketOutcome::Completed(1000))
    );
    pump(&test, &mut host, |_| {
        test.published(socket)
            .is_some_and(|flags| flags.contains(ReadinessFlags::ERROR))
    });
    assert_eq!(
        core_socket::status(&process, socket).unwrap().pending_error,
        Some(SocketError::ConnectionRefused)
    );
}

#[test]
fn a_connected_udp_socket_keeps_its_peers_datagram_from_a_burst() {
    let wire: &'static Wire = Box::leak(Box::default());
    let test = Test::new(Some(wire));
    let mut host = Host::new(wire, test.clock);
    let udp = |port| {
        let buffer = || {
            smoltcp::socket::udp::PacketBuffer::new(
                vec![smoltcp::socket::udp::PacketMetadata::EMPTY; 64],
                vec![0; 16 * 1024],
            )
        };
        let mut socket = smoltcp::socket::udp::Socket::new(buffer(), buffer());
        socket.bind(port).unwrap();
        socket
    };
    let peer = host.sockets.add(udp(7000));
    let stranger = host.sockets.add(udp(53));

    let process = test.process();
    let socket = test.socket(&process, SocketType::Datagram);
    let peer_address = SocketAddrV4::new(HOST_GATEWAY_IPV4_ADDRESS, 7000);
    assert_eq!(
        core_socket::connect(&process, socket, peer_address),
        Ok(SocketOutcome::Completed(SocketConnectionStatus::Connected))
    );
    // Resolves the neighbors both ways.
    assert_eq!(
        core_socket::send_to(&process, socket, b"hello".to_vec(), SendFlags::NONE, None),
        Ok(SocketOutcome::Completed(5))
    );
    pump(&test, &mut host, |host| {
        host.sockets
            .get_mut::<smoltcp::socket::udp::Socket>(peer)
            .recv()
            .is_ok()
    });
    let guest = core_socket::status(&process, socket)
        .unwrap()
        .local_address
        .unwrap();

    // More strangers' datagrams than a smoltcp queue holds, then the peer's,
    // all arriving in one run.
    for _ in 0..40 {
        host.sockets
            .get_mut::<smoltcp::socket::udp::Socket>(stranger)
            .send_slice(b"junk", guest)
            .unwrap();
    }
    // The host sends one datagram per socket per run.
    for _ in 0..40 {
        host.poll(test.clock);
    }
    host.sockets
        .get_mut::<smoltcp::socket::udp::Socket>(peer)
        .send_slice(b"reply", guest)
        .unwrap();
    host.poll(test.clock);
    assert_eq!(wire.to_guest.lock().len(), 41);
    test.network.poll();
    let SocketOutcome::Completed(datagram) =
        core_socket::receive_from(&process, socket, 100, ReceiveFromFlags::NONE).unwrap()
    else {
        panic!("receive failed");
    };
    assert_eq!(datagram.data, b"reply");
}

/// An ICMP "destination unreachable" with `code` about a UDP datagram from
/// port 5000 to `destination`, quoting its headers only, as from loopback
/// (no checksums).
fn unreachable(code: u8, destination: SocketAddrV4) -> Vec<u8> {
    use smoltcp::wire::Ipv4Packet;
    let mut packet = vec![0; 20 + 8 + 20 + 8];
    let mut ip = Ipv4Packet::new_unchecked(&mut packet);
    ip.set_version(4);
    ip.set_header_len(20);
    ip.set_total_len(56);
    ip.set_next_header(smoltcp::wire::IpProtocol::Icmp);
    ip.set_dst_addr(Ipv4Addr::LOCALHOST);
    let icmp = &mut packet[20..];
    icmp[0] = 3;
    icmp[1] = code;
    let mut quoted = Ipv4Packet::new_unchecked(&mut icmp[8..]);
    quoted.set_version(4);
    quoted.set_header_len(20);
    // The datagram was longer than what is quoted.
    quoted.set_total_len(1028);
    quoted.set_next_header(smoltcp::wire::IpProtocol::Udp);
    quoted.set_dst_addr(*destination.ip());
    let udp = &mut icmp[28..];
    udp[..2].copy_from_slice(&5000_u16.to_be_bytes());
    udp[2..4].copy_from_slice(&destination.port().to_be_bytes());
    packet
}

#[test]
fn only_errors_linux_reports_reach_udp_sockets() {
    let destination = address([127, 0, 0, 1], 9);
    let error = |code| udp_error(&unreachable(code, destination), Side::Internal);
    assert_eq!(
        error(3),
        Some((5000, destination, SocketError::ConnectionRefused))
    );
    assert_eq!(
        error(10),
        Some((5000, destination, SocketError::HostUnreachable))
    );
    // Soft: network and host unreachable, fragmentation needed.
    for code in [0, 1, 4] {
        assert_eq!(error(code), None, "code {code}");
    }
}

/// A connection to the host's echo server, established.
fn echo_connection(test: &Test, host: &mut Host) -> (Arc<BrokerProcess>, ObjectHandle) {
    let process = test.process();
    let socket = test.socket(&process, SocketType::Stream);
    let echo = SocketAddrV4::new(HOST_GATEWAY_IPV4_ADDRESS, ECHO_PORT);
    assert_eq!(
        core_socket::connect(&process, socket, echo),
        Ok(SocketOutcome::Completed(SocketConnectionStatus::Connecting))
    );
    pump(test, host, |_| {
        test.published(socket)
            .is_some_and(|flags| flags.contains(ReadinessFlags::WRITE))
    });
    (process, socket)
}

/// Runs both stacks for `duration`, `step` at a time.
fn run_for(test: &Test, host: &mut Host, duration: Duration, step: Duration) {
    let mut elapsed = Duration::ZERO;
    while elapsed < duration {
        test.clock.advance(step);
        elapsed += step;
        test.network.poll();
        host.poll(test.clock);
    }
}

#[test]
fn unacknowledged_data_to_a_dead_peer_times_out() {
    let wire: &'static Wire = Box::leak(Box::default());
    let test = Test::new(Some(wire));
    let mut host = Host::new(wire, test.clock);
    let (process, socket) = echo_connection(&test, &mut host);
    // The host goes away.
    wire.cut.store(true, Ordering::Relaxed);
    assert_eq!(
        core_socket::send(&process, socket, b"hello?".to_vec(), SendFlags::NONE),
        Ok(SocketOutcome::Completed(6))
    );
    run_for(
        &test,
        &mut host,
        Duration::from_mins(15),
        Duration::from_secs(5),
    );
    assert!(
        !test
            .published(socket)
            .unwrap()
            .contains(ReadinessFlags::ERROR)
    );
    run_for(
        &test,
        &mut host,
        Duration::from_mins(1),
        Duration::from_secs(5),
    );
    assert!(
        test.published(socket)
            .unwrap()
            .contains(ReadinessFlags::ERROR)
    );
    // As on Linux: the error once, then the end of the stream.
    assert_eq!(
        receive(&process, socket, 8),
        Ok(SocketOutcome::Failed(SocketError::TimedOut))
    );
    assert_eq!(receive(&process, socket, 8), END);
}

#[test]
fn an_idle_connection_does_not_time_out() {
    let wire: &'static Wire = Box::leak(Box::default());
    let test = Test::new(Some(wire));
    let mut host = Host::new(wire, test.clock);
    let (_process, socket) = echo_connection(&test, &mut host);
    // Nothing to send: even a peer gone silent is no reason to end it.
    wire.cut.store(true, Ordering::Relaxed);
    run_for(
        &test,
        &mut host,
        Duration::from_hours(1),
        Duration::from_secs(30),
    );
    assert!(
        !test
            .published(socket)
            .unwrap()
            .contains(ReadinessFlags::ERROR)
    );
}

#[test]
fn a_peer_with_a_closed_window_that_answers_keeps_the_connection() {
    let wire: &'static Wire = Box::leak(Box::default());
    let test = Test::new(Some(wire));
    let mut host = Host::new(wire, test.clock);
    let (process, socket) = echo_connection(&test, &mut host);
    // The host stops reading; the guest fills its window and more.
    host.paused = true;
    let chunk = vec![7; 32 * 1024];
    let mut sent = 0;
    for _ in 0..1000 {
        match core_socket::send(&process, socket, chunk.clone(), SendFlags::NONE) {
            Ok(SocketOutcome::Completed(n)) => sent += n,
            Err(BrokerError::WouldBlock) => {}
            other => panic!("send: {other:?}"),
        }
        test.clock.advance(Duration::from_millis(10));
        test.network.poll();
        host.poll(test.clock);
    }
    // More than the host's window: the rest waits.
    assert!(sent > 64 * 1024, "sent {sent}");
    assert!(
        !test
            .published(socket)
            .unwrap()
            .contains(ReadinessFlags::WRITE)
    );
    // Well past the timeout, with the window still closed.
    run_for(
        &test,
        &mut host,
        Duration::from_secs(2000),
        Duration::from_secs(5),
    );
    assert!(
        !test
            .published(socket)
            .unwrap()
            .contains(ReadinessFlags::ERROR)
    );
    // The host reads again: everything gets through.
    host.paused = false;
    let mut echoed = 0;
    pump(&test, &mut host, |_| {
        if let Ok(SocketOutcome::Completed(PlatformStreamReceive::Received(data))) =
            receive(&process, socket, 32 * 1024)
        {
            echoed += data.len();
        }
        echoed == sent
    });
}
