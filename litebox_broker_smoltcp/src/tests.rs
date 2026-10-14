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
use core::time::Duration;

use litebox_broker_core::BrokerCoreLimits;
use litebox_broker_core::readiness::ReadinessSink;
use litebox_broker_core::socket::SocketProvider as _;
use litebox_broker_core::socket::{self as core_socket, PlatformStreamReceive};
use litebox_broker_core::test_support::{ManualTimerProvider, TestBrokerCoreBuilder};
use litebox_broker_core::timer::TimerProvider as _;
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
use smoltcp::wire::{EthernetAddress, HardwareAddress, IpCidr};
use spin::Mutex;

use super::*;

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

impl Network for Wire {
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
    fn new(wire: &'static Wire, clock: &ManualTimerProvider) -> Self {
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

    /// Sends `last` on the echo connection, and closes it; it echoes no more.
    fn close_echo(&mut self, last: &[u8]) {
        self.paused = true;
        let echo = self.sockets.get_mut::<tcp::Socket>(self.echo);
        assert_eq!(echo.send_slice(last), Ok(last.len()));
        echo.close();
    }

    fn poll(&mut self, clock: &ManualTimerProvider) {
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
    clock: Arc<ManualTimerProvider>,
    provider: Arc<SmoltcpSocketProvider>,
    broker: litebox_broker_core::BrokerCore,
    sink: Arc<Sink>,
}

impl Test {
    fn new(link: Option<&'static dyn Network>) -> Self {
        Self::with_limits(link, &BrokerCoreLimits::DEFAULT)
    }

    /// `limits` for the stack; the broker core keeps its defaults.
    fn with_limits(link: Option<&'static dyn Network>, limits: &BrokerCoreLimits) -> Self {
        let clock = Arc::new(ManualTimerProvider::default());
        // Not at the clock's origin.
        clock.advance(Duration::from_secs(1));
        let provider = Arc::new(SmoltcpSocketProvider::new(
            limits.max_sockets,
            limits.max_sockets_per_process,
            clock.clone(),
            link,
            0x1234_5678,
        ));
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
        .with_socket_provider(provider.clone())
        .build()
        .unwrap();
        Self {
            clock,
            provider,
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

        pair.client.close_object_reference(pair.connector).unwrap();
        assert_eq!(receive(&pair.server, pair.accepted, 8), END);
        // As on the userland broker, which reports its socket pair's `EPIPE`
        // so.
        assert_eq!(
            core_socket::send(&pair.server, pair.accepted, b"x".to_vec(), SendFlags::NONE),
            Ok(SocketOutcome::Failed(SocketError::ConnectionReset))
        );
        pair.server.close_object_reference(pair.accepted).unwrap();
        pair.server.close_object_reference(pair.listener).unwrap();
        test.provider.poll();
    }
}

#[test]
fn an_aborted_guest_connection_resets_its_peer_once() {
    let test = Test::new(None);
    let pair = pair(&test, [127, 0, 0, 1]);
    // A peek chunk's worth, unread.
    let chunk = litebox_broker_protocol::socket::MAX_SOCKET_TRANSFER_SIZE;
    let data = vec![1; chunk as usize];
    assert_eq!(
        core_socket::send(&pair.server, pair.accepted, data.clone(), SendFlags::NONE),
        Ok(SocketOutcome::Completed(data.len()))
    );
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
    // A peek past it ends there, and leaves the reset, as on Linux.
    let peek = |offset| {
        core_socket::receive(
            &pair.client,
            pair.connector,
            chunk as usize,
            ReceiveFlags::PEEK,
            offset,
            offset + chunk,
        )
    };
    assert_eq!(peek(0), received(&data));
    assert_eq!(
        peek(chunk),
        Ok(SocketOutcome::Completed(PlatformStreamReceive::EndOfStream))
    );
    assert_eq!(
        receive(&pair.client, pair.connector, chunk as usize),
        received(&data)
    );
    assert_eq!(
        receive(&pair.client, pair.connector, 8),
        Ok(SocketOutcome::Failed(SocketError::ConnectionReset))
    );
    assert_eq!(receive(&pair.client, pair.connector, 8), END);
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
    // Larger than an Ethernet frame: between guest sockets, delivered whole.
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
    assert_eq!(test.provider.next_deadline(), None);
}

/// Runs both stacks, a millisecond at a time, until `done`.
fn pump(test: &Test, host: &mut Host, mut done: impl FnMut(&mut Host) -> bool) {
    for _ in 0..10_000 {
        test.provider.poll();
        host.poll(&test.clock);
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
    let mut host = Host::new(wire, &test.clock);
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
    let mut host = Host::new(wire, &test.clock);
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
        test.provider.poll();
        // The stack asks to run again while it is connecting.
        assert!(test.provider.next_deadline().is_some());
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
    // As on the userland broker, they count when creating a socket too.
    assert_eq!(
        core_socket::create(
            &client,
            CreateSocketRequest {
                address_family: AddressFamily::Ipv4,
                socket_type: SocketType::Stream,
                protocol: IpProtocol::Tcp,
            },
            test.sink.clone(),
        )
        .map(|_| ()),
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
    let third = test.socket(&client, SocketType::Stream);
    assert_eq!(
        core_socket::connect(&client, third, destination),
        Ok(SocketOutcome::Completed(SocketConnectionStatus::Connected))
    );
    // Its process ending discards it.
    let queued = || -> Vec<ProcessId> {
        let stack = test.provider.0.stack.lock();
        stack
            .entries
            .values()
            .flat_map(|entry| match &entry.kind {
                Kind::Tcp(tcp) => tcp.queued().map(|queued| queued.process).collect(),
                Kind::Udp(_) => Vec::new(),
            })
            .collect()
    };
    let processes = queued();
    assert_eq!(processes.len(), 1);
    test.provider.close_process(processes[0]);
    assert_eq!(queued(), Vec::<ProcessId>::new());
    assert_eq!(
        core_socket::accept(&server, listener, test.sink.clone()).map(|_| ()),
        Err(BrokerError::WouldBlock)
    );
}

#[test]
fn accepting_beyond_the_listeners_process_limit_fails() {
    let test = Test::with_limits(None, &BrokerCoreLimits::new_with_all_limits(4096, 0, 64, 2));
    let (server, listener) = listener(&test, address([0, 0, 0, 0], 8080), 8);
    let client = test.process();
    let destination = address([127, 0, 0, 1], 8080);
    let socket = test.socket(&client, SocketType::Stream);
    assert_eq!(
        core_socket::connect(&client, socket, destination),
        Ok(SocketOutcome::Completed(SocketConnectionStatus::Connected))
    );
    // The listener and its first accepted connection fill the server's two.
    let SocketOutcome::Completed(accepted) =
        core_socket::accept(&server, listener, test.sink.clone()).unwrap()
    else {
        panic!("accept failed");
    };
    client.close_object_reference(socket).unwrap();
    let socket = test.socket(&client, SocketType::Stream);
    assert_eq!(
        core_socket::connect(&client, socket, destination),
        Ok(SocketOutcome::Completed(SocketConnectionStatus::Connected))
    );
    // As on the userland broker; the connection waits.
    assert_eq!(
        core_socket::accept(&server, listener, test.sink.clone()).map(|_| ()),
        Err(BrokerError::ResourceExhausted)
    );
    server.close_object_reference(accepted.handle).unwrap();
    let SocketOutcome::Completed(_) =
        core_socket::accept(&server, listener, test.sink.clone()).unwrap()
    else {
        panic!("accept failed");
    };
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
    assert_eq!(test.provider.0.stack.lock().closing.len(), 1);
    test.clock.advance(CLOSE_TIMEOUT + Duration::from_secs(1));
    test.provider.poll();
    let stack = test.provider.0.stack.lock();
    assert!(stack.closing.is_empty());
    let tcp_sockets = stack
        .sockets
        .set
        .iter()
        .filter(|(_, socket)| tcp::Socket::downcast(socket).is_some())
        .count();
    assert_eq!(tcp_sockets, 0);
}

#[test]
fn retired_connections_finishing_are_bounded() {
    let wire: &'static Wire = Box::leak(Box::default());
    // Nothing answers: the connections' resets wait for their neighbor.
    wire.cut.store(true, Ordering::Relaxed);
    let test = Test::new(Some(wire));
    let client = test.process();
    for _ in 0..MAX_CLOSING + 8 {
        let socket = test.socket(&client, SocketType::Stream);
        assert_eq!(
            core_socket::connect(&client, socket, address([10, 0, 2, 77], 80)),
            Ok(SocketOutcome::Completed(SocketConnectionStatus::Connecting))
        );
        client.close_object_reference(socket).unwrap();
    }
    // Those beyond it are reset, and gone once that is sent.
    test.provider.0.run(|_| ());
    assert!(test.provider.0.stack.lock().closing.len() <= MAX_CLOSING);
}

#[test]
fn a_network_deadline_comes_due_without_running_the_stack() {
    let wire: &'static Wire = Box::leak(Box::new(Wire {
        polled: true,
        ..Wire::default()
    }));
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
    let deadline = test.provider.next_deadline().unwrap();
    assert!(deadline > test.clock.now());
    test.clock
        .advance(deadline.checked_sub(test.clock.now()).unwrap());
    let observed = test.clock.now();
    test.clock.advance(Duration::from_micros(10));
    assert!(test.provider.next_deadline().unwrap() <= observed);
    // Running the stack moves it on: a polled link, to its interval.
    test.provider.poll();
    let ran = test.clock.now();
    assert_eq!(test.provider.next_deadline(), Some(ran + POLL_INTERVAL));
    test.clock.advance(2 * POLL_INTERVAL);
    assert_eq!(test.provider.next_deadline(), Some(ran + POLL_INTERVAL));
}

#[test]
fn udp_waits_for_payload_room_and_is_woken_when_it_frees() {
    let wire: &'static Wire = Box::leak(Box::default());
    // Until the gateway answers ARP, datagrams wait in the queue.
    wire.cut.store(true, Ordering::Relaxed);
    let test = Test::new(Some(wire));
    let mut host = Host::new(wire, &test.clock);
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
    let mut host = Host::new(wire, &test.clock);
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
    test.provider.poll();
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
    test.provider.poll();
    assert_eq!(wire.to_guest.lock().len(), flood - MAX_FRAMES_PER_RUN);
    // The rest are due at the earliest next run.
    let ran = test.clock.now();
    assert_eq!(test.provider.next_deadline(), Some(ran + MIN_POLL_DELAY));
    test.clock.advance(MIN_POLL_DELAY);
    test.provider.poll();
    assert_eq!(wire.to_guest.lock().len(), flood - 2 * MAX_FRAMES_PER_RUN);
}

#[test]
fn a_lingering_closed_connection_is_reaped_on_time() {
    let wire: &'static Wire = Box::leak(Box::default());
    let test = Test::new(Some(wire));
    let mut host = Host::new(wire, &test.clock);
    let (process, socket) = echo_connection(&test, &mut host);
    // The host never closes: FIN-WAIT-2, with no timer.
    process.close_object_reference(socket).unwrap();
    run_for(
        &test,
        &mut host,
        Duration::from_secs(1),
        Duration::from_millis(10),
    );
    assert_eq!(test.provider.0.stack.lock().closing.len(), 1);
    let deadline = test.provider.next_deadline().unwrap();
    assert!(deadline <= test.clock.now() + CLOSE_TIMEOUT);
    test.clock
        .advance(deadline.checked_sub(test.clock.now()).unwrap());
    test.provider.poll();
    assert!(test.provider.0.stack.lock().closing.is_empty());
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

#[test]
fn a_guest_datagram_to_no_socket_is_refused() {
    let test = Test::new(None);
    let process = test.process();
    let socket = test.socket(&process, SocketType::Datagram);
    let closed = address([127, 0, 0, 1], 9);
    // As on the userland broker: at once, connected or not.
    assert_eq!(
        core_socket::send_to(
            &process,
            socket,
            b"x".to_vec(),
            SendFlags::NONE,
            Some(closed)
        ),
        Ok(SocketOutcome::Failed(SocketError::ConnectionRefused))
    );
    assert_eq!(
        core_socket::connect(&process, socket, closed),
        Ok(SocketOutcome::Failed(SocketError::ConnectionRefused))
    );
}

#[test]
fn a_connected_udp_socket_keeps_its_peers_datagram_from_a_burst() {
    let wire: &'static Wire = Box::leak(Box::default());
    let test = Test::new(Some(wire));
    let mut host = Host::new(wire, &test.clock);
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
        host.poll(&test.clock);
    }
    host.sockets
        .get_mut::<smoltcp::socket::udp::Socket>(peer)
        .send_slice(b"reply", guest)
        .unwrap();
    host.poll(&test.clock);
    assert_eq!(wire.to_guest.lock().len(), 41);
    test.provider.poll();
    let SocketOutcome::Completed(datagram) =
        core_socket::receive_from(&process, socket, 100, ReceiveFromFlags::NONE).unwrap()
    else {
        panic!("receive failed");
    };
    assert_eq!(datagram.data, b"reply");
}

/// An ICMP "destination unreachable" with `code` about a UDP datagram from
/// `source` to `destination`, quoting its headers only, from the gateway
/// to the guest.
fn unreachable(code: u8, source: SocketAddrV4, destination: SocketAddrV4) -> Vec<u8> {
    use smoltcp::wire::{Icmpv4Packet, Ipv4Packet};
    let mut packet = vec![0; 20 + 8 + 20 + 8];
    let mut ip = Ipv4Packet::new_unchecked(&mut packet);
    ip.set_version(4);
    ip.set_header_len(20);
    ip.set_total_len(56);
    ip.set_hop_limit(64);
    ip.set_next_header(smoltcp::wire::IpProtocol::Icmp);
    ip.set_src_addr(HOST_GATEWAY_IPV4_ADDRESS);
    ip.set_dst_addr(GUEST_IPV4_ADDRESS);
    ip.fill_checksum();
    let icmp = &mut packet[20..];
    icmp[0] = 3;
    icmp[1] = code;
    let mut quoted = Ipv4Packet::new_unchecked(&mut icmp[8..]);
    quoted.set_version(4);
    quoted.set_header_len(20);
    // The datagram was longer than what is quoted.
    quoted.set_total_len(1028);
    quoted.set_next_header(smoltcp::wire::IpProtocol::Udp);
    quoted.set_src_addr(*source.ip());
    quoted.set_dst_addr(*destination.ip());
    let udp = &mut icmp[28..];
    udp[..2].copy_from_slice(&source.port().to_be_bytes());
    udp[2..4].copy_from_slice(&destination.port().to_be_bytes());
    Icmpv4Packet::new_unchecked(&mut packet[20..]).fill_checksum();
    packet
}

#[test]
fn only_errors_linux_reports_reach_udp_sockets() {
    let source = SocketAddrV4::new(GUEST_IPV4_ADDRESS, 5000);
    let destination = SocketAddrV4::new(HOST_GATEWAY_IPV4_ADDRESS, 9);
    let error = |code| udp_error(&unreachable(code, source, destination));
    assert_eq!(
        error(3),
        Some((source, destination, SocketError::ConnectionRefused))
    );
    assert_eq!(
        error(10),
        Some((source, destination, SocketError::HostUnreachable))
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
        test.provider.poll();
        host.poll(&test.clock);
    }
}

#[test]
fn unacknowledged_data_to_a_dead_peer_times_out() {
    let wire: &'static Wire = Box::leak(Box::default());
    let test = Test::new(Some(wire));
    let mut host = Host::new(wire, &test.clock);
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
    let mut host = Host::new(wire, &test.clock);
    let (process, socket) = echo_connection(&test, &mut host);
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
    // A FIN to acknowledge arms the timeout, after the silence; the host
    // acknowledges it, and the connection lives on.
    wire.cut.store(false, Ordering::Relaxed);
    assert_eq!(
        core_socket::shutdown(&process, socket, ShutdownMode::Write),
        Ok(SocketOutcome::Completed(()))
    );
    run_for(
        &test,
        &mut host,
        Duration::from_secs(10),
        Duration::from_secs(1),
    );
    assert_eq!(
        receive(&process, socket, 8).map(|_| ()),
        Err(BrokerError::WouldBlock)
    );
    // Nor does TIME-WAIT ending, with keep-alive on, time it out.
    core_socket::set_tcp_option(
        &process,
        socket,
        litebox_broker_protocol::socket::TcpOptionValue::KeepAlive(true),
    )
    .unwrap();
    host.close_echo(b"");
    run_for(
        &test,
        &mut host,
        Duration::from_mins(1),
        Duration::from_millis(100),
    );
    assert_eq!(receive(&process, socket, 8), END);
}

#[test]
fn a_peer_with_a_closed_window_that_answers_keeps_the_connection() {
    let wire: &'static Wire = Box::leak(Box::default());
    let test = Test::new(Some(wire));
    let mut host = Host::new(wire, &test.clock);
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
        test.provider.poll();
        host.poll(&test.clock);
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

/// A UDP datagram from `source` to `destination` on the link, as the host
/// would send it to the guest, with valid checksums.
fn udp_frame(
    wire: &Wire,
    source: SocketAddrV4,
    destination: SocketAddrV4,
    payload: &[u8],
) -> Vec<u8> {
    use smoltcp::phy::ChecksumCapabilities;
    use smoltcp::wire::{
        EthernetFrame, EthernetProtocol, EthernetRepr, Ipv4Packet, Ipv4Repr, UdpPacket, UdpRepr,
    };
    let udp_len = 8 + payload.len();
    let mut frame = vec![0; 14 + 20 + udp_len];
    EthernetRepr {
        src_addr: EthernetAddress([0x02, 0, 0, 0, 0, 0x01]),
        dst_addr: EthernetAddress(wire.mac()),
        ethertype: EthernetProtocol::Ipv4,
    }
    .emit(&mut EthernetFrame::new_unchecked(&mut frame));
    let caps = ChecksumCapabilities::default();
    Ipv4Repr {
        src_addr: *source.ip(),
        dst_addr: *destination.ip(),
        next_header: smoltcp::wire::IpProtocol::Udp,
        payload_len: udp_len,
        hop_limit: 64,
    }
    .emit(&mut Ipv4Packet::new_unchecked(&mut frame[14..]), &caps);
    UdpRepr {
        src_port: source.port(),
        dst_port: destination.port(),
    }
    .emit(
        &mut UdpPacket::new_unchecked(&mut frame[34..]),
        &(*source.ip()).into(),
        &(*destination.ip()).into(),
        payload.len(),
        |buffer| buffer.copy_from_slice(payload),
        &caps,
    );
    frame
}

#[test]
fn martian_sources_from_the_link_reach_no_socket() {
    let wire: &'static Wire = Box::leak(Box::default());
    let test = Test::new(Some(wire));
    let process = test.process();
    let socket = test.socket(&process, SocketType::Datagram);
    let bound = address([0, 0, 0, 0], 5000);
    assert_eq!(
        core_socket::bind(&process, socket, bound),
        Ok(SocketOutcome::Completed(bound))
    );
    let guest = SocketAddrV4::new(GUEST_IPV4_ADDRESS, 5000);
    let receive = || core_socket::receive_from(&process, socket, 100, ReceiveFromFlags::NONE);
    // Control: a datagram from the gateway gets through.
    wire.to_guest.lock().push_back(udp_frame(
        wire,
        SocketAddrV4::new(HOST_GATEWAY_IPV4_ADDRESS, 6000),
        guest,
        b"real",
    ));
    test.provider.poll();
    assert!(
        matches!(receive(), Ok(SocketOutcome::Completed(datagram)) if datagram.data == b"real")
    );
    // Connected to a loopback peer, it must not take the link's word for it,
    // nor anyone's claiming to be the guest, or in 0/8.
    let peer = address([127, 0, 0, 1], 6000);
    let peer_socket = test.socket(&process, SocketType::Datagram);
    assert_eq!(
        core_socket::bind(&process, peer_socket, peer),
        Ok(SocketOutcome::Completed(peer))
    );
    assert_eq!(
        core_socket::connect(&process, socket, peer),
        Ok(SocketOutcome::Completed(SocketConnectionStatus::Connected))
    );
    for source in [
        peer,
        SocketAddrV4::new(GUEST_IPV4_ADDRESS, 6000),
        address([0, 0, 0, 1], 6000),
    ] {
        wire.to_guest
            .lock()
            .push_back(udp_frame(wire, source, guest, b"forged"));
    }
    // Nor anything addressed to loopback.
    wire.to_guest.lock().push_back(udp_frame(
        wire,
        SocketAddrV4::new(HOST_GATEWAY_IPV4_ADDRESS, 6000),
        address([127, 0, 0, 1], 5000),
        b"forged",
    ));
    test.provider.poll();
    assert!(wire.to_guest.lock().is_empty());
    assert_eq!(receive().map(|_| ()), Err(BrokerError::WouldBlock));
}

#[test]
fn dropped_frames_count_against_a_runs_budget() {
    let wire: &'static Wire = Box::leak(Box::default());
    let test = Test::new(Some(wire));
    // Longer than any frame the stack takes.
    let oversized = vec![0; MAX_FRAME_SIZE + 1];
    wire.to_guest
        .lock()
        .extend(core::iter::repeat_n(oversized, 3 * MAX_FRAMES_PER_RUN));
    test.provider.poll();
    assert_eq!(wire.to_guest.lock().len(), 2 * MAX_FRAMES_PER_RUN);
}

#[test]
fn sockets_beyond_the_memory_budget_fail_instead_of_panicking() {
    let wire: &'static Wire = Box::leak(Box::default());
    // Nothing answers: the connections wait, with their buffers.
    wire.cut.store(true, Ordering::Relaxed);
    let test = Test::new(Some(wire));
    let mut sockets = Vec::new();
    let failure = loop {
        // Each process has at most 256 sockets.
        let process = test.process();
        let mut result = None;
        for _ in 0..200 {
            let socket = test.socket(&process, SocketType::Stream);
            match core_socket::connect(&process, socket, address([10, 0, 2, 77], 80)) {
                Ok(SocketOutcome::Completed(SocketConnectionStatus::Connecting)) => {
                    sockets.push((process.clone(), socket));
                }
                other => {
                    result = Some(other);
                    break;
                }
            }
        }
        if let Some(result) = result {
            break result;
        }
    };
    assert_eq!(failure, Err(BrokerError::OutOfMemory));
    assert!(test.provider.0.stack.lock().sockets.room() < MAX_BUFFER_BYTES / 100);
    // A UDP socket reaching beyond the guest needs buffers too.
    let process = test.process();
    let udp = test.socket(&process, SocketType::Datagram);
    assert_eq!(
        core_socket::bind(&process, udp, address([0, 0, 0, 0], 5000)),
        Err(BrokerError::OutOfMemory)
    );
    // Closing sockets frees room, once their connections end.
    for (process, socket) in sockets.drain(..8) {
        process.close_object_reference(socket).unwrap();
    }
    test.clock.advance(CLOSE_TIMEOUT + Duration::from_secs(1));
    test.provider.poll();
    let bound = address([0, 0, 0, 0], 5000);
    assert_eq!(
        core_socket::bind(&process, udp, bound),
        Ok(SocketOutcome::Completed(bound))
    );
}

#[test]
fn a_run_sends_more_than_one_segment_per_connection() {
    let wire: &'static Wire = Box::leak(Box::default());
    let test = Test::new(Some(wire));
    let mut host = Host::new(wire, &test.clock);
    let (process, socket) = echo_connection(&test, &mut host);
    host.poll(&test.clock);
    wire.to_host.lock().clear();
    // 32 KiB, within the host's window: several segments, in this one run.
    assert_eq!(
        core_socket::send(&process, socket, vec![1; 32 * 1024], SendFlags::NONE),
        Ok(SocketOutcome::Completed(32 * 1024))
    );
    let segments = wire.to_host.lock().len();
    assert!(segments > 10, "{segments} frames");
}

#[test]
fn a_full_guest_connection_is_writable_again_once_most_of_it_drains() {
    let test = Test::new(None);
    let pair = pair(&test, [127, 0, 0, 1]);
    let chunk = vec![1; 32 * 1024];
    while let Ok(SocketOutcome::Completed(_)) =
        core_socket::send(&pair.client, pair.connector, chunk.clone(), SendFlags::NONE)
    {}
    assert!(
        !test
            .published(pair.connector)
            .unwrap()
            .contains(ReadinessFlags::WRITE)
    );
    let capacity = super::socket_pair::CAPACITY;
    let mut left = capacity;
    let mut drain_to = |rest: usize| {
        while left > rest {
            let SocketOutcome::Completed(PlatformStreamReceive::Received(data)) =
                receive(&pair.server, pair.accepted, (left - rest).min(32 * 1024)).unwrap()
            else {
                panic!("receive failed");
            };
            left -= data.len();
        }
    };
    // Half of it read: not yet writable, as an `AF_UNIX` socket pair (the
    // userland broker's).
    drain_to(capacity / 2);
    assert!(
        !test
            .published(pair.connector)
            .unwrap()
            .contains(ReadinessFlags::WRITE)
    );
    // Three quarters: writable.
    drain_to(capacity / 4);
    assert!(
        test.published(pair.connector)
            .unwrap()
            .contains(ReadinessFlags::WRITE)
    );
}

#[test]
fn closing_with_unread_data_after_a_read_shutdown_resets_the_peer() {
    let test = Test::new(None);
    // Unread: held at the shutdown, or discarded after it, where Linux would
    // queue it.
    for after_shutdown in [false, true] {
        let pair = pair(&test, [127, 0, 0, 1]);
        let send = || {
            core_socket::send(
                &pair.server,
                pair.accepted,
                b"unread".to_vec(),
                SendFlags::NONE,
            )
        };
        if !after_shutdown {
            assert_eq!(send(), Ok(SocketOutcome::Completed(6)));
        }
        assert_eq!(
            core_socket::shutdown(&pair.client, pair.connector, ShutdownMode::Read),
            Ok(SocketOutcome::Completed(()))
        );
        if after_shutdown {
            assert_eq!(send(), Ok(SocketOutcome::Completed(6)));
        }
        pair.client.close_object_reference(pair.connector).unwrap();
        // As on Linux: a reset, not an orderly end.
        assert_eq!(
            receive(&pair.server, pair.accepted, 8),
            Ok(SocketOutcome::Failed(SocketError::ConnectionReset))
        );
        pair.server.close_object_reference(pair.accepted).unwrap();
        pair.server.close_object_reference(pair.listener).unwrap();
    }
}

#[test]
fn the_networks_broadcast_address_is_refused() {
    let wire: &'static Wire = Box::leak(Box::default());
    let test = Test::new(Some(wire));
    let process = test.process();
    let broadcast = address([10, 0, 2, 255], 9);
    let udp = test.socket(&process, SocketType::Datagram);
    assert_eq!(
        core_socket::send_to(
            &process,
            udp,
            b"x".to_vec(),
            SendFlags::NONE,
            Some(broadcast)
        ),
        Ok(SocketOutcome::Failed(SocketError::PolicyDenied))
    );
    assert_eq!(
        core_socket::connect(&process, udp, broadcast),
        Ok(SocketOutcome::Failed(SocketError::PolicyDenied))
    );
    let tcp = test.socket(&process, SocketType::Stream);
    assert_eq!(
        core_socket::connect(&process, tcp, broadcast),
        Ok(SocketOutcome::Completed(SocketConnectionStatus::Failed(
            SocketError::NetworkUnreachable
        )))
    );
    assert!(wire.to_host.lock().is_empty());
}

#[test]
fn unread_data_outlives_time_wait() {
    let wire: &'static Wire = Box::leak(Box::default());
    let test = Test::new(Some(wire));
    let mut host = Host::new(wire, &test.clock);
    let (process, socket) = echo_connection(&test, &mut host);
    // The guest closes first, so it ends in TIME-WAIT.
    assert_eq!(
        core_socket::shutdown(&process, socket, ShutdownMode::Write),
        Ok(SocketOutcome::Completed(()))
    );
    host.close_echo(b"late");
    run_for(
        &test,
        &mut host,
        Duration::from_secs(1),
        Duration::from_millis(10),
    );
    // Well past TIME-WAIT, as on Linux, the data is still there to read.
    run_for(
        &test,
        &mut host,
        Duration::from_mins(2),
        Duration::from_secs(1),
    );
    assert_eq!(receive(&process, socket, 8), received(b"late"));
    assert_eq!(receive(&process, socket, 8), END);
}

#[test]
fn closing_a_listener_resets_all_its_unaccepted_connections() {
    let test = Test::new(None);
    let count = MAX_CLOSING + 36;
    let (server, listener) = listener(&test, address([127, 0, 0, 1], 8080), 1024);
    let mut connectors = Vec::new();
    // Clients in several processes, within their socket limits.
    for _ in 0..count.div_ceil(50) {
        let client = test.process();
        for _ in 0..50.min(count - connectors.len()) {
            let socket = test.socket(&client, SocketType::Stream);
            assert_eq!(
                core_socket::connect(&client, socket, address([127, 0, 0, 1], 8080)),
                Ok(SocketOutcome::Completed(SocketConnectionStatus::Connected))
            );
            connectors.push((client.clone(), socket));
        }
    }
    server.close_object_reference(listener).unwrap();
    test.provider.poll();
    // As Linux's `inet_csk_listen_stop`.
    for (client, socket) in connectors {
        assert_eq!(
            receive(&client, socket, 8),
            Ok(SocketOutcome::Failed(SocketError::ConnectionReset))
        );
    }
}

#[test]
fn data_after_both_shutdowns_resets_the_connection() {
    let wire: &'static Wire = Box::leak(Box::default());
    let test = Test::new(Some(wire));
    let mut host = Host::new(wire, &test.clock);
    let (process, socket) = echo_connection(&test, &mut host);
    assert_eq!(
        core_socket::shutdown(&process, socket, ShutdownMode::Both),
        Ok(SocketOutcome::Completed(()))
    );
    run_for(
        &test,
        &mut host,
        Duration::from_secs(1),
        Duration::from_millis(10),
    );
    host.sockets
        .get_mut::<tcp::Socket>(host.echo)
        .send_slice(b"more")
        .unwrap();
    run_for(
        &test,
        &mut host,
        Duration::from_secs(1),
        Duration::from_millis(10),
    );
    // As Linux (`tcp_rcv_state_process`): both ends see a reset.
    assert_eq!(
        receive(&process, socket, 8),
        Ok(SocketOutcome::Failed(SocketError::ConnectionReset))
    );
    assert_eq!(
        host.sockets.get::<tcp::Socket>(host.echo).state(),
        tcp::State::Closed
    );
}

#[test]
fn a_guest_connection_discards_data_after_both_shutdowns() {
    let test = Test::new(None);
    let pair = pair(&test, [127, 0, 0, 1]);
    assert_eq!(
        core_socket::shutdown(&pair.client, pair.connector, ShutdownMode::Both),
        Ok(SocketOutcome::Completed(()))
    );
    assert_eq!(receive(&pair.server, pair.accepted, 8), END);
    // As on the userland broker: discarded, without a reset.
    for _ in 0..2 {
        assert_eq!(
            core_socket::send(
                &pair.server,
                pair.accepted,
                b"more".to_vec(),
                SendFlags::NONE
            ),
            Ok(SocketOutcome::Completed(4))
        );
    }
    assert_eq!(receive(&pair.client, pair.connector, 8), END);
}

#[test]
fn an_unacknowledged_fin_times_out() {
    let wire: &'static Wire = Box::leak(Box::default());
    let test = Test::new(Some(wire));
    let mut host = Host::new(wire, &test.clock);
    let (process, socket) = echo_connection(&test, &mut host);
    wire.cut.store(true, Ordering::Relaxed);
    assert_eq!(
        core_socket::shutdown(&process, socket, ShutdownMode::Write),
        Ok(SocketOutcome::Completed(()))
    );
    run_for(
        &test,
        &mut host,
        Duration::from_mins(16),
        Duration::from_secs(5),
    );
    assert_eq!(
        receive(&process, socket, 8),
        Ok(SocketOutcome::Failed(SocketError::TimedOut))
    );
}

#[test]
fn a_keep_alive_timeout_is_a_timeout() {
    let wire: &'static Wire = Box::leak(Box::default());
    let test = Test::new(Some(wire));
    let mut host = Host::new(wire, &test.clock);
    let (process, socket) = echo_connection(&test, &mut host);
    core_socket::set_tcp_option(
        &process,
        socket,
        litebox_broker_protocol::socket::TcpOptionValue::KeepAlive(true),
    )
    .unwrap();
    wire.cut.store(true, Ordering::Relaxed);
    run_for(
        &test,
        &mut host,
        Duration::from_mins(16),
        Duration::from_secs(5),
    );
    assert_eq!(
        receive(&process, socket, 8),
        Ok(SocketOutcome::Failed(SocketError::TimedOut))
    );
}

#[test]
fn an_icmp_error_reaches_only_the_socket_that_sent_the_datagram() {
    let wire: &'static Wire = Box::leak(Box::default());
    let test = Test::new(Some(wire));
    let process = test.process();
    let socket = test.socket(&process, SocketType::Datagram);
    let bound = address([0, 0, 0, 0], 5000);
    assert_eq!(
        core_socket::bind(&process, socket, bound),
        Ok(SocketOutcome::Completed(bound))
    );
    let closed = SocketAddrV4::new(HOST_GATEWAY_IPV4_ADDRESS, 9);
    assert_eq!(
        core_socket::connect(&process, socket, closed),
        Ok(SocketOutcome::Completed(SocketConnectionStatus::Connected))
    );
    let deliver = |source: SocketAddrV4| {
        let packet = unreachable(3, source, closed);
        let mut frame = vec![0; 14];
        frame[..6].copy_from_slice(&wire.mac());
        frame[6..12].copy_from_slice(&[0x02, 0, 0, 0, 0, 0x01]);
        frame[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());
        frame.extend(packet);
        wire.to_guest.lock().push_back(frame);
        test.provider.poll();
    };
    // About a datagram from another address, with the same port and peer:
    // as Linux (`__udp4_lib_err`), not this socket's.
    deliver(address([10, 0, 2, 99], 5000));
    assert_eq!(
        core_socket::receive_from(&process, socket, 100, ReceiveFromFlags::NONE).map(|_| ()),
        Err(BrokerError::WouldBlock)
    );
    deliver(SocketAddrV4::new(GUEST_IPV4_ADDRESS, 5000));
    assert_eq!(
        core_socket::receive_from(&process, socket, 100, ReceiveFromFlags::NONE),
        Ok(SocketOutcome::Failed(SocketError::ConnectionRefused))
    );
}

#[test]
fn data_for_a_closed_socket_resets_the_sender() {
    let wire: &'static Wire = Box::leak(Box::default());
    let test = Test::new(Some(wire));
    let mut host = Host::new(wire, &test.clock);
    let (process, socket) = echo_connection(&test, &mut host);
    process.close_object_reference(socket).unwrap();
    run_for(
        &test,
        &mut host,
        Duration::from_secs(1),
        Duration::from_millis(10),
    );
    host.sockets
        .get_mut::<tcp::Socket>(host.echo)
        .send_slice(b"x")
        .unwrap();
    run_for(
        &test,
        &mut host,
        Duration::from_millis(100),
        Duration::from_millis(10),
    );
    // As Linux, at once: not after the closed socket's minute.
    assert_eq!(
        host.sockets.get::<tcp::Socket>(host.echo).state(),
        tcp::State::Closed
    );
}

#[test]
fn a_closing_connection_cannot_be_made_again() {
    let wire: &'static Wire = Box::leak(Box::default());
    let test = Test::new(Some(wire));
    let mut host = Host::new(wire, &test.clock);
    let process = test.process();
    let source = address([0, 0, 0, 0], 5000);
    let echo = SocketAddrV4::new(HOST_GATEWAY_IPV4_ADDRESS, ECHO_PORT);
    let connect = |host: &mut Host| {
        let socket = test.socket(&process, SocketType::Stream);
        assert_eq!(
            core_socket::bind(&process, socket, source),
            Ok(SocketOutcome::Completed(source))
        );
        let status = core_socket::connect(&process, socket, echo);
        if status == Ok(SocketOutcome::Completed(SocketConnectionStatus::Connecting)) {
            pump(&test, host, |_| {
                test.published(socket)
                    .is_some_and(|flags| flags.contains(ReadinessFlags::WRITE))
            });
        }
        (socket, status)
    };
    let (socket, _) = connect(&mut host);
    // The host does not close: the connection waits in FIN-WAIT-2.
    process.close_object_reference(socket).unwrap();
    run_for(
        &test,
        &mut host,
        Duration::from_secs(1),
        Duration::from_millis(10),
    );
    // As Linux (with `SO_REUSEADDR`): the port binds again, but the same
    // connection is not made twice.
    let (_, status) = connect(&mut host);
    assert_eq!(
        status,
        Ok(SocketOutcome::Completed(SocketConnectionStatus::Failed(
            SocketError::AddressNotAvailable
        )))
    );
}

#[test]
fn a_pending_udp_error_fails_the_next_send() {
    let wire: &'static Wire = Box::leak(Box::default());
    let test = Test::new(Some(wire));
    let mut host = Host::new(wire, &test.clock);
    let process = test.process();
    let socket = test.socket(&process, SocketType::Datagram);
    let closed = SocketAddrV4::new(HOST_GATEWAY_IPV4_ADDRESS, 9);
    assert_eq!(
        core_socket::connect(&process, socket, closed),
        Ok(SocketOutcome::Completed(SocketConnectionStatus::Connected))
    );
    let send = || core_socket::send_to(&process, socket, b"x".to_vec(), SendFlags::NONE, None);
    // Longer than an ICMP error quotes.
    assert_eq!(
        core_socket::send_to(&process, socket, vec![0; 1000], SendFlags::NONE, None),
        Ok(SocketOutcome::Completed(1000))
    );
    pump(&test, &mut host, |_| {
        test.published(socket)
            .is_some_and(|flags| flags.contains(ReadinessFlags::ERROR))
    });
    // As Linux: the port unreachable fails the next send, once.
    assert_eq!(
        send(),
        Ok(SocketOutcome::Failed(SocketError::ConnectionRefused))
    );
    assert_eq!(send(), Ok(SocketOutcome::Completed(1)));
}

#[test]
fn a_guest_connection_carries_what_was_sent_before_it_was_accepted() {
    let test = Test::new(None);
    let (server, listener) = listener(&test, address([127, 0, 0, 1], 8080), 4);
    let client = test.process();
    let socket = test.socket(&client, SocketType::Stream);
    assert_eq!(
        core_socket::connect(&client, socket, address([127, 0, 0, 1], 8080)),
        Ok(SocketOutcome::Completed(SocketConnectionStatus::Connected))
    );
    assert_eq!(
        core_socket::send(&client, socket, b"early".to_vec(), SendFlags::NONE),
        Ok(SocketOutcome::Completed(5))
    );
    // Closed before being accepted, gracefully: still queued.
    client.close_object_reference(socket).unwrap();
    let SocketOutcome::Completed(accepted) =
        core_socket::accept(&server, listener, test.sink.clone()).unwrap()
    else {
        panic!("accept failed");
    };
    assert_eq!(receive(&server, accepted.handle, 8), received(b"early"));
    assert_eq!(receive(&server, accepted.handle, 8), END);
}

#[test]
fn aborting_an_unaccepted_guest_connection_withdraws_it() {
    let test = Test::new(None);
    let (server, listener) = listener(&test, address([127, 0, 0, 1], 8080), 4);
    let client = test.process();
    let socket = test.socket(&client, SocketType::Stream);
    assert_eq!(
        core_socket::connect(&client, socket, address([127, 0, 0, 1], 8080)),
        Ok(SocketOutcome::Completed(SocketConnectionStatus::Connected))
    );
    assert_eq!(test.published(listener), Some(ReadinessFlags::READ));
    assert_eq!(
        core_socket::shutdown(&client, socket, ShutdownMode::Abort),
        Ok(SocketOutcome::Completed(()))
    );
    client.close_object_reference(socket).unwrap();
    // As on the userland broker.
    assert_eq!(test.published(listener), Some(ReadinessFlags::default()));
    assert_eq!(
        core_socket::accept(&server, listener, test.sink.clone()).map(|_| ()),
        Err(BrokerError::WouldBlock)
    );
    assert!(test.provider.0.stack.lock().sockets.pairs.is_empty());
}

#[test]
fn one_process_cannot_fill_a_guest_sockets_queue() {
    let test = Test::new(None);
    let receiver_process = test.process();
    let receiver = test.socket(&receiver_process, SocketType::Datagram);
    let bound = address([127, 0, 0, 1], 5000);
    assert_eq!(
        core_socket::bind(&receiver_process, receiver, bound),
        Ok(SocketOutcome::Completed(bound))
    );
    let send = |process: &BrokerProcess, socket| {
        core_socket::send_to(process, socket, b"x".to_vec(), SendFlags::NONE, Some(bound))
    };
    let flooder = test.process();
    let flood = test.socket(&flooder, SocketType::Datagram);
    for _ in 0..40 {
        assert_eq!(send(&flooder, flood), Ok(SocketOutcome::Completed(1)));
    }
    let other = test.process();
    let socket = test.socket(&other, SocketType::Datagram);
    assert_eq!(send(&other, socket), Ok(SocketOutcome::Completed(1)));
    // As on the userland broker: 16 from the flooder, then the other's.
    let mut count = 0;
    while let Ok(SocketOutcome::Completed(_)) =
        core_socket::receive_from(&receiver_process, receiver, 8, ReceiveFromFlags::NONE)
    {
        count += 1;
    }
    assert_eq!(count, 17);
}

#[test]
fn guest_connections_count_the_memory_they_hold() {
    let test = Test::new(None);
    let pair = pair(&test, [127, 0, 0, 1]);
    let queued = || test.provider.0.stack.lock().sockets.queued;
    let chunk = vec![1; 32 * 1024];
    while let Ok(SocketOutcome::Completed(_)) =
        core_socket::send(&pair.client, pair.connector, chunk.clone(), SendFlags::NONE)
    {}
    let full = queued();
    assert!(full >= super::socket_pair::CAPACITY);
    let drain = |len: usize| {
        let mut left = len;
        while left > 0 {
            let SocketOutcome::Completed(PlatformStreamReceive::Received(data)) =
                receive(&pair.server, pair.accepted, left.min(32 * 1024)).unwrap()
            else {
                panic!("receive failed");
            };
            left -= data.len();
        }
    };
    // Mostly read: the queue keeps its memory, which still counts, and
    // takes writes even with the stack's budget used up.
    drain(super::socket_pair::CAPACITY * 3 / 4);
    assert_eq!(queued(), full);
    let room = {
        let mut stack = test.provider.0.stack.lock();
        let room = stack.sockets.room();
        stack.sockets.queued += room;
        room
    };
    test.provider.poll();
    assert!(
        test.published(pair.connector)
            .unwrap()
            .contains(ReadinessFlags::WRITE)
    );
    test.provider.0.stack.lock().sockets.queued -= room;
    // All read: freed.
    drain(super::socket_pair::CAPACITY - super::socket_pair::CAPACITY * 3 / 4);
    assert_eq!(queued(), 0);
    // Held apart by a read shutdown, it counts until read.
    assert_eq!(
        core_socket::send(
            &pair.client,
            pair.connector,
            b"held".to_vec(),
            SendFlags::NONE
        ),
        Ok(SocketOutcome::Completed(4))
    );
    assert_eq!(
        core_socket::shutdown(&pair.server, pair.accepted, ShutdownMode::Read),
        Ok(SocketOutcome::Completed(()))
    );
    assert!(queued() >= 4);
    assert_eq!(receive(&pair.server, pair.accepted, 8), received(b"held"));
    assert_eq!(queued(), 0);
}

#[test]
fn a_udp_read_shutdown_drops_datagrams_from_outside() {
    let wire: &'static Wire = Box::leak(Box::default());
    let test = Test::new(Some(wire));
    let process = test.process();
    let socket = test.socket(&process, SocketType::Datagram);
    let bound = address([0, 0, 0, 0], 5000);
    assert_eq!(
        core_socket::bind(&process, socket, bound),
        Ok(SocketOutcome::Completed(bound))
    );
    assert_eq!(
        core_socket::shutdown(&process, socket, ShutdownMode::Read),
        Ok(SocketOutcome::Completed(()))
    );
    // As from guest sockets, and on the userland broker.
    wire.to_guest.lock().push_back(udp_frame(
        wire,
        SocketAddrV4::new(HOST_GATEWAY_IPV4_ADDRESS, 6000),
        SocketAddrV4::new(GUEST_IPV4_ADDRESS, 5000),
        b"late",
    ));
    test.provider.poll();
    assert!(wire.to_guest.lock().is_empty());
    assert_eq!(test.provider.0.stack.lock().sockets.queued, 0);
}

#[test]
fn datagrams_to_a_neighbor_that_never_answers_are_dropped() {
    let wire: &'static Wire = Box::leak(Box::default());
    let test = Test::new(Some(wire));
    let mut host = Host::new(wire, &test.clock);
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
    let send = |data: &[u8], to| {
        core_socket::send_to(&process, socket, data.to_vec(), SendFlags::NONE, Some(to))
    };
    let gateway = SocketAddrV4::new(HOST_GATEWAY_IPV4_ADDRESS, 53);
    // Nothing answers ARP for it.
    let unanswered = address([10, 0, 2, 77], 9);
    // Empty ones take a packet slot each, but no payload.
    while send(b"", unanswered) == Ok(SocketOutcome::Completed(0)) {}
    assert!(
        !test
            .published(socket)
            .unwrap()
            .contains(ReadinessFlags::WRITE)
    );
    run_for(
        &test,
        &mut host,
        Duration::from_secs(4),
        Duration::from_millis(100),
    );
    assert!(
        test.published(socket)
            .unwrap()
            .contains(ReadinessFlags::WRITE)
    );
    // Nor does the stack still wait for the neighbor, polled at once.
    assert!(
        test.provider
            .next_deadline()
            .is_none_or(|next| next > test.clock.now() + MIN_POLL_DELAY)
    );
    assert_eq!(send(b"lost", unanswered), Ok(SocketOutcome::Completed(4)));
    run_for(
        &test,
        &mut host,
        Duration::from_secs(1),
        Duration::from_millis(100),
    );
    assert_eq!(send(b"behind", gateway), Ok(SocketOutcome::Completed(6)));
    // Dropped, as on Linux after the neighbor's solicitations, and the
    // socket sends again. (On Linux, what is to other neighbors never waits
    // behind it; smoltcp's single queue cannot tell them apart.)
    run_for(
        &test,
        &mut host,
        Duration::from_secs(4),
        Duration::from_millis(100),
    );
    assert_eq!(send(b"later", gateway), Ok(SocketOutcome::Completed(5)));
    let mut got = Vec::new();
    pump(&test, &mut host, |host| {
        let udp = host
            .sockets
            .get_mut::<smoltcp::socket::udp::Socket>(host_udp);
        while let Ok((data, _)) = udp.recv() {
            got.push(data.to_vec());
        }
        !got.is_empty()
    });
    assert_eq!(got, [b"later".to_vec()]);
}

#[test]
fn a_reset_after_both_sides_closed_is_reported_while_data_was_unacknowledged() {
    let wire: &'static Wire = Box::leak(Box::default());
    let test = Test::new(Some(wire));
    let mut host = Host::new(wire, &test.clock);
    let (process, socket) = echo_connection(&test, &mut host);
    host.close_echo(b"");
    pump(&test, &mut host, |_| receive(&process, socket, 8) == END);
    // The guest's last data and FIN are lost, and the host resets.
    wire.cut.store(true, Ordering::Relaxed);
    assert_eq!(
        core_socket::send(&process, socket, b"unread".to_vec(), SendFlags::NONE),
        Ok(SocketOutcome::Completed(6))
    );
    assert_eq!(
        core_socket::shutdown(&process, socket, ShutdownMode::Write),
        Ok(SocketOutcome::Completed(()))
    );
    wire.cut.store(false, Ordering::Relaxed);
    host.sockets.get_mut::<tcp::Socket>(host.echo).abort();
    pump(&test, &mut host, |_| {
        test.published(socket)
            .unwrap()
            .contains(ReadinessFlags::ERROR)
    });
    assert_eq!(
        receive(&process, socket, 8),
        Ok(SocketOutcome::Failed(SocketError::ConnectionReset))
    );
}

#[test]
fn a_closed_connection_keeps_time_wait() {
    let wire: &'static Wire = Box::leak(Box::default());
    let test = Test::new(Some(wire));
    let mut host = Host::new(wire, &test.clock);
    let (process, socket) = echo_connection(&test, &mut host);
    // The guest closes first, so it ends in TIME-WAIT.
    process.close_object_reference(socket).unwrap();
    host.close_echo(b"");
    run_for(
        &test,
        &mut host,
        Duration::from_secs(5),
        Duration::from_millis(100),
    );
    // Kept for smoltcp's TIME-WAIT (Linux's is longer), so the peer's
    // retransmitted FIN would be acknowledged, not reset.
    assert_eq!(test.provider.0.stack.lock().closing.len(), 1);
    run_for(
        &test,
        &mut host,
        Duration::from_secs(10),
        Duration::from_millis(100),
    );
    assert!(test.provider.0.stack.lock().closing.is_empty());
}

#[test]
fn a_shutdown_while_connecting_ends_the_attempt() {
    let wire: &'static Wire = Box::leak(Box::default());
    let test = Test::new(Some(wire));
    let process = test.process();
    let socket = test.socket(&process, SocketType::Stream);
    assert_eq!(
        core_socket::connect(&process, socket, address([10, 0, 2, 77], 80)),
        Ok(SocketOutcome::Completed(SocketConnectionStatus::Connecting))
    );
    assert_eq!(
        core_socket::shutdown(&process, socket, ShutdownMode::Write),
        Ok(SocketOutcome::Completed(()))
    );
    test.provider.poll();
    assert!(
        test.published(socket)
            .unwrap()
            .contains(ReadinessFlags::ERROR)
    );
    // As on Linux, the attempt is gone (no reset is sent), and it reports
    // the reset once.
    assert_eq!(test.provider.0.stack.lock().sockets.set.iter().count(), 1);
    let status = core_socket::status(&process, socket).unwrap();
    assert_eq!(
        status.status,
        SocketConnectionStatus::Failed(SocketError::ConnectionReset)
    );
    assert_eq!(status.pending_error, Some(SocketError::ConnectionReset));
    assert_eq!(
        core_socket::status(&process, socket).unwrap().pending_error,
        None
    );
}

#[test]
fn a_waiting_peek_is_woken_despite_a_receive_meanwhile() {
    let test = Test::new(None);
    let pair = pair(&test, [127, 0, 0, 1]);
    let send = |data: &[u8]| {
        core_socket::send(&pair.client, pair.connector, data.to_vec(), SendFlags::NONE)
    };
    assert_eq!(send(b"abcd"), Ok(SocketOutcome::Completed(4)));
    assert_eq!(
        core_socket::receive(
            &pair.server,
            pair.accepted,
            8,
            ReceiveFlags(ReceiveFlags::PEEK.0 | ReceiveFlags::WAITALL.0),
            0,
            8
        ),
        Err(BrokerError::WouldBlock)
    );
    assert_eq!(receive(&pair.server, pair.accepted, 2), received(b"ab"));
    let publications = || test.sink.0.lock().len();
    let before = publications();
    // Readable all along: only the peek's wakeup is published.
    assert_eq!(send(b"efghij"), Ok(SocketOutcome::Completed(6)));
    assert!(publications() > before);
}
