// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Broker-owned Linux sockets driven by one epoll reactor.

use std::collections::HashMap;
use std::fmt;
use std::io::{Error, ErrorKind, Result as IoResult};
use std::net::{Ipv4Addr, SocketAddrV4};
use std::os::fd::OwnedFd;
use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, TryRecvError, TrySendError, sync_channel};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use litebox_broker_core::socket::{
    AcceptedPlatformSocket, PlatformConnectError, PlatformDatagramReceive, PlatformSocket,
    PlatformStreamReceive, SocketProvider,
};
use litebox_broker_core::{BrokerError, Result as BrokerResult, SessionId};
use litebox_broker_protocol::readiness::ReadinessFlags;
use litebox_broker_protocol::socket::{
    AddressFamily, CreateSocketRequest, IpProtocol, MAX_SOCKET_PEEK_SIZE, MAX_SOCKET_TRANSFER_SIZE,
    MAX_UDP_DATAGRAM_SIZE, ReceiveFlags, ReceiveFromFlags, SendFlags, ShutdownMode,
    SocketConnectionStatus, SocketError, SocketOutcome, SocketStatusResponse, SocketType,
    TcpOptionName, TcpOptionValue,
};
use rustix::buffer::spare_capacity;
use rustix::event::{EventfdFlags, PollFd, PollFlags, Timespec, epoll, eventfd, poll};
use rustix::io::{Errno, ioctl_fionread, read, write};
use rustix::net::{
    AddressFamily as LinuxAddressFamily, RecvFlags as LinuxRecvFlags, SendFlags as LinuxSendFlags,
    Shutdown as LinuxShutdown, SocketFlags as LinuxSocketFlags, SocketType as LinuxSocketType,
    acceptfrom_with, bind, connect, getsockname, ipproto, listen, recv, send, shutdown,
    socket_with, sockopt,
};

use litebox_broker_core::readiness::ReadinessRegistration;

mod udp;

use udp::{
    ReactorUdpBinding, ReactorUdpPeer, ReactorUdpState, UDP_EVENT_TOKEN_FLAG, UdpReceiveOrigin,
    UdpSocketState, is_local_ipv4_address,
};

/// Epoll token reserved for the eventfd that wakes the reactor for commands.
const WAKE_TOKEN: u64 = 0;
const MAX_QUEUED_SOCKET_COMMANDS: usize = 64;
const MAX_EPOLL_EVENTS: usize = 64;
const MAX_UNMATCHED_ACCEPTS_PER_COMMAND: usize = 64;
const PENDING_CONNECT_DISCARD_LIFETIME: Duration = Duration::from_mins(5);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
enum SocketLifecycleState {
    Pending = 0,
    Active = 1,
    Retiring = 2,
    Retired = 3,
}

impl SocketLifecycleState {
    fn from_raw(value: u8) -> Self {
        match value {
            0 => Self::Pending,
            1 => Self::Active,
            2 => Self::Retiring,
            3 => Self::Retired,
            _ => unreachable!("invalid Linux socket lifecycle state"),
        }
    }
}

struct SocketLifecycle {
    state: AtomicU8,
}

impl SocketLifecycle {
    fn pending() -> Self {
        Self {
            state: AtomicU8::new(SocketLifecycleState::Pending as u8),
        }
    }

    fn load(&self) -> SocketLifecycleState {
        SocketLifecycleState::from_raw(self.state.load(Ordering::Acquire))
    }

    fn activate(&self) -> bool {
        self.state
            .compare_exchange(
                SocketLifecycleState::Pending as u8,
                SocketLifecycleState::Active as u8,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
    }

    fn retire(&self, close: impl FnOnce()) {
        let mut close = Some(close);
        loop {
            match self.load() {
                SocketLifecycleState::Pending => {
                    if self
                        .state
                        .compare_exchange(
                            SocketLifecycleState::Pending as u8,
                            SocketLifecycleState::Retired as u8,
                            Ordering::AcqRel,
                            Ordering::Acquire,
                        )
                        .is_ok()
                    {
                        return;
                    }
                }
                SocketLifecycleState::Active => {
                    if self
                        .state
                        .compare_exchange(
                            SocketLifecycleState::Active as u8,
                            SocketLifecycleState::Retiring as u8,
                            Ordering::AcqRel,
                            Ordering::Acquire,
                        )
                        .is_ok()
                    {
                        close.take().expect("socket close action missing")();
                        self.state
                            .store(SocketLifecycleState::Retired as u8, Ordering::Release);
                        return;
                    }
                }
                SocketLifecycleState::Retiring => {
                    while self.load() != SocketLifecycleState::Retired {
                        thread::yield_now();
                    }
                    return;
                }
                SocketLifecycleState::Retired => return,
            }
        }
    }

    fn reactor_removed(&self) {
        self.state
            .store(SocketLifecycleState::Retired as u8, Ordering::Release);
    }
}

/// Linux-userland socket provider.
///
/// One reactor thread owns every socket descriptor and all epoll state.
/// Broker request workers submit bounded commands and wait only for one
/// immediate nonblocking operation, never for network readiness.
pub struct LinuxSocketProvider {
    reactor: Arc<ReactorClient>,
}

impl LinuxSocketProvider {
    /// Starts a provider with global and per-session socket limits.
    pub fn new(max_sockets: usize, max_sockets_per_session: usize) -> IoResult<Self> {
        Ok(Self {
            reactor: Arc::new(ReactorClient::start(max_sockets, max_sockets_per_session)?),
        })
    }
}

impl SocketProvider for LinuxSocketProvider {
    fn create(
        &self,
        session_id: SessionId,
        request: CreateSocketRequest,
        readiness: ReadinessRegistration,
    ) -> BrokerResult<Arc<dyn PlatformSocket>> {
        if socket_kind(request).is_none() {
            return Err(BrokerError::UnsupportedOperation);
        }

        let id = self.reactor.allocate_socket_id()?;
        let snapshot = Arc::new(Mutex::new(SocketSnapshot::default()));
        let lifecycle = Arc::new(SocketLifecycle::pending());
        // Allocate the provider object before the reactor creates an external
        // resource, so successful creation has no remaining Arc allocation.
        let socket = Arc::new(LinuxSocket {
            id,
            reactor: Arc::clone(&self.reactor),
            snapshot: Arc::clone(&snapshot),
            lifecycle: Arc::clone(&lifecycle),
        });
        self.reactor.request(|response| ReactorCommand::Create {
            id,
            session_id,
            request,
            readiness,
            snapshot,
            lifecycle,
            response,
        })?;
        Ok(socket)
    }

    fn close_session(&self, session_id: SessionId) {
        self.reactor.close_session(session_id);
    }
}

/// Broker-core-facing handle for a reactor-owned socket.
///
/// It submits operations by socket ID and reads cached state, but never owns or
/// accesses the host socket descriptor.
struct LinuxSocket {
    id: u64,
    reactor: Arc<ReactorClient>,
    snapshot: Arc<Mutex<SocketSnapshot>>,
    lifecycle: Arc<SocketLifecycle>,
}

impl PlatformSocket for LinuxSocket {
    fn bind(&self, address: SocketAddrV4) -> BrokerResult<SocketOutcome<SocketAddrV4>> {
        self.reactor.request(|response| ReactorCommand::Bind {
            id: self.id,
            address,
            response,
        })
    }

    fn listen(&self, backlog: u32) -> BrokerResult<SocketOutcome<SocketAddrV4>> {
        self.reactor.request(|response| ReactorCommand::Listen {
            id: self.id,
            backlog,
            response,
        })
    }

    fn accept(
        &self,
        readiness: ReadinessRegistration,
    ) -> BrokerResult<SocketOutcome<AcceptedPlatformSocket>> {
        let id = self.reactor.allocate_socket_id()?;
        let snapshot = Arc::new(Mutex::new(SocketSnapshot::default()));
        let lifecycle = Arc::new(SocketLifecycle::pending());
        let socket = Arc::new(LinuxSocket {
            id,
            reactor: Arc::clone(&self.reactor),
            snapshot: Arc::clone(&snapshot),
            lifecycle: Arc::clone(&lifecycle),
        });
        match self.reactor.request(|response| ReactorCommand::Accept {
            listener_id: self.id,
            accepted_id: id,
            readiness,
            snapshot,
            lifecycle,
            response,
        })? {
            SocketOutcome::Completed(accepted) => {
                Ok(SocketOutcome::Completed(AcceptedPlatformSocket {
                    socket,
                    remote_address: accepted.remote_address,
                }))
            }
            SocketOutcome::Failed(error) => Ok(SocketOutcome::Failed(error)),
        }
    }

    fn connect(
        &self,
        address: SocketAddrV4,
    ) -> core::result::Result<SocketConnectionStatus, PlatformConnectError> {
        self.reactor.connect(self.id, address)
    }

    fn send(&self, data: Vec<u8>, _flags: SendFlags) -> BrokerResult<SocketOutcome<usize>> {
        self.reactor.request(|response| ReactorCommand::Send {
            id: self.id,
            data,
            response,
        })
    }

    fn send_to(
        &self,
        data: Vec<u8>,
        _flags: SendFlags,
        destination: Option<SocketAddrV4>,
    ) -> BrokerResult<SocketOutcome<usize>> {
        self.reactor.request(|response| ReactorCommand::SendTo {
            id: self.id,
            data,
            destination,
            response,
        })
    }

    fn receive(
        &self,
        length: usize,
        flags: ReceiveFlags,
        peek_offset: u32,
        peek_length: u32,
    ) -> BrokerResult<SocketOutcome<PlatformStreamReceive>> {
        let peek_offset =
            usize::try_from(peek_offset).map_err(|_| BrokerError::UnsupportedOperation)?;
        let peek_length =
            usize::try_from(peek_length).map_err(|_| BrokerError::UnsupportedOperation)?;
        match self.reactor.request(|response| ReactorCommand::Receive {
            id: self.id,
            length,
            flags,
            peek_offset,
            peek_length,
            response,
        })? {
            ReactorReceiveOutcome::Received(received) => Ok(SocketOutcome::Completed(
                PlatformStreamReceive::Received(received),
            )),
            ReactorReceiveOutcome::EndOfStream => {
                Ok(SocketOutcome::Completed(PlatformStreamReceive::EndOfStream))
            }
            ReactorReceiveOutcome::Failed(error) => Ok(SocketOutcome::Failed(error)),
        }
    }

    fn receive_from(
        &self,
        length: usize,
        flags: ReceiveFromFlags,
    ) -> BrokerResult<SocketOutcome<PlatformDatagramReceive>> {
        match self
            .reactor
            .request(|response| ReactorCommand::ReceiveFrom {
                id: self.id,
                length,
                flags,
                response,
            })? {
            ReactorReceiveFromOutcome::Received {
                data: received,
                datagram_length,
                source_address,
            } => Ok(SocketOutcome::Completed(PlatformDatagramReceive {
                data: received,
                datagram_length,
                source_address,
            })),
            ReactorReceiveFromOutcome::Failed(error) => Ok(SocketOutcome::Failed(error)),
        }
    }

    fn shutdown(&self, mode: ShutdownMode) -> BrokerResult<SocketOutcome<()>> {
        self.reactor.request(|response| ReactorCommand::Shutdown {
            id: self.id,
            mode,
            response,
        })
    }

    fn set_tcp_option(&self, value: TcpOptionValue) -> BrokerResult<()> {
        self.reactor
            .request(|response| ReactorCommand::SetTcpOption {
                id: self.id,
                value,
                response,
            })
    }

    fn get_tcp_option(&self, name: TcpOptionName) -> BrokerResult<TcpOptionValue> {
        self.reactor
            .request(|response| ReactorCommand::GetTcpOption {
                id: self.id,
                name,
                response,
            })
    }

    fn status(&self) -> BrokerResult<SocketStatusResponse> {
        self.reactor.request(|response| ReactorCommand::Status {
            id: self.id,
            response,
        })
    }

    fn retire(&self) {
        self.lifecycle.retire(|| self.reactor.close_socket(self.id));
    }

    fn readiness(&self) -> ReadinessFlags {
        self.snapshot
            .lock()
            .expect("Linux socket snapshot mutex poisoned")
            .readiness
    }
}

impl Drop for LinuxSocket {
    fn drop(&mut self) {
        self.retire();
    }
}

/// Thread-safe command, wake, and lifecycle handle for the socket reactor.
struct ReactorClient {
    commands: SyncSender<ReactorCommand>,
    wake: Arc<OwnedFd>,
    next_socket_id: AtomicU64,
    thread: Mutex<Option<JoinHandle<()>>>,
}

impl ReactorClient {
    fn start(max_sockets: usize, max_sockets_per_session: usize) -> IoResult<Self> {
        let epoll_fd = epoll::create(epoll::CreateFlags::CLOEXEC)?;
        let wake = Arc::new(eventfd(0, EventfdFlags::CLOEXEC | EventfdFlags::NONBLOCK)?);
        epoll::add(
            &epoll_fd,
            wake.as_ref(),
            epoll::EventData::new_u64(WAKE_TOKEN),
            epoll::EventFlags::IN,
        )?;

        let mut sockets = HashMap::new();
        sockets
            .try_reserve(max_sockets)
            .map_err(|_| Error::new(ErrorKind::OutOfMemory, "socket table allocation failed"))?;
        let (commands, receiver) = sync_channel(MAX_QUEUED_SOCKET_COMMANDS);
        let (started, startup) = sync_channel(1);
        let reactor_wake = Arc::clone(&wake);
        let reactor_thread = thread::Builder::new()
            .name("litebox-broker-socket-reactor".into())
            .spawn(move || {
                let mut events = Vec::new();
                if events.try_reserve_exact(MAX_EPOLL_EVENTS).is_err() {
                    let _ = started.send(false);
                    return;
                }
                let mut reactor = Reactor {
                    epoll: epoll_fd,
                    wake: reactor_wake,
                    commands: receiver,
                    sockets,
                    tcp: ReactorTcpState::default(),
                    udp: ReactorUdpState::default(),
                    sessions: HashMap::new(),
                    max_sockets,
                    max_sockets_per_session,
                    retained_connector_count: 0,
                    peek_cache: None,
                    events,
                };
                if started.send(true).is_err() {
                    return;
                }
                if let Err(error) = reactor.run() {
                    reactor.fail_all_sockets();
                    std::eprintln!("broker socket reactor failed: {error}");
                }
            })?;
        match startup.recv() {
            Ok(true) => {}
            Ok(false) => {
                let _ = reactor_thread.join();
                return Err(Error::new(
                    ErrorKind::OutOfMemory,
                    "epoll event allocation failed",
                ));
            }
            Err(_) => {
                let _ = reactor_thread.join();
                return Err(Error::other("socket reactor failed during startup"));
            }
        }

        Ok(Self {
            commands,
            wake,
            next_socket_id: AtomicU64::new(1),
            thread: Mutex::new(Some(reactor_thread)),
        })
    }

    fn allocate_socket_id(&self) -> BrokerResult<u64> {
        self.next_socket_id
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |id| {
                (id < UDP_EVENT_TOKEN_FLAG - 1).then_some(id + 1)
            })
            .map_err(|_| BrokerError::ResourceExhausted)
    }

    fn request<T>(
        &self,
        make_command: impl FnOnce(SyncSender<BrokerResult<T>>) -> ReactorCommand,
    ) -> BrokerResult<T> {
        let (response, receive) = sync_channel(1);
        let command = make_command(response);
        match self.commands.try_send(command) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => return Err(BrokerError::ResourceExhausted),
            Err(TrySendError::Disconnected(_)) => return Err(BrokerError::Internal),
        }
        // Once queued, wait for acknowledgement even if the wake write fails:
        // another reactor event may still cause the command to execute.
        let _ = self.signal();
        receive.recv().map_err(|_| BrokerError::Internal)?
    }

    fn connect(
        &self,
        id: u64,
        address: SocketAddrV4,
    ) -> core::result::Result<SocketConnectionStatus, PlatformConnectError> {
        let (response, receive) = sync_channel(1);
        let command = ReactorCommand::Connect {
            id,
            address,
            response,
        };
        match self.commands.try_send(command) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => {
                return Err(PlatformConnectError::PeerUnchanged(
                    BrokerError::ResourceExhausted,
                ));
            }
            Err(TrySendError::Disconnected(_)) => {
                return Err(PlatformConnectError::PeerIndeterminate(
                    BrokerError::Internal,
                ));
            }
        }
        // A queued connect has indeterminate peer state until the reactor
        // acknowledges it, regardless of whether this wake write succeeds.
        let _ = self.signal();
        receive
            .recv()
            .map_err(|_| PlatformConnectError::PeerIndeterminate(BrokerError::Internal))?
    }

    fn close_socket(&self, id: u64) {
        let (response, receive) = sync_channel(1);
        if self
            .commands
            .send(ReactorCommand::Close { id, response })
            .is_err()
        {
            return;
        }
        // Do not release the core's socket quota until the reactor has dropped
        // the descriptor, even if the redundant wake write fails.
        let _ = self.signal();
        let _ = receive.recv();
    }

    #[cfg(test)]
    fn host_address(&self, guest_port: u16) -> Option<SocketAddrV4> {
        let (response, receive) = sync_channel(1);
        self.commands
            .send(ReactorCommand::HostAddress {
                guest_port,
                response,
            })
            .unwrap();
        self.signal().unwrap();
        receive.recv().unwrap()
    }

    #[cfg(test)]
    fn pending_guest_connection_count(&self) -> usize {
        let (response, receive) = sync_channel(1);
        self.commands
            .send(ReactorCommand::PendingGuestConnectionCount { response })
            .unwrap();
        self.signal().unwrap();
        receive.recv().unwrap()
    }

    #[cfg(test)]
    fn retained_connector_count(&self) -> usize {
        let (response, receive) = sync_channel(1);
        self.commands
            .send(ReactorCommand::RetainedConnectorCount { response })
            .unwrap();
        self.signal().unwrap();
        receive.recv().unwrap()
    }

    #[cfg(test)]
    fn udp_queued_datagram_count(&self) -> usize {
        let (response, receive) = sync_channel(1);
        self.commands
            .send(ReactorCommand::UdpQueuedDatagramCount { response })
            .unwrap();
        self.signal().unwrap();
        receive.recv().unwrap()
    }

    #[cfg(test)]
    fn udp_native_endpoint_count(&self) -> usize {
        let (response, receive) = sync_channel(1);
        self.commands
            .send(ReactorCommand::UdpNativeEndpointCount { response })
            .unwrap();
        self.signal().unwrap();
        receive.recv().unwrap()
    }

    #[cfg(test)]
    fn udp_native_receive_buffer_size(&self, guest_port: u16) -> Option<usize> {
        let (response, receive) = sync_channel(1);
        self.commands
            .send(ReactorCommand::UdpNativeReceiveBufferSize {
                guest_port,
                response,
            })
            .unwrap();
        self.signal().unwrap();
        receive.recv().unwrap().unwrap()
    }

    #[cfg(test)]
    fn udp_external_peer_count(&self) -> usize {
        let (response, receive) = sync_channel(1);
        self.commands
            .send(ReactorCommand::UdpExternalPeerCount { response })
            .unwrap();
        self.signal().unwrap();
        receive.recv().unwrap()
    }

    #[cfg(test)]
    fn exhaust_udp_endpoint_generation(&self) {
        let (response, receive) = sync_channel(1);
        self.commands
            .send(ReactorCommand::ExhaustUdpEndpointGeneration { response })
            .unwrap();
        self.signal().unwrap();
        receive.recv().unwrap();
    }

    #[cfg(test)]
    fn expire_pending_guest_connections(&self) {
        let (response, receive) = sync_channel(1);
        self.commands
            .send(ReactorCommand::ExpireDeadlinedState {
                now: Instant::now() + PENDING_CONNECT_DISCARD_LIFETIME + Duration::from_secs(1),
                response,
            })
            .unwrap();
        self.signal().unwrap();
        receive.recv().unwrap();
    }

    #[cfg(test)]
    fn defer_untracked_guest_connection(&self, guest_port: u16) {
        let (response, receive) = sync_channel(1);
        self.commands
            .send(ReactorCommand::DeferUntrackedGuestConnection {
                guest_port,
                response,
            })
            .unwrap();
        self.signal().unwrap();
        receive.recv().unwrap();
    }

    fn close_session(&self, session_id: SessionId) {
        let (response, receive) = sync_channel(1);
        if self
            .commands
            .send(ReactorCommand::CloseSession {
                session_id,
                response,
            })
            .is_err()
        {
            return;
        }
        let _ = self.signal();
        let _ = receive.recv();
    }

    fn signal(&self) -> IoResult<()> {
        let value = 1_u64.to_ne_bytes();
        loop {
            match write(self.wake.as_ref(), &value) {
                Ok(length) if length == value.len() => return Ok(()),
                Ok(_) => {
                    return Err(Error::new(
                        ErrorKind::WriteZero,
                        "eventfd wake was truncated",
                    ));
                }
                Err(Errno::INTR) => {}
                // A saturated counter is already readable and therefore does
                // not need another wake value.
                Err(Errno::AGAIN) => return Ok(()),
                Err(error) => return Err(error.into()),
            }
        }
    }
}

impl Drop for ReactorClient {
    fn drop(&mut self) {
        let (response, receive) = sync_channel(1);
        if self
            .commands
            .send(ReactorCommand::Stop { response })
            .is_ok()
        {
            let _ = self.signal();
            let _ = receive.recv();
        }
        let thread = self
            .thread
            .lock()
            .expect("socket reactor thread mutex poisoned")
            .take();
        if thread.is_some_and(|thread| thread.join().is_err()) {
            std::eprintln!("broker socket reactor panicked");
        }
    }
}

/// Bounded operations submitted to the thread that exclusively owns socket descriptors.
enum ReactorCommand {
    Create {
        id: u64,
        session_id: SessionId,
        request: CreateSocketRequest,
        readiness: ReadinessRegistration,
        snapshot: Arc<Mutex<SocketSnapshot>>,
        lifecycle: Arc<SocketLifecycle>,
        response: SyncSender<BrokerResult<()>>,
    },
    Connect {
        id: u64,
        address: SocketAddrV4,
        response: SyncSender<core::result::Result<SocketConnectionStatus, PlatformConnectError>>,
    },
    Bind {
        id: u64,
        address: SocketAddrV4,
        response: SyncSender<BrokerResult<SocketOutcome<SocketAddrV4>>>,
    },
    Listen {
        id: u64,
        backlog: u32,
        response: SyncSender<BrokerResult<SocketOutcome<SocketAddrV4>>>,
    },
    Accept {
        listener_id: u64,
        accepted_id: u64,
        readiness: ReadinessRegistration,
        snapshot: Arc<Mutex<SocketSnapshot>>,
        lifecycle: Arc<SocketLifecycle>,
        response: SyncSender<BrokerResult<SocketOutcome<AcceptedEndpoints>>>,
    },
    Send {
        id: u64,
        data: Vec<u8>,
        response: SyncSender<BrokerResult<SocketOutcome<usize>>>,
    },
    SendTo {
        id: u64,
        data: Vec<u8>,
        destination: Option<SocketAddrV4>,
        response: SyncSender<BrokerResult<SocketOutcome<usize>>>,
    },
    Receive {
        id: u64,
        length: usize,
        flags: ReceiveFlags,
        peek_offset: usize,
        peek_length: usize,
        response: SyncSender<BrokerResult<ReactorReceiveOutcome>>,
    },
    ReceiveFrom {
        id: u64,
        length: usize,
        flags: ReceiveFromFlags,
        response: SyncSender<BrokerResult<ReactorReceiveFromOutcome>>,
    },
    Shutdown {
        id: u64,
        mode: ShutdownMode,
        response: SyncSender<BrokerResult<SocketOutcome<()>>>,
    },
    SetTcpOption {
        id: u64,
        value: TcpOptionValue,
        response: SyncSender<BrokerResult<()>>,
    },
    GetTcpOption {
        id: u64,
        name: TcpOptionName,
        response: SyncSender<BrokerResult<TcpOptionValue>>,
    },
    Status {
        id: u64,
        response: SyncSender<BrokerResult<SocketStatusResponse>>,
    },
    Close {
        id: u64,
        response: SyncSender<()>,
    },
    CloseSession {
        session_id: SessionId,
        response: SyncSender<()>,
    },
    #[cfg(test)]
    HostAddress {
        guest_port: u16,
        response: SyncSender<Option<SocketAddrV4>>,
    },
    #[cfg(test)]
    PendingGuestConnectionCount {
        response: SyncSender<usize>,
    },
    #[cfg(test)]
    RetainedConnectorCount {
        response: SyncSender<usize>,
    },
    #[cfg(test)]
    UdpQueuedDatagramCount {
        response: SyncSender<usize>,
    },
    #[cfg(test)]
    UdpNativeEndpointCount {
        response: SyncSender<usize>,
    },
    #[cfg(test)]
    UdpNativeReceiveBufferSize {
        guest_port: u16,
        response: SyncSender<BrokerResult<Option<usize>>>,
    },
    #[cfg(test)]
    UdpExternalPeerCount {
        response: SyncSender<usize>,
    },
    #[cfg(test)]
    ExhaustUdpEndpointGeneration {
        response: SyncSender<()>,
    },
    #[cfg(test)]
    ExpireDeadlinedState {
        now: Instant,
        response: SyncSender<()>,
    },
    #[cfg(test)]
    DeferUntrackedGuestConnection {
        guest_port: u16,
        response: SyncSender<()>,
    },
    Stop {
        response: SyncSender<()>,
    },
}

/// Owned receive result returned across the reactor thread boundary.
enum ReactorReceiveOutcome {
    Received(Vec<u8>),
    EndOfStream,
    Failed(SocketError),
}

enum ReactorReceiveFromOutcome {
    Received {
        data: Vec<u8>,
        datagram_length: usize,
        source_address: SocketAddrV4,
    },
    Failed(SocketError),
}

struct AcceptedEndpoints {
    remote_address: SocketAddrV4,
}

/// State owned and accessed exclusively by the socket reactor thread.
struct Reactor {
    epoll: OwnedFd,
    wake: Arc<OwnedFd>,
    commands: Receiver<ReactorCommand>,
    sockets: HashMap<u64, SocketEntry>,
    tcp: ReactorTcpState,
    udp: ReactorUdpState,
    sessions: HashMap<SessionId, ReactorSessionState>,
    max_sockets: usize,
    max_sockets_per_session: usize,
    retained_connector_count: usize,
    peek_cache: Option<PeekCache>,
    events: Vec<epoll::Event>,
}

struct PeekCache {
    socket_id: u64,
    requested_length: usize,
    data: Vec<u8>,
}

/// Reactor-owned TCP descriptor and transport-specific lifecycle state.
#[expect(
    clippy::struct_excessive_bools,
    reason = "TCP lifecycle and option flags are independent"
)]
struct TcpSocketState {
    socket: OwnedFd,
    untracked_guest_listener_id: Option<u64>,
    peek_waitall_threshold: Option<usize>,
    listening: bool,
    was_listener: bool,
    abortive_close: bool,
    host_connection: Option<(SocketAddrV4, SocketAddrV4)>,
    no_delay: bool,
    keep_alive: bool,
}

/// Exactly one transport-specific payload for a live reactor socket.
enum SocketTransportState {
    Tcp(TcpSocketState),
    Udp(UdpSocketState),
}

/// Reactor-owned shared socket state and transport-specific payload.
struct SocketEntry {
    session_id: SessionId,
    transport: SocketTransportState,
    readiness: ReadinessRegistration,
    snapshot: Arc<Mutex<SocketSnapshot>>,
    connection_status: SocketConnectionStatus,
    read_shutdown: bool,
    write_shutdown: bool,
    guest_local_address: Option<SocketAddrV4>,
}

impl SocketEntry {
    fn kind(&self) -> SocketKind {
        match &self.transport {
            SocketTransportState::Tcp(_) => SocketKind::Tcp,
            SocketTransportState::Udp(_) => SocketKind::Udp,
        }
    }

    fn tcp_state(&self) -> BrokerResult<&TcpSocketState> {
        match &self.transport {
            SocketTransportState::Tcp(tcp) => Ok(tcp),
            SocketTransportState::Udp(_) => Err(BrokerError::Internal),
        }
    }

    fn tcp_state_mut(&mut self) -> BrokerResult<&mut TcpSocketState> {
        match &mut self.transport {
            SocketTransportState::Tcp(tcp) => Ok(tcp),
            SocketTransportState::Udp(_) => Err(BrokerError::Internal),
        }
    }

    fn udp_state(&self) -> BrokerResult<&UdpSocketState> {
        match &self.transport {
            SocketTransportState::Udp(udp) => Ok(udp),
            SocketTransportState::Tcp(_) => Err(BrokerError::Internal),
        }
    }

    fn udp_state_mut(&mut self) -> BrokerResult<&mut UdpSocketState> {
        match &mut self.transport {
            SocketTransportState::Udp(udp) => Ok(udp),
            SocketTransportState::Tcp(_) => Err(BrokerError::Internal),
        }
    }
}

/// Reactor-owned realization of guest TCP bindings and pending connections.
#[derive(Default)]
struct ReactorTcpState {
    bindings: HashMap<u16, ReactorTcpBinding>,
    pending_guest_connections: HashMap<(SocketAddrV4, SocketAddrV4), PendingGuestTcpConnection>,
}

/// Reactor-side per-session socket, retained-descriptor, and teardown state.
///
/// Sessions are ownership domains, not guest network namespaces.
#[derive(Default)]
struct ReactorSessionState {
    live_socket_count: usize,
    pending_guest_connection_count: usize,
    retained_connector_count: usize,
    udp_external_peer_count: usize,
    udp_queued_datagrams: usize,
    udp_queued_bytes: usize,
    closing: bool,
}

struct PendingGuestTcpConnection {
    session_id: SessionId,
    guest_address: SocketAddrV4,
    listener_id: u64,
    discard_on_accept: bool,
    discard_until_deadline: bool,
    discard_deadline: Option<Instant>,
    retained_connector: Option<OwnedFd>,
}

enum PendingGuestConnectionMatch {
    PersistentDiscard,
    Take(PendingGuestTcpConnection),
}

#[derive(Clone, Copy)]
struct ReactorTcpBinding {
    socket_id: u64,
    guest_address: SocketAddrV4,
    host_address: Option<SocketAddrV4>,
    listening: bool,
    requires_backlog_drain: bool,
    untracked_connection_deadline: Option<Instant>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SocketKind {
    Tcp,
    Udp,
}

impl ReactorTcpState {
    fn insert_binding(&mut self, binding: ReactorTcpBinding) -> BrokerResult<()> {
        let port = binding.guest_address.port();
        if port == 0 || self.bindings.contains_key(&port) {
            return Err(BrokerError::Internal);
        }
        self.bindings
            .try_reserve(1)
            .map_err(|_| BrokerError::OutOfMemory)?;
        self.bindings.insert(port, binding);
        Ok(())
    }

    fn remove_binding(&mut self, port: u16, socket_id: u64) {
        if self
            .bindings
            .get(&port)
            .is_some_and(|binding| binding.socket_id == socket_id)
        {
            self.bindings.remove(&port);
        }
    }

    fn guest_binding(&self, address: SocketAddrV4) -> Option<ReactorTcpBinding> {
        if !address.ip().is_loopback() {
            return None;
        }
        self.bindings.get(&address.port()).copied()
    }

    fn set_host_address(
        &mut self,
        port: u16,
        socket_id: u64,
        host_address: SocketAddrV4,
    ) -> BrokerResult<()> {
        let binding = self.bindings.get_mut(&port).ok_or(BrokerError::Internal)?;
        if binding.socket_id != socket_id {
            return Err(BrokerError::Internal);
        }
        binding.host_address = Some(host_address);
        Ok(())
    }

    fn mark_listening(&mut self, port: u16, socket_id: u64) -> BrokerResult<()> {
        let binding = self.bindings.get_mut(&port).ok_or(BrokerError::Internal)?;
        if binding.socket_id != socket_id || binding.host_address.is_none() {
            return Err(BrokerError::Internal);
        }
        binding.listening = true;
        Ok(())
    }

    fn stop_listening(&mut self, port: u16, socket_id: u64) -> BrokerResult<()> {
        let binding = self.bindings.get_mut(&port).ok_or(BrokerError::Internal)?;
        if binding.socket_id != socket_id {
            return Err(BrokerError::Internal);
        }
        binding.listening = false;
        binding.requires_backlog_drain = false;
        binding.untracked_connection_deadline = None;
        Ok(())
    }

    fn defer_untracked_connection(&mut self, listener_id: u64, deadline: Instant) {
        let binding = self
            .bindings
            .values_mut()
            .find(|binding| binding.socket_id == listener_id)
            .expect("untracked guest connection listener binding missing");
        binding.untracked_connection_deadline = Some(
            binding
                .untracked_connection_deadline
                .map_or(deadline, |current| current.max(deadline)),
        );
    }

    fn persist_discard_marker_for_collision(
        &mut self,
        connection: (SocketAddrV4, SocketAddrV4),
        listener_id: u64,
        deadline: Instant,
    ) -> bool {
        let Some(pending) = self.pending_guest_connections.get_mut(&connection) else {
            return false;
        };
        if !pending.discard_on_accept || pending.listener_id != listener_id {
            return false;
        }
        // A collision can represent both the old ambiguous child and the new
        // one. Keep dropping this tuple until the refreshed deadline instead
        // of blocking unrelated connections to the listener. The marker stays
        // charged to its original session even when another session refreshes
        // it; identity protection is broker-wide and adds no new record.
        pending.discard_until_deadline = true;
        pending.discard_deadline = Some(deadline);
        true
    }

    fn finish_listener_backlog_drain(&mut self, listener_id: u64) -> BrokerResult<()> {
        let binding = self
            .bindings
            .values_mut()
            .find(|binding| binding.socket_id == listener_id)
            .ok_or(BrokerError::Internal)?;
        // A tuple-unknown connect can still complete after an empty drain
        // observation, so only its maturation deadline may release that block.
        binding.requires_backlog_drain = false;
        Ok(())
    }

    fn take_pending_guest_connection(
        &mut self,
        remote_address: SocketAddrV4,
        local_address: SocketAddrV4,
    ) -> Option<PendingGuestConnectionMatch> {
        if self
            .pending_guest_connections
            .get(&(remote_address, local_address))
            .is_some_and(|connection| {
                connection.discard_on_accept && connection.discard_until_deadline
            })
        {
            return Some(PendingGuestConnectionMatch::PersistentDiscard);
        }
        self.pending_guest_connections
            .remove(&(remote_address, local_address))
            .map(PendingGuestConnectionMatch::Take)
    }

    fn insert_pending_guest_connection(
        &mut self,
        connection: (SocketAddrV4, SocketAddrV4),
        pending: PendingGuestTcpConnection,
    ) -> BrokerResult<()> {
        if self.pending_guest_connections.contains_key(&connection) {
            return Err(BrokerError::ResourceExhausted);
        }
        self.pending_guest_connections.insert(connection, pending);
        Ok(())
    }
}

fn retain_session_state(state: &ReactorSessionState) -> bool {
    !state.closing
        || state.live_socket_count != 0
        || state.pending_guest_connection_count != 0
        || state.retained_connector_count != 0
        || state.udp_external_peer_count != 0
        || state.udp_queued_datagrams != 0
        || state.udp_queued_bytes != 0
}

fn listener_backlog_is_nonempty(sockets: &HashMap<u64, SocketEntry>, listener_id: u64) -> bool {
    let Some(listener) = sockets.get(&listener_id) else {
        return false;
    };
    let Ok(tcp) = listener.tcp_state() else {
        return false;
    };
    if !tcp.listening {
        return false;
    }
    socket_backlog_is_nonempty(&tcp.socket)
}

fn socket_backlog_is_nonempty(socket: &OwnedFd) -> bool {
    let no_wait = Timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    loop {
        let mut poll_fd = [PollFd::new(socket, PollFlags::IN)];
        match poll(&mut poll_fd, Some(&no_wait)) {
            Ok(_) => return !poll_fd[0].revents().is_empty(),
            Err(Errno::INTR) => {}
            Err(_) => return true,
        }
    }
}

/// Cached connection and readiness state shared with the broker-facing handle.
///
/// The reactor updates this snapshot whenever kernel state changes, allowing
/// status and readiness queries without transferring descriptor authority or
/// submitting another reactor command.
#[derive(Clone, Copy)]
struct SocketSnapshot {
    status: SocketConnectionStatus,
    readiness: ReadinessFlags,
    local_address: Option<SocketAddrV4>,
    pending_error: Option<SocketError>,
}

impl Default for SocketSnapshot {
    fn default() -> Self {
        Self {
            status: SocketConnectionStatus::Unconnected,
            readiness: ReadinessFlags::default(),
            local_address: None,
            pending_error: None,
        }
    }
}

/// Fatal failure that terminates the socket reactor.
#[derive(Debug)]
enum ReactorFailure {
    Io(Errno),
    Broker(BrokerError),
}

impl fmt::Display for ReactorFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "I/O error: {error}"),
            Self::Broker(error) => {
                write!(formatter, "broker error: {error:?}")
            }
        }
    }
}

impl Reactor {
    fn discard_failed_connect_after_command(&mut self, id: u64, was_connecting: bool) {
        if !was_connecting {
            return;
        }
        let failed_connection = self.sockets.get(&id).and_then(|socket| {
            matches!(socket.connection_status, SocketConnectionStatus::Failed(_))
                .then(|| {
                    socket
                        .tcp_state()
                        .ok()
                        .and_then(|tcp| tcp.host_connection)
                        .map(|connection| (connection, socket.session_id))
                })
                .flatten()
        });
        if let Some((connection, session_id)) = failed_connection {
            self.discard_pending_guest_connection(connection, session_id);
        }
    }

    fn reserve_pending_guest_connection(&mut self, session_id: SessionId) -> BrokerResult<()> {
        let session = self
            .sessions
            .get(&session_id)
            .ok_or(BrokerError::Internal)?;
        // Pending records can outlive connector descriptors, so bound this
        // metadata independently using the configured socket budgets.
        if session.pending_guest_connection_count >= self.max_sockets_per_session
            || self.tcp.pending_guest_connections.len() >= self.max_sockets
        {
            return Err(BrokerError::ResourceExhausted);
        }
        self.tcp
            .pending_guest_connections
            .try_reserve(1)
            .map_err(|_| BrokerError::OutOfMemory)
    }

    fn finish_removed_pending_guest_connection(&mut self, connection: &PendingGuestTcpConnection) {
        let session = self
            .sessions
            .get_mut(&connection.session_id)
            .expect("pending guest connection session state missing");
        session.pending_guest_connection_count = session
            .pending_guest_connection_count
            .checked_sub(1)
            .expect("session pending guest connection count underflow");
        if connection.retained_connector.is_some() {
            self.retained_connector_count = self
                .retained_connector_count
                .checked_sub(1)
                .expect("reactor retained connector count underflow");
            session.retained_connector_count = session
                .retained_connector_count
                .checked_sub(1)
                .expect("session retained connector count underflow");
        }
    }

    fn insert_pending_guest_connection(
        &mut self,
        session_id: SessionId,
        connection: (SocketAddrV4, SocketAddrV4),
        guest_address: SocketAddrV4,
        listener_id: u64,
    ) -> BrokerResult<()> {
        let pending_count = self
            .sessions
            .get(&session_id)
            .ok_or(BrokerError::Internal)?
            .pending_guest_connection_count
            .checked_add(1)
            .ok_or(BrokerError::ResourceExhausted)?;
        self.tcp.insert_pending_guest_connection(
            connection,
            PendingGuestTcpConnection {
                session_id,
                guest_address,
                listener_id,
                discard_on_accept: false,
                discard_until_deadline: false,
                discard_deadline: None,
                retained_connector: None,
            },
        )?;
        self.sessions
            .get_mut(&session_id)
            .expect("pending guest connection session state missing")
            .pending_guest_connection_count = pending_count;
        Ok(())
    }

    fn discard_pending_guest_connection(
        &mut self,
        connection: (SocketAddrV4, SocketAddrV4),
        session_id: SessionId,
    ) {
        if let Some(pending) = self.tcp.pending_guest_connections.get_mut(&connection)
            && pending.session_id == session_id
        {
            // The descriptor remains open and pins the native tuple. Final
            // close starts the bounded discard deadline.
            pending.discard_on_accept = true;
            pending.discard_deadline = None;
        }
    }

    fn remove_pending_guest_connections_for_listener(&mut self, listener_id: u64) {
        let Reactor {
            tcp,
            sessions,
            retained_connector_count,
            ..
        } = self;
        tcp.pending_guest_connections.retain(|_, connection| {
            let retain = connection.listener_id != listener_id;
            if !retain {
                let session = sessions
                    .get_mut(&connection.session_id)
                    .expect("pending guest connection session state missing");
                session.pending_guest_connection_count = session
                    .pending_guest_connection_count
                    .checked_sub(1)
                    .expect("session pending guest connection count underflow");
                if connection.retained_connector.is_some() {
                    session.retained_connector_count = session
                        .retained_connector_count
                        .checked_sub(1)
                        .expect("session retained connector count underflow");
                    *retained_connector_count = retained_connector_count
                        .checked_sub(1)
                        .expect("reactor retained connector count underflow");
                }
            }
            retain
        });
        sessions.retain(|_, session| retain_session_state(session));
    }

    fn retire_session_connectors(&mut self, session_id: SessionId) {
        let discard_deadline = Instant::now() + PENDING_CONNECT_DISCARD_LIFETIME;
        let mut released = 0;
        for connection in self
            .tcp
            .pending_guest_connections
            .values_mut()
            .filter(|connection| connection.session_id == session_id)
        {
            if let Some(connector) = connection.retained_connector.take() {
                let _ = sockopt::set_socket_linger(&connector, None);
                drop(connector);
                connection.discard_on_accept = true;
                connection.discard_deadline = Some(discard_deadline);
                released += 1;
            }
        }
        self.retained_connector_count = self
            .retained_connector_count
            .checked_sub(released)
            .expect("reactor retained connector count underflow");
        if let Some(session) = self.sessions.get_mut(&session_id) {
            session.retained_connector_count = session
                .retained_connector_count
                .checked_sub(released)
                .expect("session retained connector count underflow");
        }
    }

    fn next_cleanup_deadline(&self) -> Option<Instant> {
        self.tcp
            .pending_guest_connections
            .values()
            .filter_map(|connection| connection.discard_deadline)
            .chain(
                self.tcp
                    .bindings
                    .values()
                    .filter_map(|binding| binding.untracked_connection_deadline),
            )
            .min()
    }

    fn expire_deadlined_state(&mut self, now: Instant) {
        let Reactor {
            tcp,
            sockets,
            sessions,
            retained_connector_count,
            ..
        } = self;
        let ReactorTcpState {
            bindings,
            pending_guest_connections,
        } = tcp;
        for binding in bindings.values_mut() {
            if binding
                .untracked_connection_deadline
                .is_some_and(|deadline| deadline <= now)
            {
                if listener_backlog_is_nonempty(sockets, binding.socket_id) {
                    binding.requires_backlog_drain = true;
                }
                binding.untracked_connection_deadline = None;
            }
        }
        for connection in pending_guest_connections.values().filter(|connection| {
            connection.discard_on_accept
                && connection
                    .discard_deadline
                    .is_some_and(|deadline| deadline <= now)
        }) {
            if listener_backlog_is_nonempty(sockets, connection.listener_id) {
                bindings
                    .values_mut()
                    .find(|binding| binding.socket_id == connection.listener_id)
                    .expect("pending guest connection listener binding missing")
                    .requires_backlog_drain = true;
            }
        }
        pending_guest_connections.retain(|_, connection| {
            let retain = !connection.discard_on_accept
                || connection
                    .discard_deadline
                    .is_none_or(|deadline| deadline > now);
            if !retain {
                let session = sessions
                    .get_mut(&connection.session_id)
                    .expect("pending guest connection session state missing");
                session.pending_guest_connection_count = session
                    .pending_guest_connection_count
                    .checked_sub(1)
                    .expect("session pending guest connection count underflow");
                if connection.retained_connector.is_some() {
                    session.retained_connector_count = session
                        .retained_connector_count
                        .checked_sub(1)
                        .expect("session retained connector count underflow");
                    *retained_connector_count = retained_connector_count
                        .checked_sub(1)
                        .expect("reactor retained connector count underflow");
                }
            }
            retain
        });
        sessions.retain(|_, session| retain_session_state(session));
    }

    fn take_pending_guest_connection_for_accept(
        &mut self,
        listener_id: u64,
        remote_address: SocketAddrV4,
        local_address: SocketAddrV4,
    ) -> Option<SocketAddrV4> {
        let PendingGuestConnectionMatch::Take(mut connection) = self
            .tcp
            .take_pending_guest_connection(remote_address, local_address)?
        else {
            return None;
        };
        self.finish_removed_pending_guest_connection(&connection);
        drop(connection.retained_connector.take());
        let guest_address = (!connection.discard_on_accept
            && connection.listener_id == listener_id)
            .then_some(connection.guest_address);
        self.sessions
            .retain(|_, session| retain_session_state(session));
        guest_address
    }

    fn has_accept_capacity(
        &self,
        listener_id: u64,
        listener_session_id: SessionId,
    ) -> BrokerResult<bool> {
        let global_at_limit = self
            .sockets
            .len()
            .checked_add(self.retained_connector_count)
            .is_none_or(|count| count >= self.max_sockets);
        let listener_session = self
            .sessions
            .get(&listener_session_id)
            .ok_or(BrokerError::Internal)?;
        let session_at_limit = listener_session
            .live_socket_count
            .checked_add(listener_session.retained_connector_count)
            .is_none_or(|count| count >= self.max_sockets_per_session);
        if !global_at_limit && !session_at_limit {
            return Ok(true);
        }

        for connection in self
            .tcp
            .pending_guest_connections
            .values()
            .filter(|connection| connection.listener_id == listener_id)
            .filter(|connection| !connection.discard_on_accept)
        {
            if global_at_limit && connection.retained_connector.is_none() {
                return Ok(false);
            }
            if session_at_limit
                && (connection.session_id != listener_session_id
                    || connection.retained_connector.is_none())
            {
                return Ok(false);
            }
        }
        Ok(true)
    }

    fn is_private_tcp_host_endpoint(&self, address: SocketAddrV4) -> bool {
        self.tcp
            .bindings
            .values()
            .filter_map(|binding| binding.host_address)
            .any(|host_address| host_address == address)
    }

    /// Reports whether an address names a live broker-private native UDP endpoint.
    ///
    /// Native UDP endpoints are wildcard-bound, so a local address plus a
    /// registered host port identifies the endpoint. Guest routing must check
    /// its namespace first because guest and native ports may numerically
    /// collide.
    fn is_private_udp_host_endpoint(&self, address: SocketAddrV4) -> bool {
        self.udp.is_private_host_port(address.port()) && is_local_ipv4_address(*address.ip())
    }

    fn resolve_guest_destination(
        &self,
        mut address: SocketAddrV4,
    ) -> SocketOutcome<(SocketAddrV4, Option<u64>)> {
        if address.ip().is_unspecified() {
            address = SocketAddrV4::new(Ipv4Addr::LOCALHOST, address.port());
        }
        if let Some(binding) = self.tcp.guest_binding(address) {
            // A live guest binding owns this destination port broker-wide;
            // only a listener with a fully classified backlog may receive
            // new guest connections through it.
            if !binding.listening
                || binding.requires_backlog_drain
                // Defence in depth for failures after connect(2) but before a
                // complete host tuple can be recorded.
                || binding.untracked_connection_deadline.is_some()
            {
                return SocketOutcome::Failed(SocketError::ConnectionRefused);
            }
            return match binding.host_address {
                Some(host_address) => {
                    SocketOutcome::Completed((host_address, Some(binding.socket_id)))
                }
                None => SocketOutcome::Failed(SocketError::ConnectionRefused),
            };
        }
        if self.is_private_tcp_host_endpoint(address) {
            SocketOutcome::Failed(SocketError::ConnectionRefused)
        } else {
            SocketOutcome::Completed((address, None))
        }
    }

    fn bind_socket(
        &mut self,
        id: u64,
        requested_address: SocketAddrV4,
    ) -> BrokerResult<SocketOutcome<SocketAddrV4>> {
        let (kind, already_bound) = self
            .sockets
            .get(&id)
            .map(|socket| (socket.kind(), socket.guest_local_address.is_some()))
            .ok_or(BrokerError::Internal)?;
        if kind == SocketKind::Udp {
            if already_bound {
                return Ok(SocketOutcome::Failed(SocketError::InvalidArgument));
            }
            self.udp.reserve_binding(requested_address.port())?;
            let original_bind_was_wildcard = requested_address.ip().is_unspecified();
            let internal_address = if original_bind_was_wildcard {
                SocketAddrV4::new(Ipv4Addr::LOCALHOST, requested_address.port())
            } else {
                requested_address
            };
            self.udp.insert_binding(ReactorUdpBinding {
                socket_id: id,
                guest_address: requested_address,
                internal_address,
            })?;
            let socket = self.sockets.get_mut(&id).ok_or(BrokerError::Internal)?;
            let udp = socket.udp_state_mut()?;
            udp.original_bind_was_wildcard = original_bind_was_wildcard;
            udp.internal_address = Some(internal_address);
            socket.guest_local_address = Some(requested_address);
            socket
                .snapshot
                .lock()
                .expect("Linux socket snapshot mutex poisoned")
                .local_address = Some(requested_address);
            return Ok(SocketOutcome::Completed(requested_address));
        }
        if already_bound {
            return Ok(SocketOutcome::Failed(SocketError::InvalidArgument));
        }
        let guest_address = requested_address;
        self.tcp.insert_binding(ReactorTcpBinding {
            socket_id: id,
            guest_address,
            host_address: None,
            listening: false,
            requires_backlog_drain: false,
            untracked_connection_deadline: None,
        })?;
        let socket = self.sockets.get_mut(&id).ok_or(BrokerError::Internal)?;
        socket.guest_local_address = Some(guest_address);
        socket
            .snapshot
            .lock()
            .expect("Linux socket snapshot mutex poisoned")
            .local_address = Some(guest_address);
        Ok(SocketOutcome::Completed(guest_address))
    }

    fn listen_socket(
        &mut self,
        id: u64,
        backlog: u32,
    ) -> BrokerResult<SocketOutcome<SocketAddrV4>> {
        let (kind, guest_address) = self
            .sockets
            .get(&id)
            .map(|socket| (socket.kind(), socket.guest_local_address))
            .ok_or(BrokerError::Internal)?;
        if kind != SocketKind::Tcp {
            return Ok(SocketOutcome::Failed(SocketError::InvalidArgument));
        }
        let guest_address = guest_address.ok_or(BrokerError::Internal)?;
        let needs_host_bind = local_socket_address(
            &self
                .sockets
                .get(&id)
                .ok_or(BrokerError::Internal)?
                .tcp_state()?
                .socket,
        )?
        .port()
            == 0;
        if needs_host_bind {
            let socket = self.sockets.get_mut(&id).ok_or(BrokerError::Internal)?;
            let host_address =
                match bind_host_socket(socket, SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))? {
                    SocketOutcome::Completed(address) => address,
                    SocketOutcome::Failed(error) => return Ok(SocketOutcome::Failed(error)),
                };
            self.tcp
                .set_host_address(guest_address.port(), id, host_address)?;
        }
        match listen_tcp_socket(
            &self.epoll,
            id,
            self.sockets.get_mut(&id).ok_or(BrokerError::Internal)?,
            backlog,
        )? {
            SocketOutcome::Completed(()) => {
                self.tcp.mark_listening(guest_address.port(), id)?;
                Ok(SocketOutcome::Completed(guest_address))
            }
            SocketOutcome::Failed(error) => Ok(SocketOutcome::Failed(error)),
        }
    }

    fn connect_socket(
        &mut self,
        id: u64,
        guest_address: SocketAddrV4,
    ) -> core::result::Result<SocketConnectionStatus, PlatformConnectError> {
        let kind = self.sockets.get(&id).map(SocketEntry::kind).ok_or(
            PlatformConnectError::PeerIndeterminate(BrokerError::Internal),
        )?;
        if kind == SocketKind::Udp {
            let peer = match self.resolve_udp_destination(guest_address) {
                SocketOutcome::Completed(peer) => peer,
                SocketOutcome::Failed(error) => {
                    return Ok(SocketConnectionStatus::Failed(error));
                }
            };
            let mut reused_host_address = None;
            let mut staged_endpoint = match peer {
                ReactorUdpPeer::Guest { .. } => None,
                ReactorUdpPeer::External(address) => {
                    if self
                        .sockets
                        .get(&id)
                        .ok_or(PlatformConnectError::PeerUnchanged(BrokerError::Internal))?
                        .udp_state()
                        .map_err(PlatformConnectError::PeerUnchanged)?
                        .external_endpoint
                        .is_some()
                    {
                        match self.connect_existing_udp_endpoint(id, address)? {
                            SocketOutcome::Completed(host_address) => {
                                reused_host_address = Some(host_address);
                                None
                            }
                            SocketOutcome::Failed(error) => {
                                return Ok(SocketConnectionStatus::Failed(error));
                            }
                        }
                    } else {
                        match self
                            .stage_udp_endpoint(id, address, Some(address))
                            .map_err(PlatformConnectError::PeerUnchanged)?
                        {
                            SocketOutcome::Completed(endpoint) => Some(endpoint),
                            SocketOutcome::Failed(error) => {
                                return Ok(SocketConnectionStatus::Failed(error));
                            }
                        }
                    }
                }
            };
            if let Err(error) = self.clear_udp_receive_queue(id) {
                if let Some(endpoint) = staged_endpoint.take() {
                    self.unregister_udp_endpoint(endpoint);
                }
                return Err(PlatformConnectError::PeerIndeterminate(error));
            }
            let guest_local_address = match (|| {
                let socket = self.sockets.get(&id).ok_or(BrokerError::Internal)?;
                let current = socket.guest_local_address.ok_or(BrokerError::Internal)?;
                let udp = socket.udp_state()?;
                if udp.original_bind_was_wildcard {
                    let ip = match (&peer, &staged_endpoint, reused_host_address) {
                        (ReactorUdpPeer::Guest { .. }, _, _) => Ipv4Addr::LOCALHOST,
                        (ReactorUdpPeer::External(_), Some(endpoint), _) => {
                            *endpoint.host_address.ip()
                        }
                        (ReactorUdpPeer::External(_), None, Some(host_address)) => {
                            *host_address.ip()
                        }
                        _ => return Err(BrokerError::Internal),
                    };
                    Ok(SocketAddrV4::new(ip, current.port()))
                } else {
                    Ok(current)
                }
            })() {
                Ok(address) => address,
                Err(error) => {
                    if let Some(endpoint) = staged_endpoint.take() {
                        self.unregister_udp_endpoint(endpoint);
                    }
                    return Err(PlatformConnectError::PeerIndeterminate(error));
                }
            };
            if reused_host_address.is_none() {
                self.replace_udp_endpoint(id, staged_endpoint.take());
            }
            self.clear_udp_external_peers(id)
                .map_err(PlatformConnectError::PeerIndeterminate)?;
            self.udp
                .update_guest_address(id, guest_local_address)
                .map_err(PlatformConnectError::PeerIndeterminate)?;
            let readiness = self
                .udp_readiness(id)
                .map_err(PlatformConnectError::PeerIndeterminate)?;
            let socket =
                self.sockets
                    .get_mut(&id)
                    .ok_or(PlatformConnectError::PeerIndeterminate(
                        BrokerError::Internal,
                    ))?;
            socket.guest_local_address = Some(guest_local_address);
            socket.connection_status = SocketConnectionStatus::Connected;
            socket
                .udp_state_mut()
                .map_err(PlatformConnectError::PeerIndeterminate)?
                .peer = Some(peer);
            socket
                .snapshot
                .lock()
                .expect("Linux socket snapshot mutex poisoned")
                .local_address = Some(guest_local_address);
            update_snapshot(socket, Some(SocketConnectionStatus::Connected), readiness)
                .map_err(PlatformConnectError::PeerIndeterminate)?;
            return Ok(SocketConnectionStatus::Connected);
        }
        let (session_id, local_guest_address) = self
            .sockets
            .get(&id)
            .and_then(|socket| {
                socket
                    .guest_local_address
                    .map(|address| (socket.session_id, address))
            })
            .ok_or(PlatformConnectError::PeerUnchanged(BrokerError::Internal))?;
        let (network_address, guest_listener_id) =
            match self.resolve_guest_destination(guest_address) {
                SocketOutcome::Completed(destination) => destination,
                SocketOutcome::Failed(error) => {
                    let status = SocketConnectionStatus::Failed(error);
                    let socket = self
                        .sockets
                        .get_mut(&id)
                        .ok_or(PlatformConnectError::PeerUnchanged(BrokerError::Internal))?;
                    socket.connection_status = status;
                    update_snapshot(socket, Some(status), ReadinessFlags::ERROR)
                        .map_err(PlatformConnectError::PeerIndeterminate)?;
                    return Ok(status);
                }
            };
        if guest_listener_id.is_some() {
            self.expire_deadlined_state(Instant::now());
            self.reserve_pending_guest_connection(session_id)
                .map_err(PlatformConnectError::PeerUnchanged)?;
        }
        let (status, readiness) = connect_tcp_socket(
            &self.epoll,
            id,
            self.sockets
                .get_mut(&id)
                .ok_or(PlatformConnectError::PeerUnchanged(BrokerError::Internal))?,
            network_address,
            guest_listener_id,
        )?;
        if matches!(
            status,
            SocketConnectionStatus::Connecting | SocketConnectionStatus::Connected
        ) {
            let host_address = local_socket_address(
                &self
                    .sockets
                    .get(&id)
                    .ok_or(PlatformConnectError::PeerIndeterminate(
                        BrokerError::Internal,
                    ))?
                    .tcp_state()
                    .map_err(PlatformConnectError::PeerIndeterminate)?
                    .socket,
            )
            .map_err(PlatformConnectError::PeerIndeterminate)?;
            self.tcp
                .set_host_address(local_guest_address.port(), id, host_address)
                .map_err(PlatformConnectError::PeerIndeterminate)?;
            if let Some(listener_id) = guest_listener_id {
                let connection = (host_address, network_address);
                if self.tcp.persist_discard_marker_for_collision(
                    connection,
                    listener_id,
                    Instant::now() + PENDING_CONNECT_DISCARD_LIFETIME,
                ) {
                    self.sockets
                        .get_mut(&id)
                        .ok_or(PlatformConnectError::PeerIndeterminate(
                            BrokerError::Internal,
                        ))?
                        .tcp_state_mut()
                        .map_err(PlatformConnectError::PeerIndeterminate)?
                        .untracked_guest_listener_id = None;
                    return Err(PlatformConnectError::PeerIndeterminate(
                        BrokerError::ResourceExhausted,
                    ));
                }
                self.insert_pending_guest_connection(
                    session_id,
                    connection,
                    local_guest_address,
                    listener_id,
                )
                .map_err(PlatformConnectError::PeerIndeterminate)?;
                let socket =
                    self.sockets
                        .get_mut(&id)
                        .ok_or(PlatformConnectError::PeerIndeterminate(
                            BrokerError::Internal,
                        ))?;
                let tcp = socket
                    .tcp_state_mut()
                    .map_err(PlatformConnectError::PeerIndeterminate)?;
                tcp.host_connection = Some(connection);
                tcp.untracked_guest_listener_id = None;
            }
        }
        if let Err(error) = update_snapshot(
            self.sockets
                .get(&id)
                .ok_or(PlatformConnectError::PeerIndeterminate(
                    BrokerError::Internal,
                ))?,
            Some(status),
            readiness,
        ) {
            if let Some(connection) = self
                .sockets
                .get(&id)
                .and_then(|socket| socket.tcp_state().ok().and_then(|tcp| tcp.host_connection))
            {
                self.discard_pending_guest_connection(connection, session_id);
            }
            return Err(PlatformConnectError::PeerIndeterminate(error));
        }
        Ok(status)
    }

    fn send_to_socket(
        &mut self,
        id: u64,
        data: &[u8],
        destination: Option<SocketAddrV4>,
    ) -> BrokerResult<SocketOutcome<usize>> {
        let (peer, authorize_external_reply) = {
            let socket = self.sockets.get(&id).ok_or(BrokerError::Internal)?;
            if socket.kind() != SocketKind::Udp || data.len() > MAX_UDP_DATAGRAM_SIZE as usize {
                return Ok(SocketOutcome::Failed(SocketError::InvalidArgument));
            }
            if socket.write_shutdown {
                return Ok(SocketOutcome::Failed(SocketError::Other));
            }
            let udp = socket.udp_state()?;
            match destination {
                Some(address) => match self.resolve_udp_destination(address) {
                    SocketOutcome::Completed(peer) => (peer, udp.peer.is_none()),
                    SocketOutcome::Failed(error) => return Ok(SocketOutcome::Failed(error)),
                },
                None => match udp.peer {
                    Some(peer) => (peer, false),
                    None => return Ok(SocketOutcome::Failed(SocketError::NotConnected)),
                },
            }
        };
        match peer {
            ReactorUdpPeer::Guest {
                socket_generation,
                guest_address,
            } => {
                if self
                    .udp
                    .binding_for_socket(socket_generation)
                    .is_none_or(|binding| binding.internal_address != guest_address)
                {
                    return Ok(SocketOutcome::Failed(SocketError::ConnectionRefused));
                }
                self.enqueue_guest_datagram(id, socket_generation, data)
            }
            ReactorUdpPeer::External(address) => {
                let external_peer_added = if authorize_external_reply {
                    self.reserve_udp_external_peer(id, address)?
                } else {
                    false
                };
                if self
                    .sockets
                    .get(&id)
                    .ok_or(BrokerError::Internal)?
                    .udp_state()?
                    .external_endpoint
                    .is_none()
                {
                    let endpoint = match self.stage_udp_endpoint(id, address, None) {
                        Ok(SocketOutcome::Completed(endpoint)) => endpoint,
                        Ok(SocketOutcome::Failed(error)) => {
                            if external_peer_added {
                                self.remove_udp_external_peer(id, address);
                            }
                            return Ok(SocketOutcome::Failed(error));
                        }
                        Err(error) => {
                            if external_peer_added {
                                self.remove_udp_external_peer(id, address);
                            }
                            return Err(error);
                        }
                    };
                    self.replace_udp_endpoint(id, Some(endpoint));
                }
                let outcome = self.send_external_udp(id, data, address);
                if !matches!(outcome, Ok(SocketOutcome::Completed(_))) && external_peer_added {
                    self.remove_udp_external_peer(id, address);
                }
                outcome
            }
        }
    }

    fn shutdown_socket(
        &mut self,
        socket_id: u64,
        mode: ShutdownMode,
    ) -> BrokerResult<SocketOutcome<()>> {
        let kind = self
            .sockets
            .get(&socket_id)
            .map(SocketEntry::kind)
            .ok_or(BrokerError::Internal)?;
        if kind == SocketKind::Tcp {
            return shutdown_tcp_socket(
                self.sockets
                    .get_mut(&socket_id)
                    .ok_or(BrokerError::Internal)?,
                mode,
            );
        }
        let (shut_read, shut_write) = match mode {
            ShutdownMode::Read => (true, false),
            ShutdownMode::Write => (false, true),
            ShutdownMode::Both => (true, true),
            ShutdownMode::Abort | ShutdownMode::StopListening => {
                return Ok(SocketOutcome::Failed(SocketError::InvalidArgument));
            }
            _ => return Err(BrokerError::UnsupportedOperation),
        };
        if shut_read {
            self.clear_udp_receive_queue(socket_id)?;
        }
        {
            let socket = self
                .sockets
                .get_mut(&socket_id)
                .ok_or(BrokerError::Internal)?;
            socket.read_shutdown |= shut_read;
            socket.write_shutdown |= shut_write;
            if shut_read {
                let udp = socket.udp_state_mut()?;
                if udp.peeked_origin == Some(UdpReceiveOrigin::Native) {
                    udp.peeked_origin = None;
                }
                if let Some(endpoint) = udp.external_endpoint.as_mut() {
                    endpoint.readable = false;
                }
            }
        }
        if shut_read {
            self.rearm_udp_endpoint_if_needed(socket_id)?;
        }
        self.publish_udp_readiness(socket_id)?;
        Ok(SocketOutcome::Completed(()))
    }

    fn status_socket(&mut self, socket_id: u64) -> BrokerResult<SocketStatusResponse> {
        let kind = self
            .sockets
            .get(&socket_id)
            .map(SocketEntry::kind)
            .ok_or(BrokerError::Internal)?;
        let response = status_socket(
            self.sockets
                .get_mut(&socket_id)
                .ok_or(BrokerError::Internal)?,
        );
        let response = match response {
            Ok(response) => response,
            Err(error) if kind == SocketKind::Udp => {
                self.rearm_udp_endpoint_if_needed(socket_id)?;
                return Err(error);
            }
            Err(error) => return Err(error),
        };
        if kind == SocketKind::Udp {
            let readiness = match self.udp_readiness(socket_id) {
                Ok(readiness) => readiness,
                Err(error) => {
                    self.rearm_udp_endpoint_if_needed(socket_id)?;
                    return Err(error);
                }
            };
            let publication = update_snapshot(
                self.sockets
                    .get_mut(&socket_id)
                    .ok_or(BrokerError::Internal)?,
                None,
                readiness,
            );
            self.rearm_udp_endpoint_if_needed(socket_id)?;
            // The synchronous response carries the consumed UDP error and the
            // cached snapshot is already authoritative.
            let _ = publication;
        }
        Ok(response)
    }

    fn receive_from_socket(
        &mut self,
        id: u64,
        length: usize,
        flags: ReceiveFromFlags,
    ) -> BrokerResult<ReactorReceiveFromOutcome> {
        if self
            .sockets
            .get(&id)
            .ok_or(BrokerError::Internal)?
            .read_shutdown
        {
            return Ok(ReactorReceiveFromOutcome::Failed(SocketError::NotConnected));
        }

        let pinned = self
            .sockets
            .get(&id)
            .ok_or(BrokerError::Internal)?
            .udp_state()?
            .peeked_origin;
        let next = self
            .sockets
            .get(&id)
            .ok_or(BrokerError::Internal)?
            .udp_state()?
            .next_receive_origin;
        let first = pinned.unwrap_or(next);
        let second = match first {
            UdpReceiveOrigin::Guest => UdpReceiveOrigin::Native,
            UdpReceiveOrigin::Native => UdpReceiveOrigin::Guest,
        };
        for origin in [first, second] {
            let outcome = match origin {
                UdpReceiveOrigin::Guest => self.receive_guest_udp(id, length, flags)?,
                UdpReceiveOrigin::Native => self.receive_native_udp(id, length, flags)?,
            };
            if let Some(outcome) = outcome {
                return Ok(outcome);
            }
            if pinned.is_some() {
                break;
            }
        }
        self.publish_udp_readiness(id)?;
        Err(BrokerError::WouldBlock)
    }

    fn remove_socket(&mut self, id: u64) {
        let Some((kind, session_id)) = self
            .sockets
            .get(&id)
            .map(|socket| (socket.kind(), socket.session_id))
        else {
            return;
        };
        if kind == SocketKind::Udp {
            let _ = self.clear_udp_receive_queue(id);
            self.replace_udp_endpoint(id, None);
            if let Some(binding) = self.udp.binding_for_socket(id) {
                self.udp.remove_binding(binding.guest_address.port(), id);
            }
            let external_peer_count = self
                .sockets
                .get(&id)
                .and_then(|socket| socket.udp_state().ok())
                .map_or(0, |udp| udp.external_peers.len());
            self.udp.external_peer_count = self
                .udp
                .external_peer_count
                .checked_sub(external_peer_count)
                .expect("reactor UDP external peer count underflow");
            let session = self
                .sessions
                .get_mut(&session_id)
                .expect("UDP socket session state missing");
            session.udp_external_peer_count = session
                .udp_external_peer_count
                .checked_sub(external_peer_count)
                .expect("session UDP external peer count underflow");
            self.sockets.remove(&id);
            session.live_socket_count = session
                .live_socket_count
                .checked_sub(1)
                .expect("session socket count underflow");
            self.sessions
                .retain(|_, session| retain_session_state(session));
            return;
        }

        let socket = self
            .sockets
            .remove(&id)
            .expect("checked TCP socket missing");
        let SocketEntry {
            transport,
            connection_status,
            guest_local_address,
            ..
        } = socket;
        let SocketTransportState::Tcp(TcpSocketState {
            socket,
            untracked_guest_listener_id,
            was_listener,
            abortive_close,
            host_connection,
            ..
        }) = transport
        else {
            unreachable!("checked TCP socket changed transport");
        };
        let guest_connector = untracked_guest_listener_id.is_some()
            || host_connection.is_some_and(|connection| {
                self.tcp
                    .pending_guest_connections
                    .get(&connection)
                    .is_some_and(|pending| pending.session_id == session_id)
            });
        if was_listener {
            self.remove_pending_guest_connections_for_listener(id);
        }
        if let Some(address) = guest_local_address {
            self.tcp.remove_binding(address.port(), id);
        }

        let mut socket = Some(socket);
        if !abortive_close
            && guest_connector
            && matches!(
                connection_status,
                SocketConnectionStatus::Connecting | SocketConnectionStatus::Connected
            )
        {
            let _ = shutdown(
                socket.as_ref().expect("connector descriptor missing"),
                LinuxShutdown::Both,
            );
        }
        if let Some(connection) = host_connection
            && let Some(pending) = self.tcp.pending_guest_connections.get_mut(&connection)
            && pending.session_id == session_id
        {
            let retain = !abortive_close
                && connection_status == SocketConnectionStatus::Connected
                && !pending.discard_on_accept;
            // A close that wins before native completion is observed is
            // deliberately non-deliverable; teardown never re-infers it.
            pending.discard_on_accept = !retain;
            pending.discard_deadline =
                (!retain).then(|| Instant::now() + PENDING_CONNECT_DISCARD_LIFETIME);
            if retain {
                pending.retained_connector = socket.take();
                self.retained_connector_count = self
                    .retained_connector_count
                    .checked_add(1)
                    .expect("reactor retained connector count overflow");
                let session = self
                    .sessions
                    .get_mut(&session_id)
                    .expect("socket session state missing");
                session.retained_connector_count = session
                    .retained_connector_count
                    .checked_add(1)
                    .expect("session retained connector count overflow");
            }
        }
        if let Some(listener_id) = untracked_guest_listener_id
            && self
                .tcp
                .bindings
                .values()
                .any(|binding| binding.socket_id == listener_id)
        {
            // No tuple exists to key a discard marker. Block later routes for
            // the same bounded maturation period, then probe the listener just
            // like an expiring keyed marker.
            self.tcp.defer_untracked_connection(
                listener_id,
                Instant::now() + PENDING_CONNECT_DISCARD_LIFETIME,
            );
        }
        drop(socket);
        if let Some(session) = self.sessions.get_mut(&session_id) {
            session.live_socket_count = session
                .live_socket_count
                .checked_sub(1)
                .expect("session socket count underflow");
        }
        if self
            .sessions
            .get(&session_id)
            .is_some_and(|session| session.closing)
        {
            self.retire_session_connectors(session_id);
        }
        self.sessions
            .retain(|_, session| retain_session_state(session));
    }

    fn run(&mut self) -> core::result::Result<(), ReactorFailure> {
        loop {
            let mut events = core::mem::take(&mut self.events);
            events.clear();
            let now = Instant::now();
            let timeout = self.next_cleanup_deadline().map(|deadline| {
                let duration = deadline.saturating_duration_since(now);
                Timespec {
                    tv_sec: i64::try_from(duration.as_secs()).unwrap_or(i64::MAX),
                    tv_nsec: i64::from(duration.subsec_nanos()),
                }
            });
            match epoll::wait(&self.epoll, spare_capacity(&mut events), timeout.as_ref()) {
                Ok(_) => {}
                Err(Errno::INTR) => {
                    self.events = events;
                    continue;
                }
                Err(error) => return Err(ReactorFailure::Io(error)),
            }
            self.expire_deadlined_state(Instant::now());

            // Apply readiness observed by this wait before commands. A command
            // that then reaches EAGAIN records the newer authoritative state.
            let mut wake = false;
            for event in events.drain(..) {
                let id = event.data.u64();
                if id == WAKE_TOKEN {
                    wake = true;
                } else if id & UDP_EVENT_TOKEN_FLAG != 0 {
                    self.handle_udp_endpoint_event(id, event.flags)
                        .map_err(ReactorFailure::Broker)?;
                } else {
                    let failed_connection = if let Some(socket) = self.sockets.get_mut(&id) {
                        if handle_socket_event(socket, event.flags)
                            .map_err(ReactorFailure::Broker)?
                        {
                            socket
                                .tcp_state()
                                .ok()
                                .and_then(|tcp| tcp.host_connection)
                                .map(|connection| (connection, socket.session_id))
                        } else {
                            None
                        }
                    } else {
                        None
                    };
                    if let Some((connection, session_id)) = failed_connection {
                        self.discard_pending_guest_connection(connection, session_id);
                    }
                }
            }
            self.events = events;
            if wake {
                self.drain_wake()?;
                if self.process_commands() {
                    return Ok(());
                }
            }
        }
    }

    fn drain_wake(&self) -> core::result::Result<(), ReactorFailure> {
        let mut value = [0_u8; size_of::<u64>()];
        loop {
            match read(self.wake.as_ref(), &mut value) {
                Ok(length) if length == value.len() => return Ok(()),
                Ok(_) => return Err(ReactorFailure::Io(Errno::IO)),
                Err(Errno::INTR) => {}
                Err(Errno::AGAIN) => return Ok(()),
                Err(error) => return Err(ReactorFailure::Io(error)),
            }
        }
    }

    fn process_commands(&mut self) -> bool {
        for _ in 0..MAX_QUEUED_SOCKET_COMMANDS {
            let command = match self.commands.try_recv() {
                Ok(command) => command,
                Err(TryRecvError::Empty) => return false,
                Err(TryRecvError::Disconnected) => return true,
            };
            match command {
                ReactorCommand::Create {
                    id,
                    session_id,
                    request,
                    readiness,
                    snapshot,
                    lifecycle,
                    response,
                } => {
                    let outcome = self
                        .create_socket(id, session_id, request, readiness, snapshot, &lifecycle);
                    let created = outcome.is_ok();
                    if response.send(outcome).is_err() && created {
                        self.remove_socket(id);
                        lifecycle.reactor_removed();
                    }
                }
                ReactorCommand::Connect {
                    id,
                    address,
                    response,
                } => {
                    let outcome = self.connect_socket(id, address);
                    let _ = response.send(outcome);
                }
                ReactorCommand::Bind {
                    id,
                    address,
                    response,
                } => {
                    let outcome = self.bind_socket(id, address);
                    if response.send(outcome).is_err() {
                        self.remove_socket(id);
                    }
                }
                ReactorCommand::Listen {
                    id,
                    backlog,
                    response,
                } => {
                    let outcome = self.listen_socket(id, backlog);
                    if response.send(outcome).is_err() {
                        self.remove_socket(id);
                    }
                }
                ReactorCommand::Accept {
                    listener_id,
                    accepted_id,
                    readiness,
                    snapshot,
                    lifecycle,
                    response,
                } => {
                    let outcome = self.accept_socket(
                        listener_id,
                        accepted_id,
                        readiness,
                        snapshot,
                        &lifecycle,
                    );
                    let accepted = matches!(
                        &outcome,
                        Ok(SocketOutcome::Completed(AcceptedEndpoints { .. }))
                    );
                    if response.send(outcome).is_err() && accepted {
                        self.remove_socket(accepted_id);
                        lifecycle.reactor_removed();
                    }
                }
                ReactorCommand::Send { id, data, response } => {
                    let was_connecting = self.sockets.get(&id).is_some_and(|socket| {
                        socket.connection_status == SocketConnectionStatus::Connecting
                    });
                    let outcome = self
                        .sockets
                        .get_mut(&id)
                        .ok_or(BrokerError::Internal)
                        .and_then(|socket| send_socket(socket, &data));
                    self.discard_failed_connect_after_command(id, was_connecting);
                    let _ = response.send(outcome);
                }
                ReactorCommand::SendTo {
                    id,
                    data,
                    destination,
                    response,
                } => {
                    let outcome = self.send_to_socket(id, &data, destination);
                    let _ = response.send(outcome);
                }
                ReactorCommand::Receive {
                    id,
                    length,
                    flags,
                    peek_offset,
                    peek_length,
                    response,
                } => {
                    let was_connecting = self.sockets.get(&id).is_some_and(|socket| {
                        socket.connection_status == SocketConnectionStatus::Connecting
                    });
                    let outcome = match self.sockets.get_mut(&id) {
                        Some(socket) => receive_socket(
                            socket,
                            &mut self.peek_cache,
                            id,
                            length,
                            flags,
                            peek_offset,
                            peek_length,
                        ),
                        None => Err(BrokerError::Internal),
                    };
                    self.discard_failed_connect_after_command(id, was_connecting);
                    let _ = response.send(outcome);
                }
                ReactorCommand::ReceiveFrom {
                    id,
                    length,
                    flags,
                    response,
                } => {
                    let outcome = self.receive_from_socket(id, length, flags);
                    let _ = response.send(outcome);
                }
                ReactorCommand::Shutdown { id, mode, response } => {
                    if self
                        .peek_cache
                        .as_ref()
                        .is_some_and(|cache| cache.socket_id == id)
                    {
                        self.peek_cache = None;
                    }
                    let was_listening = mode == ShutdownMode::StopListening
                        && self.sockets.get(&id).is_some_and(|socket| {
                            socket.tcp_state().is_ok_and(|tcp| tcp.listening)
                        });
                    let was_connecting = self.sockets.get(&id).is_some_and(|socket| {
                        socket.connection_status == SocketConnectionStatus::Connecting
                    });
                    let mut outcome = self.shutdown_socket(id, mode);
                    let stopped_listening = was_listening
                        && self.sockets.get(&id).is_some_and(|socket| {
                            socket.tcp_state().is_ok_and(|tcp| !tcp.listening)
                        });
                    if stopped_listening {
                        self.remove_pending_guest_connections_for_listener(id);
                        let update = self
                            .sockets
                            .get(&id)
                            .and_then(|socket| socket.guest_local_address)
                            .ok_or(BrokerError::Internal)
                            .and_then(|address| self.tcp.stop_listening(address.port(), id));
                        if let Err(error) = update {
                            outcome = Err(error);
                        }
                    }
                    self.discard_failed_connect_after_command(id, was_connecting);
                    let _ = response.send(outcome);
                }
                ReactorCommand::SetTcpOption {
                    id,
                    value,
                    response,
                } => {
                    let outcome = self
                        .sockets
                        .get_mut(&id)
                        .ok_or(BrokerError::Internal)
                        .and_then(|socket| set_tcp_option(socket, value));
                    let _ = response.send(outcome);
                }
                ReactorCommand::GetTcpOption { id, name, response } => {
                    let outcome = self
                        .sockets
                        .get(&id)
                        .ok_or(BrokerError::Internal)
                        .and_then(|socket| get_tcp_option(socket, name));
                    let _ = response.send(outcome);
                }
                ReactorCommand::Status { id, response } => {
                    let outcome = self.status_socket(id);
                    let _ = response.send(outcome);
                }
                ReactorCommand::Close { id, response } => {
                    if self
                        .peek_cache
                        .as_ref()
                        .is_some_and(|cache| cache.socket_id == id)
                    {
                        self.peek_cache = None;
                    }
                    self.remove_socket(id);
                    let _ = response.send(());
                }
                ReactorCommand::CloseSession {
                    session_id,
                    response,
                } => {
                    if let Some(session) = self.sessions.get_mut(&session_id) {
                        session.closing = true;
                    }
                    while let Some(id) = self
                        .sockets
                        .iter()
                        .find_map(|(id, socket)| (socket.session_id == session_id).then_some(*id))
                    {
                        self.remove_socket(id);
                    }
                    self.retire_session_connectors(session_id);
                    self.sessions
                        .retain(|_, session| retain_session_state(session));
                    let _ = response.send(());
                }
                #[cfg(test)]
                ReactorCommand::HostAddress {
                    guest_port,
                    response,
                } => {
                    let host_address = self
                        .tcp
                        .bindings
                        .get(&guest_port)
                        .and_then(|binding| binding.host_address)
                        .or_else(|| {
                            self.udp
                                .bindings
                                .get(&guest_port)
                                .and_then(|binding| self.sockets.get(&binding.socket_id))
                                .and_then(|socket| socket.udp_state().ok())
                                .and_then(|udp| udp.external_endpoint.as_ref())
                                .map(|endpoint| endpoint.host_address)
                        });
                    let _ = response.send(host_address);
                }
                #[cfg(test)]
                ReactorCommand::PendingGuestConnectionCount { response } => {
                    let _ = response.send(self.tcp.pending_guest_connections.len());
                }
                #[cfg(test)]
                ReactorCommand::RetainedConnectorCount { response } => {
                    let _ = response.send(self.retained_connector_count);
                }
                #[cfg(test)]
                ReactorCommand::UdpQueuedDatagramCount { response } => {
                    let _ = response.send(self.udp.queued_datagrams);
                }
                #[cfg(test)]
                ReactorCommand::UdpNativeEndpointCount { response } => {
                    let _ = response.send(self.udp.native_endpoints.len());
                }
                #[cfg(test)]
                ReactorCommand::UdpNativeReceiveBufferSize {
                    guest_port,
                    response,
                } => {
                    let size = self
                        .udp
                        .bindings
                        .get(&guest_port)
                        .and_then(|binding| self.sockets.get(&binding.socket_id))
                        .and_then(|socket| socket.udp_state().ok())
                        .and_then(|udp| udp.external_endpoint.as_ref())
                        .map(|endpoint| {
                            sockopt::socket_recv_buffer_size(&endpoint.socket)
                                .map_err(broker_error_from_errno)
                        })
                        .transpose();
                    let _ = response.send(size);
                }
                #[cfg(test)]
                ReactorCommand::UdpExternalPeerCount { response } => {
                    let _ = response.send(self.udp.external_peer_count);
                }
                #[cfg(test)]
                ReactorCommand::ExhaustUdpEndpointGeneration { response } => {
                    self.udp.next_endpoint_generation = u64::MAX;
                    let _ = response.send(());
                }
                #[cfg(test)]
                ReactorCommand::ExpireDeadlinedState { now, response } => {
                    self.expire_deadlined_state(now);
                    let _ = response.send(());
                }
                #[cfg(test)]
                ReactorCommand::DeferUntrackedGuestConnection {
                    guest_port,
                    response,
                } => {
                    let listener_id = self
                        .tcp
                        .bindings
                        .get(&guest_port)
                        .expect("test guest listener binding missing")
                        .socket_id;
                    self.tcp.defer_untracked_connection(
                        listener_id,
                        Instant::now() + PENDING_CONNECT_DISCARD_LIFETIME,
                    );
                    let _ = response.send(());
                }
                ReactorCommand::Stop { response } => {
                    while let Some(id) = self.sockets.keys().next().copied() {
                        self.remove_socket(id);
                    }
                    self.tcp.bindings.clear();
                    self.tcp.pending_guest_connections.clear();
                    self.udp.clear_live_state();
                    self.sessions.clear();
                    self.retained_connector_count = 0;
                    let _ = response.send(());
                    return true;
                }
            }
        }
        false
    }

    fn create_socket(
        &mut self,
        id: u64,
        session_id: SessionId,
        request: CreateSocketRequest,
        readiness: ReadinessRegistration,
        snapshot: Arc<Mutex<SocketSnapshot>>,
        lifecycle: &SocketLifecycle,
    ) -> BrokerResult<()> {
        if self
            .sockets
            .len()
            .checked_add(self.retained_connector_count)
            .is_none_or(|count| count >= self.max_sockets)
        {
            return Err(BrokerError::ResourceExhausted);
        }
        let kind = socket_kind(request).ok_or(BrokerError::Internal)?;
        if self.sockets.contains_key(&id) {
            return Err(BrokerError::Internal);
        }
        if !self.sessions.contains_key(&session_id) {
            self.sessions
                .try_reserve(1)
                .map_err(|_| BrokerError::OutOfMemory)?;
        }
        let session = self.sessions.entry(session_id).or_default();
        if session.closing {
            return Err(BrokerError::UnknownObject);
        }
        if session
            .live_socket_count
            .checked_add(session.retained_connector_count)
            .is_none_or(|count| count >= self.max_sockets_per_session)
        {
            return Err(BrokerError::ResourceExhausted);
        }
        let (transport, initial_readiness) = match kind {
            SocketKind::Tcp => {
                let socket = socket_with(
                    LinuxAddressFamily::INET,
                    LinuxSocketType::STREAM,
                    LinuxSocketFlags::CLOEXEC | LinuxSocketFlags::NONBLOCK,
                    Some(ipproto::TCP),
                )
                .map_err(broker_error_from_errno)?;
                epoll::add(
                    &self.epoll,
                    &socket,
                    epoll::EventData::new_u64(id),
                    idle_epoll_events(),
                )
                .map_err(broker_error_from_errno)?;
                (
                    SocketTransportState::Tcp(TcpSocketState {
                        socket,
                        untracked_guest_listener_id: None,
                        peek_waitall_threshold: None,
                        listening: false,
                        was_listener: false,
                        abortive_close: false,
                        host_connection: None,
                        no_delay: false,
                        keep_alive: false,
                    }),
                    ReadinessFlags::default(),
                )
            }
            SocketKind::Udp => (
                SocketTransportState::Udp(UdpSocketState::default()),
                ReadinessFlags::WRITE,
            ),
        };
        if initial_readiness != ReadinessFlags::default() {
            snapshot
                .lock()
                .expect("Linux socket snapshot mutex poisoned")
                .readiness = initial_readiness;
            readiness.publish(initial_readiness)?;
        }
        if !lifecycle.activate() {
            return Err(BrokerError::Internal);
        }
        self.sockets.insert(
            id,
            SocketEntry {
                session_id,
                transport,
                readiness,
                snapshot,
                connection_status: SocketConnectionStatus::Unconnected,
                read_shutdown: false,
                write_shutdown: false,
                guest_local_address: None,
            },
        );
        session.live_socket_count = session
            .live_socket_count
            .checked_add(1)
            .ok_or(BrokerError::ResourceExhausted)?;
        Ok(())
    }

    fn accept_socket(
        &mut self,
        listener_id: u64,
        accepted_id: u64,
        readiness: ReadinessRegistration,
        snapshot: Arc<Mutex<SocketSnapshot>>,
        lifecycle: &SocketLifecycle,
    ) -> BrokerResult<SocketOutcome<AcceptedEndpoints>> {
        if self.sockets.contains_key(&accepted_id) {
            return Err(BrokerError::Internal);
        }
        let (
            listener_session_id,
            listener_guest_address,
            listener_tcp_no_delay,
            listener_tcp_keep_alive,
        ) = {
            let listener = self
                .sockets
                .get(&listener_id)
                .ok_or(BrokerError::Internal)?;
            if listener.kind() != SocketKind::Tcp || !listener.tcp_state()?.listening {
                return Ok(SocketOutcome::Failed(SocketError::NotConnected));
            }
            (
                listener.session_id,
                listener.guest_local_address.ok_or(BrokerError::Internal)?,
                listener.tcp_state()?.no_delay,
                listener.tcp_state()?.keep_alive,
            )
        };
        self.expire_deadlined_state(Instant::now());
        if !self.has_accept_capacity(listener_id, listener_session_id)? {
            return Err(BrokerError::ResourceExhausted);
        }
        let mut unmatched_accept_count = 0;
        let (socket, remote_address) = loop {
            let (socket, remote_address) = loop {
                let listener = self
                    .sockets
                    .get_mut(&listener_id)
                    .ok_or(BrokerError::Internal)?;
                match acceptfrom_with(
                    &listener.tcp_state()?.socket,
                    LinuxSocketFlags::CLOEXEC | LinuxSocketFlags::NONBLOCK,
                ) {
                    Ok((socket, address)) => break (socket, address),
                    Err(Errno::INTR) => {}
                    Err(Errno::AGAIN) => {
                        clear_readiness(listener, ReadinessFlags::READ)?;
                        self.tcp.finish_listener_backlog_drain(listener_id)?;
                        return Err(BrokerError::WouldBlock);
                    }
                    Err(error) => {
                        return Ok(SocketOutcome::Failed(socket_operation_error_from_errno(
                            error,
                        )?));
                    }
                }
            };
            let remote_address =
                SocketAddrV4::try_from(remote_address.ok_or(BrokerError::Internal)?)
                    .map_err(|_| BrokerError::Internal)?;
            let host_local_address = local_socket_address(&socket)?;
            if let Some(guest_address) = self.take_pending_guest_connection_for_accept(
                listener_id,
                remote_address,
                host_local_address,
            ) {
                break (socket, guest_address);
            }
            drop(socket);
            unmatched_accept_count += 1;
            if unmatched_accept_count >= MAX_UNMATCHED_ACCEPTS_PER_COMMAND {
                let listener = self
                    .sockets
                    .get(&listener_id)
                    .ok_or(BrokerError::Internal)?;
                let readiness = listener
                    .snapshot
                    .lock()
                    .expect("Linux socket snapshot mutex poisoned")
                    .readiness;
                // Edge-triggered epoll will not report connections that remain
                // queued, so wake a blocking accept waiter to continue draining.
                listener.readiness.republish(readiness)?;
                return Err(BrokerError::WouldBlock);
            }
        };
        let listener_session = self
            .sessions
            .get(&listener_session_id)
            .ok_or(BrokerError::Internal)?;
        if self
            .sockets
            .len()
            .checked_add(self.retained_connector_count)
            .is_none_or(|count| count >= self.max_sockets)
            || listener_session
                .live_socket_count
                .checked_add(listener_session.retained_connector_count)
                .is_none_or(|count| count >= self.max_sockets_per_session)
        {
            return Err(BrokerError::ResourceExhausted);
        }
        apply_tcp_options(&socket, listener_tcp_no_delay, listener_tcp_keep_alive)?;
        let backlog_empty = {
            let listener = self
                .sockets
                .get_mut(&listener_id)
                .ok_or(BrokerError::Internal)?;
            let no_wait = Timespec {
                tv_sec: 0,
                tv_nsec: 0,
            };
            loop {
                let mut poll_fd = [PollFd::new(&listener.tcp_state()?.socket, PollFlags::IN)];
                match poll(&mut poll_fd, Some(&no_wait)) {
                    Ok(_) if poll_fd[0].revents().contains(PollFlags::IN) => break false,
                    Ok(_) => {
                        clear_readiness(listener, ReadinessFlags::READ)?;
                        break true;
                    }
                    Err(Errno::INTR) => {}
                    Err(error) => return Err(broker_error_from_errno(error)),
                }
            }
        };
        if backlog_empty {
            self.tcp.finish_listener_backlog_drain(listener_id)?;
        }
        epoll::add(
            &self.epoll,
            &socket,
            epoll::EventData::new_u64(accepted_id),
            active_epoll_events(),
        )
        .map_err(broker_error_from_errno)?;
        {
            let mut snapshot = snapshot
                .lock()
                .expect("Linux socket snapshot mutex poisoned");
            snapshot.status = SocketConnectionStatus::Connected;
            snapshot.local_address = Some(listener_guest_address);
            snapshot.readiness = ReadinessFlags::WRITE;
        }
        readiness.publish(ReadinessFlags::WRITE)?;
        if !lifecycle.activate() {
            return Err(BrokerError::Internal);
        }
        self.sockets.insert(
            accepted_id,
            SocketEntry {
                session_id: listener_session_id,
                transport: SocketTransportState::Tcp(TcpSocketState {
                    socket,
                    untracked_guest_listener_id: None,
                    peek_waitall_threshold: None,
                    listening: false,
                    was_listener: false,
                    abortive_close: false,
                    host_connection: None,
                    no_delay: listener_tcp_no_delay,
                    keep_alive: listener_tcp_keep_alive,
                }),
                readiness,
                snapshot,
                connection_status: SocketConnectionStatus::Connected,
                read_shutdown: false,
                write_shutdown: false,
                guest_local_address: Some(listener_guest_address),
            },
        );
        let session = self
            .sessions
            .get_mut(&listener_session_id)
            .ok_or(BrokerError::Internal)?;
        session.live_socket_count = session
            .live_socket_count
            .checked_add(1)
            .ok_or(BrokerError::ResourceExhausted)?;
        Ok(SocketOutcome::Completed(AcceptedEndpoints {
            remote_address,
        }))
    }

    fn fail_all_sockets(&mut self) {
        for socket in self.sockets.values_mut() {
            socket.connection_status = SocketConnectionStatus::Failed(SocketError::Other);
            let mut snapshot = socket
                .snapshot
                .lock()
                .expect("Linux socket snapshot mutex poisoned");
            snapshot.status = SocketConnectionStatus::Failed(SocketError::Other);
            snapshot.readiness = ReadinessFlags::ERROR;
            drop(snapshot);
            // The readiness path may itself be why the reactor is failing. The
            // cached terminal snapshot remains authoritative if publication is
            // no longer available.
            let _ = socket.readiness.publish(ReadinessFlags::ERROR);
        }
        self.sockets.clear();
        self.tcp.bindings.clear();
        self.tcp.pending_guest_connections.clear();
        self.udp.clear_live_state();
        self.sessions.clear();
        self.retained_connector_count = 0;
    }
}

fn connect_tcp_socket(
    epoll_fd: &OwnedFd,
    id: u64,
    socket: &mut SocketEntry,
    address: SocketAddrV4,
    guest_listener_id: Option<u64>,
) -> core::result::Result<(SocketConnectionStatus, ReadinessFlags), PlatformConnectError> {
    if let Err(error) = epoll::modify(
        epoll_fd,
        &socket
            .tcp_state()
            .map_err(PlatformConnectError::PeerUnchanged)?
            .socket,
        epoll::EventData::new_u64(id),
        active_epoll_events(),
    ) {
        return Err(PlatformConnectError::PeerUnchanged(
            broker_error_from_errno(error),
        ));
    }
    if socket.connection_status != SocketConnectionStatus::Unconnected {
        return Err(PlatformConnectError::PeerUnchanged(BrokerError::Internal));
    }
    // Record the first half of the native transition before connect(2). Any
    // later failure can then be settled or conservatively retired without
    // reconstructing whether a SYN may have reached a guest listener.
    socket.connection_status = SocketConnectionStatus::Connecting;
    socket
        .tcp_state_mut()
        .map_err(PlatformConnectError::PeerUnchanged)?
        .untracked_guest_listener_id = guest_listener_id;
    let status = loop {
        match connect(
            &socket
                .tcp_state()
                .map_err(PlatformConnectError::PeerIndeterminate)?
                .socket,
            &address,
        ) {
            Ok(()) | Err(Errno::ISCONN) => break SocketConnectionStatus::Connected,
            Err(Errno::INTR) => {}
            Err(Errno::INPROGRESS | Errno::ALREADY) => {
                break SocketConnectionStatus::Connecting;
            }
            Err(error) => {
                let error = match socket_operation_error_from_errno(error) {
                    Ok(error) => error,
                    Err(error) => {
                        socket.connection_status =
                            SocketConnectionStatus::Failed(SocketError::Other);
                        update_snapshot(
                            socket,
                            Some(SocketConnectionStatus::Failed(SocketError::Other)),
                            ReadinessFlags::ERROR,
                        )
                        .map_err(PlatformConnectError::PeerIndeterminate)?;
                        return Err(PlatformConnectError::PeerIndeterminate(error));
                    }
                };
                break SocketConnectionStatus::Failed(error);
            }
        }
    };
    socket.connection_status = status;
    if matches!(status, SocketConnectionStatus::Failed(_)) {
        socket
            .tcp_state_mut()
            .map_err(PlatformConnectError::PeerIndeterminate)?
            .untracked_guest_listener_id = None;
    }
    let readiness = match status {
        SocketConnectionStatus::Connected | SocketConnectionStatus::Connecting => {
            if socket.guest_local_address.is_none() {
                return Err(PlatformConnectError::PeerIndeterminate(
                    BrokerError::Internal,
                ));
            }
            if status == SocketConnectionStatus::Connected {
                ReadinessFlags::WRITE
            } else {
                ReadinessFlags::default()
            }
        }
        SocketConnectionStatus::Failed(_) => ReadinessFlags::ERROR,
        SocketConnectionStatus::Unconnected => ReadinessFlags::default(),
        _ => {
            return Err(PlatformConnectError::PeerIndeterminate(
                BrokerError::Internal,
            ));
        }
    };
    Ok((status, readiness))
}

fn bind_host_socket(
    socket: &mut SocketEntry,
    address: SocketAddrV4,
) -> BrokerResult<SocketOutcome<SocketAddrV4>> {
    loop {
        match bind(&socket.tcp_state()?.socket, &address) {
            Ok(()) => {
                let local_address = local_socket_address(&socket.tcp_state()?.socket)?;
                return Ok(SocketOutcome::Completed(local_address));
            }
            Err(Errno::INTR) => {}
            Err(error) => {
                return Ok(SocketOutcome::Failed(socket_operation_error_from_errno(
                    error,
                )?));
            }
        }
    }
}

fn listen_tcp_socket(
    epoll_fd: &OwnedFd,
    id: u64,
    socket: &mut SocketEntry,
    backlog: u32,
) -> BrokerResult<SocketOutcome<()>> {
    if socket.kind() != SocketKind::Tcp {
        return Ok(SocketOutcome::Failed(SocketError::InvalidArgument));
    }
    let backlog = i32::try_from(backlog).map_err(|_| BrokerError::UnsupportedOperation)?;
    let was_listening = socket.tcp_state()?.listening;
    if !was_listening {
        epoll::modify(
            epoll_fd,
            &socket.tcp_state()?.socket,
            epoll::EventData::new_u64(id),
            active_epoll_events(),
        )
        .map_err(broker_error_from_errno)?;
    }
    loop {
        match listen(&socket.tcp_state()?.socket, backlog) {
            Ok(()) => break,
            Err(Errno::INTR) => {}
            Err(error) => {
                if !was_listening {
                    epoll::modify(
                        epoll_fd,
                        &socket.tcp_state()?.socket,
                        epoll::EventData::new_u64(id),
                        idle_epoll_events(),
                    )
                    .map_err(broker_error_from_errno)?;
                }
                return Ok(SocketOutcome::Failed(socket_operation_error_from_errno(
                    error,
                )?));
            }
        }
    }
    let tcp = socket.tcp_state_mut()?;
    tcp.listening = true;
    tcp.was_listener = true;
    let mut snapshot = socket
        .snapshot
        .lock()
        .expect("Linux socket snapshot mutex poisoned");
    if !was_listening {
        snapshot.readiness = ReadinessFlags::default();
    }
    Ok(SocketOutcome::Completed(()))
}

fn send_socket(socket: &mut SocketEntry, data: &[u8]) -> BrokerResult<SocketOutcome<usize>> {
    if socket.kind() != SocketKind::Tcp {
        return Ok(SocketOutcome::Failed(SocketError::InvalidArgument));
    }
    if socket.write_shutdown {
        return Ok(SocketOutcome::Failed(SocketError::Other));
    }
    loop {
        match send(&socket.tcp_state()?.socket, data, LinuxSendFlags::NOSIGNAL) {
            Ok(sent) => {
                if sent != 0 {
                    confirm_tcp_connected(socket)?;
                }
                return Ok(SocketOutcome::Completed(sent));
            }
            Err(Errno::INTR) => {}
            Err(Errno::AGAIN) => {
                clear_readiness(socket, ReadinessFlags::WRITE)?;
                return Err(BrokerError::WouldBlock);
            }
            Err(error) => {
                let error = socket_operation_error_from_errno(error)?;
                fail_connect(socket, error)?;
                consume_synchronous_error(socket)?;
                return Ok(SocketOutcome::Failed(error));
            }
        }
    }
}

fn receive_socket(
    socket: &mut SocketEntry,
    peek_cache: &mut Option<PeekCache>,
    socket_id: u64,
    length: usize,
    flags: ReceiveFlags,
    peek_offset: usize,
    peek_length: usize,
) -> BrokerResult<ReactorReceiveOutcome> {
    if socket.kind() != SocketKind::Tcp {
        return Ok(ReactorReceiveOutcome::Failed(SocketError::InvalidArgument));
    }
    let peek = flags.contains(ReceiveFlags::PEEK);
    if !peek {
        if peek_offset != 0 || peek_length != 0 {
            return Err(BrokerError::UnsupportedOperation);
        }
        if peek_cache
            .as_ref()
            .is_some_and(|cache| cache.socket_id == socket_id)
        {
            *peek_cache = None;
        }
        return receive_socket_once(socket, zeroed_vec(length)?, LinuxRecvFlags::empty());
    }

    let peek_end = peek_offset
        .checked_add(length)
        .ok_or(BrokerError::UnsupportedOperation)?;
    let canonical_length = peek_length
        .checked_sub(peek_offset)
        .map(|remaining| remaining.min(MAX_SOCKET_TRANSFER_SIZE as usize));
    if !peek_offset.is_multiple_of(MAX_SOCKET_TRANSFER_SIZE as usize)
        || canonical_length != Some(length)
        || peek_length < peek_end
        || peek_length > MAX_SOCKET_PEEK_SIZE as usize
    {
        return Err(BrokerError::UnsupportedOperation);
    }
    if flags.contains(ReceiveFlags::WAITALL) {
        let snapshot = *socket
            .snapshot
            .lock()
            .expect("Linux socket snapshot mutex poisoned");
        let terminal = socket.read_shutdown
            || snapshot.readiness.contains(ReadinessFlags::HANGUP)
            || snapshot.readiness.contains(ReadinessFlags::ERROR);
        if socket.connection_status == SocketConnectionStatus::Connected
            && !terminal
            && ioctl_fionread(&socket.tcp_state()?.socket).map_err(broker_error_from_errno)?
                < peek_length.try_into().map_err(|_| BrokerError::Internal)?
        {
            let tcp = socket.tcp_state_mut()?;
            tcp.peek_waitall_threshold = Some(
                tcp.peek_waitall_threshold
                    .map_or(peek_length, |threshold| threshold.min(peek_length)),
            );
            return Err(BrokerError::WouldBlock);
        }
    }

    let refresh = peek_offset == 0
        || !peek_cache.as_ref().is_some_and(|cache| {
            cache.socket_id == socket_id && cache.requested_length == peek_length
        });
    if refresh {
        *peek_cache = None;
        let flags = if flags.contains(ReceiveFlags::WAITALL) {
            LinuxRecvFlags::PEEK | LinuxRecvFlags::WAITALL
        } else {
            LinuxRecvFlags::PEEK
        };
        match receive_socket_once(socket, zeroed_vec(peek_length)?, flags)? {
            ReactorReceiveOutcome::Received(data) => {
                *peek_cache = Some(PeekCache {
                    socket_id,
                    requested_length: peek_length,
                    data,
                });
            }
            outcome => return Ok(outcome),
        }
    }

    let cache = peek_cache.as_ref().ok_or(BrokerError::Internal)?;
    if cache.data.len() <= peek_offset {
        let readiness = socket
            .snapshot
            .lock()
            .expect("Linux socket snapshot mutex poisoned")
            .readiness;
        let terminal = socket.read_shutdown
            || readiness.contains(ReadinessFlags::HANGUP)
            || readiness.contains(ReadinessFlags::ERROR);
        *peek_cache = None;
        return if terminal {
            Ok(ReactorReceiveOutcome::EndOfStream)
        } else {
            Err(BrokerError::WouldBlock)
        };
    }
    let end = peek_end.min(cache.data.len());
    let mut data = Vec::new();
    data.try_reserve_exact(end - peek_offset)
        .map_err(|_| BrokerError::OutOfMemory)?;
    data.extend_from_slice(&cache.data[peek_offset..end]);
    if end < peek_end || end == peek_length {
        *peek_cache = None;
    }
    Ok(ReactorReceiveOutcome::Received(data))
}

fn zeroed_vec(length: usize) -> BrokerResult<Vec<u8>> {
    let mut data = Vec::new();
    data.try_reserve_exact(length)
        .map_err(|_| BrokerError::OutOfMemory)?;
    data.resize(length, 0);
    Ok(data)
}

fn receive_socket_once(
    socket: &mut SocketEntry,
    mut data: Vec<u8>,
    flags: LinuxRecvFlags,
) -> BrokerResult<ReactorReceiveOutcome> {
    loop {
        match recv(&socket.tcp_state()?.socket, data.as_mut_slice(), flags) {
            Ok((_buffer, 0)) => {
                confirm_tcp_connected(socket)?;
                let readiness = if socket.read_shutdown {
                    ReadinessFlags::READ
                } else {
                    ReadinessFlags::READ | ReadinessFlags::HANGUP
                };
                add_readiness(socket, readiness)?;
                return Ok(ReactorReceiveOutcome::EndOfStream);
            }
            Ok((_buffer, received)) => {
                confirm_tcp_connected(socket)?;
                data.truncate(received);
                let terminal_readable = socket.read_shutdown
                    || socket
                        .snapshot
                        .lock()
                        .expect("Linux socket snapshot mutex poisoned")
                        .readiness
                        .contains(ReadinessFlags::HANGUP);
                if !flags.contains(LinuxRecvFlags::PEEK)
                    && !terminal_readable
                    && ioctl_fionread(&socket.tcp_state()?.socket)
                        .map_err(broker_error_from_errno)?
                        == 0
                {
                    clear_readiness(socket, ReadinessFlags::READ)?;
                }
                return Ok(ReactorReceiveOutcome::Received(data));
            }
            Err(Errno::INTR) => {}
            Err(Errno::AGAIN) => {
                clear_readiness(socket, ReadinessFlags::READ)?;
                return Err(BrokerError::WouldBlock);
            }
            Err(error) => {
                let error = socket_operation_error_from_errno(error)?;
                fail_connect(socket, error)?;
                consume_synchronous_error(socket)?;
                return Ok(ReactorReceiveOutcome::Failed(error));
            }
        }
    }
}

fn set_tcp_option(socket: &mut SocketEntry, value: TcpOptionValue) -> BrokerResult<()> {
    if socket.kind() != SocketKind::Tcp {
        return Err(BrokerError::UnsupportedOperation);
    }
    match value {
        TcpOptionValue::NoDelay(value) => {
            sockopt::set_tcp_nodelay(&socket.tcp_state()?.socket, value)
                .map_err(broker_error_from_errno)?;
            socket.tcp_state_mut()?.no_delay = value;
        }
        TcpOptionValue::KeepAlive(value) => {
            sockopt::set_socket_keepalive(&socket.tcp_state()?.socket, value)
                .map_err(broker_error_from_errno)?;
            socket.tcp_state_mut()?.keep_alive = value;
        }
        _ => return Err(BrokerError::UnsupportedOperation),
    }
    Ok(())
}

fn apply_tcp_options(socket: &OwnedFd, no_delay: bool, keep_alive: bool) -> BrokerResult<()> {
    sockopt::set_tcp_nodelay(socket, no_delay).map_err(broker_error_from_errno)?;
    sockopt::set_socket_keepalive(socket, keep_alive).map_err(broker_error_from_errno)
}

fn get_tcp_option(socket: &SocketEntry, name: TcpOptionName) -> BrokerResult<TcpOptionValue> {
    if socket.kind() != SocketKind::Tcp {
        return Err(BrokerError::UnsupportedOperation);
    }
    match name {
        TcpOptionName::NoDelay => sockopt::tcp_nodelay(&socket.tcp_state()?.socket)
            .map(TcpOptionValue::NoDelay)
            .map_err(broker_error_from_errno),
        TcpOptionName::KeepAlive => sockopt::socket_keepalive(&socket.tcp_state()?.socket)
            .map(TcpOptionValue::KeepAlive)
            .map_err(broker_error_from_errno),
        _ => Err(BrokerError::UnsupportedOperation),
    }
}

fn shutdown_tcp_socket(
    socket: &mut SocketEntry,
    mode: ShutdownMode,
) -> BrokerResult<SocketOutcome<()>> {
    if socket.kind() != SocketKind::Tcp {
        return Err(BrokerError::Internal);
    }
    if mode == ShutdownMode::Abort {
        sockopt::set_socket_linger(&socket.tcp_state()?.socket, Some(Duration::ZERO))
            .map_err(broker_error_from_errno)?;
        socket.tcp_state_mut()?.abortive_close = true;
        return Ok(SocketOutcome::Completed(()));
    }
    let stop_listening = mode == ShutdownMode::StopListening;
    let listening = socket.tcp_state()?.listening;
    if stop_listening {
        if !listening {
            return Ok(SocketOutcome::Failed(SocketError::NotConnected));
        }
    } else if listening {
        return Ok(SocketOutcome::Failed(SocketError::NotConnected));
    }
    let (mode, add, clear, shuts_down_read, shuts_down_write) = match mode {
        ShutdownMode::Read => (
            LinuxShutdown::Read,
            ReadinessFlags::READ,
            ReadinessFlags::default(),
            true,
            false,
        ),
        ShutdownMode::Write => (
            LinuxShutdown::Write,
            ReadinessFlags::default(),
            ReadinessFlags::WRITE,
            false,
            true,
        ),
        ShutdownMode::Both => (
            LinuxShutdown::Both,
            ReadinessFlags::READ,
            ReadinessFlags::WRITE,
            true,
            true,
        ),
        ShutdownMode::StopListening => (
            LinuxShutdown::Read,
            ReadinessFlags::default(),
            ReadinessFlags::default(),
            true,
            false,
        ),
        _ => return Err(BrokerError::UnsupportedOperation),
    };
    loop {
        match shutdown(&socket.tcp_state()?.socket, mode) {
            Ok(()) => {}
            Err(Errno::INTR) => continue,
            Err(Errno::NOTCONN) => {
                fail_connect(socket, SocketError::NotConnected)?;
                return Ok(SocketOutcome::Failed(SocketError::NotConnected));
            }
            Err(error) => {
                let error = socket_operation_error_from_errno(error)?;
                fail_connect(socket, error)?;
                return Ok(SocketOutcome::Failed(error));
            }
        }
        if stop_listening {
            let tcp = socket.tcp_state_mut()?;
            tcp.listening = false;
            tcp.peek_waitall_threshold = None;
            socket.read_shutdown = true;
            socket.connection_status = SocketConnectionStatus::Failed(SocketError::NotConnected);
            // The native transition is complete and the cached terminal
            // snapshot is authoritative even if its notification cannot be
            // published. Acknowledge completion so core listener state cannot
            // diverge from the platform.
            let _ = update_snapshot(
                socket,
                Some(SocketConnectionStatus::Failed(SocketError::NotConnected)),
                ReadinessFlags::WRITE | ReadinessFlags::HANGUP,
            );
            return Ok(SocketOutcome::Completed(()));
        }
        socket.read_shutdown |= shuts_down_read;
        socket.write_shutdown |= shuts_down_write;
        let republish_readiness = shuts_down_read
            && socket
                .tcp_state_mut()?
                .peek_waitall_threshold
                .take()
                .is_some();
        if clear.0 != 0 {
            clear_readiness(socket, clear)?;
        }
        if add.0 != 0 {
            add_readiness(socket, add)?;
        }
        if republish_readiness {
            let readiness = socket
                .snapshot
                .lock()
                .expect("Linux socket snapshot mutex poisoned")
                .readiness;
            socket.readiness.republish(readiness)?;
        }
        return Ok(SocketOutcome::Completed(()));
    }
}

fn handle_socket_event(socket: &mut SocketEntry, events: epoll::EventFlags) -> BrokerResult<bool> {
    if socket.tcp_state().is_ok_and(|tcp| tcp.listening) {
        update_snapshot(socket, None, readiness_from_epoll(socket, events))?;
        return Ok(false);
    }
    if socket.kind() == SocketKind::Udp {
        update_snapshot(socket, None, readiness_from_epoll(socket, events))?;
        return Ok(false);
    }
    let republish_readiness = if events.contains(epoll::EventFlags::IN)
        && let Some(threshold) = socket
            .tcp_state()
            .ok()
            .and_then(|tcp| tcp.peek_waitall_threshold)
    {
        let threshold_reached = socket
            .tcp_state()
            .and_then(|tcp| ioctl_fionread(&tcp.socket).map_err(broker_error_from_errno))
            .ok()
            .and_then(|available| usize::try_from(available).ok())
            .is_none_or(|available| available >= threshold);
        if threshold_reached {
            socket.tcp_state_mut()?.peek_waitall_threshold = None;
        }
        threshold_reached
    } else {
        false
    };
    let failed_connector = match socket.connection_status {
        SocketConnectionStatus::Unconnected => false,
        SocketConnectionStatus::Connecting => {
            matches!(
                complete_connect(socket, events)?,
                SocketConnectionStatus::Failed(_)
            )
        }
        SocketConnectionStatus::Connected => {
            update_snapshot(socket, None, readiness_from_epoll(socket, events))?;
            false
        }
        SocketConnectionStatus::Failed(SocketError::NotConnected) if socket.read_shutdown => {
            update_snapshot(socket, None, ReadinessFlags::WRITE | ReadinessFlags::HANGUP)?;
            false
        }
        SocketConnectionStatus::Failed(_) => {
            update_snapshot(socket, None, ReadinessFlags::ERROR)?;
            false
        }
        _ => return Err(BrokerError::Internal),
    };
    if republish_readiness {
        let readiness = socket
            .snapshot
            .lock()
            .expect("Linux socket snapshot mutex poisoned")
            .readiness;
        socket.readiness.republish(readiness)?;
    }
    Ok(failed_connector)
}

fn complete_connect(
    socket: &mut SocketEntry,
    events: epoll::EventFlags,
) -> BrokerResult<SocketConnectionStatus> {
    // Epoll re-polls the descriptor when waiting, so OUT here reflects the
    // current post-connect state rather than readiness cached before connect.
    let status = match sockopt::socket_error(&socket.tcp_state()?.socket) {
        Ok(Ok(())) if events.contains(epoll::EventFlags::OUT) => SocketConnectionStatus::Connected,
        Ok(Ok(())) => SocketConnectionStatus::Connecting,
        Ok(Err(error)) | Err(error) => {
            SocketConnectionStatus::Failed(socket_error_from_errno(error))
        }
    };
    let readiness = match status {
        SocketConnectionStatus::Connected => {
            readiness_from_epoll(socket, events) | ReadinessFlags::WRITE
        }
        SocketConnectionStatus::Connecting => ReadinessFlags::default(),
        SocketConnectionStatus::Failed(_) => ReadinessFlags::ERROR,
        _ => return Err(BrokerError::Internal),
    };
    socket.connection_status = status;
    update_snapshot(socket, Some(status), readiness)?;
    Ok(status)
}

fn take_socket_error(socket: &SocketEntry) -> BrokerResult<Option<SocketError>> {
    let native_socket = match socket.kind() {
        SocketKind::Tcp => Some(&socket.tcp_state()?.socket),
        SocketKind::Udp => socket
            .udp_state()?
            .external_endpoint
            .as_ref()
            .map(|endpoint| &endpoint.socket),
    };
    let Some(native_socket) = native_socket else {
        return Ok(None);
    };
    match sockopt::socket_error(native_socket) {
        Ok(Ok(())) => Ok(None),
        Ok(Err(error)) | Err(error) => socket_operation_error_from_errno(error).map(Some),
    }
}

fn local_socket_address(socket: &OwnedFd) -> BrokerResult<SocketAddrV4> {
    match getsockname(socket) {
        Ok(address) => SocketAddrV4::try_from(address).map_err(|_| BrokerError::Internal),
        Err(_) => Err(BrokerError::Internal),
    }
}

fn status_socket(socket: &mut SocketEntry) -> BrokerResult<SocketStatusResponse> {
    let query_socket_error = {
        let snapshot = socket
            .snapshot
            .lock()
            .expect("Linux socket snapshot mutex poisoned");
        (socket.connection_status == SocketConnectionStatus::Connected
            || socket.kind() == SocketKind::Udp)
            && snapshot.readiness.contains(ReadinessFlags::ERROR)
    };
    let socket_error = if query_socket_error {
        let error = take_socket_error(socket)?;
        if socket.kind() == SocketKind::Udp {
            let udp = socket.udp_state_mut()?;
            udp.native_error = false;
            if let Some(endpoint) = udp.external_endpoint.as_mut() {
                endpoint.readable = false;
            }
        }
        error
    } else {
        None
    };
    let (response, readiness, republish_error) = {
        let mut snapshot = socket
            .snapshot
            .lock()
            .expect("Linux socket snapshot mutex poisoned");
        let cached_error = snapshot.pending_error.take();
        let (pending_error, next_pending_error) = shift_pending_error(cached_error, socket_error);
        snapshot.pending_error = next_pending_error;
        if pending_error.is_some() && next_pending_error.is_none() {
            snapshot.readiness = ReadinessFlags(snapshot.readiness.0 & !ReadinessFlags::ERROR.0);
        }
        (
            SocketStatusResponse {
                status: socket.connection_status,
                local_address: snapshot.local_address,
                pending_error,
            },
            snapshot.readiness,
            next_pending_error.is_some(),
        )
    };
    let publication = if republish_error {
        socket.readiness.republish(readiness)
    } else if response.pending_error.is_some() {
        socket.readiness.publish(readiness)
    } else {
        Ok(())
    };
    // UDP status synchronously returns the consumed error and updates the
    // authoritative snapshot. A notification failure must not discard that
    // only error observation.
    if socket.kind() != SocketKind::Udp {
        publication?;
    }
    Ok(response)
}

fn shift_pending_error(
    cached_error: Option<SocketError>,
    socket_error: Option<SocketError>,
) -> (Option<SocketError>, Option<SocketError>) {
    match cached_error {
        Some(error) => (Some(error), socket_error),
        None => (socket_error, None),
    }
}

fn readiness_from_epoll(socket: &SocketEntry, events: epoll::EventFlags) -> ReadinessFlags {
    let mut readiness = ReadinessFlags::default();
    if events.contains(epoll::EventFlags::IN) {
        readiness = readiness | ReadinessFlags::READ;
    }
    if events.contains(epoll::EventFlags::OUT) && !socket.write_shutdown {
        readiness = readiness | ReadinessFlags::WRITE;
    }
    if socket.kind() == SocketKind::Tcp
        && !socket.read_shutdown
        && events.intersects(epoll::EventFlags::RDHUP | epoll::EventFlags::HUP)
    {
        readiness = readiness | ReadinessFlags::READ | ReadinessFlags::HANGUP;
    }

    if events.contains(epoll::EventFlags::ERR) {
        readiness = readiness | ReadinessFlags::ERROR;
    }
    let previous = socket
        .snapshot
        .lock()
        .expect("Linux socket snapshot mutex poisoned")
        .readiness;
    ReadinessFlags(readiness.0 | previous.0)
}

const fn socket_kind(request: CreateSocketRequest) -> Option<SocketKind> {
    match (
        request.address_family,
        request.socket_type,
        request.protocol,
    ) {
        (AddressFamily::Ipv4, SocketType::Stream, IpProtocol::Tcp) => Some(SocketKind::Tcp),
        (AddressFamily::Ipv4, SocketType::Datagram, IpProtocol::Udp) => Some(SocketKind::Udp),
        _ => None,
    }
}

fn idle_epoll_events() -> epoll::EventFlags {
    epoll::EventFlags::RDHUP | epoll::EventFlags::ET
}

fn active_epoll_events() -> epoll::EventFlags {
    // Cached readiness turns these edge-triggered kernel events into the
    // level-triggered snapshots consumed by the broker protocol.
    epoll::EventFlags::IN
        | epoll::EventFlags::OUT
        | epoll::EventFlags::RDHUP
        | epoll::EventFlags::ET
}

fn update_snapshot(
    socket: &SocketEntry,
    status: Option<SocketConnectionStatus>,
    readiness: ReadinessFlags,
) -> BrokerResult<()> {
    let readiness_changed = {
        let mut snapshot = socket
            .snapshot
            .lock()
            .expect("Linux socket snapshot mutex poisoned");
        if let Some(status) = status {
            debug_assert_eq!(socket.connection_status, status);
            snapshot.status = status;
        }
        let changed = snapshot.readiness != readiness;
        snapshot.readiness = readiness;
        changed
    };
    if readiness_changed {
        socket.readiness.publish(readiness)?;
    }
    Ok(())
}

fn confirm_tcp_connected(socket: &mut SocketEntry) -> BrokerResult<()> {
    if socket.kind() != SocketKind::Tcp
        || socket.connection_status != SocketConnectionStatus::Connecting
    {
        return Ok(());
    }
    socket.connection_status = SocketConnectionStatus::Connected;
    let readiness = socket
        .snapshot
        .lock()
        .expect("Linux socket snapshot mutex poisoned")
        .readiness;
    update_snapshot(socket, Some(SocketConnectionStatus::Connected), readiness)
}

/// Records a terminal native operation while a connect is pending.
///
/// A reactor command that can call this helper must subsequently invoke
/// `Reactor::discard_failed_connect_after_command` after releasing its socket
/// table borrow.
fn fail_connect(socket: &mut SocketEntry, error: SocketError) -> BrokerResult<()> {
    if socket.kind() != SocketKind::Tcp
        || socket.connection_status != SocketConnectionStatus::Connecting
    {
        return Ok(());
    }
    socket.connection_status = SocketConnectionStatus::Failed(error);
    let readiness = socket
        .snapshot
        .lock()
        .expect("Linux socket snapshot mutex poisoned")
        .readiness
        | ReadinessFlags::ERROR;
    update_snapshot(
        socket,
        Some(SocketConnectionStatus::Failed(error)),
        readiness,
    )
}

fn add_readiness(socket: &SocketEntry, readiness: ReadinessFlags) -> BrokerResult<()> {
    let current = socket
        .snapshot
        .lock()
        .expect("Linux socket snapshot mutex poisoned")
        .readiness;
    update_snapshot(socket, None, ReadinessFlags(current.0 | readiness.0))
}

fn clear_readiness(socket: &SocketEntry, readiness: ReadinessFlags) -> BrokerResult<()> {
    let current = socket
        .snapshot
        .lock()
        .expect("Linux socket snapshot mutex poisoned")
        .readiness;
    update_snapshot(socket, None, ReadinessFlags(current.0 & !readiness.0))
}

fn consume_synchronous_error(socket: &SocketEntry) -> BrokerResult<()> {
    let query_socket_error = {
        let snapshot = socket
            .snapshot
            .lock()
            .expect("Linux socket snapshot mutex poisoned");
        if !can_consume_synchronous_error(socket.kind(), socket.connection_status) {
            return Ok(());
        }
        snapshot.pending_error.is_none()
    };
    let socket_error = if query_socket_error {
        take_socket_error(socket)?
    } else {
        None
    };
    let (readiness, changed) = {
        let mut snapshot = socket
            .snapshot
            .lock()
            .expect("Linux socket snapshot mutex poisoned");
        if snapshot.pending_error.is_none() {
            snapshot.pending_error = socket_error;
        }
        let readiness = if snapshot.pending_error.is_some() {
            snapshot.readiness | ReadinessFlags::ERROR
        } else {
            ReadinessFlags(snapshot.readiness.0 & !ReadinessFlags::ERROR.0)
        };
        let changed = readiness != snapshot.readiness;
        snapshot.readiness = readiness;
        (readiness, changed)
    };
    if changed {
        socket.readiness.publish(readiness)?;
    }
    Ok(())
}

const fn can_consume_synchronous_error(kind: SocketKind, status: SocketConnectionStatus) -> bool {
    matches!(kind, SocketKind::Udp) || matches!(status, SocketConnectionStatus::Connected)
}

const fn socket_error_from_errno(error: Errno) -> SocketError {
    match error {
        Errno::CONNREFUSED => SocketError::ConnectionRefused,
        Errno::CONNRESET | Errno::PIPE => SocketError::ConnectionReset,
        Errno::CONNABORTED => SocketError::ConnectionAborted,
        Errno::NETUNREACH => SocketError::NetworkUnreachable,
        Errno::HOSTUNREACH => SocketError::HostUnreachable,
        Errno::TIMEDOUT => SocketError::TimedOut,
        Errno::ADDRINUSE => SocketError::AddressInUse,
        Errno::ADDRNOTAVAIL => SocketError::AddressNotAvailable,
        Errno::NOTCONN => SocketError::NotConnected,
        Errno::INVAL => SocketError::InvalidArgument,
        _ => SocketError::Other,
    }
}

const fn socket_operation_error_from_errno(error: Errno) -> BrokerResult<SocketError> {
    match broker_resource_error_from_errno(error) {
        Some(error) => Err(error),
        None => Ok(socket_error_from_errno(error)),
    }
}

const fn broker_error_from_errno(error: Errno) -> BrokerError {
    match broker_resource_error_from_errno(error) {
        Some(error) => error,
        None => BrokerError::Internal,
    }
}

const fn broker_resource_error_from_errno(error: Errno) -> Option<BrokerError> {
    match error {
        Errno::NOMEM => Some(BrokerError::OutOfMemory),
        Errno::MFILE | Errno::NFILE | Errno::NOBUFS | Errno::NOSPC => {
            Some(BrokerError::ResourceExhausted)
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Read as _, Write as _};
    use std::net::Ipv4Addr;
    use std::net::{Shutdown, TcpListener, TcpStream, UdpSocket};
    use std::sync::mpsc::{Receiver, Sender, channel};
    use std::time::{Duration, Instant};

    use super::*;
    use litebox_broker_core::readiness::ReadinessSink;
    use litebox_broker_core::{
        BrokerCore, BrokerCoreLimits, BrokerSession, CallerCredential, DestinationPortRange,
        DestinationRule, Ipv4Cidr, ObjectRights, PolicyEngine, SocketPolicy,
    };
    use litebox_broker_protocol::ObjectHandle;
    use litebox_broker_protocol::socket::{Ipv4Address, Port, ReceiveSocketResponse};

    use super::udp::{
        MAX_REJECTED_UDP_DATAGRAMS_PER_COMMAND, MAX_UDP_EXTERNAL_PEERS_PER_SOCKET,
        MAX_UDP_NATIVE_RECEIVE_BUFFER, MAX_UDP_QUEUE_DATAGRAMS_PER_SOURCE,
    };

    const TEST_TIMEOUT: Duration = Duration::from_secs(30);

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct ReceivedPlatformDatagram {
        received: usize,
        datagram_length: usize,
        source_address: SocketAddrV4,
    }

    #[test]
    fn pending_socket_retirement_prevents_reactor_activation() {
        let lifecycle = SocketLifecycle::pending();
        lifecycle.retire(|| panic!("pending sockets have no reactor resource to close"));
        assert!(!lifecycle.activate());
        assert_eq!(lifecycle.load(), SocketLifecycleState::Retired);
    }

    #[test]
    fn concurrent_socket_retirement_waits_for_close_acknowledgement() {
        let lifecycle = Arc::new(SocketLifecycle::pending());
        assert!(lifecycle.activate());
        let (close_started, close_started_receive) = sync_channel(1);
        let (release_close, release_close_receive) = sync_channel(1);
        let first_lifecycle = Arc::clone(&lifecycle);
        let first = thread::spawn(move || {
            first_lifecycle.retire(|| {
                close_started.send(()).unwrap();
                release_close_receive.recv_timeout(TEST_TIMEOUT).unwrap();
            });
        });
        close_started_receive.recv_timeout(TEST_TIMEOUT).unwrap();

        let (second_started, second_started_receive) = sync_channel(1);
        let (second_finished, second_finished_receive) = sync_channel(1);
        let second_lifecycle = Arc::clone(&lifecycle);
        let second = thread::spawn(move || {
            second_started.send(()).unwrap();
            second_lifecycle.retire(|| panic!("only the active caller may close the socket"));
            second_finished.send(()).unwrap();
        });
        second_started_receive.recv_timeout(TEST_TIMEOUT).unwrap();
        assert!(
            second_finished_receive
                .recv_timeout(Duration::from_millis(100))
                .is_err()
        );

        release_close.send(()).unwrap();
        first.join().unwrap();
        second_finished_receive.recv_timeout(TEST_TIMEOUT).unwrap();
        second.join().unwrap();
        assert_eq!(lifecycle.load(), SocketLifecycleState::Retired);
    }

    fn send_bytes(
        session: &BrokerSession,
        handle: ObjectHandle,
        data: &[u8],
        flags: SendFlags,
    ) -> BrokerResult<SocketOutcome<usize>> {
        litebox_broker_core::socket::send(session, handle, data.to_vec(), flags)
    }

    fn send_datagram(
        session: &BrokerSession,
        handle: ObjectHandle,
        data: &[u8],
        flags: SendFlags,
        destination: Option<SocketAddrV4>,
    ) -> BrokerResult<SocketOutcome<usize>> {
        litebox_broker_core::socket::send_to(session, handle, data.to_vec(), flags, destination)
    }

    fn receive_into(
        session: &BrokerSession,
        handle: ObjectHandle,
        data: &mut [u8],
        flags: ReceiveFlags,
        peek_offset: u32,
        peek_length: u32,
    ) -> BrokerResult<SocketOutcome<ReceiveSocketResponse>> {
        match litebox_broker_core::socket::receive(
            session,
            handle,
            data.len(),
            flags,
            peek_offset,
            peek_length,
        )? {
            SocketOutcome::Completed(PlatformStreamReceive::Received(received)) => {
                data[..received.len()].copy_from_slice(&received);
                Ok(SocketOutcome::Completed(ReceiveSocketResponse::Received(
                    received
                        .len()
                        .try_into()
                        .map_err(|_| BrokerError::Internal)?,
                )))
            }
            SocketOutcome::Completed(PlatformStreamReceive::EndOfStream) => {
                Ok(SocketOutcome::Completed(ReceiveSocketResponse::EndOfStream))
            }
            SocketOutcome::Failed(error) => Ok(SocketOutcome::Failed(error)),
        }
    }

    fn receive_datagram_into(
        session: &BrokerSession,
        handle: ObjectHandle,
        data: &mut [u8],
        flags: ReceiveFromFlags,
    ) -> BrokerResult<SocketOutcome<ReceivedPlatformDatagram>> {
        match litebox_broker_core::socket::receive_from(session, handle, data.len(), flags)? {
            SocketOutcome::Completed(received) => {
                data[..received.data.len()].copy_from_slice(&received.data);
                Ok(SocketOutcome::Completed(ReceivedPlatformDatagram {
                    received: received.data.len(),
                    datagram_length: received.datagram_length,
                    source_address: received.source_address,
                }))
            }
            SocketOutcome::Failed(error) => Ok(SocketOutcome::Failed(error)),
        }
    }

    #[test]
    fn cached_socket_error_precedes_a_new_kernel_error() {
        assert_eq!(
            shift_pending_error(
                Some(SocketError::ConnectionRefused),
                Some(SocketError::NetworkUnreachable),
            ),
            (
                Some(SocketError::ConnectionRefused),
                Some(SocketError::NetworkUnreachable),
            )
        );
        assert_eq!(
            shift_pending_error(None, Some(SocketError::NetworkUnreachable)),
            (Some(SocketError::NetworkUnreachable), None)
        );
    }

    #[test]
    fn synchronous_errors_do_not_consume_tcp_connect_status() {
        assert!(!can_consume_synchronous_error(
            SocketKind::Tcp,
            SocketConnectionStatus::Connecting,
        ));
        assert!(can_consume_synchronous_error(
            SocketKind::Tcp,
            SocketConnectionStatus::Connected,
        ));
        assert!(can_consume_synchronous_error(
            SocketKind::Udp,
            SocketConnectionStatus::Unconnected,
        ));
    }

    #[test]
    fn pending_guest_connections_are_keyed_by_complete_host_tuple() {
        let remote_address = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 40000);
        let first_listener = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 5000);
        let second_listener = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 5001);
        let first_guest = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 1000);
        let second_guest = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 1001);
        let mut tcp = ReactorTcpState::default();
        for (listener, guest) in [
            (first_listener, first_guest),
            (second_listener, second_guest),
        ] {
            tcp.insert_pending_guest_connection(
                (remote_address, listener),
                PendingGuestTcpConnection {
                    session_id: SessionId(7),
                    guest_address: guest,
                    listener_id: 1,
                    discard_on_accept: false,
                    discard_until_deadline: false,
                    discard_deadline: None,
                    retained_connector: None,
                },
            )
            .unwrap();
        }
        assert_eq!(
            tcp.insert_pending_guest_connection(
                (remote_address, first_listener),
                PendingGuestTcpConnection {
                    session_id: SessionId(8),
                    guest_address: SocketAddrV4::new(Ipv4Addr::LOCALHOST, 1002),
                    listener_id: 1,
                    discard_on_accept: false,
                    discard_until_deadline: false,
                    discard_deadline: None,
                    retained_connector: None,
                },
            ),
            Err(BrokerError::ResourceExhausted)
        );

        assert_eq!(
            match tcp
                .take_pending_guest_connection(remote_address, second_listener)
                .unwrap()
            {
                PendingGuestConnectionMatch::Take(connection) => connection.guest_address,
                PendingGuestConnectionMatch::PersistentDiscard => {
                    panic!("deliverable connection became a discard marker")
                }
            },
            second_guest
        );
        assert_eq!(
            match tcp
                .take_pending_guest_connection(remote_address, first_listener)
                .unwrap()
            {
                PendingGuestConnectionMatch::Take(connection) => connection.guest_address,
                PendingGuestConnectionMatch::PersistentDiscard => {
                    panic!("deliverable connection became a discard marker")
                }
            },
            first_guest
        );
        assert!(tcp.pending_guest_connections.is_empty());
    }

    #[test]
    fn tuple_collision_persists_its_discard_marker() {
        let guest_address = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 5000);
        let remote_address = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 40000);
        let host_address = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 41000);
        let connection = (remote_address, host_address);
        let deadline = Instant::now() + PENDING_CONNECT_DISCARD_LIFETIME;
        let mut tcp = ReactorTcpState::default();
        tcp.insert_binding(ReactorTcpBinding {
            socket_id: 1,
            guest_address,
            host_address: Some(host_address),
            listening: true,
            requires_backlog_drain: false,
            untracked_connection_deadline: None,
        })
        .unwrap();
        assert!(!tcp.persist_discard_marker_for_collision(connection, 1, deadline));
        tcp.insert_pending_guest_connection(
            connection,
            PendingGuestTcpConnection {
                session_id: SessionId(7),
                guest_address,
                listener_id: 1,
                discard_on_accept: false,
                discard_until_deadline: false,
                discard_deadline: Some(Instant::now()),
                retained_connector: None,
            },
        )
        .unwrap();
        assert!(!tcp.persist_discard_marker_for_collision(connection, 1, deadline));
        tcp.pending_guest_connections
            .get_mut(&connection)
            .unwrap()
            .discard_on_accept = true;

        assert!(tcp.persist_discard_marker_for_collision(connection, 1, deadline));
        let marker = tcp.pending_guest_connections.get(&connection).unwrap();
        assert!(marker.discard_until_deadline);
        assert_eq!(marker.discard_deadline, Some(deadline));
        assert!(
            !tcp.bindings
                .get(&guest_address.port())
                .unwrap()
                .requires_backlog_drain
        );
        assert!(matches!(
            tcp.take_pending_guest_connection(remote_address, host_address),
            Some(PendingGuestConnectionMatch::PersistentDiscard)
        ));
        assert!(tcp.pending_guest_connections.contains_key(&connection));
    }

    #[test]
    fn listener_backlog_probe_distinguishes_empty_and_queued_children() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let listener: OwnedFd = listener.into();
        assert!(!socket_backlog_is_nonempty(&listener));

        let _connector = TcpStream::connect(address).unwrap();
        assert!(socket_backlog_is_nonempty(&listener));
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

    struct FailingReadinessSink {
        inner: TestReadinessSink,
        fail_next_publish: Mutex<Option<(ObjectHandle, usize)>>,
    }

    impl FailingReadinessSink {
        fn fail_next_publish_for(&self, handle: ObjectHandle) {
            self.fail_next_publishes_for(handle, 1);
        }

        fn fail_next_publishes_for(&self, handle: ObjectHandle, count: usize) {
            *self.fail_next_publish.lock().unwrap() = Some((handle, count));
        }
    }

    impl ReadinessSink for FailingReadinessSink {
        fn max_tracked_objects(&self) -> usize {
            self.inner.max_tracked_objects()
        }

        fn publish(&self, handle: ObjectHandle, readiness: ReadinessFlags) -> BrokerResult<()> {
            let mut fail_next_publish = self.fail_next_publish.lock().unwrap();
            if let Some((failed_handle, remaining)) = fail_next_publish.as_mut()
                && *failed_handle == handle
            {
                *remaining -= 1;
                if *remaining == 0 {
                    *fail_next_publish = None;
                }
                return Err(BrokerError::ResourceExhausted);
            }
            drop(fail_next_publish);
            self.inner.publish(handle, readiness)
        }

        fn republish(&self, handle: ObjectHandle, readiness: ReadinessFlags) -> BrokerResult<()> {
            self.publish(handle, readiness)
        }

        fn retire(&self, handle: ObjectHandle) {
            self.inner.retire(handle);
        }
    }

    #[test]
    fn untracked_guest_connection_cleanup_is_bounded_and_drains_backlog() {
        let provider = Arc::new(LinuxSocketProvider::new(6, 3).unwrap());
        let broker = BrokerCore::new_with_limits(
            PolicyEngine::with_unauthenticated_rights(ObjectRights::all())
                .with_socket_policy(SocketPolicy::Ipv4Loopback),
            BrokerCoreLimits::new_with_all_limits(12, 0, 6, 6),
            provider.clone(),
        )
        .unwrap();
        let listener_session = broker
            .create_session(CallerCredential::Unauthenticated)
            .unwrap();
        let connector_session = broker
            .create_session(CallerCredential::Unauthenticated)
            .unwrap();
        let (published, publications) = channel();
        let (retired, retirements) = channel();
        let readiness = Arc::new(TestReadinessSink { published, retired });
        let guest_address = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 8090);
        let listener = create_socket(&listener_session, readiness.clone());
        assert_eq!(
            litebox_broker_core::socket::bind(&listener_session, listener, guest_address),
            Ok(SocketOutcome::Completed(guest_address))
        );
        assert_eq!(
            litebox_broker_core::socket::listen(&listener_session, listener, 4),
            Ok(SocketOutcome::Completed(guest_address))
        );

        provider
            .reactor
            .defer_untracked_guest_connection(guest_address.port());
        let blocked = create_socket(&connector_session, readiness.clone());
        assert_eq!(
            litebox_broker_core::socket::connect(&connector_session, blocked, guest_address),
            Ok(SocketOutcome::Completed(SocketConnectionStatus::Failed(
                SocketError::ConnectionRefused
            )))
        );
        connector_session.close_object_reference(blocked).unwrap();
        assert_eq!(retirements.recv_timeout(TEST_TIMEOUT).unwrap(), blocked);

        provider.reactor.expire_pending_guest_connections();
        let connector = create_socket(&connector_session, readiness.clone());
        assert!(matches!(
            litebox_broker_core::socket::connect(&connector_session, connector, guest_address),
            Ok(SocketOutcome::Completed(
                SocketConnectionStatus::Connecting | SocketConnectionStatus::Connected
            ))
        ));
        wait_until_connected(&connector_session, connector, &publications);
        wait_until_ready(
            &listener_session,
            &publications,
            listener,
            ReadinessFlags::READ,
        );
        let accepted = match litebox_broker_core::socket::accept(
            &listener_session,
            listener,
            readiness.clone(),
        )
        .unwrap()
        {
            SocketOutcome::Completed(accepted) => accepted.handle,
            SocketOutcome::Failed(error) => panic!("guest accept failed: {error:?}"),
        };
        listener_session.close_object_reference(accepted).unwrap();
        assert_eq!(retirements.recv_timeout(TEST_TIMEOUT).unwrap(), accepted);
        connector_session.close_object_reference(connector).unwrap();
        assert_eq!(retirements.recv_timeout(TEST_TIMEOUT).unwrap(), connector);

        let private_address = provider.reactor.host_address(guest_address.port()).unwrap();
        let _unmatched = TcpStream::connect(private_address).unwrap();
        provider
            .reactor
            .defer_untracked_guest_connection(guest_address.port());
        provider.reactor.expire_pending_guest_connections();

        let gated = create_socket(&connector_session, readiness.clone());
        assert_eq!(
            litebox_broker_core::socket::connect(&connector_session, gated, guest_address),
            Ok(SocketOutcome::Completed(SocketConnectionStatus::Failed(
                SocketError::ConnectionRefused
            )))
        );
        connector_session.close_object_reference(gated).unwrap();
        assert_eq!(retirements.recv_timeout(TEST_TIMEOUT).unwrap(), gated);
        assert!(matches!(
            litebox_broker_core::socket::accept(&listener_session, listener, readiness.clone(),),
            Err(BrokerError::WouldBlock)
        ));

        let final_connector = create_socket(&connector_session, readiness);
        assert!(matches!(
            litebox_broker_core::socket::connect(
                &connector_session,
                final_connector,
                guest_address,
            ),
            Ok(SocketOutcome::Completed(
                SocketConnectionStatus::Connecting | SocketConnectionStatus::Connected
            ))
        ));
    }

    #[test]
    fn reactor_drives_a_loopback_tcp_socket() {
        assert_eq!(
            socket_operation_error_from_errno(Errno::NOMEM),
            Err(BrokerError::OutOfMemory)
        );
        assert_eq!(
            socket_operation_error_from_errno(Errno::NOBUFS),
            Err(BrokerError::ResourceExhausted)
        );

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let (allow_response, response_allowed) = channel();
        let (allow_end_of_stream, end_of_stream_allowed) = channel();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream.set_read_timeout(Some(TEST_TIMEOUT)).unwrap();
            stream.set_write_timeout(Some(TEST_TIMEOUT)).unwrap();
            let mut request = [0_u8; 4];
            stream.read_exact(&mut request).unwrap();
            assert_eq!(&request, b"ping");
            response_allowed.recv_timeout(TEST_TIMEOUT).unwrap();
            stream.write_all(b"pong").unwrap();
            end_of_stream_allowed.recv_timeout(TEST_TIMEOUT).unwrap();
            stream.shutdown(Shutdown::Write).unwrap();
        });
        let read_shutdown_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let read_shutdown_address = read_shutdown_listener.local_addr().unwrap();
        let (allow_read_shutdown_data, read_shutdown_data_allowed) = channel();
        let (read_shutdown_data_sent, read_shutdown_data_received) = channel();
        let (release_read_shutdown_server, read_shutdown_server_released) = channel();
        let read_shutdown_server = thread::spawn(move || {
            let (mut stream, _) = read_shutdown_listener.accept().unwrap();
            read_shutdown_data_allowed
                .recv_timeout(TEST_TIMEOUT)
                .unwrap();
            stream.write_all(b"x").unwrap();
            read_shutdown_data_sent.send(()).unwrap();
            read_shutdown_server_released
                .recv_timeout(TEST_TIMEOUT)
                .unwrap();
        });
        let abort_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let abort_address = abort_listener.local_addr().unwrap();
        let (abort_accepted, wait_for_abort_accept) = channel();
        let abort_server = thread::spawn(move || {
            let (mut stream, _) = abort_listener.accept().unwrap();
            stream.set_read_timeout(Some(TEST_TIMEOUT)).unwrap();
            abort_accepted.send(()).unwrap();
            let error = stream.read(&mut [0]).unwrap_err();
            assert_eq!(error.kind(), std::io::ErrorKind::ConnectionReset);
        });

        let provider = Arc::new(LinuxSocketProvider::new(8, 8).unwrap());
        let broker = BrokerCore::new_with_limits(
            PolicyEngine::with_unauthenticated_rights(ObjectRights::all())
                .with_socket_policy(SocketPolicy::Ipv4Loopback),
            BrokerCoreLimits::new_with_all_limits(16, 0, 8, 8),
            provider,
        )
        .unwrap();
        let session = broker
            .create_session(CallerCredential::Unauthenticated)
            .unwrap();
        let (published, publications) = channel();
        let (retired, retirements) = channel();
        let readiness = Arc::new(TestReadinessSink { published, retired });
        let handle = create_socket(&session, readiness.clone());
        let connect =
            litebox_broker_core::socket::connect(&session, handle, socket_address_v4(address))
                .unwrap();
        assert!(matches!(
            connect,
            SocketOutcome::Completed(
                SocketConnectionStatus::Connecting | SocketConnectionStatus::Connected
            )
        ));
        wait_until_connected(&session, handle, &publications);
        let status = litebox_broker_core::socket::status(&session, handle).unwrap();
        assert_eq!(status.status, SocketConnectionStatus::Connected);
        let local_address = status
            .local_address
            .expect("connected socket must expose its local address");
        assert_eq!(*local_address.ip(), Ipv4Addr::LOCALHOST);
        assert_ne!(local_address.port(), 0);
        assert_eq!(status.pending_error, None);
        assert_eq!(
            litebox_broker_core::socket::get_tcp_option(&session, handle, TcpOptionName::NoDelay,),
            Ok(TcpOptionValue::NoDelay(false))
        );
        litebox_broker_core::socket::set_tcp_option(
            &session,
            handle,
            TcpOptionValue::NoDelay(true),
        )
        .unwrap();
        assert_eq!(
            litebox_broker_core::socket::get_tcp_option(&session, handle, TcpOptionName::NoDelay,),
            Ok(TcpOptionValue::NoDelay(true))
        );
        assert_eq!(
            litebox_broker_core::socket::get_tcp_option(&session, handle, TcpOptionName::KeepAlive,),
            Ok(TcpOptionValue::KeepAlive(false))
        );
        litebox_broker_core::socket::set_tcp_option(
            &session,
            handle,
            TcpOptionValue::KeepAlive(true),
        )
        .unwrap();
        assert_eq!(
            litebox_broker_core::socket::get_tcp_option(&session, handle, TcpOptionName::KeepAlive,),
            Ok(TcpOptionValue::KeepAlive(true))
        );

        let mut unavailable = [0_u8; 1];
        assert_eq!(
            receive_into(&session, handle, &mut unavailable, ReceiveFlags::NONE, 0, 0,),
            Err(BrokerError::WouldBlock)
        );
        assert_eq!(
            send_bytes(&session, handle, b"ping", SendFlags::NONE,),
            Ok(SocketOutcome::Completed(4))
        );
        assert_eq!(
            litebox_broker_core::socket::shutdown(&session, handle, ShutdownMode::Write),
            Ok(SocketOutcome::Completed(()))
        );
        assert_eq!(
            send_bytes(&session, handle, b"after shutdown", SendFlags::NONE),
            Ok(SocketOutcome::Failed(SocketError::Other))
        );
        allow_response.send(()).unwrap();
        wait_until_ready(&session, &publications, handle, ReadinessFlags::READ);
        let current_readiness = session.check_readiness(handle).unwrap();
        assert!(!current_readiness.contains(ReadinessFlags::WRITE));
        assert!(!current_readiness.contains(ReadinessFlags::ERROR));

        let mut first = [0_u8; 1];
        assert_eq!(
            receive_into(&session, handle, &mut first, ReceiveFlags::NONE, 0, 0,),
            Ok(SocketOutcome::Completed(ReceiveSocketResponse::Received(1)))
        );
        assert_eq!(&first, b"p");
        assert!(
            session
                .check_readiness(handle)
                .unwrap()
                .contains(ReadinessFlags::READ)
        );
        let mut peeked = [0_u8; 3];
        assert_eq!(
            receive_into(&session, handle, &mut peeked, ReceiveFlags::PEEK, 0, 3,),
            Ok(SocketOutcome::Completed(ReceiveSocketResponse::Received(3)))
        );
        assert_eq!(&peeked, b"ong");
        let mut received = [0_u8; 3];
        assert_eq!(
            receive_into(&session, handle, &mut received, ReceiveFlags::NONE, 0, 0,),
            Ok(SocketOutcome::Completed(ReceiveSocketResponse::Received(3)))
        );
        assert_eq!(&received, b"ong");
        assert!(
            !session
                .check_readiness(handle)
                .unwrap()
                .contains(ReadinessFlags::READ)
        );
        assert_eq!(
            receive_into(&session, handle, &mut unavailable, ReceiveFlags::NONE, 0, 0,),
            Err(BrokerError::WouldBlock)
        );
        assert!(
            !session
                .check_readiness(handle)
                .unwrap()
                .contains(ReadinessFlags::READ)
        );
        allow_end_of_stream.send(()).unwrap();
        wait_for_end_of_stream(&session, handle, &publications);

        let read_shutdown_handle = create_socket(&session, readiness.clone());
        let read_shutdown_connect = litebox_broker_core::socket::connect(
            &session,
            read_shutdown_handle,
            socket_address_v4(read_shutdown_address),
        )
        .unwrap();
        assert!(matches!(
            read_shutdown_connect,
            SocketOutcome::Completed(
                SocketConnectionStatus::Connecting | SocketConnectionStatus::Connected
            )
        ));
        wait_until_connected(&session, read_shutdown_handle, &publications);
        allow_read_shutdown_data.send(()).unwrap();
        read_shutdown_data_received
            .recv_timeout(TEST_TIMEOUT)
            .unwrap();
        wait_until_ready(
            &session,
            &publications,
            read_shutdown_handle,
            ReadinessFlags::READ,
        );
        let mut read_shutdown_peek = [0_u8; 2];
        assert_eq!(
            receive_into(
                &session,
                read_shutdown_handle,
                &mut read_shutdown_peek,
                ReceiveFlags(ReceiveFlags::PEEK.0 | ReceiveFlags::WAITALL.0),
                0,
                2,
            ),
            Err(BrokerError::WouldBlock)
        );
        assert_eq!(
            litebox_broker_core::socket::shutdown(
                &session,
                read_shutdown_handle,
                ShutdownMode::Read,
            ),
            Ok(SocketOutcome::Completed(()))
        );
        wait_until_ready(
            &session,
            &publications,
            read_shutdown_handle,
            ReadinessFlags::READ,
        );
        assert_eq!(
            receive_into(
                &session,
                read_shutdown_handle,
                &mut read_shutdown_peek,
                ReceiveFlags(ReceiveFlags::PEEK.0 | ReceiveFlags::WAITALL.0),
                0,
                2,
            ),
            Ok(SocketOutcome::Completed(ReceiveSocketResponse::Received(1)))
        );
        assert_eq!(read_shutdown_peek[0], b'x');
        let mut queued_after_shutdown = [0_u8; 1];
        assert_eq!(
            receive_into(
                &session,
                read_shutdown_handle,
                &mut queued_after_shutdown,
                ReceiveFlags::NONE,
                0,
                0,
            ),
            Ok(SocketOutcome::Completed(ReceiveSocketResponse::Received(1)))
        );
        assert_eq!(queued_after_shutdown, [b'x']);
        assert!(
            session
                .check_readiness(read_shutdown_handle)
                .unwrap()
                .contains(ReadinessFlags::READ)
        );
        assert_eq!(
            receive_into(
                &session,
                read_shutdown_handle,
                &mut queued_after_shutdown,
                ReceiveFlags::NONE,
                0,
                0,
            ),
            Ok(SocketOutcome::Completed(ReceiveSocketResponse::EndOfStream))
        );
        let read_shutdown_readiness = session.check_readiness(read_shutdown_handle).unwrap();
        assert!(read_shutdown_readiness.contains(ReadinessFlags::READ));
        assert!(!read_shutdown_readiness.contains(ReadinessFlags::HANGUP));
        assert!(!read_shutdown_readiness.contains(ReadinessFlags::ERROR));

        let unconnected_handle = create_socket(&session, readiness.clone());
        assert_eq!(
            receive_into(
                &session,
                unconnected_handle,
                &mut unavailable,
                ReceiveFlags(ReceiveFlags::PEEK.0 | ReceiveFlags::WAITALL.0),
                0,
                1,
            ),
            Ok(SocketOutcome::Failed(SocketError::NotConnected))
        );
        assert_eq!(
            litebox_broker_core::socket::shutdown(&session, unconnected_handle, ShutdownMode::Both,),
            Ok(SocketOutcome::Failed(SocketError::NotConnected))
        );
        assert_eq!(
            litebox_broker_core::socket::shutdown(
                &session,
                unconnected_handle,
                ShutdownMode::StopListening,
            ),
            Ok(SocketOutcome::Failed(SocketError::NotConnected))
        );
        assert!(
            !session
                .check_readiness(unconnected_handle)
                .unwrap()
                .contains(ReadinessFlags::ERROR)
        );

        let refused_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let refused_address = refused_listener.local_addr().unwrap();
        drop(refused_listener);
        let refused_handle = create_socket(&session, readiness.clone());
        let refused_connect = litebox_broker_core::socket::connect(
            &session,
            refused_handle,
            socket_address_v4(refused_address),
        )
        .unwrap();
        assert!(matches!(
            refused_connect,
            SocketOutcome::Completed(
                SocketConnectionStatus::Connecting | SocketConnectionStatus::Failed(_)
            )
        ));
        assert_eq!(
            wait_until_failed(&session, refused_handle, &publications),
            SocketError::ConnectionRefused
        );
        assert!(
            session
                .check_readiness(refused_handle)
                .unwrap()
                .contains(ReadinessFlags::ERROR)
        );

        let abort_handle = create_socket(&session, readiness);
        let abort_connect = litebox_broker_core::socket::connect(
            &session,
            abort_handle,
            socket_address_v4(abort_address),
        )
        .unwrap();
        assert!(matches!(
            abort_connect,
            SocketOutcome::Completed(
                SocketConnectionStatus::Connecting | SocketConnectionStatus::Connected
            )
        ));
        wait_until_connected(&session, abort_handle, &publications);
        wait_for_abort_accept.recv_timeout(TEST_TIMEOUT).unwrap();
        assert_eq!(
            litebox_broker_core::socket::shutdown(&session, abort_handle, ShutdownMode::Abort),
            Ok(SocketOutcome::Completed(()))
        );
        session.close_object_reference(abort_handle).unwrap();
        assert_eq!(
            retirements.recv_timeout(TEST_TIMEOUT).unwrap(),
            abort_handle
        );
        abort_server.join().unwrap();

        session.close_object_reference(handle).unwrap();
        assert_eq!(retirements.recv_timeout(TEST_TIMEOUT).unwrap(), handle);
        session
            .close_object_reference(read_shutdown_handle)
            .unwrap();
        assert_eq!(
            retirements.recv_timeout(TEST_TIMEOUT).unwrap(),
            read_shutdown_handle
        );
        session.close_object_reference(unconnected_handle).unwrap();
        assert_eq!(
            retirements.recv_timeout(TEST_TIMEOUT).unwrap(),
            unconnected_handle
        );
        session.close_object_reference(refused_handle).unwrap();
        assert_eq!(
            retirements.recv_timeout(TEST_TIMEOUT).unwrap(),
            refused_handle
        );
        release_read_shutdown_server.send(()).unwrap();
        read_shutdown_server.join().unwrap();
        server.join().unwrap();
    }

    #[test]
    fn external_tcp_close_with_unread_data_preserves_reset() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let (data_sent, wait_for_data) = channel();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream.set_read_timeout(Some(TEST_TIMEOUT)).unwrap();
            stream.set_write_timeout(Some(TEST_TIMEOUT)).unwrap();
            stream.write_all(b"unread").unwrap();
            data_sent.send(()).unwrap();
            let error = stream.read(&mut [0_u8; 1]).unwrap_err();
            assert_eq!(error.kind(), std::io::ErrorKind::ConnectionReset);
        });

        let provider = Arc::new(LinuxSocketProvider::new(1, 1).unwrap());
        let broker = BrokerCore::new_with_limits(
            PolicyEngine::with_unauthenticated_rights(ObjectRights::all())
                .with_socket_policy(SocketPolicy::Ipv4Loopback),
            BrokerCoreLimits::new_with_all_limits(2, 0, 1, 1),
            provider,
        )
        .unwrap();
        let session = broker
            .create_session(CallerCredential::Unauthenticated)
            .unwrap();
        let (published, publications) = channel();
        let (retired, retirements) = channel();
        let readiness = Arc::new(TestReadinessSink { published, retired });
        let handle = create_socket(&session, readiness);
        assert!(matches!(
            litebox_broker_core::socket::connect(&session, handle, socket_address_v4(address),),
            Ok(SocketOutcome::Completed(
                SocketConnectionStatus::Connecting | SocketConnectionStatus::Connected
            ))
        ));
        wait_until_connected(&session, handle, &publications);
        wait_for_data.recv_timeout(TEST_TIMEOUT).unwrap();
        session.close_object_reference(handle).unwrap();
        assert_eq!(retirements.recv_timeout(TEST_TIMEOUT).unwrap(), handle);
        server.join().unwrap();
    }

    #[test]
    fn accepted_guest_tcp_close_with_unread_data_preserves_reset() {
        let provider = Arc::new(LinuxSocketProvider::new(3, 2).unwrap());
        let broker = BrokerCore::new_with_limits(
            PolicyEngine::with_unauthenticated_rights(ObjectRights::all())
                .with_socket_policy(SocketPolicy::Ipv4Loopback),
            BrokerCoreLimits::new_with_all_limits(6, 0, 3, 3),
            provider,
        )
        .unwrap();
        let listener_session = broker
            .create_session(CallerCredential::Unauthenticated)
            .unwrap();
        let connector_session = broker
            .create_session(CallerCredential::Unauthenticated)
            .unwrap();
        let (published, publications) = channel();
        let (retired, retirements) = channel();
        let readiness = Arc::new(TestReadinessSink { published, retired });
        let guest_address = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 8091);
        let listener = create_socket(&listener_session, readiness.clone());
        assert_eq!(
            litebox_broker_core::socket::bind(&listener_session, listener, guest_address),
            Ok(SocketOutcome::Completed(guest_address))
        );
        assert_eq!(
            litebox_broker_core::socket::listen(&listener_session, listener, 1),
            Ok(SocketOutcome::Completed(guest_address))
        );

        let connector = create_socket(&connector_session, readiness.clone());
        assert!(matches!(
            litebox_broker_core::socket::connect(&connector_session, connector, guest_address),
            Ok(SocketOutcome::Completed(
                SocketConnectionStatus::Connecting | SocketConnectionStatus::Connected
            ))
        ));
        wait_until_connected(&connector_session, connector, &publications);
        wait_until_ready(
            &listener_session,
            &publications,
            listener,
            ReadinessFlags::READ,
        );
        let accepted =
            match litebox_broker_core::socket::accept(&listener_session, listener, readiness)
                .unwrap()
            {
                SocketOutcome::Completed(accepted) => accepted.handle,
                SocketOutcome::Failed(error) => panic!("guest accept failed: {error:?}"),
            };
        assert_eq!(
            send_bytes(&listener_session, accepted, b"unread", SendFlags::NONE,),
            Ok(SocketOutcome::Completed(6))
        );
        wait_until_ready(
            &connector_session,
            &publications,
            connector,
            ReadinessFlags::READ,
        );

        connector_session.close_object_reference(connector).unwrap();
        assert_eq!(retirements.recv_timeout(TEST_TIMEOUT).unwrap(), connector);
        wait_until_ready(
            &listener_session,
            &publications,
            accepted,
            ReadinessFlags::READ | ReadinessFlags::ERROR | ReadinessFlags::HANGUP,
        );
        let mut byte = [0_u8; 1];
        assert_eq!(
            receive_into(
                &listener_session,
                accepted,
                &mut byte,
                ReceiveFlags::NONE,
                0,
                0,
            ),
            Ok(SocketOutcome::Failed(SocketError::ConnectionReset))
        );
    }

    #[test]
    fn reactor_assigns_a_port_to_an_unbound_tcp_listener() {
        let provider = Arc::new(LinuxSocketProvider::new(3, 3).unwrap());
        let broker = BrokerCore::new_with_limits(
            PolicyEngine::with_unauthenticated_rights(ObjectRights::all())
                .with_socket_policy(SocketPolicy::Ipv4Loopback),
            BrokerCoreLimits::new_with_all_limits(4, 0, 3, 3),
            provider.clone(),
        )
        .unwrap();
        let session = broker
            .create_session(CallerCredential::Unauthenticated)
            .unwrap();
        let (published, publications) = channel();
        let (retired, _retirements) = channel();
        let readiness = Arc::new(TestReadinessSink { published, retired });
        let listener = create_socket(&session, readiness.clone());

        let local_address = match litebox_broker_core::socket::listen(&session, listener, 1)
            .expect("listen request must succeed")
        {
            SocketOutcome::Completed(address) => address,
            SocketOutcome::Failed(error) => panic!("listen failed: {error:?}"),
        };
        assert_ne!(local_address.port(), 0);
        let private_address = provider
            .reactor
            .host_address(local_address.port())
            .expect("listening socket must have a private host endpoint");
        assert!(private_address.ip().is_loopback());
        assert_ne!(private_address.port(), 0);

        let client = create_socket(&session, readiness.clone());
        assert!(matches!(
            litebox_broker_core::socket::connect(&session, client, local_address),
            Ok(SocketOutcome::Completed(
                SocketConnectionStatus::Connecting | SocketConnectionStatus::Connected
            ))
        ));
        wait_until_connected(&session, client, &publications);
        let client_address = litebox_broker_core::socket::status(&session, client)
            .unwrap()
            .local_address
            .unwrap();
        wait_until_ready(&session, &publications, listener, ReadinessFlags::READ);
        let accepted =
            match litebox_broker_core::socket::accept(&session, listener, readiness).unwrap() {
                SocketOutcome::Completed(accepted) => accepted,
                SocketOutcome::Failed(error) => panic!("accept failed: {error:?}"),
            };
        assert_eq!(accepted.local_address, local_address);
        assert_eq!(accepted.remote_address, client_address);
    }

    #[test]
    fn guest_tcp_namespace_routes_across_sessions_and_hides_private_backend() {
        let provider = Arc::new(LinuxSocketProvider::new(5, 3).unwrap());
        let broker = BrokerCore::new_with_limits(
            PolicyEngine::with_unauthenticated_rights(ObjectRights::all())
                .with_socket_policy(SocketPolicy::Ipv4Loopback),
            BrokerCoreLimits::new_with_all_limits(8, 0, 5, 4),
            provider.clone(),
        )
        .unwrap();
        let listener_session = broker
            .create_session(CallerCredential::Unauthenticated)
            .unwrap();
        let client_session = broker
            .create_session(CallerCredential::Unauthenticated)
            .unwrap();
        let (published, publications) = channel();
        let (retired, retirements) = channel();
        let readiness = Arc::new(TestReadinessSink { published, retired });
        let shadowed_host_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        shadowed_host_listener.set_nonblocking(true).unwrap();
        let guest_port = shadowed_host_listener.local_addr().unwrap().port();
        let guest_address = SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 2), guest_port);
        let guest_destination = SocketAddrV4::new(Ipv4Addr::LOCALHOST, guest_port);
        let listener = create_socket(&listener_session, readiness.clone());
        assert_eq!(
            litebox_broker_core::socket::bind(&listener_session, listener, guest_address),
            Ok(SocketOutcome::Completed(guest_address))
        );
        assert_eq!(provider.reactor.host_address(guest_address.port()), None);

        let early_client = create_socket(&client_session, readiness.clone());
        assert_eq!(
            litebox_broker_core::socket::connect(&client_session, early_client, guest_destination,),
            Ok(SocketOutcome::Completed(SocketConnectionStatus::Failed(
                SocketError::ConnectionRefused,
            )))
        );
        assert_eq!(
            shadowed_host_listener.accept().unwrap_err().kind(),
            ErrorKind::WouldBlock
        );
        client_session.close_object_reference(early_client).unwrap();
        assert_eq!(
            retirements.recv_timeout(TEST_TIMEOUT).unwrap(),
            early_client
        );

        assert_eq!(
            litebox_broker_core::socket::listen(&listener_session, listener, 3),
            Ok(SocketOutcome::Completed(guest_address))
        );
        let private_address = provider
            .reactor
            .host_address(guest_address.port())
            .expect("listener backend must be realized");
        assert!(private_address.ip().is_loopback());
        assert_ne!(private_address, guest_address);

        let direct_client = create_socket(&client_session, readiness.clone());
        assert_eq!(
            litebox_broker_core::socket::connect(&client_session, direct_client, private_address,),
            Ok(SocketOutcome::Completed(SocketConnectionStatus::Failed(
                SocketError::ConnectionRefused,
            )))
        );
        client_session
            .close_object_reference(direct_client)
            .unwrap();
        assert_eq!(
            retirements.recv_timeout(TEST_TIMEOUT).unwrap(),
            direct_client
        );

        let native_client = TcpStream::connect(private_address).unwrap();
        wait_for_readiness(&publications, listener, ReadinessFlags::READ);
        let client = create_socket(&client_session, readiness.clone());
        assert!(matches!(
            litebox_broker_core::socket::connect(&client_session, client, guest_destination),
            Ok(SocketOutcome::Completed(
                SocketConnectionStatus::Connecting | SocketConnectionStatus::Connected
            ))
        ));
        wait_until_connected(&client_session, client, &publications);
        let client_address = litebox_broker_core::socket::status(&client_session, client)
            .unwrap()
            .local_address
            .unwrap();
        let connector_private_address = provider
            .reactor
            .host_address(client_address.port())
            .expect("connector backend must be realized");
        assert_ne!(connector_private_address, client_address);
        let connector_probe = create_socket(&client_session, readiness.clone());
        assert_eq!(
            litebox_broker_core::socket::connect(
                &client_session,
                connector_probe,
                connector_private_address,
            ),
            Ok(SocketOutcome::Completed(SocketConnectionStatus::Failed(
                SocketError::ConnectionRefused,
            )))
        );
        client_session
            .close_object_reference(connector_probe)
            .unwrap();
        assert_eq!(
            retirements.recv_timeout(TEST_TIMEOUT).unwrap(),
            connector_probe
        );
        wait_until_ready(
            &listener_session,
            &publications,
            listener,
            ReadinessFlags::READ,
        );
        let accepted = match litebox_broker_core::socket::accept(
            &listener_session,
            listener,
            readiness.clone(),
        )
        .unwrap()
        {
            SocketOutcome::Completed(accepted) => accepted,
            SocketOutcome::Failed(error) => panic!("accept failed: {error:?}"),
        };
        assert_eq!(accepted.local_address, guest_address);
        assert_eq!(accepted.remote_address, client_address);
        assert_eq!(provider.reactor.pending_guest_connection_count(), 0);
        assert_eq!(provider.reactor.retained_connector_count(), 0);

        assert_eq!(
            send_bytes(&client_session, client, b"x", SendFlags::NONE),
            Ok(SocketOutcome::Completed(1))
        );
        wait_until_ready(
            &listener_session,
            &publications,
            accepted.handle,
            ReadinessFlags::READ,
        );
        let mut byte = [0];
        assert_eq!(
            receive_into(
                &listener_session,
                accepted.handle,
                &mut byte,
                ReceiveFlags::NONE,
                0,
                0,
            ),
            Ok(SocketOutcome::Completed(ReceiveSocketResponse::Received(1)))
        );
        assert_eq!(byte, *b"x");
        assert_eq!(
            shadowed_host_listener.accept().unwrap_err().kind(),
            ErrorKind::WouldBlock
        );
        drop(native_client);
    }

    #[test]
    fn guest_transport_port_collisions_are_broker_wide_and_protocol_separate() {
        let provider = Arc::new(LinuxSocketProvider::new(4, 2).unwrap());
        let broker = BrokerCore::new_with_limits(
            PolicyEngine::with_unauthenticated_rights(ObjectRights::all())
                .with_socket_policy(SocketPolicy::Ipv4Loopback),
            BrokerCoreLimits::new_with_all_limits(4, 0, 4, 2),
            provider.clone(),
        )
        .unwrap();
        let first_session = broker
            .create_session(CallerCredential::Unauthenticated)
            .unwrap();
        let second_session = broker
            .create_session(CallerCredential::Unauthenticated)
            .unwrap();
        let (published, _publications) = channel();
        let (retired, retirements) = channel();
        let readiness = Arc::new(TestReadinessSink { published, retired });
        let first = create_socket(&first_session, readiness.clone());
        let second = create_socket(&second_session, readiness.clone());
        let first_udp = create_udp_socket(&first_session, readiness.clone());
        let second_udp = create_udp_socket(&second_session, readiness);
        let address = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 8081);
        assert_eq!(
            litebox_broker_core::socket::bind(&first_session, first, address),
            Ok(SocketOutcome::Completed(address))
        );
        assert_eq!(
            litebox_broker_core::socket::bind(&second_session, second, address),
            Ok(SocketOutcome::Failed(SocketError::AddressInUse))
        );
        first_session.close_object_reference(first).unwrap();
        assert_eq!(retirements.recv_timeout(TEST_TIMEOUT).unwrap(), first);
        assert_eq!(
            litebox_broker_core::socket::bind(&second_session, second, address),
            Ok(SocketOutcome::Completed(address))
        );
        assert_eq!(
            litebox_broker_core::socket::bind(&first_session, first_udp, address),
            Ok(SocketOutcome::Completed(address))
        );
        assert_eq!(
            litebox_broker_core::socket::bind(&second_session, second_udp, address),
            Ok(SocketOutcome::Failed(SocketError::AddressInUse))
        );
        first_session.close_object_reference(first_udp).unwrap();
        assert_eq!(retirements.recv_timeout(TEST_TIMEOUT).unwrap(), first_udp);
        assert_eq!(
            litebox_broker_core::socket::bind(&second_session, second_udp, address),
            Ok(SocketOutcome::Completed(address))
        );
    }

    #[test]
    fn connector_and_session_teardown_clean_bounded_pending_state() {
        let provider = Arc::new(LinuxSocketProvider::new(3, 1).unwrap());
        let broker = BrokerCore::new_with_limits(
            PolicyEngine::with_unauthenticated_rights(ObjectRights::all())
                .with_socket_policy(SocketPolicy::Ipv4Loopback),
            BrokerCoreLimits::new_with_all_limits(8, 0, 3, 3),
            provider.clone(),
        )
        .unwrap();
        let listener_session = broker
            .create_session(CallerCredential::Unauthenticated)
            .unwrap();
        let connector_session = broker
            .create_session(CallerCredential::Unauthenticated)
            .unwrap();
        let (published, publications) = channel();
        let (retired, retirements) = channel();
        let readiness = Arc::new(TestReadinessSink { published, retired });
        let guest_address = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 8082);
        let listener = create_socket(&listener_session, readiness.clone());
        assert_eq!(
            litebox_broker_core::socket::bind(&listener_session, listener, guest_address),
            Ok(SocketOutcome::Completed(guest_address))
        );
        assert_eq!(
            litebox_broker_core::socket::listen(&listener_session, listener, 2),
            Ok(SocketOutcome::Completed(guest_address))
        );

        let connector = create_socket(&connector_session, readiness.clone());
        assert!(matches!(
            litebox_broker_core::socket::connect(&connector_session, connector, guest_address,),
            Ok(SocketOutcome::Completed(
                SocketConnectionStatus::Connecting | SocketConnectionStatus::Connected
            ))
        ));
        wait_until_connected(&connector_session, connector, &publications);
        connector_session.close_object_reference(connector).unwrap();
        assert_eq!(retirements.recv_timeout(TEST_TIMEOUT).unwrap(), connector);
        assert_eq!(provider.reactor.pending_guest_connection_count(), 1);
        assert_eq!(provider.reactor.retained_connector_count(), 1);
        assert_eq!(
            litebox_broker_core::socket::create(
                &connector_session,
                CreateSocketRequest {
                    address_family: AddressFamily::Ipv4,
                    socket_type: SocketType::Stream,
                    protocol: IpProtocol::Tcp,
                },
                readiness.clone(),
            ),
            Err(BrokerError::ResourceExhausted)
        );
        assert_ne!(retirements.recv_timeout(TEST_TIMEOUT).unwrap(), listener);

        drop(connector_session);
        assert_eq!(provider.reactor.pending_guest_connection_count(), 1);
        assert_eq!(provider.reactor.retained_connector_count(), 0);
        provider.reactor.expire_pending_guest_connections();
        assert_eq!(provider.reactor.pending_guest_connection_count(), 0);

        let blocked_connector_session = broker
            .create_session(CallerCredential::Unauthenticated)
            .unwrap();
        let blocked_connector = create_socket(&blocked_connector_session, readiness.clone());
        assert_eq!(
            litebox_broker_core::socket::connect(
                &blocked_connector_session,
                blocked_connector,
                guest_address,
            ),
            Ok(SocketOutcome::Completed(SocketConnectionStatus::Failed(
                SocketError::ConnectionRefused
            )))
        );
        blocked_connector_session
            .close_object_reference(blocked_connector)
            .unwrap();
        assert_eq!(
            retirements.recv_timeout(TEST_TIMEOUT).unwrap(),
            blocked_connector
        );

        wait_until_ready(
            &listener_session,
            &publications,
            listener,
            ReadinessFlags::READ,
        );
        assert!(matches!(
            litebox_broker_core::socket::accept(&listener_session, listener, readiness.clone(),),
            Err(BrokerError::WouldBlock)
        ));
        assert_ne!(retirements.recv_timeout(TEST_TIMEOUT).unwrap(), listener);

        let final_connector_session = broker
            .create_session(CallerCredential::Unauthenticated)
            .unwrap();
        let final_connector = create_socket(&final_connector_session, readiness);
        assert!(matches!(
            litebox_broker_core::socket::connect(
                &final_connector_session,
                final_connector,
                guest_address,
            ),
            Ok(SocketOutcome::Completed(
                SocketConnectionStatus::Connecting | SocketConnectionStatus::Connected
            ))
        ));
        wait_until_connected(&final_connector_session, final_connector, &publications);
        assert_eq!(provider.reactor.pending_guest_connection_count(), 1);
        listener_session.close_object_reference(listener).unwrap();
        assert_eq!(retirements.recv_timeout(TEST_TIMEOUT).unwrap(), listener);
        assert_eq!(provider.reactor.pending_guest_connection_count(), 0);
        assert_eq!(provider.reactor.retained_connector_count(), 0);
    }

    #[test]
    fn graceful_connector_close_preserves_late_accept_and_eof() {
        let provider = Arc::new(LinuxSocketProvider::new(4, 2).unwrap());
        let broker = BrokerCore::new_with_limits(
            PolicyEngine::with_unauthenticated_rights(ObjectRights::all())
                .with_socket_policy(SocketPolicy::Ipv4Loopback),
            BrokerCoreLimits::new_with_all_limits(8, 0, 4, 4),
            provider.clone(),
        )
        .unwrap();
        let listener_session = broker
            .create_session(CallerCredential::Unauthenticated)
            .unwrap();
        let connector_session = broker
            .create_session(CallerCredential::Unauthenticated)
            .unwrap();
        let (published, publications) = channel();
        let (retired, retirements) = channel();
        let readiness = Arc::new(TestReadinessSink { published, retired });
        let guest_address = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 8089);
        let listener = create_socket(&listener_session, readiness.clone());
        assert_eq!(
            litebox_broker_core::socket::bind(&listener_session, listener, guest_address),
            Ok(SocketOutcome::Completed(guest_address))
        );
        assert_eq!(
            litebox_broker_core::socket::listen(&listener_session, listener, 1),
            Ok(SocketOutcome::Completed(guest_address))
        );

        let connector = create_socket(&connector_session, readiness.clone());
        assert!(matches!(
            litebox_broker_core::socket::connect(&connector_session, connector, guest_address,),
            Ok(SocketOutcome::Completed(
                SocketConnectionStatus::Connecting | SocketConnectionStatus::Connected
            ))
        ));
        wait_until_connected(&connector_session, connector, &publications);
        let connector_address = litebox_broker_core::socket::status(&connector_session, connector)
            .unwrap()
            .local_address
            .unwrap();

        connector_session.close_object_reference(connector).unwrap();
        assert_eq!(retirements.recv_timeout(TEST_TIMEOUT).unwrap(), connector);
        assert_eq!(provider.reactor.retained_connector_count(), 1);
        wait_until_ready(
            &listener_session,
            &publications,
            listener,
            ReadinessFlags::READ,
        );

        let accepted =
            match litebox_broker_core::socket::accept(&listener_session, listener, readiness)
                .unwrap()
            {
                SocketOutcome::Completed(accepted) => accepted,
                SocketOutcome::Failed(error) => panic!("late accept failed: {error:?}"),
            };
        assert_eq!(accepted.remote_address, connector_address);
        assert_eq!(provider.reactor.pending_guest_connection_count(), 0);
        assert_eq!(provider.reactor.retained_connector_count(), 0);
        wait_for_end_of_stream(&listener_session, accepted.handle, &publications);
    }

    #[test]
    fn abortive_connector_close_releases_descriptor_capacity() {
        let provider = Arc::new(LinuxSocketProvider::new(3, 1).unwrap());
        let broker = BrokerCore::new_with_limits(
            PolicyEngine::with_unauthenticated_rights(ObjectRights::all())
                .with_socket_policy(SocketPolicy::Ipv4Loopback),
            BrokerCoreLimits::new_with_all_limits(8, 0, 3, 3),
            provider.clone(),
        )
        .unwrap();
        let listener_session = broker
            .create_session(CallerCredential::Unauthenticated)
            .unwrap();
        let connector_session = broker
            .create_session(CallerCredential::Unauthenticated)
            .unwrap();
        let (published, publications) = channel();
        let (retired, retirements) = channel();
        let readiness = Arc::new(TestReadinessSink { published, retired });
        let guest_address = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 8086);
        let listener = create_socket(&listener_session, readiness.clone());
        assert_eq!(
            litebox_broker_core::socket::bind(&listener_session, listener, guest_address),
            Ok(SocketOutcome::Completed(guest_address))
        );
        assert_eq!(
            litebox_broker_core::socket::listen(&listener_session, listener, 1),
            Ok(SocketOutcome::Completed(guest_address))
        );

        let connector = create_socket(&connector_session, readiness.clone());
        assert!(matches!(
            litebox_broker_core::socket::connect(&connector_session, connector, guest_address,),
            Ok(SocketOutcome::Completed(
                SocketConnectionStatus::Connecting | SocketConnectionStatus::Connected
            ))
        ));
        wait_until_connected(&connector_session, connector, &publications);
        assert_eq!(
            litebox_broker_core::socket::shutdown(
                &connector_session,
                connector,
                ShutdownMode::Abort,
            ),
            Ok(SocketOutcome::Completed(()))
        );
        connector_session.close_object_reference(connector).unwrap();
        assert_eq!(retirements.recv_timeout(TEST_TIMEOUT).unwrap(), connector);
        assert_eq!(provider.reactor.pending_guest_connection_count(), 1);
        assert_eq!(provider.reactor.retained_connector_count(), 0);

        provider.reactor.expire_pending_guest_connections();
        assert_eq!(provider.reactor.pending_guest_connection_count(), 0);
        assert_eq!(provider.reactor.retained_connector_count(), 0);

        let replacement = create_socket(&connector_session, readiness.clone());
        assert_eq!(
            litebox_broker_core::socket::connect(&connector_session, replacement, guest_address,),
            Ok(SocketOutcome::Completed(SocketConnectionStatus::Failed(
                SocketError::ConnectionRefused
            )))
        );
        connector_session
            .close_object_reference(replacement)
            .unwrap();
        assert_eq!(retirements.recv_timeout(TEST_TIMEOUT).unwrap(), replacement);

        loop {
            match litebox_broker_core::socket::accept(
                &listener_session,
                listener,
                readiness.clone(),
            ) {
                Err(BrokerError::WouldBlock) => break,
                Ok(SocketOutcome::Failed(
                    SocketError::ConnectionAborted | SocketError::ConnectionReset,
                )) => {}
                _ => panic!("unexpected stale accept outcome"),
            }
        }

        let final_connector = create_socket(&connector_session, readiness);
        assert!(matches!(
            litebox_broker_core::socket::connect(
                &connector_session,
                final_connector,
                guest_address,
            ),
            Ok(SocketOutcome::Completed(
                SocketConnectionStatus::Connecting | SocketConnectionStatus::Connected
            ))
        ));
        wait_until_connected(&connector_session, final_connector, &publications);
    }

    #[test]
    fn accept_bounds_unmatched_private_connections_per_command() {
        let provider = Arc::new(LinuxSocketProvider::new(3, 2).unwrap());
        let broker = BrokerCore::new_with_limits(
            PolicyEngine::with_unauthenticated_rights(ObjectRights::all())
                .with_socket_policy(SocketPolicy::Ipv4Loopback),
            BrokerCoreLimits::new_with_all_limits(8, 0, 3, 3),
            provider.clone(),
        )
        .unwrap();
        let listener_session = broker
            .create_session(CallerCredential::Unauthenticated)
            .unwrap();
        let connector_session = broker
            .create_session(CallerCredential::Unauthenticated)
            .unwrap();
        let (published, publications) = channel();
        let (retired, _retirements) = channel();
        let readiness = Arc::new(TestReadinessSink { published, retired });
        let guest_address = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 8087);
        let listener = create_socket(&listener_session, readiness.clone());
        assert_eq!(
            litebox_broker_core::socket::bind(&listener_session, listener, guest_address),
            Ok(SocketOutcome::Completed(guest_address))
        );
        let unmatched_connection_count = MAX_UNMATCHED_ACCEPTS_PER_COMMAND;
        assert_eq!(
            litebox_broker_core::socket::listen(
                &listener_session,
                listener,
                u32::try_from(unmatched_connection_count + 2).unwrap(),
            ),
            Ok(SocketOutcome::Completed(guest_address))
        );
        let private_address = provider.reactor.host_address(guest_address.port()).unwrap();
        let _unmatched_connections = (0..unmatched_connection_count)
            .map(|_| TcpStream::connect(private_address).unwrap())
            .collect::<Vec<_>>();

        let connector = create_socket(&connector_session, readiness.clone());
        assert!(matches!(
            litebox_broker_core::socket::connect(&connector_session, connector, guest_address,),
            Ok(SocketOutcome::Completed(
                SocketConnectionStatus::Connecting | SocketConnectionStatus::Connected
            ))
        ));
        wait_until_connected(&connector_session, connector, &publications);
        let connector_address = litebox_broker_core::socket::status(&connector_session, connector)
            .unwrap()
            .local_address
            .unwrap();
        wait_until_ready(
            &listener_session,
            &publications,
            listener,
            ReadinessFlags::READ,
        );

        assert!(matches!(
            litebox_broker_core::socket::accept(&listener_session, listener, readiness.clone(),),
            Err(BrokerError::WouldBlock)
        ));
        assert!(
            listener_session
                .check_readiness(listener)
                .unwrap()
                .contains(ReadinessFlags::READ)
        );
        wait_for_readiness(&publications, listener, ReadinessFlags::READ);
        let accepted =
            match litebox_broker_core::socket::accept(&listener_session, listener, readiness)
                .unwrap()
            {
                SocketOutcome::Completed(accepted) => accepted,
                SocketOutcome::Failed(error) => panic!("guest accept failed: {error:?}"),
            };
        assert_eq!(accepted.remote_address, connector_address);
    }

    #[test]
    fn accept_preserves_a_queued_connection_when_retained_capacity_is_unrelated() {
        let provider = Arc::new(LinuxSocketProvider::new(4, 4).unwrap());
        let broker = BrokerCore::new_with_limits(
            PolicyEngine::with_unauthenticated_rights(ObjectRights::all())
                .with_socket_policy(SocketPolicy::Ipv4Loopback),
            BrokerCoreLimits::new_with_all_limits(8, 0, 5, 5),
            provider.clone(),
        )
        .unwrap();
        let target_listener_session = broker
            .create_session(CallerCredential::Unauthenticated)
            .unwrap();
        let target_connector_session = broker
            .create_session(CallerCredential::Unauthenticated)
            .unwrap();
        let other_listener_session = broker
            .create_session(CallerCredential::Unauthenticated)
            .unwrap();
        let other_connector_session = broker
            .create_session(CallerCredential::Unauthenticated)
            .unwrap();
        let (published, publications) = channel();
        let (retired, _retirements) = channel();
        let readiness = Arc::new(TestReadinessSink { published, retired });
        let target_address = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 8084);
        let other_address = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 8085);

        let target_listener = create_socket(&target_listener_session, readiness.clone());
        let other_listener = create_socket(&other_listener_session, readiness.clone());
        for (session, listener, address) in [
            (&target_listener_session, target_listener, target_address),
            (&other_listener_session, other_listener, other_address),
        ] {
            assert_eq!(
                litebox_broker_core::socket::bind(session, listener, address),
                Ok(SocketOutcome::Completed(address))
            );
            assert_eq!(
                litebox_broker_core::socket::listen(session, listener, 1),
                Ok(SocketOutcome::Completed(address))
            );
        }

        let target_connector = create_socket(&target_connector_session, readiness.clone());
        let other_connector = create_socket(&other_connector_session, readiness.clone());
        for (session, connector, address) in [
            (&target_connector_session, target_connector, target_address),
            (&other_connector_session, other_connector, other_address),
        ] {
            assert!(matches!(
                litebox_broker_core::socket::connect(session, connector, address),
                Ok(SocketOutcome::Completed(
                    SocketConnectionStatus::Connecting | SocketConnectionStatus::Connected
                ))
            ));
            wait_until_connected(session, connector, &publications);
        }
        let target_connector_address =
            litebox_broker_core::socket::status(&target_connector_session, target_connector)
                .unwrap()
                .local_address
                .unwrap();
        other_connector_session
            .close_object_reference(other_connector)
            .unwrap();
        assert_eq!(provider.reactor.pending_guest_connection_count(), 2);
        assert_eq!(provider.reactor.retained_connector_count(), 1);

        let deadline = Instant::now() + TEST_TIMEOUT;
        while !target_listener_session
            .check_readiness(target_listener)
            .unwrap()
            .contains(ReadinessFlags::READ)
        {
            assert!(
                Instant::now() < deadline,
                "target listener did not become ready"
            );
            std::thread::yield_now();
        }
        assert!(matches!(
            litebox_broker_core::socket::accept(
                &target_listener_session,
                target_listener,
                readiness.clone(),
            ),
            Err(BrokerError::ResourceExhausted)
        ));
        assert_eq!(provider.reactor.pending_guest_connection_count(), 2);

        other_listener_session
            .close_object_reference(other_listener)
            .unwrap();
        assert_eq!(provider.reactor.pending_guest_connection_count(), 1);
        assert_eq!(provider.reactor.retained_connector_count(), 0);
        let accepted = match litebox_broker_core::socket::accept(
            &target_listener_session,
            target_listener,
            readiness,
        )
        .unwrap()
        {
            SocketOutcome::Completed(accepted) => accepted,
            SocketOutcome::Failed(error) => panic!("target accept failed: {error:?}"),
        };
        assert_eq!(accepted.remote_address, target_connector_address);
    }

    #[test]
    fn stopped_listener_retains_guest_binding_until_close() {
        let provider = Arc::new(LinuxSocketProvider::new(2, 2).unwrap());
        let broker = BrokerCore::new_with_limits(
            PolicyEngine::with_unauthenticated_rights(ObjectRights::all())
                .with_socket_policy(SocketPolicy::Ipv4Loopback),
            BrokerCoreLimits::new_with_all_limits(4, 0, 2, 2),
            provider.clone(),
        )
        .unwrap();
        let session = broker
            .create_session(CallerCredential::Unauthenticated)
            .unwrap();
        let (published, publications) = channel();
        let (retired, retirements) = channel();
        let readiness = Arc::new(TestReadinessSink { published, retired });
        let guest_address = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 8083);
        let listener = create_socket(&session, readiness.clone());
        assert_eq!(
            litebox_broker_core::socket::bind(&session, listener, guest_address),
            Ok(SocketOutcome::Completed(guest_address))
        );
        assert_eq!(
            litebox_broker_core::socket::listen(&session, listener, 1),
            Ok(SocketOutcome::Completed(guest_address))
        );
        let private_address = provider.reactor.host_address(guest_address.port()).unwrap();
        let connector = create_socket(&session, readiness.clone());
        assert!(matches!(
            litebox_broker_core::socket::connect(&session, connector, guest_address),
            Ok(SocketOutcome::Completed(
                SocketConnectionStatus::Connecting | SocketConnectionStatus::Connected
            ))
        ));
        wait_until_connected(&session, connector, &publications);
        assert_eq!(provider.reactor.pending_guest_connection_count(), 1);

        assert_eq!(
            litebox_broker_core::socket::shutdown(&session, listener, ShutdownMode::StopListening,),
            Ok(SocketOutcome::Completed(()))
        );
        assert_eq!(provider.reactor.pending_guest_connection_count(), 0);
        assert_eq!(
            provider.reactor.host_address(guest_address.port()),
            Some(private_address)
        );
        session.close_object_reference(connector).unwrap();
        assert_eq!(retirements.recv_timeout(TEST_TIMEOUT).unwrap(), connector);

        let refused = create_socket(&session, readiness);
        assert_eq!(
            litebox_broker_core::socket::connect(&session, refused, guest_address),
            Ok(SocketOutcome::Completed(SocketConnectionStatus::Failed(
                SocketError::ConnectionRefused,
            )))
        );
        session.close_object_reference(refused).unwrap();
        assert_eq!(retirements.recv_timeout(TEST_TIMEOUT).unwrap(), refused);
        session.close_object_reference(listener).unwrap();
        assert_eq!(retirements.recv_timeout(TEST_TIMEOUT).unwrap(), listener);
        assert_eq!(provider.reactor.host_address(guest_address.port()), None);
    }

    #[test]
    fn stop_listening_cleanup_survives_readiness_failure() {
        let provider = Arc::new(LinuxSocketProvider::new(3, 1).unwrap());
        let broker = BrokerCore::new_with_limits(
            PolicyEngine::with_unauthenticated_rights(ObjectRights::all())
                .with_socket_policy(SocketPolicy::Ipv4Loopback),
            BrokerCoreLimits::new_with_all_limits(8, 0, 3, 3),
            provider.clone(),
        )
        .unwrap();
        let listener_session = broker
            .create_session(CallerCredential::Unauthenticated)
            .unwrap();
        let connector_session = broker
            .create_session(CallerCredential::Unauthenticated)
            .unwrap();
        let (published, publications) = channel();
        let (retired, retirements) = channel();
        let readiness = Arc::new(FailingReadinessSink {
            inner: TestReadinessSink { published, retired },
            fail_next_publish: Mutex::new(None),
        });
        let guest_address = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 8088);
        let listener = create_socket(&listener_session, readiness.clone());
        assert_eq!(
            litebox_broker_core::socket::bind(&listener_session, listener, guest_address),
            Ok(SocketOutcome::Completed(guest_address))
        );
        assert_eq!(
            litebox_broker_core::socket::listen(&listener_session, listener, 1),
            Ok(SocketOutcome::Completed(guest_address))
        );

        let connector = create_socket(&connector_session, readiness.clone());
        assert!(matches!(
            litebox_broker_core::socket::connect(&connector_session, connector, guest_address,),
            Ok(SocketOutcome::Completed(
                SocketConnectionStatus::Connecting | SocketConnectionStatus::Connected
            ))
        ));
        wait_until_connected(&connector_session, connector, &publications);
        wait_until_ready(
            &listener_session,
            &publications,
            listener,
            ReadinessFlags::READ,
        );
        connector_session.close_object_reference(connector).unwrap();
        assert_eq!(retirements.recv_timeout(TEST_TIMEOUT).unwrap(), connector);
        assert_eq!(provider.reactor.pending_guest_connection_count(), 1);
        assert_eq!(provider.reactor.retained_connector_count(), 1);

        readiness.fail_next_publish_for(listener);
        assert_eq!(
            litebox_broker_core::socket::shutdown(
                &listener_session,
                listener,
                ShutdownMode::StopListening,
            ),
            Ok(SocketOutcome::Completed(()))
        );
        assert_eq!(provider.reactor.pending_guest_connection_count(), 0);
        assert_eq!(provider.reactor.retained_connector_count(), 0);
        assert_eq!(
            litebox_broker_core::socket::listen(&listener_session, listener, 1),
            Ok(SocketOutcome::Failed(SocketError::InvalidArgument))
        );

        listener_session.close_object_reference(listener).unwrap();
        assert_eq!(retirements.recv_timeout(TEST_TIMEOUT).unwrap(), listener);
        assert_eq!(provider.reactor.pending_guest_connection_count(), 0);
        assert_eq!(provider.reactor.retained_connector_count(), 0);
    }

    #[test]
    fn reactor_drives_a_loopback_tcp_listener() {
        let provider = Arc::new(LinuxSocketProvider::new(6, 6).unwrap());
        let broker = BrokerCore::new_with_limits(
            PolicyEngine::with_unauthenticated_rights(ObjectRights::all())
                .with_socket_policy(SocketPolicy::Ipv4Loopback),
            BrokerCoreLimits::new_with_all_limits(8, 0, 6, 6),
            provider,
        )
        .unwrap();
        let session = broker
            .create_session(CallerCredential::Unauthenticated)
            .unwrap();
        let (published, publications) = channel();
        let (retired, retirements) = channel();
        let readiness = Arc::new(TestReadinessSink { published, retired });
        let listener = create_socket(&session, readiness.clone());
        let requested_address = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0);
        let local_address =
            match litebox_broker_core::socket::bind(&session, listener, requested_address).unwrap()
            {
                SocketOutcome::Completed(address) => address,
                SocketOutcome::Failed(error) => panic!("bind failed: {error:?}"),
            };
        assert_eq!(local_address.ip(), requested_address.ip());
        assert_ne!(local_address.port(), 0);
        assert_eq!(
            litebox_broker_core::socket::listen(&session, listener, 8),
            Ok(SocketOutcome::Completed(local_address))
        );
        assert_eq!(
            litebox_broker_core::socket::shutdown(&session, listener, ShutdownMode::Write),
            Ok(SocketOutcome::Failed(SocketError::NotConnected))
        );
        assert!(matches!(
            litebox_broker_core::socket::accept(&session, listener, readiness.clone()),
            Err(BrokerError::WouldBlock)
        ));
        let failed_accept_handle = retirements.recv_timeout(TEST_TIMEOUT).unwrap();
        assert_ne!(failed_accept_handle, listener);
        assert!(
            !session
                .check_readiness(listener)
                .unwrap()
                .contains(ReadinessFlags::READ)
        );

        let first_client = create_socket(&session, readiness.clone());
        let second_client = create_socket(&session, readiness.clone());
        for client in [first_client, second_client] {
            assert!(matches!(
                litebox_broker_core::socket::connect(&session, client, local_address),
                Ok(SocketOutcome::Completed(
                    SocketConnectionStatus::Connecting | SocketConnectionStatus::Connected
                ))
            ));
            wait_until_connected(&session, client, &publications);
        }
        let first_client_address = litebox_broker_core::socket::status(&session, first_client)
            .unwrap()
            .local_address
            .unwrap();
        let second_client_address = litebox_broker_core::socket::status(&session, second_client)
            .unwrap()
            .local_address
            .unwrap();
        wait_until_ready(&session, &publications, listener, ReadinessFlags::READ);
        assert_eq!(
            litebox_broker_core::socket::listen(&session, listener, 4),
            Ok(SocketOutcome::Completed(local_address))
        );

        let first = match litebox_broker_core::socket::accept(&session, listener, readiness.clone())
            .unwrap()
        {
            SocketOutcome::Completed(accepted) => accepted,
            SocketOutcome::Failed(error) => panic!("first accept failed: {error:?}"),
        };
        assert_eq!(first.local_address, local_address);
        assert_eq!(first.remote_address, first_client_address);
        assert!(
            session
                .check_readiness(listener)
                .unwrap()
                .contains(ReadinessFlags::READ),
            "accept must preserve listener readiness until the queue is observed empty"
        );

        let second =
            match litebox_broker_core::socket::accept(&session, listener, readiness.clone())
                .unwrap()
            {
                SocketOutcome::Completed(accepted) => accepted,
                SocketOutcome::Failed(error) => panic!("second accept failed: {error:?}"),
            };
        assert_eq!(second.local_address, local_address);
        assert_eq!(second.remote_address, second_client_address);
        assert!(
            !session
                .check_readiness(listener)
                .unwrap()
                .contains(ReadinessFlags::READ),
            "accept must clear listener readiness after draining the queue"
        );
        assert!(matches!(
            litebox_broker_core::socket::accept(&session, listener, readiness.clone()),
            Err(BrokerError::WouldBlock)
        ));
        assert!(
            !session
                .check_readiness(listener)
                .unwrap()
                .contains(ReadinessFlags::READ)
        );

        assert_eq!(
            send_bytes(&session, first_client, b"request", SendFlags::NONE),
            Ok(SocketOutcome::Completed(7))
        );
        let mut request = [0_u8; 7];
        loop {
            match receive_into(
                &session,
                first.handle,
                &mut request,
                ReceiveFlags::NONE,
                0,
                0,
            ) {
                Ok(SocketOutcome::Completed(ReceiveSocketResponse::Received(7))) => break,
                Err(BrokerError::WouldBlock) => {
                    wait_until_ready(&session, &publications, first.handle, ReadinessFlags::READ);
                }
                outcome => panic!("unexpected accepted receive outcome: {outcome:?}"),
            }
        }
        assert_eq!(&request, b"request");
        assert_eq!(
            send_bytes(&session, first.handle, b"response", SendFlags::NONE,),
            Ok(SocketOutcome::Completed(8))
        );
        let mut response = [0_u8; 8];
        loop {
            match receive_into(
                &session,
                first_client,
                &mut response,
                ReceiveFlags::NONE,
                0,
                0,
            ) {
                Ok(SocketOutcome::Completed(ReceiveSocketResponse::Received(8))) => break,
                Err(BrokerError::WouldBlock) => {
                    wait_until_ready(&session, &publications, first_client, ReadinessFlags::READ);
                }
                outcome => panic!("unexpected client receive outcome: {outcome:?}"),
            }
        }
        assert_eq!(&response, b"response");
        assert_eq!(
            litebox_broker_core::socket::shutdown(&session, listener, ShutdownMode::StopListening,),
            Ok(SocketOutcome::Completed(()))
        );
        wait_until_ready(&session, &publications, listener, ReadinessFlags::HANGUP);
        assert!(
            session
                .check_readiness(listener)
                .unwrap()
                .contains(ReadinessFlags::HANGUP)
        );
        assert!(matches!(
            litebox_broker_core::socket::accept(&session, listener, readiness.clone()),
            Ok(SocketOutcome::Failed(SocketError::NotConnected))
        ));
        session.close_object_reference(first.handle).unwrap();
        drop(session);
        let expected = [first.handle, second.handle, listener];
        let deadline = Instant::now() + TEST_TIMEOUT;
        let mut observed = std::vec::Vec::new();
        while expected.iter().any(|handle| !observed.contains(handle)) {
            let remaining = deadline
                .checked_duration_since(Instant::now())
                .expect("timed out waiting for listener retirements");
            observed.push(retirements.recv_timeout(remaining).unwrap());
        }
    }

    #[test]
    fn guest_udp_readiness_failure_rolls_back_enqueue() {
        let provider = Arc::new(LinuxSocketProvider::new(2, 1).unwrap());
        let broker = BrokerCore::new_with_limits(
            PolicyEngine::with_unauthenticated_rights(ObjectRights::all())
                .with_socket_policy(SocketPolicy::Ipv4Loopback),
            BrokerCoreLimits::new_with_all_limits(4, 0, 2, 1),
            provider.clone(),
        )
        .unwrap();
        let receiver_session = broker
            .create_session(CallerCredential::Unauthenticated)
            .unwrap();
        let sender_session = broker
            .create_session(CallerCredential::Unauthenticated)
            .unwrap();
        let (published, _publications) = channel();
        let (retired, _retirements) = channel();
        let readiness = Arc::new(FailingReadinessSink {
            inner: TestReadinessSink { published, retired },
            fail_next_publish: Mutex::new(None),
        });
        let receiver = create_udp_socket(&receiver_session, readiness.clone());
        let receiver_address = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 18100);
        assert_eq!(
            litebox_broker_core::socket::bind(&receiver_session, receiver, receiver_address,),
            Ok(SocketOutcome::Completed(receiver_address))
        );
        let sender = create_udp_socket(&sender_session, readiness.clone());

        readiness.fail_next_publish_for(receiver);
        assert_eq!(
            send_datagram(
                &sender_session,
                sender,
                b"dropped",
                SendFlags::NONE,
                Some(receiver_address),
            ),
            Ok(SocketOutcome::Completed(7))
        );
        assert_eq!(provider.reactor.udp_queued_datagram_count(), 0);
        let mut data = [0; 7];
        assert_eq!(
            receive_datagram_into(
                &receiver_session,
                receiver,
                &mut data,
                ReceiveFromFlags::NONE,
            ),
            Err(BrokerError::WouldBlock)
        );

        assert_eq!(
            send_datagram(
                &sender_session,
                sender,
                b"queued",
                SendFlags::NONE,
                Some(receiver_address),
            ),
            Ok(SocketOutcome::Completed(6))
        );
        assert_eq!(provider.reactor.udp_queued_datagram_count(), 1);
    }

    #[test]
    fn guest_udp_receive_survives_readiness_publication_failure() {
        let provider = Arc::new(LinuxSocketProvider::new(2, 1).unwrap());
        let broker = BrokerCore::new_with_limits(
            PolicyEngine::with_unauthenticated_rights(ObjectRights::all())
                .with_socket_policy(SocketPolicy::Ipv4Loopback),
            BrokerCoreLimits::new_with_all_limits(4, 0, 2, 1),
            provider.clone(),
        )
        .unwrap();
        let receiver_session = broker
            .create_session(CallerCredential::Unauthenticated)
            .unwrap();
        let sender_session = broker
            .create_session(CallerCredential::Unauthenticated)
            .unwrap();
        let (published, _publications) = channel();
        let (retired, _retirements) = channel();
        let readiness = Arc::new(FailingReadinessSink {
            inner: TestReadinessSink { published, retired },
            fail_next_publish: Mutex::new(None),
        });
        let receiver = create_udp_socket(&receiver_session, readiness.clone());
        let receiver_address = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 18101);
        assert_eq!(
            litebox_broker_core::socket::bind(&receiver_session, receiver, receiver_address,),
            Ok(SocketOutcome::Completed(receiver_address))
        );
        let sender = create_udp_socket(&sender_session, readiness.clone());
        assert_eq!(
            send_datagram(
                &sender_session,
                sender,
                b"queued",
                SendFlags::NONE,
                Some(receiver_address),
            ),
            Ok(SocketOutcome::Completed(6))
        );
        let sender_address = litebox_broker_core::socket::status(&sender_session, sender)
            .unwrap()
            .local_address
            .map(|address| SocketAddrV4::new(Ipv4Addr::LOCALHOST, address.port()))
            .unwrap();

        readiness.fail_next_publish_for(receiver);
        let mut data = [0; 6];
        assert_eq!(
            receive_datagram_into(
                &receiver_session,
                receiver,
                &mut data,
                ReceiveFromFlags::NONE,
            ),
            Ok(SocketOutcome::Completed(ReceivedPlatformDatagram {
                received: 6,
                datagram_length: 6,
                source_address: sender_address,
            }))
        );
        assert_eq!(&data, b"queued");
        assert_eq!(provider.reactor.udp_queued_datagram_count(), 0);
        assert!(
            !receiver_session
                .check_readiness(receiver)
                .unwrap()
                .contains(ReadinessFlags::READ)
        );
    }

    #[test]
    fn native_udp_readiness_failure_does_not_fail_shared_reactor() {
        let provider = Arc::new(LinuxSocketProvider::new(2, 2).unwrap());
        let broker = BrokerCore::new_with_limits(
            PolicyEngine::with_unauthenticated_rights(ObjectRights::all())
                .with_socket_policy(SocketPolicy::Ipv4Loopback),
            BrokerCoreLimits::new_with_all_limits(4, 0, 2, 2),
            provider,
        )
        .unwrap();
        let session = broker
            .create_session(CallerCredential::Unauthenticated)
            .unwrap();
        let (published, publications) = channel();
        let (retired, _retirements) = channel();
        let readiness = Arc::new(FailingReadinessSink {
            inner: TestReadinessSink { published, retired },
            fail_next_publish: Mutex::new(None),
        });
        let socket = create_udp_socket(&session, readiness.clone());
        let external = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        external.set_read_timeout(Some(TEST_TIMEOUT)).unwrap();
        let external_address = socket_address_v4(external.local_addr().unwrap());
        assert_eq!(
            send_datagram(
                &session,
                socket,
                b"contact",
                SendFlags::NONE,
                Some(external_address),
            ),
            Ok(SocketOutcome::Completed(7))
        );
        let mut contact = [0; 7];
        let (_, native_address) = external.recv_from(&mut contact).unwrap();
        assert_eq!(&contact, b"contact");

        readiness.fail_next_publish_for(socket);
        external.send_to(b"reply", native_address).unwrap();
        let deadline = Instant::now() + TEST_TIMEOUT;
        while !session
            .check_readiness(socket)
            .unwrap()
            .contains(ReadinessFlags::READ)
        {
            assert!(
                Instant::now() < deadline,
                "timed out waiting for cached native UDP readiness"
            );
            thread::sleep(Duration::from_millis(1));
        }
        readiness.fail_next_publish_for(socket);
        let mut reply = [0; 5];
        assert_eq!(
            receive_datagram_into(&session, socket, &mut reply, ReceiveFromFlags::NONE,),
            Ok(SocketOutcome::Completed(ReceivedPlatformDatagram {
                received: 5,
                datagram_length: 5,
                source_address: external_address,
            }))
        );
        assert_eq!(&reply, b"reply");
        assert!(
            !session
                .check_readiness(socket)
                .unwrap()
                .contains(ReadinessFlags::READ)
        );

        external.send_to(b"first", native_address).unwrap();
        external.send_to(b"second", native_address).unwrap();
        wait_until_ready(&session, &publications, socket, ReadinessFlags::READ);
        readiness.fail_next_publish_for(socket);
        for (index, expected) in [b"first".as_slice(), b"second".as_slice()]
            .into_iter()
            .enumerate()
        {
            let mut data = [0; 6];
            assert_eq!(
                receive_datagram_into(
                    &session,
                    socket,
                    &mut data[..expected.len()],
                    ReceiveFromFlags::NONE,
                ),
                Ok(SocketOutcome::Completed(ReceivedPlatformDatagram {
                    received: expected.len(),
                    datagram_length: expected.len(),
                    source_address: external_address,
                }))
            );
            assert_eq!(&data[..expected.len()], expected);
            if index == 0 {
                assert!(
                    session
                        .check_readiness(socket)
                        .unwrap()
                        .contains(ReadinessFlags::READ)
                );
            }
        }
        assert!(
            !session
                .check_readiness(socket)
                .unwrap()
                .contains(ReadinessFlags::READ)
        );
    }

    #[test]
    fn udp_status_publication_failure_still_rearms_native_endpoint() {
        let provider = Arc::new(LinuxSocketProvider::new(1, 1).unwrap());
        let broker = BrokerCore::new_with_limits(
            PolicyEngine::with_unauthenticated_rights(ObjectRights::all())
                .with_socket_policy(SocketPolicy::Ipv4Loopback),
            BrokerCoreLimits::new_with_all_limits(2, 0, 1, 1),
            provider,
        )
        .unwrap();
        let session = broker
            .create_session(CallerCredential::Unauthenticated)
            .unwrap();
        let (published, publications) = channel();
        let (retired, _retirements) = channel();
        let readiness = Arc::new(FailingReadinessSink {
            inner: TestReadinessSink { published, retired },
            fail_next_publish: Mutex::new(None),
        });
        let socket = create_udp_socket(&session, readiness.clone());
        let refused = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let refused_address = socket_address_v4(refused.local_addr().unwrap());
        drop(refused);
        assert_eq!(
            litebox_broker_core::socket::connect(&session, socket, refused_address),
            Ok(SocketOutcome::Completed(SocketConnectionStatus::Connected))
        );
        let local_address = litebox_broker_core::socket::status(&session, socket)
            .unwrap()
            .local_address;
        assert_eq!(
            send_datagram(&session, socket, b"first", SendFlags::NONE, None),
            Ok(SocketOutcome::Completed(5))
        );
        wait_until_ready(&session, &publications, socket, ReadinessFlags::ERROR);

        readiness.fail_next_publishes_for(socket, 2);
        assert_eq!(
            litebox_broker_core::socket::status(&session, socket),
            Ok(SocketStatusResponse {
                status: SocketConnectionStatus::Connected,
                local_address,
                pending_error: Some(SocketError::ConnectionRefused),
            })
        );
        assert!(
            !session
                .check_readiness(socket)
                .unwrap()
                .contains(ReadinessFlags::ERROR)
        );

        assert_eq!(
            send_datagram(&session, socket, b"second", SendFlags::NONE, None),
            Ok(SocketOutcome::Completed(6))
        );
        let deadline = Instant::now() + TEST_TIMEOUT;
        while !session
            .check_readiness(socket)
            .unwrap()
            .contains(ReadinessFlags::ERROR)
        {
            assert!(
                Instant::now() < deadline,
                "timed out waiting for the rearmed UDP error"
            );
            thread::sleep(Duration::from_millis(1));
        }
    }

    #[test]
    fn guest_udp_queue_pressure_drops_new_datagrams_successfully() {
        let provider = Arc::new(LinuxSocketProvider::new(2, 1).unwrap());
        let broker = BrokerCore::new_with_limits(
            PolicyEngine::with_unauthenticated_rights(ObjectRights::all())
                .with_socket_policy(SocketPolicy::Ipv4Loopback),
            BrokerCoreLimits::new_with_all_limits(4, 0, 2, 1),
            provider.clone(),
        )
        .unwrap();
        let receiver_session = broker
            .create_session(CallerCredential::Unauthenticated)
            .unwrap();
        let sender_session = broker
            .create_session(CallerCredential::Unauthenticated)
            .unwrap();
        let (published, _publications) = channel();
        let (retired, _retirements) = channel();
        let readiness = Arc::new(TestReadinessSink { published, retired });
        let receiver = create_udp_socket(&receiver_session, readiness.clone());
        let receiver_address = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 18102);
        assert_eq!(
            litebox_broker_core::socket::bind(&receiver_session, receiver, receiver_address,),
            Ok(SocketOutcome::Completed(receiver_address))
        );
        let sender = create_udp_socket(&sender_session, readiness);
        assert_eq!(
            send_datagram(
                &sender_session,
                sender,
                &[],
                SendFlags::NONE,
                Some(receiver_address),
            ),
            Ok(SocketOutcome::Completed(0))
        );
        for _ in 0..MAX_UDP_QUEUE_DATAGRAMS_PER_SOURCE {
            assert_eq!(
                send_datagram(
                    &sender_session,
                    sender,
                    b"x",
                    SendFlags::NONE,
                    Some(receiver_address),
                ),
                Ok(SocketOutcome::Completed(1))
            );
        }
        assert_eq!(
            provider.reactor.udp_queued_datagram_count(),
            MAX_UDP_QUEUE_DATAGRAMS_PER_SOURCE
        );

        let mut empty = [];
        assert_eq!(
            receive_datagram_into(
                &receiver_session,
                receiver,
                &mut empty,
                ReceiveFromFlags::NONE,
            ),
            Ok(SocketOutcome::Completed(ReceivedPlatformDatagram {
                received: 0,
                datagram_length: 0,
                source_address: litebox_broker_core::socket::status(&sender_session, sender)
                    .unwrap()
                    .local_address
                    .map(|address| SocketAddrV4::new(Ipv4Addr::LOCALHOST, address.port()))
                    .unwrap(),
            }))
        );
        for _ in 1..MAX_UDP_QUEUE_DATAGRAMS_PER_SOURCE {
            let mut byte = [0];
            assert!(matches!(
                receive_datagram_into(
                    &receiver_session,
                    receiver,
                    &mut byte,
                    ReceiveFromFlags::NONE,
                ),
                Ok(SocketOutcome::Completed(ReceivedPlatformDatagram {
                    received: 1,
                    datagram_length: 1,
                    ..
                }))
            ));
            assert_eq!(byte, *b"x");
        }
        assert_eq!(provider.reactor.udp_queued_datagram_count(), 0);
    }

    #[test]
    fn udp_external_peer_authorization_is_bounded_without_eviction() {
        let provider = Arc::new(LinuxSocketProvider::new(1, 1).unwrap());
        let broker = BrokerCore::new_with_limits(
            PolicyEngine::with_unauthenticated_rights(ObjectRights::all())
                .with_socket_policy(SocketPolicy::Ipv4Loopback),
            BrokerCoreLimits::new_with_all_limits(2, 0, 1, 1),
            provider,
        )
        .unwrap();
        let session = broker
            .create_session(CallerCredential::Unauthenticated)
            .unwrap();
        let (published, publications) = channel();
        let (retired, _retirements) = channel();
        let readiness = Arc::new(TestReadinessSink { published, retired });
        let handle = create_udp_socket(&session, readiness);

        let first = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        first.set_read_timeout(Some(TEST_TIMEOUT)).unwrap();
        let first_address = socket_address_v4(first.local_addr().unwrap());
        assert_eq!(
            send_datagram(&session, handle, b"x", SendFlags::NONE, Some(first_address),),
            Ok(SocketOutcome::Completed(1))
        );
        let mut byte = [0];
        let (_, native_source) = first.recv_from(&mut byte).unwrap();
        let native_source = socket_address_v4(native_source);

        let mut peers = Vec::new();
        while peers.len() < MAX_UDP_EXTERNAL_PEERS_PER_SOCKET - 1 {
            let peer = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
            let address = socket_address_v4(peer.local_addr().unwrap());
            if address.port() == native_source.port() {
                continue;
            }
            assert_eq!(
                send_datagram(&session, handle, b"x", SendFlags::NONE, Some(address),),
                Ok(SocketOutcome::Completed(1))
            );
            peers.push(peer);
        }
        let overflow = loop {
            let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
            if socket.local_addr().unwrap().port() != native_source.port() {
                break socket;
            }
        };
        assert_eq!(
            send_datagram(
                &session,
                handle,
                b"overflow",
                SendFlags::NONE,
                Some(socket_address_v4(overflow.local_addr().unwrap())),
            ),
            Err(BrokerError::ResourceExhausted)
        );

        first.send_to(b"reply", native_source).unwrap();
        wait_until_ready(&session, &publications, handle, ReadinessFlags::READ);
        let mut reply = [0; 5];
        assert_eq!(
            receive_datagram_into(&session, handle, &mut reply, ReceiveFromFlags::NONE,),
            Ok(SocketOutcome::Completed(ReceivedPlatformDatagram {
                received: 5,
                datagram_length: 5,
                source_address: first_address,
            }))
        );
        assert_eq!(&reply, b"reply");
    }

    #[test]
    fn reactor_preserves_udp_datagram_semantics() {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        server.set_read_timeout(Some(TEST_TIMEOUT)).unwrap();
        let server_address = socket_address_v4(server.local_addr().unwrap());
        let provider = Arc::new(LinuxSocketProvider::new(2, 2).unwrap());
        let socket_policy = SocketPolicy::from_udp_destination_rules(&[
            DestinationRule::new(
                CallerCredential::Unauthenticated,
                Ipv4Cidr::new(Ipv4Address([127, 0, 0, 0]), 8).unwrap(),
                DestinationPortRange::new(Port(1), Port(u16::MAX)).unwrap(),
            ),
            DestinationRule::new(
                CallerCredential::Unauthenticated,
                Ipv4Cidr::new(Ipv4Address([255, 255, 255, 255]), 32).unwrap(),
                DestinationPortRange::new(Port(9), Port(9)).unwrap(),
            ),
        ])
        .unwrap();
        let broker = BrokerCore::new_with_limits(
            PolicyEngine::with_unauthenticated_rights(ObjectRights::all())
                .with_socket_policy(socket_policy),
            BrokerCoreLimits::new_with_all_limits(4, 0, 2, 2),
            provider.clone(),
        )
        .unwrap();
        let session = broker
            .create_session(CallerCredential::Unauthenticated)
            .unwrap();
        let (published, publications) = channel();
        let (retired, retirements) = channel();
        let readiness = Arc::new(TestReadinessSink { published, retired });
        let handle = litebox_broker_core::socket::create(
            &session,
            CreateSocketRequest {
                address_family: AddressFamily::Ipv4,
                socket_type: SocketType::Datagram,
                protocol: IpProtocol::Udp,
            },
            readiness.clone(),
        )
        .unwrap();

        wait_until_ready(&session, &publications, handle, ReadinessFlags::WRITE);
        let shutdown_handle = litebox_broker_core::socket::create(
            &session,
            CreateSocketRequest {
                address_family: AddressFamily::Ipv4,
                socket_type: SocketType::Datagram,
                protocol: IpProtocol::Udp,
            },
            readiness.clone(),
        )
        .unwrap();
        wait_until_ready(
            &session,
            &publications,
            shutdown_handle,
            ReadinessFlags::WRITE,
        );
        assert_eq!(
            litebox_broker_core::socket::shutdown(&session, shutdown_handle, ShutdownMode::Both,),
            Ok(SocketOutcome::Completed(()))
        );
        let shutdown_readiness = session.check_readiness(shutdown_handle).unwrap();
        assert!(shutdown_readiness.contains(ReadinessFlags::READ));
        assert!(!shutdown_readiness.contains(ReadinessFlags::WRITE));
        assert_eq!(
            send_datagram(
                &session,
                shutdown_handle,
                b"after shutdown",
                SendFlags::NONE,
                Some(server_address),
            ),
            Ok(SocketOutcome::Failed(SocketError::Other))
        );
        let mut shutdown_data = [0; 1];
        assert_eq!(
            receive_datagram_into(
                &session,
                shutdown_handle,
                &mut shutdown_data,
                ReceiveFromFlags::NONE,
            ),
            Ok(SocketOutcome::Failed(SocketError::NotConnected))
        );
        session.close_object_reference(shutdown_handle).unwrap();
        assert_eq!(
            retirements.recv_timeout(TEST_TIMEOUT).unwrap(),
            shutdown_handle
        );
        let read_shutdown_handle = create_udp_socket(&session, readiness);
        assert_eq!(
            send_datagram(
                &session,
                read_shutdown_handle,
                b"before shutdown",
                SendFlags::NONE,
                Some(server_address),
            ),
            Ok(SocketOutcome::Completed(15))
        );
        let mut before_shutdown = [0; 15];
        let (_, read_shutdown_source) = server.recv_from(&mut before_shutdown).unwrap();
        assert_eq!(&before_shutdown, b"before shutdown");
        assert_eq!(
            litebox_broker_core::socket::shutdown(
                &session,
                read_shutdown_handle,
                ShutdownMode::Read,
            ),
            Ok(SocketOutcome::Completed(()))
        );
        assert_eq!(
            send_datagram(
                &session,
                read_shutdown_handle,
                b"write only",
                SendFlags::NONE,
                Some(server_address),
            ),
            Ok(SocketOutcome::Completed(10))
        );
        let mut write_only = [0; 10];
        let (received, source_after_read_shutdown) = server.recv_from(&mut write_only).unwrap();
        assert_eq!(received, write_only.len());
        assert_eq!(&write_only, b"write only");
        assert_eq!(source_after_read_shutdown, read_shutdown_source);
        assert_eq!(
            receive_datagram_into(
                &session,
                read_shutdown_handle,
                &mut shutdown_data,
                ReceiveFromFlags::NONE,
            ),
            Ok(SocketOutcome::Failed(SocketError::NotConnected))
        );
        session
            .close_object_reference(read_shutdown_handle)
            .unwrap();
        assert_eq!(
            retirements.recv_timeout(TEST_TIMEOUT).unwrap(),
            read_shutdown_handle
        );

        assert_eq!(
            send_datagram(
                &session,
                handle,
                b"denied",
                SendFlags::NONE,
                Some(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 53)),
            ),
            Ok(SocketOutcome::Failed(SocketError::PolicyDenied))
        );
        assert_eq!(
            send_datagram(
                &session,
                handle,
                b"implicit bind",
                SendFlags::NONE,
                Some(SocketAddrV4::new(Ipv4Addr::BROADCAST, 9)),
            ),
            Ok(SocketOutcome::Failed(SocketError::Other))
        );
        let implicitly_bound = litebox_broker_core::socket::status(&session, handle)
            .unwrap()
            .local_address
            .unwrap();
        assert!(implicitly_bound.ip().is_unspecified());
        assert_ne!(implicitly_bound.port(), 0);
        let mut no_data = [0; 1];
        assert_eq!(
            receive_datagram_into(&session, handle, &mut no_data, ReceiveFromFlags::NONE,),
            Err(BrokerError::WouldBlock)
        );
        assert_eq!(
            send_datagram(
                &session,
                handle,
                b"ping",
                SendFlags::NONE,
                Some(server_address),
            ),
            Ok(SocketOutcome::Completed(4))
        );
        let mut packet = vec![0; MAX_UDP_DATAGRAM_SIZE as usize];
        let (received, source) = server.recv_from(&mut packet).unwrap();
        assert_eq!(&packet[..received], b"ping");
        let source = socket_address_v4(source);
        let status = litebox_broker_core::socket::status(&session, handle).unwrap();
        assert_eq!(status.status, SocketConnectionStatus::Unconnected);
        let local_address = status.local_address.unwrap();
        assert!(local_address.ip().is_unspecified());
        assert_eq!(local_address, implicitly_bound);
        assert!(source.ip().is_loopback());

        server.send_to(&[], source).unwrap();
        wait_until_ready(&session, &publications, handle, ReadinessFlags::READ);
        let mut zero = [];
        assert_eq!(
            receive_datagram_into(&session, handle, &mut zero, ReceiveFromFlags::NONE,),
            Ok(SocketOutcome::Completed(ReceivedPlatformDatagram {
                received: 0,
                datagram_length: 0,
                source_address: server_address,
            }))
        );
        assert_eq!(
            receive_datagram_into(&session, handle, &mut zero, ReceiveFromFlags::NONE,),
            Err(BrokerError::WouldBlock)
        );

        server.send_to(b"abcdef", source).unwrap();
        wait_until_ready(&session, &publications, handle, ReadinessFlags::READ);
        let mut peeked = [0; 3];
        assert_eq!(
            receive_datagram_into(&session, handle, &mut peeked, ReceiveFromFlags::PEEK,),
            Ok(SocketOutcome::Completed(ReceivedPlatformDatagram {
                received: 3,
                datagram_length: 6,
                source_address: server_address,
            }))
        );
        assert_eq!(&peeked, b"abc");
        peeked.fill(0);
        assert_eq!(
            receive_datagram_into(&session, handle, &mut peeked, ReceiveFromFlags::PEEK,),
            Ok(SocketOutcome::Completed(ReceivedPlatformDatagram {
                received: 3,
                datagram_length: 6,
                source_address: server_address,
            }))
        );
        assert_eq!(&peeked, b"abc");
        let mut truncated = [0; 4];
        assert_eq!(
            receive_datagram_into(&session, handle, &mut truncated, ReceiveFromFlags::NONE,),
            Ok(SocketOutcome::Completed(ReceivedPlatformDatagram {
                received: 4,
                datagram_length: 6,
                source_address: server_address,
            }))
        );
        assert_eq!(&truncated, b"abcd");
        assert_eq!(
            receive_datagram_into(&session, handle, &mut no_data, ReceiveFromFlags::NONE,),
            Err(BrokerError::WouldBlock)
        );

        assert_eq!(
            litebox_broker_core::socket::connect(&session, handle, server_address),
            Ok(SocketOutcome::Completed(SocketConnectionStatus::Connected))
        );
        let connected_status = litebox_broker_core::socket::status(&session, handle).unwrap();
        assert_eq!(connected_status.status, SocketConnectionStatus::Connected);
        assert_eq!(
            connected_status.local_address,
            Some(SocketAddrV4::new(Ipv4Addr::LOCALHOST, local_address.port()))
        );
        let maximum = vec![0x5a; MAX_UDP_DATAGRAM_SIZE as usize];
        assert_eq!(
            send_datagram(&session, handle, &maximum, SendFlags::NONE, None,),
            Ok(SocketOutcome::Completed(maximum.len()))
        );
        let (received, connected_source) = server.recv_from(&mut packet).unwrap();
        assert_eq!(received, maximum.len());
        assert_eq!(&packet[..received], maximum.as_slice());
        let connected_source = socket_address_v4(connected_source);
        assert!(connected_source.ip().is_loopback());
        assert_eq!(connected_source, source);
        assert_eq!(provider.reactor.udp_native_endpoint_count(), 1);
        assert_eq!(
            litebox_broker_core::socket::connect(
                &session,
                handle,
                SocketAddrV4::new(Ipv4Addr::BROADCAST, 9),
            ),
            Ok(SocketOutcome::Failed(SocketError::Other))
        );
        assert_eq!(
            send_datagram(&session, handle, b"old peer", SendFlags::NONE, None),
            Ok(SocketOutcome::Completed(8))
        );
        let (received, preserved_source) = server.recv_from(&mut packet).unwrap();
        assert_eq!(&packet[..received], b"old peer");
        assert_eq!(socket_address_v4(preserved_source), source);

        let refused_socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let refused_address = socket_address_v4(refused_socket.local_addr().unwrap());
        drop(refused_socket);
        assert_eq!(
            litebox_broker_core::socket::connect(&session, handle, refused_address),
            Ok(SocketOutcome::Completed(SocketConnectionStatus::Connected))
        );
        assert_eq!(
            send_datagram(&session, handle, b"refused", SendFlags::NONE, None,),
            Ok(SocketOutcome::Completed(7))
        );
        wait_until_ready(&session, &publications, handle, ReadinessFlags::ERROR);
        assert_eq!(
            send_datagram(
                &session,
                handle,
                b"broadcast",
                SendFlags::NONE,
                Some(SocketAddrV4::new(Ipv4Addr::BROADCAST, 9)),
            ),
            Ok(SocketOutcome::Failed(SocketError::Other))
        );
        let send_error_status = litebox_broker_core::socket::status(&session, handle).unwrap();
        assert_eq!(
            send_error_status.pending_error,
            Some(SocketError::ConnectionRefused)
        );
        assert!(
            !session
                .check_readiness(handle)
                .unwrap()
                .contains(ReadinessFlags::ERROR)
        );
        assert_eq!(
            send_datagram(&session, handle, b"refused again", SendFlags::NONE, None,),
            Ok(SocketOutcome::Completed(13))
        );
        wait_until_ready(&session, &publications, handle, ReadinessFlags::ERROR);
        assert_eq!(
            litebox_broker_core::socket::connect(
                &session,
                handle,
                SocketAddrV4::new(Ipv4Addr::BROADCAST, 9),
            ),
            Ok(SocketOutcome::Failed(SocketError::Other))
        );
        let refused_status = litebox_broker_core::socket::status(&session, handle).unwrap();
        assert_eq!(
            refused_status.pending_error,
            Some(SocketError::ConnectionRefused)
        );
        assert!(
            !session
                .check_readiness(handle)
                .unwrap()
                .contains(ReadinessFlags::ERROR)
        );
        assert_eq!(
            litebox_broker_core::socket::connect(&session, handle, server_address),
            Ok(SocketOutcome::Completed(SocketConnectionStatus::Connected))
        );

        assert_eq!(
            litebox_broker_core::socket::shutdown(&session, handle, ShutdownMode::Write),
            Ok(SocketOutcome::Completed(()))
        );
        assert_eq!(
            litebox_broker_core::socket::connect(&session, handle, server_address),
            Ok(SocketOutcome::Completed(SocketConnectionStatus::Connected))
        );
        assert!(
            !session
                .check_readiness(handle)
                .unwrap()
                .contains(ReadinessFlags::WRITE)
        );
        assert_eq!(
            send_datagram(&session, handle, b"after shutdown", SendFlags::NONE, None,),
            Ok(SocketOutcome::Failed(SocketError::Other))
        );

        session.close_object_reference(handle).unwrap();
        assert_eq!(retirements.recv_timeout(TEST_TIMEOUT).unwrap(), handle);
    }

    #[test]
    fn guest_udp_namespace_routes_across_sessions_and_filters_private_endpoints() {
        let provider = Arc::new(LinuxSocketProvider::new(6, 3).unwrap());
        let broker = BrokerCore::new_with_limits(
            PolicyEngine::with_unauthenticated_rights(ObjectRights::all())
                .with_socket_policy(SocketPolicy::Ipv4Loopback),
            BrokerCoreLimits::new_with_all_limits(8, 0, 6, 3),
            provider.clone(),
        )
        .unwrap();
        let receiver_session = broker
            .create_session(CallerCredential::Unauthenticated)
            .unwrap();
        let sender_session = broker
            .create_session(CallerCredential::Unauthenticated)
            .unwrap();
        let (published, publications) = channel();
        let (retired, retirements) = channel();
        let readiness = Arc::new(TestReadinessSink { published, retired });

        let shadowed_host_socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        shadowed_host_socket
            .set_nonblocking(true)
            .expect("failed to make shadow socket nonblocking");
        let guest_port = shadowed_host_socket.local_addr().unwrap().port();
        let receiver_guest_address = SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 2), guest_port);
        let receiver = create_udp_socket(&receiver_session, readiness.clone());
        assert_eq!(
            litebox_broker_core::socket::bind(&receiver_session, receiver, receiver_guest_address,),
            Ok(SocketOutcome::Completed(receiver_guest_address))
        );
        assert_eq!(
            provider.reactor.host_address(receiver_guest_address.port()),
            None
        );
        assert_eq!(provider.reactor.udp_native_endpoint_count(), 0);

        let sender = create_udp_socket(&sender_session, readiness.clone());
        assert_eq!(
            send_datagram(
                &sender_session,
                sender,
                b"request",
                SendFlags::NONE,
                Some(receiver_guest_address),
            ),
            Ok(SocketOutcome::Completed(7))
        );
        let sender_guest_address = litebox_broker_core::socket::status(&sender_session, sender)
            .unwrap()
            .local_address
            .expect("implicit UDP bind missing");
        let sender_source_address =
            SocketAddrV4::new(Ipv4Addr::LOCALHOST, sender_guest_address.port());
        wait_until_ready(
            &receiver_session,
            &publications,
            receiver,
            ReadinessFlags::READ,
        );
        let mut request = [0; 7];
        assert_eq!(
            receive_datagram_into(
                &receiver_session,
                receiver,
                &mut request,
                ReceiveFromFlags::NONE,
            ),
            Ok(SocketOutcome::Completed(ReceivedPlatformDatagram {
                received: 7,
                datagram_length: 7,
                source_address: sender_source_address,
            }))
        );
        assert_eq!(&request, b"request");

        assert_eq!(
            send_datagram(
                &receiver_session,
                receiver,
                b"response",
                SendFlags::NONE,
                Some(sender_source_address),
            ),
            Ok(SocketOutcome::Completed(8))
        );
        wait_until_ready(&sender_session, &publications, sender, ReadinessFlags::READ);
        let mut response = [0; 8];
        assert_eq!(
            receive_datagram_into(
                &sender_session,
                sender,
                &mut response,
                ReceiveFromFlags::NONE,
            ),
            Ok(SocketOutcome::Completed(ReceivedPlatformDatagram {
                received: 8,
                datagram_length: 8,
                source_address: receiver_guest_address,
            }))
        );
        assert_eq!(&response, b"response");
        sender_session.close_object_reference(sender).unwrap();
        assert_eq!(retirements.recv_timeout(TEST_TIMEOUT).unwrap(), sender);

        assert_eq!(
            shadowed_host_socket
                .recv_from(&mut [0; 1])
                .unwrap_err()
                .kind(),
            ErrorKind::WouldBlock
        );

        let external = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        external.set_read_timeout(Some(TEST_TIMEOUT)).unwrap();
        let external_address = socket_address_v4(external.local_addr().unwrap());
        assert_eq!(
            send_datagram(
                &receiver_session,
                receiver,
                b"contact",
                SendFlags::NONE,
                Some(external_address),
            ),
            Ok(SocketOutcome::Completed(7))
        );
        let mut external_packet = [0; 7];
        let (_, receiver_source) = external.recv_from(&mut external_packet).unwrap();
        assert_eq!(&external_packet, b"contact");
        assert_eq!(provider.reactor.udp_native_endpoint_count(), 1);
        assert!(
            provider
                .reactor
                .udp_native_receive_buffer_size(receiver_guest_address.port())
                .is_some_and(|size| size <= MAX_UDP_NATIVE_RECEIVE_BUFFER)
        );
        let receiver_private_address =
            SocketAddrV4::new(Ipv4Addr::LOCALHOST, receiver_source.port());
        let probe = create_udp_socket(&sender_session, readiness);
        let probe_guest_port = (1_u16..=u16::MAX)
            .find(|port| *port != receiver_guest_address.port() && *port != receiver_source.port())
            .unwrap();
        let probe_guest_address = SocketAddrV4::new(Ipv4Addr::LOCALHOST, probe_guest_port);
        assert_eq!(
            litebox_broker_core::socket::bind(&sender_session, probe, probe_guest_address,),
            Ok(SocketOutcome::Completed(probe_guest_address))
        );
        assert_eq!(
            send_datagram(
                &sender_session,
                probe,
                b"private",
                SendFlags::NONE,
                Some(receiver_private_address),
            ),
            Ok(SocketOutcome::Failed(SocketError::ConnectionRefused))
        );
        let receiver_private_alias =
            SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 3), receiver_source.port());
        assert_eq!(
            send_datagram(
                &sender_session,
                probe,
                b"private alias",
                SendFlags::NONE,
                Some(receiver_private_alias),
            ),
            Ok(SocketOutcome::Failed(SocketError::ConnectionRefused))
        );
        external.send_to(b"reply", receiver_source).unwrap();
        wait_until_ready(
            &receiver_session,
            &publications,
            receiver,
            ReadinessFlags::READ,
        );
        assert_eq!(
            send_datagram(
                &sender_session,
                probe,
                b"guest",
                SendFlags::NONE,
                Some(receiver_guest_address),
            ),
            Ok(SocketOutcome::Completed(5))
        );
        let mut reply = [0; 5];
        assert_eq!(
            receive_datagram_into(
                &receiver_session,
                receiver,
                &mut reply,
                ReceiveFromFlags::PEEK,
            ),
            Ok(SocketOutcome::Completed(ReceivedPlatformDatagram {
                received: 5,
                datagram_length: 5,
                source_address: external_address,
            }))
        );
        assert_eq!(&reply, b"reply");
        reply.fill(0);
        assert_eq!(
            receive_datagram_into(
                &receiver_session,
                receiver,
                &mut reply,
                ReceiveFromFlags::NONE,
            ),
            Ok(SocketOutcome::Completed(ReceivedPlatformDatagram {
                received: 5,
                datagram_length: 5,
                source_address: external_address,
            }))
        );
        assert_eq!(&reply, b"reply");
        reply.fill(0);
        assert_eq!(
            receive_datagram_into(
                &receiver_session,
                receiver,
                &mut reply,
                ReceiveFromFlags::NONE,
            ),
            Ok(SocketOutcome::Completed(ReceivedPlatformDatagram {
                received: 5,
                datagram_length: 5,
                source_address: probe_guest_address,
            }))
        );
        assert_eq!(&reply, b"guest");
    }

    #[test]
    fn udp_endpoint_staging_error_rolls_back_external_peer_reservation() {
        let provider = Arc::new(LinuxSocketProvider::new(2, 2).unwrap());
        let broker = BrokerCore::new_with_limits(
            PolicyEngine::with_unauthenticated_rights(ObjectRights::all())
                .with_socket_policy(SocketPolicy::Ipv4Loopback),
            BrokerCoreLimits::new_with_all_limits(4, 0, 2, 2),
            provider.clone(),
        )
        .unwrap();
        let session = broker
            .create_session(CallerCredential::Unauthenticated)
            .unwrap();
        let (published, _publications) = channel();
        let (retired, _retirements) = channel();
        let readiness = Arc::new(TestReadinessSink { published, retired });
        let socket = create_udp_socket(&session, readiness);
        let external = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let external_address = socket_address_v4(external.local_addr().unwrap());

        provider.reactor.exhaust_udp_endpoint_generation();
        assert_eq!(
            send_datagram(
                &session,
                socket,
                b"not sent",
                SendFlags::NONE,
                Some(external_address),
            ),
            Err(BrokerError::ResourceExhausted)
        );
        assert_eq!(provider.reactor.udp_external_peer_count(), 0);
        assert_eq!(provider.reactor.udp_native_endpoint_count(), 0);

        session.close_object_reference(socket).unwrap();
    }

    #[test]
    fn stale_udp_datagrams_are_not_relabelled_after_guest_port_reuse() {
        let provider = Arc::new(LinuxSocketProvider::new(5, 3).unwrap());
        let broker = BrokerCore::new_with_limits(
            PolicyEngine::with_unauthenticated_rights(ObjectRights::all())
                .with_socket_policy(SocketPolicy::Ipv4Loopback),
            BrokerCoreLimits::new_with_all_limits(8, 0, 5, 3),
            provider.clone(),
        )
        .unwrap();
        let receiver_session = broker
            .create_session(CallerCredential::Unauthenticated)
            .unwrap();
        let source_session = broker
            .create_session(CallerCredential::Unauthenticated)
            .unwrap();
        let (published, publications) = channel();
        let (retired, retirements) = channel();
        let readiness = Arc::new(TestReadinessSink { published, retired });
        let receiver_port_guard = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let source_port_guard = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let receiver_port = receiver_port_guard.local_addr().unwrap().port();
        let source_port = source_port_guard.local_addr().unwrap().port();
        let receiver_address = SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 2), receiver_port);
        let source_address = SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 3), source_port);

        let receiver = create_udp_socket(&receiver_session, readiness.clone());
        assert_eq!(
            litebox_broker_core::socket::bind(&receiver_session, receiver, receiver_address,),
            Ok(SocketOutcome::Completed(receiver_address))
        );
        let source = create_udp_socket(&source_session, readiness.clone());
        assert_eq!(
            litebox_broker_core::socket::bind(&source_session, source, source_address),
            Ok(SocketOutcome::Completed(source_address))
        );
        assert_eq!(provider.reactor.udp_native_endpoint_count(), 0);
        assert_eq!(
            send_datagram(
                &source_session,
                source,
                b"old",
                SendFlags::NONE,
                Some(receiver_address),
            ),
            Ok(SocketOutcome::Completed(3))
        );
        wait_until_ready(
            &receiver_session,
            &publications,
            receiver,
            ReadinessFlags::READ,
        );
        assert_eq!(provider.reactor.udp_queued_datagram_count(), 1);

        source_session.close_object_reference(source).unwrap();
        assert_eq!(retirements.recv_timeout(TEST_TIMEOUT).unwrap(), source);

        let replacement = create_udp_socket(&source_session, readiness);
        let replacement_address =
            SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 4), source_address.port());
        assert_eq!(
            litebox_broker_core::socket::bind(&source_session, replacement, replacement_address,),
            Ok(SocketOutcome::Completed(replacement_address))
        );
        assert_eq!(
            send_datagram(
                &source_session,
                replacement,
                b"fresh",
                SendFlags::NONE,
                Some(receiver_address),
            ),
            Ok(SocketOutcome::Completed(5))
        );

        let mut payload = [0; 5];
        assert_eq!(
            receive_datagram_into(
                &receiver_session,
                receiver,
                &mut payload,
                ReceiveFromFlags::NONE,
            ),
            Ok(SocketOutcome::Completed(ReceivedPlatformDatagram {
                received: 3,
                datagram_length: 3,
                source_address,
            }))
        );
        assert_eq!(&payload[..3], b"old");
        assert_eq!(
            receive_datagram_into(
                &receiver_session,
                receiver,
                &mut payload,
                ReceiveFromFlags::NONE,
            ),
            Ok(SocketOutcome::Completed(ReceivedPlatformDatagram {
                received: 5,
                datagram_length: 5,
                source_address: replacement_address,
            }))
        );
        assert_eq!(&payload, b"fresh");
        assert_eq!(provider.reactor.udp_queued_datagram_count(), 0);
    }

    #[test]
    fn udp_queued_datagrams_survive_source_session_teardown() {
        let provider = Arc::new(LinuxSocketProvider::new(3, 1).unwrap());
        let broker = BrokerCore::new_with_limits(
            PolicyEngine::with_unauthenticated_rights(ObjectRights::all())
                .with_socket_policy(SocketPolicy::Ipv4Loopback),
            BrokerCoreLimits::new_with_all_limits(6, 0, 3, 1),
            provider.clone(),
        )
        .unwrap();
        let source_session = broker
            .create_session(CallerCredential::Unauthenticated)
            .unwrap();
        let first_receiver_session = broker
            .create_session(CallerCredential::Unauthenticated)
            .unwrap();
        let second_receiver_session = broker
            .create_session(CallerCredential::Unauthenticated)
            .unwrap();
        let replacement_session = broker
            .create_session(CallerCredential::Unauthenticated)
            .unwrap();
        let (published, publications) = channel();
        let (retired, retirements) = channel();
        let readiness = Arc::new(TestReadinessSink { published, retired });
        let first_address = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 18082);
        let second_address = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 18083);
        let first_receiver = create_udp_socket(&first_receiver_session, readiness.clone());
        let second_receiver = create_udp_socket(&second_receiver_session, readiness.clone());
        assert_eq!(
            litebox_broker_core::socket::bind(
                &first_receiver_session,
                first_receiver,
                first_address,
            ),
            Ok(SocketOutcome::Completed(first_address))
        );
        assert_eq!(
            litebox_broker_core::socket::bind(
                &second_receiver_session,
                second_receiver,
                second_address,
            ),
            Ok(SocketOutcome::Completed(second_address))
        );
        let source = create_udp_socket(&source_session, readiness.clone());

        assert_eq!(
            send_datagram(
                &source_session,
                source,
                b"first",
                SendFlags::NONE,
                Some(first_address),
            ),
            Ok(SocketOutcome::Completed(5))
        );
        let source_address = litebox_broker_core::socket::status(&source_session, source)
            .unwrap()
            .local_address
            .map(|address| SocketAddrV4::new(Ipv4Addr::LOCALHOST, address.port()))
            .expect("implicit UDP source bind missing");
        assert_eq!(provider.reactor.udp_queued_datagram_count(), 1);
        assert_eq!(
            send_datagram(
                &source_session,
                source,
                b"second",
                SendFlags::NONE,
                Some(second_address),
            ),
            Ok(SocketOutcome::Completed(6))
        );
        assert_eq!(provider.reactor.udp_queued_datagram_count(), 2);
        wait_until_ready(
            &first_receiver_session,
            &publications,
            first_receiver,
            ReadinessFlags::READ,
        );
        let mut payload = [0; 6];
        assert_eq!(
            receive_datagram_into(
                &first_receiver_session,
                first_receiver,
                &mut payload,
                ReceiveFromFlags::NONE,
            ),
            Ok(SocketOutcome::Completed(ReceivedPlatformDatagram {
                received: 5,
                datagram_length: 5,
                source_address,
            }))
        );
        assert_eq!(&payload[..5], b"first");
        assert_eq!(
            receive_datagram_into(
                &first_receiver_session,
                first_receiver,
                &mut payload,
                ReceiveFromFlags::NONE,
            ),
            Err(BrokerError::WouldBlock)
        );
        assert_eq!(provider.reactor.udp_queued_datagram_count(), 1);
        wait_until_ready(
            &second_receiver_session,
            &publications,
            second_receiver,
            ReadinessFlags::READ,
        );
        drop(source_session);
        assert_eq!(retirements.recv_timeout(TEST_TIMEOUT).unwrap(), source);
        assert_eq!(provider.reactor.udp_queued_datagram_count(), 1);

        let replacement = create_udp_socket(&replacement_session, readiness);
        assert_eq!(
            receive_datagram_into(
                &second_receiver_session,
                second_receiver,
                &mut payload,
                ReceiveFromFlags::NONE,
            ),
            Ok(SocketOutcome::Completed(ReceivedPlatformDatagram {
                received: 6,
                datagram_length: 6,
                source_address,
            }))
        );
        assert_eq!(&payload, b"second");
        assert_eq!(provider.reactor.udp_queued_datagram_count(), 0);

        replacement_session
            .close_object_reference(replacement)
            .unwrap();
    }

    #[test]
    fn connected_guest_udp_enforces_barriers_peek_and_peer_generations() {
        let provider = Arc::new(LinuxSocketProvider::new(4, 2).unwrap());
        let broker = BrokerCore::new_with_limits(
            PolicyEngine::with_unauthenticated_rights(ObjectRights::all())
                .with_socket_policy(SocketPolicy::Ipv4Loopback),
            BrokerCoreLimits::new_with_all_limits(8, 0, 4, 2),
            provider.clone(),
        )
        .unwrap();
        let first_session = broker
            .create_session(CallerCredential::Unauthenticated)
            .unwrap();
        let second_session = broker
            .create_session(CallerCredential::Unauthenticated)
            .unwrap();
        let (published, publications) = channel();
        let (retired, _retirements) = channel();
        let readiness = Arc::new(TestReadinessSink { published, retired });
        let expected_first_address = SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 2), 18080);
        let second_address = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 18081);
        let second = create_udp_socket(&second_session, readiness.clone());
        assert_eq!(
            litebox_broker_core::socket::bind(&second_session, second, second_address),
            Ok(SocketOutcome::Completed(second_address))
        );

        let first = create_udp_socket(&first_session, readiness.clone());
        assert_eq!(
            litebox_broker_core::socket::bind(&first_session, first, expected_first_address,),
            Ok(SocketOutcome::Completed(expected_first_address))
        );
        assert_eq!(
            send_datagram(
                &second_session,
                second,
                b"stale",
                SendFlags::NONE,
                Some(expected_first_address),
            ),
            Ok(SocketOutcome::Completed(5))
        );
        wait_until_ready(&first_session, &publications, first, ReadinessFlags::READ);
        assert_eq!(provider.reactor.udp_queued_datagram_count(), 1);
        assert_eq!(
            litebox_broker_core::socket::connect(&first_session, first, second_address),
            Ok(SocketOutcome::Completed(SocketConnectionStatus::Connected))
        );
        assert_eq!(provider.reactor.udp_queued_datagram_count(), 0);
        let mut stale = [0; 5];
        assert_eq!(
            receive_datagram_into(&first_session, first, &mut stale, ReceiveFromFlags::NONE,),
            Err(BrokerError::WouldBlock)
        );
        let first_address = litebox_broker_core::socket::status(&first_session, first)
            .unwrap()
            .local_address
            .expect("connected UDP socket lost its local address");
        assert_eq!(first_address, expected_first_address);
        assert_eq!(
            send_datagram(&first_session, first, b"one", SendFlags::NONE, None,),
            Ok(SocketOutcome::Completed(3))
        );
        wait_until_ready(&second_session, &publications, second, ReadinessFlags::READ);
        let mut first_payload = [0; 3];
        assert_eq!(
            receive_datagram_into(
                &second_session,
                second,
                &mut first_payload,
                ReceiveFromFlags::PEEK,
            ),
            Ok(SocketOutcome::Completed(ReceivedPlatformDatagram {
                received: 3,
                datagram_length: 3,
                source_address: first_address,
            }))
        );
        assert_eq!(&first_payload, b"one");
        first_payload.fill(0);
        assert_eq!(
            receive_datagram_into(
                &second_session,
                second,
                &mut first_payload,
                ReceiveFromFlags::NONE,
            ),
            Ok(SocketOutcome::Completed(ReceivedPlatformDatagram {
                received: 3,
                datagram_length: 3,
                source_address: first_address,
            }))
        );
        assert_eq!(&first_payload, b"one");

        assert_eq!(
            litebox_broker_core::socket::connect(&second_session, second, first_address),
            Ok(SocketOutcome::Completed(SocketConnectionStatus::Connected))
        );
        assert_eq!(
            send_datagram(&second_session, second, b"two", SendFlags::NONE, None,),
            Ok(SocketOutcome::Completed(3))
        );
        wait_until_ready(&first_session, &publications, first, ReadinessFlags::READ);
        let mut second_payload = [0; 3];
        assert_eq!(
            receive_datagram_into(
                &first_session,
                first,
                &mut second_payload,
                ReceiveFromFlags::NONE,
            ),
            Ok(SocketOutcome::Completed(ReceivedPlatformDatagram {
                received: 3,
                datagram_length: 3,
                source_address: second_address,
            }))
        );
        assert_eq!(&second_payload, b"two");

        second_session.close_object_reference(second).unwrap();
        let replacement = create_udp_socket(&second_session, readiness);
        assert_eq!(
            litebox_broker_core::socket::bind(&second_session, replacement, second_address),
            Ok(SocketOutcome::Completed(second_address))
        );
        assert_eq!(
            send_datagram(&first_session, first, b"stale peer", SendFlags::NONE, None),
            Ok(SocketOutcome::Failed(SocketError::ConnectionRefused))
        );
    }

    #[test]
    fn externally_connected_udp_preserves_guest_routing_identity() {
        let Some(local_ip) = non_loopback_local_ipv4() else {
            return;
        };
        let external = UdpSocket::bind((local_ip, 0)).unwrap();
        external.set_read_timeout(Some(TEST_TIMEOUT)).unwrap();
        let external_address = socket_address_v4(external.local_addr().unwrap());
        let provider = Arc::new(LinuxSocketProvider::new(4, 2).unwrap());
        let policy = SocketPolicy::from_udp_destination_rules(&[
            DestinationRule::new(
                CallerCredential::Unauthenticated,
                Ipv4Cidr::new(Ipv4Address([127, 0, 0, 0]), 8).unwrap(),
                DestinationPortRange::new(Port(1), Port(u16::MAX)).unwrap(),
            ),
            DestinationRule::new(
                CallerCredential::Unauthenticated,
                Ipv4Cidr::new(Ipv4Address(local_ip.octets()), 32).unwrap(),
                DestinationPortRange::new(Port(1), Port(u16::MAX)).unwrap(),
            ),
        ])
        .unwrap();
        let broker = BrokerCore::new_with_limits(
            PolicyEngine::with_unauthenticated_rights(ObjectRights::all())
                .with_socket_policy(policy),
            BrokerCoreLimits::new_with_all_limits(6, 0, 4, 2),
            provider.clone(),
        )
        .unwrap();
        let source_session = broker
            .create_session(CallerCredential::Unauthenticated)
            .unwrap();
        let receiver_session = broker
            .create_session(CallerCredential::Unauthenticated)
            .unwrap();
        let (published, publications) = channel();
        let (retired, _retirements) = channel();
        let readiness = Arc::new(TestReadinessSink { published, retired });
        let receiver_address = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 18084);
        let receiver = create_udp_socket(&receiver_session, readiness.clone());
        assert_eq!(
            litebox_broker_core::socket::bind(&receiver_session, receiver, receiver_address,),
            Ok(SocketOutcome::Completed(receiver_address))
        );
        let source = create_udp_socket(&source_session, readiness);
        assert_eq!(
            litebox_broker_core::socket::connect(&source_session, source, external_address),
            Ok(SocketOutcome::Completed(SocketConnectionStatus::Connected))
        );
        let source_address = litebox_broker_core::socket::status(&source_session, source)
            .unwrap()
            .local_address
            .expect("connected UDP source address missing");
        assert_eq!(source_address.ip(), &local_ip);
        let internal_source_address = SocketAddrV4::new(Ipv4Addr::LOCALHOST, source_address.port());

        assert_eq!(
            send_datagram(&source_session, source, b"external", SendFlags::NONE, None),
            Ok(SocketOutcome::Completed(8))
        );
        let mut external_payload = [0; 8];
        let (external_received, _) = external.recv_from(&mut external_payload).unwrap();
        assert_eq!(external_received, external_payload.len());
        assert_eq!(&external_payload, b"external");

        assert_eq!(
            send_datagram(
                &source_session,
                source,
                b"guest",
                SendFlags::NONE,
                Some(receiver_address),
            ),
            Ok(SocketOutcome::Completed(5))
        );
        wait_until_ready(
            &receiver_session,
            &publications,
            receiver,
            ReadinessFlags::READ,
        );
        let mut guest_payload = [0; 5];
        assert_eq!(
            receive_datagram_into(
                &receiver_session,
                receiver,
                &mut guest_payload,
                ReceiveFromFlags::NONE,
            ),
            Ok(SocketOutcome::Completed(ReceivedPlatformDatagram {
                received: 5,
                datagram_length: 5,
                source_address: internal_source_address,
            }))
        );
        assert_eq!(&guest_payload, b"guest");
        assert_eq!(
            receive_datagram_into(
                &receiver_session,
                receiver,
                &mut guest_payload,
                ReceiveFromFlags::NONE,
            ),
            Err(BrokerError::WouldBlock)
        );
        assert_eq!(provider.reactor.udp_queued_datagram_count(), 0);
        assert_eq!(
            send_datagram(
                &receiver_session,
                receiver,
                b"reply",
                SendFlags::NONE,
                Some(internal_source_address),
            ),
            Ok(SocketOutcome::Completed(5))
        );
        assert_eq!(provider.reactor.udp_queued_datagram_count(), 0);
        assert_eq!(
            receive_datagram_into(
                &source_session,
                source,
                &mut guest_payload,
                ReceiveFromFlags::NONE,
            ),
            Err(BrokerError::WouldBlock)
        );
        assert_eq!(provider.reactor.udp_queued_datagram_count(), 0);
    }

    #[test]
    fn guest_connected_udp_drains_native_ingress_without_delivering_it() {
        let provider = Arc::new(LinuxSocketProvider::new(4, 2).unwrap());
        let broker = BrokerCore::new_with_limits(
            PolicyEngine::with_unauthenticated_rights(ObjectRights::all())
                .with_socket_policy(SocketPolicy::Ipv4Loopback),
            BrokerCoreLimits::new_with_all_limits(8, 0, 4, 2),
            provider.clone(),
        )
        .unwrap();
        let receiver_session = broker
            .create_session(CallerCredential::Unauthenticated)
            .unwrap();
        let sender_session = broker
            .create_session(CallerCredential::Unauthenticated)
            .unwrap();
        let (published, publications) = channel();
        let (retired, _retirements) = channel();
        let readiness = Arc::new(TestReadinessSink { published, retired });
        let guest_port = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let receiver_address = SocketAddrV4::new(Ipv4Addr::LOCALHOST, guest_port);
        let receiver = create_udp_socket(&receiver_session, readiness.clone());
        assert_eq!(
            litebox_broker_core::socket::bind(&receiver_session, receiver, receiver_address,),
            Ok(SocketOutcome::Completed(receiver_address))
        );
        let sender = create_udp_socket(&sender_session, readiness);
        assert_eq!(
            send_datagram(
                &sender_session,
                sender,
                b"warmup",
                SendFlags::NONE,
                Some(receiver_address),
            ),
            Ok(SocketOutcome::Completed(6))
        );
        wait_for_readiness(&publications, receiver, ReadinessFlags::READ);
        let source_address = litebox_broker_core::socket::status(&sender_session, sender)
            .unwrap()
            .local_address
            .map(|address| SocketAddrV4::new(Ipv4Addr::LOCALHOST, address.port()))
            .unwrap();
        let mut warmup = [0; 6];
        assert_eq!(
            receive_datagram_into(
                &receiver_session,
                receiver,
                &mut warmup,
                ReceiveFromFlags::NONE,
            ),
            Ok(SocketOutcome::Completed(ReceivedPlatformDatagram {
                received: 6,
                datagram_length: 6,
                source_address,
            }))
        );
        assert_eq!(&warmup, b"warmup");
        assert_eq!(
            litebox_broker_core::socket::connect(&receiver_session, receiver, source_address,),
            Ok(SocketOutcome::Completed(SocketConnectionStatus::Connected))
        );

        let attacker = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        attacker.set_read_timeout(Some(TEST_TIMEOUT)).unwrap();
        let attacker_address = socket_address_v4(attacker.local_addr().unwrap());
        assert_eq!(
            send_datagram(
                &receiver_session,
                receiver,
                b"contact",
                SendFlags::NONE,
                Some(attacker_address),
            ),
            Ok(SocketOutcome::Completed(7))
        );
        let mut contact = [0; 7];
        let (_, receiver_native_address) = attacker.recv_from(&mut contact).unwrap();
        assert_eq!(&contact, b"contact");
        assert_eq!(provider.reactor.udp_native_endpoint_count(), 1);
        for _ in 0..=MAX_REJECTED_UDP_DATAGRAMS_PER_COMMAND {
            attacker.send_to(b"x", receiver_native_address).unwrap();
        }
        assert_eq!(
            send_datagram(
                &sender_session,
                sender,
                b"ok",
                SendFlags::NONE,
                Some(receiver_address),
            ),
            Ok(SocketOutcome::Completed(2))
        );
        wait_for_readiness(&publications, receiver, ReadinessFlags::READ);
        let mut payload = [0; 2];
        assert_eq!(
            receive_datagram_into(
                &receiver_session,
                receiver,
                &mut payload,
                ReceiveFromFlags::NONE,
            ),
            Ok(SocketOutcome::Completed(ReceivedPlatformDatagram {
                received: 2,
                datagram_length: 2,
                source_address,
            }))
        );
        assert_eq!(&payload, b"ok");
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
        (!address.ip().is_unspecified() && !address.ip().is_loopback()).then_some(*address.ip())
    }

    fn create_socket(
        session: &litebox_broker_core::BrokerSession,
        readiness: Arc<dyn ReadinessSink>,
    ) -> ObjectHandle {
        litebox_broker_core::socket::create(
            session,
            CreateSocketRequest {
                address_family: AddressFamily::Ipv4,
                socket_type: SocketType::Stream,
                protocol: IpProtocol::Tcp,
            },
            readiness,
        )
        .unwrap()
    }

    fn create_udp_socket(
        session: &litebox_broker_core::BrokerSession,
        readiness: Arc<dyn ReadinessSink>,
    ) -> ObjectHandle {
        litebox_broker_core::socket::create(
            session,
            CreateSocketRequest {
                address_family: AddressFamily::Ipv4,
                socket_type: SocketType::Datagram,
                protocol: IpProtocol::Udp,
            },
            readiness,
        )
        .unwrap()
    }

    fn wait_until_connected(
        session: &litebox_broker_core::BrokerSession,
        handle: ObjectHandle,
        publications: &Receiver<(ObjectHandle, ReadinessFlags)>,
    ) {
        let deadline = Instant::now() + TEST_TIMEOUT;
        loop {
            match litebox_broker_core::socket::status(session, handle)
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
        session: &litebox_broker_core::BrokerSession,
        handle: ObjectHandle,
        publications: &Receiver<(ObjectHandle, ReadinessFlags)>,
    ) -> SocketError {
        let deadline = Instant::now() + TEST_TIMEOUT;
        loop {
            match litebox_broker_core::socket::status(session, handle)
                .unwrap()
                .status
            {
                SocketConnectionStatus::Connecting => {
                    wait_for_readiness_until(publications, handle, ReadinessFlags::ERROR, deadline);
                }
                SocketConnectionStatus::Failed(error) => return error,
                status => panic!("unexpected connect status: {status:?}"),
            }
        }
    }

    fn wait_for_end_of_stream(
        session: &litebox_broker_core::BrokerSession,
        handle: ObjectHandle,
        publications: &Receiver<(ObjectHandle, ReadinessFlags)>,
    ) {
        let deadline = Instant::now() + TEST_TIMEOUT;
        loop {
            let mut byte = [0_u8; 1];
            match receive_into(session, handle, &mut byte, ReceiveFlags::NONE, 0, 0) {
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

    fn wait_until_ready(
        session: &litebox_broker_core::BrokerSession,
        publications: &Receiver<(ObjectHandle, ReadinessFlags)>,
        handle: ObjectHandle,
        readiness: ReadinessFlags,
    ) {
        let deadline = Instant::now() + TEST_TIMEOUT;
        loop {
            if session.check_readiness(handle).unwrap().contains(readiness) {
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
}
