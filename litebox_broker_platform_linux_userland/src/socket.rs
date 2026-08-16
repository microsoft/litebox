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
    ReactorUdpBinding, ReactorUdpPeer, ReactorUdpState, UDP_EVENT_TOKEN_FLAG, UdpNativeErrorState,
    UdpReceiveOrigin, UdpSocketState, is_local_ipv4_address,
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
        self.retire_with_wait_observer(close, || {});
    }

    fn retire_with_wait_observer(&self, close: impl FnOnce(), mut observe_wait: impl FnMut()) {
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
                    observe_wait();
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
    fn udp_native_head_datagram_bytes(&self, guest_port: u16) -> usize {
        let (response, receive) = sync_channel(1);
        self.commands
            .send(ReactorCommand::UdpNativeHeadDatagramBytes {
                guest_port,
                response,
            })
            .unwrap();
        self.signal().unwrap();
        receive.recv().unwrap().unwrap()
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
    UdpNativeHeadDatagramBytes {
        guest_port: u16,
        response: SyncSender<BrokerResult<usize>>,
    },
    #[cfg(test)]
    ExerciseUdpReceiveRejectionCap {
        guest_port: u16,
        ready: SyncSender<()>,
        proceed: Receiver<()>,
        response: SyncSender<BrokerResult<(bool, usize)>>,
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
    /// Native UDP endpoints reserve their host port through an initial wildcard
    /// bind, so a local address plus a registered host port identifies the
    /// endpoint. Guest routing must check its namespace first because guest and
    /// native ports may numerically collide.
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
            // Queue discard and shutdown state are already committed.
            let _ = self.rearm_udp_endpoint_if_needed(socket_id);
        }
        // The cached snapshot remains authoritative if notification fails.
        let _ = self.publish_udp_readiness(socket_id);
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
            let rearm = self.rearm_udp_endpoint_if_needed(socket_id);
            // The synchronous response carries the consumed UDP error and the
            // cached snapshot is already authoritative. Do not discard that
            // error if rearming the endpoint fails after consumption.
            if let Err(error) = rearm {
                if let Some(pending_error) = response.pending_error {
                    let socket = self
                        .sockets
                        .get_mut(&socket_id)
                        .expect("UDP status socket disappeared after rearm failure");
                    let next_pending_error = {
                        let mut snapshot = socket
                            .snapshot
                            .lock()
                            .expect("Linux socket snapshot mutex poisoned");
                        let next_pending_error = snapshot.pending_error.replace(pending_error);
                        snapshot.readiness = snapshot.readiness | ReadinessFlags::ERROR;
                        next_pending_error
                    };
                    if let Some(next_pending_error) = next_pending_error {
                        socket
                            .udp_state_mut()
                            .expect("UDP status socket changed kind after rearm failure")
                            .native_error = UdpNativeErrorState::Consumed(next_pending_error);
                    }
                    let readiness = socket
                        .snapshot
                        .lock()
                        .expect("Linux socket snapshot mutex poisoned")
                        .readiness;
                    let _ = socket.readiness.publish(readiness);
                }
                return Err(error);
            }
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
                ReactorCommand::UdpNativeHeadDatagramBytes {
                    guest_port,
                    response,
                } => {
                    let outcome = self
                        .udp
                        .bindings
                        .get(&guest_port)
                        .ok_or(BrokerError::Internal)
                        .and_then(|binding| self.udp_native_head_datagram_bytes(binding.socket_id));
                    let _ = response.send(outcome);
                }
                #[cfg(test)]
                ReactorCommand::ExerciseUdpReceiveRejectionCap {
                    guest_port,
                    ready,
                    proceed,
                    response,
                } => {
                    let outcome = (|| {
                        let socket_id = self
                            .udp
                            .bindings
                            .get(&guest_port)
                            .ok_or(BrokerError::Internal)?
                            .socket_id;
                        ready.send(()).map_err(|_| BrokerError::Internal)?;
                        proceed
                            .recv_timeout(Duration::from_secs(10))
                            .map_err(|_| BrokerError::Internal)?;
                        self.sockets
                            .get_mut(&socket_id)
                            .ok_or(BrokerError::Internal)?
                            .udp_state_mut()?
                            .external_endpoint
                            .as_mut()
                            .ok_or(BrokerError::Internal)?
                            .readable = true;
                        if self
                            .receive_native_udp(socket_id, 1, ReceiveFromFlags::NONE)?
                            .is_some()
                        {
                            return Err(BrokerError::Internal);
                        }
                        let readable = self
                            .sockets
                            .get(&socket_id)
                            .ok_or(BrokerError::Internal)?
                            .udp_state()?
                            .external_endpoint
                            .as_ref()
                            .map(|endpoint| endpoint.readable)
                            .ok_or(BrokerError::Internal)?;
                        let head_datagram_bytes = self.udp_native_head_datagram_bytes(socket_id)?;
                        Ok((readable, head_datagram_bytes))
                    })();
                    let _ = response.send(outcome);
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
                    confirm_tcp_connected(socket);
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
                fail_connect(socket, error);
                let _ = consume_synchronous_error(socket);
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

    let refresh_exhausted_cache = match peek_cache.as_ref() {
        Some(cache)
            if cache.socket_id == socket_id
                && cache.requested_length == peek_length
                && cache.data.len() <= peek_offset =>
        {
            usize::try_from(
                ioctl_fionread(&socket.tcp_state()?.socket).map_err(broker_error_from_errno)?,
            )
            .map_err(|_| BrokerError::Internal)?
                > cache.data.len()
        }
        _ => false,
    };
    let refresh = peek_offset == 0
        || !peek_cache.as_ref().is_some_and(|cache| {
            cache.socket_id == socket_id && cache.requested_length == peek_length
        })
        || refresh_exhausted_cache;
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
                confirm_tcp_connected(socket);
                let readiness = if socket.read_shutdown {
                    ReadinessFlags::READ
                } else {
                    ReadinessFlags::READ | ReadinessFlags::HANGUP
                };
                let _ = add_readiness(socket, readiness);
                return Ok(ReactorReceiveOutcome::EndOfStream);
            }
            Ok((_buffer, received)) => {
                confirm_tcp_connected(socket);
                data.truncate(received);
                let terminal_readable = socket.read_shutdown
                    || socket
                        .snapshot
                        .lock()
                        .expect("Linux socket snapshot mutex poisoned")
                        .readiness
                        .contains(ReadinessFlags::HANGUP);
                if !flags.contains(LinuxRecvFlags::PEEK) && !terminal_readable {
                    let no_queued_data = ioctl_fionread(&socket.tcp_state()?.socket)
                        .is_ok_and(|available| available == 0);
                    if no_queued_data {
                        let _ = clear_readiness(socket, ReadinessFlags::READ);
                    }
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
                fail_connect(socket, error);
                let _ = consume_synchronous_error(socket);
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
                fail_connect(socket, SocketError::NotConnected);
                return Ok(SocketOutcome::Failed(SocketError::NotConnected));
            }
            Err(error) => {
                let error = socket_operation_error_from_errno(error)?;
                fail_connect(socket, error);
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
        let current = socket
            .snapshot
            .lock()
            .expect("Linux socket snapshot mutex poisoned")
            .readiness;
        let readiness = ReadinessFlags((current.0 & !clear.0) | add.0);
        // Native shutdown and the cached directional state are committed.
        let _ = update_snapshot(socket, None, readiness);
        if republish_readiness {
            let _ = socket.readiness.republish(readiness);
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
        let native_error = if socket.kind() == SocketKind::Udp {
            socket.udp_state()?.native_error
        } else {
            UdpNativeErrorState::None
        };
        let error = match native_error {
            UdpNativeErrorState::Consumed(error) => Some(error),
            UdpNativeErrorState::None | UdpNativeErrorState::PendingKernel => {
                take_socket_error(socket)?
            }
        };
        if socket.kind() == SocketKind::Udp {
            let udp = socket.udp_state_mut()?;
            udp.native_error = UdpNativeErrorState::None;
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
    // The synchronous response carries the consumed error and the cached
    // snapshot is authoritative. Notification failure must not discard the
    // caller's only observation of that error.
    let _ = publication;
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

fn confirm_tcp_connected(socket: &mut SocketEntry) {
    if socket.kind() != SocketKind::Tcp
        || socket.connection_status != SocketConnectionStatus::Connecting
    {
        return;
    }
    socket.connection_status = SocketConnectionStatus::Connected;
    let readiness = socket
        .snapshot
        .lock()
        .expect("Linux socket snapshot mutex poisoned")
        .readiness;
    let _ = update_snapshot(socket, Some(SocketConnectionStatus::Connected), readiness);
}

/// Records a terminal native operation while a connect is pending.
///
/// A reactor command that can call this helper must subsequently invoke
/// `Reactor::discard_failed_connect_after_command` after releasing its socket
/// table borrow.
fn fail_connect(socket: &mut SocketEntry, error: SocketError) {
    if socket.kind() != SocketKind::Tcp
        || socket.connection_status != SocketConnectionStatus::Connecting
    {
        return;
    }
    socket.connection_status = SocketConnectionStatus::Failed(error);
    let readiness = socket
        .snapshot
        .lock()
        .expect("Linux socket snapshot mutex poisoned")
        .readiness
        | ReadinessFlags::ERROR;
    let _ = update_snapshot(
        socket,
        Some(SocketConnectionStatus::Failed(error)),
        readiness,
    );
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
mod tests;
