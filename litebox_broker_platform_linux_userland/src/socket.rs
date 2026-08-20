// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Broker-owned Linux sockets driven by one epoll reactor.

use std::collections::HashMap;
use std::fmt;
use std::io::{Error, ErrorKind, Result as IoResult};
use std::net::SocketAddrV4;
use std::os::fd::OwnedFd;
use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, TryRecvError, sync_channel};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
#[cfg(test)]
use std::time::Duration;

use litebox_broker_core::socket::{
    AcceptedPlatformSocket, GuestSocketBinding, GuestSourceLease, PlatformConnectError,
    PlatformDatagramReceive, PlatformSocket, PlatformSocketStatus, PlatformStreamReceive,
    SocketProvider,
};
use litebox_broker_core::{BrokerError, Result as BrokerResult, SessionId};
use litebox_broker_protocol::readiness::ReadinessFlags;
use litebox_broker_protocol::socket::{
    AddressFamily, CreateSocketRequest, IpProtocol, MAX_UDP_DATAGRAM_SIZE, ReceiveFlags,
    ReceiveFromFlags, SendFlags, ShutdownMode, SocketConnectionStatus, SocketError, SocketOutcome,
    SocketType, TcpOptionName, TcpOptionValue,
};
use rustix::buffer::spare_capacity;
use rustix::event::{EventfdFlags, epoll, eventfd};
use rustix::io::{Errno, read, write};
use rustix::net::{getsockname, sockopt};

use litebox_broker_core::readiness::ReadinessRegistration;
#[cfg(test)]
use litebox_broker_protocol::socket::{MAX_SOCKET_TRANSFER_SIZE, SocketStatusResponse};

mod tcp;
mod udp;

#[cfg(test)]
use tcp::TcpDescriptor;
use tcp::{
    AcceptedEndpoints, ReactorReceiveOutcome, ReactorTcpState, TcpSocketState,
    consume_pending_guest_reset, create_tcp_transport, guest_reset_pending, handle_socket_event,
};
use udp::{
    ReactorUdpBinding, ReactorUdpPeer, ReactorUdpState, UDP_EVENT_TOKEN_FLAG, UdpReceiveOrigin,
    UdpSocketState, is_local_ipv4_address,
};

/// Epoll token reserved for the eventfd that wakes the reactor for commands.
const WAKE_TOKEN: u64 = 0;
const MAX_QUEUED_SOCKET_COMMANDS: usize = 64;
const MAX_EPOLL_EVENTS: usize = 64;

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
    fn bind(&self, binding: GuestSocketBinding) -> BrokerResult<SocketOutcome<SocketAddrV4>> {
        self.reactor.request(|response| ReactorCommand::Bind {
            id: self.id,
            binding,
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
                    local_address: accepted.local_address,
                    remote_address: accepted.remote_address,
                    guest_source_lease: accepted.guest_source_lease,
                }))
            }
            SocketOutcome::Failed(error) => Ok(SocketOutcome::Failed(error)),
        }
    }

    fn connect(
        &self,
        address: SocketAddrV4,
        guest_source_lease: Option<GuestSourceLease>,
    ) -> core::result::Result<SocketConnectionStatus, PlatformConnectError> {
        self.reactor.connect(self.id, address, guest_source_lease)
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

    fn status(&self) -> BrokerResult<PlatformSocketStatus> {
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
        // Block until the reactor has queue space rather than surfacing a
        // transiently full command queue as a resource error. A valid operation
        // always completes, and there is no Linux errno for "retry, the broker
        // is momentarily busy"; the caller already waits for the reactor's
        // acknowledgement below, so waiting for it to accept the command is the
        // same order of blocking. A send failure means the reactor is gone.
        if self.commands.send(command).is_err() {
            return Err(BrokerError::Internal);
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
        guest_source_lease: Option<GuestSourceLease>,
    ) -> core::result::Result<SocketConnectionStatus, PlatformConnectError> {
        let (response, receive) = sync_channel(1);
        let command = ReactorCommand::Connect {
            id,
            address,
            guest_source_lease,
            response,
        };
        // Block until the reactor has queue space (see `request`): a transiently
        // full command queue is internal backpressure, not a connect failure the
        // guest should see. A send failure means the reactor is gone, leaving
        // peer state indeterminate.
        if self.commands.send(command).is_err() {
            return Err(PlatformConnectError::PeerIndeterminate(
                BrokerError::Internal,
            ));
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
    fn queued_guest_connection_count(&self) -> usize {
        let (response, receive) = sync_channel(1);
        self.commands
            .send(ReactorCommand::QueuedGuestConnectionCount { response })
            .unwrap();
        self.signal().unwrap();
        receive.recv().unwrap()
    }

    #[cfg(test)]
    fn tcp_descriptor_counts(&self) -> (usize, usize, usize) {
        let (response, receive) = sync_channel(1);
        self.commands
            .send(ReactorCommand::TcpDescriptorCounts { response })
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
    fn udp_native_event_token_count(&self) -> usize {
        let (response, receive) = sync_channel(1);
        self.commands
            .send(ReactorCommand::UdpNativeEventTokenCount { response })
            .unwrap();
        self.signal().unwrap();
        receive.recv().unwrap()
    }

    #[cfg(test)]
    fn inject_udp_status_errors(
        &self,
        guest_port: u16,
        cached_error: SocketError,
        native_error: SocketError,
    ) {
        let (response, receive) = sync_channel(1);
        self.commands
            .send(ReactorCommand::InjectUdpStatusErrors {
                guest_port,
                cached_error,
                native_error,
                response,
            })
            .unwrap();
        self.signal().unwrap();
        receive.recv().unwrap().unwrap();
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
    fn exhaust_udp_event_tokens(&self) {
        let (response, receive) = sync_channel(1);
        self.commands
            .send(ReactorCommand::ExhaustUdpEventTokens { response })
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
        guest_source_lease: Option<GuestSourceLease>,
        response: SyncSender<core::result::Result<SocketConnectionStatus, PlatformConnectError>>,
    },
    Bind {
        id: u64,
        binding: GuestSocketBinding,
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
        response: SyncSender<BrokerResult<PlatformSocketStatus>>,
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
    QueuedGuestConnectionCount {
        response: SyncSender<usize>,
    },
    #[cfg(test)]
    TcpDescriptorCounts {
        response: SyncSender<(usize, usize, usize)>,
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
    UdpNativeEventTokenCount {
        response: SyncSender<usize>,
    },
    #[cfg(test)]
    InjectUdpStatusErrors {
        guest_port: u16,
        cached_error: SocketError,
        native_error: SocketError,
        response: SyncSender<BrokerResult<()>>,
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
    ExhaustUdpEventTokens {
        response: SyncSender<()>,
    },
    Stop {
        response: SyncSender<()>,
    },
}

enum ReactorReceiveFromOutcome {
    Received {
        data: Vec<u8>,
        datagram_length: usize,
        source_address: SocketAddrV4,
    },
    Failed(SocketError),
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
    events: Vec<epoll::Event>,
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

/// Reactor-side per-session socket and teardown state.
///
/// Sessions are ownership domains, not guest network namespaces.
#[derive(Default)]
struct ReactorSessionState {
    live_socket_count: usize,
    pending_guest_connection_count: usize,
    udp_external_peer_count: usize,
    udp_queued_datagrams: usize,
    udp_queued_bytes: usize,
    closing: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SocketKind {
    Tcp,
    Udp,
}

fn retain_session_state(state: &ReactorSessionState) -> bool {
    !state.closing
        || state.live_socket_count != 0
        || state.pending_guest_connection_count != 0
        || state.udp_external_peer_count != 0
        || state.udp_queued_datagrams != 0
        || state.udp_queued_bytes != 0
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
    fn is_private_udp_host_endpoint(&self, address: SocketAddrV4) -> bool {
        self.udp.is_private_host_port(address.port()) && is_local_ipv4_address(*address.ip())
    }

    fn bind_socket(
        &mut self,
        id: u64,
        binding: GuestSocketBinding,
    ) -> BrokerResult<SocketOutcome<SocketAddrV4>> {
        let requested_address = binding.requested();
        let (kind, already_bound) = self
            .sockets
            .get(&id)
            .map(|socket| (socket.kind(), socket.guest_local_address.is_some()))
            .ok_or(BrokerError::Internal)?;
        let binding_kind = if binding.is_tcp() {
            SocketKind::Tcp
        } else {
            SocketKind::Udp
        };
        if !binding.is_valid() || binding_kind != kind {
            return Err(BrokerError::Internal);
        }
        if kind == SocketKind::Udp {
            if already_bound {
                return Ok(SocketOutcome::Failed(SocketError::InvalidArgument));
            }
            self.udp.insert_binding(ReactorUdpBinding {
                socket_id: id,
                guest_binding: binding,
            })?;
            let socket = self.sockets.get_mut(&id).ok_or(BrokerError::Internal)?;
            socket.guest_local_address = Some(requested_address);
            socket
                .snapshot
                .lock()
                .expect("Linux socket snapshot mutex poisoned")
                .local_address = Some(requested_address);
            return Ok(SocketOutcome::Completed(requested_address));
        }
        self.bind_tcp_socket(id, binding, already_bound)
    }

    fn connect_socket(
        &mut self,
        id: u64,
        guest_address: SocketAddrV4,
        guest_source_lease: Option<GuestSourceLease>,
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
                        .native_endpoint
                        .as_ref()
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
                let binding = self
                    .udp
                    .binding_for_socket(id)
                    .ok_or(BrokerError::Internal)?;
                if binding.guest_binding.is_wildcard() {
                    let ip = match (&peer, &staged_endpoint, reused_host_address) {
                        (ReactorUdpPeer::Guest { guest_address, .. }, _, _) => {
                            return binding
                                .guest_binding
                                .guest_source_address(*guest_address)
                                .ok_or(BrokerError::Internal);
                        }
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
                self.replace_udp_endpoint(id, staged_endpoint.take())
                    .map_err(PlatformConnectError::PeerIndeterminate)?;
            }
            self.clear_udp_external_peers(id)
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
            let udp = socket
                .udp_state_mut()
                .map_err(PlatformConnectError::PeerIndeterminate)?;
            udp.peer = Some(peer);
            socket
                .snapshot
                .lock()
                .expect("Linux socket snapshot mutex poisoned")
                .local_address = Some(guest_local_address);
            update_snapshot(socket, Some(SocketConnectionStatus::Connected), readiness)
                .map_err(PlatformConnectError::PeerIndeterminate)?;
            return Ok(SocketConnectionStatus::Connected);
        }
        self.connect_tcp_guest(id, guest_address, guest_source_lease)
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
                let source_address = self
                    .udp
                    .binding_for_socket(id)
                    .and_then(|binding| binding.guest_binding.guest_source_address(guest_address))
                    .ok_or(BrokerError::Internal)?;
                if self
                    .udp
                    .binding_for_socket(socket_generation)
                    .is_none_or(|binding| !binding.guest_binding.covers(guest_address))
                {
                    return Ok(SocketOutcome::Failed(SocketError::ConnectionRefused));
                }
                self.enqueue_guest_datagram(id, socket_generation, source_address, data)
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
                    .native_endpoint
                    .as_ref()
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
                    self.replace_udp_endpoint(id, Some(endpoint))?;
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
            return self.shutdown_tcp_socket(socket_id, mode);
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
                if let Some(endpoint) = udp.native_endpoint.as_mut() {
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

    fn status_socket(&mut self, socket_id: u64) -> BrokerResult<PlatformSocketStatus> {
        let kind = self
            .sockets
            .get(&socket_id)
            .map(SocketEntry::kind)
            .ok_or(BrokerError::Internal)?;
        if kind == SocketKind::Udp {
            return self.status_udp_socket(socket_id);
        }
        status_socket(
            self.sockets
                .get_mut(&socket_id)
                .ok_or(BrokerError::Internal)?,
        )
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
            let _ = self.replace_udp_endpoint(id, None);
            if let Some(binding) = self.udp.binding_for_socket(id) {
                self.udp
                    .remove_binding(binding.guest_binding.requested().port(), id);
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

        self.remove_tcp_socket(id, session_id);
    }

    fn run(&mut self) -> core::result::Result<(), ReactorFailure> {
        loop {
            let mut events = core::mem::take(&mut self.events);
            events.clear();
            match epoll::wait(&self.epoll, spare_capacity(&mut events), None) {
                Ok(_) => {}
                Err(Errno::INTR) => {
                    self.events = events;
                    continue;
                }
                Err(error) => return Err(ReactorFailure::Io(error)),
            }
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
                } else if let Some(socket) = self.sockets.get_mut(&id) {
                    handle_socket_event(socket, event.flags).map_err(ReactorFailure::Broker)?;
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
                    guest_source_lease,
                    response,
                } => {
                    let outcome = self.connect_socket(id, address, guest_source_lease);
                    let peer_may_have_changed =
                        !matches!(&outcome, Err(PlatformConnectError::PeerUnchanged(_)));
                    if response.send(outcome).is_err() && peer_may_have_changed {
                        if let Some(socket) = self.sockets.get_mut(&id)
                            && let Ok(tcp) = socket.tcp_state_mut()
                        {
                            tcp.abortive_close = true;
                        }
                        self.remove_socket(id);
                    }
                }
                ReactorCommand::Bind {
                    id,
                    binding,
                    response,
                } => {
                    let outcome = self.bind_socket(id, binding);
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
                        if let Some(socket) = self.sockets.get_mut(&accepted_id)
                            && let Ok(tcp) = socket.tcp_state_mut()
                        {
                            tcp.abortive_close = true;
                        }
                        self.remove_socket(accepted_id);
                        lifecycle.reactor_removed();
                    }
                }
                ReactorCommand::Send { id, data, response } => {
                    let outcome = self.send_tcp_socket(id, &data);
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
                    let outcome =
                        self.receive_tcp_socket(id, length, flags, peek_offset, peek_length);
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
                    let outcome = self.shutdown_socket(id, mode);
                    let _ = response.send(outcome);
                }
                ReactorCommand::SetTcpOption {
                    id,
                    value,
                    response,
                } => {
                    let outcome = self.set_tcp_socket_option(id, value);
                    let _ = response.send(outcome);
                }
                ReactorCommand::GetTcpOption { id, name, response } => {
                    let outcome = self.get_tcp_socket_option(id, name);
                    let _ = response.send(outcome);
                }
                ReactorCommand::Status { id, response } => {
                    let outcome = self.status_socket(id);
                    let _ = response.send(outcome);
                }
                ReactorCommand::Close { id, response } => {
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
                    self.purge_connector_session_queues(session_id);
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
                        .udp
                        .bindings
                        .get(guest_port)
                        .and_then(|binding| self.sockets.get(&binding.socket_id))
                        .and_then(|socket| socket.udp_state().ok())
                        .and_then(|udp| udp.native_endpoint.as_ref())
                        .map(|endpoint| endpoint.host_address);
                    let _ = response.send(host_address);
                }
                #[cfg(test)]
                ReactorCommand::QueuedGuestConnectionCount { response } => {
                    let _ = response.send(self.tcp.queued_guest_connection_count);
                }
                #[cfg(test)]
                ReactorCommand::TcpDescriptorCounts { response } => {
                    let mut unrealized = 0;
                    let mut native = 0;
                    let mut guest = 0;
                    for descriptor in self
                        .sockets
                        .values()
                        .filter_map(|socket| socket.tcp_state().ok())
                        .map(|tcp| &tcp.descriptor)
                    {
                        match descriptor {
                            TcpDescriptor::Unrealized => unrealized += 1,
                            TcpDescriptor::NativeInet(_) => native += 1,
                            TcpDescriptor::GuestUnix(_) => guest += 1,
                        }
                    }
                    let _ = response.send((unrealized, native, guest));
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
                ReactorCommand::UdpNativeEventTokenCount { response } => {
                    let _ = response.send(self.udp.event_tokens.len());
                }
                #[cfg(test)]
                ReactorCommand::InjectUdpStatusErrors {
                    guest_port,
                    cached_error,
                    native_error,
                    response,
                } => {
                    let outcome =
                        self.inject_udp_status_errors(guest_port, cached_error, native_error);
                    let _ = response.send(outcome);
                }
                #[cfg(test)]
                ReactorCommand::UdpNativeReceiveBufferSize {
                    guest_port,
                    response,
                } => {
                    let size = self
                        .udp
                        .bindings
                        .get(guest_port)
                        .and_then(|binding| self.sockets.get(&binding.socket_id))
                        .and_then(|socket| socket.udp_state().ok())
                        .and_then(|udp| udp.native_endpoint.as_ref())
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
                        .get(guest_port)
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
                            .get(guest_port)
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
                            .native_endpoint
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
                            .native_endpoint
                            .as_ref()
                            .map(|endpoint| endpoint.readable)
                            .ok_or(BrokerError::Internal)?;
                        let head_datagram_bytes = self.udp_native_head_datagram_bytes(socket_id)?;
                        Ok((readable, head_datagram_bytes))
                    })();
                    let _ = response.send(outcome);
                }
                #[cfg(test)]
                ReactorCommand::ExhaustUdpEventTokens { response } => {
                    self.udp.next_event_token = UDP_EVENT_TOKEN_FLAG - 1;
                    let _ = response.send(());
                }
                ReactorCommand::Stop { response } => {
                    while let Some(id) = self.sockets.keys().next().copied() {
                        self.remove_socket(id);
                    }
                    self.tcp.clear_live_state();
                    self.udp.clear_live_state();
                    self.sessions.clear();
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
            .checked_add(self.tcp.queued_guest_connection_count)
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
            .checked_add(session.pending_guest_connection_count)
            .is_none_or(|count| count >= self.max_sockets_per_session)
        {
            return Err(BrokerError::ResourceExhausted);
        }
        let (transport, initial_readiness) = match kind {
            SocketKind::Tcp => (create_tcp_transport(), ReadinessFlags::default()),
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
        self.tcp.clear_live_state();
        self.udp.clear_live_state();
        self.sessions.clear();
    }
}

fn zeroed_vec(length: usize) -> BrokerResult<Vec<u8>> {
    let mut data = Vec::new();
    data.try_reserve_exact(length)
        .map_err(|_| BrokerError::OutOfMemory)?;
    data.resize(length, 0);
    Ok(data)
}

fn take_socket_error(socket: &SocketEntry) -> BrokerResult<Option<SocketError>> {
    let tcp = socket.tcp_state()?;
    if !tcp.descriptor.is_native() {
        return Ok(None);
    }
    let native_socket = tcp.descriptor.socket()?;
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

fn status_socket(socket: &mut SocketEntry) -> BrokerResult<PlatformSocketStatus> {
    let query_socket_error = {
        let snapshot = socket
            .snapshot
            .lock()
            .expect("Linux socket snapshot mutex poisoned");
        socket.connection_status == SocketConnectionStatus::Connected
            && snapshot.readiness.contains(ReadinessFlags::ERROR)
    };
    let socket_error = if query_socket_error {
        take_socket_error(socket)?
    } else {
        None
    };
    let pending_guest_reset = guest_reset_pending(socket)?;
    let (response, readiness, republish_error) = {
        let mut snapshot = socket
            .snapshot
            .lock()
            .expect("Linux socket snapshot mutex poisoned");
        let cached_error = snapshot.pending_error.take();
        let socket_error =
            if pending_guest_reset && cached_error != Some(SocketError::ConnectionReset) {
                Some(SocketError::ConnectionReset)
            } else {
                socket_error
            };
        let (pending_error, next_pending_error) = shift_pending_error(cached_error, socket_error);
        snapshot.pending_error = next_pending_error;
        if pending_error.is_some() && next_pending_error.is_none() {
            snapshot.readiness = ReadinessFlags(snapshot.readiness.0 & !ReadinessFlags::ERROR.0);
        }
        (
            PlatformSocketStatus {
                status: socket.connection_status,
                local_address: snapshot.local_address,
                pending_error,
            },
            snapshot.readiness,
            next_pending_error.is_some(),
        )
    };
    if pending_guest_reset
        && response.pending_error == Some(SocketError::ConnectionReset)
        && !consume_pending_guest_reset(socket)?
    {
        return Err(BrokerError::Internal);
    }
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
