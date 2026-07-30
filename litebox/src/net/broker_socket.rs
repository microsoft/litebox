// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use alloc::sync::{Arc, Weak};
use core::{
    net::{SocketAddr, SocketAddrV4},
    sync::atomic::{AtomicBool, Ordering},
};

use litebox_broker_protocol::ObjectHandle;
use litebox_broker_protocol::socket::{
    Ipv4Address, MAX_SOCKET_TRANSFER_SIZE, Port, ReceiveFlags as BrokerReceiveFlags,
    ReceiveSocketResponse, SendFlags as BrokerSendFlags, ShutdownMode,
    SocketAddressV4 as BrokerSocketAddressV4, SocketConnectionStatus,
    SocketError as BrokerSocketError, SocketOutcome, SocketStatusResponse,
};

use super::{
    ReceiveFlags,
    errors::{ConnectError, RemoteAddrError, SocketAsyncError},
    socket_channel::{ChannelReadError, ChannelWriteError, SocketState},
};
use crate::{
    broker::{BrokerControl, BrokerPollableRegistry, error::BrokerObjectError, readiness_events},
    event::{Events, IOPollable, observer::Observer, polling::Pollee},
    platform::TimeProvider,
    sync::{Mutex, RawSyncPrimitivesProvider},
};

struct BrokerSocketState {
    connection: SocketConnectionStatus,
    local_address: Option<SocketAddrV4>,
    remote_address: Option<SocketAddrV4>,
    nodelay: bool,
    keep_alive: Option<core::time::Duration>,
    congestion: super::CongestionControl,
    async_error: u32,
}

/// Local state and readiness adapter for one broker-owned TCP socket.
pub struct BrokerTcpSocket<Platform: RawSyncPrimitivesProvider + TimeProvider> {
    broker: Arc<dyn BrokerControl>,
    handle: ObjectHandle,
    pollable_registry: Arc<BrokerPollableRegistry<Platform>>,
    pollee: Arc<Pollee<Platform>>,
    connect_lock: Mutex<Platform, ()>,
    state: Mutex<Platform, BrokerSocketState>,
    read_shutdown: AtomicBool,
    write_shutdown: AtomicBool,
}

impl<Platform: RawSyncPrimitivesProvider + TimeProvider> BrokerTcpSocket<Platform> {
    pub(super) fn new(
        broker: Arc<dyn BrokerControl>,
        pollable_registry: Arc<BrokerPollableRegistry<Platform>>,
    ) -> Result<Arc<Self>, BrokerObjectError> {
        let handle = broker
            .create_tcp_socket()
            .map_err(BrokerObjectError::from)?;
        let socket = Arc::new(Self {
            broker,
            handle,
            pollable_registry,
            pollee: Arc::new(Pollee::new()),
            connect_lock: Mutex::new(()),
            state: Mutex::new(BrokerSocketState {
                connection: SocketConnectionStatus::Unconnected,
                local_address: None,
                remote_address: None,
                nodelay: false,
                keep_alive: None,
                congestion: super::CongestionControl::None,
                async_error: 0,
            }),
            read_shutdown: AtomicBool::new(false),
            write_shutdown: AtomicBool::new(false),
        });
        socket
            .pollable_registry
            .register_pollable(handle, &socket.pollee);
        Ok(socket)
    }

    pub(super) fn connect(
        &self,
        address: SocketAddrV4,
        check_progress: bool,
    ) -> Result<(), ConnectError> {
        let _connect = self.connect_lock.lock();
        if check_progress {
            let response = self
                .broker
                .socket_status(self.handle)
                .map_err(|error| ConnectError::Socket(socket_error_from_control(error.into())))?;
            let status = response.status;
            self.apply_status_response(response);
            return self.update_connection_status(status, None);
        }
        let previous = self.state.lock().connection;
        let outcome = self
            .broker
            .connect_socket(
                self.handle,
                BrokerSocketAddressV4 {
                    address: Ipv4Address(address.ip().octets()),
                    port: Port(address.port()),
                },
            )
            .map_err(|error| ConnectError::Socket(socket_error_from_control(error.into())))?;
        let status = match outcome {
            SocketOutcome::Completed(status) => status,
            SocketOutcome::Failed(error) => {
                let error = socket_error(error);
                self.consume_synchronous_error();
                return Err(ConnectError::Socket(error));
            }
        };
        let remote_address = (previous == SocketConnectionStatus::Unconnected).then_some(address);
        self.update_connection_status(status, remote_address)
    }

    pub(super) fn remote_addr(&self) -> Result<SocketAddr, RemoteAddrError> {
        self.refresh_status(false);
        let state = self.state.lock();
        if state.connection != SocketConnectionStatus::Connected {
            return Err(RemoteAddrError::NotConnected);
        }
        state
            .remote_address
            .map(SocketAddr::V4)
            .ok_or(RemoteAddrError::NotConnected)
    }

    pub(super) fn local_addr(&self) -> SocketAddr {
        self.refresh_status(true);
        self.state.lock().local_address.map_or_else(
            || SocketAddr::V4(SocketAddrV4::new(core::net::Ipv4Addr::UNSPECIFIED, 0)),
            SocketAddr::V4,
        )
    }

    pub(super) fn shutdown(&self, mode: ShutdownMode) -> Result<(), SocketAsyncError> {
        match self
            .broker
            .shutdown_socket(self.handle, mode)
            .map_err(|error| socket_error_from_control(error.into()))?
        {
            SocketOutcome::Completed(()) => {
                if matches!(mode, ShutdownMode::Read | ShutdownMode::Both) {
                    self.read_shutdown.store(true, Ordering::Release);
                }
                if matches!(mode, ShutdownMode::Write | ShutdownMode::Both) {
                    self.write_shutdown.store(true, Ordering::Release);
                    self.pollee.notify_observers(Events::OUT);
                }
                Ok(())
            }
            SocketOutcome::Failed(error) => {
                let error = socket_error(error);
                self.consume_synchronous_error();
                Err(error)
            }
        }
    }

    pub(super) fn set_tcp_option(&self, option: super::TcpOptionData) {
        let mut state = self.state.lock();
        match option {
            super::TcpOptionData::NODELAY(nodelay) => state.nodelay = nodelay,
            super::TcpOptionData::KEEPALIVE(keep_alive) => state.keep_alive = keep_alive,
            super::TcpOptionData::CONGESTION(congestion) => state.congestion = congestion,
        }
    }

    pub(super) fn get_tcp_option(&self, name: super::TcpOptionName) -> super::TcpOptionData {
        let state = self.state.lock();
        match name {
            super::TcpOptionName::NODELAY => super::TcpOptionData::NODELAY(state.nodelay),
            super::TcpOptionName::KEEPALIVE => super::TcpOptionData::KEEPALIVE(state.keep_alive),
            super::TcpOptionName::CONGESTION => {
                super::TcpOptionData::CONGESTION(match state.congestion {
                    super::CongestionControl::None => super::CongestionControl::None,
                    super::CongestionControl::Reno => super::CongestionControl::Reno,
                    super::CongestionControl::Cubic => super::CongestionControl::Cubic,
                })
            }
        }
    }

    pub(super) fn set_state(&self, state: SocketState) {
        let connection = match state {
            SocketState::Initial => SocketConnectionStatus::Unconnected,
            SocketState::Connecting => SocketConnectionStatus::Connecting,
            SocketState::Connected => SocketConnectionStatus::Connected,
            SocketState::Error => self.state.lock().connection,
            SocketState::Listening | SocketState::Closed => return,
        };
        update_connection_state(&mut self.state.lock(), connection);
    }

    pub(super) fn set_async_error(&self, error: SocketAsyncError) {
        self.state.lock().async_error = error as u32;
    }

    pub(super) fn get_async_error(&self, clear: bool) -> Option<SocketAsyncError> {
        self.refresh_status(true);
        let mut state = self.state.lock();
        let raw = state.async_error;
        if clear {
            state.async_error = 0;
        }
        let failed = matches!(state.connection, SocketConnectionStatus::Failed(_));
        drop(state);
        if clear && raw != 0 && failed {
            self.pollee
                .notify_observers(Events::IN | Events::OUT | Events::HUP);
        }
        SocketAsyncError::from_u32(raw)
    }

    pub(super) fn try_read(
        &self,
        buffer: &mut [u8],
        flags: ReceiveFlags,
        source_address: Option<&mut Option<SocketAddr>>,
    ) -> Result<usize, ChannelReadError> {
        if self.read_shutdown.load(Ordering::Acquire) {
            return Err(ChannelReadError::ReadShutdown);
        }
        if let Some(source_address) = source_address {
            *source_address = None;
        }
        if buffer.is_empty() {
            return Ok(0);
        }
        let length = buffer.len().min(MAX_SOCKET_TRANSFER_SIZE as usize);
        let discard = flags.contains(ReceiveFlags::DISCARD);
        let flags = if flags.contains(ReceiveFlags::PEEK) {
            BrokerReceiveFlags::PEEK
        } else {
            BrokerReceiveFlags::NONE
        };
        let outcome =
            match self
                .broker
                .receive_socket(self.handle, &mut buffer[..length], flags, discard)
            {
                Ok(outcome) => outcome,
                Err(error) => {
                    let error = BrokerObjectError::from(error);
                    if error == BrokerObjectError::WouldBlock {
                        return Ok(0);
                    }
                    return Err(read_error_from_control(error));
                }
            };
        match outcome {
            SocketOutcome::Completed(ReceiveSocketResponse::Received(received)) => {
                let received = usize::try_from(received)
                    .map_err(|_| ChannelReadError::Socket(SocketAsyncError::Other))?;
                Ok(received)
            }
            SocketOutcome::Completed(ReceiveSocketResponse::EndOfStream) => {
                Err(ChannelReadError::ConnectionClosed)
            }
            SocketOutcome::Completed(_) => Err(ChannelReadError::Socket(SocketAsyncError::Other)),
            SocketOutcome::Failed(error) => {
                let error = socket_error(error);
                self.consume_synchronous_error();
                Err(ChannelReadError::Socket(error))
            }
        }
    }

    pub(super) fn try_write(&self, buffer: &[u8]) -> Result<usize, ChannelWriteError> {
        if self.write_shutdown.load(Ordering::Acquire) {
            return Err(ChannelWriteError::WriteShutdown);
        }
        if buffer.is_empty() {
            return Ok(0);
        }
        let length = buffer.len().min(MAX_SOCKET_TRANSFER_SIZE as usize);
        let outcome = self
            .broker
            .send_socket(self.handle, &buffer[..length], BrokerSendFlags::NONE)
            .map_err(|error| write_error_from_control(error.into()))?;
        match outcome {
            SocketOutcome::Completed(sent) => Ok(sent),
            SocketOutcome::Failed(error) => {
                let error = socket_error(error);
                self.consume_synchronous_error();
                Err(ChannelWriteError::Socket(error))
            }
        }
    }

    fn update_connection_status(
        &self,
        status: SocketConnectionStatus,
        remote_address: Option<SocketAddrV4>,
    ) -> Result<(), ConnectError> {
        let status = {
            let mut state = self.state.lock();
            let status = update_connection_state(&mut state, status);
            if state.remote_address.is_none() {
                state.remote_address = remote_address;
            }
            status
        };
        match status {
            SocketConnectionStatus::Connected => Ok(()),
            SocketConnectionStatus::Connecting => Err(ConnectError::InProgress),
            SocketConnectionStatus::Failed(error) => {
                let error = socket_error(error);
                self.consume_synchronous_error();
                Err(ConnectError::Socket(error))
            }
            SocketConnectionStatus::Unconnected => Err(ConnectError::InvalidState),
            _ => Err(ConnectError::Socket(SocketAsyncError::Other)),
        }
    }

    fn refresh_status(&self, include_connected: bool) {
        let connection = self.state.lock().connection;
        if connection != SocketConnectionStatus::Connecting
            && !(include_connected && connection == SocketConnectionStatus::Connected)
        {
            return;
        }
        match self.broker.socket_status(self.handle) {
            Ok(response) => self.apply_status_response(response),
            Err(error) => self.set_async_error(socket_error_from_control(error.into())),
        }
    }

    fn apply_status_response(&self, response: SocketStatusResponse) {
        let mut state = self.state.lock();
        let previous_connection = state.connection;
        let connection = update_connection_state(&mut state, response.status);
        let connection_error = match (previous_connection, connection) {
            (
                SocketConnectionStatus::Unconnected | SocketConnectionStatus::Connecting,
                SocketConnectionStatus::Failed(error),
            ) => Some(error),
            _ => None,
        };
        if let Some(address) = response.local_address {
            state.local_address = Some(SocketAddrV4::new(
                core::net::Ipv4Addr::from(address.address.0),
                address.port.0,
            ));
        }

        if let Some(error) = response.pending_error {
            state.async_error = socket_error(error) as u32;
        } else if let Some(error) = connection_error {
            state.async_error = socket_error(error) as u32;
        }
    }

    fn consume_synchronous_error(&self) {
        self.refresh_status(true);
        let mut state = self.state.lock();
        state.async_error = 0;
        let failed = matches!(state.connection, SocketConnectionStatus::Failed(_));
        drop(state);
        if failed {
            self.pollee
                .notify_observers(Events::IN | Events::OUT | Events::HUP);
        }
    }
}

fn update_connection_state(
    state: &mut BrokerSocketState,
    connection: SocketConnectionStatus,
) -> SocketConnectionStatus {
    if matches!(
        state.connection,
        SocketConnectionStatus::Connected | SocketConnectionStatus::Failed(_)
    ) {
        return state.connection;
    }
    state.connection = connection;
    connection
}

impl<Platform: RawSyncPrimitivesProvider + TimeProvider> IOPollable for BrokerTcpSocket<Platform> {
    fn register_observer(&self, observer: Weak<dyn Observer<Events>>, mut filter: Events) {
        if filter.contains(Events::RDHUP) {
            filter.insert(Events::HUP);
        }
        self.pollee.register_observer(observer, filter);
    }

    fn check_io_events(&self) -> Events {
        let (mut events, broker_readiness_available) =
            match self.broker.check_readiness(self.handle) {
                Ok(readiness) => (socket_readiness_events(readiness), true),
                Err(_) => (Events::ERR, false),
            };
        let connection = self.state.lock().connection;
        if connection == SocketConnectionStatus::Connecting
            || events.intersects(Events::OUT | Events::ERR)
        {
            self.refresh_status(events.contains(Events::ERR));
        }
        let state = self.state.lock();
        let connection = state.connection;
        let has_async_error = state.async_error != 0;
        drop(state);
        if has_async_error {
            events.insert(Events::ERR);
        } else if broker_readiness_available
            && matches!(connection, SocketConnectionStatus::Failed(_))
        {
            events.remove(Events::ERR);
        }
        if matches!(connection, SocketConnectionStatus::Failed(_)) {
            events.insert(Events::IN | Events::OUT | Events::HUP);
        }
        if self.write_shutdown.load(Ordering::Acquire) {
            events.insert(Events::OUT);
        }
        events
    }
}

fn socket_readiness_events(
    readiness: litebox_broker_protocol::readiness::ReadinessFlags,
) -> Events {
    let mut events = readiness_events(readiness);
    events.set(
        Events::RDHUP,
        readiness.contains(litebox_broker_protocol::readiness::ReadinessFlags::HANGUP),
    );
    events.remove(Events::HUP);
    events
}

impl<Platform: RawSyncPrimitivesProvider + TimeProvider> Drop for BrokerTcpSocket<Platform> {
    fn drop(&mut self) {
        self.pollable_registry.unregister_pollable(self.handle);
        let _ = self.broker.close_object(self.handle);
    }
}

fn read_error_from_control(error: BrokerObjectError) -> ChannelReadError {
    match error {
        BrokerObjectError::WouldBlock => ChannelReadError::Socket(SocketAsyncError::Other),
        BrokerObjectError::PeerClosed => ChannelReadError::ConnectionClosed,
        error => ChannelReadError::Socket(socket_error_from_control(error)),
    }
}

fn write_error_from_control(error: BrokerObjectError) -> ChannelWriteError {
    match error {
        BrokerObjectError::WouldBlock => ChannelWriteError::BufferFull,
        BrokerObjectError::PeerClosed => ChannelWriteError::ConnectionClosed,
        error => ChannelWriteError::Socket(socket_error_from_control(error)),
    }
}

const fn socket_error_from_control(error: BrokerObjectError) -> SocketAsyncError {
    match error {
        BrokerObjectError::Control
        | BrokerObjectError::InvalidObject
        | BrokerObjectError::PeerClosed
        | BrokerObjectError::WouldBlock => SocketAsyncError::Other,
        BrokerObjectError::ResourceExhausted | BrokerObjectError::OutOfMemory => {
            SocketAsyncError::ResourceExhausted
        }
        BrokerObjectError::PermissionDenied => SocketAsyncError::PolicyDenied,
        BrokerObjectError::UnsupportedOperation => SocketAsyncError::UnsupportedOperation,
    }
}

const fn socket_error(error: BrokerSocketError) -> SocketAsyncError {
    match error {
        BrokerSocketError::ConnectionRefused => SocketAsyncError::ConnectionRefused,
        BrokerSocketError::ConnectionReset => SocketAsyncError::ConnectionReset,
        BrokerSocketError::ConnectionAborted => SocketAsyncError::ConnectionAborted,
        BrokerSocketError::NetworkUnreachable => SocketAsyncError::NetworkUnreachable,
        BrokerSocketError::HostUnreachable => SocketAsyncError::HostUnreachable,
        BrokerSocketError::TimedOut => SocketAsyncError::TimedOut,
        BrokerSocketError::AddressInUse => SocketAsyncError::AddressInUse,
        BrokerSocketError::AddressNotAvailable => SocketAsyncError::AddressNotAvailable,
        BrokerSocketError::NotConnected => SocketAsyncError::NotConnected,
        BrokerSocketError::PolicyDenied => SocketAsyncError::PolicyDenied,
        _ => SocketAsyncError::Other,
    }
}
