// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use alloc::sync::{Arc, Weak};
use core::{
    net::{SocketAddr, SocketAddrV4},
    sync::atomic::{AtomicBool, Ordering},
};

use litebox_broker_protocol::ObjectHandle;
use litebox_broker_protocol::socket::{
    Ipv4Address, MAX_SOCKET_PEEK_SIZE, MAX_SOCKET_TRANSFER_SIZE, Port,
    ReceiveFlags as BrokerReceiveFlags, ReceiveSocketResponse, SendFlags as BrokerSendFlags,
    ShutdownMode, SocketAddressV4 as BrokerSocketAddressV4, SocketConnectionStatus,
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

const _: () = assert!(MAX_SOCKET_PEEK_SIZE as usize == super::SOCKET_RECEIVE_OPERATION_SIZE);

struct BrokerSocketState {
    connection: SocketConnectionStatus,
    local_address: Option<SocketAddrV4>,
    remote_address: Option<SocketAddrV4>,
    async_error: u32,
}

impl BrokerSocketState {
    fn update_connection(&mut self, connection: SocketConnectionStatus) -> SocketConnectionStatus {
        if matches!(
            self.connection,
            SocketConnectionStatus::Connected | SocketConnectionStatus::Failed(_)
        ) {
            return self.connection;
        }
        self.connection = connection;
        connection
    }
}

/// Local state and readiness adapter for one broker-owned TCP socket.
pub struct BrokerTcpSocket<Platform: RawSyncPrimitivesProvider + TimeProvider> {
    broker: Arc<dyn BrokerControl>,
    handle: ObjectHandle,
    pollable_registry: Arc<BrokerPollableRegistry<Platform>>,
    pollee: Arc<Pollee<Platform>>,
    receive_lock: Mutex<Platform, ()>,
    state: Mutex<Platform, BrokerSocketState>,
    write_shutdown: AtomicBool,
    closed: AtomicBool,
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
            receive_lock: Mutex::new(()),
            state: Mutex::new(BrokerSocketState {
                connection: SocketConnectionStatus::Unconnected,
                local_address: None,
                remote_address: None,
                async_error: 0,
            }),
            write_shutdown: AtomicBool::new(false),
            closed: AtomicBool::new(false),
        });
        socket
            .pollable_registry
            .register_pollable(handle, &socket.pollee);
        Ok(socket)
    }

    pub(super) fn start_connect(&self, address: SocketAddrV4) -> Result<(), ConnectError> {
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
            .map_err(|error| {
                ConnectError::OperationFailed(BrokerObjectError::from(error).into())
            })?;
        let status = match outcome {
            SocketOutcome::Completed(status) => status,
            SocketOutcome::Failed(error) => {
                let error = error.into();
                self.consume_synchronous_error();
                return Err(ConnectError::OperationFailed(error));
            }
        };
        let remote_address = (previous == SocketConnectionStatus::Unconnected).then_some(address);
        self.handle_connect_status(status, remote_address)
    }

    pub(super) fn check_connect_progress(&self) -> Result<(), ConnectError> {
        let response = self.broker.socket_status(self.handle).map_err(|error| {
            ConnectError::OperationFailed(BrokerObjectError::from(error).into())
        })?;
        let status = response.status;
        self.apply_socket_status(response);
        self.handle_connect_status(status, None)
    }

    pub(super) fn remote_addr(&self) -> Result<SocketAddr, RemoteAddrError> {
        self.refresh_connection_status(false);
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
        self.refresh_connection_status(true);
        self.state.lock().local_address.map_or_else(
            || SocketAddr::V4(SocketAddrV4::new(core::net::Ipv4Addr::UNSPECIFIED, 0)),
            SocketAddr::V4,
        )
    }

    pub(super) fn shutdown(&self, mode: ShutdownMode) -> Result<(), SocketAsyncError> {
        match self
            .broker
            .shutdown_socket(self.handle, mode)
            .map_err(|error| SocketAsyncError::from(BrokerObjectError::from(error)))?
        {
            SocketOutcome::Completed(()) => {
                if matches!(mode, ShutdownMode::Write | ShutdownMode::Both) {
                    self.write_shutdown.store(true, Ordering::Release);
                    self.pollee.notify_observers(Events::OUT);
                }
                Ok(())
            }
            SocketOutcome::Failed(error) => {
                let error = error.into();
                Err(error)
            }
        }
    }

    pub(super) fn set_state(&self, state: SocketState) {
        if state == SocketState::Closed {
            self.close(false);
            return;
        }
        if self.closed.load(Ordering::Acquire) {
            return;
        }
        let connection = match state {
            SocketState::Initial => SocketConnectionStatus::Unconnected,
            SocketState::Connecting => SocketConnectionStatus::Connecting,
            SocketState::Connected => SocketConnectionStatus::Connected,
            SocketState::Error => self.state.lock().connection,
            SocketState::Listening | SocketState::Closed => return,
        };
        self.state.lock().update_connection(connection);
    }

    pub(super) fn set_async_error(&self, error: SocketAsyncError) {
        if self.closed.load(Ordering::Acquire) {
            return;
        }
        self.state.lock().async_error = error as u32;
    }

    pub(super) fn get_async_error(&self, clear: bool) -> Option<SocketAsyncError> {
        if self.closed.load(Ordering::Acquire) {
            return None;
        }
        self.refresh_connection_status(true);
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
        if self.closed.load(Ordering::Acquire) {
            return Err(ChannelReadError::ConnectionClosed);
        }
        if let Some(source_address) = source_address {
            *source_address = None;
        }
        if buffer.is_empty() {
            return Ok(0);
        }
        let _receive = self.receive_lock.lock();
        let discard = flags.contains(ReceiveFlags::DISCARD);
        let mut broker_flags = BrokerReceiveFlags::NONE;
        let peek = flags.contains(ReceiveFlags::PEEK);
        let wait_all = flags.contains(ReceiveFlags::WAITALL);
        if peek {
            broker_flags.0 |= BrokerReceiveFlags::PEEK.0;
        }
        if wait_all {
            broker_flags.0 |= BrokerReceiveFlags::WAITALL.0;
        }
        let target = if peek {
            buffer.len().min(MAX_SOCKET_PEEK_SIZE as usize)
        } else {
            buffer.len().min(MAX_SOCKET_TRANSFER_SIZE as usize)
        };
        let mut offset = 0;
        loop {
            let length = (target - offset).min(MAX_SOCKET_TRANSFER_SIZE as usize);
            let outcome = match self.broker.receive_socket(
                self.handle,
                &mut buffer[offset..offset + length],
                broker_flags,
                u32::try_from(offset)
                    .map_err(|_| ChannelReadError::Socket(SocketAsyncError::BackendFailure))?,
                if peek {
                    u32::try_from(target)
                        .map_err(|_| ChannelReadError::Socket(SocketAsyncError::BackendFailure))?
                } else {
                    0
                },
                discard,
            ) {
                Ok(outcome) => outcome,
                Err(error) => {
                    if self.closed.load(Ordering::Acquire) {
                        return Err(ChannelReadError::ConnectionClosed);
                    }
                    let error = BrokerObjectError::from(error);
                    if error == BrokerObjectError::WouldBlock {
                        if offset != 0 {
                            return Ok(offset);
                        }
                        return Err(ChannelReadError::WouldBlock);
                    }
                    return Err(error.into());
                }
            };
            match outcome {
                SocketOutcome::Completed(ReceiveSocketResponse::Received(received)) => {
                    let received = usize::try_from(received)
                        .map_err(|_| ChannelReadError::Socket(SocketAsyncError::BackendFailure))?;
                    offset += received;
                    if !peek || received < length || offset == target {
                        return Ok(offset);
                    }
                }
                SocketOutcome::Completed(ReceiveSocketResponse::EndOfStream) => {
                    return if offset == 0 {
                        Err(ChannelReadError::ConnectionClosed)
                    } else {
                        Ok(offset)
                    };
                }
                SocketOutcome::Completed(_) => {
                    return Err(ChannelReadError::Socket(SocketAsyncError::BackendFailure));
                }
                SocketOutcome::Failed(error) => {
                    let error = error.into();
                    self.consume_synchronous_error();
                    if offset != 0 {
                        self.set_async_error(error);
                        return Ok(offset);
                    }
                    return Err(ChannelReadError::Socket(error));
                }
            }
        }
    }

    pub(super) fn try_write(&self, buffer: &[u8]) -> Result<usize, ChannelWriteError> {
        if self.closed.load(Ordering::Acquire) {
            return Err(ChannelWriteError::ConnectionClosed);
        }
        if self.write_shutdown.load(Ordering::Acquire) {
            return Err(ChannelWriteError::WriteShutdown);
        }
        let length = buffer.len().min(MAX_SOCKET_TRANSFER_SIZE as usize);
        let outcome = self
            .broker
            .send_socket(self.handle, &buffer[..length], BrokerSendFlags::NONE)
            .map_err(|error| {
                if self.closed.load(Ordering::Acquire) {
                    ChannelWriteError::ConnectionClosed
                } else {
                    ChannelWriteError::from(BrokerObjectError::from(error))
                }
            })?;
        match outcome {
            SocketOutcome::Completed(sent) => Ok(sent),
            SocketOutcome::Failed(error) => {
                let error = error.into();
                self.consume_synchronous_error();
                Err(ChannelWriteError::Socket(error))
            }
        }
    }

    fn handle_connect_status(
        &self,
        status: SocketConnectionStatus,
        remote_address: Option<SocketAddrV4>,
    ) -> Result<(), ConnectError> {
        let status = {
            let mut state = self.state.lock();
            let status = state.update_connection(status);
            if state.remote_address.is_none() {
                state.remote_address = remote_address;
            }
            status
        };
        match status {
            SocketConnectionStatus::Connected => Ok(()),
            SocketConnectionStatus::Connecting => Err(ConnectError::InProgress),
            SocketConnectionStatus::Failed(error) => {
                let error = error.into();
                self.consume_synchronous_error();
                Err(ConnectError::OperationFailed(error))
            }
            SocketConnectionStatus::Unconnected => Err(ConnectError::InvalidState),
            _ => Err(ConnectError::OperationFailed(
                SocketAsyncError::BackendFailure,
            )),
        }
    }

    fn refresh_connection_status(&self, include_connected: bool) {
        if self.closed.load(Ordering::Acquire) {
            return;
        }
        let connection = self.state.lock().connection;
        if connection != SocketConnectionStatus::Connecting
            && !(include_connected && connection == SocketConnectionStatus::Connected)
        {
            return;
        }
        match self.broker.socket_status(self.handle) {
            Ok(response) => self.apply_socket_status(response),
            Err(error) if !self.closed.load(Ordering::Acquire) => {
                self.set_async_error(BrokerObjectError::from(error).into());
            }
            Err(_) => {}
        }
    }

    fn apply_socket_status(&self, response: SocketStatusResponse) {
        let mut state = self.state.lock();
        let previous_connection = state.connection;
        let connection = state.update_connection(response.status);
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
            state.async_error = SocketAsyncError::from(error) as u32;
        } else if let Some(error) = connection_error {
            state.async_error = SocketAsyncError::from(error) as u32;
        }
    }

    fn consume_synchronous_error(&self) {
        self.refresh_connection_status(true);
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

impl<Platform: RawSyncPrimitivesProvider + TimeProvider> IOPollable for BrokerTcpSocket<Platform> {
    fn register_observer(&self, observer: Weak<dyn Observer<Events>>, mut filter: Events) {
        if filter.contains(Events::RDHUP) {
            filter.insert(Events::HUP);
        }
        self.pollee.register_observer(observer, filter);
    }

    fn check_io_events(&self) -> Events {
        if self.closed.load(Ordering::Acquire) {
            return Events::OUT | Events::HUP;
        }
        let (mut events, broker_readiness_available) =
            match self.broker.check_readiness(self.handle) {
                Ok(readiness) => (socket_readiness_events(readiness), true),
                Err(_) => (Events::ERR, false),
            };
        let connection = self.state.lock().connection;
        if connection == SocketConnectionStatus::Connecting
            || events.intersects(Events::OUT | Events::ERR)
        {
            self.refresh_connection_status(events.contains(Events::ERR));
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

impl<Platform: RawSyncPrimitivesProvider + TimeProvider> BrokerTcpSocket<Platform> {
    pub(super) fn close(&self, abortive: bool) {
        if self.closed.swap(true, Ordering::AcqRel) {
            return;
        }
        self.pollable_registry.unregister_pollable(self.handle);
        if abortive {
            let _ = self
                .broker
                .shutdown_socket(self.handle, ShutdownMode::Abort);
        }
        let _ = self.broker.close_object(self.handle);
        self.pollee.notify_observers(Events::OUT | Events::HUP);
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
        self.close(false);
    }
}

impl From<BrokerObjectError> for ChannelReadError {
    fn from(error: BrokerObjectError) -> Self {
        match error {
            BrokerObjectError::WouldBlock => Self::WouldBlock,
            BrokerObjectError::PeerClosed => Self::ConnectionClosed,
            error => Self::Socket(error.into()),
        }
    }
}

impl From<BrokerObjectError> for ChannelWriteError {
    fn from(error: BrokerObjectError) -> Self {
        match error {
            BrokerObjectError::WouldBlock => Self::BufferFull,
            BrokerObjectError::PeerClosed => Self::ConnectionClosed,
            error => Self::Socket(error.into()),
        }
    }
}

impl From<BrokerObjectError> for SocketAsyncError {
    fn from(error: BrokerObjectError) -> Self {
        match error {
            BrokerObjectError::Control
            | BrokerObjectError::InvalidObject
            | BrokerObjectError::PeerClosed
            | BrokerObjectError::WouldBlock => Self::BackendFailure,
            BrokerObjectError::ResourceExhausted | BrokerObjectError::OutOfMemory => {
                Self::ResourceExhausted
            }
            BrokerObjectError::PermissionDenied => Self::PolicyDenied,
            BrokerObjectError::UnsupportedOperation => Self::UnsupportedOperation,
        }
    }
}

impl From<BrokerSocketError> for SocketAsyncError {
    fn from(error: BrokerSocketError) -> Self {
        match error {
            BrokerSocketError::ConnectionRefused => Self::ConnectionRefused,
            BrokerSocketError::ConnectionReset => Self::ConnectionReset,
            BrokerSocketError::ConnectionAborted => Self::ConnectionAborted,
            BrokerSocketError::NetworkUnreachable => Self::NetworkUnreachable,
            BrokerSocketError::HostUnreachable => Self::HostUnreachable,
            BrokerSocketError::TimedOut => Self::TimedOut,
            BrokerSocketError::AddressInUse => Self::AddressInUse,
            BrokerSocketError::AddressNotAvailable => Self::AddressNotAvailable,
            BrokerSocketError::NotConnected => Self::NotConnected,
            BrokerSocketError::PolicyDenied => Self::PolicyDenied,
            _ => Self::BackendFailure,
        }
    }
}
