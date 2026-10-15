// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! A broker-owned TCP socket.

use alloc::sync::{Arc, Weak};
use core::net::{SocketAddr, SocketAddrV4};

use litebox_broker_protocol::{
    ObjectHandle,
    fs::FileOpenFlags,
    socket::{
        AcceptSocketResponse, MAX_SOCKET_PEEK_SIZE, MAX_SOCKET_TRANSFER_SIZE,
        ReceiveFlags as BrokerReceiveFlags, ReceiveSocketResponse, SendFlags as BrokerSendFlags,
        ShutdownMode, SocketConnectionStatus, SocketError as BrokerSocketError, SocketOutcome,
        SocketStatusResponse,
    },
};
use litebox_platform::time::TimeProvider;

use super::{
    ReceiveFlags,
    errors::{
        AcceptError, BindError, ConnectError, ListenError, RemoteAddrError, SocketAsyncError,
        SocketReadError, SocketWriteError,
    },
    is_nonblocking_would_block,
};
use crate::{
    broker::{BrokerControl, BrokerPollableRegistry, error::BrokerObjectError, readiness_events},
    event::{Events, IOPollable, observer::Observer, polling::Pollee},
    sync::{Mutex, MutexGuard, RawSyncPrimitivesProvider},
};

const _: () = assert!(MAX_SOCKET_PEEK_SIZE as usize == super::SOCKET_RECEIVE_OPERATION_SIZE);

#[expect(
    clippy::struct_excessive_bools,
    reason = "socket state latches are independent"
)]
struct TcpSocketState {
    connection: SocketConnectionStatus,
    local_address: Option<SocketAddrV4>,
    remote_address: Option<SocketAddrV4>,
    async_error: Option<TcpAsyncError>,
    next_async_error: Option<TcpAsyncError>,
    listening: bool,
    /// Whether the connection has been reported as established, by `connect`
    /// or a shutdown, so that a later `connect` fails (Linux's `SS_CONNECTED`).
    connect_reported: bool,
    /// Directions shut down by this socket. Like Linux, a socket records a
    /// shutdown even when it is not connected, and keeps it if it connects later.
    read_shutdown: bool,
    write_shutdown: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TcpAsyncError {
    Other(SocketAsyncError),
    ConnectionFailure(SocketAsyncError),
}

impl TcpAsyncError {
    fn error(self) -> SocketAsyncError {
        match self {
            Self::Other(error) | Self::ConnectionFailure(error) => error,
        }
    }
}

impl TcpSocketState {
    fn prepend_async_error(&mut self, error: SocketAsyncError) {
        self.next_async_error = self.async_error;
        self.async_error = Some(TcpAsyncError::Other(error));
    }

    fn append_retained_error(&mut self, error: TcpAsyncError) {
        let error = Some(error);
        if self.async_error.is_none() {
            self.async_error = error;
        } else if self.next_async_error.is_none() {
            self.next_async_error = error;
        }
    }

    fn take_async_error(&mut self) -> Option<SocketAsyncError> {
        let error = self.async_error.take();
        self.async_error = self.next_async_error.take();
        error.map(TcpAsyncError::error)
    }

    fn take_connection_failure(&mut self) -> Option<SocketAsyncError> {
        if let Some(TcpAsyncError::ConnectionFailure(error)) = self.next_async_error {
            self.next_async_error = None;
            Some(error)
        } else if let Some(TcpAsyncError::ConnectionFailure(_)) = self.async_error {
            self.take_async_error()
        } else {
            None
        }
    }

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

    /// Returns the socket to the unconnected state once `connect` has reported
    /// the failure of its connection attempt, claiming that failure unless
    /// another operation has already reported it.
    fn disconnect(&mut self) -> Option<SocketAsyncError> {
        let error = self.take_connection_failure();
        self.reset_connection();
        error
    }

    /// Returns the socket to the unconnected state, discarding its shutdowns
    /// as Linux's `tcp_disconnect` does.
    fn reset_connection(&mut self) {
        self.connection = SocketConnectionStatus::Unconnected;
        self.read_shutdown = false;
        self.write_shutdown = false;
    }
}

/// Local state and readiness adapter for one broker-owned TCP socket, which
/// closes its handle when dropped.
pub(super) struct TcpSocket<Platform: RawSyncPrimitivesProvider + TimeProvider> {
    broker: Arc<dyn BrokerControl>,
    handle: ObjectHandle,
    pollable_registry: Arc<BrokerPollableRegistry<Platform>>,
    pollee: Arc<Pollee<Platform>>,
    status_lock: Mutex<Platform, ()>,
    receive_lock: Mutex<Platform, ()>,
    state: Mutex<Platform, TcpSocketState>,
}

impl<Platform: RawSyncPrimitivesProvider + TimeProvider> TcpSocket<Platform> {
    /// The broker handle this socket owns.
    pub(super) fn handle(&self) -> ObjectHandle {
        self.handle
    }

    pub(super) fn broker(&self) -> &dyn BrokerControl {
        &*self.broker
    }

    pub(super) fn new(
        broker: Arc<dyn BrokerControl>,
        pollable_registry: Arc<BrokerPollableRegistry<Platform>>,
        flags: FileOpenFlags,
    ) -> Result<Self, BrokerObjectError> {
        let handle = broker
            .create_tcp_socket(flags)
            .map_err(BrokerObjectError::from)?;
        let socket = Self {
            broker,
            handle,
            pollable_registry,
            pollee: Arc::new(Pollee::new()),
            status_lock: Mutex::new(()),
            receive_lock: Mutex::new(()),
            state: Mutex::new(TcpSocketState {
                connection: SocketConnectionStatus::Unconnected,
                local_address: None,
                remote_address: None,
                async_error: None,
                next_async_error: None,
                listening: false,
                connect_reported: false,
                read_shutdown: false,
                write_shutdown: false,
            }),
        };
        socket
            .pollable_registry
            .register_pollable(handle, &socket.pollee);
        Ok(socket)
    }

    fn from_accepted(
        broker: Arc<dyn BrokerControl>,
        pollable_registry: Arc<BrokerPollableRegistry<Platform>>,
        accepted: AcceptSocketResponse,
    ) -> Self {
        let socket = Self {
            broker,
            handle: accepted.handle,
            pollable_registry,
            pollee: Arc::new(Pollee::new()),
            status_lock: Mutex::new(()),
            receive_lock: Mutex::new(()),
            state: Mutex::new(TcpSocketState {
                connection: SocketConnectionStatus::Connected,
                local_address: Some(accepted.local_address),
                remote_address: Some(accepted.remote_address),
                async_error: None,
                next_async_error: None,
                listening: false,
                connect_reported: true,
                read_shutdown: false,
                write_shutdown: false,
            }),
        };
        socket
            .pollable_registry
            .register_pollable(accepted.handle, &socket.pollee);
        socket
    }

    pub(super) fn bind(&self, address: SocketAddrV4) -> Result<(), BindError> {
        if self.state.lock().local_address.is_some() {
            return Err(BindError::AlreadyBound);
        }
        let outcome = self
            .broker
            .bind_socket(self.handle, address)
            .map_err(|error| BindError::OperationFailed(BrokerObjectError::from(error).into()))?;
        match outcome {
            SocketOutcome::Completed(local_address) => {
                self.state.lock().local_address = Some(local_address);
                Ok(())
            }
            SocketOutcome::Failed(error) => {
                Err(BindError::OperationFailed(SocketAsyncError::from(error)))
            }
        }
    }

    pub(super) fn listen(&self, backlog: u32) -> Result<(), ListenError> {
        let outcome = self
            .broker
            .listen_socket(self.handle, backlog)
            .map_err(|error| ListenError::OperationFailed(BrokerObjectError::from(error).into()))?;
        match outcome {
            SocketOutcome::Completed(local_address) => {
                let mut state = self.state.lock();
                state.local_address = Some(local_address);
                state.listening = true;
                Ok(())
            }
            SocketOutcome::Failed(error) => Err(ListenError::OperationFailed(error.into())),
        }
    }

    /// Accepts a connection, giving the new socket the status `flags`.
    pub(super) fn accept(&self, flags: FileOpenFlags) -> Result<Self, AcceptError> {
        if !self.state.lock().listening {
            return Err(AcceptError::NotListening);
        }
        let outcome = self
            .broker
            .accept_socket(self.handle, flags)
            .map_err(|error| {
                if is_nonblocking_would_block(error) {
                    return AcceptError::NonBlocking;
                }
                let error = BrokerObjectError::from(error);
                if error == BrokerObjectError::WouldBlock {
                    AcceptError::NoConnectionsReady
                } else {
                    AcceptError::OperationFailed(error.into())
                }
            })?;
        match outcome {
            SocketOutcome::Completed(accepted) => Ok(Self::from_accepted(
                Arc::clone(&self.broker),
                Arc::clone(&self.pollable_registry),
                accepted,
            )),
            SocketOutcome::Failed(BrokerSocketError::NotConnected) => {
                Err(AcceptError::NotListening)
            }
            SocketOutcome::Failed(error) => Err(AcceptError::OperationFailed(error.into())),
        }
    }

    pub(super) fn start_connect(&self, address: SocketAddrV4) -> Result<(), ConnectError> {
        let status_guard = self.status_lock.lock();
        let (previous, already_connected) = {
            let state = self.state.lock();
            (state.connection, state.listening || state.connect_reported)
        };
        // Like Linux, check the socket's state before the address.
        if already_connected {
            return Err(ConnectError::AlreadyConnected);
        }
        if previous != SocketConnectionStatus::Unconnected {
            // An earlier attempt has not been reported yet; report its outcome
            // if it has one.
            return match self.connect_progress(status_guard) {
                Err(ConnectError::InProgress) => Err(ConnectError::AlreadyInProgress),
                result => result,
            };
        }
        if address.port() == 0 || address.ip().is_unspecified() {
            // Like a connection Linux refuses, this disconnects the socket,
            // discarding its shutdowns.
            self.state.lock().reset_connection();
            return Err(ConnectError::Unaddressable);
        }
        let outcome = self
            .broker
            .connect_socket(self.handle, address)
            .map_err(|error| {
                ConnectError::OperationFailed(BrokerObjectError::from(error).into())
            })?;
        let status = match outcome {
            SocketOutcome::Completed(status) => status,
            SocketOutcome::Failed(error) => {
                let error = error.into();
                return Err(ConnectError::OperationFailed(error));
            }
        };
        let status = {
            let mut state = self.state.lock();
            let status = state.update_connection(status);
            if state.remote_address.is_none() {
                state.remote_address = Some(address);
            }
            status
        };
        let result = match status {
            SocketConnectionStatus::Connected => {
                self.state.lock().connect_reported = true;
                Ok(())
            }
            SocketConnectionStatus::Connecting => Err(ConnectError::InProgress),
            SocketConnectionStatus::Failed(error) => {
                let _ = self.state.lock().disconnect();
                drop(status_guard);
                self.pollee.wake_observers();
                self.pollee.notify_observers(Events::OUT | Events::HUP);
                return Err(ConnectError::OperationFailed(error.into()));
            }
            SocketConnectionStatus::Unconnected => Err(ConnectError::InvalidState),
            _ => Err(ConnectError::OperationFailed(
                SocketAsyncError::BackendFailure,
            )),
        };
        drop(status_guard);
        result
    }

    pub(super) fn check_connect_progress(&self) -> Result<(), ConnectError> {
        self.connect_progress(self.status_lock.lock())
    }

    /// Reports the outcome of the pending connection attempt, if it has one.
    fn connect_progress(
        &self,
        status_guard: MutexGuard<'_, Platform, ()>,
    ) -> Result<(), ConnectError> {
        let response = self.broker.socket_status(self.handle).map_err(|error| {
            ConnectError::OperationFailed(BrokerObjectError::from(error).into())
        })?;
        let status = response.status;
        self.apply_socket_status(response);
        if matches!(status, SocketConnectionStatus::Failed(_)) {
            // Whichever operation claims the failure first reports it, leaving
            // only an abort for a later `connect` to report.
            let error = self
                .state
                .lock()
                .disconnect()
                .unwrap_or(SocketAsyncError::ConnectionAborted);
            drop(status_guard);
            self.pollee.wake_observers();
            self.pollee.notify_observers(Events::OUT | Events::HUP);
            return Err(ConnectError::OperationFailed(error));
        }
        if status == SocketConnectionStatus::Connected {
            self.state.lock().connect_reported = true;
        }
        drop(status_guard);
        match status {
            SocketConnectionStatus::Connected => Ok(()),
            SocketConnectionStatus::Connecting => Err(ConnectError::InProgress),
            SocketConnectionStatus::Unconnected => Err(ConnectError::InvalidState),
            _ => Err(ConnectError::OperationFailed(
                SocketAsyncError::BackendFailure,
            )),
        }
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
        let connecting = self.state.lock().connection == SocketConnectionStatus::Connecting;
        match self
            .broker
            .shutdown_socket(self.handle, mode)
            .map_err(|error| SocketAsyncError::from(BrokerObjectError::from(error)))?
        {
            SocketOutcome::Completed(()) => {
                if connecting && self.abort_connect() {
                    return Ok(());
                }
                self.record_shutdown(mode);
                Ok(())
            }
            SocketOutcome::Failed(BrokerSocketError::NotConnected) => {
                // Like Linux, a socket without a connection records the shutdown
                // even though the call fails.
                self.record_shutdown(mode);
                Err(SocketAsyncError::NotConnected)
            }
            SocketOutcome::Failed(error) => {
                let error = error.into();
                Err(error)
            }
        }
    }

    /// Records a shutdown, which, like Linux's `inet_shutdown`, also reports an
    /// established connection so that a later `connect` fails.
    fn record_shutdown(&self, mode: ShutdownMode) {
        let mut events = Events::empty();
        let mut state = self.state.lock();
        if state.connection == SocketConnectionStatus::Connected {
            state.connect_reported = true;
        }
        if matches!(mode, ShutdownMode::Read | ShutdownMode::Both) {
            state.read_shutdown = true;
            events |= Events::IN | Events::RDHUP;
        }
        if matches!(mode, ShutdownMode::Write | ShutdownMode::Both) {
            state.write_shutdown = true;
            events |= Events::OUT;
        }
        if state.read_shutdown && state.write_shutdown {
            events |= Events::HUP;
        }
        drop(state);
        self.pollee.notify_observers(events);
    }

    /// Returns the socket to the unconnected state, retaining the error, if
    /// shutting it down aborted its pending connect.
    fn abort_connect(&self) -> bool {
        let status_guard = self.status_lock.lock();
        let Ok(response) = self.broker.socket_status(self.handle) else {
            return false;
        };
        let failed = matches!(response.status, SocketConnectionStatus::Failed(_));
        // This records the failure unless a concurrent status refresh already has.
        self.apply_socket_status(response);
        if !failed {
            return false;
        }
        self.state.lock().reset_connection();
        drop(status_guard);
        self.pollee.wake_observers();
        self.pollee
            .notify_observers(Events::OUT | Events::HUP | Events::ERR);
        true
    }

    pub(super) fn is_listening(&self) -> bool {
        self.state.lock().listening
    }

    pub(super) fn stop_listening(&self) -> Result<(), SocketAsyncError> {
        match self
            .broker
            .shutdown_socket(self.handle, ShutdownMode::StopListening)
            .map_err(|error| SocketAsyncError::from(BrokerObjectError::from(error)))?
        {
            SocketOutcome::Completed(()) => {
                let mut state = self.state.lock();
                state.listening = false;
                // Like Linux, which disconnects a listener to stop it.
                state.reset_connection();
                drop(state);
                self.pollee.notify_observers(Events::OUT | Events::HUP);
                Ok(())
            }
            SocketOutcome::Failed(error) => Err(error.into()),
        }
    }

    pub(super) fn set_async_error(&self, error: SocketAsyncError) {
        let status_guard = self.status_lock.lock();
        self.state.lock().prepend_async_error(error);
        drop(status_guard);
        self.pollee.notify_observers(Events::ERR);
    }

    pub(super) fn get_async_error(&self, clear: bool) -> Option<SocketAsyncError> {
        let status_guard = self.status_lock.lock();
        self.refresh_connection_status_locked(true);
        let mut state = self.state.lock();
        let error = if clear {
            state.take_async_error()
        } else {
            state.async_error.map(TcpAsyncError::error)
        };
        let needs_refill = clear && error.is_some() && state.async_error.is_none();
        let failed = matches!(state.connection, SocketConnectionStatus::Failed(_));
        drop(state);
        if clear && error.is_some() {
            if needs_refill {
                self.refresh_connection_status_locked(true);
            }
            drop(status_guard);
            self.pollee.wake_observers();
            if failed {
                self.pollee
                    .notify_observers(Events::IN | Events::OUT | Events::HUP);
            }
        }
        error
    }

    pub(super) fn try_read(
        &self,
        buffer: &mut [u8],
        flags: ReceiveFlags,
        source_address: Option<&mut Option<SocketAddr>>,
    ) -> Result<usize, SocketReadError> {
        if let Some(source_address) = source_address {
            *source_address = None;
        }
        if buffer.is_empty() {
            return Ok(0);
        }
        let read_shutdown = {
            let state = self.state.lock();
            match state.connection {
                // As in Linux, a listener ignores shutdowns, and a pending error
                // is reported before a shutdown.
                SocketConnectionStatus::Unconnected
                    if state.read_shutdown && !state.listening && state.async_error.is_none() =>
                {
                    return Err(SocketReadError::ReadShutdown);
                }
                SocketConnectionStatus::Unconnected => return Err(SocketReadError::NotConnected),
                SocketConnectionStatus::Failed(_) => {
                    return Err(SocketReadError::ConnectionClosed);
                }
                _ => {}
            }
            state.read_shutdown
        };
        let _receive = self.receive_lock.lock();
        let discard = flags.contains(ReceiveFlags::DISCARD);
        let mut broker_flags = BrokerReceiveFlags::NONE;
        let peek = flags.contains(ReceiveFlags::PEEK);
        let wait_all = flags.contains(ReceiveFlags::WAITALL);
        if peek {
            broker_flags.0 |= BrokerReceiveFlags::PEEK.0;
        }
        // The broker's socket does not know about a shutdown recorded before it
        // connected, so it must not wait for more data than is queued.
        if wait_all && peek && !read_shutdown {
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
                    .map_err(|_| SocketReadError::Socket(SocketAsyncError::BackendFailure))?,
                if peek {
                    u32::try_from(target)
                        .map_err(|_| SocketReadError::Socket(SocketAsyncError::BackendFailure))?
                } else {
                    0
                },
                discard,
            ) {
                Ok(outcome) => outcome,
                Err(error) => {
                    let nonblocking = is_nonblocking_would_block(error);
                    let error = if nonblocking {
                        BrokerObjectError::WouldBlock
                    } else {
                        BrokerObjectError::from(error)
                    };
                    if error == BrokerObjectError::WouldBlock {
                        if offset != 0 {
                            return Ok(offset);
                        }
                        // The broker's socket does not know about a shutdown
                        // recorded before it connected.
                        if read_shutdown {
                            return Err(SocketReadError::ReadShutdown);
                        }
                        return Err(if nonblocking {
                            SocketReadError::NonBlocking
                        } else {
                            SocketReadError::WouldBlock
                        });
                    }
                    return Err(error.into());
                }
            };
            match outcome {
                SocketOutcome::Completed(ReceiveSocketResponse::Received(received)) => {
                    let received = usize::try_from(received)
                        .map_err(|_| SocketReadError::Socket(SocketAsyncError::BackendFailure))?;
                    offset += received;
                    if !peek || received < length || offset == target {
                        return Ok(offset);
                    }
                }
                SocketOutcome::Completed(ReceiveSocketResponse::EndOfStream) => {
                    return if offset == 0 {
                        Err(SocketReadError::ConnectionClosed)
                    } else {
                        Ok(offset)
                    };
                }
                SocketOutcome::Completed(_) => {
                    return Err(SocketReadError::Socket(SocketAsyncError::BackendFailure));
                }
                SocketOutcome::Failed(error) => {
                    let error = error.into();
                    self.refresh_after_synchronous_error();
                    if offset != 0 {
                        self.set_async_error(error);
                        return Ok(offset);
                    }
                    return Err(SocketReadError::Socket(error));
                }
            }
        }
    }

    pub(super) fn try_write(&self, buffer: &[u8]) -> Result<usize, SocketWriteError> {
        let (write_shutdown, connection) = {
            let state = self.state.lock();
            (state.write_shutdown, state.connection)
        };
        if write_shutdown {
            // As in Linux, a send waits for a pending connection attempt, and
            // reports its failure, before it reports a write shutdown recorded
            // before connecting. Nothing else refreshes the cached status while
            // a send waits, so it does so here.
            if connection == SocketConnectionStatus::Connecting {
                self.refresh_connection_status(false);
                let state = self.state.lock();
                if state.connection == SocketConnectionStatus::Connecting
                    && state.async_error.is_none()
                {
                    return Err(SocketWriteError::BufferFull);
                }
            }
            return Err(SocketWriteError::WriteShutdown);
        }
        if matches!(
            connection,
            SocketConnectionStatus::Unconnected | SocketConnectionStatus::Failed(_)
        ) {
            return Err(SocketWriteError::NotConnected);
        }
        let length = buffer.len().min(MAX_SOCKET_TRANSFER_SIZE as usize);
        let outcome = self
            .broker
            .send_socket(self.handle, &buffer[..length], BrokerSendFlags::NONE)
            .map_err(|error| {
                if is_nonblocking_would_block(error) {
                    SocketWriteError::NonBlocking
                } else {
                    SocketWriteError::from(BrokerObjectError::from(error))
                }
            })?;
        match outcome {
            SocketOutcome::Completed(sent) => Ok(sent),
            SocketOutcome::Failed(BrokerSocketError::NotConnected) => {
                self.refresh_after_synchronous_error();
                Err(SocketWriteError::NotConnected)
            }
            SocketOutcome::Failed(error) => {
                let error = error.into();
                self.refresh_after_synchronous_error();
                Err(SocketWriteError::Socket(error))
            }
        }
    }

    fn refresh_connection_status(&self, include_connected: bool) {
        let _status_guard = self.status_lock.lock();
        self.refresh_connection_status_locked(include_connected);
    }

    fn refresh_connection_status_locked(&self, include_connected: bool) {
        let state = self.state.lock();
        if state.async_error.is_some() {
            return;
        }
        let connection = state.connection;
        drop(state);
        if connection != SocketConnectionStatus::Connecting
            && !(include_connected && connection == SocketConnectionStatus::Connected)
        {
            return;
        }
        match self.broker.socket_status(self.handle) {
            Ok(response) => self.apply_socket_status(response),
            Err(error) => {
                self.state
                    .lock()
                    .prepend_async_error(BrokerObjectError::from(error).into());
            }
        }
    }

    fn apply_socket_status(&self, response: SocketStatusResponse) {
        if let Some(error) = self.update_socket_status(response) {
            self.state.lock().append_retained_error(error);
        }
    }

    fn update_socket_status(&self, response: SocketStatusResponse) -> Option<TcpAsyncError> {
        let mut state = self.state.lock();
        let previous_connection = state.connection;
        let connection = state.update_connection(response.status);
        // Only a pending connection attempt can fail; an unconnected socket has
        // already recorded the failure of its last attempt.
        let connection_error = match (previous_connection, connection) {
            (SocketConnectionStatus::Connecting, SocketConnectionStatus::Failed(error)) => {
                Some(error)
            }
            _ => None,
        };
        if let Some(address) = response.local_address {
            state.local_address = Some(address);
        }

        response
            .pending_error
            .map(SocketAsyncError::from)
            .map(TcpAsyncError::Other)
            .or_else(|| {
                connection_error
                    .map(SocketAsyncError::from)
                    .map(TcpAsyncError::ConnectionFailure)
            })
    }

    /// Refreshes status after a synchronous failure, draining both backend error slots.
    fn refresh_after_synchronous_error(&self) {
        let status_guard = self.status_lock.lock();
        for _ in 0..2 {
            let connection = self.state.lock().connection;
            if !matches!(
                connection,
                SocketConnectionStatus::Connecting | SocketConnectionStatus::Connected
            ) {
                break;
            }
            let response = match self.broker.socket_status(self.handle) {
                Ok(response) => response,
                Err(error) => {
                    self.state
                        .lock()
                        .append_retained_error(TcpAsyncError::Other(
                            BrokerObjectError::from(error).into(),
                        ));
                    break;
                }
            };
            let Some(pending_error) = self.update_socket_status(response) else {
                break;
            };
            self.state.lock().append_retained_error(pending_error);
        }
        let failed = matches!(
            self.state.lock().connection,
            SocketConnectionStatus::Failed(_)
        );
        self.state.lock().take_connection_failure();
        drop(status_guard);
        self.pollee.wake_observers();
        if failed {
            self.pollee
                .notify_observers(Events::IN | Events::OUT | Events::HUP);
        }
    }
}

impl<Platform: RawSyncPrimitivesProvider + TimeProvider> IOPollable for TcpSocket<Platform> {
    fn register_observer(&self, observer: Weak<dyn Observer<Events>>, mut filter: Events) {
        if filter.contains(Events::RDHUP) {
            filter.insert(Events::HUP);
        }
        self.pollee.register_observer(observer, filter);
    }

    fn check_io_events(&self) -> Events {
        let (listening, connection) = {
            let state = self.state.lock();
            (state.listening, state.connection)
        };
        // Only a listening or connecting/connected socket has broker readiness
        // to observe; the other states are fully described by the cache.
        let mut events = Events::empty();
        if listening
            || matches!(
                connection,
                SocketConnectionStatus::Connecting | SocketConnectionStatus::Connected
            )
        {
            events = self
                .broker
                .check_readiness(self.handle)
                .map_or(Events::ERR, readiness_events);
            if connection == SocketConnectionStatus::Connecting
                || events.intersects(Events::OUT | Events::ERR)
            {
                self.refresh_connection_status(events.contains(Events::ERR));
            }
        }
        let state = self.state.lock();
        let listening = state.listening;
        let connection = state.connection;
        let has_async_error = state.async_error.is_some();
        let read_shutdown = state.read_shutdown;
        let write_shutdown = state.write_shutdown;
        drop(state);
        match connection {
            // A failed connection attempt leaves the socket closed in both directions.
            SocketConnectionStatus::Failed(_) => {
                events = Events::IN | Events::OUT | Events::HUP | Events::RDHUP;
            }
            SocketConnectionStatus::Unconnected if !listening => {
                events = Events::OUT | Events::HUP;
            }
            _ => {}
        }
        if !listening {
            // As in Linux's `tcp_poll`, a write shutdown makes a socket
            // writable only once it is no longer connecting.
            if read_shutdown {
                events |= Events::IN | Events::RDHUP;
            }
            if write_shutdown && connection != SocketConnectionStatus::Connecting {
                events |= Events::OUT;
            }
            // Both directions are closed once the write side is shut down and
            // the read side is shut down, locally or by the peer.
            if write_shutdown && events.contains(Events::RDHUP) {
                events |= Events::HUP;
            }
        }
        if has_async_error {
            events.insert(Events::ERR);
        }
        events
    }
}

impl<Platform: RawSyncPrimitivesProvider + TimeProvider> Drop for TcpSocket<Platform> {
    fn drop(&mut self) {
        self.pollable_registry.unregister_pollable(self.handle);
        let _ = self.broker.close_object(self.handle);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tcp_error_retention_is_bounded_to_current_and_predecessor() {
        let mut state = TcpSocketState {
            connection: SocketConnectionStatus::Connected,
            local_address: None,
            remote_address: None,
            async_error: None,
            next_async_error: None,
            listening: false,
            connect_reported: false,
            read_shutdown: false,
            write_shutdown: false,
        };

        state.prepend_async_error(SocketAsyncError::NetworkUnreachable);
        state.prepend_async_error(SocketAsyncError::ConnectionRefused);
        state.prepend_async_error(SocketAsyncError::TimedOut);

        assert_eq!(state.take_async_error(), Some(SocketAsyncError::TimedOut));
        assert_eq!(
            state.take_async_error(),
            Some(SocketAsyncError::ConnectionRefused)
        );
        assert_eq!(state.take_async_error(), None);
    }

    #[test]
    fn tcp_status_error_is_appended_after_cached_error() {
        let mut state = TcpSocketState {
            connection: SocketConnectionStatus::Connected,
            local_address: None,
            remote_address: None,
            async_error: Some(TcpAsyncError::Other(SocketAsyncError::NetworkUnreachable)),
            next_async_error: None,
            listening: false,
            connect_reported: false,
            read_shutdown: false,
            write_shutdown: false,
        };

        state.append_retained_error(TcpAsyncError::Other(SocketAsyncError::ConnectionRefused));

        assert_eq!(
            state.take_async_error(),
            Some(SocketAsyncError::NetworkUnreachable)
        );
        assert_eq!(
            state.take_async_error(),
            Some(SocketAsyncError::ConnectionRefused)
        );
    }

    #[test]
    fn cached_connect_failure_is_removed_by_source() {
        let mut state = TcpSocketState {
            connection: SocketConnectionStatus::Failed(BrokerSocketError::ConnectionRefused),
            local_address: None,
            remote_address: None,
            async_error: Some(TcpAsyncError::Other(SocketAsyncError::ConnectionRefused)),
            next_async_error: Some(TcpAsyncError::ConnectionFailure(
                SocketAsyncError::ConnectionRefused,
            )),
            listening: false,
            connect_reported: false,
            read_shutdown: false,
            write_shutdown: false,
        };

        state.take_connection_failure();

        assert_eq!(
            state.take_async_error(),
            Some(SocketAsyncError::ConnectionRefused)
        );
        assert_eq!(state.take_async_error(), None);
    }
}
