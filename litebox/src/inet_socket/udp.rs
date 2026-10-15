// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! A broker-owned UDP socket.

use alloc::sync::{Arc, Weak};
use core::{
    net::{SocketAddr, SocketAddrV4},
    sync::atomic::{AtomicBool, Ordering},
};

use litebox_broker_protocol::{
    ObjectHandle,
    fs::FileOpenFlags,
    socket::{
        MAX_UDP_DATAGRAM_SIZE, ReceiveFromFlags as BrokerReceiveFromFlags,
        ReceiveFromSocketResponse, SendFlags as BrokerSendFlags, ShutdownMode,
        SocketConnectionStatus, SocketError as BrokerSocketError, SocketOutcome,
        SocketStatusResponse,
    },
};
use litebox_platform::time::TimeProvider;

use super::{
    ReceiveFlags,
    errors::{
        BindError, ConnectError, RemoteAddrError, SocketAsyncError, SocketReadError,
        SocketWriteError,
    },
    is_nonblocking_would_block,
};
use crate::{
    broker::{BrokerControl, BrokerPollableRegistry, error::BrokerObjectError, readiness_events},
    event::{Events, IOPollable, observer::Observer, polling::Pollee},
    sync::{Mutex, RawSyncPrimitivesProvider},
};

struct UdpSocketState {
    connection: SocketConnectionStatus,
    local_address: Option<SocketAddrV4>,
    remote_address: Option<SocketAddrV4>,
    async_error: u32,
    next_async_error: u32,
}

impl UdpSocketState {
    fn prepend_async_error(&mut self, error: SocketAsyncError) {
        if self.async_error != 0 {
            self.next_async_error = self.async_error;
        }
        self.async_error = error as u32;
    }

    fn take_async_error(&mut self) -> u32 {
        let error = self.async_error;
        self.async_error = self.next_async_error;
        self.next_async_error = 0;
        error
    }
}

/// Local state and readiness adapter for one broker-owned UDP socket, which
/// closes its handle when dropped.
pub(super) struct UdpSocket<Platform: RawSyncPrimitivesProvider + TimeProvider> {
    broker: Arc<dyn BrokerControl>,
    handle: ObjectHandle,
    pollable_registry: Arc<BrokerPollableRegistry<Platform>>,
    pollee: Arc<Pollee<Platform>>,
    configuration_lock: Mutex<Platform, ()>,
    receive_lock: Mutex<Platform, ()>,
    send_lock: Mutex<Platform, ()>,
    state: Mutex<Platform, UdpSocketState>,
    read_shutdown: AtomicBool,
    write_shutdown: AtomicBool,
}

impl<Platform: RawSyncPrimitivesProvider + TimeProvider> UdpSocket<Platform> {
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
            .create_udp_socket(flags)
            .map_err(BrokerObjectError::from)?;
        let socket = Self {
            broker,
            handle,
            pollable_registry,
            pollee: Arc::new(Pollee::new()),
            configuration_lock: Mutex::new(()),
            receive_lock: Mutex::new(()),
            send_lock: Mutex::new(()),
            state: Mutex::new(UdpSocketState {
                connection: SocketConnectionStatus::Unconnected,
                local_address: None,
                remote_address: None,
                async_error: 0,
                next_async_error: 0,
            }),
            read_shutdown: AtomicBool::new(false),
            write_shutdown: AtomicBool::new(false),
        };
        socket
            .pollable_registry
            .register_pollable(handle, &socket.pollee);
        Ok(socket)
    }

    pub(super) fn bind(&self, address: SocketAddrV4) -> Result<(), BindError> {
        let _configuration = self.configuration_lock.lock();
        self.refresh_status_locked();
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

    pub(super) fn start_connect(&self, address: SocketAddrV4) -> Result<(), ConnectError> {
        if address.port() == 0 || address.ip().is_unspecified() {
            return Err(ConnectError::Unaddressable);
        }
        let _configuration = self.configuration_lock.lock();
        let outcome = self
            .broker
            .connect_socket(self.handle, address)
            .map_err(|error| {
                ConnectError::OperationFailed(BrokerObjectError::from(error).into())
            })?;
        match outcome {
            SocketOutcome::Completed(SocketConnectionStatus::Connected) => {
                let mut state = self.state.lock();
                state.connection = SocketConnectionStatus::Connected;
                state.remote_address = Some(address);
                Ok(())
            }
            SocketOutcome::Completed(_) => Err(ConnectError::OperationFailed(
                SocketAsyncError::BackendFailure,
            )),
            SocketOutcome::Failed(error) => {
                Err(ConnectError::OperationFailed(SocketAsyncError::from(error)))
            }
        }
    }

    pub(super) fn check_connect_progress(&self) -> Result<(), ConnectError> {
        self.refresh_status();
        match self.state.lock().connection {
            SocketConnectionStatus::Connected => Ok(()),
            SocketConnectionStatus::Failed(error) => {
                Err(ConnectError::OperationFailed(SocketAsyncError::from(error)))
            }
            _ => Err(ConnectError::InvalidState),
        }
    }

    pub(super) fn local_addr(&self) -> SocketAddr {
        self.refresh_status();
        self.state.lock().local_address.map_or_else(
            || SocketAddr::V4(SocketAddrV4::new(core::net::Ipv4Addr::UNSPECIFIED, 0)),
            SocketAddr::V4,
        )
    }

    pub(super) fn remote_addr(&self) -> Result<SocketAddr, RemoteAddrError> {
        self.refresh_status();
        let state = self.state.lock();
        if state.connection != SocketConnectionStatus::Connected {
            return Err(RemoteAddrError::NotConnected);
        }
        state
            .remote_address
            .map(SocketAddr::V4)
            .ok_or(RemoteAddrError::NotConnected)
    }

    pub(super) fn shutdown(&self, mode: ShutdownMode) -> Result<(), SocketAsyncError> {
        let _configuration = self.configuration_lock.lock();
        let _receive = matches!(mode, ShutdownMode::Read | ShutdownMode::Both)
            .then(|| self.receive_lock.lock());
        let _send =
            matches!(mode, ShutdownMode::Write | ShutdownMode::Both).then(|| self.send_lock.lock());
        let connected = self.state.lock().connection == SocketConnectionStatus::Connected;
        match self
            .broker
            .shutdown_socket(self.handle, mode)
            .map_err(|error| SocketAsyncError::from(BrokerObjectError::from(error)))?
        {
            SocketOutcome::Completed(()) => {
                let mut events = Events::empty();
                if matches!(mode, ShutdownMode::Read | ShutdownMode::Both) {
                    self.read_shutdown.store(true, Ordering::Release);
                    events.insert(Events::IN | Events::RDHUP);
                }
                if matches!(mode, ShutdownMode::Write | ShutdownMode::Both) {
                    self.write_shutdown.store(true, Ordering::Release);
                    events.insert(Events::OUT);
                }
                if self.read_shutdown.load(Ordering::Acquire)
                    && self.write_shutdown.load(Ordering::Acquire)
                {
                    events.insert(Events::HUP);
                }
                self.pollee.notify_observers(events);
                if connected {
                    Ok(())
                } else {
                    Err(SocketAsyncError::NotConnected)
                }
            }
            SocketOutcome::Failed(error) => Err(error.into()),
        }
    }

    pub(super) fn set_async_error(&self, error: SocketAsyncError) {
        let configuration = self.configuration_lock.lock();
        self.state.lock().prepend_async_error(error);
        drop(configuration);
        self.pollee.notify_observers(Events::ERR);
    }

    pub(super) fn get_async_error(&self, clear: bool) -> Option<SocketAsyncError> {
        let configuration = self.configuration_lock.lock();
        self.refresh_status_locked();
        let mut state = self.state.lock();
        let raw = state.async_error;
        if clear {
            state.take_async_error();
        }
        drop(state);
        if clear && raw != 0 {
            if self.state.lock().async_error == 0 {
                self.refresh_status_locked();
            }
            drop(configuration);
            self.pollee.wake_observers();
        }
        SocketAsyncError::from_u32(raw)
    }

    fn take_async_error(&self) -> Option<SocketAsyncError> {
        let configuration = self.configuration_lock.lock();
        let mut state = self.state.lock();
        let raw = state.take_async_error();
        let needs_refill = raw != 0 && state.async_error == 0;
        drop(state);
        if raw != 0 {
            if needs_refill {
                self.refresh_status_locked();
            }
            drop(configuration);
            self.pollee.wake_observers();
        }
        SocketAsyncError::from_u32(raw)
    }

    pub(super) fn try_read(
        &self,
        buffer: &mut [u8],
        flags: ReceiveFlags,
        mut source_address: Option<&mut Option<SocketAddr>>,
    ) -> Result<usize, SocketReadError> {
        if let Some(error) = self.take_async_error() {
            return Err(SocketReadError::Socket(error));
        }
        if self.read_shutdown.load(Ordering::Acquire) {
            return Err(SocketReadError::ReadShutdown);
        }
        if let Some(source_address) = &mut source_address {
            **source_address = None;
        }
        let receive = self.receive_lock.lock();
        if self.read_shutdown.load(Ordering::Acquire) {
            return Err(SocketReadError::ReadShutdown);
        }
        let mut broker_flags = BrokerReceiveFromFlags::NONE;
        if flags.contains(ReceiveFlags::PEEK) {
            broker_flags.0 |= BrokerReceiveFromFlags::PEEK.0;
        }
        let target_length = if flags.contains(ReceiveFlags::DISCARD) {
            0
        } else {
            buffer.len().min(MAX_UDP_DATAGRAM_SIZE as usize)
        };
        let outcome = self.broker.receive_from_socket(
            self.handle,
            &mut buffer[..target_length],
            broker_flags,
        );
        drop(receive);
        let outcome = match outcome {
            Ok(outcome) => outcome,
            Err(error) => {
                let nonblocking = is_nonblocking_would_block(error);
                if (nonblocking || BrokerObjectError::from(error) == BrokerObjectError::WouldBlock)
                    && let Some(error) = self.take_async_error()
                {
                    return Err(SocketReadError::Socket(error));
                }
                if nonblocking {
                    return Err(SocketReadError::NonBlocking);
                }
                return Err(SocketReadError::from(BrokerObjectError::from(error)));
            }
        };
        match outcome {
            SocketOutcome::Completed(ReceiveFromSocketResponse {
                received,
                datagram_length,
                source_address: response_source_address,
            }) => {
                if let Some(source_address) = source_address {
                    *source_address = Some(SocketAddr::V4(response_source_address));
                }
                let received = usize::try_from(received)
                    .map_err(|_| SocketReadError::Socket(SocketAsyncError::BackendFailure))?;
                let datagram_length = usize::try_from(datagram_length)
                    .map_err(|_| SocketReadError::Socket(SocketAsyncError::BackendFailure))?;
                debug_assert!(received <= target_length);
                Ok(datagram_length)
            }
            SocketOutcome::Failed(BrokerSocketError::NotConnected)
                if self.read_shutdown.load(Ordering::Acquire) =>
            {
                Err(SocketReadError::ReadShutdown)
            }
            SocketOutcome::Failed(error) => {
                self.refresh_status();
                Err(SocketReadError::Socket(error.into()))
            }
        }
    }

    pub(super) fn try_write(
        &self,
        buffer: &[u8],
        destination: Option<SocketAddr>,
    ) -> Result<usize, SocketWriteError> {
        if let Some(error) = self.take_async_error() {
            return Err(SocketWriteError::Socket(error));
        }
        if self.write_shutdown.load(Ordering::Acquire) {
            return Err(SocketWriteError::WriteShutdown);
        }
        let send_operation = self.send_lock.lock();
        if self.write_shutdown.load(Ordering::Acquire) {
            return Err(SocketWriteError::WriteShutdown);
        }
        if buffer.len() > MAX_UDP_DATAGRAM_SIZE as usize {
            return Err(SocketWriteError::MessageTooLong);
        }
        let destination = match destination {
            Some(SocketAddr::V4(address)) => Some(address),
            Some(SocketAddr::V6(_)) => return Err(SocketWriteError::Unaddressable),
            None => None,
        };
        if destination.is_none()
            && self.state.lock().connection != SocketConnectionStatus::Connected
        {
            return Err(SocketWriteError::DestinationAddressRequired);
        }
        let outcome =
            self.broker
                .send_to_socket(self.handle, buffer, BrokerSendFlags::NONE, destination);
        drop(send_operation);
        let outcome = match outcome {
            Ok(outcome) => outcome,
            Err(error) => {
                let nonblocking = is_nonblocking_would_block(error);
                if (nonblocking || BrokerObjectError::from(error) == BrokerObjectError::WouldBlock)
                    && let Some(error) = self.take_async_error()
                {
                    return Err(SocketWriteError::Socket(error));
                }
                if nonblocking {
                    return Err(SocketWriteError::NonBlocking);
                }
                return Err(SocketWriteError::from(BrokerObjectError::from(error)));
            }
        };
        match outcome {
            SocketOutcome::Completed(sent) => Ok(sent),
            SocketOutcome::Failed(error) => {
                self.refresh_status();
                Err(SocketWriteError::Socket(error.into()))
            }
        }
    }

    fn refresh_status(&self) {
        let _configuration = self.configuration_lock.lock();
        self.refresh_status_locked();
    }

    fn refresh_status_locked(&self) {
        if self.state.lock().async_error != 0 {
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
        let mut state = self.state.lock();
        state.connection = response.status;
        if let Some(address) = response.local_address {
            state.local_address = Some(address);
        }
        if state.async_error == 0
            && let Some(error) = response.pending_error
        {
            state.async_error = SocketAsyncError::from(error) as u32;
        }
    }
}

impl<Platform: RawSyncPrimitivesProvider + TimeProvider> IOPollable for UdpSocket<Platform> {
    fn register_observer(&self, observer: Weak<dyn Observer<Events>>, filter: Events) {
        self.pollee.register_observer(observer, filter);
    }

    fn check_io_events(&self) -> Events {
        let mut events = match self.broker.check_readiness(self.handle) {
            Ok(readiness) => readiness_events(readiness),
            Err(_) => Events::ERR,
        };
        if events.contains(Events::ERR) && self.state.lock().async_error == 0 {
            self.refresh_status();
        }
        if self.state.lock().async_error != 0 {
            events.insert(Events::ERR);
        }
        if self.read_shutdown.load(Ordering::Acquire) {
            events.insert(Events::IN | Events::RDHUP);
        }
        if self.write_shutdown.load(Ordering::Acquire) {
            events.insert(Events::OUT);
        }
        if self.read_shutdown.load(Ordering::Acquire) && self.write_shutdown.load(Ordering::Acquire)
        {
            events.insert(Events::HUP);
        }
        events
    }
}

impl<Platform: RawSyncPrimitivesProvider + TimeProvider> Drop for UdpSocket<Platform> {
    fn drop(&mut self) {
        self.pollable_registry.unregister_pollable(self.handle);
        let _ = self.broker.close_object(self.handle);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn restored_udp_error_precedes_prefetched_successor() {
        let mut state = UdpSocketState {
            connection: SocketConnectionStatus::Connected,
            local_address: None,
            remote_address: None,
            async_error: SocketAsyncError::NetworkUnreachable as u32,
            next_async_error: 0,
        };

        state.prepend_async_error(SocketAsyncError::ConnectionRefused);

        assert_eq!(
            SocketAsyncError::from_u32(state.take_async_error()),
            Some(SocketAsyncError::ConnectionRefused)
        );
        assert_eq!(
            SocketAsyncError::from_u32(state.take_async_error()),
            Some(SocketAsyncError::NetworkUnreachable)
        );
    }
}
