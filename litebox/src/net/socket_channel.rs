// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Socket I/O and readiness proxies.

use core::net::SocketAddr;
use litebox_platform::time::TimeProvider;

use crate::{
    event::{Events, IOPollable, observer::Observer},
    sync::RawSyncPrimitivesProvider,
};

/// Socket state used by the Linux shim when publishing state transitions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum SocketState {
    /// Socket is in its initial state.
    Initial = 0,
    /// Socket is connecting.
    Connecting = 1,
    /// Socket is connected and ready for data transfer.
    Connected = 2,
    /// Socket is listening for incoming connections.
    Listening = 3,
    /// Socket encountered an error.
    Error = 4,
    /// Socket is closed.
    Closed = 5,
}

/// Possible errors from [`NetworkProxy::try_read`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelReadError {
    /// The local read side has been shut down.
    ReadShutdown,
    /// No data is currently available.
    WouldBlock,
    /// The stream has not reached a connected state.
    NotConnected,
    /// The stream is closed.
    ConnectionClosed,
    /// The host network operation failed.
    Socket(super::errors::SocketAsyncError),
}

/// Possible errors from [`NetworkProxy::try_write`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelWriteError {
    /// The local write side has been shut down.
    WriteShutdown,
    /// The stream has not reached a connected state.
    NotConnected,
    /// The stream is closed.
    ConnectionClosed,
    /// The destination address cannot be used.
    Unaddressable,
    /// The transmit buffer is full.
    BufferFull,
    /// The datagram exceeds the protocol maximum.
    MessageTooLong,
    /// A destination address is required but was not provided.
    DestinationAddressRequired,
    /// The host network operation failed.
    Socket(super::errors::SocketAsyncError),
}

/// A proxy for broker-owned network socket operations and readiness.
pub enum NetworkProxy<Platform: RawSyncPrimitivesProvider + TimeProvider> {
    /// Broker-owned TCP stream proxy.
    BrokerStream(alloc::sync::Arc<super::BrokerTcpSocket<Platform>>),
    /// Broker-owned UDP datagram proxy.
    BrokerDatagram(alloc::sync::Arc<super::BrokerUdpSocket<Platform>>),
}

impl<Platform: RawSyncPrimitivesProvider + TimeProvider> NetworkProxy<Platform> {
    /// Set the socket state.
    pub fn set_state(&self, state: SocketState) {
        match self {
            Self::BrokerStream(socket) => socket.set_state(state),
            Self::BrokerDatagram(socket) => socket.set_state(state),
        }
    }

    /// Set the asynchronous socket error.
    pub fn set_async_error(&self, error: super::errors::SocketAsyncError) {
        match self {
            Self::BrokerStream(socket) => socket.set_async_error(error),
            Self::BrokerDatagram(socket) => socket.set_async_error(error),
        }
    }

    /// Read and optionally clear the asynchronous socket error.
    pub fn get_async_error(&self, clear: bool) -> Option<super::errors::SocketAsyncError> {
        match self {
            Self::BrokerStream(socket) => socket.get_async_error(clear),
            Self::BrokerDatagram(socket) => socket.get_async_error(clear),
        }
    }

    /// Attempt to read data from the socket.
    pub fn try_read(
        &self,
        buf: &mut [u8],
        flags: super::ReceiveFlags,
        source_addr: Option<&mut Option<SocketAddr>>,
    ) -> Result<usize, ChannelReadError> {
        match self {
            Self::BrokerStream(socket) => socket.try_read(buf, flags, source_addr),
            Self::BrokerDatagram(socket) => socket.try_read(buf, flags, source_addr),
        }
    }

    /// Attempt to write data to the socket.
    pub fn try_write(
        &self,
        buf: &[u8],
        flags: super::SendFlags,
        destination: Option<SocketAddr>,
    ) -> Result<usize, ChannelWriteError> {
        if !flags.is_empty() {
            unimplemented!()
        }
        if let Some(addr) = destination
            && (addr.port() == 0 || addr.ip().is_unspecified())
        {
            return Err(ChannelWriteError::Unaddressable);
        }
        match self {
            Self::BrokerStream(socket) => socket.try_write(buf),
            Self::BrokerDatagram(socket) => socket.try_write(buf, destination),
        }
    }
}

impl<Platform: RawSyncPrimitivesProvider + TimeProvider> IOPollable for NetworkProxy<Platform> {
    fn register_observer(&self, observer: alloc::sync::Weak<dyn Observer<Events>>, mask: Events) {
        match self {
            Self::BrokerStream(socket) => socket.register_observer(observer, mask),
            Self::BrokerDatagram(socket) => socket.register_observer(observer, mask),
        }
    }

    fn check_io_events(&self) -> Events {
        match self {
            Self::BrokerStream(socket) => socket.check_io_events(),
            Self::BrokerDatagram(socket) => socket.check_io_events(),
        }
    }
}
