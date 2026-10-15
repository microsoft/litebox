// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Datagram I/O on a broker-owned UDP socket.

use core::net::SocketAddr;

use litebox_broker_protocol::socket::{
    MAX_UDP_DATAGRAM_SIZE, ReceiveFromFlags as BrokerReceiveFromFlags,
    SendFlags as BrokerSendFlags, SocketError as BrokerSocketError, SocketOutcome,
};
use litebox_platform::time::TimeProvider;

use super::{
    InetSocket, ReceiveFlags,
    errors::{SocketAsyncError, SocketReadError, SocketWriteError},
    is_nonblocking_would_block,
};
use crate::{broker::error::BrokerObjectError, sync::RawSyncPrimitivesProvider};

impl<Platform: RawSyncPrimitivesProvider + TimeProvider> InetSocket<Platform> {
    /// Receives one datagram, returning its whole length, and stores its
    /// sender's address in `source_address` if requested.
    pub(super) fn read_datagram(
        &self,
        buffer: &mut [u8],
        flags: ReceiveFlags,
        source_address: Option<&mut Option<SocketAddr>>,
    ) -> Result<usize, SocketReadError> {
        let mut broker_flags = BrokerReceiveFromFlags::NONE;
        if flags.contains(ReceiveFlags::PEEK) {
            broker_flags.0 |= BrokerReceiveFromFlags::PEEK.0;
        }
        let length = if flags.contains(ReceiveFlags::DISCARD) {
            0
        } else {
            buffer.len().min(MAX_UDP_DATAGRAM_SIZE as usize)
        };
        match self
            .broker
            .receive_from_socket(self.handle, &mut buffer[..length], broker_flags)
        {
            Ok(SocketOutcome::Completed(received)) => {
                if let Some(source_address) = source_address {
                    *source_address = Some(SocketAddr::V4(received.source_address));
                }
                usize::try_from(received.datagram_length)
                    .map_err(|_| SocketReadError::Socket(SocketAsyncError::BackendFailure))
            }
            Ok(SocketOutcome::Failed(BrokerSocketError::Shutdown)) => {
                Err(SocketReadError::ReadShutdown)
            }
            Ok(SocketOutcome::Failed(error)) => Err(SocketReadError::Socket(error.into())),
            Err(error) if is_nonblocking_would_block(error) => Err(SocketReadError::NonBlocking),
            Err(error) => Err(BrokerObjectError::from(error).into()),
        }
    }

    /// Sends `buffer` as one datagram, to `destination` if provided, and
    /// otherwise to the connected peer.
    pub(super) fn write_datagram(
        &self,
        buffer: &[u8],
        destination: Option<SocketAddr>,
    ) -> Result<usize, SocketWriteError> {
        if buffer.len() > MAX_UDP_DATAGRAM_SIZE as usize {
            return Err(SocketWriteError::MessageTooLong);
        }
        let destination = match destination {
            Some(SocketAddr::V4(address)) => Some(address),
            Some(SocketAddr::V6(_)) => return Err(SocketWriteError::Unaddressable),
            None => None,
        };
        match self
            .broker
            .send_to_socket(self.handle, buffer, BrokerSendFlags::NONE, destination)
        {
            Ok(SocketOutcome::Completed(sent)) => Ok(sent),
            Ok(SocketOutcome::Failed(BrokerSocketError::Shutdown)) => {
                Err(SocketWriteError::WriteShutdown)
            }
            Ok(SocketOutcome::Failed(BrokerSocketError::DestinationAddressRequired)) => {
                Err(SocketWriteError::DestinationAddressRequired)
            }
            Ok(SocketOutcome::Failed(error)) => Err(SocketWriteError::Socket(error.into())),
            Err(error) if is_nonblocking_would_block(error) => Err(SocketWriteError::NonBlocking),
            Err(error) => Err(BrokerObjectError::from(error).into()),
        }
    }
}
