// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Stream I/O on a broker-owned TCP socket.

use litebox_broker_protocol::socket::{
    MAX_SOCKET_PEEK_SIZE, MAX_SOCKET_TRANSFER_SIZE, ReceiveFlags as BrokerReceiveFlags,
    ReceiveSocketResponse, SendFlags as BrokerSendFlags, SocketError as BrokerSocketError,
    SocketOutcome,
};
use litebox_platform::time::TimeProvider;

use super::{
    InetSocket, ReceiveFlags,
    errors::{SocketAsyncError, SocketReadError, SocketWriteError},
    is_nonblocking_would_block,
};
use crate::{broker::error::BrokerObjectError, sync::RawSyncPrimitivesProvider};

const _: () = assert!(MAX_SOCKET_PEEK_SIZE as usize == super::SOCKET_RECEIVE_OPERATION_SIZE);

impl<Platform: RawSyncPrimitivesProvider + TimeProvider> InetSocket<Platform> {
    /// Reads stream bytes, peeking at up to [`MAX_SOCKET_PEEK_SIZE`] bytes
    /// with one request per transfer.
    pub(super) fn read_stream(
        &self,
        buffer: &mut [u8],
        flags: ReceiveFlags,
    ) -> Result<usize, SocketReadError> {
        if buffer.is_empty() {
            return Ok(0);
        }
        let _receive = self.receive_lock.lock();
        let discard = flags.contains(ReceiveFlags::DISCARD);
        let peek = flags.contains(ReceiveFlags::PEEK);
        let mut broker_flags = BrokerReceiveFlags::NONE;
        if peek {
            broker_flags.0 |= BrokerReceiveFlags::PEEK.0;
            if flags.contains(ReceiveFlags::WAITALL) {
                broker_flags.0 |= BrokerReceiveFlags::WAITALL.0;
            }
        }
        let target = buffer.len().min(if peek {
            MAX_SOCKET_PEEK_SIZE as usize
        } else {
            MAX_SOCKET_TRANSFER_SIZE as usize
        });
        let backend_failure = || SocketReadError::Socket(SocketAsyncError::BackendFailure);
        let peek_length = if peek {
            u32::try_from(target).map_err(|_| backend_failure())?
        } else {
            0
        };
        let mut offset = 0;
        loop {
            let length = (target - offset).min(MAX_SOCKET_TRANSFER_SIZE as usize);
            let outcome = self.broker.receive_socket(
                self.handle,
                &mut buffer[offset..offset + length],
                broker_flags,
                u32::try_from(offset).map_err(|_| backend_failure())?,
                peek_length,
                discard,
            );
            match outcome {
                Ok(SocketOutcome::Completed(ReceiveSocketResponse::Received(received))) => {
                    let received = usize::try_from(received).map_err(|_| backend_failure())?;
                    offset += received;
                    if !peek || received < length || offset == target {
                        return Ok(offset);
                    }
                }
                Ok(SocketOutcome::Completed(ReceiveSocketResponse::EndOfStream)) => {
                    return if offset == 0 {
                        Err(SocketReadError::ConnectionClosed)
                    } else {
                        Ok(offset)
                    };
                }
                Ok(SocketOutcome::Completed(_)) => return Err(backend_failure()),
                Ok(SocketOutcome::Failed(error)) if offset != 0 => {
                    // The bytes already peeked are returned. A
                    // transport error the failed request consumed is left
                    // pending, while a shutdown or disconnection persists.
                    if !matches!(
                        error,
                        BrokerSocketError::Shutdown | BrokerSocketError::NotConnected
                    ) {
                        let _ = self.broker.set_socket_error(self.handle, error);
                    }
                    return Ok(offset);
                }
                Ok(SocketOutcome::Failed(BrokerSocketError::Shutdown)) => {
                    return Err(SocketReadError::ReadShutdown);
                }
                Ok(SocketOutcome::Failed(BrokerSocketError::NotConnected)) => {
                    return Err(SocketReadError::NotConnected);
                }
                Ok(SocketOutcome::Failed(error)) => {
                    return Err(SocketReadError::Socket(error.into()));
                }
                Err(error) if is_nonblocking_would_block(error) => {
                    return if offset == 0 {
                        Err(SocketReadError::NonBlocking)
                    } else {
                        Ok(offset)
                    };
                }
                Err(error) => {
                    let error = BrokerObjectError::from(error);
                    if offset != 0 && error == BrokerObjectError::WouldBlock {
                        return Ok(offset);
                    }
                    return Err(error.into());
                }
            }
        }
    }

    /// Writes up to [`MAX_SOCKET_TRANSFER_SIZE`] stream bytes.
    pub(super) fn write_stream(&self, buffer: &[u8]) -> Result<usize, SocketWriteError> {
        let length = buffer.len().min(MAX_SOCKET_TRANSFER_SIZE as usize);
        match self
            .broker
            .send_socket(self.handle, &buffer[..length], BrokerSendFlags::NONE)
        {
            Ok(SocketOutcome::Completed(sent)) => Ok(sent),
            Ok(SocketOutcome::Failed(BrokerSocketError::Shutdown)) => {
                Err(SocketWriteError::WriteShutdown)
            }
            Ok(SocketOutcome::Failed(BrokerSocketError::NotConnected)) => {
                Err(SocketWriteError::NotConnected)
            }
            Ok(SocketOutcome::Failed(error)) => Err(SocketWriteError::Socket(error.into())),
            Err(error) if is_nonblocking_would_block(error) => Err(SocketWriteError::NonBlocking),
            Err(error) => Err(BrokerObjectError::from(error).into()),
        }
    }
}
