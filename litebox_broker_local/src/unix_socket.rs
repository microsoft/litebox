// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use alloc::vec::Vec;

use litebox_broker_protocol::ObjectHandle;
use litebox_broker_protocol::error::ErrorCode;
use litebox_broker_protocol::fs::{FileMode, FileOpenFlags, FileUser};
use litebox_broker_protocol::message::{
    BrokerOperation, BrokerResult, UnixSocketRequest, UnixSocketResponse,
};
use litebox_broker_protocol::shared_buffer::SharedBufferSequence;
use litebox_broker_protocol::socket::{ShutdownMode, SocketType};
use litebox_broker_protocol::unix_socket::{
    AcceptUnixSocketRequest, BindUnixSocketRequest, ConnectUnixSocketRequest,
    CreateUnixSocketPairResponse, CreateUnixSocketRequest, GetUnixSocketNameRequest,
    GetUnixSocketOptionsResponse, ListenUnixSocketRequest, MAX_ENCODED_UNIX_SOCKET_ADDRESS_SIZE,
    MAX_ENCODED_UNIX_SOCKET_NAME_SIZE, MAX_UNIX_SOCKET_TRANSFER_SIZE, ReceiveUnixSocketRequest,
    ReceiveUnixSocketResponse, SendUnixSocketRequest, SetUnixSocketOptionRequest,
    ShutdownUnixSocketRequest, UnixSocketError, UnixSocketName, UnixSocketOption,
};
use litebox_broker_transport::channel::LocalCallChannel;

use crate::{BrokerLocal, BrokerLocalError, Result};

type UnixSocketResult<T> = core::result::Result<T, UnixSocketError>;

impl<Channel: LocalCallChannel> BrokerLocal<Channel> {
    /// Creates a broker-owned Unix socket.
    ///
    /// # Panics
    ///
    /// Panics if the broker returns a response for a different operation.
    pub fn create_unix_socket(
        &self,
        socket_type: SocketType,
        flags: FileOpenFlags,
    ) -> Result<ObjectHandle, Channel::Error> {
        match self.request_unix_socket(UnixSocketRequest::Create(CreateUnixSocketRequest {
            socket_type,
            flags,
        }))? {
            UnixSocketResponse::Create(response) => Ok(response.handle),
            response => panic!("broker returned unexpected Unix socket response: {response:?}"),
        }
    }

    /// Creates a pair of connected broker-owned Unix sockets.
    ///
    /// # Panics
    ///
    /// Panics if the broker returns a response for a different operation.
    pub fn create_unix_socket_pair(
        &self,
        socket_type: SocketType,
        flags: FileOpenFlags,
    ) -> Result<CreateUnixSocketPairResponse, Channel::Error> {
        match self.request_unix_socket(UnixSocketRequest::CreatePair(CreateUnixSocketRequest {
            socket_type,
            flags,
        }))? {
            UnixSocketResponse::CreatePair(response) => Ok(response),
            response => panic!("broker returned unexpected Unix socket response: {response:?}"),
        }
    }

    /// Binds a Unix socket to an encoded address staged in `buffer`.
    ///
    /// # Panics
    ///
    /// Panics if `buffer` does not match `address` or the broker returns a
    /// response for a different operation.
    pub fn bind_unix_socket(
        &self,
        handle: ObjectHandle,
        buffer: SharedBufferSequence,
        address: &[u8],
        user: FileUser,
        mode: FileMode,
    ) -> Result<UnixSocketResult<()>, Channel::Error> {
        self.stage_unix_socket_buffer(buffer, address, MAX_ENCODED_UNIX_SOCKET_ADDRESS_SIZE)?;
        match self.request_unix_socket(UnixSocketRequest::Bind(BindUnixSocketRequest {
            handle,
            address: buffer,
            user,
            mode,
        }))? {
            UnixSocketResponse::Bind => Ok(Ok(())),
            UnixSocketResponse::Failed(error) => Ok(Err(error)),
            response => panic!("broker returned unexpected Unix socket response: {response:?}"),
        }
    }

    /// Makes a bound stream socket accept connections.
    ///
    /// # Panics
    ///
    /// Panics if the broker returns a response for a different operation.
    pub fn listen_unix_socket(
        &self,
        handle: ObjectHandle,
        backlog: u32,
    ) -> Result<UnixSocketResult<()>, Channel::Error> {
        match self.request_unix_socket(UnixSocketRequest::Listen(ListenUnixSocketRequest {
            handle,
            backlog,
        }))? {
            UnixSocketResponse::Listen => Ok(Ok(())),
            UnixSocketResponse::Failed(error) => Ok(Err(error)),
            response => panic!("broker returned unexpected Unix socket response: {response:?}"),
        }
    }

    /// Connects a Unix socket to an encoded address staged in `buffer`.
    ///
    /// # Panics
    ///
    /// Panics if `buffer` does not match `address` or the broker returns a
    /// response for a different operation.
    pub fn connect_unix_socket(
        &self,
        handle: ObjectHandle,
        buffer: SharedBufferSequence,
        address: &[u8],
        user: FileUser,
    ) -> Result<UnixSocketResult<()>, Channel::Error> {
        self.stage_unix_socket_buffer(buffer, address, MAX_ENCODED_UNIX_SOCKET_ADDRESS_SIZE)?;
        match self.request_unix_socket(UnixSocketRequest::Connect(ConnectUnixSocketRequest {
            handle,
            address: buffer,
            user,
        }))? {
            UnixSocketResponse::Connect => Ok(Ok(())),
            UnixSocketResponse::Failed(error) => Ok(Err(error)),
            response => panic!("broker returned unexpected Unix socket response: {response:?}"),
        }
    }

    /// Accepts one pending connection from a listening Unix socket.
    ///
    /// # Panics
    ///
    /// Panics if the broker returns a response for a different operation.
    pub fn accept_unix_socket(
        &self,
        handle: ObjectHandle,
        flags: FileOpenFlags,
    ) -> Result<UnixSocketResult<ObjectHandle>, Channel::Error> {
        match self.request_unix_socket(UnixSocketRequest::Accept(AcceptUnixSocketRequest {
            handle,
            flags,
        }))? {
            UnixSocketResponse::Accept(response) => Ok(Ok(response.handle)),
            UnixSocketResponse::Failed(error) => Ok(Err(error)),
            response => panic!("broker returned unexpected Unix socket response: {response:?}"),
        }
    }

    /// Sends `staged`, an encoded destination address of `address_length`
    /// bytes followed by the data, from a Unix socket.
    ///
    /// Returns the number of data bytes sent.
    ///
    /// # Panics
    ///
    /// Panics if `buffer` does not match `staged`, `address_length` exceeds
    /// it, or the broker returns an invalid response.
    pub fn send_unix_socket(
        &self,
        handle: ObjectHandle,
        buffer: SharedBufferSequence,
        staged: &[u8],
        address_length: usize,
        user: FileUser,
    ) -> Result<UnixSocketResult<usize>, Channel::Error> {
        let data_length = staged
            .len()
            .checked_sub(address_length)
            .expect("staged send must hold its address");
        self.stage_unix_socket_buffer(buffer, staged, MAX_UNIX_SOCKET_TRANSFER_SIZE)?;
        match self.request_unix_socket(UnixSocketRequest::Send(SendUnixSocketRequest {
            handle,
            buffer,
            address_length: u32::try_from(address_length)
                .expect("staged address fits the transfer limit"),
            user,
        }))? {
            UnixSocketResponse::Send(response) => {
                let sent = response.sent as usize;
                assert!(
                    sent <= data_length && (sent != 0 || data_length == 0),
                    "broker returned an invalid Unix socket send length"
                );
                Ok(Ok(sent))
            }
            UnixSocketResponse::Failed(error) => Ok(Err(error)),
            response => panic!("broker returned unexpected Unix socket response: {response:?}"),
        }
    }

    /// Receives data from a Unix socket into `destination` through
    /// `buffer`, which must hold `destination` plus an encoded name, as for a
    /// non-blocking socket if `nonblocking` is set.
    ///
    /// Returns the received lengths and the sender's name.
    ///
    /// # Panics
    ///
    /// Panics if `buffer` is not `destination.len()` plus
    /// [`MAX_ENCODED_UNIX_SOCKET_NAME_SIZE`] bytes, or the broker returns an
    /// invalid response.
    pub fn receive_unix_socket(
        &self,
        handle: ObjectHandle,
        buffer: SharedBufferSequence,
        destination: &mut [u8],
        peek: bool,
        nonblocking: bool,
    ) -> Result<UnixSocketResult<(ReceiveUnixSocketResponse, UnixSocketName)>, Channel::Error> {
        let capacity = destination.len();
        self.validate_unix_socket_buffer(
            buffer,
            capacity + MAX_ENCODED_UNIX_SOCKET_NAME_SIZE as usize,
            MAX_UNIX_SOCKET_TRANSFER_SIZE,
        )?;
        match self.request_unix_socket(UnixSocketRequest::Receive(ReceiveUnixSocketRequest {
            handle,
            buffer,
            capacity: u32::try_from(capacity).expect("validated capacity fits in u32"),
            peek,
            nonblocking,
        }))? {
            UnixSocketResponse::Receive(response) => {
                let received = response.received as usize;
                let source_length = response.source_length as usize;
                assert!(
                    received <= capacity
                        && received <= response.length as usize
                        && source_length <= MAX_ENCODED_UNIX_SOCKET_NAME_SIZE as usize,
                    "broker returned inconsistent Unix socket receive lengths"
                );
                let mut staged = Vec::new();
                staged
                    .try_reserve_exact(received + source_length)
                    .map_err(|_| BrokerLocalError::Broker(ErrorCode::OutOfMemory))?;
                staged.resize(received + source_length, 0);
                self.read_shared_buffer(buffer, &mut staged);
                let (data, source) = staged.split_at(received);
                destination[..received].copy_from_slice(data);
                let source = UnixSocketName::decode(source)
                    .expect("broker returned an invalid Unix socket source name");
                Ok(Ok((response, source)))
            }
            UnixSocketResponse::Failed(error) => Ok(Err(error)),
            response => panic!("broker returned unexpected Unix socket response: {response:?}"),
        }
    }

    /// Shuts down one or both directions of a Unix socket.
    ///
    /// # Panics
    ///
    /// Panics if the broker returns a response for a different operation.
    pub fn shutdown_unix_socket(
        &self,
        handle: ObjectHandle,
        mode: ShutdownMode,
    ) -> Result<UnixSocketResult<()>, Channel::Error> {
        match self.request_unix_socket(UnixSocketRequest::Shutdown(ShutdownUnixSocketRequest {
            handle,
            mode,
        }))? {
            UnixSocketResponse::Shutdown => Ok(Ok(())),
            UnixSocketResponse::Failed(error) => Ok(Err(error)),
            response => panic!("broker returned unexpected Unix socket response: {response:?}"),
        }
    }

    /// Reads the name of a Unix socket, or of its peer if `peer` is set,
    /// through `buffer` of [`MAX_ENCODED_UNIX_SOCKET_NAME_SIZE`] bytes.
    ///
    /// # Panics
    ///
    /// Panics if `buffer` has the wrong length or the broker returns an
    /// invalid response.
    pub fn unix_socket_name(
        &self,
        handle: ObjectHandle,
        peer: bool,
        buffer: SharedBufferSequence,
    ) -> Result<UnixSocketResult<UnixSocketName>, Channel::Error> {
        self.validate_unix_socket_buffer(
            buffer,
            MAX_ENCODED_UNIX_SOCKET_NAME_SIZE as usize,
            MAX_ENCODED_UNIX_SOCKET_NAME_SIZE,
        )?;
        match self.request_unix_socket(UnixSocketRequest::GetName(GetUnixSocketNameRequest {
            handle,
            peer,
            buffer,
        }))? {
            UnixSocketResponse::GetName(response) => {
                let length = response.length as usize;
                assert!(
                    length <= MAX_ENCODED_UNIX_SOCKET_NAME_SIZE as usize,
                    "broker returned an oversized Unix socket name"
                );
                let mut encoded = [0; MAX_ENCODED_UNIX_SOCKET_NAME_SIZE as usize];
                self.read_shared_buffer(buffer, &mut encoded[..length]);
                Ok(Ok(UnixSocketName::decode(&encoded[..length])
                    .expect("broker returned an invalid Unix socket name")))
            }
            UnixSocketResponse::Failed(error) => Ok(Err(error)),
            response => panic!("broker returned unexpected Unix socket response: {response:?}"),
        }
    }

    /// Stores one option of a Unix socket.
    ///
    /// # Panics
    ///
    /// Panics if the broker returns a response for a different operation.
    pub fn set_unix_socket_option(
        &self,
        handle: ObjectHandle,
        option: UnixSocketOption,
    ) -> Result<(), Channel::Error> {
        match self.request_unix_socket(UnixSocketRequest::SetOption(
            SetUnixSocketOptionRequest { handle, option },
        ))? {
            UnixSocketResponse::SetOption => Ok(()),
            response => panic!("broker returned unexpected Unix socket response: {response:?}"),
        }
    }

    /// Reads the type and stored options of a Unix socket.
    ///
    /// # Panics
    ///
    /// Panics if the broker returns a response for a different operation.
    pub fn unix_socket_options(
        &self,
        handle: ObjectHandle,
    ) -> Result<GetUnixSocketOptionsResponse, Channel::Error> {
        match self.request_unix_socket(UnixSocketRequest::GetOptions(handle))? {
            UnixSocketResponse::GetOptions(response) => Ok(response),
            response => panic!("broker returned unexpected Unix socket response: {response:?}"),
        }
    }

    fn stage_unix_socket_buffer(
        &self,
        buffer: SharedBufferSequence,
        data: &[u8],
        max_length: u32,
    ) -> Result<(), Channel::Error> {
        self.validate_unix_socket_buffer(buffer, data.len(), max_length)?;
        self.write_shared_buffer(buffer, data);
        Ok(())
    }

    fn validate_unix_socket_buffer(
        &self,
        buffer: SharedBufferSequence,
        expected_length: usize,
        max_length: u32,
    ) -> Result<(), Channel::Error> {
        if buffer.length() > max_length {
            return Err(BrokerLocalError::Broker(ErrorCode::ResourceExhausted));
        }
        assert_eq!(
            expected_length,
            buffer.length() as usize,
            "shared data must match its buffer sequence"
        );
        let _ = buffer
            .descriptors(self.shared_buffers.layout())
            .expect("shared buffer sequence must identify valid slot ranges");
        Ok(())
    }

    fn request_unix_socket(
        &self,
        request: UnixSocketRequest,
    ) -> Result<UnixSocketResponse, Channel::Error> {
        match self.request(BrokerOperation::UnixSocket(request))? {
            BrokerResult::UnixSocket(response) => Ok(response),
            BrokerResult::Error(error) => Err(BrokerLocalError::Broker(error)),
            response => panic!("broker returned unexpected Unix socket response: {response:?}"),
        }
    }
}
