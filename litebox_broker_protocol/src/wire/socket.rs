// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use core::net::{Ipv4Addr, SocketAddrV4};

use crate::message::{SocketRequest, SocketResponse};
use crate::shared_buffer::{SharedBufferDescriptor, SharedBufferSlotIndex};
use crate::socket::{
    AcceptSocketRequest, AcceptSocketResponse, AddressFamily, BindSocketRequest,
    BindSocketResponse, ConnectSocketRequest, ConnectSocketResponse, CreateSocketRequest,
    CreateSocketResponse, IpProtocol, ListenSocketRequest, ListenSocketResponse, ReceiveFlags,
    ReceiveFromFlags, ReceiveFromSocketRequest, ReceiveFromSocketResponse, ReceiveSocketRequest,
    ReceiveSocketResponse, SendFlags, SendSocketRequest, SendSocketResponse, SendToSocketRequest,
    SendToSocketResponse, ShutdownMode, ShutdownSocketRequest, SocketConnectionStatus, SocketError,
    SocketStatusRequest, SocketStatusResponse, SocketType,
};

use super::WireError;
use super::primitive::{Decoder, Encoder};

const SOCKET_TAG_CREATE: u8 = 0;
const SOCKET_TAG_CONNECT: u8 = 1;
const SOCKET_TAG_SEND: u8 = 2;
const SOCKET_TAG_RECEIVE: u8 = 3;
const SOCKET_TAG_SHUTDOWN: u8 = 4;
const SOCKET_TAG_STATUS: u8 = 5;
const SOCKET_TAG_FAILED: u8 = 6;
const SOCKET_TAG_BIND: u8 = 7;
const SOCKET_TAG_LISTEN: u8 = 8;
const SOCKET_TAG_ACCEPT: u8 = 9;
const SOCKET_TAG_SEND_TO: u8 = 10;
const SOCKET_TAG_RECEIVE_FROM: u8 = 11;

const ADDRESS_FAMILY_TAG_IPV4: u8 = 0;

const TYPE_TAG_STREAM: u8 = 0;
const TYPE_TAG_DATAGRAM: u8 = 1;

const IP_PROTOCOL_TAG_TCP: u8 = 0;
const IP_PROTOCOL_TAG_UDP: u8 = 1;

const SHUTDOWN_TAG_READ: u8 = 0;
const SHUTDOWN_TAG_WRITE: u8 = 1;
const SHUTDOWN_TAG_BOTH: u8 = 2;
const SHUTDOWN_TAG_ABORT: u8 = 3;
const SHUTDOWN_TAG_STOP_LISTENING: u8 = 4;

const CONNECTION_STATUS_TAG_UNCONNECTED: u8 = 0;
const CONNECTION_STATUS_TAG_CONNECTING: u8 = 1;
const CONNECTION_STATUS_TAG_CONNECTED: u8 = 2;
const CONNECTION_STATUS_TAG_FAILED: u8 = 3;

const RECEIVE_RESPONSE_TAG_RECEIVED: u8 = 0;
const RECEIVE_RESPONSE_TAG_END_OF_STREAM: u8 = 1;

pub(super) fn encode_socket_request(encoder: &mut Encoder, request: SocketRequest) {
    match request {
        SocketRequest::Create(request) => {
            encoder.u8(SOCKET_TAG_CREATE);
            encoder.u8(match request.address_family {
                AddressFamily::Ipv4 => ADDRESS_FAMILY_TAG_IPV4,
            });
            encoder.u8(match request.socket_type {
                SocketType::Stream => TYPE_TAG_STREAM,
                SocketType::Datagram => TYPE_TAG_DATAGRAM,
            });
            encoder.u8(match request.protocol {
                IpProtocol::Tcp => IP_PROTOCOL_TAG_TCP,
                IpProtocol::Udp => IP_PROTOCOL_TAG_UDP,
            });
        }
        SocketRequest::Connect(request) => {
            encoder.u8(SOCKET_TAG_CONNECT);
            encoder.handle(request.handle);
            encode_address(encoder, request.address);
        }
        SocketRequest::Bind(request) => {
            encoder.u8(SOCKET_TAG_BIND);
            encoder.handle(request.handle);
            encode_address(encoder, request.address);
        }
        SocketRequest::Listen(request) => {
            encoder.u8(SOCKET_TAG_LISTEN);
            encoder.handle(request.handle);
            encoder.u32(request.backlog);
        }
        SocketRequest::Accept(request) => {
            encoder.u8(SOCKET_TAG_ACCEPT);
            encoder.handle(request.handle);
        }
        SocketRequest::Send(request) => {
            encoder.u8(SOCKET_TAG_SEND);
            encoder.handle(request.handle);
            encode_shared_buffer_descriptor(encoder, request.buffer);
            encoder.u32(request.flags.0);
        }
        SocketRequest::SendTo(request) => {
            encoder.u8(SOCKET_TAG_SEND_TO);
            encoder.handle(request.handle);
            encode_shared_buffer_descriptor(encoder, request.buffer);
            encoder.u32(request.flags.0);
            encode_optional_address(encoder, request.destination);
        }
        SocketRequest::Receive(request) => {
            encoder.u8(SOCKET_TAG_RECEIVE);
            encoder.handle(request.handle);
            encode_shared_buffer_descriptor(encoder, request.buffer);
            encoder.u32(request.flags.0);
            encoder.u32(request.peek_offset);
            encoder.u32(request.peek_length);
        }
        SocketRequest::ReceiveFrom(request) => {
            encoder.u8(SOCKET_TAG_RECEIVE_FROM);
            encoder.handle(request.handle);
            encode_shared_buffer_descriptor(encoder, request.buffer);
            encoder.u32(request.flags.0);
        }
        SocketRequest::Shutdown(request) => {
            encoder.u8(SOCKET_TAG_SHUTDOWN);
            encoder.handle(request.handle);
            encoder.u8(match request.mode {
                ShutdownMode::Read => SHUTDOWN_TAG_READ,
                ShutdownMode::Write => SHUTDOWN_TAG_WRITE,
                ShutdownMode::Both => SHUTDOWN_TAG_BOTH,
                ShutdownMode::Abort => SHUTDOWN_TAG_ABORT,
                ShutdownMode::StopListening => SHUTDOWN_TAG_STOP_LISTENING,
            });
        }
        SocketRequest::Status(request) => {
            encoder.u8(SOCKET_TAG_STATUS);
            encoder.handle(request.handle);
        }
    }
}

pub(super) fn decode_socket_request(decoder: &mut Decoder<'_>) -> Result<SocketRequest, WireError> {
    match decoder.u8()? {
        SOCKET_TAG_CREATE => Ok(SocketRequest::Create(CreateSocketRequest {
            address_family: match decoder.u8()? {
                ADDRESS_FAMILY_TAG_IPV4 => AddressFamily::Ipv4,
                _ => return Err(WireError::InvalidTag),
            },
            socket_type: match decoder.u8()? {
                TYPE_TAG_STREAM => SocketType::Stream,
                TYPE_TAG_DATAGRAM => SocketType::Datagram,
                _ => return Err(WireError::InvalidTag),
            },
            protocol: match decoder.u8()? {
                IP_PROTOCOL_TAG_TCP => IpProtocol::Tcp,
                IP_PROTOCOL_TAG_UDP => IpProtocol::Udp,
                _ => return Err(WireError::InvalidTag),
            },
        })),
        SOCKET_TAG_CONNECT => Ok(SocketRequest::Connect(ConnectSocketRequest {
            handle: decoder.handle()?,
            address: decode_address(decoder)?,
        })),
        SOCKET_TAG_BIND => Ok(SocketRequest::Bind(BindSocketRequest {
            handle: decoder.handle()?,
            address: decode_address(decoder)?,
        })),
        SOCKET_TAG_LISTEN => Ok(SocketRequest::Listen(ListenSocketRequest {
            handle: decoder.handle()?,
            backlog: decoder.u32()?,
        })),
        SOCKET_TAG_ACCEPT => Ok(SocketRequest::Accept(AcceptSocketRequest {
            handle: decoder.handle()?,
        })),
        SOCKET_TAG_SEND => Ok(SocketRequest::Send(SendSocketRequest {
            handle: decoder.handle()?,
            buffer: decode_shared_buffer_descriptor(decoder)?,
            flags: SendFlags(decoder.u32()?),
        })),
        SOCKET_TAG_SEND_TO => Ok(SocketRequest::SendTo(SendToSocketRequest {
            handle: decoder.handle()?,
            buffer: decode_shared_buffer_descriptor(decoder)?,
            flags: SendFlags(decoder.u32()?),
            destination: decode_optional_address(decoder)?,
        })),
        SOCKET_TAG_RECEIVE => Ok(SocketRequest::Receive(ReceiveSocketRequest {
            handle: decoder.handle()?,
            buffer: decode_shared_buffer_descriptor(decoder)?,
            flags: ReceiveFlags(decoder.u32()?),
            peek_offset: decoder.u32()?,
            peek_length: decoder.u32()?,
        })),
        SOCKET_TAG_RECEIVE_FROM => Ok(SocketRequest::ReceiveFrom(ReceiveFromSocketRequest {
            handle: decoder.handle()?,
            buffer: decode_shared_buffer_descriptor(decoder)?,
            flags: ReceiveFromFlags(decoder.u32()?),
        })),
        SOCKET_TAG_SHUTDOWN => Ok(SocketRequest::Shutdown(ShutdownSocketRequest {
            handle: decoder.handle()?,
            mode: match decoder.u8()? {
                SHUTDOWN_TAG_READ => ShutdownMode::Read,
                SHUTDOWN_TAG_WRITE => ShutdownMode::Write,
                SHUTDOWN_TAG_BOTH => ShutdownMode::Both,
                SHUTDOWN_TAG_ABORT => ShutdownMode::Abort,
                SHUTDOWN_TAG_STOP_LISTENING => ShutdownMode::StopListening,
                _ => return Err(WireError::InvalidTag),
            },
        })),
        SOCKET_TAG_STATUS => Ok(SocketRequest::Status(SocketStatusRequest {
            handle: decoder.handle()?,
        })),
        _ => Err(WireError::InvalidTag),
    }
}

pub(super) fn encode_socket_response(encoder: &mut Encoder, response: SocketResponse) {
    match response {
        SocketResponse::Create(response) => {
            encoder.u8(SOCKET_TAG_CREATE);
            encoder.handle(response.handle);
        }
        SocketResponse::Connect(response) => {
            encoder.u8(SOCKET_TAG_CONNECT);
            encode_connection_status(encoder, response.status);
        }
        SocketResponse::Bind(response) => {
            encoder.u8(SOCKET_TAG_BIND);
            encode_address(encoder, response.local_address);
        }
        SocketResponse::Listen(response) => {
            encoder.u8(SOCKET_TAG_LISTEN);
            encode_address(encoder, response.local_address);
        }
        SocketResponse::Accept(response) => {
            encoder.u8(SOCKET_TAG_ACCEPT);
            encoder.handle(response.handle);
            encode_address(encoder, response.local_address);
            encode_address(encoder, response.remote_address);
        }
        SocketResponse::Send(response) => {
            encoder.u8(SOCKET_TAG_SEND);
            encoder.u32(response.sent);
        }
        SocketResponse::SendTo(response) => {
            encoder.u8(SOCKET_TAG_SEND_TO);
            encoder.u32(response.sent);
        }
        SocketResponse::Receive(response) => {
            encoder.u8(SOCKET_TAG_RECEIVE);
            match response {
                ReceiveSocketResponse::Received(received) => {
                    encoder.u8(RECEIVE_RESPONSE_TAG_RECEIVED);
                    encoder.u32(received);
                }
                ReceiveSocketResponse::EndOfStream => {
                    encoder.u8(RECEIVE_RESPONSE_TAG_END_OF_STREAM);
                }
            }
        }
        SocketResponse::ReceiveFrom(response) => {
            encoder.u8(SOCKET_TAG_RECEIVE_FROM);
            encoder.u32(response.received);
            encoder.u32(response.datagram_length);
            encode_address(encoder, response.source_address);
        }
        SocketResponse::Shutdown => encoder.u8(SOCKET_TAG_SHUTDOWN),
        SocketResponse::Status(response) => {
            encoder.u8(SOCKET_TAG_STATUS);
            encode_connection_status(encoder, response.status);
            encode_optional_address(encoder, response.local_address);
            encode_optional_socket_error(encoder, response.pending_error);
        }
        SocketResponse::Failed(error) => {
            encoder.u8(SOCKET_TAG_FAILED);
            encode_socket_error(encoder, error);
        }
    }
}

pub(super) fn decode_socket_response(
    decoder: &mut Decoder<'_>,
) -> Result<SocketResponse, WireError> {
    match decoder.u8()? {
        SOCKET_TAG_CREATE => Ok(SocketResponse::Create(CreateSocketResponse {
            handle: decoder.handle()?,
        })),
        SOCKET_TAG_CONNECT => Ok(SocketResponse::Connect(ConnectSocketResponse {
            status: decode_connection_status(decoder)?,
        })),
        SOCKET_TAG_BIND => Ok(SocketResponse::Bind(BindSocketResponse {
            local_address: decode_address(decoder)?,
        })),
        SOCKET_TAG_LISTEN => Ok(SocketResponse::Listen(ListenSocketResponse {
            local_address: decode_address(decoder)?,
        })),
        SOCKET_TAG_ACCEPT => Ok(SocketResponse::Accept(AcceptSocketResponse {
            handle: decoder.handle()?,
            local_address: decode_address(decoder)?,
            remote_address: decode_address(decoder)?,
        })),
        SOCKET_TAG_SEND => Ok(SocketResponse::Send(SendSocketResponse {
            sent: decoder.u32()?,
        })),
        SOCKET_TAG_SEND_TO => Ok(SocketResponse::SendTo(SendToSocketResponse {
            sent: decoder.u32()?,
        })),
        SOCKET_TAG_RECEIVE => Ok(SocketResponse::Receive(match decoder.u8()? {
            RECEIVE_RESPONSE_TAG_RECEIVED => ReceiveSocketResponse::Received(decoder.u32()?),
            RECEIVE_RESPONSE_TAG_END_OF_STREAM => ReceiveSocketResponse::EndOfStream,
            _ => return Err(WireError::InvalidTag),
        })),
        SOCKET_TAG_RECEIVE_FROM => Ok(SocketResponse::ReceiveFrom(ReceiveFromSocketResponse {
            received: decoder.u32()?,
            datagram_length: decoder.u32()?,
            source_address: decode_address(decoder)?,
        })),
        SOCKET_TAG_SHUTDOWN => Ok(SocketResponse::Shutdown),
        SOCKET_TAG_STATUS => Ok(SocketResponse::Status(SocketStatusResponse {
            status: decode_connection_status(decoder)?,
            local_address: decode_optional_address(decoder)?,
            pending_error: decode_optional_socket_error(decoder)?,
        })),
        SOCKET_TAG_FAILED => Ok(SocketResponse::Failed(decode_socket_error(decoder)?)),
        _ => Err(WireError::InvalidTag),
    }
}

fn encode_connection_status(encoder: &mut Encoder, status: SocketConnectionStatus) {
    match status {
        SocketConnectionStatus::Unconnected => encoder.u8(CONNECTION_STATUS_TAG_UNCONNECTED),
        SocketConnectionStatus::Connecting => encoder.u8(CONNECTION_STATUS_TAG_CONNECTING),
        SocketConnectionStatus::Connected => encoder.u8(CONNECTION_STATUS_TAG_CONNECTED),
        SocketConnectionStatus::Failed(error) => {
            encoder.u8(CONNECTION_STATUS_TAG_FAILED);
            encode_socket_error(encoder, error);
        }
    }
}

fn decode_connection_status(
    decoder: &mut Decoder<'_>,
) -> Result<SocketConnectionStatus, WireError> {
    match decoder.u8()? {
        CONNECTION_STATUS_TAG_UNCONNECTED => Ok(SocketConnectionStatus::Unconnected),
        CONNECTION_STATUS_TAG_CONNECTING => Ok(SocketConnectionStatus::Connecting),
        CONNECTION_STATUS_TAG_CONNECTED => Ok(SocketConnectionStatus::Connected),
        CONNECTION_STATUS_TAG_FAILED => Ok(SocketConnectionStatus::Failed(decode_socket_error(
            decoder,
        )?)),
        _ => Err(WireError::InvalidTag),
    }
}

fn encode_socket_error(encoder: &mut Encoder, error: SocketError) {
    encoder.u8(error.as_raw());
}

fn decode_socket_error(decoder: &mut Decoder<'_>) -> Result<SocketError, WireError> {
    SocketError::from_raw(decoder.u8()?).ok_or(WireError::InvalidTag)
}

fn encode_address(encoder: &mut Encoder, address: SocketAddrV4) {
    for octet in address.ip().octets() {
        encoder.u8(octet);
    }
    encoder.u16(address.port());
}

fn decode_address(decoder: &mut Decoder<'_>) -> Result<SocketAddrV4, WireError> {
    let mut octets = [0; 4];
    for octet in &mut octets {
        *octet = decoder.u8()?;
    }
    Ok(SocketAddrV4::new(Ipv4Addr::from(octets), decoder.u16()?))
}

fn encode_optional_address(encoder: &mut Encoder, address: Option<SocketAddrV4>) {
    encoder.u8(u8::from(address.is_some()));
    if let Some(address) = address {
        encode_address(encoder, address);
    }
}

fn decode_optional_address(decoder: &mut Decoder<'_>) -> Result<Option<SocketAddrV4>, WireError> {
    match decoder.u8()? {
        0 => Ok(None),
        1 => decode_address(decoder).map(Some),
        _ => Err(WireError::InvalidTag),
    }
}

fn encode_optional_socket_error(encoder: &mut Encoder, error: Option<SocketError>) {
    encoder.u8(u8::from(error.is_some()));
    if let Some(error) = error {
        encode_socket_error(encoder, error);
    }
}

fn decode_optional_socket_error(
    decoder: &mut Decoder<'_>,
) -> Result<Option<SocketError>, WireError> {
    match decoder.u8()? {
        0 => Ok(None),
        1 => decode_socket_error(decoder).map(Some),
        _ => Err(WireError::InvalidTag),
    }
}

fn encode_shared_buffer_descriptor(encoder: &mut Encoder, descriptor: SharedBufferDescriptor) {
    encoder.u32(descriptor.slot_index.0);
    encoder.u32(descriptor.length);
}

fn decode_shared_buffer_descriptor(
    decoder: &mut Decoder<'_>,
) -> Result<SharedBufferDescriptor, WireError> {
    Ok(SharedBufferDescriptor {
        slot_index: SharedBufferSlotIndex(decoder.u32()?),
        length: decoder.u32()?,
    })
}
