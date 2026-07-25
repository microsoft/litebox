// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use crate::message::{SocketRequest, SocketResponse};
use crate::shared_buffer::{SharedBufferDescriptor, SharedBufferSlotIndex};
use crate::socket::{
    AddressFamily, ConnectSocketRequest, ConnectSocketResponse, ConnectStatus, CreateSocketRequest,
    CreateSocketResponse, IpProtocol, Ipv4Address, Port, ReceiveFlags, ReceiveSocketRequest,
    ReceiveSocketResponse, SendFlags, SendSocketRequest, SendSocketResponse, ShutdownMode,
    ShutdownSocketRequest, SocketAddressV4, SocketError, SocketStatusRequest, SocketStatusResponse,
    SocketType,
};

use super::WireError;
use super::primitive::{Decoder, Encoder};

const SOCKET_REQUEST_TAG_CREATE: u8 = 0;
const SOCKET_REQUEST_TAG_CONNECT: u8 = 1;
const SOCKET_REQUEST_TAG_SEND: u8 = 2;
const SOCKET_REQUEST_TAG_RECEIVE: u8 = 3;
const SOCKET_REQUEST_TAG_SHUTDOWN: u8 = 4;
const SOCKET_REQUEST_TAG_STATUS: u8 = 5;

const SOCKET_RESPONSE_TAG_CREATED: u8 = 0;
const SOCKET_RESPONSE_TAG_CONNECT: u8 = 1;
const SOCKET_RESPONSE_TAG_SENT: u8 = 2;
const SOCKET_RESPONSE_TAG_RECEIVED: u8 = 3;
const SOCKET_RESPONSE_TAG_SHUTDOWN: u8 = 4;
const SOCKET_RESPONSE_TAG_STATUS: u8 = 5;

const ADDRESS_FAMILY_TAG_IPV4: u8 = 0;

const TYPE_TAG_STREAM: u8 = 0;

const IP_PROTOCOL_TAG_TCP: u8 = 0;

const SHUTDOWN_TAG_READ: u8 = 0;
const SHUTDOWN_TAG_WRITE: u8 = 1;
const SHUTDOWN_TAG_BOTH: u8 = 2;

const CONNECT_TAG_CONNECTED: u8 = 0;
const CONNECT_TAG_IN_PROGRESS: u8 = 1;

const STATUS_TAG_OK: u8 = 0;
const STATUS_TAG_ERROR: u8 = 1;

const SOCKET_ERROR_TAG_CONNECTION_REFUSED: u8 = 0;
const SOCKET_ERROR_TAG_CONNECTION_RESET: u8 = 1;
const SOCKET_ERROR_TAG_CONNECTION_ABORTED: u8 = 2;
const SOCKET_ERROR_TAG_NETWORK_UNREACHABLE: u8 = 3;
const SOCKET_ERROR_TAG_HOST_UNREACHABLE: u8 = 4;
const SOCKET_ERROR_TAG_TIMED_OUT: u8 = 5;
const SOCKET_ERROR_TAG_ADDRESS_IN_USE: u8 = 6;
const SOCKET_ERROR_TAG_ADDRESS_NOT_AVAILABLE: u8 = 7;
const SOCKET_ERROR_TAG_POLICY_DENIED: u8 = 8;
const SOCKET_ERROR_TAG_OTHER: u8 = 9;

pub(super) fn encode_socket_request(encoder: &mut Encoder, request: SocketRequest) {
    match request {
        SocketRequest::Create(request) => {
            encoder.u8(SOCKET_REQUEST_TAG_CREATE);
            encoder.u8(match request.address_family {
                AddressFamily::Ipv4 => ADDRESS_FAMILY_TAG_IPV4,
            });
            encoder.u8(match request.socket_type {
                SocketType::Stream => TYPE_TAG_STREAM,
            });
            encoder.u8(match request.protocol {
                IpProtocol::Tcp => IP_PROTOCOL_TAG_TCP,
            });
        }
        SocketRequest::Connect(request) => {
            encoder.u8(SOCKET_REQUEST_TAG_CONNECT);
            encoder.handle(request.handle);
            encode_address(encoder, request.address);
        }
        SocketRequest::Send(request) => {
            encoder.u8(SOCKET_REQUEST_TAG_SEND);
            encoder.handle(request.handle);
            encode_shared_buffer_descriptor(encoder, request.buffer);
            encoder.u32(request.flags.0);
        }
        SocketRequest::Receive(request) => {
            encoder.u8(SOCKET_REQUEST_TAG_RECEIVE);
            encoder.handle(request.handle);
            encode_shared_buffer_descriptor(encoder, request.buffer);
            encoder.u32(request.flags.0);
        }
        SocketRequest::Shutdown(request) => {
            encoder.u8(SOCKET_REQUEST_TAG_SHUTDOWN);
            encoder.handle(request.handle);
            encoder.u8(match request.mode {
                ShutdownMode::Read => SHUTDOWN_TAG_READ,
                ShutdownMode::Write => SHUTDOWN_TAG_WRITE,
                ShutdownMode::Both => SHUTDOWN_TAG_BOTH,
            });
        }
        SocketRequest::Status(request) => {
            encoder.u8(SOCKET_REQUEST_TAG_STATUS);
            encoder.handle(request.handle);
        }
    }
}

pub(super) fn decode_socket_request(decoder: &mut Decoder<'_>) -> Result<SocketRequest, WireError> {
    match decoder.u8()? {
        SOCKET_REQUEST_TAG_CREATE => Ok(SocketRequest::Create(CreateSocketRequest {
            address_family: match decoder.u8()? {
                ADDRESS_FAMILY_TAG_IPV4 => AddressFamily::Ipv4,
                _ => return Err(WireError::InvalidTag),
            },
            socket_type: match decoder.u8()? {
                TYPE_TAG_STREAM => SocketType::Stream,
                _ => return Err(WireError::InvalidTag),
            },
            protocol: match decoder.u8()? {
                IP_PROTOCOL_TAG_TCP => IpProtocol::Tcp,
                _ => return Err(WireError::InvalidTag),
            },
        })),
        SOCKET_REQUEST_TAG_CONNECT => Ok(SocketRequest::Connect(ConnectSocketRequest {
            handle: decoder.handle()?,
            address: decode_address(decoder)?,
        })),
        SOCKET_REQUEST_TAG_SEND => Ok(SocketRequest::Send(SendSocketRequest {
            handle: decoder.handle()?,
            buffer: decode_shared_buffer_descriptor(decoder)?,
            flags: SendFlags(decoder.u32()?),
        })),
        SOCKET_REQUEST_TAG_RECEIVE => Ok(SocketRequest::Receive(ReceiveSocketRequest {
            handle: decoder.handle()?,
            buffer: decode_shared_buffer_descriptor(decoder)?,
            flags: ReceiveFlags(decoder.u32()?),
        })),
        SOCKET_REQUEST_TAG_SHUTDOWN => Ok(SocketRequest::Shutdown(ShutdownSocketRequest {
            handle: decoder.handle()?,
            mode: match decoder.u8()? {
                SHUTDOWN_TAG_READ => ShutdownMode::Read,
                SHUTDOWN_TAG_WRITE => ShutdownMode::Write,
                SHUTDOWN_TAG_BOTH => ShutdownMode::Both,
                _ => return Err(WireError::InvalidTag),
            },
        })),
        SOCKET_REQUEST_TAG_STATUS => Ok(SocketRequest::Status(SocketStatusRequest {
            handle: decoder.handle()?,
        })),
        _ => Err(WireError::InvalidTag),
    }
}

pub(super) fn encode_socket_response(encoder: &mut Encoder, response: SocketResponse) {
    match response {
        SocketResponse::Create(response) => {
            encoder.u8(SOCKET_RESPONSE_TAG_CREATED);
            encoder.handle(response.handle);
        }
        SocketResponse::Connect(response) => {
            encoder.u8(SOCKET_RESPONSE_TAG_CONNECT);
            encoder.u8(match response.status {
                ConnectStatus::Connected => CONNECT_TAG_CONNECTED,
                ConnectStatus::InProgress => CONNECT_TAG_IN_PROGRESS,
            });
        }
        SocketResponse::Send(response) => {
            encoder.u8(SOCKET_RESPONSE_TAG_SENT);
            encoder.u32(response.sent);
        }
        SocketResponse::Receive(response) => {
            encoder.u8(SOCKET_RESPONSE_TAG_RECEIVED);
            encoder.u32(response.received);
        }
        SocketResponse::Shutdown => encoder.u8(SOCKET_RESPONSE_TAG_SHUTDOWN),
        SocketResponse::Status(response) => {
            encoder.u8(SOCKET_RESPONSE_TAG_STATUS);
            match response.error {
                None => encoder.u8(STATUS_TAG_OK),
                Some(error) => {
                    encoder.u8(STATUS_TAG_ERROR);
                    encoder.u8(match error {
                        SocketError::ConnectionRefused => SOCKET_ERROR_TAG_CONNECTION_REFUSED,
                        SocketError::ConnectionReset => SOCKET_ERROR_TAG_CONNECTION_RESET,
                        SocketError::ConnectionAborted => SOCKET_ERROR_TAG_CONNECTION_ABORTED,
                        SocketError::NetworkUnreachable => SOCKET_ERROR_TAG_NETWORK_UNREACHABLE,
                        SocketError::HostUnreachable => SOCKET_ERROR_TAG_HOST_UNREACHABLE,
                        SocketError::TimedOut => SOCKET_ERROR_TAG_TIMED_OUT,
                        SocketError::AddressInUse => SOCKET_ERROR_TAG_ADDRESS_IN_USE,
                        SocketError::AddressNotAvailable => SOCKET_ERROR_TAG_ADDRESS_NOT_AVAILABLE,
                        SocketError::PolicyDenied => SOCKET_ERROR_TAG_POLICY_DENIED,
                        SocketError::Other => SOCKET_ERROR_TAG_OTHER,
                    });
                }
            }
        }
    }
}

pub(super) fn decode_socket_response(
    decoder: &mut Decoder<'_>,
) -> Result<SocketResponse, WireError> {
    match decoder.u8()? {
        SOCKET_RESPONSE_TAG_CREATED => Ok(SocketResponse::Create(CreateSocketResponse {
            handle: decoder.handle()?,
        })),
        SOCKET_RESPONSE_TAG_CONNECT => Ok(SocketResponse::Connect(ConnectSocketResponse {
            status: match decoder.u8()? {
                CONNECT_TAG_CONNECTED => ConnectStatus::Connected,
                CONNECT_TAG_IN_PROGRESS => ConnectStatus::InProgress,
                _ => return Err(WireError::InvalidTag),
            },
        })),
        SOCKET_RESPONSE_TAG_SENT => Ok(SocketResponse::Send(SendSocketResponse {
            sent: decoder.u32()?,
        })),
        SOCKET_RESPONSE_TAG_RECEIVED => Ok(SocketResponse::Receive(ReceiveSocketResponse {
            received: decoder.u32()?,
        })),
        SOCKET_RESPONSE_TAG_SHUTDOWN => Ok(SocketResponse::Shutdown),
        SOCKET_RESPONSE_TAG_STATUS => Ok(SocketResponse::Status(SocketStatusResponse {
            error: match decoder.u8()? {
                STATUS_TAG_OK => None,
                STATUS_TAG_ERROR => Some(match decoder.u8()? {
                    SOCKET_ERROR_TAG_CONNECTION_REFUSED => SocketError::ConnectionRefused,
                    SOCKET_ERROR_TAG_CONNECTION_RESET => SocketError::ConnectionReset,
                    SOCKET_ERROR_TAG_CONNECTION_ABORTED => SocketError::ConnectionAborted,
                    SOCKET_ERROR_TAG_NETWORK_UNREACHABLE => SocketError::NetworkUnreachable,
                    SOCKET_ERROR_TAG_HOST_UNREACHABLE => SocketError::HostUnreachable,
                    SOCKET_ERROR_TAG_TIMED_OUT => SocketError::TimedOut,
                    SOCKET_ERROR_TAG_ADDRESS_IN_USE => SocketError::AddressInUse,
                    SOCKET_ERROR_TAG_ADDRESS_NOT_AVAILABLE => SocketError::AddressNotAvailable,
                    SOCKET_ERROR_TAG_POLICY_DENIED => SocketError::PolicyDenied,
                    SOCKET_ERROR_TAG_OTHER => SocketError::Other,
                    _ => return Err(WireError::InvalidTag),
                }),
                _ => return Err(WireError::InvalidTag),
            },
        })),
        _ => Err(WireError::InvalidTag),
    }
}

fn encode_address(encoder: &mut Encoder, address: SocketAddressV4) {
    for octet in address.address.0 {
        encoder.u8(octet);
    }
    encoder.u16(address.port.0);
}

fn decode_address(decoder: &mut Decoder<'_>) -> Result<SocketAddressV4, WireError> {
    let mut octets = [0; 4];
    for octet in &mut octets {
        *octet = decoder.u8()?;
    }
    Ok(SocketAddressV4 {
        address: Ipv4Address(octets),
        port: Port(decoder.u16()?),
    })
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
