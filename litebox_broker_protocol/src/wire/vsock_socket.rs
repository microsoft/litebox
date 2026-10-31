// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use crate::message::{VsockSocketRequest, VsockSocketResponse};
use crate::socket::{
    AcceptSocketRequest, CheckConnectSocketRequest, ConnectSocketResponse, CreateSocketResponse,
    GetSocketNameRequest, ListenSocketRequest, SendFlags, SendSocketRequest, SendSocketResponse,
    ShutdownSocketRequest, TakeSocketErrorRequest, TakeSocketErrorResponse,
};
use crate::vsock_socket::{
    AcceptVsockSocketResponse, BindVsockSocketRequest, ConnectVsockSocketRequest,
    CreateVsockSocketRequest, GetVsockSocketNameResponse, ReceiveVsockSocketRequest, VsockAddress,
};

use super::WireError;
use super::fs::decode_open_flags;
use super::primitive::{Decoder, Encoder};
use super::socket::{
    decode_bool, decode_connection_status, decode_optional_socket_error, decode_receive_response,
    decode_shutdown_mode, decode_socket_error, encode_bool, encode_connection_status,
    encode_optional_socket_error, encode_receive_response, encode_shutdown_mode,
    encode_socket_error,
};

const TAG_CREATE: u8 = 0;
const TAG_BIND: u8 = 1;
const TAG_LISTEN: u8 = 2;
const TAG_ACCEPT: u8 = 3;
const TAG_CONNECT: u8 = 4;
const TAG_CHECK_CONNECT: u8 = 5;
const TAG_CANCEL_CONNECT: u8 = 6;
const TAG_TAKE_ERROR: u8 = 7;
const TAG_SEND: u8 = 8;
const TAG_RECEIVE: u8 = 9;
const TAG_SHUTDOWN: u8 = 10;
const TAG_GET_NAME: u8 = 11;
const TAG_FAILED: u8 = 12;

pub(super) fn encode_vsock_socket_request(encoder: &mut Encoder, request: VsockSocketRequest) {
    match request {
        VsockSocketRequest::Create(request) => {
            encoder.u8(TAG_CREATE);
            encoder.u16(request.flags.bits());
        }
        VsockSocketRequest::Bind(request) => {
            encoder.u8(TAG_BIND);
            encoder.handle(request.handle);
            encode_address(encoder, request.address);
        }
        VsockSocketRequest::Listen(request) => {
            encoder.u8(TAG_LISTEN);
            encoder.handle(request.handle);
            encoder.u32(request.backlog);
        }
        VsockSocketRequest::Accept(request) => {
            encoder.u8(TAG_ACCEPT);
            encoder.handle(request.handle);
            encoder.u16(request.flags.bits());
        }
        VsockSocketRequest::Connect(request) => {
            encoder.u8(TAG_CONNECT);
            encoder.handle(request.handle);
            encode_address(encoder, request.address);
        }
        VsockSocketRequest::CheckConnect(request) => {
            encoder.u8(TAG_CHECK_CONNECT);
            encoder.handle(request.handle);
        }
        VsockSocketRequest::CancelConnect(request) => {
            encoder.u8(TAG_CANCEL_CONNECT);
            encoder.handle(request.handle);
        }
        VsockSocketRequest::TakeError(request) => {
            encoder.u8(TAG_TAKE_ERROR);
            encoder.handle(request.handle);
        }
        VsockSocketRequest::Send(request) => {
            encoder.u8(TAG_SEND);
            encoder.handle(request.handle);
            encoder.shared_buffer_sequence(request.buffer);
            encoder.u32(request.flags.0);
        }
        VsockSocketRequest::Receive(request) => {
            encoder.u8(TAG_RECEIVE);
            encoder.handle(request.handle);
            encoder.shared_buffer_sequence(request.buffer);
        }
        VsockSocketRequest::Shutdown(request) => {
            encoder.u8(TAG_SHUTDOWN);
            encoder.handle(request.handle);
            encode_shutdown_mode(encoder, request.mode);
        }
        VsockSocketRequest::GetName(request) => {
            encoder.u8(TAG_GET_NAME);
            encoder.handle(request.handle);
            encode_bool(encoder, request.peer);
        }
    }
}

pub(super) fn decode_vsock_socket_request(
    decoder: &mut Decoder<'_>,
) -> Result<VsockSocketRequest, WireError> {
    Ok(match decoder.u8()? {
        TAG_CREATE => VsockSocketRequest::Create(CreateVsockSocketRequest {
            flags: decode_open_flags(decoder)?,
        }),
        TAG_BIND => VsockSocketRequest::Bind(BindVsockSocketRequest {
            handle: decoder.handle()?,
            address: decode_address(decoder)?,
        }),
        TAG_LISTEN => VsockSocketRequest::Listen(ListenSocketRequest {
            handle: decoder.handle()?,
            backlog: decoder.u32()?,
        }),
        TAG_ACCEPT => VsockSocketRequest::Accept(AcceptSocketRequest {
            handle: decoder.handle()?,
            flags: decode_open_flags(decoder)?,
        }),
        TAG_CONNECT => VsockSocketRequest::Connect(ConnectVsockSocketRequest {
            handle: decoder.handle()?,
            address: decode_address(decoder)?,
        }),
        TAG_CHECK_CONNECT => VsockSocketRequest::CheckConnect(CheckConnectSocketRequest {
            handle: decoder.handle()?,
        }),
        TAG_CANCEL_CONNECT => VsockSocketRequest::CancelConnect(CheckConnectSocketRequest {
            handle: decoder.handle()?,
        }),
        TAG_TAKE_ERROR => VsockSocketRequest::TakeError(TakeSocketErrorRequest {
            handle: decoder.handle()?,
        }),
        TAG_SEND => VsockSocketRequest::Send(SendSocketRequest {
            handle: decoder.handle()?,
            buffer: decoder.shared_buffer_sequence()?,
            flags: SendFlags(decoder.u32()?),
        }),
        TAG_RECEIVE => VsockSocketRequest::Receive(ReceiveVsockSocketRequest {
            handle: decoder.handle()?,
            buffer: decoder.shared_buffer_sequence()?,
        }),
        TAG_SHUTDOWN => VsockSocketRequest::Shutdown(ShutdownSocketRequest {
            handle: decoder.handle()?,
            mode: decode_shutdown_mode(decoder)?,
        }),
        TAG_GET_NAME => VsockSocketRequest::GetName(GetSocketNameRequest {
            handle: decoder.handle()?,
            peer: decode_bool(decoder)?,
        }),
        _ => return Err(WireError::InvalidTag),
    })
}

pub(super) fn encode_vsock_socket_response(encoder: &mut Encoder, response: VsockSocketResponse) {
    match response {
        VsockSocketResponse::Create(response) => {
            encoder.u8(TAG_CREATE);
            encoder.handle(response.handle);
        }
        VsockSocketResponse::Bind => encoder.u8(TAG_BIND),
        VsockSocketResponse::Listen => encoder.u8(TAG_LISTEN),
        VsockSocketResponse::Accept(response) => {
            encoder.u8(TAG_ACCEPT);
            encoder.handle(response.handle);
            encode_address(encoder, response.remote_address);
        }
        VsockSocketResponse::Connect(response) => {
            encoder.u8(TAG_CONNECT);
            encode_connection_status(encoder, response.status);
        }
        VsockSocketResponse::CheckConnect(response) => {
            encoder.u8(TAG_CHECK_CONNECT);
            encode_connection_status(encoder, response.status);
        }
        VsockSocketResponse::CancelConnect => encoder.u8(TAG_CANCEL_CONNECT),
        VsockSocketResponse::TakeError(response) => {
            encoder.u8(TAG_TAKE_ERROR);
            encode_optional_socket_error(encoder, response.error);
        }
        VsockSocketResponse::Send(response) => {
            encoder.u8(TAG_SEND);
            encoder.u32(response.sent);
        }
        VsockSocketResponse::Receive(response) => {
            encoder.u8(TAG_RECEIVE);
            encode_receive_response(encoder, response);
        }
        VsockSocketResponse::Shutdown => encoder.u8(TAG_SHUTDOWN),
        VsockSocketResponse::GetName(response) => {
            encoder.u8(TAG_GET_NAME);
            encode_bool(encoder, response.address.is_some());
            if let Some(address) = response.address {
                encode_address(encoder, address);
            }
        }
        VsockSocketResponse::Failed(error) => {
            encoder.u8(TAG_FAILED);
            encode_socket_error(encoder, error);
        }
    }
}

pub(super) fn decode_vsock_socket_response(
    decoder: &mut Decoder<'_>,
) -> Result<VsockSocketResponse, WireError> {
    Ok(match decoder.u8()? {
        TAG_CREATE => VsockSocketResponse::Create(CreateSocketResponse {
            handle: decoder.handle()?,
        }),
        TAG_BIND => VsockSocketResponse::Bind,
        TAG_LISTEN => VsockSocketResponse::Listen,
        TAG_ACCEPT => VsockSocketResponse::Accept(AcceptVsockSocketResponse {
            handle: decoder.handle()?,
            remote_address: decode_address(decoder)?,
        }),
        TAG_CONNECT => VsockSocketResponse::Connect(ConnectSocketResponse {
            status: decode_connection_status(decoder)?,
        }),
        TAG_CHECK_CONNECT => VsockSocketResponse::CheckConnect(ConnectSocketResponse {
            status: decode_connection_status(decoder)?,
        }),
        TAG_CANCEL_CONNECT => VsockSocketResponse::CancelConnect,
        TAG_TAKE_ERROR => VsockSocketResponse::TakeError(TakeSocketErrorResponse {
            error: decode_optional_socket_error(decoder)?,
        }),
        TAG_SEND => VsockSocketResponse::Send(SendSocketResponse {
            sent: decoder.u32()?,
        }),
        TAG_RECEIVE => VsockSocketResponse::Receive(decode_receive_response(decoder)?),
        TAG_SHUTDOWN => VsockSocketResponse::Shutdown,
        TAG_GET_NAME => VsockSocketResponse::GetName(GetVsockSocketNameResponse {
            address: if decode_bool(decoder)? {
                Some(decode_address(decoder)?)
            } else {
                None
            },
        }),
        TAG_FAILED => VsockSocketResponse::Failed(decode_socket_error(decoder)?),
        _ => return Err(WireError::InvalidTag),
    })
}

fn encode_address(encoder: &mut Encoder, address: VsockAddress) {
    encoder.u32(address.cid);
    encoder.u32(address.port);
}

fn decode_address(decoder: &mut Decoder<'_>) -> Result<VsockAddress, WireError> {
    Ok(VsockAddress {
        cid: decoder.u32()?,
        port: decoder.u32()?,
    })
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use super::*;
    use crate::fs::FileOpenFlags;
    use crate::message::{BrokerOperation, BrokerRequest, BrokerResponse, BrokerResult};
    use crate::shared_buffer::{
        MAX_SHARED_BUFFER_SEQUENCE_SLOTS, SharedBufferSequence, SharedBufferSlotIndex,
    };
    use crate::socket::{ReceiveSocketResponse, ShutdownMode, SocketConnectionStatus, SocketError};
    use crate::vsock_socket::{VMADDR_CID_ANY, VMADDR_CID_HOST, VMADDR_PORT_ANY};
    use crate::wire::{
        MAX_ENCODED_ACTIVE_MESSAGE_SIZE, decode_handshake_request, decode_handshake_response,
        decode_request, decode_response, encode_request, encode_response,
    };
    use crate::{ObjectHandle, RequestId};

    const REQUEST_ID: RequestId = RequestId(0x0102_0304_0506_0708);
    const HANDLE: ObjectHandle = ObjectHandle(9);
    const HOST: VsockAddress = VsockAddress {
        cid: VMADDR_CID_HOST,
        port: 0x0102_0304,
    };

    fn buffer(length: u32) -> SharedBufferSequence {
        SharedBufferSequence::new(&[SharedBufferSlotIndex(3)], length).unwrap()
    }

    /// The largest sequence a request carries.
    fn largest_buffer() -> SharedBufferSequence {
        let slots: [SharedBufferSlotIndex; MAX_SHARED_BUFFER_SEQUENCE_SLOTS] =
            core::array::from_fn(|slot| {
                SharedBufferSlotIndex(u32::MAX - u32::try_from(slot).unwrap())
            });
        SharedBufferSequence::new(&slots, u32::MAX).unwrap()
    }

    fn requests() -> Vec<VsockSocketRequest> {
        Vec::from([
            VsockSocketRequest::Create(CreateVsockSocketRequest {
                flags: FileOpenFlags::NONBLOCKING,
            }),
            VsockSocketRequest::Bind(BindVsockSocketRequest {
                handle: HANDLE,
                address: VsockAddress {
                    cid: VMADDR_CID_ANY,
                    port: VMADDR_PORT_ANY,
                },
            }),
            VsockSocketRequest::Listen(ListenSocketRequest {
                handle: HANDLE,
                backlog: 128,
            }),
            VsockSocketRequest::Accept(AcceptSocketRequest {
                handle: HANDLE,
                flags: FileOpenFlags::NONE,
            }),
            VsockSocketRequest::Connect(ConnectVsockSocketRequest {
                handle: HANDLE,
                address: HOST,
            }),
            VsockSocketRequest::CheckConnect(CheckConnectSocketRequest { handle: HANDLE }),
            VsockSocketRequest::CancelConnect(CheckConnectSocketRequest { handle: HANDLE }),
            VsockSocketRequest::TakeError(TakeSocketErrorRequest { handle: HANDLE }),
            VsockSocketRequest::Send(SendSocketRequest {
                handle: HANDLE,
                buffer: buffer(5),
                flags: SendFlags::NONE,
            }),
            VsockSocketRequest::Receive(ReceiveVsockSocketRequest {
                handle: HANDLE,
                buffer: buffer(7),
            }),
            VsockSocketRequest::Shutdown(ShutdownSocketRequest {
                handle: HANDLE,
                mode: ShutdownMode::Write,
            }),
            VsockSocketRequest::GetName(GetSocketNameRequest {
                handle: HANDLE,
                peer: true,
            }),
            VsockSocketRequest::Send(SendSocketRequest {
                handle: HANDLE,
                buffer: largest_buffer(),
                flags: SendFlags::NONE,
            }),
            VsockSocketRequest::Receive(ReceiveVsockSocketRequest {
                handle: HANDLE,
                buffer: largest_buffer(),
            }),
        ])
    }

    fn responses() -> Vec<VsockSocketResponse> {
        Vec::from([
            VsockSocketResponse::Create(CreateSocketResponse { handle: HANDLE }),
            VsockSocketResponse::Bind,
            VsockSocketResponse::Listen,
            VsockSocketResponse::Accept(AcceptVsockSocketResponse {
                handle: HANDLE,
                remote_address: HOST,
            }),
            VsockSocketResponse::Connect(ConnectSocketResponse {
                status: SocketConnectionStatus::Connecting,
            }),
            VsockSocketResponse::CheckConnect(ConnectSocketResponse {
                status: SocketConnectionStatus::Connected,
            }),
            VsockSocketResponse::CancelConnect,
            VsockSocketResponse::TakeError(TakeSocketErrorResponse {
                error: Some(SocketError::TimedOut),
            }),
            VsockSocketResponse::Send(SendSocketResponse { sent: 5 }),
            VsockSocketResponse::Receive(ReceiveSocketResponse::Received(7)),
            VsockSocketResponse::Shutdown,
            VsockSocketResponse::GetName(GetVsockSocketNameResponse { address: None }),
            VsockSocketResponse::GetName(GetVsockSocketNameResponse {
                address: Some(HOST),
            }),
            VsockSocketResponse::Failed(SocketError::ConnectionReset),
        ])
    }

    fn encoded_request(request: VsockSocketRequest) -> Vec<u8> {
        encode_request(BrokerRequest {
            request_id: REQUEST_ID,
            operation: BrokerOperation::VsockSocket(request),
        })
    }

    fn encoded_response(response: VsockSocketResponse) -> Vec<u8> {
        encode_response(BrokerResponse {
            request_id: REQUEST_ID,
            result: BrokerResult::VsockSocket(response),
        })
    }

    #[test]
    fn requests_and_responses_round_trip_and_reject_every_truncation() {
        for request in requests() {
            let operation = BrokerOperation::VsockSocket(request.clone());
            let encoded = encoded_request(request.clone());
            assert!(encoded.len() <= MAX_ENCODED_ACTIVE_MESSAGE_SIZE);
            assert_eq!(
                decode_request(&encoded),
                Ok(BrokerRequest {
                    request_id: REQUEST_ID,
                    operation: operation.clone(),
                })
            );
            assert_eq!(
                decode_handshake_request(&encoded),
                Err(WireError::WrongMessagePhase)
            );
            for length in 0..encoded.len() {
                assert_eq!(
                    decode_request(&encoded[..length]),
                    Err(WireError::TruncatedFrame)
                );
            }
            let mut trailing = encoded;
            trailing.push(0);
            assert_eq!(decode_request(&trailing), Err(WireError::TrailingBytes));
            // Only transfers lease shared memory.
            let leases = operation.shared_buffer();
            match request {
                VsockSocketRequest::Send(SendSocketRequest { buffer, .. })
                | VsockSocketRequest::Receive(ReceiveVsockSocketRequest { buffer, .. }) => {
                    assert_eq!(leases, Some(buffer));
                }
                _ => assert_eq!(leases, None),
            }
        }
        for response in responses() {
            let encoded = encoded_response(response.clone());
            assert!(encoded.len() <= MAX_ENCODED_ACTIVE_MESSAGE_SIZE);
            assert_eq!(
                decode_response(&encoded),
                Ok(BrokerResponse {
                    request_id: REQUEST_ID,
                    result: BrokerResult::VsockSocket(response),
                })
            );
            assert_eq!(
                decode_handshake_response(&encoded),
                Err(WireError::WrongMessagePhase)
            );
            for length in 0..encoded.len() {
                assert_eq!(
                    decode_response(&encoded[..length]),
                    Err(WireError::TruncatedFrame)
                );
            }
            let mut trailing = encoded;
            trailing.push(0);
            assert_eq!(decode_response(&trailing), Err(WireError::TrailingBytes));
        }
    }

    #[test]
    fn wire_shapes_are_pinned() {
        assert_eq!(
            encoded_request(VsockSocketRequest::Connect(ConnectVsockSocketRequest {
                handle: HANDLE,
                address: HOST,
            })),
            [
                18, 8, 7, 6, 5, 4, 3, 2, 1, 4, 9, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 4, 3, 2, 1
            ]
        );
        assert_eq!(
            encoded_response(VsockSocketResponse::Accept(AcceptVsockSocketResponse {
                handle: HANDLE,
                remote_address: HOST,
            })),
            [
                18, 8, 7, 6, 5, 4, 3, 2, 1, 3, 9, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 4, 3, 2, 1
            ]
        );
        assert_eq!(
            encoded_response(VsockSocketResponse::Failed(SocketError::ConnectionReset)),
            [18, 8, 7, 6, 5, 4, 3, 2, 1, 12, 2]
        );
    }

    /// Replaces the last byte of `frame`, a value's tag, with `tag`.
    fn with_last_byte(mut frame: Vec<u8>, tag: u8) -> Vec<u8> {
        *frame.last_mut().unwrap() = tag;
        frame
    }

    #[test]
    fn decoding_rejects_unknown_tags_and_flags() {
        let unknown_request = with_last_byte(
            encoded_request(VsockSocketRequest::CheckConnect(
                CheckConnectSocketRequest { handle: HANDLE },
            ))[..10]
                .to_vec(),
            0xff,
        );
        assert_eq!(decode_request(&unknown_request), Err(WireError::InvalidTag));
        let unknown_response = with_last_byte(encoded_response(VsockSocketResponse::Bind), 13);
        assert_eq!(
            decode_response(&unknown_response),
            Err(WireError::InvalidTag)
        );

        // Status flags outside the defined bits are rejected, not masked.
        let frame = with_last_byte(
            encoded_request(VsockSocketRequest::Create(CreateVsockSocketRequest {
                flags: FileOpenFlags::NONE,
            })),
            0x80,
        );
        assert_eq!(decode_request(&frame), Err(WireError::InvalidTag));
        let frame = with_last_byte(
            encoded_response(VsockSocketResponse::GetName(GetVsockSocketNameResponse {
                address: None,
            })),
            2,
        );
        assert_eq!(decode_response(&frame), Err(WireError::InvalidTag));
    }
}
