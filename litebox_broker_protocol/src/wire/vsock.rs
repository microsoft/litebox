// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use crate::message::{VsockRequest, VsockResponse};
use crate::socket::{
    AcceptSocketRequest, CheckConnectSocketRequest, ConnectSocketResponse, CreateSocketResponse,
    GetSocketNameRequest, ListenSocketRequest, ReceiveFlags, SendFlags, SendSocketRequest,
    SendSocketResponse, ShutdownSocketRequest, TakeSocketErrorRequest, TakeSocketErrorResponse,
};
use crate::vsock::{
    AcceptVsockSocketResponse, BindVsockSocketRequest, CancelVsockConnectRequest,
    ConnectVsockSocketRequest, CreateVsockSocketRequest, GetVsockSocketNameResponse,
    ReceiveVsockSocketRequest, VsockAddress,
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

const VSOCK_TAG_CREATE: u8 = 0;
const VSOCK_TAG_BIND: u8 = 1;
const VSOCK_TAG_LISTEN: u8 = 2;
const VSOCK_TAG_ACCEPT: u8 = 3;
const VSOCK_TAG_CONNECT: u8 = 4;
const VSOCK_TAG_CHECK_CONNECT: u8 = 5;
const VSOCK_TAG_CANCEL_CONNECT: u8 = 6;
const VSOCK_TAG_TAKE_ERROR: u8 = 7;
const VSOCK_TAG_SEND: u8 = 8;
const VSOCK_TAG_RECEIVE: u8 = 9;
const VSOCK_TAG_SHUTDOWN: u8 = 10;
const VSOCK_TAG_GET_NAME: u8 = 11;
const VSOCK_TAG_FAILED: u8 = 12;

pub(super) fn encode_vsock_request(encoder: &mut Encoder, request: VsockRequest) {
    match request {
        VsockRequest::Create(request) => {
            encoder.u8(VSOCK_TAG_CREATE);
            encoder.u16(request.flags.bits());
        }
        VsockRequest::Bind(request) => {
            encoder.u8(VSOCK_TAG_BIND);
            encoder.handle(request.handle);
            encode_address(encoder, request.address);
        }
        VsockRequest::Listen(request) => {
            encoder.u8(VSOCK_TAG_LISTEN);
            encoder.handle(request.handle);
            encoder.u32(request.backlog);
        }
        VsockRequest::Accept(request) => {
            encoder.u8(VSOCK_TAG_ACCEPT);
            encoder.handle(request.handle);
            encoder.u16(request.flags.bits());
        }
        VsockRequest::Connect(request) => {
            encoder.u8(VSOCK_TAG_CONNECT);
            encoder.handle(request.handle);
            encode_address(encoder, request.address);
        }
        VsockRequest::CheckConnect(request) => {
            encoder.u8(VSOCK_TAG_CHECK_CONNECT);
            encoder.handle(request.handle);
        }
        VsockRequest::CancelConnect(request) => {
            encoder.u8(VSOCK_TAG_CANCEL_CONNECT);
            encoder.handle(request.handle);
        }
        VsockRequest::TakeError(request) => {
            encoder.u8(VSOCK_TAG_TAKE_ERROR);
            encoder.handle(request.handle);
        }
        VsockRequest::Send(request) => {
            encoder.u8(VSOCK_TAG_SEND);
            encoder.handle(request.handle);
            encoder.shared_buffer_sequence(request.buffer);
            encoder.u32(request.flags.0);
        }
        VsockRequest::Receive(request) => {
            encoder.u8(VSOCK_TAG_RECEIVE);
            encoder.handle(request.handle);
            encoder.shared_buffer_sequence(request.buffer);
            encoder.u32(request.flags.0);
        }
        VsockRequest::Shutdown(request) => {
            encoder.u8(VSOCK_TAG_SHUTDOWN);
            encoder.handle(request.handle);
            encode_shutdown_mode(encoder, request.mode);
        }
        VsockRequest::GetName(request) => {
            encoder.u8(VSOCK_TAG_GET_NAME);
            encoder.handle(request.handle);
            encode_bool(encoder, request.peer);
        }
    }
}

pub(super) fn decode_vsock_request(decoder: &mut Decoder<'_>) -> Result<VsockRequest, WireError> {
    Ok(match decoder.u8()? {
        VSOCK_TAG_CREATE => VsockRequest::Create(CreateVsockSocketRequest {
            flags: decode_open_flags(decoder)?,
        }),
        VSOCK_TAG_BIND => VsockRequest::Bind(BindVsockSocketRequest {
            handle: decoder.handle()?,
            address: decode_address(decoder)?,
        }),
        VSOCK_TAG_LISTEN => VsockRequest::Listen(ListenSocketRequest {
            handle: decoder.handle()?,
            backlog: decoder.u32()?,
        }),
        VSOCK_TAG_ACCEPT => VsockRequest::Accept(AcceptSocketRequest {
            handle: decoder.handle()?,
            flags: decode_open_flags(decoder)?,
        }),
        VSOCK_TAG_CONNECT => VsockRequest::Connect(ConnectVsockSocketRequest {
            handle: decoder.handle()?,
            address: decode_address(decoder)?,
        }),
        VSOCK_TAG_CHECK_CONNECT => VsockRequest::CheckConnect(CheckConnectSocketRequest {
            handle: decoder.handle()?,
        }),
        VSOCK_TAG_CANCEL_CONNECT => VsockRequest::CancelConnect(CancelVsockConnectRequest {
            handle: decoder.handle()?,
        }),
        VSOCK_TAG_TAKE_ERROR => VsockRequest::TakeError(TakeSocketErrorRequest {
            handle: decoder.handle()?,
        }),
        VSOCK_TAG_SEND => VsockRequest::Send(SendSocketRequest {
            handle: decoder.handle()?,
            buffer: decoder.shared_buffer_sequence()?,
            flags: SendFlags(decoder.u32()?),
        }),
        VSOCK_TAG_RECEIVE => VsockRequest::Receive(ReceiveVsockSocketRequest {
            handle: decoder.handle()?,
            buffer: decoder.shared_buffer_sequence()?,
            flags: ReceiveFlags(decoder.u32()?),
        }),
        VSOCK_TAG_SHUTDOWN => VsockRequest::Shutdown(ShutdownSocketRequest {
            handle: decoder.handle()?,
            mode: decode_shutdown_mode(decoder)?,
        }),
        VSOCK_TAG_GET_NAME => VsockRequest::GetName(GetSocketNameRequest {
            handle: decoder.handle()?,
            peer: decode_bool(decoder)?,
        }),
        _ => return Err(WireError::InvalidTag),
    })
}

pub(super) fn encode_vsock_response(encoder: &mut Encoder, response: VsockResponse) {
    match response {
        VsockResponse::Create(response) => {
            encoder.u8(VSOCK_TAG_CREATE);
            encoder.handle(response.handle);
        }
        VsockResponse::Bind => encoder.u8(VSOCK_TAG_BIND),
        VsockResponse::Listen => encoder.u8(VSOCK_TAG_LISTEN),
        VsockResponse::Accept(response) => {
            encoder.u8(VSOCK_TAG_ACCEPT);
            encoder.handle(response.handle);
            encode_address(encoder, response.peer_address);
        }
        VsockResponse::Connect(response) => {
            encoder.u8(VSOCK_TAG_CONNECT);
            encode_connection_status(encoder, response.status);
        }
        VsockResponse::CheckConnect(response) => {
            encoder.u8(VSOCK_TAG_CHECK_CONNECT);
            encode_connection_status(encoder, response.status);
        }
        VsockResponse::CancelConnect => encoder.u8(VSOCK_TAG_CANCEL_CONNECT),
        VsockResponse::TakeError(response) => {
            encoder.u8(VSOCK_TAG_TAKE_ERROR);
            encode_optional_socket_error(encoder, response.error);
        }
        VsockResponse::Send(response) => {
            encoder.u8(VSOCK_TAG_SEND);
            encoder.u32(response.sent);
        }
        VsockResponse::Receive(response) => {
            encoder.u8(VSOCK_TAG_RECEIVE);
            encode_receive_response(encoder, response);
        }
        VsockResponse::Shutdown => encoder.u8(VSOCK_TAG_SHUTDOWN),
        VsockResponse::GetName(response) => {
            encoder.u8(VSOCK_TAG_GET_NAME);
            encode_bool(encoder, response.address.is_some());
            if let Some(address) = response.address {
                encode_address(encoder, address);
            }
        }
        VsockResponse::Failed(error) => {
            encoder.u8(VSOCK_TAG_FAILED);
            encode_socket_error(encoder, error);
        }
    }
}

pub(super) fn decode_vsock_response(decoder: &mut Decoder<'_>) -> Result<VsockResponse, WireError> {
    Ok(match decoder.u8()? {
        VSOCK_TAG_CREATE => VsockResponse::Create(CreateSocketResponse {
            handle: decoder.handle()?,
        }),
        VSOCK_TAG_BIND => VsockResponse::Bind,
        VSOCK_TAG_LISTEN => VsockResponse::Listen,
        VSOCK_TAG_ACCEPT => VsockResponse::Accept(AcceptVsockSocketResponse {
            handle: decoder.handle()?,
            peer_address: decode_address(decoder)?,
        }),
        VSOCK_TAG_CONNECT => VsockResponse::Connect(ConnectSocketResponse {
            status: decode_connection_status(decoder)?,
        }),
        VSOCK_TAG_CHECK_CONNECT => VsockResponse::CheckConnect(ConnectSocketResponse {
            status: decode_connection_status(decoder)?,
        }),
        VSOCK_TAG_CANCEL_CONNECT => VsockResponse::CancelConnect,
        VSOCK_TAG_TAKE_ERROR => VsockResponse::TakeError(TakeSocketErrorResponse {
            error: decode_optional_socket_error(decoder)?,
        }),
        VSOCK_TAG_SEND => VsockResponse::Send(SendSocketResponse {
            sent: decoder.u32()?,
        }),
        VSOCK_TAG_RECEIVE => VsockResponse::Receive(decode_receive_response(decoder)?),
        VSOCK_TAG_SHUTDOWN => VsockResponse::Shutdown,
        VSOCK_TAG_GET_NAME => VsockResponse::GetName(GetVsockSocketNameResponse {
            address: if decode_bool(decoder)? {
                Some(decode_address(decoder)?)
            } else {
                None
            },
        }),
        VSOCK_TAG_FAILED => VsockResponse::Failed(decode_socket_error(decoder)?),
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
    use crate::shared_buffer::{SharedBufferSequence, SharedBufferSlotIndex};
    use crate::socket::{ReceiveSocketResponse, ShutdownMode, SocketConnectionStatus, SocketError};
    use crate::vsock::{VMADDR_CID_ANY, VMADDR_CID_HOST, VMADDR_PORT_ANY};
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

    fn requests() -> Vec<VsockRequest> {
        Vec::from([
            VsockRequest::Create(CreateVsockSocketRequest {
                flags: FileOpenFlags::NONBLOCKING,
            }),
            VsockRequest::Bind(BindVsockSocketRequest {
                handle: HANDLE,
                address: VsockAddress {
                    cid: VMADDR_CID_ANY,
                    port: VMADDR_PORT_ANY,
                },
            }),
            VsockRequest::Listen(ListenSocketRequest {
                handle: HANDLE,
                backlog: 128,
            }),
            VsockRequest::Accept(AcceptSocketRequest {
                handle: HANDLE,
                flags: FileOpenFlags::NONE,
            }),
            VsockRequest::Connect(ConnectVsockSocketRequest {
                handle: HANDLE,
                address: HOST,
            }),
            VsockRequest::CheckConnect(CheckConnectSocketRequest { handle: HANDLE }),
            VsockRequest::CancelConnect(CancelVsockConnectRequest { handle: HANDLE }),
            VsockRequest::TakeError(TakeSocketErrorRequest { handle: HANDLE }),
            VsockRequest::Send(SendSocketRequest {
                handle: HANDLE,
                buffer: buffer(5),
                flags: SendFlags::NONE,
            }),
            VsockRequest::Receive(ReceiveVsockSocketRequest {
                handle: HANDLE,
                buffer: buffer(7),
                flags: ReceiveFlags::NONE,
            }),
            VsockRequest::Shutdown(ShutdownSocketRequest {
                handle: HANDLE,
                mode: ShutdownMode::Write,
            }),
            VsockRequest::GetName(GetSocketNameRequest {
                handle: HANDLE,
                peer: true,
            }),
        ])
    }

    fn responses() -> Vec<VsockResponse> {
        Vec::from([
            VsockResponse::Create(CreateSocketResponse { handle: HANDLE }),
            VsockResponse::Bind,
            VsockResponse::Listen,
            VsockResponse::Accept(AcceptVsockSocketResponse {
                handle: HANDLE,
                peer_address: HOST,
            }),
            VsockResponse::Connect(ConnectSocketResponse {
                status: SocketConnectionStatus::Connecting,
            }),
            VsockResponse::CheckConnect(ConnectSocketResponse {
                status: SocketConnectionStatus::Unconnected,
            }),
            VsockResponse::CheckConnect(ConnectSocketResponse {
                status: SocketConnectionStatus::Connected,
            }),
            VsockResponse::CancelConnect,
            VsockResponse::TakeError(TakeSocketErrorResponse { error: None }),
            VsockResponse::TakeError(TakeSocketErrorResponse {
                error: Some(SocketError::TimedOut),
            }),
            VsockResponse::Send(SendSocketResponse { sent: 5 }),
            VsockResponse::Receive(ReceiveSocketResponse::Received(7)),
            VsockResponse::Receive(ReceiveSocketResponse::EndOfStream),
            VsockResponse::Shutdown,
            VsockResponse::GetName(GetVsockSocketNameResponse { address: None }),
            VsockResponse::GetName(GetVsockSocketNameResponse {
                address: Some(HOST),
            }),
            VsockResponse::Failed(SocketError::ConnectionReset),
        ])
    }

    fn encoded_request(request: VsockRequest) -> Vec<u8> {
        encode_request(BrokerRequest {
            request_id: REQUEST_ID,
            operation: BrokerOperation::Vsock(request),
        })
    }

    fn encoded_response(response: VsockResponse) -> Vec<u8> {
        encode_response(BrokerResponse {
            request_id: REQUEST_ID,
            result: BrokerResult::Vsock(response),
        })
    }

    #[test]
    fn requests_and_responses_round_trip_and_reject_every_truncation() {
        for request in requests() {
            let operation = BrokerOperation::Vsock(request.clone());
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
                VsockRequest::Send(SendSocketRequest { buffer, .. })
                | VsockRequest::Receive(ReceiveVsockSocketRequest { buffer, .. }) => {
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
                    result: BrokerResult::Vsock(response),
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
            encoded_request(VsockRequest::Connect(ConnectVsockSocketRequest {
                handle: HANDLE,
                address: HOST,
            })),
            [
                18, 8, 7, 6, 5, 4, 3, 2, 1, 4, 9, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 4, 3, 2, 1
            ]
        );
        assert_eq!(
            encoded_response(VsockResponse::Accept(AcceptVsockSocketResponse {
                handle: HANDLE,
                peer_address: HOST,
            })),
            [
                18, 8, 7, 6, 5, 4, 3, 2, 1, 3, 9, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 4, 3, 2, 1
            ]
        );
        assert_eq!(
            encoded_response(VsockResponse::Failed(SocketError::ConnectionReset)),
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
            encoded_request(VsockRequest::CheckConnect(CheckConnectSocketRequest {
                handle: HANDLE,
            }))[..10]
                .to_vec(),
            0xff,
        );
        assert_eq!(decode_request(&unknown_request), Err(WireError::InvalidTag));
        let unknown_response = with_last_byte(encoded_response(VsockResponse::Bind), 13);
        assert_eq!(
            decode_response(&unknown_response),
            Err(WireError::InvalidTag)
        );

        // Status flags outside the defined bits are rejected, not masked.
        for request in [
            VsockRequest::Create(CreateVsockSocketRequest {
                flags: FileOpenFlags::NONE,
            }),
            VsockRequest::Accept(AcceptSocketRequest {
                handle: HANDLE,
                flags: FileOpenFlags::NONE,
            }),
        ] {
            let frame = with_last_byte(encoded_request(request), 0x80);
            assert_eq!(decode_request(&frame), Err(WireError::InvalidTag));
        }
        let frame = with_last_byte(
            encoded_request(VsockRequest::Shutdown(ShutdownSocketRequest {
                handle: HANDLE,
                mode: ShutdownMode::Both,
            })),
            0xff,
        );
        assert_eq!(decode_request(&frame), Err(WireError::InvalidTag));
        let frame = with_last_byte(
            encoded_request(VsockRequest::GetName(GetSocketNameRequest {
                handle: HANDLE,
                peer: false,
            })),
            2,
        );
        assert_eq!(decode_request(&frame), Err(WireError::InvalidTag));

        for frame in [
            with_last_byte(
                encoded_response(VsockResponse::Connect(ConnectSocketResponse {
                    status: SocketConnectionStatus::Connected,
                })),
                0xff,
            ),
            with_last_byte(
                encoded_response(VsockResponse::TakeError(TakeSocketErrorResponse {
                    error: None,
                })),
                2,
            ),
            with_last_byte(
                encoded_response(VsockResponse::Receive(ReceiveSocketResponse::EndOfStream)),
                2,
            ),
            with_last_byte(
                encoded_response(VsockResponse::GetName(GetVsockSocketNameResponse {
                    address: None,
                })),
                2,
            ),
            with_last_byte(
                encoded_response(VsockResponse::Failed(SocketError::Other)),
                0,
            ),
        ] {
            assert_eq!(decode_response(&frame), Err(WireError::InvalidTag));
        }
    }
}
