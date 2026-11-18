// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use crate::vsock_socket::{VsockCid, VsockPort};

wire_newtype!(VsockCid: u32);
wire_newtype!(VsockPort: u32);

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use crate::fs::FileOpenFlags;
    use crate::message::{
        BrokerOperation, BrokerRequest, BrokerResponse, BrokerResult, VsockSocketRequest,
        VsockSocketResponse,
    };
    use crate::shared_buffer::{
        MAX_SHARED_BUFFER_SEQUENCE_SLOTS, SharedBufferSequence, SharedBufferSlotIndex,
    };
    use crate::socket::{
        AcceptSocketRequest, CheckConnectSocketRequest, ConnectSocketResponse,
        CreateSocketResponse, GetSocketNameRequest, ListenSocketRequest, ReceiveSocketResponse,
        SendFlags, SendSocketRequest, SendSocketResponse, ShutdownMode, ShutdownSocketRequest,
        SocketConnectionStatus, SocketError, SocketType, TakeSocketErrorRequest,
        TakeSocketErrorResponse,
    };
    use crate::vsock_socket::{
        AcceptVsockSocketResponse, BindVsockSocketRequest, ConnectVsockSocketRequest,
        CreateVsockSocketRequest, GetVsockSocketNameResponse, ReceiveVsockSocketRequest,
        VsockAddress, VsockCid, VsockPort,
    };
    use crate::wire::{
        MAX_ENCODED_ACTIVE_MESSAGE_SIZE, WireError, decode_handshake_request,
        decode_handshake_response, decode_request, decode_response, encode_request,
        encode_response,
    };
    use crate::{ObjectHandle, RequestId};

    const REQUEST_ID: RequestId = RequestId(0x0102_0304_0506_0708);
    const HANDLE: ObjectHandle = ObjectHandle(9);
    const HOST: VsockAddress = VsockAddress {
        cid: VsockCid::HOST,
        port: VsockPort(0x0102_0304),
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
                socket_type: SocketType::Stream,
                flags: FileOpenFlags::NONBLOCKING,
            }),
            VsockSocketRequest::Create(CreateVsockSocketRequest {
                socket_type: SocketType::SeqPacket,
                flags: FileOpenFlags::NONE,
            }),
            VsockSocketRequest::Bind(BindVsockSocketRequest {
                handle: HANDLE,
                address: VsockAddress {
                    cid: VsockCid::ANY,
                    port: VsockPort::ANY,
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
        encode_request(&BrokerRequest {
            request_id: REQUEST_ID,
            operation: BrokerOperation::VsockSocket(request),
        })
    }

    fn encoded_response(response: VsockSocketResponse) -> Vec<u8> {
        encode_response(&BrokerResponse {
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
            encoded_request(VsockSocketRequest::Create(CreateVsockSocketRequest {
                socket_type: SocketType::Stream,
                flags: FileOpenFlags::NONBLOCKING,
            })),
            [1, 8, 7, 6, 5, 4, 3, 2, 1, 17, 0, 0, 32, 0]
        );
        assert_eq!(
            encoded_request(VsockSocketRequest::Connect(ConnectVsockSocketRequest {
                handle: HANDLE,
                address: HOST,
            })),
            [
                1, 8, 7, 6, 5, 4, 3, 2, 1, 17, 4, 9, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 4, 3, 2, 1
            ]
        );
        assert_eq!(
            encoded_response(VsockSocketResponse::Accept(AcceptVsockSocketResponse {
                handle: HANDLE,
                remote_address: HOST,
            })),
            [
                1, 8, 7, 6, 5, 4, 3, 2, 1, 17, 3, 9, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 4, 3, 2, 1
            ]
        );
        assert_eq!(
            encoded_response(VsockSocketResponse::Failed(SocketError::ConnectionReset)),
            [1, 8, 7, 6, 5, 4, 3, 2, 1, 17, 12, 1]
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
            ))[..11]
                .to_vec(),
            0xff,
        );
        assert_eq!(decode_request(&unknown_request), Err(WireError::InvalidTag));
        let unknown_response = with_last_byte(encoded_response(VsockSocketResponse::Bind), 13);
        assert_eq!(
            decode_response(&unknown_response),
            Err(WireError::InvalidTag)
        );

        // Unknown socket types are rejected.
        let create = encoded_request(VsockSocketRequest::Create(CreateVsockSocketRequest {
            socket_type: SocketType::Stream,
            flags: FileOpenFlags::NONE,
        }));
        let frame = with_last_byte(create[..12].to_vec(), 0xff);
        assert_eq!(decode_request(&frame), Err(WireError::InvalidTag));
        // Status flags outside the defined bits are rejected, not masked.
        let frame = with_last_byte(create, 0x80);
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
