// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Typed broker-local adapters for broker requests and notifications.
//!
//! The local control adapter owns request/response sequencing but does not own a channel.
//! Userland, kernel, or ring-buffer deployments can provide channels by
//! implementing [`litebox_broker_protocol::channel::LocalControlChannel`].
//! Notification receive adapters are intentionally separate so active control
//! requests remain strictly paired with their responses.

#![no_std]

extern crate alloc;

#[cfg(test)]
extern crate std;

mod error;
mod event;
mod pipe;

use alloc::sync::Arc;

use litebox_broker_protocol::channel::{LocalControlChannel, LocalNotificationChannel};
use litebox_broker_protocol::error::ErrorCode;
use litebox_broker_protocol::message::{
    BrokerHandshakeRequest, BrokerHandshakeResponse, BrokerNotification, BrokerOperation,
    BrokerRequest, BrokerResponse, BrokerResult,
};
use litebox_broker_protocol::pipe::PIPE_TRANSFER_BUFFER_SIZE;
use litebox_broker_protocol::readiness::ReadinessFlags;
use litebox_broker_protocol::shared_memory::SharedMemory;
use litebox_broker_protocol::{BROKER_PROTOCOL_VERSION, ObjectHandle, RequestId};

pub use error::{BrokerLocalError, Result};

/// Typed broker-local control adapter for broker operations.
///
/// The shared memory belongs to the broker association and is reused for each
/// serialized pipe transfer.
pub struct BrokerLocal<Channel: LocalControlChannel> {
    channel: Channel,
    shared_memory: Arc<dyn SharedMemory>,
    next_request_id: u64,
}

/// Broker-local receive adapter for broker-initiated asynchronous notifications.
pub struct BrokerNotifications<Channel: LocalNotificationChannel> {
    channel: Channel,
}

impl<Channel: LocalControlChannel> BrokerLocal<Channel> {
    /// Negotiates the broker protocol, then establishes the association shared
    /// memory before active requests begin.
    ///
    /// # Panics
    ///
    /// Panics if the broker reports an unrecoverable error, returns a protocol
    /// response that does not match the negotiation request, or setup returns
    /// shared memory with an invalid size.
    pub fn negotiate(
        mut channel: Channel,
        receive_shared_memory: impl FnOnce(
            &mut Channel,
        ) -> core::result::Result<
            Arc<dyn SharedMemory>,
            Channel::Error,
        >,
    ) -> Result<Self, Channel::Error> {
        let requested = BROKER_PROTOCOL_VERSION;
        let request = BrokerHandshakeRequest {
            protocol_version: requested,
        };
        channel
            .send_handshake_request(&request)
            .map_err(BrokerLocalError::Channel)?;
        match channel
            .recv_handshake_response()
            .map_err(BrokerLocalError::Channel)?
            .ok_or(BrokerLocalError::ChannelClosed)?
        {
            response @ BrokerHandshakeResponse::Negotiated {
                broker_protocol_version,
            } => {
                assert_eq!(
                    requested, broker_protocol_version,
                    "broker returned unexpected negotiation response: {response:?}"
                );
                let shared_memory =
                    receive_shared_memory(&mut channel).map_err(BrokerLocalError::Channel)?;
                assert_eq!(
                    shared_memory.len(),
                    PIPE_TRANSFER_BUFFER_SIZE,
                    "broker association shared memory has an invalid size"
                );
                Ok(Self {
                    channel,
                    shared_memory,
                    next_request_id: 0,
                })
            }
            BrokerHandshakeResponse::VersionMismatch { .. } => {
                Err(BrokerLocalError::Broker(ErrorCode::UnsupportedVersion))
            }
            BrokerHandshakeResponse::Error(error) => match error {
                ErrorCode::UnsupportedVersion | ErrorCode::PolicyDenied => {
                    Err(BrokerLocalError::Broker(error))
                }
                ErrorCode::MalformedRequest
                | ErrorCode::ProtocolState
                | ErrorCode::UnsupportedOperation
                | ErrorCode::Internal => panic!("broker returned unrecoverable error: {error}"),
                _ => panic!("broker returned unexpected negotiation error: {error}"),
            },
        }
    }

    /// Sends one active broker request.
    ///
    /// # Panics
    ///
    /// Panics if the broker reports an unrecoverable error or returns a protocol
    /// response that does not match an active request.
    pub(crate) fn request(
        &mut self,
        operation: BrokerOperation,
    ) -> Result<BrokerResult, Channel::Error> {
        let request_id = RequestId(self.next_request_id);
        self.next_request_id = self
            .next_request_id
            .checked_add(1)
            .ok_or(BrokerLocalError::RequestIdExhausted)?;
        self.channel
            .send_request(&BrokerRequest {
                request_id,
                operation,
            })
            .map_err(BrokerLocalError::Channel)?;
        let BrokerResponse {
            request_id: response_id,
            result,
        } = self
            .channel
            .recv_response()
            .map_err(BrokerLocalError::Channel)?
            .ok_or(BrokerLocalError::ChannelClosed)?;
        if response_id != request_id {
            return Err(BrokerLocalError::UnexpectedResponseId {
                expected: request_id,
                actual: response_id,
            });
        }
        match result {
            BrokerResult::Error(error) => match error {
                ErrorCode::PolicyDenied
                | ErrorCode::UnknownObject
                | ErrorCode::InvalidRights
                | ErrorCode::ResourceExhausted
                | ErrorCode::WouldBlock
                | ErrorCode::PeerClosed
                | ErrorCode::OutOfMemory => Err(BrokerLocalError::Broker(error)),
                ErrorCode::UnsupportedVersion
                | ErrorCode::MalformedRequest
                | ErrorCode::ProtocolState
                | ErrorCode::UnsupportedOperation
                | ErrorCode::Internal => panic!("broker returned unrecoverable error: {error}"),
                _ => panic!("broker returned unsupported error: {error}"),
            },
            result @ (BrokerResult::Event(_)
            | BrokerResult::Pipe(_)
            | BrokerResult::ObjectClosed
            | BrokerResult::Readiness(_)) => Ok(result),
        }
    }

    /// Checks the current readiness of a broker-owned object.
    ///
    /// # Panics
    ///
    /// Panics if the broker reports an unrecoverable error or returns a
    /// response that does not match the issued readiness request.
    pub fn check_readiness(
        &mut self,
        handle: ObjectHandle,
    ) -> Result<ReadinessFlags, Channel::Error> {
        match self.request(BrokerOperation::CheckReadiness(handle))? {
            BrokerResult::Readiness(readiness) => Ok(readiness),
            BrokerResult::Error(error) => Err(BrokerLocalError::Broker(error)),
            response => panic!("broker returned unexpected readiness response: {response:?}"),
        }
    }

    /// Closes one broker object reference.
    ///
    /// # Panics
    ///
    /// Panics if the broker reports an unrecoverable error or returns a protocol
    /// response that does not match an object close request.
    pub fn close_object(&mut self, handle: ObjectHandle) -> Result<(), Channel::Error> {
        match self.request(BrokerOperation::CloseObject(handle))? {
            BrokerResult::ObjectClosed => Ok(()),
            BrokerResult::Error(error) => Err(BrokerLocalError::Broker(error)),
            response @ (BrokerResult::Event(_)
            | BrokerResult::Pipe(_)
            | BrokerResult::Readiness(_)) => {
                panic!("broker returned unexpected close response: {response:?}");
            }
        }
    }
}

impl<Channel: LocalNotificationChannel> BrokerNotifications<Channel> {
    /// Creates a notification receiver from an already-associated notification channel.
    pub const fn new(channel: Channel) -> Self {
        Self { channel }
    }

    /// Receives the next broker notification.
    ///
    /// Returns `Ok(None)` when the broker closed the notification channel cleanly.
    pub fn recv_notification(&mut self) -> Result<Option<BrokerNotification>, Channel::Error> {
        self.channel
            .recv_notification()
            .map_err(BrokerLocalError::Channel)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::cell::Cell;
    use core::convert::Infallible;
    use litebox_broker_protocol::ObjectHandle;
    use litebox_broker_protocol::ProtocolVersion;
    use litebox_broker_protocol::channel::LocalNotificationChannel;
    use litebox_broker_protocol::message::ReadinessNotification;
    use litebox_broker_protocol::readiness::ReadinessFlags;

    #[test]
    fn negotiate_runs_setup_after_response_before_active_requests() {
        let channel = FakeControlChannel::new(
            Some(BrokerHandshakeResponse::Negotiated {
                broker_protocol_version: BROKER_PROTOCOL_VERSION,
            }),
            None,
        );
        let setup_calls = Cell::new(0);
        let local = BrokerLocal::negotiate(channel, |channel| {
            assert!(channel.sent_handshake_request.is_some());
            assert!(channel.handshake_response.is_none());
            assert!(channel.sent_request.is_none());
            setup_calls.set(setup_calls.get() + 1);
            Ok(noop_shared_memory())
        })
        .unwrap();

        assert_eq!(
            local.channel.sent_handshake_request,
            Some(BrokerHandshakeRequest {
                protocol_version: BROKER_PROTOCOL_VERSION
            })
        );
        assert_eq!(setup_calls.get(), 1);
    }

    #[test]
    fn close_object_sends_close_object_request() {
        let handle = ObjectHandle(7);
        let request = BrokerOperation::CloseObject(handle);
        let response = BrokerResult::ObjectClosed;
        let channel = FakeControlChannel::new(None, Some(response.clone()));
        let mut local = BrokerLocal {
            channel,
            shared_memory: noop_shared_memory(),
            next_request_id: 0,
        };

        assert!(local.close_object(handle).is_ok());
        assert_eq!(
            local.channel.sent_request,
            Some(BrokerRequest {
                request_id: RequestId(0),
                operation: request,
            })
        );
    }

    #[test]
    fn active_requests_use_monotonic_identifiers() {
        let handle = ObjectHandle(7);
        let channel = FakeControlChannel::new(None, Some(BrokerResult::ObjectClosed));
        let mut local = BrokerLocal {
            channel,
            shared_memory: noop_shared_memory(),
            next_request_id: 0,
        };

        local.close_object(handle).unwrap();
        assert_eq!(
            local.channel.sent_request.as_ref().unwrap().request_id,
            RequestId(0)
        );

        local.channel.response = Some(BrokerResult::ObjectClosed);
        local.close_object(handle).unwrap();
        assert_eq!(
            local.channel.sent_request.as_ref().unwrap().request_id,
            RequestId(1)
        );
    }

    #[test]
    fn active_request_rejects_mismatched_response_identifier() {
        let channel = FakeControlChannel::new(None, Some(BrokerResult::ObjectClosed));
        let mut local = BrokerLocal {
            channel,
            shared_memory: noop_shared_memory(),
            next_request_id: 0,
        };
        local.channel.response_id = Some(RequestId(9));

        assert!(matches!(
            local.close_object(ObjectHandle(7)),
            Err(BrokerLocalError::UnexpectedResponseId {
                expected: RequestId(0),
                actual: RequestId(9),
            })
        ));
    }

    #[test]
    fn active_request_identifier_exhaustion_does_not_wrap() {
        let channel = FakeControlChannel::new(None, Some(BrokerResult::ObjectClosed));
        let mut local = BrokerLocal {
            channel,
            shared_memory: noop_shared_memory(),
            next_request_id: u64::MAX,
        };

        assert!(matches!(
            local.close_object(ObjectHandle(7)),
            Err(BrokerLocalError::RequestIdExhausted)
        ));
        assert!(local.channel.sent_request.is_none());
    }

    #[test]
    fn active_request_returns_recoverable_broker_error() {
        let channel =
            FakeControlChannel::new(None, Some(BrokerResult::Error(ErrorCode::WouldBlock)));
        let mut local = BrokerLocal {
            channel,
            shared_memory: noop_shared_memory(),
            next_request_id: 0,
        };

        assert!(matches!(
            local.create_event_with_count(0),
            Err(BrokerLocalError::Broker(ErrorCode::WouldBlock))
        ));
    }

    #[test]
    #[should_panic(expected = "broker returned unrecoverable error")]
    fn active_request_panics_on_unrecoverable_broker_error() {
        let channel = FakeControlChannel::new(None, Some(BrokerResult::Error(ErrorCode::Internal)));
        let mut local = BrokerLocal {
            channel,
            shared_memory: noop_shared_memory(),
            next_request_id: 0,
        };

        let _ = local.create_event_with_count(0);
    }

    #[test]
    fn negotiate_rejects_broker_different_version_without_setup() {
        let broker_protocol_version = ProtocolVersion(BROKER_PROTOCOL_VERSION.0 + 1);
        let channel = FakeControlChannel::new(
            Some(BrokerHandshakeResponse::Negotiated {
                broker_protocol_version,
            }),
            None,
        );
        let setup_called = Cell::new(false);

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = BrokerLocal::negotiate(channel, |_| {
                setup_called.set(true);
                Ok(noop_shared_memory())
            });
        }));
        assert_panic_contains(result, "broker returned unexpected negotiation response");
        assert!(!setup_called.get());
    }

    #[test]
    fn notification_receiver_returns_broker_notifications() {
        let notification = BrokerNotification::Readiness(ReadinessNotification {
            handle: ObjectHandle(7),
            readiness: ReadinessFlags::READ,
        });
        let mut receiver = BrokerNotifications::new(FakeNotificationChannel {
            notification: Some(notification.clone()),
        });

        assert_eq!(receiver.recv_notification().unwrap(), Some(notification));
        assert_eq!(receiver.recv_notification().unwrap(), None);
    }

    #[test]
    fn negotiate_rejects_broker_unsupported_version_response() {
        let broker_protocol_version = ProtocolVersion(BROKER_PROTOCOL_VERSION.0 + 1);
        let channel = FakeControlChannel::new(
            Some(BrokerHandshakeResponse::VersionMismatch {
                broker_protocol_version,
            }),
            None,
        );

        let setup_called = Cell::new(false);
        assert!(matches!(
            BrokerLocal::negotiate(channel, |_| {
                setup_called.set(true);
                Ok(noop_shared_memory())
            }),
            Err(BrokerLocalError::Broker(ErrorCode::UnsupportedVersion))
        ));
        assert!(!setup_called.get());
    }

    #[test]
    fn negotiate_skips_setup_before_panicking_on_unrecoverable_broker_error() {
        let channel = FakeControlChannel::new(
            Some(BrokerHandshakeResponse::Error(ErrorCode::Internal)),
            None,
        );
        let setup_called = Cell::new(false);

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = BrokerLocal::negotiate(channel, |_| {
                setup_called.set(true);
                Ok(noop_shared_memory())
            });
        }));
        assert_panic_contains(result, "broker returned unrecoverable error");
        assert!(!setup_called.get());
    }

    #[test]
    fn negotiate_propagates_shared_memory_receive_error() {
        let channel = FakeControlChannel::new(
            Some(BrokerHandshakeResponse::Negotiated {
                broker_protocol_version: BROKER_PROTOCOL_VERSION,
            }),
            None,
        );

        assert!(matches!(
            BrokerLocal::negotiate(channel, |_| Err(FakeChannelError::SharedMemoryReceive)),
            Err(BrokerLocalError::Channel(
                FakeChannelError::SharedMemoryReceive
            ))
        ));
    }

    #[test]
    #[should_panic(expected = "broker association shared memory has an invalid size")]
    fn negotiate_rejects_invalid_shared_memory_size() {
        let channel = FakeControlChannel::new(
            Some(BrokerHandshakeResponse::Negotiated {
                broker_protocol_version: BROKER_PROTOCOL_VERSION,
            }),
            None,
        );

        let _ = BrokerLocal::negotiate(channel, |_| {
            Ok(Arc::new(NoopSharedMemory {
                length: PIPE_TRANSFER_BUFFER_SIZE - 1,
            }) as Arc<dyn SharedMemory>)
        });
    }

    fn assert_panic_contains(result: std::thread::Result<()>, expected: &str) {
        let panic = result.expect_err("operation did not panic");
        let message = if let Some(message) = panic.downcast_ref::<&str>() {
            *message
        } else if let Some(message) = panic.downcast_ref::<std::string::String>() {
            message.as_str()
        } else {
            panic!("unexpected panic payload");
        };
        assert!(
            message.contains(expected),
            "panic message did not contain {expected:?}: {message}"
        );
    }

    struct FakeControlChannel {
        sent_handshake_request: Option<BrokerHandshakeRequest>,
        sent_request: Option<BrokerRequest>,
        handshake_response: Option<BrokerHandshakeResponse>,
        response: Option<BrokerResult>,
        response_id: Option<RequestId>,
    }

    #[derive(Debug, PartialEq, Eq)]
    enum FakeChannelError {
        SharedMemoryReceive,
    }

    struct NoopSharedMemory {
        length: usize,
    }

    impl SharedMemory for NoopSharedMemory {
        fn len(&self) -> usize {
            self.length
        }

        fn read(
            &self,
            _offset: usize,
            destination: &mut [u8],
        ) -> core::result::Result<(), litebox_broker_protocol::shared_memory::SharedMemoryError>
        {
            destination.fill(0);
            Ok(())
        }

        fn write(
            &self,
            _offset: usize,
            _source: &[u8],
        ) -> core::result::Result<(), litebox_broker_protocol::shared_memory::SharedMemoryError>
        {
            Ok(())
        }
    }

    fn noop_shared_memory() -> Arc<dyn SharedMemory> {
        Arc::new(NoopSharedMemory {
            length: PIPE_TRANSFER_BUFFER_SIZE,
        })
    }

    impl FakeControlChannel {
        const fn new(
            handshake_response: Option<BrokerHandshakeResponse>,
            response: Option<BrokerResult>,
        ) -> Self {
            Self {
                sent_handshake_request: None,
                sent_request: None,
                handshake_response,
                response,
                response_id: None,
            }
        }
    }

    impl LocalControlChannel for FakeControlChannel {
        type Error = FakeChannelError;

        fn send_handshake_request(
            &mut self,
            request: &BrokerHandshakeRequest,
        ) -> core::result::Result<(), Self::Error> {
            self.sent_handshake_request = Some(request.clone());
            Ok(())
        }

        fn recv_handshake_response(
            &mut self,
        ) -> core::result::Result<Option<BrokerHandshakeResponse>, Self::Error> {
            Ok(self.handshake_response.take())
        }

        fn send_request(
            &mut self,
            request: &BrokerRequest,
        ) -> core::result::Result<(), Self::Error> {
            self.sent_request = Some(request.clone());
            Ok(())
        }

        fn recv_response(&mut self) -> core::result::Result<Option<BrokerResponse>, Self::Error> {
            Ok(self.response.take().map(|result| BrokerResponse {
                request_id: self.response_id.unwrap_or_else(|| {
                    self.sent_request
                        .as_ref()
                        .expect("response requires a sent request")
                        .request_id
                }),
                result,
            }))
        }
    }

    struct FakeNotificationChannel {
        notification: Option<BrokerNotification>,
    }

    impl LocalNotificationChannel for FakeNotificationChannel {
        type Error = Infallible;

        fn recv_notification(
            &mut self,
        ) -> core::result::Result<Option<BrokerNotification>, Self::Error> {
            Ok(self.notification.take())
        }
    }
}
