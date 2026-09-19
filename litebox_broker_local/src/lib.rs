// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Portable local endpoint for broker associations.
//!
//! This crate is the in-sandbox counterpart to `litebox_broker_host`. It
//! negotiates an association, turns typed object operations into broker
//! requests, manages access to the association's shared buffers, assigns request
//! identifiers, and verifies that responses are correctly correlated. A
//! separate notification adapter receives broker-to-local readiness updates.
//!
//! The endpoint is channel-neutral. Deployments provide local channels through
//! `litebox_broker_transport`; concrete bindings such as
//! `litebox_broker_transport_linux_userland` decide how messages move.

#![no_std]

extern crate alloc;

#[cfg(test)]
extern crate std;

mod error;
mod event;
mod fs;
mod pipe;
mod process;
mod random;
mod socket;
mod stdio;

#[cfg(any(test, feature = "test-support"))]
pub mod test_support;

use alloc::{sync::Arc, vec::Vec};
use core::sync::atomic::{AtomicU64, Ordering};

use litebox_broker_protocol::error::ErrorCode;
use litebox_broker_protocol::message::{
    BrokerHandshakeRequest, BrokerHandshakeResponse, BrokerNotification, BrokerOperation,
    BrokerRequest, BrokerResponse, BrokerResult,
};
use litebox_broker_protocol::process::ProcessStartupData;
use litebox_broker_protocol::readiness::ReadinessFlags;
use litebox_broker_protocol::shared_buffer::{SHARED_BUFFER_LAYOUT, SharedBufferSequence};
use litebox_broker_protocol::{
    BROKER_PROTOCOL_VERSION, ObjectHandle, ProcessId, RequestId, ThreadId,
};
use litebox_broker_transport::channel::{
    LocalCallChannel, LocalNotificationChannel, LocalSetupChannel,
};
use litebox_broker_transport::shared_memory::{SharedBufferPool, SharedMemory};

pub use error::{BrokerLocalError, Result};

/// Typed broker-local control adapter for broker operations.
///
/// The shared-buffer pool belongs to the broker association. Payload request
/// sequences identify operation-scoped slots managed by the caller.
pub struct BrokerLocal<Channel: LocalCallChannel> {
    channel: Channel,
    process_id: ProcessId,
    initial_thread_id: ThreadId,
    shared_buffers: SharedBufferPool<Arc<dyn SharedMemory>>,
    next_request_id: AtomicU64,
}

/// Broker-local receive adapter for broker-initiated asynchronous notifications.
pub struct BrokerNotifications<Channel: LocalNotificationChannel> {
    channel: Channel,
}

impl<Channel: LocalCallChannel> BrokerLocal<Channel> {
    fn new(
        channel: Channel,
        process_id: ProcessId,
        initial_thread_id: ThreadId,
        shared_memory: Arc<dyn SharedMemory>,
    ) -> Self {
        let shared_buffers = SharedBufferPool::new(shared_memory, SHARED_BUFFER_LAYOUT)
            .expect("broker association shared memory has an invalid size");
        Self {
            channel,
            process_id,
            initial_thread_id,
            shared_buffers,
            next_request_id: AtomicU64::new(0),
        }
    }

    /// Negotiates the broker protocol on `setup`, then consumes it into the
    /// active call channel and association shared memory before active requests
    /// begin.
    ///
    /// `activate` owns every deployment-specific setup step that must complete
    /// after negotiation, such as receiving shared memory and starting the
    /// active transport. Any additional endpoints activation produces, such as
    /// a notification receiver, are returned to the caller as `Activated`.
    /// Child startup data is copied from the negotiated shared-buffer pool and
    /// returned when present.
    ///
    /// # Panics
    ///
    /// Panics if the broker reports an unrecoverable error, returns a protocol
    /// response that does not match the negotiation request, or setup returns
    /// shared memory with an invalid size.
    pub fn negotiate<Setup: LocalSetupChannel<Error = Channel::Error>, Activated>(
        mut setup: Setup,
        activate: impl FnOnce(
            Setup,
        ) -> core::result::Result<
            (Channel, Arc<dyn SharedMemory>, Activated),
            Channel::Error,
        >,
    ) -> Result<(Self, Option<ProcessStartupData>, Activated), Channel::Error> {
        let requested = BROKER_PROTOCOL_VERSION;
        let request = BrokerHandshakeRequest {
            protocol_version: requested,
        };
        setup
            .send_handshake_request(&request)
            .map_err(BrokerLocalError::Channel)?;
        match setup
            .recv_handshake_response()
            .map_err(BrokerLocalError::Channel)?
            .ok_or(BrokerLocalError::ChannelClosed)?
        {
            response @ BrokerHandshakeResponse::Negotiated {
                broker_protocol_version,
                process_id,
                initial_thread_id,
                startup,
            } => {
                assert_eq!(
                    requested, broker_protocol_version,
                    "broker returned unexpected negotiation response: {response:?}"
                );
                let (channel, shared_memory, activated) =
                    activate(setup).map_err(BrokerLocalError::Channel)?;
                let local = Self::new(channel, process_id, initial_thread_id, shared_memory);
                let startup = match startup {
                    Some(startup) => {
                        let mut payload = Vec::new();
                        payload
                            .try_reserve_exact(startup.buffer.length() as usize)
                            .map_err(|_| BrokerLocalError::Broker(ErrorCode::OutOfMemory))?;
                        payload.resize(startup.buffer.length() as usize, 0);
                        local.read_shared_buffer(startup.buffer, &mut payload);
                        Some(ProcessStartupData {
                            format: startup.format,
                            version: startup.version,
                            payload,
                            inherited_objects: startup.inherited_objects,
                        })
                    }
                    None => None,
                };
                Ok((local, startup, activated))
            }
            BrokerHandshakeResponse::VersionMismatch { .. } => {
                Err(BrokerLocalError::Broker(ErrorCode::UnsupportedVersion))
            }
            BrokerHandshakeResponse::Error(error) => match error {
                ErrorCode::UnsupportedVersion
                | ErrorCode::PolicyDenied
                | ErrorCode::ResourceExhausted
                | ErrorCode::OutOfMemory => Err(BrokerLocalError::Broker(error)),
                ErrorCode::MalformedRequest
                | ErrorCode::ProtocolState
                | ErrorCode::UnsupportedOperation
                | ErrorCode::Internal => panic!("broker returned unrecoverable error: {error}"),
                _ => panic!("broker returned unexpected negotiation error: {error}"),
            },
        }
    }

    /// Returns the assigned process ID.
    #[must_use]
    pub const fn process_id(&self) -> ProcessId {
        self.process_id
    }

    /// Returns the broker-assigned initial thread ID.
    #[must_use]
    pub const fn initial_thread_id(&self) -> ThreadId {
        self.initial_thread_id
    }

    /// Creates a broker thread belonging to this process.
    ///
    /// # Panics
    ///
    /// Panics if the broker returns a response for a different operation.
    pub fn create_thread(&self) -> Result<ThreadId, Channel::Error> {
        match self.request(BrokerOperation::CreateThread)? {
            BrokerResult::ThreadCreated(thread_id) => Ok(thread_id),
            BrokerResult::Error(error) => Err(BrokerLocalError::Broker(error)),
            response => panic!("broker returned unexpected create-thread response: {response:?}"),
        }
    }

    /// Records broker thread exit after local teardown completes.
    ///
    /// # Panics
    ///
    /// Panics if the broker returns a response for a different operation.
    pub fn exit_thread(&self, thread_id: ThreadId) -> Result<(), Channel::Error> {
        match self.request(BrokerOperation::ExitThread(thread_id))? {
            BrokerResult::ThreadExited => Ok(()),
            BrokerResult::Error(error) => Err(BrokerLocalError::Broker(error)),
            response => {
                panic!("broker returned unexpected exit-thread response: {response:?}")
            }
        }
    }

    /// Sends one active broker request.
    ///
    /// # Panics
    ///
    /// Panics if the broker reports an unrecoverable error or returns a protocol
    /// response that does not match an active request.
    pub(crate) fn request(
        &self,
        operation: BrokerOperation,
    ) -> Result<BrokerResult, Channel::Error> {
        let request_id = self
            .next_request_id
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |request_id| {
                request_id.checked_add(1)
            })
            .map(RequestId)
            .map_err(|_| BrokerLocalError::RequestIdExhausted)?;
        let BrokerResponse {
            request_id: response_id,
            result,
        } = self
            .channel
            .call(BrokerRequest {
                request_id,
                operation,
            })
            .map_err(BrokerLocalError::Channel)?;
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
                | ErrorCode::OutOfMemory
                | ErrorCode::UnsupportedOperation => Err(BrokerLocalError::Broker(error)),
                ErrorCode::UnsupportedVersion
                | ErrorCode::MalformedRequest
                | ErrorCode::ProtocolState
                | ErrorCode::Internal => panic!("broker returned unrecoverable error: {error}"),
                _ => panic!("broker returned unsupported error: {error}"),
            },
            result => Ok(result),
        }
    }

    fn write_shared_buffer(&self, buffer: SharedBufferSequence, data: &[u8]) {
        assert_eq!(
            data.len(),
            buffer.length() as usize,
            "shared data must match its buffer sequence"
        );
        let mut offset = 0;
        for descriptor in buffer
            .descriptors(self.shared_buffers.layout())
            .expect("shared buffer sequence must identify valid slot ranges")
        {
            let end = offset + descriptor.length as usize;
            self.shared_buffers
                .write(descriptor.slot_index, &data[offset..end])
                .expect("validated shared buffer sequence must be accessible");
            offset = end;
        }
    }

    fn read_shared_buffer(&self, buffer: SharedBufferSequence, destination: &mut [u8]) {
        assert!(
            destination.len() <= buffer.length() as usize,
            "shared buffer sequence must cover the destination"
        );
        let mut offset = 0;
        for descriptor in buffer
            .descriptors(self.shared_buffers.layout())
            .expect("shared buffer sequence must identify valid slot ranges")
        {
            if offset == destination.len() {
                break;
            }
            let length = (destination.len() - offset).min(descriptor.length as usize);
            let end = offset + length;
            self.shared_buffers
                .read(descriptor.slot_index, &mut destination[offset..end])
                .expect("validated shared buffer sequence must be accessible");
            offset = end;
        }
        assert_eq!(
            offset,
            destination.len(),
            "shared buffer sequence must cover the destination"
        );
    }

    /// Checks the current readiness of a broker-owned object.
    ///
    /// # Panics
    ///
    /// Panics if the broker reports an unrecoverable error or returns a
    /// response that does not match the issued readiness request.
    pub fn check_readiness(&self, handle: ObjectHandle) -> Result<ReadinessFlags, Channel::Error> {
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
    pub fn close_object(&self, handle: ObjectHandle) -> Result<(), Channel::Error> {
        match self.request(BrokerOperation::CloseObject(handle))? {
            BrokerResult::ObjectClosed => Ok(()),
            BrokerResult::Error(error) => Err(BrokerLocalError::Broker(error)),
            response => {
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
    use core::cell::{Cell, RefCell};
    use core::convert::Infallible;
    use litebox_broker_protocol::message::{ReadinessNotification, StdioRequest, StdioResponse};
    use litebox_broker_protocol::readiness::ReadinessFlags;
    use litebox_broker_protocol::shared_buffer::{SharedBufferSequence, SharedBufferSlotIndex};
    use litebox_broker_protocol::stdio::{
        IsTerminalStdioRequest, IsTerminalStdioResponse, ReadStdioRequest, ReadStdioResponse,
        StdioOutputStream, StdioStream, WriteStdioRequest, WriteStdioResponse,
    };
    use litebox_broker_protocol::{ObjectHandle, ProcessId, ProtocolVersion, ThreadId};
    use litebox_broker_transport::channel::LocalNotificationChannel;
    use std::sync::Mutex;

    use crate::test_support::test_broker_local;

    fn test_process_id() -> ProcessId {
        ProcessId(1)
    }

    #[test]
    fn negotiate_runs_setup_after_response_before_active_requests() {
        let channel = FakeControlChannel::new(
            Some(BrokerHandshakeResponse::Negotiated {
                broker_protocol_version: BROKER_PROTOCOL_VERSION,
                process_id: test_process_id(),
                initial_thread_id: ThreadId(2),
                startup: None,
            }),
            None,
        );
        let setup_calls = Cell::new(0);
        let (local, startup, ()) = BrokerLocal::negotiate(channel, |channel| {
            assert!(channel.sent_handshake_request.is_some());
            assert!(channel.handshake_response.is_none());
            assert!(channel.sent_request.borrow().is_none());
            setup_calls.set(setup_calls.get() + 1);
            Ok((channel, noop_shared_memory(), ()))
        })
        .unwrap();

        assert_eq!(
            local.channel.sent_handshake_request,
            Some(BrokerHandshakeRequest {
                protocol_version: BROKER_PROTOCOL_VERSION
            })
        );
        assert_eq!(setup_calls.get(), 1);
        assert!(startup.is_none());
        assert_eq!(local.process_id(), test_process_id());
        assert_eq!(local.initial_thread_id(), ThreadId(2));
    }

    #[test]
    fn close_object_sends_close_object_request() {
        let handle = ObjectHandle(7);
        let request = BrokerOperation::CloseObject(handle);
        let response = BrokerResult::ObjectClosed;
        let channel = FakeControlChannel::new(None, Some(response.clone()));
        let local = test_broker_local(channel, noop_shared_memory());

        assert!(local.close_object(handle).is_ok());
        assert_eq!(
            local.channel.sent_request.borrow().clone(),
            Some(BrokerRequest {
                request_id: RequestId(0),
                operation: request,
            })
        );
    }

    #[test]
    fn thread_lifecycle_sends_owned_id() {
        let thread_id = ThreadId(7);
        let channel = FakeControlChannel::new(None, Some(BrokerResult::ThreadCreated(thread_id)));
        let local = test_broker_local(channel, noop_shared_memory());

        assert_eq!(local.create_thread().unwrap(), thread_id);
        assert_eq!(
            local.channel.sent_request.borrow().clone(),
            Some(BrokerRequest {
                request_id: RequestId(0),
                operation: BrokerOperation::CreateThread,
            })
        );

        *local.channel.response.borrow_mut() = Some(BrokerResult::ThreadExited);
        local.exit_thread(thread_id).unwrap();
        assert_eq!(
            local.channel.sent_request.borrow().clone(),
            Some(BrokerRequest {
                request_id: RequestId(1),
                operation: BrokerOperation::ExitThread(thread_id),
            })
        );
    }

    #[test]
    fn write_stdio_stages_the_requested_stream_and_buffer() {
        let buffer = sequence(2, 3);
        let channel = FakeControlChannel::new(
            None,
            Some(BrokerResult::Stdio(StdioResponse::Write(
                WriteStdioResponse { written: 2 },
            ))),
        );
        let local = test_broker_local(channel, noop_shared_memory());

        assert_eq!(
            local
                .write_stdio(StdioOutputStream::Stderr, buffer, b"err")
                .unwrap(),
            2
        );
        assert_eq!(
            local.channel.sent_request.borrow().clone(),
            Some(BrokerRequest {
                request_id: RequestId(0),
                operation: BrokerOperation::Stdio(StdioRequest::Write(WriteStdioRequest {
                    stream: StdioOutputStream::Stderr,
                    buffer,
                })),
            })
        );
    }

    #[test]
    fn read_stdio_requests_and_reads_the_shared_buffer() {
        let buffer = sequence(2, 3);
        let channel = FakeControlChannel::new(
            None,
            Some(BrokerResult::Stdio(StdioResponse::Read(
                ReadStdioResponse { read: 2 },
            ))),
        );
        let local = test_broker_local(channel, noop_shared_memory());
        let mut output = [0xff; 3];

        assert_eq!(local.read_stdio(buffer, &mut output).unwrap(), 2);
        assert_eq!(output, [0, 0, 0xff]);
        assert_eq!(
            local.channel.sent_request.borrow().clone(),
            Some(BrokerRequest {
                request_id: RequestId(0),
                operation: BrokerOperation::Stdio(StdioRequest::Read(ReadStdioRequest { buffer })),
            })
        );
    }

    #[test]
    fn stdio_terminal_query_requests_the_selected_stream() {
        let channel = FakeControlChannel::new(
            None,
            Some(BrokerResult::Stdio(StdioResponse::IsTerminal(
                IsTerminalStdioResponse { is_terminal: true },
            ))),
        );
        let local = test_broker_local(channel, noop_shared_memory());

        assert!(local.is_stdio_terminal(StdioStream::Stderr).unwrap());
        assert_eq!(
            local.channel.sent_request.borrow().clone(),
            Some(BrokerRequest {
                request_id: RequestId(0),
                operation: BrokerOperation::Stdio(StdioRequest::IsTerminal(
                    IsTerminalStdioRequest {
                        stream: StdioStream::Stderr,
                    },
                )),
            })
        );
    }

    fn sequence(slot: u32, length: u32) -> SharedBufferSequence {
        SharedBufferSequence::new(&[SharedBufferSlotIndex(slot)], length).unwrap()
    }

    #[test]
    fn active_requests_use_monotonic_identifiers() {
        let handle = ObjectHandle(7);
        let channel = FakeControlChannel::new(None, Some(BrokerResult::ObjectClosed));
        let local = test_broker_local(channel, noop_shared_memory());

        local.close_object(handle).unwrap();
        assert_eq!(
            local
                .channel
                .sent_request
                .borrow()
                .as_ref()
                .unwrap()
                .request_id,
            RequestId(0)
        );

        *local.channel.response.borrow_mut() = Some(BrokerResult::ObjectClosed);
        local.close_object(handle).unwrap();
        assert_eq!(
            local
                .channel
                .sent_request
                .borrow()
                .as_ref()
                .unwrap()
                .request_id,
            RequestId(1)
        );
    }

    #[test]
    fn concurrent_active_requests_use_distinct_identifiers() {
        let local = Arc::new(test_broker_local(
            ConcurrentCallChannel {
                request_ids: Mutex::new(std::vec::Vec::new()),
            },
            noop_shared_memory(),
        ));
        let callers = (0..16)
            .map(|handle| {
                let local = Arc::clone(&local);
                std::thread::spawn(move || local.close_object(ObjectHandle(handle)))
            })
            .collect::<std::vec::Vec<_>>();

        for caller in callers {
            caller.join().unwrap().unwrap();
        }
        let mut request_ids = local.channel.request_ids.lock().unwrap().clone();
        request_ids.sort();
        assert_eq!(
            request_ids,
            (0..16).map(RequestId).collect::<std::vec::Vec<_>>()
        );
    }

    #[test]
    fn active_request_rejects_mismatched_response_identifier() {
        let channel = FakeControlChannel::new(None, Some(BrokerResult::ObjectClosed));
        let local = test_broker_local(channel, noop_shared_memory());
        local.channel.response_id.set(Some(RequestId(9)));

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
        let local = test_broker_local(channel, noop_shared_memory());
        local.next_request_id.store(u64::MAX, Ordering::Relaxed);

        assert!(matches!(
            local.close_object(ObjectHandle(7)),
            Err(BrokerLocalError::RequestIdExhausted)
        ));
        assert!(local.channel.sent_request.borrow().is_none());
    }

    #[test]
    fn active_request_returns_recoverable_broker_errors() {
        for error in [ErrorCode::WouldBlock, ErrorCode::UnsupportedOperation] {
            let channel = FakeControlChannel::new(None, Some(BrokerResult::Error(error)));
            let local = test_broker_local(channel, noop_shared_memory());

            assert!(matches!(
                local.create_event_with_count(0),
                Err(BrokerLocalError::Broker(actual)) if actual == error
            ));
        }
    }

    #[test]
    #[should_panic(expected = "broker returned unrecoverable error")]
    fn active_request_panics_on_unrecoverable_broker_error() {
        let channel = FakeControlChannel::new(None, Some(BrokerResult::Error(ErrorCode::Internal)));
        let local = test_broker_local(channel, noop_shared_memory());

        let _ = local.create_event_with_count(0);
    }

    #[test]
    fn negotiate_rejects_broker_different_version_without_setup() {
        let broker_protocol_version = ProtocolVersion(BROKER_PROTOCOL_VERSION.0 + 1);
        let channel = FakeControlChannel::new(
            Some(BrokerHandshakeResponse::Negotiated {
                broker_protocol_version,
                process_id: test_process_id(),
                initial_thread_id: ThreadId(2),
                startup: None,
            }),
            None,
        );
        let setup_called = Cell::new(false);

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = BrokerLocal::negotiate(channel, |channel| {
                setup_called.set(true);
                Ok((channel, noop_shared_memory(), ()))
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
            BrokerLocal::negotiate(channel, |channel| {
                setup_called.set(true);
                Ok((channel, noop_shared_memory(), ()))
            }),
            Err(BrokerLocalError::Broker(ErrorCode::UnsupportedVersion))
        ));
        assert!(!setup_called.get());
    }

    #[test]
    fn negotiate_returns_resource_allocation_errors() {
        for error in [ErrorCode::ResourceExhausted, ErrorCode::OutOfMemory] {
            let channel =
                FakeControlChannel::new(Some(BrokerHandshakeResponse::Error(error)), None);
            let setup_called = Cell::new(false);

            assert!(matches!(
                BrokerLocal::negotiate(channel, |channel| {
                    setup_called.set(true);
                    Ok((channel, noop_shared_memory(), ()))
                }),
                Err(BrokerLocalError::Broker(reported)) if reported == error
            ));
            assert!(!setup_called.get());
        }
    }

    #[test]
    fn negotiate_skips_setup_before_panicking_on_unrecoverable_broker_error() {
        let channel = FakeControlChannel::new(
            Some(BrokerHandshakeResponse::Error(ErrorCode::Internal)),
            None,
        );
        let setup_called = Cell::new(false);

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = BrokerLocal::negotiate(channel, |channel| {
                setup_called.set(true);
                Ok((channel, noop_shared_memory(), ()))
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
                process_id: test_process_id(),
                initial_thread_id: ThreadId(2),
                startup: None,
            }),
            None,
        );

        assert!(matches!(
            BrokerLocal::<FakeControlChannel>::negotiate(channel, |_| {
                Err::<(FakeControlChannel, Arc<dyn SharedMemory>, ()), _>(
                    FakeChannelError::SharedMemoryReceive,
                )
            }),
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
                process_id: test_process_id(),
                initial_thread_id: ThreadId(2),
                startup: None,
            }),
            None,
        );

        let _ = BrokerLocal::negotiate(channel, |channel| {
            Ok((
                channel,
                Arc::new(NoopSharedMemory {
                    length: litebox_broker_protocol::shared_buffer::SHARED_BUFFER_POOL_SIZE - 1,
                }) as Arc<dyn SharedMemory>,
                (),
            ))
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
        sent_request: RefCell<Option<BrokerRequest>>,
        handshake_response: Option<BrokerHandshakeResponse>,
        response: RefCell<Option<BrokerResult>>,
        response_id: Cell<Option<RequestId>>,
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
        ) -> core::result::Result<(), litebox_broker_transport::shared_memory::SharedMemoryError>
        {
            destination.fill(0);
            Ok(())
        }

        fn write(
            &self,
            _offset: usize,
            _source: &[u8],
        ) -> core::result::Result<(), litebox_broker_transport::shared_memory::SharedMemoryError>
        {
            Ok(())
        }
    }

    fn noop_shared_memory() -> Arc<dyn SharedMemory> {
        Arc::new(NoopSharedMemory {
            length: litebox_broker_protocol::shared_buffer::SHARED_BUFFER_POOL_SIZE,
        })
    }

    impl FakeControlChannel {
        const fn new(
            handshake_response: Option<BrokerHandshakeResponse>,
            response: Option<BrokerResult>,
        ) -> Self {
            Self {
                sent_handshake_request: None,
                sent_request: RefCell::new(None),
                handshake_response,
                response: RefCell::new(response),
                response_id: Cell::new(None),
            }
        }
    }

    impl LocalSetupChannel for FakeControlChannel {
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
    }

    impl LocalCallChannel for FakeControlChannel {
        type Error = FakeChannelError;

        fn call(
            &self,
            request: BrokerRequest,
        ) -> core::result::Result<BrokerResponse, Self::Error> {
            *self.sent_request.borrow_mut() = Some(request);
            let result = self
                .response
                .borrow_mut()
                .take()
                .expect("response requires a scripted result");
            Ok(BrokerResponse {
                request_id: self.response_id.get().unwrap_or_else(|| {
                    self.sent_request
                        .borrow()
                        .as_ref()
                        .expect("response requires a sent request")
                        .request_id
                }),
                result,
            })
        }
    }

    struct FakeNotificationChannel {
        notification: Option<BrokerNotification>,
    }

    struct ConcurrentCallChannel {
        request_ids: Mutex<std::vec::Vec<RequestId>>,
    }

    impl LocalCallChannel for ConcurrentCallChannel {
        type Error = Infallible;

        fn call(
            &self,
            request: BrokerRequest,
        ) -> core::result::Result<BrokerResponse, Self::Error> {
            self.request_ids.lock().unwrap().push(request.request_id);
            Ok(BrokerResponse {
                request_id: request.request_id,
                result: BrokerResult::ObjectClosed,
            })
        }
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
