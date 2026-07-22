// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use litebox_broker_protocol::ObjectHandle;
use litebox_broker_protocol::channel::LocalControlChannel;
use litebox_broker_protocol::message::{BrokerOperation, BrokerResult, PipeRequest, PipeResponse};
use litebox_broker_protocol::pipe::{
    CreatePipeRequest, CreatePipeResponse, MAX_PIPE_TRANSFER_SIZE, ReadPipeRequest,
    WritePipeRequest,
};
use litebox_broker_protocol::shared_memory::SharedBufferDescriptor;

use crate::{BrokerLocal, BrokerLocalError, Result};

impl<Channel: LocalControlChannel> BrokerLocal<Channel> {
    /// Creates a broker-owned byte pipe.
    ///
    /// # Panics
    ///
    /// Panics if the broker reports an unrecoverable error or returns a
    /// response that does not match the issued pipe request, or if `buffer` is
    /// not a valid lease whose length matches `destination`.
    pub fn create_pipe(
        &self,
        capacity: u64,
        atomic_write_size: u64,
    ) -> Result<CreatePipeResponse, Channel::Error> {
        let response = self.request_pipe(PipeRequest::Create(CreatePipeRequest {
            capacity,
            atomic_write_size,
        }))?;
        let PipeResponse::Create(response) = response else {
            panic!("broker returned unexpected pipe create response: {response:?}");
        };
        Ok(response)
    }

    /// Reads bytes from a broker-owned pipe into an operation-scoped shared
    /// buffer lease.
    ///
    /// The caller must retain exclusive ownership of the descriptor's slot
    /// until this method returns.
    ///
    /// # Panics
    ///
    /// Panics if the broker reports an unrecoverable error or returns a
    /// response that does not match the issued pipe request, or if `buffer` is
    /// not a valid lease whose length matches `data`.
    pub fn read_pipe(
        &self,
        handle: ObjectHandle,
        buffer: SharedBufferDescriptor,
        destination: &mut [u8],
    ) -> Result<usize, Channel::Error> {
        if buffer.length > MAX_PIPE_TRANSFER_SIZE {
            return Err(BrokerLocalError::Broker(
                litebox_broker_protocol::error::ErrorCode::ResourceExhausted,
            ));
        }
        assert_eq!(
            destination.len(),
            buffer.length as usize,
            "shared pipe read destination must match its descriptor"
        );
        self.shared_buffers
            .layout()
            .range(buffer.slot_index, destination.len())
            .expect("shared pipe read descriptor must identify a valid slot range");
        let response = self.request_pipe(PipeRequest::Read(ReadPipeRequest { handle, buffer }))?;
        let PipeResponse::Read(response) = response else {
            panic!("broker returned unexpected pipe read response: {response:?}");
        };
        assert!(
            response.read <= buffer.length,
            "broker returned oversized pipe read"
        );
        let read = response.read as usize;
        self.shared_buffers
            .read(buffer.slot_index, &mut destination[..read])
            .expect("validated shared pipe read range must be accessible");
        Ok(read)
    }

    /// Writes bytes to a broker-owned pipe from an operation-scoped shared
    /// buffer lease.
    ///
    /// The caller must retain exclusive ownership of the descriptor's slot
    /// until this method returns.
    ///
    /// # Panics
    ///
    /// Panics if the broker reports an unrecoverable error or returns a
    /// response that does not match the issued pipe request.
    pub fn write_pipe(
        &self,
        handle: ObjectHandle,
        buffer: SharedBufferDescriptor,
        data: &[u8],
    ) -> Result<usize, Channel::Error> {
        if buffer.length > MAX_PIPE_TRANSFER_SIZE {
            return Err(BrokerLocalError::Broker(
                litebox_broker_protocol::error::ErrorCode::ResourceExhausted,
            ));
        }
        assert_eq!(
            data.len(),
            buffer.length as usize,
            "shared pipe write data must match its descriptor"
        );
        self.shared_buffers
            .write(buffer.slot_index, data)
            .expect("validated shared pipe write range must be accessible");
        let response =
            self.request_pipe(PipeRequest::Write(WritePipeRequest { handle, buffer }))?;
        let PipeResponse::Write(response) = response else {
            panic!("broker returned unexpected pipe write response: {response:?}");
        };
        let written = response.written as usize;
        assert!(
            written <= data.len(),
            "broker returned oversized shared pipe write"
        );
        Ok(written)
    }

    fn request_pipe(&self, request: PipeRequest) -> Result<PipeResponse, Channel::Error> {
        match self.request(BrokerOperation::Pipe(request))? {
            BrokerResult::Pipe(response) => Ok(response),
            BrokerResult::Error(error) => Err(BrokerLocalError::Broker(error)),
            response @ (BrokerResult::ObjectClosed
            | BrokerResult::Readiness(_)
            | BrokerResult::Event(_)) => {
                panic!("broker returned unexpected pipe response: {response:?}");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::sync::Arc;
    use alloc::vec::Vec;
    use core::{cell::RefCell, convert::Infallible};
    use std::collections::VecDeque;
    use std::sync::Mutex;

    use litebox_broker_protocol::BROKER_PROTOCOL_VERSION;
    use litebox_broker_protocol::channel::LocalControlChannel;
    use litebox_broker_protocol::message::{
        BrokerHandshakeRequest, BrokerHandshakeResponse, BrokerOperation, BrokerRequest,
        BrokerResponse, BrokerResult,
    };
    use litebox_broker_protocol::pipe::{ReadPipeResponse, WritePipeResponse};
    use litebox_broker_protocol::shared_memory::{
        SHARED_BUFFER_POOL_SIZE, SHARED_BUFFER_SLOT_SIZE, SharedBufferSlotIndex, SharedMemory,
        SharedMemoryError,
    };

    #[test]
    fn pipe_uses_the_descriptor_slot_for_data_operations() {
        let read_handle = ObjectHandle(1);
        let write_handle = ObjectHandle(2);
        let memory = Arc::new(TestSharedMemory::new(SHARED_BUFFER_POOL_SIZE));
        let channel = ScriptedChannel::new([
            BrokerResult::Pipe(PipeResponse::Create(CreatePipeResponse {
                read_handle,
                write_handle,
            })),
            BrokerResult::Pipe(PipeResponse::Write(WritePipeResponse { written: 2 })),
            BrokerResult::Pipe(PipeResponse::Read(ReadPipeResponse { read: 2 })),
        ]);
        let local = BrokerLocal::negotiate(channel, |_| Ok(memory.clone())).unwrap();
        let write_buffer = descriptor(2, 3);
        let read_buffer = descriptor(4, 3);

        local.create_pipe(64, 16).unwrap();
        assert_eq!(
            local
                .write_pipe(write_handle, write_buffer, &[1, 2, 3])
                .unwrap(),
            2
        );
        let mut staged = [0; 3];
        memory
            .read(2 * SHARED_BUFFER_SLOT_SIZE as usize, &mut staged)
            .unwrap();
        assert_eq!(staged, [1, 2, 3]);

        memory
            .write(4 * SHARED_BUFFER_SLOT_SIZE as usize, &[4, 5, 6])
            .unwrap();
        let mut read_data = [0; 3];
        let read = local
            .read_pipe(read_handle, read_buffer, &mut read_data)
            .unwrap();
        assert_eq!(read, 2);
        assert_eq!(&read_data[..read], &[4, 5]);
        assert_eq!(
            local.channel.sent_operations.borrow().as_slice(),
            &[
                BrokerOperation::Pipe(PipeRequest::Create(CreatePipeRequest {
                    capacity: 64,
                    atomic_write_size: 16,
                })),
                BrokerOperation::Pipe(PipeRequest::Write(WritePipeRequest {
                    handle: write_handle,
                    buffer: write_buffer,
                })),
                BrokerOperation::Pipe(PipeRequest::Read(ReadPipeRequest {
                    handle: read_handle,
                    buffer: read_buffer,
                })),
            ]
        );
    }

    #[test]
    fn pipe_rejects_oversized_transfers_before_request() {
        let memory = Arc::new(TestSharedMemory::new(SHARED_BUFFER_POOL_SIZE));
        let channel = ScriptedChannel::new([]);
        let local = BrokerLocal::negotiate(channel, |_| Ok(memory)).unwrap();
        let oversized = descriptor(0, MAX_PIPE_TRANSFER_SIZE + 1);

        assert!(matches!(
            local.read_pipe(ObjectHandle(1), oversized, &mut []),
            Err(BrokerLocalError::Broker(
                litebox_broker_protocol::error::ErrorCode::ResourceExhausted
            ))
        ));
        assert!(matches!(
            local.write_pipe(ObjectHandle(2), oversized, &[]),
            Err(BrokerLocalError::Broker(
                litebox_broker_protocol::error::ErrorCode::ResourceExhausted
            ))
        ));
        assert!(local.channel.sent_operations.borrow().is_empty());
    }

    #[test]
    #[should_panic(expected = "broker returned oversized pipe read")]
    fn read_pipe_rejects_oversized_response() {
        let channel =
            ScriptedChannel::new([BrokerResult::Pipe(PipeResponse::Read(ReadPipeResponse {
                read: 2,
            }))]);
        let memory = Arc::new(TestSharedMemory::new(SHARED_BUFFER_POOL_SIZE));
        let local = BrokerLocal::negotiate(channel, |_| Ok(memory)).unwrap();
        let mut destination = [0];

        let _ = local.read_pipe(ObjectHandle(1), descriptor(0, 1), &mut destination);
    }

    #[test]
    #[should_panic(expected = "broker returned oversized shared pipe write")]
    fn write_pipe_rejects_oversized_response() {
        let channel =
            ScriptedChannel::new([BrokerResult::Pipe(PipeResponse::Write(WritePipeResponse {
                written: 2,
            }))]);
        let memory = Arc::new(TestSharedMemory::new(SHARED_BUFFER_POOL_SIZE));
        let local = BrokerLocal::negotiate(channel, |_| Ok(memory)).unwrap();

        let _ = local.write_pipe(ObjectHandle(1), descriptor(0, 1), &[0]);
    }

    const fn descriptor(slot: u32, length: u32) -> SharedBufferDescriptor {
        SharedBufferDescriptor {
            slot_index: SharedBufferSlotIndex(slot),
            length,
        }
    }

    #[derive(Clone)]
    struct TestSharedMemory(Arc<Mutex<Vec<u8>>>);

    impl TestSharedMemory {
        fn new(length: usize) -> Self {
            Self(Arc::new(Mutex::new(std::vec![0; length])))
        }
    }

    impl SharedMemory for TestSharedMemory {
        fn len(&self) -> usize {
            self.0.lock().unwrap().len()
        }

        fn read(
            &self,
            offset: usize,
            destination: &mut [u8],
        ) -> core::result::Result<(), SharedMemoryError> {
            let memory = self.0.lock().unwrap();
            let end = offset
                .checked_add(destination.len())
                .ok_or(SharedMemoryError::InvalidRange)?;
            let source = memory
                .get(offset..end)
                .ok_or(SharedMemoryError::InvalidRange)?;
            destination.copy_from_slice(source);
            Ok(())
        }

        fn write(
            &self,
            offset: usize,
            source: &[u8],
        ) -> core::result::Result<(), SharedMemoryError> {
            let mut memory = self.0.lock().unwrap();
            let end = offset
                .checked_add(source.len())
                .ok_or(SharedMemoryError::InvalidRange)?;
            let destination = memory
                .get_mut(offset..end)
                .ok_or(SharedMemoryError::InvalidRange)?;
            destination.copy_from_slice(source);
            Ok(())
        }
    }

    struct ScriptedChannel {
        results: RefCell<VecDeque<BrokerResult>>,
        sent_operations: RefCell<Vec<BrokerOperation>>,
    }

    impl ScriptedChannel {
        fn new(results: impl IntoIterator<Item = BrokerResult>) -> Self {
            Self {
                results: RefCell::new(results.into_iter().collect()),
                sent_operations: RefCell::new(Vec::new()),
            }
        }
    }

    impl LocalControlChannel for ScriptedChannel {
        type Error = Infallible;

        fn send_handshake_request(
            &mut self,
            request: &BrokerHandshakeRequest,
        ) -> core::result::Result<(), Self::Error> {
            assert_eq!(request.protocol_version, BROKER_PROTOCOL_VERSION);
            Ok(())
        }

        fn recv_handshake_response(
            &mut self,
        ) -> core::result::Result<Option<BrokerHandshakeResponse>, Self::Error> {
            Ok(Some(BrokerHandshakeResponse::Negotiated {
                broker_protocol_version: BROKER_PROTOCOL_VERSION,
            }))
        }
        fn call(
            &self,
            request: BrokerRequest,
        ) -> core::result::Result<BrokerResponse, Self::Error> {
            self.sent_operations.borrow_mut().push(request.operation);
            Ok(BrokerResponse {
                request_id: request.request_id,
                result: self
                    .results
                    .borrow_mut()
                    .pop_front()
                    .expect("response requires a scripted result"),
            })
        }
    }
}
