// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use alloc::vec::Vec;

use litebox_broker_protocol::error::ErrorCode;
use litebox_broker_protocol::message::{
    BrokerOperation, BrokerResult, ProcessRequest, ProcessResponse,
};
use litebox_broker_protocol::process::{
    ChildExit, ChildSelector, DuplicateObjectsToChildRequest, ExitChildProcessRequest,
    MAX_CHILD_MEMORY_WRITE_SIZE, MAX_CHILD_OBJECT_DUPLICATES, MAX_PROCESS_BOOTSTRAP_SIZE,
    ProcessExitStatus, ProcessIdentity, ProcessInfo, ProcessStartupDescriptor,
    StartChildProcessRequest, ThreadInfo, WriteChildMemoryRequest,
};
use litebox_broker_protocol::shared_buffer::SharedBufferSequence;
use litebox_broker_protocol::{ObjectHandle, ProcessId, ThreadId};
use litebox_broker_transport::channel::LocalCallChannel;

use crate::{BrokerLocal, BrokerLocalError, Result};

impl<Channel: LocalCallChannel> BrokerLocal<Channel> {
    /// Starts a pending child created by [`Self::allocate_child_process`].
    ///
    /// This call blocks until the child's broker association is active or
    /// launch fails. The caller must retain exclusive ownership of the
    /// bootstrap sequence until this method returns.
    ///
    /// # Panics
    ///
    /// Panics if the bootstrap length differs from the shared-buffer sequence
    /// or the broker returns a response for another operation.
    pub fn start_child_process(
        &self,
        child_process_id: ProcessId,
        buffer: SharedBufferSequence,
        bootstrap: &[u8],
    ) -> Result<(), Channel::Error> {
        if buffer.length() > MAX_PROCESS_BOOTSTRAP_SIZE {
            return Err(BrokerLocalError::Broker(ErrorCode::ResourceExhausted));
        }

        self.write_shared_buffer(buffer, bootstrap);
        match self.request_process(ProcessRequest::StartChild(StartChildProcessRequest {
            child_process_id,
            startup: ProcessStartupDescriptor { buffer },
        }))? {
            ProcessResponse::StartChild => Ok(()),
            response => panic!("broker returned unexpected process response: {response:?}"),
        }
    }

    /// Writes `data` at `offset` of the memory image of a pending child
    /// created by [`Self::allocate_child_process`].
    ///
    /// The caller must retain exclusive ownership of the data sequence until
    /// this method returns.
    ///
    /// # Panics
    ///
    /// Panics if the data length differs from the shared-buffer sequence or the
    /// broker returns a response for another operation.
    pub fn write_child_memory(
        &self,
        child_process_id: ProcessId,
        offset: u64,
        buffer: SharedBufferSequence,
        data: &[u8],
    ) -> Result<(), Channel::Error> {
        if buffer.length() > MAX_CHILD_MEMORY_WRITE_SIZE {
            return Err(BrokerLocalError::Broker(ErrorCode::ResourceExhausted));
        }

        self.write_shared_buffer(buffer, data);
        match self.request_process(ProcessRequest::WriteChildMemory(WriteChildMemoryRequest {
            child_process_id,
            offset,
            data: buffer,
        }))? {
            ProcessResponse::WriteChildMemory => Ok(()),
            response => panic!("broker returned unexpected process response: {response:?}"),
        }
    }

    /// Records the exit of a pending child created by
    /// [`Self::allocate_child_process`] that never started.
    ///
    /// # Panics
    ///
    /// Panics if the broker returns a response for another operation.
    pub fn exit_child_process(
        &self,
        child_process_id: ProcessId,
        exit_status: ProcessExitStatus,
    ) -> Result<(), Channel::Error> {
        match self.request_process(ProcessRequest::ExitChild(ExitChildProcessRequest {
            child_process_id,
            exit_status,
        }))? {
            ProcessResponse::ExitChild => Ok(()),
            response => panic!("broker returned unexpected process response: {response:?}"),
        }
    }

    /// Discards a pending child created by [`Self::allocate_child_process`]
    /// that never started, as if it had never been created.
    ///
    /// # Panics
    ///
    /// Panics if the broker returns a response for another operation.
    pub fn cancel_child_process(&self, child_process_id: ProcessId) -> Result<(), Channel::Error> {
        match self.request_process(ProcessRequest::CancelChild(child_process_id))? {
            ProcessResponse::CancelChild => Ok(()),
            response => panic!("broker returned unexpected process response: {response:?}"),
        }
    }

    /// Duplicates this process's object references into a pending child
    /// created by [`Self::allocate_child_process`], returning the child's
    /// handles in the same order.
    ///
    /// `buffer` carries the handles, so its length must be exactly eight bytes
    /// per handle.
    ///
    /// # Panics
    ///
    /// Panics if `handles` is empty or exceeds [`MAX_CHILD_OBJECT_DUPLICATES`],
    /// if `buffer` does not match `handles`, or if the broker returns a
    /// response for another operation.
    pub fn duplicate_objects_to_child(
        &self,
        child_process_id: ProcessId,
        buffer: SharedBufferSequence,
        handles: &[ObjectHandle],
    ) -> Result<Vec<ObjectHandle>, Channel::Error> {
        assert!(
            !handles.is_empty() && handles.len() <= MAX_CHILD_OBJECT_DUPLICATES as usize,
            "child object duplication must carry between one and the maximum handles"
        );
        let mut data = Vec::new();
        let mut duplicates = Vec::new();
        data.try_reserve_exact(handles.len() * size_of::<u64>())
            .and_then(|()| duplicates.try_reserve_exact(handles.len()))
            .map_err(|_| BrokerLocalError::Broker(ErrorCode::OutOfMemory))?;
        data.extend(handles.iter().flat_map(|handle| handle.0.to_le_bytes()));
        self.write_shared_buffer(buffer, &data);
        match self.request_process(ProcessRequest::DuplicateObjectsToChild(
            DuplicateObjectsToChildRequest {
                child_process_id,
                handles: buffer,
            },
        ))? {
            ProcessResponse::DuplicateObjectsToChild => {
                self.read_shared_buffer(buffer, &mut data);
                let (handles, _) = data.as_chunks::<{ size_of::<u64>() }>();
                duplicates.extend(
                    handles
                        .iter()
                        .map(|bytes| ObjectHandle(u64::from_le_bytes(*bytes))),
                );
                Ok(duplicates)
            }
            response => panic!("broker returned unexpected process response: {response:?}"),
        }
    }

    /// Reports this process's final termination status before its runner
    /// exits.
    ///
    /// # Panics
    ///
    /// Panics if the broker returns a response for another operation.
    pub fn report_exit_status(&self, exit_status: ProcessExitStatus) -> Result<(), Channel::Error> {
        match self.request_process(ProcessRequest::ReportExitStatus(exit_status))? {
            ProcessResponse::ReportExitStatus => Ok(()),
            response => panic!("broker returned unexpected process response: {response:?}"),
        }
    }

    /// Sets whether this process retains its children's exits until it
    /// collects them, rather than discarding each when the child terminates.
    ///
    /// # Panics
    ///
    /// Panics if the broker returns a response for another operation.
    pub fn set_child_exit_retention(&self, enabled: bool) -> Result<(), Channel::Error> {
        match self.request_process(ProcessRequest::SetChildExitRetention(enabled))? {
            ProcessResponse::SetChildExitRetention => Ok(()),
            response => panic!("broker returned unexpected process response: {response:?}"),
        }
    }

    /// Sets whether this process adopts the orphaned children of its exiting
    /// descendants.
    ///
    /// # Panics
    ///
    /// Panics if the broker returns a response for another operation.
    pub fn set_orphan_adoption(&self, enabled: bool) -> Result<(), Channel::Error> {
        match self.request_process(ProcessRequest::SetOrphanAdoption(enabled))? {
            ProcessResponse::SetOrphanAdoption => Ok(()),
            response => panic!("broker returned unexpected process response: {response:?}"),
        }
    }

    /// Allocates one pending child process of this process.
    ///
    /// # Panics
    ///
    /// Panics if the broker returns a response for another operation.
    pub fn allocate_child_process(&self) -> Result<ProcessIdentity, Channel::Error> {
        match self.request_process(ProcessRequest::AllocateChild)? {
            ProcessResponse::AllocateChild(child) => Ok(child),
            response => panic!("broker returned unexpected process response: {response:?}"),
        }
    }

    /// Collects the exit of this process's oldest exited child that
    /// `selector` matches, removing the child from the process tree.
    ///
    /// Returns `WouldBlock` if only live children match, and `UnknownObject`
    /// if none does.
    ///
    /// # Panics
    ///
    /// Panics if the broker returns a response for another operation.
    pub fn collect_child_exit(&self, selector: ChildSelector) -> Result<ChildExit, Channel::Error> {
        match self.request_process(ProcessRequest::CollectChildExit(selector))? {
            ProcessResponse::CollectChildExit(exit) => Ok(exit),
            response => panic!("broker returned unexpected process response: {response:?}"),
        }
    }

    /// Returns the place in the process tree of process `process_id`.
    ///
    /// Returns `UnknownObject` if no such process exists.
    ///
    /// # Panics
    ///
    /// Panics if the broker returns a response for another operation.
    pub fn process_info(&self, process_id: ProcessId) -> Result<ProcessInfo, Channel::Error> {
        match self.request_process(ProcessRequest::GetInfo(process_id))? {
            ProcessResponse::GetInfo(info) => Ok(info),
            response => panic!("broker returned unexpected process response: {response:?}"),
        }
    }

    /// Returns the process thread `thread_id` belongs to.
    ///
    /// Returns `UnknownObject` if no such thread exists.
    ///
    /// # Panics
    ///
    /// Panics if the broker returns a response for another operation.
    pub fn thread_info(&self, thread_id: ThreadId) -> Result<ThreadInfo, Channel::Error> {
        match self.request_process(ProcessRequest::GetThreadInfo(thread_id))? {
            ProcessResponse::GetThreadInfo(info) => Ok(info),
            response => panic!("broker returned unexpected process response: {response:?}"),
        }
    }

    fn request_process(&self, request: ProcessRequest) -> Result<ProcessResponse, Channel::Error> {
        match self.request(BrokerOperation::Process(request))? {
            BrokerResult::Process(response) => Ok(response),
            BrokerResult::Error(error) => Err(BrokerLocalError::Broker(error)),
            response => panic!("broker returned unexpected process response: {response:?}"),
        }
    }
}
