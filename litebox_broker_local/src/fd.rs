// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use alloc::vec::Vec;

use litebox_broker_protocol::ProcessId;
use litebox_broker_protocol::error::ErrorCode;
use litebox_broker_protocol::fd::{
    FD_LIST_STRIDE, FdCreate, FdInfo, FdOperation, FdRequest, FdResponse,
};
use litebox_broker_protocol::fs::OpenFileRequest;
use litebox_broker_protocol::message::{BrokerOperation, BrokerResult};
use litebox_broker_protocol::shared_buffer::{SHARED_BUFFER_SLOT_SIZE, SharedBufferSequence};
use litebox_broker_transport::channel::LocalCallChannel;

use crate::{BrokerLocal, BrokerLocalError, Result};

impl<Channel: LocalCallChannel> BrokerLocal<Channel> {
    /// Sends a descriptor-table operation.
    ///
    /// # Panics
    /// Panics if the response is not a descriptor-table response.
    pub fn fd_request(&self, request: FdRequest) -> Result<FdResponse, Channel::Error> {
        match self.request(BrokerOperation::Fd(request))? {
            BrokerResult::Fd(response) => Ok(response),
            response => panic!("unexpected broker fd response: {response:?}"),
        }
    }

    /// Stages an open path and asks the broker to open and install it.
    pub fn open_fd(
        &self,
        pending_child: Option<ProcessId>,
        request: OpenFileRequest,
        path: &str,
        cloexec: bool,
    ) -> Result<FdResponse, Channel::Error> {
        self.write_file_buffer(request.path, path.as_bytes(), SHARED_BUFFER_SLOT_SIZE)?;
        self.fd_request(FdRequest {
            pending_child,
            operation: FdOperation::Create {
                object: FdCreate::Open(request),
                cloexec,
            },
        })
    }

    /// Copies the Unix peer name staged by an fd accept operation.
    pub fn fd_unix_peer(
        &self,
        buffer: SharedBufferSequence,
        len: u8,
    ) -> Result<litebox_broker_protocol::unix_socket::UnixSocketName, Channel::Error> {
        let mut bytes =
            [0; litebox_broker_protocol::unix_socket::MAX_ENCODED_UNIX_SOCKET_NAME_SIZE as usize];
        let bytes = bytes
            .get_mut(..usize::from(len))
            .ok_or(BrokerLocalError::Broker(ErrorCode::Internal))?;
        self.read_shared_buffer(buffer, bytes);
        litebox_broker_protocol::unix_socket::UnixSocketName::decode(bytes)
            .map_err(|_| BrokerLocalError::Broker(ErrorCode::Internal))
    }

    /// Lists the selected table, optionally sweeping CLOEXEC first.
    ///
    /// # Panics
    /// Panics if the broker returns a malformed snapshot.
    pub fn list_fds(
        &self,
        pending_child: Option<ProcessId>,
        buffer: SharedBufferSequence,
        exec: bool,
    ) -> Result<(u64, Vec<FdInfo>), Channel::Error> {
        let operation = if exec {
            FdOperation::Exec(Some(buffer))
        } else {
            FdOperation::List(buffer)
        };
        let response = self.fd_request(FdRequest {
            pending_child,
            operation,
        })?;
        let FdResponse::Listed { revision, entries } = response else {
            panic!("unexpected broker fd list response: {response:?}");
        };
        let count = entries as usize;
        assert!(
            count <= buffer.length() as usize / FD_LIST_STRIDE,
            "oversized fd snapshot"
        );
        let mut fds = Vec::new();
        fds.try_reserve_exact(count)
            .map_err(|_| BrokerLocalError::Broker(ErrorCode::OutOfMemory))?;
        for index in 0..count {
            let mut record = [0; FD_LIST_STRIDE];
            self.read_shared_buffer_at(buffer, index * FD_LIST_STRIDE, &mut record);
            fds.push(FdInfo::read(&record).expect("invalid fd snapshot record"));
        }
        Ok((revision, fds))
    }
}
