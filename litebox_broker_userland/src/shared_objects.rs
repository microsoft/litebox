// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Host-file-backed storage for the broker's in-memory files, and its delivery to runners.

use std::io::{Error as IoError, ErrorKind, Result as IoResult};

use litebox_broker_core::BrokerProcess;
use litebox_broker_core::fs::errors::MapSharedError;
use litebox_broker_core::fs::shared_storage::{HostHandle, SharedFileObject};
use litebox_broker_host::RequestFailure;
use litebox_broker_protocol::fs::{FileError, MapFileRequest, MapFileResponse};
use litebox_broker_protocol::message::{BrokerOperation, BrokerResult, FileRequest, FileResponse};

/// Delivers host shared objects to the runner of one association.
pub trait SharedObjectDelivery: Send + Sync {
    /// Delivers `object` to the runner, readable and, if `writable` is set, writable, returning
    /// the token the runner takes it with. The runner maps it up to `end`, a byte offset that
    /// may lie past the end of the file.
    ///
    /// Fails with [`ErrorKind::Unsupported`] if this deployment cannot deliver `object` at all,
    /// which the runner sees as a file it cannot share.
    fn deliver(&self, object: &dyn SharedFileObject, writable: bool, end: u64) -> IoResult<u64>;

    /// Delivers segment backing, allowing platforms to impose a lower permission ceiling.
    fn deliver_sysv(
        &self,
        object: &dyn SharedFileObject,
        writable: bool,
        end: u64,
    ) -> IoResult<u64> {
        self.deliver(object, writable, end)
    }
}

/// Returns `object`'s host handle for delivering it with `writable` rights.
#[cfg_attr(
    not(any(target_os = "linux", all(windows, target_arch = "x86_64"))),
    expect(dead_code, reason = "only deployments that deliver objects use this")
)]
fn host_handle(
    object: &dyn SharedFileObject,
    writable: bool,
) -> IoResult<Box<dyn HostHandle + '_>> {
    object.host_handle(writable).map_err(|error| match error {
        MapSharedError::Unsupported => IoError::new(ErrorKind::Unsupported, error),
        MapSharedError::NoMemory => IoError::new(ErrorKind::OutOfMemory, error),
        error => IoError::other(error),
    })
}

/// Handles file mapping and keyed shared segment requests, delivering shared memory through
/// `delivery`. Returns `None` for other operations.
///
/// Without a delivery adapter, the broker host can handle metadata operations but cannot
/// create backing storage or deliver an attachment.
pub fn handle_map_file<Delivery: SharedObjectDelivery>(
    delivery: &Delivery,
    process: &BrokerProcess,
    operation: &BrokerOperation,
) -> Option<Result<BrokerResult, RequestFailure>> {
    if let BrokerOperation::Segment(request) = *operation {
        #[cfg(target_os = "linux")]
        let provider = Some(
            &linux::MemfdFileMemoryProvider
                as &dyn litebox_broker_core::fs::shared_storage::SharedFileMemoryProvider,
        );
        #[cfg(all(windows, target_arch = "x86_64"))]
        let provider = Some(
            &windows::TempFileMemoryProvider
                as &dyn litebox_broker_core::fs::shared_storage::SharedFileMemoryProvider,
        );
        #[cfg(not(any(target_os = "linux", all(windows, target_arch = "x86_64"))))]
        let provider = None;
        return Some(
            litebox_broker_core::segment::operate(
                process,
                request,
                provider,
                |object, writable, end| {
                    delivery
                        .deliver_sysv(object, writable, end)
                        .map_err(delivery_failure)
                },
            )
            .map(BrokerResult::Segment)
            .map_err(RequestFailure::from),
        );
    }
    let BrokerOperation::File(FileRequest::Map(MapFileRequest { handle, end })) = *operation else {
        return None;
    };
    let response = match litebox_broker_core::fs::map_shared(process, handle) {
        Err(error) => return Some(Err(RequestFailure::from(error))),
        Ok(Err(error)) => FileResponse::Failed(error),
        Ok(Ok(mapping)) => match delivery.deliver(&*mapping.object, mapping.writable, end) {
            Ok(token) => FileResponse::Map(MapFileResponse {
                memory: mapping.memory_id,
                token,
                writable: mapping.writable,
            }),
            Err(error) => FileResponse::Failed(delivery_failure(error)),
        },
    };
    Some(Ok(BrokerResult::File(response)))
}

/// Reports and classifies a failure to deliver a shared object to the runner.
fn delivery_failure(error: IoError) -> FileError {
    litebox_util_log::warn!(error:% = error; "failed to deliver a shared object");
    // Unsupported delivery allows ordinary file mappings to fall back, but fails segment attaches.
    match error.kind() {
        ErrorKind::Unsupported => FileError::NoSuchDevice,
        ErrorKind::OutOfMemory | ErrorKind::WouldBlock => FileError::NoSpace,
        #[cfg(target_os = "linux")]
        _ if litebox_broker_transport_linux_userland::is_resource_exhaustion(&error) => {
            FileError::NoSpace
        }
        _ => FileError::Io,
    }
}

#[cfg(any(target_os = "linux", all(windows, target_arch = "x86_64")))]
mod host_file;

/// Memfd-backed shared file memory for Linux.
#[cfg(target_os = "linux")]
pub mod linux;

/// Temporary-file-backed shared file memory for Windows.
#[cfg(all(windows, target_arch = "x86_64"))]
pub mod windows;
