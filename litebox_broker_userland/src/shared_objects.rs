// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Host-file-backed storage for the broker's in-memory files, and its delivery to runners.

use std::io::{Error as IoError, ErrorKind, Result as IoResult};

use std::sync::Arc;

use litebox_broker_core::BrokerProcess;
use litebox_broker_core::fs::errors::MapSharedError;
use litebox_broker_core::fs::shared_storage::{
    HostHandle, SharedFileMemoryProvider, SharedFileObject,
};
use litebox_broker_host::RequestFailure;
use litebox_broker_protocol::fs::{FileError, MapFileRequest, MapFileResponse};
use litebox_broker_protocol::message::{
    BrokerOperation, BrokerResult, FileRequest, FileResponse, SegmentRequest, SegmentResponse,
};

/// Delivers host shared objects to the runner of one association.
pub trait SharedObjectDelivery: Send + Sync {
    /// Delivers `object` to the runner, readable and, if `writable` is set, writable, returning
    /// the token the runner takes it with. The runner maps it up to `end`, a byte offset that
    /// may lie past the end of the file.
    ///
    /// Fails with [`ErrorKind::Unsupported`] if this deployment cannot deliver `object` at all,
    /// which the runner sees as a file it cannot share.
    fn deliver(&self, object: &dyn SharedFileObject, writable: bool, end: u64) -> IoResult<u64>;

    /// Delivers the backing object of a keyed shared segment, as [`Self::deliver`] does a
    /// file's. Segments are never executable: a deployment whose handles can carry that ceiling
    /// withholds the right to map them executable, and the runner's memory manager refuses to
    /// map them executable in any case.
    fn deliver_segment(
        &self,
        object: &dyn SharedFileObject,
        writable: bool,
        end: u64,
    ) -> IoResult<u64> {
        self.deliver(object, writable, end)
    }
}

/// Returns this platform's provider of host shared memory, which holds the contents of shared
/// files and keyed shared segments, if it has one.
#[must_use]
pub fn host_memory_provider() -> Option<Arc<dyn SharedFileMemoryProvider>> {
    #[cfg(target_os = "linux")]
    return Some(Arc::new(linux::MemfdFileMemoryProvider));
    #[cfg(all(windows, target_arch = "x86_64"))]
    return Some(Arc::new(windows::TempFileMemoryProvider));
    #[cfg(not(any(target_os = "linux", all(windows, target_arch = "x86_64"))))]
    None
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

/// Handles the requests that deliver host shared objects: file mappings and segment attaches,
/// delivering them through `delivery`. Returns `None` for other operations.
pub fn handle_shared_object_request<Delivery: SharedObjectDelivery>(
    delivery: &Delivery,
    process: &BrokerProcess,
    operation: &BrokerOperation,
) -> Option<Result<BrokerResult, RequestFailure>> {
    match *operation {
        BrokerOperation::Segment(SegmentRequest::PrepareAttach(request)) => {
            let result = litebox_broker_core::segment::prepare_attach(
                process,
                request,
                |object, writable, end| {
                    delivery
                        .deliver_segment(object, writable, end)
                        .map_err(report_delivery_failure)
                },
            );
            Some(
                result
                    .map(|prepared| {
                        BrokerResult::Segment(
                            prepared.map_or_else(
                                SegmentResponse::Failed,
                                SegmentResponse::PrepareAttach,
                            ),
                        )
                    })
                    .map_err(RequestFailure::from),
            )
        }
        BrokerOperation::File(FileRequest::Map(MapFileRequest { handle, end })) => {
            let response = match litebox_broker_core::fs::map_shared(process, handle) {
                Err(error) => return Some(Err(RequestFailure::from(error))),
                Ok(Err(error)) => FileResponse::Failed(error),
                Ok(Ok(mapping)) => {
                    match delivery.deliver(&*mapping.object, mapping.writable, end) {
                        Ok(token) => FileResponse::Map(MapFileResponse {
                            memory: mapping.memory_id,
                            token,
                            writable: mapping.writable,
                        }),
                        Err(error) => FileResponse::Failed(report_delivery_failure(error)),
                    }
                }
            };
            Some(Ok(BrokerResult::File(response)))
        }
        _ => None,
    }
}

/// Logs a failure to deliver a shared object to the runner and classifies it.
fn report_delivery_failure(error: IoError) -> FileError {
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
