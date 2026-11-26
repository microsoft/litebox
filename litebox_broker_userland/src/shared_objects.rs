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
        error => IoError::other(error),
    })
}

/// Handles a request to map a file, delivering its shared memory through `delivery`, or returns
/// `None` for other operations.
///
/// Associations without a delivery leave the request to the broker host, which refuses it.
pub fn handle_map_file<Delivery: SharedObjectDelivery>(
    delivery: &Delivery,
    process: &BrokerProcess,
    operation: &BrokerOperation,
) -> Option<Result<BrokerResult, RequestFailure>> {
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
            Err(error) => {
                litebox_util_log::warn!(error:% = error; "failed to deliver a shared file");
                // A deployment that cannot deliver this kind of object, such as a broker
                // without `/proc` to reopen a memfd read-only, cannot share the file, so a
                // runner falls back as for any file it cannot share. Other failures, such as
                // a runner leaving too many deliveries untaken, are a lack of resources.
                FileResponse::Failed(if error.kind() == ErrorKind::Unsupported {
                    FileError::NoSuchDevice
                } else {
                    FileError::NoSpace
                })
            }
        },
    };
    Some(Ok(BrokerResult::File(response)))
}

#[cfg(any(target_os = "linux", all(windows, target_arch = "x86_64")))]
mod host_file;

/// Memfd-backed shared file memory for Linux.
#[cfg(target_os = "linux")]
pub mod linux;

/// Temporary-file-backed shared file memory for Windows.
#[cfg(all(windows, target_arch = "x86_64"))]
pub mod windows;
