// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Host-file-backed storage for the broker's in-memory files, and its delivery to runners.
//!
//! Linux uses memfds and Windows uses temporary files. Both providers access contents through
//! positional I/O, including staged copies for buffers that cannot expose their bytes directly.
//! When a runner asks to map a file, the association's [`SharedObjectDelivery`] hands it the
//! file's [`SharedFileObject`] out of band, through the host handle the object lends, and the
//! response carries the token it takes the object with.

use std::io::{Error as IoError, ErrorKind, Result as IoResult};

use litebox_broker_core::BrokerProcess;
use litebox_broker_core::fs::shared_memory::{HostHandle, SharedFileMemoryError, SharedFileObject};
use litebox_broker_host::RequestFailure;
use litebox_broker_protocol::fs::{FileError, MapFileRequest, MapFileResponse};
use litebox_broker_protocol::message::{BrokerOperation, BrokerResult, FileRequest, FileResponse};

/// Delivers host shared objects to the runner of one association.
pub trait SharedObjectDelivery: Send + Sync {
    /// Delivers `object` to the runner, readable and, if `writable` is set, writable, returning
    /// the token the runner takes it with.
    ///
    /// Fails with [`ErrorKind::Unsupported`] if this deployment cannot deliver `object` at all,
    /// which the runner sees as a file it cannot share.
    fn deliver(&self, object: &dyn SharedFileObject, writable: bool) -> IoResult<u64>;
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
        SharedFileMemoryError::Unsupported => IoError::new(ErrorKind::Unsupported, error),
        error => IoError::other(error),
    })
}

/// Handles a request to map a file, delivering its shared memory through `delivery`, or returns
/// `None` for other operations.
pub(crate) fn handle_map_file(
    delivery: Option<&dyn SharedObjectDelivery>,
    process: &BrokerProcess,
    operation: &BrokerOperation,
) -> Option<Result<BrokerResult, RequestFailure>> {
    let BrokerOperation::File(FileRequest::Map(MapFileRequest { handle })) = *operation else {
        return None;
    };
    let response = match delivery {
        None => FileResponse::Failed(FileError::NoSuchDevice),
        Some(delivery) => match litebox_broker_core::fs::map_shared(process, handle) {
            Err(error) => return Some(Err(RequestFailure::from(error))),
            Ok(Err(error)) => FileResponse::Failed(error),
            Ok(Ok(mapping)) => match delivery.deliver(&*mapping.object, mapping.writable) {
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
        },
    };
    Some(Ok(BrokerResult::File(response)))
}

/// A file's contents in a host file, accessed with positional I/O.
#[cfg(any(target_os = "linux", all(windows, target_arch = "x86_64")))]
mod host_file;

/// Memfd-backed shared file memory for Linux.
#[cfg(target_os = "linux")]
pub mod linux;

/// Temporary-file-backed shared file memory for Windows.
///
/// Pagefile-backed sections cannot grow, but sections of a file can be created at any size the
/// file has, so a mapped file's contents live in a temporary file that is deleted when the broker
/// closes it. Every runner mapping the file gets its own section of it, sized to the file when
/// mapped, and all sections of one file share the file's pages.
#[cfg(all(windows, target_arch = "x86_64"))]
pub mod windows;

/// The host's module, which provides the host-specific parts of [`host_file`].
#[cfg(target_os = "linux")]
use linux as platform;
#[cfg(all(windows, target_arch = "x86_64"))]
use windows as platform;
