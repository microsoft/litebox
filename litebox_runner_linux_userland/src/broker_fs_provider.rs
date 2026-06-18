// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Runner-side implementation of [`BrokerFsProvider`].
//!
//! Wraps the same `FdTokenClient` the pipe provider uses;
//! `register_ofd` / `clone_ofd` are the only methods. Subscribe /
//! release / dup_handle / query_events are intentionally
//! unimplemented at the `BrokerSubscribable` layer — an OFD
//! registry entry is not an event source, and its lifecycle is
//! tied to the 9P fid's `Tclunk`, not a per-handle ref. Callers
//! should manipulate the registry entry via `Tclunk` on the
//! installed fid (or, prospectively, via a future explicit
//! release wire op).

use litebox_common_linux::broker_fs_provider::BrokerFsProvider;
use litebox_common_linux::cwfd::broker_subscribable::{
    BrokerEventCallback, BrokerOpError, BrokerSubscribable,
};
use litebox_common_linux::fd_token_client::{ClientError, FdTokenClient};
use std::sync::Arc;

pub struct RunnerBrokerFsProvider {
    client: Arc<FdTokenClient>,
}

impl RunnerBrokerFsProvider {
    pub fn new(client: Arc<FdTokenClient>) -> Self {
        Self { client }
    }
}

impl BrokerSubscribable for RunnerBrokerFsProvider {
    fn subscribe(
        &self,
        _handle: u64,
        _events_mask: u32,
        _callback: Arc<dyn BrokerEventCallback>,
    ) -> Result<u64, BrokerOpError> {
        // OFD registry entries are not event sources; subscription
        // makes no sense for them. Returning ProtocolNotSupported
        // matches other providers' "this op isn't part of my
        // surface" idiom.
        Err(BrokerOpError::ProtocolNotSupported)
    }

    fn unsubscribe(&self, _handle: u64, _subscription_id: u64) {}

    fn release(&self, _handle: u64) {
        // OFD entries don't have a `release` wire op today; their
        // lifecycle is tied to the 9P fid's `Tclunk`. If the caller
        // installed the cloned fid and then needs to drop it, it
        // should issue a 9P `Tclunk` on the fid number it chose.
    }

    fn dup_handle(&self, _handle: u64) -> Result<(), BrokerOpError> {
        // To "dup" an OFD entry, callers should issue another
        // `clone_ofd` with a fresh `new_fid`. Per-handle dup is
        // intentionally not exposed here because the install path
        // is a 9P fid, not a free-floating broker handle.
        Err(BrokerOpError::ProtocolNotSupported)
    }

    fn query_events(&self, _handle: u64) -> Result<u32, BrokerOpError> {
        Err(BrokerOpError::ProtocolNotSupported)
    }
}

impl BrokerFsProvider for RunnerBrokerFsProvider {
    fn register_ofd(&self, fid: u32) -> Result<u64, BrokerOpError> {
        self.client
            .register_ofd(fid)
            .map_err(client_err_to_broker_err)
    }

    fn clone_ofd(&self, open_file_id: u64, new_fid: u32) -> Result<(), BrokerOpError> {
        self.client
            .clone_ofd(open_file_id, new_fid)
            .map_err(client_err_to_broker_err)
    }
}

fn client_err_to_broker_err(e: ClientError) -> BrokerOpError {
    // reason: unsupported variants intentionally share the
    // generic-Io fallback; this trait surface is intentionally
    // narrow and the broker error catalog is broader.
    #[allow(clippy::wildcard_enum_match_arm)]
    match e {
        ClientError::UnknownHandle { .. } => BrokerOpError::UnknownHandle,
        ClientError::WouldBlock => BrokerOpError::WouldBlock,
        ClientError::InvalidValue { .. } | ClientError::Protocol(_) => BrokerOpError::InvalidValue,
        ClientError::PermissionDenied => BrokerOpError::PermissionDenied,
        ClientError::ProtocolNotSupported | ClientError::SubsystemMismatch => {
            BrokerOpError::ProtocolNotSupported
        }
        _ => BrokerOpError::Io,
    }
}
