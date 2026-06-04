// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Trait abstraction for broker-hosted **9P FS fid** operations.
//!
//! Legacy-pipes Phase 3 (D3): the broker-global OFD registry
//! ([`litebox_broker::ofd_registry::OfdRegistry`]) holds host
//! `fs::File` handles minted by one 9P session and re-installable on
//! another. The wire ops are `RegisterOfd` / `CloneOfd` on the
//! fd-token-socket; this trait is the shim-side abstraction the
//! `litebox_shim_linux` callers use, paired with the runner-side
//! `RunnerBrokerFsProvider` impl that forwards to `FdTokenClient`.
//!
//! POSIX inherited-fd semantics (shared kernel position) are
//! preserved end-to-end: the broker does the cross-fid sharing via
//! `try_clone` on the underlying `fs::File`, which is `dup(2)` —
//! exactly the kernel mechanism Linux fork inheritance relies on.
//!
//! This trait is intentionally narrow (two methods) so test mocks
//! can stub it without pulling in the whole pipe surface.

use crate::cwfd::broker_subscribable::{BrokerOpError, BrokerSubscribable};

/// Provider for the broker-hosted OFD registry. Object-safe.
pub trait BrokerFsProvider: BrokerSubscribable {
    /// Register an already-open 9P `fid` in the broker's OFD
    /// registry for cross-session sharing.
    ///
    /// Issued by the **parent** shim. The broker walks its paired
    /// `nine_p::Server`'s fid table for `fid`, requires it to be
    /// open with a host `fs::File`, dups via `try_clone()`
    /// (kernel OFD sharing), and inserts the clone under a fresh
    /// `OpenFileId`. The returned id is broker-scoped and should
    /// be shipped to the worker via `--broker-fd-bridge fs_fid:…`.
    ///
    /// Refcount on success: the parent's existing fid carries the
    /// id and its eventual `Tclunk` releases one ref. The worker's
    /// subsequent [`clone_ofd`](Self::clone_ofd) bumps the refcount
    /// and inserts a sibling fid that carries the id too, so the
    /// worker's `Tclunk` also releases one ref.
    fn register_ofd(&self, fid: u32) -> Result<u64, BrokerOpError>;

    /// Clone a previously-registered OFD into a fresh 9P `new_fid`
    /// on the **worker's** 9P session.
    ///
    /// Issued by the **worker** shim. The broker looks up
    /// `open_file_id` in the global registry, increments its
    /// refcount, dups the underlying host `fs::File` via
    /// `try_clone()`, synthesises a fresh `FidState` (open,
    /// canonical, carrying the same path + OFD id so its
    /// `Tclunk` releases the registry refcount), and installs it
    /// at `new_fid` in the worker's paired `nine_p::Server`'s
    /// fid table. After this returns Ok, the worker's standard
    /// 9P `Twrite`/`Tread` against `new_fid` share the kernel
    /// OFD with the parent's original fid (shared offset).
    fn clone_ofd(&self, open_file_id: u64, new_fid: u32) -> Result<(), BrokerOpError>;
}
