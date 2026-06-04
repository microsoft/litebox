// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Shim-side accessor for the broker-hosted FS-fid provider
//! ([`BrokerFsProvider`]).
//!
//! Legacy-pipes Phase 3 (D3): the runner installs a concrete
//! provider at startup (typically wrapping `FdTokenClient`) via
//! [`set_broker_fs_provider`]. Shim code that needs to issue
//! `RegisterOfd` / `CloneOfd` over the fd-token-socket retrieves
//! the provider via [`broker_fs_provider`]; the result is `None`
//! when no broker is available (e.g., the standalone test build
//! that doesn't wire a runner), letting callers fall back to the
//! legacy in-process FS path.

use alloc::sync::Arc;
use litebox_common_linux::broker_fs_provider::BrokerFsProvider;

static BROKER_FS_PROVIDER: once_cell::race::OnceBox<Arc<dyn BrokerFsProvider>> =
    once_cell::race::OnceBox::new();

pub fn set_broker_fs_provider(
    provider: Arc<dyn BrokerFsProvider>,
) -> Result<(), alloc::boxed::Box<Arc<dyn BrokerFsProvider>>> {
    BROKER_FS_PROVIDER.set(alloc::boxed::Box::new(provider))
}

pub fn broker_fs_provider() -> Option<Arc<dyn BrokerFsProvider>> {
    BROKER_FS_PROVIDER.get().cloned()
}
