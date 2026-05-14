// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Broker-hosted process identity (Phase 1: pid allocation only).
//!
//! Each Linux guest process in a sandbox is represented by a
//! [`ProcessState`] entry in the broker's process-only
//! [`BrokerStateRegistry`] instance (sibling to the existing
//! fd-state registry). The [`StateHandle.id()`] of a `Process`-tagged
//! entry IS the globally-unique guest pid — workers receive it via
//! `RegisterProcess` and use the low 32 bits as the Linux pid.
//!
//! # What's in the payload (Phase 1)
//!
//! Nothing. The pid is the StateHandle id; refcount semantics handle
//! the lifetime; per-shim `ProcessRegistry` still owns parent/child
//! links, exit state, and pgrp/session. The empty payload exists so
//! the `StateObject` machinery (subsystem tag check, refcounted
//! drop, future subscription_list integration) works uniformly.
//!
//! # What's coming in later phases
//!
//! - Phase 2 (parent/child links): `parent: Option<StateHandle>`,
//!   `children: Vec<StateHandle>`, plus `SetParent`/`AddChild`/
//!   `RemoveChild` RPCs.
//! - Phase 3 (exit notifications): `exit_state: Option<i32>` plus
//!   a [`crate::subscription_list::SubscriptionList`] so parent
//!   workers can subscribe-on-fork and be woken on exit.
//! - Phase 4 (pgrp/session): `pgid: StateHandle`, `sid: StateHandle`
//!   pointing at sibling `ProcessGroupState` / `SessionState` entries.

use core::any::Any;
use std::sync::Arc;

use litebox_common_linux::fd_transfer_frame::SubsystemTag;

use crate::state_registry::StateObject;

/// Broker-hosted state for one guest process. Phase 1: opaque pid
/// holder; payload extends in subsequent phases (see module doc).
#[derive(Debug, Default)]
pub struct ProcessState {
    // No fields in Phase 1.
}

impl ProcessState {
    pub fn new() -> Self {
        Self::default()
    }

    /// Convenience constructor that wraps the new state in an `Arc`
    /// for direct hand-off to
    /// [`crate::state_registry::BrokerStateRegistry::register`].
    pub fn arc() -> Arc<dyn StateObject + Send + Sync> {
        Arc::new(Self::new())
    }
}

impl StateObject for ProcessState {
    fn subsystem_tag(&self) -> SubsystemTag {
        SubsystemTag::Process
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subsystem_tag_is_process() {
        let s = ProcessState::new();
        assert_eq!(s.subsystem_tag(), SubsystemTag::Process);
    }
}
