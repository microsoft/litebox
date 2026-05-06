// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Typed agent identifiers and capability handles.
//!
//! The integration test harness drives a tree of long-lived agent
//! processes spawned by the coordinator (A, AA, AB, AAA, AAB, B, NP,
//! NPC, D3, D4, D5). To prevent tests from referring to agents they
//! didn't declare at registration time, the *only* way to talk to an
//! agent is via an [`AgentHandle`] obtained from
//! [`RegistrationContext::require`]. There is no public constructor
//! for `AgentHandle`, no accessor that returns the underlying name,
//! and no `&str`-based `send` overload reachable from tests. This
//! makes under-declaration a compile error, not a runtime check.
//!
//! The coordinator-internal mapping `AgentHandle -> &'static str`
//! lives in this module and is `pub(super)`, accessible only to the
//! `coordinator` module.

use std::fmt;

/// All agents the coordinator may spawn. The name of each variant is
/// the wire-level agent identifier as it appears in test ids and in
/// the protocol's `Forward { target, .. }` field.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum AgentName {
    /// The coordinator process itself (local `init` target).
    Init,
    A,
    AA,
    AB,
    AAA,
    AAB,
    B,
    NP,
    NPC,
    D3,
    D4,
    D5,
    /// Subtree-kill ephemeral root. Spawned as a direct child of the
    /// coordinator (like A, B) and intended to be SIGKILLed by the
    /// SK.subtree.* tests. Per-Trial docker isolation guarantees no
    /// pollution across tests.
    E,
    /// Direct child of `E`. Used by `SK.subtree.deep_nonpie` to test
    /// non-PIE descendants two levels deep.
    EE,
}

impl AgentName {
    /// Wire-level name used in protocol commands.
    pub const fn name(self) -> &'static str {
        match self {
            AgentName::Init => "init",
            AgentName::A => "A",
            AgentName::AA => "AA",
            AgentName::AB => "AB",
            AgentName::AAA => "AAA",
            AgentName::AAB => "AAB",
            AgentName::B => "B",
            AgentName::NP => "NP",
            AgentName::NPC => "NPC",
            AgentName::D3 => "D3",
            AgentName::D4 => "D4",
            AgentName::D5 => "D5",
            AgentName::E => "E",
            AgentName::EE => "EE",
        }
    }

    /// The chain of agents that must already exist for `self` to be
    /// reachable. For A and B this is empty; for D5 it is
    /// `[A, AA, D3, D4]`. Used by `spawn_tree` to expand a per-test
    /// declared set into the full set of agents that must be alive.
    pub const fn ancestors(self) -> &'static [AgentName] {
        match self {
            AgentName::Init | AgentName::A | AgentName::B => &[],
            AgentName::AA | AgentName::AB => &[AgentName::A],
            AgentName::AAA | AgentName::AAB => &[AgentName::A, AgentName::AA],
            AgentName::NP => &[AgentName::A],
            AgentName::NPC => &[AgentName::A, AgentName::NP],
            AgentName::D3 => &[AgentName::A, AgentName::AA],
            AgentName::D4 => &[AgentName::A, AgentName::AA, AgentName::D3],
            AgentName::D5 => &[AgentName::A, AgentName::AA, AgentName::D3, AgentName::D4],
            AgentName::E => &[],
            AgentName::EE => &[AgentName::E],
        }
    }
}

impl fmt::Display for AgentName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// Capability to send commands to a specific agent.
///
/// Cloneable so a registration closure can capture multiple copies
/// for use across nested async tasks. Constructed only by
/// [`RegistrationContext::require`].
#[derive(Clone, Debug)]
pub struct AgentHandle {
    pub(super) name: AgentName,
}

impl AgentHandle {
    /// Internal accessor; visible to the coordinator module only.
    pub(super) fn name(&self) -> AgentName {
        self.name
    }
}
