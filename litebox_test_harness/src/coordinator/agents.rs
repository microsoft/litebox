// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Typed agent identifiers and capability handles.
//!
//! The integration test harness drives a tree of long-lived agent
//! processes spawned by the coordinator (A, AA, AB, AAA, AAB, B, BB, NP,
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
#[allow(clippy::upper_case_acronyms)] // NPC, AAA, AAB are wire-protocol names.
pub enum AgentName {
    /// The coordinator process itself (local `init` target).
    Init,
    A,
    AA,
    AB,
    AAA,
    AAB,
    B,
    BB,
    NP,
    NPC,
    D3,
    D4,
    D5,
    /// Subtree-kill ephemeral root. Spawned as a direct child of the
    /// coordinator (like A, B) and intended to be `SIGKILLed` by the
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
            AgentName::BB => "BB",
            AgentName::NP => "NP",
            AgentName::NPC => "NPC",
            AgentName::D3 => "D3",
            AgentName::D4 => "D4",
            AgentName::D5 => "D5",
            AgentName::E => "E",
            AgentName::EE => "EE",
        }
    }

    /// Inverse of `name()` — looks up a static `AgentName` from the
    /// wire-level identifier. Returns `None` for unknown names
    /// (e.g., ephemeral child labels like `R`, `R2`, `NPx`).
    pub(super) fn from_wire(name: &str) -> Option<Self> {
        match name {
            "init" => Some(AgentName::Init),
            "A" => Some(AgentName::A),
            "AA" => Some(AgentName::AA),
            "AB" => Some(AgentName::AB),
            "AAA" => Some(AgentName::AAA),
            "AAB" => Some(AgentName::AAB),
            "B" => Some(AgentName::B),
            "BB" => Some(AgentName::BB),
            "NP" => Some(AgentName::NP),
            "NPC" => Some(AgentName::NPC),
            "D3" => Some(AgentName::D3),
            "D4" => Some(AgentName::D4),
            "D5" => Some(AgentName::D5),
            "E" => Some(AgentName::E),
            "EE" => Some(AgentName::EE),
            _ => None,
        }
    }

    /// The chain of agents that must already exist for `self` to be
    /// reachable. For A and B this is empty; for D5 it is
    /// `[A, AA, D3, D4]`. Used by `spawn_tree` to expand a per-test
    /// declared set into the full set of agents that must be alive.
    #[allow(clippy::match_same_arms)] // Each variant is intentionally distinct even if some chains coincide.
    pub const fn ancestors(self) -> &'static [AgentName] {
        match self {
            AgentName::Init | AgentName::A | AgentName::B => &[],
            AgentName::AA | AgentName::AB => &[AgentName::A],
            AgentName::BB => &[AgentName::B],
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

    /// Direct parent in the canonical spawn tree, or `None` for
    /// top-level agents (direct children of the coordinator).
    #[allow(dead_code)] // Used by tree migration as callers shift
    // from hard-coded routing to spec-driven.
    pub const fn parent(self) -> Option<AgentName> {
        match self {
            AgentName::Init | AgentName::A | AgentName::B | AgentName::E => None,
            AgentName::AA | AgentName::AB | AgentName::NP => Some(AgentName::A),
            AgentName::BB => Some(AgentName::B),
            AgentName::AAA | AgentName::AAB | AgentName::D3 => Some(AgentName::AA),
            AgentName::NPC => Some(AgentName::NP),
            AgentName::D4 => Some(AgentName::D3),
            AgentName::D5 => Some(AgentName::D4),
            AgentName::EE => Some(AgentName::E),
        }
    }
}

/// Whether a spawned agent is part of the standard tree (the
/// coordinator expects it to stay alive for the whole run) or a
/// disposable subtree (the SK family `SIGKILL`s these and the
/// coordinator should not flag the disappearance).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum IsolationKind {
    Standard,
    DisposableSubtree,
}

/// Binary-type axis a spawned agent runs as. Mirrors
/// [`crate::BinaryType`] but kept here to avoid a public module
/// re-export. The two enums are kept in sync by the From/Into impls
/// on the coordinator side.
///
/// The coordinator translates `Pie` to `Command::Spawn`, `NonPie` to
/// `Command::SpawnRemote`, and the static-PIE / musl variants to the
/// appropriate binary-type-bridged spawn path.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[allow(dead_code)] // Static-PIE / musl variants are referenced as the
// tree migrates per-test-family from hard-coded
// NP/D3-D5 callers to spec-driven binary types.
pub enum AgentBinary {
    Pie,
    NonPie,
    StaticPieGlibc,
    StaticPieMusl,
    NonPieStaticMusl,
}

/// Declarative spec for one agent in the canonical spawn tree.
///
/// `spawn_tree` walks the list of specs in topological order
/// (parents before children) and spawns each via the appropriate
/// `Command::Spawn` / `Command::SpawnRemote` (wrapped in `Forward`s
/// to reach non-direct ancestors as needed).
#[derive(Clone, Debug)]
pub struct AgentSpec {
    pub name: AgentName,
    pub parent: Option<AgentName>,
    pub binary: AgentBinary,
    /// Whether the SK family considers this agent disposable. Read
    /// by the validator (added in a follow-up wave); allow-dead in
    /// the meantime.
    #[allow(dead_code)]
    pub isolation: IsolationKind,
}

/// The default agent tree the coordinator can spawn from. Each entry
/// records a structural agent name plus its binary type and
/// isolation flavor. `spawn_tree` filters by which agents the running
/// test set actually needs.
///
/// **Legacy names retained as compatibility shims.** `NP`/`NPC`/`D3`/
/// `D4`/`D5` are spelled out here with their original
/// (parent, binary) tuples so callers continue to compile without
/// change while individual coordinator files migrate to the
/// pure-structural taxonomy. Once all callers are migrated, these
/// entries (and the corresponding enum variants) are removed.
#[must_use]
pub fn default_tree() -> Vec<AgentSpec> {
    use AgentBinary::{NonPie, Pie};
    use IsolationKind::{DisposableSubtree, Standard};

    vec![
        // ── Standard-tree top level ─────────────────────────────────
        AgentSpec {
            name: AgentName::A,
            parent: None,
            binary: Pie,
            isolation: Standard,
        },
        AgentSpec {
            name: AgentName::B,
            parent: None,
            binary: Pie,
            isolation: Standard,
        },
        // ── Standard-tree depth-2 ───────────────────────────────────
        AgentSpec {
            name: AgentName::AA,
            parent: Some(AgentName::A),
            binary: Pie,
            isolation: Standard,
        },
        AgentSpec {
            name: AgentName::AB,
            parent: Some(AgentName::A),
            binary: Pie,
            isolation: Standard,
        },
        AgentSpec {
            name: AgentName::BB,
            parent: Some(AgentName::B),
            binary: Pie,
            isolation: Standard,
        },
        // ── Standard-tree depth-3 ───────────────────────────────────
        AgentSpec {
            name: AgentName::AAA,
            parent: Some(AgentName::AA),
            binary: Pie,
            isolation: Standard,
        },
        AgentSpec {
            name: AgentName::AAB,
            parent: Some(AgentName::AA),
            binary: Pie,
            isolation: Standard,
        },
        // ── Disposable subtree (SK family SIGKILLs these) ───────────
        AgentSpec {
            name: AgentName::E,
            parent: None,
            binary: Pie,
            isolation: DisposableSubtree,
        },
        AgentSpec {
            name: AgentName::EE,
            parent: Some(AgentName::E),
            binary: Pie,
            isolation: DisposableSubtree,
        },
        // ── Legacy compat shims (to be migrated) ────────────────────
        AgentSpec {
            name: AgentName::NP,
            parent: Some(AgentName::A),
            binary: NonPie,
            isolation: Standard,
        },
        AgentSpec {
            name: AgentName::NPC,
            parent: Some(AgentName::NP),
            binary: Pie,
            isolation: Standard,
        },
        AgentSpec {
            name: AgentName::D3,
            parent: Some(AgentName::AA),
            binary: Pie,
            isolation: Standard,
        },
        AgentSpec {
            name: AgentName::D4,
            parent: Some(AgentName::D3),
            binary: NonPie,
            isolation: Standard,
        },
        AgentSpec {
            name: AgentName::D5,
            parent: Some(AgentName::D4),
            binary: Pie,
            isolation: Standard,
        },
    ]
}

/// Look up an `AgentSpec` by name in the default tree. Returns
/// `None` for `Init` (which is the coordinator itself, not a spawned
/// agent).
#[must_use]
pub fn agent_spec(name: AgentName) -> Option<AgentSpec> {
    default_tree().into_iter().find(|s| s.name == name)
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

/// How an ephemeral child agent is materialized at runtime. Selected
/// at registration time so the lazy matrix knows whether non-PIE
/// infrastructure must be brought up.
#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(dead_code)] // `Pie` is intentional API surface; no current consumer.
pub enum SpawnKind {
    /// PIE child via `Command::Spawn { children: vec![label] }`.
    Pie,
    /// Non-PIE child via `Command::SpawnRemote { children: vec![label] }`.
    /// Implies the lazy matrix must spawn the non-PIE infrastructure.
    NonPie,
    /// `Command::Fork { name, binary, inherit_listen_ports }`. Used by
    /// `port_router`. `binary` is `"self"` (PIE) or `"nonpie"`.
    /// Inheriting non-empty `inherit_listen_ports` requires non-PIE
    /// infra only when `binary == "nonpie"`.
    Fork {
        binary: &'static str,
        inherit_listen_ports: Vec<u16>,
    },
}

impl SpawnKind {
    /// Whether this kind requires the non-PIE subtree to be spawned
    /// up front (so the broker has the rewritten non-PIE binary
    /// cached and the host worker is ready).
    pub(super) fn needs_nonpie(&self) -> bool {
        match self {
            SpawnKind::Pie => false,
            SpawnKind::NonPie => true,
            SpawnKind::Fork { binary, .. } => *binary == "nonpie",
        }
    }
}

/// Capability to send commands to an ephemeral child agent that the
/// test will spawn under a static parent at runtime. Distinct from
/// [`AgentHandle`] because the runner does not own the process —
/// lifecycle (spawn / Exit / SIGKILL) is driven by routed commands
/// through the parent.
///
/// Constructed only by [`RegistrationContext::declare_ephemeral`].
/// The wire-level label and parent are private; tests can only use
/// the handle through [`crate::coordinator::run_context::RunContext`]
/// methods that take `&EphemeralHandle`.
#[derive(Clone, Debug)]
pub struct EphemeralHandle {
    pub(super) parent: AgentName,
    pub(super) label: String,
    pub(super) kind: SpawnKind,
}

impl EphemeralHandle {
    pub(super) fn parent(&self) -> AgentName {
        self.parent
    }
    pub(super) fn label(&self) -> &str {
        &self.label
    }
    pub(super) fn kind(&self) -> &SpawnKind {
        &self.kind
    }
}
