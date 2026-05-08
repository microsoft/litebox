// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Typed agent identifiers and capability handles.
//!
//! The integration test harness drives a tree of long-lived agent
//! processes spawned by the coordinator. Agent names encode the binary
//! type at every hop (`dpg` = dynamic PIE glibc, `dng` = dynamic
//! non-PIE glibc) plus an ordinal when there are multiple siblings of
//! the same binary type. To prevent tests from referring to agents they
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

/// All agents the coordinator may spawn. The name of each variant maps
/// to the wire-level agent identifier used in test ids and in the
/// protocol's `Forward { target, .. }` field.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum AgentName {
    /// The coordinator process itself (local `init` target).
    Init,
    Dpg1,
    Dpg1Dpg1,
    Dpg1Dpg2,
    Dpg1Dpg1Dpg1,
    Dpg1Dpg1Dpg2,
    Dpg2,
    Dpg2Dpg,
    Dpg1Dng,
    Dpg1DngDpg,
    /// Static-PIE-glibc child of `Dpg1`. Long-lived agent that
    /// exercises **static-PIE-glibc as a forking parent** in the
    /// matrix. Static-PIE-glibc binaries still load `ld.so` at
    /// runtime for nss/dlopen, so the parent-side syscall
    /// instrumentation differs from both ordinary PIE-glibc (which
    /// uses ld.so for everything) and from static-PIE-musl (which
    /// has no ld.so at all). Without this slot, every fan-out test
    /// would only ever fork from PIE-glibc / non-PIE-glibc parents.
    Dpg1Spg,
    /// Static-PIE-musl child of `Dpg1`. Long-lived agent that
    /// exercises **static-PIE-musl as a forking parent** in the
    /// matrix. This is the same binary form as VS Code's `cli`
    /// (`code-alpine-x64`). Truly static, no `PT_INTERP`. Without
    /// this slot, only `VS.shape.smoke` exercises StaticPieMusl as
    /// a parent — everything else only execs into it as a child.
    Dpg1Spm,
    /// Non-PIE static-musl child of `Dpg1`. Long-lived agent for
    /// **non-PIE-static-musl as a forking parent**. Combines the
    /// fixed-load address constraint of non-PIE with the
    /// no-ld.so / variant-I-TLS regime of musl-static — a
    /// combination not exercised by any other slot.
    Dpg1Snm,
    /// Subtree-kill ephemeral root. Spawned as a direct child of the
    /// coordinator (like `Dpg1`, `Dpg2`) and intended to be `SIGKILLed`
    /// by the SK.subtree.* tests. Per-Trial docker isolation guarantees
    /// no pollution across tests.
    Dpg3,
    /// Direct child of `Dpg3`. Used by `SK.subtree.deep_nonpie` to test
    /// descendants two levels deep.
    Dpg3Dpg,
    VsCodeSshdPty,
    VsCodeLoginBash,
    VsCodePipedSh,
    VsCodeLauncherBash,
    VsCodeCli,
    VsCodeNode,
}

impl AgentName {
    /// Wire-level name used in protocol commands.
    pub const fn name(self) -> &'static str {
        match self {
            AgentName::Init => "init",
            AgentName::Dpg1 => "dpg1",
            AgentName::Dpg2 => "dpg2",
            AgentName::Dpg3 => "dpg3",
            AgentName::Dpg1Dpg1 => "dpg1_dpg1",
            AgentName::Dpg1Dpg2 => "dpg1_dpg2",
            AgentName::Dpg1Dng => "dpg1_dng",
            AgentName::Dpg1Dpg1Dpg1 => "dpg1_dpg1_dpg1",
            AgentName::Dpg1Dpg1Dpg2 => "dpg1_dpg1_dpg2",
            AgentName::Dpg1DngDpg => "dpg1_dng_dpg",
            AgentName::Dpg1Spg => "dpg1_spg",
            AgentName::Dpg1Spm => "dpg1_spm",
            AgentName::Dpg1Snm => "dpg1_snm",
            AgentName::Dpg2Dpg => "dpg2_dpg",
            AgentName::Dpg3Dpg => "dpg3_dpg",
            AgentName::VsCodeSshdPty => "vscode_sshd_pty",
            AgentName::VsCodeLoginBash => "vscode_login_bash",
            AgentName::VsCodePipedSh => "vscode_piped_sh",
            AgentName::VsCodeLauncherBash => "vscode_launcher_bash",
            AgentName::VsCodeCli => "vscode_cli",
            AgentName::VsCodeNode => "vscode_node",
        }
    }

    /// Inverse of `name()` — looks up a static `AgentName` from the
    /// wire-level identifier. Returns `None` for unknown names
    /// (e.g., ephemeral child labels like `R`, `R2`, `NPx`).
    pub(super) fn from_wire(name: &str) -> Option<Self> {
        match name {
            "init" => Some(AgentName::Init),
            "dpg1" => Some(AgentName::Dpg1),
            "dpg2" => Some(AgentName::Dpg2),
            "dpg3" => Some(AgentName::Dpg3),
            "dpg1_dpg1" => Some(AgentName::Dpg1Dpg1),
            "dpg1_dpg2" => Some(AgentName::Dpg1Dpg2),
            "dpg1_dng" => Some(AgentName::Dpg1Dng),
            "dpg1_dpg1_dpg1" => Some(AgentName::Dpg1Dpg1Dpg1),
            "dpg1_dpg1_dpg2" => Some(AgentName::Dpg1Dpg1Dpg2),
            "dpg1_dng_dpg" => Some(AgentName::Dpg1DngDpg),
            "dpg1_spg" => Some(AgentName::Dpg1Spg),
            "dpg1_spm" => Some(AgentName::Dpg1Spm),
            "dpg1_snm" => Some(AgentName::Dpg1Snm),
            "dpg2_dpg" => Some(AgentName::Dpg2Dpg),
            "dpg3_dpg" => Some(AgentName::Dpg3Dpg),
            "vscode_sshd_pty" => Some(AgentName::VsCodeSshdPty),
            "vscode_login_bash" => Some(AgentName::VsCodeLoginBash),
            "vscode_piped_sh" => Some(AgentName::VsCodePipedSh),
            "vscode_launcher_bash" => Some(AgentName::VsCodeLauncherBash),
            "vscode_cli" => Some(AgentName::VsCodeCli),
            "vscode_node" => Some(AgentName::VsCodeNode),
            _ => None,
        }
    }

    /// The chain of agents that must already exist for `self` to be
    /// reachable. For `Dpg1` and `Dpg2` this is empty; for
    /// `Dpg1Dpg1Dpg1DngDpg` it is
    /// `[Dpg1, Dpg1Dng]`. Used by `spawn_tree` to expand a per-test
    /// declared set into the full set of agents that must be alive.
    pub const fn ancestors(self) -> &'static [AgentName] {
        match self {
            AgentName::Init
            | AgentName::Dpg1
            | AgentName::Dpg2
            | AgentName::Dpg3
            | AgentName::VsCodeSshdPty => &[],
            AgentName::Dpg1Dpg1 | AgentName::Dpg1Dpg2 | AgentName::Dpg1Dng => &[AgentName::Dpg1],
            AgentName::Dpg1Spg | AgentName::Dpg1Spm | AgentName::Dpg1Snm => &[AgentName::Dpg1],
            AgentName::Dpg2Dpg => &[AgentName::Dpg2],
            AgentName::Dpg3Dpg => &[AgentName::Dpg3],
            AgentName::Dpg1Dpg1Dpg1 | AgentName::Dpg1Dpg1Dpg2 => {
                &[AgentName::Dpg1, AgentName::Dpg1Dpg1]
            }
            AgentName::Dpg1DngDpg => &[AgentName::Dpg1, AgentName::Dpg1Dng],
            AgentName::VsCodeLoginBash => &[AgentName::VsCodeSshdPty],
            AgentName::VsCodePipedSh => &[AgentName::VsCodeSshdPty, AgentName::VsCodeLoginBash],
            AgentName::VsCodeLauncherBash => &[
                AgentName::VsCodeSshdPty,
                AgentName::VsCodeLoginBash,
                AgentName::VsCodePipedSh,
            ],
            AgentName::VsCodeCli => &[
                AgentName::VsCodeSshdPty,
                AgentName::VsCodeLoginBash,
                AgentName::VsCodePipedSh,
                AgentName::VsCodeLauncherBash,
            ],
            AgentName::VsCodeNode => &[
                AgentName::VsCodeSshdPty,
                AgentName::VsCodeLoginBash,
                AgentName::VsCodePipedSh,
                AgentName::VsCodeLauncherBash,
                AgentName::VsCodeCli,
            ],
        }
    }

    /// Direct parent in the canonical spawn tree, or `None` for
    /// top-level agents (direct children of the coordinator).
    #[allow(dead_code)] // Used by tree migration as callers shift from hard-coded routing to spec-driven.
    pub const fn parent(self) -> Option<AgentName> {
        match self {
            AgentName::Init
            | AgentName::Dpg1
            | AgentName::Dpg2
            | AgentName::Dpg3
            | AgentName::VsCodeSshdPty => None,
            AgentName::Dpg1Dpg1 | AgentName::Dpg1Dpg2 | AgentName::Dpg1Dng => Some(AgentName::Dpg1),
            AgentName::Dpg1Spg | AgentName::Dpg1Spm | AgentName::Dpg1Snm => Some(AgentName::Dpg1),
            AgentName::Dpg2Dpg => Some(AgentName::Dpg2),
            AgentName::Dpg3Dpg => Some(AgentName::Dpg3),
            AgentName::Dpg1Dpg1Dpg1 | AgentName::Dpg1Dpg1Dpg2 => Some(AgentName::Dpg1Dpg1),
            AgentName::Dpg1DngDpg => Some(AgentName::Dpg1Dng),
            AgentName::VsCodeLoginBash => Some(AgentName::VsCodeSshdPty),
            AgentName::VsCodePipedSh => Some(AgentName::VsCodeLoginBash),
            AgentName::VsCodeLauncherBash => Some(AgentName::VsCodePipedSh),
            AgentName::VsCodeCli => Some(AgentName::VsCodeLauncherBash),
            AgentName::VsCodeNode => Some(AgentName::VsCodeCli),
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

impl AgentBinary {
    pub(super) const fn needs_companion_binary(self) -> bool {
        !matches!(self, Self::Pie)
    }

    pub(super) const fn fork_binary_label(self) -> &'static str {
        match self {
            Self::Pie => "self",
            Self::NonPie => "nonpie",
            Self::StaticPieGlibc => "static-pie-glibc",
            Self::StaticPieMusl => "static-pie-musl",
            Self::NonPieStaticMusl => "non-pie-static-musl",
        }
    }
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
/// records a structural agent name plus its binary type and isolation
/// flavor. `spawn_tree` filters by which agents the running test set
/// actually needs.
#[must_use]
pub fn default_tree() -> Vec<AgentSpec> {
    use AgentBinary::{NonPie, Pie};
    use IsolationKind::{DisposableSubtree, Standard};

    let mut specs = vec![
        AgentSpec {
            name: AgentName::Dpg1,
            parent: None,
            binary: Pie,
            isolation: Standard,
        },
        AgentSpec {
            name: AgentName::Dpg2,
            parent: None,
            binary: Pie,
            isolation: Standard,
        },
        AgentSpec {
            name: AgentName::Dpg3,
            parent: None,
            binary: Pie,
            isolation: DisposableSubtree,
        },
        AgentSpec {
            name: AgentName::Dpg1Dpg1,
            parent: Some(AgentName::Dpg1),
            binary: Pie,
            isolation: Standard,
        },
        AgentSpec {
            name: AgentName::Dpg1Dpg2,
            parent: Some(AgentName::Dpg1),
            binary: Pie,
            isolation: Standard,
        },
        AgentSpec {
            name: AgentName::Dpg1Dng,
            parent: Some(AgentName::Dpg1),
            binary: NonPie,
            isolation: Standard,
        },
        AgentSpec {
            name: AgentName::Dpg1Dpg1Dpg1,
            parent: Some(AgentName::Dpg1Dpg1),
            binary: Pie,
            isolation: Standard,
        },
        AgentSpec {
            name: AgentName::Dpg1Dpg1Dpg2,
            parent: Some(AgentName::Dpg1Dpg1),
            binary: Pie,
            isolation: Standard,
        },
        AgentSpec {
            name: AgentName::Dpg1DngDpg,
            parent: Some(AgentName::Dpg1Dng),
            binary: Pie,
            isolation: Standard,
        },
        // ── Static-leg parents under Dpg1 ───────────────────────────
        // These slots give every BinaryType leg a long-lived agent so
        // matrix tests (EXEC_AGENTS, NPIPE_AGENTS, EP, US6, …)
        // exercise each binary type as a *forking parent*, not just
        // as an exec child. The shim's syscall instrumentation,
        // vDSO state, and fd-bridge tables live in the parent
        // process, so the parent's binary type matters.
        //
        // Coverage scenarios:
        //   - Dpg1Spg: static-PIE-glibc still loads ld.so for
        //     nss/dlopen at runtime. Distinct from ordinary PIE-glibc
        //     (which is fully dynamic) and from static-PIE-musl
        //     (no ld.so at all).
        //   - Dpg1Spm: same binary form as VS Code's `cli`
        //     (cli-alpine-x64). Truly static, no PT_INTERP. Without
        //     this slot, only VS.shape.smoke exercised StaticPieMusl
        //     as a fork parent.
        //   - Dpg1Snm: non-PIE-static-musl. Combines the fixed-load
        //     address constraint of non-PIE with the no-ld.so /
        //     variant-I-TLS regime of musl-static.
        AgentSpec {
            name: AgentName::Dpg1Spg,
            parent: Some(AgentName::Dpg1),
            binary: AgentBinary::StaticPieGlibc,
            isolation: Standard,
        },
        AgentSpec {
            name: AgentName::Dpg1Spm,
            parent: Some(AgentName::Dpg1),
            binary: AgentBinary::StaticPieMusl,
            isolation: Standard,
        },
        AgentSpec {
            name: AgentName::Dpg1Snm,
            parent: Some(AgentName::Dpg1),
            binary: AgentBinary::NonPieStaticMusl,
            isolation: Standard,
        },
        AgentSpec {
            name: AgentName::Dpg2Dpg,
            parent: Some(AgentName::Dpg2),
            binary: Pie,
            isolation: Standard,
        },
        AgentSpec {
            name: AgentName::Dpg3Dpg,
            parent: Some(AgentName::Dpg3),
            binary: Pie,
            isolation: DisposableSubtree,
        },
    ];
    specs.extend(super::vscode_shape::vscode_tree_specs());
    specs
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
