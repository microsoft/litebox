// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Semantic coordinator topology for VS Code Server shape canaries.

use super::TestOutcome;
use super::agents::{AgentBinary, AgentName, AgentSpec, IsolationKind};
use super::registry::Registry;
use crate::protocol::{Command, Response};

/// Semantic agents in the VS Code Server process-tree shape.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum VsCodeAgent {
    SshdPty,
    LoginBash,
    PipedSh,
    LauncherBash,
    Cli,
    Node,
}

impl VsCodeAgent {
    /// Wire-level name used in protocol commands.
    pub const fn name(self) -> &'static str {
        match self {
            Self::SshdPty => "vscode_sshd_pty",
            Self::LoginBash => "vscode_login_bash",
            Self::PipedSh => "vscode_piped_sh",
            Self::LauncherBash => "vscode_launcher_bash",
            Self::Cli => "vscode_cli",
            Self::Node => "vscode_node",
        }
    }
}

impl From<VsCodeAgent> for AgentName {
    fn from(agent: VsCodeAgent) -> Self {
        match agent {
            VsCodeAgent::SshdPty => Self::VsCodeSshdPty,
            VsCodeAgent::LoginBash => Self::VsCodeLoginBash,
            VsCodeAgent::PipedSh => Self::VsCodePipedSh,
            VsCodeAgent::LauncherBash => Self::VsCodeLauncherBash,
            VsCodeAgent::Cli => Self::VsCodeCli,
            VsCodeAgent::Node => Self::VsCodeNode,
        }
    }
}

/// Return the canonical VS Code Server process-shape specs in topological order.
#[must_use]
pub fn vscode_tree_specs() -> Vec<AgentSpec> {
    use AgentBinary::{NonPie, Pie, StaticPieMusl};
    use IsolationKind::Standard;

    vec![
        AgentSpec {
            name: AgentName::VsCodeSshdPty,
            parent: None,
            binary: Pie,
            isolation: Standard,
        },
        AgentSpec {
            name: AgentName::VsCodeLoginBash,
            parent: Some(AgentName::VsCodeSshdPty),
            binary: NonPie,
            isolation: Standard,
        },
        AgentSpec {
            name: AgentName::VsCodePipedSh,
            parent: Some(AgentName::VsCodeLoginBash),
            binary: NonPie,
            isolation: Standard,
        },
        AgentSpec {
            name: AgentName::VsCodeLauncherBash,
            parent: Some(AgentName::VsCodePipedSh),
            binary: NonPie,
            isolation: Standard,
        },
        AgentSpec {
            name: AgentName::VsCodeCli,
            parent: Some(AgentName::VsCodeLauncherBash),
            // VS Code's `cli-alpine-x64` distribution: static-PIE
            // linked against musl, no PT_INTERP. Confirmed via
            // `readelf` of /root/.vscode-server/code-<commit>.
            binary: StaticPieMusl,
            isolation: Standard,
        },
        AgentSpec {
            name: AgentName::VsCodeNode,
            parent: Some(AgentName::VsCodeCli),
            // VS Code Server's bundled Node.js is the standard
            // linux-x64 distribution: ET_EXEC, dynamically linked,
            // INTERP=/lib64/ld-linux-x86-64.so.2 (NonPieGlibc).
            // Confirmed via readelf on
            // /root/.vscode-server/cli/servers/Stable-<commit>/server/node
            // and strace evidence (access("/etc/ld.so.preload")
            // immediately after execve).
            binary: NonPie,
            isolation: Standard,
        },
    ]
}

pub(super) fn register_vscode_shape_tests(reg: &mut Registry<'_>) {
    reg.test("vscode", "shape", "VS.shape.smoke")
        .timeout(60)
        .build(|cx| {
            let sshd_pty = cx.require(VsCodeAgent::SshdPty);
            let login_bash = cx.require(VsCodeAgent::LoginBash);
            let piped_sh = cx.require(VsCodeAgent::PipedSh);
            let launcher_bash = cx.require(VsCodeAgent::LauncherBash);
            let cli = cx.require(VsCodeAgent::Cli);
            let node = cx.require(VsCodeAgent::Node);
            Box::new(move |run| {
                Box::pin(async move {
                    let agents = [
                        (VsCodeAgent::SshdPty, sshd_pty),
                        (VsCodeAgent::LoginBash, login_bash),
                        (VsCodeAgent::PipedSh, piped_sh),
                        (VsCodeAgent::LauncherBash, launcher_bash),
                        (VsCodeAgent::Cli, cli),
                        (VsCodeAgent::Node, node),
                    ];

                    for (agent, handle) in &agents {
                        let resp = run.send(handle, Command::GetPid).await;
                        if !matches!(resp, Response::Ok { data: Some(_) }) {
                            return TestOutcome::new(agent.name(), false, format!("{resp:?}"));
                        }
                    }

                    TestOutcome::new("vscode_shape", true, "all agents responded")
                })
            })
        });
}
