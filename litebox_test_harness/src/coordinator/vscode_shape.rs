// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Semantic coordinator topology for VS Code Server shape canaries.
//!
//! Hosts the `VS.shape.*` family (full VS Code Server process-tree topology)
//! and the `CSM.*` family (CLI Startup Mimic — VS Code CLI link-mode startup
//! shape).

use serde::{Deserialize, Serialize};

use super::TestOutcome;
use super::agents::{AgentBinary, AgentName, AgentSpec, IsolationKind, SpawnKind};
use super::registry::Registry;
use crate::handlers::{HandlerCtx, HandlerError, HandlerToken};
use crate::register_handler;

// ═══════════════════════════════════════════════════════════════════
// CSM: CLI Startup Mimic — VS Code CLI link-mode startup shape
// ═══════════════════════════════════════════════════════════════════

#[derive(Serialize, Deserialize, Debug)]
struct CliStartupMimicArgs {}

const CLI_STARTUP_MIMIC: HandlerToken<CliStartupMimicArgs, super::common::DetailOut> =
    HandlerToken::new("platform_fixes.cli_startup_mimic");

async fn handle_cli_startup_mimic(
    _args: CliStartupMimicArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<super::common::DetailOut, HandlerError> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|e| HandlerError::from(format!("bind cli startup mimic listener: {e}")))?;
    let addr = listener
        .local_addr()
        .map_err(|e| HandlerError::from(format!("listener addr: {e}")))?;
    Ok(super::common::DetailOut {
        detail: format!("CLI_STARTUP_MIMIC_OK {addr}"),
    })
}

const CSM_DELIVERIES: &[&str] = &["tokio_pipe", "bash_heredoc_pipe"];

pub(crate) fn register_cli_startup_mimic_tests(reg: &mut Registry<'_>) {
    register_handler!(CLI_STARTUP_MIMIC, handle_cli_startup_mimic);

    for &delivery in CSM_DELIVERIES {
        for &bt in crate::BinaryType::ALL {
            for &agent in super::common::CANARY_AGENTS {
                let agent_s = agent.to_string();
                let bt_label = bt.label();
                let test_id = format!("CSM.{delivery}.{bt_label}.{agent}");
                reg.test("fork", "cli_startup_mimic", test_id)
                    .timeout(60)
                    .build(move |cx| {
                        let leaf = cx.declare_ephemeral(
                            agent,
                            format!("CliStartupMimic_{delivery}_{bt_label}_{agent}"),
                            SpawnKind::Fork {
                                binary: super::common::fork_binary_label(bt),
                                inherit_listen_ports: vec![],
                            },
                        );
                        Box::new(move |run| {
                            let a = agent_s.clone();
                            Box::pin(async move {
                                let result = run
                                    .run_leaf(&leaf, &CLI_STARTUP_MIMIC, CliStartupMimicArgs {})
                                    .await;
                                let pass = matches!(&result, Ok(out) if out.detail.contains("CLI_STARTUP_MIMIC_OK"));
                                TestOutcome::new(&a, pass, format!("{result:?}"))
                            })
                        })
                    });
            }
        }
    }
}

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

#[derive(Serialize, Deserialize)]
struct PidOut {
    pid: u32,
}

const GET_PID: HandlerToken<(), PidOut> = HandlerToken::new("vscode_shape.get_pid");

async fn handle_get_pid(_args: (), _ctx: &mut HandlerCtx<'_>) -> Result<PidOut, HandlerError> {
    Ok(PidOut {
        pid: std::process::id(),
    })
}

pub(super) fn register_vscode_shape_tests(reg: &mut Registry<'_>) {
    register_handler!(GET_PID, handle_get_pid);

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
                        match run.send_named_typed(handle, &GET_PID, ()).await {
                            Ok(out) if out.pid > 0 => {}
                            Ok(out) => {
                                return TestOutcome::new(
                                    agent.name(),
                                    false,
                                    format!("non-positive pid {}", out.pid),
                                );
                            }
                            Err(e) => {
                                return TestOutcome::new(agent.name(), false, format!("{e:?}"));
                            }
                        }
                    }

                    TestOutcome::new("vscode_shape", true, "all agents responded")
                })
            })
        });
}
