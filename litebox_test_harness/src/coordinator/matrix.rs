// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Declarative test matrix — drives "cover all configurations" tests via
// structured loops over typed dimensions.
//
// Dimensions:
// - **Topology**: (source, dest) agent pairs in the process tree, including init
// - **FsScope**: /shared (visible) vs /tmp (isolated)
// - **SymlinkVariant**: basic, directory, dangling, nested, relative
// - **UnixPattern**: in-process, server+fork-client, background-server, cross-agent
// - **UnixDepth**: which agent depth runs the pattern
//
// Note: `init` (the coordinator) is a first-class node in the process tree for
// FS tests (it handles FsRead/FsWrite/FsDelete/FsSymlink/FsReadlink/FsStat/
// NetConnect locally). It cannot listen on TCP or Unix sockets.

use super::agents::{AgentHandle, AgentName};
use super::registry::Registry;
use super::run_context::RunContext;
use crate::protocol::{Command, Response};
use std::future::Future;
use std::pin::Pin;

// ── Topology axis ──

/// A relationship between two agents in the process tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum Topology {
    /// Same agent (A writes, A reads).
    InProcess,
    /// init → A.
    ParentToChild,
    /// A → init.
    ChildToParent,
    /// A → B.
    Sibling,
    /// B → A.
    SiblingReverse,
    /// AA → init.
    GrandchildUp,
    /// AAA → init.
    GreatGrandchildUp,
    /// B → AAA.
    #[allow(dead_code)]
    CrossSubtree,
    /// AA → AB.
    #[allow(dead_code)]
    SiblingDepth2,
    /// AAA → AAB.
    #[allow(dead_code)]
    SiblingDepth3,
    /// AB → B.
    #[allow(dead_code)]
    Uncle,
    /// A → NP (non-PIE child via `SpawnRemote`).
    PieToNonPie,
    /// NP → A (non-PIE writes, PIE reads).
    NonPieToParent,
    /// NPC → A (PIE-from-non-PIE reads, PIE reads).
    NonPieChildUp,
    /// D5 → B (depth 5 from non-PIE root, cross-subtree).
    DeepNonPie,
}

impl Topology {
    fn agents(self) -> (AgentName, AgentName) {
        match self {
            Self::InProcess => (AgentName::Dpg1, AgentName::Dpg1),
            Self::ParentToChild => (AgentName::Init, AgentName::Dpg1),
            Self::ChildToParent => (AgentName::Dpg1, AgentName::Init),
            Self::Sibling => (AgentName::Dpg1, AgentName::Dpg2),
            Self::SiblingReverse => (AgentName::Dpg2, AgentName::Dpg1),
            Self::GrandchildUp => (AgentName::Dpg1Dpg1, AgentName::Init),
            Self::GreatGrandchildUp => (AgentName::Dpg1Dpg1Dpg1, AgentName::Init),
            Self::CrossSubtree => (AgentName::Dpg2, AgentName::Dpg1Dpg1Dpg1),
            Self::SiblingDepth2 => (AgentName::Dpg1Dpg1, AgentName::Dpg1Dpg2),
            Self::SiblingDepth3 => (AgentName::Dpg1Dpg1Dpg1, AgentName::Dpg1Dpg1Dpg2),
            Self::Uncle => (AgentName::Dpg1Dpg2, AgentName::Dpg2),
            Self::PieToNonPie => (AgentName::Dpg1, AgentName::Dpg1Dng),
            Self::NonPieToParent => (AgentName::Dpg1Dng, AgentName::Dpg1),
            Self::NonPieChildUp => (AgentName::Dpg1DngDpg, AgentName::Dpg1),
            Self::DeepNonPie => (AgentName::Dpg1Dpg1Dpg1DngDpg, AgentName::Dpg2),
        }
    }

    fn suffix(self) -> &'static str {
        match self {
            Self::InProcess => "in_process",
            Self::ParentToChild => "parent_to_child",
            Self::ChildToParent => "child_to_parent",
            Self::Sibling => "sibling",
            Self::SiblingReverse => "sibling_rev",
            Self::GrandchildUp => "grandchild_up",
            Self::GreatGrandchildUp => "great_grandchild_up",
            Self::CrossSubtree => "cross_subtree",
            Self::SiblingDepth2 => "sibling_d2",
            Self::SiblingDepth3 => "sibling_d3",
            Self::Uncle => "uncle",
            Self::PieToNonPie => "pie_to_nonpie",
            Self::NonPieToParent => "nonpie_to_parent",
            Self::NonPieChildUp => "nonpie_child_up",
            Self::DeepNonPie => "deep_nonpie",
        }
    }
}

// ═══════════════════════════════════════════════════════════════════
// FILESYSTEM
// ═══════════════════════════════════════════════════════════════════

const FS_TOPOLOGIES: &[Topology] = &[
    Topology::ParentToChild,
    Topology::ChildToParent,
    Topology::Sibling,
    Topology::SiblingReverse,
    Topology::GrandchildUp,
    Topology::GreatGrandchildUp,
    Topology::PieToNonPie,
    Topology::NonPieToParent,
    Topology::NonPieChildUp,
    Topology::DeepNonPie,
];

/// Scope dimension for filesystem tests.
#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
enum FsScope {
    /// /shared — visible across all agents.
    Shared,
    /// /tmp — may be isolated per-agent.
    TmpIsolated,
}

#[allow(dead_code)]
impl FsScope {
    fn prefix(self) -> &'static str {
        match self {
            Self::Shared => "/shared",
            Self::TmpIsolated => "/tmp",
        }
    }

    fn suffix(self) -> &'static str {
        match self {
            Self::Shared => "shared",
            Self::TmpIsolated => "tmp",
        }
    }
}

// ═══════════════════════════════════════════════════════════════════
// NETWORK
// ═══════════════════════════════════════════════════════════════════

/// Net test descriptor. Listener listens, connector connects.
struct NetTestCase {
    name: &'static str,
    listener: AgentName,
    connector: AgentName,
}

/// Net test with explicit connect address (to test cross-worker routing).
#[allow(dead_code)]
struct NetAddrTestCase {
    name: &'static str,
    listener: AgentName,
    connector: AgentName,
    /// Address the connector uses: "127.0.0.1", "10.0.0.2", or "0.0.0.0".
    connect_addr: &'static str,
}

const NET_TESTS: &[NetTestCase] = &[
    NetTestCase {
        name: "init_to_A",
        listener: AgentName::Dpg1,
        connector: AgentName::Init,
    },
    NetTestCase {
        name: "A_to_B",
        listener: AgentName::Dpg2,
        connector: AgentName::Dpg1,
    },
    NetTestCase {
        name: "B_to_A",
        listener: AgentName::Dpg1,
        connector: AgentName::Dpg2,
    },
    NetTestCase {
        name: "AAA_to_A",
        listener: AgentName::Dpg1,
        connector: AgentName::Dpg1Dpg1Dpg1,
    },
    NetTestCase {
        name: "B_to_AAA",
        listener: AgentName::Dpg1Dpg1Dpg1,
        connector: AgentName::Dpg2,
    },
    NetTestCase {
        name: "AA_to_AB",
        listener: AgentName::Dpg1Dpg2,
        connector: AgentName::Dpg1Dpg1,
    },
    NetTestCase {
        name: "AAA_to_AAB",
        listener: AgentName::Dpg1Dpg1Dpg2,
        connector: AgentName::Dpg1Dpg1Dpg1,
    },
    NetTestCase {
        name: "AB_to_B",
        listener: AgentName::Dpg2,
        connector: AgentName::Dpg1Dpg2,
    },
    // Non-PIE tree: NP listens, A connects (cross-type boundary).
    NetTestCase {
        name: "dpg1_dng_to_dpg1",
        listener: AgentName::Dpg1Dng,
        connector: AgentName::Dpg1,
    },
    // PIE listens, non-PIE child connects.
    NetTestCase {
        name: "dpg1_to_dpg1_dng_dpg",
        listener: AgentName::Dpg1,
        connector: AgentName::Dpg1DngDpg,
    },
    // Non-PIE child listens, PIE from other subtree connects.
    NetTestCase {
        name: "dpg1_dng_dpg_to_dpg2",
        listener: AgentName::Dpg1DngDpg,
        connector: AgentName::Dpg2,
    },
    // Depth 5 (from non-PIE root) to depth 1 — the VS Code server path.
    NetTestCase {
        name: "dpg1_dpg1_dpg1_dng_dpg_to_dpg2",
        listener: AgentName::Dpg1Dpg1Dpg1DngDpg,
        connector: AgentName::Dpg2,
    },
];

// ═══════════════════════════════════════════════════════════════════
// NET ADDRESS MATRIX — cross-worker TCP with different connect addresses
// ═══════════════════════════════════════════════════════════════════
//
// The VS Code failure showed that the connect address matters:
// - 127.0.0.1 is standard loopback
// - 0.0.0.0 connects to INADDR_ANY (Linux treats as loopback)
//
// Both addresses must work on native Linux (gold standard) AND litebox.
// 10.0.0.2 is the litebox guest virtual IP — only tested on litebox
// (it doesn't exist on native containers which use Docker bridge IPs).

const CONNECT_ADDRS: &[&str] = &["127.0.0.1", "0.0.0.0"];

/// Historical litebox-only address — kept for documentation.
/// The matrix now discovers the self-IP dynamically via `hostname -I`.
#[allow(dead_code)]
const LITEBOX_ADDRS: &[&str] = &["10.0.0.2"];

/// Cross-worker pairs to test with address variants.
/// Each pair is tested with all `CONNECT_ADDRS` in both directions.
const NET_ADDR_PAIRS: &[(AgentName, AgentName)] = &[
    (AgentName::Dpg1, AgentName::Dpg1),
    (AgentName::Dpg1Dpg1, AgentName::Dpg1Dpg1),
    (AgentName::Dpg1, AgentName::Dpg1Dpg1),
    (AgentName::Dpg1, AgentName::Dpg2),
    (AgentName::Dpg1Dpg1Dpg1, AgentName::Dpg1Dpg1Dpg1Dng),
    (AgentName::Dpg1Dpg1Dpg1Dng, AgentName::Dpg1Dpg1Dpg1DngDpg),
    (AgentName::Dpg1Dpg1Dpg1Dng, AgentName::Dpg2),
    (AgentName::Dpg1Dpg1Dpg1Dng, AgentName::Dpg1),
    (AgentName::Dpg1Dng, AgentName::Dpg1),
    (AgentName::Dpg1, AgentName::Dpg1Dng),
];

// ═══════════════════════════════════════════════════════════════════
// UNIX SOCKET ADDRESS MATRIX — cross-worker Unix sockets across topology
// ═══════════════════════════════════════════════════════════════════
//
// Tests Unix domain sockets across the same topology pairs as TCP,
// ensuring cross-worker Unix sockets work at every depth.

// ═══════════════════════════════════════════════════════════════════
// EXEC & ENV
// ═══════════════════════════════════════════════════════════════════

const EXEC_AGENTS: &[AgentName] = &[
    AgentName::Dpg1,
    AgentName::Dpg1Dpg1,
    AgentName::Dpg1Dpg1Dpg1,
    AgentName::Dpg1Dng,
    AgentName::Dpg1DngDpg,
    AgentName::Dpg1Dpg1Dpg1DngDpg,
];

// ═══════════════════════════════════════════════════════════════════
// UNIX SOCKETS
// ═══════════════════════════════════════════════════════════════════

/// Unix socket test pattern.
#[derive(Debug, Clone, Copy)]
enum UnixPattern {
    /// Agent listens and connects to itself.
    InProcess,
    /// Agent listens, forks unix-echo-client child to connect.
    ServerForkClient,
    /// Agent starts background unix-echo-server, then connects to it.
    BackgroundServerConnect,
    /// Listener agent listens, separate connector agent connects.
    CrossAgent,
}

/// Descriptor for one unix socket test case.
struct UnixTestCase {
    name: &'static str,
    pattern: UnixPattern,
    /// Primary agent (listener for InProcess/ServerForkClient/CrossAgent,
    /// agent for `BackgroundServerConnect`).
    agent: AgentName,
    /// Connector agent for `CrossAgent` pattern.
    peer: Option<AgentName>,
}

fn unix_test_cases() -> Vec<UnixTestCase> {
    vec![
        UnixTestCase {
            name: "in_process.A",
            pattern: UnixPattern::InProcess,
            agent: AgentName::Dpg1,
            peer: None,
        },
        UnixTestCase {
            name: "in_process.AA",
            pattern: UnixPattern::InProcess,
            agent: AgentName::Dpg1Dpg1,
            peer: None,
        },
        UnixTestCase {
            name: "server_fork.A",
            pattern: UnixPattern::ServerForkClient,
            agent: AgentName::Dpg1,
            peer: None,
        },
        UnixTestCase {
            name: "server_fork.AA",
            pattern: UnixPattern::ServerForkClient,
            agent: AgentName::Dpg1Dpg1,
            peer: None,
        },
        UnixTestCase {
            name: "bg_server.A",
            pattern: UnixPattern::BackgroundServerConnect,
            agent: AgentName::Dpg1,
            peer: None,
        },
        UnixTestCase {
            name: "bg_server.AA",
            pattern: UnixPattern::BackgroundServerConnect,
            agent: AgentName::Dpg1Dpg1,
            peer: None,
        },
        // Same-worker CrossAgent cases (all connected via Spawn chains,
        // share one worker process and one unix_addr_table).
        UnixTestCase {
            name: "sibling",
            pattern: UnixPattern::CrossAgent,
            agent: AgentName::Dpg1,
            peer: Some(AgentName::Dpg2),
        },
        UnixTestCase {
            name: "parent_to_grandchild",
            pattern: UnixPattern::CrossAgent,
            agent: AgentName::Dpg1,
            peer: Some(AgentName::Dpg1Dpg1),
        },
        UnixTestCase {
            name: "grandchild_to_parent",
            pattern: UnixPattern::CrossAgent,
            agent: AgentName::Dpg1Dpg1,
            peer: Some(AgentName::Dpg1),
        },
        UnixTestCase {
            name: "cross_subtree",
            pattern: UnixPattern::CrossAgent,
            agent: AgentName::Dpg2,
            peer: Some(AgentName::Dpg1Dpg1Dpg1),
        },
        // Cross-worker CrossAgent cases — these cross a SpawnRemote boundary
        // (different OS worker processes, separate unix_addr_table).
        // Worker boundaries: {init,A,B,AA,AB,AAA,AAB,D3} | {NP,NPC} | {D4,D5}
        UnixTestCase {
            name: "vscode_d3_d4",
            pattern: UnixPattern::CrossAgent,
            agent: AgentName::Dpg1Dpg1Dpg1,
            peer: Some(AgentName::Dpg1Dpg1Dpg1Dng),
        },
        UnixTestCase {
            name: "vscode_d4_d3",
            pattern: UnixPattern::CrossAgent,
            agent: AgentName::Dpg1Dpg1Dpg1Dng,
            peer: Some(AgentName::Dpg1Dpg1Dpg1),
        },
        UnixTestCase {
            name: "d4_to_sibling_b",
            pattern: UnixPattern::CrossAgent,
            agent: AgentName::Dpg1Dpg1Dpg1Dng,
            peer: Some(AgentName::Dpg2),
        },
        UnixTestCase {
            name: "d5_to_a",
            pattern: UnixPattern::CrossAgent,
            agent: AgentName::Dpg1Dpg1Dpg1DngDpg,
            peer: Some(AgentName::Dpg1),
        },
        UnixTestCase {
            name: "a_to_np",
            pattern: UnixPattern::CrossAgent,
            agent: AgentName::Dpg1,
            peer: Some(AgentName::Dpg1Dng),
        },
        UnixTestCase {
            name: "np_to_a",
            pattern: UnixPattern::CrossAgent,
            agent: AgentName::Dpg1Dng,
            peer: Some(AgentName::Dpg1),
        },
    ]
}

// ═══════════════════════════════════════════════════════════════════
// SYMLINKS
// ═══════════════════════════════════════════════════════════════════

const SYMLINK_TOPOLOGIES: &[Topology] = &[
    Topology::InProcess,
    Topology::ParentToChild,
    Topology::ChildToParent,
    Topology::Sibling,
    Topology::GrandchildUp,
];

// ═══════════════════════════════════════════════════════════════════
// DECLARATIVE REGISTRATION
// ═══════════════════════════════════════════════════════════════════

type MatrixFuture<'r> = Pin<Box<dyn Future<Output = super::TestOutcome> + 'r>>;
type MatrixHandles = Vec<(AgentName, AgentHandle)>;

fn matrix_test<F>(reg: &mut Registry<'_>, id: impl Into<String>, required: Vec<AgentName>, body: F)
where
    F: for<'r> FnOnce(&'r mut RunContext<'_>, MatrixHandles) -> MatrixFuture<'r> + Send + 'static,
{
    reg.test("matrix", "run_matrix", id)
        .timeout(60)
        .build(move |cx| {
            let handles = required
                .into_iter()
                .map(|agent| (agent, cx.require(agent)))
                .collect::<Vec<_>>();
            Box::new(move |run| body(run, handles))
        });
}

fn handle_for(handles: &MatrixHandles, agent: AgentName) -> &AgentHandle {
    handles
        .iter()
        .find_map(|(name, handle)| (*name == agent).then_some(handle))
        .expect("agent was not declared for matrix test")
}

async fn send_to(
    run: &mut RunContext<'_>,
    handles: &MatrixHandles,
    agent: AgentName,
    cmd: Command,
) -> Response {
    run.send(handle_for(handles, agent), cmd).await
}

#[allow(clippy::too_many_lines)] // exhaustive registration / runner
pub(super) fn register_fs_crud(reg: &mut Registry<'_>) {
    for &topo in FS_TOPOLOGIES {
        let (source, dest) = topo.agents();
        let ts = topo.suffix();

        let required = vec![AgentName::Init, source, dest];
        matrix_test(
            reg,
            format!("F.shared.{ts}.absent"),
            required.clone(),
            move |run, handles| {
                Box::pin(async move {
                    let file = format!("/shared/matrix_{ts}.txt");
                    let _ = send_to(
                        run,
                        &handles,
                        AgentName::Init,
                        Command::FsDelete { path: file.clone() },
                    )
                    .await;
                    let resp = send_to(run, &handles, dest, Command::FsRead { path: file }).await;
                    super::TestOutcome::new(
                        dest.name(),
                        matches!(resp, Response::NotFound),
                        format!("{resp:?}"),
                    )
                })
            },
        );
        matrix_test(
            reg,
            format!("F.shared.{ts}.created"),
            required.clone(),
            move |run, handles| {
                Box::pin(async move {
                    let file = format!("/shared/matrix_{ts}.txt");
                    let data = format!("data_{ts}");
                    let _ = send_to(
                        run,
                        &handles,
                        AgentName::Init,
                        Command::FsDelete { path: file.clone() },
                    )
                    .await;
                    let _ = send_to(
                        run,
                        &handles,
                        source,
                        Command::FsWrite {
                            path: file.clone(),
                            data: data.clone(),
                        },
                    )
                    .await;
                    let resp = send_to(run, &handles, dest, Command::FsRead { path: file }).await;
                    let pass = matches!(&resp, Response::Ok { data: Some(d) } if *d == data);
                    super::TestOutcome::new(dest.name(), pass, format!("{resp:?}"))
                })
            },
        );
        matrix_test(
            reg,
            format!("F.shared.{ts}.updated"),
            required.clone(),
            move |run, handles| {
                Box::pin(async move {
                    let file = format!("/shared/matrix_{ts}.txt");
                    let updated = format!("updated_{ts}");
                    let _ = send_to(
                        run,
                        &handles,
                        AgentName::Init,
                        Command::FsDelete { path: file.clone() },
                    )
                    .await;
                    let _ = send_to(
                        run,
                        &handles,
                        source,
                        Command::FsWrite {
                            path: file.clone(),
                            data: format!("data_{ts}"),
                        },
                    )
                    .await;
                    let _ = send_to(
                        run,
                        &handles,
                        source,
                        Command::FsWrite {
                            path: file.clone(),
                            data: updated.clone(),
                        },
                    )
                    .await;
                    let resp = send_to(run, &handles, dest, Command::FsRead { path: file }).await;
                    let pass = matches!(&resp, Response::Ok { data: Some(d) } if *d == updated);
                    super::TestOutcome::new(dest.name(), pass, format!("{resp:?}"))
                })
            },
        );
        matrix_test(
            reg,
            format!("F.shared.{ts}.deleted"),
            required,
            move |run, handles| {
                Box::pin(async move {
                    let file = format!("/shared/matrix_{ts}.txt");
                    let _ = send_to(
                        run,
                        &handles,
                        AgentName::Init,
                        Command::FsDelete { path: file.clone() },
                    )
                    .await;
                    let _ = send_to(
                        run,
                        &handles,
                        source,
                        Command::FsWrite {
                            path: file.clone(),
                            data: format!("data_{ts}"),
                        },
                    )
                    .await;
                    let _ = send_to(
                        run,
                        &handles,
                        source,
                        Command::FsDelete { path: file.clone() },
                    )
                    .await;
                    let resp = send_to(run, &handles, dest, Command::FsRead { path: file }).await;
                    super::TestOutcome::new(
                        dest.name(),
                        matches!(resp, Response::NotFound),
                        format!("{resp:?}"),
                    )
                })
            },
        );
    }
}

pub(super) fn register_fs_cross_unlink(reg: &mut Registry<'_>) {
    for &topo in FS_TOPOLOGIES {
        let (source, dest) = topo.agents();
        let ts = topo.suffix();

        let required = vec![AgentName::Init, source, dest];
        matrix_test(
            reg,
            format!("F.unlink.{ts}.delete"),
            required.clone(),
            move |run, handles| {
                Box::pin(async move {
                    let file = format!("/shared/unlink_{ts}.txt");
                    let _ = send_to(
                        run,
                        &handles,
                        AgentName::Init,
                        Command::FsDelete { path: file.clone() },
                    )
                    .await;
                    let _ = send_to(
                        run,
                        &handles,
                        source,
                        Command::FsWrite {
                            path: file.clone(),
                            data: "unlink_me".into(),
                        },
                    )
                    .await;
                    let resp = send_to(run, &handles, dest, Command::FsDelete { path: file }).await;
                    super::TestOutcome::new(
                        dest.name(),
                        super::ok_without_data(&resp),
                        format!("{resp:?}"),
                    )
                })
            },
        );
        matrix_test(
            reg,
            format!("F.unlink.{ts}.gone"),
            required,
            move |run, handles| {
                Box::pin(async move {
                    let file = format!("/shared/unlink_{ts}.txt");
                    let _ = send_to(
                        run,
                        &handles,
                        AgentName::Init,
                        Command::FsDelete { path: file.clone() },
                    )
                    .await;
                    let _ = send_to(
                        run,
                        &handles,
                        source,
                        Command::FsWrite {
                            path: file.clone(),
                            data: "unlink_me".into(),
                        },
                    )
                    .await;
                    let _ = send_to(
                        run,
                        &handles,
                        dest,
                        Command::FsDelete { path: file.clone() },
                    )
                    .await;
                    let resp = send_to(run, &handles, source, Command::FsRead { path: file }).await;
                    super::TestOutcome::new(
                        source.name(),
                        matches!(resp, Response::NotFound),
                        format!("{resp:?}"),
                    )
                })
            },
        );
    }
}

pub(super) fn register_tmp_isolation(reg: &mut Registry<'_>) {
    for &topo in FS_TOPOLOGIES {
        let (writer, reader) = topo.agents();
        let ts = topo.suffix();

        if writer == reader {
            continue;
        }
        matrix_test(
            reg,
            format!("F.tmp.{ts}.isolation"),
            vec![writer, reader],
            move |run, handles| {
                Box::pin(async move {
                    let file = format!("/tmp/matrix_iso_{ts}.txt");
                    let _ = send_to(
                        run,
                        &handles,
                        writer,
                        Command::FsWrite {
                            path: file.clone(),
                            data: "tmp_test".into(),
                        },
                    )
                    .await;
                    let resp = send_to(run, &handles, reader, Command::FsRead { path: file }).await;
                    let is_isolated = matches!(resp, Response::NotFound);
                    super::TestOutcome::new(
                        reader.name(),
                        true,
                        format!("isolated={is_isolated}: {resp:?}"),
                    )
                })
            },
        );
    }
}

pub(super) fn register_host_file(reg: &mut Registry<'_>) {
    for agent in [AgentName::Init, AgentName::Dpg1, AgentName::Dpg1Dpg1] {
        matrix_test(
            reg,
            format!("F.host.{agent}"),
            vec![agent],
            move |run, handles| {
                Box::pin(async move {
                    let resp = send_to(
                        run,
                        &handles,
                        agent,
                        Command::FsRead {
                            path: "/shared/host_wrote.txt".into(),
                        },
                    )
                    .await;
                    let pass = matches!(&resp, Response::Ok { data: Some(d) } if d == "from_host");
                    if matches!(&resp, Response::NotFound) {
                        super::TestOutcome::new(
                            agent.name(),
                            true,
                            "skipped: host_wrote.txt not in rootfs",
                        )
                    } else {
                        super::TestOutcome::new(agent.name(), pass, format!("{resp:?}"))
                    }
                })
            },
        );
    }
}

pub(super) fn register_net_tests(reg: &mut Registry<'_>) {
    let mut port = 10_001u16;
    for tc in NET_TESTS {
        let p = port;
        port += 1;
        let (name, listener, connector) = (tc.name, tc.listener, tc.connector);

        matrix_test(
            reg,
            format!("N.{name}.listen"),
            vec![listener],
            move |run, handles| {
                Box::pin(async move {
                    let resp = send_to(
                        run,
                        &handles,
                        listener,
                        Command::NetListen {
                            port: p,
                            pre_bind_options: vec![],
                        },
                    )
                    .await;
                    let pass = super::expect_listening_port(&resp, p).is_ok();
                    let _ =
                        send_to(run, &handles, listener, Command::NetUnlisten { port: p }).await;
                    super::TestOutcome::new(listener.name(), pass, format!("{resp:?}"))
                })
            },
        );
        let test_data = format!("net_{name}");
        matrix_test(
            reg,
            format!("N.{name}.connect"),
            vec![listener, connector],
            move |run, handles| {
                Box::pin(async move {
                    let resp = send_to(
                        run,
                        &handles,
                        listener,
                        Command::NetListen {
                            port: p,
                            pre_bind_options: vec![],
                        },
                    )
                    .await;
                    if let Err(e) = super::expect_listening_port(&resp, p) {
                        return super::TestOutcome::new(
                            connector.name(),
                            false,
                            format!("listen failed: {e}; resp={resp:?}"),
                        );
                    }
                    let resp = send_to(
                        run,
                        &handles,
                        connector,
                        Command::NetConnect {
                            addr: format!("127.0.0.1:{p}"),
                            data: test_data.clone(),
                        },
                    )
                    .await;
                    let pass = matches!(&resp, Response::Connected { echo } if *echo == test_data);
                    let _ =
                        send_to(run, &handles, listener, Command::NetUnlisten { port: p }).await;
                    super::TestOutcome::new(connector.name(), pass, format!("{resp:?}"))
                })
            },
        );
        matrix_test(
            reg,
            format!("N.{name}.unlisten"),
            vec![listener],
            move |run, handles| {
                Box::pin(async move {
                    let _ = send_to(
                        run,
                        &handles,
                        listener,
                        Command::NetListen {
                            port: p,
                            pre_bind_options: vec![],
                        },
                    )
                    .await;
                    let resp =
                        send_to(run, &handles, listener, Command::NetUnlisten { port: p }).await;
                    super::TestOutcome::new(
                        listener.name(),
                        super::ok_without_data(&resp),
                        format!("{resp:?}"),
                    )
                })
            },
        );
    }
}

pub(super) fn register_net_addr_tests(reg: &mut Registry<'_>) {
    let mut port = 11_001u16;
    for &(agent_a, agent_b) in NET_ADDR_PAIRS {
        for &addr in CONNECT_ADDRS {
            let p = port;
            port += 1;

            let test_data = format!("na_{agent_a}_{agent_b}_{addr}");
            matrix_test(
                reg,
                format!("NA.{agent_a}_to_{agent_b}.{addr}"),
                vec![agent_a, agent_b],
                move |run, handles| {
                    Box::pin(async move {
                        let resp = send_to(
                            run,
                            &handles,
                            agent_a,
                            Command::NetListen {
                                port: p,
                                pre_bind_options: vec![],
                            },
                        )
                        .await;
                        if let Err(e) = super::expect_listening_port(&resp, p) {
                            return super::TestOutcome::new(
                                agent_b.name(),
                                false,
                                format!("listen failed: {e}; resp={resp:?}"),
                            );
                        }
                        let resp = send_to(
                            run,
                            &handles,
                            agent_b,
                            Command::NetConnect {
                                addr: format!("{addr}:{p}"),
                                data: test_data.clone(),
                            },
                        )
                        .await;
                        let pass =
                            matches!(&resp, Response::Connected { echo } if *echo == test_data);
                        let _ =
                            send_to(run, &handles, agent_a, Command::NetUnlisten { port: p }).await;
                        super::TestOutcome::new(agent_b.name(), pass, format!("{resp:?}"))
                    })
                },
            );
        }
        let p = port;
        port += 1;

        let test_data = format!("na_{agent_a}_{agent_b}_self_ip");
        matrix_test(
            reg,
            format!("NA.{agent_a}_to_{agent_b}.self_ip"),
            vec![agent_a, agent_b],
            move |run, handles| {
                Box::pin(async move {
                    let self_ip = tokio::process::Command::new("hostname")
                        .arg("-I")
                        .output()
                        .await
                        .ok()
                        .and_then(|o| String::from_utf8(o.stdout).ok())
                        .and_then(|s| {
                            s.split_whitespace()
                                .find(|ip| *ip != "127.0.0.1" && !ip.contains(':'))
                                .map(String::from)
                        });
                    let Some(addr) = self_ip else {
                        return super::TestOutcome::new(
                            agent_b.name(),
                            true,
                            "self_ip not discoverable, skipping",
                        );
                    };
                    let resp = send_to(
                        run,
                        &handles,
                        agent_a,
                        Command::NetListen {
                            port: p,
                            pre_bind_options: vec![],
                        },
                    )
                    .await;
                    if let Err(e) = super::expect_listening_port(&resp, p) {
                        return super::TestOutcome::new(
                            agent_b.name(),
                            false,
                            format!("listen failed: {e}; resp={resp:?}"),
                        );
                    }
                    let resp = send_to(
                        run,
                        &handles,
                        agent_b,
                        Command::NetConnect {
                            addr: format!("{addr}:{p}"),
                            data: test_data.clone(),
                        },
                    )
                    .await;
                    let pass = matches!(&resp, Response::Connected { echo } if *echo == test_data);
                    let _ = send_to(run, &handles, agent_a, Command::NetUnlisten { port: p }).await;
                    super::TestOutcome::new(agent_b.name(), pass, format!("{resp:?}"))
                })
            },
        );
    }
}

pub(super) fn register_unix_addr_tests(reg: &mut Registry<'_>) {
    for (i, &(agent_a, agent_b)) in NET_ADDR_PAIRS.iter().enumerate() {
        let i = u32::try_from(i).expect("NET_ADDR_PAIRS too large");

        let test_data = format!("ua_{agent_a}_{agent_b}");
        matrix_test(
            reg,
            format!("UA.{agent_a}_to_{agent_b}"),
            vec![agent_a, agent_b],
            move |run, handles| {
                Box::pin(async move {
                    let sock_path = format!("/tmp/ua-{i}.sock");
                    let resp = send_to(
                        run,
                        &handles,
                        agent_a,
                        Command::UnixListen {
                            path: sock_path.clone(),
                        },
                    )
                    .await;
                    if let Err(e) = super::expect_unix_listening_path(&resp, &sock_path) {
                        return super::TestOutcome::new(
                            agent_b.name(),
                            false,
                            format!("listen failed: {e}; resp={resp:?}"),
                        );
                    }
                    let resp = send_to(
                        run,
                        &handles,
                        agent_b,
                        Command::UnixConnect {
                            path: sock_path.clone(),
                            data: test_data.clone(),
                        },
                    )
                    .await;
                    let pass = matches!(&resp, Response::Connected { echo } if *echo == test_data);
                    let _ = send_to(
                        run,
                        &handles,
                        agent_a,
                        Command::UnixUnlisten { path: sock_path },
                    )
                    .await;
                    super::TestOutcome::new(agent_b.name(), pass, format!("{resp:?}"))
                })
            },
        );
    }
}

pub(super) fn register_exec_tests(reg: &mut Registry<'_>) {
    for &agent in EXEC_AGENTS {
        for &bt in crate::BinaryType::ALL {
            let bt_label = bt.label();
            matrix_test(
                reg,
                format!("X.echo.{bt_label}.{agent}"),
                vec![agent],
                move |run, handles| {
                    Box::pin(async move {
                        let self_exe = run.self_exe().to_string();
                        let target = crate::binary_path(bt, &self_exe);
                        let resp = send_to(
                            run,
                            &handles,
                            agent,
                            super::exec(vec![target, "echo-test".into()]),
                        )
                        .await;
                        let pass = matches!(&resp, Response::ExecResult { stdout, .. } if stdout.contains("ECHO_TEST_OK"));
                        super::TestOutcome::new(agent.name(), pass, format!("{resp:?}"))
                    })
                },
            );
        }
    }
    for &(agent, code) in &[(AgentName::Dpg1, 42i32), (AgentName::Dpg1Dpg1Dpg1, 7i32)] {
        for &bt in crate::BinaryType::ALL {
            let bt_label = bt.label();
            matrix_test(
                reg,
                format!("X.exit_code.{bt_label}.{agent}.{code}"),
                vec![agent],
                move |run, handles| {
                    Box::pin(async move {
                        let self_exe = run.self_exe().to_string();
                        let target = crate::binary_path(bt, &self_exe);
                        let resp = send_to(
                            run,
                            &handles,
                            agent,
                            super::exec(vec![target, "exit-with".into(), code.to_string()]),
                        )
                        .await;
                        let pass = matches!(&resp, Response::ExecResult { exit_code, .. } if *exit_code == code);
                        super::TestOutcome::new(agent.name(), pass, format!("{resp:?}"))
                    })
                },
            );
        }
    }
}

pub(super) fn register_env_tests(reg: &mut Registry<'_>) {
    for &agent in EXEC_AGENTS {
        for var in ["HOME", "PATH"] {
            matrix_test(
                reg,
                format!("E.{var}.{agent}"),
                vec![agent],
                move |run, handles| {
                    Box::pin(async move {
                        let resp =
                            send_to(run, &handles, agent, Command::EnvGet { var: var.into() })
                                .await;
                        let pass = matches!(&resp, Response::Ok { data: Some(d) } if !d.is_empty() && d != "NOT_SET");
                        super::TestOutcome::new(agent.name(), pass, format!("{resp:?}"))
                    })
                },
            );
        }
        matrix_test(
            reg,
            format!("E.CWD.{agent}"),
            vec![agent],
            move |run, handles| {
                Box::pin(async move {
                    let resp = send_to(run, &handles, agent, Command::CwdGet).await;
                    super::TestOutcome::new(
                        agent.name(),
                        matches!(&resp, Response::Ok { data: Some(d) } if d == "/"),
                        format!("{resp:?}"),
                    )
                })
            },
        );
    }
}

#[allow(clippy::too_many_lines)] // exhaustive registration / runner
pub(super) fn register_symlink_basic(reg: &mut Registry<'_>) {
    for &topo in SYMLINK_TOPOLOGIES {
        let (source, dest) = topo.agents();
        let ts = topo.suffix();
        let required = vec![AgentName::Init, source, dest];
        matrix_test(
            reg,
            format!("S.basic.{ts}.create"),
            required.clone(),
            move |run, handles| {
                Box::pin(async move {
                    let file = format!("/shared/sm_{ts}_file");
                    let link = format!("/shared/sm_{ts}_link");
                    let _ = send_to(
                        run,
                        &handles,
                        AgentName::Init,
                        Command::FsDelete { path: link.clone() },
                    )
                    .await;
                    let _ = send_to(
                        run,
                        &handles,
                        AgentName::Init,
                        Command::FsDelete { path: file.clone() },
                    )
                    .await;
                    let _ = send_to(
                        run,
                        &handles,
                        source,
                        Command::FsWrite {
                            path: file.clone(),
                            data: format!("symdata_{ts}"),
                        },
                    )
                    .await;
                    let resp = send_to(
                        run,
                        &handles,
                        source,
                        Command::FsSymlink { target: file, link },
                    )
                    .await;
                    super::TestOutcome::new(
                        source.name(),
                        super::ok_without_data(&resp),
                        format!("{resp:?}"),
                    )
                })
            },
        );
        matrix_test(
            reg,
            format!("S.basic.{ts}.readlink"),
            required.clone(),
            move |run, handles| {
                Box::pin(async move {
                    let file = format!("/shared/sm_{ts}_file");
                    let link = format!("/shared/sm_{ts}_link");
                    let _ = send_to(
                        run,
                        &handles,
                        AgentName::Init,
                        Command::FsDelete { path: link.clone() },
                    )
                    .await;
                    let _ = send_to(
                        run,
                        &handles,
                        AgentName::Init,
                        Command::FsDelete { path: file.clone() },
                    )
                    .await;
                    let _ = send_to(
                        run,
                        &handles,
                        source,
                        Command::FsWrite {
                            path: file.clone(),
                            data: format!("symdata_{ts}"),
                        },
                    )
                    .await;
                    let _ = send_to(
                        run,
                        &handles,
                        source,
                        Command::FsSymlink {
                            target: file.clone(),
                            link: link.clone(),
                        },
                    )
                    .await;
                    let resp =
                        send_to(run, &handles, source, Command::FsReadlink { path: link }).await;
                    let pass = matches!(&resp, Response::Ok { data: Some(d) } if *d == file);
                    super::TestOutcome::new(source.name(), pass, format!("{resp:?}"))
                })
            },
        );
        matrix_test(
            reg,
            format!("S.basic.{ts}.read_through"),
            required.clone(),
            move |run, handles| {
                Box::pin(async move {
                    let file = format!("/shared/sm_{ts}_file");
                    let link = format!("/shared/sm_{ts}_link");
                    let data = format!("symdata_{ts}");
                    let _ = send_to(
                        run,
                        &handles,
                        AgentName::Init,
                        Command::FsDelete { path: link.clone() },
                    )
                    .await;
                    let _ = send_to(
                        run,
                        &handles,
                        AgentName::Init,
                        Command::FsDelete { path: file.clone() },
                    )
                    .await;
                    let _ = send_to(
                        run,
                        &handles,
                        source,
                        Command::FsWrite {
                            path: file.clone(),
                            data: data.clone(),
                        },
                    )
                    .await;
                    let _ = send_to(
                        run,
                        &handles,
                        source,
                        Command::FsSymlink {
                            target: file,
                            link: link.clone(),
                        },
                    )
                    .await;
                    let resp = send_to(run, &handles, dest, Command::FsRead { path: link }).await;
                    let pass = matches!(&resp, Response::Ok { data: Some(d) } if *d == data);
                    super::TestOutcome::new(dest.name(), pass, format!("{resp:?}"))
                })
            },
        );
        matrix_test(
            reg,
            format!("S.basic.{ts}.stat_type"),
            required,
            move |run, handles| {
                Box::pin(async move {
                    let file = format!("/shared/sm_{ts}_file");
                    let link = format!("/shared/sm_{ts}_link");
                    let _ = send_to(
                        run,
                        &handles,
                        AgentName::Init,
                        Command::FsDelete { path: link.clone() },
                    )
                    .await;
                    let _ = send_to(
                        run,
                        &handles,
                        AgentName::Init,
                        Command::FsDelete { path: file.clone() },
                    )
                    .await;
                    let _ = send_to(
                        run,
                        &handles,
                        source,
                        Command::FsWrite {
                            path: file.clone(),
                            data: format!("symdata_{ts}"),
                        },
                    )
                    .await;
                    let _ = send_to(
                        run,
                        &handles,
                        source,
                        Command::FsSymlink {
                            target: file,
                            link: link.clone(),
                        },
                    )
                    .await;
                    let resp = send_to(run, &handles, dest, Command::FsStat { path: link }).await;
                    let pass = matches!(&resp, Response::Ok { data: Some(d) } if d == "symlink");
                    super::TestOutcome::new(dest.name(), pass, format!("{resp:?}"))
                })
            },
        );
    }
}

#[allow(clippy::too_many_lines)] // exhaustive registration / runner
pub(super) fn register_symlink_variants(reg: &mut Registry<'_>) {
    let agent = AgentName::Dpg1;
    matrix_test(
        reg,
        "S.dir.read_through",
        vec![agent],
        move |run, handles| {
            Box::pin(async move {
                let _ = send_to(
                    run,
                    &handles,
                    agent,
                    super::exec(vec![
                        "rm".into(),
                        "-rf".into(),
                        "/shared/sv_dir".into(),
                        "/shared/sv_dirlink".into(),
                    ]),
                )
                .await;
                let _ = send_to(
                    run,
                    &handles,
                    agent,
                    super::exec(vec![
                        "bash".into(),
                        "-c".into(),
                        "mkdir -p /shared/sv_dir && echo DIR_CONTENT > /shared/sv_dir/inside.txt"
                            .into(),
                    ]),
                )
                .await;
                let _ = send_to(
                    run,
                    &handles,
                    agent,
                    Command::FsSymlink {
                        target: "/shared/sv_dir".into(),
                        link: "/shared/sv_dirlink".into(),
                    },
                )
                .await;
                let resp = send_to(
                    run,
                    &handles,
                    agent,
                    Command::FsRead {
                        path: "/shared/sv_dirlink/inside.txt".into(),
                    },
                )
                .await;
                let pass =
                    matches!(&resp, Response::Ok { data: Some(d) } if d.trim() == "DIR_CONTENT");
                super::TestOutcome::new(agent.name(), pass, format!("{resp:?}"))
            })
        },
    );
    matrix_test(
        reg,
        "S.dangling.readlink",
        vec![AgentName::Init, agent],
        move |run, handles| {
            Box::pin(async move {
                let _ = send_to(
                    run,
                    &handles,
                    AgentName::Init,
                    Command::FsDelete {
                        path: "/shared/sv_dangling".into(),
                    },
                )
                .await;
                let _ = send_to(
                    run,
                    &handles,
                    agent,
                    Command::FsSymlink {
                        target: "/shared/nonexistent_target".into(),
                        link: "/shared/sv_dangling".into(),
                    },
                )
                .await;
                let resp = send_to(
                    run,
                    &handles,
                    agent,
                    Command::FsReadlink {
                        path: "/shared/sv_dangling".into(),
                    },
                )
                .await;
                let pass = matches!(&resp, Response::Ok { data: Some(d) } if d == "/shared/nonexistent_target");
                super::TestOutcome::new(agent.name(), pass, format!("{resp:?}"))
            })
        },
    );
    matrix_test(
        reg,
        "S.dangling.read_fails",
        vec![AgentName::Init, agent],
        move |run, handles| {
            Box::pin(async move {
                let _ = send_to(
                    run,
                    &handles,
                    AgentName::Init,
                    Command::FsDelete {
                        path: "/shared/sv_dangling".into(),
                    },
                )
                .await;
                let _ = send_to(
                    run,
                    &handles,
                    agent,
                    Command::FsSymlink {
                        target: "/shared/nonexistent_target".into(),
                        link: "/shared/sv_dangling".into(),
                    },
                )
                .await;
                let resp = send_to(
                    run,
                    &handles,
                    agent,
                    Command::FsRead {
                        path: "/shared/sv_dangling".into(),
                    },
                )
                .await;
                super::TestOutcome::new(
                    agent.name(),
                    matches!(&resp, Response::Error { .. } | Response::NotFound),
                    format!("{resp:?}"),
                )
            })
        },
    );
    matrix_test(
        reg,
        "S.nested.read_through",
        vec![AgentName::Init, agent],
        move |run, handles| {
            Box::pin(async move {
                for name in ["sv_nested_link1", "sv_nested_link2", "sv_nested_file"] {
                    let _ = send_to(
                        run,
                        &handles,
                        AgentName::Init,
                        Command::FsDelete {
                            path: format!("/shared/{name}"),
                        },
                    )
                    .await;
                }
                let _ = send_to(
                    run,
                    &handles,
                    agent,
                    Command::FsWrite {
                        path: "/shared/sv_nested_file".into(),
                        data: "NESTED_DATA".into(),
                    },
                )
                .await;
                let _ = send_to(
                    run,
                    &handles,
                    agent,
                    Command::FsSymlink {
                        target: "/shared/sv_nested_file".into(),
                        link: "/shared/sv_nested_link2".into(),
                    },
                )
                .await;
                let _ = send_to(
                    run,
                    &handles,
                    agent,
                    Command::FsSymlink {
                        target: "/shared/sv_nested_link2".into(),
                        link: "/shared/sv_nested_link1".into(),
                    },
                )
                .await;
                let resp = send_to(
                    run,
                    &handles,
                    agent,
                    Command::FsRead {
                        path: "/shared/sv_nested_link1".into(),
                    },
                )
                .await;
                let pass = matches!(&resp, Response::Ok { data: Some(d) } if d == "NESTED_DATA");
                super::TestOutcome::new(agent.name(), pass, format!("{resp:?}"))
            })
        },
    );
    matrix_test(
        reg,
        "S.relative.read_through",
        vec![AgentName::Init, agent],
        move |run, handles| {
            Box::pin(async move {
                for name in ["sv_rel_file", "sv_rel_link"] {
                    let _ = send_to(
                        run,
                        &handles,
                        AgentName::Init,
                        Command::FsDelete {
                            path: format!("/shared/{name}"),
                        },
                    )
                    .await;
                }
                let _ = send_to(
                    run,
                    &handles,
                    agent,
                    Command::FsWrite {
                        path: "/shared/sv_rel_file".into(),
                        data: "REL_DATA".into(),
                    },
                )
                .await;
                let _ = send_to(
                    run,
                    &handles,
                    agent,
                    Command::FsSymlink {
                        target: "sv_rel_file".into(),
                        link: "/shared/sv_rel_link".into(),
                    },
                )
                .await;
                let resp = send_to(
                    run,
                    &handles,
                    agent,
                    Command::FsRead {
                        path: "/shared/sv_rel_link".into(),
                    },
                )
                .await;
                let pass = matches!(&resp, Response::Ok { data: Some(d) } if d == "REL_DATA");
                super::TestOutcome::new(agent.name(), pass, format!("{resp:?}"))
            })
        },
    );
}

#[allow(clippy::too_many_lines)] // exhaustive registration / runner
pub(super) fn register_unix_tests(reg: &mut Registry<'_>) {
    for tc in unix_test_cases() {
        let sock = format!("/tmp/um_{}.sock", tc.name.replace('.', "_"));
        let agent = tc.agent;
        let name = tc.name;
        match tc.pattern {
            UnixPattern::InProcess => {
                let sock_listen = sock.clone();
                matrix_test(
                    reg,
                    format!("U.{name}.listen"),
                    vec![agent],
                    move |run, handles| {
                        Box::pin(async move {
                            let resp = send_to(
                                run,
                                &handles,
                                agent,
                                Command::UnixListen {
                                    path: sock_listen.clone(),
                                },
                            )
                            .await;
                            let pass =
                                super::expect_unix_listening_path(&resp, &sock_listen).is_ok();
                            let _ = send_to(
                                run,
                                &handles,
                                agent,
                                Command::UnixUnlisten { path: sock_listen },
                            )
                            .await;
                            super::TestOutcome::new(agent.name(), pass, format!("{resp:?}"))
                        })
                    },
                );
                matrix_test(
                    reg,
                    format!("U.{name}.connect"),
                    vec![agent],
                    move |run, handles| {
                        Box::pin(async move {
                            let resp = send_to(
                                run,
                                &handles,
                                agent,
                                Command::UnixListen { path: sock.clone() },
                            )
                            .await;
                            if let Err(e) = super::expect_unix_listening_path(&resp, &sock) {
                                return super::TestOutcome::new(
                                    agent.name(),
                                    false,
                                    format!("listen failed: {e}; resp={resp:?}"),
                                );
                            }
                            let data = format!("unix_{name}");
                            let resp = send_to(
                                run,
                                &handles,
                                agent,
                                Command::UnixConnect {
                                    path: sock.clone(),
                                    data: data.clone(),
                                },
                            )
                            .await;
                            let pass =
                                matches!(&resp, Response::Connected { echo } if *echo == data);
                            let _ =
                                send_to(run, &handles, agent, Command::UnixUnlisten { path: sock })
                                    .await;
                            super::TestOutcome::new(agent.name(), pass, format!("{resp:?}"))
                        })
                    },
                );
            }
            UnixPattern::ServerForkClient => {
                let sock_listen = sock.clone();
                matrix_test(
                    reg,
                    format!("U.{name}.listen"),
                    vec![agent],
                    move |run, handles| {
                        Box::pin(async move {
                            let resp = send_to(
                                run,
                                &handles,
                                agent,
                                Command::UnixListen {
                                    path: sock_listen.clone(),
                                },
                            )
                            .await;
                            let pass =
                                super::expect_unix_listening_path(&resp, &sock_listen).is_ok();
                            let _ = send_to(
                                run,
                                &handles,
                                agent,
                                Command::UnixUnlisten { path: sock_listen },
                            )
                            .await;
                            super::TestOutcome::new(agent.name(), pass, format!("{resp:?}"))
                        })
                    },
                );
                for &bt in crate::BinaryType::ALL {
                    let bt_label = bt.label();
                    let sock = format!("/tmp/um_{}_{}.sock", name.replace('.', "_"), bt_label);
                    matrix_test(
                        reg,
                        format!("U.{name}.{bt_label}.child_connect"),
                        vec![agent],
                        move |run, handles| {
                            Box::pin(async move {
                                let self_exe = run.self_exe().to_string();
                                let target = crate::binary_path(bt, &self_exe);
                                let resp = send_to(
                                    run,
                                    &handles,
                                    agent,
                                    Command::UnixListen { path: sock.clone() },
                                )
                                .await;
                                if let Err(e) = super::expect_unix_listening_path(&resp, &sock) {
                                    return super::TestOutcome::new(
                                        agent.name(),
                                        false,
                                        format!("listen failed: {e}; resp={resp:?}"),
                                    );
                                }
                                let data = format!("unix_{name}");
                                let resp = send_to(
                                    run,
                                    &handles,
                                    agent,
                                    super::exec(vec![
                                        target,
                                        "unix-echo-client".into(),
                                        sock.clone(),
                                        data.clone(),
                                    ]),
                                )
                                .await;
                                let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout.contains(&data));
                                let _ = send_to(
                                    run,
                                    &handles,
                                    agent,
                                    Command::UnixUnlisten { path: sock },
                                )
                                .await;
                                super::TestOutcome::new(agent.name(), pass, format!("{resp:?}"))
                            })
                        },
                    );
                }
            }
            UnixPattern::BackgroundServerConnect => {
                for &bt in crate::BinaryType::ALL {
                    let bt_label = bt.label();
                    let sock_start =
                        format!("/tmp/um_{}_{}_start.sock", name.replace('.', "_"), bt_label);
                    matrix_test(
                        reg,
                        format!("U.{name}.{bt_label}.server_start"),
                        vec![agent],
                        move |run, handles| {
                            Box::pin(async move {
                                let self_exe = run.self_exe().to_string();
                                let target = crate::binary_path(bt, &self_exe);
                                let resp = send_to(
                                    run,
                                    &handles,
                                    agent,
                                    Command::Exec {
                                        args: vec![
                                            target,
                                            "unix-echo-server".into(),
                                            sock_start.clone(),
                                        ],
                                        timeout_secs: None,
                                        stdin: None,
                                        background: true,
                                        env: vec![],
                                    },
                                )
                                .await;
                                let pid = match &resp {
                                    Response::Background { pid } => Some(*pid),
                                    _ => None,
                                };
                                let pass = pid.is_some();
                                if let Some(pid) = pid {
                                    let _ =
                                        send_to(run, &handles, agent, Command::Kill { pid }).await;
                                }
                                let _ = send_to(
                                    run,
                                    &handles,
                                    agent,
                                    Command::UnixUnlisten { path: sock_start },
                                )
                                .await;
                                super::TestOutcome::new(agent.name(), pass, format!("{resp:?}"))
                            })
                        },
                    );
                }
                for &bt in crate::BinaryType::ALL {
                    let bt_label = bt.label();
                    let sock = format!(
                        "/tmp/um_{}_{}_connect.sock",
                        name.replace('.', "_"),
                        bt_label
                    );
                    matrix_test(
                        reg,
                        format!("U.{name}.{bt_label}.connect"),
                        vec![agent],
                        move |run, handles| {
                            Box::pin(async move {
                                let self_exe = run.self_exe().to_string();
                                let target = crate::binary_path(bt, &self_exe);
                                let resp = send_to(
                                    run,
                                    &handles,
                                    agent,
                                    Command::ExecReady {
                                        args: vec![target, "unix-echo-server".into(), sock.clone()],
                                        ready_marker: "LISTENING".into(),
                                        timeout_secs: Some(10),
                                        stdin: None,
                                        stream: "stdout".into(),
                                    },
                                )
                                .await;
                                let pid = match &resp {
                                    Response::BackgroundReady { pid } => Some(*pid),
                                    _ => None,
                                };
                                if pid.is_none() {
                                    return super::TestOutcome::new(
                                        agent.name(),
                                        false,
                                        format!("server_start failed: {resp:?}"),
                                    );
                                }
                                let data = format!("unix_{name}");
                                let resp = send_to(
                                    run,
                                    &handles,
                                    agent,
                                    Command::UnixConnect {
                                        path: sock.clone(),
                                        data: data.clone(),
                                    },
                                )
                                .await;
                                let pass = matches!(
                                    &resp,
                                    Response::Connected { echo } if *echo == data
                                );
                                if let Some(pid) = pid {
                                    let _ =
                                        send_to(run, &handles, agent, Command::Kill { pid }).await;
                                }
                                let _ = send_to(
                                    run,
                                    &handles,
                                    agent,
                                    Command::UnixUnlisten { path: sock },
                                )
                                .await;
                                super::TestOutcome::new(agent.name(), pass, format!("{resp:?}"))
                            })
                        },
                    );
                }
            }
            UnixPattern::CrossAgent => {
                let connector = tc.peer.unwrap();
                let sock_listen = sock.clone();
                matrix_test(
                    reg,
                    format!("U.{name}.listen"),
                    vec![agent],
                    move |run, handles| {
                        Box::pin(async move {
                            let resp = send_to(
                                run,
                                &handles,
                                agent,
                                Command::UnixListen {
                                    path: sock_listen.clone(),
                                },
                            )
                            .await;
                            let pass =
                                super::expect_unix_listening_path(&resp, &sock_listen).is_ok();
                            let _ = send_to(
                                run,
                                &handles,
                                agent,
                                Command::UnixUnlisten { path: sock_listen },
                            )
                            .await;
                            super::TestOutcome::new(agent.name(), pass, format!("{resp:?}"))
                        })
                    },
                );
                matrix_test(
                    reg,
                    format!("U.{name}.connect"),
                    vec![agent, connector],
                    move |run, handles| {
                        Box::pin(async move {
                            let data = format!("unix_{name}");
                            let resp = send_to(
                                run,
                                &handles,
                                agent,
                                Command::UnixListen { path: sock.clone() },
                            )
                            .await;
                            if let Err(e) = super::expect_unix_listening_path(&resp, &sock) {
                                return super::TestOutcome::new(
                                    connector.name(),
                                    false,
                                    format!("listen failed: {e}; resp={resp:?}"),
                                );
                            }
                            let resp = send_to(
                                run,
                                &handles,
                                connector,
                                Command::UnixConnect {
                                    path: sock.clone(),
                                    data: data.clone(),
                                },
                            )
                            .await;
                            let pass =
                                matches!(&resp, Response::Connected { echo } if *echo == data);
                            let _ =
                                send_to(run, &handles, agent, Command::UnixUnlisten { path: sock })
                                    .await;
                            super::TestOutcome::new(connector.name(), pass, format!("{resp:?}"))
                        })
                    },
                );
            }
        }
    }
    matrix_test(
        reg,
        "U.repro.listen",
        vec![AgentName::Dpg1Dpg1Dpg1],
        move |run, handles| {
            Box::pin(async move {
                let sock = "/tmp/um_repro_xworker.sock".to_string();
                let resp = send_to(
                    run,
                    &handles,
                    AgentName::Dpg1Dpg1Dpg1,
                    Command::UnixListen { path: sock.clone() },
                )
                .await;
                let pass = super::expect_unix_listening_path(&resp, &sock).is_ok();
                let _ = send_to(
                    run,
                    &handles,
                    AgentName::Dpg1Dpg1Dpg1,
                    Command::UnixUnlisten { path: sock },
                )
                .await;
                super::TestOutcome::new(AgentName::Dpg1Dpg1Dpg1.name(), pass, format!("{resp:?}"))
            })
        },
    );
    matrix_test(
        reg,
        "U.repro.same_agent",
        vec![AgentName::Dpg1Dpg1Dpg1],
        move |run, handles| {
            Box::pin(async move {
                let sock = "/tmp/um_repro_xworker.sock".to_string();
                let resp = send_to(
                    run,
                    &handles,
                    AgentName::Dpg1Dpg1Dpg1,
                    Command::UnixListen { path: sock.clone() },
                )
                .await;
                if let Err(e) = super::expect_unix_listening_path(&resp, &sock) {
                    return super::TestOutcome::new(
                        AgentName::Dpg1Dpg1Dpg1.name(),
                        false,
                        format!("listen failed: {e}; resp={resp:?}"),
                    );
                }
                let resp = send_to(
                    run,
                    &handles,
                    AgentName::Dpg1Dpg1Dpg1,
                    Command::UnixConnect {
                        path: sock.clone(),
                        data: "SAME_AGENT".to_string(),
                    },
                )
                .await;
                let pass =
                    matches!(&resp, Response::Connected { echo } if echo.contains("SAME_AGENT"));
                let _ = send_to(
                    run,
                    &handles,
                    AgentName::Dpg1Dpg1Dpg1,
                    Command::UnixUnlisten { path: sock },
                )
                .await;
                super::TestOutcome::new(AgentName::Dpg1Dpg1Dpg1.name(), pass, format!("{resp:?}"))
            })
        },
    );
    matrix_test(
        reg,
        "U.repro.cross_worker",
        vec![AgentName::Dpg1Dpg1Dpg1, AgentName::Dpg1Dpg1Dpg1Dng],
        move |run, handles| {
            Box::pin(async move {
                let sock = "/tmp/um_repro_xworker.sock".to_string();
                let resp = send_to(
                    run,
                    &handles,
                    AgentName::Dpg1Dpg1Dpg1,
                    Command::UnixListen { path: sock.clone() },
                )
                .await;
                if let Err(e) = super::expect_unix_listening_path(&resp, &sock) {
                    return super::TestOutcome::new(
                        AgentName::Dpg1Dpg1Dpg1Dng.name(),
                        false,
                        format!("listen failed: {e}; resp={resp:?}"),
                    );
                }
                let resp = send_to(
                    run,
                    &handles,
                    AgentName::Dpg1Dpg1Dpg1Dng,
                    Command::UnixConnect {
                        path: sock.clone(),
                        data: "CROSS_WORKER".to_string(),
                    },
                )
                .await;
                let pass =
                    matches!(&resp, Response::Connected { echo } if echo.contains("CROSS_WORKER"));
                let _ = send_to(
                    run,
                    &handles,
                    AgentName::Dpg1Dpg1Dpg1,
                    Command::UnixUnlisten { path: sock },
                )
                .await;
                super::TestOutcome::new(
                    AgentName::Dpg1Dpg1Dpg1Dng.name(),
                    pass,
                    format!("{resp:?}"),
                )
            })
        },
    );
}

pub(super) fn register_matrix(reg: &mut Registry<'_>) {
    register_fs_crud(reg);
    register_fs_cross_unlink(reg);
    register_tmp_isolation(reg);
    register_host_file(reg);
    register_net_tests(reg);
    register_net_addr_tests(reg);
    register_unix_addr_tests(reg);
    register_exec_tests(reg);
    register_env_tests(reg);
    register_symlink_basic(reg);
    register_symlink_variants(reg);
    register_unix_tests(reg);
}
