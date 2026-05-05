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

use super::TestRunner;
use crate::protocol::{Command, Response};
use std::collections::HashSet;

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
    /// A → NP (non-PIE child via SpawnRemote).
    PieToNonPie,
    /// NP → A (non-PIE writes, PIE reads).
    NonPieToParent,
    /// NPC → A (PIE-from-non-PIE reads, PIE reads).
    NonPieChildUp,
    /// D5 → B (depth 5 from non-PIE root, cross-subtree).
    DeepNonPie,
}

impl Topology {
    fn agents(self) -> (&'static str, &'static str) {
        match self {
            Self::InProcess => ("A", "A"),
            Self::ParentToChild => ("init", "A"),
            Self::ChildToParent => ("A", "init"),
            Self::Sibling => ("A", "B"),
            Self::SiblingReverse => ("B", "A"),
            Self::GrandchildUp => ("AA", "init"),
            Self::GreatGrandchildUp => ("AAA", "init"),
            Self::CrossSubtree => ("B", "AAA"),
            Self::SiblingDepth2 => ("AA", "AB"),
            Self::SiblingDepth3 => ("AAA", "AAB"),
            Self::Uncle => ("AB", "B"),
            Self::PieToNonPie => ("A", "NP"),
            Self::NonPieToParent => ("NP", "A"),
            Self::NonPieChildUp => ("NPC", "A"),
            Self::DeepNonPie => ("D5", "B"),
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

    /// Whether this topology requires non-PIE agents (NP, NPC, D3-D5).
    fn requires_nonpie(self) -> bool {
        matches!(
            self,
            Self::PieToNonPie | Self::NonPieToParent | Self::NonPieChildUp | Self::DeepNonPie
        )
    }
}

// ── Xfail registry ──

#[allow(dead_code)]
fn build_xfail_set() -> HashSet<&'static str> {
    HashSet::new()
}

#[allow(dead_code)]
fn record(
    r: &mut TestRunner,
    test_id: &str,
    agent: &str,
    pass: bool,
    detail: &str,
    xfails: &HashSet<&str>,
) {
    if let Some(&reason) = xfails.get(test_id) {
        r.record_xfail(test_id, agent, pass, reason, detail);
    } else {
        r.record(test_id, agent, pass, detail);
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

/// Whether an agent name requires the non-PIE subtree.
fn agent_requires_nonpie(name: &str) -> bool {
    matches!(name, "NP" | "NPC" | "D3" | "D4" | "D5")
}

/// Net test descriptor. Listener listens, connector connects.
struct NetTestCase {
    name: &'static str,
    listener: &'static str,
    connector: &'static str,
}

/// Net test with explicit connect address (to test cross-worker routing).
#[allow(dead_code)]
struct NetAddrTestCase {
    name: &'static str,
    listener: &'static str,
    connector: &'static str,
    /// Address the connector uses: "127.0.0.1", "10.0.0.2", or "0.0.0.0".
    connect_addr: &'static str,
}

const NET_TESTS: &[NetTestCase] = &[
    NetTestCase {
        name: "init_to_A",
        listener: "A",
        connector: "init",
    },
    NetTestCase {
        name: "A_to_B",
        listener: "B",
        connector: "A",
    },
    NetTestCase {
        name: "B_to_A",
        listener: "A",
        connector: "B",
    },
    NetTestCase {
        name: "AAA_to_A",
        listener: "A",
        connector: "AAA",
    },
    NetTestCase {
        name: "B_to_AAA",
        listener: "AAA",
        connector: "B",
    },
    NetTestCase {
        name: "AA_to_AB",
        listener: "AB",
        connector: "AA",
    },
    NetTestCase {
        name: "AAA_to_AAB",
        listener: "AAB",
        connector: "AAA",
    },
    NetTestCase {
        name: "AB_to_B",
        listener: "B",
        connector: "AB",
    },
    // Non-PIE tree: NP listens, A connects (cross-type boundary).
    NetTestCase {
        name: "NP_to_A",
        listener: "NP",
        connector: "A",
    },
    // PIE listens, non-PIE child connects.
    NetTestCase {
        name: "A_to_NPC",
        listener: "A",
        connector: "NPC",
    },
    // Non-PIE child listens, PIE from other subtree connects.
    NetTestCase {
        name: "NPC_to_B",
        listener: "NPC",
        connector: "B",
    },
    // Depth 5 (from non-PIE root) to depth 1 — the VS Code server path.
    NetTestCase {
        name: "D5_to_B",
        listener: "D5",
        connector: "B",
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
/// Each pair is tested with all CONNECT_ADDRS in both directions.
const NET_ADDR_PAIRS: &[(&str, &str)] = &[
    // Same worker (baseline)
    ("A", "A"),
    ("AA", "AA"),
    // Parent-child (init → fork-restore)
    ("A", "AA"),
    // Sibling fork-restores
    ("A", "B"),
    // VS Code topology: fork-restore ↔ worker-exec
    ("D3", "D4"),
    // Deeper: worker-exec ↔ fork-restore-from-worker-exec
    ("D4", "D5"),
    // Cross-subtree with worker-exec
    ("D4", "B"),
    ("D4", "A"),
    // Non-PIE worker-exec ↔ PIE parent
    ("NP", "A"),
    ("A", "NP"),
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

const EXEC_AGENTS: &[&str] = &["A", "AA", "AAA", "NP", "NPC", "D5"];

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
    /// agent for BackgroundServerConnect).
    agent: &'static str,
    /// Connector agent for CrossAgent pattern.
    peer: Option<&'static str>,
}

fn unix_test_cases() -> Vec<UnixTestCase> {
    vec![
        UnixTestCase {
            name: "in_process.A",
            pattern: UnixPattern::InProcess,
            agent: "A",
            peer: None,
        },
        UnixTestCase {
            name: "in_process.AA",
            pattern: UnixPattern::InProcess,
            agent: "AA",
            peer: None,
        },
        UnixTestCase {
            name: "server_fork.A",
            pattern: UnixPattern::ServerForkClient,
            agent: "A",
            peer: None,
        },
        UnixTestCase {
            name: "server_fork.AA",
            pattern: UnixPattern::ServerForkClient,
            agent: "AA",
            peer: None,
        },
        UnixTestCase {
            name: "bg_server.A",
            pattern: UnixPattern::BackgroundServerConnect,
            agent: "A",
            peer: None,
        },
        UnixTestCase {
            name: "bg_server.AA",
            pattern: UnixPattern::BackgroundServerConnect,
            agent: "AA",
            peer: None,
        },
        // Same-worker CrossAgent cases (all connected via Spawn chains,
        // share one worker process and one unix_addr_table).
        UnixTestCase {
            name: "sibling",
            pattern: UnixPattern::CrossAgent,
            agent: "A",
            peer: Some("B"),
        },
        UnixTestCase {
            name: "parent_to_grandchild",
            pattern: UnixPattern::CrossAgent,
            agent: "A",
            peer: Some("AA"),
        },
        UnixTestCase {
            name: "grandchild_to_parent",
            pattern: UnixPattern::CrossAgent,
            agent: "AA",
            peer: Some("A"),
        },
        UnixTestCase {
            name: "cross_subtree",
            pattern: UnixPattern::CrossAgent,
            agent: "B",
            peer: Some("AAA"),
        },
        // Cross-worker CrossAgent cases — these cross a SpawnRemote boundary
        // (different OS worker processes, separate unix_addr_table).
        // Worker boundaries: {init,A,B,AA,AB,AAA,AAB,D3} | {NP,NPC} | {D4,D5}
        UnixTestCase {
            name: "vscode_d3_d4",
            pattern: UnixPattern::CrossAgent,
            agent: "D3",
            peer: Some("D4"),
        },
        UnixTestCase {
            name: "vscode_d4_d3",
            pattern: UnixPattern::CrossAgent,
            agent: "D4",
            peer: Some("D3"),
        },
        UnixTestCase {
            name: "d4_to_sibling_b",
            pattern: UnixPattern::CrossAgent,
            agent: "D4",
            peer: Some("B"),
        },
        UnixTestCase {
            name: "d5_to_a",
            pattern: UnixPattern::CrossAgent,
            agent: "D5",
            peer: Some("A"),
        },
        UnixTestCase {
            name: "a_to_np",
            pattern: UnixPattern::CrossAgent,
            agent: "A",
            peer: Some("NP"),
        },
        UnixTestCase {
            name: "np_to_a",
            pattern: UnixPattern::CrossAgent,
            agent: "NP",
            peer: Some("A"),
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
// MATRIX RUNNER
// ═══════════════════════════════════════════════════════════════════
// force
// ═══════════════════════════════════════════════════════════════════
// DECLARATIVE REGISTRATION — append to matrix.rs
// ═══════════════════════════════════════════════════════════════════
//
// Each `register_*` function pushes `super::Test` structs into a Vec.
// Sequential operations (write→read→update→delete) are grouped into
// a single closure.

// Declarative register functions for the matrix test suite.
//
// Each `register_*` function pushes self-contained `Test` structs into the
// provided vector. Every `r.record()` call in the old imperative code becomes
// exactly one `Test` push with the same test ID and agent.
//
// Designed to be appended to (or included from) `matrix.rs`.


// ═══════════════════════════════════════════════════════════════════
// 1. FILESYSTEM CRUD — F.shared.{topo}.{absent,created,updated,deleted}
// ═══════════════════════════════════════════════════════════════════

/// Registers 4 tests per topology: absent, created, updated, deleted.
/// Total: 4 × |FS_TOPOLOGIES| (with nonpie-skip fallback).
pub(super) fn register_fs_crud(tests: &mut Vec<super::Test>) {
    let has_nonpie = crate::find_nonpie_binary().is_some();
    for &topo in FS_TOPOLOGIES {
        let (source, dest) = topo.agents();
        let ts = topo.suffix();

        if topo.requires_nonpie() && !has_nonpie {
            for op in &["absent", "created", "updated", "deleted"] {
                let dest = dest.to_string();
                let id = format!("F.shared.{ts}.{op}");
                tests.push(super::Test {
                    suite: "matrix",
                    group: "run_matrix",
                    id,
                    xfail: None,
                    timeout_secs: 60,
                    run: Box::new(move |_r| {
                        Box::pin(async move {
                            super::TestOutcome::new(
                                &dest,
                                false,
                                "FAIL: nonpie binary not found — mount at /opt/nonpie",
                            )
                        })
                    }),
                });
            }
            continue;
        }

        let source = source.to_string();
        let dest = dest.to_string();
        let ts_s: String = ts.to_string();

        // ── absent ──
        {
            let _source = source.clone();
            let dest = dest.clone();
            let ts_s = ts_s.clone();
            tests.push(super::Test {
                suite: "matrix",
                group: "run_matrix",
                id: format!("F.shared.{ts_s}.absent"),
                xfail: None,
                timeout_secs: 60,
                run: Box::new(move |r| {
                    Box::pin(async move {
                        let file = format!("/shared/matrix_{ts_s}.txt");
                        let _ = r
                            .send("init", Command::FsDelete { path: file.clone() })
                            .await;
                        let resp = r.send(&dest, Command::FsRead { path: file }).await;
                        let pass = matches!(resp, Response::NotFound);
                        super::TestOutcome::new(&dest, pass, format!("{resp:?}"))
                    })
                }),
            });
        }

        // ── created ──
        {
            let source = source.clone();
            let dest = dest.clone();
            let ts_s = ts_s.clone();
            tests.push(super::Test {
                suite: "matrix",
                group: "run_matrix",
                id: format!("F.shared.{ts_s}.created"),
                xfail: None,
                timeout_secs: 60,
                run: Box::new(move |r| {
                    Box::pin(async move {
                        let file = format!("/shared/matrix_{ts_s}.txt");
                        let data = format!("data_{ts_s}");
                        let _ = r
                            .send("init", Command::FsDelete { path: file.clone() })
                            .await;
                        r.send(
                            &source,
                            Command::FsWrite {
                                path: file.clone(),
                                data: data.clone(),
                            },
                        )
                        .await;
                        let resp = r.send(&dest, Command::FsRead { path: file }).await;
                        let pass = matches!(&resp, Response::Ok { data: Some(d) } if *d == data);
                        super::TestOutcome::new(&dest, pass, format!("{resp:?}"))
                    })
                }),
            });
        }

        // ── updated ──
        {
            let source = source.clone();
            let dest = dest.clone();
            let ts_s = ts_s.clone();
            tests.push(super::Test {
                suite: "matrix",
                group: "run_matrix",
                id: format!("F.shared.{ts_s}.updated"),
                xfail: None,
                timeout_secs: 60,
                run: Box::new(move |r| {
                    Box::pin(async move {
                        let file = format!("/shared/matrix_{ts_s}.txt");
                        let data = format!("data_{ts_s}");
                        let updated = format!("updated_{ts_s}");
                        let _ = r
                            .send("init", Command::FsDelete { path: file.clone() })
                            .await;
                        r.send(
                            &source,
                            Command::FsWrite {
                                path: file.clone(),
                                data: data.clone(),
                            },
                        )
                        .await;
                        r.send(
                            &source,
                            Command::FsWrite {
                                path: file.clone(),
                                data: updated.clone(),
                            },
                        )
                        .await;
                        let resp = r.send(&dest, Command::FsRead { path: file }).await;
                        let pass = matches!(&resp, Response::Ok { data: Some(d) } if *d == updated);
                        super::TestOutcome::new(&dest, pass, format!("{resp:?}"))
                    })
                }),
            });
        }

        // ── deleted ──
        {
            let source = source.clone();
            let dest = dest.clone();
            let ts_s = ts_s.clone();
            tests.push(super::Test {
                suite: "matrix",
                group: "run_matrix",
                id: format!("F.shared.{ts_s}.deleted"),
                xfail: None,
                timeout_secs: 60,
                run: Box::new(move |r| {
                    Box::pin(async move {
                        let file = format!("/shared/matrix_{ts_s}.txt");
                        let data = format!("data_{ts_s}");
                        let _ = r
                            .send("init", Command::FsDelete { path: file.clone() })
                            .await;
                        r.send(
                            &source,
                            Command::FsWrite {
                                path: file.clone(),
                                data,
                            },
                        )
                        .await;
                        r.send(&source, Command::FsDelete { path: file.clone() })
                            .await;
                        let resp = r.send(&dest, Command::FsRead { path: file }).await;
                        let pass = matches!(resp, Response::NotFound);
                        super::TestOutcome::new(&dest, pass, format!("{resp:?}"))
                    })
                }),
            });
        }
    }
}

// ═══════════════════════════════════════════════════════════════════
// 2. FILESYSTEM CROSS-UNLINK — F.unlink.{topo}.{delete,gone}
// ═══════════════════════════════════════════════════════════════════

pub(super) fn register_fs_cross_unlink(tests: &mut Vec<super::Test>) {
    let has_nonpie = crate::find_nonpie_binary().is_some();
    for &topo in FS_TOPOLOGIES {
        if topo.requires_nonpie() && !has_nonpie {
            let ts = topo.suffix();
            let (_, dest) = topo.agents();
            for op in &["delete", "gone"] {
                let id = format!("F.unlink.{ts}.{op}");
                let dest = dest.to_string();
                tests.push(super::Test {
                    suite: "matrix",
                    group: "run_matrix",
                    id,
                    xfail: None,
                    timeout_secs: 60,
                    run: Box::new(move |_r| {
                        Box::pin(async move {
                            super::TestOutcome::new(
                                &dest,
                                false,
                                "nonpie binary not found".to_string(),
                            )
                        })
                    }),
                });
            }
            continue;
        }
        let (source, dest) = topo.agents();
        let ts = topo.suffix();
        let source = source.to_string();
        let dest = dest.to_string();
        let ts_s = ts.to_string();

        // ── delete ──
        {
            let source = source.clone();
            let dest = dest.clone();
            let ts_s = ts_s.clone();
            tests.push(super::Test {
                suite: "matrix",
                group: "run_matrix",
                id: format!("F.unlink.{ts_s}.delete"),
                xfail: None,
                timeout_secs: 60,
                run: Box::new(move |r| {
                    Box::pin(async move {
                        let file = format!("/shared/unlink_{ts_s}.txt");
                        let _ = r
                            .send("init", Command::FsDelete { path: file.clone() })
                            .await;
                        r.send(
                            &source,
                            Command::FsWrite {
                                path: file.clone(),
                                data: "unlink_me".into(),
                            },
                        )
                        .await;
                        let resp = r.send(&dest, Command::FsDelete { path: file }).await;
                        let pass = matches!(&resp, Response::Ok { .. });
                        super::TestOutcome::new(&dest, pass, format!("{resp:?}"))
                    })
                }),
            });
        }

        // ── gone ──
        {
            let source = source.clone();
            let dest = dest.clone();
            let ts_s = ts_s.clone();
            tests.push(super::Test {
                suite: "matrix",
                group: "run_matrix",
                id: format!("F.unlink.{ts_s}.gone"),
                xfail: None,
                timeout_secs: 60,
                run: Box::new(move |r| {
                    Box::pin(async move {
                        let file = format!("/shared/unlink_{ts_s}.txt");
                        let _ = r
                            .send("init", Command::FsDelete { path: file.clone() })
                            .await;
                        r.send(
                            &source,
                            Command::FsWrite {
                                path: file.clone(),
                                data: "unlink_me".into(),
                            },
                        )
                        .await;
                        let _ = r
                            .send(&dest, Command::FsDelete { path: file.clone() })
                            .await;
                        let resp = r.send(&source, Command::FsRead { path: file }).await;
                        let pass = matches!(resp, Response::NotFound);
                        super::TestOutcome::new(&source, pass, format!("{resp:?}"))
                    })
                }),
            });
        }
    }
}

// ═══════════════════════════════════════════════════════════════════
// 3. /tmp ISOLATION — F.tmp.{topo}.isolation
// ═══════════════════════════════════════════════════════════════════

pub(super) fn register_tmp_isolation(tests: &mut Vec<super::Test>) {
    let has_nonpie = crate::find_nonpie_binary().is_some();
    for &topo in FS_TOPOLOGIES {
        if topo.requires_nonpie() && !has_nonpie {
            let ts = topo.suffix();
            let (_, dest) = topo.agents();
            let id = format!("F.tmp.{ts}.isolation");
            let dest = dest.to_string();
            tests.push(super::Test {
                suite: "matrix",
                group: "run_matrix",
                id,
                xfail: None,
                timeout_secs: 60,
                run: Box::new(move |_r| {
                    Box::pin(async move {
                        super::TestOutcome::new(&dest, false, "nonpie binary not found".to_string())
                    })
                }),
            });
            continue;
        }
        let (writer, reader) = topo.agents();
        if writer == reader {
            continue; // skip InProcess
        }
        let ts = topo.suffix();
        let writer = writer.to_string();
        let reader = reader.to_string();
        let ts_s = ts.to_string();

        tests.push(super::Test {
            suite: "matrix",
            group: "run_matrix",
            id: format!("F.tmp.{ts_s}.isolation"),
            xfail: None,
            timeout_secs: 60,
            run: Box::new(move |r| {
                Box::pin(async move {
                    let file = format!("/tmp/matrix_iso_{ts_s}.txt");
                    r.send(
                        &writer,
                        Command::FsWrite {
                            path: file.clone(),
                            data: "tmp_test".into(),
                        },
                    )
                    .await;
                    let resp = r.send(&reader, Command::FsRead { path: file }).await;
                    let is_isolated = matches!(resp, Response::NotFound);
                    super::TestOutcome::new(
                        &reader,
                        true, // informational — always pass
                        format!("isolated={is_isolated}: {resp:?}"),
                    )
                })
            }),
        });
    }
}

// ═══════════════════════════════════════════════════════════════════
// 4. HOST FILE — F.host.{agent} + write_for_host
// ═══════════════════════════════════════════════════════════════════

pub(super) fn register_host_file(tests: &mut Vec<super::Test>) {
    for &agent in &["init", "A", "AA"] {
        let agent = agent.to_string();
        tests.push(super::Test {
            suite: "matrix",
            group: "run_matrix",
            id: format!("F.host.{agent}"),
            xfail: None,
            timeout_secs: 60,
            run: Box::new(move |r| {
                Box::pin(async move {
                    let resp = r
                        .send(
                            &agent,
                            Command::FsRead {
                                path: "/shared/host_wrote.txt".into(),
                            },
                        )
                        .await;
                    let pass = matches!(&resp, Response::Ok { data: Some(d) } if d == "from_host");
                    if matches!(&resp, Response::NotFound) {
                        // File not pre-created by host — skip (not a sandbox failure).
                        super::TestOutcome::new(
                            &agent,
                            true,
                            "skipped: host_wrote.txt not in rootfs",
                        )
                    } else {
                        super::TestOutcome::new(&agent, pass, format!("{resp:?}"))
                    }
                })
            }),
        });
    }

    // Write file for host to read after exit.
}

// ═══════════════════════════════════════════════════════════════════
// 5. TCP NETWORK — N.{name}.{listen,connect,unlisten}
// ═══════════════════════════════════════════════════════════════════

pub(super) fn register_net_tests(tests: &mut Vec<super::Test>) {
    let has_nonpie = crate::find_nonpie_binary().is_some();
    let mut port = 10_001u16;

    for tc in NET_TESTS {
        let p = port;
        port += 1;

        if !has_nonpie
            && (agent_requires_nonpie(tc.listener) || agent_requires_nonpie(tc.connector))
        {
            for suffix in &["listen", "connect", "unlisten"] {
                let listener = tc.listener.to_string();
                let id = format!("N.{}.{suffix}", tc.name);
                tests.push(super::Test {
                    suite: "matrix",
                    group: "run_matrix",
                    id,
                    xfail: None,
                    timeout_secs: 60,
                    run: Box::new(move |_r| {
                        Box::pin(async move {
                            super::TestOutcome::new(
                                &listener,
                                false,
                                "FAIL: nonpie binary not found — mount at /opt/nonpie",
                            )
                        })
                    }),
                });
            }
            continue;
        }

        let name: &'static str = tc.name;
        let listener: &'static str = tc.listener;
        let connector: &'static str = tc.connector;

        // ── listen ──
        {
            tests.push(super::Test {
                suite: "matrix",
                group: "run_matrix",
                id: format!("N.{name}.listen"),
                xfail: None,
                timeout_secs: 60,
                run: Box::new(move |r| {
                    Box::pin(async move {
                        let resp = r.send(listener, Command::NetListen { port: p }).await;
                        let pass = matches!(resp, Response::Listening { .. });
                        // Clean up: unlisten so the port is free.
                        let _ = r.send(listener, Command::NetUnlisten { port: p }).await;
                        super::TestOutcome::new(listener, pass, format!("{resp:?}"))
                    })
                }),
            });
        }

        // ── connect ──
        {
            let test_data = format!("net_{name}");
            tests.push(super::Test {
                suite: "matrix",
                group: "run_matrix",
                id: format!("N.{name}.connect"),
                xfail: None,
                timeout_secs: 60,
                run: Box::new(move |r| {
                    Box::pin(async move {
                        // Self-contained: listen, connect, unlisten.
                        let resp = r.send(listener, Command::NetListen { port: p }).await;
                        if !matches!(resp, Response::Listening { .. }) {
                            return super::TestOutcome::new(
                                connector,
                                false,
                                format!("listen failed: {resp:?}"),
                            );
                        }
                        let resp = r
                            .send(
                                connector,
                                Command::NetConnect {
                                    addr: format!("127.0.0.1:{p}"),
                                    data: test_data.clone(),
                                },
                            )
                            .await;
                        let pass =
                            matches!(&resp, Response::Connected { echo } if *echo == test_data);
                        let _ = r.send(listener, Command::NetUnlisten { port: p }).await;
                        super::TestOutcome::new(connector, pass, format!("{resp:?}"))
                    })
                }),
            });
        }

        // ── unlisten ──
        {
            tests.push(super::Test {
                suite: "matrix",
                group: "run_matrix",
                id: format!("N.{name}.unlisten"),
                xfail: None,
                timeout_secs: 60,
                run: Box::new(move |r| {
                    Box::pin(async move {
                        // Self-contained: listen then unlisten.
                        let _ = r.send(listener, Command::NetListen { port: p }).await;
                        let resp = r.send(listener, Command::NetUnlisten { port: p }).await;
                        let pass = matches!(resp, Response::Ok { .. });
                        super::TestOutcome::new(listener, pass, format!("{resp:?}"))
                    })
                }),
            });
        }
    }
}

// ═══════════════════════════════════════════════════════════════════
// 6. NETWORK ADDRESS MATRIX — NA.{a}_to_{b}.{addr}
// ═══════════════════════════════════════════════════════════════════

pub(super) fn register_net_addr_tests(tests: &mut Vec<super::Test>) {
    let has_nonpie = crate::find_nonpie_binary().is_some();
    let mut port = 11_001u16;

    // We register tests for the two portable addresses; the self_ip
    // address is discovered at runtime and added dynamically.
    // To keep test IDs stable, the self_ip test uses "self_ip" as label.

    for &(agent_a, agent_b) in NET_ADDR_PAIRS {
        // Static addresses: 127.0.0.1, 0.0.0.0
        for &addr in CONNECT_ADDRS {
            let p = port;
            port += 1;

            if !has_nonpie && (agent_requires_nonpie(agent_a) || agent_requires_nonpie(agent_b)) {
                let agent_b_s = agent_b.to_string();
                let id = format!("NA.{agent_a}_to_{agent_b}.{addr}");
                tests.push(super::Test {
                    suite: "matrix",
                    group: "run_matrix",
                    id,
                    xfail: None,
                    timeout_secs: 60,
                    run: Box::new(move |_r| {
                        Box::pin(async move {
                            super::TestOutcome::new(
                                &agent_b_s,
                                false,
                                "FAIL: nonpie binary not found — mount at /opt/nonpie",
                            )
                        })
                    }),
                });
                continue;
            }

            let test_id = format!("NA.{agent_a}_to_{agent_b}.{addr}");
            let test_data = format!("na_{agent_a}_{agent_b}_{addr}");

            tests.push(super::Test {
                suite: "matrix",
                group: "run_matrix",
                id: test_id,
                xfail: None,
                timeout_secs: 60,
                run: Box::new(move |r| {
                    Box::pin(async move {
                        let resp = r.send(agent_a, Command::NetListen { port: p }).await;
                        if !matches!(resp, Response::Listening { .. }) {
                            return super::TestOutcome::new(
                                agent_b,
                                false,
                                format!("listen failed: {resp:?}"),
                            );
                        }
                        let resp = r
                            .send(
                                agent_b,
                                Command::NetConnect {
                                    addr: format!("{addr}:{p}"),
                                    data: test_data.clone(),
                                },
                            )
                            .await;
                        let pass =
                            matches!(&resp, Response::Connected { echo } if *echo == test_data);
                        let _ = r.send(agent_a, Command::NetUnlisten { port: p }).await;
                        super::TestOutcome::new(agent_b, pass, format!("{resp:?}"))
                    })
                }),
            });
        }

        // self_ip address (discovered at runtime via `hostname -I`)
        {
            let p = port;
            port += 1;

            if !has_nonpie && (agent_requires_nonpie(agent_a) || agent_requires_nonpie(agent_b)) {
                let agent_b_s = agent_b.to_string();
                let id = format!("NA.{agent_a}_to_{agent_b}.self_ip");
                tests.push(super::Test {
                    suite: "matrix",
                    group: "run_matrix",
                    id,
                    xfail: None,
                    timeout_secs: 60,
                    run: Box::new(move |_r| {
                        Box::pin(async move {
                            super::TestOutcome::new(
                                &agent_b_s,
                                false,
                                "FAIL: nonpie binary not found — mount at /opt/nonpie",
                            )
                        })
                    }),
                });
                continue;
            }

            let test_data = format!("na_{agent_a}_{agent_b}_self_ip");
            tests.push(super::Test {
                suite: "matrix",
                group: "run_matrix",
                id: format!("NA.{agent_a}_to_{agent_b}.self_ip"),
                xfail: None,
                timeout_secs: 60,
                run: Box::new(move |r| {
                    Box::pin(async move {
                        // Discover self IP at test time.
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
                                agent_b,
                                true, // skip — no self IP
                                "self_ip not discoverable, skipping",
                            );
                        };
                        let resp = r.send(agent_a, Command::NetListen { port: p }).await;
                        if !matches!(resp, Response::Listening { .. }) {
                            return super::TestOutcome::new(
                                agent_b,
                                false,
                                format!("listen failed: {resp:?}"),
                            );
                        }
                        let resp = r
                            .send(
                                agent_b,
                                Command::NetConnect {
                                    addr: format!("{addr}:{p}"),
                                    data: test_data.clone(),
                                },
                            )
                            .await;
                        let pass =
                            matches!(&resp, Response::Connected { echo } if *echo == test_data);
                        let _ = r.send(agent_a, Command::NetUnlisten { port: p }).await;
                        super::TestOutcome::new(agent_b, pass, format!("{resp:?}"))
                    })
                }),
            });
        }
    }
}

// ═══════════════════════════════════════════════════════════════════
// 7. UNIX ADDRESS MATRIX — UA.{a}_to_{b}
// ═══════════════════════════════════════════════════════════════════

pub(super) fn register_unix_addr_tests(tests: &mut Vec<super::Test>) {
    let has_nonpie = crate::find_nonpie_binary().is_some();
    let mut idx = 0u32;

    for &(agent_a, agent_b) in NET_ADDR_PAIRS {
        let i = idx;
        idx += 1;

        if !has_nonpie && (agent_requires_nonpie(agent_a) || agent_requires_nonpie(agent_b)) {
            let agent_b_s = agent_b.to_string();
            tests.push(super::Test {
                suite: "matrix",
                group: "run_matrix",
                id: format!("UA.{agent_a}_to_{agent_b}"),
                xfail: None,
                timeout_secs: 60,
                run: Box::new(move |_r| {
                    Box::pin(async move {
                        super::TestOutcome::new(
                            &agent_b_s,
                            false,
                            "FAIL: nonpie binary not found — mount at /opt/nonpie",
                        )
                    })
                }),
            });
            continue;
        }

        let test_data = format!("ua_{agent_a}_{agent_b}");
        tests.push(super::Test {
            suite: "matrix",
            group: "run_matrix",
            id: format!("UA.{agent_a}_to_{agent_b}"),
            xfail: None,
            timeout_secs: 60,
            run: Box::new(move |r| {
                Box::pin(async move {
                    let sock_path = format!("/tmp/ua-{i}.sock");
                    let resp = r
                        .send(
                            agent_a,
                            Command::UnixListen {
                                path: sock_path.clone(),
                            },
                        )
                        .await;
                    if !matches!(&resp, Response::UnixListening { .. }) {
                        return super::TestOutcome::new(
                            agent_b,
                            false,
                            format!("listen failed: {resp:?}"),
                        );
                    }
                    let resp = r
                        .send(
                            agent_b,
                            Command::UnixConnect {
                                path: sock_path.clone(),
                                data: test_data.clone(),
                            },
                        )
                        .await;
                    let pass = matches!(&resp, Response::Connected { echo } if *echo == test_data);
                    let _ = r
                        .send(agent_a, Command::UnixUnlisten { path: sock_path })
                        .await;
                    super::TestOutcome::new(agent_b, pass, format!("{resp:?}"))
                })
            }),
        });
    }
}

// ═══════════════════════════════════════════════════════════════════
// 8. EXEC — X.echo.{agent}, X.exit_code.{agent}.{code}
// ═══════════════════════════════════════════════════════════════════

pub(super) fn register_exec_tests(tests: &mut Vec<super::Test>) {
    let has_nonpie = crate::find_nonpie_binary().is_some();

    for &agent in EXEC_AGENTS {
        if !has_nonpie && agent_requires_nonpie(agent) {
            let agent_s = agent.to_string();
            tests.push(super::Test {
                suite: "matrix",
                group: "run_matrix",
                id: format!("X.echo.{agent}"),
                xfail: None,
                timeout_secs: 60,
                run: Box::new(move |_r| {
                    Box::pin(async move {
                        super::TestOutcome::new(
                            &agent_s,
                            false,
                            "FAIL: nonpie binary not found — mount at /opt/nonpie",
                        )
                    })
                }),
            });
            continue;
        }

        tests.push(super::Test {
            suite: "matrix",
            group: "run_matrix",
            id: format!("X.echo.{agent}"),
            xfail: None,
            timeout_secs: 60,
            run: Box::new(move |r| {
                Box::pin(async move {
                    let self_exe = r.self_exe.clone();
                    let resp = r
                        .send(agent, super::exec(vec![self_exe, "echo-test".into()]))
                        .await;
                    let pass = matches!(
                        &resp,
                        Response::ExecResult { stdout, .. } if stdout.contains("ECHO_TEST_OK")
                    );
                    super::TestOutcome::new(agent, pass, format!("{resp:?}"))
                })
            }),
        });
    }

    // Exit code propagation.
    for &(agent, code) in &[("A", 42i32), ("AAA", 7i32)] {
        tests.push(super::Test {
            suite: "matrix",
            group: "run_matrix",
            id: format!("X.exit_code.{agent}.{code}"),
            xfail: None,
            timeout_secs: 60,
            run: Box::new(move |r| {
                Box::pin(async move {
                    let self_exe = r.self_exe.clone();
                    let resp = r
                        .send(
                            agent,
                            super::exec(vec![self_exe, "exit-with".into(), code.to_string()]),
                        )
                        .await;
                    let pass = matches!(
                        &resp,
                        Response::ExecResult { exit_code, .. } if *exit_code == code
                    );
                    super::TestOutcome::new(agent, pass, format!("{resp:?}"))
                })
            }),
        });
    }
}

// ═══════════════════════════════════════════════════════════════════
// 9. ENV — E.HOME.{agent}, E.PATH.{agent}, E.CWD.{agent}
// ═══════════════════════════════════════════════════════════════════

pub(super) fn register_env_tests(tests: &mut Vec<super::Test>) {
    let has_nonpie = crate::find_nonpie_binary().is_some();

    for &agent in EXEC_AGENTS {
        if !has_nonpie && agent_requires_nonpie(agent) {
            for var in &["HOME", "PATH", "CWD"] {
                let agent_s = agent.to_string();
                let id = format!("E.{var}.{agent}");
                tests.push(super::Test {
                    suite: "matrix",
                    group: "run_matrix",
                    id,
                    xfail: None,
                    timeout_secs: 60,
                    run: Box::new(move |_r| {
                        Box::pin(async move {
                            super::TestOutcome::new(
                                &agent_s,
                                false,
                                "FAIL: nonpie binary not found — mount at /opt/nonpie",
                            )
                        })
                    }),
                });
            }
            continue;
        }

        // E.HOME
        {
            tests.push(super::Test {
                suite: "matrix",
                group: "run_matrix",
                id: format!("E.HOME.{agent}"),
                xfail: None,
                timeout_secs: 60,
                run: Box::new(move |r| {
                    Box::pin(async move {
                        let resp = r.send(agent, Command::EnvGet { var: "HOME".into() }).await;
                        let pass = matches!(
                            &resp,
                            Response::Ok { data: Some(d) } if !d.is_empty() && d != "NOT_SET"
                        );
                        super::TestOutcome::new(agent, pass, format!("{resp:?}"))
                    })
                }),
            });
        }

        // E.PATH
        {
            tests.push(super::Test {
                suite: "matrix",
                group: "run_matrix",
                id: format!("E.PATH.{agent}"),
                xfail: None,
                timeout_secs: 60,
                run: Box::new(move |r| {
                    Box::pin(async move {
                        let resp = r.send(agent, Command::EnvGet { var: "PATH".into() }).await;
                        let pass = matches!(
                            &resp,
                            Response::Ok { data: Some(d) } if !d.is_empty() && d != "NOT_SET"
                        );
                        super::TestOutcome::new(agent, pass, format!("{resp:?}"))
                    })
                }),
            });
        }

        // E.CWD
        {
            tests.push(super::Test {
                suite: "matrix",
                group: "run_matrix",
                id: format!("E.CWD.{agent}"),
                xfail: None,
                timeout_secs: 60,
                run: Box::new(move |r| {
                    Box::pin(async move {
                        let resp = r.send(agent, Command::CwdGet).await;
                        let pass = matches!(&resp, Response::Ok { data: Some(_) });
                        super::TestOutcome::new(agent, pass, format!("{resp:?}"))
                    })
                }),
            });
        }
    }
}

// ═══════════════════════════════════════════════════════════════════
// 10. SYMLINK BASIC — S.basic.{topo}.{create,readlink,read_through,stat_type}
// ═══════════════════════════════════════════════════════════════════

pub(super) fn register_symlink_basic(tests: &mut Vec<super::Test>) {
    for &topo in SYMLINK_TOPOLOGIES {
        let (source, dest) = topo.agents();
        let ts = topo.suffix();
        let source = source.to_string();
        let dest = dest.to_string();
        let ts_s = ts.to_string();

        // S.basic.{ts}.create
        {
            let source = source.clone();
            let ts_s = ts_s.clone();
            tests.push(super::Test {
                suite: "matrix",
                group: "run_matrix",
                id: format!("S.basic.{ts_s}.create"),
                xfail: None, // xfail probed at runtime
                timeout_secs: 60,
                run: Box::new(move |r| {
                    Box::pin(async move {
                        let file = format!("/shared/sm_{ts_s}_file");
                        let link = format!("/shared/sm_{ts_s}_link");
                        let data = format!("symdata_{ts_s}");
                        let _ = r
                            .send("init", Command::FsDelete { path: link.clone() })
                            .await;
                        let _ = r
                            .send("init", Command::FsDelete { path: file.clone() })
                            .await;
                        r.send(
                            &source,
                            Command::FsWrite {
                                path: file.clone(),
                                data,
                            },
                        )
                        .await;
                        let resp = r
                            .send(&source, Command::FsSymlink { target: file, link })
                            .await;
                        let pass = matches!(&resp, Response::Ok { .. });
                        super::TestOutcome::new(&source, pass, format!("{resp:?}"))
                    })
                }),
            });
        }

        // S.basic.{ts}.readlink
        {
            let source = source.clone();
            let ts_s = ts_s.clone();
            tests.push(super::Test {
                suite: "matrix",
                group: "run_matrix",
                id: format!("S.basic.{ts_s}.readlink"),
                xfail: None,
                timeout_secs: 60,
                run: Box::new(move |r| {
                    Box::pin(async move {
                        let file = format!("/shared/sm_{ts_s}_file");
                        let link = format!("/shared/sm_{ts_s}_link");
                        let data = format!("symdata_{ts_s}");
                        let _ = r
                            .send("init", Command::FsDelete { path: link.clone() })
                            .await;
                        let _ = r
                            .send("init", Command::FsDelete { path: file.clone() })
                            .await;
                        r.send(
                            &source,
                            Command::FsWrite {
                                path: file.clone(),
                                data,
                            },
                        )
                        .await;
                        r.send(
                            &source,
                            Command::FsSymlink {
                                target: file.clone(),
                                link: link.clone(),
                            },
                        )
                        .await;
                        let resp = r.send(&source, Command::FsReadlink { path: link }).await;
                        let pass = matches!(&resp, Response::Ok { data: Some(d) } if *d == file);
                        super::TestOutcome::new(&source, pass, format!("{resp:?}"))
                    })
                }),
            });
        }

        // S.basic.{ts}.read_through
        {
            let source = source.clone();
            let dest = dest.clone();
            let ts_s = ts_s.clone();
            tests.push(super::Test {
                suite: "matrix",
                group: "run_matrix",
                id: format!("S.basic.{ts_s}.read_through"),
                xfail: None,
                timeout_secs: 60,
                run: Box::new(move |r| {
                    Box::pin(async move {
                        let file = format!("/shared/sm_{ts_s}_file");
                        let link = format!("/shared/sm_{ts_s}_link");
                        let data = format!("symdata_{ts_s}");
                        let _ = r
                            .send("init", Command::FsDelete { path: link.clone() })
                            .await;
                        let _ = r
                            .send("init", Command::FsDelete { path: file.clone() })
                            .await;
                        r.send(
                            &source,
                            Command::FsWrite {
                                path: file.clone(),
                                data: data.clone(),
                            },
                        )
                        .await;
                        r.send(
                            &source,
                            Command::FsSymlink {
                                target: file,
                                link: link.clone(),
                            },
                        )
                        .await;
                        let resp = r.send(&dest, Command::FsRead { path: link }).await;
                        let pass = matches!(&resp, Response::Ok { data: Some(d) } if *d == data);
                        super::TestOutcome::new(&dest, pass, format!("{resp:?}"))
                    })
                }),
            });
        }

        // S.basic.{ts}.stat_type
        {
            let source = source.clone();
            let dest = dest.clone();
            let ts_s = ts_s.clone();
            tests.push(super::Test {
                suite: "matrix",
                group: "run_matrix",
                id: format!("S.basic.{ts_s}.stat_type"),
                xfail: None,
                timeout_secs: 60,
                run: Box::new(move |r| {
                    Box::pin(async move {
                        let file = format!("/shared/sm_{ts_s}_file");
                        let link = format!("/shared/sm_{ts_s}_link");
                        let data = format!("symdata_{ts_s}");
                        let _ = r
                            .send("init", Command::FsDelete { path: link.clone() })
                            .await;
                        let _ = r
                            .send("init", Command::FsDelete { path: file.clone() })
                            .await;
                        r.send(
                            &source,
                            Command::FsWrite {
                                path: file.clone(),
                                data,
                            },
                        )
                        .await;
                        r.send(
                            &source,
                            Command::FsSymlink {
                                target: file,
                                link: link.clone(),
                            },
                        )
                        .await;
                        let resp = r.send(&dest, Command::FsStat { path: link }).await;
                        let pass =
                            matches!(&resp, Response::Ok { data: Some(d) } if d == "symlink");
                        super::TestOutcome::new(&dest, pass, format!("{resp:?}"))
                    })
                }),
            });
        }
    }
}

// ═══════════════════════════════════════════════════════════════════
// 11. SYMLINK VARIANTS — S.{dir,dangling,nested,relative}.*
// ═══════════════════════════════════════════════════════════════════

pub(super) fn register_symlink_variants(tests: &mut Vec<super::Test>) {
    // S.dir.read_through
    tests.push(super::Test {
        suite: "matrix",
        group: "run_matrix",
        id: "S.dir.read_through".to_string(),
        xfail: None,
            timeout_secs: 60,
        run: Box::new(move |r| {
            Box::pin(async move {
                let agent = "A";
                let _ = r
                    .send(
                        agent,
                        super::exec(vec![
                            "rm".into(),
                            "-rf".into(),
                            "/shared/sv_dir".into(),
                            "/shared/sv_dirlink".into(),
                        ]),
                    )
                    .await;
                let _ = r
                    .send(
                        agent,
                        super::exec(vec![
                            "bash".into(),
                            "-c".into(),
                            "mkdir -p /shared/sv_dir && echo DIR_CONTENT > /shared/sv_dir/inside.txt"
                                .into(),
                        ]),
                    )
                    .await;
                r.send(
                    agent,
                    Command::FsSymlink {
                        target: "/shared/sv_dir".into(),
                        link: "/shared/sv_dirlink".into(),
                    },
                )
                .await;
                let resp = r
                    .send(
                        agent,
                        Command::FsRead {
                            path: "/shared/sv_dirlink/inside.txt".into(),
                        },
                    )
                    .await;
                let pass =
                    matches!(&resp, Response::Ok { data: Some(d) } if d.trim() == "DIR_CONTENT");
                super::TestOutcome::new(agent, pass, format!("{resp:?}"))
            })
        }),
    });

    // S.dangling.readlink
    tests.push(super::Test {
        suite: "matrix",
        group: "run_matrix",
        id: "S.dangling.readlink".to_string(),
        xfail: None,
        timeout_secs: 60,
        run: Box::new(move |r| {
            Box::pin(async move {
                let agent = "A";
                let _ = r
                    .send(
                        "init",
                        Command::FsDelete {
                            path: "/shared/sv_dangling".into(),
                        },
                    )
                    .await;
                r.send(
                    agent,
                    Command::FsSymlink {
                        target: "/shared/nonexistent_target".into(),
                        link: "/shared/sv_dangling".into(),
                    },
                )
                .await;
                let resp = r
                    .send(
                        agent,
                        Command::FsReadlink {
                            path: "/shared/sv_dangling".into(),
                        },
                    )
                    .await;
                let pass = matches!(
                    &resp,
                    Response::Ok { data: Some(d) } if d == "/shared/nonexistent_target"
                );
                super::TestOutcome::new(agent, pass, format!("{resp:?}"))
            })
        }),
    });

    // S.dangling.read_fails
    tests.push(super::Test {
        suite: "matrix",
        group: "run_matrix",
        id: "S.dangling.read_fails".to_string(),
        xfail: None,
        timeout_secs: 60,
        run: Box::new(move |r| {
            Box::pin(async move {
                let agent = "A";
                let _ = r
                    .send(
                        "init",
                        Command::FsDelete {
                            path: "/shared/sv_dangling".into(),
                        },
                    )
                    .await;
                r.send(
                    agent,
                    Command::FsSymlink {
                        target: "/shared/nonexistent_target".into(),
                        link: "/shared/sv_dangling".into(),
                    },
                )
                .await;
                let resp = r
                    .send(
                        agent,
                        Command::FsRead {
                            path: "/shared/sv_dangling".into(),
                        },
                    )
                    .await;
                let pass = matches!(&resp, Response::Error { .. } | Response::NotFound);
                super::TestOutcome::new(agent, pass, format!("{resp:?}"))
            })
        }),
    });

    // S.nested.read_through
    tests.push(super::Test {
        suite: "matrix",
        group: "run_matrix",
        id: "S.nested.read_through".to_string(),
        xfail: None,
        timeout_secs: 60,
        run: Box::new(move |r| {
            Box::pin(async move {
                let agent = "A";
                for name in ["sv_nested_link1", "sv_nested_link2", "sv_nested_file"] {
                    let _ = r
                        .send(
                            "init",
                            Command::FsDelete {
                                path: format!("/shared/{name}"),
                            },
                        )
                        .await;
                }
                r.send(
                    agent,
                    Command::FsWrite {
                        path: "/shared/sv_nested_file".into(),
                        data: "NESTED_DATA".into(),
                    },
                )
                .await;
                r.send(
                    agent,
                    Command::FsSymlink {
                        target: "/shared/sv_nested_file".into(),
                        link: "/shared/sv_nested_link2".into(),
                    },
                )
                .await;
                r.send(
                    agent,
                    Command::FsSymlink {
                        target: "/shared/sv_nested_link2".into(),
                        link: "/shared/sv_nested_link1".into(),
                    },
                )
                .await;
                let resp = r
                    .send(
                        agent,
                        Command::FsRead {
                            path: "/shared/sv_nested_link1".into(),
                        },
                    )
                    .await;
                let pass = matches!(&resp, Response::Ok { data: Some(d) } if d == "NESTED_DATA");
                super::TestOutcome::new(agent, pass, format!("{resp:?}"))
            })
        }),
    });

    // S.relative.read_through
    tests.push(super::Test {
        suite: "matrix",
        group: "run_matrix",
        id: "S.relative.read_through".to_string(),
        xfail: None,
        timeout_secs: 60,
        run: Box::new(move |r| {
            Box::pin(async move {
                let agent = "A";
                for name in ["sv_rel_file", "sv_rel_link"] {
                    let _ = r
                        .send(
                            "init",
                            Command::FsDelete {
                                path: format!("/shared/{name}"),
                            },
                        )
                        .await;
                }
                r.send(
                    agent,
                    Command::FsWrite {
                        path: "/shared/sv_rel_file".into(),
                        data: "REL_DATA".into(),
                    },
                )
                .await;
                r.send(
                    agent,
                    Command::FsSymlink {
                        target: "sv_rel_file".into(),
                        link: "/shared/sv_rel_link".into(),
                    },
                )
                .await;
                let resp = r
                    .send(
                        agent,
                        Command::FsRead {
                            path: "/shared/sv_rel_link".into(),
                        },
                    )
                    .await;
                let pass = matches!(&resp, Response::Ok { data: Some(d) } if d == "REL_DATA");
                super::TestOutcome::new(agent, pass, format!("{resp:?}"))
            })
        }),
    });
}

// ═══════════════════════════════════════════════════════════════════
// 12. UNIX SOCKETS — U.{name}.{listen,connect,...}
// ═══════════════════════════════════════════════════════════════════

pub(super) fn register_unix_tests(tests: &mut Vec<super::Test>) {
    let has_nonpie = crate::find_nonpie_binary().is_some();

    for tc in unix_test_cases() {
        if !has_nonpie
            && (agent_requires_nonpie(tc.agent)
                || tc.peer.is_some_and(|p| agent_requires_nonpie(p)))
        {
            let suffixes: &[&str] = match tc.pattern {
                UnixPattern::InProcess => &["listen", "connect"],
                UnixPattern::ServerForkClient => &["listen", "child_connect"],
                UnixPattern::BackgroundServerConnect => &["server_start", "connect"],
                UnixPattern::CrossAgent => &["listen", "connect"],
            };
            for suffix in suffixes {
                let agent_s = tc.agent.to_string();
                let id = format!("U.{}.{suffix}", tc.name);
                tests.push(super::Test {
                    suite: "matrix",
                    group: "run_matrix",
                    id,
                    xfail: None,
                    timeout_secs: 60,
                    run: Box::new(move |_r| {
                        Box::pin(async move {
                            super::TestOutcome::new(
                                &agent_s,
                                false,
                                "FAIL: nonpie binary not found — mount at /opt/nonpie",
                            )
                        })
                    }),
                });
            }
            continue;
        }

        let sock = format!("/tmp/um_{}.sock", tc.name.replace('.', "_"));

        match tc.pattern {
            UnixPattern::InProcess => {
                // U.{name}.listen
                {
                    let agent: &'static str = tc.agent;
                    let sock = sock.clone();
                    let name: &'static str = tc.name;
                    tests.push(super::Test {
                        suite: "matrix",
                        group: "run_matrix",
                        id: format!("U.{name}.listen"),
                        xfail: None,
                        timeout_secs: 60,
                        run: Box::new(move |r| {
                            Box::pin(async move {
                                let resp = r
                                    .send(agent, Command::UnixListen { path: sock.clone() })
                                    .await;
                                let pass = matches!(&resp, Response::UnixListening { .. });
                                let _ = r.send(agent, Command::UnixUnlisten { path: sock }).await;
                                super::TestOutcome::new(agent, pass, format!("{resp:?}"))
                            })
                        }),
                    });
                }
                // U.{name}.connect
                {
                    let agent: &'static str = tc.agent;
                    let sock = sock.clone();
                    let name: &'static str = tc.name;
                    tests.push(super::Test {
                        suite: "matrix",
                        group: "run_matrix",
                        id: format!("U.{name}.connect"),
                        xfail: None,
                        timeout_secs: 60,
                        run: Box::new(move |r| {
                            Box::pin(async move {
                                let resp = r
                                    .send(agent, Command::UnixListen { path: sock.clone() })
                                    .await;
                                if !matches!(&resp, Response::UnixListening { .. }) {
                                    return super::TestOutcome::new(
                                        agent,
                                        false,
                                        format!("listen failed: {resp:?}"),
                                    );
                                }
                                let data = format!("unix_{name}");
                                let resp = r
                                    .send(
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
                                let _ = r.send(agent, Command::UnixUnlisten { path: sock }).await;
                                super::TestOutcome::new(agent, pass, format!("{resp:?}"))
                            })
                        }),
                    });
                }
            }

            UnixPattern::ServerForkClient => {
                // U.{name}.listen
                {
                    let agent: &'static str = tc.agent;
                    let sock = sock.clone();
                    let name: &'static str = tc.name;
                    tests.push(super::Test {
                        suite: "matrix",
                        group: "run_matrix",
                        id: format!("U.{name}.listen"),
                        xfail: None,
                        timeout_secs: 60,
                        run: Box::new(move |r| {
                            Box::pin(async move {
                                let resp = r
                                    .send(agent, Command::UnixListen { path: sock.clone() })
                                    .await;
                                let pass = matches!(&resp, Response::UnixListening { .. });
                                let _ = r.send(agent, Command::UnixUnlisten { path: sock }).await;
                                super::TestOutcome::new(agent, pass, format!("{resp:?}"))
                            })
                        }),
                    });
                }
                // U.{name}.child_connect
                {
                    let agent: &'static str = tc.agent;
                    let sock = sock.clone();
                    let name: &'static str = tc.name;
                    tests.push(super::Test {
                        suite: "matrix",
                        group: "run_matrix",
                        id: format!("U.{name}.child_connect"),
                        xfail: None,
                        timeout_secs: 60,
                        run: Box::new(move |r| {
                            Box::pin(async move {
                                let self_exe = r.self_exe.clone();
                                let resp = r
                                    .send(agent, Command::UnixListen { path: sock.clone() })
                                    .await;
                                if !matches!(&resp, Response::UnixListening { .. }) {
                                    return super::TestOutcome::new(
                                        agent,
                                        false,
                                        format!("listen failed: {resp:?}"),
                                    );
                                }
                                let data = format!("unix_{name}");
                                let resp = r
                                    .send(
                                        agent,
                                        super::exec(vec![
                                            self_exe,
                                            "unix-echo-client".into(),
                                            sock.clone(),
                                            data.clone(),
                                        ]),
                                    )
                                    .await;
                                let pass = matches!(
                                    &resp,
                                    Response::ExecResult { exit_code: 0, stdout, .. }
                                        if stdout.contains(&data)
                                );
                                let _ = r.send(agent, Command::UnixUnlisten { path: sock }).await;
                                super::TestOutcome::new(agent, pass, format!("{resp:?}"))
                            })
                        }),
                    });
                }
            }

            UnixPattern::BackgroundServerConnect => {
                // U.{name}.server_start
                {
                    let agent: &'static str = tc.agent;
                    let sock = sock.clone();
                    let name: &'static str = tc.name;
                    tests.push(super::Test {
                        suite: "matrix",
                        group: "run_matrix",
                        id: format!("U.{name}.server_start"),
                        xfail: None,
                        timeout_secs: 60,
                        run: Box::new(move |r| {
                            Box::pin(async move {
                                let self_exe = r.self_exe.clone();
                                let resp = r
                                    .send(
                                        agent,
                                        Command::Exec {
                                            args: vec![
                                                self_exe,
                                                "unix-echo-server".into(),
                                                sock.clone(),
                                            ],
                                            timeout_secs: None,
                                            stdin: None,
                                            background: true,
                                        },
                                    )
                                    .await;
                                let pid = match &resp {
                                    Response::Background { pid } => Some(*pid),
                                    _ => None,
                                };
                                let pass = pid.is_some();
                                // Kill the server.
                                if let Some(pid) = pid {
                                    let _ = r.send(agent, Command::Kill { pid }).await;
                                }
                                let _ = r.send(agent, Command::UnixUnlisten { path: sock }).await;
                                super::TestOutcome::new(agent, pass, format!("{resp:?}"))
                            })
                        }),
                    });
                }
                // U.{name}.connect
                {
                    let agent: &'static str = tc.agent;
                    let sock = sock.clone();
                    let name: &'static str = tc.name;
                    tests.push(super::Test {
                        suite: "matrix",
                        group: "run_matrix",
                        id: format!("U.{name}.connect"),
                        xfail: None,
                        timeout_secs: 60,
                        run: Box::new(move |r| {
                            Box::pin(async move {
                                let self_exe = r.self_exe.clone();
                                let resp = r
                                    .send(
                                        agent,
                                        Command::Exec {
                                            args: vec![
                                                self_exe,
                                                "unix-echo-server".into(),
                                                sock.clone(),
                                            ],
                                            timeout_secs: None,
                                            stdin: None,
                                            background: true,
                                        },
                                    )
                                    .await;
                                let pid = match &resp {
                                    Response::Background { pid } => Some(*pid),
                                    _ => None,
                                };
                                if pid.is_none() {
                                    return super::TestOutcome::new(
                                        agent,
                                        false,
                                        format!("server_start failed: {resp:?}"),
                                    );
                                }

                                tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

                                let data = format!("unix_{name}");
                                let resp = r
                                    .send(
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
                                    let _ = r.send(agent, Command::Kill { pid }).await;
                                }
                                let _ = r.send(agent, Command::UnixUnlisten { path: sock }).await;
                                super::TestOutcome::new(agent, pass, format!("{resp:?}"))
                            })
                        }),
                    });
                }
            }

            UnixPattern::CrossAgent => {
                let connector: &'static str = tc.peer.unwrap();
                let agent: &'static str = tc.agent;
                let name: &'static str = tc.name;

                // U.{name}.listen
                {
                    let sock = sock.clone();
                    tests.push(super::Test {
                        suite: "matrix",
                        group: "run_matrix",
                        id: format!("U.{name}.listen"),
                        xfail: None,
                        timeout_secs: 60,
                        run: Box::new(move |r| {
                            Box::pin(async move {
                                let resp = r
                                    .send(agent, Command::UnixListen { path: sock.clone() })
                                    .await;
                                let pass = matches!(&resp, Response::UnixListening { .. });
                                let _ = r.send(agent, Command::UnixUnlisten { path: sock }).await;
                                super::TestOutcome::new(agent, pass, format!("{resp:?}"))
                            })
                        }),
                    });
                }

                // U.{name}.connect
                {
                    let sock = sock.clone();
                    tests.push(super::Test {
                        suite: "matrix",
                        group: "run_matrix",
                        id: format!("U.{name}.connect"),
                        xfail: None,
                        timeout_secs: 60,
                        run: Box::new(move |r| {
                            Box::pin(async move {
                                let data = format!("unix_{name}");
                                let resp = r
                                    .send(agent, Command::UnixListen { path: sock.clone() })
                                    .await;
                                if !matches!(&resp, Response::UnixListening { .. }) {
                                    return super::TestOutcome::new(
                                        connector,
                                        false,
                                        format!("listen failed: {resp:?}"),
                                    );
                                }
                                let resp = r
                                    .send(
                                        connector,
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
                                let _ = r.send(agent, Command::UnixUnlisten { path: sock }).await;
                                super::TestOutcome::new(connector, pass, format!("{resp:?}"))
                            })
                        }),
                    });
                }
            }
        }
    }

    // ── Minimal cross-worker unix socket repro ──
    if has_nonpie {
        // U.repro.listen
        tests.push(super::Test {
            suite: "matrix",
            group: "run_matrix",
            id: "U.repro.listen".to_string(),
            xfail: None,
            timeout_secs: 60,
            run: Box::new(move |r| {
                Box::pin(async move {
                    let sock = "/tmp/um_repro_xworker.sock".to_string();
                    let resp = r
                        .send("D3", Command::UnixListen { path: sock.clone() })
                        .await;
                    let pass = matches!(&resp, Response::UnixListening { .. });
                    let _ = r.send("D3", Command::UnixUnlisten { path: sock }).await;
                    super::TestOutcome::new("D3", pass, format!("{resp:?}"))
                })
            }),
        });

        // U.repro.same_agent
        tests.push(super::Test {
            suite: "matrix",
            group: "run_matrix",
            id: "U.repro.same_agent".to_string(),
            xfail: None,
            timeout_secs: 60,
            run: Box::new(move |r| {
                Box::pin(async move {
                    let sock = "/tmp/um_repro_xworker.sock".to_string();
                    let resp = r
                        .send("D3", Command::UnixListen { path: sock.clone() })
                        .await;
                    if !matches!(&resp, Response::UnixListening { .. }) {
                        return super::TestOutcome::new(
                            "D3",
                            false,
                            format!("listen failed: {resp:?}"),
                        );
                    }
                    let resp = r
                        .send(
                            "D3",
                            Command::UnixConnect {
                                path: sock.clone(),
                                data: "SAME_AGENT".to_string(),
                            },
                        )
                        .await;
                    let pass =
                        matches!(&resp, Response::Connected { echo } if echo.contains("SAME_AGENT"));
                    let _ = r
                        .send("D3", Command::UnixUnlisten { path: sock })
                        .await;
                    super::TestOutcome::new("D3", pass, format!("{resp:?}"))
                })
            }),
        });

        // U.repro.cross_worker
        tests.push(super::Test {
            suite: "matrix",
            group: "run_matrix",
            id: "U.repro.cross_worker".to_string(),
            xfail: None,
            timeout_secs: 60,
            run: Box::new(move |r| {
                Box::pin(async move {
                    let sock = "/tmp/um_repro_xworker.sock".to_string();
                    let resp = r
                        .send("D3", Command::UnixListen { path: sock.clone() })
                        .await;
                    if !matches!(&resp, Response::UnixListening { .. }) {
                        return super::TestOutcome::new(
                            "D4",
                            false,
                            format!("listen failed: {resp:?}"),
                        );
                    }
                    let resp = r
                        .send(
                            "D4",
                            Command::UnixConnect {
                                path: sock.clone(),
                                data: "CROSS_WORKER".to_string(),
                            },
                        )
                        .await;
                    let pass = matches!(
                        &resp,
                        Response::Connected { echo } if echo.contains("CROSS_WORKER")
                    );
                    let _ = r.send("D3", Command::UnixUnlisten { path: sock }).await;
                    super::TestOutcome::new("D4", pass, format!("{resp:?}"))
                })
            }),
        });
    } else {
        for (id, agent) in [
            ("U.repro.listen", "D3"),
            ("U.repro.same_agent", "D3"),
            ("U.repro.cross_worker", "D4"),
        ] {
            let agent = agent.to_string();
            tests.push(super::Test {
                suite: "matrix",
                group: "run_matrix",
                id: id.to_string(),
                xfail: None,
                timeout_secs: 60,
                run: Box::new(move |_r| {
                    Box::pin(async move {
                        super::TestOutcome::new(
                            &agent,
                            false,
                            "FAIL: nonpie binary not found — mount at /opt/nonpie",
                        )
                    })
                }),
            });
        }
    }
}

// ═══════════════════════════════════════════════════════════════════
// MASTER REGISTER — collects all matrix tests
// ═══════════════════════════════════════════════════════════════════

/// Register all matrix tests into the given vector.
///
/// Replaces the old `run_matrix_tests` imperative runner.
/// Environment setup (/shared, /root, host_wrote.txt) should be done
/// by the caller before running these tests.
pub(super) fn register_matrix(tests: &mut Vec<super::Test>) {
    register_fs_crud(tests);
    register_fs_cross_unlink(tests);
    register_tmp_isolation(tests);
    register_host_file(tests);
    register_net_tests(tests);
    register_net_addr_tests(tests);
    register_unix_addr_tests(tests);
    register_exec_tests(tests);
    register_env_tests(tests);
    register_symlink_basic(tests);
    register_symlink_variants(tests);
    register_unix_tests(tests);
}
