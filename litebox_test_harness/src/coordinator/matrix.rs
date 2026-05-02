// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Declarative test matrix — drives "cover all configurations" tests via
//! structured loops over typed dimensions.
//!
//! Dimensions:
//! - **Topology**: (source, dest) agent pairs in the process tree, including init
//! - **FsScope**: /shared (visible) vs /tmp (isolated)
//! - **SymlinkVariant**: basic, directory, dangling, nested, relative
//! - **UnixPattern**: in-process, server+fork-client, background-server, cross-agent
//! - **UnixDepth**: which agent depth runs the pattern
//!
//! Note: `init` (the coordinator) is a first-class node in the process tree for
//! FS tests (it handles FsRead/FsWrite/FsDelete/FsSymlink/FsReadlink/FsStat/
//! NetConnect locally). It cannot listen on TCP or Unix sockets.

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

fn record_xfail_if(
    r: &mut TestRunner,
    test_id: &str,
    agent: &str,
    pass: bool,
    detail: &str,
    xfail_reason: Option<&str>,
) {
    if let Some(reason) = xfail_reason {
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

/// FS CRUD on /shared: source writes, dest reads, verifies.
async fn test_fs_crud(r: &mut TestRunner, topo: Topology) {
    let (source, dest) = topo.agents();
    let ts = topo.suffix();
    let file = format!("/shared/matrix_{ts}.txt");
    let data = format!("data_{ts}");
    let updated = format!("updated_{ts}");

    let _ = r
        .send("init", Command::FsDelete { path: file.clone() })
        .await;

    let resp = r.send(dest, Command::FsRead { path: file.clone() }).await;
    r.record(
        &format!("F.shared.{ts}.absent"),
        dest,
        matches!(resp, Response::NotFound),
        &format!("{resp:?}"),
    );

    r.send(
        source,
        Command::FsWrite {
            path: file.clone(),
            data: data.clone(),
        },
    )
    .await;
    let resp = r.send(dest, Command::FsRead { path: file.clone() }).await;
    let pass = matches!(&resp, Response::Ok { data: Some(d) } if *d == data);
    r.record(
        &format!("F.shared.{ts}.created"),
        dest,
        pass,
        &format!("{resp:?}"),
    );

    r.send(
        source,
        Command::FsWrite {
            path: file.clone(),
            data: updated.clone(),
        },
    )
    .await;
    let resp = r.send(dest, Command::FsRead { path: file.clone() }).await;
    let pass = matches!(&resp, Response::Ok { data: Some(d) } if *d == updated);
    r.record(
        &format!("F.shared.{ts}.updated"),
        dest,
        pass,
        &format!("{resp:?}"),
    );

    r.send(source, Command::FsDelete { path: file.clone() })
        .await;
    let resp = r.send(dest, Command::FsRead { path: file.clone() }).await;
    r.record(
        &format!("F.shared.{ts}.deleted"),
        dest,
        matches!(resp, Response::NotFound),
        &format!("{resp:?}"),
    );
}

/// Cross-topology unlink: source creates file, dest unlinks it.
/// Reproduces the VS Code pattern where code-server creates log files
/// and a later session tries to clean them up.
async fn test_fs_cross_unlink(r: &mut TestRunner, topo: Topology) {
    let (source, dest) = topo.agents();
    let ts = topo.suffix();
    let file = format!("/shared/unlink_{ts}.txt");

    // Clean up from prior runs.
    let _ = r
        .send("init", Command::FsDelete { path: file.clone() })
        .await;

    // Source creates the file.
    r.send(
        source,
        Command::FsWrite {
            path: file.clone(),
            data: "unlink_me".into(),
        },
    )
    .await;

    // Dest unlinks it.
    let resp = r.send(dest, Command::FsDelete { path: file.clone() }).await;
    let delete_ok = matches!(&resp, Response::Ok { .. });
    r.record(
        &format!("F.unlink.{ts}.delete"),
        dest,
        delete_ok,
        &format!("{resp:?}"),
    );

    // Source confirms it's gone.
    let resp = r.send(source, Command::FsRead { path: file.clone() }).await;
    r.record(
        &format!("F.unlink.{ts}.gone"),
        source,
        matches!(resp, Response::NotFound),
        &format!("{resp:?}"),
    );
}

/// /tmp isolation: writer writes to /tmp, reader checks visibility.
async fn test_tmp_isolation(r: &mut TestRunner, topo: Topology) {
    let (writer, reader) = topo.agents();
    if writer == reader {
        return; // skip InProcess — same agent sees its own /tmp
    }
    let ts = topo.suffix();
    let file = format!("/tmp/matrix_iso_{ts}.txt");

    r.send(
        writer,
        Command::FsWrite {
            path: file.clone(),
            data: "tmp_test".into(),
        },
    )
    .await;
    let resp = r.send(reader, Command::FsRead { path: file.clone() }).await;
    let is_isolated = matches!(resp, Response::NotFound);
    r.record(
        &format!("F.tmp.{ts}.isolation"),
        reader,
        true, // informational — always pass
        &format!("isolated={is_isolated}: {resp:?}"),
    );
}

/// Host-written file visibility: build_rootfs puts /shared/host_wrote.txt.
async fn test_host_file(r: &mut TestRunner) {
    for agent in &["init", "A", "AA"] {
        let resp = r
            .send(
                agent,
                Command::FsRead {
                    path: "/shared/host_wrote.txt".into(),
                },
            )
            .await;
        let pass = matches!(&resp, Response::Ok { data: Some(d) } if d == "from_host");
        let test_id = format!("F.host.{agent}");
        if matches!(&resp, Response::NotFound) {
            // File not in rootfs — skip (environment precondition, not a test failure).
            r.record(&test_id, agent, false, "FAIL: host_wrote.txt not in rootfs");
        } else {
            r.record(&test_id, agent, pass, &format!("{resp:?}"));
        }
    }
    // Write file for host to read after exit.
    r.send(
        "init",
        Command::FsWrite {
            path: "/shared/for_host.txt".into(),
            data: "from_agent".into(),
        },
    )
    .await;
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

async fn run_net_tests(r: &mut TestRunner) {
    let has_nonpie = crate::find_nonpie_binary().is_some();
    let mut port = 10_001u16;
    for tc in NET_TESTS {
        if !has_nonpie
            && (agent_requires_nonpie(tc.listener) || agent_requires_nonpie(tc.connector))
        {
            r.record(
                &format!("N.{}.listen", tc.name),
                tc.listener,
                false,
                "FAIL: nonpie binary not found — mount at /opt/nonpie",
            );
            port += 1;
            continue;
        }

        let test_data = format!("net_{}", tc.name);

        let resp = r.send(tc.listener, Command::NetListen { port }).await;
        r.record(
            &format!("N.{}.listen", tc.name),
            tc.listener,
            matches!(resp, Response::Listening { .. }),
            &format!("{resp:?}"),
        );

        let resp = r
            .send(
                tc.connector,
                Command::NetConnect {
                    addr: format!("127.0.0.1:{port}"),
                    data: test_data.clone(),
                },
            )
            .await;
        let pass = matches!(&resp, Response::Connected { echo } if *echo == test_data);
        r.record(
            &format!("N.{}.connect", tc.name),
            tc.connector,
            pass,
            &format!("{resp:?}"),
        );

        let resp = r.send(tc.listener, Command::NetUnlisten { port }).await;
        r.record(
            &format!("N.{}.unlisten", tc.name),
            tc.listener,
            matches!(resp, Response::Ok { .. }),
            &format!("{resp:?}"),
        );

        port += 1;
    }
}

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

async fn run_net_addr_tests(r: &mut TestRunner) {
    let has_nonpie = crate::find_nonpie_binary().is_some();
    let mut port = 11_001u16;

    // Discover the host's non-loopback IP dynamically.
    // On native Docker: bridge IP (e.g., 172.17.0.5)
    // On litebox: smoltcp virtual IP (10.0.0.2)
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

    // Build address list: portable + self-IP (if discovered)
    let mut addrs: Vec<&str> = CONNECT_ADDRS.to_vec();
    if let Some(ref ip) = self_ip {
        addrs.push(ip.as_str());
    }

    let self_ip_label = self_ip.as_deref().unwrap_or("none");
    eprintln!(
        "[matrix] === Network Address ({} pairs × {} addrs [127.0.0.1, 0.0.0.0, {self_ip_label}]) ===",
        NET_ADDR_PAIRS.len(),
        addrs.len(),
    );

    for &(agent_a, agent_b) in NET_ADDR_PAIRS {
        for &addr in &addrs {
            let is_self_ip = self_ip.as_deref() == Some(addr);
            // Skip non-PIE agents if binary not available
            if !has_nonpie && (agent_requires_nonpie(agent_a) || agent_requires_nonpie(agent_b)) {
                r.record(
                    &format!("NA.{agent_a}_to_{agent_b}.{addr}"),
                    agent_a,
                    false,
                    "FAIL: nonpie binary not found — mount at /opt/nonpie",
                );
                port += 1;
                continue;
            }

            // Direction 1: agent_a listens, agent_b connects
            let test_id = format!("NA.{agent_a}_to_{agent_b}.{addr}");
            let test_data = format!("na_{agent_a}_{agent_b}_{addr}");

            let resp = r.send(agent_a, Command::NetListen { port }).await;
            let listen_ok = matches!(resp, Response::Listening { .. });
            if !listen_ok {
                r.record(
                    &test_id,
                    agent_a,
                    false,
                    &format!("listen failed: {resp:?}"),
                );
                port += 1;
                continue;
            }

            let resp = r
                .send(
                    agent_b,
                    Command::NetConnect {
                        addr: format!("{addr}:{port}"),
                        data: test_data.clone(),
                    },
                )
                .await;
            let pass = matches!(&resp, Response::Connected { echo } if *echo == test_data);

            if is_self_ip {
                // 10.0.0.2 (or the native equivalent) — on native this is
                // the Docker bridge IP, on litebox it's the smoltcp virtual IP.
                // Both should work as self-connect. If the address wasn't
                // discoverable, the test was skipped (no is_litebox_only entry).
                r.record(&test_id, agent_b, pass, &format!("{resp:?}"));
            } else {
                r.record(&test_id, agent_b, pass, &format!("{resp:?}"));
            }

            let _ = r.send(agent_a, Command::NetUnlisten { port }).await;
            port += 1;
        }
    }
}

// ═══════════════════════════════════════════════════════════════════
// UNIX SOCKET ADDRESS MATRIX — cross-worker Unix sockets across topology
// ═══════════════════════════════════════════════════════════════════
//
// Tests Unix domain sockets across the same topology pairs as TCP,
// ensuring cross-worker Unix sockets work at every depth.

async fn run_unix_addr_tests(r: &mut TestRunner) {
    let has_nonpie = crate::find_nonpie_binary().is_some();
    let mut idx = 0u32;

    for &(agent_a, agent_b) in NET_ADDR_PAIRS {
        if !has_nonpie && (agent_requires_nonpie(agent_a) || agent_requires_nonpie(agent_b)) {
            r.record(
                &format!("UA.{agent_a}_to_{agent_b}"),
                agent_a,
                false,
                "FAIL: nonpie binary not found — mount at /opt/nonpie",
            );
            idx += 1;
            continue;
        }

        let test_id = format!("UA.{agent_a}_to_{agent_b}");
        let sock_path = format!("/tmp/ua-{idx}.sock");
        let test_data = format!("ua_{agent_a}_{agent_b}");

        let resp = r
            .send(
                agent_a,
                Command::UnixListen {
                    path: sock_path.clone(),
                },
            )
            .await;
        let listen_ok = matches!(&resp, Response::UnixListening { .. });
        if !listen_ok {
            r.record(
                &test_id,
                agent_a,
                false,
                &format!("listen failed: {resp:?}"),
            );
            idx += 1;
            continue;
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
        r.record(&test_id, agent_b, pass, &format!("{resp:?}"));

        let _ = r
            .send(agent_a, Command::UnixUnlisten { path: sock_path })
            .await;
        idx += 1;
    }
}

// ═══════════════════════════════════════════════════════════════════
// EXEC & ENV
// ═══════════════════════════════════════════════════════════════════

const EXEC_AGENTS: &[&str] = &["A", "AA", "AAA", "NP", "NPC", "D5"];

async fn run_exec_tests(r: &mut TestRunner) {
    let self_exe = r.self_exe.clone();
    let has_nonpie = crate::find_nonpie_binary().is_some();

    for &agent in EXEC_AGENTS {
        if !has_nonpie && agent_requires_nonpie(agent) {
            r.record(
                &format!("X.echo.{agent}"),
                agent,
                false,
                "FAIL: nonpie binary not found — mount at /opt/nonpie",
            );
            continue;
        }
        // Echo test.
        let resp = r
            .send(
                agent,
                super::exec(vec![self_exe.clone(), "echo-test".into()]),
            )
            .await;
        let pass =
            matches!(&resp, Response::ExecResult { stdout, .. } if stdout.contains("ECHO_TEST_OK"));
        r.record(
            &format!("X.echo.{agent}"),
            agent,
            pass,
            &format!("{resp:?}"),
        );
    }

    // Exit code propagation.
    for &(agent, code) in &[("A", 42), ("AAA", 7)] {
        let resp = r
            .send(
                agent,
                super::exec(vec![self_exe.clone(), "exit-with".into(), code.to_string()]),
            )
            .await;
        let pass = matches!(&resp, Response::ExecResult { exit_code, .. } if *exit_code == code);
        r.record(
            &format!("X.exit_code.{agent}.{code}"),
            agent,
            pass,
            &format!("{resp:?}"),
        );
    }
}

async fn run_env_tests(r: &mut TestRunner) {
    let has_nonpie = crate::find_nonpie_binary().is_some();
    for &agent in EXEC_AGENTS {
        if !has_nonpie && agent_requires_nonpie(agent) {
            r.record(
                &format!("E.HOME.{agent}"),
                agent,
                false,
                "FAIL: nonpie binary not found — mount at /opt/nonpie",
            );
            continue;
        }
        let resp = r.send(agent, Command::EnvGet { var: "HOME".into() }).await;
        let pass =
            matches!(&resp, Response::Ok { data: Some(d) } if !d.is_empty() && d != "NOT_SET");
        r.record(
            &format!("E.HOME.{agent}"),
            agent,
            pass,
            &format!("{resp:?}"),
        );

        let resp = r.send(agent, Command::EnvGet { var: "PATH".into() }).await;
        let pass =
            matches!(&resp, Response::Ok { data: Some(d) } if !d.is_empty() && d != "NOT_SET");
        r.record(
            &format!("E.PATH.{agent}"),
            agent,
            pass,
            &format!("{resp:?}"),
        );

        let resp = r.send(agent, Command::CwdGet).await;
        let pass = matches!(&resp, Response::Ok { data: Some(_) });
        r.record(&format!("E.CWD.{agent}"), agent, pass, &format!("{resp:?}"));
    }
}

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

async fn run_unix_tests(r: &mut TestRunner) {
    let self_exe = r.self_exe.clone();
    let has_nonpie = crate::find_nonpie_binary().is_some();

    for tc in &unix_test_cases() {
        // Skip tests that require non-PIE agents when the binary isn't available.
        if !has_nonpie
            && (agent_requires_nonpie(tc.agent)
                || tc.peer.is_some_and(|p| agent_requires_nonpie(p)))
        {
            r.record(
                &format!("U.{}.listen", tc.name),
                tc.agent,
                false,
                "FAIL: nonpie binary not found — mount at /opt/nonpie",
            );
            continue;
        }

        let sock = format!("/tmp/um_{}.sock", tc.name.replace('.', "_"));

        match tc.pattern {
            UnixPattern::InProcess => {
                let resp = r
                    .send(tc.agent, Command::UnixListen { path: sock.clone() })
                    .await;
                r.record(
                    &format!("U.{}.listen", tc.name),
                    tc.agent,
                    matches!(&resp, Response::UnixListening { .. }),
                    &format!("{resp:?}"),
                );

                let data = format!("unix_{}", tc.name);
                let resp = r
                    .send(
                        tc.agent,
                        Command::UnixConnect {
                            path: sock.clone(),
                            data: data.clone(),
                        },
                    )
                    .await;
                let pass = matches!(&resp, Response::Connected { echo } if *echo == data);
                r.record(
                    &format!("U.{}.connect", tc.name),
                    tc.agent,
                    pass,
                    &format!("{resp:?}"),
                );

                let _ = r.send(tc.agent, Command::UnixUnlisten { path: sock }).await;
            }

            UnixPattern::ServerForkClient => {
                let resp = r
                    .send(tc.agent, Command::UnixListen { path: sock.clone() })
                    .await;
                r.record(
                    &format!("U.{}.listen", tc.name),
                    tc.agent,
                    matches!(&resp, Response::UnixListening { .. }),
                    &format!("{resp:?}"),
                );

                let data = format!("unix_{}", tc.name);
                let resp = r
                    .send(
                        tc.agent,
                        super::exec(vec![
                            self_exe.clone(),
                            "unix-echo-client".into(),
                            sock.clone(),
                            data.clone(),
                        ]),
                    )
                    .await;
                let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout.contains(&data));
                r.record(
                    &format!("U.{}.child_connect", tc.name),
                    tc.agent,
                    pass,
                    &format!("{resp:?}"),
                );

                let _ = r.send(tc.agent, Command::UnixUnlisten { path: sock }).await;
            }

            UnixPattern::BackgroundServerConnect => {
                let resp = r
                    .send(
                        tc.agent,
                        Command::Exec {
                            args: vec![self_exe.clone(), "unix-echo-server".into(), sock.clone()],
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
                r.record(
                    &format!("U.{}.server_start", tc.name),
                    tc.agent,
                    pid.is_some(),
                    &format!("{resp:?}"),
                );

                tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

                let data = format!("unix_{}", tc.name);
                let resp = r
                    .send(
                        tc.agent,
                        Command::UnixConnect {
                            path: sock.clone(),
                            data: data.clone(),
                        },
                    )
                    .await;
                let pass = matches!(&resp, Response::Connected { echo } if *echo == data);
                r.record(
                    &format!("U.{}.connect", tc.name),
                    tc.agent,
                    pass,
                    &format!("{resp:?}"),
                );

                if let Some(pid) = pid {
                    let _ = r.send(tc.agent, Command::Kill { pid }).await;
                }
                let _ = r.send(tc.agent, Command::UnixUnlisten { path: sock }).await;
            }

            UnixPattern::CrossAgent => {
                let connector = tc.peer.unwrap();
                let data = format!("unix_{}", tc.name);

                let resp = r
                    .send(tc.agent, Command::UnixListen { path: sock.clone() })
                    .await;
                r.record(
                    &format!("U.{}.listen", tc.name),
                    tc.agent,
                    matches!(&resp, Response::UnixListening { .. }),
                    &format!("{resp:?}"),
                );

                let resp = r
                    .send(
                        connector,
                        Command::UnixConnect {
                            path: sock.clone(),
                            data: data.clone(),
                        },
                    )
                    .await;

                let pass = matches!(&resp, Response::Connected { echo } if *echo == data);
                r.record(
                    &format!("U.{}.connect", tc.name),
                    connector,
                    pass,
                    &format!("{resp:?}"),
                );

                let _ = r.send(tc.agent, Command::UnixUnlisten { path: sock }).await;
            }
        }
    }

    // ── Minimal cross-worker unix socket repro ──
    // This test isolates the exact failure point:
    //   1. D3 (init worker) listens on a unix socket → TCP listener starts
    //   2. D4 (worker-exec) connects → TCP connect succeeds through broker
    //   3. D3's echo task should accept() and echo back → FAILS
    //
    // Control: same-agent connect (D3→D3) works. Cross-agent (D4→D3) doesn't.
    // Root cause: tokio's reactor isn't woken by backlog.pollee.notify_observers
    // because the unix socket fd's epoll observer doesn't propagate the wakeup.
    if has_nonpie {
        let sock = "/tmp/um_repro_xworker.sock".to_string();

        // Step 1: D3 listens.
        let resp = r
            .send("D3", Command::UnixListen { path: sock.clone() })
            .await;
        let listen_ok = matches!(&resp, Response::UnixListening { .. });
        r.record("U.repro.listen", "D3", listen_ok, &format!("{resp:?}"));

        if listen_ok {
            // Step 2: Same-agent connect (D3→D3) — should work.
            let resp = r
                .send(
                    "D3",
                    Command::UnixConnect {
                        path: sock.clone(),
                        data: "SAME_AGENT".to_string(),
                    },
                )
                .await;
            let same_ok =
                matches!(&resp, Response::Connected { echo } if echo.contains("SAME_AGENT"));
            r.record("U.repro.same_agent", "D3", same_ok, &format!("{resp:?}"));

            // Step 3: Cross-agent connect (D4→D3) — this is the bug.
            let resp = r
                .send(
                    "D4",
                    Command::UnixConnect {
                        path: sock.clone(),
                        data: "CROSS_WORKER".to_string(),
                    },
                )
                .await;
            let cross_ok =
                matches!(&resp, Response::Connected { echo } if echo.contains("CROSS_WORKER"));
            r.record("U.repro.cross_worker", "D4", cross_ok, &format!("{resp:?}"));

            let _ = r.send("D3", Command::UnixUnlisten { path: sock }).await;
        }
    }
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

/// Symlink variant dimension.
#[derive(Debug, Clone, Copy)]
enum SymlinkVariant {
    /// File symlink — test across all topologies.
    Basic,
    /// Symlink to a directory, read file through it.
    Directory,
    /// Symlink to nonexistent target — readlink succeeds, read fails.
    Dangling,
    /// link1 → link2 → file chain.
    Nested,
    /// Relative target path.
    Relative,
}

impl SymlinkVariant {
    fn suffix(self) -> &'static str {
        match self {
            Self::Basic => "basic",
            Self::Directory => "dir",
            Self::Dangling => "dangling",
            Self::Nested => "nested",
            Self::Relative => "relative",
        }
    }
}

const SYMLINK_VARIANTS: &[SymlinkVariant] = &[
    SymlinkVariant::Basic,
    SymlinkVariant::Directory,
    SymlinkVariant::Dangling,
    SymlinkVariant::Nested,
    SymlinkVariant::Relative,
];

/// Test basic file symlink across topologies.
async fn test_symlink_basic(r: &mut TestRunner, topo: Topology, symlink_unsupported: bool) {
    let (source, dest) = topo.agents();
    let ts = topo.suffix();
    let file = format!("/shared/sm_{ts}_file");
    let link = format!("/shared/sm_{ts}_link");
    let data = format!("symdata_{ts}");
    let xfail = if symlink_unsupported {
        Some("symlink() returns ENOTSUP")
    } else {
        None
    };

    let _ = r
        .send("init", Command::FsDelete { path: link.clone() })
        .await;
    let _ = r
        .send("init", Command::FsDelete { path: file.clone() })
        .await;

    r.send(
        source,
        Command::FsWrite {
            path: file.clone(),
            data: data.clone(),
        },
    )
    .await;

    let resp = r
        .send(
            source,
            Command::FsSymlink {
                target: file.clone(),
                link: link.clone(),
            },
        )
        .await;
    record_xfail_if(
        r,
        &format!("S.basic.{ts}.create"),
        source,
        matches!(&resp, Response::Ok { .. }),
        &format!("{resp:?}"),
        xfail,
    );

    let resp = r
        .send(source, Command::FsReadlink { path: link.clone() })
        .await;
    let pass = matches!(&resp, Response::Ok { data: Some(d) } if *d == file);
    record_xfail_if(
        r,
        &format!("S.basic.{ts}.readlink"),
        source,
        pass,
        &format!("{resp:?}"),
        xfail,
    );

    let resp = r.send(dest, Command::FsRead { path: link.clone() }).await;
    let pass = matches!(&resp, Response::Ok { data: Some(d) } if *d == data);
    record_xfail_if(
        r,
        &format!("S.basic.{ts}.read_through"),
        dest,
        pass,
        &format!("{resp:?}"),
        xfail,
    );

    let resp = r.send(dest, Command::FsStat { path: link.clone() }).await;
    let pass = matches!(&resp, Response::Ok { data: Some(d) } if d == "symlink");
    record_xfail_if(
        r,
        &format!("S.basic.{ts}.stat_type"),
        dest,
        pass,
        &format!("{resp:?}"),
        xfail,
    );
}

/// Test symlink variants (InProcess only — tests symlink semantics).
async fn test_symlink_variant(
    r: &mut TestRunner,
    variant: SymlinkVariant,
    symlink_unsupported: bool,
) {
    let vs = variant.suffix();
    let xfail = if symlink_unsupported {
        Some("symlink() returns ENOTSUP")
    } else {
        None
    };
    let agent = "A";

    match variant {
        SymlinkVariant::Basic => {} // handled by test_symlink_basic

        SymlinkVariant::Directory => {
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
            let pass = matches!(&resp, Response::Ok { data: Some(d) } if d.trim() == "DIR_CONTENT");
            record_xfail_if(
                r,
                &format!("S.{vs}.read_through"),
                agent,
                pass,
                &format!("{resp:?}"),
                xfail,
            );
        }

        SymlinkVariant::Dangling => {
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
            let pass = matches!(&resp, Response::Ok { data: Some(d) } if d == "/shared/nonexistent_target");
            record_xfail_if(
                r,
                &format!("S.{vs}.readlink"),
                agent,
                pass,
                &format!("{resp:?}"),
                xfail,
            );

            let resp = r
                .send(
                    agent,
                    Command::FsRead {
                        path: "/shared/sv_dangling".into(),
                    },
                )
                .await;
            let pass = matches!(&resp, Response::Error { .. } | Response::NotFound);
            // read_dangling always passes regardless of symlink support.
            r.record(
                &format!("S.{vs}.read_fails"),
                agent,
                pass,
                &format!("{resp:?}"),
            );
        }

        SymlinkVariant::Nested => {
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
            record_xfail_if(
                r,
                &format!("S.{vs}.read_through"),
                agent,
                pass,
                &format!("{resp:?}"),
                xfail,
            );
        }

        SymlinkVariant::Relative => {
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
            record_xfail_if(
                r,
                &format!("S.{vs}.read_through"),
                agent,
                pass,
                &format!("{resp:?}"),
                xfail,
            );
        }
    }
}

// ═══════════════════════════════════════════════════════════════════
// MATRIX RUNNER
// ═══════════════════════════════════════════════════════════════════

pub(crate) async fn run_matrix_tests(r: &mut TestRunner) {
    // ── Environment setup ──
    let _ = tokio::fs::create_dir_all("/shared").await;
    let _ = tokio::fs::create_dir_all("/root").await;
    // Ensure host_wrote.txt exists for F.host tests.
    if !std::path::Path::new("/shared/host_wrote.txt").exists() {
        let _ = tokio::fs::write("/shared/host_wrote.txt", "from_host").await;
    }

    let has_nonpie = crate::find_nonpie_binary().is_some();

    // ── Filesystem: scope × topology ──
    eprintln!(
        "[matrix] === FS: shared × {} topologies ===",
        FS_TOPOLOGIES.len()
    );
    for &topo in FS_TOPOLOGIES {
        if topo.requires_nonpie() && !has_nonpie {
            let ts = topo.suffix();
            r.record(
                &format!("F.shared.{ts}.absent"),
                topo.agents().1,
                false,
                "FAIL: nonpie binary not found — mount at /opt/nonpie",
            );
            continue;
        }
        test_fs_crud(r, topo).await;
    }

    eprintln!("[matrix] === FS: /tmp isolation ===");
    for &topo in FS_TOPOLOGIES {
        if topo.requires_nonpie() && !has_nonpie {
            continue;
        }
        test_tmp_isolation(r, topo).await;
    }

    eprintln!(
        "[matrix] === FS: cross-unlink × {} topologies ===",
        FS_TOPOLOGIES.len()
    );
    for &topo in FS_TOPOLOGIES {
        if topo.requires_nonpie() && !has_nonpie {
            continue;
        }
        test_fs_cross_unlink(r, topo).await;
    }

    eprintln!("[matrix] === FS: host file ===");
    test_host_file(r).await;

    // ── Network ──
    eprintln!("[matrix] === Network ({} cases) ===", NET_TESTS.len());
    run_net_tests(r).await;

    // ── Network Address Matrix ──
    run_net_addr_tests(r).await;

    // ── Unix Socket Address Matrix ──
    eprintln!(
        "[matrix] === Unix Socket Address ({} pairs) ===",
        NET_ADDR_PAIRS.len(),
    );
    run_unix_addr_tests(r).await;

    // ── Exec & Env ──
    eprintln!("[matrix] === Exec ({} agents) ===", EXEC_AGENTS.len());
    run_exec_tests(r).await;

    eprintln!("[matrix] === Env ({} agents) ===", EXEC_AGENTS.len());
    run_env_tests(r).await;

    // ── Unix Sockets ──
    eprintln!(
        "[matrix] === Unix Sockets ({} cases) ===",
        unix_test_cases().len()
    );
    run_unix_tests(r).await;

    // ── Symlinks: variant × topology ──
    // Probe symlink support once.
    let probe = r
        .send(
            "A",
            Command::FsSymlink {
                target: "/tmp/matrix_probe_target".into(),
                link: "/tmp/matrix_probe_link".into(),
            },
        )
        .await;
    let symlink_unsupported =
        matches!(&probe, Response::Error { error } if error.contains("not supported"));
    let _ = r
        .send(
            "A",
            Command::FsDelete {
                path: "/tmp/matrix_probe_link".into(),
            },
        )
        .await;

    eprintln!(
        "[matrix] === Symlinks: basic × {} topologies ===",
        SYMLINK_TOPOLOGIES.len()
    );
    for &topo in SYMLINK_TOPOLOGIES {
        test_symlink_basic(r, topo, symlink_unsupported).await;
    }

    eprintln!(
        "[matrix] === Symlinks: {} variants (InProcess) ===",
        SYMLINK_VARIANTS.len() - 1
    );
    for &variant in SYMLINK_VARIANTS {
        if matches!(variant, SymlinkVariant::Basic) {
            continue; // already covered above
        }
        test_symlink_variant(r, variant, symlink_unsupported).await;
    }
}
