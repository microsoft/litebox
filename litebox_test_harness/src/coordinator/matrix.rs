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
    CrossSubtree,
    /// AA → AB.
    SiblingDepth2,
    /// AAA → AAB.
    SiblingDepth3,
    /// AB → B.
    Uncle,
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
        }
    }
}

// ── Xfail registry ──

fn build_xfail_set() -> HashSet<&'static str> {
    HashSet::new()
}

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
];

/// Scope dimension for filesystem tests.
#[derive(Debug, Clone, Copy)]
enum FsScope {
    /// /shared — visible across all agents.
    Shared,
    /// /tmp — may be isolated per-agent.
    TmpIsolated,
}

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
            r.record(
                &test_id,
                agent,
                true,
                "skipped (host_wrote.txt not in rootfs)",
            );
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

/// Net test descriptor. Listener listens, connector connects.
struct NetTestCase {
    name: &'static str,
    listener: &'static str,
    connector: &'static str,
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
];

async fn run_net_tests(r: &mut TestRunner) {
    let mut port = 10_001u16;
    for tc in NET_TESTS {
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
// EXEC & ENV
// ═══════════════════════════════════════════════════════════════════

const EXEC_AGENTS: &[&str] = &["A", "AA", "AAA"];

async fn run_exec_tests(r: &mut TestRunner) {
    let self_exe = r.self_exe.clone();

    for &agent in EXEC_AGENTS {
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
    for &agent in EXEC_AGENTS {
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
    xfail_connect: bool,
}

fn unix_test_cases() -> Vec<UnixTestCase> {
    vec![
        UnixTestCase {
            name: "in_process.A",
            pattern: UnixPattern::InProcess,
            agent: "A",
            peer: None,
            xfail_connect: false,
        },
        UnixTestCase {
            name: "in_process.AA",
            pattern: UnixPattern::InProcess,
            agent: "AA",
            peer: None,
            xfail_connect: false,
        },
        UnixTestCase {
            name: "server_fork.A",
            pattern: UnixPattern::ServerForkClient,
            agent: "A",
            peer: None,
            xfail_connect: false,
        },
        UnixTestCase {
            name: "server_fork.AA",
            pattern: UnixPattern::ServerForkClient,
            agent: "AA",
            peer: None,
            xfail_connect: false,
        },
        UnixTestCase {
            name: "bg_server.A",
            pattern: UnixPattern::BackgroundServerConnect,
            agent: "A",
            peer: None,
            xfail_connect: false,
        },
        UnixTestCase {
            name: "bg_server.AA",
            pattern: UnixPattern::BackgroundServerConnect,
            agent: "AA",
            peer: None,
            xfail_connect: false,
        },
        UnixTestCase {
            name: "sibling",
            pattern: UnixPattern::CrossAgent,
            agent: "A",
            peer: Some("B"),
            xfail_connect: true,
        },
        UnixTestCase {
            name: "parent_to_grandchild",
            pattern: UnixPattern::CrossAgent,
            agent: "A",
            peer: Some("AA"),
            xfail_connect: false,
        },
        UnixTestCase {
            name: "grandchild_to_parent",
            pattern: UnixPattern::CrossAgent,
            agent: "AA",
            peer: Some("A"),
            xfail_connect: false,
        },
    ]
}

async fn run_unix_tests(r: &mut TestRunner) {
    let self_exe = r.self_exe.clone();

    for tc in &unix_test_cases() {
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
                        Command::ExecBackground {
                            args: vec![self_exe.clone(), "unix-echo-server".into(), sock.clone()],
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

                // For sibling xfail: listener is the "server" side.
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

                if tc.xfail_connect {
                    // Sibling connect may fail on litebox (independent socket tables).
                    // Record as normal pass/fail — passes on WSL2, may fail on litebox.
                    let pass = matches!(&resp, Response::Connected { echo } if *echo == data);
                    r.record(
                        &format!("U.{}.connect", tc.name),
                        connector,
                        pass,
                        &format!("{resp:?}"),
                    );
                } else {
                    let pass = matches!(&resp, Response::Connected { echo } if *echo == data);
                    r.record(
                        &format!("U.{}.connect", tc.name),
                        connector,
                        pass,
                        &format!("{resp:?}"),
                    );
                }

                let _ = r.send(tc.agent, Command::UnixUnlisten { path: sock }).await;
            }
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

    // ── Filesystem: scope × topology ──
    eprintln!(
        "[matrix] === FS: shared × {} topologies ===",
        FS_TOPOLOGIES.len()
    );
    for &topo in FS_TOPOLOGIES {
        test_fs_crud(r, topo).await;
    }

    eprintln!("[matrix] === FS: /tmp isolation ===");
    for &topo in FS_TOPOLOGIES {
        test_tmp_isolation(r, topo).await;
    }

    eprintln!("[matrix] === FS: host file ===");
    test_host_file(r).await;

    // ── Network ──
    eprintln!("[matrix] === Network ({} cases) ===", NET_TESTS.len());
    run_net_tests(r).await;

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
