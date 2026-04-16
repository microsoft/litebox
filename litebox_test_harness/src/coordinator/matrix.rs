// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Declarative test matrix — defines topology axes and drives "cover all
//! configurations" tests via structured loops instead of hand-enumerating
//! every combination.
//!
//! Each capability (fs, net, unix, symlink, env) has a single generic test
//! function parameterized by topology. Adding a new topology automatically
//! generates tests for all capabilities; adding a new capability
//! automatically covers all topologies.

use super::TestRunner;
use crate::protocol::{Command, Response};
use std::collections::HashMap;

// ── Topology axis ──

/// A relationship between two agents in the process tree.
/// Each variant maps to a concrete (source, dest) agent pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum Topology {
    /// Same agent acts as both source and destination.
    InProcess,
    /// Parent writes, child reads (init → A).
    ParentToChild,
    /// Child writes, parent reads (A → init).
    ChildToParent,
    /// Sibling agents (A → B).
    Sibling,
    /// Reverse sibling (B → A).
    SiblingReverse,
    /// Grandchild to grandparent (AA → init).
    GrandchildUp,
    /// Great-grandchild to root (AAA → init).
    GreatGrandchildUp,
    /// Cross-subtree (B → AAA).
    CrossSubtree,
    /// Sibling at depth 2 (AA → AB).
    SiblingDepth2,
    /// Sibling at depth 3 (AAA → AAB).
    SiblingDepth3,
    /// Uncle relationship (AB → B).
    Uncle,
}

impl Topology {
    /// Returns (source_agent, dest_agent).
    ///
    /// For directional tests: `source` performs the action (write, listen),
    /// `dest` observes the result (read, connect).
    pub(crate) fn agents(self) -> (&'static str, &'static str) {
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

    /// Short suffix for test IDs, e.g. "parent_to_child".
    pub(crate) fn suffix(self) -> &'static str {
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

pub(crate) type XfailKey = (&'static str, &'static str);

/// Build the xfail map. Key is (capability_prefix, topology_suffix).
pub(crate) fn build_xfail_map() -> HashMap<XfailKey, &'static str> {
    let mut m = HashMap::new();
    // Unix sockets: siblings have independent address tables.
    m.insert(
        ("U", "sibling"),
        "sibling workers have independent Unix socket address tables",
    );
    m
}

fn lookup_xfail(
    xfails: &HashMap<XfailKey, &'static str>,
    prefix: &'static str,
    topo: Topology,
) -> Option<&'static str> {
    xfails.get(&(prefix, topo.suffix())).copied()
}

// ── Standard topology sets ──

pub(crate) const FS_TOPOLOGIES: &[Topology] = &[
    Topology::ParentToChild,
    Topology::ChildToParent,
    Topology::Sibling,
    Topology::SiblingReverse,
    Topology::GrandchildUp,
    Topology::GreatGrandchildUp,
];

pub(crate) const NET_TOPOLOGIES: &[Topology] = &[
    Topology::ParentToChild,
    Topology::Sibling,
    Topology::SiblingReverse,
    // GrandchildUp excluded: dest=init can't listen. Covered by
    // deep_to_ancestor test added below the loop.
    Topology::CrossSubtree,
    Topology::SiblingDepth2,
    Topology::SiblingDepth3,
    Topology::Uncle,
];

pub(crate) const UNIX_TOPOLOGIES: &[Topology] = &[
    Topology::InProcess,
    Topology::ParentToChild,
    Topology::ChildToParent,
    Topology::Sibling,
    Topology::GrandchildUp,
];

pub(crate) const SYMLINK_TOPOLOGIES: &[Topology] = &[
    Topology::InProcess,
    Topology::ParentToChild,
    Topology::ChildToParent,
    Topology::Sibling,
    Topology::GrandchildUp,
];

pub(crate) const EXEC_TOPOLOGIES: &[Topology] = &[
    Topology::InProcess,
    Topology::GrandchildUp,
    Topology::GreatGrandchildUp,
];

pub(crate) const ENV_TOPOLOGIES: &[Topology] = &[
    Topology::InProcess,
    Topology::GrandchildUp,
    Topology::GreatGrandchildUp,
];

// ── Generic test functions ──

/// Test filesystem CRUD: source writes, dest reads, source updates/deletes.
pub(crate) async fn test_fs_crud(
    r: &mut TestRunner,
    topo: Topology,
    xfails: &HashMap<XfailKey, &'static str>,
) {
    let (source, dest) = topo.agents();
    let suffix = topo.suffix();
    let file = format!("/shared/matrix_{suffix}.txt");
    let data = format!("data_{suffix}");
    let updated = format!("updated_{suffix}");
    let xfail_reason = lookup_xfail(xfails, "F", topo);

    // Clean up from prior runs.
    let _ = r
        .send("init", Command::FsDelete { path: file.clone() })
        .await;

    // Absent.
    let resp = r.send(dest, Command::FsRead { path: file.clone() }).await;
    record(
        r,
        &format!("F.{suffix}.absent"),
        dest,
        matches!(resp, Response::NotFound),
        &format!("{resp:?}"),
        xfail_reason,
    );

    // Create.
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
    record(
        r,
        &format!("F.{suffix}.created"),
        dest,
        pass,
        &format!("{resp:?}"),
        xfail_reason,
    );

    // Update.
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
    record(
        r,
        &format!("F.{suffix}.updated"),
        dest,
        pass,
        &format!("{resp:?}"),
        xfail_reason,
    );

    // Delete.
    r.send(source, Command::FsDelete { path: file.clone() })
        .await;
    let resp = r.send(dest, Command::FsRead { path: file.clone() }).await;
    record(
        r,
        &format!("F.{suffix}.deleted"),
        dest,
        matches!(resp, Response::NotFound),
        &format!("{resp:?}"),
        xfail_reason,
    );
}

/// Test network echo: dest listens, source connects, verify echo, unlisten.
pub(crate) async fn test_net_echo(
    r: &mut TestRunner,
    topo: Topology,
    port: u16,
    xfails: &HashMap<XfailKey, &'static str>,
) {
    let (source, dest) = topo.agents();
    let suffix = topo.suffix();
    let test_data = format!("net_{suffix}");
    let xfail_reason = lookup_xfail(xfails, "N", topo);

    // For net, "dest" is the listener (server), "source" is the client.
    let resp = r.send(dest, Command::NetListen { port }).await;
    record(
        r,
        &format!("N.{suffix}.listen"),
        dest,
        matches!(resp, Response::Listening { .. }),
        &format!("{resp:?}"),
        xfail_reason,
    );

    let resp = r
        .send(
            source,
            Command::NetConnect {
                addr: format!("127.0.0.1:{port}"),
                data: test_data.clone(),
            },
        )
        .await;
    let pass = matches!(&resp, Response::Connected { echo } if *echo == test_data);
    record(
        r,
        &format!("N.{suffix}.connect"),
        source,
        pass,
        &format!("{resp:?}"),
        xfail_reason,
    );

    let resp = r.send(dest, Command::NetUnlisten { port }).await;
    record(
        r,
        &format!("N.{suffix}.unlisten"),
        dest,
        matches!(resp, Response::Ok { .. }),
        &format!("{resp:?}"),
        xfail_reason,
    );
}

/// Test Unix socket echo. Different topologies require different protocol
/// patterns (in-process, parent-server/child-client, etc.).
pub(crate) async fn test_unix_socket(
    r: &mut TestRunner,
    topo: Topology,
    xfails: &HashMap<XfailKey, &'static str>,
) {
    let suffix = topo.suffix();
    let sock_path = format!("/tmp/matrix_{suffix}.sock");
    let test_data = format!("unix_{suffix}");
    let xfail_reason = lookup_xfail(xfails, "U", topo);

    match topo {
        Topology::InProcess => {
            let (agent, _) = topo.agents();
            let resp = r
                .send(
                    agent,
                    Command::UnixListen {
                        path: sock_path.clone(),
                    },
                )
                .await;
            record(
                r,
                &format!("U.{suffix}.listen"),
                agent,
                matches!(&resp, Response::UnixListening { .. }),
                &format!("{resp:?}"),
                xfail_reason,
            );

            let resp = r
                .send(
                    agent,
                    Command::UnixConnect {
                        path: sock_path.clone(),
                        data: test_data.clone(),
                    },
                )
                .await;
            let pass = matches!(&resp, Response::Connected { echo } if *echo == test_data);
            record(
                r,
                &format!("U.{suffix}.connect"),
                agent,
                pass,
                &format!("{resp:?}"),
                xfail_reason,
            );

            let _ = r
                .send(agent, Command::UnixUnlisten { path: sock_path })
                .await;
        }

        Topology::ParentToChild => {
            // Agent listens, forks unix-echo-client to connect.
            let (_, dest) = topo.agents();
            let agent = dest; // A
            let resp = r
                .send(
                    agent,
                    Command::UnixListen {
                        path: sock_path.clone(),
                    },
                )
                .await;
            record(
                r,
                &format!("U.{suffix}.listen"),
                agent,
                matches!(&resp, Response::UnixListening { .. }),
                &format!("{resp:?}"),
                xfail_reason,
            );

            let resp = r
                .send(
                    agent,
                    super::exec(vec![
                        r.self_exe.clone(),
                        "unix-echo-client".into(),
                        sock_path.clone(),
                        test_data.clone(),
                    ]),
                )
                .await;
            let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout.contains(&test_data));
            record(
                r,
                &format!("U.{suffix}.child_connect"),
                agent,
                pass,
                &format!("{resp:?}"),
                xfail_reason,
            );

            let _ = r
                .send(agent, Command::UnixUnlisten { path: sock_path })
                .await;
        }

        Topology::ChildToParent => {
            // Fork background unix-echo-server, then parent agent connects.
            let (source, _) = topo.agents();
            let agent = source; // A
            let resp = r
                .send(
                    agent,
                    Command::ExecBackground {
                        args: vec![
                            r.self_exe.clone(),
                            "unix-echo-server".into(),
                            sock_path.clone(),
                        ],
                    },
                )
                .await;
            let server_pid = match &resp {
                Response::Background { pid } => Some(*pid),
                _ => None,
            };
            record(
                r,
                &format!("U.{suffix}.server_start"),
                agent,
                server_pid.is_some(),
                &format!("{resp:?}"),
                xfail_reason,
            );

            tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

            let resp = r
                .send(
                    agent,
                    Command::UnixConnect {
                        path: sock_path.clone(),
                        data: test_data.clone(),
                    },
                )
                .await;
            let pass = matches!(&resp, Response::Connected { echo } if *echo == test_data);
            record(
                r,
                &format!("U.{suffix}.parent_connect"),
                agent,
                pass,
                &format!("{resp:?}"),
                xfail_reason,
            );

            if let Some(pid) = server_pid {
                let _ = r.send(agent, Command::Kill { pid }).await;
            }
            let _ = r
                .send(agent, Command::UnixUnlisten { path: sock_path })
                .await;
        }

        Topology::Sibling => {
            // Source listens, dest tries to connect (expected to fail).
            let (source, dest) = topo.agents();
            let resp = r
                .send(
                    source,
                    Command::UnixListen {
                        path: sock_path.clone(),
                    },
                )
                .await;
            // Listen should always pass — only connect is xfailed.
            record(
                r,
                &format!("U.{suffix}.listen"),
                source,
                matches!(&resp, Response::UnixListening { .. }),
                &format!("{resp:?}"),
                None,
            );

            let resp = r
                .send(
                    dest,
                    Command::UnixConnect {
                        path: sock_path.clone(),
                        data: test_data.clone(),
                    },
                )
                .await;
            let pass = matches!(
                &resp,
                Response::ConnectFailed { .. } | Response::Error { .. }
            );
            record(
                r,
                &format!("U.{suffix}.connect"),
                dest,
                pass,
                &format!("{resp:?}"),
                xfail_reason,
            );

            let _ = r
                .send(source, Command::UnixUnlisten { path: sock_path })
                .await;
        }

        Topology::GrandchildUp => {
            // Source (AA) listens, parent (A) connects.
            let (source, _) = topo.agents();
            let connector = "A";
            let resp = r
                .send(
                    source,
                    Command::UnixListen {
                        path: sock_path.clone(),
                    },
                )
                .await;
            record(
                r,
                &format!("U.{suffix}.listen"),
                source,
                matches!(&resp, Response::UnixListening { .. }),
                &format!("{resp:?}"),
                xfail_reason,
            );

            let resp = r
                .send(
                    connector,
                    Command::UnixConnect {
                        path: sock_path.clone(),
                        data: test_data.clone(),
                    },
                )
                .await;
            let pass = matches!(&resp, Response::Connected { echo } if *echo == test_data);
            record(
                r,
                &format!("U.{suffix}.connect"),
                connector,
                pass,
                &format!("{resp:?}"),
                xfail_reason,
            );

            let _ = r
                .send(source, Command::UnixUnlisten { path: sock_path })
                .await;
        }

        _ => {}
    }
}

/// Test symlink: source creates file + symlink, dest reads through.
pub(crate) async fn test_symlink(
    r: &mut TestRunner,
    topo: Topology,
    symlink_unsupported: bool,
    xfails: &HashMap<XfailKey, &'static str>,
) {
    let (source, dest) = topo.agents();
    let suffix = topo.suffix();
    let file = format!("/shared/sm_{suffix}_file");
    let link = format!("/shared/sm_{suffix}_link");
    let data = format!("symdata_{suffix}");

    let xfail_reason = if symlink_unsupported {
        Some("symlink() returns ENOTSUP")
    } else {
        lookup_xfail(xfails, "S", topo)
    };

    // Clean up.
    let _ = r
        .send("init", Command::FsDelete { path: link.clone() })
        .await;
    let _ = r
        .send("init", Command::FsDelete { path: file.clone() })
        .await;

    // Create file.
    r.send(
        source,
        Command::FsWrite {
            path: file.clone(),
            data: data.clone(),
        },
    )
    .await;

    // Create symlink.
    let resp = r
        .send(
            source,
            Command::FsSymlink {
                target: file.clone(),
                link: link.clone(),
            },
        )
        .await;
    record(
        r,
        &format!("S.{suffix}.create"),
        source,
        matches!(&resp, Response::Ok { .. }),
        &format!("{resp:?}"),
        xfail_reason,
    );

    // Readlink.
    let resp = r
        .send(source, Command::FsReadlink { path: link.clone() })
        .await;
    let pass = matches!(&resp, Response::Ok { data: Some(d) } if *d == file);
    record(
        r,
        &format!("S.{suffix}.readlink"),
        source,
        pass,
        &format!("{resp:?}"),
        xfail_reason,
    );

    // Read through.
    let resp = r.send(dest, Command::FsRead { path: link.clone() }).await;
    let pass = matches!(&resp, Response::Ok { data: Some(d) } if *d == data);
    record(
        r,
        &format!("S.{suffix}.read_through"),
        dest,
        pass,
        &format!("{resp:?}"),
        xfail_reason,
    );

    // Stat type.
    let resp = r.send(dest, Command::FsStat { path: link.clone() }).await;
    let pass = matches!(&resp, Response::Ok { data: Some(d) } if d == "symlink");
    record(
        r,
        &format!("S.{suffix}.stat_type"),
        dest,
        pass,
        &format!("{resp:?}"),
        xfail_reason,
    );
}

/// Test exec (echo-test) from an agent at a given topology.
pub(crate) async fn test_exec_echo(
    r: &mut TestRunner,
    topo: Topology,
    xfails: &HashMap<XfailKey, &'static str>,
) {
    let (agent, _) = topo.agents();
    let suffix = topo.suffix();
    let self_exe = r.self_exe.clone();
    let xfail_reason = lookup_xfail(xfails, "X", topo);

    let resp = r
        .send(agent, super::exec(vec![self_exe, "echo-test".into()]))
        .await;
    let pass =
        matches!(&resp, Response::ExecResult { stdout, .. } if stdout.contains("ECHO_TEST_OK"));
    record(
        r,
        &format!("X.{suffix}.echo"),
        agent,
        pass,
        &format!("{resp:?}"),
        xfail_reason,
    );
}

/// Test environment variables from an agent.
pub(crate) async fn test_env(
    r: &mut TestRunner,
    topo: Topology,
    xfails: &HashMap<XfailKey, &'static str>,
) {
    let (agent, _) = topo.agents();
    let suffix = topo.suffix();
    let xfail_reason = lookup_xfail(xfails, "E", topo);

    let resp = r.send(agent, Command::EnvGet { var: "HOME".into() }).await;
    let pass = matches!(&resp, Response::Ok { data: Some(d) } if !d.is_empty() && d != "NOT_SET");
    record(
        r,
        &format!("E.{suffix}.HOME"),
        agent,
        pass,
        &format!("{resp:?}"),
        xfail_reason,
    );

    let resp = r.send(agent, Command::EnvGet { var: "PATH".into() }).await;
    let pass = matches!(&resp, Response::Ok { data: Some(d) } if !d.is_empty() && d != "NOT_SET");
    record(
        r,
        &format!("E.{suffix}.PATH"),
        agent,
        pass,
        &format!("{resp:?}"),
        xfail_reason,
    );

    let resp = r.send(agent, Command::CwdGet).await;
    let pass = matches!(&resp, Response::Ok { data: Some(_) });
    record(
        r,
        &format!("E.{suffix}.CWD"),
        agent,
        pass,
        &format!("{resp:?}"),
        xfail_reason,
    );
}

// ── Helper ──

fn record(
    r: &mut TestRunner,
    test: &str,
    agent: &str,
    pass: bool,
    detail: &str,
    xfail_reason: Option<&str>,
) {
    if let Some(reason) = xfail_reason {
        r.record_xfail(test, agent, pass, reason, detail);
    } else {
        r.record(test, agent, pass, detail);
    }
}

// ── Matrix runner ──

/// Run all matrix-driven capability × topology tests.
pub(crate) async fn run_matrix_tests(r: &mut TestRunner) {
    let xfails = build_xfail_map();

    eprintln!(
        "[matrix] === Filesystem ({} topologies) ===",
        FS_TOPOLOGIES.len()
    );
    let _ = tokio::fs::create_dir_all("/shared").await;
    for &topo in FS_TOPOLOGIES {
        test_fs_crud(r, topo, &xfails).await;
    }

    eprintln!(
        "[matrix] === Network ({} topologies + deep_to_ancestor) ===",
        NET_TOPOLOGIES.len()
    );
    let mut port = 10_001u16;
    for &topo in NET_TOPOLOGIES {
        test_net_echo(r, topo, port, &xfails).await;
        port += 1;
    }
    // Deep-child-to-ancestor: AAA connects to A's listener.
    // Can't use GrandchildUp topology (dest=init can't listen).
    {
        let listener = "A";
        let connector = "AAA";
        let resp = r.send(listener, Command::NetListen { port }).await;
        record(
            r,
            "N.deep_to_ancestor.listen",
            listener,
            matches!(resp, Response::Listening { .. }),
            &format!("{resp:?}"),
            None,
        );
        let resp = r
            .send(
                connector,
                Command::NetConnect {
                    addr: format!("127.0.0.1:{port}"),
                    data: "net_deep_to_ancestor".into(),
                },
            )
            .await;
        let pass = matches!(&resp, Response::Connected { echo } if echo == "net_deep_to_ancestor");
        record(
            r,
            "N.deep_to_ancestor.connect",
            connector,
            pass,
            &format!("{resp:?}"),
            None,
        );
        let resp = r.send(listener, Command::NetUnlisten { port }).await;
        record(
            r,
            "N.deep_to_ancestor.unlisten",
            listener,
            matches!(resp, Response::Ok { .. }),
            &format!("{resp:?}"),
            None,
        );
    }

    eprintln!(
        "[matrix] === Exec ({} topologies) ===",
        EXEC_TOPOLOGIES.len()
    );
    for &topo in EXEC_TOPOLOGIES {
        test_exec_echo(r, topo, &xfails).await;
    }

    eprintln!("[matrix] === Env ({} topologies) ===", ENV_TOPOLOGIES.len());
    for &topo in ENV_TOPOLOGIES {
        test_env(r, topo, &xfails).await;
    }

    eprintln!(
        "[matrix] === Unix Sockets ({} topologies) ===",
        UNIX_TOPOLOGIES.len()
    );
    for &topo in UNIX_TOPOLOGIES {
        test_unix_socket(r, topo, &xfails).await;
    }

    eprintln!(
        "[matrix] === Symlinks ({} topologies) ===",
        SYMLINK_TOPOLOGIES.len()
    );
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

    for &topo in SYMLINK_TOPOLOGIES {
        test_symlink(r, topo, symlink_unsupported, &xfails).await;
    }
}
