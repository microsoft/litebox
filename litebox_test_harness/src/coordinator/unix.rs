// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Unix domain socket tests — in-process and cross-process relay.

use super::TestRunner;
use crate::protocol::{Command, Response};

pub(super) async fn unix_tests(r: &mut TestRunner) {
    // U1: In-process Unix socket lifecycle
    // Create, bind, listen, accept (via tokio task), send, recv — all within
    // the same agent process. Tests basic AF_UNIX support.
    let resp = r
        .send(
            "A",
            Command::UnixSocketTest {
                path: "/tmp/u1.sock".into(),
            },
        )
        .await;
    let pass = matches!(&resp, Response::Ok { data: Some(d) } if d.contains("unix_socket_ok"));
    r.record("U1.in_process", "A", pass, &format!("{resp:?}"));

    // U1b: Same from a deeper worker
    let resp = r
        .send(
            "AA",
            Command::UnixSocketTest {
                path: "/tmp/u1b.sock".into(),
            },
        )
        .await;
    let pass = matches!(&resp, Response::Ok { data: Some(d) } if d.contains("unix_socket_ok"));
    r.record("U1b.in_process_deep", "AA", pass, &format!("{resp:?}"));

    // U2: Cross-process relay — parent binds, forked child connects
    let self_exe = r.self_exe.clone();
    let resp = r
        .send(
            "A",
            Command::UnixSocketRelay {
                path: "/tmp/u2.sock".into(),
                self_exe: self_exe.clone(),
            },
        )
        .await;
    let pass = matches!(&resp, Response::Ok { data: Some(d) } if d.contains("unix_relay_ok"));
    r.record("U2.parent_server", "A", pass, &format!("{resp:?}"));

    // U3: Reverse relay — forked child binds, parent connects
    // This is the VS Code pattern (code-server creates socket, CLI connects).
    let resp = r
        .send(
            "A",
            Command::UnixSocketReverseRelay {
                path: "/tmp/u3.sock".into(),
                self_exe: self_exe.clone(),
            },
        )
        .await;
    let pass =
        matches!(&resp, Response::Ok { data: Some(d) } if d.contains("unix_reverse_relay_ok"));
    r.record("U3.child_server", "A", pass, &format!("{resp:?}"));

    // U4: Parent-server relay from deeper worker
    let resp = r
        .send(
            "AA",
            Command::UnixSocketRelay {
                path: "/tmp/u4.sock".into(),
                self_exe: self_exe.clone(),
            },
        )
        .await;
    let pass = matches!(&resp, Response::Ok { data: Some(d) } if d.contains("unix_relay_ok"));
    r.record("U4.deep_parent_server", "AA", pass, &format!("{resp:?}"));

    // U5: Reverse relay from deeper worker
    let resp = r
        .send(
            "AA",
            Command::UnixSocketReverseRelay {
                path: "/tmp/u5.sock".into(),
                self_exe,
            },
        )
        .await;
    let pass =
        matches!(&resp, Response::Ok { data: Some(d) } if d.contains("unix_reverse_relay_ok"));
    r.record("U5.deep_child_server", "AA", pass, &format!("{resp:?}"));
}
