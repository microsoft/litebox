// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Unix domain socket tests — decomposed into primitive operations.

use super::{exec, TestRunner};
use crate::protocol::{Command, Response};

pub(super) async fn unix_tests(r: &mut TestRunner) {
    let self_exe = r.self_exe.clone();

    // U1: In-process Unix socket echo
    // Agent binds a Unix socket, then connects to itself.
    let resp = r
        .send("A", Command::UnixListen { path: "/tmp/u1.sock".into() })
        .await;
    r.record(
        "U1.listen",
        "A",
        matches!(&resp, Response::UnixListening { .. }),
        &format!("{resp:?}"),
    );

    let resp = r
        .send(
            "A",
            Command::UnixConnect {
                path: "/tmp/u1.sock".into(),
                data: "U1_DATA".into(),
            },
        )
        .await;
    let pass = matches!(&resp, Response::Connected { echo } if echo == "U1_DATA");
    r.record("U1.connect", "A", pass, &format!("{resp:?}"));

    let resp = r
        .send("A", Command::UnixUnlisten { path: "/tmp/u1.sock".into() })
        .await;
    r.record(
        "U1.unlisten",
        "A",
        matches!(&resp, Response::Ok { .. }),
        &format!("{resp:?}"),
    );

    // U1b: Same from a deeper worker
    let resp = r
        .send("AA", Command::UnixListen { path: "/tmp/u1b.sock".into() })
        .await;
    r.record(
        "U1b.listen",
        "AA",
        matches!(&resp, Response::UnixListening { .. }),
        &format!("{resp:?}"),
    );
    let resp = r
        .send(
            "AA",
            Command::UnixConnect {
                path: "/tmp/u1b.sock".into(),
                data: "U1B_DATA".into(),
            },
        )
        .await;
    let pass = matches!(&resp, Response::Connected { echo } if echo == "U1B_DATA");
    r.record("U1b.connect", "AA", pass, &format!("{resp:?}"));
    let _ = r
        .send(
            "AA",
            Command::UnixUnlisten {
                path: "/tmp/u1b.sock".into(),
            },
        )
        .await;

    // U2: Parent server, forked child client
    // Agent A listens, then forks unix-echo-client to connect.
    let resp = r
        .send("A", Command::UnixListen { path: "/tmp/u2.sock".into() })
        .await;
    r.record(
        "U2.listen",
        "A",
        matches!(&resp, Response::UnixListening { .. }),
        &format!("{resp:?}"),
    );
    let resp = r
        .send(
            "A",
            exec(vec![
                self_exe.clone(),
                "unix-echo-client".into(),
                "/tmp/u2.sock".into(),
                "U2_CHILD_DATA".into(),
            ]),
        )
        .await;
    let pass =
        matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout.contains("U2_CHILD_DATA"));
    r.record("U2.child_connect", "A", pass, &format!("{resp:?}"));
    let _ = r
        .send("A", Command::UnixUnlisten { path: "/tmp/u2.sock".into() })
        .await;

    // U3: Forked child server, parent client (VS Code pattern)
    // Fork unix-echo-server as background process, then parent connects.
    let resp = r
        .send(
            "A",
            Command::ExecBackground {
                args: vec![
                    self_exe.clone(),
                    "unix-echo-server".into(),
                    "/tmp/u3.sock".into(),
                ],
            },
        )
        .await;
    let server_pid = match &resp {
        Response::Background { pid } => Some(*pid),
        _ => None,
    };
    r.record(
        "U3.server_start",
        "A",
        server_pid.is_some(),
        &format!("{resp:?}"),
    );

    // Wait for server to bind.
    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

    let resp = r
        .send(
            "A",
            Command::UnixConnect {
                path: "/tmp/u3.sock".into(),
                data: "U3_REVERSE".into(),
            },
        )
        .await;
    let pass = matches!(&resp, Response::Connected { echo } if echo == "U3_REVERSE");
    r.record("U3.parent_connect", "A", pass, &format!("{resp:?}"));

    if let Some(pid) = server_pid {
        let _ = r.send("A", Command::Kill { pid }).await;
    }
    let _ = r
        .send("A", Command::UnixUnlisten { path: "/tmp/u3.sock".into() })
        .await;

    // U4: Parent server from deeper worker
    let resp = r
        .send(
            "AA",
            Command::UnixListen {
                path: "/tmp/u4.sock".into(),
            },
        )
        .await;
    r.record(
        "U4.listen",
        "AA",
        matches!(&resp, Response::UnixListening { .. }),
        &format!("{resp:?}"),
    );
    let resp = r
        .send(
            "AA",
            exec(vec![
                self_exe.clone(),
                "unix-echo-client".into(),
                "/tmp/u4.sock".into(),
                "U4_DEEP".into(),
            ]),
        )
        .await;
    let pass =
        matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout.contains("U4_DEEP"));
    r.record("U4.child_connect", "AA", pass, &format!("{resp:?}"));
    let _ = r
        .send(
            "AA",
            Command::UnixUnlisten {
                path: "/tmp/u4.sock".into(),
            },
        )
        .await;

    // U5: Reverse relay from deeper worker
    let resp = r
        .send(
            "AA",
            Command::ExecBackground {
                args: vec![
                    self_exe,
                    "unix-echo-server".into(),
                    "/tmp/u5.sock".into(),
                ],
            },
        )
        .await;
    let server_pid = match &resp {
        Response::Background { pid } => Some(*pid),
        _ => None,
    };
    r.record(
        "U5.server_start",
        "AA",
        server_pid.is_some(),
        &format!("{resp:?}"),
    );

    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

    let resp = r
        .send(
            "AA",
            Command::UnixConnect {
                path: "/tmp/u5.sock".into(),
                data: "U5_DEEP_REVERSE".into(),
            },
        )
        .await;
    let pass = matches!(&resp, Response::Connected { echo } if echo == "U5_DEEP_REVERSE");
    r.record("U5.parent_connect", "AA", pass, &format!("{resp:?}"));

    if let Some(pid) = server_pid {
        let _ = r.send("AA", Command::Kill { pid }).await;
    }
    let _ = r
        .send(
            "AA",
            Command::UnixUnlisten {
                path: "/tmp/u5.sock".into(),
            },
        )
        .await;

    // U6: Sibling Unix socket — document known limitation.
    r.record_xfail(
        "U6.sibling",
        "A↔B",
        false,
        "sibling workers have independent Unix socket address tables",
        "not executed — architectural limitation",
    );
}
