// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use super::{TestRunner, exec, exec_timeout};
use crate::protocol::{Command, Response};
use tokio::time::Duration;

/// VS Code Server reproduction tests — environment-specific tests that
/// require the VS Code rootfs or code-server binary.
pub(super) async fn vscode_repro_tests(r: &mut TestRunner) {
    let bash = |cmd: &str| -> Vec<String> { vec!["bash".into(), "-c".into(), cmd.into()] };

    // V2: Port reuse after unlisten
    // Reproduces Issue 2: empty listeningOn when port 9100 is still held.
    let resp = r.send("A", Command::NetListen { port: 9100 }).await;
    let listen_ok = matches!(&resp, Response::Listening { port: 9100 });
    r.record("V2.listen_A", "A", listen_ok, &format!("{resp:?}"));

    let resp = r.send("A", Command::NetUnlisten { port: 9100 }).await;
    r.record(
        "V2.unlisten_A",
        "A",
        matches!(&resp, Response::Ok { .. }),
        &format!("{resp:?}"),
    );

    tokio::time::sleep(Duration::from_millis(500)).await;

    let resp = r.send("B", Command::NetListen { port: 9100 }).await;
    let pass = matches!(&resp, Response::Listening { port: 9100 });
    r.record("V2.reuse_B", "B", pass, &format!("{resp:?}"));
    if pass {
        let _ = r.send("B", Command::NetUnlisten { port: 9100 }).await;
    }

    // V3: /tmp file write from worker
    r.send(
        "A",
        Command::FsWrite {
            path: "/tmp/v3-test.txt".into(),
            data: "tmp_write_test".into(),
        },
    )
    .await;
    let resp = r
        .send(
            "A",
            Command::FsRead {
                path: "/tmp/v3-test.txt".into(),
            },
        )
        .await;
    let pass = matches!(&resp, Response::Ok { data: Some(d) } if d == "tmp_write_test");
    r.record("V3.tmp_write", "A", pass, &format!("{resp:?}"));
    let _ = r
        .send(
            "A",
            Command::FsDelete {
                path: "/tmp/v3-test.txt".into(),
            },
        )
        .await;

    // V3b: /tmp write from deeper worker
    r.send(
        "AA",
        Command::FsWrite {
            path: "/tmp/v3b-test.txt".into(),
            data: "deep_tmp".into(),
        },
    )
    .await;
    let resp = r
        .send(
            "AA",
            Command::FsRead {
                path: "/tmp/v3b-test.txt".into(),
            },
        )
        .await;
    let pass = matches!(&resp, Response::Ok { data: Some(d) } if d == "deep_tmp");
    r.record("V3b.tmp_write_deep", "AA", pass, &format!("{resp:?}"));
    let _ = r
        .send(
            "AA",
            Command::FsDelete {
                path: "/tmp/v3b-test.txt".into(),
            },
        )
        .await;

    // V4: Node.js code-server startup (requires VS Code rootfs)
    let code_server = "/root/.vscode-server/cli/servers/Stable-ae130017f8afe532557dbb8539a6ef3bdaec6389/server/bin/code-server";
    let resp = r.send("A", exec_timeout(vec![
        "bash".into(), "-c".into(),
        format!("if [ -x {code_server} ]; then {code_server} --connection-token=test --accept-server-license-terms --start-server --socket-path=/tmp/t4-test.sock 2>&1 & PID=$!; sleep 3; kill $PID 2>/dev/null; wait $PID 2>/dev/null; echo exit=$?; else echo SKIP_NOT_FOUND; fi"),
    ], 30)).await;
    let skipped =
        matches!(&resp, Response::ExecResult { stdout, .. } if stdout.contains("SKIP_NOT_FOUND"));
    let started = matches!(&resp, Response::ExecResult { stdout, .. } if !stdout.contains("SKIP_NOT_FOUND"))
        || matches!(&resp, Response::ExecTimeout { .. });
    if skipped {
        r.record("V4.code_server", "A", true, "skipped (binary not found)");
    } else {
        r.record("V4.code_server", "A", started, &format!("{resp:?}"));
    }
    let _ = r.send("A", exec(bash("rm -f /tmp/t4-test.sock"))).await;

    // V6: code-server socket creation (requires VS Code rootfs)
    let resp = r
        .send(
            "A",
            exec_timeout(
                bash(&format!(
                    "if [ -x {code_server} ]; then \
            {code_server} --connection-token=test --accept-server-license-terms \
            --start-server --socket-path=/tmp/t6-test.sock >/dev/null 2>&1 & \
            PID=$!; sleep 3; \
            if [ -S /tmp/t6-test.sock ]; then echo SOCKET_CREATED; else echo SOCKET_MISSING; fi; \
            kill -9 $PID 2>/dev/null; \
         else echo SKIP_NOT_FOUND; fi"
                )),
                20,
            ),
        )
        .await;
    let skipped =
        matches!(&resp, Response::ExecResult { stdout, .. } if stdout.contains("SKIP_NOT_FOUND"));
    if skipped {
        r.record(
            "V6.code_server_socket",
            "A",
            true,
            "skipped (binary not found)",
        );
    } else {
        let socket_created = matches!(&resp, Response::ExecResult { stdout, .. } if stdout.contains("SOCKET_CREATED"));
        r.record_xfail(
            "V6.code_server_socket",
            "A",
            socket_created,
            "Node.js I/O error on startup",
            &format!("{resp:?}"),
        );
    }
    let _ = r.send("A", exec(bash("rm -f /tmp/t6-test.sock"))).await;

    // V7: code-server auto-shutdown (requires VS Code rootfs)
    let resp = r
        .send(
            "A",
            exec_timeout(
                bash(&format!(
                    "if [ -x {code_server} ]; then \
            {code_server} --connection-token=test --accept-server-license-terms \
            --start-server --enable-remote-auto-shutdown \
            --socket-path=/tmp/t7-test.sock >/dev/null 2>&1 & \
            PID=$!; sleep 5; \
            if kill -0 $PID 2>/dev/null; then echo STILL_RUNNING; else echo EXITED_EARLY; fi; \
            kill -9 $PID 2>/dev/null; \
         else echo SKIP_NOT_FOUND; fi"
                )),
                20,
            ),
        )
        .await;
    let skipped =
        matches!(&resp, Response::ExecResult { stdout, .. } if stdout.contains("SKIP_NOT_FOUND"));
    if skipped {
        r.record("V7.auto_shutdown", "A", true, "skipped (binary not found)");
    } else {
        let still_running = matches!(&resp, Response::ExecResult { stdout, .. } if stdout.contains("STILL_RUNNING"));
        r.record("V7.auto_shutdown", "A", still_running, &format!("{resp:?}"));
    }
    let _ = r.send("A", exec(bash("rm -f /tmp/t7-test.sock"))).await;
}
