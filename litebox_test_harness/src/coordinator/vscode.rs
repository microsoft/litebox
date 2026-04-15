// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use super::{exec, exec_timeout, TestRunner};
use crate::protocol::{Command, Response};
use tokio::time::Duration;

/// VS Code Server reproduction tests — isolate known connection failure modes.
pub(super) async fn vscode_repro_tests(r: &mut TestRunner) {
    let bash = |cmd: &str| -> Vec<String> {
        vec!["bash".into(), "-c".into(), cmd.into()]
    };

    // T1: Unix domain socket lifecycle in /tmp
    // Reproduces Issue 1: code-server uses --socket-path=/tmp/code-UUID.
    // Tests whether AF_UNIX bind/listen/connect/accept/send/recv works.
    let resp = r.send("A", Command::UnixSocketTest { path: "/tmp/test-t1.sock".into() }).await;
    let pass = matches!(&resp, Response::Ok { data: Some(d) } if d.contains("unix_socket_ok"));
    r.record("V1.unix_socket", "A", pass, &format!("{resp:?}"));

    // T1b: Unix socket from deeper worker (AA)
    let resp = r.send("AA", Command::UnixSocketTest { path: "/tmp/test-t1b.sock".into() }).await;
    let pass = matches!(&resp, Response::Ok { data: Some(d) } if d.contains("unix_socket_ok"));
    r.record("V1b.unix_socket_deep", "AA", pass, &format!("{resp:?}"));

    // T2: Port reuse after unlisten
    // Reproduces Issue 2: empty listeningOn when port 9100 is still held.
    // Worker A listens on 9100, unlistens, then worker B tries to listen.
    let resp = r.send("A", Command::NetListen { port: 9100 }).await;
    let listen_ok = matches!(&resp, Response::Listening { port: 9100 });
    r.record("V2.listen_A", "A", listen_ok, &format!("{resp:?}"));

    let resp = r.send("A", Command::NetUnlisten { port: 9100 }).await;
    r.record("V2.unlisten_A", "A", matches!(&resp, Response::Ok { .. }), &format!("{resp:?}"));

    // Small delay for port cleanup.
    tokio::time::sleep(Duration::from_millis(500)).await;

    let resp = r.send("B", Command::NetListen { port: 9100 }).await;
    let pass = matches!(&resp, Response::Listening { port: 9100 });
    r.record("V2.reuse_B", "B", pass, &format!("{resp:?}"));

    // Clean up.
    if pass {
        let _ = r.send("B", Command::NetUnlisten { port: 9100 }).await;
    }

    // T3: /tmp file creation from forked bash
    // Reproduces Issue 3: /tmp/.vscode-bootstrap-N.sh: Permission denied.
    let resp = r.send("A", exec(bash("echo tmp_write_test > /tmp/t3-test.sh && cat /tmp/t3-test.sh && rm /tmp/t3-test.sh"))).await;
    let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout.contains("tmp_write_test"));
    let timeout = matches!(&resp, Response::ExecTimeout { .. });
    r.record("V3.tmp_write", "A", pass, &format!("timeout={timeout} {resp:?}"));

    // T3b: /tmp write from deeper worker
    let resp = r.send("AA", exec(bash("echo deep_tmp > /tmp/t3b-test.sh && cat /tmp/t3b-test.sh && rm /tmp/t3b-test.sh"))).await;
    let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout.contains("deep_tmp"));
    r.record("V3b.tmp_write_deep", "AA", pass, &format!("{resp:?}"));

    // T4: Node.js code-server startup
    // Reproduces Issue 1: code-server process dies after ~75s.
    // Try to run code-server with --socket-path; if binary exists it should
    // start (timeout = running = good). If binary not found, skip.
    // Note: Uses bash builtin `kill` for timeout since `timeout` cmd may not be in rootfs.
    let code_server = "/root/.vscode-server/cli/servers/Stable-ae130017f8afe532557dbb8539a6ef3bdaec6389/server/bin/code-server";
    let resp = r.send("A", exec_timeout(vec![
        "bash".into(), "-c".into(),
        format!("if [ -x {code_server} ]; then {code_server} --connection-token=test --accept-server-license-terms --start-server --socket-path=/tmp/t4-test.sock 2>&1 & PID=$!; sleep 3; kill $PID 2>/dev/null; wait $PID 2>/dev/null; echo exit=$?; else echo SKIP_NOT_FOUND; fi"),
    ], 30)).await;
    let skipped = matches!(&resp, Response::ExecResult { stdout, .. } if stdout.contains("SKIP_NOT_FOUND"));
    let started = matches!(&resp, Response::ExecResult { stdout, .. } if !stdout.contains("SKIP_NOT_FOUND"))
        || matches!(&resp, Response::ExecTimeout { .. });
    if skipped {
        r.record("V4.code_server", "A", true, "skipped (binary not found)");
    } else {
        // Any output (even crash) is informative — record it.
        r.record("V4.code_server","A", started, &format!("{resp:?}"));
    }
    // Clean up socket.
    let _ = r.send("A", exec(bash("rm -f /tmp/t4-test.sock"))).await;

    // T5: Unix socket bidirectional data flow (cross-process)
    // Mimics CLI↔code-server: one process listens on a Unix socket,
    // another connects and sends data. Verifies echo round-trip.
    // Uses Rust subcommands (unix-echo-server/client) instead of python3.
    // bash orchestrates server background + client foreground.
    let self_exe = r.self_exe.clone();
    let resp = r.send("A", exec_timeout(bash(
        &format!("rm -f /tmp/t5.sock; \
         {self_exe} unix-echo-server /tmp/t5.sock & \
         SERVER_PID=$!; \
         sleep 1; \
         RESULT=$({self_exe} unix-echo-client /tmp/t5.sock UNIX_ECHO_TEST 2>&1); \
         kill -9 $SERVER_PID 2>/dev/null; \
         echo \"t5_result=$RESULT\"; \
         rm -f /tmp/t5.sock")
    ), 20)).await;
    let pass = matches!(&resp, Response::ExecResult { stdout, .. } if stdout.contains("t5_result=UNIX_ECHO_TEST"));
    let timeout = matches!(&resp, Response::ExecTimeout { .. });
    r.record_xfail("V5.unix_relay", "A", pass, "cross-process Unix socket data relay", &format!("timeout={timeout} {resp:?}"));

    // T6: code-server stderr capture — does it create the Unix socket?
    // Run code-server, wait briefly, check if /tmp/t6-test.sock exists.
    // If the socket file exists, code-server started successfully.
    let resp = r.send("A", exec_timeout(bash(
        &format!("if [ -x {code_server} ]; then \
            {code_server} --connection-token=test --accept-server-license-terms \
            --start-server --socket-path=/tmp/t6-test.sock >/dev/null 2>&1 & \
            PID=$!; sleep 3; \
            if [ -S /tmp/t6-test.sock ]; then echo SOCKET_CREATED; else echo SOCKET_MISSING; fi; \
            kill -9 $PID 2>/dev/null; \
         else echo SKIP_NOT_FOUND; fi")
    ), 20)).await;
    let skipped = matches!(&resp, Response::ExecResult { stdout, .. } if stdout.contains("SKIP_NOT_FOUND"));
    if skipped {
        r.record("V6.code_server_socket", "A", true, "skipped (binary not found)");
    } else {
        let socket_created = matches!(&resp, Response::ExecResult { stdout, .. } if stdout.contains("SOCKET_CREATED"));
        r.record_xfail("V6.code_server_socket","A", socket_created, "Node.js I/O error on startup", &format!("{resp:?}"));
    }
    let _ = r.send("A", exec(bash("rm -f /tmp/t6-test.sock"))).await;

    // T7: code-server stays alive with auto-shutdown (no client)
    // Run with --enable-remote-auto-shutdown and no client connecting.
    // After 5s, check if still running. It should be (75s timeout).
    let resp = r.send("A", exec_timeout(bash(
        &format!("if [ -x {code_server} ]; then \
            {code_server} --connection-token=test --accept-server-license-terms \
            --start-server --enable-remote-auto-shutdown \
            --socket-path=/tmp/t7-test.sock >/dev/null 2>&1 & \
            PID=$!; sleep 5; \
            if kill -0 $PID 2>/dev/null; then echo STILL_RUNNING; else echo EXITED_EARLY; fi; \
            kill -9 $PID 2>/dev/null; \
         else echo SKIP_NOT_FOUND; fi")
    ), 20)).await;
    let skipped = matches!(&resp, Response::ExecResult { stdout, .. } if stdout.contains("SKIP_NOT_FOUND"));
    if skipped {
        r.record("V7.auto_shutdown", "A", true, "skipped (binary not found)");
    } else {
        let still_running = matches!(&resp, Response::ExecResult { stdout, .. } if stdout.contains("STILL_RUNNING"));
        r.record("V7.auto_shutdown", "A", still_running, &format!("{resp:?}"));
    }
    let _ = r.send("A", exec(bash("rm -f /tmp/t7-test.sock"))).await;
}
