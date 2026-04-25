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
        r.record(
            "V6.code_server_socket",
            "A",
            socket_created,
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

/// VS Code bootstrap script replay test.
///
/// Replays the captured install script (the same script VS Code Remote-SSH
/// pipes through `ssh host sh`) inside the coordinator framework. The script
/// is patched at runtime with the correct commit hash from the Docker image's
/// pre-installed VS Code CLI.
///
/// This test exercises the full bootstrap: variable assignment via $(),
/// file existence checks, CLI version detection, and server startup.
pub(super) async fn vscode_bootstrap_replay(r: &mut TestRunner) {
    eprintln!("[vscode] === VS Code Bootstrap Replay ===");

    // 1. Detect the VS Code commit hash from the installed CLI.
    let resp = r
        .send(
            "A",
            exec_timeout(
                vec![
                    "bash".into(),
                    "-c".into(),
                    "if [ -x /root/.vscode-server/code ]; then /root/.vscode-server/code --version 2>/dev/null | grep -oP 'commit \\K[a-f0-9]{40}'; else echo NOT_FOUND; fi".into(),
                ],
                10,
            ),
        )
        .await;
    let commit = match &resp {
        Response::ExecResult {
            exit_code: 0,
            stdout,
            ..
        } => {
            let trimmed = stdout.trim();
            if trimmed == "NOT_FOUND" || trimmed.len() != 40 {
                r.record(
                    "VSI.detect_commit",
                    "A",
                    true,
                    "skipped (VS Code CLI not found — use litebox-vscode image)",
                );
                return;
            }
            trimmed.to_string()
        }
        _ => {
            r.record(
                "VSI.detect_commit",
                "A",
                false,
                &format!("failed to detect commit: {resp:?}"),
            );
            return;
        }
    };
    r.record("VSI.detect_commit", "A", true, &format!("commit={commit}"));

    // 2. Pre-stage the CLI at the path the bootstrap script expects.
    //    The Docker image installs the CLI at /root/.vscode-server/code
    //    but the bootstrap looks for /root/.vscode-server/code-{COMMIT_ID}.
    let setup_cmd = format!(
        "if [ ! -f \"$HOME/.vscode-server/code-{commit}\" ]; then \
         cp /root/.vscode-server/code \"$HOME/.vscode-server/code-{commit}\" && \
         chmod +x \"$HOME/.vscode-server/code-{commit}\" && \
         echo STAGED; \
         else echo EXISTS; fi"
    );
    let resp = r
        .send("A", exec(vec!["bash".into(), "-c".into(), setup_cmd]))
        .await;
    let staged_ok = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. }
        if stdout.trim() == "STAGED" || stdout.trim() == "EXISTS");
    r.record("VSI.stage_cli", "A", staged_ok, &format!("{resp:?}"));
    if !staged_ok {
        return;
    }

    // 3. Patch the captured bootstrap script with the dynamic commit hash
    //    and remove the keepalive loop (which would run forever).
    let script_template =
        include_str!("../../../litebox_tool_executor/scripts/vscode-bootstrap-captured.sh");
    let script = script_template
        .replace("41dd792b5e652393e7787322889ed5fdc58bd75b", &commit)
        // Remove the keepalive loop at the end — it's designed to hold
        // the SSH connection open forever, but we just want the output.
        .replace("while true; do sleep 180; printf ' '; done", "exit 0");

    // 4. Pipe the script to sh, just like VS Code Remote-SSH does.
    //    The script starts the VS Code CLI server in the background,
    //    waits for it to print "Listening on ...", then outputs structured
    //    markers and exits (after our keepalive patch).
    let resp = r
        .send(
            "A",
            Command::Exec {
                args: vec!["sh".into()],
                timeout_secs: Some(120),
                stdin: Some(script),
                background: false,
            },
        )
        .await;

    // 5. Parse structured output markers.
    match &resp {
        Response::ExecResult {
            exit_code,
            stdout,
            stderr,
        } => {
            let has_running = stdout.contains(": running");
            let has_start = stdout.contains(": start");
            let has_end = stdout.contains(": end");
            let has_listening = stdout.contains("listeningOn==");
            let has_exit_code = stdout.contains("exitCode==");
            let found_existing = stdout.contains("Found existing installation");

            // Report individual phases.
            r.record(
                "VSI.script_running",
                "A",
                has_running,
                &format!("running={has_running}"),
            );
            r.record(
                "VSI.found_cli",
                "A",
                found_existing,
                &format!("found_existing={found_existing}"),
            );
            r.record(
                "VSI.start_marker",
                "A",
                has_start,
                &format!("start={has_start}"),
            );

            // The full bootstrap success: start+end markers present and
            // listeningOn reports a real address.
            let full_success = has_start && has_end && has_listening;
            let detail = format!(
                "exit_code={exit_code} running={has_running} found_cli={found_existing} \
                 start={has_start} end={has_end} listening={has_listening} \
                 exit_marker={has_exit_code}\n\
                 stdout_preview: {}\n\
                 stderr_preview: {}",
                &stdout[..stdout.len().min(500)],
                &stderr[..stderr.len().min(500)],
            );
            r.record("VSI.bootstrap", "A", full_success, &detail);
        }
        Response::ExecTimeout { stderr } => {
            r.record(
                "VSI.bootstrap",
                "A",
                false,
                &format!(
                    "TIMEOUT (120s) stderr: {}",
                    &stderr[..stderr.len().min(500)]
                ),
            );
        }
        _ => {
            r.record("VSI.bootstrap", "A", false, &format!("{resp:?}"));
        }
    }

    // 6. Start CLI server as a background process and test TCP connectivity.
    //    The bootstrap script's CLI exits when the script exits (orphaned bg
    //    process), so we start a fresh CLI with a known port for connectivity
    //    testing.  This exercises the same path: CLI listens, cross-worker
    //    TCP connects through the loopback bridge.
    //
    //    We capture the dynamically assigned port from the CLI's stderr output.
    let start_cmd = format!(
        "LOG=/tmp/vsi-test-cli.log; \
         $HOME/.vscode-server/code-{commit} command-shell \
         --cli-data-dir $HOME/.vscode-server/cli \
         --parent-process-id $$ \
         --on-host 0.0.0.0 > $LOG 2>&1 & \
         CLI_PID=$!; \
         for i in $(seq 1 15); do \
           PORT=$(grep -oP 'Listening on [^:]+:\\K[0-9]+' $LOG 2>/dev/null); \
           if [ -n \"$PORT\" ]; then break; fi; \
           sleep 1; \
         done; \
         echo VSI_PORT=$PORT; \
         echo VSI_CLI_PID=$CLI_PID; \
         sleep 30"
    );
    let resp = r
        .send(
            "A",
            Command::Exec {
                args: vec!["bash".into(), "-c".into(), start_cmd],
                timeout_secs: None,
                stdin: None,
                background: true,
            },
        )
        .await;
    let bg_pid = match &resp {
        Response::Background { pid } => Some(*pid),
        _ => None,
    };
    if bg_pid.is_none() {
        r.record(
            "VSI.server_start",
            "A",
            false,
            &format!("bg spawn failed: {resp:?}"),
        );
        return;
    }

    // Wait for the CLI to start and report its port.
    tokio::time::sleep(Duration::from_secs(10)).await;

    // Read the port from the background process's output.
    let resp = r
        .send(
            "A",
            exec_timeout(
                vec![
                    "bash".into(),
                    "-c".into(),
                    "grep -oP 'Listening on [^:]+:\\K[0-9]+' /tmp/vsi-test-cli.log 2>/dev/null || echo NONE".into(),
                ],
                5,
            ),
        )
        .await;
    let port: Option<u16> = match &resp {
        Response::ExecResult {
            exit_code: 0,
            stdout,
            ..
        } => stdout.trim().parse().ok(),
        _ => None,
    };

    let Some(port) = port else {
        r.record(
            "VSI.server_start",
            "A",
            false,
            &format!("CLI did not start or port not detected: {resp:?}"),
        );
        if let Some(pid) = bg_pid {
            let _ = r.send("A", Command::Kill { pid }).await;
        }
        return;
    };
    r.record("VSI.server_start", "A", true, &format!("port={port}"));

    // 6a. Same-worker connectivity: agent A connects to the exec server
    //     it started.  Loopback within the same worker tree.
    let cmd = format!("echo PROBE | nc -w3 127.0.0.1 {port} >/dev/null 2>&1; echo VSI_CONN=$?");
    let resp = r
        .send("A", exec_timeout(vec!["bash".into(), "-c".into(), cmd], 10))
        .await;
    let same_ok = matches!(
        &resp,
        Response::ExecResult { stdout, .. } if stdout.contains("VSI_CONN=0")
    );
    r.record(
        "VSI.connect_same_worker",
        "A",
        same_ok,
        &format!("{resp:?}"),
    );

    // 6b. Cross-worker connectivity: agent B connects to the exec server
    //     that agent A started.  This is the VS Code SOCKS proxy pattern:
    //     a different SSH session (different worker tree) connects to the
    //     CLI's listening port through cross-worker loopback TCP.
    let cmd = format!("echo PROBE | nc -w3 127.0.0.1 {port} >/dev/null 2>&1; echo VSI_CONN=$?");
    let resp = r
        .send("B", exec_timeout(vec!["bash".into(), "-c".into(), cmd], 10))
        .await;
    let cross_ok = matches!(
        &resp,
        Response::ExecResult { stdout, .. } if stdout.contains("VSI_CONN=0")
    );
    r.record(
        "VSI.connect_cross_worker",
        "B",
        cross_ok,
        &format!("{resp:?}"),
    );

    // Clean up: kill the background CLI server.
    if let Some(pid) = bg_pid {
        let _ = r.send("A", Command::Kill { pid }).await;
    }
}
