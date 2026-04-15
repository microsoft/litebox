// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use super::{exec, exec_timeout, TestRunner};
use crate::protocol::Response;

pub(super) async fn exec_tests(r: &mut TestRunner) {
    let self_exe = r.self_exe.clone();

    // X1: fork+exec from first-level worker
    let resp = r.send("A", exec(vec![self_exe.clone(), "echo-test".into()])).await;
    let pass = matches!(&resp, Response::ExecResult { stdout, .. } if stdout.contains("ECHO_TEST_OK"));
    r.record("X1.A", "A", pass, &format!("{resp:?}"));

    // X2: fork+exec from second-level worker
    let resp = r.send("AA", exec(vec![self_exe.clone(), "echo-test".into()])).await;
    let pass = matches!(&resp, Response::ExecResult { stdout, .. } if stdout.contains("ECHO_TEST_OK"));
    r.record("X2.AA", "AA", pass, &format!("{resp:?}"));

    // X3: fork+exec from third-level worker
    let resp = r.send("AAA", exec(vec![self_exe.clone(), "echo-test".into()])).await;
    let pass = matches!(&resp, Response::ExecResult { stdout, .. } if stdout.contains("ECHO_TEST_OK"));
    r.record("X3.AAA", "AAA", pass, &format!("{resp:?}"));

    // X4: exit code propagation
    let resp = r.send("A", exec(vec![self_exe.clone(), "exit-with".into(), "42".into()])).await;
    let pass = matches!(&resp, Response::ExecResult { exit_code: 42, .. });
    r.record("X4.exit_code", "A", pass, &format!("{resp:?}"));

    // X5: exit code from deep worker
    let resp = r.send("AAA", exec(vec![self_exe.clone(), "exit-with".into(), "7".into()])).await;
    let pass = matches!(&resp, Response::ExecResult { exit_code: 7, .. });
    r.record("X5.deep_exit", "AAA", pass, &format!("{resp:?}"));

    // ── Delayed-fork limitation reproduction tests ──
    // Each test runs a shell command via bash -c to exercise specific
    // fork patterns that stress litebox's delayed-fork (vfork) architecture.
    // Tests that deadlock will timeout after 10s and return ExecTimeout.

    let bash = |cmd: &str| -> Vec<String> {
        vec!["bash".into(), "-c".into(), cmd.into()]
    };

    // X6: Baseline — simple bash echo (fork+exec, no pipes)
    // Expected: pass — same as X1 but through bash.
    let resp = r.send("A", exec(bash("echo hello_from_bash"))).await;
    let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout.contains("hello_from_bash"));
    r.record("X6.bash_echo", "A", pass, &format!("{resp:?}"));

    // X7: Command substitution — $(echo inner)
    // This forks a subshell to run `echo inner`, captures its stdout.
    // The subshell does fork+exec of echo, then the parent reads the result.
    let resp = r.send("A", exec(bash("echo $(echo inner_value)"))).await;
    let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout.contains("inner_value"));
    r.record("X7.cmd_substitution", "A", pass, &format!("{resp:?}"));

    // X8: Pipe inside command substitution — $(echo hello | cat)
    // Known delayed-fork stress test: subshell forks twice (echo + cat),
    // cat calls read() which is non-pre-exec, triggering delayed fork.
    // Pipe data from echo must be bridged to the new worker for cat.
    let resp = r.send("A", exec(bash("echo $(echo pipe_data | cat)"))).await;
    let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout.contains("pipe_data"));
    let timeout = matches!(&resp, Response::ExecTimeout { .. });
    r.record("X8.pipe_in_subshell", "A", pass, &format!("timeout={timeout} {resp:?}"));

    // X9: Process substitution — cat <(echo hello)
    // Uses /dev/fd/N (procfs symlink to anonymous pipe). Previously failed
    // because /dev/fd was not mounted; now fixed by synthetic /dev/fd/N
    // handling in the shim (open, readlink, stat).
    let resp = r.send("A", exec(bash("cat <(echo proc_sub_data)"))).await;
    let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout.contains("proc_sub_data"));
    let timeout = matches!(&resp, Response::ExecTimeout { .. });
    r.record("X9.process_substitution", "A", pass, &format!("timeout={timeout} {resp:?}"));

    // X10: Simple two-stage pipe — echo | cat
    // Shell forks twice (one for echo, one for cat), connects via pipe.
    // Each fork is serialized due to vfork semantics.
    let resp = r.send("A", exec(bash("echo pipe_two_stage | cat"))).await;
    let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout.contains("pipe_two_stage"));
    let timeout = matches!(&resp, Response::ExecTimeout { .. });
    r.record("X10.simple_pipe", "A", pass, &format!("timeout={timeout} {resp:?}"));

    // X11: Three-stage pipe — echo | cat | cat
    // Three children, two pipes. Tests chained pipe bridging across
    // multiple delayed-fork migrations.
    let resp = r.send("A", exec(bash("echo three_stage | cat | cat"))).await;
    let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout.contains("three_stage"));
    let timeout = matches!(&resp, Response::ExecTimeout { .. });
    r.record("X11.three_stage_pipe", "A", pass, &format!("timeout={timeout} {resp:?}"));

    // X12: Background process with wait — sleep 0 & wait; echo done
    // fork() for `sleep 0` with & makes parent continue. But vfork blocks
    // the parent until the child does exec or exits. Tests whether
    // backgrounding works at all.
    let resp = r.send("A", exec(bash("sleep 0 & wait; echo bg_done"))).await;
    let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout.contains("bg_done"));
    let timeout = matches!(&resp, Response::ExecTimeout { .. });
    r.record("X12.background_wait", "A", pass, &format!("timeout={timeout} {resp:?}"));

    // X13: Multiple background processes — echo a & echo b & wait
    // Two concurrent forks. With vfork semantics, these run serially.
    // Tests whether the outputs from both appear.
    let resp = r.send("A", exec(bash("echo bg_a & echo bg_b & wait"))).await;
    let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout.contains("bg_a") && stdout.contains("bg_b"));
    let timeout = matches!(&resp, Response::ExecTimeout { .. });
    r.record("X13.multi_background", "A", pass, &format!("timeout={timeout} {resp:?}"));

    // X14: Subshell exit code — (exit 42); echo $?
    // Subshell fork with immediate exit. Tests whether exit code
    // propagates back through the vfork/delayed-fork path.
    let resp = r.send("A", exec(bash("(exit 42); echo $?"))).await;
    let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout.contains("42"));
    let timeout = matches!(&resp, Response::ExecTimeout { .. });
    r.record("X14.subshell_exit_code", "A", pass, &format!("timeout={timeout} {resp:?}"));

    // X15: Sequential commands without pipes (baseline)
    // Multiple fork+exec operations chained with &&. No pipes between them,
    // just sequential execution. Validates basic multi-command shell scripts.
    let resp = r.send("A", exec(bash("echo seq_a && echo seq_b && echo seq_c"))).await;
    let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout.contains("seq_a") && stdout.contains("seq_c"));
    r.record("X15.sequential_cmds", "A", pass, &format!("{resp:?}"));

    // ── More aggressive delayed-fork stress tests ──

    // X16: Deeply nested command substitution
    // Each $(…) creates a subshell fork. Three levels of nesting means
    // three sequential fork+exec+capture cycles.
    let resp = r.send("A", exec(bash("echo $(echo $(echo deep_nested))"))).await;
    let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout.contains("deep_nested"));
    let timeout = matches!(&resp, Response::ExecTimeout { .. });
    r.record("X16.nested_subshell", "A", pass, &format!("timeout={timeout} {resp:?}"));

    // X17: Here-document — uses an internal pipe to feed stdin
    // bash creates a pipe for the heredoc content, forks the command,
    // and the child reads from the pipe.
    let resp = r.send("A", exec(bash("cat <<'EOF'\nheredoc_line\nEOF"))).await;
    let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout.contains("heredoc_line"));
    let timeout = matches!(&resp, Response::ExecTimeout { .. });
    r.record("X17.heredoc", "A", pass, &format!("timeout={timeout} {resp:?}"));

    // X18: Here-string — simpler variant of heredoc
    let resp = r.send("A", exec(bash("cat <<< 'herestring_data'"))).await;
    let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout.contains("herestring_data"));
    let timeout = matches!(&resp, Response::ExecTimeout { .. });
    r.record("X18.herestring", "A", pass, &format!("timeout={timeout} {resp:?}"));

    // X19: Pipe with grep — common real-world pattern
    // Tests pipe bridging with a program (grep) that does buffered reads.
    let resp = r.send("A", exec(bash("echo -e 'alpha\\nbeta\\ngamma' | grep beta"))).await;
    let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout.contains("beta"));
    let timeout = matches!(&resp, Response::ExecTimeout { .. });
    r.record("X19.pipe_grep", "A", pass, &format!("timeout={timeout} {resp:?}"));

    // X20: Command substitution with pipe and wc — VS Code install pattern
    // `$(curl ... | sh)` like patterns use command substitution + pipe.
    let resp = r.send("A", exec(bash("echo $(echo 'line1\\nline2\\nline3' | wc -l)"))).await;
    let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout.trim() != "");
    let timeout = matches!(&resp, Response::ExecTimeout { .. });
    r.record("X20.subshell_pipe_wc", "A", pass, &format!("timeout={timeout} {resp:?}"));

    // X21: Backtick substitution (older syntax) — equivalent to $() but
    // tests different bash code path.
    let resp = r.send("A", exec(bash("echo `echo backtick_val`"))).await;
    let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout.contains("backtick_val"));
    let timeout = matches!(&resp, Response::ExecTimeout { .. });
    r.record("X21.backtick_subst", "A", pass, &format!("timeout={timeout} {resp:?}"));

    // X22: Pipe to while-read loop — common shell pattern that does
    // fork + pipe + read in a loop. The read is non-pre-exec.
    let resp = r.send("A", exec(bash("echo -e 'a\\nb\\nc' | while read line; do echo \"got_$line\"; done"))).await;
    let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout.contains("got_a") && stdout.contains("got_c"));
    let timeout = matches!(&resp, Response::ExecTimeout { .. });
    r.record("X22.pipe_while_read", "A", pass, &format!("timeout={timeout} {resp:?}"));

    // X23: Pipe from second-level worker — same as X10 but from AA.
    // Tests whether pipe bridging works differently at deeper nesting.
    let resp = r.send("AA", exec(bash("echo deeper_pipe | cat"))).await;
    let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout.contains("deeper_pipe"));
    let timeout = matches!(&resp, Response::ExecTimeout { .. });
    r.record("X23.deep_pipe", "AA", pass, &format!("timeout={timeout} {resp:?}"));

    // X24: Pipe in subshell from deep worker — X8 from AAA.
    let resp = r.send("AAA", exec(bash("echo $(echo deep_sub | cat)"))).await;
    let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout.contains("deep_sub"));
    let timeout = matches!(&resp, Response::ExecTimeout { .. });
    r.record("X24.deep_subshell_pipe", "AAA", pass, &format!("timeout={timeout} {resp:?}"));

    // X25: xargs — forks multiple child processes from piped input.
    let resp = r.send("A", exec(bash("echo -e 'p\\nq\\nr' | xargs -I{} echo xargs_{}"))).await;
    let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout.contains("xargs_p") && stdout.contains("xargs_r"));
    let timeout = matches!(&resp, Response::ExecTimeout { .. });
    r.record("X25.xargs", "A", pass, &format!("timeout={timeout} {resp:?}"));

    // ── Node.js exec tests (V6 investigation) ──
    // Incremental tests narrowing the gap between working minimal tests
    // and the failing VS Code code-server Node.js startup.

    // X26: Exec system Node.js directly from worker
    // Skip if node is not in the rootfs (exit 127 = not found).
    let resp = r.send("A", exec(vec![
        "/usr/local/bin/node".into(), "-e".into(), "console.log('node_ok')".into(),
    ])).await;
    let not_found = matches!(&resp, Response::ExecResult { exit_code: 127, .. })
        || matches!(&resp, Response::Error { error } if error.contains("exec spawn"));
    if not_found {
        r.record("X26.node_direct", "A", true, "skipped (node not in rootfs)");
    } else {
        let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout.contains("node_ok"));
        r.record("X26.node_direct", "A", pass, &format!("{resp:?}"));
    }

    // X27: Exec Node.js from depth-2 worker
    let resp = r.send("AA", exec(vec![
        "/usr/local/bin/node".into(), "-e".into(), "console.log('node_deep_ok')".into(),
    ])).await;
    let not_found = matches!(&resp, Response::ExecResult { exit_code: 127, .. })
        || matches!(&resp, Response::Error { error } if error.contains("exec spawn"));
    if not_found {
        r.record("X27.node_deep", "AA", true, "skipped (node not in rootfs)");
    } else {
        let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout.contains("node_deep_ok"));
        r.record("X27.node_deep", "AA", pass, &format!("{resp:?}"));
    }

    // X28: Exec Node.js via shell script indirection (sh → node)
    // This mimics code-server's invocation pattern.
    let resp = r.send("A", exec(bash(
        "if command -v node >/dev/null 2>&1; then \
         echo '#!/usr/bin/env sh' > /tmp/x28.sh && \
         echo 'exec /usr/local/bin/node -e \"console.log(\\\"script_ok\\\")\"' >> /tmp/x28.sh && \
         chmod +x /tmp/x28.sh && \
         /tmp/x28.sh 2>&1; \
         rm -f /tmp/x28.sh; \
         else echo SKIP_NOT_FOUND; fi"
    ))).await;
    let skipped = matches!(&resp, Response::ExecResult { stdout, .. } if stdout.contains("SKIP_NOT_FOUND"));
    if skipped {
        r.record("X28.node_via_script", "A", true, "skipped (node not in rootfs)");
    } else {
        let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout.contains("script_ok"));
        r.record("X28.node_via_script", "A", pass, &format!("{resp:?}"));
    }

    // X29: Exec VS Code's bundled node (124MB binary)
    let bundled_node = "/root/.vscode-server/cli/servers/Stable-ae130017f8afe532557dbb8539a6ef3bdaec6389/server/node";
    let resp = r.send("A", exec(bash(
        &format!("if [ -x {bundled_node} ]; then \
         {bundled_node} -e 'console.log(\"bundled_ok\")' 2>&1; \
         else echo SKIP_NOT_FOUND; fi")
    ))).await;
    let skipped = matches!(&resp, Response::ExecResult { stdout, .. } if stdout.contains("SKIP_NOT_FOUND"));
    if skipped {
        r.record("X29.node_bundled", "A", true, "skipped (bundled node not found)");
    } else {
        let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout.contains("bundled_ok"));
        r.record("X29.node_bundled", "A", pass, &format!("{resp:?}"));
    }
}
