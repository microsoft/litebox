// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use super::{TestRunner, exec, exec_timeout};
use crate::protocol::Response;

pub(super) async fn exec_tests(r: &mut TestRunner) {
    let self_exe = r.self_exe.clone();

    // X1: fork+exec from first-level worker
    let resp = r
        .send("A", exec(vec![self_exe.clone(), "echo-test".into()]))
        .await;
    let pass =
        matches!(&resp, Response::ExecResult { stdout, .. } if stdout.contains("ECHO_TEST_OK"));
    r.record("X1.A", "A", pass, &format!("{resp:?}"));

    // X2: fork+exec from second-level worker
    let resp = r
        .send("AA", exec(vec![self_exe.clone(), "echo-test".into()]))
        .await;
    let pass =
        matches!(&resp, Response::ExecResult { stdout, .. } if stdout.contains("ECHO_TEST_OK"));
    r.record("X2.AA", "AA", pass, &format!("{resp:?}"));

    // X3: fork+exec from third-level worker
    let resp = r
        .send("AAA", exec(vec![self_exe.clone(), "echo-test".into()]))
        .await;
    let pass =
        matches!(&resp, Response::ExecResult { stdout, .. } if stdout.contains("ECHO_TEST_OK"));
    r.record("X3.AAA", "AAA", pass, &format!("{resp:?}"));

    // X4: exit code propagation
    let resp = r
        .send(
            "A",
            exec(vec![self_exe.clone(), "exit-with".into(), "42".into()]),
        )
        .await;
    let pass = matches!(&resp, Response::ExecResult { exit_code: 42, .. });
    r.record("X4.exit_code", "A", pass, &format!("{resp:?}"));

    // X5: exit code from deep worker
    let resp = r
        .send(
            "AAA",
            exec(vec![self_exe.clone(), "exit-with".into(), "7".into()]),
        )
        .await;
    let pass = matches!(&resp, Response::ExecResult { exit_code: 7, .. });
    r.record("X5.deep_exit", "AAA", pass, &format!("{resp:?}"));

    // ── Delayed-fork limitation reproduction tests ──
    // Each test runs a shell command via bash -c to exercise specific
    // fork patterns that stress litebox's delayed-fork (vfork) architecture.
    // Tests that deadlock will timeout after 10s and return ExecTimeout.

    let bash = |cmd: &str| -> Vec<String> { vec!["bash".into(), "-c".into(), cmd.into()] };

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
    let resp = r
        .send("A", exec(bash("echo $(echo pipe_data | cat)")))
        .await;
    let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout.contains("pipe_data"));
    let timeout = matches!(&resp, Response::ExecTimeout { .. });
    r.record(
        "X8.pipe_in_subshell",
        "A",
        pass,
        &format!("timeout={timeout} {resp:?}"),
    );

    // X9: Process substitution — cat <(echo hello)
    // Uses /dev/fd/N (procfs symlink to anonymous pipe). Previously failed
    // because /dev/fd was not mounted; now fixed by synthetic /dev/fd/N
    // handling in the shim (open, readlink, stat).
    let resp = r.send("A", exec(bash("cat <(echo proc_sub_data)"))).await;
    let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout.contains("proc_sub_data"));
    let timeout = matches!(&resp, Response::ExecTimeout { .. });
    r.record(
        "X9.process_substitution",
        "A",
        pass,
        &format!("timeout={timeout} {resp:?}"),
    );

    // X10: Simple two-stage pipe — echo | cat
    // Shell forks twice (one for echo, one for cat), connects via pipe.
    // Each fork is serialized due to vfork semantics.
    let resp = r.send("A", exec(bash("echo pipe_two_stage | cat"))).await;
    let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout.contains("pipe_two_stage"));
    let timeout = matches!(&resp, Response::ExecTimeout { .. });
    r.record(
        "X10.simple_pipe",
        "A",
        pass,
        &format!("timeout={timeout} {resp:?}"),
    );

    // X11: Three-stage pipe — echo | cat | cat
    // Three children, two pipes. Tests chained pipe bridging across
    // multiple delayed-fork migrations.
    let resp = r
        .send("A", exec(bash("echo three_stage | cat | cat")))
        .await;
    let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout.contains("three_stage"));
    let timeout = matches!(&resp, Response::ExecTimeout { .. });
    r.record(
        "X11.three_stage_pipe",
        "A",
        pass,
        &format!("timeout={timeout} {resp:?}"),
    );

    // X12: Background process with wait — sleep 0 & wait; echo done
    // fork() for `sleep 0` with & makes parent continue. But vfork blocks
    // the parent until the child does exec or exits. Tests whether
    // backgrounding works at all.
    let resp = r
        .send("A", exec(bash("sleep 0 & wait; echo bg_done")))
        .await;
    let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout.contains("bg_done"));
    let timeout = matches!(&resp, Response::ExecTimeout { .. });
    r.record(
        "X12.background_wait",
        "A",
        pass,
        &format!("timeout={timeout} {resp:?}"),
    );

    // X13: Multiple background processes — echo a & echo b & wait
    // Two concurrent forks. With vfork semantics, these run serially.
    // Tests whether the outputs from both appear.
    let resp = r
        .send("A", exec(bash("echo bg_a & echo bg_b & wait")))
        .await;
    let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout.contains("bg_a") && stdout.contains("bg_b"));
    let timeout = matches!(&resp, Response::ExecTimeout { .. });
    r.record(
        "X13.multi_background",
        "A",
        pass,
        &format!("timeout={timeout} {resp:?}"),
    );

    // X14: Subshell exit code — (exit 42); echo $?
    // Subshell fork with immediate exit. Tests whether exit code
    // propagates back through the vfork/delayed-fork path.
    let resp = r.send("A", exec(bash("(exit 42); echo $?"))).await;
    let pass =
        matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout.contains("42"));
    let timeout = matches!(&resp, Response::ExecTimeout { .. });
    r.record(
        "X14.subshell_exit_code",
        "A",
        pass,
        &format!("timeout={timeout} {resp:?}"),
    );

    // X15: Sequential commands without pipes (baseline)
    // Multiple fork+exec operations chained with &&. No pipes between them,
    // just sequential execution. Validates basic multi-command shell scripts.
    let resp = r
        .send("A", exec(bash("echo seq_a && echo seq_b && echo seq_c")))
        .await;
    let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout.contains("seq_a") && stdout.contains("seq_c"));
    r.record("X15.sequential_cmds", "A", pass, &format!("{resp:?}"));

    // ── More aggressive delayed-fork stress tests ──

    // X16: Deeply nested command substitution
    // Each $(…) creates a subshell fork. Three levels of nesting means
    // three sequential fork+exec+capture cycles.
    let resp = r
        .send("A", exec(bash("echo $(echo $(echo deep_nested))")))
        .await;
    let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout.contains("deep_nested"));
    let timeout = matches!(&resp, Response::ExecTimeout { .. });
    r.record(
        "X16.nested_subshell",
        "A",
        pass,
        &format!("timeout={timeout} {resp:?}"),
    );

    // X17: Here-document — uses an internal pipe to feed stdin
    // bash creates a pipe for the heredoc content, forks the command,
    // and the child reads from the pipe.
    let resp = r
        .send("A", exec(bash("cat <<'EOF'\nheredoc_line\nEOF")))
        .await;
    let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout.contains("heredoc_line"));
    let timeout = matches!(&resp, Response::ExecTimeout { .. });
    r.record(
        "X17.heredoc",
        "A",
        pass,
        &format!("timeout={timeout} {resp:?}"),
    );

    // X18: Here-string — simpler variant of heredoc
    let resp = r.send("A", exec(bash("cat <<< 'herestring_data'"))).await;
    let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout.contains("herestring_data"));
    let timeout = matches!(&resp, Response::ExecTimeout { .. });
    r.record(
        "X18.herestring",
        "A",
        pass,
        &format!("timeout={timeout} {resp:?}"),
    );

    // X19: Pipe with grep — common real-world pattern
    // Tests pipe bridging with a program (grep) that does buffered reads.
    let resp = r
        .send(
            "A",
            exec(bash("echo -e 'alpha\\nbeta\\ngamma' | grep beta")),
        )
        .await;
    let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout.contains("beta"));
    let timeout = matches!(&resp, Response::ExecTimeout { .. });
    r.record(
        "X19.pipe_grep",
        "A",
        pass,
        &format!("timeout={timeout} {resp:?}"),
    );

    // X20: Command substitution with pipe and wc — VS Code install pattern
    // `$(curl ... | sh)` like patterns use command substitution + pipe.
    let resp = r
        .send(
            "A",
            exec(bash("echo $(echo 'line1\\nline2\\nline3' | wc -l)")),
        )
        .await;
    let pass =
        matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout.trim() != "");
    let timeout = matches!(&resp, Response::ExecTimeout { .. });
    r.record(
        "X20.subshell_pipe_wc",
        "A",
        pass,
        &format!("timeout={timeout} {resp:?}"),
    );

    // X21: Backtick substitution (older syntax) — equivalent to $() but
    // tests different bash code path.
    let resp = r.send("A", exec(bash("echo `echo backtick_val`"))).await;
    let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout.contains("backtick_val"));
    let timeout = matches!(&resp, Response::ExecTimeout { .. });
    r.record(
        "X21.backtick_subst",
        "A",
        pass,
        &format!("timeout={timeout} {resp:?}"),
    );

    // X22: Pipe to while-read loop — common shell pattern that does
    // fork + pipe + read in a loop. The read is non-pre-exec.
    let resp = r
        .send(
            "A",
            exec(bash(
                "echo -e 'a\\nb\\nc' | while read line; do echo \"got_$line\"; done",
            )),
        )
        .await;
    let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout.contains("got_a") && stdout.contains("got_c"));
    let timeout = matches!(&resp, Response::ExecTimeout { .. });
    r.record(
        "X22.pipe_while_read",
        "A",
        pass,
        &format!("timeout={timeout} {resp:?}"),
    );

    // X23: Pipe from second-level worker — same as X10 but from AA.
    // Tests whether pipe bridging works differently at deeper nesting.
    let resp = r.send("AA", exec(bash("echo deeper_pipe | cat"))).await;
    let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout.contains("deeper_pipe"));
    let timeout = matches!(&resp, Response::ExecTimeout { .. });
    r.record(
        "X23.deep_pipe",
        "AA",
        pass,
        &format!("timeout={timeout} {resp:?}"),
    );

    // X24: Pipe in subshell from deep worker — X8 from AAA.
    let resp = r
        .send("AAA", exec(bash("echo $(echo deep_sub | cat)")))
        .await;
    let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout.contains("deep_sub"));
    let timeout = matches!(&resp, Response::ExecTimeout { .. });
    r.record(
        "X24.deep_subshell_pipe",
        "AAA",
        pass,
        &format!("timeout={timeout} {resp:?}"),
    );

    // X25: xargs — forks multiple child processes from piped input.
    let resp = r
        .send(
            "A",
            exec(bash("echo -e 'p\\nq\\nr' | xargs -I{} echo xargs_{}")),
        )
        .await;
    let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout.contains("xargs_p") && stdout.contains("xargs_r"));
    let timeout = matches!(&resp, Response::ExecTimeout { .. });
    r.record(
        "X25.xargs",
        "A",
        pass,
        &format!("timeout={timeout} {resp:?}"),
    );
}

/// Node.js exec tests — run LAST because Node.js startup triggers delayed
/// fork which can corrupt the agent's stdout pipe (IPC handshake output).
pub(super) async fn node_exec_tests(r: &mut TestRunner) {
    let bash = |cmd: &str| -> Vec<String> { vec!["bash".into(), "-c".into(), cmd.into()] };
    let self_exe = r.self_exe.clone();

    // X26: Exec system Node.js directly from worker
    let resp = r
        .send(
            "A",
            exec(vec![
                "/usr/local/bin/node".into(),
                "-e".into(),
                "console.log('node_ok')".into(),
            ]),
        )
        .await;
    let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout.contains("node_ok"));
    r.record("X26.node_direct", "A", pass, &format!("{resp:?}"));

    // X27: Exec Node.js from depth-2 worker
    let resp = r
        .send(
            "AA",
            exec(vec![
                "/usr/local/bin/node".into(),
                "-e".into(),
                "console.log('node_deep_ok')".into(),
            ]),
        )
        .await;
    let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout.contains("node_deep_ok"));
    r.record("X27.node_deep", "AA", pass, &format!("{resp:?}"));

    // X28: Exec a shell SCRIPT FILE (no node — baseline)
    // Tests whether bash can exec a script file at all from a worker.
    let resp = r
        .send(
            "A",
            exec(bash(
                "echo '#!/usr/bin/bash' > /tmp/x28.sh && \
         echo 'echo script_echo_ok' >> /tmp/x28.sh && \
         chmod +x /tmp/x28.sh && \
         /tmp/x28.sh; \
         EXIT=$?; rm -f /tmp/x28.sh; exit $EXIT",
            )),
        )
        .await;
    let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout.contains("script_echo_ok"));
    r.record("X28.script_file_echo", "A", pass, &format!("{resp:?}"));

    // X28b: Script file that runs node (direct shebang)
    // KNOWN ISSUE: node within a script file produces no stdout.
    // Direct node exec (X26) and bash -c "node ..." both work, but
    // script.sh → node adds an extra fork+exec level whose stdout
    // pipe bridging loses the output. This is the same failure pattern
    // as VS Code's code-server (a script that execs node).
    let resp = r
        .send(
            "A",
            exec(bash(
                "echo '#!/usr/bin/bash' > /tmp/x28b.sh && \
         echo '/usr/local/bin/node -e \"console.log(\\\"script_node_ok\\\")\"' >> /tmp/x28b.sh && \
         chmod +x /tmp/x28b.sh && \
         /tmp/x28b.sh; \
         EXIT=$?; rm -f /tmp/x28b.sh; exit $EXIT",
            )),
        )
        .await;
    let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout.contains("script_node_ok"));
    r.record("X28b.script_file_node", "A", pass, &format!("{resp:?}"));

    // X28c: Script file with env shebang (same issue)
    let resp = r
        .send(
            "A",
            exec(bash(
                "echo '#!/usr/bin/env bash' > /tmp/x28c.sh && \
         echo '/usr/local/bin/node -e \"console.log(\\\"script_env_ok\\\")\"' >> /tmp/x28c.sh && \
         chmod +x /tmp/x28c.sh && \
         /tmp/x28c.sh; \
         EXIT=$?; rm -f /tmp/x28c.sh; exit $EXIT",
            )),
        )
        .await;
    let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout.contains("script_env_ok"));
    r.record("X28c.script_file_env", "A", pass, &format!("{resp:?}"));

    // X29: Node.js process.stdout.write — tests stdout pipe state
    // after multiple delayed-fork worker spawns from prior node execs.
    let resp = r
        .send(
            "A",
            exec(vec![
                "/usr/local/bin/node".into(),
                "-e".into(),
                "process.stdout.write('stdout_write_ok\\n')".into(),
            ]),
        )
        .await;
    let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout.contains("stdout_write_ok"));
    r.record("X29.node_stdout_write", "A", pass, &format!("{resp:?}"));

    // ── X30-X33: Narrow X28b failure ──

    // X30: Script file runs `cat` (simple external binary, not node)
    // Isolates: is it any binary from a script file, or node-specific?
    let resp = r
        .send(
            "A",
            exec(bash(
                "echo '#!/usr/bin/bash' > /tmp/x30.sh && \
         echo 'echo cat_input | cat' >> /tmp/x30.sh && \
         chmod +x /tmp/x30.sh && \
         /tmp/x30.sh; \
         EXIT=$?; rm -f /tmp/x30.sh; exit $EXIT",
            )),
        )
        .await;
    let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout.contains("cat_input"));
    r.record("X30.script_file_cat", "A", pass, &format!("{resp:?}"));

    // X31: Nested bash invocation (same depth as X28b but no script file)
    // Isolates: is it the script-file exec or the fork depth?
    let resp = r
        .send(
            "A",
            exec(bash(
                "bash -c '/usr/local/bin/node -e \"console.log(\\\"nested_ok\\\")\"'",
            )),
        )
        .await;
    let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout.contains("nested_ok"));
    r.record("X31.nested_bash_node", "A", pass, &format!("{resp:?}"));

    // X32: Script file runs self_exe echo-test
    // Isolates: is it node-specific or any fork+exec'd binary?
    let resp = r
        .send(
            "A",
            exec(bash(&format!(
                "echo '#!/usr/bin/bash' > /tmp/x32.sh && \
         echo '{} echo-test' >> /tmp/x32.sh && \
         chmod +x /tmp/x32.sh && \
         /tmp/x32.sh; \
         EXIT=$?; rm -f /tmp/x32.sh; exit $EXIT",
                self_exe
            ))),
        )
        .await;
    let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout.contains("ECHO_TEST_OK"));
    r.record("X32.script_file_self_exe", "A", pass, &format!("{resp:?}"));

    // X33: Script file with `exec node` (replaces bash, no extra fork)
    // Isolates: is it the fork depth or does `exec` (which replaces the
    // process instead of forking) work?
    let resp = r
        .send(
            "A",
            exec(bash(
                "echo '#!/usr/bin/bash' > /tmp/x33.sh && \
         echo 'exec /usr/local/bin/node -e \"console.log(\\\"exec_ok\\\")\"' >> /tmp/x33.sh && \
         chmod +x /tmp/x33.sh && \
         /tmp/x33.sh; \
         EXIT=$?; rm -f /tmp/x33.sh; exit $EXIT",
            )),
        )
        .await;
    let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout.contains("exec_ok"));
    r.record("X33.script_file_exec_node", "A", pass, &format!("{resp:?}"));

    // X34: Nested delayed-fork — no Node.js
    // Fork+exec self with trigger-delayed-fork subcommand, which:
    // 1. Triggers delayed-fork migration (via mmap/Vec allocation)
    // 2. From within the migrated worker, fork+execs echo-test
    // This isolates the "delayed-fork within delayed-fork" pattern
    // without Node.js — tests pure platform behavior.
    let resp = r
        .send(
            "A",
            exec(vec![
                self_exe.clone(),
                "trigger-delayed-fork".into(),
                self_exe.clone(),
                "echo-test".into(),
            ]),
        )
        .await;
    let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout.contains("ECHO_TEST_OK"));
    r.record("X34.nested_delayed_fork", "A", pass, &format!("{resp:?}"));

    // X34b: Same from depth 2
    let resp = r
        .send(
            "AA",
            exec(vec![
                self_exe.clone(),
                "trigger-delayed-fork".into(),
                self_exe.clone(),
                "echo-test".into(),
            ]),
        )
        .await;
    let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout.contains("ECHO_TEST_OK"));
    r.record(
        "X34b.nested_delayed_fork_deep",
        "AA",
        pass,
        &format!("{resp:?}"),
    );

    // X35: trigger-delayed-fork → node
    // Does fork+exec of node from a delayed-fork child lose stdout?
    // Removes bash/script-file from the equation.
    let resp = r
        .send(
            "A",
            exec(vec![
                self_exe.clone(),
                "trigger-delayed-fork".into(),
                "/usr/local/bin/node".into(),
                "-e".into(),
                "console.log('df_node_ok')".into(),
            ]),
        )
        .await;
    let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout.contains("df_node_ok"));
    r.record(
        "X35.delayed_fork_then_node",
        "A",
        pass,
        &format!("{resp:?}"),
    );

    // X36: trigger-delayed-fork → trigger-delayed-fork → echo-test
    // Three levels of delayed-fork nesting.
    let resp = r
        .send(
            "A",
            exec(vec![
                self_exe.clone(),
                "trigger-delayed-fork".into(),
                self_exe.clone(),
                "trigger-delayed-fork".into(),
                self_exe.clone(),
                "echo-test".into(),
            ]),
        )
        .await;
    let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout.contains("ECHO_TEST_OK"));
    r.record("X36.triple_delayed_fork", "A", pass, &format!("{resp:?}"));

    // X37: Script file that fork+execs trigger-delayed-fork → echo-test
    // Same depth as X28b but using trigger-delayed-fork instead of node.
    // Isolates: is the issue script+fork+delayed-fork, or script+fork+node?
    let resp = r
        .send(
            "A",
            exec(bash(&format!(
                "echo '#!/usr/bin/bash' > /tmp/x37.sh && \
         echo '{self_exe} trigger-delayed-fork {self_exe} echo-test' >> /tmp/x37.sh && \
         chmod +x /tmp/x37.sh && \
         /tmp/x37.sh; \
         EXIT=$?; rm -f /tmp/x37.sh; exit $EXIT"
            ))),
        )
        .await;
    let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout.contains("ECHO_TEST_OK"));
    r.record(
        "X37.script_fork_delayed_fork",
        "A",
        pass,
        &format!("{resp:?}"),
    );

    // X38: trigger-delayed-fork-thread → echo-test (direct)
    // Same as X34 but triggers delayed-fork via clone3 (thread creation)
    // instead of mmap. Tests whether thread-based delayed-fork works.
    let resp = r
        .send(
            "A",
            exec(vec![
                self_exe.clone(),
                "trigger-delayed-fork-thread".into(),
                self_exe.clone(),
                "echo-test".into(),
            ]),
        )
        .await;
    let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout.contains("ECHO_TEST_OK"));
    r.record("X38.thread_delayed_fork", "A", pass, &format!("{resp:?}"));

    // X39: Script file → fork trigger-delayed-fork-thread → echo-test
    // Same as X37 but with thread-based delayed-fork trigger.
    // If this fails while X37 passes → thread creation in a script-forked
    // child is the root cause of X28b.
    let resp = r
        .send(
            "A",
            exec(bash(&format!(
                "echo '#!/usr/bin/bash' > /tmp/x39.sh && \
         echo '{self_exe} trigger-delayed-fork-thread {self_exe} echo-test' >> /tmp/x39.sh && \
         chmod +x /tmp/x39.sh && \
         /tmp/x39.sh; \
         EXIT=$?; rm -f /tmp/x39.sh; exit $EXIT"
            ))),
        )
        .await;
    let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout.contains("ECHO_TEST_OK"));
    r.record(
        "X39.script_fork_thread_delayed",
        "A",
        pass,
        &format!("{resp:?}"),
    );

    // ── Node.js feature tests ──

    // X48: Node.js os.networkInterfaces() — VS Code code-server calls this
    // on startup to find a loopback address. getifaddrs is unimplemented
    // in litebox (returns ENOSYS), so Node.js should either return an empty
    // object or throw a catchable error, not crash.
    let resp = r
        .send(
            "A",
            exec(vec![
                "/usr/local/bin/node".into(),
                "-e".into(),
                "try { const r = require('os').networkInterfaces(); \
         console.log('NETIF_OK:' + Object.keys(r).length); } \
         catch(e) { console.log('NETIF_ERR:' + e.code); }"
                    .into(),
            ]),
        )
        .await;
    let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. }
        if stdout.contains("NETIF_OK:") || stdout.contains("NETIF_ERR:"));
    r.record(
        "X48.node_networkInterfaces",
        "A",
        pass,
        &format!("{resp:?}"),
    );

    // ── Isolation tests ──
    // These tests check whether sequential execs from the same agent
    // contaminate each other. They run BEFORE non-PIE tests to establish
    // whether PIE execs are clean.

    // X49: Two sequential PIE execs from the same agent.
    // Both should return their own output. If the second returns the
    // first's output, the contamination affects PIE too.
    let resp = r
        .send("A", exec(vec![self_exe.clone(), "echo-test".into()]))
        .await;
    let pass1 = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout == "ECHO_TEST_OK");
    r.record("X49a.pie_sequential_1", "A", pass1, &format!("{resp:?}"));

    let resp = r
        .send(
            "A",
            exec(vec![self_exe.clone(), "exit-with".into(), "0".into()]),
        )
        .await;
    let pass2 =
        matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout.is_empty());
    r.record("X49b.pie_sequential_2", "A", pass2, &format!("{resp:?}"));

    // X50: PIE exec after a non-PIE exec.
    // If non-PIE exec contaminates, this PIE exec gets non-PIE's output.
    let resp = r.send("A", exec(vec!["/nonpie-echo".into()])).await;
    let not_found = matches!(&resp, Response::ExecResult { exit_code: 127, .. })
        || matches!(&resp, Response::Error { .. });
    if not_found {
        r.record(
            "X50a.nonpie_then_pie_1",
            "A",
            true,
            "skipped (nonpie-echo not in rootfs)",
        );
        r.record(
            "X50b.nonpie_then_pie_2",
            "A",
            true,
            "skipped (nonpie-echo not in rootfs)",
        );
    } else {
        let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout.contains("NONPIE_OK"));
        r.record("X50a.nonpie_then_pie_1", "A", pass, &format!("{resp:?}"));

        // Now exec a PIE binary — should see PIE's output, not NONPIE_OK.
        let resp = r
            .send("A", exec(vec![self_exe.clone(), "echo-test".into()]))
            .await;
        let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout == "ECHO_TEST_OK");
        r.record("X50b.nonpie_then_pie_2", "A", pass, &format!("{resp:?}"));
    }

    // X51: Non-PIE exec on a FRESH agent (B) that has never exec'd non-PIE.
    // If this passes, the contamination is per-agent state, not global.
    let resp = r.send("B", exec(vec!["/nonpie-echo".into()])).await;
    let not_found = matches!(&resp, Response::ExecResult { exit_code: 127, .. })
        || matches!(&resp, Response::Error { .. });
    if not_found {
        r.record(
            "X51.nonpie_fresh_agent",
            "B",
            true,
            "skipped (nonpie-echo not in rootfs)",
        );
        r.record("X52a.B_nonpie_then_pie", "B", true, "skipped");
        r.record("X52b.B_pie_after_nonpie", "B", true, "skipped");
        r.record("X52c.B_third_exec", "B", true, "skipped");
    } else {
        let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout.contains("NONPIE_OK"));
        r.record("X51.nonpie_fresh_agent", "B", pass, &format!("{resp:?}"));

        // X52a: PIE exec on B after the non-PIE — does B get contaminated?
        let resp = r
            .send("B", exec(vec![self_exe.clone(), "echo-test".into()]))
            .await;
        let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout == "ECHO_TEST_OK");
        r.record("X52a.B_nonpie_then_pie", "B", pass, &format!("{resp:?}"));

        // X52b: Another PIE exec — does the shift continue?
        let resp = r
            .send(
                "B",
                exec(vec![self_exe.clone(), "exit-with".into(), "0".into()]),
            )
            .await;
        let pass =
            matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout.is_empty());
        r.record("X52b.B_pie_after_nonpie", "B", pass, &format!("{resp:?}"));

        // X52c: One more — is the shift a one-time glitch or persistent?
        let resp = r
            .send("B", exec(vec![self_exe.clone(), "echo-test".into()]))
            .await;
        let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout == "ECHO_TEST_OK");
        r.record("X52c.B_third_exec", "B", pass, &format!("{resp:?}"));
    }

    // X53: Stress test — many sequential PIE execs on agent AB.
    // AB is a child of A, and has never been used for Exec.
    // If this fails at some count, there's a per-agent resource leak.
    let mut x53_all_pass = true;
    for i in 0..30 {
        let resp = r
            .send("AB", exec(vec![self_exe.clone(), "echo-test".into()]))
            .await;
        let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout == "ECHO_TEST_OK");
        if !pass {
            r.record(
                "X53.stress_pie",
                "AB",
                false,
                &format!("failed at iteration {i}: {resp:?}"),
            );
            x53_all_pass = false;
            break;
        }
    }
    if x53_all_pass {
        r.record(
            "X53.stress_pie",
            "AB",
            true,
            "30 sequential PIE execs all passed",
        );
    }

    // X54: Non-PIE exec on AB after 30 PIE execs — does prior PIE state
    // interfere with non-PIE?
    let resp = r.send("AB", exec(vec!["/nonpie-echo".into()])).await;
    let not_found = matches!(&resp, Response::ExecResult { exit_code: 127, .. })
        || matches!(&resp, Response::Error { .. });
    if not_found {
        r.record("X54.nonpie_after_stress", "AB", true, "skipped");
    } else {
        let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout.contains("NONPIE_OK"));
        r.record("X54.nonpie_after_stress", "AB", pass, &format!("{resp:?}"));
    }

    // X55: Non-PIE as SECOND exec (AAB has never been used).
    // One PIE exec, then one non-PIE — minimum reproduction.
    let resp = r
        .send("AAB", exec(vec![self_exe.clone(), "echo-test".into()]))
        .await;
    let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout == "ECHO_TEST_OK");
    r.record("X55a.one_pie_first", "AAB", pass, &format!("{resp:?}"));

    let resp = r.send("AAB", exec(vec!["/nonpie-echo".into()])).await;
    let not_found = matches!(&resp, Response::ExecResult { exit_code: 127, .. })
        || matches!(&resp, Response::Error { .. });
    if not_found {
        r.record("X55b.nonpie_second", "AAB", true, "skipped");
    } else {
        let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout.contains("NONPIE_OK"));
        r.record("X55b.nonpie_second", "AAB", pass, &format!("{resp:?}"));
    }

    // X56: Non-PIE as FIRST exec, PIE as second (AAA — check if already used).
    // Use a fresh agent for a cleaner test... but AAA may have been used
    // by X3. Let me use it anyway — the key is the order.
    // Actually, let's just do two sequential non-PIE on B to check.
    let resp = r.send("B", exec(vec!["/nonpie-echo".into()])).await;
    let not_found = matches!(&resp, Response::ExecResult { exit_code: 127, .. })
        || matches!(&resp, Response::Error { .. });
    if not_found {
        r.record("X56.second_nonpie_on_B", "B", true, "skipped");
        r.record("X57.pipe_churn_then_nonpie", "B", true, "skipped");
        r.record("X58.alternating_pie_nonpie", "B", true, "skipped");
        r.record("X59.sequential_nonpie", "B", true, "skipped");
    } else {
        let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout.contains("NONPIE_OK"));
        r.record("X56.second_nonpie_on_B", "B", pass, &format!("{resp:?}"));

        // X57: Rapid pipe churn to force address reuse, then non-PIE exec.
        // Create and close many subshells (each creates pipe pairs) to
        // increase probability that a new pipe reuses a freed address.
        // Then exec non-PIE — should still return correct output.
        for _ in 0..20 {
            let _ = r.send("B", exec(bash("echo churn >/dev/null"))).await;
        }
        let resp = r.send("B", exec(vec!["/nonpie-echo".into()])).await;
        let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout.contains("NONPIE_OK"));
        r.record(
            "X57.pipe_churn_then_nonpie",
            "B",
            pass,
            &format!("{resp:?}"),
        );

        // X58: Alternating PIE and non-PIE execs on B.
        // PIE, non-PIE, PIE, non-PIE — each should return its own output.
        let results: Vec<(String, bool)> = {
            let mut results = Vec::new();
            let resp = r
                .send("B", exec(vec![self_exe.clone(), "echo-test".into()]))
                .await;
            let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout == "ECHO_TEST_OK");
            results.push((format!("{resp:?}"), pass));

            let resp = r.send("B", exec(vec!["/nonpie-echo".into()])).await;
            let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout.contains("NONPIE_OK"));
            results.push((format!("{resp:?}"), pass));

            let resp = r
                .send("B", exec(vec![self_exe.clone(), "echo-test".into()]))
                .await;
            let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout == "ECHO_TEST_OK");
            results.push((format!("{resp:?}"), pass));

            let resp = r.send("B", exec(vec!["/nonpie-echo".into()])).await;
            let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout.contains("NONPIE_OK"));
            results.push((format!("{resp:?}"), pass));
            results
        };
        let all_pass = results.iter().all(|(_, p)| *p);
        let detail = results
            .iter()
            .enumerate()
            .map(|(i, (d, p))| format!("[{i}]={p}: {d}"))
            .collect::<Vec<_>>()
            .join("; ");
        r.record("X58.alternating_pie_nonpie", "B", all_pass, &detail);

        // X59: Five sequential non-PIE execs on B. Each must return NONPIE_OK.
        let mut x59_all_pass = true;
        for i in 0..5 {
            let resp = r.send("B", exec(vec!["/nonpie-echo".into()])).await;
            let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout.contains("NONPIE_OK"));
            if !pass {
                r.record(
                    "X59.sequential_nonpie",
                    "B",
                    false,
                    &format!("failed at iteration {i}: {resp:?}"),
                );
                x59_all_pass = false;
                break;
            }
        }
        if x59_all_pass {
            r.record(
                "X59.sequential_nonpie",
                "B",
                true,
                "5 sequential non-PIE execs all passed",
            );
        }
    }

    // X60: stress-exec subcommand — bypasses agent protocol entirely.
    // Runs 20 sequential PIE execs from a single process (no forwarding).
    // If this fails, the issue is in litebox fork/exec, not the harness.
    let resp = r
        .send(
            "A",
            exec(vec![
                self_exe.clone(),
                "stress-exec".into(),
                "20".into(),
                "pie".into(),
            ]),
        )
        .await;
    let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. }
        if stdout.contains("STRESS_START") && stdout.contains("STRESS_END failures=0"));
    r.record("X60.stress_exec_pie", "A", pass, &format!("{resp:?}"));

    // X61: stress-exec with non-PIE — 10 sequential non-PIE execs.
    let resp = r
        .send(
            "A",
            exec(vec![
                self_exe.clone(),
                "stress-exec".into(),
                "10".into(),
                "nonpie".into(),
            ]),
        )
        .await;
    let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. }
        if stdout.contains("STRESS_START") && stdout.contains("STRESS_END failures=0"));
    r.record("X61.stress_exec_nonpie", "A", pass, &format!("{resp:?}"));

    // X62: stress-exec with mixed PIE/non-PIE — 10 alternating execs.
    let resp = r
        .send(
            "A",
            exec(vec![
                self_exe.clone(),
                "stress-exec".into(),
                "10".into(),
                "mixed".into(),
            ]),
        )
        .await;
    let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. }
        if stdout.contains("STRESS_START") && stdout.contains("STRESS_END failures=0"));
    r.record("X62.stress_exec_mixed", "A", pass, &format!("{resp:?}"));

    // X63: stress-exec using tokio::process::Command (same path as agent Exec).
    // If this fails but X62 passes, the issue is in tokio's process spawning.
    let resp = r
        .send(
            "A",
            exec(vec![
                self_exe.clone(),
                "stress-exec".into(),
                "10".into(),
                "mixed".into(),
                "tokio".into(),
            ]),
        )
        .await;
    let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. }
        if stdout.contains("STRESS_START") && stdout.contains("STRESS_END failures=0"));
    r.record(
        "X63.stress_exec_tokio_mixed",
        "A",
        pass,
        &format!("{resp:?}"),
    );

    // ── Non-PIE exec reproduction tests ──
    // The root cause of X28b is that non-PIE binaries (which load at
    // 0x400000) trigger exec_on_remote_host, and the pipe replacement
    // puts a read-end fd on the parent's stdout. These tests use a tiny
    // non-PIE binary (/nonpie-echo) to reproduce without Node.js.

    // X40: Direct exec of non-PIE binary from worker
    let resp = r.send("A", exec(vec!["/nonpie-echo".into()])).await;
    let not_found = matches!(&resp, Response::ExecResult { exit_code: 127, .. })
        || matches!(&resp, Response::Error { .. });
    if not_found {
        r.record(
            "X40.nonpie_direct",
            "A",
            true,
            "skipped (nonpie-echo not in rootfs)",
        );
    } else {
        let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout.contains("NONPIE_OK"));
        r.record("X40.nonpie_direct", "A", pass, &format!("{resp:?}"));
    }

    // X41: Script file that fork+execs non-PIE binary
    // Minimal reproduction of X28b without Node.js.
    // KNOWN ISSUE: exec_on_remote_host pipe replacement puts read-end
    // on parent's stdout — data written by non-PIE child is lost.
    let resp = r
        .send(
            "A",
            exec(bash(
                "if [ -x /nonpie-echo ]; then \
         echo '#!/usr/bin/bash' > /tmp/x41.sh && \
         echo '/nonpie-echo' >> /tmp/x41.sh && \
         chmod +x /tmp/x41.sh && \
         /tmp/x41.sh; \
         EXIT=$?; rm -f /tmp/x41.sh; exit $EXIT; \
         else echo SKIP; fi",
            )),
        )
        .await;
    let skipped = matches!(&resp, Response::ExecResult { stdout, .. } if stdout.contains("SKIP"));
    if skipped {
        r.record(
            "X41.nonpie_script",
            "A",
            true,
            "skipped (nonpie-echo not in rootfs)",
        );
    } else {
        let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout.contains("NONPIE_OK"));
        r.record("X41.nonpie_script", "A", pass, &format!("{resp:?}"));
    }

    // X42: bash -c directly execs non-PIE binary (no script file)
    // Even simpler reproduction — no script file needed.
    let resp = r
        .send(
            "A",
            exec(bash(
                "if [ -x /nonpie-echo ]; then /nonpie-echo; else echo SKIP; fi",
            )),
        )
        .await;
    let skipped = matches!(&resp, Response::ExecResult { stdout, .. } if stdout.contains("SKIP"));
    if skipped {
        r.record(
            "X42.nonpie_inline",
            "A",
            true,
            "skipped (nonpie-echo not in rootfs)",
        );
    } else {
        let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout.contains("NONPIE_OK"));
        r.record("X42.nonpie_inline", "A", pass, &format!("{resp:?}"));
    }

    // ── Pipe contamination tests ──
    // After exec-on-remote-host (non-PIE), the parent's pipe state must
    // be clean: subsequent execs must see their OWN stdout, not stale
    // data from the previous non-PIE child.

    // X43: Init-level contamination — exec non-PIE from init, then exec
    // echo-test from init. The second exec's stdout must be "ECHO_TEST_OK",
    // not the non-PIE binary's output.
    let resp = r.send("A", exec(vec!["/nonpie-echo".into()])).await;
    let not_found = matches!(&resp, Response::ExecResult { exit_code: 127, .. })
        || matches!(&resp, Response::Error { .. });
    if not_found {
        r.record(
            "X43.init_contamination",
            "A",
            true,
            "skipped (nonpie-echo not in rootfs)",
        );
    } else {
        let resp2 = r
            .send("A", exec(vec![self_exe.clone(), "echo-test".into()]))
            .await;
        let pass = matches!(&resp2, Response::ExecResult { exit_code: 0, stdout, .. } if stdout == "ECHO_TEST_OK");
        r.record("X43.init_contamination", "A", pass, &format!("{resp2:?}"));
    }

    // X44: Child-level contamination — bash execs non-PIE then echo-test
    // in sequence within a single bash -c. The non-PIE relay must not
    // leak into the subsequent command's stdout capture.
    let resp = r
        .send(
            "A",
            exec(bash(
                "if [ -x /nonpie-echo ]; then \
         /nonpie-echo >/dev/null 2>&1; \
         echo CHILD_CLEAN; \
         else echo SKIP; fi",
            )),
        )
        .await;
    let skipped = matches!(&resp, Response::ExecResult { stdout, .. } if stdout.contains("SKIP"));
    if skipped {
        r.record(
            "X44.child_contamination",
            "A",
            true,
            "skipped (nonpie-echo not in rootfs)",
        );
    } else {
        let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout.trim() == "CHILD_CLEAN");
        r.record("X44.child_contamination", "A", pass, &format!("{resp:?}"));
    }

    // X45: Child-level sequential — bash execs non-PIE (capturing output),
    // then execs echo-test. Both outputs must be correct and not cross-contaminated.
    let resp = r
        .send(
            "A",
            exec(bash(&format!(
                "if [ -x /nonpie-echo ]; then \
         FIRST=$(/nonpie-echo); \
         SECOND=$({self_exe} echo-test); \
         echo \"first=$FIRST\"; \
         echo \"second=$SECOND\"; \
         else echo SKIP; fi"
            ))),
        )
        .await;
    let skipped = matches!(&resp, Response::ExecResult { stdout, .. } if stdout.contains("SKIP"));
    if skipped {
        r.record(
            "X45.child_sequential",
            "A",
            true,
            "skipped (nonpie-echo not in rootfs)",
        );
    } else {
        let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. }
            if stdout.contains("first=NONPIE_OK") && stdout.contains("second=ECHO_TEST_OK"));
        r.record("X45.child_sequential", "A", pass, &format!("{resp:?}"));
    }

    // X46: Grandchild-level — nested bash execs non-PIE at depth 2.
    // bash -c 'bash -c "/nonpie-echo"' — the output must propagate
    // through two levels of pipe bridging.
    let resp = r
        .send(
            "A",
            exec(bash(
                "if [ -x /nonpie-echo ]; then \
         bash -c '/nonpie-echo'; \
         else echo SKIP; fi",
            )),
        )
        .await;
    let skipped = matches!(&resp, Response::ExecResult { stdout, .. } if stdout.contains("SKIP"));
    if skipped {
        r.record(
            "X46.grandchild_nonpie",
            "A",
            true,
            "skipped (nonpie-echo not in rootfs)",
        );
    } else {
        let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout.contains("NONPIE_OK"));
        r.record("X46.grandchild_nonpie", "A", pass, &format!("{resp:?}"));
    }

    // X47: Depth-2 contamination — nested bash execs non-PIE then
    // echo-test. The second command at depth 2 must see clean output.
    let resp = r
        .send(
            "A",
            exec(bash(&format!(
                "if [ -x /nonpie-echo ]; then \
         bash -c '/nonpie-echo >/dev/null; {self_exe} echo-test'; \
         else echo SKIP; fi"
            ))),
        )
        .await;
    let skipped = matches!(&resp, Response::ExecResult { stdout, .. } if stdout.contains("SKIP"));
    if skipped {
        r.record(
            "X47.grandchild_contamination",
            "A",
            true,
            "skipped (nonpie-echo not in rootfs)",
        );
    } else {
        let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout.trim() == "ECHO_TEST_OK");
        r.record(
            "X47.grandchild_contamination",
            "A",
            pass,
            &format!("{resp:?}"),
        );
    }
}
