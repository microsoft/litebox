// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Placeholder for special-case leaves already covered by sibling modules in this wave.

use super::*;

/// Register terminal ioctl tests.
pub(super) fn register_terminal_ioctl(reg: &mut Registry<'_>) {
    super::exit::register();
    let ops = ["tcgets", "tcsets", "tcsetsw", "tcsetsf", "tiocgwinsz"];
    let fds = [0, 1, 2];
    for op in &ops {
        for fd in &fds {
            for &bt in crate::BinaryType::ALL {
                let id = format!("TERM.{op}_fd{fd}.{}", bt.label());
                let op = op.to_string();
                let fd_str = fd.to_string();
                typed_test!(
                    reg,
                    "matrix",
                    "terminal_ioctl",
                    id,
                    timeout = 60,
                    agents[a = AgentName::Dpg1],
                    |run| {
                        let self_exe = run.self_exe().to_string();
                        let target = crate::binary_path(bt, &self_exe);
                        let resp = run
                            .send_named_typed(
                                &a,
                                &EXEC_BIN,
                                ExecBinArgs {
                                    argv: vec![
                                        target,
                                        "exit-test".into(),
                                        "term".into(),
                                        op,
                                        fd_str,
                                    ],
                                    timeout_ms: Some(8 * 1000),
                                    stdin: None,
                                    env: vec![],
                                },
                            )
                            .await;
                        // tcgetattr / tcsetattr / TIOCGWINSZ on a pipe must
                        // return ENOTTY (errno=25). Exec wires stdio to pipes,
                        // so every (op, fd) row should produce TERM_ERR with
                        // errno=25.
                        // Exit code: tcgets/tiocgwinsz return from main (exit 0);
                        // tcsets/tcsetsw/tcsetsf hit the phase=tcgetattr fast-fail
                        // and call process::exit(1).
                        let pass = matches!(
                            &resp,
                            Ok(out) if matches!(out.exit_code, 0 | 1)
                                && out.stdout.contains("TERM_ERR")
                                && out.stdout.contains("errno=25")
                        );
                        crate::coordinator::TestOutcome::new("A", pass, format!("{resp:?}"))
                    }
                );
            }
        }
    }
}
