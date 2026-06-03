// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Placeholder for special-case leaves already covered by sibling modules in this wave.

use super::*;

// Register pipe EOF tests.
pub(crate) fn register_pipe_eof(reg: &mut Registry<'_>) {
    // Long-lived agents this fan-out runs in. One slot per
    // BinaryType leg plus the VS-Code-shape transition slots so
    // each fork-parent code path is exercised.
    for &agent in &[
        AgentName::Dpg1,         // PIE-glibc
        AgentName::Dpg1Dpg1,     // PIE-glibc depth-2
        AgentName::Dpg2,         // PIE-glibc sibling subtree
        AgentName::Dpg1Dpg1Dpg1, // PIE-glibc depth-3
        AgentName::Dpg1Dng,      // non-PIE-glibc (node form)
        AgentName::Dpg1DngDng,   // bash → bash (VS Code hot path)
        AgentName::Dpg1DngSpm,   // bash → cli (VS Code hot path)
        AgentName::Dpg1Spg,      // static-PIE-glibc
        AgentName::Dpg1Spm,      // static-PIE-musl (cli form)
        AgentName::Dpg1SpmDng,   // cli → node (VS Code signature)
        AgentName::Dpg1Snm,      // non-PIE-static-musl
    ] {
        for &bt in crate::BinaryType::ALL {
            let id = format!("P1.pipe_eof_fork.{}.{agent}", bt.label());
            let agent_name = agent;
            let agent_label = agent.to_string();
            typed_test!(
                reg,
                "xworker",
                "pipe_eof",
                id,
                timeout = 60,
                agents[handle = agent_name],
                |run| {
                    let self_exe = run.self_exe().to_string();
                    let target = crate::binary_path(bt, &self_exe);
                    let resp = run
                        .send_named_typed(
                            &handle,
                            &EXEC_BIN,
                            ExecBinArgs {
                                argv: vec![target, "pipe-test".into(), "eof-fork".into()],
                                timeout_ms: Some(20 * 1000),
                                stdin: None,
                                env: vec![],
                            },
                        )
                        .await;
                    let pass = matches!(&resp, Ok(out) if out.exit_code == 0 && out.stdout.contains("P1_EOF_OK"));
                    crate::coordinator::TestOutcome::new(&agent_label, pass, format!("{resp:?}"))
                }
            );
        }
    }

    for &agent in &[AgentName::Dpg1, AgentName::Dpg1Dpg1, AgentName::Dpg2] {
        for &bt in crate::BinaryType::ALL {
            let id = format!("P2.pipe_eof_exec.{}.{agent}", bt.label());
            let agent_name = agent;
            let agent_label = agent.to_string();
            typed_test!(
                reg,
                "xworker",
                "pipe_eof",
                id,
                timeout = 60,
                agents[handle = agent_name],
                |run| {
                    let self_exe = run.self_exe().to_string();
                    let target = crate::binary_path(bt, &self_exe);
                    let resp = run
                        .send_named_typed(
                            &handle,
                            &EXEC_BIN,
                            ExecBinArgs {
                                argv: vec![self_exe, "pipe-test".into(), "eof-exec".into(), target],
                                timeout_ms: Some(20 * 1000),
                                stdin: None,
                                env: vec![],
                            },
                        )
                        .await;
                    let pass = matches!(&resp, Ok(out) if out.exit_code == 0 && out.stdout.contains("P2_EOF_OK"));
                    crate::coordinator::TestOutcome::new(&agent_label, pass, format!("{resp:?}"))
                }
            );
        }
    }
}

/// Register PFLG.nonblock_fork.* matrix probes — verify per-end
/// O_NONBLOCK preservation across fork.  Exercises the runner's
/// child-only-local-pipe Phase 2 BrokerPipe path (parent closes both
/// ends after fork; child holds the only references). Matrix:
///
///   (r_nb, w_nb) ∈ {(0,0), (1,0), (0,1), (1,1)}
///   × fork-agent shape ∈ {Dpg1, Dpg1Dpg1, Dpg1DngDng}
///   × BinaryType
///
/// The asymmetric cases (1,0)/(0,1) catch regressions where one
/// per-end flag is mistakenly applied to both ends (or to the wrong
/// end). Symmetric cases catch broad NONBLOCK loss.
pub(crate) fn register_pipe_nonblock_fork(reg: &mut Registry<'_>) {
    let combos: &[(bool, bool, &str)] = &[
        (false, false, "rb_wb"),
        (true, false, "rn_wb"),
        (false, true, "rb_wn"),
        (true, true, "rn_wn"),
    ];
    let agents = &[
        AgentName::Dpg1,       // PIE-glibc, depth-1
        AgentName::Dpg1Dpg1,   // PIE-glibc, depth-2 (nested fork)
        AgentName::Dpg1DngDng, // VS-Code-shape transition (mux dispatcher)
    ];
    for &(r_nb, w_nb, suffix) in combos {
        for &agent in agents {
            for &bt in crate::BinaryType::ALL {
                let id = format!("PFLG.nonblock_fork.{suffix}.{}.{agent}", bt.label());
                let agent_name = agent;
                let agent_label = agent.to_string();
                let r_arg = if r_nb { "1" } else { "0" };
                let w_arg = if w_nb { "1" } else { "0" };
                typed_test!(
                    reg,
                    "xworker",
                    "pipe_nonblock_fork",
                    id,
                    timeout = 60,
                    agents[handle = agent_name],
                    |run| {
                        let self_exe = run.self_exe().to_string();
                        let target = crate::binary_path(bt, &self_exe);
                        let resp = run
                            .send_named_typed(
                                &handle,
                                &EXEC_BIN,
                                ExecBinArgs {
                                    argv: vec![
                                        target,
                                        "pipe-test".into(),
                                        "nonblock-fork".into(),
                                        r_arg.into(),
                                        w_arg.into(),
                                    ],
                                    timeout_ms: Some(20 * 1000),
                                    stdin: None,
                                    env: vec![],
                                },
                            )
                            .await;
                        let pass = matches!(
                            &resp,
                            Ok(out) if out.exit_code == 0 && out.stdout.contains("PFLG_NB_OK")
                        );
                        crate::coordinator::TestOutcome::new(
                            &agent_label,
                            pass,
                            format!("{resp:?}"),
                        )
                    }
                );
            }
        }
    }
}
