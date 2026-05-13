// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Platform fix validation tests — matrix-loop tests that prove specific bug
//! fixes are needed by exercising the exact behavior each fix corrected.
//!
//! Each test category targets a commit in the wportnoy/vscode-server-in-litebox
//! branch and must pass on both native WSL2 (gold standard) and litebox.

#![allow(clippy::items_after_statements)]

use serde::{Deserialize, Serialize};

use super::agents::AgentName;
use super::matrix::{EXEC, ExecArgs};
use super::registry::Registry;
use crate::protocol::Response;

pub(super) const AGENTS: &[AgentName] = &[AgentName::Dpg1, AgentName::Dpg1Dpg1, AgentName::Dpg2];

#[derive(Serialize, Deserialize, Debug)]
pub(super) struct DetailOut {
    pub(super) detail: String,
}

/// Register the platform-fixes-specific handlers (non-canonical
/// handlers that are unique to this family). Canonical handlers
/// (`EXEC`, `FS_READ`, `NET_LISTEN`, etc.) are registered by
/// `register_matrix_handlers` in `matrix.rs`.
pub(crate) fn register_pf_specific_handlers() {
    crate::register_leaf_subcommand!("proc-probe", leaf_subcmd::subcmd_proc_probe);
    crate::register_leaf_subcommand!("check-ppid", leaf_subcmd::subcmd_check_ppid);
}

pub(super) fn fork_binary_label(bt: crate::BinaryType) -> &'static str {
    match bt {
        crate::BinaryType::PieGlibc => "self",
        crate::BinaryType::NonPieGlibc => "nonpie",
        crate::BinaryType::StaticPieGlibc => "static-pie-glibc",
        crate::BinaryType::StaticPieMusl => "static-pie-musl",
        crate::BinaryType::NonPieStaticMusl => "non-pie-static-musl",
    }
}

mod leaf_subcmd {
    pub(super) fn subcmd_check_ppid(_args: &[String]) -> i32 {
        let ppid = unsafe { libc::getppid() };
        let proc_exists = std::path::Path::new(&format!("/proc/{ppid}")).exists();
        let kill_ret = unsafe { libc::kill(ppid, 0) };
        let kill_errno = if kill_ret != 0 {
            std::io::Error::last_os_error().raw_os_error().unwrap_or(-1)
        } else {
            0
        };
        let kill_ok = kill_ret == 0;
        println!("ppid={ppid} proc={proc_exists} kill0={kill_ok} errno={kill_errno}");
        0
    }

    pub(super) fn subcmd_proc_probe(args: &[String]) -> i32 {
        let pid = unsafe { libc::getpid() };
        let parent_pid = unsafe { libc::getppid() };
        let self_exists = std::path::Path::new("/proc/self").exists();
        let self_cmdline = std::fs::read_to_string("/proc/self/cmdline")
            .map(|s| !s.is_empty())
            .unwrap_or(false);
        let self_stat = std::fs::read_to_string("/proc/self/stat")
            .map(|s| !s.is_empty())
            .unwrap_or(false);
        let own_proc = std::path::Path::new(&format!("/proc/{pid}")).exists();
        let own_cmdline = std::fs::read_to_string(format!("/proc/{pid}/cmdline"))
            .map(|s| !s.is_empty())
            .unwrap_or(false);
        let ppid_proc = std::path::Path::new(&format!("/proc/{parent_pid}")).exists();
        let ppid_cmdline = std::fs::read_to_string(format!("/proc/{parent_pid}/cmdline"))
            .map(|s| !s.is_empty())
            .unwrap_or(false);
        let ppid_kill0_ret = unsafe { libc::kill(parent_pid, 0) };
        let ppid_kill0_errno = if ppid_kill0_ret != 0 {
            std::io::Error::last_os_error().raw_os_error().unwrap_or(-1)
        } else {
            0
        };
        let ppid_kill0 = ppid_kill0_ret == 0;
        print!("pid={pid} ppid={parent_pid}");
        print!(" self={self_exists} self_cmdline={self_cmdline} self_stat={self_stat}");
        print!(" own_proc={own_proc} own_cmdline={own_cmdline}");
        print!(
            " ppid_proc={ppid_proc} ppid_cmdline={ppid_cmdline} ppid_kill0={ppid_kill0} ppid_kill0_errno={ppid_kill0_errno}"
        );
        if let Some(target) = args.get(2).and_then(|s| s.parse::<i32>().ok()) {
            let t_proc = std::path::Path::new(&format!("/proc/{target}")).exists();
            let t_kill0 = unsafe { libc::kill(target, 0) } == 0;
            print!(" target={target} target_proc={t_proc} target_kill0={t_kill0}");
        }
        println!();
        0
    }

    fn m_target_binary() -> String {
        if let Ok(p) = std::env::var("LITEBOX_M_TARGET_BINARY")
            && !p.is_empty()
        {
            return p;
        }
        crate::nonpie_binary()
    }

    pub(super) fn subcmd_m1_tokio_spawn_nonpie(_args: &[String]) -> i32 {
        let nonpie = m_target_binary();
        let parent_pid = std::process::id();
        eprintln!("[M1] pid={parent_pid} spawning nonpie={nonpie}");

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("tokio runtime");
        let result: Result<(), String> = rt.block_on(async {
            let out = tokio::process::Command::new(&nonpie)
                .arg("echo-test")
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .output()
                .await
                .map_err(|e| format!("spawn: {e}"))?;
            if !out.status.success() {
                return Err(format!("child exit: {:?}", out.status));
            }
            let stdout = String::from_utf8_lossy(&out.stdout);
            if !stdout.contains("ECHO_TEST_OK") {
                return Err(format!("child stdout missing ECHO_TEST_OK: {stdout:?}"));
            }
            Ok(())
        });
        match result {
            Ok(()) => {
                eprintln!("[M1] pid={parent_pid} child OK, parent surviving");
                println!("M1_OK pid={parent_pid}");
            }
            Err(e) => {
                eprintln!("[M1] pid={parent_pid} FAIL: {e}");
                println!("M1_FAIL:{e}");
                std::process::exit(1);
            }
        }
        0
    }

    pub(super) fn subcmd_m2_libc_spawn_nonpie(_args: &[String]) -> i32 {
        let nonpie = m_target_binary();
        let parent_pid = std::process::id();
        eprintln!("[M2] pid={parent_pid} libc fork+execve nonpie={nonpie}");

        let mut pipefd = [-1i32; 2];
        if unsafe { libc::pipe(pipefd.as_mut_ptr()) } != 0 {
            println!("M2_FAIL:pipe");
            std::process::exit(1);
        }
        let pipe_r = pipefd[0];
        let pipe_w = pipefd[1];

        let pid = unsafe { libc::fork() };
        if pid < 0 {
            println!("M2_FAIL:fork");
            std::process::exit(1);
        }
        if pid == 0 {
            unsafe {
                libc::dup2(pipe_w, 1);
                libc::close(pipe_r);
                libc::close(pipe_w);
            }
            use std::ffi::CString;
            let bin = CString::new(nonpie.as_str()).unwrap();
            let arg_sub = CString::new("echo-test").unwrap();
            let argv = [bin.as_ptr(), arg_sub.as_ptr(), core::ptr::null()];
            unsafe { libc::execv(bin.as_ptr(), argv.as_ptr()) };
            std::process::exit(127);
        }
        unsafe { libc::close(pipe_w) };
        let mut buf = [0u8; 4096];
        let n = unsafe { libc::read(pipe_r, buf.as_mut_ptr() as *mut _, buf.len()) };
        unsafe { libc::close(pipe_r) };
        let mut status = 0i32;
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
        loop {
            let ret = unsafe { libc::waitpid(pid, &raw mut status, libc::WNOHANG) };
            if ret > 0 {
                break;
            }
            if std::time::Instant::now() >= deadline {
                unsafe { libc::kill(pid, libc::SIGKILL) };
                unsafe { libc::waitpid(pid, std::ptr::null_mut(), 0) };
                println!("M2_FAIL:wait_timeout");
                std::process::exit(1);
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        if !libc::WIFEXITED(status) || libc::WEXITSTATUS(status) != 0 {
            println!("M2_FAIL:child_status={status}");
            std::process::exit(1);
        }
        if n <= 0 {
            println!("M2_FAIL:no_child_stdout");
            std::process::exit(1);
        }
        let out = String::from_utf8_lossy(&buf[..n as usize]).into_owned();
        if !out.contains("ECHO_TEST_OK") {
            println!("M2_FAIL:bad_stdout:{out:?}");
            std::process::exit(1);
        }
        eprintln!("[M2] pid={parent_pid} child OK, parent surviving");
        println!("M2_OK pid={parent_pid}");
        0
    }

    pub(super) fn subcmd_m3_tokio_spawn_nonpie_then_work(_args: &[String]) -> i32 {
        let nonpie = m_target_binary();
        let parent_pid = std::process::id();
        eprintln!("[M3] pid={parent_pid} step 1: spawn nonpie");

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("tokio runtime");
        let m1_result: Result<(), String> = rt.block_on(async {
            let out = tokio::process::Command::new(&nonpie)
                .arg("echo-test")
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .output()
                .await
                .map_err(|e| format!("spawn: {e}"))?;
            if !out.status.success() {
                return Err(format!("child exit: {:?}", out.status));
            }
            Ok(())
        });
        if let Err(e) = m1_result {
            println!("M3_FAIL:step1:{e}");
            std::process::exit(1);
        }
        eprintln!("[M3] pid={parent_pid} step 2: post-spawn work");
        drop(rt);
        let stat = std::fs::read_to_string("/proc/self/stat")
            .map_err(|e| format!("read /proc/self/stat: {e}"));
        let scratch = format!("/tmp/m3-{parent_pid}.txt");
        let write_res = std::fs::write(&scratch, b"M3_PARENT_ALIVE\n")
            .map_err(|e| format!("write {scratch}: {e}"));
        let read_back =
            std::fs::read_to_string(&scratch).map_err(|e| format!("read {scratch}: {e}"));
        let _ = std::fs::remove_file(&scratch);
        match (stat, write_res, read_back) {
            (Ok(_), Ok(()), Ok(s)) if s.contains("M3_PARENT_ALIVE") => {
                eprintln!("[M3] pid={parent_pid} step 2 OK");
                println!("M3_OK pid={parent_pid}");
            }
            (s, w, r) => {
                println!("M3_FAIL:step2:stat={s:?},write={w:?},read={r:?}");
                std::process::exit(1);
            }
        }
        0
    }

    pub(super) fn subcmd_m4_tokio_spawn_nonpie_repeated(args: &[String]) -> i32 {
        let n: usize = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(5);
        let nonpie = m_target_binary();
        let parent_pid = std::process::id();
        eprintln!("[M4] pid={parent_pid} N={n} spawning nonpie={nonpie}");

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("tokio runtime");
        let result: Result<usize, String> = rt.block_on(async {
            for i in 0..n {
                let out = tokio::process::Command::new(&nonpie)
                    .arg("echo-test")
                    .stdin(std::process::Stdio::null())
                    .stdout(std::process::Stdio::piped())
                    .stderr(std::process::Stdio::piped())
                    .output()
                    .await
                    .map_err(|e| format!("spawn iter={i}: {e}"))?;
                if !out.status.success() {
                    return Err(format!("iter={i} child exit: {:?}", out.status));
                }
                let stdout = String::from_utf8_lossy(&out.stdout);
                if !stdout.contains("ECHO_TEST_OK") {
                    return Err(format!("iter={i} bad stdout: {stdout:?}"));
                }
                eprintln!("[M4] pid={parent_pid} iter={i} OK");
            }
            Ok(n)
        });
        match result {
            Ok(k) => {
                eprintln!("[M4] pid={parent_pid} all {k} iterations OK");
                println!("M4_OK pid={parent_pid} iterations={k}");
            }
            Err(e) => {
                println!("M4_FAIL:{e}");
                std::process::exit(1);
            }
        }
        0
    }

    pub(super) fn subcmd_bs1_tokio_spawn_nonpie_stderr(_args: &[String]) -> i32 {
        let nonpie = m_target_binary();
        let parent_pid = std::process::id();
        eprintln!("[BS1] pid={parent_pid} spawning nonpie={nonpie} stderr-only-test");
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("tokio runtime");
        let result: Result<(), String> = rt.block_on(async {
            let out = tokio::process::Command::new(&nonpie)
                .arg("stderr-only-test")
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .output()
                .await
                .map_err(|e| format!("spawn: {e}"))?;
            if !out.status.success() {
                return Err(format!("child exit: {:?}", out.status));
            }
            let stderr = String::from_utf8_lossy(&out.stderr);
            if !stderr.contains("STDERR_ONLY_OK") {
                return Err(format!("child stderr missing STDERR_ONLY_OK: {stderr:?}"));
            }
            Ok(())
        });
        match result {
            Ok(()) => {
                eprintln!("[BS1] pid={parent_pid} OK");
                println!("BS1_OK pid={parent_pid}");
            }
            Err(e) => {
                println!("BS1_FAIL:{e}");
                std::process::exit(1);
            }
        }
        0
    }

    pub(super) fn subcmd_bs2_tokio_spawn_nonpie_stdin_echo(_args: &[String]) -> i32 {
        let nonpie = m_target_binary();
        let parent_pid = std::process::id();
        eprintln!("[BS2] pid={parent_pid} spawning nonpie={nonpie} stdin-echo-test");
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("tokio runtime");
        let result: Result<(), String> = rt.block_on(async {
            use tokio::io::AsyncWriteExt;
            let mut child = tokio::process::Command::new(&nonpie)
                .arg("stdin-echo-test")
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .spawn()
                .map_err(|e| format!("spawn: {e}"))?;
            if let Some(mut stdin) = child.stdin.take() {
                stdin
                    .write_all(b"BS2_PING\n")
                    .await
                    .map_err(|e| format!("write stdin: {e}"))?;
                drop(stdin);
            }
            let out = child
                .wait_with_output()
                .await
                .map_err(|e| format!("wait: {e}"))?;
            if !out.status.success() {
                return Err(format!("child exit: {:?}", out.status));
            }
            let stdout = String::from_utf8_lossy(&out.stdout);
            if !stdout.contains("BS2_PING") {
                return Err(format!("child stdout missing BS2_PING: {stdout:?}"));
            }
            Ok(())
        });
        match result {
            Ok(()) => {
                eprintln!("[BS2] pid={parent_pid} OK");
                println!("BS2_OK pid={parent_pid}");
            }
            Err(e) => {
                println!("BS2_FAIL:{e}");
                std::process::exit(1);
            }
        }
        0
    }

    pub(super) fn subcmd_bs3_tokio_spawn_nonpie_large_stdout(_args: &[String]) -> i32 {
        let nonpie = m_target_binary();
        let parent_pid = std::process::id();
        eprintln!("[BS3] pid={parent_pid} spawning nonpie={nonpie} large-stdout-test");
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("tokio runtime");
        let result: Result<(), String> = rt.block_on(async {
            let out = tokio::process::Command::new(&nonpie)
                .arg("large-stdout-test")
                .arg("65536")
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .output()
                .await
                .map_err(|e| format!("spawn: {e}"))?;
            if !out.status.success() {
                return Err(format!("child exit: {:?}", out.status));
            }
            let stdout = String::from_utf8_lossy(&out.stdout);
            if !stdout.contains("LARGE_STDOUT_OK") {
                return Err(format!(
                    "child stdout missing LARGE_STDOUT_OK (got {} bytes)",
                    stdout.len()
                ));
            }
            Ok(())
        });
        match result {
            Ok(()) => {
                eprintln!("[BS3] pid={parent_pid} OK");
                println!("BS3_OK pid={parent_pid}");
            }
            Err(e) => {
                println!("BS3_FAIL:{e}");
                std::process::exit(1);
            }
        }
        0
    }
}

// ═══════════════════════════════════════════════════════════════════
// M1-M4: Minimal canary repros for SpawnRemote/non-PIE bug
// ═══════════════════════════════════════════════════════════════════
//
// These are the minimal repros for the wave-0 canary cascade. The
// canary itself runs `Exec [self_exe, "echo-test"]` on agent A. It
// times out under litebox not because echo-test is broken, but
// because spawn_tree's earlier SpawnRemote NP call killed agent A
// as a side effect.
//
// Each M test runs as `Exec [self_exe, "M{N}-..."]` from a launcher
// agent. The M subprocess then spawns a non-PIE child via the
// indicated mechanism and verifies the parent process is still
// alive after wait. If the parent dies before printing M{N}_OK,
// the launcher's Exec times out or returns a bad exit code, and
// the test FAILs.
//
// Matrix: 4 M variants × 5 launchers (A, AA, D3, D4, D5):
//   - A, AA, D3, D5 are PIE — they exec a PIE M-subprocess. The
//     canary mechanism (PIE process tokio runtime spawning non-PIE
//     child) is reproduced inside the M subprocess.
//   - D4 is non-PIE — it execs a non-PIE M-subprocess. This tests
//     the related non-PIE → non-PIE spawn path.
//
// Native must pass all 20 tests.

pub(crate) fn register_minimal_canary_tests(reg: &mut Registry<'_>) {
    register_pf_specific_handlers();
    // Register the M1-M4 + BS1-BS3 leaf subcommands. These stay as
    // argv subcommands (not handlers) because they test fresh-process
    // stdio inheritance across fork+exec; bodies live in `mod leaf_subcmd`
    // at the bottom of this file.
    crate::register_leaf_subcommand!(
        "M1-tokio-spawn-nonpie",
        leaf_subcmd::subcmd_m1_tokio_spawn_nonpie
    );
    crate::register_leaf_subcommand!(
        "M2-libc-spawn-nonpie",
        leaf_subcmd::subcmd_m2_libc_spawn_nonpie
    );
    crate::register_leaf_subcommand!(
        "M3-tokio-spawn-nonpie-then-work",
        leaf_subcmd::subcmd_m3_tokio_spawn_nonpie_then_work
    );
    crate::register_leaf_subcommand!(
        "M4-tokio-spawn-nonpie-repeated",
        leaf_subcmd::subcmd_m4_tokio_spawn_nonpie_repeated
    );
    crate::register_leaf_subcommand!(
        "BS1-tokio-spawn-nonpie-stderr",
        leaf_subcmd::subcmd_bs1_tokio_spawn_nonpie_stderr
    );
    crate::register_leaf_subcommand!(
        "BS2-tokio-spawn-nonpie-stdin-echo",
        leaf_subcmd::subcmd_bs2_tokio_spawn_nonpie_stdin_echo
    );
    crate::register_leaf_subcommand!(
        "BS3-tokio-spawn-nonpie-large-stdout",
        leaf_subcmd::subcmd_bs3_tokio_spawn_nonpie_large_stdout
    );

    const M_LAUNCHERS: &[AgentName] = &[
        AgentName::Dpg1,
        AgentName::Dpg1Dpg1,
        AgentName::Dpg1Dpg1Dpg1,
        AgentName::Dpg1Dng,
        AgentName::Dpg1DngDpg,
    ];
    const M_VARIANTS: &[(&str, &str, &str, u64)] = &[
        // (id_prefix, subcommand, expected_stdout_marker, exec_timeout_secs)
        ("M1", "M1-tokio-spawn-nonpie", "M1_OK", 30),
        ("M2", "M2-libc-spawn-nonpie", "M2_OK", 30),
        ("M3", "M3-tokio-spawn-nonpie-then-work", "M3_OK", 30),
        ("M4", "M4-tokio-spawn-nonpie-repeated", "M4_OK", 60),
        // BS-variants: minimal stdio-direction repros for Bug B.
        // Same matrix shape as M1-M4. See main.rs comments for what
        // each subcommand exercises.
        ("BS1", "BS1-tokio-spawn-nonpie-stderr", "BS1_OK", 30),
        ("BS2", "BS2-tokio-spawn-nonpie-stdin-echo", "BS2_OK", 30),
        ("BS3", "BS3-tokio-spawn-nonpie-large-stdout", "BS3_OK", 30),
    ];

    for &launcher in M_LAUNCHERS {
        for &(id_prefix, subcommand, marker, timeout_secs) in M_VARIANTS {
            for &target_bt in crate::BinaryType::ALL {
                let launcher_s = launcher.to_string();
                let subcommand_s: String = subcommand.into();
                let marker_s: String = marker.into();
                let target_label = target_bt.label();
                let test_id = format!("{id_prefix}.{launcher_s}.{target_label}");
                reg.test("fork", "minimal_canary", test_id)
                    .timeout(timeout_secs + 10)
                    .build(move |cx| {
                        let handle = cx.require(launcher);
                        Box::new(move |run| {
                            let l = launcher_s.clone();
                            let sc = subcommand_s.clone();
                            let m = marker_s.clone();
                            let self_exe = run.self_exe().to_string();
                            Box::pin(async move {
                                let target = crate::binary_path(target_bt, &self_exe);
                                // Inject the target binary path into
                                // the M/BS subcommand via the
                                // `LITEBOX_M_TARGET_BINARY` env var.
                                let resp = run
                                    .typed_or_error(
                                        &handle,
                                        &EXEC,
                                        ExecArgs {
                                            args: vec![self_exe, sc],
                                            timeout_secs: Some(timeout_secs),
                                            stdin: None,
                                            background: false,
                                            env: vec![("LITEBOX_M_TARGET_BINARY".into(), target)],
                                        },
                                    )
                                    .await;
                                let pass = matches!(
                                    &resp,
                                    Response::ExecResult { exit_code: 0, stdout, .. }
                                        if stdout.contains(m.as_str())
                                );
                                super::TestOutcome::new(&l, pass, format!("{resp:?}"))
                            })
                        })
                    });
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════════════
// SP: stdin-pipe command substitution
// ═══════════════════════════════════════════════════════════════════
