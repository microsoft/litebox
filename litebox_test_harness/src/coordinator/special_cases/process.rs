// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Process special-case probes (FORK_SETSID.*, INV.*).

use super::*;

use crate::coordinator::TestOutcome;

#[derive(Clone, Copy)]
enum ProcessLeaf {
    ForkSetsidBasic,
    BrokerProcessRegisteredAfterFork,
}

impl ProcessLeaf {
    fn subcommand(self) -> &'static str {
        match self {
            Self::ForkSetsidBasic => "fork-setsid-basic",
            Self::BrokerProcessRegisteredAfterFork => "broker-process-registered-after-fork",
        }
    }

    fn ok_marker(self) -> &'static str {
        match self {
            Self::ForkSetsidBasic => "FORK_SETSID_OK",
            Self::BrokerProcessRegisteredAfterFork => "BROKER_PROCESS_REGISTERED_OK",
        }
    }
}

pub(crate) fn register_process_tests(reg: &mut Registry<'_>) {
    register();
    register_leaf(reg, "FORK_SETSID.basic", ProcessLeaf::ForkSetsidBasic);
    register_leaf(
        reg,
        "INV.broker_process_registered_for_forked_children",
        ProcessLeaf::BrokerProcessRegisteredAfterFork,
    );
}

fn register_leaf(reg: &mut Registry<'_>, id_prefix: &'static str, leaf: ProcessLeaf) {
    for &bt in crate::BinaryType::ALL {
        let id = format!("{id_prefix}.{}", bt.label());
        typed_test!(
            reg,
            "matrix",
            "process_special",
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
                            argv: vec![target, "process-test".into(), leaf.subcommand().into()],
                            timeout_ms: Some(10 * 1000),
                            stdin: None,
                            env: vec![],
                        },
                    )
                    .await;
                let pass = matches!(&resp, Ok(out) if out.stdout.contains(leaf.ok_marker()));
                TestOutcome::new("A", pass, format!("{resp:?}"))
            }
        );
    }
}

pub(super) fn register() {
    crate::register_leaf_subcommand!("process-test", subcmd_process_test);
}

fn subcmd_process_test(args: &[String]) -> i32 {
    match args.get(2).map(String::as_str) {
        Some("fork-setsid-basic") => run_fork_setsid_basic(),
        Some("broker-process-registered-after-fork") => run_broker_process_registered_after_fork(),
        Some(other) => {
            eprintln!("unknown process test: {other}");
            1
        }
        None => {
            eprintln!("missing process test name");
            1
        }
    }
}

fn run_fork_setsid_basic() -> i32 {
    run_child_probe(|| {
        let pid = unsafe { libc::getpid() };
        let sid = unsafe { libc::setsid() };
        if sid != pid {
            return Err(format!(
                "setsid returned {sid}, expected pid {pid}, errno={}",
                errno()
            ));
        }
        let getsid = unsafe { libc::getsid(0) };
        if getsid != pid {
            return Err(format!("getsid(0) returned {getsid}, expected {pid}"));
        }
        let pgid = unsafe { libc::getpgid(0) };
        if pgid != pid {
            return Err(format!("getpgid(0) returned {pgid}, expected {pid}"));
        }
        Ok("FORK_SETSID_OK")
    })
}

fn run_broker_process_registered_after_fork() -> i32 {
    run_child_probe(|| {
        let pid = unsafe { libc::getpid() };
        let pidfd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
        if pidfd < 0 {
            return Err(format!("pidfd_open({pid}) failed errno={}", errno()));
        }
        unsafe {
            libc::close(pidfd as libc::c_int);
        }
        Ok("BROKER_PROCESS_REGISTERED_OK")
    })
}

fn run_child_probe(probe: fn() -> Result<&'static str, String>) -> i32 {
    let mut pipe_fds = [0; 2];
    if unsafe { libc::pipe(pipe_fds.as_mut_ptr()) } != 0 {
        eprintln!("pipe failed errno={}", errno());
        return 1;
    }
    let child = unsafe { libc::fork() };
    if child < 0 {
        eprintln!("fork failed errno={}", errno());
        unsafe {
            libc::close(pipe_fds[0]);
            libc::close(pipe_fds[1]);
        }
        return 1;
    }
    if child == 0 {
        unsafe {
            libc::close(pipe_fds[0]);
        }
        let msg = match probe() {
            Ok(marker) => format!("{marker}\n"),
            Err(err) => format!("FAIL:{err}\n"),
        };
        unsafe {
            libc::write(pipe_fds[1], msg.as_ptr().cast::<libc::c_void>(), msg.len());
            libc::close(pipe_fds[1]);
            libc::_exit(if msg.starts_with("FAIL:") { 1 } else { 0 });
        }
    }

    unsafe {
        libc::close(pipe_fds[1]);
    }
    let mut buf = [0_u8; 256];
    let n = unsafe {
        libc::read(
            pipe_fds[0],
            buf.as_mut_ptr().cast::<libc::c_void>(),
            buf.len(),
        )
    };
    unsafe {
        libc::close(pipe_fds[0]);
    }
    let mut status = 0;
    let waited = unsafe { libc::waitpid(child, &raw mut status, 0) };
    if waited != child {
        eprintln!("waitpid({child}) returned {waited}, errno={}", errno());
        return 1;
    }
    let output = if n > 0 {
        String::from_utf8_lossy(&buf[..n as usize]).to_string()
    } else {
        String::new()
    };
    print!("{output}");
    if libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0 {
        0
    } else {
        eprintln!("child failed status={status} output={output:?}");
        1
    }
}

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(-1)
}
