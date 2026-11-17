// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use std::fmt::Write as _;
use std::path::PathBuf;
use std::{env, fs};

// Dedicated fixtures build static binaries concurrently; exclude them to avoid
// colliding with this sweep's dynamic `<stem>_rewriter` outputs.
const DEDICATED_C_TESTS: &[&str] = &[
    "aarch64_hwcaps.c",
    "async_x16.c",
    "auxv_execfn.c",
    "cpu_time_parent.c",
    "ctty_parent.c",
    "fork_chain_parent.c",
    "fork_parent.c",
    "fork_interrupt_parent.c",
    "fork_threads_parent.c",
    "fork_aarch64_state.c",
    "fork_epoll_parent.c",
    "fork_event_parent.c",
    "fork_flock_parent.c",
    "fork_inet_parent.c",
    "fork_shared_futex_parent.c",
    "fork_unix_parent.c",
    "gate_signals.c",
    "native_tp.c",
    "inherited_ignored_signals.c",
    "pid_namespace.c",
    "prctl_flags.c",
    "process_group_parent.c",
    "process_tree_parent.c",
    "regular_file_readiness.c",
    "rlimit_parent.c",
    "shared_file_mapping.c",
    "sigreturn.c",
    "sigreturn_simd.c",
    "sigtimedwait_fork_parent.c",
    "thread_kill_process_parent.c",
    "svc_scratch_regs.c",
    "sve_async.c",
    "sve_signal.c",
    "sve_syscall_abi.c",
    "sve_x18.c",
    "tty.c",
    "utimensat.c",
    "uts_ipc_namespace.c",
    "vfork_fault_parent.c",
    "vfork_exec_child.c",
    "vfork_fd_parent.c",
    "vfork_fd_ops_parent.c",
    "vfork_exec_parent.c",
    "vfork_job_control_parent.c",
    "vfork_kill_parent.c",
    "vfork_pipe_parent.c",
    "vfork_exit_parent.c",
    "vfork_reap_parent.c",
    "vfork_sigchld_parent.c",
    "vfork_shell_parent.c",
    "vfork_signal_parent.c",
    "vfork_spawn_parent.c",
    "waitid_parent.c",
];

const BROKER_ONLY_C_TESTS: &[&str] = &[
    "eventfd.c",
    "getrandom_broker.c",
    "pipe_broker.c",
    "tcp_broker.c",
    "tcp_broker_server.c",
    "tcp_broker_states.c",
    "udp_broker.c",
    "udp_broker_namespace.c",
    "urandom_broker.c",
];

fn main() -> std::io::Result<()> {
    println!("cargo:rerun-if-changed=tests");
    let manifest_dir = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let mut files = Vec::new();
    for entry in fs::read_dir(manifest_dir.join("tests"))? {
        let path = entry?.path();
        if path.is_file() && path.extension().and_then(|ext| ext.to_str()) == Some("c") {
            files.push(path);
        }
    }
    files.sort();

    let mut generated =
        String::from("macro_rules! for_each_c_test {\n    ($callback:ident) => {\n");
    for path in files {
        let name = path.file_name().unwrap().to_str().unwrap();
        let stem = path.file_stem().unwrap().to_str().unwrap();
        assert!(
            !matches!(stem, "_" | "self" | "Self" | "super" | "crate")
                && stem.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_')
                && stem.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'),
            "cannot use C test file {name:?} as a Rust test identifier"
        );
        // Running with --run-ignored would collide with dedicated tests' outputs
        // and fail without a broker.
        let attributes = if DEDICATED_C_TESTS.contains(&name) {
            "#[ignore = \"has a dedicated test\"] "
        } else if BROKER_ONLY_C_TESTS.contains(&name) {
            "#[ignore = \"needs the broker\"] "
        } else {
            ""
        };
        let source = format!("./tests/{name}");
        writeln!(
            generated,
            "        $callback!({attributes}r#{stem}, {source:?});"
        )
        .unwrap();
    }
    generated.push_str("    };\n}\n");
    let out_dir = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    fs::write(out_dir.join("c_tests.rs"), generated)
}
