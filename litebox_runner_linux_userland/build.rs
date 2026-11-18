// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use std::fmt::Write as _;
use std::path::PathBuf;
use std::{env, fs};

// Programs with a dedicated test, which the sweeps skip: dedicated fixtures build static binaries
// concurrently, which would collide with the sweeps' outputs.
const DEDICATED_C_TESTS: &[&str] = &[
    "aarch64_hwcaps.c",
    "async_x16.c",
    "fork_chain_parent.c",
    "fork_aarch64_state.c",
    "fork_shared_futex_parent.c",
    "gate_signals.c",
    "native_tp.c",
    "inherited_ignored_signals.c",
    "mount.c",
    "pid_namespace.c",
    "root_init.c",
    "sigreturn.c",
    "sigreturn_simd.c",
    "svc_scratch_regs.c",
    "sve_async.c",
    "sve_signal.c",
    "sve_syscall_abi.c",
    "sve_x18.c",
    "tty.c",
    "uts_ipc_namespace.c",
    "vfork_job_control_parent.c",
    "vfork_shell_parent.c",
];

// Programs that other tests run, which are no tests themselves.
const HELPER_C_PROGRAMS: &[&str] = &["vfork_exec_child.c"];

// Programs that create processes, which LiteBox allows only with `--allow-process-duplication`,
// other than those in `WITH_EXEC_CHILD_C_TESTS`, which do too.
const DUPLICATING_C_TESTS: &[&str] = &[
    "auxv_execfn.c",
    "cpu_time_parent.c",
    "ctty_parent.c",
    "fork_epoll_parent.c",
    "fork_event_parent.c",
    "fork_flock_parent.c",
    "fork_interrupt_parent.c",
    "fork_parent.c",
    "fork_threads_parent.c",
    "parent_death_signal.c",
    "pidfd_parent.c",
    "prctl_flags.c",
    "process_group_parent.c",
    "process_tree_parent.c",
    "rlimit_parent.c",
    "shared_file_mapping.c",
    "shared_memory_segment.c",
    "sigtimedwait_fork_parent.c",
    "thread_kill_process_parent.c",
    "vfork_exit_parent.c",
    "vfork_fault_parent.c",
    "waitid_parent.c",
];

// Programs that create processes and take, as their only argument, the path of
// `vfork_exec_child.c` built like them, which they execute.
const WITH_EXEC_CHILD_C_TESTS: &[&str] = &[
    "fork_inet_parent.c",
    "fork_unix_parent.c",
    "vfork_exec_parent.c",
    "vfork_fd_ops_parent.c",
    "vfork_fd_parent.c",
    "vfork_kill_parent.c",
    "vfork_pipe_parent.c",
    "vfork_reap_parent.c",
    "vfork_sigchld_parent.c",
    "vfork_signal_parent.c",
    "vfork_spawn_parent.c",
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

// Programs the native sweep skips, beyond those with a dedicated test, and why.
const NATIVE_SKIPPED_C_TESTS: &[(&str, &str)] = &[
    (
        "fork_inet_parent.c",
        "expects LiteBox's initial process to adopt an orphan, which natively the first process \
         of the PID namespace does",
    ),
    (
        "pipe_broker.c",
        "Linux keeps a writer to a full pipe blocked until a reader frees a whole page; LiteBox \
         wakes it after a 1-byte read",
    ),
    (
        "process_tree_parent.c",
        "expects LiteBox's initial process to have no parent and adopt orphans, which natively \
         only the first process of a PID namespace does, but that one also ignores signals it has \
         no handler for",
    ),
    (
        "shared_memory_segment.c",
        "gives a segment to a user the native user namespace doesn't map, and keys segments by \
         PID in the host's IPC namespace, where every native run has the same PID",
    ),
    ("tcp_broker.c", "needs arguments from its broker test"),
    (
        "tcp_broker_states.c",
        "needs arguments from its broker test",
    ),
    ("udp_broker.c", "needs arguments from its broker test"),
    (
        "udp_broker_namespace.c",
        "needs arguments from its broker test",
    ),
    (
        "vsock_unsupported.c",
        "checks LiteBox's policy; Linux supports AF_VSOCK",
    ),
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
    check_lists(&files);

    let mut generated =
        String::from("macro_rules! for_each_c_test {\n    ($callback:ident) => {\n");
    for path in files {
        let name = path.file_name().unwrap().to_str().unwrap();
        if HELPER_C_PROGRAMS.contains(&name) {
            continue;
        }
        let stem = path.file_stem().unwrap().to_str().unwrap();
        assert!(
            !matches!(stem, "_" | "self" | "Self" | "super" | "crate")
                && stem.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_')
                && stem.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'),
            "cannot use C test file {name:?} as a Rust test identifier"
        );
        // Each sweep maps the kind to its own ignore policy.
        let kind = if DEDICATED_C_TESTS.contains(&name) {
            "dedicated"
        } else if BROKER_ONLY_C_TESTS.contains(&name) {
            "broker"
        } else if DUPLICATING_C_TESTS.contains(&name) {
            "duplicating"
        } else if WITH_EXEC_CHILD_C_TESTS.contains(&name) {
            "with_exec_child"
        } else {
            "plain"
        };
        let source = format!("./tests/{name}");
        let native_skip = NATIVE_SKIPPED_C_TESTS
            .iter()
            .find(|(skipped, _)| *skipped == name)
            .map_or_else(String::new, |(_, reason)| {
                format!(", ignore_natively = {reason:?}")
            });
        writeln!(
            generated,
            "        $callback!({kind} r#{stem}, {source:?}{native_skip});"
        )
        .unwrap();
    }
    generated.push_str("    };\n}\n");
    let out_dir = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    fs::write(out_dir.join("c_tests.rs"), generated)
}

/// Checks that each listed program is one of `files`, in at most one list of kinds, and not both
/// dedicated and skipped natively, which would give it two native ignore reasons.
fn check_lists(files: &[PathBuf]) {
    let kinds = [
        DEDICATED_C_TESTS,
        HELPER_C_PROGRAMS,
        DUPLICATING_C_TESTS,
        WITH_EXEC_CHILD_C_TESTS,
        BROKER_ONLY_C_TESTS,
    ];
    let skipped = NATIVE_SKIPPED_C_TESTS.iter().map(|(name, _)| name);
    for name in kinds.iter().flat_map(|list| list.iter()).chain(skipped) {
        assert!(
            files.iter().any(|path| path.file_name().unwrap() == *name),
            "listed C program {name:?} doesn't exist"
        );
    }
    for name in kinds.iter().flat_map(|list| list.iter()) {
        let lists = kinds.iter().filter(|list| list.contains(name)).count();
        assert_eq!(lists, 1, "C program {name:?} is in {lists} lists of kinds");
    }
    for (name, _) in NATIVE_SKIPPED_C_TESTS {
        assert!(
            !DEDICATED_C_TESTS.contains(name) && !HELPER_C_PROGRAMS.contains(name),
            "C program {name:?} is skipped natively but has no sweep test"
        );
    }
}
