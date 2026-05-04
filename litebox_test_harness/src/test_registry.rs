// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Test group registry — single source of truth for all coordinator
//! test groups.
//!
//! This module is shared between:
//! - `coordinator/mod.rs` (dispatch loop)
//! - `tests/integration.rs` (Trial registration)
//!
//! To add a new test group:
//! 1. Add an entry to `TEST_GROUPS` here
//! 2. Add a match arm in `coordinator::run_group()`

/// Registry of all test groups. Each entry is `(suite, group_name)`.
pub const TEST_GROUPS: &[(&str, &str)] = &[
    // matrix — capability × topology cross-product
    // ("matrix", "run_matrix"), // converted
    // ("matrix", "netlink"), // converted to register_netlink
    // ("matrix", "net_ipv6"), // converted
    // ("matrix", "terminal_ioctl"), // converted
    // ("matrix", "fs_io"), // converted
    // ("matrix", "poll_ready"), // converted
    // ("matrix", "bind_getsockname"), // converted
    // ("matrix", "pipe_pair_id"), // converted
    // ("matrix", "pipe_nonblock"), // converted
    // ("matrix", "epoll_socket"), // converted
    // ("matrix", "loopback_tcp"), // converted
    // ("matrix", "proc_filesystem"), // converted
    // fork — fork/exec patterns, delayed fork, PIE/non-PIE
    // ("fork", "fork_matrix"), // converted
    // ("fork", "exit_data_integrity"), // converted
    // ("fork", "nonpie_pipe_chain"), // converted
    // ("fork", "bash_fork_exec"), // converted
    // ("fork", "fork_from_worker_exec"), // converted
    // ("fork", "concurrent_fork"), // converted
    // ("fork", "pid_visibility"), // converted
    // ("fork", "capture_pipe"), // converted
    // ("fork", "node_exit"), // converted
    // shell — bash-specific redirect, touch, stdin-pipe
    // ("shell", "stdin_pipe_subst"), // converted
    // ("shell", "subst_capture"), // converted
    // ("shell", "touch_redirect"), // converted
    // ("shell", "file_redirect"), // converted
    // ("shell", "stdin_script"), // converted
    // xworker — cross-worker FS, TCP, unix sockets, port routing
    // ("xworker", "cross_worker_first_connect"), // converted
    // ("xworker", "cross_worker_self_connect"), // converted
    // ("xworker", "cross_worker_file"), // converted
    // ("xworker", "fork_listen_close"), // converted
    // ("xworker", "unix_socket"), // converted
    // ("xworker", "cross_worker"), // converted
    // ("xworker", "pipe_eof"), // converted
    // ("xworker", "pipe_bridge"), // converted
    // ("xworker", "concurrent_fork_pipeline"), // converted
    // ("xworker", "concurrent_exec"), // converted
    // ("xworker", "vscode_install_pipeline"), // converted
    // ("xworker", "concurrent_fs_rwlock"), // converted
    // stress — TCP stress, port router, file+TCP combined
    // ("stress", "tcp_stress"), // converted
    // ("stress", "file_tcp"), // converted
    // ("stress", "port_router"), // converted
    // contamination — state accumulation (MUST run last)
    // ("contamination", "canary"), // converted
    // ("contamination", "contamination_sequence"), // converted
];

/// Default per-group timeout in seconds.
const DEFAULT_GROUP_TIMEOUT: u64 = 60;

/// Get the timeout for a specific test group.
/// Each group now spawns a fresh agent tree (~10s overhead), so
/// timeouts must account for that on top of the test itself.
pub fn group_timeout(suite: &str, group: &str) -> u64 {
    match (suite, group) {
        ("stress", _) => 180,
        ("matrix", "run_matrix") => 120,
        ("matrix", "loopback_tcp") => 90,
        ("matrix", "epoll_socket") => 90,
        ("xworker", _) => 90,
        ("fork", "fork_matrix") => 90,
        ("fork", "nonpie_pipe_chain") => 90,
        ("fork", "fork_from_worker_exec") => 90,
        _ => DEFAULT_GROUP_TIMEOUT,
    }
}

/// Check whether a `(suite, group)` pair matches a `--filter=` argument.
///
/// - `None` → run everything
/// - `Some("fork")` → run all groups in fork suite
/// - `Some("fork,shell")` → run all groups in fork and shell suites
/// - `Some("fork.exit_data_integrity")` → run only that group
pub fn matches_filter(filter: Option<&str>, suite: &str, group: &str) -> bool {
    match filter {
        None => true,
        Some(f) => f.split(',').any(|part| {
            if let Some((fs, fg)) = part.split_once('.') {
                suite == fs && group == fg
            } else {
                suite == part
            }
        }),
    }
}
