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
    ("matrix", "run_matrix"),
    ("matrix", "netlink"),
    ("matrix", "net_ipv6"),
    ("matrix", "terminal_ioctl"),
    ("matrix", "fs_io"),
    ("matrix", "poll_ready"),
    ("matrix", "bind_getsockname"),
    ("matrix", "pipe_pair_id"),
    ("matrix", "pipe_nonblock"),
    ("matrix", "epoll_socket"),
    ("matrix", "loopback_tcp"),
    ("matrix", "proc_filesystem"),
    // fork — fork/exec patterns, delayed fork, PIE/non-PIE
    ("fork", "fork_matrix"),
    ("fork", "exit_data_integrity"),
    ("fork", "nonpie_pipe_chain"),
    ("fork", "bash_fork_exec"),
    ("fork", "fork_from_worker_exec"),
    ("fork", "concurrent_fork"),
    ("fork", "pid_visibility"),
    ("fork", "capture_pipe"),
    ("fork", "node_exit"),
    // shell — bash-specific redirect, touch, stdin-pipe
    ("shell", "stdin_pipe_subst"),
    ("shell", "subst_capture"),
    ("shell", "touch_redirect"),
    ("shell", "file_redirect"),
    ("shell", "stdin_script"),
    // xworker — cross-worker FS, TCP, unix sockets, port routing
    ("xworker", "cross_worker_first_connect"),
    ("xworker", "cross_worker_self_connect"),
    ("xworker", "cross_worker_file"),
    ("xworker", "fork_listen_close"),
    ("xworker", "unix_socket"),
    ("xworker", "cross_worker"),
    ("xworker", "pipe_eof"),
    ("xworker", "pipe_bridge"),
    ("xworker", "concurrent_fork_pipeline"),
    ("xworker", "concurrent_exec"),
    ("xworker", "vscode_install_pipeline"),
    ("xworker", "concurrent_fs_rwlock"),
    // stress — TCP stress, port router, file+TCP combined
    ("stress", "tcp_stress"),
    ("stress", "file_tcp"),
    ("stress", "port_router"),
    // contamination — state accumulation (MUST run last)
    ("contamination", "canary"),
    ("contamination", "contamination_sequence"),
];

/// Default per-group timeout in seconds.
const DEFAULT_GROUP_TIMEOUT: u64 = 60;

/// Get the timeout for a specific test group.
pub fn group_timeout(suite: &str, group: &str) -> u64 {
    match (suite, group) {
        ("stress", _) => 120,
        ("matrix", "run_matrix") => 90,
        _ => DEFAULT_GROUP_TIMEOUT,
    }
}

/// Check whether a `(suite, group)` pair matches a `--filter=` argument.
///
/// - `None` → run everything
/// - `Some("fork")` → run all groups in fork suite
/// - `Some("fork.exit_data_integrity")` → run only that group
pub fn matches_filter(filter: Option<&str>, suite: &str, group: &str) -> bool {
    match filter {
        None => true,
        Some(f) => {
            if let Some((fs, fg)) = f.split_once('.') {
                suite == fs && group == fg
            } else {
                suite == f
            }
        }
    }
}
