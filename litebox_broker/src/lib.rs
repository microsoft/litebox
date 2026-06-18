// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Litebox File Broker — policy-enforced external file access for sandboxed
//! processes.
//!
//! Provides a 9P2000.L server that serves files from the host filesystem
//! with policy enforcement and optional ELF syscall rewriting.
//! Also provides a network proxy that bridges guest networking over IPC.

pub mod audit;
pub mod cwfd;
pub mod net_proxy;
pub mod nine_p;
pub mod nine_p_session_registry;
pub mod ofd_registry;
pub mod policy;
pub mod sandbox_policy;
pub mod sock_compat;

// Backwards-compatible re-exports of the cross-worker fd-transport
// modules now living under [`cwfd`]. Keeps existing
// `litebox_broker::eventfd_state::*` etc. import paths working.
pub use cwfd::{
    eventfd_state, fd_token_service, fd_token_socket, fd_tokens, inet_raw_state,
    inotify_dispatcher, inotify_state, pgrp_signal_inbox, pidfd_state, pipe_state, process_state,
    pty_state, signalfd_state, socket_dgram_state, socket_seqpacket_state, socketpair_state,
    state_registry, state_service, subscription_list, tcp_conn_state, timerfd_state,
};
