// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Cross-worker FD transport (broker side).
//!
//! Modules implementing the Phase 2 / Phase 3 / Phase B broker
//! services that let guest workers share kernel objects across
//! host-process boundaries:
//!
//! * [`fd_tokens`] — broker-global token registry (Phase 2).
//! * [`fd_token_service`] — request handler for token RPCs.
//! * [`fd_token_socket`] — control-socket dispatch (token + state).
//! * [`state_registry`] — broker state-object registry (Phase B).
//! * [`state_service`] — request handler for state-object RPCs.
//! * [`eventfd_state`] — concrete `StateObject` for eventfd state.
//! * [`subscription_list`] — broker → worker notification fan-out.
//!
//! See `docs/design/cross-worker-fd-transport.md` for the full plan.

pub mod eventfd_state;
pub mod fd_token_service;
pub mod fd_token_socket;
pub mod fd_tokens;
pub mod host_fd_state;
pub mod inet_dgram_state;
pub mod inet_listener_state;
pub mod inet_raw_state;
pub mod inotify_dispatcher;
pub mod inotify_state;
pub mod pgrp_signal_inbox;
pub mod pidfd_state;
pub mod pipe_state;
pub mod process_state;
pub mod pty_state;
pub mod signalfd_state;
pub mod socket_dgram_state;
pub mod socket_seqpacket_state;
pub mod socketpair_state;
pub mod state_registry;
pub mod state_service;
pub mod subscription_list;

#[cfg(loom)]
mod subscription_list_loom;

#[cfg(test)]
mod subscription_list_proptest;
pub mod tcp_conn_state;
pub mod timerfd_state;
