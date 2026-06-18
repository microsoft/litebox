// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Cross-worker FD transport (worker side).
//!
//! Worker-process facing pieces of the cross-worker fd-transport
//! plan (see `docs/design/cross-worker-fd-transport.md`):
//!
//! * [`fd_token_protocol`] — wire-level RPC frames (`no_std`).
//! * [`notification_frame`] — broker → worker event-frame codec
//!   (`no_std`).
//! * [`broker_eventfd_provider`] — trait the shim uses to talk to
//!   the broker for eventfd state.
//! * [`fd_token_client`] — std/unix TCP client for the broker
//!   token + state services.
//! * [`notification_ring`] — std/unix sender/receiver pair for
//!   broker → worker notification frames.
//! * [`broker_eventfd`] — worker-side facade combining the
//!   token client with the notification dispatcher.

pub mod broker_eventfd_provider;
pub mod broker_fs_provider;
pub mod broker_inet_dgram_provider;
pub mod broker_inet_listener_provider;
pub mod broker_inet_raw_provider;
pub mod broker_inotify_provider;
pub mod broker_pgrp_signal_provider;
pub mod broker_pidfd_provider;
pub mod broker_pipe_provider;
pub mod broker_pty_provider;
pub mod broker_signalfd_provider;
pub mod broker_socket_dgram_provider;
pub mod broker_socket_seqpacket_provider;
pub mod broker_socketpair_provider;
pub mod broker_subscribable;
pub mod broker_tcp_conn_provider;
pub mod broker_timerfd_provider;
pub mod broker_unix_stream_provider;
pub mod fd_token_protocol;
pub mod fd_transfer_frame;
pub mod guest_pid_provider;
pub mod notification_frame;

#[cfg(all(feature = "std", unix))]
pub mod broker_eventfd;
#[cfg(all(feature = "std", unix))]
pub mod fd_token_client;
#[cfg(all(feature = "std", unix))]
pub mod notification_ring;
