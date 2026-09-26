// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// This broker speaks the Linux host transport (`memfd` shared memory and
// `SCM_RIGHTS` over Unix sockets), which `litebox_broker_transport_linux_userland`
// confines to Linux, so the whole crate follows it there.
#![cfg(target_os = "linux")]

//! Support for the Linux-userland broker process.
//!
//! The broker executable composes `litebox_broker_core` and
//! `litebox_broker_host` with the Linux host endpoints from
//! `litebox_broker_transport_linux_userland`. It owns runner process lifecycle,
//! socket setup, and worker threads. This library exposes components shared by
//! the executable and its integration tests, currently readiness publication.

pub mod readiness;
