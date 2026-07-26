// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Linux-userland broker host deployment support.
//!
//! The broker host binary in this crate owns process, socket, and thread
//! policy, binding `litebox_broker_core` and `litebox_broker_host` to the
//! concrete host endpoints in `litebox_broker_transport_linux_userland`. This
//! library holds the deployment pieces that are useful outside `main`, so
//! integration tests can drive the same code the binary runs.

pub mod readiness;
