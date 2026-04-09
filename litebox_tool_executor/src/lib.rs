// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! A sandboxed tool executor built on LiteBox.
//!
//! Spawns `litebox_runner_linux_userland` as a subprocess to execute
//! Linux commands in a LiteBox sandbox. Provides direct and interactive
//! REPL modes.

pub mod ssh_server;
