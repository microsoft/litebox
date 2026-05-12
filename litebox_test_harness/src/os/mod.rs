// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Scenario-friendly wrappers over Linux OS primitives.

pub mod epoll;
pub mod eventfd;
pub mod inotify;
pub mod pidfd;
pub mod pty;
pub mod socket;
pub mod unix_socket;
