// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Hosted userland bindings for the portable broker local endpoint.

#![cfg(any(
    target_os = "linux",
    target_os = "macos",
    all(windows, target_arch = "x86_64")
))]

#[cfg(any(target_os = "linux", target_os = "macos"))]
mod unix;
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub use unix::{BrokerAssociationFailureCoordinator, start_notification_receiver};

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::{BrokerConnection, connect, connect_stream};

#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
pub use macos::{BrokerConnection, connect};

#[cfg(all(windows, target_arch = "x86_64"))]
mod windows;
#[cfg(all(windows, target_arch = "x86_64"))]
pub use windows::{BrokerConnection, connect, start_notification_receiver};
