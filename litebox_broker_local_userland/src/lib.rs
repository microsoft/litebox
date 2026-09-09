// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Hosted userland bindings for the portable broker local endpoint.

#![cfg(any(
    target_os = "linux",
    all(target_os = "windows", target_arch = "x86_64")
))]

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::{
    BrokerAssociationFailureCoordinator, BrokerConnection, connect, start_notification_receiver,
};

#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
mod windows;
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
pub use windows::{BrokerConnection, connect, start_notification_receiver};
