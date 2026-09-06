// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Userland bindings for connecting the portable broker local endpoint to an
//! external or same-process broker host.

#![cfg(any(target_os = "linux", all(windows, target_arch = "x86_64")))]

mod in_process;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::{
    BrokerAssociationFailureCoordinator, BrokerConnection, connect, connect_in_process,
    start_notification_receiver,
};

#[cfg(all(windows, target_arch = "x86_64"))]
mod windows;
#[cfg(all(windows, target_arch = "x86_64"))]
pub use windows::{BrokerConnection, connect, connect_in_process, start_notification_receiver};
