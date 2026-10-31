// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use std::{
    ffi::OsString,
    path::{Path, PathBuf},
};

pub(crate) fn runner_binary() -> OsString {
    std::env::var_os("NEXTEST_BIN_EXE_litebox_runner_linux_on_macos_userland")
        .unwrap_or_else(|| env!("CARGO_BIN_EXE_litebox_runner_linux_on_macos_userland").into())
}

/// Returns the userland broker built next to `runner`, which a workspace build or a test run
/// that also selects `litebox_broker_userland` produces.
pub(crate) fn broker_binary(runner: &OsString) -> PathBuf {
    let broker = Path::new(runner).with_file_name("litebox-broker-userland");
    assert!(
        broker.is_file(),
        "broker tests require a build of litebox_broker_userland producing {}",
        broker.display()
    );
    broker
}
