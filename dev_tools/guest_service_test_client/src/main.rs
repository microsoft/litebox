// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! `guest_service_test_client`, the stacked runners' host test client (see the library).

#[cfg(target_os = "linux")]
fn main() {
    guest_service_test_client::main();
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("guest_service_test_client runs on Linux only");
    std::process::exit(1);
}
