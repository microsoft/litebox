// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! `litebox-guest-service`, the LiteBox guest service (see the library).

#[cfg(target_os = "linux")]
fn main() {
    litebox_guest_service::run();
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("litebox-guest-service runs on Linux only");
    std::process::exit(1);
}
