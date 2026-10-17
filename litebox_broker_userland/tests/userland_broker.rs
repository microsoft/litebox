// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#[cfg(target_os = "linux")]
#[path = "linux/userland_broker.rs"]
mod linux;

fn main() {
    #[cfg(target_os = "linux")]
    linux::main();

    #[cfg(not(target_os = "linux"))]
    eprintln!("Skipping userland_broker: this test requires Linux.");
}
