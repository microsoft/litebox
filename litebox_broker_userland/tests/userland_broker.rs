// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#[cfg(target_os = "linux")]
#[path = "linux/userland_broker.rs"]
mod linux;

fn main() {
    #[cfg(target_os = "linux")]
    linux::main();
}
