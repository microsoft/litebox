// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

fn main() {
    // Forked children continue at their parent's syscall entry point, which is
    // inside the runner, so the runner must load at the same address in every
    // process.
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        println!("cargo:rustc-link-arg-bins=/DYNAMICBASE:NO");
    }
}
