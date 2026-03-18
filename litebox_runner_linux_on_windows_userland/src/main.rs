// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Restrict this crate to only work on Windows. For now, we are restricting this to only x86-64
// Windows, but we _may_ allow for more in the future, if we find it useful to do so.

#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
fn main() -> anyhow::Result<()> {
    use clap::Parser as _;
    use litebox_runner_linux_on_windows_userland::CliArgs;

    let args = CliArgs::parse();

    // Run on a thread with 8 MiB stack (matching Linux default).
    // The Windows default main-thread stack is only 1 MiB, which is
    // insufficient for the deeply-nested shim call chains.
    let builder = std::thread::Builder::new().stack_size(8 * 1024 * 1024);
    let handle = builder
        .spawn(move || litebox_runner_linux_on_windows_userland::run(args))
        .expect("failed to spawn main worker thread");
    handle.join().unwrap()
}

#[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
fn main() {
    eprintln!("This program is only supported on Windows x86_64");
    std::process::exit(1);
}
