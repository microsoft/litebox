// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
fn main() -> anyhow::Result<()> {
    use clap::Parser as _;
    use litebox_runner_windows_userland::CliArgs;

    let args = CliArgs::parse();

    // Run on a thread with 8 MiB stack (matching Linux default).
    let builder = std::thread::Builder::new().stack_size(8 * 1024 * 1024);
    let handle = builder
        .spawn(move || litebox_runner_windows_userland::run(args))
        .expect("failed to spawn main worker thread");
    handle.join().unwrap()
}

#[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
fn main() {
    eprintln!("This program is only supported on Windows x86_64");
    std::process::exit(1);
}
