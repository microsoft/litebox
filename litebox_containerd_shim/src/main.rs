// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! `containerd-shim-litebox-v1`, the containerd runtime v2 shim of `io.containerd.litebox.v1`.
//!
//! Each container has one shim daemon, which hosts the container's LiteBox broker and runs every
//! guest process in a runner process: this binary in a private mode that calls the unchanged
//! Linux runner library.

#[cfg(target_os = "linux")]
mod broker;
#[cfg(target_os = "linux")]
mod error;
#[cfg(target_os = "linux")]
mod events;
#[cfg(target_os = "linux")]
mod image_fs;
#[cfg(target_os = "linux")]
mod mounts;
#[cfg(target_os = "linux")]
mod runner;
#[cfg(target_os = "linux")]
mod service;
#[cfg(target_os = "linux")]
mod spec;
#[cfg(target_os = "linux")]
mod stdio;

#[cfg(target_os = "linux")]
const RUNTIME: &str = "io.containerd.litebox.v1";

#[cfg(target_os = "linux")]
fn main() {
    use containerd_shim::protos::protobuf::{Message as _, MessageField};
    use containerd_shim::protos::types::introspection::{RuntimeInfo, RuntimeVersion};

    let args = std::env::args_os().skip(1).collect::<Vec<_>>();
    if let Some(runner::RUNNER_MODE) = args.first().and_then(|mode| mode.to_str()) {
        runner::runner_main(&args[1..]);
    }
    let flags = containerd_shim::parse(&args);
    // containerd asks for the runtime's information with `-info`, which the crate ignores.
    if flags.as_ref().is_ok_and(|flags| flags.info) {
        let info = RuntimeInfo {
            name: RUNTIME.to_owned(),
            version: MessageField::some(RuntimeVersion {
                version: env!("CARGO_PKG_VERSION").to_owned(),
                ..Default::default()
            }),
            ..Default::default()
        };
        let written = info
            .write_to_bytes()
            .map_err(std::io::Error::other)
            .and_then(|info| std::io::Write::write_all(&mut std::io::stdout(), &info));
        std::process::exit(i32::from(written.is_err()));
    }
    if flags.is_ok_and(|flags| flags.action.is_empty()) {
        // The daemon: still single-threaded, as entering a mount namespace requires. Without
        // root (as in tests) it mounts nothing, and containerd's root file system mounts are
        // rejected.
        if rustix::process::geteuid().is_root()
            && let Err(error) = mounts::enter_private_namespace()
        {
            eprintln!("cannot enter a private mount namespace: {error}");
            std::process::exit(1);
        }
    }
    // Every child has exactly one owner that reaps it, so neither the crate's reaper nor a
    // subreaper may take children's exits.
    let config = containerd_shim::Config {
        no_reaper: true,
        no_sub_reaper: true,
        ..containerd_shim::Config::default()
    };
    containerd_shim::run::<service::Shim>(RUNTIME, Some(config));
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("containerd-shim-litebox-v1 supports only Linux hosts");
    std::process::exit(1);
}
