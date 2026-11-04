// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! `containerd-shim-litebox-v1`, the containerd runtime v2 shim of `io.containerd.litebox.v1`.
//!
//! Each container has a shim daemon, which builds the container's root archive, runs
//! `litebox-broker-userland` with the LiteBox guest service as its root process, and drives the
//! guest service through the broker's hybrid vsock bridge. The same executable is the broker's
//! guardian and its runner.

#![cfg(target_os = "linux")]

mod guardian;
mod rootfs;
mod sandbox;
mod service;
mod spec;
mod stdio;

use std::ffi::OsString;

use containerd_shim::protos::protobuf::{Message as _, MessageField};
use containerd_shim::protos::ttrpc::{self, Code};
use containerd_shim::protos::types::introspection::{RuntimeInfo, RuntimeVersion};

const RUNTIME: &str = "io.containerd.litebox.v1";

type Result<T> = std::result::Result<T, ttrpc::Error>;

/// A failed request, as containerd sees it.
fn error(code: Code, message: impl ToString) -> ttrpc::Error {
    ttrpc::Error::RpcStatus(ttrpc::get_status(code, message))
}

fn invalid(message: impl ToString) -> ttrpc::Error {
    error(Code::INVALID_ARGUMENT, message)
}

fn unsupported(message: impl ToString) -> ttrpc::Error {
    error(Code::UNIMPLEMENTED, message)
}

fn internal(message: impl ToString) -> ttrpc::Error {
    error(Code::INTERNAL, message)
}

/// Runs the shim: the broker's runner, the guardian, or one of containerd's actions.
pub fn main() {
    let args: Vec<OsString> = std::env::args_os().collect();
    // The broker runs its runners as `<runner> --unstable --broker-control-channel PATH ...`.
    if args.get(1).is_some_and(|arg| arg == "--unstable")
        && args
            .get(2)
            .is_some_and(|arg| arg == "--broker-control-channel")
    {
        run_runner(args);
    }
    if args
        .get(1)
        .is_some_and(|arg| arg == guardian::GUARDIAN_MODE)
    {
        guardian::main(&args[2..]);
    }
    // containerd asks for the runtime's information with `-info`, which the crate ignores.
    if containerd_shim::parse(args.get(1..).unwrap_or_default()).is_ok_and(|flags| flags.info) {
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
    // Every child has one owner that reaps it: neither the crate's reaper nor a subreaper.
    let config = containerd_shim::Config {
        no_reaper: true,
        no_sub_reaper: true,
        ..Default::default()
    };
    containerd_shim::run::<service::Shim>(RUNTIME, Some(config));
}

/// Runs the LiteBox runner library and exits with its code. Runners die with the guardian's
/// process group (see [`guardian`]).
fn run_runner(args: Vec<OsString>) -> ! {
    use clap::Parser as _;

    let args = match litebox_runner_linux_userland::CliArgs::try_parse_from(args) {
        Ok(args) => args,
        Err(error) => {
            eprintln!("litebox runner: {error}");
            std::process::exit(2);
        }
    };
    match litebox_runner_linux_userland::run(args) {
        Ok(code) => std::process::exit(code),
        Err(error) => {
            eprintln!("litebox runner failed: {error:#}");
            std::process::exit(1);
        }
    }
}
