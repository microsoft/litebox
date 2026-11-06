// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! `containerd-shim-litebox-v1`, the containerd runtime v2 shim of `io.containerd.litebox.v1`.
//!
//! Each container has a shim daemon, which builds the container's root archive, runs
//! `litebox-broker-userland` with the LiteBox guest service as its root process, and drives the
//! guest service through the broker's hybrid vsock bridge. The broker runs each guest process in
//! LiteBox's own runner; on Linux, the same executable is the broker's guardian.

#![cfg(target_os = "linux")]

mod hooks;
mod rootfs;
mod sandbox;
mod service;
mod spec;
mod stdio;

use std::ffi::OsString;
use std::process::{Child, ExitStatus};
use std::time::Duration;

use containerd_shim::protos::protobuf::{Message as _, MessageField};
use containerd_shim::protos::ttrpc::{self, Code};
use containerd_shim::protos::types::introspection::{RuntimeInfo, RuntimeVersion};

const RUNTIME: &str = "io.containerd.litebox.v1";

/// How much of a failed hook's stderr, or of the guest service's error message, an error shows.
const MAX_ERROR_DETAIL: usize = 4096;

/// `detail` cut to [`MAX_ERROR_DETAIL`] bytes, on a character boundary.
fn truncated(detail: &str) -> &str {
    &detail[..detail.floor_char_boundary(MAX_ERROR_DETAIL)]
}

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

/// Waits up to `timeout` for `child`, not reaped yet, to exit; returns whether it did.
fn exits_within(child: &Child, timeout: Duration) -> std::io::Result<bool> {
    // Not reaped yet, so its pid still names it.
    let pid = rustix::process::Pid::from_child(child);
    let pidfd = rustix::process::pidfd_open(pid, rustix::process::PidfdFlags::empty())?;
    let timeout = rustix::event::Timespec::try_from(timeout).ok();
    let mut fds = [rustix::event::PollFd::new(
        &pidfd,
        rustix::event::PollFlags::IN,
    )];
    loop {
        match rustix::event::poll(&mut fds, timeout.as_ref()) {
            Err(rustix::io::Errno::INTR) => {}
            polled => return Ok(polled? > 0),
        }
    }
}

/// Waits for `child` to exit, killing it after `timeout` if any; `None` if it was killed. A child
/// that cannot be waited for so is killed and reaped too, before the error is returned.
fn wait_or_kill(
    child: &mut Child,
    timeout: Option<Duration>,
) -> std::io::Result<Option<ExitStatus>> {
    if let Some(timeout) = timeout {
        let exited = exits_within(child, timeout);
        if !matches!(exited, Ok(true)) {
            let _ = child.kill();
            child.wait()?;
            return exited.map(|_| None);
        }
    }
    child.wait().map(Some)
}

/// Runs the shim: a private mode, or one of containerd's actions.
pub fn main() {
    let args: Vec<OsString> = std::env::args_os().collect();
    sandbox::run_private_mode(&args);
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
    // A panic ends the shim at once, whichever thread it hits, rather than leaving the others to
    // its poisoned locks: containerd then cleans up, and the guardian ends the broker. The default
    // hook prints it to stderr too: the actions have no log, but containerd records their stderr.
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        log::error!("{info}");
        default_hook(info);
        std::process::abort();
    }));
    containerd_shim::run::<service::Shim>(RUNTIME, Some(config));
}
