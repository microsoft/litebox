// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! The LiteBox guest service: the broker's root process, which creates and supervises the
//! container's processes for the containerd shim, serving `litebox_guest_service_protocol` on
//! vsock port 1024. It logs to its stderr, which the broker forwards to its own.
//!
//! It runs in images of any libc, so build it statically linked:
//! `RUSTFLAGS='-C target-feature=+crt-static' cargo build --release -p litebox_guest_service
//! --target x86_64-unknown-linux-gnu` (or `aarch64-unknown-linux-gnu`); the explicit target keeps
//! the flag off build scripts and procedural macros.

#![cfg(target_os = "linux")]

/// Logs to stderr, ignoring a failed write, which would make `eprintln!` panic.
macro_rules! log {
    ($($arg:tt)*) => {{
        use std::io::Write as _;
        let _ = writeln!(std::io::stderr(), "litebox-guest-service: {}", format_args!($($arg)*));
    }};
}

mod process;
mod service;

use std::sync::Arc;

use litebox_guest_service_protocol::GUEST_SERVICE_PORT;
use litebox_guest_service_protocol::guest_service_ttrpc::create_guest_service;

/// Runs the guest service until the broker ends.
pub fn run() -> ! {
    // A panic would leave a request unanswered, the table's lock poisoned or the reaper stopped:
    // as process 1, the guest service ends instead.
    std::panic::set_hook(Box::new(|info| {
        log!("{info}");
        std::process::abort();
    }));
    // Only LiteBox's first guest process has these, and confines `kill(-1)` to the guest.
    if (std::process::id(), std::os::unix::process::parent_id()) != (1, 0) {
        log!("not the first process of a LiteBox guest");
        std::process::exit(1);
    }
    let service = Arc::new(service::Service::default());
    let reaper = Arc::clone(&service);
    std::thread::spawn(move || reaper.reap());
    // Close-on-exec, and on any CID.
    let served = ttrpc::Server::new()
        .bind(&format!("vsock://-1:{GUEST_SERVICE_PORT}"))
        .map(|server| server.register_service(create_guest_service(service)))
        .and_then(|mut server| server.start().map(|()| server));
    match served {
        // The server serves from threads of its own while it lives.
        Ok(_server) => loop {
            std::thread::park();
        },
        Err(error) => {
            log!("cannot serve port {GUEST_SERVICE_PORT}: {error}");
            std::process::exit(1);
        }
    }
}
