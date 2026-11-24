// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! The LiteBox guest service: the broker's root process, which creates and supervises the
//! containers' processes for the containerd shim, serving `litebox_guest_service_protocol` on
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

use std::convert::Infallible;
use std::sync::Arc;

use litebox_guest_service_protocol::GUEST_SERVICE_PORT;
use litebox_guest_service_protocol::guest_service_ttrpc_async::create_guest_service;

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
        fail("not the first process of a LiteBox guest");
    }
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
        .unwrap_or_else(|error| fail(format!("cannot start the runtime: {error}")));
    // Every thread starts now, so that none can fail to start later.
    let service = service::Service::new(runtime.handle().clone())
        .and_then(|service| {
            let reaper = service.clone();
            std::thread::Builder::new()
                .name("reaper".to_owned())
                .spawn(move || reaper.reap())?;
            Ok(service)
        })
        .unwrap_or_else(|error| fail(format!("cannot start a thread: {error}")));
    let Err(error) = runtime.block_on(serve(service));
    fail(format!("cannot serve port {GUEST_SERVICE_PORT}: {error}"));
}

fn fail(message: impl std::fmt::Display) -> ! {
    log!("{message}");
    std::process::exit(1);
}

async fn serve(service: service::Service) -> ttrpc::Result<Infallible> {
    // Close-on-exec, and on any CID.
    let mut server = ttrpc::r#async::Server::new()
        .bind(&format!("vsock://-1:{GUEST_SERVICE_PORT}"))?
        .register_service(create_guest_service(Arc::new(service)));
    server.start().await?;
    // The server's tasks run only while `block_on` does.
    std::future::pending().await
}
