// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! The `litebox_egress_proxy` executable.
//!
//! Startup failures are reported on standard error and produce a nonzero exit
//! status; the readiness line on standard output is written only once the proxy
//! is fully configured and listening.

use std::process::ExitCode;

use clap::Parser;
use litebox_egress_proxy::config::Cli;
use litebox_egress_proxy::run;

fn main() -> ExitCode {
    let config = match Cli::parse().into_config() {
        Ok(config) => config,
        Err(error) => return fail(&error),
    };

    // A single-threaded runtime keeps the standalone TCB deterministic; all
    // request and tunnel work is asynchronous and explicitly bounded.
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => return fail(&error),
    };

    match runtime.block_on(run(&config)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => fail(&error),
    }
}

/// Reports a fatal error on standard error, including its causes.
fn fail(error: &dyn core::error::Error) -> ExitCode {
    eprint!("litebox_egress_proxy: {error}");
    let mut source = error.source();
    while let Some(cause) = source {
        eprint!(": {cause}");
        source = cause.source();
    }
    eprintln!();
    ExitCode::FAILURE
}
