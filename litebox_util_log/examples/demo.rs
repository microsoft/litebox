// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Demonstration of litebox_util_log functionality.
//!
//! Run this example with the log backend (default):
//!   cargo run -p litebox_util_log --example demo
//!
//! Run this example with the tracing backend:
//!   cargo run -p litebox_util_log --example demo --no-default-features --features backend_tracing
//!
//! To see all log levels including debug and trace:
//!   RUST_LOG=trace cargo run -p litebox_util_log --example demo

use litebox_util_log::{
    Level, debug, debug_span, error, error_span, info, info_span, log, trace, trace_span, warn,
    warn_span,
};

fn main() {
    // Initialize the appropriate subscriber based on the backend feature
    #[cfg(feature = "backend_log")]
    {
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("trace"))
            .format_timestamp_millis()
            .init();
    }

    #[cfg(feature = "backend_tracing")]
    {
        use tracing_subscriber::{EnvFilter, fmt};
        fmt()
            .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "trace".into()))
            .init();
    }

    println!("=== litebox_util_log Demo ===\n");

    // -------------------------------------------------------------------------
    // Basic logging at different levels
    // -------------------------------------------------------------------------
    println!("--- Basic Logging ---");
    error!("This is an error message");
    warn!("This is a warning message");
    info!("This is an info message");
    debug!("This is a debug message");
    trace!("This is a trace message");
    println!();

    // -------------------------------------------------------------------------
    // Logging with key-value pairs using different capture modes
    // -------------------------------------------------------------------------
    println!("--- Key-Value Logging ---");

    // Debug capture (:? or :debug)
    let user_id = 42;
    let username = "alice";
    info!(user_id:?, username:?; "User logged in");

    // Display capture (:% or :display)
    let status = "active";
    info!(status:%; "Account status");

    // Explicit values (different from variable names)
    let count = 5;
    info!(items:? = count, category:% = "electronics"; "Inventory update");

    // Multiple key-value pairs
    let x = 10;
    let y = 20;
    let z = 30;
    debug!(x:?, y:?, z:?; "Coordinates");

    // Error capture (:err)
    let error_msg = "connection timeout";
    error!(reason:err = error_msg; "Operation failed");
    println!();

    // -------------------------------------------------------------------------
    // Using the generic log! macro with explicit levels
    // -------------------------------------------------------------------------
    println!("--- Generic log! Macro ---");
    log!(Level::Info, "Generic info message");
    log!(Level::Warn, severity:? = 3; "Warning with severity level");
    println!();

    // -------------------------------------------------------------------------
    // Spans - structured logging contexts
    // -------------------------------------------------------------------------
    println!("--- Spans ---");

    // Simple span without key-value pairs
    {
        let _span = info_span!("simple_operation");
        info!("Inside simple span");
        // Span exits when _span is dropped
    }

    // Span with key-value pairs
    {
        let request_id = "req-12345";
        let _span = info_span!("handle_request", request_id:?);
        info!("Processing request");
        debug!("Validating input");

        // Nested span
        {
            let _inner = debug_span!("database_query", table:% = "users");
            trace!("Executing SQL");
        }

        info!("Request completed");
    }

    // Different span levels
    {
        let _e = error_span!("critical_section");
        error!("In critical section");
    }

    {
        let _w = warn_span!("degraded_mode", reason:% = "high_load");
        warn!("Operating in degraded mode");
    }

    {
        let _t = trace_span!("inner_loop", iteration:? = 1);
        trace!("Very detailed tracing");
    }
    println!();

    // -------------------------------------------------------------------------
    // Realistic example: simulated request handling
    // -------------------------------------------------------------------------
    println!("--- Realistic Example: Request Handling ---");
    simulate_request_handling();
    println!();

    println!("=== Demo Complete ===");
}

/// Simulates a realistic request handling scenario with nested spans and logging.
fn simulate_request_handling() {
    let request_id = "req-abc-123";
    let user_agent = "Mozilla/5.0";
    let method = "GET";
    let path = "/api/users/42";

    // Outer span for the entire request
    let _request_span = info_span!("http_request", request_id:?, method:%, path:%);

    info!(user_agent:%; "Received request");

    // Authentication phase
    {
        let _auth_span = debug_span!("authentication");
        debug!("Validating token");
        trace!("Token signature verified");
        info!("User authenticated");
    }

    // Authorization phase
    {
        let _authz_span = debug_span!("authorization", resource:% = "users", action:% = "read");
        debug!("Checking permissions");
        info!("Access granted");
    }

    // Business logic
    {
        let _logic_span = debug_span!("business_logic");

        // Simulate database access
        {
            let _db_span = trace_span!("database", query:% = "SELECT * FROM users WHERE id = 42");
            trace!("Connecting to database");
            trace!("Executing query");
            debug!(rows:? = 1; "Query returned");
        }

        // Simulate some processing
        for i in 0..3 {
            let _iter_span = trace_span!("process_item", i);
            trace!("Processing item");
        }

        info!("Business logic completed");
    }

    // Response
    {
        let status_code = 200;
        let response_size = 1024;
        info!(status_code:?, response_size:?; "Sending response");
    }

    info!("Request completed successfully");
}
