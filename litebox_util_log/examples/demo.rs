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
    Level, debug, debug_span, error, error_span, info, info_span, instrument, log, trace,
    trace_span, warn, warn_span,
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

    // -------------------------------------------------------------------------
    // Instrument attribute macro
    // -------------------------------------------------------------------------
    println!("--- Instrument Macro ---");
    demonstrate_instrument();
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

/// Demonstrates the #[instrument] attribute macro.
fn demonstrate_instrument() {
    // Basic instrumented function - captures all args
    let result = add_numbers(10, 20);
    info!(result:?; "add_numbers returned");

    // Function with specific field capture modes
    process_user(42, "alice", "secret123");

    // Function that skips sensitive data
    authenticate("admin", "hunter2");

    // Function with skip_all
    handle_sensitive_data("classified", 9001);

    // Function with custom span name
    my_internal_function();

    // Instrumented function that returns a value
    let doubled = double_value(21);
    info!(doubled:?; "double_value returned");
}

/// Basic instrumented function - automatically captures all arguments with Debug.
#[instrument(level = debug)]
fn add_numbers(a: i32, b: i32) -> i32 {
    debug!("Performing addition");
    a + b
}

/// Instrumented function with specific fields and capture modes.
/// Only captures `id` (Debug) and `name` (Display), not `password`.
#[instrument(level = info, fields(id:?, name:%))]
fn process_user(id: u64, name: &str, password: &str) {
    info!("Processing user data");
    // password is intentionally not captured in the span
    let _ = password;
}

/// Instrumented function that skips specific arguments.
#[instrument(level = warn, skip(password))]
fn authenticate(username: &str, password: &str) {
    warn!("Authenticating user");
    let _ = password;
}

/// Instrumented function that skips all arguments.
#[instrument(level = trace, skip_all)]
fn handle_sensitive_data(data: &str, classification: u32) {
    trace!("Handling sensitive data");
    let _ = (data, classification);
}

/// Instrumented function with a custom span name.
#[instrument(level = info, name = "custom_operation")]
fn my_internal_function() {
    info!("Inside function with custom span name");
}

/// Instrumented function that returns a value.
#[instrument(level = debug)]
fn double_value(x: i32) -> i32 {
    debug!("Doubling the value");
    x * 2
}
