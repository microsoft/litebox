// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Public logging and span macros.
//!
//! This module contains all the public macros for logging at various levels
//! and for creating spans. These macros provide a unified interface that works
//! with both the `backend_log` and `backend_tracing` features.
//!
//! All macros support two forms:
//! - Simple message: `info!("message")`
//! - Key-value pairs with message: `info!(key:? = value; "message")`

// =============================================================================
// LOGGING MACROS
// =============================================================================

/// Log at the error level.
///
/// Use this for serious problems that need immediate attention, such as
/// unrecoverable errors or situations indicating bugs.
///
/// # Example
///
/// ```ignore
/// error!("Something went wrong");
/// error!(code:? = 500; "HTTP error");
/// ```
#[macro_export]
macro_rules! error {
    // Key-value pairs with message
    ($($key:ident $(:$cap:tt)? $(= $value:expr)?),+ ; $msg:literal) => {
        $crate::__log_impl!($crate::Level::Error, $($key $(:$cap)? $(= $value)?),+ ; $msg)
    };
    // Just message (literal only)
    ($msg:literal) => {
        $crate::__log_impl!($crate::Level::Error, $msg)
    };
}

/// Log at the warn level.
///
/// Use this for potential issues or unexpected situations that don't prevent
/// operation but may indicate problems.
///
/// # Example
///
/// ```ignore
/// warn!("This is a warning");
/// warn!(retries:? = 3; "Retrying operation");
/// ```
#[macro_export]
macro_rules! warn {
    ($($key:ident $(:$cap:tt)? $(= $value:expr)?),+ ; $msg:literal) => {
        $crate::__log_impl!($crate::Level::Warn, $($key $(:$cap)? $(= $value)?),+ ; $msg)
    };
    ($msg:literal) => {
        $crate::__log_impl!($crate::Level::Warn, $msg)
    };
}

/// Log at the info level.
///
/// Use this for general informational messages about normal operation,
/// such as startup messages or high-level progress updates.
///
/// # Example
///
/// ```ignore
/// info!("Server started");
/// info!(port:? = 8080; "Listening on port");
/// ```
#[macro_export]
macro_rules! info {
    ($($key:ident $(:$cap:tt)? $(= $value:expr)?),+ ; $msg:literal) => {
        $crate::__log_impl!($crate::Level::Info, $($key $(:$cap)? $(= $value)?),+ ; $msg)
    };
    ($msg:literal) => {
        $crate::__log_impl!($crate::Level::Info, $msg)
    };
}

/// Log at the debug level.
///
/// Use this for detailed diagnostic information useful during development
/// and debugging. Typically disabled in production.
///
/// # Example
///
/// ```ignore
/// debug!("Processing item");
/// debug!(item_id:? = id; "Processing");
/// ```
#[macro_export]
macro_rules! debug {
    ($($key:ident $(:$cap:tt)? $(= $value:expr)?),+ ; $msg:literal) => {
        $crate::__log_impl!($crate::Level::Debug, $($key $(:$cap)? $(= $value)?),+ ; $msg)
    };
    ($msg:literal) => {
        $crate::__log_impl!($crate::Level::Debug, $msg)
    };
}

/// Log at the trace level.
///
/// Use this for very fine-grained debugging information, such as tracing
/// control flow through functions. Typically disabled except when debugging
/// specific issues.
///
/// # Example
///
/// ```ignore
/// trace!("Entering function");
/// trace!(params:? = args; "Function called with");
/// ```
#[macro_export]
macro_rules! trace {
    ($($key:ident $(:$cap:tt)? $(= $value:expr)?),+ ; $msg:literal) => {
        $crate::__log_impl!($crate::Level::Trace, $($key $(:$cap)? $(= $value)?),+ ; $msg)
    };
    ($msg:literal) => {
        $crate::__log_impl!($crate::Level::Trace, $msg)
    };
}

/// Log at the specified level.
///
/// Use this when the log level needs to be determined at runtime or when
/// writing generic logging code.
///
/// # Example
///
/// ```ignore
/// log!(Level::Info, "Hello");
/// log!(Level::Debug, count:? = 42; "Count is");
/// ```
#[macro_export]
macro_rules! log {
    ($level:expr, $($key:ident $(:$cap:tt)? $(= $value:expr)?),+ ; $msg:literal) => {
        $crate::__log_impl!($level, $($key $(:$cap)? $(= $value)?),+ ; $msg)
    };
    ($level:expr, $msg:literal) => {
        $crate::__log_impl!($level, $msg)
    };
}

// =============================================================================
// SPAN MACROS
// =============================================================================

/// Create a span at the specified level. Returns a guard that exits the span when dropped.
///
/// Spans are used to represent a period of time or a logical operation. With the
/// `backend_log` feature, this emits log messages at span entry and exit. With the
/// `backend_tracing` feature, this creates a proper tracing span with full context.
///
/// The returned guard must be held for the duration of the span. Dropping the guard
/// (explicitly or when it goes out of scope) ends the span.
///
/// # Example
///
/// ```ignore
/// let _span = span!(Level::Info, "process_request", request_id:? = id);
/// // ... do work ...
/// // span exits when _span is dropped
///
/// // Without key-value pairs:
/// let _span = span!(Level::Debug, "my_span");
/// ```
#[macro_export]
macro_rules! span {
    // With key-value pairs
    ($level:expr, $name:expr, $($key:ident $(:$cap:tt)? $(= $value:expr)?),+) => {
        $crate::__span_impl!($level, $name, $($key $(:$cap)? $(= $value)?),+)
    };
    // Just name
    ($level:expr, $name:expr) => {
        $crate::__span_impl!($level, $name)
    };
}

/// Create an error-level span. Returns a guard that exits the span when dropped.
///
/// Use for spans around operations that are being traced due to error conditions.
///
/// # Example
///
/// ```ignore
/// let _span = error_span!("critical_operation", error_code:? = code);
/// ```
#[macro_export]
macro_rules! error_span {
    ($name:expr, $($key:ident $(:$cap:tt)? $(= $value:expr)?),+) => {
        $crate::span!($crate::Level::Error, $name, $($key $(:$cap)? $(= $value)?),+)
    };
    ($name:expr) => {
        $crate::span!($crate::Level::Error, $name)
    };
}

/// Create a warn-level span. Returns a guard that exits the span when dropped.
///
/// Use for spans around operations that may be problematic or degraded.
///
/// # Example
///
/// ```ignore
/// let _span = warn_span!("degraded_operation", reason:% = reason);
/// ```
#[macro_export]
macro_rules! warn_span {
    ($name:expr, $($key:ident $(:$cap:tt)? $(= $value:expr)?),+) => {
        $crate::span!($crate::Level::Warn, $name, $($key $(:$cap)? $(= $value)?),+)
    };
    ($name:expr) => {
        $crate::span!($crate::Level::Warn, $name)
    };
}

/// Create an info-level span. Returns a guard that exits the span when dropped.
///
/// Use for spans around high-level operations that should be visible in normal logs.
///
/// # Example
///
/// ```ignore
/// let _span = info_span!("handle_request", request_id:? = id);
/// ```
#[macro_export]
macro_rules! info_span {
    ($name:expr, $($key:ident $(:$cap:tt)? $(= $value:expr)?),+) => {
        $crate::span!($crate::Level::Info, $name, $($key $(:$cap)? $(= $value)?),+)
    };
    ($name:expr) => {
        $crate::span!($crate::Level::Info, $name)
    };
}

/// Create a debug-level span. Returns a guard that exits the span when dropped.
///
/// Use for spans around operations that are useful for debugging but not needed
/// in production logs.
///
/// # Example
///
/// ```ignore
/// let _span = debug_span!("process_item", item_id:? = id);
/// ```
#[macro_export]
macro_rules! debug_span {
    ($name:expr, $($key:ident $(:$cap:tt)? $(= $value:expr)?),+) => {
        $crate::span!($crate::Level::Debug, $name, $($key $(:$cap)? $(= $value)?),+)
    };
    ($name:expr) => {
        $crate::span!($crate::Level::Debug, $name)
    };
}

/// Create a trace-level span. Returns a guard that exits the span when dropped.
///
/// Use for fine-grained spans in performance-critical or frequently-called code.
/// Typically disabled except when debugging specific issues.
///
/// # Example
///
/// ```ignore
/// let _span = trace_span!("inner_loop", iteration:? = i);
/// ```
#[macro_export]
macro_rules! trace_span {
    ($name:expr, $($key:ident $(:$cap:tt)? $(= $value:expr)?),+) => {
        $crate::span!($crate::Level::Trace, $name, $($key $(:$cap)? $(= $value)?),+)
    };
    ($name:expr) => {
        $crate::span!($crate::Level::Trace, $name)
    };
}
