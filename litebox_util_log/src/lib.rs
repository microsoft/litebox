// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Logging facade for LiteBox that provides a unified interface for logging
//! with support for either `log` or `tracing` backends.
//!
//! # Features
//!
//! - `backend_log` (default): Uses the `log` crate for logging events.
//!   Spans are emulated by logging events at span entry and exit.
//! - `backend_tracing`: Uses the `tracing` crate with full span support.
//!
//! # Key-Value Capture Modes
//!
//! This crate supports the same capture modes as `log`'s `kv` feature:
//!
//! - `:?` or `:debug` - Capture the value using `Debug`
//! - `:%` or `:display` - Capture the value using `Display`
//! - `:err` - Capture the value using `std::error::Error` (requires `kv_std`)
//! - `:sval` - Capture the value using `sval::Value` (requires `kv_sval`)
//! - `:serde` - Capture the value using `serde::Serialize` (requires `kv_serde`)
//!
//! # Example
//!
//! ```ignore
//! use litebox_util_log::{info, debug, info_span, instrument};
//!
//! // Simple logging
//! info!("Hello, world!");
//!
//! // Logging with key-value pairs
//! let user_id = 42;
//! info!(user_id:? = user_id; "User logged in");
//!
//! // Using spans (returns a guard, exits when dropped)
//! let _span = info_span!("my_operation", request_id:? = req_id);
//! // ... do work ...
//! debug!("Processing request");
//! // span exits when _span is dropped
//!
//! // Using the instrument attribute macro
//! #[instrument(level = debug, fields(user_id:?))]
//! fn process_user(user_id: u64, data: &str) {
//!     info!("Processing user");
//! }
//! ```

#![no_std]

// Compile-time check: at least one backend must be enabled
// Note: When both backends are enabled, backend_tracing takes precedence.
#[cfg(not(any(feature = "backend_log", feature = "backend_tracing")))]
compile_error!("Either `backend_log` or `backend_tracing` feature must be enabled.");

// =============================================================================
// Module declarations
// =============================================================================

// Public macros module - macros are exported at crate root via #[macro_export]
#[macro_use]
mod macros;

// Backend-specific implementations
// Only one backend is active at a time (tracing takes precedence if both enabled)
#[cfg(all(feature = "backend_log", not(feature = "backend_tracing")))]
#[macro_use]
mod backend_log;

#[cfg(feature = "backend_tracing")]
#[macro_use]
mod backend_tracing;

// =============================================================================
// Public re-exports
// =============================================================================

// Re-export the instrument attribute macro
pub use litebox_util_log_macros::instrument;

// =============================================================================
// Level enum
// =============================================================================

/// Log level that abstracts over backend-specific level types.
///
/// This enum provides a unified way to specify log levels regardless of
/// whether the `backend_log` or `backend_tracing` feature is enabled.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Level {
    /// Error level - for serious problems that need immediate attention.
    Error,
    /// Warn level - for potential issues or unexpected situations.
    Warn,
    /// Info level - for general informational messages.
    Info,
    /// Debug level - for debugging information useful during development.
    Debug,
    /// Trace level - for very verbose debugging, typically disabled in production.
    Trace,
}

// Re-export SpanGuard from the active backend
#[cfg(all(feature = "backend_log", not(feature = "backend_tracing")))]
pub use backend_log::SpanGuard;

#[cfg(feature = "backend_tracing")]
pub use backend_tracing::SpanGuard;

// =============================================================================
// Internal module for macro implementation details
// =============================================================================

/// Internal module for macro implementation details.
/// Not part of the public API.
#[doc(hidden)]
pub mod __private {
    #[cfg(all(feature = "backend_log", not(feature = "backend_tracing")))]
    pub use log;
    #[cfg(all(feature = "backend_log", not(feature = "backend_tracing")))]
    pub use log::Level;

    #[cfg(feature = "backend_tracing")]
    pub use tracing;
    #[cfg(feature = "backend_tracing")]
    pub use tracing::Level;
}
