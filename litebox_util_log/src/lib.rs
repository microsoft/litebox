// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! # LiteBox Logging Utilities
//!
//! A unified logging facade for LiteBox that abstracts over different logging backends.
//!
//! This crate provides macros for structured logging and tracing spans that work
//! consistently regardless of whether the underlying backend is `log` or `tracing`.
//!
//! ## Features
//!
//! - `backend_log` (default): Uses the [`log`](https://docs.rs/log) crate for logging events.
//!   Spans are emulated by logging events at span entry and exit.
//!
//! - `backend_tracing`: Uses the [`tracing`](https://docs.rs/tracing) crate with full span support.
//!   However, since `tracing` does not natively support `sval` or `serde` key-value capture,
//!   values captured with `:sval` or `:serde` are silently downgraded to their `Debug` (`{:?}`)
//!   representations.
//!
//! When both features are enabled, `backend_tracing` takes precedence.
//!
//! ## Key-Value Capture Modes
//!
//! This crate supports the same capture modes as `log`'s `kv` feature:
//!
//! - `:?` or `:debug` - Capture the value using `Debug`
//! - `:%` or `:display` - Capture the value using `Display`
//! - `:err` - Capture the value using `std::error::Error` (requires `kv_std`)
//! - `:sval` - Capture the value using `sval::Value` (requires `kv_sval`)
//! - `:serde` - Capture the value using `serde::Serialize` (requires `kv_serde`)
//!
//! ## Example
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

#[cfg(not(any(feature = "backend_log", feature = "backend_tracing")))]
compile_error!("Either `backend_log` or `backend_tracing` feature must be enabled.");

#[macro_use]
mod macros;

#[cfg(all(feature = "backend_log", not(feature = "backend_tracing")))]
#[macro_use]
mod backend_log;

#[cfg(feature = "backend_tracing")]
#[macro_use]
mod backend_tracing;

pub use litebox_util_log_macros::instrument;

/// Log level that abstracts over backend-specific level types.
///
/// Levels are ordered from most severe to least severe: `Error` > `Warn` > `Info` > `Debug` > `Trace`.
/// This ordering is used by logging implementations to filter messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Level {
    /// Serious problems that need immediate attention.
    Error,
    /// Potential issues or unexpected situations.
    Warn,
    /// General informational messages.
    Info,
    /// Debugging information useful during development.
    Debug,
    /// Very verbose debugging, typically disabled in production.
    Trace,
}

#[cfg(all(feature = "backend_log", not(feature = "backend_tracing")))]
pub use backend_log::SpanGuard;

#[cfg(feature = "backend_tracing")]
pub use backend_tracing::SpanGuard;

/// Internal module exposing backend types for use by exported macros.
///
/// This module is public only because macros need access to backend types at the
/// call site. It is not part of the public API and should not be used directly.
/// Breaking changes to this module are not considered semver violations.
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
