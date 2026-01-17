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

// Re-export the instrument attribute macro
pub use litebox_util_log_macros::instrument;

// Re-export useful items from backends
#[cfg(all(feature = "backend_log", not(feature = "backend_tracing")))]
pub use log::{LevelFilter, log_enabled};

#[cfg(feature = "backend_tracing")]
pub use tracing::level_enabled as log_enabled;

// Compile-time check: at least one backend must be enabled
// Note: When both backends are enabled, backend_tracing takes precedence.
#[cfg(not(any(feature = "backend_log", feature = "backend_tracing")))]
compile_error!("Either `backend_log` or `backend_tracing` feature must be enabled.");

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

// =============================================================================
// LOGGING MACROS
// =============================================================================

/// Log at the error level.
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
/// With the `backend_log` feature, this emits log messages at span entry and exit.
/// With the `backend_tracing` feature, this creates a proper tracing span.
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

// =============================================================================
// BACKEND-SPECIFIC IMPLEMENTATION - LOG
// =============================================================================

#[cfg(all(feature = "backend_log", not(feature = "backend_tracing")))]
mod log_backend {
    /// Guard that logs span exit when dropped.
    pub struct SpanGuard {
        #[doc(hidden)]
        pub name: &'static str,
        #[doc(hidden)]
        pub level: crate::Level,
        #[doc(hidden)]
        pub module_path: &'static str,
    }

    impl Drop for SpanGuard {
        fn drop(&mut self) {
            match self.level {
                crate::Level::Error => {
                    log::log!(target: self.module_path, log::Level::Error, "[SPAN EXIT] {}", self.name);
                }
                crate::Level::Warn => {
                    log::log!(target: self.module_path, log::Level::Warn, "[SPAN EXIT] {}", self.name);
                }
                crate::Level::Info => {
                    log::log!(target: self.module_path, log::Level::Info, "[SPAN EXIT] {}", self.name);
                }
                crate::Level::Debug => {
                    log::log!(target: self.module_path, log::Level::Debug, "[SPAN EXIT] {}", self.name);
                }
                crate::Level::Trace => {
                    log::log!(target: self.module_path, log::Level::Trace, "[SPAN EXIT] {}", self.name);
                }
            }
        }
    }
}

#[cfg(all(feature = "backend_log", not(feature = "backend_tracing")))]
pub use log_backend::SpanGuard;

/// Internal macro for log backend implementation.
#[doc(hidden)]
#[cfg(all(feature = "backend_log", not(feature = "backend_tracing")))]
#[macro_export]
macro_rules! __log_impl {
    // With key-value pairs - format them into the message
    ($level:expr, $($key:ident $(:$cap:tt)? $(= $value:expr)?),+ ; $msg:literal) => {{
        match $level {
            $crate::Level::Error => $crate::__private::log::log!(
                $crate::__private::log::Level::Error,
                concat!($($crate::__kv_format_log!($key $(:$cap)?)),+ , " | ", $msg),
                $($crate::__kv_value_log!($key $(:$cap)? $(= $value)?)),+
            ),
            $crate::Level::Warn => $crate::__private::log::log!(
                $crate::__private::log::Level::Warn,
                concat!($($crate::__kv_format_log!($key $(:$cap)?)),+ , " | ", $msg),
                $($crate::__kv_value_log!($key $(:$cap)? $(= $value)?)),+
            ),
            $crate::Level::Info => $crate::__private::log::log!(
                $crate::__private::log::Level::Info,
                concat!($($crate::__kv_format_log!($key $(:$cap)?)),+ , " | ", $msg),
                $($crate::__kv_value_log!($key $(:$cap)? $(= $value)?)),+
            ),
            $crate::Level::Debug => $crate::__private::log::log!(
                $crate::__private::log::Level::Debug,
                concat!($($crate::__kv_format_log!($key $(:$cap)?)),+ , " | ", $msg),
                $($crate::__kv_value_log!($key $(:$cap)? $(= $value)?)),+
            ),
            $crate::Level::Trace => $crate::__private::log::log!(
                $crate::__private::log::Level::Trace,
                concat!($($crate::__kv_format_log!($key $(:$cap)?)),+ , " | ", $msg),
                $($crate::__kv_value_log!($key $(:$cap)? $(= $value)?)),+
            ),
        }
    }};
    // Without key-value pairs - simple message (literal only)
    ($level:expr, $msg:literal) => {
        match $level {
            $crate::Level::Error => $crate::__private::log::log!($crate::__private::log::Level::Error, $msg),
            $crate::Level::Warn => $crate::__private::log::log!($crate::__private::log::Level::Warn, $msg),
            $crate::Level::Info => $crate::__private::log::log!($crate::__private::log::Level::Info, $msg),
            $crate::Level::Debug => $crate::__private::log::log!($crate::__private::log::Level::Debug, $msg),
            $crate::Level::Trace => $crate::__private::log::log!($crate::__private::log::Level::Trace, $msg),
        }
    };
}

/// Internal macro to format key-value pairs for string-based logging.
#[doc(hidden)]
#[macro_export]
macro_rules! __kv_format_log {
    ($key:ident :?) => {
        concat!(stringify!($key), "={:?} ")
    };
    ($key:ident :debug) => {
        concat!(stringify!($key), "={:?} ")
    };
    ($key:ident :%) => {
        concat!(stringify!($key), "={} ")
    };
    ($key:ident :display) => {
        concat!(stringify!($key), "={} ")
    };
    ($key:ident :err) => {
        concat!(stringify!($key), "={} ")
    };
    ($key:ident :sval) => {
        concat!(stringify!($key), "={:?} ")
    };
    ($key:ident :serde) => {
        concat!(stringify!($key), "={:?} ")
    };
    ($key:ident) => {
        concat!(stringify!($key), "={:?} ")
    };
}

/// Internal macro to extract values for string-based logging.
#[doc(hidden)]
#[macro_export]
macro_rules! __kv_value_log {
    ($key:ident $(:$cap:tt)? = $value:expr) => {
        $value
    };
    ($key:ident $(:$cap:tt)?) => {
        $key
    };
}

/// Internal macro for span implementation with log backend.
#[doc(hidden)]
#[cfg(all(feature = "backend_log", not(feature = "backend_tracing")))]
#[macro_export]
macro_rules! __span_impl {
    ($level:expr, $name:expr, $($key:ident $(:$cap:tt)? $(= $value:expr)?),+) => {{
        let __level = $level;
        match __level {
            $crate::Level::Error => $crate::__private::log::log!(
                $crate::__private::log::Level::Error,
                concat!("[SPAN ENTER] ", $name, " | ", $($crate::__kv_format_log!($key $(:$cap)?)),+),
                $($crate::__kv_value_log!($key $(:$cap)? $(= $value)?)),+
            ),
            $crate::Level::Warn => $crate::__private::log::log!(
                $crate::__private::log::Level::Warn,
                concat!("[SPAN ENTER] ", $name, " | ", $($crate::__kv_format_log!($key $(:$cap)?)),+),
                $($crate::__kv_value_log!($key $(:$cap)? $(= $value)?)),+
            ),
            $crate::Level::Info => $crate::__private::log::log!(
                $crate::__private::log::Level::Info,
                concat!("[SPAN ENTER] ", $name, " | ", $($crate::__kv_format_log!($key $(:$cap)?)),+),
                $($crate::__kv_value_log!($key $(:$cap)? $(= $value)?)),+
            ),
            $crate::Level::Debug => $crate::__private::log::log!(
                $crate::__private::log::Level::Debug,
                concat!("[SPAN ENTER] ", $name, " | ", $($crate::__kv_format_log!($key $(:$cap)?)),+),
                $($crate::__kv_value_log!($key $(:$cap)? $(= $value)?)),+
            ),
            $crate::Level::Trace => $crate::__private::log::log!(
                $crate::__private::log::Level::Trace,
                concat!("[SPAN ENTER] ", $name, " | ", $($crate::__kv_format_log!($key $(:$cap)?)),+),
                $($crate::__kv_value_log!($key $(:$cap)? $(= $value)?)),+
            ),
        };
        $crate::SpanGuard { name: $name, level: __level, module_path: module_path!() }
    }};
    ($level:expr, $name:expr) => {{
        let __level = $level;
        match __level {
            $crate::Level::Error => $crate::__private::log::log!($crate::__private::log::Level::Error, "[SPAN ENTER] {}", $name),
            $crate::Level::Warn => $crate::__private::log::log!($crate::__private::log::Level::Warn, "[SPAN ENTER] {}", $name),
            $crate::Level::Info => $crate::__private::log::log!($crate::__private::log::Level::Info, "[SPAN ENTER] {}", $name),
            $crate::Level::Debug => $crate::__private::log::log!($crate::__private::log::Level::Debug, "[SPAN ENTER] {}", $name),
            $crate::Level::Trace => $crate::__private::log::log!($crate::__private::log::Level::Trace, "[SPAN ENTER] {}", $name),
        };
        $crate::SpanGuard { name: $name, level: __level, module_path: module_path!() }
    }};
}

// =============================================================================
// BACKEND-SPECIFIC IMPLEMENTATION - TRACING
// =============================================================================

#[cfg(feature = "backend_tracing")]
mod tracing_backend {
    /// Guard that wraps a tracing span's entered guard.
    pub struct SpanGuard {
        #[doc(hidden)]
        #[allow(dead_code)]
        pub inner: tracing::span::EnteredSpan,
    }
}

#[cfg(feature = "backend_tracing")]
pub use tracing_backend::SpanGuard;

/// Internal macro for tracing backend implementation.
#[doc(hidden)]
#[cfg(feature = "backend_tracing")]
#[macro_export]
macro_rules! __log_impl {
    // With key-value pairs - format them into the message (like log backend)
    ($level:expr, $($key:ident $(:$cap:tt)? $(= $value:expr)?),+ ; $msg:literal) => {{
        // Use the same formatting approach as log backend for consistency
        $crate::__tracing_event_simple!(
            $level,
            concat!($($crate::__kv_format_log!($key $(:$cap)?)),+ , " | ", $msg),
            $($crate::__kv_value_log!($key $(:$cap)? $(= $value)?)),+
        )
    }};
    // Without key-value pairs (literal only)
    ($level:expr, $msg:literal) => {
        $crate::__tracing_event_simple!($level, $msg)
    };
}

/// Internal macro for tracing events with key-value pairs.
/// Internal macro for simple tracing events.
#[doc(hidden)]
#[cfg(feature = "backend_tracing")]
#[macro_export]
macro_rules! __tracing_event_simple {
    // With format arguments
    ($level:expr, $fmt:expr, $($arg:expr),+) => {
        match $level {
            $crate::Level::Error => {
                $crate::__private::tracing::event!($crate::__private::tracing::Level::ERROR, $fmt, $($arg),+)
            }
            $crate::Level::Warn => {
                $crate::__private::tracing::event!($crate::__private::tracing::Level::WARN, $fmt, $($arg),+)
            }
            $crate::Level::Info => {
                $crate::__private::tracing::event!($crate::__private::tracing::Level::INFO, $fmt, $($arg),+)
            }
            $crate::Level::Debug => {
                $crate::__private::tracing::event!($crate::__private::tracing::Level::DEBUG, $fmt, $($arg),+)
            }
            $crate::Level::Trace => {
                $crate::__private::tracing::event!($crate::__private::tracing::Level::TRACE, $fmt, $($arg),+)
            }
        }
    };
    // Just a literal message
    ($level:expr, $msg:literal) => {
        match $level {
            $crate::Level::Error => {
                $crate::__private::tracing::event!($crate::__private::tracing::Level::ERROR, $msg)
            }
            $crate::Level::Warn => {
                $crate::__private::tracing::event!($crate::__private::tracing::Level::WARN, $msg)
            }
            $crate::Level::Info => {
                $crate::__private::tracing::event!($crate::__private::tracing::Level::INFO, $msg)
            }
            $crate::Level::Debug => {
                $crate::__private::tracing::event!($crate::__private::tracing::Level::DEBUG, $msg)
            }
            $crate::Level::Trace => {
                $crate::__private::tracing::event!($crate::__private::tracing::Level::TRACE, $msg)
            }
        }
    };
}

/// Internal macro for span implementation with tracing backend.
///
/// Note: Due to tracing's macro parsing limitations, key-value pairs cannot be
/// passed as span fields. Instead, they are logged as an event at span entry.
#[doc(hidden)]
#[cfg(feature = "backend_tracing")]
#[macro_export]
macro_rules! __span_impl {
    ($level:expr, $name:expr, $($key:ident $(:$cap:tt)? $(= $value:expr)?),+) => {{
        // Create a real tracing span (without fields due to macro limitations)
        let __level = $level;
        let span = match __level {
            $crate::Level::Error => {
                $crate::__private::tracing::span!($crate::__private::tracing::Level::ERROR, $name)
            }
            $crate::Level::Warn => {
                $crate::__private::tracing::span!($crate::__private::tracing::Level::WARN, $name)
            }
            $crate::Level::Info => {
                $crate::__private::tracing::span!($crate::__private::tracing::Level::INFO, $name)
            }
            $crate::Level::Debug => {
                $crate::__private::tracing::span!($crate::__private::tracing::Level::DEBUG, $name)
            }
            $crate::Level::Trace => {
                $crate::__private::tracing::span!($crate::__private::tracing::Level::TRACE, $name)
            }
        };
        let guard = span.entered();
        // Log kv pairs as an event within the span
        $crate::__tracing_event_simple!(
            __level,
            concat!("[SPAN FIELDS] ", $($crate::__kv_format_log!($key $(:$cap)?)),+),
            $($crate::__kv_value_log!($key $(:$cap)? $(= $value)?)),+
        );
        $crate::SpanGuard { inner: guard }
    }};
    ($level:expr, $name:expr) => {{
        let span = match $level {
            $crate::Level::Error => {
                $crate::__private::tracing::span!($crate::__private::tracing::Level::ERROR, $name)
            }
            $crate::Level::Warn => {
                $crate::__private::tracing::span!($crate::__private::tracing::Level::WARN, $name)
            }
            $crate::Level::Info => {
                $crate::__private::tracing::span!($crate::__private::tracing::Level::INFO, $name)
            }
            $crate::Level::Debug => {
                $crate::__private::tracing::span!($crate::__private::tracing::Level::DEBUG, $name)
            }
            $crate::Level::Trace => {
                $crate::__private::tracing::span!($crate::__private::tracing::Level::TRACE, $name)
            }
        };
        $crate::SpanGuard { inner: span.entered() }
    }};
}
