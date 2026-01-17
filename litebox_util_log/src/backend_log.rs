// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Log backend implementation.
//!
//! This module provides the backend implementation when using the `log` crate
//! with proper structured key-value logging via the `kv` feature.
//!
//! Since `log` does not have native span support, spans are emulated by:
//! - Logging a `[SPAN ENTER]` message when the span is created
//! - Logging a `[SPAN EXIT]` message when the span guard is dropped
//!
//! This allows log subscribers to correlate related log messages, though it
//! lacks the full hierarchical context that `tracing` provides.

// =============================================================================
// SpanGuard
// =============================================================================

/// RAII guard that logs span exit when dropped.
///
/// This type is returned by span macros (e.g., [`info_span!`](crate::info_span)) when
/// using the `backend_log` feature. Holding this guard keeps the logical span "active".
/// When the guard is dropped (either explicitly or when it goes out of scope),
/// a `[SPAN EXIT]` message is logged at the same level as the span entry.
///
/// # Example
///
/// ```ignore
/// let _guard = info_span!("my_operation");
/// // ... do work ...
/// // [SPAN EXIT] is logged here when _guard goes out of scope
/// ```
pub struct SpanGuard {
    /// The name of the span, used in the exit log message.
    #[doc(hidden)]
    pub name: &'static str,
    /// The log level at which to emit the exit message.
    #[doc(hidden)]
    pub level: crate::Level,
    /// The module path for the log target.
    #[doc(hidden)]
    pub module_path: &'static str,
}

impl Drop for SpanGuard {
    /// Logs a `[SPAN EXIT]` message at the span's level when the guard is dropped.
    fn drop(&mut self) {
        // Match to convert from our Level enum to log::Level.
        match self.level {
            crate::Level::Error => {
                log::log!(target: self.module_path, log::Level::Error, span = self.name; "[SPAN EXIT]");
            }
            crate::Level::Warn => {
                log::log!(target: self.module_path, log::Level::Warn, span = self.name; "[SPAN EXIT]");
            }
            crate::Level::Info => {
                log::log!(target: self.module_path, log::Level::Info, span = self.name; "[SPAN EXIT]");
            }
            crate::Level::Debug => {
                log::log!(target: self.module_path, log::Level::Debug, span = self.name; "[SPAN EXIT]");
            }
            crate::Level::Trace => {
                log::log!(target: self.module_path, log::Level::Trace, span = self.name; "[SPAN EXIT]");
            }
        }
    }
}

// =============================================================================
// Internal macros
// =============================================================================

/// Internal macro for log backend implementation.
///
/// This macro dispatches log events to the `log` crate, properly using log's `kv`
/// feature to pass structured key-value pairs. The match converts from our
/// [`Level`](crate::Level) enum to [`log::Level`].
///
/// Not intended for direct use; called by the public logging macros.
#[doc(hidden)]
#[macro_export]
macro_rules! __log_impl {
    // With key-value pairs - pass them directly to log's kv syntax
    ($level:expr, $($key:tt $(:$cap:tt)? $(= $value:expr)?),+ ; $msg:literal) => {{
        match $level {
            $crate::Level::Error => $crate::__private::log::log!(
                $crate::__private::log::Level::Error,
                $($key $(:$cap)? $(= $value)?),+;
                $msg
            ),
            $crate::Level::Warn => $crate::__private::log::log!(
                $crate::__private::log::Level::Warn,
                $($key $(:$cap)? $(= $value)?),+;
                $msg
            ),
            $crate::Level::Info => $crate::__private::log::log!(
                $crate::__private::log::Level::Info,
                $($key $(:$cap)? $(= $value)?),+;
                $msg
            ),
            $crate::Level::Debug => $crate::__private::log::log!(
                $crate::__private::log::Level::Debug,
                $($key $(:$cap)? $(= $value)?),+;
                $msg
            ),
            $crate::Level::Trace => $crate::__private::log::log!(
                $crate::__private::log::Level::Trace,
                $($key $(:$cap)? $(= $value)?),+;
                $msg
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

/// Internal macro for span implementation with log backend.
///
/// Creates a [`SpanGuard`] and emits a `[SPAN ENTER]` log message. The guard
/// will emit `[SPAN EXIT]` when dropped. Key-value pairs are included in the
/// entry message using log's `kv` syntax.
///
/// Not intended for direct use; called by the public span macros.
#[doc(hidden)]
#[macro_export]
macro_rules! __span_impl {
    ($level:expr, $name:expr, $($key:tt $(:$cap:tt)? $(= $value:expr)?),+) => {{
        let __level = $level;
        match __level {
            $crate::Level::Error => $crate::__private::log::log!(
                $crate::__private::log::Level::Error,
                span = $name, $($key $(:$cap)? $(= $value)?),+;
                "[SPAN ENTER]"
            ),
            $crate::Level::Warn => $crate::__private::log::log!(
                $crate::__private::log::Level::Warn,
                span = $name, $($key $(:$cap)? $(= $value)?),+;
                "[SPAN ENTER]"
            ),
            $crate::Level::Info => $crate::__private::log::log!(
                $crate::__private::log::Level::Info,
                span = $name, $($key $(:$cap)? $(= $value)?),+;
                "[SPAN ENTER]"
            ),
            $crate::Level::Debug => $crate::__private::log::log!(
                $crate::__private::log::Level::Debug,
                span = $name, $($key $(:$cap)? $(= $value)?),+;
                "[SPAN ENTER]"
            ),
            $crate::Level::Trace => $crate::__private::log::log!(
                $crate::__private::log::Level::Trace,
                span = $name, $($key $(:$cap)? $(= $value)?),+;
                "[SPAN ENTER]"
            ),
        };
        $crate::SpanGuard { name: $name, level: __level, module_path: module_path!() }
    }};
    ($level:expr, $name:expr) => {{
        let __level = $level;
        match __level {
            $crate::Level::Error => $crate::__private::log::log!($crate::__private::log::Level::Error, span = $name; "[SPAN ENTER]"),
            $crate::Level::Warn => $crate::__private::log::log!($crate::__private::log::Level::Warn, span = $name; "[SPAN ENTER]"),
            $crate::Level::Info => $crate::__private::log::log!($crate::__private::log::Level::Info, span = $name; "[SPAN ENTER]"),
            $crate::Level::Debug => $crate::__private::log::log!($crate::__private::log::Level::Debug, span = $name; "[SPAN ENTER]"),
            $crate::Level::Trace => $crate::__private::log::log!($crate::__private::log::Level::Trace, span = $name; "[SPAN ENTER]"),
        };
        $crate::SpanGuard { name: $name, level: __level, module_path: module_path!() }
    }};
}
