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

impl crate::Level {
    /// Converts this level to the corresponding `log::Level`.
    #[doc(hidden)]
    pub const fn to_log_level(self) -> log::Level {
        match self {
            crate::Level::Error => log::Level::Error,
            crate::Level::Warn => log::Level::Warn,
            crate::Level::Info => log::Level::Info,
            crate::Level::Debug => log::Level::Debug,
            crate::Level::Trace => log::Level::Trace,
        }
    }
}

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
    fn drop(&mut self) {
        log::log!(target: self.module_path, self.level.to_log_level(), span = self.name; "[SPAN EXIT]");
    }
}

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
    ($level:expr, $($key:tt $(:$cap:tt)? $(= $value:expr)?),+ ; $msg:literal) => {{
        $crate::__private::log::log!(
            $crate::Level::to_log_level($level),
            $($key $(:$cap)? $(= $value)?),+;
            $msg
        )
    }};
    ($level:expr, $msg:literal) => {
        $crate::__private::log::log!($crate::Level::to_log_level($level), $msg)
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
        $crate::__private::log::log!(
            $crate::Level::to_log_level(__level),
            span = $name, $($key $(:$cap)? $(= $value)?),+;
            "[SPAN ENTER]"
        );
        $crate::SpanGuard { name: $name, level: __level, module_path: module_path!() }
    }};
    ($level:expr, $name:expr) => {{
        let __level = $level;
        $crate::__private::log::log!($crate::Level::to_log_level(__level), span = $name; "[SPAN ENTER]");
        $crate::SpanGuard { name: $name, level: __level, module_path: module_path!() }
    }};
}
