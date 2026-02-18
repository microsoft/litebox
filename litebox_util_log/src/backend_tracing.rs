// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Tracing backend implementation.
//!
//! This module provides the backend implementation when using the `tracing` crate.
//! Unlike the log backend, this provides full native span support with proper
//! hierarchical context propagation.
//!
//! The macros in this module transform our unified key-value syntax into
//! tracing's native field syntax using a tt-muncher pattern.

impl crate::Level {
    /// Converts this level to the corresponding `tracing::Level`.
    #[doc(hidden)]
    pub const fn to_tracing_level(self) -> tracing::Level {
        match self {
            crate::Level::Error => tracing::Level::ERROR,
            crate::Level::Warn => tracing::Level::WARN,
            crate::Level::Info => tracing::Level::INFO,
            crate::Level::Debug => tracing::Level::DEBUG,
            crate::Level::Trace => tracing::Level::TRACE,
        }
    }
}

/// RAII guard that wraps a tracing span's entered guard.
///
/// This type is returned by span macros (e.g., [`info_span!`](crate::info_span)) when
/// using the `backend_tracing` feature. The span remains "entered" (active) as long
/// as this guard exists. When dropped, the span is exited.
///
/// Unlike the log backend's `SpanGuard`, this provides full tracing semantics
/// including hierarchical span relationships and context propagation.
///
/// # Example
///
/// ```ignore
/// let _guard = info_span!("my_operation");
/// // Span is now entered and active
/// info!("This log is inside the span");
/// // Span exits when _guard goes out of scope
/// ```
pub struct SpanGuard {
    /// The wrapped tracing span guard. Public for macro access but not part of
    /// the public API.
    #[doc(hidden)]
    #[allow(dead_code)]
    pub inner: tracing::span::EnteredSpan,
}

/// Internal macro for tracing backend implementation.
///
/// This macro transforms our unified key-value syntax into tracing's native
/// event syntax. The transformation is handled by [`__tracing_dispatch`].
///
/// Not intended for direct use; called by the public logging macros.
#[doc(hidden)]
#[macro_export]
macro_rules! __log_impl {
    ($level:expr, $($key:ident $(:$cap:tt)? $(= $value:expr)?),+ ; $msg:literal) => {{
        $crate::__tracing_dispatch!(
            [event]
            [$level]
            [$msg]
            []
            [$($key $(:$cap)? $(= $value)?),+]
        )
    }};
    ($level:expr, $msg:literal) => {
        $crate::__private::tracing::event!($crate::Level::to_tracing_level($level), $msg)
    };
}

/// Unified internal macro to dispatch and process key-value pairs for tracing.
///
/// Uses a tt-muncher pattern to transform fields from our unified syntax
/// (e.g., `key:? = value`) into tracing's native syntax (e.g., `key = ?value`).
///
/// The macro processes fields one at a time, accumulating transformed fields
/// until no input remains, then emits the final event or span based on mode.
///
/// Arguments: `[mode] [level] [msg_or_name] [accumulated_fields] [remaining_input]`
///
/// Where `mode` is either `event` or `span`.
#[doc(hidden)]
#[macro_export]
macro_rules! __tracing_dispatch {
    // Field: key:? = value (Debug with explicit value)
    ([$mode:ident] [$level:expr] [$target:tt] [$($acc:tt)*] [$key:ident :? = $value:expr $(, $($rest:tt)*)?]) => {
        $crate::__tracing_dispatch!(
            [$mode] [$level] [$target]
            [$($acc)* $key = ?$value,]
            [$($($rest)*)?]
        )
    };

    // Field: key:debug = value
    ([$mode:ident] [$level:expr] [$target:tt] [$($acc:tt)*] [$key:ident :debug = $value:expr $(, $($rest:tt)*)?]) => {
        $crate::__tracing_dispatch!(
            [$mode] [$level] [$target]
            [$($acc)* $key = ?$value,]
            [$($($rest)*)?]
        )
    };

    // Field: key:% = value (Display with explicit value)
    ([$mode:ident] [$level:expr] [$target:tt] [$($acc:tt)*] [$key:ident :% = $value:expr $(, $($rest:tt)*)?]) => {
        $crate::__tracing_dispatch!(
            [$mode] [$level] [$target]
            [$($acc)* $key = %$value,]
            [$($($rest)*)?]
        )
    };

    // Field: key:display = value
    ([$mode:ident] [$level:expr] [$target:tt] [$($acc:tt)*] [$key:ident :display = $value:expr $(, $($rest:tt)*)?]) => {
        $crate::__tracing_dispatch!(
            [$mode] [$level] [$target]
            [$($acc)* $key = %$value,]
            [$($($rest)*)?]
        )
    };

    // Field: key:err = value (errors use Display)
    ([$mode:ident] [$level:expr] [$target:tt] [$($acc:tt)*] [$key:ident :err = $value:expr $(, $($rest:tt)*)?]) => {
        $crate::__tracing_dispatch!(
            [$mode] [$level] [$target]
            [$($acc)* $key = %$value,]
            [$($($rest)*)?]
        )
    };

    // Field: key:sval = value (fallback to Debug)
    ([$mode:ident] [$level:expr] [$target:tt] [$($acc:tt)*] [$key:ident :sval = $value:expr $(, $($rest:tt)*)?]) => {
        $crate::__tracing_dispatch!(
            [$mode] [$level] [$target]
            [$($acc)* $key = ?$value,]
            [$($($rest)*)?]
        )
    };

    // Field: key:serde = value (fallback to Debug)
    ([$mode:ident] [$level:expr] [$target:tt] [$($acc:tt)*] [$key:ident :serde = $value:expr $(, $($rest:tt)*)?]) => {
        $crate::__tracing_dispatch!(
            [$mode] [$level] [$target]
            [$($acc)* $key = ?$value,]
            [$($($rest)*)?]
        )
    };

    // Field: key = value (no capture mode)
    ([$mode:ident] [$level:expr] [$target:tt] [$($acc:tt)*] [$key:ident = $value:expr $(, $($rest:tt)*)?]) => {
        $crate::__tracing_dispatch!(
            [$mode] [$level] [$target]
            [$($acc)* $key = $value,]
            [$($($rest)*)?]
        )
    };

    // Field: key:cap (shorthand with capture mode) -> delegates to key:cap = key
    ([$mode:ident] [$level:expr] [$target:tt] [$($acc:tt)*] [$key:ident :$cap:tt $(, $($rest:tt)*)?]) => {
        $crate::__tracing_dispatch!(
            [$mode] [$level] [$target]
            [$($acc)*]
            [$key :$cap = $key $(, $($rest)*)?]
        )
    };

    // Field: key (bare identifier) -> delegates to key = key
    ([$mode:ident] [$level:expr] [$target:tt] [$($acc:tt)*] [$key:ident $(, $($rest:tt)*)?]) => {
        $crate::__tracing_dispatch!(
            [$mode] [$level] [$target]
            [$($acc)*]
            [$key = $key $(, $($rest)*)?]
        )
    };

    ([event] [$level:expr] [$msg:literal] [$($acc:tt)*] []) => {
        $crate::__private::tracing::event!($crate::Level::to_tracing_level($level), $($acc)* $msg)
    };
    ([span] [$level:expr] [$name:expr] [$($acc:tt)*] []) => {{
        let span = $crate::__private::tracing::span!($crate::Level::to_tracing_level($level), $name, $($acc)*);
        $crate::SpanGuard { inner: span.entered() }
    }};
}

/// Internal macro for span implementation with tracing backend.
///
/// Creates a tracing span with the given name and fields, enters it, and
/// returns a [`SpanGuard`] wrapping the entered span.
///
/// Not intended for direct use; called by the public span macros.
#[doc(hidden)]
#[macro_export]
macro_rules! __span_impl {
    ($level:expr, $name:expr, $($key:ident $(:$cap:tt)? $(= $value:expr)?),+) => {{
        $crate::__tracing_dispatch!(
            [span]
            [$level]
            [$name]
            []
            [$($key $(:$cap)? $(= $value)?),+]
        )
    }};
    ($level:expr, $name:expr) => {{
        let span = $crate::__private::tracing::span!($crate::Level::to_tracing_level($level), $name,);
        $crate::SpanGuard { inner: span.entered() }
    }};
}
