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
/// event syntax. The transformation is handled by [`__tracing_event_dispatch`].
///
/// Not intended for direct use; called by the public logging macros.
#[doc(hidden)]
#[macro_export]
macro_rules! __log_impl {
    ($level:expr, $($key:ident $(:$cap:tt)? $(= $value:expr)?),+ ; $msg:literal) => {{
        $crate::__tracing_event_dispatch!(
            [$level]
            [$msg]
            []
            [$($key $(:$cap)? $(= $value)?),+]
        )
    }};
    ($level:expr, $msg:literal) => {
        $crate::__tracing_event_emit!([$level], $msg)
    };
}

/// Internal macro to emit a tracing event at the specified level.
///
/// This handles the runtime-to-compile-time level dispatch required by
/// tracing's event macro.
#[doc(hidden)]
#[macro_export]
macro_rules! __tracing_event_emit {
    ([$level:expr], $($fields:tt)+) => {
        $crate::__private::tracing::event!($crate::Level::to_tracing_level($level), $($fields)+)
    };
}

/// Internal macro to dispatch and process key-value pairs for tracing events.
///
/// Uses a tt-muncher pattern to transform fields from our unified syntax
/// (e.g., `key:? = value`) into tracing's native syntax (e.g., `key = ?value`).
///
/// The macro processes fields one at a time, accumulating transformed fields
/// until no input remains, then emits the final event.
///
/// Arguments: `[level] [msg] [accumulated_fields] [remaining_input]`
#[doc(hidden)]
#[macro_export]
macro_rules! __tracing_event_dispatch {
    // === Field processing rules (with explicit value) ===

    // Field: key:? = value (Debug with explicit value)
    ([$level:expr] [$msg:literal] [$($acc:tt)*] [$key:ident :? = $value:expr , $($rest:tt)*]) => {
        $crate::__tracing_event_dispatch!(
            [$level] [$msg]
            [$($acc)* $key = ?$value,]
            [$($rest)*]
        )
    };
    ([$level:expr] [$msg:literal] [$($acc:tt)*] [$key:ident :? = $value:expr]) => {
        $crate::__tracing_event_dispatch!(
            [$level] [$msg]
            [$($acc)* $key = ?$value,]
            []
        )
    };

    // Field: key:debug = value
    ([$level:expr] [$msg:literal] [$($acc:tt)*] [$key:ident :debug = $value:expr , $($rest:tt)*]) => {
        $crate::__tracing_event_dispatch!(
            [$level] [$msg]
            [$($acc)* $key = ?$value,]
            [$($rest)*]
        )
    };
    ([$level:expr] [$msg:literal] [$($acc:tt)*] [$key:ident :debug = $value:expr]) => {
        $crate::__tracing_event_dispatch!(
            [$level] [$msg]
            [$($acc)* $key = ?$value,]
            []
        )
    };

    // Field: key:% = value (Display with explicit value)
    ([$level:expr] [$msg:literal] [$($acc:tt)*] [$key:ident :% = $value:expr , $($rest:tt)*]) => {
        $crate::__tracing_event_dispatch!(
            [$level] [$msg]
            [$($acc)* $key = %$value,]
            [$($rest)*]
        )
    };
    ([$level:expr] [$msg:literal] [$($acc:tt)*] [$key:ident :% = $value:expr]) => {
        $crate::__tracing_event_dispatch!(
            [$level] [$msg]
            [$($acc)* $key = %$value,]
            []
        )
    };

    // Field: key:display = value
    ([$level:expr] [$msg:literal] [$($acc:tt)*] [$key:ident :display = $value:expr , $($rest:tt)*]) => {
        $crate::__tracing_event_dispatch!(
            [$level] [$msg]
            [$($acc)* $key = %$value,]
            [$($rest)*]
        )
    };
    ([$level:expr] [$msg:literal] [$($acc:tt)*] [$key:ident :display = $value:expr]) => {
        $crate::__tracing_event_dispatch!(
            [$level] [$msg]
            [$($acc)* $key = %$value,]
            []
        )
    };

    // Field: key:err = value (errors use Display)
    ([$level:expr] [$msg:literal] [$($acc:tt)*] [$key:ident :err = $value:expr , $($rest:tt)*]) => {
        $crate::__tracing_event_dispatch!(
            [$level] [$msg]
            [$($acc)* $key = %$value,]
            [$($rest)*]
        )
    };
    ([$level:expr] [$msg:literal] [$($acc:tt)*] [$key:ident :err = $value:expr]) => {
        $crate::__tracing_event_dispatch!(
            [$level] [$msg]
            [$($acc)* $key = %$value,]
            []
        )
    };

    // Field: key:sval = value (fallback to Debug)
    ([$level:expr] [$msg:literal] [$($acc:tt)*] [$key:ident :sval = $value:expr , $($rest:tt)*]) => {
        $crate::__tracing_event_dispatch!(
            [$level] [$msg]
            [$($acc)* $key = ?$value,]
            [$($rest)*]
        )
    };
    ([$level:expr] [$msg:literal] [$($acc:tt)*] [$key:ident :sval = $value:expr]) => {
        $crate::__tracing_event_dispatch!(
            [$level] [$msg]
            [$($acc)* $key = ?$value,]
            []
        )
    };

    // Field: key:serde = value (fallback to Debug)
    ([$level:expr] [$msg:literal] [$($acc:tt)*] [$key:ident :serde = $value:expr , $($rest:tt)*]) => {
        $crate::__tracing_event_dispatch!(
            [$level] [$msg]
            [$($acc)* $key = ?$value,]
            [$($rest)*]
        )
    };
    ([$level:expr] [$msg:literal] [$($acc:tt)*] [$key:ident :serde = $value:expr]) => {
        $crate::__tracing_event_dispatch!(
            [$level] [$msg]
            [$($acc)* $key = ?$value,]
            []
        )
    };

    // Field: key = value (no capture mode, default to Debug)
    ([$level:expr] [$msg:literal] [$($acc:tt)*] [$key:ident = $value:expr , $($rest:tt)*]) => {
        $crate::__tracing_event_dispatch!(
            [$level] [$msg]
            [$($acc)* $key = ?$value,]
            [$($rest)*]
        )
    };
    ([$level:expr] [$msg:literal] [$($acc:tt)*] [$key:ident = $value:expr]) => {
        $crate::__tracing_event_dispatch!(
            [$level] [$msg]
            [$($acc)* $key = ?$value,]
            []
        )
    };

    // === Field processing rules (shorthand - value is variable with same name) ===

    // Field: key:? (Debug shorthand)
    ([$level:expr] [$msg:literal] [$($acc:tt)*] [$key:ident :? , $($rest:tt)*]) => {
        $crate::__tracing_event_dispatch!(
            [$level] [$msg]
            [$($acc)* $key = ?$key,]
            [$($rest)*]
        )
    };
    ([$level:expr] [$msg:literal] [$($acc:tt)*] [$key:ident :?]) => {
        $crate::__tracing_event_dispatch!(
            [$level] [$msg]
            [$($acc)* $key = ?$key,]
            []
        )
    };

    // Field: key:debug (Debug shorthand)
    ([$level:expr] [$msg:literal] [$($acc:tt)*] [$key:ident :debug , $($rest:tt)*]) => {
        $crate::__tracing_event_dispatch!(
            [$level] [$msg]
            [$($acc)* $key = ?$key,]
            [$($rest)*]
        )
    };
    ([$level:expr] [$msg:literal] [$($acc:tt)*] [$key:ident :debug]) => {
        $crate::__tracing_event_dispatch!(
            [$level] [$msg]
            [$($acc)* $key = ?$key,]
            []
        )
    };

    // Field: key:% (Display shorthand)
    ([$level:expr] [$msg:literal] [$($acc:tt)*] [$key:ident :% , $($rest:tt)*]) => {
        $crate::__tracing_event_dispatch!(
            [$level] [$msg]
            [$($acc)* $key = %$key,]
            [$($rest)*]
        )
    };
    ([$level:expr] [$msg:literal] [$($acc:tt)*] [$key:ident :%]) => {
        $crate::__tracing_event_dispatch!(
            [$level] [$msg]
            [$($acc)* $key = %$key,]
            []
        )
    };

    // Field: key:display (Display shorthand)
    ([$level:expr] [$msg:literal] [$($acc:tt)*] [$key:ident :display , $($rest:tt)*]) => {
        $crate::__tracing_event_dispatch!(
            [$level] [$msg]
            [$($acc)* $key = %$key,]
            [$($rest)*]
        )
    };
    ([$level:expr] [$msg:literal] [$($acc:tt)*] [$key:ident :display]) => {
        $crate::__tracing_event_dispatch!(
            [$level] [$msg]
            [$($acc)* $key = %$key,]
            []
        )
    };

    // Field: key:err (Display shorthand for errors)
    ([$level:expr] [$msg:literal] [$($acc:tt)*] [$key:ident :err , $($rest:tt)*]) => {
        $crate::__tracing_event_dispatch!(
            [$level] [$msg]
            [$($acc)* $key = %$key,]
            [$($rest)*]
        )
    };
    ([$level:expr] [$msg:literal] [$($acc:tt)*] [$key:ident :err]) => {
        $crate::__tracing_event_dispatch!(
            [$level] [$msg]
            [$($acc)* $key = %$key,]
            []
        )
    };

    // Field: key:sval (fallback shorthand)
    ([$level:expr] [$msg:literal] [$($acc:tt)*] [$key:ident :sval , $($rest:tt)*]) => {
        $crate::__tracing_event_dispatch!(
            [$level] [$msg]
            [$($acc)* $key = ?$key,]
            [$($rest)*]
        )
    };
    ([$level:expr] [$msg:literal] [$($acc:tt)*] [$key:ident :sval]) => {
        $crate::__tracing_event_dispatch!(
            [$level] [$msg]
            [$($acc)* $key = ?$key,]
            []
        )
    };

    // Field: key:serde (fallback shorthand)
    ([$level:expr] [$msg:literal] [$($acc:tt)*] [$key:ident :serde , $($rest:tt)*]) => {
        $crate::__tracing_event_dispatch!(
            [$level] [$msg]
            [$($acc)* $key = ?$key,]
            [$($rest)*]
        )
    };
    ([$level:expr] [$msg:literal] [$($acc:tt)*] [$key:ident :serde]) => {
        $crate::__tracing_event_dispatch!(
            [$level] [$msg]
            [$($acc)* $key = ?$key,]
            []
        )
    };

    // Field: key (bare identifier, default to Debug)
    ([$level:expr] [$msg:literal] [$($acc:tt)*] [$key:ident , $($rest:tt)*]) => {
        $crate::__tracing_event_dispatch!(
            [$level] [$msg]
            [$($acc)* $key = ?$key,]
            [$($rest)*]
        )
    };
    ([$level:expr] [$msg:literal] [$($acc:tt)*] [$key:ident]) => {
        $crate::__tracing_event_dispatch!(
            [$level] [$msg]
            [$($acc)* $key = ?$key,]
            []
        )
    };

    // === Base case: no more input, emit the event ===
    ([$level:expr] [$msg:literal] [$($acc:tt)*] []) => {
        $crate::__tracing_event_emit!([$level], $($acc)* $msg)
    };
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
        $crate::__tracing_span_dispatch!(
            [$level]
            [$name]
            []
            [$($key $(:$cap)? $(= $value)?),+]
        )
    }};
    ($level:expr, $name:expr) => {{
        $crate::__tracing_span_emit!([$level], [$name],)
    }};
}

/// Internal macro to emit a tracing span at the specified level.
///
/// Creates and enters the span, returning a [`SpanGuard`] that exits the span
/// when dropped.
#[doc(hidden)]
#[macro_export]
macro_rules! __tracing_span_emit {
    ([$level:expr], [$name:expr], $($fields:tt)*) => {{
        let span = $crate::__private::tracing::span!($crate::Level::to_tracing_level($level), $name, $($fields)*);
        $crate::SpanGuard { inner: span.entered() }
    }};
}

/// Internal macro to dispatch and process key-value pairs for tracing spans.
///
/// Uses a tt-muncher pattern to transform fields from our unified syntax
/// into tracing's native span field syntax. Similar to [`__tracing_event_dispatch`]
/// but for span creation rather than event emission.
///
/// Arguments: `[level] [name] [accumulated_fields] [remaining_input]`
#[doc(hidden)]
#[macro_export]
macro_rules! __tracing_span_dispatch {
    // === Field processing rules (with explicit value) ===

    // Field: key:? = value (Debug with explicit value)
    ([$level:expr] [$name:expr] [$($acc:tt)*] [$key:ident :? = $value:expr , $($rest:tt)*]) => {
        $crate::__tracing_span_dispatch!(
            [$level] [$name]
            [$($acc)* $key = ?$value,]
            [$($rest)*]
        )
    };
    ([$level:expr] [$name:expr] [$($acc:tt)*] [$key:ident :? = $value:expr]) => {
        $crate::__tracing_span_dispatch!(
            [$level] [$name]
            [$($acc)* $key = ?$value,]
            []
        )
    };

    // Field: key:debug = value
    ([$level:expr] [$name:expr] [$($acc:tt)*] [$key:ident :debug = $value:expr , $($rest:tt)*]) => {
        $crate::__tracing_span_dispatch!(
            [$level] [$name]
            [$($acc)* $key = ?$value,]
            [$($rest)*]
        )
    };
    ([$level:expr] [$name:expr] [$($acc:tt)*] [$key:ident :debug = $value:expr]) => {
        $crate::__tracing_span_dispatch!(
            [$level] [$name]
            [$($acc)* $key = ?$value,]
            []
        )
    };

    // Field: key:% = value (Display with explicit value)
    ([$level:expr] [$name:expr] [$($acc:tt)*] [$key:ident :% = $value:expr , $($rest:tt)*]) => {
        $crate::__tracing_span_dispatch!(
            [$level] [$name]
            [$($acc)* $key = %$value,]
            [$($rest)*]
        )
    };
    ([$level:expr] [$name:expr] [$($acc:tt)*] [$key:ident :% = $value:expr]) => {
        $crate::__tracing_span_dispatch!(
            [$level] [$name]
            [$($acc)* $key = %$value,]
            []
        )
    };

    // Field: key:display = value
    ([$level:expr] [$name:expr] [$($acc:tt)*] [$key:ident :display = $value:expr , $($rest:tt)*]) => {
        $crate::__tracing_span_dispatch!(
            [$level] [$name]
            [$($acc)* $key = %$value,]
            [$($rest)*]
        )
    };
    ([$level:expr] [$name:expr] [$($acc:tt)*] [$key:ident :display = $value:expr]) => {
        $crate::__tracing_span_dispatch!(
            [$level] [$name]
            [$($acc)* $key = %$value,]
            []
        )
    };

    // Field: key:err = value (errors use Display)
    ([$level:expr] [$name:expr] [$($acc:tt)*] [$key:ident :err = $value:expr , $($rest:tt)*]) => {
        $crate::__tracing_span_dispatch!(
            [$level] [$name]
            [$($acc)* $key = %$value,]
            [$($rest)*]
        )
    };
    ([$level:expr] [$name:expr] [$($acc:tt)*] [$key:ident :err = $value:expr]) => {
        $crate::__tracing_span_dispatch!(
            [$level] [$name]
            [$($acc)* $key = %$value,]
            []
        )
    };

    // Field: key:sval = value (fallback to Debug)
    ([$level:expr] [$name:expr] [$($acc:tt)*] [$key:ident :sval = $value:expr , $($rest:tt)*]) => {
        $crate::__tracing_span_dispatch!(
            [$level] [$name]
            [$($acc)* $key = ?$value,]
            [$($rest)*]
        )
    };
    ([$level:expr] [$name:expr] [$($acc:tt)*] [$key:ident :sval = $value:expr]) => {
        $crate::__tracing_span_dispatch!(
            [$level] [$name]
            [$($acc)* $key = ?$value,]
            []
        )
    };

    // Field: key:serde = value (fallback to Debug)
    ([$level:expr] [$name:expr] [$($acc:tt)*] [$key:ident :serde = $value:expr , $($rest:tt)*]) => {
        $crate::__tracing_span_dispatch!(
            [$level] [$name]
            [$($acc)* $key = ?$value,]
            [$($rest)*]
        )
    };
    ([$level:expr] [$name:expr] [$($acc:tt)*] [$key:ident :serde = $value:expr]) => {
        $crate::__tracing_span_dispatch!(
            [$level] [$name]
            [$($acc)* $key = ?$value,]
            []
        )
    };

    // Field: key = value (no capture mode, default to Debug)
    ([$level:expr] [$name:expr] [$($acc:tt)*] [$key:ident = $value:expr , $($rest:tt)*]) => {
        $crate::__tracing_span_dispatch!(
            [$level] [$name]
            [$($acc)* $key = ?$value,]
            [$($rest)*]
        )
    };
    ([$level:expr] [$name:expr] [$($acc:tt)*] [$key:ident = $value:expr]) => {
        $crate::__tracing_span_dispatch!(
            [$level] [$name]
            [$($acc)* $key = ?$value,]
            []
        )
    };

    // === Field processing rules (shorthand - value is variable with same name) ===

    // Field: key:? (Debug shorthand)
    ([$level:expr] [$name:expr] [$($acc:tt)*] [$key:ident :? , $($rest:tt)*]) => {
        $crate::__tracing_span_dispatch!(
            [$level] [$name]
            [$($acc)* $key = ?$key,]
            [$($rest)*]
        )
    };
    ([$level:expr] [$name:expr] [$($acc:tt)*] [$key:ident :?]) => {
        $crate::__tracing_span_dispatch!(
            [$level] [$name]
            [$($acc)* $key = ?$key,]
            []
        )
    };

    // Field: key:debug (Debug shorthand)
    ([$level:expr] [$name:expr] [$($acc:tt)*] [$key:ident :debug , $($rest:tt)*]) => {
        $crate::__tracing_span_dispatch!(
            [$level] [$name]
            [$($acc)* $key = ?$key,]
            [$($rest)*]
        )
    };
    ([$level:expr] [$name:expr] [$($acc:tt)*] [$key:ident :debug]) => {
        $crate::__tracing_span_dispatch!(
            [$level] [$name]
            [$($acc)* $key = ?$key,]
            []
        )
    };

    // Field: key:% (Display shorthand)
    ([$level:expr] [$name:expr] [$($acc:tt)*] [$key:ident :% , $($rest:tt)*]) => {
        $crate::__tracing_span_dispatch!(
            [$level] [$name]
            [$($acc)* $key = %$key,]
            [$($rest)*]
        )
    };
    ([$level:expr] [$name:expr] [$($acc:tt)*] [$key:ident :%]) => {
        $crate::__tracing_span_dispatch!(
            [$level] [$name]
            [$($acc)* $key = %$key,]
            []
        )
    };

    // Field: key:display (Display shorthand)
    ([$level:expr] [$name:expr] [$($acc:tt)*] [$key:ident :display , $($rest:tt)*]) => {
        $crate::__tracing_span_dispatch!(
            [$level] [$name]
            [$($acc)* $key = %$key,]
            [$($rest)*]
        )
    };
    ([$level:expr] [$name:expr] [$($acc:tt)*] [$key:ident :display]) => {
        $crate::__tracing_span_dispatch!(
            [$level] [$name]
            [$($acc)* $key = %$key,]
            []
        )
    };

    // Field: key:err (Display shorthand for errors)
    ([$level:expr] [$name:expr] [$($acc:tt)*] [$key:ident :err , $($rest:tt)*]) => {
        $crate::__tracing_span_dispatch!(
            [$level] [$name]
            [$($acc)* $key = %$key,]
            [$($rest)*]
        )
    };
    ([$level:expr] [$name:expr] [$($acc:tt)*] [$key:ident :err]) => {
        $crate::__tracing_span_dispatch!(
            [$level] [$name]
            [$($acc)* $key = %$key,]
            []
        )
    };

    // Field: key:sval (fallback shorthand)
    ([$level:expr] [$name:expr] [$($acc:tt)*] [$key:ident :sval , $($rest:tt)*]) => {
        $crate::__tracing_span_dispatch!(
            [$level] [$name]
            [$($acc)* $key = ?$key,]
            [$($rest)*]
        )
    };
    ([$level:expr] [$name:expr] [$($acc:tt)*] [$key:ident :sval]) => {
        $crate::__tracing_span_dispatch!(
            [$level] [$name]
            [$($acc)* $key = ?$key,]
            []
        )
    };

    // Field: key:serde (fallback shorthand)
    ([$level:expr] [$name:expr] [$($acc:tt)*] [$key:ident :serde , $($rest:tt)*]) => {
        $crate::__tracing_span_dispatch!(
            [$level] [$name]
            [$($acc)* $key = ?$key,]
            [$($rest)*]
        )
    };
    ([$level:expr] [$name:expr] [$($acc:tt)*] [$key:ident :serde]) => {
        $crate::__tracing_span_dispatch!(
            [$level] [$name]
            [$($acc)* $key = ?$key,]
            []
        )
    };

    // Field: key (bare identifier, default to Debug)
    ([$level:expr] [$name:expr] [$($acc:tt)*] [$key:ident , $($rest:tt)*]) => {
        $crate::__tracing_span_dispatch!(
            [$level] [$name]
            [$($acc)* $key = ?$key,]
            [$($rest)*]
        )
    };
    ([$level:expr] [$name:expr] [$($acc:tt)*] [$key:ident]) => {
        $crate::__tracing_span_dispatch!(
            [$level] [$name]
            [$($acc)* $key = ?$key,]
            []
        )
    };

    // === Base case: no more input, emit the span ===
    ([$level:expr] [$name:expr] [$($acc:tt)*] []) => {
        $crate::__tracing_span_emit!([$level], [$name], $($acc)*)
    };
}
