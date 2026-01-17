// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Tracing backend implementation.
//!
//! This module provides the backend implementation when using the `tracing` crate.

/// Guard that wraps a tracing span's entered guard.
pub struct SpanGuard {
    #[doc(hidden)]
    #[allow(dead_code)]
    pub inner: tracing::span::EnteredSpan,
}

/// Internal macro for tracing backend implementation.
///
/// This properly captures key-value pairs as structured tracing fields.
#[doc(hidden)]
#[macro_export]
macro_rules! __log_impl {
    // With key-value pairs - dispatch to field processor
    ($level:expr, $($key:ident $(:$cap:tt)? $(= $value:expr)?),+ ; $msg:literal) => {{
        $crate::__tracing_event_dispatch!(
            [$level]
            [$msg]
            []
            [$($key $(:$cap)? $(= $value)?),+]
        )
    }};
    // Without key-value pairs (literal only)
    ($level:expr, $msg:literal) => {
        $crate::__tracing_event_emit!([$level], $msg)
    };
}

/// Internal macro to emit a tracing event at the specified level.
#[doc(hidden)]
#[macro_export]
macro_rules! __tracing_event_emit {
    // With fields
    ([$level:expr], $($fields:tt)+) => {
        match $level {
            $crate::Level::Error => {
                $crate::__private::tracing::event!($crate::__private::tracing::Level::ERROR, $($fields)+)
            }
            $crate::Level::Warn => {
                $crate::__private::tracing::event!($crate::__private::tracing::Level::WARN, $($fields)+)
            }
            $crate::Level::Info => {
                $crate::__private::tracing::event!($crate::__private::tracing::Level::INFO, $($fields)+)
            }
            $crate::Level::Debug => {
                $crate::__private::tracing::event!($crate::__private::tracing::Level::DEBUG, $($fields)+)
            }
            $crate::Level::Trace => {
                $crate::__private::tracing::event!($crate::__private::tracing::Level::TRACE, $($fields)+)
            }
        }
    };
}

/// Internal macro to dispatch and process key-value pairs for tracing events.
/// Uses tt-muncher pattern to transform fields into tracing's native syntax.
/// Arguments: [level] [msg] [accumulated_fields] [remaining_input]
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
/// This properly captures key-value pairs as structured span fields.
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
#[doc(hidden)]
#[macro_export]
macro_rules! __tracing_span_emit {
    ([$level:expr], [$name:expr], $($fields:tt)*) => {{
        let span = match $level {
            $crate::Level::Error => {
                $crate::__private::tracing::span!($crate::__private::tracing::Level::ERROR, $name, $($fields)*)
            }
            $crate::Level::Warn => {
                $crate::__private::tracing::span!($crate::__private::tracing::Level::WARN, $name, $($fields)*)
            }
            $crate::Level::Info => {
                $crate::__private::tracing::span!($crate::__private::tracing::Level::INFO, $name, $($fields)*)
            }
            $crate::Level::Debug => {
                $crate::__private::tracing::span!($crate::__private::tracing::Level::DEBUG, $name, $($fields)*)
            }
            $crate::Level::Trace => {
                $crate::__private::tracing::span!($crate::__private::tracing::Level::TRACE, $name, $($fields)*)
            }
        };
        $crate::SpanGuard { inner: span.entered() }
    }};
}

/// Internal macro to dispatch and process key-value pairs for tracing spans.
/// Uses tt-muncher pattern to transform fields into tracing's native syntax.
/// Arguments: [level] [name] [accumulated_fields] [remaining_input]
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
