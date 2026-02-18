// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Public logging and span macros.
//!
//! All macros support two forms:
//! - Simple message: `info!("message")`
//! - Key-value pairs with message: `info!(key:? = value; "message")`

/// Log at the specified level.
#[macro_export]
macro_rules! log {
    ($level:expr, $($key:ident $(:$cap:tt)? $(= $value:expr)?),+ ; $msg:literal) => {
        $crate::__log_impl!($level, $($key $(:$cap)? $(= $value)?),+ ; $msg)
    };
    ($level:expr, $msg:literal) => {
        $crate::__log_impl!($level, $msg)
    };
}

/// Create a span at the specified level. Returns a guard that exits the span when dropped.
#[macro_export]
macro_rules! span {
    ($level:expr, $name:expr, $($key:ident $(:$cap:tt)? $(= $value:expr)?),+) => {
        $crate::__span_impl!($level, $name, $($key $(:$cap)? $(= $value)?),+)
    };
    ($level:expr, $name:expr) => {
        $crate::__span_impl!($level, $name)
    };
}

/// Helper macro to work around the inability to use `$` in nested macro definitions.
macro_rules! with_dollar_sign {
    ($($body:tt)*) => {
        macro_rules! __with_dollar_sign { $($body)* }
        __with_dollar_sign!($);
    }
}

macro_rules! define_log_macro {
    ($name:ident, $level:ident) => {
        with_dollar_sign! {
            ($d:tt) => {
                #[doc = concat!("Log at the ", stringify!($level), " level.")]
                #[macro_export]
                macro_rules! $name {
                    ($d( $d key:ident $d(:$d cap:tt)? $d(= $d value:expr)?),+ ; $d msg:literal) => {
                        $crate::__log_impl!($crate::Level::$level, $d( $d key $d(:$d cap)? $d(= $d value)?),+ ; $d msg)
                    };
                    ($d msg:literal) => {
                        $crate::__log_impl!($crate::Level::$level, $d msg)
                    };
                }
            }
        }
    };
}

macro_rules! define_span_macro {
    ($name:ident, $level:ident) => {
        with_dollar_sign! {
            ($d:tt) => {
                #[doc = concat!("Create a ", stringify!($level), "-level span.")]
                #[macro_export]
                macro_rules! $name {
                    ($d name_arg:expr, $d( $d key:ident $d(:$d cap:tt)? $d(= $d value:expr)?),+) => {
                        $crate::span!($crate::Level::$level, $d name_arg, $d( $d key $d(:$d cap)? $d(= $d value)?),+)
                    };
                    ($d name_arg:expr) => {
                        $crate::span!($crate::Level::$level, $d name_arg)
                    };
                }
            }
        }
    };
}

define_log_macro!(error, Error);
define_log_macro!(warn, Warn);
define_log_macro!(info, Info);
define_log_macro!(debug, Debug);
define_log_macro!(trace, Trace);

define_span_macro!(error_span, Error);
define_span_macro!(warn_span, Warn);
define_span_macro!(info_span, Info);
define_span_macro!(debug_span, Debug);
define_span_macro!(trace_span, Trace);
