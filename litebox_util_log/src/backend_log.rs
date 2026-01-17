// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Log backend implementation.
//!
//! This module provides the backend implementation when using the `log` crate
//! with proper structured key-value logging via the `kv` feature.

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

/// Internal macro for log backend implementation.
///
/// This properly uses log's kv feature to pass structured key-value pairs.
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
