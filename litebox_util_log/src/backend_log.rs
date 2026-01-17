// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Log backend implementation.
//!
//! This module provides the backend implementation when using the `log` crate.

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

/// Internal macro for log backend implementation.
#[doc(hidden)]
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
