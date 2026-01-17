//! Tests for the litebox_util_log facade.
//!
//! These tests exercise the unified API and work with either backend.

use litebox_util_log::{
    debug, debug_span, error, error_span, info, info_span, log, span, trace, trace_span, warn,
    warn_span,
};

// Import the private level constants for use with generic log!/span! macros
use litebox_util_log::__private::{LEVEL_DEBUG, LEVEL_ERROR, LEVEL_INFO, LEVEL_TRACE, LEVEL_WARN};

#[test]
fn test_log_macro_simple() {
    log!(LEVEL_INFO, "simple log message");
    log!(LEVEL_ERROR, "error level message");
    log!(LEVEL_WARN, "warning level message");
    log!(LEVEL_DEBUG, "debug level message");
    log!(LEVEL_TRACE, "trace level message");
}

#[test]
fn test_log_macro_with_kv_debug() {
    let value = 42;
    log!(LEVEL_INFO, value:?; "message with debug capture");
    log!(LEVEL_INFO, value:debug; "message with explicit debug");
}

#[test]
fn test_log_macro_with_kv_display() {
    let value = "hello";
    log!(LEVEL_INFO, value:%; "message with display capture");
    log!(LEVEL_INFO, value:display; "message with explicit display");
}

#[test]
fn test_log_macro_with_kv_explicit_value() {
    log!(LEVEL_INFO, count:? = 100; "explicit value");
    log!(LEVEL_INFO, name:% = "test"; "explicit display value");
}

#[test]
fn test_log_macro_with_multiple_kv() {
    let x = 1;
    let y = 2;
    log!(LEVEL_INFO, x:?, y:?; "multiple key-values");
}

#[test]
fn test_log_macro_with_kv_err() {
    let error = "something went wrong";
    log!(LEVEL_ERROR, error:err; "error capture");
}

#[test]
fn test_log_macro_with_kv_sval() {
    let data = vec![1, 2, 3];
    log!(LEVEL_DEBUG, data:sval; "sval capture");
}

#[test]
fn test_log_macro_with_kv_serde() {
    let data = (1, "two", 3.0);
    log!(LEVEL_DEBUG, data:serde; "serde capture");
}

#[test]
fn test_level_specific_macros_simple() {
    error!("error message");
    warn!("warn message");
    info!("info message");
    debug!("debug message");
    trace!("trace message");
}

#[test]
fn test_level_specific_macros_with_kv() {
    let value = 42;
    error!(value:?; "error with kv");
    warn!(value:?; "warn with kv");
    info!(value:?; "info with kv");
    debug!(value:?; "debug with kv");
    trace!(value:?; "trace with kv");
}

#[test]
fn test_span_macro_simple() {
    let _guard = span!(LEVEL_INFO, "test_span");
}

#[test]
fn test_span_macro_with_kv() {
    let request_id = 12345;
    let _guard = span!(LEVEL_INFO, "request_handler", request_id:?);
}

#[test]
fn test_span_level_macros() {
    let _e = error_span!("error_span");
    let _w = warn_span!("warn_span");
    let _i = info_span!("info_span");
    let _d = debug_span!("debug_span");
    let _t = trace_span!("trace_span");
}

#[test]
fn test_span_level_macros_with_kv() {
    let id = 1;
    let _e = error_span!("error_span", id:?);
    let _w = warn_span!("warn_span", id:?);
    let _i = info_span!("info_span", id:?);
    let _d = debug_span!("debug_span", id:?);
    let _t = trace_span!("trace_span", id:?);
}

#[test]
fn test_span_guard_drop() {
    {
        let _guard = info_span!("scoped_span");
        info!("inside span");
    }
    info!("after span dropped");
}

#[test]
fn test_nested_spans() {
    let _outer = info_span!("outer");
    {
        let _inner = debug_span!("inner");
        debug!("in inner span");
    }
    info!("back in outer span");
}

#[test]
fn test_mixed_kv_captures() {
    let debug_val = vec![1, 2, 3];
    let display_val = "hello";
    log!(LEVEL_INFO, debug_val:?, display_val:%; "mixed captures");
}

#[test]
fn test_kv_with_explicit_and_implicit_values() {
    let implicit = 42;
    log!(LEVEL_INFO, implicit:?, explicit:? = 100; "mixed implicit and explicit");
}
