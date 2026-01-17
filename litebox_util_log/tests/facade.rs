//! Tests for the litebox_util_log facade.
//!
//! These tests exercise the unified API and work with either backend.

use litebox_util_log::{
    Level, debug, debug_span, error, error_span, info, info_span, instrument, log, span, trace,
    trace_span, warn, warn_span,
};

#[test]
fn test_log_macro_simple() {
    log!(Level::Info, "simple log message");
    log!(Level::Error, "error level message");
    log!(Level::Warn, "warning level message");
    log!(Level::Debug, "debug level message");
    log!(Level::Trace, "trace level message");
}

#[test]
fn test_log_macro_with_kv_debug() {
    let value = 42;
    log!(Level::Info, value:?; "message with debug capture");
    log!(Level::Info, value:debug; "message with explicit debug");
}

#[test]
fn test_log_macro_with_kv_display() {
    let value = "hello";
    log!(Level::Info, value:%; "message with display capture");
    log!(Level::Info, value:display; "message with explicit display");
}

#[test]
fn test_log_macro_with_kv_explicit_value() {
    log!(Level::Info, count:? = 100; "explicit value");
    log!(Level::Info, name:% = "test"; "explicit display value");
}

#[test]
fn test_log_macro_with_multiple_kv() {
    let x = 1;
    let y = 2;
    log!(Level::Info, x:?, y:?; "multiple key-values");
}

#[test]
#[cfg(feature = "kv_std")]
fn test_log_macro_with_kv_err() {
    let error = "something went wrong";
    log!(Level::Error, error:err; "error capture");
}

#[test]
#[cfg(feature = "kv_sval")]
fn test_log_macro_with_kv_sval() {
    let data = vec![1, 2, 3];
    log!(Level::Debug, data:sval; "sval capture");
}

#[test]
#[cfg(feature = "kv_serde")]
fn test_log_macro_with_kv_serde() {
    let data = (1, "two", 3.0);
    log!(Level::Debug, data:serde; "serde capture");
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
    let _guard = span!(Level::Info, "test_span");
}

#[test]
fn test_span_macro_with_kv() {
    let request_id = 12345;
    let _guard = span!(Level::Info, "request_handler", request_id:?);
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
    log!(Level::Info, debug_val:?, display_val:%; "mixed captures");
}

#[test]
fn test_kv_with_explicit_and_implicit_values() {
    let implicit = 42;
    log!(Level::Info, implicit:?, explicit:? = 100; "mixed implicit and explicit");
}

// =============================================================================
// INSTRUMENT MACRO TESTS
// =============================================================================

#[instrument(level = info)]
fn instrumented_simple() {
    info!("inside instrumented function");
}

#[test]
fn test_instrument_simple() {
    instrumented_simple();
}

#[instrument(level = debug)]
fn instrumented_with_args(x: u32, y: &str) {
    debug!("processing");
    let _ = (x, y);
}

#[test]
fn test_instrument_with_args() {
    instrumented_with_args(42, "hello");
}

#[instrument(level = trace, fields(id:?, name:%))]
fn instrumented_with_specific_fields(id: u64, name: &str, _secret: &str) {
    trace!("handling request");
    let _ = (id, name);
}

#[test]
fn test_instrument_with_specific_fields() {
    instrumented_with_specific_fields(123, "test", "secret_value");
}

#[instrument(level = info, skip(password))]
fn instrumented_with_skip(username: &str, password: &str) {
    info!("authenticating user");
    let _ = (username, password);
}

#[test]
fn test_instrument_with_skip() {
    instrumented_with_skip("alice", "hunter2");
}

#[instrument(level = debug, skip_all)]
fn instrumented_skip_all(sensitive: &str, also_sensitive: u64) {
    debug!("doing something sensitive");
    let _ = (sensitive, also_sensitive);
}

#[test]
fn test_instrument_skip_all() {
    instrumented_skip_all("secret", 42);
}

#[instrument(level = warn, name = "custom_span_name")]
fn instrumented_with_custom_name() {
    warn!("inside custom named span");
}

#[test]
fn test_instrument_custom_name() {
    instrumented_with_custom_name();
}

#[instrument(level = info)]
fn instrumented_returning_value(x: i32) -> i32 {
    x * 2
}

#[test]
fn test_instrument_with_return_value() {
    let result = instrumented_returning_value(21);
    assert_eq!(result, 42);
}

#[instrument(level = debug, fields(a:debug, b:display))]
fn instrumented_with_explicit_capture_modes(a: i32, b: &str) {
    debug!("explicit modes");
    let _ = (a, b);
}

#[test]
fn test_instrument_explicit_capture_modes() {
    instrumented_with_explicit_capture_modes(42, "hello");
}
