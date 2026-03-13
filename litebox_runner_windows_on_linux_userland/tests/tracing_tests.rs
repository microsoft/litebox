// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Integration tests for API tracing
#![allow(clippy::similar_names)]

use litebox_platform_linux_for_windows::LinuxPlatformForWindows;
use litebox_shim_windows::syscalls::ntdll::NtdllApi;
use litebox_shim_windows::tracing::{
    ApiCategory, FilterRule, TraceConfig, TraceFilter, TraceFormat, TracedNtdllApi, Tracer,
};
use std::sync::Arc;

#[test]
fn test_tracing_text_format() {
    let config = TraceConfig::enabled().with_format(TraceFormat::Text);
    let filter = TraceFilter::new();
    let tracer = Arc::new(Tracer::new(config, filter).unwrap());

    let platform = LinuxPlatformForWindows::new();
    let mut traced = TracedNtdllApi::new(platform, tracer);

    // This should generate trace output
    let stdout = traced.get_std_output();
    let result = traced.write_console(stdout, "Test message\n");
    assert!(result.is_ok());
}

#[test]
fn test_tracing_filter_by_category() {
    let config = TraceConfig::enabled();
    let filter = TraceFilter::new().add_rule(FilterRule::Category(vec![ApiCategory::ConsoleIo]));
    let tracer = Arc::new(Tracer::new(config, filter).unwrap());

    let platform = LinuxPlatformForWindows::new();
    let mut traced = TracedNtdllApi::new(platform, tracer);

    let stdout = traced.get_std_output();
    let result = traced.write_console(stdout, "Console IO traced\n");
    assert!(result.is_ok());
}
