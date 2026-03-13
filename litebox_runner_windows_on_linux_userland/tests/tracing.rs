// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Integration tests for API tracing functionality

#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use litebox_platform_linux_for_windows::LinuxPlatformForWindows;
use litebox_shim_windows::syscalls::ntdll::NtdllApi;
use litebox_shim_windows::tracing::{
    ApiCategory, FilterRule, TraceConfig, TraceFilter, TraceFormat, TraceOutput, TracedNtdllApi,
    Tracer,
};
use std::sync::Arc;

/// Test that tracing can be enabled and disabled
#[test]
fn test_tracing_enabled_disabled() {
    // Test with tracing disabled
    let config_disabled = TraceConfig::default();
    assert!(!config_disabled.enabled);

    // Test with tracing enabled
    let config_enabled = TraceConfig::enabled();
    assert!(config_enabled.enabled);
}

/// Test different trace formats
#[test]
fn test_trace_formats() {
    let config_text = TraceConfig::enabled().with_format(TraceFormat::Text);
    assert_eq!(config_text.format, TraceFormat::Text);

    let config_json = TraceConfig::enabled().with_format(TraceFormat::Json);
    assert_eq!(config_json.format, TraceFormat::Json);
}

/// Test trace output destinations
#[test]
fn test_trace_output() {
    let config_stdout = TraceConfig::enabled();
    assert!(matches!(config_stdout.output, TraceOutput::Stdout));

    let config_file = TraceConfig::enabled().with_output(TraceOutput::File("trace.log".into()));
    assert!(matches!(config_file.output, TraceOutput::File(_)));
}

/// Test trace filtering by pattern
#[test]
fn test_trace_filter_pattern() {
    let filter = TraceFilter::new().add_rule(FilterRule::Pattern("Nt*File".to_string()));
    // Filter created successfully
    assert!(format!("{filter:?}").contains("Pattern"));
}

/// Test trace filtering by category
#[test]
fn test_trace_filter_category() {
    let filter = TraceFilter::new().add_rule(FilterRule::Category(vec![ApiCategory::FileIo]));
    // Filter created successfully
    assert!(format!("{filter:?}").contains("Category"));
}

/// Test traced API wrapper with memory operations
#[test]
fn test_traced_memory_operations() {
    // Create a temporary file for trace output
    let temp_dir = std::env::temp_dir();
    let trace_file = temp_dir.join("test_trace_memory.txt");

    // Clean up any existing trace file
    let _ = std::fs::remove_file(&trace_file);

    // Set up tracing to file
    let config = TraceConfig::enabled()
        .with_format(TraceFormat::Text)
        .with_output(TraceOutput::File(trace_file.clone()));

    let filter = TraceFilter::new();
    let tracer = Arc::new(Tracer::new(config, filter).expect("Failed to create tracer"));

    // Create platform and wrap with tracing
    let platform = LinuxPlatformForWindows::new();
    let mut traced_platform = TracedNtdllApi::new(platform, tracer);

    // Perform memory operations that should be traced
    let size = 4096;
    let protect = 0x40; // PAGE_EXECUTE_READWRITE

    // Allocate memory
    let addr = traced_platform
        .nt_allocate_virtual_memory(size, protect)
        .expect("Failed to allocate memory");

    // Free memory
    traced_platform
        .nt_free_virtual_memory(addr, size)
        .expect("Failed to free memory");

    // Drop the traced platform to flush the trace file
    drop(traced_platform);

    // Read the trace file
    let trace_contents = std::fs::read_to_string(&trace_file).expect("Failed to read trace file");

    // Verify the trace contains expected API calls
    assert!(
        trace_contents.contains("NtAllocateVirtualMemory"),
        "Trace should contain NtAllocateVirtualMemory"
    );
    assert!(
        trace_contents.contains("NtFreeVirtualMemory"),
        "Trace should contain NtFreeVirtualMemory"
    );
    assert!(
        trace_contents.contains("CALL"),
        "Trace should contain CALL events"
    );
    assert!(
        trace_contents.contains("RETURN"),
        "Trace should contain RETURN events"
    );

    // Clean up
    let _ = std::fs::remove_file(&trace_file);
}

/// Test traced API wrapper with console operations
#[test]
fn test_traced_console_operations() {
    // Create a temporary file for trace output
    let temp_dir = std::env::temp_dir();
    let trace_file = temp_dir.join("test_trace_console.json");

    // Clean up any existing trace file
    let _ = std::fs::remove_file(&trace_file);

    // Set up tracing to file with JSON format
    let config = TraceConfig::enabled()
        .with_format(TraceFormat::Json)
        .with_output(TraceOutput::File(trace_file.clone()));

    let filter = TraceFilter::new();
    let tracer = Arc::new(Tracer::new(config, filter).expect("Failed to create tracer"));

    // Create platform and wrap with tracing
    let platform = LinuxPlatformForWindows::new();
    let mut traced_platform = TracedNtdllApi::new(platform, tracer);

    // Perform console operation
    let stdout_handle = traced_platform.get_std_output();
    let _ = traced_platform.write_console(stdout_handle, "Test message\n");

    // Drop to flush
    drop(traced_platform);

    // Read the trace file
    let trace_contents = std::fs::read_to_string(&trace_file).expect("Failed to read trace file");

    // Verify JSON format
    assert!(
        trace_contents.contains("\"function\":\"WriteConsole\""),
        "Trace should contain WriteConsole in JSON format"
    );
    assert!(
        trace_contents.contains("\"category\":\"console_io\""),
        "Trace should contain console_io category"
    );
    assert!(
        trace_contents.contains("\"event\":\"call\""),
        "Trace should contain call event"
    );

    // Clean up
    let _ = std::fs::remove_file(&trace_file);
}

/// Test traced API with category filtering
#[test]
fn test_traced_with_category_filter() {
    // Create a temporary file for trace output
    let temp_dir = std::env::temp_dir();
    let trace_file = temp_dir.join("test_trace_filtered.txt");

    // Clean up any existing trace file
    let _ = std::fs::remove_file(&trace_file);

    // Set up tracing with category filter (only memory operations)
    let config = TraceConfig::enabled()
        .with_format(TraceFormat::Text)
        .with_output(TraceOutput::File(trace_file.clone()));

    let filter = TraceFilter::new().add_rule(FilterRule::Category(vec![ApiCategory::Memory]));
    let tracer = Arc::new(Tracer::new(config, filter).expect("Failed to create tracer"));

    // Create platform and wrap with tracing
    let platform = LinuxPlatformForWindows::new();
    let mut traced_platform = TracedNtdllApi::new(platform, tracer);

    // Perform both memory and console operations
    let size = 4096;
    let protect = 0x40;
    let addr = traced_platform
        .nt_allocate_virtual_memory(size, protect)
        .expect("Failed to allocate memory");

    let stdout_handle = traced_platform.get_std_output();
    let _ = traced_platform.write_console(stdout_handle, "Test message\n");

    let _ = traced_platform.nt_free_virtual_memory(addr, size);

    // Drop to flush
    drop(traced_platform);

    // Read the trace file
    let trace_contents = std::fs::read_to_string(&trace_file).expect("Failed to read trace file");

    // Verify only memory operations are traced
    assert!(
        trace_contents.contains("NtAllocateVirtualMemory"),
        "Trace should contain memory operations"
    );
    assert!(
        !trace_contents.contains("WriteConsole"),
        "Trace should NOT contain console operations due to filter"
    );

    // Clean up
    let _ = std::fs::remove_file(&trace_file);
}

/// Test that tracing can be disabled (zero overhead)
#[test]
fn test_tracing_disabled_no_output() {
    // Create a temporary file for trace output
    let temp_dir = std::env::temp_dir();
    let trace_file = temp_dir.join("test_trace_disabled.txt");

    // Clean up any existing trace file
    let _ = std::fs::remove_file(&trace_file);

    // Set up tracing but keep it DISABLED
    let config = TraceConfig::default() // disabled by default
        .with_format(TraceFormat::Text)
        .with_output(TraceOutput::File(trace_file.clone()));

    let filter = TraceFilter::new();
    let tracer = Arc::new(Tracer::new(config, filter).expect("Failed to create tracer"));

    // Create platform and wrap with tracing
    let platform = LinuxPlatformForWindows::new();
    let mut traced_platform = TracedNtdllApi::new(platform, tracer);

    // Perform operations
    let size = 4096;
    let protect = 0x40;
    let addr = traced_platform
        .nt_allocate_virtual_memory(size, protect)
        .expect("Failed to allocate memory");
    let _ = traced_platform.nt_free_virtual_memory(addr, size);

    // Drop to flush
    drop(traced_platform);

    // The trace file should not exist or be empty since tracing is disabled
    if trace_file.exists() {
        let trace_contents = std::fs::read_to_string(&trace_file).expect("Failed to read file");
        assert!(
            trace_contents.is_empty(),
            "Trace file should be empty when tracing is disabled"
        );
    }

    // Clean up
    let _ = std::fs::remove_file(&trace_file);
}
