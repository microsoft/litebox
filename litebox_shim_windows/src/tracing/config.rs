// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Tracing configuration

use std::path::PathBuf;

/// Trace output format
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TraceFormat {
    /// Human-readable text format
    Text,
    /// JSON format for machine parsing
    Json,
}

/// Trace output destination
#[derive(Debug, Clone)]
pub enum TraceOutput {
    /// Output to stdout
    Stdout,
    /// Output to a file
    File(PathBuf),
}

/// Tracing configuration
#[derive(Debug, Clone)]
pub struct TraceConfig {
    /// Whether tracing is enabled
    pub enabled: bool,
    /// Output format
    pub format: TraceFormat,
    /// Output destination
    pub output: TraceOutput,
    /// Include timestamps in traces
    pub include_timestamps: bool,
    /// Include thread IDs in traces
    pub include_thread_ids: bool,
}

impl Default for TraceConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            format: TraceFormat::Text,
            output: TraceOutput::Stdout,
            include_timestamps: true,
            include_thread_ids: true,
        }
    }
}

impl TraceConfig {
    /// Create a new trace configuration with tracing enabled
    pub fn enabled() -> Self {
        Self {
            enabled: true,
            ..Default::default()
        }
    }

    /// Set the output format
    #[must_use]
    pub fn with_format(mut self, format: TraceFormat) -> Self {
        self.format = format;
        self
    }

    /// Set the output destination
    #[must_use]
    pub fn with_output(mut self, output: TraceOutput) -> Self {
        self.output = output;
        self
    }

    /// Enable or disable timestamps
    #[must_use]
    pub fn with_timestamps(mut self, enable: bool) -> Self {
        self.include_timestamps = enable;
        self
    }

    /// Enable or disable thread IDs
    #[must_use]
    pub fn with_thread_ids(mut self, enable: bool) -> Self {
        self.include_thread_ids = enable;
        self
    }
}
