// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! API tracing framework for Windows syscalls
//!
//! This module provides configurable tracing of Windows API calls for
//! debugging and security analysis.

pub mod config;
pub mod event;
pub mod filter;
pub mod formatter;
pub mod tracer;
pub mod wrapper;

pub use config::{TraceConfig, TraceFormat, TraceOutput};
pub use event::{ApiCategory, EventType, TraceEvent};
pub use filter::{FilterRule, TraceFilter};
pub use formatter::{JsonFormatter, TextFormatter, TraceFormatter};
pub use tracer::Tracer;
pub use wrapper::TracedNtdllApi;
