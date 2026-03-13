// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Main tracer component

use super::{
    config::{TraceConfig, TraceFormat, TraceOutput},
    event::TraceEvent,
    filter::TraceFilter,
    formatter::{JsonFormatter, TextFormatter, TraceFormatter},
};
use std::fs::File;
use std::io::{self, BufWriter, Write};
use std::sync::{Arc, Mutex};

/// Main tracer for API calls
pub struct Tracer {
    config: TraceConfig,
    filter: TraceFilter,
    writer: Arc<Mutex<Box<dyn Write + Send>>>,
    formatter: Box<dyn TraceFormatter + Send + Sync>,
}

impl Tracer {
    /// Create a new tracer with the given configuration
    pub fn new(config: TraceConfig, filter: TraceFilter) -> io::Result<Self> {
        let writer: Box<dyn Write + Send> = match &config.output {
            TraceOutput::Stdout => Box::new(io::stdout()),
            TraceOutput::File(path) => {
                let file = File::create(path)?;
                Box::new(BufWriter::new(file))
            }
        };

        let formatter: Box<dyn TraceFormatter + Send + Sync> = match config.format {
            TraceFormat::Text => Box::new(TextFormatter::new()),
            TraceFormat::Json => Box::new(JsonFormatter::new()),
        };

        Ok(Self {
            config,
            filter,
            writer: Arc::new(Mutex::new(writer)),
            formatter,
        })
    }

    /// Trace an event
    pub fn trace(&self, event: TraceEvent) {
        // Skip if tracing is disabled
        if !self.config.enabled {
            return;
        }

        // Check filter
        if !self.filter.should_trace(&event) {
            return;
        }

        // Format and write the event
        if let Ok(mut writer) = self.writer.lock() {
            let _ = self.formatter.format(&event, &self.config, &mut *writer);
            let _ = writer.flush();
        }
    }

    /// Check if tracing is enabled
    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }
}

impl Default for Tracer {
    fn default() -> Self {
        Self::new(TraceConfig::default(), TraceFilter::default())
            .expect("Failed to create default tracer")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tracing::event::ApiCategory;

    #[test]
    fn test_tracer_disabled() {
        let config = TraceConfig::default(); // disabled by default
        let filter = TraceFilter::default();
        let tracer = Tracer::new(config, filter).unwrap();

        assert!(!tracer.is_enabled());
    }

    #[test]
    fn test_tracer_enabled() {
        let config = TraceConfig::enabled();
        let filter = TraceFilter::default();
        let tracer = Tracer::new(config, filter).unwrap();

        assert!(tracer.is_enabled());
    }

    #[test]
    fn test_tracer_trace_event() {
        let config = TraceConfig::enabled();
        let filter = TraceFilter::default();
        let tracer = Tracer::new(config, filter).unwrap();

        let event = TraceEvent::call("NtCreateFile", ApiCategory::FileIo);
        tracer.trace(event); // Should not panic
    }
}
