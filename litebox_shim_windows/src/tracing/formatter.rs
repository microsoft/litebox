// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Trace event formatters

use super::config::TraceConfig;
use super::event::TraceEvent;
use std::fmt::Write as FmtWrite;
use std::io::{self, Write};
use std::time::SystemTime;

/// Trait for formatting trace events
pub trait TraceFormatter {
    /// Format a trace event to the output
    fn format(
        &self,
        event: &TraceEvent,
        config: &TraceConfig,
        writer: &mut dyn Write,
    ) -> io::Result<()>;
}

/// Text formatter - human-readable output
pub struct TextFormatter;

impl TextFormatter {
    /// Create a new text formatter
    pub fn new() -> Self {
        Self
    }

    fn format_timestamp(timestamp: SystemTime) -> String {
        match timestamp.duration_since(SystemTime::UNIX_EPOCH) {
            Ok(duration) => {
                let secs = duration.as_secs();
                let millis = duration.subsec_millis();
                format!("{secs}.{millis:03}")
            }
            Err(_) => "0.000".to_string(),
        }
    }
}

impl Default for TextFormatter {
    fn default() -> Self {
        Self::new()
    }
}

impl TraceFormatter for TextFormatter {
    fn format(
        &self,
        event: &TraceEvent,
        config: &TraceConfig,
        writer: &mut dyn Write,
    ) -> io::Result<()> {
        let mut output = String::new();

        // Add timestamp if configured
        if config.include_timestamps {
            write!(output, "[{}] ", Self::format_timestamp(event.timestamp)).unwrap();
        }

        // Add thread ID if configured and available
        if config.include_thread_ids {
            if let Some(tid) = event.thread_id {
                write!(output, "[TID:{tid:04}] ").unwrap();
            } else {
                output.push_str("[TID:main] ");
            }
        }

        // Add event type
        write!(output, "{:<6} ", event.event_type).unwrap();

        // Add function name
        output.push_str(&event.function);

        // Add arguments or return value
        if let Some(ref args) = event.args {
            write!(output, "({args})").unwrap();
        } else {
            output.push_str("()");
        }

        if let Some(ref ret) = event.return_value {
            write!(output, " -> {ret}").unwrap();
        }

        writeln!(writer, "{output}")
    }
}

/// JSON formatter - machine-parseable output
pub struct JsonFormatter;

impl JsonFormatter {
    /// Create a new JSON formatter
    pub fn new() -> Self {
        Self
    }

    fn escape_json_string(s: &str) -> String {
        s.replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('\n', "\\n")
            .replace('\r', "\\r")
            .replace('\t', "\\t")
    }
}

impl Default for JsonFormatter {
    fn default() -> Self {
        Self::new()
    }
}

impl TraceFormatter for JsonFormatter {
    fn format(
        &self,
        event: &TraceEvent,
        config: &TraceConfig,
        writer: &mut dyn Write,
    ) -> io::Result<()> {
        write!(writer, "{{")?;

        // Timestamp
        if config.include_timestamps {
            match event.timestamp.duration_since(SystemTime::UNIX_EPOCH) {
                Ok(duration) => {
                    let secs = duration.as_secs();
                    let nanos = duration.subsec_nanos();
                    write!(writer, "\"timestamp\":{secs}.{nanos:09},")?;
                }
                Err(_) => {
                    write!(writer, "\"timestamp\":0.0,")?;
                }
            }
        }

        // Thread ID
        if config.include_thread_ids {
            if let Some(tid) = event.thread_id {
                write!(writer, "\"thread_id\":{tid},")?;
            } else {
                write!(writer, "\"thread_id\":null,")?;
            }
        }

        // Event type
        let event_type_str = match event.event_type {
            super::event::EventType::Call => "call",
            super::event::EventType::Return => "return",
        };
        write!(writer, "\"event\":\"{event_type_str}\"")?;

        // Category
        write!(writer, ",\"category\":\"{}\"", event.category)?;

        // Function name
        write!(
            writer,
            ",\"function\":\"{}\"",
            Self::escape_json_string(&event.function)
        )?;

        // Arguments
        if let Some(ref args) = event.args {
            write!(writer, ",\"args\":\"{}\"", Self::escape_json_string(args))?;
        }

        // Return value
        if let Some(ref ret) = event.return_value {
            write!(writer, ",\"return\":\"{}\"", Self::escape_json_string(ret))?;
        }

        writeln!(writer, "}}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tracing::event::ApiCategory;

    #[test]
    fn test_text_formatter() {
        let formatter = TextFormatter::new();
        let config = TraceConfig::default();
        let event = TraceEvent::call("NtCreateFile", ApiCategory::FileIo)
            .with_args("path=\"test.txt\", access=GENERIC_READ".to_string());

        let mut output = Vec::new();
        formatter.format(&event, &config, &mut output).unwrap();

        let output_str = String::from_utf8(output).unwrap();
        assert!(output_str.contains("CALL"));
        assert!(output_str.contains("NtCreateFile"));
        assert!(output_str.contains("test.txt"));
    }

    #[test]
    fn test_json_formatter() {
        let formatter = JsonFormatter::new();
        let config = TraceConfig::default();
        let event = TraceEvent::call("NtCreateFile", ApiCategory::FileIo)
            .with_args("path=\"test.txt\"".to_string());

        let mut output = Vec::new();
        formatter.format(&event, &config, &mut output).unwrap();

        let output_str = String::from_utf8(output).unwrap();
        assert!(output_str.contains("\"event\":\"call\""));
        assert!(output_str.contains("\"function\":\"NtCreateFile\""));
        assert!(output_str.contains("\"category\":\"file_io\""));
    }

    #[test]
    fn test_json_escape() {
        assert_eq!(
            JsonFormatter::escape_json_string("test\"quote"),
            "test\\\"quote"
        );
        assert_eq!(
            JsonFormatter::escape_json_string("test\\slash"),
            "test\\\\slash"
        );
        assert_eq!(
            JsonFormatter::escape_json_string("test\nline"),
            "test\\nline"
        );
    }
}
