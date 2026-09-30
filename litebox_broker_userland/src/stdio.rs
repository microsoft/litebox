// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Inherited host standard streams for userland brokers.

use std::io::{Error as IoError, ErrorKind, Read as _, Result as IoResult};

use litebox_broker_core::stdio::{
    StdioOutputStream, StdioProvider, StdioProviderError, StdioStream,
};

/// Routes standard I/O for the broker's single child runner through inherited
/// streams.
///
/// A broker serving multiple runners will need association-specific stream
/// endpoints instead of sharing process-wide standard streams.
pub struct UserlandStdioProvider;

impl StdioProvider for UserlandStdioProvider {
    fn is_terminal(&self, stream: StdioStream) -> bool {
        use std::io::IsTerminal as _;

        match stream {
            StdioStream::Stdin => std::io::stdin().is_terminal(),
            StdioStream::Stdout => std::io::stdout().is_terminal(),
            StdioStream::Stderr => std::io::stderr().is_terminal(),
        }
    }

    fn read(&self, output: &mut [u8]) -> Result<usize, StdioProviderError> {
        loop {
            match std::io::stdin().read(output) {
                Err(error) if error.kind() == ErrorKind::Interrupted => {}
                result => return result.map_err(map_stdio_error),
            }
        }
    }

    fn write(&self, stream: StdioOutputStream, input: &[u8]) -> Result<usize, StdioProviderError> {
        match stream {
            StdioOutputStream::Stdout => write_and_flush(std::io::stdout().lock(), input),
            StdioOutputStream::Stderr => write_and_flush(std::io::stderr().lock(), input),
        }
        .map_err(map_stdio_error)
    }
}

fn map_stdio_error(error: IoError) -> StdioProviderError {
    if error.kind() == ErrorKind::BrokenPipe {
        StdioProviderError::Closed
    } else {
        StdioProviderError::Failed
    }
}

fn write_and_flush(mut output: impl std::io::Write, input: &[u8]) -> IoResult<usize> {
    let written = output.write(input)?;
    output.flush()?;
    Ok(written)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct RecordingOutput {
        bytes: Vec<u8>,
        flushes: usize,
    }

    impl std::io::Write for RecordingOutput {
        fn write(&mut self, input: &[u8]) -> IoResult<usize> {
            let written = input.len().min(3);
            self.bytes.extend(&input[..written]);
            Ok(written)
        }

        fn flush(&mut self) -> IoResult<()> {
            self.flushes += 1;
            Ok(())
        }
    }

    #[test]
    fn write_reports_partial_writes_and_flushes() {
        let mut output = RecordingOutput::default();

        assert_eq!(write_and_flush(&mut output, b"prompt").unwrap(), 3);
        assert_eq!(output.bytes, b"pro");
        assert_eq!(output.flushes, 1);
    }
}
