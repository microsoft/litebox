// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use std::collections::VecDeque;
use std::io::{Error as IoError, ErrorKind, Read as _, Result as IoResult};
use std::sync::Mutex;
use std::sync::mpsc::{Receiver, RecvTimeoutError, SyncSender, TrySendError, sync_channel};
use std::time::Duration;

use litebox_broker_core::AssociationCancellation;
use litebox_broker_core::stdio::{StdioProvider, StdioProviderError};
use litebox_broker_protocol::stdio::{MAX_STDIO_TRANSFER_SIZE, StdioOutputStream, StdioStream};

const CANCELLATION_POLL_INTERVAL: Duration = Duration::from_millis(50);
const WRITE_RETRY_DELAY: Duration = Duration::from_millis(1);

/// Routes standard I/O for the broker's single child runner through inherited
/// streams.
///
/// A broker serving multiple runners will need association-specific stream
/// endpoints instead of sharing process-wide standard streams.
pub(super) struct UserlandStdioProvider {
    stdin: Mutex<StdinState>,
    stdout: SyncSender<StdioWriteOperation>,
    stderr: SyncSender<StdioWriteOperation>,
}

struct StdinState {
    receiver: Option<Receiver<StdinReadResult>>,
    buffered: VecDeque<u8>,
    eof: bool,
}

enum StdinReadResult {
    Data(Vec<u8>),
    Eof,
    Error(StdioProviderError),
}

struct StdioWriteOperation {
    input: Vec<u8>,
    completion: SyncSender<Result<usize, StdioProviderError>>,
}

impl UserlandStdioProvider {
    pub(super) fn new() -> IoResult<Self> {
        let (stdout, stdout_receiver) = sync_channel(super::WORKER_COUNT);
        std::thread::Builder::new()
            .name("litebox-broker-stdout".to_owned())
            .spawn(move || pump_stdout(stdout_receiver))?;
        let (stderr, stderr_receiver) = sync_channel(super::WORKER_COUNT);
        std::thread::Builder::new()
            .name("litebox-broker-stderr".to_owned())
            .spawn(move || pump_stderr(stderr_receiver))?;
        Ok(Self {
            stdin: Mutex::new(StdinState {
                receiver: None,
                buffered: VecDeque::new(),
                eof: false,
            }),
            stdout,
            stderr,
        })
    }
}

impl StdioProvider for UserlandStdioProvider {
    fn is_terminal(&self, stream: StdioStream) -> Result<bool, StdioProviderError> {
        use std::io::IsTerminal as _;

        Ok(match stream {
            StdioStream::Stdin => std::io::stdin().is_terminal(),
            StdioStream::Stdout => std::io::stdout().is_terminal(),
            StdioStream::Stderr => std::io::stderr().is_terminal(),
        })
    }

    fn read(
        &self,
        cancellation: &AssociationCancellation,
        output: &mut [u8],
    ) -> Result<usize, StdioProviderError> {
        if output.is_empty() {
            return Ok(0);
        }
        let mut stdin = self.stdin.lock().map_err(|_| StdioProviderError::Failed)?;
        loop {
            if cancellation.is_cancelled() {
                return Err(StdioProviderError::Closed);
            }
            if !stdin.buffered.is_empty() {
                let read = output.len().min(stdin.buffered.len());
                for destination in &mut output[..read] {
                    *destination = stdin
                        .buffered
                        .pop_front()
                        .expect("buffered stdin length was checked");
                }
                return Ok(read);
            }
            if stdin.eof {
                return Ok(0);
            }
            if stdin.receiver.is_none() {
                let (sender, receiver) = sync_channel(1);
                std::thread::Builder::new()
                    .name("litebox-broker-stdin".to_owned())
                    .spawn(move || pump_stdin(sender))
                    .map_err(|_| StdioProviderError::Failed)?;
                stdin.receiver = Some(receiver);
            }
            match stdin
                .receiver
                .as_ref()
                .expect("stdin pump was started")
                .recv_timeout(CANCELLATION_POLL_INTERVAL)
            {
                Ok(StdinReadResult::Data(data)) => stdin.buffered.extend(data),
                Ok(StdinReadResult::Eof) => stdin.eof = true,
                Ok(StdinReadResult::Error(error)) => return Err(error),
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => return Err(StdioProviderError::Failed),
            }
        }
    }

    fn write(
        &self,
        cancellation: &AssociationCancellation,
        stream: StdioOutputStream,
        input: &[u8],
    ) -> Result<usize, StdioProviderError> {
        let sender = match stream {
            StdioOutputStream::Stdout => &self.stdout,
            StdioOutputStream::Stderr => &self.stderr,
        };
        let (completion, completed) = sync_channel(1);
        let mut request = StdioWriteOperation {
            input: input.to_vec(),
            completion,
        };
        loop {
            if cancellation.is_cancelled() {
                return Err(StdioProviderError::Closed);
            }
            match sender.try_send(request) {
                Ok(()) => break,
                Err(TrySendError::Full(pending)) => request = pending,
                Err(TrySendError::Disconnected(_)) => {
                    return Err(StdioProviderError::Failed);
                }
            }
            std::thread::sleep(WRITE_RETRY_DELAY);
        }
        loop {
            match completed.recv_timeout(CANCELLATION_POLL_INTERVAL) {
                Ok(result) => return result,
                Err(RecvTimeoutError::Timeout) if cancellation.is_cancelled() => {
                    return Err(StdioProviderError::Closed);
                }
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => {
                    return Err(StdioProviderError::Failed);
                }
            }
        }
    }
}

fn pump_stdin(sender: SyncSender<StdinReadResult>) {
    let stdin = std::io::stdin();
    let mut stdin = stdin.lock();
    let mut buffer = vec![0; MAX_STDIO_TRANSFER_SIZE as usize];
    loop {
        let (result, finished) = match stdin.read(&mut buffer) {
            Ok(0) => (StdinReadResult::Eof, true),
            Ok(read) => (StdinReadResult::Data(buffer[..read].to_vec()), false),
            Err(error) if error.kind() == ErrorKind::Interrupted => continue,
            Err(error) => (StdinReadResult::Error(map_stdio_error(error)), true),
        };
        if sender.send(result).is_err() || finished {
            return;
        }
    }
}

fn pump_stdout(receiver: Receiver<StdioWriteOperation>) {
    pump_output(std::io::stdout(), receiver);
}

fn pump_stderr(receiver: Receiver<StdioWriteOperation>) {
    pump_output(std::io::stderr(), receiver);
}

fn pump_output(mut output: impl std::io::Write, receiver: Receiver<StdioWriteOperation>) {
    while let Ok(request) = receiver.recv() {
        let result = write_and_flush(&mut output, &request.input).map_err(map_stdio_error);
        let _ = request.completion.send(result);
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
    use std::sync::Arc;

    use super::*;

    #[derive(Default)]
    struct RecordingOutput {
        bytes: Arc<Mutex<Vec<u8>>>,
        flushes: Arc<Mutex<usize>>,
    }

    impl std::io::Write for RecordingOutput {
        fn write(&mut self, input: &[u8]) -> IoResult<usize> {
            let written = input.len().min(3);
            self.bytes.lock().unwrap().extend(&input[..written]);
            Ok(written)
        }

        fn flush(&mut self) -> IoResult<()> {
            *self.flushes.lock().unwrap() += 1;
            Ok(())
        }
    }

    fn test_stdio_provider(receiver: Receiver<StdinReadResult>) -> UserlandStdioProvider {
        let (stdout, _stdout_receiver) = sync_channel(1);
        let (stderr, _stderr_receiver) = sync_channel(1);
        UserlandStdioProvider {
            stdin: Mutex::new(StdinState {
                receiver: Some(receiver),
                buffered: VecDeque::new(),
                eof: false,
            }),
            stdout,
            stderr,
        }
    }

    #[test]
    fn provider_defers_stdin_pump_until_read() {
        let provider = UserlandStdioProvider::new().unwrap();

        assert!(provider.stdin.lock().unwrap().receiver.is_none());
    }

    #[test]
    fn provider_preserves_partial_reads_and_eof() {
        let (sender, receiver) = sync_channel(2);
        sender
            .send(StdinReadResult::Data(b"input".to_vec()))
            .unwrap();
        sender.send(StdinReadResult::Eof).unwrap();
        let provider = test_stdio_provider(receiver);
        let cancellation = AssociationCancellation::default();

        let mut first = [0xa5; 3];
        assert_eq!(provider.read(&cancellation, &mut first), Ok(3));
        assert_eq!(&first, b"inp");

        let mut second = [0xa5; 4];
        assert_eq!(provider.read(&cancellation, &mut second), Ok(2));
        assert_eq!(&second, b"ut\xa5\xa5");
        assert_eq!(provider.read(&cancellation, &mut second), Ok(0));
    }

    #[test]
    fn provider_waits_for_output_write_and_flush() {
        let bytes = Arc::new(Mutex::new(Vec::new()));
        let flushes = Arc::new(Mutex::new(0));
        let (stdout, stdout_receiver) = sync_channel(1);
        let output = RecordingOutput {
            bytes: Arc::clone(&bytes),
            flushes: Arc::clone(&flushes),
        };
        let writer = std::thread::spawn(move || pump_output(output, stdout_receiver));
        let (_stdin_sender, stdin_receiver) = sync_channel(1);
        let (stderr, _stderr_receiver) = sync_channel(1);
        let provider = UserlandStdioProvider {
            stdin: Mutex::new(StdinState {
                receiver: Some(stdin_receiver),
                buffered: VecDeque::new(),
                eof: false,
            }),
            stdout,
            stderr,
        };

        assert_eq!(
            provider.write(
                &AssociationCancellation::default(),
                StdioOutputStream::Stdout,
                b"prompt",
            ),
            Ok(3)
        );

        drop(provider);
        writer.join().unwrap();
        assert_eq!(*bytes.lock().unwrap(), b"pro");
        assert_eq!(*flushes.lock().unwrap(), 1);
    }
}
