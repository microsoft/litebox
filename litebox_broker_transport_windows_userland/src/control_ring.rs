// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Active Windows-userland broker endpoints over a shared control ring.

pub use crate::host::{
    WindowsControlRingHostCallLane, WindowsControlRingHostCallLaneSource,
    WindowsControlRingHostNotificationChannel, WindowsControlRingHostShutdown,
};
pub use crate::local::{
    WindowsControlRingLocalCallChannel, WindowsControlRingLocalNotificationChannel,
};

use std::io::{Error, ErrorKind, Result as IoResult};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Instant;

use litebox_broker_transport::ring_association::AssociationStream;
use windows_sys::Win32::Foundation::ERROR_PIPE_NOT_CONNECTED;
use windows_sys::Win32::System::Pipes::DisconnectNamedPipe;

use crate::named_pipe::WindowsNamedPipeStream;
use crate::setup::{OwnedEvent, invalid_data};

/// The setup pipe of a negotiated association, which activation retains for
/// liveness and teardown.
pub(crate) struct PipeAssociationStream {
    /// Whether this end is the pipe server, which disconnects the pipe instance
    /// on shutdown so the client observes it.
    server: bool,
    setup_deadline: Option<Instant>,
    /// Signaled on shutdown to cancel the liveness read.
    shutdown_event: OwnedEvent,
    /// The pipe, or `None` once the association ended, so its handle closes
    /// promptly.
    stream: Mutex<Option<Arc<WindowsNamedPipeStream>>>,
}

impl PipeAssociationStream {
    /// Wraps `stream`, bounding the remaining setup I/O by `setup_deadline`.
    pub(crate) fn new(
        stream: WindowsNamedPipeStream,
        server: bool,
        setup_deadline: Option<Instant>,
    ) -> IoResult<Self> {
        Ok(Self {
            server,
            setup_deadline,
            shutdown_event: OwnedEvent::manual_reset()?,
            stream: Mutex::new(Some(Arc::new(stream))),
        })
    }

    /// Returns the pipe for setup I/O.
    fn setup_stream(&mut self) -> IoResult<&WindowsNamedPipeStream> {
        self.stream
            .get_mut()
            .expect("broker association pipe mutex poisoned")
            .as_deref()
            .ok_or_else(|| {
                Error::new(
                    ErrorKind::NotConnected,
                    "broker association pipe was shut down",
                )
            })
    }

    fn stream(&self) -> MutexGuard<'_, Option<Arc<WindowsNamedPipeStream>>> {
        self.stream
            .lock()
            .expect("broker association pipe mutex poisoned")
    }
}

impl AssociationStream for PipeAssociationStream {
    fn read_frame(&mut self) -> IoResult<Option<Vec<u8>>> {
        let deadline = self.setup_deadline;
        self.setup_stream()?.read_frame(deadline)
    }

    fn write_frame(&mut self, frame: &[u8]) -> IoResult<()> {
        let deadline = self.setup_deadline;
        self.setup_stream()?.write_frame(frame, deadline)
    }

    fn wait_for_close(&self) -> IoResult<()> {
        let Some(stream) = self.stream().clone() else {
            return Ok(());
        };
        let mut byte = [0];
        match stream.read_until_cancelled(&mut byte, &self.shutdown_event) {
            Ok(0) => {
                // The peer closed the pipe, so shutdown needs no disconnect.
                self.stream().take();
                Ok(())
            }
            Ok(_) => Err(invalid_data(
                "peer sent unexpected active control-pipe data",
            )),
            Err(error) if error.kind() == ErrorKind::ConnectionAborted => Ok(()),
            Err(error) => Err(error),
        }
    }

    fn shutdown(&self) -> IoResult<()> {
        let Some(stream) = self.stream().take() else {
            return Ok(());
        };
        let mut first_error = self.shutdown_event.set().err();
        // SAFETY: This is the server handle of the active named-pipe instance.
        if self.server && unsafe { DisconnectNamedPipe(stream.handle()) } == 0 {
            let error = Error::last_os_error();
            if error.raw_os_error() != Some(ERROR_PIPE_NOT_CONNECTED.cast_signed())
                && first_error.is_none()
            {
                first_error = Some(error);
            }
        }
        first_error.map_or(Ok(()), Err)
    }
}
