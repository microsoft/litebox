// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Active Windows-userland broker endpoints over a shared control ring.

pub use crate::host::{
    WindowsControlRingHostNotificationChannel, WindowsControlRingHostRequestSource,
    WindowsControlRingHostResponseSink, WindowsControlRingHostShutdown,
};
pub use crate::local::{
    WindowsControlRingLocalCallChannel, WindowsControlRingLocalNotificationChannel,
};

use std::io::{Error, Result as IoResult};
use std::sync::{Arc, Mutex};
use windows_sys::Win32::Foundation::ERROR_PIPE_NOT_CONNECTED;
use windows_sys::Win32::System::Pipes::DisconnectNamedPipe;

use crate::named_pipe::WindowsNamedPipeStream;
use crate::setup::OwnedEvent;

pub(crate) struct PipeLiveness {
    server: bool,
    shutdown_event: OwnedEvent,
    state: Mutex<PipeLivenessState>,
}

struct PipeLivenessState {
    stream: Option<Arc<WindowsNamedPipeStream>>,
    shutdown: bool,
}

impl PipeLiveness {
    pub(crate) fn new(stream: Arc<WindowsNamedPipeStream>, server: bool) -> IoResult<Self> {
        Ok(Self {
            server,
            shutdown_event: OwnedEvent::manual_reset()?,
            state: Mutex::new(PipeLivenessState {
                stream: Some(stream),
                shutdown: false,
            }),
        })
    }

    pub(crate) fn shutdown(&self) -> IoResult<()> {
        let stream = {
            let mut state = self
                .state
                .lock()
                .map_err(|_| Error::other("broker pipe liveness mutex poisoned"))?;
            if state.shutdown {
                return Ok(());
            }
            state.shutdown = true;
            state.stream.take()
        };

        let mut first_error = self.shutdown_event.set().err();
        if self.server
            && let Some(stream) = &stream
        {
            // SAFETY: This is a duplicated server handle for the active named-pipe instance.
            if unsafe { DisconnectNamedPipe(file_handle(stream)) } == 0 {
                let error = Error::last_os_error();
                if error.raw_os_error() != Some(ERROR_PIPE_NOT_CONNECTED.cast_signed())
                    && first_error.is_none()
                {
                    first_error = Some(error);
                }
            }
        }
        drop(stream);
        match first_error {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    pub(crate) fn peer_closed(&self) {
        if let Ok(mut state) = self.state.lock() {
            state.shutdown = true;
            state.stream.take();
        }
    }

    pub(crate) fn shutdown_handle(&self) -> windows_sys::Win32::Foundation::HANDLE {
        self.shutdown_event.handle()
    }
}

fn file_handle(stream: &WindowsNamedPipeStream) -> windows_sys::Win32::Foundation::HANDLE {
    stream.handle()
}
