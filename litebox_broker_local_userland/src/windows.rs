// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use std::ffi::{OsStr, OsString};
use std::io::{Error, ErrorKind, Result as IoResult};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context as _, Result};
use litebox_broker_core::BrokerCore;
use litebox_broker_local::{BrokerLocal, BrokerNotifications};
use litebox_broker_protocol::message::BrokerNotification;
use litebox_broker_protocol::shared_buffer::SHARED_BUFFER_POOL_SIZE;
use litebox_broker_transport::control_ring::ControlRing;
use litebox_broker_transport_windows_userland::control_ring::{
    WindowsControlRingLocalCallChannel, WindowsControlRingLocalNotificationChannel,
};
use litebox_broker_transport_windows_userland::named_pipe::{
    WindowsNamedPipeHostSetupChannel, WindowsNamedPipeListener, WindowsNamedPipeLocalSetupChannel,
    WindowsNamedPipeStream, validate_client_process,
};
use litebox_broker_transport_windows_userland::shared_memory::WindowsSharedMemory;
use windows_sys::Win32::System::Threading::GetCurrentProcess;

use crate::in_process::InProcessHostThread;

const SETUP_TIMEOUT: Duration = Duration::from_secs(5);
const ACCEPT_RETRY_DELAY: Duration = Duration::from_millis(10);

/// An active Windows-userland broker association.
pub struct BrokerConnection {
    /// Synchronous broker request channel.
    pub local: BrokerLocal<WindowsControlRingLocalCallChannel>,
    /// Asynchronous broker notification channel.
    pub notifications: BrokerNotifications<WindowsControlRingLocalNotificationChannel>,
}

/// Connects to and negotiates an association with a Windows-userland broker.
pub fn connect(control_pipe: &OsStr) -> Result<BrokerConnection> {
    let deadline = Instant::now() + SETUP_TIMEOUT;
    let setup =
        WindowsNamedPipeLocalSetupChannel::connect_with_setup_deadline(control_pipe, deadline)
            .with_context(|| {
                format!(
                    "failed to connect to broker at {}",
                    std::path::Path::new(control_pipe).display()
                )
            })?;
    negotiate(setup, None)
}

/// Connects to a broker core hosted in this process over the production
/// Windows named-pipe, shared-section, and control-ring transport.
///
/// Active-association failure shuts down the transport and joins the broker
/// host thread before failure handling returns.
pub fn connect_in_process(broker: &BrokerCore) -> Result<BrokerConnection> {
    let deadline = Instant::now() + SETUP_TIMEOUT;
    let pipe_name = unique_control_pipe_name();
    let listener = WindowsNamedPipeListener::bind(&pipe_name)
        .context("failed to create in-process broker control pipe")?;
    let broker = broker.clone();
    let host_thread = Arc::new(InProcessHostThread::new(
        std::thread::Builder::new()
            .name("litebox-broker-host".to_owned())
            .spawn(move || {
                let control_stream = accept_in_process_client(listener, deadline)?;
                validate_client_process(&control_stream, std::process::id())?;
                let control_channel = WindowsNamedPipeHostSetupChannel::from_host_guaranteed(
                    control_stream,
                    deadline,
                );
                // SAFETY: GetCurrentProcess returns the documented pseudo-handle
                // for the current process and does not transfer ownership.
                let current_process = unsafe { GetCurrentProcess() };
                litebox_broker_userland::runtime::serve_association(
                    &broker,
                    control_channel,
                    || WindowsSharedMemory::create(SHARED_BUFFER_POOL_SIZE),
                    WindowsSharedMemory::create_control_ring,
                    |channel, shared_memory, control_memory| {
                        channel.send_shared_memory(shared_memory, current_process)?;
                        channel.send_shared_memory(control_memory, current_process)
                    },
                    WindowsNamedPipeHostSetupChannel::into_active,
                )
            })
            .context("failed to start in-process broker host")?,
    ));
    let connection =
        WindowsNamedPipeLocalSetupChannel::connect_with_setup_deadline(&pipe_name, deadline)
            .context("failed to connect to in-process broker")
            .and_then(|setup| negotiate(setup, Some(Arc::clone(&host_thread))));
    match connection {
        Ok(connection) => Ok(connection),
        Err(error) => match host_thread.join() {
            Ok(()) => Err(error),
            Err(host_error) => {
                Err(error.context(format!("in-process broker host failed: {host_error}")))
            }
        },
    }
}

fn negotiate(
    setup: WindowsNamedPipeLocalSetupChannel,
    host_thread: Option<Arc<InProcessHostThread>>,
) -> Result<BrokerConnection> {
    let (local, notifications) = BrokerLocal::negotiate(setup, |mut setup| {
        let shared_memory = Arc::new(setup.receive_shared_memory(SHARED_BUFFER_POOL_SIZE)?);
        let control_memory = setup.receive_control_ring()?;
        let control_ring = ControlRing::new(control_memory).map_err(|error| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("invalid broker control ring: {error:?}"),
            )
        })?;
        let (calls, notifications) =
            setup.into_active_with_failure_handler(control_ring, move || {
                if let Some(host_thread) = &host_thread {
                    host_thread.join_and_report();
                }
            })?;
        Ok((calls, shared_memory, notifications))
    })
    .context("broker negotiation failed")?;
    Ok(BrokerConnection {
        local,
        notifications: BrokerNotifications::new(notifications),
    })
}

fn accept_in_process_client(
    mut listener: WindowsNamedPipeListener,
    deadline: Instant,
) -> IoResult<WindowsNamedPipeStream> {
    loop {
        match listener.try_accept() {
            Ok(stream) => return Ok(stream),
            Err(error) if error.kind() == ErrorKind::WouldBlock && Instant::now() < deadline => {
                std::thread::sleep(
                    ACCEPT_RETRY_DELAY.min(deadline.saturating_duration_since(Instant::now())),
                );
            }
            Err(error) if error.kind() == ErrorKind::WouldBlock => {
                return Err(Error::new(
                    ErrorKind::TimedOut,
                    "timed out accepting in-process broker connection",
                ));
            }
            Err(error) => return Err(error),
        }
    }
}

fn unique_control_pipe_name() -> OsString {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!(
        r"\\.\pipe\litebox-in-process-broker-{}-{nonce}",
        std::process::id()
    )
    .into()
}

/// Starts the broker notification receiver for an active association.
pub fn start_notification_receiver(
    mut notifications: BrokerNotifications<WindowsControlRingLocalNotificationChannel>,
    dispatch_notification: impl Fn(BrokerNotification) + Send + 'static,
    dispatch_failure: impl Fn() + Send + 'static,
) -> Result<()> {
    std::thread::Builder::new()
        .name("litebox-broker-notifications".to_owned())
        .spawn(move || {
            let error = loop {
                match notifications.recv_notification() {
                    Ok(Some(notification)) => dispatch_notification(notification),
                    Ok(None) => break None,
                    Err(error) => break Some(error),
                }
            };
            dispatch_failure();
            if let Some(error) = error {
                eprintln!("failed to receive broker notification: {error}");
            }
        })
        .context("failed to start broker notification receiver")?;
    Ok(())
}
