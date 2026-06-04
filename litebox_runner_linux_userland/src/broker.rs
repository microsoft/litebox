// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use std::{
    net::Shutdown,
    path::Path,
    thread,
    time::{Duration, Instant},
};

use alloc::sync::Arc;
use anyhow::{Context as _, Result};
use litebox::{BrokerControl, BrokerControlError};
use litebox_broker_local::{BrokerClient, BrokerClientWorker};
use litebox_broker_protocol::{BrokerRequest, BrokerResponse, CoreRequest, CoreResponse};
use litebox_broker_transport::unix_socket::UnixStreamClientControlChannel;

const SETUP_TIMEOUT: Duration = Duration::from_secs(5);
const ACTIVE_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const RETRY_DELAY: Duration = Duration::from_millis(20);

type Client = BrokerClient<UnixStreamClientControlChannel>;
type ClientWorker = BrokerClientWorker<UnixStreamClientControlChannel>;

pub(crate) struct BrokerConnection {
    control: Arc<BrokerControlClient>,
}

struct BrokerControlClient {
    worker: ClientWorker,
}

pub(crate) fn connect(socket_path: Option<&Path>) -> Result<Option<BrokerConnection>> {
    match socket_path {
        Some(path) => connect_to_endpoint(path).map(Some),
        None => Ok(None),
    }
}

impl BrokerConnection {
    pub(crate) fn control(&self) -> Arc<dyn BrokerControl> {
        self.control.clone()
    }

    pub(crate) fn shutdown(self) {
        self.control.shutdown();
    }
}

impl Drop for BrokerConnection {
    fn drop(&mut self) {
        self.control.shutdown();
    }
}

impl BrokerControlClient {
    fn new(client: Client, shutdown_stream: std::os::unix::net::UnixStream) -> Self {
        Self {
            worker: BrokerClientWorker::new_with_shutdown_hook(client, move || {
                let _ = shutdown_stream.shutdown(Shutdown::Both);
            }),
        }
    }

    fn shutdown(&self) {
        self.worker.shutdown();
    }
}

impl BrokerControl for BrokerControlClient {
    fn request(
        &self,
        request: CoreRequest,
    ) -> core::result::Result<CoreResponse, BrokerControlError> {
        match self
            .worker
            .active_raw_request(BrokerRequest::Core(request))
            .map_err(|_| BrokerControlError::Transport)?
        {
            BrokerResponse::Core(response) => Ok(response),
            BrokerResponse::Error(error) => Err(BrokerControlError::Broker(error)),
            _ => Err(BrokerControlError::UnexpectedResponse),
        }
    }
}

fn connect_to_endpoint(socket_path: &Path) -> Result<BrokerConnection> {
    let setup_deadline = Instant::now() + SETUP_TIMEOUT;
    let mut client = connect_with_retry(socket_path, setup_deadline)
        .with_context(|| format!("failed to connect to broker at {}", socket_path.display()))?;
    let shutdown_stream = client
        .control_channel_mut()
        .try_clone_stream()
        .context("failed to clone broker control channel for shutdown")?;
    client
        .control_channel_mut()
        .set_io_timeout(Some(ACTIVE_REQUEST_TIMEOUT))
        .context("failed to configure broker active request timeout")?;
    Ok(BrokerConnection {
        control: Arc::new(BrokerControlClient::new(client, shutdown_stream)),
    })
}

fn connect_with_retry(socket_path: &Path, setup_deadline: Instant) -> Result<Client> {
    loop {
        match UnixStreamClientControlChannel::connect(socket_path) {
            Ok(mut channel) => {
                channel
                    .set_io_deadline(Some(setup_deadline))
                    .context("failed to configure broker setup deadline")?;
                let mut client = BrokerClient::new(channel);
                client.negotiate().context("broker negotiation failed")?;
                return Ok(client);
            }
            Err(error) => {
                if Instant::now() >= setup_deadline {
                    return Err(error).context("timed out connecting to broker");
                }
            }
        }
        let remaining = setup_deadline.saturating_duration_since(Instant::now());
        thread::sleep(RETRY_DELAY.min(remaining));
    }
}
