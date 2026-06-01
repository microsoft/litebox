// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use std::{
    path::Path,
    thread,
    time::{Duration, Instant},
};

use anyhow::{Context as _, Result};
use litebox_broker_client::BrokerClient;
use litebox_broker_unix_socket::UnixStreamClientControlChannel;

const SETUP_TIMEOUT: Duration = Duration::from_secs(5);
const RETRY_DELAY: Duration = Duration::from_millis(20);

type Client = BrokerClient<UnixStreamClientControlChannel>;

pub(crate) struct BrokerConnection {
    client: Option<Client>,
}

pub(crate) fn connect(socket_path: Option<&Path>) -> Result<Option<BrokerConnection>> {
    match socket_path {
        Some(path) => connect_to_endpoint(path).map(Some),
        None => Ok(None),
    }
}

impl BrokerConnection {
    pub(crate) fn shutdown(mut self) {
        self.client.take();
    }
}

impl Drop for BrokerConnection {
    fn drop(&mut self) {
        self.client.take();
    }
}

fn connect_to_endpoint(socket_path: &Path) -> Result<BrokerConnection> {
    let setup_deadline = Instant::now() + SETUP_TIMEOUT;
    let mut client = connect_with_retry(socket_path, setup_deadline)
        .with_context(|| format!("failed to connect to broker at {}", socket_path.display()))?;
    client
        .control_channel_mut()
        .set_io_deadline(None)
        .context("failed to clear broker setup deadline")?;
    Ok(BrokerConnection {
        client: Some(client),
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
