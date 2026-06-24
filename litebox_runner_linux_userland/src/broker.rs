// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use std::{
    path::Path,
    time::{Duration, Instant},
};

use anyhow::{Context as _, Result};
use litebox_broker_local::BrokerLocal;
use litebox_broker_transport::unix_socket::UnixStreamLocalControlChannel;

const SETUP_TIMEOUT: Duration = Duration::from_secs(5);
const ACTIVE_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const RETRY_DELAY: Duration = Duration::from_millis(20);
type Local = BrokerLocal<UnixStreamLocalControlChannel>;

pub(crate) struct BrokerConnection {
    local: Local,
}

pub(crate) fn connect(socket_path: Option<&Path>) -> Result<Option<BrokerConnection>> {
    match socket_path {
        Some(path) => connect_to_endpoint(path).map(Some),
        None => Ok(None),
    }
}

impl BrokerConnection {
    pub(crate) fn into_local(self) -> Local {
        self.local
    }
}

fn connect_to_endpoint(socket_path: &Path) -> Result<BrokerConnection> {
    let setup_deadline = Instant::now() + SETUP_TIMEOUT;
    let mut local = connect_with_retry(socket_path, setup_deadline)
        .with_context(|| format!("failed to connect to broker at {}", socket_path.display()))?;
    local
        .control_channel_mut()
        .set_io_timeout(Some(ACTIVE_REQUEST_TIMEOUT))
        .context("failed to configure broker active request timeout")?;
    Ok(BrokerConnection { local })
}

fn connect_with_retry(socket_path: &Path, setup_deadline: Instant) -> Result<Local> {
    loop {
        match UnixStreamLocalControlChannel::connect(socket_path) {
            Ok(mut channel) => {
                channel
                    .set_io_deadline(Some(setup_deadline))
                    .context("failed to configure broker setup deadline")?;
                let local = BrokerLocal::negotiate(channel).context("broker negotiation failed")?;
                return Ok(local);
            }
            Err(error) => {
                if Instant::now() >= setup_deadline {
                    return Err(error).context("timed out connecting to broker");
                }
            }
        }
        let remaining = setup_deadline.saturating_duration_since(Instant::now());
        std::thread::sleep(RETRY_DELAY.min(remaining));
    }
}
