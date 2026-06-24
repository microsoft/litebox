// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use std::{
    path::{Path, PathBuf},
    thread,
    time::{Duration, Instant},
};

use anyhow::{Context as _, Result};
use litebox_broker_local::BrokerLocal;
use litebox_broker_transport::unix_socket::UnixStreamLocalControlChannel;

const SETUP_TIMEOUT: Duration = Duration::from_secs(5);
const ACTIVE_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const RETRY_DELAY: Duration = Duration::from_millis(20);
pub(crate) const BROKER_SOCKET_ENV: &str = "LITEBOX_BROKER_SOCKET";
type Local = BrokerLocal<UnixStreamLocalControlChannel>;

pub(crate) struct BrokerConnection {
    local: Local,
}

pub(crate) fn connect() -> Result<Option<BrokerConnection>> {
    match std::env::var_os(BROKER_SOCKET_ENV) {
        Some(socket_path) => connect_to_endpoint(&PathBuf::from(socket_path)).map(Some),
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
        thread::sleep(RETRY_DELAY.min(remaining));
    }
}
