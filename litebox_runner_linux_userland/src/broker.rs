// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use std::{
    path::Path,
    sync::Mutex,
    thread,
    time::{Duration, Instant},
};

use alloc::sync::Arc;
use anyhow::{Context as _, Result};
use litebox::{BrokerControl, BrokerControlError};
use litebox_broker_local::BrokerLocal;
use litebox_broker_protocol::{BrokerRequest, BrokerResponse, CoreRequest, CoreResponse};
use litebox_broker_transport::unix_socket::UnixStreamLocalControlChannel;

const SETUP_TIMEOUT: Duration = Duration::from_secs(5);
const ACTIVE_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const RETRY_DELAY: Duration = Duration::from_millis(20);
type Local = BrokerLocal<UnixStreamLocalControlChannel>;

pub(crate) struct BrokerConnection {
    control: Arc<BrokerLocalControl>,
}

struct BrokerLocalControl {
    local: Mutex<Local>,
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
}

impl BrokerLocalControl {
    fn new(local: Local) -> Self {
        Self {
            local: Mutex::new(local),
        }
    }
}

impl BrokerControl for BrokerLocalControl {
    fn request(
        &self,
        request: CoreRequest,
    ) -> core::result::Result<CoreResponse, BrokerControlError> {
        match self
            .local
            .lock()
            .map_err(|_| BrokerControlError::Transport)?
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
    let mut local = connect_with_retry(socket_path, setup_deadline)
        .with_context(|| format!("failed to connect to broker at {}", socket_path.display()))?;
    local
        .control_channel_mut()
        .set_io_timeout(Some(ACTIVE_REQUEST_TIMEOUT))
        .context("failed to configure broker active request timeout")?;
    Ok(BrokerConnection {
        control: Arc::new(BrokerLocalControl::new(local)),
    })
}

fn connect_with_retry(socket_path: &Path, setup_deadline: Instant) -> Result<Local> {
    loop {
        match UnixStreamLocalControlChannel::connect(socket_path) {
            Ok(mut channel) => {
                channel
                    .set_io_deadline(Some(setup_deadline))
                    .context("failed to configure broker setup deadline")?;
                let mut local = BrokerLocal::new(channel);
                local.negotiate().context("broker negotiation failed")?;
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
