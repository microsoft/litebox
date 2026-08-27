// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use std::error::Error;
use std::io::Result as IoResult;
use std::os::unix::net::UnixListener;
use std::process::Child;
use std::sync::Arc;
use std::time::Instant;

use litebox_broker_core::{BrokerCore, BrokerCoreLimits, ObjectRights, PolicyEngine};
use litebox_broker_platform_linux_userland::LinuxSocketProvider;
use litebox_broker_protocol::message::{BrokerRequest, BrokerResponse};
use litebox_broker_protocol::shared_buffer::SHARED_BUFFER_POOL_SIZE;
use litebox_broker_transport::channel::HostReceive;
use litebox_broker_transport_linux_userland::memfd::MemfdSharedMemory;
use litebox_broker_transport_linux_userland::unix_socket::{
    UnixControlRingHostRequestSource, UnixControlRingHostResponseSink, UnixControlRingHostShutdown,
    UnixStreamHostSetupChannel, validate_peer_process,
};

use super::{
    HostAssociationShutdown, HostRequestSource, HostResponseSink, SETUP_TIMEOUT,
    configured_socket_policy,
};

impl HostRequestSource for UnixControlRingHostRequestSource {
    fn recv_request(&mut self) -> IoResult<HostReceive<BrokerRequest>> {
        Self::recv_request(self)
    }
}

impl HostResponseSink for UnixControlRingHostResponseSink {
    fn send_response(&self, response: &BrokerResponse) -> IoResult<()> {
        Self::send_response(self, response)
    }
}

impl HostAssociationShutdown for UnixControlRingHostShutdown {
    fn shutdown(&self) -> IoResult<()> {
        Self::shutdown(self)
    }
}

pub(super) fn run(args: super::CliArgs) -> Result<(), Box<dyn Error>> {
    let socket_dir = tempfile::Builder::new()
        .prefix("litebox-broker-userland-")
        .tempdir()?;
    let control_socket_path = socket_dir.path().join("broker.sock");
    let control_listener = UnixListener::bind(&control_socket_path)?;
    control_listener.set_nonblocking(true)?;
    let limits = BrokerCoreLimits::DEFAULT;
    let broker = BrokerCore::new_with_limits(
        PolicyEngine::with_host_guaranteed_rights(ObjectRights::all()).with_socket_policy(
            configured_socket_policy(&args.allow_tcp_destination, &args.allow_udp_destination)?,
        ),
        limits,
        Arc::new(LinuxSocketProvider::new_with_dns_records(
            limits.max_sockets,
            limits.max_sockets_per_session,
            &args.dns_a_record,
        )?),
    )?;

    crate::run_runner_process(
        &args,
        control_socket_path.as_os_str(),
        |runner, runner_process_id| {
            serve_runner(&broker, &control_listener, runner, runner_process_id)
        },
    )
}

fn serve_runner(
    broker: &BrokerCore,
    control_listener: &UnixListener,
    runner: &mut Child,
    runner_process_id: u32,
) -> Result<(), Box<dyn Error>> {
    let setup_deadline = Instant::now() + SETUP_TIMEOUT;
    let control_stream = crate::accept_runner_channel(runner, setup_deadline, "control", || {
        control_listener.accept().map(|(stream, _)| stream)
    })?;
    validate_peer_process(&control_stream, runner_process_id)?;
    let control_channel =
        UnixStreamHostSetupChannel::from_host_guaranteed(control_stream, setup_deadline);
    crate::serve_runner(
        broker,
        control_channel,
        || MemfdSharedMemory::create(SHARED_BUFFER_POOL_SIZE),
        MemfdSharedMemory::create_control_ring,
        |channel, shared_memory, control_memory| {
            channel.send_memfd(shared_memory, Some(setup_deadline))?;
            channel.send_memfd(control_memory, Some(setup_deadline))?;
            Ok(())
        },
        UnixStreamHostSetupChannel::into_active,
    )
}
