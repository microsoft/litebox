// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Out-of-process macOS broker. The runner is untrusted; only the broker owns
//! host standard streams and the initial filesystem archive.
use std::error::Error;
use std::io::{Error as IoError, ErrorKind};
use std::os::unix::fs::PermissionsExt as _;
use std::os::unix::net::UnixListener;
use std::time::Instant;

use litebox_broker_core::{ObjectRights, PolicyEngine};
use litebox_broker_platform_macos_userland::MacosSyncPrimitivesProvider;
use litebox_broker_protocol::shared_buffer::SHARED_BUFFER_POOL_SIZE;
use litebox_broker_transport_macos_userland::shared_memory::MacosSharedMemory;
use litebox_broker_transport_macos_userland::unix_socket::{
    UnixStreamHostSetupChannel, validate_peer_process,
};
use litebox_broker_userland::builder::BrokerCoreBuilder;

pub(super) fn run(args: super::CliArgs) -> Result<(), Box<dyn Error>> {
    if args.in_process_runner {
        return Err(IoError::new(
            ErrorKind::Unsupported,
            "macOS requires a separate broker process; --in-process-runner is unsupported",
        )
        .into());
    }
    if !args.allow_tcp_destination.is_empty() || !args.allow_udp_destination.is_empty() {
        return Err(IoError::new(
            ErrorKind::Unsupported,
            "the macOS broker does not support host networking",
        )
        .into());
    }
    // Keep the path comfortably below Darwin's 104-byte sockaddr_un limit.
    // Create the directory with mode 0700 rather than relying on the host umask.
    let directory = tempfile::Builder::new()
        .prefix("lb-broker-")
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir_in("/tmp")?;
    let socket_path = directory.path().join("control.sock");
    let listener = UnixListener::bind(&socket_path)?;
    listener.set_nonblocking(true)?;
    let fs = super::create_file_service::<MacosSyncPrimitivesProvider>(
        args.fs_initial_files.as_deref(),
    )?;
    let policy = PolicyEngine::with_host_guaranteed_rights(ObjectRights::all())
        .with_socket_policy(super::configured_socket_policy(&[], &[])?);
    let broker = BrokerCoreBuilder::new(policy)
        .with_file_service(fs)
        .build()?;
    super::run_runner_process(&args, socket_path.as_os_str(), None, |runner, pid| {
        let deadline = Instant::now() + super::SETUP_TIMEOUT;
        let stream = super::accept_runner_channel(
            deadline,
            "control",
            || {
                runner
                    .try_wait()
                    .map(|status| status.map(|status| format!("exited with {status}")))
            },
            || listener.accept().map(|(stream, _)| stream),
        )?;
        // Authenticate before granting HostGuaranteed authority or transferring
        // any descriptors. The child is not reaped/reused during association setup.
        stream.set_nonblocking(false)?; // Darwin accept inherits listener flags.
        validate_peer_process(&stream, pid)?;
        let setup = UnixStreamHostSetupChannel::from_host_guaranteed(stream, deadline);
        litebox_broker_userland::runtime::serve_association(
            &broker,
            setup,
            || MacosSharedMemory::create(SHARED_BUFFER_POOL_SIZE),
            MacosSharedMemory::create_control_ring,
            |channel, buffers, control| {
                channel.send_shared_memory(buffers, Some(deadline))?;
                channel.send_shared_memory(control, Some(deadline))
            },
            UnixStreamHostSetupChannel::into_active,
        )?;
        Ok(())
    })
}
