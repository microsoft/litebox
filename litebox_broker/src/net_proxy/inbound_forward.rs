// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};

use tracing::{error, info, warn};

use crate::state_registry::BrokerStateRegistry;

/// An inbound TCP port forward: host listens on a port and hands accepted
/// connections to a matching broker-held listener.
pub(super) struct InboundForward {
    pub(super) listener: TcpListener,
    pub(super) guest_ip: Ipv4Addr,
    pub(super) guest_port: u16,
}

pub(super) enum BrokerHeldAccept {
    Delivered,
    NoListener(TcpStream),
    Rejected,
}

pub(super) fn setup_inbound_listeners(
    inbound_forwards: &[(u16, Ipv4Addr, u16)],
    state_registry: Option<&BrokerStateRegistry>,
) -> Vec<InboundForward> {
    let mut inbound_listeners = Vec::new();

    for (host_port, guest_ip, guest_port) in inbound_forwards {
        match TcpListener::bind(format!("0.0.0.0:{host_port}")) {
            Ok(listener) => {
                listener.set_nonblocking(true).ok();
                info!("inbound TCP forward: host:{host_port} → {guest_ip}:{guest_port}");
                inbound_listeners.push(InboundForward {
                    listener,
                    guest_ip: *guest_ip,
                    guest_port: *guest_port,
                });
                // Tell the broker state registry that this guest port is
                // already serviced by an inbound forwarder so any worker
                // `bind(guest_port)` virtual-binds instead of trying to
                // grab the (already-in-use) host port.
                if let Some(registry) = state_registry {
                    registry.add_inbound_forwarded_port(*guest_port);
                }
            }
            Err(e) => {
                error!("failed to bind inbound forward on port {host_port}: {e}");
            }
        }
    }

    inbound_listeners
}

pub(super) fn try_accept_broker_held(
    fwd: &InboundForward,
    stream: TcpStream,
    peer: SocketAddr,
    state_registry: Option<&BrokerStateRegistry>,
) -> BrokerHeldAccept {
    if let Some(listener) = state_registry
        .and_then(|registry| registry.resolve_broker_held_inet_listener_for_inbound(fwd.guest_port))
    {
        match listener.accept_inbound(stream, peer) {
            Ok(()) => BrokerHeldAccept::Delivered,
            Err(e) => {
                warn!(
                    "broker-held listener rejected host-inbound stream for port {}: {e}",
                    fwd.guest_port
                );
                BrokerHeldAccept::Rejected
            }
        }
    } else {
        BrokerHeldAccept::NoListener(stream)
    }
}
