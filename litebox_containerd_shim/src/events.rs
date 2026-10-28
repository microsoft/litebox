// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Forwarding of task events to containerd, in queue order.

use std::sync::mpsc;
use std::time::Duration;

use containerd_shim::protos::protobuf::MessageDyn;
use containerd_shim::protos::ttrpc::context;
use containerd_shim::publisher::RemotePublisher;

/// Bounds the forwarding of one event.
const PUBLISH_TIMEOUT: Duration = Duration::from_secs(5);

pub(crate) enum Outgoing {
    Event(&'static str, Box<dyn MessageDyn>),
    /// Acknowledges that every earlier event was forwarded or dropped, so that `Shutdown` exits
    /// only after the container's last events.
    Flush(mpsc::SyncSender<()>),
}

/// Forwards queued events to containerd through `publisher` in order. An event that fails is
/// retried once on a new connection to `address`, since containerd may have restarted.
pub(crate) fn publish_events(
    mut publisher: RemotePublisher,
    address: &str,
    namespace: &str,
    outgoing: &mpsc::Receiver<Outgoing>,
) {
    let timeout =
        || context::with_timeout(i64::try_from(PUBLISH_TIMEOUT.as_nanos()).unwrap_or(i64::MAX));
    for message in outgoing {
        let (topic, event) = match message {
            Outgoing::Event(topic, event) => (topic, event),
            Outgoing::Flush(done) => {
                let _ = done.send(());
                continue;
            }
        };
        let Err(error) = publisher.publish(timeout(), topic, namespace, event.clone_box()) else {
            continue;
        };
        log::warn!("cannot publish {topic}, reconnecting: {error}");
        let retried = RemotePublisher::new(address).and_then(|reconnected| {
            publisher = reconnected;
            publisher.publish(timeout(), topic, namespace, event)
        });
        if let Err(error) = retried {
            log::error!("dropping {topic}: {error}");
        }
    }
}
