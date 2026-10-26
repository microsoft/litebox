// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Active control-ring broker associations over a retained setup stream.
//!
//! Once setup has negotiated an association and transferred its control ring,
//! each peer activates its ring endpoints here. Requests, responses, and
//! notifications then move over the ring, and the setup stream is retained
//! only to observe that the peer went away and to signal fail-closed teardown.
//! A hosted deployment supplies that stream by implementing
//! [`AssociationStream`] for its setup channel, such as a Unix-domain socket
//! or a Windows named pipe.

mod host;
mod local;

pub use host::{
    ControlRingHostCallLane, ControlRingHostCallLaneSource, ControlRingHostNotificationChannel,
    ControlRingHostShutdown, activate_host,
};
pub use local::{
    ControlRingLocalCallChannel, ControlRingLocalNotificationChannel, ControlRingLocalShutdown,
    activate_local,
};

use alloc::format;
use alloc::vec::Vec;
use std::io::{Error, ErrorKind};

use litebox_broker_protocol::wire::WireError;

use crate::control_ring::ControlRingError;

/// The setup stream of a broker association, which activation retains for
/// liveness and fail-closed teardown once the control ring carries traffic.
pub trait AssociationStream: Send + Sync {
    /// Reads one setup frame, bounded by the setup deadline.
    ///
    /// Returns `Ok(None)` when the peer closed cleanly on a frame boundary.
    fn read_frame(&mut self) -> Result<Option<Vec<u8>>, Error>;

    /// Writes one setup frame, bounded by the setup deadline.
    fn write_frame(&mut self, frame: &[u8]) -> Result<(), Error>;

    /// Blocks until the stream ends.
    ///
    /// Returns `Ok` once the peer closed the stream or
    /// [`shutdown`](Self::shutdown) ended it, and an error if the peer sent
    /// data or the wait failed.
    fn wait_for_close(&self) -> Result<(), Error>;

    /// Ends the stream in both directions, which ends
    /// [`wait_for_close`](Self::wait_for_close) and lets the peer observe the
    /// close.
    ///
    /// Must tolerate repeated calls and a peer that already closed the stream.
    fn shutdown(&self) -> Result<(), Error>;
}

/// Reads the peer's control-ring setup acknowledgement and checks that it is
/// `ready_token`.
fn read_ready_token(
    stream: &mut dyn AssociationStream,
    ready_token: &[u8],
    peer: &str,
) -> Result<(), Error> {
    let Some(ready) = stream.read_frame()? else {
        return Err(Error::new(
            ErrorKind::UnexpectedEof,
            format!("{peer} closed before control-ring setup acknowledgement"),
        ));
    };
    if ready != ready_token {
        return Err(Error::new(
            ErrorKind::InvalidData,
            format!("{peer} sent an invalid control-ring setup acknowledgement"),
        ));
    }
    Ok(())
}

fn single_lane_layout() -> Error {
    Error::new(
        ErrorKind::InvalidInput,
        "broker control-ring layout has a single lane",
    )
}

/// Maps a decode failure to the fail-closed error both endpoints report.
fn wire_error(error: WireError) -> Error {
    Error::new(
        ErrorKind::InvalidData,
        format!("invalid broker wire message: {error}"),
    )
}

/// Maps a control-ring failure to the fail-closed error both endpoints report.
fn ring_error(error: ControlRingError) -> Error {
    Error::new(
        ErrorKind::InvalidData,
        format!("invalid broker control ring: {error:?}"),
    )
}

#[cfg(test)]
mod tests;
