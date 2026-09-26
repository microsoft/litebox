// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Transport for a point-to-point, non-IP byte channel (e.g. a vsock-style hypercall channel),
//! generic over whatever actually backs it.
//!
//! [`ShimTransport`](crate::transport::ShimTransport) is TCP-specific: it goes through
//! [`litebox::net::Network`], a full smoltcp IP stack. A vsock-style channel is not IP traffic
//! and has no address, port, or routing -- it is architecturally a peer to the IP stack, not a
//! mode of it (see `litebox_runner_snp`'s boot-channel design notes). [`PointToPointTransport`]
//! is the transport-agnostic counterpart: it implements the same
//! [`litebox::fs::nine_p::transport::Read`]/`Write` contract `ShimTransport` does, but over any
//! [`ByteChannel`], so the 9P client above it needs no changes at all to run over a real
//! vsock-style channel once one exists.
//!
//! No platform in this repo backs [`ByteChannel`] with a real vsock-style hypercall yet -- see
//! `docs/vsock-boot-channel.md` for the host-side contract a future SEV-SNP implementation would
//! need. This module exists so that day's patch is "implement `ByteChannel` for the real
//! hypercall and switch the call site," not "invent this whole abstraction under pressure."

use litebox::fs::nine_p::transport;

/// A point-to-point, non-IP byte channel: something that can move bytes to and from a single
/// fixed peer, with no addressing of its own.
///
/// Implementations are non-blocking: `try_read`/`try_write` return `Ok(0)` (not an error) when
/// no progress can be made right now, exactly like [`litebox::net::socket_channel::NetworkProxy`]'s
/// `try_read`, so [`PointToPointTransport`] can spin-poll them the same way
/// [`ShimTransport`](crate::transport::ShimTransport) spin-polls its `NetworkProxy`.
pub trait ByteChannel {
    /// Reads up to `buf.len()` bytes. `Ok(0)` means no data is available right now, not EOF --
    /// this channel has no end-of-stream concept, matching a real vsock-style channel's lifetime
    /// being tied to the VM itself, not to a stream close.
    fn try_read(&mut self, buf: &mut [u8]) -> Result<usize, ChannelError>;

    /// Writes up to `buf.len()` bytes. `Ok(0)` means the channel is temporarily full, not an
    /// error -- the caller should retry.
    fn try_write(&mut self, buf: &[u8]) -> Result<usize, ChannelError>;
}

/// Opaque channel failure. [`ByteChannel`] implementations do not need Linux `errno` semantics
/// (there is no guest-visible fd behind this channel -- see [`PointToPointTransport`]'s doc
/// comment), so this carries no payload; callers only need to know the channel is no longer
/// usable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChannelError;

/// A [`litebox::fs::nine_p::transport::Read`]/`Write` implementation over any [`ByteChannel`].
///
/// This is the transport-agnostic sibling of
/// [`ShimTransport`](crate::transport::ShimTransport): where that type is hardwired to a raw TCP
/// `SocketFd`, this type is generic over the channel, so the same spin-poll `Read`/`Write` glue
/// works for a TCP-backed channel, a test mock, or (once implemented) a real vsock-style
/// hypercall channel, without duplicating this code three times.
pub struct PointToPointTransport<C: ByteChannel> {
    channel: C,
}

impl<C: ByteChannel> PointToPointTransport<C> {
    pub fn new(channel: C) -> Self {
        Self { channel }
    }
}

impl<C: ByteChannel> transport::Read for PointToPointTransport<C> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, transport::ReadError> {
        loop {
            match self.channel.try_read(buf) {
                Ok(0) => core::hint::spin_loop(),
                Ok(n) => return Ok(n),
                Err(ChannelError) => return Err(transport::ReadError),
            }
        }
    }
}

impl<C: ByteChannel> transport::Write for PointToPointTransport<C> {
    fn write(&mut self, buf: &[u8]) -> Result<usize, transport::WriteError> {
        loop {
            match self.channel.try_write(buf) {
                Ok(0) => core::hint::spin_loop(),
                Ok(n) => return Ok(n),
                Err(ChannelError) => return Err(transport::WriteError),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use std::sync::mpsc;

    use litebox::fs::nine_p::transport::{Read as _, Write as _};

    use super::*;

    /// An in-process mock [`ByteChannel`], standing in for a real vsock-style hypercall channel:
    /// two byte queues, one per direction, so a pair of these forms a full-duplex pipe between
    /// "guest" and "host" ends -- close enough to a real point-to-point channel's contract
    /// (no addressing, no stream EOF, `Ok(0)` for "nothing right now") to exercise
    /// [`PointToPointTransport`]'s spin-poll logic honestly.
    struct MockChannel {
        outgoing: mpsc::Sender<u8>,
        incoming: mpsc::Receiver<u8>,
    }

    fn mock_pair() -> (MockChannel, MockChannel) {
        let (a_to_b_tx, a_to_b_rx) = mpsc::channel();
        let (b_to_a_tx, b_to_a_rx) = mpsc::channel();
        (
            MockChannel {
                outgoing: a_to_b_tx,
                incoming: b_to_a_rx,
            },
            MockChannel {
                outgoing: b_to_a_tx,
                incoming: a_to_b_rx,
            },
        )
    }

    impl ByteChannel for MockChannel {
        fn try_read(&mut self, buf: &mut [u8]) -> Result<usize, ChannelError> {
            let mut n = 0;
            while n < buf.len() {
                match self.incoming.try_recv() {
                    Ok(byte) => {
                        buf[n] = byte;
                        n += 1;
                    }
                    Err(mpsc::TryRecvError::Empty) => break,
                    Err(mpsc::TryRecvError::Disconnected) => return Err(ChannelError),
                }
            }
            Ok(n)
        }

        fn try_write(&mut self, buf: &[u8]) -> Result<usize, ChannelError> {
            for &byte in buf {
                self.outgoing.send(byte).map_err(|_| ChannelError)?;
            }
            Ok(buf.len())
        }
    }

    #[test]
    fn round_trips_bytes_in_both_directions() {
        let (a, b) = mock_pair();
        let mut guest = PointToPointTransport::new(a);
        let mut host = PointToPointTransport::new(b);

        guest.write_all(b"ping").unwrap();
        let mut buf = [0u8; 4];
        host.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"ping");

        host.write_all(b"pong!").unwrap();
        let mut buf = [0u8; 5];
        guest.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"pong!");
    }

    #[test]
    fn read_spins_rather_than_erroring_when_nothing_is_available_yet() {
        // No writer has sent anything: try_read must return Ok(0), not an error -- `read_exact`
        // must not give up after one empty poll, which is exactly the "spin until the byte a
        // concurrent writer sends a moment later arrives" behavior the boot channel depends on.
        let (a, b) = mock_pair();
        let mut guest_side = a;
        std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(20));
            guest_side.try_write(b"late").unwrap();
        });

        let mut host = PointToPointTransport::new(b);
        let mut buf = [0u8; 4];
        host.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"late");
    }

    #[test]
    fn disconnected_channel_reports_a_transport_error_not_a_hang() {
        let (a, b) = mock_pair();
        drop(a);
        let mut host = PointToPointTransport::new(b);
        let mut buf = [0u8; 1];
        assert!(host.read(&mut buf).is_err());
    }
}
