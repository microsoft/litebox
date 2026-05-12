// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Wire format for the broker→worker notification ring.
//!
//! # Why this exists
//!
//! Phase B of the cross-worker fd-transport plan adds broker-hosted
//! state objects (eventfd, timerfd, signalfd, TCP sockets, ...) that
//! workers reference by opaque [`StateHandle`]. Workers' `epoll_wait`
//! / `poll` paths must wake up when those broker-held state objects
//! change, which means the broker has to push asynchronous events
//! into worker processes.
//!
//! A synchronous `PollWait` RPC over the existing TCP control socket
//! would work correctness-wise but pin worker threads, which we've
//! found is expensive on poll-heavy workloads. Instead, each worker
//! gets a dedicated **notification ring** (one-way, broker → worker)
//! on top of the existing [`crate::shmem_ring`] substrate. When state
//! changes match a subscription, the broker writes one
//! [`NotificationFrame`] to the worker's ring and futex-wakes any
//! reader thread.
//!
//! # Wire format (little-endian)
//!
//! ```text
//!  offset  size  field
//! ───────  ────  ────────────────────────────────────────────────
//!    0      4    magic = 0x544E_424C ("LBNT")          // u32
//!    4      2    version = 1                           // u16
//!    6      2    flags = 0                             // u16 (reserved)
//!    8      8    subscription_id                       // u64
//!   16      4    events (epoll-style bitmask)          // u32
//!   20      4    reserved (must be zero)               // u32
//! ───────
//!   24  total bytes per notification
//! ```
//!
//! Fixed-size, byte-aligned with the shm-ring framing. The
//! `subscription_id` is opaque to this codec — assigned by the
//! worker on `Subscribe`, looked up by the worker on receive.
//!
//! The `events` field uses the same bit layout as Linux's epoll
//! events (POLLIN / POLLOUT / POLLHUP / POLLERR), which is what
//! the worker-side `Pollee` translates into local wake events.
//!
//! # Phase boundary
//!
//! This module is **Phase B-Step3a** of the broker-hosted-state plan:
//! pure data + tests, no I/O. Step 3b will wire it into the broker's
//! ring writer; step 3c will integrate with `StateObject` subscriptions.

/// Wire magic ("LBNT" — LiteBox Notification). Distinct from the
/// data-plane LBFD magic so a wire dump can be unambiguously sorted
/// even on a hypothetical channel that carried both (none do today).
pub const NOTIFICATION_MAGIC: u32 = 0x544E_424C;

/// Wire-format version. Receivers reject mismatched versions.
pub const NOTIFICATION_VERSION: u16 = 1;

/// Total fixed-size length of a notification frame in bytes.
pub const NOTIFICATION_FRAME_LEN: usize = 24;

/// Epoll-style event bit. Matches Linux's `EPOLLIN`.
pub const NOTIFY_EVENT_IN: u32 = 0x0001;
/// Epoll-style event bit. Matches Linux's `EPOLLOUT`.
pub const NOTIFY_EVENT_OUT: u32 = 0x0004;
/// Epoll-style event bit. Matches Linux's `EPOLLERR`.
pub const NOTIFY_EVENT_ERR: u32 = 0x0008;
/// Epoll-style event bit. Matches Linux's `EPOLLHUP`.
pub const NOTIFY_EVENT_HUP: u32 = 0x0010;

/// Bit mask containing every notification event this codec
/// understands. Receivers should reject frames carrying bits outside
/// this mask as malformed.
pub const NOTIFY_EVENT_MASK_ALL: u32 =
    NOTIFY_EVENT_IN | NOTIFY_EVENT_OUT | NOTIFY_EVENT_ERR | NOTIFY_EVENT_HUP;

/// A decoded notification frame. Subscription identity is u64;
/// events ride as an epoll-style bitmask.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NotificationFrame {
    pub subscription_id: u64,
    pub events: u32,
}

/// Errors produced by [`decode_notification`] and [`encode_notification`].
#[derive(Debug, PartialEq, Eq)]
pub enum NotificationError {
    /// Buffer was shorter than [`NOTIFICATION_FRAME_LEN`].
    Truncated { have: usize, need: usize },
    /// Magic word did not match [`NOTIFICATION_MAGIC`].
    BadMagic { found: u32 },
    /// Receiver does not implement the announced version.
    UnsupportedVersion { version: u16 },
    /// `flags` had a non-zero bit set; reserved flags must be zero in
    /// version 1.
    UnknownFlags { flags: u16 },
    /// `events` carried bits outside [`NOTIFY_EVENT_MASK_ALL`]. Treated
    /// as malformed input — a future event bit must come with a
    /// version bump.
    UnknownEvents { events: u32 },
    /// `reserved` field was non-zero. Future versions may use it; in
    /// version 1 it MUST be zero.
    NonZeroReserved { reserved: u32 },
    /// Encoder caller supplied events outside [`NOTIFY_EVENT_MASK_ALL`].
    EncodeUnknownEvents { events: u32 },
}

impl core::fmt::Display for NotificationError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            NotificationError::Truncated { have, need } => {
                write!(f, "notification frame truncated: have {have}, need {need}")
            }
            NotificationError::BadMagic { found } => {
                write!(
                    f,
                    "bad notification magic: 0x{found:08x}, expected 0x{NOTIFICATION_MAGIC:08x}"
                )
            }
            NotificationError::UnsupportedVersion { version } => {
                write!(f, "unsupported notification version: {version}")
            }
            NotificationError::UnknownFlags { flags } => {
                write!(f, "unknown notification flags: 0x{flags:04x}")
            }
            NotificationError::UnknownEvents { events } => {
                write!(
                    f,
                    "unknown event bits in notification: 0x{events:08x} (mask 0x{NOTIFY_EVENT_MASK_ALL:08x})"
                )
            }
            NotificationError::NonZeroReserved { reserved } => {
                write!(
                    f,
                    "non-zero reserved field in notification frame: 0x{reserved:08x}"
                )
            }
            NotificationError::EncodeUnknownEvents { events } => {
                write!(
                    f,
                    "encode events 0x{events:08x} contains bits outside mask 0x{NOTIFY_EVENT_MASK_ALL:08x}"
                )
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for NotificationError {}

/// Encodes a notification frame into a fixed-size byte array.
/// Returns `Err` if `events` contains bits outside
/// [`NOTIFY_EVENT_MASK_ALL`] — callers must mask client-supplied
/// events to the supported set before invoking.
pub fn encode_notification(
    frame: NotificationFrame,
) -> Result<[u8; NOTIFICATION_FRAME_LEN], NotificationError> {
    if frame.events & !NOTIFY_EVENT_MASK_ALL != 0 {
        return Err(NotificationError::EncodeUnknownEvents {
            events: frame.events,
        });
    }
    let mut out = [0u8; NOTIFICATION_FRAME_LEN];
    out[0..4].copy_from_slice(&NOTIFICATION_MAGIC.to_le_bytes());
    out[4..6].copy_from_slice(&NOTIFICATION_VERSION.to_le_bytes());
    out[6..8].copy_from_slice(&0u16.to_le_bytes()); // flags reserved
    out[8..16].copy_from_slice(&frame.subscription_id.to_le_bytes());
    out[16..20].copy_from_slice(&frame.events.to_le_bytes());
    out[20..24].copy_from_slice(&0u32.to_le_bytes()); // reserved
    Ok(out)
}

/// Decodes a notification frame from the first
/// [`NOTIFICATION_FRAME_LEN`] bytes of `buf`. Validates magic,
/// version, flags, reserved-zero, and that `events` lies in
/// [`NOTIFY_EVENT_MASK_ALL`].
pub fn decode_notification(buf: &[u8]) -> Result<NotificationFrame, NotificationError> {
    if buf.len() < NOTIFICATION_FRAME_LEN {
        return Err(NotificationError::Truncated {
            have: buf.len(),
            need: NOTIFICATION_FRAME_LEN,
        });
    }
    let magic = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
    if magic != NOTIFICATION_MAGIC {
        return Err(NotificationError::BadMagic { found: magic });
    }
    let version = u16::from_le_bytes([buf[4], buf[5]]);
    if version != NOTIFICATION_VERSION {
        return Err(NotificationError::UnsupportedVersion { version });
    }
    let flags = u16::from_le_bytes([buf[6], buf[7]]);
    if flags != 0 {
        return Err(NotificationError::UnknownFlags { flags });
    }
    let subscription_id = u64::from_le_bytes([
        buf[8], buf[9], buf[10], buf[11], buf[12], buf[13], buf[14], buf[15],
    ]);
    let events = u32::from_le_bytes([buf[16], buf[17], buf[18], buf[19]]);
    if events & !NOTIFY_EVENT_MASK_ALL != 0 {
        return Err(NotificationError::UnknownEvents { events });
    }
    let reserved = u32::from_le_bytes([buf[20], buf[21], buf[22], buf[23]]);
    if reserved != 0 {
        return Err(NotificationError::NonZeroReserved { reserved });
    }
    Ok(NotificationFrame {
        subscription_id,
        events,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_in_event() {
        let f = NotificationFrame {
            subscription_id: 42,
            events: NOTIFY_EVENT_IN,
        };
        let bytes = encode_notification(f).expect("encode");
        let g = decode_notification(&bytes).expect("decode");
        assert_eq!(f, g);
    }

    #[test]
    fn round_trip_multi_event() {
        let f = NotificationFrame {
            subscription_id: 0xdead_beef_cafe_babe,
            events: NOTIFY_EVENT_IN | NOTIFY_EVENT_OUT | NOTIFY_EVENT_HUP,
        };
        let bytes = encode_notification(f).expect("encode");
        let g = decode_notification(&bytes).expect("decode");
        assert_eq!(f, g);
    }

    #[test]
    fn round_trip_zero_events_ok() {
        // Zero events is meaningless in practice but the codec must
        // accept it for forward compatibility (e.g. heartbeat frames).
        let f = NotificationFrame {
            subscription_id: 1,
            events: 0,
        };
        let bytes = encode_notification(f).expect("encode");
        let g = decode_notification(&bytes).expect("decode");
        assert_eq!(f, g);
    }

    #[test]
    fn encode_rejects_unknown_event_bits() {
        let f = NotificationFrame {
            subscription_id: 1,
            events: 0x8000_0000, // outside the mask
        };
        match encode_notification(f) {
            Err(NotificationError::EncodeUnknownEvents { events }) => {
                assert_eq!(events, 0x8000_0000);
            }
            other => panic!("expected EncodeUnknownEvents, got {other:?}"),
        }
    }

    #[test]
    fn decode_rejects_unknown_event_bits() {
        // Build a frame manually with bits outside the mask.
        let mut bytes = [0u8; NOTIFICATION_FRAME_LEN];
        bytes[0..4].copy_from_slice(&NOTIFICATION_MAGIC.to_le_bytes());
        bytes[4..6].copy_from_slice(&NOTIFICATION_VERSION.to_le_bytes());
        bytes[16..20].copy_from_slice(&0x1000u32.to_le_bytes());
        match decode_notification(&bytes) {
            Err(NotificationError::UnknownEvents { events: 0x1000 }) => {}
            other => panic!("expected UnknownEvents, got {other:?}"),
        }
    }

    #[test]
    fn decode_rejects_truncated_buffer() {
        let bytes = [0u8; NOTIFICATION_FRAME_LEN - 1];
        match decode_notification(&bytes) {
            Err(NotificationError::Truncated { have, need }) => {
                assert_eq!(have, NOTIFICATION_FRAME_LEN - 1);
                assert_eq!(need, NOTIFICATION_FRAME_LEN);
            }
            other => panic!("expected Truncated, got {other:?}"),
        }
    }

    #[test]
    fn decode_rejects_bad_magic() {
        let f = NotificationFrame {
            subscription_id: 1,
            events: NOTIFY_EVENT_IN,
        };
        let mut bytes = encode_notification(f).unwrap();
        bytes[0..4].copy_from_slice(&0xdead_beef_u32.to_le_bytes());
        match decode_notification(&bytes) {
            Err(NotificationError::BadMagic { found: 0xdead_beef }) => {}
            other => panic!("expected BadMagic, got {other:?}"),
        }
    }

    #[test]
    fn decode_rejects_bad_version() {
        let f = NotificationFrame {
            subscription_id: 1,
            events: NOTIFY_EVENT_IN,
        };
        let mut bytes = encode_notification(f).unwrap();
        bytes[4..6].copy_from_slice(&99u16.to_le_bytes());
        match decode_notification(&bytes) {
            Err(NotificationError::UnsupportedVersion { version: 99 }) => {}
            other => panic!("expected UnsupportedVersion, got {other:?}"),
        }
    }

    #[test]
    fn decode_rejects_nonzero_flags() {
        let f = NotificationFrame {
            subscription_id: 1,
            events: NOTIFY_EVENT_IN,
        };
        let mut bytes = encode_notification(f).unwrap();
        bytes[6..8].copy_from_slice(&1u16.to_le_bytes());
        match decode_notification(&bytes) {
            Err(NotificationError::UnknownFlags { flags: 1 }) => {}
            other => panic!("expected UnknownFlags, got {other:?}"),
        }
    }

    #[test]
    fn decode_rejects_nonzero_reserved() {
        let f = NotificationFrame {
            subscription_id: 1,
            events: NOTIFY_EVENT_IN,
        };
        let mut bytes = encode_notification(f).unwrap();
        bytes[20..24].copy_from_slice(&0xcafeu32.to_le_bytes());
        match decode_notification(&bytes) {
            Err(NotificationError::NonZeroReserved { reserved: 0xcafe }) => {}
            other => panic!("expected NonZeroReserved, got {other:?}"),
        }
    }

    #[test]
    fn frame_constants_match_doc() {
        assert_eq!(NOTIFICATION_FRAME_LEN, 24);
        // Magic spells "LBNT" in little-endian.
        assert_eq!(&NOTIFICATION_MAGIC.to_le_bytes(), b"LBNT");
        assert_eq!(NOTIFICATION_VERSION, 1);
        // Event masks match epoll constants on Linux.
        assert_eq!(NOTIFY_EVENT_IN, 0x0001);
        assert_eq!(NOTIFY_EVENT_OUT, 0x0004);
        assert_eq!(NOTIFY_EVENT_ERR, 0x0008);
        assert_eq!(NOTIFY_EVENT_HUP, 0x0010);
        assert_eq!(NOTIFY_EVENT_MASK_ALL, 0x001d);
    }

    #[test]
    fn all_events_combined_round_trip() {
        let f = NotificationFrame {
            subscription_id: u64::MAX,
            events: NOTIFY_EVENT_MASK_ALL,
        };
        let bytes = encode_notification(f).unwrap();
        let g = decode_notification(&bytes).unwrap();
        assert_eq!(f, g);
    }
}
