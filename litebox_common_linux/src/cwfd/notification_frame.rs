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

/// Length of the fixed notification header in bytes.
pub const NOTIFICATION_FRAME_HEADER_LEN: usize = 24;

/// Total fixed-size length of a notification frame in bytes.
pub const NOTIFICATION_FRAME_LEN: usize = NOTIFICATION_FRAME_HEADER_LEN;

/// Frame flags for the fixed event-only variant.
pub const NOTIFICATION_FRAME_FIXED: u16 = 0;
/// Frame flags for the event + opaque length-prefixed payload variant.
pub const NOTIFICATION_FRAME_PAYLOAD: u16 = 1;

/// Maximum opaque payload carried by one notification frame.
pub const NOTIFICATION_PAYLOAD_MAX: usize = 4096;

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

extern crate alloc;
use alloc::vec::Vec;

/// A decoded notification frame. Subscription identity is u64;
/// events ride as an epoll-style bitmask.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NotificationFrame {
    /// Fixed-size event-only notification (the original Phase-B format).
    Fixed { subscription_id: u64, events: u32 },
    /// Event notification carrying an opaque length-prefixed payload.
    Payload {
        subscription_id: u64,
        events: u32,
        payload: Vec<u8>,
    },
}

impl NotificationFrame {
    #[must_use]
    pub const fn fixed(subscription_id: u64, events: u32) -> Self {
        Self::Fixed {
            subscription_id,
            events,
        }
    }

    #[must_use]
    pub fn payload(subscription_id: u64, events: u32, payload: Vec<u8>) -> Self {
        Self::Payload {
            subscription_id,
            events,
            payload,
        }
    }

    #[must_use]
    pub const fn subscription_id(&self) -> u64 {
        match self {
            Self::Fixed {
                subscription_id, ..
            }
            | Self::Payload {
                subscription_id, ..
            } => *subscription_id,
        }
    }

    #[must_use]
    pub const fn events(&self) -> u32 {
        match self {
            Self::Fixed { events, .. } | Self::Payload { events, .. } => *events,
        }
    }

    #[must_use]
    pub fn payload_bytes(&self) -> Option<&[u8]> {
        match self {
            Self::Fixed { .. } => None,
            Self::Payload { payload, .. } => Some(payload),
        }
    }
}

/// Errors produced by [`decode_notification`] and [`encode_notification`].
#[derive(Debug, PartialEq, Eq)]
pub enum NotificationError {
    /// Buffer was shorter than the advertised frame length.
    Truncated { have: usize, need: usize },
    /// Magic word did not match [`NOTIFICATION_MAGIC`].
    BadMagic { found: u32 },
    /// Receiver does not implement the announced version.
    UnsupportedVersion { version: u16 },
    /// `flags` had an unknown bit pattern.
    UnknownFlags { flags: u16 },
    /// `events` carried bits outside [`NOTIFY_EVENT_MASK_ALL`]. Treated
    /// as malformed input — a future event bit must come with a
    /// version bump.
    UnknownEvents { events: u32 },
    /// `reserved` field was non-zero on a fixed frame. Future versions
    /// may use it; in version 1 fixed frames MUST set it to zero.
    NonZeroReserved { reserved: u32 },
    /// Payload length exceeded [`NOTIFICATION_PAYLOAD_MAX`].
    PayloadTooLarge { len: usize, max: usize },
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
            NotificationError::PayloadTooLarge { len, max } => {
                write!(f, "notification payload length {len} exceeds max {max}")
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

/// Encodes a notification frame into bytes.
///
/// Fixed frames retain the original 24-byte wire format. Payload frames
/// use `flags = 1` and store the little-endian payload length in the
/// formerly-reserved word at bytes 20..24, followed by the opaque bytes.
pub fn encode_notification(frame: &NotificationFrame) -> Result<Vec<u8>, NotificationError> {
    if frame.events() & !NOTIFY_EVENT_MASK_ALL != 0 {
        return Err(NotificationError::EncodeUnknownEvents {
            events: frame.events(),
        });
    }
    let payload_len = frame.payload_bytes().map_or(0, <[u8]>::len);
    if payload_len > NOTIFICATION_PAYLOAD_MAX {
        return Err(NotificationError::PayloadTooLarge {
            len: payload_len,
            max: NOTIFICATION_PAYLOAD_MAX,
        });
    }

    let mut out = Vec::with_capacity(NOTIFICATION_FRAME_HEADER_LEN + payload_len);
    out.extend_from_slice(&NOTIFICATION_MAGIC.to_le_bytes());
    out.extend_from_slice(&NOTIFICATION_VERSION.to_le_bytes());
    let flags = if payload_len == 0 && matches!(frame, NotificationFrame::Fixed { .. }) {
        NOTIFICATION_FRAME_FIXED
    } else {
        NOTIFICATION_FRAME_PAYLOAD
    };
    out.extend_from_slice(&flags.to_le_bytes());
    out.extend_from_slice(&frame.subscription_id().to_le_bytes());
    out.extend_from_slice(&frame.events().to_le_bytes());
    #[allow(clippy::cast_possible_truncation)]
    out.extend_from_slice(&(payload_len as u32).to_le_bytes());
    if let Some(payload) = frame.payload_bytes() {
        out.extend_from_slice(payload);
    }
    Ok(out)
}

/// Returns the total encoded length advertised by a notification header.
pub fn encoded_notification_len(header: &[u8]) -> Result<usize, NotificationError> {
    if header.len() < NOTIFICATION_FRAME_HEADER_LEN {
        return Err(NotificationError::Truncated {
            have: header.len(),
            need: NOTIFICATION_FRAME_HEADER_LEN,
        });
    }
    validate_header_prefix(header)?;
    let flags = u16::from_le_bytes([header[6], header[7]]);
    let payload_len = u32::from_le_bytes([header[20], header[21], header[22], header[23]]) as usize;
    match flags {
        NOTIFICATION_FRAME_FIXED => {
            if payload_len != 0 {
                return Err(NotificationError::NonZeroReserved {
                    reserved: payload_len as u32,
                });
            }
            Ok(NOTIFICATION_FRAME_HEADER_LEN)
        }
        NOTIFICATION_FRAME_PAYLOAD => {
            if payload_len > NOTIFICATION_PAYLOAD_MAX {
                return Err(NotificationError::PayloadTooLarge {
                    len: payload_len,
                    max: NOTIFICATION_PAYLOAD_MAX,
                });
            }
            Ok(NOTIFICATION_FRAME_HEADER_LEN + payload_len)
        }
        other => Err(NotificationError::UnknownFlags { flags: other }),
    }
}

/// Decodes a notification frame from `buf`.
pub fn decode_notification(buf: &[u8]) -> Result<NotificationFrame, NotificationError> {
    let need = encoded_notification_len(buf)?;
    if buf.len() < need {
        return Err(NotificationError::Truncated {
            have: buf.len(),
            need,
        });
    }
    let subscription_id = u64::from_le_bytes([
        buf[8], buf[9], buf[10], buf[11], buf[12], buf[13], buf[14], buf[15],
    ]);
    let events = u32::from_le_bytes([buf[16], buf[17], buf[18], buf[19]]);
    if events & !NOTIFY_EVENT_MASK_ALL != 0 {
        return Err(NotificationError::UnknownEvents { events });
    }
    let flags = u16::from_le_bytes([buf[6], buf[7]]);
    match flags {
        NOTIFICATION_FRAME_FIXED => Ok(NotificationFrame::Fixed {
            subscription_id,
            events,
        }),
        NOTIFICATION_FRAME_PAYLOAD => Ok(NotificationFrame::Payload {
            subscription_id,
            events,
            payload: buf[NOTIFICATION_FRAME_HEADER_LEN..need].to_vec(),
        }),
        other => Err(NotificationError::UnknownFlags { flags: other }),
    }
}

fn validate_header_prefix(buf: &[u8]) -> Result<(), NotificationError> {
    let magic = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
    if magic != NOTIFICATION_MAGIC {
        return Err(NotificationError::BadMagic { found: magic });
    }
    let version = u16::from_le_bytes([buf[4], buf[5]]);
    if version != NOTIFICATION_VERSION {
        return Err(NotificationError::UnsupportedVersion { version });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn round_trip_in_event() {
        let f = NotificationFrame::fixed(42, NOTIFY_EVENT_IN);
        let bytes = encode_notification(&f).expect("encode");
        assert_eq!(bytes.len(), NOTIFICATION_FRAME_LEN);
        let g = decode_notification(&bytes).expect("decode");
        assert_eq!(f, g);
    }

    #[test]
    fn round_trip_multi_event() {
        let f = NotificationFrame::fixed(
            0xdead_beef_cafe_babe,
            NOTIFY_EVENT_IN | NOTIFY_EVENT_OUT | NOTIFY_EVENT_HUP,
        );
        let bytes = encode_notification(&f).expect("encode");
        let g = decode_notification(&bytes).expect("decode");
        assert_eq!(f, g);
    }

    #[test]
    fn round_trip_zero_events_ok() {
        let f = NotificationFrame::fixed(1, 0);
        let bytes = encode_notification(&f).expect("encode");
        let g = decode_notification(&bytes).expect("decode");
        assert_eq!(f, g);
    }

    #[test]
    fn round_trip_payload() {
        let payload = (0u8..128).collect::<Vec<_>>();
        let f = NotificationFrame::payload(7, NOTIFY_EVENT_IN, payload.clone());
        let bytes = encode_notification(&f).expect("encode");
        assert_eq!(bytes.len(), NOTIFICATION_FRAME_HEADER_LEN + payload.len());
        assert_eq!(
            encoded_notification_len(&bytes[..NOTIFICATION_FRAME_HEADER_LEN]).unwrap(),
            bytes.len()
        );
        let g = decode_notification(&bytes).expect("decode");
        assert_eq!(g.subscription_id(), 7);
        assert_eq!(g.events(), NOTIFY_EVENT_IN);
        assert_eq!(g.payload_bytes(), Some(payload.as_slice()));
        assert_eq!(f, g);
    }

    #[test]
    fn empty_payload_still_uses_payload_variant() {
        let f = NotificationFrame::payload(9, NOTIFY_EVENT_IN, Vec::new());
        let bytes = encode_notification(&f).expect("encode");
        assert_eq!(
            u16::from_le_bytes([bytes[6], bytes[7]]),
            NOTIFICATION_FRAME_PAYLOAD
        );
        let g = decode_notification(&bytes).expect("decode");
        assert!(matches!(g, NotificationFrame::Payload { .. }));
    }

    #[test]
    fn encode_rejects_unknown_event_bits() {
        let f = NotificationFrame::fixed(1, 0x8000_0000);
        match encode_notification(&f) {
            Err(NotificationError::EncodeUnknownEvents { events }) => {
                assert_eq!(events, 0x8000_0000);
            }
            other => panic!("expected EncodeUnknownEvents, got {other:?}"),
        }
    }

    #[test]
    fn encode_rejects_oversized_payload() {
        let f =
            NotificationFrame::payload(1, NOTIFY_EVENT_IN, vec![0; NOTIFICATION_PAYLOAD_MAX + 1]);
        match encode_notification(&f) {
            Err(NotificationError::PayloadTooLarge { len, max }) => {
                assert_eq!(len, NOTIFICATION_PAYLOAD_MAX + 1);
                assert_eq!(max, NOTIFICATION_PAYLOAD_MAX);
            }
            other => panic!("expected PayloadTooLarge, got {other:?}"),
        }
    }

    #[test]
    fn decode_rejects_unknown_event_bits() {
        let mut bytes = vec![0u8; NOTIFICATION_FRAME_LEN];
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
    fn decode_rejects_truncated_payload() {
        let f = NotificationFrame::payload(1, NOTIFY_EVENT_IN, vec![1, 2, 3, 4]);
        let mut bytes = encode_notification(&f).unwrap();
        bytes.pop();
        match decode_notification(&bytes) {
            Err(NotificationError::Truncated { have, need }) => {
                assert_eq!(have, NOTIFICATION_FRAME_HEADER_LEN + 3);
                assert_eq!(need, NOTIFICATION_FRAME_HEADER_LEN + 4);
            }
            other => panic!("expected Truncated, got {other:?}"),
        }
    }

    #[test]
    fn decode_rejects_bad_magic() {
        let f = NotificationFrame::fixed(1, NOTIFY_EVENT_IN);
        let mut bytes = encode_notification(&f).unwrap();
        bytes[0..4].copy_from_slice(&0xdead_beef_u32.to_le_bytes());
        match decode_notification(&bytes) {
            Err(NotificationError::BadMagic { found: 0xdead_beef }) => {}
            other => panic!("expected BadMagic, got {other:?}"),
        }
    }

    #[test]
    fn decode_rejects_bad_version() {
        let f = NotificationFrame::fixed(1, NOTIFY_EVENT_IN);
        let mut bytes = encode_notification(&f).unwrap();
        bytes[4..6].copy_from_slice(&99u16.to_le_bytes());
        match decode_notification(&bytes) {
            Err(NotificationError::UnsupportedVersion { version: 99 }) => {}
            other => panic!("expected UnsupportedVersion, got {other:?}"),
        }
    }

    #[test]
    fn decode_rejects_bad_flags() {
        let f = NotificationFrame::fixed(1, NOTIFY_EVENT_IN);
        let mut bytes = encode_notification(&f).unwrap();
        bytes[6..8].copy_from_slice(&99u16.to_le_bytes());
        match decode_notification(&bytes) {
            Err(NotificationError::UnknownFlags { flags: 99 }) => {}
            other => panic!("expected UnknownFlags, got {other:?}"),
        }
    }

    #[test]
    fn decode_rejects_nonzero_reserved_on_fixed() {
        let f = NotificationFrame::fixed(1, NOTIFY_EVENT_IN);
        let mut bytes = encode_notification(&f).unwrap();
        bytes[20..24].copy_from_slice(&0xcafeu32.to_le_bytes());
        match decode_notification(&bytes) {
            Err(NotificationError::NonZeroReserved { reserved: 0xcafe }) => {}
            other => panic!("expected NonZeroReserved, got {other:?}"),
        }
    }

    #[test]
    fn frame_constants_match_doc() {
        assert_eq!(NOTIFICATION_FRAME_LEN, 24);
        assert_eq!(&NOTIFICATION_MAGIC.to_le_bytes(), b"LBNT");
        assert_eq!(NOTIFICATION_VERSION, 1);
        assert_eq!(NOTIFY_EVENT_IN, 0x0001);
        assert_eq!(NOTIFY_EVENT_OUT, 0x0004);
        assert_eq!(NOTIFY_EVENT_ERR, 0x0008);
        assert_eq!(NOTIFY_EVENT_HUP, 0x0010);
        assert_eq!(NOTIFY_EVENT_MASK_ALL, 0x001d);
    }

    #[test]
    fn all_events_combined_round_trip() {
        let f = NotificationFrame::fixed(u64::MAX, NOTIFY_EVENT_MASK_ALL);
        let bytes = encode_notification(&f).unwrap();
        let g = decode_notification(&bytes).unwrap();
        assert_eq!(f, g);
    }
}
