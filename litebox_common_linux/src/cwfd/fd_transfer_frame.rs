// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Wire format for cross-worker `SCM_RIGHTS` over the broker-mediated TCP
//! transport in `UnixTransport::Tcp`.
//!
//! # Why this exists
//!
//! Same-worker Unix sockets carry a `Message { data, passed_fds }` directly
//! through an in-memory channel; the `passed_fds` ride alongside the data
//! payload as `Vec<PassedFd>`. Cross-worker Unix sockets, however, are
//! tunnelled through the broker's smoltcp TCP proxy as a raw byte stream
//! (`UnixTransport::Tcp` in `litebox_shim_linux/src/syscalls/unix.rs`).
//! Today that byte stream carries `data` only — `passed_fds` are silently
//! dropped at the send side (see line ~704 of that file). The receiver
//! observes the bytes but never sees the fds, so cross-worker
//! `SCM_RIGHTS` is broken.
//!
//! This module defines a small, length-prefixed framing layer that lets
//! both ends agree on message boundaries *and* an out-of-band fd-token
//! list per message. It carries:
//!
//! - the original `data` payload (verbatim bytes),
//! - the count of passed fds,
//! - a [`PassedToken`] per passed fd — a tagged broker-allocated id.
//!   Each token is encoded on the wire as a `u64`: the low 8 bits carry
//!   a [`SubsystemTag`] discriminator (so the receiver knows what kind
//!   of subsystem entry to construct around the materialised host fd),
//!   and the high 56 bits carry the broker-registry id. 56 bits at
//!   nanosecond allocation is over 2 years — comfortably above any
//!   plausible worker lifetime.
//!
//! A single `UnixTransport::Tcp` carries a sequence of these frames.
//! Stream sockets concatenate frames; seqpacket sockets emit one frame
//! per message. Either way the framing tells the receiver where one
//! `Message` ends and the next begins, which is exactly what the
//! in-memory `Channel` variant gets for free.
//!
//! # Subsystem tag
//!
//! [`SubsystemTag`] is open-ended on purpose. The codec accepts tags it
//! doesn't recognise (surfacing them as [`SubsystemTag::Unknown(u8)`]):
//! this is the constraint required to extend the supported subsystem
//! set later without a wire-version bump. The shim integration treats
//! an unknown tag as a per-fd protocol error (drop that fd, deliver
//! the rest of the message), not a fatal stream error.
//!
//! Initial Phase 3c-ii scope ("Option B"): `Eventfd` and `TcpSocket`.
//! Additional tags (`Pipe`, `File`, `Signalfd`, `Timerfd`, `UnixSocket`)
//! land incrementally as their per-subsystem `host_raw_fd_for_passing` /
//! `from_host_fd` accessors are added.
//!
//! # Wire format (little-endian)
//!
//! ```text
//! offset  size  field
//! ──────  ────  ──────────────────────────────────────────────
//!   0      4    magic = 0x4C42_4644 ("LBFD")        // u32
//!   4      2    version = 1                         // u16
//!   6      2    flags = 0                           // u16 (reserved)
//!   8      4    data_len    (≤ DATA_MAX)            // u32
//!  12      4    fd_count    (≤ FD_COUNT_MAX)        // u32
//!  16      8    token[0]                            // u64 (tag:8 | id:56)
//!  24      8    token[1]                            // u64
//!   …      …    …                                   //
//!  16+8K    L   data[0..L]                          // raw bytes
//! ```
//!
//! Total frame length = `16 + 8 * fd_count + data_len`. A zero-fd
//! frame is the common case and adds 16 bytes of overhead per message.
//!
//! # No regression risk to same-worker traffic
//!
//! `UnixTransport::Channel` does not use this format and is not affected.
//! Phase 3 wires this format only into the `UnixTransport::Tcp` arm of
//! `try_sendto`/`try_recvfrom`.
//!
//! # Phase boundary
//!
//! This module is **Phase 3a** of the cross-worker fd transport plan:
//! pure data + tests, no IPC integration, no broker round-trips. Phase
//! 3b will add broker control opcodes that turn host fds into token ids
//! and back. Phase 3c will plumb `passed_fds` → tokens (via 3b) →
//! frames (this module) → wire → frames → tokens → host fds.

use alloc::vec::Vec;

/// Discriminator byte that tells the receiver what kind of subsystem
/// entry to build around a materialised host fd.
///
/// # Extensibility
///
/// This enum is **open-ended on purpose**. New subsystems get a new
/// `u8` tag value and a new named variant; the decoder accepts unknown
/// tags by surfacing them as [`SubsystemTag::Unknown(u8)`]. The shim
/// integration treats unknown tags as per-fd protocol errors (drop that
/// fd, deliver the rest of the message) — not a fatal stream error —
/// which lets us roll out new subsystems without coordinated upgrades.
///
/// Reserved range: `0` is "Unspecified" (decoder treats it like
/// `Unknown(0)`) so a freshly zero-initialised wire buffer never looks
/// like a valid token. Values `1..=127` are reserved for named
/// subsystems; `128..=255` are reserved for future use (potentially
/// vendor-specific tags).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SubsystemTag {
    /// Linux `eventfd2(2)`-created fd. Wire value `1`.
    Eventfd,
    /// Connected TCP socket. Wire value `2`. (Phase 3c-ii: includes
    /// `SOCK_STREAM` AF_INET / AF_INET6 sockets. Listening sockets are
    /// distinguished only after materialisation via `SO_ACCEPTCONN`.)
    TcpSocket,
    /// Linux pidfd (`pidfd_open(2)`-created). Wire value `3`. P2.B.
    Pidfd,
    /// Linux AF_UNIX socket. Wire value `4`. P2.A. Distinguishes
    /// `SOCK_STREAM` / `SOCK_SEQPACKET` / `SOCK_DGRAM` and
    /// listening-vs-connected only via post-materialise inspection.
    UnixSocket,
    /// Linux `signalfd(2)`-created fd. Wire value `5`. P2.C.
    Signalfd,
    /// Linux `timerfd_create(2)`-created fd. Wire value `6` (future).
    Timerfd,
    /// Linux `inotify_init1(2)`-created fd. Wire value `7` (future).
    Inotify,
    /// Broker-hosted process identity. Wire value `8`. The
    /// [`StateHandle.id`] of a `Process`-tagged entry is the
    /// globally-unique Linux guest pid (truncated to `u32` at the
    /// shim boundary). The payload is empty in the initial phase;
    /// later phases attach parent/children/exit state.
    Process,
    /// Broker-hosted anonymous pipe. Wire value `9`. Phase C.
    Pipe,
    /// Broker-hosted pipe read end for SCM_RIGHTS token transfer. Wire value `14`.
    PipeRead,
    /// Broker-hosted pipe write end for SCM_RIGHTS token transfer. Wire value `15`.
    PipeWrite,
    /// Broker-hosted pseudo-terminal endpoint. Wire value `10`.
    /// Phase E reserves this tag for PTY master/slave identity that
    /// must survive cross-worker `exec_on_remote_host`.
    Pty,
    /// Broker-hosted TCP listener. Wire value `11`. Phase A.
    InetListener,
    /// Broker-hosted UDP datagram socket. Wire value `12`. Phase C.
    InetDgram,
    /// Broker-hosted raw IPv4 socket. Wire value `13`. Phase D.
    InetRaw,
    /// Broker-hosted attached host fd. Wire value `16`. Phase 3:
    /// the worker (or parent) SCM_RIGHTS-passes a host fd into the
    /// broker; the broker owns it thereafter and exposes a
    /// pipe-shaped read/write surface for it. Used by the
    /// legacy-pipes phase-3 migration to retire the mux relay's
    /// `--pipe-bridge` (host-fd-passthrough) topology.
    HostFd,
    /// Broker OFD-registry file token. Wire value `17`. Used by broker-backed
    /// AF_UNIX datagram SCM_RIGHTS to reconstruct a 9P file fid that shares the
    /// sender's open file description.
    File,
    /// Tag that this receiver doesn't recognise. Carries the raw u8
    /// value so the receiver can log diagnostics; callers should reject
    /// the specific fd while continuing to deliver the rest of the
    /// message.
    Unknown(u8),
}

impl SubsystemTag {
    /// Wire byte for this tag.
    pub fn as_u8(self) -> u8 {
        match self {
            SubsystemTag::Eventfd => 1,
            SubsystemTag::TcpSocket => 2,
            SubsystemTag::Pidfd => 3,
            SubsystemTag::UnixSocket => 4,
            SubsystemTag::Signalfd => 5,
            SubsystemTag::Timerfd => 6,
            SubsystemTag::Inotify => 7,
            SubsystemTag::Process => 8,
            SubsystemTag::Pipe => 9,
            SubsystemTag::Pty => 10,
            SubsystemTag::InetListener => 11,
            SubsystemTag::InetDgram => 12,
            SubsystemTag::InetRaw => 13,
            SubsystemTag::PipeRead => 14,
            SubsystemTag::PipeWrite => 15,
            SubsystemTag::HostFd => 16,
            SubsystemTag::File => 17,
            SubsystemTag::Unknown(v) => v,
        }
    }

    /// Decodes a wire byte. Never fails: unknown values surface as
    /// `Unknown(raw)` rather than an error, so a single unrecognised
    /// fd doesn't sink the surrounding message.
    pub fn from_u8(raw: u8) -> Self {
        match raw {
            1 => SubsystemTag::Eventfd,
            2 => SubsystemTag::TcpSocket,
            3 => SubsystemTag::Pidfd,
            4 => SubsystemTag::UnixSocket,
            5 => SubsystemTag::Signalfd,
            6 => SubsystemTag::Timerfd,
            7 => SubsystemTag::Inotify,
            8 => SubsystemTag::Process,
            9 => SubsystemTag::Pipe,
            10 => SubsystemTag::Pty,
            11 => SubsystemTag::InetListener,
            12 => SubsystemTag::InetDgram,
            13 => SubsystemTag::InetRaw,
            14 => SubsystemTag::PipeRead,
            15 => SubsystemTag::PipeWrite,
            16 => SubsystemTag::HostFd,
            17 => SubsystemTag::File,
            other => SubsystemTag::Unknown(other),
        }
    }

    /// True iff this tag is a named (known) subsystem this build
    /// understands. Callers use this to decide whether to attempt
    /// `from_host_fd` construction or to fail-soft on the receive path.
    pub fn is_known(self) -> bool {
        !matches!(self, SubsystemTag::Unknown(_))
    }
}

/// A broker-allocated fd token tagged with the receiving subsystem.
///
/// Encoded on the wire as a single `u64`: the low 8 bits carry the
/// [`SubsystemTag`] and the high 56 bits carry the broker registry id.
/// 56-bit id space at nanosecond allocation rate covers > 2 years —
/// effectively unlimited at any plausible worker lifetime.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PassedToken(u64);

/// Maximum broker token id encodable in [`PassedToken`]: `2^56 - 1`.
pub const PASSED_TOKEN_MAX_ID: u64 = (1u64 << 56) - 1;

impl PassedToken {
    /// Constructs a token from a tag and a broker id. Returns
    /// [`FrameError::EncodeIdTooLarge`] if `id` exceeds
    /// [`PASSED_TOKEN_MAX_ID`]; broker token-id allocation is monotonic
    /// from 1, so callers can safely treat overflow as a long-term
    /// invariant violation rather than a hot-path concern.
    pub fn new(tag: SubsystemTag, id: u64) -> Result<Self, FrameError> {
        if id > PASSED_TOKEN_MAX_ID {
            return Err(FrameError::EncodeIdTooLarge { id });
        }
        Ok(Self((id << 8) | u64::from(tag.as_u8())))
    }

    /// Reconstructs a token from its raw u64 wire encoding. No validation —
    /// any u64 maps to *some* token, with `tag` possibly `Unknown(_)`.
    pub fn from_raw(raw: u64) -> Self {
        Self(raw)
    }

    /// Raw u64 wire encoding (low byte = tag, high 56 bits = id).
    pub fn raw(self) -> u64 {
        self.0
    }

    /// Subsystem tag.
    pub fn tag(self) -> SubsystemTag {
        #[allow(clippy::cast_possible_truncation)]
        SubsystemTag::from_u8((self.0 & 0xff) as u8)
    }

    /// Broker registry id (56 bits).
    pub fn id(self) -> u64 {
        self.0 >> 8
    }
}

/// A buffer-accumulating reader for [`FdTransferFrame`]s arriving on a
/// byte stream in arbitrary-sized chunks.
///
/// The receive side of `UnixTransport::Tcp` reads bytes from a smoltcp
/// TCP stream. Those bytes carry an unbroken sequence of LBFD frames,
/// but `try_read` may surface them in chunks that don't align to frame
/// boundaries. `FdTransferReader` hides that: callers
///
/// 1. invoke [`push`](Self::push) for each freshly-received chunk;
/// 2. invoke [`take_frame`](Self::take_frame) until it returns `None`,
///    yielding one decoded frame's worth of `(tokens, data)` per call.
///
/// State is kept across calls in an internal `Vec<u8>`. Once a complete
/// frame's worth of bytes has been consumed, the buffer compacts the
/// remaining tail in place so memory does not grow without bound.
///
/// Phase 3c-i.2: pure state, no I/O. Phase 3c-ii will instantiate one
/// `FdTransferReader` per `UnixTransport::Tcp` and feed it the bytes
/// returned by `proxy.try_read`.
pub struct FdTransferReader {
    buf: Vec<u8>,
}

/// One frame's worth of payload extracted by
/// [`FdTransferReader::take_frame`]. Both `tokens` and `data` are owned
/// because the underlying buffer slot may be compacted on the next
/// `push` / `take_frame`; returning slices would tie the caller's hands.
#[derive(Debug, PartialEq, Eq)]
pub struct OwnedFrame {
    pub tokens: Vec<PassedToken>,
    pub data: Vec<u8>,
}

/// A single unit pulled from a mixed framed/raw byte stream by
/// [`FdTransferReader::take_unit`].
///
/// Stream transports (the broker AF_UNIX `SOCK_STREAM` socketpair and
/// named unix-stream) carry SCM-bearing LBFD frames *interleaved* with
/// ordinary unframed `write(2)` bytes, and `read(2)` boundaries split or
/// coalesce them arbitrarily. `take_unit` resynchronises the stream one
/// unit at a time.
#[derive(Debug, PartialEq, Eq)]
pub enum ReaderUnit {
    /// A complete decoded frame; its bytes have been consumed.
    Frame(OwnedFrame),
    /// A run of raw, non-framed bytes (consumed). They precede the next
    /// frame magic, or are trailing bytes when no frame follows.
    Raw(Vec<u8>),
    /// Not enough buffered bytes to decide yet — `push` more and retry.
    NeedMore,
}

impl Default for FdTransferReader {
    fn default() -> Self {
        Self::new()
    }
}

impl FdTransferReader {
    /// Creates an empty reader.
    pub fn new() -> Self {
        Self { buf: Vec::new() }
    }

    /// Returns the number of buffered bytes not yet consumed by
    /// [`take_frame`]. Intended for telemetry / tests; not part of the
    /// production wire protocol.
    pub fn buffered_bytes(&self) -> usize {
        self.buf.len()
    }

    /// Appends `chunk` to the internal buffer. Cheap (`extend_from_slice`).
    pub fn push(&mut self, chunk: &[u8]) {
        self.buf.extend_from_slice(chunk);
    }

    /// Tries to extract one complete frame from the front of the
    /// buffer.
    ///
    /// Returns:
    /// - `Ok(Some(OwnedFrame))` when a full frame is available; the
    ///   bytes for that frame are removed from the buffer.
    /// - `Ok(None)` when not enough bytes are buffered yet for either
    ///   a complete header or a complete body. The caller should
    ///   `push` more bytes and try again.
    /// - `Err(FrameError)` when the frame is structurally malformed
    ///   (bad magic, unsupported version, oversized fields). The
    ///   buffer state on a malformed frame is undefined and the caller
    ///   SHOULD treat the stream as unrecoverable (close the
    ///   underlying transport).
    pub fn take_frame(&mut self) -> Result<Option<OwnedFrame>, FrameError> {
        match decode_frame(&self.buf) {
            Ok(decoded) => {
                let consumed = decoded.consumed;
                let tokens = decoded.tokens;
                let data = decoded.data.to_vec();
                // Compact the buffer in place: drop the consumed prefix.
                self.buf.drain(..consumed);
                Ok(Some(OwnedFrame { tokens, data }))
            }
            Err(FrameError::HeaderTruncated { .. } | FrameError::BodyTruncated { .. }) => Ok(None),
            Err(other) => Err(other),
        }
    }

    /// Extract the next [`ReaderUnit`] from the front of the buffer,
    /// transparently separating interleaved LBFD frames from raw bytes
    /// across arbitrary `read(2)` chunking.
    ///
    /// Semantics:
    /// - Buffer empty → [`ReaderUnit::NeedMore`].
    /// - Begins with [`FRAME_MAGIC`] and a full frame is buffered →
    ///   [`ReaderUnit::Frame`] (bytes consumed).
    /// - Begins with the magic but the frame body has not fully arrived →
    ///   [`ReaderUnit::NeedMore`].
    /// - Begins with the magic but the frame is structurally malformed (a
    ///   false-positive magic embedded in raw data, or genuine
    ///   corruption) → one raw byte is yielded so the stream
    ///   resynchronises (`decode_frame` bounds every length field, so this
    ///   cannot mistake garbage for an unbounded truncated body).
    /// - Otherwise the leading non-framed bytes up to the next magic
    ///   occurrence are returned as [`ReaderUnit::Raw`]. A 1..=3-byte
    ///   partial magic at the very tail is retained (it may be the head of
    ///   an as-yet-incomplete frame); if that prefix is all that remains,
    ///   [`ReaderUnit::NeedMore`] is returned.
    pub fn take_unit(&mut self) -> ReaderUnit {
        let magic = FRAME_MAGIC.to_le_bytes();
        let n = self.buf.len();
        if n == 0 {
            return ReaderUnit::NeedMore;
        }
        let starts_with_magic = n >= 4 && self.buf[..4] == magic;
        if starts_with_magic {
            return match decode_frame(&self.buf) {
                Ok(decoded) => {
                    let frame = OwnedFrame {
                        tokens: decoded.tokens,
                        data: decoded.data.to_vec(),
                    };
                    self.buf.drain(..decoded.consumed);
                    ReaderUnit::Frame(frame)
                }
                Err(FrameError::HeaderTruncated { .. } | FrameError::BodyTruncated { .. }) => {
                    ReaderUnit::NeedMore
                }
                Err(_) => {
                    // Valid magic word but malformed frame: treat the lead
                    // byte as raw and resync.
                    let b = self.buf.remove(0);
                    ReaderUnit::Raw(alloc::vec![b])
                }
            };
        }
        // Does not begin with a full magic. If the whole (short) buffer is
        // a strict prefix of the magic, it might be a frame head still
        // arriving — wait for more.
        if n < 4 && self.buf[..] == magic[..n] {
            return ReaderUnit::NeedMore;
        }
        // Raw run: bytes up to the next full magic occurrence (scan from
        // offset 1 since offset 0 is known not to start a full magic).
        let mut i = 1usize;
        let mut found = None;
        while i + 4 <= n {
            if self.buf[i..i + 4] == magic {
                found = Some(i);
                break;
            }
            i += 1;
        }
        let cut = if let Some(f) = found {
            f
        } else {
            // Retain a trailing partial-magic prefix (1..=3 bytes).
            let maxp = core::cmp::min(3, n);
            let mut keep = 0usize;
            for p in (1..=maxp).rev() {
                if self.buf[n - p..] == magic[..p] {
                    keep = p;
                    break;
                }
            }
            n - keep
        };
        if cut == 0 {
            return ReaderUnit::NeedMore;
        }
        let raw: Vec<u8> = self.buf[..cut].to_vec();
        self.buf.drain(..cut);
        ReaderUnit::Raw(raw)
    }
}

/// Per-endpoint receive-side reassembly for the in-band LBFD framing used
/// to carry `SCM_RIGHTS` fd tokens over a byte-stream transport (the
/// broker AF_UNIX `SOCK_STREAM` socketpair and named unix-stream).
///
/// Framed (fd-bearing) and unframed writes interleave on the stream and
/// `read(2)` boundaries coalesce or split them arbitrarily, so the reader
/// must persist across `recvmsg` calls. The pre-fix code rebuilt a fresh
/// [`FdTransferReader`] per call and decoded only one frame, silently
/// dropping every coalesced frame after the first — the bug that stalled
/// VS Code's exthost handle passing.
///
/// [`read_unit`](Self::read_unit) returns exactly one stream *unit* per
/// call (one frame's data + its tokens, or a run of raw bytes), matching
/// Linux's per-ancillary-boundary `SOCK_STREAM` delivery, and buffers any
/// payload that overran the caller's buffer.
#[derive(Default)]
pub struct StreamScmDeframer {
    reader: FdTransferReader,
    /// Decoded data bytes not yet delivered because they overran a
    /// caller's buffer. Returned (token-less) on subsequent reads.
    pending: Vec<u8>,
}

impl StreamScmDeframer {
    /// 60 KiB staging chunk per `fill`, matching the broker socketpair /
    /// unix-stream per-RPC read cap.
    const STAGE: usize = 60 * 1024;

    pub fn new() -> Self {
        Self::default()
    }

    /// Deframe one stream unit into `buf`, returning `(bytes_copied,
    /// tokens)`. `fill(staging)` reads up to `staging.len()` raw bytes
    /// from the underlying transport (returning `0` on EOF) and is called
    /// only when more bytes are needed to complete the next unit.
    pub fn read_unit<E>(
        &mut self,
        buf: &mut [u8],
        mut fill: impl FnMut(&mut [u8]) -> Result<usize, E>,
    ) -> Result<(usize, Vec<PassedToken>), E> {
        if buf.is_empty() {
            return Ok((0, Vec::new()));
        }
        // Deliver any leftover decoded bytes first (token-less tail of a
        // frame / raw run that overran a prior caller's buffer).
        if !self.pending.is_empty() {
            let n = buf.len().min(self.pending.len());
            buf[..n].copy_from_slice(&self.pending[..n]);
            self.pending.drain(..n);
            return Ok((n, Vec::new()));
        }
        loop {
            match self.reader.take_unit() {
                ReaderUnit::Frame(frame) => {
                    let n = buf.len().min(frame.data.len());
                    buf[..n].copy_from_slice(&frame.data[..n]);
                    if n < frame.data.len() {
                        self.pending.extend_from_slice(&frame.data[n..]);
                    }
                    return Ok((n, frame.tokens));
                }
                ReaderUnit::Raw(bytes) => {
                    let n = buf.len().min(bytes.len());
                    buf[..n].copy_from_slice(&bytes[..n]);
                    if n < bytes.len() {
                        self.pending.extend_from_slice(&bytes[n..]);
                    }
                    return Ok((n, Vec::new()));
                }
                ReaderUnit::NeedMore => {
                    let mut staging = alloc::vec![0u8; Self::STAGE];
                    let size = fill(&mut staging)?;
                    if size == 0 {
                        // EOF / read-shutdown: no further units possible.
                        return Ok((0, Vec::new()));
                    }
                    self.reader.push(&staging[..size]);
                }
            }
        }
    }
}

#[cfg(test)]
mod reader_tests {
    use super::*;
    use alloc::vec;

    fn pt(id: u64) -> PassedToken {
        PassedToken::new(SubsystemTag::Eventfd, id).expect("test id fits")
    }

    fn encoded_frame(tokens: &[PassedToken], data: &[u8]) -> Vec<u8> {
        let mut buf = Vec::new();
        FdTransferFrame { tokens, data }.encode(&mut buf).unwrap();
        buf
    }

    #[test]
    fn empty_reader_returns_none() {
        let mut r = FdTransferReader::new();
        assert!(r.take_frame().unwrap().is_none());
    }

    #[test]
    fn push_then_take_one_frame() {
        let mut r = FdTransferReader::new();
        r.push(&encoded_frame(&[pt(1), pt(2)], b"hello"));
        let frame = r.take_frame().unwrap().expect("frame ready");
        assert_eq!(frame.tokens, vec![pt(1), pt(2)]);
        assert_eq!(frame.data, b"hello");
        assert_eq!(r.buffered_bytes(), 0);
        assert!(r.take_frame().unwrap().is_none());
    }

    #[test]
    fn push_byte_at_a_time_eventually_yields_frame() {
        // The reader must tolerate single-byte chunks (worst case under
        // congested non-blocking TCP).
        let mut r = FdTransferReader::new();
        let bytes = encoded_frame(&[pt(42)], b"trickle");
        for &b in &bytes {
            r.push(&[b]);
        }
        let frame = r.take_frame().unwrap().expect("frame ready");
        assert_eq!(frame.tokens, vec![pt(42)]);
        assert_eq!(frame.data, b"trickle");
    }

    #[test]
    fn take_unit_empty_is_need_more() {
        let mut r = FdTransferReader::new();
        assert_eq!(r.take_unit(), ReaderUnit::NeedMore);
    }

    #[test]
    fn take_unit_drains_two_coalesced_frames() {
        // The regression that broke VS Code: two SCM frames in one read
        // must both be recoverable, one per take_unit call.
        let mut r = FdTransferReader::new();
        r.push(&encoded_frame(&[pt(1)], b"a"));
        r.push(&encoded_frame(&[pt(2)], b"b"));
        let ReaderUnit::Frame(f) = r.take_unit() else {
            panic!("expected first frame");
        };
        assert_eq!(f.tokens, vec![pt(1)]);
        assert_eq!(f.data, b"a");
        let ReaderUnit::Frame(f) = r.take_unit() else {
            panic!("expected second frame");
        };
        assert_eq!(f.tokens, vec![pt(2)]);
        assert_eq!(f.data, b"b");
        assert_eq!(r.take_unit(), ReaderUnit::NeedMore);
    }

    #[test]
    fn take_unit_raw_then_frame() {
        let mut r = FdTransferReader::new();
        r.push(b"plain json bytes");
        r.push(&encoded_frame(&[pt(9)], b"x"));
        let ReaderUnit::Raw(raw) = r.take_unit() else {
            panic!("expected raw run");
        };
        assert_eq!(raw, b"plain json bytes");
        let ReaderUnit::Frame(f) = r.take_unit() else {
            panic!("expected frame");
        };
        assert_eq!(f.tokens, vec![pt(9)]);
        assert_eq!(f.data, b"x");
    }

    #[test]
    fn take_unit_frame_then_raw() {
        let mut r = FdTransferReader::new();
        r.push(&encoded_frame(&[pt(3)], b"hdr"));
        r.push(b"tail-bytes");
        assert!(matches!(r.take_unit(), ReaderUnit::Frame(_)));
        let ReaderUnit::Raw(raw) = r.take_unit() else {
            panic!("expected trailing raw");
        };
        assert_eq!(raw, b"tail-bytes");
    }

    #[test]
    fn take_unit_partial_frame_is_need_more() {
        let mut r = FdTransferReader::new();
        let bytes = encoded_frame(&[pt(5)], b"incomplete");
        r.push(&bytes[..bytes.len() - 1]); // header complete, body short
        assert_eq!(r.take_unit(), ReaderUnit::NeedMore);
        r.push(&bytes[bytes.len() - 1..]);
        assert!(matches!(r.take_unit(), ReaderUnit::Frame(_)));
    }

    #[test]
    fn take_unit_retains_tail_partial_magic() {
        // A raw run that ends in the first bytes of a magic must NOT
        // consume the partial magic — it could be the head of the next
        // frame.
        let mut r = FdTransferReader::new();
        let magic = FRAME_MAGIC.to_le_bytes();
        r.push(b"raw");
        r.push(&magic[..2]); // two leading magic bytes, frame not yet here
        let ReaderUnit::Raw(raw) = r.take_unit() else {
            panic!("expected raw without the partial magic");
        };
        assert_eq!(raw, b"raw");
        // Only the 2-byte partial magic remains; still undecidable.
        assert_eq!(r.take_unit(), ReaderUnit::NeedMore);
        // Completing the frame makes it decodable.
        let frame = encoded_frame(&[pt(8)], b"z");
        r.push(&frame[2..]);
        let ReaderUnit::Frame(f) = r.take_unit() else {
            panic!("expected frame after completion");
        };
        assert_eq!(f.data, b"z");
    }

    /// A `fill` closure that streams `wire` in `chunk`-sized pieces; used
    /// to drive `StreamScmDeframer::read_unit` deterministically.
    fn chunked_fill(wire: Vec<u8>, chunk: usize) -> impl FnMut(&mut [u8]) -> Result<usize, ()> {
        let mut cursor = 0usize;
        move |staging: &mut [u8]| {
            let take = staging.len().min(chunk).min(wire.len() - cursor);
            staging[..take].copy_from_slice(&wire[cursor..cursor + take]);
            cursor += take;
            Ok(take)
        }
    }

    #[test]
    fn deframer_drains_coalesced_frames() {
        // Two fd-bearing frames delivered in one fill must each surface
        // with their own token, one per read_unit call.
        let mut wire = Vec::new();
        wire.extend_from_slice(&encoded_frame(&[pt(1)], b"a"));
        wire.extend_from_slice(&encoded_frame(&[pt(2)], b"b"));
        let mut fill = chunked_fill(wire, usize::MAX);
        let mut d = StreamScmDeframer::new();
        let mut buf = [0u8; 64];
        let (n1, t1) = d.read_unit(&mut buf, &mut fill).unwrap();
        assert_eq!(&buf[..n1], b"a");
        assert_eq!(t1, vec![pt(1)]);
        let (n2, t2) = d.read_unit(&mut buf, &mut fill).unwrap();
        assert_eq!(&buf[..n2], b"b");
        assert_eq!(t2, vec![pt(2)]);
    }

    #[test]
    fn deframer_reassembles_split_frame() {
        // A frame delivered one byte per fill must still reassemble.
        let wire = encoded_frame(&[pt(5)], b"trickle");
        let mut fill = chunked_fill(wire, 1);
        let mut d = StreamScmDeframer::new();
        let mut buf = [0u8; 64];
        let (n, t) = d.read_unit(&mut buf, &mut fill).unwrap();
        assert_eq!(&buf[..n], b"trickle");
        assert_eq!(t, vec![pt(5)]);
    }

    #[test]
    fn deframer_buffers_overrun_into_pending() {
        // A caller buffer smaller than the frame data gets the token with
        // the first chunk; the remainder drains token-less.
        let wire = encoded_frame(&[pt(7)], b"hello");
        let mut fill = chunked_fill(wire, usize::MAX);
        let mut d = StreamScmDeframer::new();
        let mut buf = [0u8; 2];
        let (n1, t1) = d.read_unit(&mut buf, &mut fill).unwrap();
        assert_eq!(&buf[..n1], b"he");
        assert_eq!(t1, vec![pt(7)]);
        let (n2, t2) = d.read_unit(&mut buf, &mut fill).unwrap();
        assert_eq!(&buf[..n2], b"ll");
        assert!(t2.is_empty());
        let (n3, t3) = d.read_unit(&mut buf, &mut fill).unwrap();
        assert_eq!(&buf[..n3], b"o");
        assert!(t3.is_empty());
    }

    #[test]
    fn deframer_eof_returns_zero() {
        let mut fill = chunked_fill(Vec::new(), usize::MAX);
        let mut d = StreamScmDeframer::new();
        let mut buf = [0u8; 16];
        let (n, t) = d.read_unit(&mut buf, &mut fill).unwrap();
        assert_eq!(n, 0);
        assert!(t.is_empty());
    }

    #[test]
    fn body_truncated_returns_none_until_complete() {
        let mut r = FdTransferReader::new();
        let bytes = encoded_frame(&[pt(7)], b"halfsies");

        // Push everything except the last byte: header complete, body short.
        r.push(&bytes[..bytes.len() - 1]);
        assert!(r.take_frame().unwrap().is_none());

        // Now the last byte arrives: frame becomes available.
        r.push(&bytes[bytes.len() - 1..]);
        let frame = r.take_frame().unwrap().expect("now ready");
        assert_eq!(frame.tokens, vec![pt(7)]);
        assert_eq!(frame.data, b"halfsies");
    }

    #[test]
    fn header_truncated_returns_none_until_complete() {
        let mut r = FdTransferReader::new();
        // First, push fewer than HEADER_LEN bytes.
        r.push(&[0xa5; 4]);
        assert!(r.take_frame().unwrap().is_none());

        // Now push a complete frame; the bogus prefix bytes will form a
        // bad-magic header. We expect a hard error.
        let mut bytes = encoded_frame(&[], b"xx");
        bytes.splice(0..0, [0u8; 0]); // no-op, just to keep ordering clear
        r.push(&bytes);

        match r.take_frame() {
            Err(FrameError::BadMagic { .. }) => {}
            other => panic!("expected BadMagic from desync, got {other:?}"),
        }
    }

    #[test]
    fn back_to_back_frames_in_one_push() {
        let mut r = FdTransferReader::new();
        let mut bytes = encoded_frame(&[pt(1)], b"a");
        bytes.extend_from_slice(&encoded_frame(&[pt(2), pt(3)], b"bcd"));
        bytes.extend_from_slice(&encoded_frame(&[], b""));
        r.push(&bytes);

        let f1 = r.take_frame().unwrap().expect("f1");
        assert_eq!(f1.tokens, vec![pt(1)]);
        assert_eq!(f1.data, b"a");

        let f2 = r.take_frame().unwrap().expect("f2");
        assert_eq!(f2.tokens, vec![pt(2), pt(3)]);
        assert_eq!(f2.data, b"bcd");

        let f3 = r.take_frame().unwrap().expect("f3");
        assert!(f3.tokens.is_empty());
        assert!(f3.data.is_empty());

        assert!(r.take_frame().unwrap().is_none());
        assert_eq!(r.buffered_bytes(), 0);
    }

    #[test]
    fn frame_split_across_pushes_reassembles() {
        // The classic non-aligned-chunks case: header bytes arrive in
        // one chunk, body in a different chunk.
        let mut r = FdTransferReader::new();
        let bytes = encoded_frame(&[pt(100), pt(200), pt(300)], b"reassembly_check");
        let split = bytes.len() / 2;
        r.push(&bytes[..split]);
        assert!(r.take_frame().unwrap().is_none());

        r.push(&bytes[split..]);
        let frame = r.take_frame().unwrap().expect("frame ready");
        assert_eq!(frame.tokens, vec![pt(100), pt(200), pt(300)]);
        assert_eq!(frame.data, b"reassembly_check");
    }

    #[test]
    fn partial_frame_then_extra_partial_frame_compacts_buffer() {
        // Frame A complete + Frame B partial in one push.
        // After taking A, the buffer should hold only B's partial bytes.
        let mut r = FdTransferReader::new();
        let a = encoded_frame(&[pt(1)], b"first");
        let b = encoded_frame(&[pt(2), pt(3)], b"second");
        let mut chunk = a.clone();
        chunk.extend_from_slice(&b[..5]); // first 5 bytes of frame B
        r.push(&chunk);

        let f_a = r.take_frame().unwrap().expect("frame A");
        assert_eq!(f_a.tokens, vec![pt(1)]);
        assert_eq!(f_a.data, b"first");

        // Frame B is incomplete.
        assert!(r.take_frame().unwrap().is_none());
        assert_eq!(r.buffered_bytes(), 5);

        // Push the remainder of B.
        r.push(&b[5..]);
        let f_b = r.take_frame().unwrap().expect("frame B");
        assert_eq!(f_b.tokens, vec![pt(2), pt(3)]);
        assert_eq!(f_b.data, b"second");
        assert_eq!(r.buffered_bytes(), 0);
    }

    #[test]
    fn bad_magic_in_header_surfaces_as_error() {
        let mut r = FdTransferReader::new();
        r.push(&[0u8; FRAME_HEADER_LEN]); // all zeros = bad magic
        match r.take_frame() {
            Err(FrameError::BadMagic { .. }) => {}
            other => panic!("expected BadMagic, got {other:?}"),
        }
    }

    #[test]
    fn unsupported_version_surfaces_as_error() {
        let mut r = FdTransferReader::new();
        let mut bytes = encoded_frame(&[], b"x");
        bytes[4..6].copy_from_slice(&99u16.to_le_bytes());
        r.push(&bytes);
        match r.take_frame() {
            Err(FrameError::UnsupportedVersion { version: 99 }) => {}
            other => panic!("expected UnsupportedVersion, got {other:?}"),
        }
    }

    #[test]
    fn many_random_chunk_sizes_round_trip() {
        // Encode a sequence of 20 frames with varied sizes, then push the
        // bytes through the reader in a fixed pseudo-random chunk pattern.
        // Verifies the reader's state machine handles arbitrary chunk
        // alignment over many frames.
        let frames: Vec<(Vec<PassedToken>, Vec<u8>)> = (0..20)
            .map(|i: usize| {
                let n_tokens = i % 5;
                let tokens: Vec<PassedToken> = (0..n_tokens as u64)
                    .map(|t| pt((i as u64) * 100 + t))
                    .collect();
                #[allow(clippy::cast_possible_truncation)]
                let data = vec![i as u8; (i * 7) % 90];
                (tokens, data)
            })
            .collect();

        let mut all_bytes = Vec::new();
        for (tokens, data) in &frames {
            all_bytes.extend_from_slice(&encoded_frame(tokens, data));
        }

        let mut r = FdTransferReader::new();
        let chunk_sizes = [1, 2, 3, 5, 7, 11, 13, 17, 23];
        let mut idx = 0;
        let mut decoded = Vec::new();
        let mut cs_i = 0;

        while idx < all_bytes.len() || decoded.len() < frames.len() {
            if idx < all_bytes.len() {
                let cs = chunk_sizes[cs_i % chunk_sizes.len()].min(all_bytes.len() - idx);
                cs_i += 1;
                r.push(&all_bytes[idx..idx + cs]);
                idx += cs;
            }
            while let Some(f) = r.take_frame().unwrap() {
                decoded.push(f);
            }
        }

        assert_eq!(decoded.len(), frames.len());
        for (i, (expected, got)) in frames.iter().zip(decoded.iter()).enumerate() {
            assert_eq!(got.tokens, expected.0, "tokens mismatch at frame {i}");
            assert_eq!(got.data, expected.1, "data mismatch at frame {i}");
        }
        assert_eq!(r.buffered_bytes(), 0);
    }
}

/// Wire-format magic number ("LBFD" — LiteBox Fd Frame).
pub const FRAME_MAGIC: u32 = 0x4C42_4644;

/// Wire-format version. Receivers reject mismatched versions.
pub const FRAME_VERSION: u16 = 1;

/// Maximum payload bytes per frame. Matches `UNIX_BUF_SIZE` in
/// `litebox_shim_linux/src/syscalls/unix.rs`. Frames larger than this
/// would never fit in a single recv buffer round trip on the receiver.
pub const DATA_MAX: u32 = 65_536;

/// Maximum fds per frame. The Linux kernel's `SCM_MAX_FD` is 253; we use
/// the same cap to stay aligned with what `sendmsg` accepts on the
/// originating side. A passed fd here is 8 bytes on the wire (token id),
/// so the worst-case fd-only overhead is ~2 KiB.
pub const FD_COUNT_MAX: u32 = 253;

/// Size in bytes of the fixed-size frame header.
pub const FRAME_HEADER_LEN: usize = 16;

/// Errors produced by [`FdTransferFrame::decode`] and [`FdTransferFrame::encoded_len`].
#[derive(Debug, PartialEq, Eq)]
pub enum FrameError {
    /// Available bytes are smaller than the fixed header.
    HeaderTruncated { have: usize, need: usize },
    /// Available bytes are smaller than the announced full-frame length
    /// (header + tokens + data).
    BodyTruncated { have: usize, need: usize },
    /// Magic word did not match [`FRAME_MAGIC`]. Indicates a desynchronised
    /// stream or wire-format corruption.
    BadMagic { found: u32 },
    /// Receiver does not implement the announced version.
    UnsupportedVersion { version: u16 },
    /// `data_len` exceeded [`DATA_MAX`]. Treated as malformed input.
    DataTooLarge { data_len: u32, max: u32 },
    /// `fd_count` exceeded [`FD_COUNT_MAX`]. Treated as malformed input.
    FdCountTooLarge { fd_count: u32, max: u32 },
    /// `flags` had a non-zero bit set; reserved flags must be zero in
    /// version 1. Forward-compatible decoders that wish to ignore unknown
    /// flags can choose to suppress this error, but the canonical decoder
    /// rejects so a future flag rollout does not silently misbehave.
    UnknownFlags { flags: u16 },
    /// Same as [`FrameError::DataTooLarge`] but at encode time: caller
    /// supplied a payload that exceeds the wire limit.
    EncodeDataTooLarge { data_len: usize, max: u32 },
    /// Same as [`FrameError::FdCountTooLarge`] but at encode time.
    EncodeFdCountTooLarge { fd_count: usize, max: u32 },
    /// A [`PassedToken`] was constructed with an id that does not fit
    /// in the 56-bit on-wire id field. The broker allocates token ids
    /// monotonically from 1, so seeing this in practice indicates a
    /// long-lived broker or a bug.
    EncodeIdTooLarge { id: u64 },
}

impl core::fmt::Display for FrameError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            FrameError::HeaderTruncated { have, need } => {
                write!(f, "frame header truncated: have {have}, need {need}")
            }
            FrameError::BodyTruncated { have, need } => {
                write!(f, "frame body truncated: have {have}, need {need}")
            }
            FrameError::BadMagic { found } => {
                write!(
                    f,
                    "bad frame magic: found 0x{found:08x}, expected 0x{FRAME_MAGIC:08x}"
                )
            }
            FrameError::UnsupportedVersion { version } => {
                write!(f, "unsupported frame version: {version}")
            }
            FrameError::DataTooLarge { data_len, max } => {
                write!(f, "decoded data_len {data_len} exceeds max {max}")
            }
            FrameError::FdCountTooLarge { fd_count, max } => {
                write!(f, "decoded fd_count {fd_count} exceeds max {max}")
            }
            FrameError::UnknownFlags { flags } => {
                write!(f, "unknown reserved flags: 0x{flags:04x}")
            }
            FrameError::EncodeDataTooLarge { data_len, max } => {
                write!(f, "encode data_len {data_len} exceeds max {max}")
            }
            FrameError::EncodeFdCountTooLarge { fd_count, max } => {
                write!(f, "encode fd_count {fd_count} exceeds max {max}")
            }
            FrameError::EncodeIdTooLarge { id } => {
                write!(f, "encode token id {id} exceeds 56-bit wire field")
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for FrameError {}

/// A decoded frame referencing borrowed payload bytes from the receive
/// buffer. The `tokens` are owned (small allocation, ≤ 253 × 8 bytes); the
/// data slice borrows from the input to avoid copying the bulk payload.
#[derive(Debug, PartialEq, Eq)]
pub struct DecodedFrame<'a> {
    pub tokens: Vec<PassedToken>,
    pub data: &'a [u8],
    /// Total bytes consumed from the input (header + tokens + data). The
    /// caller advances its read cursor by this many bytes.
    pub consumed: usize,
}

/// An encodable frame. The `tokens` and `data` references describe a
/// single message's worth of payload + fd-token list.
pub struct FdTransferFrame<'a> {
    pub tokens: &'a [PassedToken],
    pub data: &'a [u8],
}

impl FdTransferFrame<'_> {
    /// Returns the number of bytes that [`Self::encode`] will write, or an
    /// error if the inputs exceed the wire limits.
    pub fn encoded_len(&self) -> Result<usize, FrameError> {
        if self.data.len() > DATA_MAX as usize {
            return Err(FrameError::EncodeDataTooLarge {
                data_len: self.data.len(),
                max: DATA_MAX,
            });
        }
        if self.tokens.len() > FD_COUNT_MAX as usize {
            return Err(FrameError::EncodeFdCountTooLarge {
                fd_count: self.tokens.len(),
                max: FD_COUNT_MAX,
            });
        }
        Ok(FRAME_HEADER_LEN + 8 * self.tokens.len() + self.data.len())
    }

    /// Appends the encoded frame to `out`. Returns the number of bytes
    /// appended on success, or a [`FrameError`] if the inputs exceed the
    /// wire limits (in which case `out` is left unchanged).
    pub fn encode(&self, out: &mut Vec<u8>) -> Result<usize, FrameError> {
        let total = self.encoded_len()?;
        out.reserve(total);
        let start = out.len();

        out.extend_from_slice(&FRAME_MAGIC.to_le_bytes());
        out.extend_from_slice(&FRAME_VERSION.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes()); // flags reserved
        // SAFETY of casts: encoded_len() above already validated that
        // self.data.len() ≤ DATA_MAX (u32) and self.tokens.len() ≤
        // FD_COUNT_MAX (u32), so the truncation cannot lose information.
        #[allow(clippy::cast_possible_truncation)]
        out.extend_from_slice(&(self.data.len() as u32).to_le_bytes());
        #[allow(clippy::cast_possible_truncation)]
        out.extend_from_slice(&(self.tokens.len() as u32).to_le_bytes());

        for &t in self.tokens {
            out.extend_from_slice(&t.raw().to_le_bytes());
        }

        out.extend_from_slice(self.data);

        debug_assert_eq!(out.len() - start, total);
        Ok(total)
    }
}

/// Decodes one frame from the start of `buf`. Returns the decoded frame
/// (with `tokens` owned and `data` borrowing from `buf`) plus the number
/// of bytes consumed from `buf`. The caller is responsible for advancing
/// its read cursor by `decoded.consumed`.
///
/// Returns:
/// - `Err(HeaderTruncated)` if `buf` is shorter than [`FRAME_HEADER_LEN`].
/// - `Err(BodyTruncated)` if the announced body extends beyond `buf`.
/// - `Err(BadMagic)` / `Err(UnsupportedVersion)` / `Err(UnknownFlags)`
///   for protocol violations (caller should treat as a fatal stream error).
/// - `Err(DataTooLarge)` / `Err(FdCountTooLarge)` for malformed sizes.
pub fn decode_frame(buf: &[u8]) -> Result<DecodedFrame<'_>, FrameError> {
    if buf.len() < FRAME_HEADER_LEN {
        return Err(FrameError::HeaderTruncated {
            have: buf.len(),
            need: FRAME_HEADER_LEN,
        });
    }

    let magic = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
    if magic != FRAME_MAGIC {
        return Err(FrameError::BadMagic { found: magic });
    }

    let version = u16::from_le_bytes([buf[4], buf[5]]);
    if version != FRAME_VERSION {
        return Err(FrameError::UnsupportedVersion { version });
    }

    let flags = u16::from_le_bytes([buf[6], buf[7]]);
    if flags != 0 {
        return Err(FrameError::UnknownFlags { flags });
    }

    let data_len = u32::from_le_bytes([buf[8], buf[9], buf[10], buf[11]]);
    if data_len > DATA_MAX {
        return Err(FrameError::DataTooLarge {
            data_len,
            max: DATA_MAX,
        });
    }

    let fd_count = u32::from_le_bytes([buf[12], buf[13], buf[14], buf[15]]);
    if fd_count > FD_COUNT_MAX {
        return Err(FrameError::FdCountTooLarge {
            fd_count,
            max: FD_COUNT_MAX,
        });
    }

    let tokens_len = 8usize * fd_count as usize;
    let total = FRAME_HEADER_LEN + tokens_len + data_len as usize;
    if buf.len() < total {
        return Err(FrameError::BodyTruncated {
            have: buf.len(),
            need: total,
        });
    }

    let tokens_start = FRAME_HEADER_LEN;
    let data_start = tokens_start + tokens_len;
    let data_end = data_start + data_len as usize;

    let mut tokens = Vec::with_capacity(fd_count as usize);
    for i in 0..fd_count as usize {
        let off = tokens_start + 8 * i;
        let raw = u64::from_le_bytes([
            buf[off],
            buf[off + 1],
            buf[off + 2],
            buf[off + 3],
            buf[off + 4],
            buf[off + 5],
            buf[off + 6],
            buf[off + 7],
        ]);
        tokens.push(PassedToken::from_raw(raw));
    }

    Ok(DecodedFrame {
        tokens,
        data: &buf[data_start..data_end],
        consumed: total,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    /// Test helper: wrap a u64 id in a [`PassedToken`] with the
    /// `Eventfd` subsystem tag. Tests in this module care about
    /// id-level round-trip behaviour, not subsystem tagging.
    fn pt(id: u64) -> PassedToken {
        PassedToken::new(SubsystemTag::Eventfd, id).expect("test id fits in 56 bits")
    }

    #[test]
    fn passed_token_tag_and_id_round_trip() {
        for &tag in &[SubsystemTag::Eventfd, SubsystemTag::TcpSocket] {
            for &id in &[0u64, 1, 42, 0xff, 0x100, PASSED_TOKEN_MAX_ID] {
                let t = PassedToken::new(tag, id).unwrap();
                assert_eq!(t.tag(), tag);
                assert_eq!(t.id(), id);
                // Round trip through raw u64.
                let again = PassedToken::from_raw(t.raw());
                assert_eq!(again, t);
            }
        }
    }

    #[test]
    fn passed_token_rejects_oversized_id() {
        let too_big = PASSED_TOKEN_MAX_ID + 1;
        match PassedToken::new(SubsystemTag::Eventfd, too_big) {
            Err(FrameError::EncodeIdTooLarge { id }) => assert_eq!(id, too_big),
            other => panic!("expected EncodeIdTooLarge, got {other:?}"),
        }
    }

    #[test]
    fn subsystem_tag_unknown_round_trips_through_u8() {
        // Skip known values; pick a few unrecognised bytes (incl.
        // mid-range and 0x7f / 0x80 / 0xff boundary cases).
        for raw in [0u8, 0x55, 0x7e, 0x7f, 0x80, 0xfe, 0xff] {
            let tag = SubsystemTag::from_u8(raw);
            assert_eq!(tag.as_u8(), raw);
            assert!(!tag.is_known(), "raw {raw:#x} should be Unknown");
            match tag {
                SubsystemTag::Unknown(v) => assert_eq!(v, raw),
                SubsystemTag::Eventfd
                | SubsystemTag::TcpSocket
                | SubsystemTag::Pidfd
                | SubsystemTag::UnixSocket
                | SubsystemTag::Signalfd
                | SubsystemTag::Timerfd
                | SubsystemTag::Inotify
                | SubsystemTag::Process
                | SubsystemTag::Pipe
                | SubsystemTag::PipeRead
                | SubsystemTag::PipeWrite
                | SubsystemTag::Pty
                | SubsystemTag::InetListener
                | SubsystemTag::InetDgram
                | SubsystemTag::InetRaw
                | SubsystemTag::HostFd
                | SubsystemTag::File => panic!("expected Unknown({raw:#x}), got {tag:?}"),
            }
        }
    }

    #[test]
    fn subsystem_tag_known_values() {
        assert_eq!(SubsystemTag::Eventfd.as_u8(), 1);
        assert_eq!(SubsystemTag::TcpSocket.as_u8(), 2);
        assert_eq!(SubsystemTag::Pidfd.as_u8(), 3);
        assert_eq!(SubsystemTag::UnixSocket.as_u8(), 4);
        assert_eq!(SubsystemTag::Signalfd.as_u8(), 5);
        assert_eq!(SubsystemTag::Timerfd.as_u8(), 6);
        assert_eq!(SubsystemTag::Inotify.as_u8(), 7);
        assert_eq!(SubsystemTag::Pipe.as_u8(), 9);
        assert_eq!(SubsystemTag::PipeRead.as_u8(), 14);
        assert_eq!(SubsystemTag::PipeWrite.as_u8(), 15);
        assert_eq!(SubsystemTag::HostFd.as_u8(), 16);
        assert_eq!(SubsystemTag::File.as_u8(), 17);
        for tag in [
            SubsystemTag::Eventfd,
            SubsystemTag::TcpSocket,
            SubsystemTag::Pidfd,
            SubsystemTag::UnixSocket,
            SubsystemTag::Signalfd,
            SubsystemTag::Timerfd,
            SubsystemTag::Inotify,
            SubsystemTag::Process,
            SubsystemTag::Pipe,
            SubsystemTag::Pty,
            SubsystemTag::InetListener,
            SubsystemTag::InetDgram,
            SubsystemTag::InetRaw,
            SubsystemTag::PipeRead,
            SubsystemTag::PipeWrite,
            SubsystemTag::HostFd,
            SubsystemTag::File,
        ] {
            assert!(tag.is_known(), "{tag:?} should be known");
            assert_eq!(SubsystemTag::from_u8(tag.as_u8()), tag);
        }
    }

    #[test]
    fn decoder_preserves_unknown_subsystem_tags() {
        // Manually construct a frame with a token whose tag byte = 99
        // (Unknown). The decoder must surface that as Unknown(99) — not
        // an error. This is the constraint that lets us roll out new
        // subsystems incrementally without bumping the wire version.
        let unknown_tag_raw = 99u8;
        let id = 1234u64;
        let token_raw = (id << 8) | u64::from(unknown_tag_raw);
        let token = PassedToken::from_raw(token_raw);

        let frame = FdTransferFrame {
            tokens: &[token],
            data: b"payload",
        };
        let mut buf = Vec::new();
        frame.encode(&mut buf).expect("encode");

        let decoded = decode_frame(&buf).expect("decode must accept unknown tag");
        assert_eq!(decoded.tokens.len(), 1);
        assert_eq!(
            decoded.tokens[0].tag(),
            SubsystemTag::Unknown(unknown_tag_raw)
        );
        assert_eq!(decoded.tokens[0].id(), id);
    }

    #[test]
    fn round_trip_empty_data_no_fds() {
        let frame = FdTransferFrame {
            tokens: &[],
            data: &[],
        };
        let mut buf = Vec::new();
        let n = frame.encode(&mut buf).expect("encode");
        assert_eq!(n, FRAME_HEADER_LEN);
        assert_eq!(buf.len(), FRAME_HEADER_LEN);

        let decoded = decode_frame(&buf).expect("decode");
        assert!(decoded.tokens.is_empty());
        assert!(decoded.data.is_empty());
        assert_eq!(decoded.consumed, FRAME_HEADER_LEN);
    }

    #[test]
    fn round_trip_data_only() {
        let payload = b"hello cross-worker world";
        let frame = FdTransferFrame {
            tokens: &[],
            data: payload,
        };
        let mut buf = Vec::new();
        frame.encode(&mut buf).expect("encode");

        let decoded = decode_frame(&buf).expect("decode");
        assert!(decoded.tokens.is_empty());
        assert_eq!(decoded.data, payload);
        assert_eq!(decoded.consumed, FRAME_HEADER_LEN + payload.len());
    }

    #[test]
    fn round_trip_tokens_only() {
        let tokens = [pt(1), pt(42), pt(0x00de_adbe_efca_feba)];
        let frame = FdTransferFrame {
            tokens: &tokens,
            data: &[],
        };
        let mut buf = Vec::new();
        frame.encode(&mut buf).expect("encode");

        let decoded = decode_frame(&buf).expect("decode");
        assert_eq!(&decoded.tokens[..], &tokens[..]);
        assert!(decoded.data.is_empty());
        assert_eq!(decoded.consumed, FRAME_HEADER_LEN + 8 * tokens.len());
    }

    #[test]
    fn round_trip_full_frame() {
        let tokens = [pt(7), pt(8), pt(9)];
        let payload = b"some bytes plus three fd tokens";
        let frame = FdTransferFrame {
            tokens: &tokens,
            data: payload,
        };
        let mut buf = Vec::new();
        let n = frame.encode(&mut buf).expect("encode");
        assert_eq!(n, FRAME_HEADER_LEN + 24 + payload.len());

        let decoded = decode_frame(&buf).expect("decode");
        assert_eq!(&decoded.tokens[..], &tokens[..]);
        assert_eq!(decoded.data, payload);
        assert_eq!(decoded.consumed, n);
    }

    #[test]
    fn back_to_back_frames_share_buffer() {
        // The receiver must be able to peel one frame off and keep going.
        let p1 = b"first";
        let p2 = b"second message";
        let mut buf = Vec::new();

        FdTransferFrame {
            tokens: &[pt(1), pt(2)],
            data: p1,
        }
        .encode(&mut buf)
        .expect("encode 1");
        FdTransferFrame {
            tokens: &[pt(3)],
            data: p2,
        }
        .encode(&mut buf)
        .expect("encode 2");

        let f1 = decode_frame(&buf).expect("decode 1");
        assert_eq!(f1.tokens, [pt(1), pt(2)]);
        assert_eq!(f1.data, p1);

        let f2 = decode_frame(&buf[f1.consumed..]).expect("decode 2");
        assert_eq!(f2.tokens, [pt(3)]);
        assert_eq!(f2.data, p2);

        assert_eq!(f1.consumed + f2.consumed, buf.len());
    }

    #[test]
    fn header_truncation_returns_specific_error() {
        let short = [0u8; FRAME_HEADER_LEN - 1];
        match decode_frame(&short) {
            Err(FrameError::HeaderTruncated { have, need }) => {
                assert_eq!(have, FRAME_HEADER_LEN - 1);
                assert_eq!(need, FRAME_HEADER_LEN);
            }
            other => panic!("expected HeaderTruncated, got {other:?}"),
        }
    }

    #[test]
    fn body_truncation_returns_specific_error() {
        // Encode a frame, then truncate one byte off the data tail.
        let mut buf = Vec::new();
        FdTransferFrame {
            tokens: &[],
            data: b"abc",
        }
        .encode(&mut buf)
        .unwrap();
        buf.truncate(buf.len() - 1);

        match decode_frame(&buf) {
            Err(FrameError::BodyTruncated { have, need }) => {
                assert_eq!(have, buf.len());
                assert_eq!(need, FRAME_HEADER_LEN + 3);
            }
            other => panic!("expected BodyTruncated, got {other:?}"),
        }
    }

    #[test]
    fn bad_magic_rejected() {
        let mut buf = Vec::from([0u8; FRAME_HEADER_LEN]);
        // Leave magic = 0; valid header would have FRAME_MAGIC.
        match decode_frame(&buf) {
            Err(FrameError::BadMagic { found: 0 }) => {}
            other => panic!("expected BadMagic, got {other:?}"),
        }
        // A different non-magic value also rejected.
        buf[..4].copy_from_slice(&0xdeadbeef_u32.to_le_bytes());
        match decode_frame(&buf) {
            Err(FrameError::BadMagic { found: 0xdeadbeef }) => {}
            other => panic!("expected BadMagic, got {other:?}"),
        }
    }

    #[test]
    fn unsupported_version_rejected() {
        let mut buf = Vec::new();
        FdTransferFrame {
            tokens: &[],
            data: &[],
        }
        .encode(&mut buf)
        .unwrap();
        // Tamper version field to 99.
        buf[4..6].copy_from_slice(&99u16.to_le_bytes());

        match decode_frame(&buf) {
            Err(FrameError::UnsupportedVersion { version: 99 }) => {}
            other => panic!("expected UnsupportedVersion, got {other:?}"),
        }
    }

    #[test]
    fn unknown_flags_rejected() {
        let mut buf = Vec::new();
        FdTransferFrame {
            tokens: &[],
            data: &[],
        }
        .encode(&mut buf)
        .unwrap();
        buf[6..8].copy_from_slice(&1u16.to_le_bytes()); // any non-zero

        match decode_frame(&buf) {
            Err(FrameError::UnknownFlags { flags: 1 }) => {}
            other => panic!("expected UnknownFlags, got {other:?}"),
        }
    }

    #[test]
    fn decode_rejects_oversized_data_len() {
        let mut buf = Vec::from([0u8; FRAME_HEADER_LEN]);
        buf[..4].copy_from_slice(&FRAME_MAGIC.to_le_bytes());
        buf[4..6].copy_from_slice(&FRAME_VERSION.to_le_bytes());
        // flags = 0 already
        let oversized = DATA_MAX + 1;
        buf[8..12].copy_from_slice(&oversized.to_le_bytes());
        // fd_count = 0 already

        match decode_frame(&buf) {
            Err(FrameError::DataTooLarge { data_len, max }) => {
                assert_eq!(data_len, oversized);
                assert_eq!(max, DATA_MAX);
            }
            other => panic!("expected DataTooLarge, got {other:?}"),
        }
    }

    #[test]
    fn decode_rejects_oversized_fd_count() {
        let mut buf = Vec::from([0u8; FRAME_HEADER_LEN]);
        buf[..4].copy_from_slice(&FRAME_MAGIC.to_le_bytes());
        buf[4..6].copy_from_slice(&FRAME_VERSION.to_le_bytes());
        let oversized = FD_COUNT_MAX + 1;
        buf[12..16].copy_from_slice(&oversized.to_le_bytes());

        match decode_frame(&buf) {
            Err(FrameError::FdCountTooLarge { fd_count, max }) => {
                assert_eq!(fd_count, oversized);
                assert_eq!(max, FD_COUNT_MAX);
            }
            other => panic!("expected FdCountTooLarge, got {other:?}"),
        }
    }

    #[test]
    fn encode_rejects_oversized_data() {
        let big = vec![0u8; DATA_MAX as usize + 1];
        let frame = FdTransferFrame {
            tokens: &[],
            data: &big,
        };
        let mut out = Vec::new();
        match frame.encode(&mut out) {
            Err(FrameError::EncodeDataTooLarge { data_len, max }) => {
                assert_eq!(data_len, big.len());
                assert_eq!(max, DATA_MAX);
            }
            other => panic!("expected EncodeDataTooLarge, got {other:?}"),
        }
        assert!(out.is_empty(), "out must be unchanged on encode failure");
    }

    #[test]
    fn encode_rejects_oversized_fd_count() {
        let many: Vec<PassedToken> = (0..=(FD_COUNT_MAX as usize))
            .map(|i| pt(i as u64))
            .collect();
        let frame = FdTransferFrame {
            tokens: &many,
            data: &[],
        };
        let mut out = Vec::new();
        match frame.encode(&mut out) {
            Err(FrameError::EncodeFdCountTooLarge { fd_count, max }) => {
                assert_eq!(fd_count, many.len());
                assert_eq!(max, FD_COUNT_MAX);
            }
            other => panic!("expected EncodeFdCountTooLarge, got {other:?}"),
        }
        assert!(out.is_empty(), "out must be unchanged on encode failure");
    }

    #[test]
    fn boundary_max_data_len_round_trips() {
        let payload = vec![0xa5u8; DATA_MAX as usize];
        let frame = FdTransferFrame {
            tokens: &[pt(1), pt(2), pt(3)],
            data: &payload,
        };
        let mut buf = Vec::new();
        frame.encode(&mut buf).expect("encode at max");
        let decoded = decode_frame(&buf).expect("decode at max");
        assert_eq!(decoded.tokens, [pt(1), pt(2), pt(3)]);
        assert_eq!(decoded.data.len(), DATA_MAX as usize);
        assert!(decoded.data.iter().all(|&b| b == 0xa5));
    }

    #[test]
    fn boundary_max_fd_count_round_trips() {
        let tokens: Vec<PassedToken> = (0..u64::from(FD_COUNT_MAX)).map(pt).collect();
        let frame = FdTransferFrame {
            tokens: &tokens,
            data: b"x",
        };
        let mut buf = Vec::new();
        frame.encode(&mut buf).expect("encode at max fd_count");
        let decoded = decode_frame(&buf).expect("decode at max fd_count");
        assert_eq!(decoded.tokens, tokens);
        assert_eq!(decoded.data, b"x");
    }

    #[test]
    fn frame_constants_match_doc() {
        // Sanity: FRAME_HEADER_LEN is the documented 16-byte layout.
        assert_eq!(FRAME_HEADER_LEN, 16);
        // ASCII for "LBFD" little-endian.
        assert_eq!(&FRAME_MAGIC.to_le_bytes(), b"DFBL");
    }
}
