// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! A browser-based viewer for the guest framebuffer: one tiny HTTP server that serves an
//! embedded single-page canvas client at `/` and speaks a WebSocket protocol at `/ws`.
//!
//! Rationale: macOS's built-in Screen Sharing refuses to dial localhost (it treats a
//! self-connection as controlling your own screen), so "just point a VNC viewer at
//! 127.0.0.1" fails on exactly the machine the runner runs on. A browser has no such rule,
//! ships on every host, and needs no install. The page and the wire protocol are both ours,
//! so this sidesteps RFB client compatibility entirely.
//!
//! Wire protocol, deliberately simpler than RFB:
//! * server -> client, binary: `[u16 width BE][u16 height BE][width*height*4 RGBA bytes]` --
//!   one whole frame per message, sent only when the frame content changed, at most every
//!   `FRAME_INTERVAL` (50ms), and only once the browser has acknowledged the previous frame:
//!   each frame is followed by a WebSocket ping carrying the frame's sequence number, and every
//!   browser answers pings with a pong automatically (RFC 6455 §5.5.2), so the pong is a
//!   frame-consumed signal that needs nothing from the page's own script (see `FrameAcks`).
//! * client -> server, binary: `[1u8][down u8][keysym u32 BE]` for keys (X11 keysyms, same
//!   values RFB uses, so the runner's existing translation applies unchanged), and
//!   `[2u8][button_mask u8][x u16 BE][y u16 BE]` for pointer state (RFB-style mask: bit 0
//!   left, bit 1 middle, bit 2 right, bits 3/4 wheel up/down edges).
//!
//! Hand-rolled HTTP/WebSocket (RFC 6455) rather than a crate dependency, for the same reason
//! the RFB server is hand-rolled (see the crate docs): the handshake needs only SHA-1 +
//! base64, both small enough to carry inline, and the framing needed here is a strict subset
//! of the RFC.

use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, PoisonError};
use std::time::Duration;

use crate::server::{
    FramebufferSource, InputClient, InputEvent, InputHandler, InputMessage, KeyEvent, PointerEvent,
};

/// Interval between frame pushes to a connected browser. Same cadence as the RFB server's
/// `UPDATE_INTERVAL`; unchanged frames are skipped entirely, so idle cost is one
/// snapshot+compare per tick.
const FRAME_INTERVAL: Duration = Duration::from_millis(50);

/// Longest the pusher waits for the pong acknowledging the previous frame before sending the next
/// one regardless. Bounds the damage a client that never answers pings can do to its own frame
/// rate (1 fps) without letting it hold a frame back forever.
const FRAME_ACK_TIMEOUT: Duration = Duration::from_secs(1);

/// Maximum time a client may spend completing its HTTP request head.
const HTTP_HEAD_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// The embedded viewer page served at `/`.
const VIEWER_HTML: &str = include_str!("viewer.html");

/// A browser-viewer server for a guest framebuffer. Mirrors [`crate::RfbServer`]'s lifecycle:
/// bind before any sandbox comes up, then `run` the accept loop on its own thread.
pub struct WebServer<F: FramebufferSource> {
    listener: TcpListener,
    framebuffer: Arc<F>,
    shutdown: Arc<AtomicBool>,
}

impl<F: FramebufferSource> WebServer<F> {
    /// Binds a new server. `addr` defaults to `127.0.0.1` (localhost-only) when `None`,
    /// matching the RFB server's default-closed posture.
    ///
    /// # Errors
    ///
    /// Fails if the TCP listener cannot bind.
    pub fn bind(addr: Option<IpAddr>, port: u16, framebuffer: Arc<F>) -> io::Result<Self> {
        let addr = addr.unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST));
        let listener = TcpListener::bind((addr, port))?;
        Ok(Self {
            listener,
            framebuffer,
            shutdown: Arc::new(AtomicBool::new(false)),
        })
    }

    /// The address this server actually bound to.
    ///
    /// # Errors
    ///
    /// Propagates the socket's `local_addr` failure.
    pub fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
        self.listener.local_addr()
    }

    /// See [`crate::RfbServer::shutdown_handle`].
    #[must_use]
    pub fn shutdown_handle(&self) -> crate::ShutdownHandle {
        crate::ShutdownHandle {
            flag: Arc::clone(&self.shutdown),
        }
    }

    /// Accepts connections until shut down, serving each on its own spawned thread; same
    /// contract as [`crate::RfbServer::run`].
    ///
    /// # Errors
    ///
    /// Returns any accept-loop error other than the polling `WouldBlock`.
    pub fn run(&self, on_input: impl Fn(InputMessage) + Send + Sync + 'static) -> io::Result<()> {
        self.listener.set_nonblocking(true)?;
        let on_input: Arc<InputHandler> = Arc::new(on_input);
        while !self.shutdown.load(Ordering::Relaxed) {
            match self.listener.accept() {
                Ok((stream, peer)) => {
                    litebox_util_log::info!(peer:% = peer; "web viewer client connecting");
                    let framebuffer = Arc::clone(&self.framebuffer);
                    let on_input = Arc::clone(&on_input);
                    std::thread::spawn(move || {
                        if let Err(e) = serve_connection(stream, &framebuffer, &on_input) {
                            litebox_util_log::debug!(peer:% = peer, error:% = e; "web viewer client done");
                        }
                    });
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    std::thread::sleep(std::time::Duration::from_millis(500));
                }
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }
}

/// Reads one HTTP request head (through `\r\n\r\n`) and routes it.
fn serve_connection<F: FramebufferSource>(
    stream: TcpStream,
    framebuffer: &Arc<F>,
    on_input: &Arc<InputHandler>,
) -> io::Result<()> {
    serve_connection_with_head_timeout(stream, framebuffer, on_input, HTTP_HEAD_TIMEOUT)
}

fn serve_connection_with_head_timeout<F: FramebufferSource>(
    mut stream: TcpStream,
    framebuffer: &Arc<F>,
    on_input: &Arc<InputHandler>,
    budget: std::time::Duration,
) -> io::Result<()> {
    stream.set_nonblocking(false)?;
    stream.set_nodelay(true)?;
    let local_addr = stream.local_addr()?;
    let deadline = std::time::Instant::now()
        .checked_add(budget)
        .ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "HTTP head timeout too large")
        })?;

    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if head.len() > 16 * 1024 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "header too long",
            ));
        }
        let remaining = deadline
            .checked_duration_since(std::time::Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "HTTP head timed out"))?;
        stream.set_read_timeout(Some(remaining))?;
        stream.read_exact(&mut byte)?;
        head.push(byte[0]);
    }
    stream.set_read_timeout(None)?;
    let head = String::from_utf8_lossy(&head).into_owned();
    let request_line = head.lines().next().unwrap_or("");
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let path = parts.next().unwrap_or("");

    let header = |name: &str| -> Option<&str> {
        let mut values = head.lines().filter_map(|line| {
            let (key, value) = line.split_once(':')?;
            key.trim().eq_ignore_ascii_case(name).then(|| value.trim())
        });
        let value = values.next()?;
        values.next().is_none().then_some(value)
    };

    if !method.eq_ignore_ascii_case("GET") {
        stream.write_all(b"HTTP/1.1 405 Method Not Allowed\r\nConnection: close\r\n\r\n")?;
        return Ok(());
    }

    match path {
        "/" | "/index.html" => {
            let body = VIEWER_HTML.as_bytes();
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            stream.write_all(resp.as_bytes())?;
            stream.write_all(body)?;
            Ok(())
        }
        "/ws" => {
            let Some(key) = header("Sec-WebSocket-Key").filter(|key| !key.is_empty()) else {
                stream.write_all(b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n")?;
                return Ok(());
            };
            let valid_upgrade = header("Upgrade")
                .is_some_and(|value| value.eq_ignore_ascii_case("websocket"))
                && header("Connection").is_some_and(|value| {
                    value
                        .split(',')
                        .any(|token| token.trim().eq_ignore_ascii_case("upgrade"))
                })
                && header("Sec-WebSocket-Version") == Some("13");
            if !valid_upgrade {
                stream.write_all(b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n")?;
                return Ok(());
            }
            let valid_origin = match (header("Host"), header("Origin")) {
                (Some(host), Some(origin)) => {
                    let endpoint_host = local_addr.to_string();
                    let loopback_host = format!("localhost:{}", local_addr.port());
                    let host_allowed = host.eq_ignore_ascii_case(&endpoint_host)
                        || (local_addr.ip().is_loopback()
                            && host.eq_ignore_ascii_case(&loopback_host));
                    host_allowed && origin.eq_ignore_ascii_case(&format!("http://{host}"))
                }
                _ => false,
            };
            if !valid_origin {
                stream.write_all(b"HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n")?;
                return Ok(());
            }
            let accept = websocket_accept_value(key);
            let resp = format!(
                "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n"
            );
            stream.write_all(resp.as_bytes())?;
            serve_websocket(stream, framebuffer, on_input)
        }
        _ => {
            stream.write_all(b"HTTP/1.1 404 Not Found\r\nConnection: close\r\n\r\n")?;
            Ok(())
        }
    }
}

/// Serializes every server-to-client operation on one connection.
struct WsWriter {
    stream: std::sync::Mutex<TcpStream>,
}

impl WsWriter {
    fn new(stream: TcpStream) -> Self {
        Self {
            stream: std::sync::Mutex::new(stream),
        }
    }

    fn write(&self, operation: impl FnOnce(&mut TcpStream) -> io::Result<()>) -> io::Result<()> {
        let mut stream = self
            .stream
            .lock()
            .map_err(|_| io::Error::other("WebSocket writer lock poisoned"))?;
        if let Err(error) = operation(&mut stream) {
            let _ = stream.shutdown(std::net::Shutdown::Both);
            return Err(error);
        }
        Ok(())
    }

    fn write_binary(&self, payload: &[u8]) -> io::Result<()> {
        self.write(|stream| write_ws_binary_frames(stream, payload))
    }

    fn write_control(&self, opcode: u8, payload: &[u8]) -> io::Result<()> {
        // 0x8 close, 0x9 ping (the pusher's frame-consumed probe, see `FrameAcks`), 0xa pong.
        if !matches!(opcode, 0x8..=0xa) || payload.len() > 125 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid WebSocket control frame",
            ));
        }
        self.write(|stream| write_ws_frame(stream, true, opcode, payload))
    }

    fn try_write_control(&self, opcode: u8, payload: &[u8]) -> io::Result<()> {
        if !matches!(opcode, 0x8..=0xa) || payload.len() > 125 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid WebSocket control frame",
            ));
        }
        let Ok(mut stream) = self.stream.try_lock() else {
            // A framebuffer write can fill the socket after the peer has stopped reading. Input
            // teardown must never wait behind it; closing the TCP stream is itself a valid close
            // response when the best-effort control frame cannot be written immediately.
            return Ok(());
        };
        write_ws_frame(&mut stream, true, opcode, payload)
    }
}

/// Frame acknowledgements for one browser connection: the highest frame sequence number whose
/// ping the client has answered, shared between the reader thread (which records pongs) and the
/// pusher (which waits for them). The wire protocol carries no application-level ack and the
/// page's script must not change, but a browser pongs only once its network stack has read
/// past the frame, and Chromium/Firefox read from the socket only as fast as the page consumes
/// messages -- so waiting for the pong keeps at most one frame in flight per client and lets
/// the pusher snapshot the newest frame at the moment the browser is ready for it. Without it,
/// TCP alone lets a slow page queue seconds of stale frames in socket and browser buffers.
struct FrameAcks {
    state: Mutex<AckState>,
    changed: Condvar,
}

#[derive(Default)]
struct AckState {
    acked: u64,
    stop: bool,
}

impl FrameAcks {
    fn new() -> Self {
        Self {
            state: Mutex::new(AckState::default()),
            changed: Condvar::new(),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, AckState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn ack(&self, seq: u64) {
        let mut state = self.lock();
        state.acked = state.acked.max(seq);
        self.changed.notify_all();
    }

    fn stop(&self) {
        self.lock().stop = true;
        self.changed.notify_all();
    }

    /// Waits until frame `seq` is acknowledged or `timeout` passes; `false` once stopped.
    fn wait_acked(&self, seq: u64, timeout: Duration) -> bool {
        let (state, _) = self
            .changed
            .wait_timeout_while(self.lock(), timeout, |state| {
                state.acked < seq && !state.stop
            })
            .unwrap_or_else(PoisonError::into_inner);
        !state.stop
    }
}

/// After the 101: a pusher thread streams changed frames while this thread reads input
/// messages -- the same two-thread split as the RFB server's `serve_client`.
fn serve_websocket<F: FramebufferSource>(
    stream: TcpStream,
    framebuffer: &Arc<F>,
    on_input: &Arc<InputHandler>,
) -> io::Result<()> {
    let write_stream = stream.try_clone()?;
    write_stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    let writer = Arc::new(WsWriter::new(write_stream));
    let mut input_client = InputClient::connect(&**on_input);
    let acks = Arc::new(FrameAcks::new());
    let pusher = {
        let framebuffer = Arc::clone(framebuffer);
        let writer = Arc::clone(&writer);
        let acks = Arc::clone(&acks);
        std::thread::spawn(move || {
            let mut pixels = Vec::new();
            // Pixels of the last frame sent, so unchanged frames are skipped outright.
            let mut sent = Vec::new();
            let mut message = Vec::new();
            let mut seq = 0u64;
            loop {
                std::thread::sleep(FRAME_INTERVAL);
                if !acks.wait_acked(seq, FRAME_ACK_TIMEOUT) {
                    break;
                }
                let (width, height) = framebuffer.dimensions();
                framebuffer.snapshot_into(&mut pixels);
                if pixels == sent {
                    continue;
                }
                message.clear();
                message.extend_from_slice(&width.to_be_bytes());
                message.extend_from_slice(&height.to_be_bytes());
                // XRGB8888 little-endian memory order is B,G,R,X; the canvas wants R,G,B,A.
                for px in pixels.as_chunks::<4>().0 {
                    message.extend_from_slice(&[px[2], px[1], px[0], 0xff]);
                }
                seq += 1;
                if writer.write_binary(&message).is_err()
                    || writer.write_control(0x9, &seq.to_be_bytes()).is_err()
                {
                    break;
                }
                std::mem::swap(&mut sent, &mut pixels);
            }
        })
    };

    let result = read_ws_loop(stream, &writer, &acks, &mut input_client);
    // Input cleanup must not wait behind a framebuffer writer blocked on the disconnected socket.
    drop(input_client);
    acks.stop();
    let _ = pusher.join();
    result
}

/// One logical server-to-client binary message, split into bounded RFC 6455 fragments.
fn write_ws_binary_frames(stream: &mut TcpStream, payload: &[u8]) -> io::Result<()> {
    const FRAME_PAYLOAD_LIMIT: usize = u16::MAX as usize;

    if payload.is_empty() {
        return write_ws_frame(stream, true, 0x2, payload);
    }

    let mut chunks = payload.chunks(FRAME_PAYLOAD_LIMIT).peekable();
    let mut opcode = 0x2;
    while let Some(chunk) = chunks.next() {
        write_ws_frame(stream, chunks.peek().is_none(), opcode, chunk)?;
        opcode = 0x0;
    }
    Ok(())
}

fn write_ws_frame(stream: &mut TcpStream, fin: bool, opcode: u8, payload: &[u8]) -> io::Result<()> {
    let mut header = [0u8; 4];
    header[0] = (if fin { 0x80 } else { 0 }) | opcode;
    let header_len = if payload.len() < 126 {
        #[allow(clippy::cast_possible_truncation)]
        {
            header[1] = payload.len() as u8;
        }
        2
    } else {
        let len = u16::try_from(payload.len()).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "oversized WebSocket fragment")
        })?;
        header[1] = 126;
        header[2..].copy_from_slice(&len.to_be_bytes());
        4
    };
    stream.write_all(&header[..header_len])?;
    stream.write_all(payload)
}

/// Client-to-server frames: masked per RFC 6455. Handles binary input messages, answers ping
/// with pong, records the frame acknowledged by a pong, exits on close.
fn read_ws_loop(
    mut stream: TcpStream,
    writer: &WsWriter,
    acks: &FrameAcks,
    input_client: &mut InputClient<'_>,
) -> io::Result<()> {
    loop {
        let mut hdr = [0u8; 2];
        match stream.read_exact(&mut hdr) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(e) => return Err(e),
        }
        let fin = hdr[0] & 0x80 != 0;
        let opcode = hdr[0] & 0x0f;
        let masked = hdr[1] & 0x80 != 0;
        if hdr[0] & 0x70 != 0 || !fin || !masked {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid WebSocket client frame",
            ));
        }
        let mut len = u64::from(hdr[1] & 0x7f);
        if len == 126 {
            let mut ext = [0u8; 2];
            stream.read_exact(&mut ext)?;
            len = u64::from(u16::from_be_bytes(ext));
        } else if len == 127 {
            let mut ext = [0u8; 8];
            stream.read_exact(&mut ext)?;
            len = u64::from_be_bytes(ext);
        }
        if (opcode >= 0x8 && (len > 125 || (opcode == 0x8 && len == 1))) || len > 4096 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid WebSocket frame length",
            ));
        }
        let mut mask = [0u8; 4];
        stream.read_exact(&mut mask)?;
        #[allow(clippy::cast_possible_truncation)]
        let mut payload = vec![0u8; len as usize];
        stream.read_exact(&mut payload)?;
        for (i, b) in payload.iter_mut().enumerate() {
            *b ^= mask[i % 4];
        }
        match opcode {
            // Binary: our input messages.
            0x2 => match payload.first() {
                Some(1) if payload.len() == 6 => {
                    let key = u32::from_be_bytes([payload[2], payload[3], payload[4], payload[5]]);
                    input_client.send(InputEvent::Key(KeyEvent {
                        down: payload[1] != 0,
                        key,
                    }));
                }
                Some(2) if payload.len() == 6 => {
                    input_client.send(InputEvent::Pointer(PointerEvent {
                        button_mask: payload[1],
                        x: u16::from_be_bytes([payload[2], payload[3]]),
                        y: u16::from_be_bytes([payload[4], payload[5]]),
                    }));
                }
                _ => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "invalid WebSocket input message",
                    ));
                }
            },
            // Ping -> pong with the same payload.
            0x9 => writer.write_control(0xa, &payload)?,
            // Close -> close with the same payload.
            0x8 => {
                input_client.disconnect();
                writer.try_write_control(0x8, &payload)?;
                return Ok(());
            }
            // Pong: the answer to the ping sent after a frame carries that frame's sequence
            // number (see `FrameAcks`); any other pong is a no-op.
            0xa => {
                if let Ok(seq) = <[u8; 8]>::try_from(payload.as_slice()) {
                    acks.ack(u64::from_be_bytes(seq));
                }
            }
            // This endpoint accepts binary input only.
            0x1 => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "unsupported WebSocket text message",
                ));
            }
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "unsupported WebSocket opcode",
                ));
            }
        }
    }
}

/// RFC 6455 §4.2.2: `base64(SHA1(key ++ magic GUID))`.
fn websocket_accept_value(key: &str) -> String {
    let mut input = key.as_bytes().to_vec();
    input.extend_from_slice(b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
    base64(&sha1(&input))
}

/// SHA-1 (RFC 3174). Used only for the WebSocket handshake, where SHA-1's cryptographic
/// weakness is irrelevant (the value is an anti-cache token, not a security boundary).
fn sha1(data: &[u8]) -> [u8; 20] {
    let mut state: [u32; 5] = [
        0x6745_2301,
        0xefcd_ab89,
        0x98ba_dcfe,
        0x1032_5476,
        0xc3d2_e1f0,
    ];
    let bit_len = (data.len() as u64).wrapping_mul(8);
    let mut msg = data.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());
    for chunk in msg.as_chunks::<64>().0 {
        let mut sched = [0u32; 80];
        for (i, word) in chunk.as_chunks::<4>().0.iter().enumerate() {
            sched[i] = u32::from_be_bytes(*word);
        }
        for i in 16..80 {
            sched[i] = (sched[i - 3] ^ sched[i - 8] ^ sched[i - 14] ^ sched[i - 16]).rotate_left(1);
        }
        // RFC 3174's own variable names for the working state and round function.
        let (mut va, mut vb, mut vc, mut vd, mut ve) =
            (state[0], state[1], state[2], state[3], state[4]);
        for (i, &word) in sched.iter().enumerate() {
            let (round_fn, round_k) = match i {
                0..=19 => ((vb & vc) | (!vb & vd), 0x5a82_7999u32),
                20..=39 => (vb ^ vc ^ vd, 0x6ed9_eba1),
                40..=59 => ((vb & vc) | (vb & vd) | (vc & vd), 0x8f1b_bcdc),
                _ => (vb ^ vc ^ vd, 0xca62_c1d6),
            };
            let temp = va
                .rotate_left(5)
                .wrapping_add(round_fn)
                .wrapping_add(ve)
                .wrapping_add(round_k)
                .wrapping_add(word);
            ve = vd;
            vd = vc;
            vc = vb.rotate_left(30);
            vb = va;
            va = temp;
        }
        state[0] = state[0].wrapping_add(va);
        state[1] = state[1].wrapping_add(vb);
        state[2] = state[2].wrapping_add(vc);
        state[3] = state[3].wrapping_add(vd);
        state[4] = state[4].wrapping_add(ve);
    }
    let mut out = [0u8; 20];
    for (i, word) in state.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}

/// Standard base64 with padding.
fn base64(data: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        out.push(ALPHABET[(n >> 18) as usize & 63] as char);
        out.push(ALPHABET[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            ALPHABET[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            ALPHABET[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}
