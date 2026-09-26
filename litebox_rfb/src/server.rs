// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use std::io::{self, Write};
use std::net::{IpAddr, Ipv4Addr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, PoisonError};
use std::time::{Duration, Instant};

use crate::proto::{self, PixelFormat};

/// A boxed input-message handler, shared across every connected client's serving thread.
pub(crate) type InputHandler = dyn Fn(InputMessage) + Send + Sync;

static NEXT_INPUT_CLIENT_ID: AtomicU64 = AtomicU64::new(1);

/// A pointer (mouse) event received from a connected client (RFC 6143 §7.5.5).
#[derive(Debug, Clone, Copy)]
pub struct PointerEvent {
    /// Bit N set = button N+1 currently pressed (bit 0 = left, bit 1 = middle, bit 2 = right,
    /// bits 3/4 = scroll wheel up/down on most clients).
    pub button_mask: u8,
    pub x: u16,
    pub y: u16,
}

/// A key event received from a connected client (RFC 6143 §7.5.4). `key` is an X11 keysym
/// value, which is what every RFB client sends -- interpreting it into a guest scancode is the
/// caller's responsibility (litebox's evdev-emulation layer, once it exists).
#[derive(Debug, Clone, Copy)]
pub struct KeyEvent {
    pub down: bool,
    pub key: u32,
}

/// An input event this server received from a connected client, handed to
/// [`RfbServer::run`]'s caller-supplied handler.
#[derive(Debug, Clone, Copy)]
pub enum InputEvent {
    Pointer(PointerEvent),
    Key(KeyEvent),
}

/// Process-unique identity of one input-capable RFB or browser connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct InputClientId(u64);

/// Input connection lifecycle and event stream delivered to the runner.
#[derive(Debug, Clone, Copy)]
pub enum InputMessage {
    Connected(InputClientId),
    Event {
        client: InputClientId,
        event: InputEvent,
    },
    Disconnected(InputClientId),
}

/// Emits a balanced connection lifecycle even when a read loop returns through an error path.
pub(crate) struct InputClient<'a> {
    id: Option<InputClientId>,
    on_input: &'a InputHandler,
}

impl<'a> InputClient<'a> {
    pub(crate) fn connect(on_input: &'a InputHandler) -> Self {
        let raw = NEXT_INPUT_CLIENT_ID
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |id| id.checked_add(1))
            .expect("RFB input client ID space exhausted");
        let client = Self {
            id: Some(InputClientId(raw)),
            on_input,
        };
        (client.on_input)(InputMessage::Connected(
            client.id.expect("new input client must be connected"),
        ));
        client
    }

    pub(crate) fn send(&self, event: InputEvent) {
        let Some(client) = self.id else {
            return;
        };
        (self.on_input)(InputMessage::Event { client, event });
    }

    pub(crate) fn disconnect(&mut self) {
        if let Some(client) = self.id.take() {
            (self.on_input)(InputMessage::Disconnected(client));
        }
    }
}

impl Drop for InputClient<'_> {
    fn drop(&mut self) {
        self.disconnect();
    }
}

/// What this server needs from a caller-owned framebuffer: current dimensions and a snapshot of
/// the pixel bytes. Kept minimal and decoupled from any concrete framebuffer type (in
/// particular, `litebox::fs::devices::framebuffer::Framebuffer<Platform>` is generic over a
/// platform type this crate has no reason to depend on) -- the caller adapts its own
/// framebuffer type to this trait.
pub trait FramebufferSource: Send + Sync + 'static {
    /// Current `(width, height)` in pixels.
    fn dimensions(&self) -> (u16, u16);

    /// Copy the current frame's pixel bytes (32bpp, litebox's native in-memory XRGB8888 layout,
    /// row-major, `dimensions().0 * 4` stride, no padding between rows) into `dst`, resizing it
    /// to fit exactly.
    fn snapshot_into(&self, dst: &mut Vec<u8>);
}

/// A minimal RFB server bound to one address, presenting one [`FramebufferSource`] to any number
/// of concurrently connected clients (each served on its own thread).
pub struct RfbServer<F: FramebufferSource> {
    listener: TcpListener,
    framebuffer: Arc<F>,
    shutdown: Arc<AtomicBool>,
}

impl<F: FramebufferSource> RfbServer<F> {
    /// Binds a new server. `addr` defaults to `127.0.0.1` (localhost-only) when `None` --
    /// callers wanting LAN/remote access must opt in explicitly by passing an address that says
    /// so, matching this feature's default-closed security posture (see the `--vnc` flag's own
    /// doc comment in the runner that constructs this).
    pub fn bind(addr: Option<IpAddr>, port: u16, framebuffer: Arc<F>) -> io::Result<Self> {
        let addr = addr.unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST));
        let listener = TcpListener::bind((addr, port))?;
        Ok(Self {
            listener,
            framebuffer,
            shutdown: Arc::new(AtomicBool::new(false)),
        })
    }

    /// The address this server actually bound to (useful when `port` was `0`, letting the OS
    /// pick one).
    pub fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
        self.listener.local_addr()
    }

    /// A handle that, when [`ShutdownHandle::signal`] is called, makes every in-progress and
    /// future `accept()` in [`Self::run`] return promptly (checked once per `accept()` timeout
    /// tick -- see [`Self::run`]'s doc comment for the exact latency bound).
    pub fn shutdown_handle(&self) -> ShutdownHandle {
        ShutdownHandle {
            flag: Arc::clone(&self.shutdown),
        }
    }

    /// Accepts connections until shut down, serving each on its own spawned thread. `on_input`
    /// is called from whichever client thread received the event -- callers that need to
    /// serialize input from multiple concurrent clients (only one guest to drive, potentially
    /// several attached viewers) must do so themselves (e.g. route through a single mpsc
    /// channel), matching this server's single-writer-elsewhere design rather than imposing one
    /// here.
    ///
    /// Checks the shutdown flag once per accept-loop iteration; `accept()` itself is given a
    /// 500ms read timeout via a raw socket option so a call to [`ShutdownHandle::signal`] is
    /// noticed within that bound rather than blocking forever on a `TcpListener` with no pending
    /// connection.
    pub fn run(&self, on_input: impl Fn(InputMessage) + Send + Sync + 'static) -> io::Result<()> {
        self.listener.set_nonblocking(true)?;
        let on_input: Arc<InputHandler> = Arc::new(on_input);
        while !self.shutdown.load(Ordering::Relaxed) {
            match self.listener.accept() {
                Ok((stream, peer)) => {
                    litebox_util_log::info!(peer:% = peer; "rfb client connecting");
                    let framebuffer = Arc::clone(&self.framebuffer);
                    let on_input = Arc::clone(&on_input);
                    let shutdown = Arc::clone(&self.shutdown);
                    std::thread::spawn(move || {
                        if let Err(e) = serve_client(stream, &framebuffer, &on_input, &shutdown) {
                            litebox_util_log::debug!(peer:% = peer, error:% = e; "rfb client disconnected");
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

/// A handle to request shutdown of a running [`RfbServer::run`] loop.
#[derive(Clone)]
pub struct ShutdownHandle {
    pub(crate) flag: Arc<AtomicBool>,
}

impl ShutdownHandle {
    pub fn signal(&self) {
        self.flag.store(true, Ordering::Relaxed);
    }
}

/// Minimum interval between two framebuffer snapshots taken for one client: the cap on the update
/// rate a client can pull (20 Hz), and the poll period while a client's outstanding
/// `FramebufferUpdateRequest` waits for the screen to change.
const UPDATE_INTERVAL: Duration = Duration::from_millis(50);

/// Height of the full-width bands the framebuffer is diffed in. An incremental update carries only
/// the bands that changed since the previous update to that client, merged into one Raw rectangle
/// per run of adjacent dirty bands.
const BAND_ROWS: u16 = 32;

/// One client's outstanding `FramebufferUpdateRequest` state, shared between the reader thread
/// that records requests and the update thread that answers them.
///
/// Updates are sent only while a request is outstanding (RFC 6143 §7.5.3). Every real client
/// re-requests immediately after consuming an update, so this is RFB's own flow control: a client
/// has at most one update in flight, a slow client never accumulates a backlog of stale frames,
/// and each update is built from the newest frame at the moment the client is ready for it
/// (intermediate frames are simply never captured). One client's pace affects nobody else --
/// each connection has its own reader and update thread and its own snapshot.
struct UpdateRequest {
    state: Mutex<RequestState>,
    changed: Condvar,
}

#[derive(Default)]
struct RequestState {
    /// Bumped by every request, so the update thread can tell whether the request it just
    /// answered is still the newest or a further one arrived while it was writing.
    seq: u64,
    /// A request has arrived and not yet been answered.
    pending: bool,
    /// The outstanding request (or one coalesced into it) had `incremental = 0`: answer with the
    /// whole framebuffer rather than only the bands that changed.
    full: bool,
    /// The reader thread is done; the update thread must exit.
    stop: bool,
}

impl UpdateRequest {
    fn new() -> Self {
        Self {
            state: Mutex::new(RequestState::default()),
            changed: Condvar::new(),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, RequestState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn request(&self, full: bool) {
        let mut state = self.lock();
        state.seq += 1;
        state.pending = true;
        state.full |= full;
        self.changed.notify_one();
    }

    fn stop(&self) {
        self.lock().stop = true;
        self.changed.notify_all();
    }

    /// Blocks until a request is outstanding, returning its sequence number and whether it wants
    /// the whole framebuffer; `None` once stopped.
    fn wait(&self) -> Option<(u64, bool)> {
        let state = self
            .changed
            .wait_while(self.lock(), |state| !state.pending && !state.stop)
            .unwrap_or_else(PoisonError::into_inner);
        (!state.stop).then_some((state.seq, state.full))
    }

    /// Marks request `seq` answered. A request that arrived after `seq` was taken stays
    /// outstanding: the client asked again after this update was already being built, and
    /// dropping that request would leave it waiting forever.
    fn answered(&self, seq: u64) {
        let mut state = self.lock();
        if state.seq == seq {
            state.pending = false;
            state.full = false;
        }
    }
}

fn serve_client<F: FramebufferSource>(
    mut stream: TcpStream,
    framebuffer: &Arc<F>,
    on_input: &Arc<InputHandler>,
    shutdown: &AtomicBool,
) -> io::Result<()> {
    // `TcpStream`s returned from `TcpListener::accept()` inherit the listener's non-blocking
    // mode (set in `RfbServer::run` so the accept loop itself can poll the shutdown flag) --
    // this thread wants ordinary blocking reads/writes for the handshake and message loop below.
    stream.set_nonblocking(false)?;
    stream.set_nodelay(true)?;
    handshake(&mut stream)?;

    // A second thread on the same connection writes framebuffer updates while this (the
    // original) thread blocks reading client input -- RFB is bidirectional on one TCP
    // connection, and cloning a `TcpStream` yields an independent handle to the same underlying
    // socket, safe to read/write from different threads concurrently.
    let mut write_stream = stream.try_clone()?;
    // Bounds how long a client that stops draining its socket (zero TCP receive window, no
    // RST) can pin the update thread inside a blocking write: without this, that thread -- and
    // the fd it holds -- leaks for the life of the process instead of tearing the connection
    // down. Generous relative to `UPDATE_INTERVAL` since it only fires for a genuinely stalled
    // peer, matching the web viewer's own write timeout (`web.rs`'s `WsWriter`).
    write_stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    let (width, height) = framebuffer.dimensions();
    write_server_init(&mut stream, width, height)?;
    let input_client = InputClient::connect(&**on_input);

    let requests = Arc::new(UpdateRequest::new());
    let pusher = {
        let framebuffer = Arc::clone(framebuffer);
        let requests = Arc::clone(&requests);
        std::thread::spawn(move || {
            if serve_updates(&mut write_stream, &*framebuffer, &requests).is_err() {
                // Wake the reader thread out of its blocking read so the connection tears down
                // promptly instead of lingering until the peer notices.
                let _ = write_stream.shutdown(std::net::Shutdown::Both);
            }
        })
    };

    let result = read_client_loop(&mut stream, &input_client, &requests, shutdown);
    // Release this client's held input before waiting for the framebuffer pusher. Its socket write
    // may still be blocked or timing out after the reader observed disconnect.
    drop(input_client);

    requests.stop();
    let _ = pusher.join();
    result
}

/// Answers a client's `FramebufferUpdateRequest`s until stopped or the socket fails. See
/// [`UpdateRequest`] for the flow-control contract.
fn serve_updates(
    stream: &mut TcpStream,
    framebuffer: &impl FramebufferSource,
    requests: &UpdateRequest,
) -> io::Result<()> {
    let mut current = Vec::new();
    // Pixels of the last update written to this client (empty until the first), so that an
    // incremental update carries only the bands that changed since then.
    let mut sent = Vec::new();
    let mut sent_dims = (0u16, 0u16);
    let mut last_snapshot: Option<Instant> = None;
    let mut message = Vec::new();
    while let Some((seq, full)) = requests.wait() {
        if let Some(at) = last_snapshot {
            std::thread::sleep(UPDATE_INTERVAL.saturating_sub(at.elapsed()));
        }
        // Dimensions are re-read every time so a mid-session `FBIOPUT_VSCREENINFO` resize is
        // picked up without a dedicated notification channel; the client sees it as an ordinary
        // full FramebufferUpdate whose rectangle now covers the new size (`DesktopSize`
        // pseudo-encoding is out of scope, see the module doc comment).
        let dims = framebuffer.dimensions();
        framebuffer.snapshot_into(&mut current);
        last_snapshot = Some(Instant::now());
        let stride = usize::from(dims.0) * 4;
        let rows = current.len().checked_div(stride).map_or(0, |rows| {
            u16::try_from(rows).unwrap_or(u16::MAX).min(dims.1)
        });
        let full = full || dims != sent_dims || current.len() != sent.len();
        let rects = if rows == 0 {
            Vec::new()
        } else if full {
            vec![(0, rows)]
        } else {
            dirty_bands(&sent, &current, stride, rows)
        };
        if rects.is_empty() && !full {
            // Nothing changed: the request stays outstanding and is re-evaluated next tick.
            continue;
        }
        encode_framebuffer_update(&mut message, dims.0, stride, &current, &rects);
        stream.write_all(&message)?;
        stream.flush()?;
        std::mem::swap(&mut sent, &mut current);
        sent_dims = dims;
        requests.answered(seq);
    }
    Ok(())
}

/// The `(y, height)` runs of adjacent [`BAND_ROWS`]-row bands whose pixels differ between
/// `sent` and `current` (both `rows * stride` bytes).
fn dirty_bands(sent: &[u8], current: &[u8], stride: usize, rows: u16) -> Vec<(u16, u16)> {
    let mut runs: Vec<(u16, u16)> = Vec::new();
    let mut y = 0u16;
    while y < rows {
        let height = BAND_ROWS.min(rows - y);
        let bytes = usize::from(y) * stride..usize::from(y + height) * stride;
        if sent[bytes.clone()] != current[bytes] {
            match runs.last_mut() {
                Some((run_y, run_height)) if *run_y + *run_height == y => *run_height += height,
                _ => runs.push((y, height)),
            }
        }
        y += height;
    }
    runs
}

/// RFC 6143 §7.6.1: one `FramebufferUpdate` message with one full-width Raw rectangle per
/// `(y, height)` entry of `rects`, assembled into `out` so the whole update leaves in one write.
fn encode_framebuffer_update(
    out: &mut Vec<u8>,
    width: u16,
    stride: usize,
    pixels: &[u8],
    rects: &[(u16, u16)],
) {
    out.clear();
    out.extend_from_slice(&[proto::SERVER_FRAMEBUFFER_UPDATE, 0 /* padding */]);
    // Dirty runs are separated by clean bands, so there are at most `u16::MAX / BAND_ROWS / 2`
    // of them: the count always fits.
    out.extend_from_slice(&u16::try_from(rects.len()).unwrap_or(u16::MAX).to_be_bytes());
    for &(y, height) in rects {
        // Rectangle header: x, y, width, height, encoding-type.
        out.extend_from_slice(&0u16.to_be_bytes());
        out.extend_from_slice(&y.to_be_bytes());
        out.extend_from_slice(&width.to_be_bytes());
        out.extend_from_slice(&height.to_be_bytes());
        out.extend_from_slice(&proto::ENCODING_RAW.to_be_bytes());
        out.extend_from_slice(&pixels[usize::from(y) * stride..usize::from(y + height) * stride]);
    }
}

/// RFC 6143 §7.1: version negotiation, security handshake (`None` only), `ClientInit`.
fn handshake(stream: &mut (impl io::Read + io::Write)) -> io::Result<()> {
    // §7.1.1: server sends its supported version first.
    stream.write_all(proto::PROTOCOL_VERSION)?;
    let mut client_version = [0u8; 12];
    stream.read_exact(&mut client_version)?;
    // Accept any client-claimed version -- this server only ever speaks the 3.8 message set
    // regardless of what the client says, which is compatible with every RFB client in
    // practice (3.3/3.7/3.8 client message framing for the subset used here is identical).

    // §7.1.2: security-types list, one type (`None`), then read the client's chosen type back.
    stream.write_all(&[1u8, proto::SECURITY_TYPE_NONE])?;
    let mut chosen = [0u8; 1];
    stream.read_exact(&mut chosen)?;

    // §7.1.3: SecurityResult -- always OK, since `None` cannot fail.
    stream.write_all(&proto::SECURITY_RESULT_OK.to_be_bytes())?;

    // §7.3.1: ClientInit (one byte, shared-flag) -- read and ignore; this server always allows
    // shared access (multiple simultaneous viewers), matching the single-guest/many-observers
    // shape the framebuffer feature is built for.
    let mut shared_flag = [0u8; 1];
    stream.read_exact(&mut shared_flag)?;

    Ok(())
}

/// RFC 6143 §7.3.2: `ServerInit` -- framebuffer dimensions, pixel format, name.
fn write_server_init(stream: &mut impl io::Write, width: u16, height: u16) -> io::Result<()> {
    /// Desktop name sent in `ServerInit`. Fixed at compile time, so casting its `len()` to `u32`
    /// below can never truncate.
    const NAME: &[u8] = b"litebox";
    #[allow(clippy::cast_possible_truncation)]
    const NAME_LEN: u32 = NAME.len() as u32;

    stream.write_all(&width.to_be_bytes())?;
    stream.write_all(&height.to_be_bytes())?;
    PixelFormat::write(stream)?;
    stream.write_all(&NAME_LEN.to_be_bytes())?;
    stream.write_all(NAME)?;
    stream.flush()
}

/// Reads and dispatches client-to-server messages until the connection closes or a fatal I/O
/// error occurs. RFC 6143 §7.5.
fn read_client_loop(
    stream: &mut impl io::Read,
    input_client: &InputClient<'_>,
    requests: &UpdateRequest,
    shutdown: &AtomicBool,
) -> io::Result<()> {
    let mut msg_type = [0u8; 1];
    loop {
        if shutdown.load(Ordering::Relaxed) {
            return Ok(());
        }
        match stream.read_exact(&mut msg_type) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(e) => return Err(e),
        }
        match msg_type[0] {
            proto::CLIENT_SET_PIXEL_FORMAT => {
                // 3 bytes padding + 16-byte PIXEL_FORMAT the client wants -- ignored; this
                // server always sends its own fixed 32bpp format (RFC 6143 permits a server to
                // do this; a compliant client must be able to consume it).
                proto::skip(stream, 3 + 16)?;
            }
            proto::CLIENT_SET_ENCODINGS => {
                proto::skip(stream, 1)?; // padding
                let count = proto::read_u16(stream)?;
                proto::skip(stream, usize::from(count) * 4)?; // each encoding is an i32
            }
            proto::CLIENT_FRAMEBUFFER_UPDATE_REQUEST => {
                let mut incremental = [0u8; 1];
                stream.read_exact(&mut incremental)?;
                // x,y,w,h (u16 each) -- ignored: updates always cover full-width bands, which a
                // client must tolerate (§7.5.3 lets a server send more than the requested area).
                proto::skip(stream, 2 + 2 + 2 + 2)?;
                requests.request(incremental[0] == 0);
            }
            proto::CLIENT_KEY_EVENT => {
                let mut down_byte = [0u8; 1];
                stream.read_exact(&mut down_byte)?;
                proto::skip(stream, 2)?; // padding
                let key = proto::read_u32(stream)?;
                input_client.send(InputEvent::Key(KeyEvent {
                    down: down_byte[0] != 0,
                    key,
                }));
            }
            proto::CLIENT_POINTER_EVENT => {
                let mut mask = [0u8; 1];
                stream.read_exact(&mut mask)?;
                let x = proto::read_u16(stream)?;
                let y = proto::read_u16(stream)?;
                input_client.send(InputEvent::Pointer(PointerEvent {
                    button_mask: mask[0],
                    x,
                    y,
                }));
            }
            proto::CLIENT_CUT_TEXT => {
                proto::skip(stream, 3)?; // padding
                let len = proto::read_u32(stream)?;
                proto::skip(stream, len as usize)?;
            }
            unknown => {
                litebox_util_log::warn!(msg_type:% = unknown; "rfb: unrecognized client message type, closing connection");
                return Ok(());
            }
        }
    }
}
