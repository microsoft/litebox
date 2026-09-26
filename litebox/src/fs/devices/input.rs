// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! `/dev/input/event*` (evdev) emulation: a virtual keyboard and a virtual absolute-position
//! pointer, fed by a runner-side injector (the RFB server's input events) and read by guest
//! evdev consumers (evtest-style readers, X11 input drivers, libinput).
//!
//! Two devices, fixed:
//! * `event0` -- keyboard: `EV_KEY` for codes 1..=127 (the full AT-set-1 main block). No
//!   `EV_REP`: the X server does software autorepeat, and omitting the bit means consumers
//!   never issue `EVIOCGREP` (which would otherwise have to succeed -- libevdev aborts on its
//!   failure when the bit is advertised).
//! * `event1` -- pointer: `EV_KEY` for `BTN_LEFT`/`BTN_RIGHT`/`BTN_MIDDLE`, `EV_ABS` for
//!   `ABS_X`/`ABS_Y` over a fixed `0..=32767` range, `EV_REL` for `REL_WHEEL`. Absolute rather
//!   than relative because the RFB `PointerEvent` carries absolute screen coordinates; QEMU's
//!   `usb-tablet` uses the same fixed-range-absolute shape for the same reason (converting to
//!   deltas would drift and pin at screen edges). The injector scales screen coordinates into
//!   the fixed range, so the device never needs to know the framebuffer geometry.
//!
//! The wire ABI (`struct input_event` = 24 bytes on LP64, the `EVIOC*` ioctl family, bitmap
//! byte-count return values) follows `include/uapi/linux/input.h` and `drivers/input/evdev.c`
//! exactly; deviations real consumers depend on are called out inline.

use alloc::collections::VecDeque;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;

use crate::event::polling::Pollee;
use crate::event::{Events, observer::Observer};
use crate::platform::TimeProvider;
use crate::sync::{Mutex, RawSyncPrimitivesProvider};

use super::super::backend::{
    Backend, BackendHandles, DirHandle, FileHandle, PermissionCheck, Permissioned, SeekBehavior,
    WalkOutcome, WalkStopReason, WalkingDirHandle,
};
use super::super::errors::{
    ChmodError, ChownError, FileStatusError, MkdirError, OpenError, PathError, ReadDirError,
    ReadError, RmdirError, TruncateError, UnlinkError, UtimeError, WalkError, WriteError,
};
use super::super::inode_allocator::InodeAllocator;
use super::super::{DirEntry, FileStatus, FileType, Mode, NodeInfo, OFlags, Timestamp, UserInfo};

/// evdev's character-device major (`Documentation/admin-guide/devices.txt`: 13 = input core).
pub const INPUT_MAJOR: usize = 13;
/// `event0`'s minor; `eventN` = `EVENT_MINOR_BASE + N`, matching real Linux.
pub const EVENT_MINOR_BASE: usize = 64;
/// `/dev/input/mice`'s minor (13:63), matching real Linux `mousedev`.
pub const MICE_MINOR: usize = 63;

/// `EV_VERSION` from `linux/input.h` -- what `EVIOCGVERSION` must report.
const EV_VERSION: u32 = 0x0001_0001;

/// Event type codes (`linux/input-event-codes.h`).
pub const EV_SYN: u16 = 0x00;
pub const EV_KEY: u16 = 0x01;
pub const EV_REL: u16 = 0x02;
pub const EV_ABS: u16 = 0x03;
/// `SYN_REPORT`: terminates every injected event batch.
pub const SYN_REPORT: u16 = 0;
pub const BTN_LEFT: u16 = 0x110;
pub const BTN_RIGHT: u16 = 0x111;
pub const BTN_MIDDLE: u16 = 0x112;
pub const REL_WHEEL: u16 = 0x08;
pub const ABS_X: u16 = 0x00;
pub const ABS_Y: u16 = 0x01;

/// The fixed coordinate range both `ABS_X` and `ABS_Y` report (`0..=ABS_RANGE_MAX`). Injectors
/// scale real screen coordinates into this range; consumers scale back out against their own
/// notion of the screen. Same value QEMU's usb-tablet uses.
pub const ABS_RANGE_MAX: i32 = 32767;

/// Highest `KEY_*`/`BTN_*` code (`KEY_MAX` in `linux/input-event-codes.h`); the code space is
/// `0..=KEY_MAX` = 0x300 bits.
const KEY_MAX: usize = 0x2ff;
/// Bitmap length in bytes for the `EV_KEY` code space (0x300 bits = 96 bytes).
const KEY_BITMAP_BYTES: usize = (KEY_MAX + 1).div_ceil(8);

/// Which of the two virtual devices a handle refers to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DeviceKind {
    Keyboard,
    Pointer,
    /// `/dev/input/mice`: the `mousedev` PS/2-protocol aggregate device, a *byte* stream
    /// rather than `struct input_event`s. Served from the registry's dedicated mice state,
    /// not the event queues; `index` therefore must never be called on it.
    Mice,
}

impl DeviceKind {
    const ALL: &'static [(&'static str, DeviceKind)] = &[
        ("event0", DeviceKind::Keyboard),
        ("event1", DeviceKind::Pointer),
        ("mice", DeviceKind::Mice),
    ];

    fn index(self) -> usize {
        match self {
            DeviceKind::Keyboard => 0,
            DeviceKind::Pointer => 1,
            DeviceKind::Mice => unreachable!("mice is not an evdev event queue"),
        }
    }

    fn from_minor(minor: usize) -> Option<Self> {
        if minor == MICE_MINOR {
            return Some(DeviceKind::Mice);
        }
        match minor.checked_sub(EVENT_MINOR_BASE)? {
            0 => Some(DeviceKind::Keyboard),
            1 => Some(DeviceKind::Pointer),
            _ => None,
        }
    }

    fn name(self) -> &'static str {
        match self {
            DeviceKind::Keyboard => "litebox-keyboard",
            DeviceKind::Pointer => "litebox-pointer",
            DeviceKind::Mice => "litebox-mice",
        }
    }
}

/// One queued `struct input_event`, held decomposed; serialized to the 24-byte LP64 wire form
/// (`__kernel_ulong_t` sec + usec, then `__u16 type`, `__u16 code`, `__s32 value`) at read time.
#[derive(Debug, Clone, Copy)]
struct QueuedEvent {
    sec: u64,
    usec: u64,
    r#type: u16,
    code: u16,
    value: i32,
}

/// Serialized size of one `struct input_event` on LP64 guests.
pub const INPUT_EVENT_SIZE: usize = 24;

impl QueuedEvent {
    fn serialize_into(self, dst: &mut [u8]) {
        dst[0..8].copy_from_slice(&self.sec.to_le_bytes());
        dst[8..16].copy_from_slice(&self.usec.to_le_bytes());
        dst[16..18].copy_from_slice(&self.r#type.to_le_bytes());
        dst[18..20].copy_from_slice(&self.code.to_le_bytes());
        dst[20..24].copy_from_slice(&self.value.to_le_bytes());
    }
}

/// Bound on queued events per device; on overflow the oldest events are dropped (input
/// injection must never block or grow without bound when no guest is reading).
const QUEUE_CAP: usize = 1024;

struct DeviceData {
    queue: VecDeque<QueuedEvent>,
    key_bitmap: [u8; KEY_BITMAP_BYTES],
}

struct DeviceState<Platform: RawSyncPrimitivesProvider + TimeProvider + 'static> {
    data: Mutex<Platform, DeviceData>,
    pollee: Pollee<Platform>,
}

/// PS/2 protocol emulation modes, exactly `mousedev`'s: plain 3-byte PS/2 until the ImPS/2
/// magic knock (rate 200,100,80) upgrades to 4-byte-with-wheel, and the Explorer knock
/// (200,200,80) to 4-byte-with-wheel-and-side-buttons.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MiceMode {
    Ps2,
    Imps,
    Exps,
}

impl MiceMode {
    fn id(self) -> u8 {
        match self {
            MiceMode::Ps2 => 0,
            MiceMode::Imps => 3,
            MiceMode::Exps => 4,
        }
    }

    fn packet_len(self) -> usize {
        match self {
            MiceMode::Ps2 => 3,
            MiceMode::Imps | MiceMode::Exps => 4,
        }
    }
}

/// Protocol + conversion state for `/dev/input/mice`, all under one lock.
struct MiceCtl {
    mode: MiceMode,
    imps_progress: usize,
    imex_progress: usize,
    /// Command responses; REPLACED wholesale by each `write` (mousedev semantics: its response
    /// buffer is rewritten per byte, so only the last command's response is ever readable --
    /// which is exactly what links2's read-until-ACK-then-read-ID handshake depends on).
    responses: VecDeque<u8>,
    /// Motion packets, appended per injected pointer event, drained after `responses`.
    packets: VecDeque<u8>,
    /// Last absolute pixel position, for delta conversion; `None` until the first event
    /// (which then moves by (0,0) rather than jumping).
    last: Option<(i32, i32)>,
}

struct MiceDev<Platform: RawSyncPrimitivesProvider + TimeProvider + 'static> {
    ctl: Mutex<Platform, MiceCtl>,
    pollee: Pollee<Platform>,
}

/// Bound on buffered mice packet bytes; oldest whole packets are dropped on overflow.
const MICE_PACKET_CAP: usize = 4096;

struct RegistryInner<Platform: RawSyncPrimitivesProvider + TimeProvider + 'static> {
    devices: [DeviceState<Platform>; 2],
    mice: MiceDev<Platform>,
}

/// A cheap-to-clone handle to the two virtual input devices' shared state: the runner side
/// injects events through it, the shim side drains them and answers `EVIOC*` ioctls through it.
pub struct InputRegistry<Platform: RawSyncPrimitivesProvider + TimeProvider + 'static> {
    inner: Arc<RegistryInner<Platform>>,
}

impl<Platform: RawSyncPrimitivesProvider + TimeProvider + 'static> Clone
    for InputRegistry<Platform>
{
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

impl<Platform: RawSyncPrimitivesProvider + TimeProvider + 'static> Default
    for InputRegistry<Platform>
{
    fn default() -> Self {
        Self::new()
    }
}

/// Everything the shim needs to service one decoded `EVIOC*` request. `Copy.rc` mirrors the
/// kernel's convention exactly: string and bitmap reads return the copied byte count, fixed
/// struct reads return 0.
pub enum EvdevIoctlReply {
    /// Copy `data` to the caller's buffer; the syscall returns `rc`.
    Copy { data: Vec<u8>, rc: u32 },
    /// Success with no data transfer; the syscall returns `rc`.
    Plain { rc: u32 },
    /// Fail with `ENOENT` (unset string properties, per `drivers/input/evdev.c`).
    NoEntry,
    /// Fail with `EINVAL` (unknown or unsupported command -- the kernel's actual answer for an
    /// unrecognized `'E'` ioctl, not `ENOTTY`).
    Invalid,
}

impl<Platform: RawSyncPrimitivesProvider + TimeProvider + 'static> InputRegistry<Platform> {
    #[must_use]
    pub fn new() -> Self {
        let device = || DeviceState {
            data: Mutex::new(DeviceData {
                queue: VecDeque::new(),
                key_bitmap: [0; KEY_BITMAP_BYTES],
            }),
            pollee: Pollee::new(),
        };
        Self {
            inner: Arc::new(RegistryInner {
                devices: [device(), device()],
                mice: MiceDev {
                    ctl: Mutex::new(MiceCtl {
                        mode: MiceMode::Ps2,
                        imps_progress: 0,
                        imex_progress: 0,
                        responses: VecDeque::new(),
                        packets: VecDeque::new(),
                        last: None,
                    }),
                    pollee: Pollee::new(),
                },
            }),
        }
    }

    fn push_batch(&self, kind: DeviceKind, now: core::time::Duration, events: &[(u16, u16, i32)]) {
        let sec = now.as_secs();
        let usec = u64::from(now.subsec_micros());
        let dev = &self.inner.devices[kind.index()];
        {
            let mut data = dev.data.lock();
            for &(r#type, code, value) in events {
                if r#type == EV_KEY && usize::from(code) <= KEY_MAX {
                    let bit = usize::from(code);
                    if value == 0 {
                        data.key_bitmap[bit / 8] &= !(1 << (bit % 8));
                    } else if value == 1 {
                        data.key_bitmap[bit / 8] |= 1 << (bit % 8);
                    }
                }
                if data.queue.len() >= QUEUE_CAP {
                    data.queue.pop_front();
                }
                data.queue.push_back(QueuedEvent {
                    sec,
                    usec,
                    r#type,
                    code,
                    value,
                });
            }
            // Every batch ends in a SYN_REPORT so consumers see a complete frame.
            if data.queue.len() >= QUEUE_CAP {
                data.queue.pop_front();
            }
            data.queue.push_back(QueuedEvent {
                sec,
                usec,
                r#type: EV_SYN,
                code: SYN_REPORT,
                value: 0,
            });
        }
        dev.pollee.notify_observers(Events::IN);
    }

    /// Inject a key press/release. `code` is an evdev `KEY_*`/`BTN_*` code; `now` is a
    /// monotonic timestamp (any fixed epoch -- consumers only compare deltas).
    pub fn inject_key(&self, code: u16, down: bool, now: core::time::Duration) {
        self.push_batch(
            DeviceKind::Keyboard,
            now,
            &[(EV_KEY, code, i32::from(down))],
        );
    }

    /// Inject an absolute pointer position (each axis already scaled to `0..=ABS_RANGE_MAX`)
    /// plus the current button state delta, if any.
    pub fn inject_pointer_abs(
        &self,
        x: i32,
        y: i32,
        button_changes: &[(u16, bool)],
        now: core::time::Duration,
    ) {
        let mut events: Vec<(u16, u16, i32)> = vec![(EV_ABS, ABS_X, x), (EV_ABS, ABS_Y, y)];
        for &(btn, down) in button_changes {
            events.push((EV_KEY, btn, i32::from(down)));
        }
        self.push_batch(DeviceKind::Pointer, now, &events);
    }

    /// Inject a scroll-wheel step (+1 = away from the user, matching evdev convention).
    pub fn inject_wheel(&self, delta: i32, now: core::time::Duration) {
        self.push_batch(DeviceKind::Pointer, now, &[(EV_REL, REL_WHEEL, delta)]);
    }

    /// Block (or fail with [`crate::event::polling::TryOpError::TryAgain`] when `nonblock`)
    /// until at least one whole event is available for the device at `minor`, then drain as
    /// many whole events as fit in `buf`. Returns the byte count written. The caller must have
    /// already rejected buffers shorter than one event.
    pub fn read_blocking(
        &self,
        cx: &crate::event::wait::WaitContext<'_, Platform>,
        minor: usize,
        buf: &mut [u8],
        nonblock: bool,
    ) -> Result<usize, crate::event::polling::TryOpError<core::convert::Infallible>> {
        let Some(kind) = DeviceKind::from_minor(minor) else {
            // Unknown minor: nothing will ever arrive; report as would-block rather than hang.
            return Err(crate::event::polling::TryOpError::TryAgain);
        };
        let pollee = if kind == DeviceKind::Mice {
            &self.inner.mice.pollee
        } else {
            &self.inner.devices[kind.index()].pollee
        };
        pollee.wait(cx, nonblock, Events::IN, || {
            let n = self.try_drain(minor, buf);
            if n == 0 {
                Err(crate::event::polling::TryOpError::TryAgain)
            } else {
                Ok(n)
            }
        })
    }

    /// Drain up to `buf.len() / 24` whole queued events for the device at `minor` into `buf`,
    /// non-blocking. Returns the byte count written; 0 means the queue is empty (the caller
    /// decides whether that is `EAGAIN` or a reason to block via [`Self::read_blocking`]).
    ///
    /// Mirrors `evdev_read`: a buffer smaller than one event is an error surfaced by the caller
    /// (this function just returns 0 for it, and the shim rejects short buffers with `EINVAL`
    /// before calling in).
    pub fn try_drain(&self, minor: usize, buf: &mut [u8]) -> usize {
        let Some(kind) = DeviceKind::from_minor(minor) else {
            return 0;
        };
        if kind == DeviceKind::Mice {
            return self.mice_try_drain(buf);
        }
        let dev = &self.inner.devices[kind.index()];
        let mut data = dev.data.lock();
        let mut written = 0;
        while written + INPUT_EVENT_SIZE <= buf.len() {
            let Some(event) = data.queue.pop_front() else {
                break;
            };
            event.serialize_into(&mut buf[written..written + INPUT_EVENT_SIZE]);
            written += INPUT_EVENT_SIZE;
        }
        if !data.queue.is_empty() {
            drop(data);
            // More events remain: leave the readiness signal up for the next reader/poller.
            dev.pollee.notify_observers(Events::IN);
        }
        written
    }

    /// Readiness for the device at `minor`: `IN` when events are queued. `None` for a minor
    /// outside the two devices this registry hosts.
    pub fn check_io_events(&self, minor: usize) -> Option<Events> {
        let kind = DeviceKind::from_minor(minor)?;
        let mut events = Events::empty();
        if kind == DeviceKind::Mice {
            let ctl = self.inner.mice.ctl.lock();
            if !ctl.responses.is_empty() || !ctl.packets.is_empty() {
                events |= Events::IN;
            }
            return Some(events);
        }
        let dev = &self.inner.devices[kind.index()];
        if !dev.data.lock().queue.is_empty() {
            events |= Events::IN;
        }
        Some(events)
    }

    /// Register a poll observer on the device at `minor` (the poll/epoll wakeup path). No-op
    /// for a minor outside this registry.
    pub fn register_observer(
        &self,
        minor: usize,
        observer: alloc::sync::Weak<dyn Observer<Events>>,
        mask: Events,
    ) {
        match DeviceKind::from_minor(minor) {
            Some(DeviceKind::Mice) => {
                self.inner.mice.pollee.register_observer(observer, mask);
            }
            Some(kind) => {
                self.inner.devices[kind.index()]
                    .pollee
                    .register_observer(observer, mask);
            }
            None => {}
        }
    }

    /// Unregister a poll observer from the device at `minor`. No-op for a minor outside this
    /// registry.
    pub fn unregister_observer(
        &self,
        minor: usize,
        observer: alloc::sync::Weak<dyn Observer<Events>>,
    ) {
        match DeviceKind::from_minor(minor) {
            Some(DeviceKind::Mice) => {
                self.inner.mice.pollee.unregister_observer(observer);
            }
            Some(kind) => {
                self.inner.devices[kind.index()]
                    .pollee
                    .unregister_observer(observer);
            }
            None => {}
        }
    }

    /// The `mousedev` magic knock upgrading to ImPS/2 (`set rate 200, 100, 80`).
    const IMPS_SEQ: [u8; 6] = [0xf3, 200, 0xf3, 100, 0xf3, 80];
    /// The knock upgrading to Explorer PS/2 (`set rate 200, 200, 80`).
    const IMEX_SEQ: [u8; 6] = [0xf3, 200, 0xf3, 200, 0xf3, 80];

    /// Guest bytes written to `/dev/input/mice`: run `mousedev`'s exact protocol. Every byte
    /// advances the mode-upgrade sequence matchers; the response buffer is REPLACED by each
    /// byte's response (so only the last command's response survives a multi-byte write --
    /// the `mousedev` behavior links2's handshake depends on). Returns `data.len()`.
    pub fn mice_write(&self, data: &[u8]) -> usize {
        let mice = &self.inner.mice;
        {
            let mut ctl = mice.ctl.lock();
            for &c in data {
                if c == Self::IMEX_SEQ[ctl.imex_progress] {
                    ctl.imex_progress += 1;
                    if ctl.imex_progress == Self::IMEX_SEQ.len() {
                        ctl.imex_progress = 0;
                        ctl.mode = MiceMode::Exps;
                    }
                } else {
                    ctl.imex_progress = 0;
                }
                if c == Self::IMPS_SEQ[ctl.imps_progress] {
                    ctl.imps_progress += 1;
                    if ctl.imps_progress == Self::IMPS_SEQ.len() {
                        ctl.imps_progress = 0;
                        ctl.mode = MiceMode::Imps;
                    }
                } else {
                    ctl.imps_progress = 0;
                }
                ctl.responses.clear();
                ctl.responses.push_back(0xfa);
                match c {
                    // Get ID: the mode's device ID.
                    0xf2 => {
                        let id = ctl.mode.id();
                        ctl.responses.push_back(id);
                    }
                    // Get info: rate/resolution/scaling placeholders, as mousedev reports.
                    0xe9 => ctl.responses.extend([100, 100, 100]),
                    // Reset: back to bare PS/2, self-test passed, mouse ID 0.
                    0xff => {
                        ctl.mode = MiceMode::Ps2;
                        ctl.imps_progress = 0;
                        ctl.imex_progress = 0;
                        ctl.responses.extend([0xaa, 0x00]);
                    }
                    // Poll: one zero-motion packet.
                    0xeb => {
                        let len = ctl.mode.packet_len();
                        ctl.responses.push_back(0x08);
                        for _ in 1..len {
                            ctl.responses.push_back(0);
                        }
                    }
                    _ => {}
                }
            }
        }
        mice.pollee.notify_observers(Events::IN);
        data.len()
    }

    /// Drain protocol responses (first) then motion packets into `buf`, non-blocking.
    pub fn mice_try_drain(&self, buf: &mut [u8]) -> usize {
        let mice = &self.inner.mice;
        let mut ctl = mice.ctl.lock();
        let mut written = 0;
        while written < buf.len() {
            let Some(b) = ctl.responses.pop_front() else {
                break;
            };
            buf[written] = b;
            written += 1;
        }
        while written < buf.len() {
            let Some(b) = ctl.packets.pop_front() else {
                break;
            };
            buf[written] = b;
            written += 1;
        }
        let more = !ctl.responses.is_empty() || !ctl.packets.is_empty();
        drop(ctl);
        if more {
            mice.pollee.notify_observers(Events::IN);
        }
        written
    }

    /// Inject a pointer event as PS/2 motion packets: `px`/`py` are absolute screen pixels
    /// (converted to deltas against the last event -- a PS/2 mouse only speaks deltas),
    /// `buttons` is the PS/2 button byte (bit0 left, bit1 right, bit2 middle), `wheel` a
    /// scroll step (+1 toward the user / scroll down, -1 away, matching what a consumer of
    /// byte 3 expects). Large motions split across packets (per-packet delta is 8-bit).
    pub fn inject_mice_pointer(&self, px: i32, py: i32, buttons: u8, wheel: i8) {
        let mice = &self.inner.mice;
        {
            let mut ctl = mice.ctl.lock();
            let (lx, ly) = ctl.last.unwrap_or((px, py));
            ctl.last = Some((px, py));
            let mut dx = px - lx;
            // Screen y grows downward; PS/2 y grows upward.
            let mut dy = ly - py;
            let mut wheel = wheel;
            loop {
                let sx = dx.clamp(-127, 127);
                let sy = dy.clamp(-127, 127);
                dx -= sx;
                dy -= sy;
                let sw = wheel;
                wheel = 0;
                let mut b0 = 0x08 | (buttons & 0x07);
                if sx < 0 {
                    b0 |= 0x10;
                }
                if sy < 0 {
                    b0 |= 0x20;
                }
                let mode = ctl.mode;
                let packet_len = mode.packet_len();
                while ctl.packets.len() + packet_len > MICE_PACKET_CAP {
                    for _ in 0..packet_len {
                        ctl.packets.pop_front();
                    }
                }
                ctl.packets.push_back(b0);
                // Two's-complement low byte; the sign rides in `b0`'s overflow bits.
                ctl.packets
                    .push_back(i8::try_from(sx).unwrap_or(0).cast_unsigned());
                ctl.packets
                    .push_back(i8::try_from(sy).unwrap_or(0).cast_unsigned());
                match mode {
                    MiceMode::Ps2 => {}
                    MiceMode::Imps => ctl.packets.push_back(sw.cast_unsigned()),
                    // Explorer: wheel is a 4-bit signed field; buttons 4/5 unimplemented.
                    MiceMode::Exps => ctl.packets.push_back(sw.cast_unsigned() & 0x0f),
                }
                if dx == 0 && dy == 0 {
                    break;
                }
            }
        }
        mice.pollee.notify_observers(Events::IN);
    }

    /// Answer one `EVIOC*` ioctl for the device at `minor`. `cmd` is the raw ioctl number;
    /// `write_arg` is the integer argument for the write-direction commands that carry their
    /// value in the argument itself (`EVIOCGRAB`) or in user memory the shim already read
    /// (`EVIOCSCLOCKID`).
    ///
    /// The asm-generic ioctl encoding (identical on x86-64 and aarch64) is decoded here:
    /// `nr = cmd & 0xff`, `size = (cmd >> 16) & 0x3fff` -- the `len` parameter of the
    /// variable-length getters (`EVIOCGNAME(len)` etc.) rides in the size field, so matching is
    /// on `nr` alone with `size` as the caller's buffer bound.
    #[must_use]
    pub fn evdev_ioctl(&self, minor: usize, cmd: u32, write_arg: i32) -> EvdevIoctlReply {
        let Some(kind) = DeviceKind::from_minor(minor) else {
            return EvdevIoctlReply::Invalid;
        };
        if kind == DeviceKind::Mice {
            // `mousedev` is not an evdev device; it answers no `EVIOC*` command.
            return EvdevIoctlReply::Invalid;
        }
        let nr = cmd & 0xff;
        let size = (cmd >> 16) as usize & 0x3fff;

        // Copy `full` truncated to the caller's buffer size, returning the kernel's rc
        // convention for bitmap/string reads: the copied byte count.
        let copy_counted = |full: &[u8]| {
            let n = full.len().min(size);
            EvdevIoctlReply::Copy {
                data: full[..n].to_vec(),
                rc: u32::try_from(n).unwrap_or(u32::MAX),
            }
        };
        // Fixed-size struct reads return 0, not the byte count.
        let copy_zero_rc = |full: &[u8]| {
            let n = full.len().min(size);
            EvdevIoctlReply::Copy {
                data: full[..n].to_vec(),
                rc: 0,
            }
        };

        match nr {
            // EVIOCGVERSION
            0x01 => copy_zero_rc(&EV_VERSION.to_le_bytes()),
            // EVIOCGID: struct input_id { bustype, vendor, product, version } -- BUS_VIRTUAL.
            0x02 => {
                let id: [u16; 4] = [
                    0x06,
                    0x1b0c,
                    u16::try_from(kind.index()).unwrap_or(0) + 1,
                    1,
                ];
                let mut bytes = [0u8; 8];
                for (i, v) in id.iter().enumerate() {
                    bytes[i * 2..i * 2 + 2].copy_from_slice(&v.to_le_bytes());
                }
                copy_zero_rc(&bytes)
            }
            // EVIOCGNAME
            0x06 => {
                let mut name: Vec<u8> = kind.name().as_bytes().to_vec();
                name.push(0);
                copy_counted(&name)
            }
            // EVIOCGPHYS / EVIOCGUNIQ: unset -- ENOENT, the errno libevdev explicitly
            // tolerates (any other failure aborts its device setup).
            0x07 | 0x08 => EvdevIoctlReply::NoEntry,
            // EVIOCGPROP / EVIOCGLED / EVIOCGSND / EVIOCGSW: all-zero bitmaps (no
            // properties, LEDs, sounds, or switches).
            0x09 | 0x19 | 0x1a | 0x1b => copy_counted(&vec![0u8; size]),
            // EVIOCGKEY reports the device's current aggregate key/button state. This state is
            // updated when input is injected, independently of whether queued records were read.
            0x18 => {
                let data = self.inner.devices[kind.index()].data.lock();
                copy_counted(&data.key_bitmap)
            }
            // EVIOCGBIT(ev, len): nr = 0x20 + ev.
            0x20..=0x3f => {
                let ev = u16::try_from(nr - 0x20).unwrap_or(u16::MAX);
                copy_counted(&capability_bitmap(kind, ev))
            }
            // EVIOCGABS(axis): nr = 0x40 + axis; struct input_absinfo, rc 0.
            0x40..=0x7f => {
                let axis = u16::try_from(nr - 0x40).unwrap_or(u16::MAX);
                if kind != DeviceKind::Pointer || (axis != ABS_X && axis != ABS_Y) {
                    return EvdevIoctlReply::Invalid;
                }
                // { value, minimum, maximum, fuzz, flat, resolution }, all i32.
                let fields: [i32; 6] = [0, 0, ABS_RANGE_MAX, 0, 0, 0];
                let mut bytes = [0u8; 24];
                for (i, v) in fields.iter().enumerate() {
                    bytes[i * 4..i * 4 + 4].copy_from_slice(&v.to_le_bytes());
                }
                copy_zero_rc(&bytes)
            }
            // EVIOCGRAB: single-consumer arbitration is meaningless here (one guest, devices
            // exist only for it) -- both grab and release trivially succeed.
            0x90 => EvdevIoctlReply::Plain { rc: 0 },
            // EVIOCSCLOCKID: accept CLOCK_REALTIME(0)/CLOCK_MONOTONIC(1)/CLOCK_BOOTTIME(7).
            // Timestamps are already monotonic-from-arbitrary-epoch, which satisfies every
            // consumer that asks for CLOCK_MONOTONIC (they only compare deltas).
            0xa0 => {
                if matches!(write_arg, 0 | 1 | 7) {
                    EvdevIoctlReply::Plain { rc: 0 }
                } else {
                    EvdevIoctlReply::Invalid
                }
            }
            _ => EvdevIoctlReply::Invalid,
        }
    }
}

/// The `EVIOCGBIT` bitmap for event type `ev` (0 = the type bitmap itself). A free function --
/// the capability shape is fixed per device kind and needs no registry state.
fn capability_bitmap(kind: DeviceKind, ev: u16) -> Vec<u8> {
    let set_bit = |bits: &mut [u8], n: u16| {
        let n = n as usize;
        bits[n / 8] |= 1 << (n % 8);
    };
    match ev {
        0 => {
            // Type bitmap: which EV_* types the device generates.
            let mut bits = vec![0u8; 4];
            set_bit(&mut bits, EV_SYN);
            set_bit(&mut bits, EV_KEY);
            if kind == DeviceKind::Pointer {
                set_bit(&mut bits, EV_REL);
                set_bit(&mut bits, EV_ABS);
            }
            bits
        }
        ev if ev == EV_KEY => {
            let mut bits = vec![0u8; KEY_BITMAP_BYTES];
            match kind {
                DeviceKind::Keyboard => {
                    // The whole AT-set-1 main block. Code 0 is KEY_RESERVED and stays 0.
                    for code in 1..=127u16 {
                        set_bit(&mut bits, code);
                    }
                }
                // `mice` never reaches here (no evdev ioctls on it); the pointer shape is
                // the honest fallback if it ever did.
                DeviceKind::Pointer | DeviceKind::Mice => {
                    set_bit(&mut bits, BTN_LEFT);
                    set_bit(&mut bits, BTN_RIGHT);
                    set_bit(&mut bits, BTN_MIDDLE);
                }
            }
            bits
        }
        ev if ev == EV_REL && kind == DeviceKind::Pointer => {
            let mut bits = vec![0u8; 2];
            set_bit(&mut bits, REL_WHEEL);
            bits
        }
        ev if ev == EV_ABS && kind == DeviceKind::Pointer => {
            let mut bits = vec![0u8; 8];
            set_bit(&mut bits, ABS_X);
            set_bit(&mut bits, ABS_Y);
            bits
        }
        // Every other type: an empty bitmap of the right shape (libevdev issues GBIT for
        // EV_LED/EV_SW/EV_MSC/EV_FF/EV_SND unconditionally and needs success, not EINVAL).
        _ => vec![0u8; 8],
    }
}

/// A [`Backend`] serving `/dev/input`: directory listing plus open handles onto the registry's
/// two devices. Reads/writes on the resulting fds are intercepted shim-side (which has the
/// wait-context needed to block); the [`Backend::read`] here only serves the non-blocking
/// leftovers path and reports "would block" as [`ReadError::Io`], which the interception layer
/// prevents real consumers from ever seeing.
pub struct InputDevices<Platform: RawSyncPrimitivesProvider + TimeProvider + 'static> {
    registry: InputRegistry<Platform>,
    root_inode: NodeInfo,
    _alloc: InodeAllocator,
}

impl<Platform: RawSyncPrimitivesProvider + TimeProvider + 'static> InputDevices<Platform> {
    #[must_use]
    pub fn new(allocator: InodeAllocator, registry: InputRegistry<Platform>) -> Self {
        let root_inode = allocator.next();
        Self {
            registry,
            root_inode,
            _alloc: allocator,
        }
    }

    fn device_minor(kind: DeviceKind) -> usize {
        match kind {
            DeviceKind::Mice => MICE_MINOR,
            _ => EVENT_MINOR_BASE + kind.index(),
        }
    }

    fn device_status(kind: DeviceKind) -> FileStatus {
        let minor = Self::device_minor(kind);
        FileStatus {
            file_type: FileType::CharacterDevice,
            mode: Mode::RUSR | Mode::WUSR | Mode::RGRP | Mode::WGRP | Mode::ROTH | Mode::WOTH,
            size: 0,
            owner: UserInfo::ROOT,
            node_info: NodeInfo {
                dev: 5,
                ino: 32 + minor,
                rdev: core::num::NonZeroUsize::new((INPUT_MAJOR << 8) | minor),
            },
            blksize: 0x1000,
            atime: Timestamp::default(),
            mtime: Timestamp::default(),
            ctime: Timestamp::default(),
        }
    }
}

/// Open-file handle: which device.
#[derive(Debug, Clone, Copy)]
pub struct InputFileHandle {
    kind: DeviceKind,
}

/// Directory handle (the single `/dev/input` directory).
#[derive(Debug, Clone, Copy)]
pub struct InputDirHandle;

impl<Platform: RawSyncPrimitivesProvider + TimeProvider + 'static>
    super::super::backend::private::Sealed for InputDevices<Platform>
{
}

impl<Platform: RawSyncPrimitivesProvider + TimeProvider + 'static> BackendHandles
    for InputDevices<Platform>
{
    type WalkingDirHandle<'a> = InputDirHandle;
    type FileHandle = InputFileHandle;
    type DirHandle = InputDirHandle;
}

impl<Platform: RawSyncPrimitivesProvider + TimeProvider + 'static> Backend
    for InputDevices<Platform>
{
    fn root(&self) -> WalkingDirHandle<'_> {
        WalkingDirHandle::from_typed::<Self>(InputDirHandle)
    }

    fn walk_directories<'a>(
        &'a self,
        from: WalkingDirHandle<'a>,
        components: &[&str],
    ) -> Result<WalkOutcome<WalkingDirHandle<'a>>, WalkError> {
        let from = from.into_typed::<Self>();
        if let Some(&component) = components.first() {
            if DeviceKind::ALL.iter().any(|(n, _)| *n == component) {
                return Ok(WalkOutcome {
                    components: vec![],
                    last: WalkingDirHandle::from_typed::<Self>(from),
                    stop_reason: WalkStopReason::StoppedAtNonDirectory,
                });
            }
            return Err(WalkError::PathError(PathError::NoSuchFileOrDirectory));
        }
        Ok(WalkOutcome {
            components: vec![],
            last: WalkingDirHandle::from_typed::<Self>(from),
            stop_reason: WalkStopReason::CompleteDirectory,
        })
    }

    fn owned_dir_at(
        &self,
        dir: WalkingDirHandle<'_>,
        _flags: OFlags,
    ) -> Result<DirHandle, OpenError> {
        Ok(DirHandle::from_typed::<Self>(dir.into_typed::<Self>()))
    }

    fn walking_dir_at<'a>(&'a self, dir: &DirHandle) -> Option<WalkingDirHandle<'a>> {
        Some(WalkingDirHandle::from_typed::<Self>(
            *dir.get_typed::<Self>(),
        ))
    }

    fn open_file_at(
        &self,
        dir: WalkingDirHandle<'_>,
        name: &str,
        flags: OFlags,
    ) -> Result<Permissioned<FileHandle>, OpenError> {
        let _dir = dir.into_typed::<Self>();
        let kind = DeviceKind::ALL
            .iter()
            .find(|(n, _)| *n == name)
            .map(|(_, k)| *k)
            .ok_or(OpenError::PathError(PathError::NoSuchFileOrDirectory))?;
        if flags.contains(OFlags::DIRECTORY) {
            return Err(OpenError::PathError(PathError::ComponentNotADirectory));
        }
        Ok(Permissioned {
            item: FileHandle::from_typed::<Self>(InputFileHandle { kind }),
            permissions: PermissionCheck::ByBackend,
        })
    }

    fn list_dir_at(&self, handle: DirHandle) -> Result<Vec<DirEntry>, ReadDirError> {
        let _handle = handle.into_typed::<Self>();
        Ok(DeviceKind::ALL
            .iter()
            .map(|(n, k)| DirEntry {
                name: String::from(*n),
                file_type: FileType::CharacterDevice,
                ino_info: Some(Self::device_status(*k).node_info),
            })
            .collect())
    }

    fn read(&self, h: &FileHandle, buf: &mut [u8], _offset: usize) -> Result<usize, ReadError> {
        let h = h.get_typed::<Self>();
        let minor = Self::device_minor(h.kind);
        let n = self.registry.try_drain(minor, buf);
        if n == 0 {
            // Empty queue: a real evdev fd would block here, but this trait has no wait
            // context. The shim's read interception (which does) prevents consumers from
            // reaching this path; anything that does anyway gets a plain I/O error rather
            // than a silent fake EOF.
            return Err(ReadError::Io);
        }
        Ok(n)
    }

    fn write(&self, h: &FileHandle, buf: &[u8], _offset: usize) -> Result<usize, WriteError> {
        if h.get_typed::<Self>().kind == DeviceKind::Mice {
            // PS/2 command bytes drive the mousedev protocol state machine.
            return Ok(self.registry.mice_write(buf));
        }
        // Guests write LED/MSC events back to input devices (X11 sets keyboard LEDs on
        // CapsLock). There is no LED to light; accept and discard so the caller never fails.
        Ok(buf.len())
    }

    fn truncate(&self, _h: &FileHandle, _len: usize) -> Result<(), TruncateError> {
        Err(TruncateError::IsTerminalDevice)
    }

    fn seek_behavior(&self, _h: &FileHandle) -> SeekBehavior {
        // evdev has no llseek; reads are stream-ordered events.
        SeekBehavior::NonSeekable
    }

    fn file_status(&self, h: &FileHandle) -> Result<FileStatus, FileStatusError> {
        Ok(Self::device_status(h.get_typed::<Self>().kind))
    }

    fn dir_status(&self, h: &DirHandle) -> Result<FileStatus, FileStatusError> {
        let _h = h.get_typed::<Self>();
        Ok(FileStatus {
            file_type: FileType::Directory,
            mode: Mode::RWXU | Mode::RGRP | Mode::XGRP | Mode::ROTH | Mode::XOTH,
            size: super::super::DEFAULT_DIRECTORY_SIZE,
            owner: UserInfo::ROOT,
            node_info: self.root_inode.clone(),
            blksize: super::super::DEFAULT_DIRECTORY_SIZE,
            atime: Timestamp::default(),
            mtime: Timestamp::default(),
            ctime: Timestamp::default(),
        })
    }

    fn create_file_at(
        &self,
        _dir: DirHandle,
        _name: &str,
        _mode: Mode,
    ) -> Result<FileHandle, OpenError> {
        Err(OpenError::ReadOnlyFileSystem)
    }

    fn mkdir_at(&self, _dir: DirHandle, _name: &str, _mode: Mode) -> Result<DirHandle, MkdirError> {
        Err(MkdirError::ReadOnlyFileSystem)
    }

    fn unlink_at(&self, _dir: DirHandle, _name: &str) -> Result<(), UnlinkError> {
        Err(UnlinkError::ReadOnlyFileSystem)
    }

    fn rmdir_at(&self, _dir: DirHandle, _name: &str) -> Result<(), RmdirError> {
        Err(RmdirError::ReadOnlyFileSystem)
    }

    fn chmod_at(&self, _dir: DirHandle, _name: &str, _mode: Mode) -> Result<(), ChmodError> {
        Err(ChmodError::ReadOnlyFileSystem)
    }

    fn chmod_file(&self, _h: &FileHandle, _mode: Mode) -> Result<(), ChmodError> {
        Err(ChmodError::ReadOnlyFileSystem)
    }

    fn chmod_dir(&self, _h: &DirHandle, _mode: Mode) -> Result<(), ChmodError> {
        Err(ChmodError::ReadOnlyFileSystem)
    }

    fn chown_at(
        &self,
        _dir: DirHandle,
        _name: &str,
        _user: Option<u16>,
        _group: Option<u16>,
    ) -> Result<(), ChownError> {
        Err(ChownError::ReadOnlyFileSystem)
    }

    fn utimensat_at(
        &self,
        _dir: DirHandle,
        _name: &str,
        _atime: Option<Timestamp>,
        _mtime: Option<Timestamp>,
    ) -> Result<(), UtimeError> {
        Err(UtimeError::ReadOnlyFileSystem)
    }

    fn utimensat_file(
        &self,
        _h: &FileHandle,
        _atime: Option<Timestamp>,
        _mtime: Option<Timestamp>,
    ) -> Result<(), UtimeError> {
        Err(UtimeError::ReadOnlyFileSystem)
    }

    fn utimensat_dir(
        &self,
        _h: &DirHandle,
        _atime: Option<Timestamp>,
        _mtime: Option<Timestamp>,
    ) -> Result<(), UtimeError> {
        Err(UtimeError::ReadOnlyFileSystem)
    }
}
