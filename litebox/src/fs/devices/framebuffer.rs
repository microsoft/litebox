// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! `/dev/fb0` state: geometry, backing pixel store, and the fbdev ioctl structs.
//!
//! Scope of this pass: `open`/`read`/`write`/`lseek`/`ioctl` are fully implemented against a
//! host-owned pixel store -- this alone gives a real, working path for any consumer that reads
//! and writes through plain syscalls (x11vnc's `-rawfb` mode explicitly falls back to
//! `lseek`+`read` when `mmap` fails, so it works unmodified against this backend today).
//! `mmap` is deliberately left on its existing (unchanged) `MAP_SHARED`+`PROT_WRITE` rejection:
//! a memcpy-snapshot mapping would silently fail to propagate guest pixel writes back to this
//! store (or vice versa), which is worse than not supporting mmap at all for a backend whose
//! whole purpose is making guest-painted pixels visible elsewhere. Coherent mmap needs either a
//! new platform API to map this store's memory directly into guest VA space, or an explicit
//! flush-on-fault/flush-on-unmap bridge; scoped to a follow-up pass once the read/write path
//! above is verified live end to end.

use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use zerocopy::{FromBytes, Immutable, IntoBytes};

use crate::sync::{Mutex, RawSyncPrimitivesProvider};

/// Bytes per pixel for the one pixel format litebox's `/dev/fb0` ever reports: XRGB8888 (bits
/// 31:24 unused/transparency-ignored, 23:16 red, 15:8 green, 7:0 blue -- matches Qt's
/// `Format_ARGB32` bitfields and `softbuffer`'s `0x00RRGGBB` convention end to end, so no host or
/// guest side of the pipeline ever needs a pixel-format conversion step).
pub const BYTES_PER_PIXEL: u32 = 4;

/// `include/uapi/linux/fb.h`'s `struct fb_bitfield`, verbatim layout (three `__u32`s, densely
/// packed -- no compiler padding on any target).
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, FromBytes, IntoBytes, Immutable)]
pub struct FbBitfield {
    pub offset: u32,
    pub length: u32,
    pub msb_right: u32,
}

const fn bitfield(offset: u32, length: u32) -> FbBitfield {
    FbBitfield {
        offset,
        length,
        msb_right: 0,
    }
}

/// `include/uapi/linux/fb.h`'s `struct fb_var_screeninfo`, verbatim field order. No `unsigned
/// long` fields, so this is densely packed on both 32- and 64-bit targets -- no manual padding
/// needed for `#[repr(C)]` to reproduce the kernel's layout bit for bit.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, FromBytes, IntoBytes, Immutable)]
pub struct FbVarScreeninfo {
    pub xres: u32,
    pub yres: u32,
    pub xres_virtual: u32,
    pub yres_virtual: u32,
    pub xoffset: u32,
    pub yoffset: u32,
    pub bits_per_pixel: u32,
    pub grayscale: u32,
    pub red: FbBitfield,
    pub green: FbBitfield,
    pub blue: FbBitfield,
    pub transp: FbBitfield,
    pub nonstd: u32,
    pub activate: u32,
    pub height: u32,
    pub width: u32,
    pub accel_flags: u32,
    pub pixclock: u32,
    pub left_margin: u32,
    pub right_margin: u32,
    pub upper_margin: u32,
    pub lower_margin: u32,
    pub hsync_len: u32,
    pub vsync_len: u32,
    pub sync: u32,
    pub vmode: u32,
    pub rotate: u32,
    pub colorspace: u32,
    pub reserved: [u32; 4],
}

/// `include/uapi/linux/fb.h`'s `struct fb_fix_screeninfo`, verbatim field order. `smem_start`/
/// `mmio_start` are `unsigned long` (LP64: 8 bytes, 8-byte aligned); the kernel's C struct has no
/// explicit packing attribute, so on a 64-bit target the compiler inserts 2 bytes of padding
/// after `ywrapstep` (aligns `line_length` to 4), 4 bytes after `line_length` (aligns
/// `mmio_start` to 8), and 2 bytes of tail padding after `reserved` (rounds the 8-byte-aligned
/// struct to a multiple of 8) -- total size 80 bytes. Those three gaps are made explicit
/// (`_pad_after_ywrapstep`/`_pad_after_line_length`/`_pad_tail`) rather than left implicit,
/// because `zerocopy`'s `IntoBytes` derive refuses any type with compiler-inserted padding (an
/// uninitialized-byte soundness hole `Immutable`/`IntoBytes` cannot allow) -- writing the same
/// gaps as real, always-zeroed fields reproduces the kernel's exact byte layout while staying
/// derivable. The `size_of` assertion below is a tripwire against an accidental reordering
/// silently breaking that.
#[repr(C)]
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, Immutable)]
pub struct FbFixScreeninfo {
    pub id: [u8; 16],
    pub smem_start: u64,
    pub smem_len: u32,
    pub r#type: u32,
    pub type_aux: u32,
    pub visual: u32,
    pub xpanstep: u16,
    pub ypanstep: u16,
    pub ywrapstep: u16,
    _pad_after_ywrapstep: u16,
    pub line_length: u32,
    _pad_after_line_length: u32,
    pub mmio_start: u64,
    pub mmio_len: u32,
    pub accel: u32,
    pub capabilities: u16,
    pub reserved: [u16; 2],
    _pad_tail: u16,
}

const _: () = assert!(core::mem::size_of::<FbFixScreeninfo>() == 80);

/// `FB_TYPE_PACKED_PIXELS` (`include/uapi/linux/fb.h`).
const FB_TYPE_PACKED_PIXELS: u32 = 0;
/// `FB_VISUAL_TRUECOLOR` (`include/uapi/linux/fb.h`).
const FB_VISUAL_TRUECOLOR: u32 = 2;
/// `FB_ACCEL_NONE` (`include/uapi/linux/fb.h`).
const FB_ACCEL_NONE: u32 = 0;

/// Live `/dev/fb0` geometry plus the pixel store it describes.
///
/// `yres_virtual = 2 * yres` by construction (see `resize` below): the lower half is the visible
/// page, the upper half a second page a `FBIOPAN_DISPLAY` caller can flip to for tear-free double
/// buffering. `xres_virtual == xres` -- litebox's fbdev never supports horizontal virtual panning
/// (`xpanstep == 0` in `fix_screeninfo` advertises exactly that).
struct FramebufferState {
    xres: u32,
    yres: u32,
    /// Pan offset in the Y direction, in pixels; `0` or `yres`, the top of whichever page is
    /// currently visible. See `pan` below.
    yoffset: u32,
    /// `xres * (2 * yres) * BYTES_PER_PIXEL` bytes, row-major, top-left first, `line_length`
    /// stride between rows -- exactly what every fbdev consumer's `mmap` expects to find.
    pixels: Vec<u8>,
    /// A guest `mmap` of `/dev/fb0`, when one is live: `(guest_address, byte_length)`. On
    /// litebox's userland platforms the guest and the runner share one host address space, so
    /// while this is set it IS the pixel store -- every accessor (fd `read`/`write`, the RFB
    /// snapshot) goes through the mapping instead of `pixels`, giving the mmap-write ->
    /// remote-viewer coherence real fbdev applications (`links2 -g`, netsurf-fbdev, Xorg
    /// fbdev) depend on. The shim registers it at `mmap` time (pre-filled from `pixels`) and
    /// MUST clear it (under this state's lock) before any overlapping guest `munmap` actually
    /// unmaps, or a concurrent RFB snapshot would read through a dangling pointer.
    mapping: Option<(usize, usize)>,
}

impl FramebufferState {
    fn line_length(&self) -> u32 {
        self.xres * BYTES_PER_PIXEL
    }

    fn smem_len(&self) -> u32 {
        self.line_length() * self.yres * 2
    }

    /// The live pixel bytes: the guest mapping while one is registered (see `mapping`), else
    /// the owned store. Only call with the state lock held (the `&mut self` receiver enforces
    /// that transitively -- every caller goes through the mutex).
    fn pixel_bytes_mut(&mut self) -> &mut [u8] {
        match self.mapping {
            // SAFETY: the shim guarantees (a) the mapping covers `len` readable+writable bytes
            // in this same address space for as long as it stays registered, and (b) it is
            // deregistered under this state's lock before the guest unmaps it. Concurrent guest
            // writes to the same pages are benign data races at the pixel level (tearing), the
            // same property a real shared-framebuffer mapping has.
            Some((addr, len)) => unsafe {
                core::slice::from_raw_parts_mut(addr as *mut u8, len.min(self.pixels.len()))
            },
            None => &mut self.pixels,
        }
    }

    fn var_screeninfo(&self) -> FbVarScreeninfo {
        FbVarScreeninfo {
            xres: self.xres,
            yres: self.yres,
            xres_virtual: self.xres,
            yres_virtual: self.yres * 2,
            xoffset: 0,
            yoffset: self.yoffset,
            bits_per_pixel: BYTES_PER_PIXEL * 8,
            grayscale: 0,
            // XRGB8888: transp/red/green/blue occupy bits [31:24]/[23:16]/[15:8]/[7:0].
            red: bitfield(16, 8),
            green: bitfield(8, 8),
            blue: bitfield(0, 8),
            transp: bitfield(24, 8),
            nonstd: 0,
            activate: 0, // FB_ACTIVATE_NOW
            height: 0,   // unknown physical size -- 0 is the documented "not available" value
            width: 0,
            accel_flags: 0,
            pixclock: 0,
            left_margin: 0,
            right_margin: 0,
            upper_margin: 0,
            lower_margin: 0,
            hsync_len: 0,
            vsync_len: 0,
            sync: 0,
            vmode: 0, // FB_VMODE_NONINTERLACED
            rotate: 0,
            colorspace: 0,
            reserved: [0; 4],
        }
    }

    fn fix_screeninfo(&self) -> FbFixScreeninfo {
        let mut id = [0u8; 16];
        id[..7].copy_from_slice(b"litebox");
        FbFixScreeninfo {
            id,
            smem_start: 0,
            smem_len: self.smem_len(),
            r#type: FB_TYPE_PACKED_PIXELS,
            type_aux: 0,
            visual: FB_VISUAL_TRUECOLOR,
            xpanstep: 0,
            ypanstep: 1,
            ywrapstep: 0,
            _pad_after_ywrapstep: 0,
            line_length: self.line_length(),
            _pad_after_line_length: 0,
            mmio_start: 0,
            mmio_len: 0,
            accel: FB_ACCEL_NONE,
            capabilities: 0,
            reserved: [0; 2],
            _pad_tail: 0,
        }
    }

    /// Reallocate the pixel store for a new visible geometry, preserving `yres_virtual = 2 *
    /// yres` and resetting to the top page. Existing pixel content is not preserved across a
    /// resize (real fbdev drivers do not guarantee this either -- `FBIOPUT_VSCREENINFO` callers
    /// are expected to redraw).
    fn resize(&mut self, xres: u32, yres: u32) {
        self.xres = xres;
        self.yres = yres;
        self.yoffset = 0;
        self.pixels = vec![0u8; (self.line_length() * yres * 2) as usize];
        // A live guest mapping is sized for the OLD geometry; dropping the registration (not
        // the guest's pages -- those stay mapped and writable, just no longer the store) is
        // the safe answer. Real fbdev consumers munmap+remap after a mode change anyway.
        self.mapping = None;
    }

    /// Apply a `FBIOPAN_DISPLAY` request: `yoffset` must be exactly `0` or `yres` (the top of one
    /// of the two virtual pages) -- litebox's fbdev supports only the page-flip double-buffer
    /// idiom, not arbitrary sub-page panning.
    fn pan(&mut self, yoffset: u32) -> bool {
        if yoffset == 0 || yoffset == self.yres {
            self.yoffset = yoffset;
            true
        } else {
            false
        }
    }

    /// Byte range of the currently visible page within [`Self::pixels`].
    fn visible_range(&self) -> core::ops::Range<usize> {
        let start = (self.yoffset * self.line_length()) as usize;
        start..start + (self.yres * self.line_length()) as usize
    }
}

/// Default geometry for a freshly constructed [`Framebuffer`]: 1024x768, the same default a
/// generic `vesafb`/`efifb` commonly reports, chosen so guests that never call
/// `FBIOPUT_VSCREENINFO` still get a usable canvas.
const DEFAULT_XRES: u32 = 1024;
const DEFAULT_YRES: u32 = 768;

/// Snapshot of [`Framebuffer`] geometry a runner-side reader (the RFB server) needs to interpret
/// the pixel store -- everything in [`FbFixScreeninfo`]/[`FbVarScreeninfo`] that actually varies
/// at runtime, without exposing the ioctl-struct wire shape to non-fbdev callers.
#[derive(Debug, Clone, Copy)]
pub struct FramebufferGeometry {
    pub xres: u32,
    pub yres: u32,
    pub line_length: u32,
}

/// Shared `/dev/fb0` state: geometry plus the pixel store, `Arc`-cheap to clone so the shim's
/// `Devices` backend and a runner-side reader can hold independent handles to the same
/// framebuffer without any host-shared-memory mapping.
pub struct Framebuffer<Platform: RawSyncPrimitivesProvider + 'static> {
    inner: Arc<Mutex<Platform, FramebufferState>>,
}

impl<Platform: RawSyncPrimitivesProvider + 'static> Clone for Framebuffer<Platform> {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

impl<Platform: RawSyncPrimitivesProvider + 'static> Framebuffer<Platform> {
    /// Construct a new framebuffer at the default geometry (1024x768).
    #[must_use]
    pub fn new() -> Self {
        let mut state = FramebufferState {
            xres: 0,
            yres: 0,
            yoffset: 0,
            pixels: Vec::new(),
            mapping: None,
        };
        state.resize(DEFAULT_XRES, DEFAULT_YRES);
        Self {
            inner: Arc::new(Mutex::new(state)),
        }
    }

    /// Snapshot the framebuffer's current `struct fb_var_screeninfo` (`FBIOGET_VSCREENINFO`).
    #[must_use]
    pub fn var_screeninfo(&self) -> FbVarScreeninfo {
        self.inner.lock().var_screeninfo()
    }

    /// Snapshot the framebuffer's current `struct fb_fix_screeninfo` (`FBIOGET_FSCREENINFO`).
    #[must_use]
    pub fn fix_screeninfo(&self) -> FbFixScreeninfo {
        self.inner.lock().fix_screeninfo()
    }

    /// Apply a `FBIOPUT_VSCREENINFO` request. litebox clamps rather than rejects a request it
    /// cannot satisfy exactly (matching real fbdev drivers, which round to the nearest mode they
    /// support and expect the caller to re-read `FBIOGET_VSCREENINFO` to see what was actually
    /// applied) -- so this never fails; the caller reads back the (possibly adjusted)
    /// `FbVarScreeninfo` afterward. `0`-sized requests are clamped to the current geometry rather
    /// than accepted verbatim.
    pub fn put_var_screeninfo(&self, req: &FbVarScreeninfo) {
        let mut state = self.inner.lock();
        let xres = if req.xres == 0 { state.xres } else { req.xres };
        let yres = if req.yres == 0 { state.yres } else { req.yres };
        if xres != state.xres || yres != state.yres {
            state.resize(xres, yres);
        }
    }

    /// Apply a `FBIOPAN_DISPLAY` request. Returns `false` (caller maps to `EINVAL`) for any
    /// `yoffset` other than `0` or the current `yres`.
    #[must_use]
    pub fn pan_display(&self, yoffset: u32) -> bool {
        self.inner.lock().pan(yoffset)
    }

    /// Read `buf.len()` bytes starting at `offset` within the full (both-page) pixel store,
    /// zero-filling any portion past the end -- matches a real fbdev's "reads past `smem_len`
    /// return zeros" `mmap`-equivalent behavior for the plain `read(2)`/`cp` fallback path.
    pub(super) fn read_at(&self, buf: &mut [u8], offset: usize) -> usize {
        let mut state = self.inner.lock();
        let pixels = state.pixel_bytes_mut();
        let available = pixels.len().saturating_sub(offset);
        let n = buf.len().min(available);
        buf[..n].copy_from_slice(&pixels[offset..offset + n]);
        buf[n..].fill(0);
        n
    }

    /// Write `buf` starting at `offset` within the full (both-page) pixel store; bytes landing
    /// past the store's end are silently discarded (matches a real fbdev device's tolerance of
    /// an out-of-range write rather than erroring).
    pub(super) fn write_at(&self, buf: &[u8], offset: usize) -> usize {
        let mut state = self.inner.lock();
        let pixels = state.pixel_bytes_mut();
        if offset >= pixels.len() {
            return buf.len();
        }
        let available = pixels.len() - offset;
        let n = buf.len().min(available);
        pixels[offset..offset + n].copy_from_slice(&buf[..n]);
        n
    }

    /// Read the currently *visible* page (post-pan) into `dst`, for a runner-side presenter/RFB
    /// server -- distinct from the fbdev `read`/`write` path, which serves the raw byte-offset
    /// contract over the full two-page store.
    pub fn read_visible_into(&self, dst: &mut Vec<u8>) {
        let mut state = self.inner.lock();
        let range = state.visible_range();
        let pixels = state.pixel_bytes_mut();
        let end = range.end.min(pixels.len());
        let start = range.start.min(end);
        dst.clear();
        dst.extend_from_slice(&pixels[start..end]);
    }

    /// Current geometry, for a runner-side reader that needs `xres`/`yres`/stride but not the
    /// full ioctl-struct shape.
    pub fn geometry(&self) -> FramebufferGeometry {
        let state = self.inner.lock();
        FramebufferGeometry {
            xres: state.xres,
            yres: state.yres,
            line_length: state.line_length(),
        }
    }

    pub(super) fn smem_len(&self) -> u32 {
        self.inner.lock().smem_len()
    }

    /// Register a live guest `mmap` of the framebuffer at `guest_addr`..`guest_addr + len`.
    /// The mapped pages are pre-filled from the current pixel store, then become the store:
    /// every subsequent accessor reads/writes through the mapping, so guest stores to the
    /// mapped pages are immediately visible to the RFB snapshot with no flush step.
    ///
    /// # Safety
    ///
    /// `guest_addr` must address `len` readable+writable bytes in this process that stay
    /// valid until [`Self::clear_guest_mapping_overlapping`] runs; the caller (the shim's `mmap`/`munmap`
    /// paths) must clear the registration before the pages are ever unmapped.
    pub unsafe fn set_guest_mapping(&self, guest_addr: usize, len: usize) {
        let mut state = self.inner.lock();
        let n = len.min(state.pixels.len());
        // SAFETY: caller contract -- `guest_addr` covers `len` writable bytes.
        let dst = unsafe { core::slice::from_raw_parts_mut(guest_addr as *mut u8, n) };
        dst.copy_from_slice(&state.pixels[..n]);
        state.mapping = Some((guest_addr, len));
    }

    /// The live guest mapping, if one is registered: `(guest_address, byte_length)`. Lets the
    /// shim's bulk-release paths (execve) test whether a range about to be freed carries the
    /// registration without holding this lock across the release.
    #[must_use]
    pub fn guest_mapping(&self) -> Option<(usize, usize)> {
        self.inner.lock().mapping
    }

    /// Deregister the guest mapping if `[start, start + len)` overlaps it, copying the mapped
    /// content back into the owned store first so the framebuffer survives the unmap with its
    /// last-drawn contents intact. No-op when nothing is registered or the range is unrelated.
    ///
    /// Must run BEFORE the overlapping pages are actually unmapped (the copy-back reads them);
    /// a partial unmap deregisters the whole mapping -- the remainder stays mapped but stops
    /// being the pixel store, which is safe (writes there just stop propagating).
    pub fn clear_guest_mapping_overlapping(&self, start: usize, len: usize) {
        let mut state = self.inner.lock();
        let Some((addr, map_len)) = state.mapping else {
            return;
        };
        let map_end = addr.saturating_add(map_len);
        let end = start.saturating_add(len);
        if end <= addr || start >= map_end {
            return;
        }
        let n = map_len.min(state.pixels.len());
        // SAFETY: the mapping is still registered, so per `set_guest_mapping`'s contract the
        // pages are still valid until this function clears it below.
        let src = unsafe { core::slice::from_raw_parts(addr as *const u8, n) };
        let copied: Vec<u8> = src.to_vec();
        state.pixels[..n].copy_from_slice(&copied);
        state.mapping = None;
    }
}

impl<Platform: RawSyncPrimitivesProvider + 'static> Default for Framebuffer<Platform> {
    fn default() -> Self {
        Self::new()
    }
}
