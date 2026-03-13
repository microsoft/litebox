// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! GDI32.dll function implementations
//!
//! This module provides minimal stub implementations of the Windows GDI
//! (Graphics Device Interface) API.  These stubs allow programs that link
//! against GDI32 to run in a headless Linux environment without crashing.
//! All drawing operations are silently discarded; functions return values
//! that indicate success so that callers can continue without error-checking.

// Allow unsafe operations inside unsafe functions
#![allow(unsafe_op_in_unsafe_fn)]

use core::ffi::c_void;

// ── Return-value constants ────────────────────────────────────────────────────

/// Fake non-null HGDIOBJ returned by `GetStockObject`
const FAKE_HGDIOBJ: usize = 0x0000_6D01;

/// Fake non-null HBRUSH returned by `CreateSolidBrush`
const FAKE_HBRUSH: usize = 0x0000_B001;

/// Fake non-null HGDIOBJ returned as the previous object by `SelectObject`
const FAKE_PREV_OBJ: usize = 0x0000_6D02;

/// Fake non-null HDC returned by `CreateCompatibleDC`
const FAKE_COMPAT_HDC: usize = 0x0000_0DC1;

/// Fake non-null HFONT returned by `CreateFontW`
const FAKE_HFONT: usize = 0x0000_F001;

/// Fake non-null HBITMAP returned by `CreateCompatibleBitmap` / `CreateDIBSection`
const FAKE_HBITMAP: usize = 0x0000_B177;

/// Fake non-null HPEN returned by `CreatePen`
const FAKE_HPEN: usize = 0x0000_CEED;

/// Fake non-null HRGN returned by `CreateRectRgn`
const FAKE_HRGN: usize = 0x0000_BEEF;

// ── GDI32 stub implementations ────────────────────────────────────────────────

/// `GetStockObject` — retrieve a handle to one of the stock pens, brushes,
/// fonts, or palettes.
///
/// Returns a fake non-null HGDIOBJ in headless mode.
///
/// # Safety
/// `object` is a plain integer; always safe.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gdi32_GetStockObject(_object: i32) -> *mut c_void {
    FAKE_HGDIOBJ as *mut c_void
}

/// `CreateSolidBrush` — create a logical brush with the specified solid color.
///
/// Returns a fake non-null HBRUSH in headless mode.
///
/// # Safety
/// `color` is a plain integer (COLORREF); always safe.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gdi32_CreateSolidBrush(_color: u32) -> *mut c_void {
    FAKE_HBRUSH as *mut c_void
}

/// `DeleteObject` — delete a logical pen, brush, font, bitmap, region, or palette.
///
/// Returns 1 (TRUE); there are no real GDI objects to delete in headless mode.
///
/// # Safety
/// `object` is not meaningfully dereferenced; always safe.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gdi32_DeleteObject(_object: *mut c_void) -> i32 {
    1
}

/// `SelectObject` — select an object into the specified device context.
///
/// Returns a fake previous HGDIOBJ so that callers can restore it.
///
/// # Safety
/// Parameters are not meaningfully dereferenced; always safe.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gdi32_SelectObject(
    _hdc: *mut c_void,
    _object: *mut c_void,
) -> *mut c_void {
    FAKE_PREV_OBJ as *mut c_void
}

/// `CreateCompatibleDC` — create a memory device context compatible with the
/// specified device.
///
/// Returns a fake non-null HDC in headless mode.
///
/// # Safety
/// `hdc` is not dereferenced; always safe.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gdi32_CreateCompatibleDC(_hdc: *mut c_void) -> *mut c_void {
    FAKE_COMPAT_HDC as *mut c_void
}

/// `DeleteDC` — delete the specified device context.
///
/// Returns 1 (TRUE); there are no real DCs to delete in headless mode.
///
/// # Safety
/// `hdc` is not meaningfully dereferenced; always safe.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gdi32_DeleteDC(_hdc: *mut c_void) -> i32 {
    1
}

/// `SetBkColor` — set the current background color of the specified device context.
///
/// Returns the previous background color (0 = black) in headless mode.
///
/// # Safety
/// `hdc` is not meaningfully dereferenced; always safe.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gdi32_SetBkColor(_hdc: *mut c_void, _color: u32) -> u32 {
    0 // CLR_INVALID would be 0xFFFF_FFFF; 0 means "previous was black"
}

/// `SetTextColor` — set the text color for the specified device context.
///
/// Returns the previous text color (0 = black) in headless mode.
///
/// # Safety
/// `hdc` is not meaningfully dereferenced; always safe.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gdi32_SetTextColor(_hdc: *mut c_void, _color: u32) -> u32 {
    0
}

/// `TextOutW` — write a character string at the specified location.
///
/// Returns 1 (TRUE); the text is silently discarded in headless mode.
///
/// # Safety
/// `string` and `hdc` are not meaningfully dereferenced; always safe.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gdi32_TextOutW(
    _hdc: *mut c_void,
    _x: i32,
    _y: i32,
    _string: *const u16,
    _c: i32,
) -> i32 {
    1
}

/// `Rectangle` — draw a rectangle.
///
/// Returns 1 (TRUE); the drawing is silently discarded in headless mode.
///
/// # Safety
/// `hdc` is not meaningfully dereferenced; always safe.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gdi32_Rectangle(
    _hdc: *mut c_void,
    _left: i32,
    _top: i32,
    _right: i32,
    _bottom: i32,
) -> i32 {
    1
}

/// `FillRect` — fill a rectangle using the specified brush.
///
/// Returns 1 (non-zero = success); the fill is silently discarded in headless mode.
///
/// # Safety
/// `rect` and `brush` are not meaningfully dereferenced; always safe.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gdi32_FillRect(
    _hdc: *mut c_void,
    _rect: *const c_void,
    _brush: *mut c_void,
) -> i32 {
    1
}

/// `CreateFontW` — create a logical font with the specified characteristics.
///
/// Returns a fake non-null HFONT in headless mode.
///
/// # Safety
/// Pointer parameters are not dereferenced; always safe.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gdi32_CreateFontW(
    _height: i32,
    _width: i32,
    _escapement: i32,
    _orientation: i32,
    _weight: i32,
    _italic: u32,
    _underline: u32,
    _strike_out: u32,
    _char_set: u32,
    _out_precision: u32,
    _clip_precision: u32,
    _quality: u32,
    _pitch_and_family: u32,
    _face_name: *const u16,
) -> *mut c_void {
    FAKE_HFONT as *mut c_void
}

/// `GetTextExtentPoint32W` — compute the width and height of the specified string
/// of text.
///
/// Writes a fake SIZE of (8, 16) — 8 pixels wide per character × 16 pixels tall —
/// and returns 1 (TRUE).
///
/// # Safety
/// `size` must be either null or a valid writable buffer of ≥ 8 bytes (2 × i32).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gdi32_GetTextExtentPoint32W(
    _hdc: *mut c_void,
    _string: *const u16,
    c: i32,
    size: *mut i32,
) -> i32 {
    if !size.is_null() {
        // SAFETY: caller guarantees `size` points to a SIZE (2 × i32).
        size.write(c * 8); // cx: 8 pixels per character
        size.add(1).write(16); // cy: 16 pixels tall
    }
    1
}

// ── Phase 45: Extended graphics primitives ────────────────────────────────────

/// `GetDeviceCaps` — retrieve device-specific information for the specified device.
///
/// Returns representative values for a headless 800×600 display.
///
/// # Safety
/// `hdc` is not meaningfully dereferenced; always safe.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gdi32_GetDeviceCaps(_hdc: *mut c_void, index: i32) -> i32 {
    // Common CAPS indices
    match index {
        8 => 800,      // HORZRES — horizontal resolution in pixels
        10 => 600,     // VERTRES — vertical resolution in pixels
        12 => 32,      // BITSPIXEL — 32-bit color
        88 | 90 => 96, // LOGPIXELSX / LOGPIXELSY — 96 dpi
        _ => 0,
    }
}

/// `SetBkMode` — set the background mix mode for the specified device context.
///
/// Returns 1 (previous background mode = OPAQUE); no-op in headless mode.
///
/// # Safety
/// `hdc` is not meaningfully dereferenced; always safe.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gdi32_SetBkMode(_hdc: *mut c_void, _mode: i32) -> i32 {
    1 // OPAQUE
}

/// `SetMapMode` — set the mapping mode of the specified device context.
///
/// Returns 1 (MM_TEXT); no-op in headless mode.
///
/// # Safety
/// `hdc` is not meaningfully dereferenced; always safe.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gdi32_SetMapMode(_hdc: *mut c_void, _mode: i32) -> i32 {
    1 // MM_TEXT
}

/// `SetViewportOrgEx` — set the origin of the viewport for the specified device context.
///
/// Writes (0, 0) as the previous origin and returns 1 (TRUE).
///
/// # Safety
/// `point` must be a valid 2-i32 buffer or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gdi32_SetViewportOrgEx(
    _hdc: *mut c_void,
    _x: i32,
    _y: i32,
    point: *mut i32,
) -> i32 {
    if !point.is_null() {
        // SAFETY: caller guarantees `point` points to a POINT (2 × i32).
        point.write(0);
        point.add(1).write(0);
    }
    1
}

/// `CreatePen` — create a logical pen with the specified style, width, and color.
///
/// Returns a fake non-null HPEN in headless mode.
///
/// # Safety
/// No pointer parameters; always safe.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gdi32_CreatePen(_style: i32, _width: i32, _color: u32) -> *mut c_void {
    FAKE_HPEN as *mut c_void
}

/// `CreatePenIndirect` — create a logical cosmetic pen from a LOGPEN structure.
///
/// Returns a fake non-null HPEN in headless mode.
///
/// # Safety
/// `logpen` is not meaningfully dereferenced; always safe.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gdi32_CreatePenIndirect(_logpen: *const c_void) -> *mut c_void {
    FAKE_HPEN as *mut c_void
}

/// `CreateBrushIndirect` — create a logical brush from a LOGBRUSH structure.
///
/// Returns a fake non-null HBRUSH in headless mode.
///
/// # Safety
/// `logbrush` is not meaningfully dereferenced; always safe.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gdi32_CreateBrushIndirect(_logbrush: *const c_void) -> *mut c_void {
    FAKE_HBRUSH as *mut c_void
}

/// `CreatePatternBrush` — create a logical brush with the specified bitmap pattern.
///
/// Returns a fake non-null HBRUSH in headless mode.
///
/// # Safety
/// `hbm` is not meaningfully dereferenced; always safe.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gdi32_CreatePatternBrush(_hbm: *mut c_void) -> *mut c_void {
    FAKE_HBRUSH as *mut c_void
}

/// `CreateHatchBrush` — create a logical brush with the specified hatch pattern.
///
/// Returns a fake non-null HBRUSH in headless mode.
///
/// # Safety
/// No pointer parameters; always safe.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gdi32_CreateHatchBrush(_style: i32, _color: u32) -> *mut c_void {
    FAKE_HBRUSH as *mut c_void
}

/// `CreateBitmap` — create a bitmap with the specified width, height, and color format.
///
/// Returns a fake non-null HBITMAP in headless mode.
///
/// # Safety
/// `pbm_bits` is not meaningfully dereferenced; always safe.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gdi32_CreateBitmap(
    _width: i32,
    _height: i32,
    _planes: u32,
    _bit_count: u32,
    _pbm_bits: *const c_void,
) -> *mut c_void {
    FAKE_HBITMAP as *mut c_void
}

/// `CreateCompatibleBitmap` — create a bitmap compatible with the specified device context.
///
/// Returns a fake non-null HBITMAP in headless mode.
///
/// # Safety
/// `hdc` is not meaningfully dereferenced; always safe.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gdi32_CreateCompatibleBitmap(
    _hdc: *mut c_void,
    _cx: i32,
    _cy: i32,
) -> *mut c_void {
    FAKE_HBITMAP as *mut c_void
}

/// `CreateDIBSection` — create a DIB that applications can write to directly.
///
/// Returns a fake non-null HBITMAP; `*ppv_bits` is set to null in headless mode.
///
/// # Safety
/// `ppv_bits` must be a valid pointer-to-pointer or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gdi32_CreateDIBSection(
    _hdc: *mut c_void,
    _pbmi: *const c_void,
    _usage: u32,
    ppv_bits: *mut *mut c_void,
    _h_section: *mut c_void,
    _offset: u32,
) -> *mut c_void {
    if !ppv_bits.is_null() {
        // SAFETY: caller guarantees `ppv_bits` is a valid pointer-to-pointer.
        ppv_bits.write(core::ptr::null_mut());
    }
    FAKE_HBITMAP as *mut c_void
}

/// `GetDIBits` — retrieve the bits of the specified compatible bitmap.
///
/// Returns 0 (no scan lines transferred) in headless mode.
///
/// # Safety
/// Pointer parameters are not meaningfully dereferenced; always safe.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gdi32_GetDIBits(
    _hdc: *mut c_void,
    _hbm: *mut c_void,
    _start: u32,
    _lines: u32,
    _pv_bits: *mut c_void,
    _pbmi: *mut c_void,
    _usage: u32,
) -> i32 {
    0
}

/// `SetDIBits` — set the pixels in a compatible bitmap.
///
/// Returns 1 (non-zero = success); pixels are silently discarded in headless mode.
///
/// # Safety
/// Pointer parameters are not meaningfully dereferenced; always safe.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gdi32_SetDIBits(
    _hdc: *mut c_void,
    _hbm: *mut c_void,
    _start: u32,
    _lines: u32,
    _pv_bits: *const c_void,
    _pbmi: *const c_void,
    _usage: u32,
) -> i32 {
    1
}

/// `BitBlt` — perform a bit-block transfer between device contexts.
///
/// Returns 1 (TRUE); the operation is silently discarded in headless mode.
///
/// # Safety
/// Parameters are not meaningfully dereferenced; always safe.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gdi32_BitBlt(
    _hdc_dst: *mut c_void,
    _x: i32,
    _y: i32,
    _cx: i32,
    _cy: i32,
    _hdc_src: *mut c_void,
    _x1: i32,
    _y1: i32,
    _rop: u32,
) -> i32 {
    1
}

/// `StretchBlt` — copy a bitmap from source to destination, stretching or compressing as needed.
///
/// Returns 1 (TRUE); the operation is silently discarded in headless mode.
///
/// # Safety
/// Parameters are not meaningfully dereferenced; always safe.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gdi32_StretchBlt(
    _hdc_dst: *mut c_void,
    _xdst: i32,
    _ydst: i32,
    _wdst: i32,
    _hdst: i32,
    _hdc_src: *mut c_void,
    _xsrc: i32,
    _ysrc: i32,
    _wsrc: i32,
    _hsrc: i32,
    _rop: u32,
) -> i32 {
    1
}

/// `PatBlt` — paint the specified rectangle using the brush currently selected into the DC.
///
/// Returns 1 (TRUE); the operation is silently discarded in headless mode.
///
/// # Safety
/// `hdc` is not meaningfully dereferenced; always safe.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gdi32_PatBlt(
    _hdc: *mut c_void,
    _x: i32,
    _y: i32,
    _w: i32,
    _h: i32,
    _rop: u32,
) -> i32 {
    1
}

/// `GetPixel` — retrieve the red, green, blue (RGB) color value of the pixel at the given coordinates.
///
/// Returns 0 (black) in headless mode.
///
/// # Safety
/// `hdc` is not meaningfully dereferenced; always safe.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gdi32_GetPixel(_hdc: *mut c_void, _x: i32, _y: i32) -> u32 {
    0
}

/// `SetPixel` — set the pixel at the given coordinates to the specified color.
///
/// Returns the color value passed (clr_ref); pixels are silently discarded in headless mode.
///
/// # Safety
/// `hdc` is not meaningfully dereferenced; always safe.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gdi32_SetPixel(_hdc: *mut c_void, _x: i32, _y: i32, clr_ref: u32) -> u32 {
    clr_ref
}

/// `MoveToEx` — update the current position to the specified point.
///
/// Writes (0, 0) as the previous position and returns 1 (TRUE).
///
/// # Safety
/// `point` must be a valid 2-i32 buffer or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gdi32_MoveToEx(
    _hdc: *mut c_void,
    _x: i32,
    _y: i32,
    point: *mut i32,
) -> i32 {
    if !point.is_null() {
        // SAFETY: caller guarantees `point` points to a POINT (2 × i32).
        point.write(0);
        point.add(1).write(0);
    }
    1
}

/// `LineTo` — draw a line from the current position to the specified point.
///
/// Returns 1 (TRUE); the line is silently discarded in headless mode.
///
/// # Safety
/// `hdc` is not meaningfully dereferenced; always safe.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gdi32_LineTo(_hdc: *mut c_void, _x: i32, _y: i32) -> i32 {
    1
}

/// `Polyline` — draw a series of line segments by connecting points in a buffer.
///
/// Returns 1 (TRUE); the polyline is silently discarded in headless mode.
///
/// # Safety
/// `apt` is not meaningfully dereferenced; always safe.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gdi32_Polyline(
    _hdc: *mut c_void,
    _apt: *const c_void,
    _count: i32,
) -> i32 {
    1
}

/// `Polygon` — draw a polygon.
///
/// Returns 1 (TRUE); the polygon is silently discarded in headless mode.
///
/// # Safety
/// `apt` is not meaningfully dereferenced; always safe.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gdi32_Polygon(_hdc: *mut c_void, _apt: *const c_void, _count: i32) -> i32 {
    1
}

/// `Ellipse` — draw an ellipse.
///
/// Returns 1 (TRUE); the ellipse is silently discarded in headless mode.
///
/// # Safety
/// `hdc` is not meaningfully dereferenced; always safe.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gdi32_Ellipse(
    _hdc: *mut c_void,
    _left: i32,
    _top: i32,
    _right: i32,
    _bottom: i32,
) -> i32 {
    1
}

/// `Arc` — draw an elliptical arc.
///
/// Returns 1 (TRUE); the arc is silently discarded in headless mode.
///
/// # Safety
/// `hdc` is not meaningfully dereferenced; always safe.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gdi32_Arc(
    _hdc: *mut c_void,
    _left: i32,
    _top: i32,
    _right: i32,
    _bottom: i32,
    _xstart: i32,
    _ystart: i32,
    _xend: i32,
    _yend: i32,
) -> i32 {
    1
}

/// `RoundRect` — draw a rectangle with rounded corners.
///
/// Returns 1 (TRUE); the rounded rectangle is silently discarded in headless mode.
///
/// # Safety
/// `hdc` is not meaningfully dereferenced; always safe.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gdi32_RoundRect(
    _hdc: *mut c_void,
    _left: i32,
    _top: i32,
    _right: i32,
    _bottom: i32,
    _width: i32,
    _height: i32,
) -> i32 {
    1
}

/// `GetTextMetricsW` — fill a TEXTMETRICW structure for the current font.
///
/// Writes placeholder metrics (height=16, average width=8) and returns 1 (TRUE).
///
/// # Safety
/// `tm` must be a valid writable pointer to at least `sizeof(TEXTMETRICW) = 60` bytes
/// (15 i32-equivalent units), or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gdi32_GetTextMetricsW(_hdc: *mut c_void, tm: *mut i32) -> i32 {
    if !tm.is_null() {
        // TEXTMETRICW: zero the entire structure first (15 i32-equivalent fields = 60 bytes)
        // SAFETY: caller guarantees `tm` points to a TEXTMETRICW.
        for i in 0..15 {
            tm.add(i).write(0);
        }
        // tmHeight (offset 0) = 16
        tm.write(16);
        // tmAveCharWidth (offset 5 × 4 bytes) = 8
        tm.add(5).write(8);
        // tmMaxCharWidth (offset 6 × 4 bytes) = 16
        tm.add(6).write(16);
    }
    1
}

/// `CreateRectRgn` — create a rectangular region.
///
/// Returns a fake non-null HRGN in headless mode.
///
/// # Safety
/// No pointer parameters; always safe.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gdi32_CreateRectRgn(
    _left: i32,
    _top: i32,
    _right: i32,
    _bottom: i32,
) -> *mut c_void {
    FAKE_HRGN as *mut c_void
}

/// `SelectClipRgn` — select a region as the current clipping region for the device context.
///
/// Returns 1 (SIMPLEREGION); no-op in headless mode.
///
/// # Safety
/// Parameters are not meaningfully dereferenced; always safe.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gdi32_SelectClipRgn(_hdc: *mut c_void, _hrgn: *mut c_void) -> i32 {
    1 // SIMPLEREGION
}

/// `GetClipBox` — retrieve the bounding rectangle of the current clipping region.
///
/// Fills a fake 800×600 clip region and returns 1 (SIMPLEREGION).
///
/// # Safety
/// `rect` must be a valid 4-i32 buffer or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gdi32_GetClipBox(_hdc: *mut c_void, rect: *mut i32) -> i32 {
    if !rect.is_null() {
        // SAFETY: caller guarantees `rect` points to a RECT (4 × i32).
        rect.write(0); // left
        rect.add(1).write(0); // top
        rect.add(2).write(800); // right
        rect.add(3).write(600); // bottom
    }
    1 // SIMPLEREGION
}

/// `SetStretchBltMode` — set the bitmap stretching mode in the specified device context.
///
/// Returns 1 (previous BLACKONWHITE mode); no-op in headless mode.
///
/// # Safety
/// `hdc` is not meaningfully dereferenced; always safe.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gdi32_SetStretchBltMode(_hdc: *mut c_void, _mode: i32) -> i32 {
    1 // BLACKONWHITE
}

/// `GetObjectW` — retrieve information for the specified graphics object.
///
/// Returns 0 (object not found) in headless mode.
///
/// # Safety
/// `pv` is not meaningfully dereferenced; always safe.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gdi32_GetObjectW(_h: *mut c_void, _c: i32, _pv: *mut c_void) -> i32 {
    0
}

/// `GetCurrentObject` — retrieve a handle to the currently selected object of a given type.
///
/// Returns a fake non-null object handle in headless mode.
///
/// # Safety
/// `hdc` is not meaningfully dereferenced; always safe.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gdi32_GetCurrentObject(_hdc: *mut c_void, _type: u32) -> *mut c_void {
    FAKE_HGDIOBJ as *mut c_void
}

/// `ExcludeClipRect` — remove a rectangle from the clipping region.
///
/// Returns 1 (SIMPLEREGION); no-op in headless mode.
///
/// # Safety
/// `hdc` is not meaningfully dereferenced; always safe.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gdi32_ExcludeClipRect(
    _hdc: *mut c_void,
    _left: i32,
    _top: i32,
    _right: i32,
    _bottom: i32,
) -> i32 {
    1
}

/// `IntersectClipRect` — create a new clipping region from the intersection.
///
/// Returns 1 (SIMPLEREGION); no-op in headless mode.
///
/// # Safety
/// `hdc` is not meaningfully dereferenced; always safe.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gdi32_IntersectClipRect(
    _hdc: *mut c_void,
    _left: i32,
    _top: i32,
    _right: i32,
    _bottom: i32,
) -> i32 {
    1
}

/// `SaveDC` — save the current state of the specified device context.
///
/// Returns 1 (saved state ID); no-op in headless mode.
///
/// # Safety
/// `hdc` is not meaningfully dereferenced; always safe.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gdi32_SaveDC(_hdc: *mut c_void) -> i32 {
    1
}

/// `RestoreDC` — restore a device context to the specified state.
///
/// Returns 1 (TRUE); no-op in headless mode.
///
/// # Safety
/// `hdc` is not meaningfully dereferenced; always safe.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gdi32_RestoreDC(_hdc: *mut c_void, _saved_dc: i32) -> i32 {
    1
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_stock_object_returns_nonnull() {
        // SAFETY: plain integer argument; always safe.
        let obj = unsafe { gdi32_GetStockObject(0) }; // WHITE_BRUSH = 0
        assert!(!obj.is_null());
    }

    #[test]
    fn test_create_solid_brush_returns_nonnull() {
        // SAFETY: color is a plain u32; always safe.
        let brush = unsafe { gdi32_CreateSolidBrush(0x00FF_0000) }; // red
        assert!(!brush.is_null());
    }

    #[test]
    fn test_delete_object_returns_one() {
        // SAFETY: null GDI object; stub does not dereference it.
        let result = unsafe { gdi32_DeleteObject(std::ptr::null_mut()) };
        assert_eq!(result, 1);
    }

    #[test]
    fn test_select_object_returns_fake_prev() {
        // SAFETY: null HDC and null object; stub does not dereference them.
        let prev = unsafe { gdi32_SelectObject(std::ptr::null_mut(), std::ptr::null_mut()) };
        assert!(!prev.is_null());
    }

    #[test]
    fn test_create_compatible_dc_returns_nonnull() {
        // SAFETY: null HDC; stub does not dereference it.
        let hdc = unsafe { gdi32_CreateCompatibleDC(std::ptr::null_mut()) };
        assert!(!hdc.is_null());
    }

    #[test]
    fn test_delete_dc_returns_one() {
        // SAFETY: null HDC; stub does not dereference it.
        let result = unsafe { gdi32_DeleteDC(std::ptr::null_mut()) };
        assert_eq!(result, 1);
    }

    #[test]
    fn test_set_bk_color_returns_previous() {
        // SAFETY: null HDC; stub does not dereference it.
        let prev = unsafe { gdi32_SetBkColor(std::ptr::null_mut(), 0x00FF_0000) };
        assert_eq!(prev, 0);
    }

    #[test]
    fn test_set_text_color_returns_previous() {
        // SAFETY: null HDC; stub does not dereference it.
        let prev = unsafe { gdi32_SetTextColor(std::ptr::null_mut(), 0x0000_00FF) };
        assert_eq!(prev, 0);
    }

    #[test]
    fn test_text_out_returns_one() {
        // SAFETY: all null/integer parameters; stub does not dereference them.
        let result = unsafe { gdi32_TextOutW(std::ptr::null_mut(), 0, 0, std::ptr::null(), 0) };
        assert_eq!(result, 1);
    }

    #[test]
    fn test_rectangle_returns_one() {
        // SAFETY: null HDC; stub does not dereference it.
        let result = unsafe { gdi32_Rectangle(std::ptr::null_mut(), 0, 0, 100, 100) };
        assert_eq!(result, 1);
    }

    #[test]
    fn test_fill_rect_returns_nonzero() {
        // SAFETY: all null parameters; stub does not dereference them.
        let result =
            unsafe { gdi32_FillRect(std::ptr::null_mut(), std::ptr::null(), std::ptr::null_mut()) };
        assert_ne!(result, 0);
    }

    #[test]
    fn test_create_font_returns_nonnull() {
        // SAFETY: all integer/null parameters; stub does not dereference them.
        let hfont = unsafe {
            gdi32_CreateFontW(16, 0, 0, 0, 400, 0, 0, 0, 0, 0, 0, 0, 0, std::ptr::null())
        };
        assert!(!hfont.is_null());
    }

    #[test]
    fn test_get_text_extent_returns_one_and_fills_size() {
        // SAFETY: size is a valid 2-i32 buffer; string pointer is null (c=0).
        let mut size = [0i32; 2];
        let result = unsafe {
            gdi32_GetTextExtentPoint32W(
                std::ptr::null_mut(),
                std::ptr::null(),
                5,
                size.as_mut_ptr(),
            )
        };
        assert_eq!(result, 1);
        assert_eq!(size[0], 40); // 5 chars × 8 px
        assert_eq!(size[1], 16);
    }

    #[test]
    fn test_get_text_extent_null_size() {
        // SAFETY: null size; GetTextExtentPoint32W guards with null check.
        let result = unsafe {
            gdi32_GetTextExtentPoint32W(
                std::ptr::null_mut(),
                std::ptr::null(),
                3,
                std::ptr::null_mut(),
            )
        };
        assert_eq!(result, 1);
    }

    // ── Phase 45 tests ────────────────────────────────────────────────────
    #[test]
    fn test_create_pen_returns_nonnull() {
        // SAFETY: integer parameters; always safe.
        let hpen = unsafe { gdi32_CreatePen(0, 1, 0) };
        assert!(!hpen.is_null());
    }

    #[test]
    fn test_create_compatible_bitmap_returns_nonnull() {
        // SAFETY: null HDC; stub returns a fake HBITMAP.
        let hbm = unsafe { gdi32_CreateCompatibleBitmap(std::ptr::null_mut(), 100, 100) };
        assert!(!hbm.is_null());
    }

    #[test]
    fn test_create_dib_section_returns_nonnull_and_nulls_bits() {
        let mut bits: *mut c_void = 0xDEAD as *mut c_void;
        // SAFETY: bits is a valid pointer-to-pointer.
        let hbm = unsafe {
            gdi32_CreateDIBSection(
                std::ptr::null_mut(),
                std::ptr::null(),
                0,
                &raw mut bits,
                std::ptr::null_mut(),
                0,
            )
        };
        assert!(!hbm.is_null());
        assert!(bits.is_null());
    }

    #[test]
    fn test_bit_blt_returns_one() {
        // SAFETY: null parameters; stub does not dereference them.
        let result = unsafe {
            gdi32_BitBlt(
                std::ptr::null_mut(),
                0,
                0,
                100,
                100,
                std::ptr::null_mut(),
                0,
                0,
                0xCC0020,
            )
        };
        assert_eq!(result, 1);
    }

    #[test]
    fn test_move_to_ex_writes_zero_origin() {
        let mut pt = [1i32; 2];
        // SAFETY: pt is a valid 2-i32 buffer.
        let result = unsafe { gdi32_MoveToEx(std::ptr::null_mut(), 50, 50, pt.as_mut_ptr()) };
        assert_eq!(result, 1);
        assert_eq!(pt, [0i32; 2]);
    }

    #[test]
    fn test_line_to_returns_one() {
        // SAFETY: null HDC; stub does not dereference it.
        let result = unsafe { gdi32_LineTo(std::ptr::null_mut(), 100, 100) };
        assert_eq!(result, 1);
    }

    #[test]
    fn test_ellipse_returns_one() {
        // SAFETY: null HDC; stub does not dereference it.
        let result = unsafe { gdi32_Ellipse(std::ptr::null_mut(), 0, 0, 100, 100) };
        assert_eq!(result, 1);
    }

    #[test]
    fn test_round_rect_returns_one() {
        // SAFETY: null HDC; stub does not dereference it.
        let result = unsafe { gdi32_RoundRect(std::ptr::null_mut(), 0, 0, 100, 100, 10, 10) };
        assert_eq!(result, 1);
    }

    #[test]
    fn test_get_text_metrics_fills_height() {
        let mut tm = [0i32; 15];
        // SAFETY: tm is a valid 15-i32 buffer (sizeof(TEXTMETRICW) = 60 bytes).
        let result = unsafe { gdi32_GetTextMetricsW(std::ptr::null_mut(), tm.as_mut_ptr()) };
        assert_eq!(result, 1);
        assert_eq!(tm[0], 16); // tmHeight
        assert_eq!(tm[5], 8); // tmAveCharWidth
        assert_eq!(tm[6], 16); // tmMaxCharWidth
    }

    #[test]
    fn test_create_rect_rgn_returns_nonnull() {
        // SAFETY: integer parameters; always safe.
        let hrgn = unsafe { gdi32_CreateRectRgn(0, 0, 100, 100) };
        assert!(!hrgn.is_null());
    }

    #[test]
    fn test_get_clip_box_fills_800x600() {
        let mut rect = [0i32; 4];
        // SAFETY: rect is a valid 4-i32 buffer.
        let result = unsafe { gdi32_GetClipBox(std::ptr::null_mut(), rect.as_mut_ptr()) };
        assert_eq!(result, 1);
        assert_eq!(rect[2], 800);
        assert_eq!(rect[3], 600);
    }

    #[test]
    fn test_save_restore_dc() {
        // SAFETY: null HDC; stubs do not dereference it.
        let saved = unsafe { gdi32_SaveDC(std::ptr::null_mut()) };
        assert_eq!(saved, 1);
        let result = unsafe { gdi32_RestoreDC(std::ptr::null_mut(), saved) };
        assert_eq!(result, 1);
    }

    #[test]
    fn test_set_bk_mode_returns_previous() {
        // SAFETY: null HDC; stub does not dereference it.
        let prev = unsafe { gdi32_SetBkMode(std::ptr::null_mut(), 2) }; // TRANSPARENT
        assert_eq!(prev, 1); // previous = OPAQUE
    }
}
