// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! USER32.dll function implementations
//!
//! This module provides minimal stub implementations of the Windows USER32 GUI
//! API. These stubs allow programs that link against USER32 to run in a headless
//! Linux environment without crashing. GUI operations print diagnostic messages
//! to stderr and return values that indicate "no window / no messages", enabling
//! programs with optional GUI code paths to continue executing their non-GUI
//! logic.

// Allow unsafe operations inside unsafe functions
#![allow(unsafe_op_in_unsafe_fn)]

use core::ffi::c_void;

// ── Return-value constants ────────────────────────────────────────────────────

/// IDOK — returned by `MessageBoxW` when the user clicks OK (or when headless)
const IDOK: i32 = 1;

/// Fake non-null HWND returned by `CreateWindowExW`
const FAKE_HWND: usize = 0x0000_BEEF;

/// Fake non-zero ATOM returned by `RegisterClassExW`
const FAKE_ATOM: u16 = 1;

/// Fake non-null HCURSOR returned by `LoadCursorW`
const FAKE_HCURSOR: usize = 0x0000_C001;

/// Fake non-null HICON returned by `LoadIconW`
const FAKE_HICON: usize = 0x0000_1C04;

/// Fake non-null HDC returned by `GetDC`, `BeginPaint`, etc.
const FAKE_HDC: usize = 0x0000_0D0C;

/// Fake non-null HMENU returned by `CreateMenu` / `CreatePopupMenu`
const FAKE_HMENU: usize = 0x0000_FEED;

/// IDCANCEL — returned by `DialogBoxParamW` cancel path
const IDCANCEL: i32 = 2;

// ── Wide-string helper ────────────────────────────────────────────────────────

/// Convert a null-terminated UTF-16 pointer to a `String`, or return an empty
/// string if the pointer is null.
///
/// # Safety
/// `ptr` must be either null or a valid, non-dangling pointer to a
/// null-terminated UTF-16 string. Reading up to 32 768 code units.
unsafe fn wide_to_string(ptr: *const u16) -> String {
    if ptr.is_null() {
        return String::new();
    }
    // SAFETY: Caller guarantees `ptr` is a valid null-terminated UTF-16 string.
    let mut len = 0usize;
    while len < 32_768 && *ptr.add(len) != 0 {
        len += 1;
    }
    let slice = std::slice::from_raw_parts(ptr, len);
    String::from_utf16_lossy(slice)
}

// ── USER32 stub implementations ───────────────────────────────────────────────

/// `MessageBoxW` — display a modal dialog box.
///
/// In headless mode (no display), the message and caption are printed to stderr
/// and IDOK (1) is returned, as if the user clicked OK.
///
/// # Safety
/// `text` and `caption` must be null-terminated UTF-16 strings or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn user32_MessageBoxW(
    _hwnd: *mut c_void,
    text: *const u16,
    caption: *const u16,
    _msg_type: u32,
) -> i32 {
    let text_str = wide_to_string(text);
    let caption_str = wide_to_string(caption);
    eprintln!("[USER32] MessageBoxW: [{caption_str}] {text_str}");
    IDOK
}

/// `RegisterClassExW` — register a window class.
///
/// Returns a fake non-zero ATOM so that the caller believes the class was
/// registered successfully.
///
/// # Safety
/// `wndclassex` must be a valid pointer or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn user32_RegisterClassExW(_wndclassex: *const c_void) -> u16 {
    FAKE_ATOM
}

/// `CreateWindowExW` — create an overlapped, pop-up, or child window.
///
/// Returns a fake non-null HWND.
///
/// # Safety
/// All pointer parameters must be valid or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn user32_CreateWindowExW(
    _ex_style: u32,
    _class_name: *const u16,
    _window_name: *const u16,
    _style: u32,
    _x: i32,
    _y: i32,
    _width: i32,
    _height: i32,
    _parent: *mut c_void,
    _menu: *mut c_void,
    _instance: *mut c_void,
    _param: *mut c_void,
) -> *mut c_void {
    FAKE_HWND as *mut c_void
}

/// `ShowWindow` — set the show state of the specified window.
///
/// Returns 1 (non-zero), indicating the window was previously visible.
///
/// # Safety
/// `hwnd` must be a valid HWND or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn user32_ShowWindow(_hwnd: *mut c_void, _cmd_show: i32) -> i32 {
    1
}

/// `UpdateWindow` — update the client area of the specified window.
///
/// Returns 1 (TRUE).
///
/// # Safety
/// `hwnd` must be a valid HWND or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn user32_UpdateWindow(_hwnd: *mut c_void) -> i32 {
    1
}

/// `GetMessageW` — retrieve a message from the thread's message queue.
///
/// Returns 0, indicating a `WM_QUIT` message was received, so that message
/// loops in headless programs terminate immediately.
///
/// # Safety
/// `msg` must be a valid pointer to a MSG structure or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn user32_GetMessageW(
    _msg: *mut c_void,
    _hwnd: *mut c_void,
    _msg_filter_min: u32,
    _msg_filter_max: u32,
) -> i32 {
    0
}

/// `TranslateMessage` — translate virtual-key messages into character messages.
///
/// Returns 0 (no translation performed).
///
/// # Safety
/// `msg` must be a valid pointer to a MSG structure or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn user32_TranslateMessage(_msg: *const c_void) -> i32 {
    0
}

/// `DispatchMessageW` — dispatch a message to a window procedure.
///
/// Returns 0.
///
/// # Safety
/// `msg` must be a valid pointer to a MSG structure or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn user32_DispatchMessageW(_msg: *const c_void) -> isize {
    0
}

/// `DestroyWindow` — destroy the specified window.
///
/// Returns 1 (TRUE).
///
/// # Safety
/// `hwnd` must be a valid HWND or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn user32_DestroyWindow(_hwnd: *mut c_void) -> i32 {
    1
}

/// `PostQuitMessage` — indicate a request to terminate an application.
///
/// In headless mode there is no message queue, so this is a no-op.
///
/// # Safety
/// Always safe to call; the parameter is an exit code integer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn user32_PostQuitMessage(_exit_code: i32) {}

/// `DefWindowProcW` — call the default window procedure.
///
/// Returns 0 (no action taken in headless mode).
///
/// # Safety
/// All pointer/integer parameters are accepted without dereference.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn user32_DefWindowProcW(
    _hwnd: *mut c_void,
    _msg: u32,
    _wparam: usize,
    _lparam: isize,
) -> isize {
    0
}

/// `LoadCursorW` — load a cursor resource.
///
/// Returns a fake non-null HCURSOR so callers believe the cursor was loaded.
///
/// # Safety
/// Parameters are not dereferenced; always safe.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn user32_LoadCursorW(
    _hinstance: *mut c_void,
    _cursor_name: *const u16,
) -> *mut c_void {
    FAKE_HCURSOR as *mut c_void
}

/// `LoadIconW` — load an icon resource.
///
/// Returns a fake non-null HICON.
///
/// # Safety
/// Parameters are not dereferenced; always safe.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn user32_LoadIconW(
    _hinstance: *mut c_void,
    _icon_name: *const u16,
) -> *mut c_void {
    FAKE_HICON as *mut c_void
}

/// `GetSystemMetrics` — retrieve the specified system metric or configuration setting.
///
/// Returns sensible defaults for a headless 800×600 environment:
/// - `SM_CXSCREEN` (0) / `SM_CXFULLSCREEN` (16) → 800
/// - `SM_CYSCREEN` (1) / `SM_CYFULLSCREEN` (17) → 600
/// - All others → 0
///
/// # Safety
/// Always safe to call; `n_index` is a plain integer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn user32_GetSystemMetrics(n_index: i32) -> i32 {
    match n_index {
        0 | 16 => 800, // SM_CXSCREEN / SM_CXFULLSCREEN
        1 | 17 => 600, // SM_CYSCREEN / SM_CYFULLSCREEN
        _ => 0,
    }
}

/// `SetWindowLongPtrW` — change a window attribute (64-bit).
///
/// Returns 0 (the fake previous value) in headless mode.
///
/// # Safety
/// `hwnd` is not dereferenced; always safe.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn user32_SetWindowLongPtrW(
    _hwnd: *mut c_void,
    _n_index: i32,
    _new_long: isize,
) -> isize {
    0
}

/// `GetWindowLongPtrW` — retrieve a window attribute (64-bit).
///
/// Returns 0 in headless mode.
///
/// # Safety
/// `hwnd` is not dereferenced; always safe.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn user32_GetWindowLongPtrW(_hwnd: *mut c_void, _n_index: i32) -> isize {
    0
}

/// `SendMessageW` — send a message to a window procedure and wait for it to return.
///
/// Returns 0 in headless mode (no window procedure to dispatch to).
///
/// # Safety
/// Parameters are not dereferenced; always safe.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn user32_SendMessageW(
    _hwnd: *mut c_void,
    _msg: u32,
    _wparam: usize,
    _lparam: isize,
) -> isize {
    0
}

/// `PostMessageW` — post a message to a message queue.
///
/// Returns 1 (TRUE) in headless mode; the message is silently discarded.
///
/// # Safety
/// Parameters are not dereferenced; always safe.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn user32_PostMessageW(
    _hwnd: *mut c_void,
    _msg: u32,
    _wparam: usize,
    _lparam: isize,
) -> i32 {
    1
}

/// `PeekMessageW` — check for a message and optionally remove it from the queue.
///
/// Returns 0 (no message available) in headless mode, causing message loops to
/// yield rather than spin.
///
/// # Safety
/// `msg` must be a valid pointer to a MSG structure or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn user32_PeekMessageW(
    _msg: *mut c_void,
    _hwnd: *mut c_void,
    _msg_filter_min: u32,
    _msg_filter_max: u32,
    _remove_msg: u32,
) -> i32 {
    0
}

/// `BeginPaint` — prepare the specified window for painting.
///
/// Returns a fake HDC so that paint code can continue without crashing.
/// `paint_struct`, if non-null, is zero-filled (100 bytes) to satisfy callers
/// that inspect the `rcPaint` rectangle.
///
/// # Safety
/// `paint_struct` must be either null or a valid writable buffer of ≥ 100 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn user32_BeginPaint(
    _hwnd: *mut c_void,
    paint_struct: *mut u8,
) -> *mut c_void {
    if !paint_struct.is_null() {
        // SAFETY: caller guarantees paint_struct is a valid writable ≥100-byte buffer.
        core::ptr::write_bytes(paint_struct, 0, 100);
    }
    FAKE_HDC as *mut c_void
}

/// `EndPaint` — mark the end of painting in the specified window.
///
/// Returns 1 (TRUE).
///
/// # Safety
/// Parameters are not meaningfully dereferenced; always safe.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn user32_EndPaint(_hwnd: *mut c_void, _paint_struct: *const c_void) -> i32 {
    1
}

/// `GetClientRect` — retrieve the coordinates of a window's client area.
///
/// Fills the RECT structure (4 × i32 = 16 bytes) with a default 800×600
/// client area (`left=0, top=0, right=800, bottom=600`).  Returns 1 (TRUE).
///
/// # Safety
/// `rect` must be either null or a valid writable buffer of ≥ 16 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn user32_GetClientRect(_hwnd: *mut c_void, rect: *mut i32) -> i32 {
    if !rect.is_null() {
        // SAFETY: caller guarantees `rect` points to a RECT (4 × i32).
        rect.write(0); // left
        rect.add(1).write(0); // top
        rect.add(2).write(800); // right
        rect.add(3).write(600); // bottom
    }
    1
}

/// `InvalidateRect` — add a rectangle to the update region of a window.
///
/// Returns 1 (TRUE); the repaint is silently skipped in headless mode.
///
/// # Safety
/// `rect` is not dereferenced; always safe.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn user32_InvalidateRect(
    _hwnd: *mut c_void,
    _rect: *const c_void,
    _erase: i32,
) -> i32 {
    1
}

/// `SetTimer` — create a timer with a specified time-out value.
///
/// Timers are not supported in headless mode. Returns 0 to indicate failure,
/// consistent with the Windows documentation for a non-window timer that
/// could not be created.
///
/// # Safety
/// Parameters are not dereferenced; always safe.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn user32_SetTimer(
    _hwnd: *mut c_void,
    _id_event: usize,
    _elapse: u32,
    _timer_func: *const c_void,
) -> usize {
    0
}

/// `KillTimer` — destroy the specified timer.
///
/// Returns 1 (TRUE); there are no real timers to destroy in headless mode.
///
/// # Safety
/// Parameters are not dereferenced; always safe.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn user32_KillTimer(_hwnd: *mut c_void, _id_event: usize) -> i32 {
    1
}

/// `GetDC` — retrieve the device context for a window's client area.
///
/// Returns a fake non-null HDC.
///
/// # Safety
/// `hwnd` is not dereferenced; always safe.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn user32_GetDC(_hwnd: *mut c_void) -> *mut c_void {
    FAKE_HDC as *mut c_void
}

/// `ReleaseDC` — release a device context.
///
/// Returns 1 (TRUE).
///
/// # Safety
/// Parameters are not dereferenced; always safe.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn user32_ReleaseDC(_hwnd: *mut c_void, _hdc: *mut c_void) -> i32 {
    1
}

// ── Phase 27: Character Conversion ───────────────────────────────────────────

/// CharUpperW - converts a character or string to uppercase
/// If the high-order word of the input is zero, the character is treated as a single
/// wide char and returned uppercased. Otherwise the pointer is treated as a string
/// (in-place conversion) and returned.
/// # Safety
/// When called with a string pointer (high word != 0), the pointer must point to
/// a valid null-terminated wide string with writable memory.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn user32_CharUpperW(lpsz: *mut u16) -> *mut u16 {
    let val = lpsz as usize;
    if (val >> 16) == 0 {
        // Single character mode: the high-order word is zero; the low word is the character.
        // SAFETY: (val >> 16) == 0 guarantees val < 65536; the u32 cast never truncates
        // (usize -> u32 is lossless for values < 65536), and the u16 cast is safe for the same reason.
        #[allow(clippy::cast_possible_truncation)]
        let ch = char::from_u32(val as u32).unwrap_or('\0');
        #[allow(clippy::cast_possible_truncation)]
        let upper = ch.to_uppercase().next().map_or(val as u16, |c| c as u16);
        upper as usize as *mut u16
    } else {
        // String mode: convert in place
        let mut ptr = lpsz;
        // SAFETY: caller guarantees ptr is a valid null-terminated wide string.
        while unsafe { *ptr } != 0 {
            let ch = char::from_u32(u32::from(unsafe { *ptr })).unwrap_or('\0');
            let upper = ch
                .to_uppercase()
                .next()
                .map_or(unsafe { *ptr }, |c| c as u16);
            // SAFETY: ptr is within the valid string range checked by the while condition.
            unsafe { *ptr = upper };
            ptr = unsafe { ptr.add(1) };
        }
        lpsz
    }
}

/// CharLowerW - converts a character or string to lowercase
/// If the high-order word of the input is zero, the character is treated as a single
/// wide char and returned lowercased. Otherwise the pointer is treated as a string
/// (in-place conversion) and returned.
/// # Safety
/// When called with a string pointer (high word != 0), the pointer must point to
/// a valid null-terminated wide string with writable memory.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn user32_CharLowerW(lpsz: *mut u16) -> *mut u16 {
    let val = lpsz as usize;
    if (val >> 16) == 0 {
        // Single character mode: the high-order word is zero; the low word is the character.
        // SAFETY: (val >> 16) == 0 guarantees val < 65536; the u32 cast never truncates
        // (usize -> u32 is lossless for values < 65536), and the u16 cast is safe for the same reason.
        #[allow(clippy::cast_possible_truncation)]
        let ch = char::from_u32(val as u32).unwrap_or('\0');
        #[allow(clippy::cast_possible_truncation)]
        let lower = ch.to_lowercase().next().map_or(val as u16, |c| c as u16);
        lower as usize as *mut u16
    } else {
        let mut ptr = lpsz;
        // SAFETY: caller guarantees ptr is a valid null-terminated wide string.
        while unsafe { *ptr } != 0 {
            let ch = char::from_u32(u32::from(unsafe { *ptr })).unwrap_or('\0');
            let lower = ch
                .to_lowercase()
                .next()
                .map_or(unsafe { *ptr }, |c| c as u16);
            // SAFETY: ptr is within the valid string range checked by the while condition.
            unsafe { *ptr = lower };
            ptr = unsafe { ptr.add(1) };
        }
        lpsz
    }
}

/// CharUpperA - converts an ANSI character or string to uppercase
/// If the high-order word of the input is zero, treats the low byte as a single
/// character and returns it uppercased. Otherwise converts the string in place.
/// # Safety
/// When called with a string pointer (high word != 0), the pointer must point to
/// a valid null-terminated ANSI string with writable memory.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn user32_CharUpperA(lpsz: *mut u8) -> *mut u8 {
    let val = lpsz as usize;
    if (val >> 16) == 0 {
        // Single character mode: the high-order word is zero; the low word is the character.
        #[allow(clippy::cast_possible_truncation)]
        let b = val as u8;
        b.to_ascii_uppercase() as usize as *mut u8
    } else {
        let mut ptr = lpsz;
        // SAFETY: caller guarantees ptr is a valid null-terminated ANSI string.
        while unsafe { *ptr } != 0 {
            // SAFETY: ptr is within the valid string range checked by the while condition.
            unsafe { *ptr = (*ptr).to_ascii_uppercase() };
            ptr = unsafe { ptr.add(1) };
        }
        lpsz
    }
}

/// CharLowerA - converts an ANSI character or string to lowercase
/// If the high-order word of the input is zero, treats the low byte as a single
/// character and returns it lowercased. Otherwise converts the string in place.
/// # Safety
/// When called with a string pointer (high word != 0), the pointer must point to
/// a valid null-terminated ANSI string with writable memory.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn user32_CharLowerA(lpsz: *mut u8) -> *mut u8 {
    let val = lpsz as usize;
    if (val >> 16) == 0 {
        // Single character mode: the high-order word is zero; the low word is the character.
        #[allow(clippy::cast_possible_truncation)]
        let b = val as u8;
        b.to_ascii_lowercase() as usize as *mut u8
    } else {
        let mut ptr = lpsz;
        // SAFETY: caller guarantees ptr is a valid null-terminated ANSI string.
        while unsafe { *ptr } != 0 {
            // SAFETY: ptr is within the valid string range checked by the while condition.
            unsafe { *ptr = (*ptr).to_ascii_lowercase() };
            ptr = unsafe { ptr.add(1) };
        }
        lpsz
    }
}

// ── Phase 27: Character Classification ───────────────────────────────────────

/// IsCharAlphaW - determines whether a character is an alphabetic Unicode character
/// Returns 1 (TRUE) if the character is alphabetic, 0 (FALSE) otherwise.
/// # Safety
/// This function is safe to call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn user32_IsCharAlphaW(ch: u16) -> i32 {
    i32::from(char::from_u32(u32::from(ch)).is_some_and(char::is_alphabetic))
}

/// IsCharAlphaNumericW - determines whether a character is an alphanumeric Unicode character
/// Returns 1 (TRUE) if the character is alphanumeric, 0 (FALSE) otherwise.
/// # Safety
/// This function is safe to call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn user32_IsCharAlphaNumericW(ch: u16) -> i32 {
    i32::from(char::from_u32(u32::from(ch)).is_some_and(char::is_alphanumeric))
}

/// IsCharUpperW - determines whether a character is an uppercase Unicode character
/// Returns 1 (TRUE) if the character is uppercase, 0 (FALSE) otherwise.
/// # Safety
/// This function is safe to call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn user32_IsCharUpperW(ch: u16) -> i32 {
    i32::from(char::from_u32(u32::from(ch)).is_some_and(char::is_uppercase))
}

/// IsCharLowerW - determines whether a character is a lowercase Unicode character
/// Returns 1 (TRUE) if the character is lowercase, 0 (FALSE) otherwise.
/// # Safety
/// This function is safe to call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn user32_IsCharLowerW(ch: u16) -> i32 {
    i32::from(char::from_u32(u32::from(ch)).is_some_and(char::is_lowercase))
}

// ── Phase 27: Window Utilities ────────────────────────────────────────────────

/// IsWindow - determines whether the specified window handle identifies an existing window
/// In headless mode, no real windows exist; always returns FALSE.
/// # Safety
/// `hwnd` is accepted as an opaque value and is not dereferenced.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn user32_IsWindow(_hwnd: *mut c_void) -> i32 {
    0 // FALSE (headless)
}

/// IsWindowEnabled - determines whether the specified window is enabled for mouse/keyboard input
/// In headless mode, returns FALSE.
/// # Safety
/// `hwnd` is accepted as an opaque value and is not dereferenced.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn user32_IsWindowEnabled(_hwnd: *mut c_void) -> i32 {
    0 // FALSE (headless)
}

/// IsWindowVisible - determines whether the specified window is visible
/// In headless mode, returns FALSE.
/// # Safety
/// `hwnd` is accepted as an opaque value and is not dereferenced.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn user32_IsWindowVisible(_hwnd: *mut c_void) -> i32 {
    0 // FALSE (headless)
}

/// EnableWindow - enables or disables mouse/keyboard input to the specified window
/// In headless mode, returns FALSE (window was previously disabled).
/// # Safety
/// `hwnd` is accepted as an opaque value and is not dereferenced.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn user32_EnableWindow(_hwnd: *mut c_void, _enable: i32) -> i32 {
    0 // FALSE (headless)
}

/// GetWindowTextW - copies the text of a window's title bar into a buffer
/// In headless mode, no windows exist; returns 0 (empty/no text).
/// # Safety
/// `hwnd` is accepted as opaque; not dereferenced.
/// `string` must point to at least `max_count` wide chars if non-null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn user32_GetWindowTextW(
    _hwnd: *mut c_void,
    string: *mut u16,
    max_count: i32,
) -> i32 {
    if !string.is_null() && max_count > 0 {
        // SAFETY: string has at least max_count wide chars; we write a single null terminator.
        unsafe { *string = 0 };
    }
    0 // empty string
}

/// SetWindowTextW - changes the text of the specified window's title bar
/// In headless mode, returns FALSE (no window to update).
/// # Safety
/// `hwnd` is accepted as an opaque value and is not dereferenced.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn user32_SetWindowTextW(_hwnd: *mut c_void, _string: *const u16) -> i32 {
    0 // FALSE (headless)
}

/// GetParent - retrieves a handle to the specified window's parent
/// In headless mode, returns NULL (no parent window exists).
/// # Safety
/// `hwnd` is accepted as an opaque value and is not dereferenced.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn user32_GetParent(_hwnd: *mut c_void) -> *mut c_void {
    core::ptr::null_mut()
}

// ── Phase 28: Window utility stubs ────────────────────────────────────────

/// FindWindowW - find a window by class and/or window name. Always returns NULL (headless).
///
/// # Safety
/// Pointer arguments are ignored in this headless stub implementation.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn user32_FindWindowW(
    _lp_class_name: *const c_void,
    _lp_window_name: *const c_void,
) -> *mut c_void {
    core::ptr::null_mut()
}

/// FindWindowExW - find a child window. Always returns NULL (headless).
///
/// # Safety
/// Pointer arguments are ignored in this headless stub implementation.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn user32_FindWindowExW(
    _hwnd_parent: *mut c_void,
    _hwnd_child_after: *mut c_void,
    _lp_class: *const c_void,
    _lp_window: *const c_void,
) -> *mut c_void {
    core::ptr::null_mut()
}

/// GetForegroundWindow - returns the foreground window. Always returns NULL (headless).
///
/// # Safety
/// No preconditions.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn user32_GetForegroundWindow() -> *mut c_void {
    core::ptr::null_mut()
}

/// SetForegroundWindow - sets the foreground window. Returns FALSE (headless).
///
/// # Safety
/// No preconditions.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn user32_SetForegroundWindow(_hwnd: *mut c_void) -> i32 {
    0
}

/// BringWindowToTop - brings window to top. Returns FALSE (headless).
///
/// # Safety
/// No preconditions.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn user32_BringWindowToTop(_hwnd: *mut c_void) -> i32 {
    0
}

/// GetWindowRect - gets window bounding rectangle. Fills rect with zeros, returns TRUE.
///
/// # Safety
/// `rect` if non-null must be writable for 4 i32 values (RECT structure).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn user32_GetWindowRect(_hwnd: *mut c_void, rect: *mut i32) -> i32 {
    if !rect.is_null() {
        for i in 0..4 {
            *rect.add(i) = 0;
        }
    }
    1
}

/// SetWindowPos - sets window position and size. Returns TRUE (headless).
///
/// # Safety
/// No preconditions.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn user32_SetWindowPos(
    _hwnd: *mut c_void,
    _hwnd_insert_after: *mut c_void,
    _x: i32,
    _y: i32,
    _cx: i32,
    _cy: i32,
    _flags: u32,
) -> i32 {
    1
}

/// MoveWindow - moves and resizes a window. Returns TRUE (headless).
///
/// # Safety
/// No preconditions.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn user32_MoveWindow(
    _hwnd: *mut c_void,
    _x: i32,
    _y: i32,
    _w: i32,
    _h: i32,
    _repaint: i32,
) -> i32 {
    1
}

/// GetCursorPos - gets cursor position. Sets point to (0,0), returns TRUE.
///
/// # Safety
/// `point` if non-null must be writable for 2 i32 values (POINT structure).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn user32_GetCursorPos(point: *mut i32) -> i32 {
    if !point.is_null() {
        *point = 0;
        *point.add(1) = 0;
    }
    1
}

/// SetCursorPos - sets cursor position. Returns TRUE (headless).
///
/// # Safety
/// No preconditions.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn user32_SetCursorPos(_x: i32, _y: i32) -> i32 {
    1
}

/// ScreenToClient - converts screen coordinates to client coordinates. No-op, returns TRUE.
///
/// # Safety
/// `point` must be a valid pointer to a POINT structure if non-null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn user32_ScreenToClient(_hwnd: *mut c_void, _point: *mut i32) -> i32 {
    1
}

/// ClientToScreen - converts client coordinates to screen coordinates. No-op, returns TRUE.
///
/// # Safety
/// `point` must be a valid pointer to a POINT structure if non-null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn user32_ClientToScreen(_hwnd: *mut c_void, _point: *mut i32) -> i32 {
    1
}

/// ShowCursor - shows or hides the cursor. Returns 1 (cursor display count).
///
/// # Safety
/// No preconditions.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn user32_ShowCursor(_show: i32) -> i32 {
    1
}

/// GetFocus - returns the focused window handle. Always returns NULL (headless).
///
/// # Safety
/// No preconditions.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn user32_GetFocus() -> *mut c_void {
    core::ptr::null_mut()
}

/// SetFocus - sets focus to a window. Always returns NULL (headless).
///
/// # Safety
/// No preconditions.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn user32_SetFocus(_hwnd: *mut c_void) -> *mut c_void {
    core::ptr::null_mut()
}

// ── Phase 45: Dialog, menu, clipboard, drawing, capture, misc GUI ─────────────

/// `RegisterClassW` — non-Ex variant; equivalent to `RegisterClassExW` in our stub.
///
/// Returns a fake non-zero ATOM.
///
/// # Safety
/// `wndclass` must be a valid pointer or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn user32_RegisterClassW(_wndclass: *const c_void) -> u16 {
    FAKE_ATOM
}

/// `CreateWindowW` — non-Ex variant; delegates to the Ex variant with `ex_style = 0`.
///
/// Returns a fake non-null HWND.
///
/// # Safety
/// All pointer parameters must be valid or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn user32_CreateWindowW(
    class_name: *const u16,
    window_name: *const u16,
    style: u32,
    x: i32,
    y: i32,
    width: i32,
    height: i32,
    parent: *mut c_void,
    menu: *mut c_void,
    instance: *mut c_void,
    param: *mut c_void,
) -> *mut c_void {
    user32_CreateWindowExW(
        0,
        class_name,
        window_name,
        style,
        x,
        y,
        width,
        height,
        parent,
        menu,
        instance,
        param,
    )
}

/// `DialogBoxParamW` — create and display a modal dialog box.
///
/// In headless mode, the dialog is never shown; returns IDCANCEL (2).
///
/// # Safety
/// Pointer parameters must be valid or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn user32_DialogBoxParamW(
    _instance: *mut c_void,
    _template_name: *const u16,
    _parent: *mut c_void,
    _dialog_proc: *const c_void,
    _init_param: isize,
) -> isize {
    IDCANCEL as isize
}

/// `CreateDialogParamW` — create a modeless dialog box.
///
/// Returns a fake non-null HWND; the dialog is never shown in headless mode.
///
/// # Safety
/// Pointer parameters must be valid or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn user32_CreateDialogParamW(
    _instance: *mut c_void,
    _template_name: *const u16,
    _parent: *mut c_void,
    _dialog_proc: *const c_void,
    _init_param: isize,
) -> *mut c_void {
    FAKE_HWND as *mut c_void
}

/// `EndDialog` — destroy a modal dialog box.
///
/// Returns 1 (TRUE); the dialog was never created in headless mode.
///
/// # Safety
/// `hwnd` is not meaningfully dereferenced; always safe.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn user32_EndDialog(_hwnd: *mut c_void, _result: isize) -> i32 {
    1
}

/// `GetDlgItem` — retrieve a handle to a control in a dialog box.
///
/// Returns a fake non-null HWND for any control ID.
///
/// # Safety
/// `hwnd` is not meaningfully dereferenced; always safe.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn user32_GetDlgItem(_hwnd: *mut c_void, _id_dlg_item: i32) -> *mut c_void {
    FAKE_HWND as *mut c_void
}

/// `GetDlgItemTextW` — retrieve the text of a dialog control.
///
/// Writes an empty string and returns 0 (headless mode).
///
/// # Safety
/// `string` must be a valid buffer of at least `max_count` UTF-16 code units,
/// or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn user32_GetDlgItemTextW(
    _hwnd: *mut c_void,
    _id_dlg_item: i32,
    string: *mut u16,
    max_count: i32,
) -> u32 {
    if !string.is_null() && max_count > 0 {
        // SAFETY: caller guarantees `string` points to at least `max_count` u16s.
        string.write(0);
    }
    0
}

/// `SetDlgItemTextW` — set the text of a dialog control.
///
/// Returns 1 (TRUE); the operation is silently discarded in headless mode.
///
/// # Safety
/// `string` must be a valid null-terminated UTF-16 string or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn user32_SetDlgItemTextW(
    _hwnd: *mut c_void,
    _id_dlg_item: i32,
    _string: *const u16,
) -> i32 {
    1
}

/// `SendDlgItemMessageW` — send a message to a control in a dialog box.
///
/// Returns 0; all messages are silently discarded in headless mode.
///
/// # Safety
/// Parameters are not meaningfully dereferenced; always safe.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn user32_SendDlgItemMessageW(
    _hwnd: *mut c_void,
    _id_dlg_item: i32,
    _msg: u32,
    _wparam: usize,
    _lparam: isize,
) -> isize {
    0
}

/// `GetDlgItemInt` — retrieve an integer value from a dialog control.
///
/// Returns 0 and sets `*translated` to 0 in headless mode.
///
/// # Safety
/// `translated` must be a valid writable pointer or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn user32_GetDlgItemInt(
    _hwnd: *mut c_void,
    _id_dlg_item: i32,
    translated: *mut i32,
    _signed: i32,
) -> u32 {
    if !translated.is_null() {
        // SAFETY: caller guarantees `translated` is a valid pointer.
        translated.write(0);
    }
    0
}

/// `SetDlgItemInt` — set an integer value in a dialog control.
///
/// Returns 1 (TRUE); the operation is silently discarded in headless mode.
///
/// # Safety
/// `hwnd` is not meaningfully dereferenced; always safe.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn user32_SetDlgItemInt(
    _hwnd: *mut c_void,
    _id_dlg_item: i32,
    _value: u32,
    _signed: i32,
) -> i32 {
    1
}

/// `CheckDlgButton` — change the check state of a button in a dialog box.
///
/// Returns 1 (TRUE); the operation is silently discarded in headless mode.
///
/// # Safety
/// `hwnd` is not meaningfully dereferenced; always safe.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn user32_CheckDlgButton(
    _hwnd: *mut c_void,
    _id_button: i32,
    _check: u32,
) -> i32 {
    1
}

/// `IsDlgButtonChecked` — determine whether a dialog button is checked.
///
/// Returns 0 (BST_UNCHECKED) in headless mode.
///
/// # Safety
/// `hwnd` is not meaningfully dereferenced; always safe.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn user32_IsDlgButtonChecked(_hwnd: *mut c_void, _id_button: i32) -> u32 {
    0 // BST_UNCHECKED
}

/// `DrawTextW` — draw formatted text in the specified rectangle.
///
/// Returns 1 (non-zero line count); text is silently discarded in headless mode.
///
/// # Safety
/// Pointer parameters are not meaningfully dereferenced; always safe.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn user32_DrawTextW(
    _hdc: *mut c_void,
    _string: *const u16,
    _count: i32,
    _rect: *mut c_void,
    _format: u32,
) -> i32 {
    1
}

/// `DrawTextA` — draw formatted text (ANSI) in the specified rectangle.
///
/// Returns 1 (non-zero line count); text is silently discarded in headless mode.
///
/// # Safety
/// Pointer parameters are not meaningfully dereferenced; always safe.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn user32_DrawTextA(
    _hdc: *mut c_void,
    _string: *const u8,
    _count: i32,
    _rect: *mut c_void,
    _format: u32,
) -> i32 {
    1
}

/// `DrawTextExW` — draw formatted text with extended options.
///
/// Returns 1 (non-zero line count); text is silently discarded in headless mode.
///
/// # Safety
/// Pointer parameters are not meaningfully dereferenced; always safe.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn user32_DrawTextExW(
    _hdc: *mut c_void,
    _string: *mut u16,
    _count: i32,
    _rect: *mut c_void,
    _format: u32,
    _dtp: *mut c_void,
) -> i32 {
    1
}

/// `AdjustWindowRect` — calculate the required size of the window rectangle.
///
/// Leaves the rectangle unchanged (0-sized client area would be same as window);
/// returns 1 (TRUE).
///
/// # Safety
/// `rect` must be a valid 4-i32 buffer or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn user32_AdjustWindowRect(_rect: *mut i32, _style: u32, _menu: i32) -> i32 {
    1
}

/// `AdjustWindowRectEx` — calculate the required size of the window rectangle
/// including extended style.
///
/// Leaves the rectangle unchanged; returns 1 (TRUE).
///
/// # Safety
/// `rect` must be a valid 4-i32 buffer or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn user32_AdjustWindowRectEx(
    _rect: *mut i32,
    _style: u32,
    _menu: i32,
    _ex_style: u32,
) -> i32 {
    1
}

/// `SystemParametersInfoW` — query or set system-wide parameters.
///
/// Returns 1 (TRUE); parameters are not modified in headless mode.
///
/// # Safety
/// `pv_param` is not meaningfully dereferenced; always safe.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn user32_SystemParametersInfoW(
    _action: u32,
    _ui_param: u32,
    _pv_param: *mut c_void,
    _win_ini: u32,
) -> i32 {
    1
}

/// `SystemParametersInfoA` — ANSI variant of `SystemParametersInfoW`.
///
/// Returns 1 (TRUE); parameters are not modified in headless mode.
///
/// # Safety
/// `pv_param` is not meaningfully dereferenced; always safe.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn user32_SystemParametersInfoA(
    _action: u32,
    _ui_param: u32,
    _pv_param: *mut c_void,
    _win_ini: u32,
) -> i32 {
    1
}

/// `CreateMenu` — create a menu.
///
/// Returns a fake non-null HMENU in headless mode.
///
/// # Safety
/// No parameters; always safe.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn user32_CreateMenu() -> *mut c_void {
    FAKE_HMENU as *mut c_void
}

/// `CreatePopupMenu` — create a pop-up menu.
///
/// Returns a fake non-null HMENU in headless mode.
///
/// # Safety
/// No parameters; always safe.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn user32_CreatePopupMenu() -> *mut c_void {
    FAKE_HMENU as *mut c_void
}

/// `DestroyMenu` — destroy a menu.
///
/// Returns 1 (TRUE); no real menu to destroy in headless mode.
///
/// # Safety
/// `menu` is not meaningfully dereferenced; always safe.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn user32_DestroyMenu(_menu: *mut c_void) -> i32 {
    1
}

/// `AppendMenuW` — append a new item to a menu.
///
/// Returns 1 (TRUE); menu items are silently discarded in headless mode.
///
/// # Safety
/// Pointer parameters are not meaningfully dereferenced; always safe.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn user32_AppendMenuW(
    _menu: *mut c_void,
    _flags: u32,
    _id_new_item: usize,
    _new_item: *const u16,
) -> i32 {
    1
}

/// `InsertMenuItemW` — insert a new menu item.
///
/// Returns 1 (TRUE); menu items are silently discarded in headless mode.
///
/// # Safety
/// Pointer parameters are not meaningfully dereferenced; always safe.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn user32_InsertMenuItemW(
    _menu: *mut c_void,
    _item: u32,
    _by_position: i32,
    _mii: *const c_void,
) -> i32 {
    1
}

/// `GetMenu` — retrieve the handle of the menu assigned to the specified window.
///
/// Returns a fake non-null HMENU in headless mode.
///
/// # Safety
/// `hwnd` is not meaningfully dereferenced; always safe.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn user32_GetMenu(_hwnd: *mut c_void) -> *mut c_void {
    FAKE_HMENU as *mut c_void
}

/// `SetMenu` — assign a new menu to the specified window.
///
/// Returns 1 (TRUE); the operation is silently discarded in headless mode.
///
/// # Safety
/// Parameters are not meaningfully dereferenced; always safe.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn user32_SetMenu(_hwnd: *mut c_void, _menu: *mut c_void) -> i32 {
    1
}

/// `DrawMenuBar` — redraw the menu bar of the specified window.
///
/// Returns 1 (TRUE); no-op in headless mode.
///
/// # Safety
/// `hwnd` is not meaningfully dereferenced; always safe.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn user32_DrawMenuBar(_hwnd: *mut c_void) -> i32 {
    1
}

/// `TrackPopupMenu` — display a shortcut menu and track the selection.
///
/// Returns 0 (no item selected) in headless mode.
///
/// # Safety
/// Pointer parameters are not meaningfully dereferenced; always safe.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn user32_TrackPopupMenu(
    _menu: *mut c_void,
    _flags: u32,
    _x: i32,
    _y: i32,
    _reserved: i32,
    _hwnd: *mut c_void,
    _rect: *const c_void,
) -> i32 {
    0
}

/// `SetCapture` — capture the mouse and associate it with the specified window.
///
/// Returns a fake HWND (previous capture owner, none in headless mode).
///
/// # Safety
/// `hwnd` is not meaningfully dereferenced; always safe.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn user32_SetCapture(_hwnd: *mut c_void) -> *mut c_void {
    core::ptr::null_mut()
}

/// `ReleaseCapture` — release the mouse capture.
///
/// Returns 1 (TRUE); no-op in headless mode.
///
/// # Safety
/// No parameters; always safe.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn user32_ReleaseCapture() -> i32 {
    1
}

/// `GetCapture` — retrieve the handle to the window that has captured the mouse.
///
/// Returns null (no capture) in headless mode.
///
/// # Safety
/// No parameters; always safe.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn user32_GetCapture() -> *mut c_void {
    core::ptr::null_mut()
}

/// `TrackMouseEvent` — post messages when the mouse pointer leaves a window.
///
/// Returns 1 (TRUE); no-op in headless mode.
///
/// # Safety
/// `event_track` is not meaningfully dereferenced; always safe.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn user32_TrackMouseEvent(_event_track: *mut c_void) -> i32 {
    1
}

/// `RedrawWindow` — update the specified rectangle/region in a window's client area.
///
/// Returns 1 (TRUE); no-op in headless mode.
///
/// # Safety
/// Pointer parameters are not meaningfully dereferenced; always safe.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn user32_RedrawWindow(
    _hwnd: *mut c_void,
    _update_rect: *const c_void,
    _update_rgn: *mut c_void,
    _flags: u32,
) -> i32 {
    1
}

/// `OpenClipboard` — open the clipboard for examination or modification.
///
/// Returns 1 (TRUE); no-op in headless mode.
///
/// # Safety
/// `hwnd_new_owner` is not meaningfully dereferenced; always safe.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn user32_OpenClipboard(_hwnd_new_owner: *mut c_void) -> i32 {
    1
}

/// `CloseClipboard` — close the clipboard.
///
/// Returns 1 (TRUE); no-op in headless mode.
///
/// # Safety
/// No parameters; always safe.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn user32_CloseClipboard() -> i32 {
    1
}

/// `EmptyClipboard` — empty the clipboard and free handles to data.
///
/// Returns 1 (TRUE); no-op in headless mode.
///
/// # Safety
/// No parameters; always safe.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn user32_EmptyClipboard() -> i32 {
    1
}

/// `GetClipboardData` — retrieve data from the clipboard in a specified format.
///
/// Returns null (no clipboard data) in headless mode.
///
/// # Safety
/// No pointer parameters; always safe.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn user32_GetClipboardData(_format: u32) -> *mut c_void {
    core::ptr::null_mut()
}

/// `SetClipboardData` — place data on the clipboard in a specified format.
///
/// Returns `mem_handle`; the data is silently discarded in headless mode.
///
/// # Safety
/// `mem_handle` is not meaningfully dereferenced; always safe.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn user32_SetClipboardData(
    _format: u32,
    mem_handle: *mut c_void,
) -> *mut c_void {
    mem_handle
}

/// `LoadStringW` — load a string resource from an executable file.
///
/// Writes an empty string and returns 0 in headless mode (no resources).
///
/// # Safety
/// `buffer` must be a valid buffer of at least `n_buf_max` UTF-16 code units,
/// or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn user32_LoadStringW(
    _instance: *mut c_void,
    _uid: u32,
    buffer: *mut u16,
    n_buf_max: i32,
) -> i32 {
    if !buffer.is_null() && n_buf_max > 0 {
        // SAFETY: caller guarantees `buffer` is a valid buffer of `n_buf_max` u16s.
        buffer.write(0);
    }
    0
}

/// `LoadBitmapW` — load a bitmap resource from an executable file.
///
/// Returns null (no bitmap) in headless mode.
///
/// # Safety
/// Pointer parameters are not meaningfully dereferenced; always safe.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn user32_LoadBitmapW(
    _instance: *mut c_void,
    _bitmap_name: *const u16,
) -> *mut c_void {
    core::ptr::null_mut()
}

/// `LoadImageW` — load a bitmap, cursor, or icon resource.
///
/// Returns null (no image) in headless mode.
///
/// # Safety
/// Pointer parameters are not meaningfully dereferenced; always safe.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn user32_LoadImageW(
    _instance: *mut c_void,
    _name: *const u16,
    _type: u32,
    _cx: i32,
    _cy: i32,
    _load: u32,
) -> *mut c_void {
    core::ptr::null_mut()
}

/// `CallWindowProcW` — pass a message to the specified window procedure.
///
/// Returns 0; no real window procedure to call in headless mode.
///
/// # Safety
/// Pointer parameters are not meaningfully dereferenced; always safe.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn user32_CallWindowProcW(
    _prev_wnd_func: *const c_void,
    _hwnd: *mut c_void,
    _msg: u32,
    _wparam: usize,
    _lparam: isize,
) -> isize {
    0
}

/// `GetWindowInfo` — retrieve information about the specified window.
///
/// Returns 1 (TRUE) and zeroes the info structure in headless mode.
///
/// # Safety
/// `pwi` must be a valid writable pointer to at least 60 bytes (WINDOWINFO), or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn user32_GetWindowInfo(_hwnd: *mut c_void, pwi: *mut u8) -> i32 {
    if !pwi.is_null() {
        // WINDOWINFO is ~60 bytes; zero it out
        // SAFETY: caller guarantees `pwi` points to a WINDOWINFO structure.
        for i in 0..60 {
            pwi.add(i).write(0);
        }
    }
    1
}

/// `MapWindowPoints` — convert a set of points from one window's coordinate space
/// to another.
///
/// Returns 0; no-op in headless mode (no real coordinate spaces).
///
/// # Safety
/// `points` is not meaningfully dereferenced; always safe.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn user32_MapWindowPoints(
    _hwnd_from: *mut c_void,
    _hwnd_to: *mut c_void,
    _points: *mut c_void,
    _count: u32,
) -> i32 {
    0
}

/// `MonitorFromWindow` — retrieve the handle of the display monitor nearest to a window.
///
/// Returns a fake non-null HMONITOR in headless mode.
///
/// # Safety
/// `hwnd` is not meaningfully dereferenced; always safe.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn user32_MonitorFromWindow(_hwnd: *mut c_void, _flags: u32) -> *mut c_void {
    // Return a sentinel HMONITOR value
    core::ptr::dangling_mut::<c_void>()
}

/// `MonitorFromPoint` — retrieve the handle of the display monitor nearest to a point.
///
/// Returns a fake non-null HMONITOR in headless mode.
///
/// # Safety
/// No meaningful pointer parameters; always safe.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn user32_MonitorFromPoint(_x: i32, _y: i32, _flags: u32) -> *mut c_void {
    core::ptr::dangling_mut::<c_void>()
}

/// `GetMonitorInfoW` — retrieve information about a display monitor.
///
/// Fills a fake 800×600 monitor info and returns 1 (TRUE).
///
/// # Safety
/// `lpmi` must be a valid writable pointer to at least 40 bytes (MONITORINFO), or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn user32_GetMonitorInfoW(_monitor: *mut c_void, lpmi: *mut i32) -> i32 {
    if !lpmi.is_null() {
        // MONITORINFO layout (40 bytes):
        //   cbSize  (4 bytes) — already set by caller; leave
        //   rcMonitor: left, top, right, bottom  (16 bytes)
        //   rcWork:    left, top, right, bottom  (16 bytes)
        //   dwFlags   (4 bytes)
        // SAFETY: caller guarantees `lpmi` points to a MONITORINFO structure.
        lpmi.add(1).write(0); // rcMonitor.left
        lpmi.add(2).write(0); // rcMonitor.top
        lpmi.add(3).write(800); // rcMonitor.right
        lpmi.add(4).write(600); // rcMonitor.bottom
        lpmi.add(5).write(0); // rcWork.left
        lpmi.add(6).write(0); // rcWork.top
        lpmi.add(7).write(800); // rcWork.right
        lpmi.add(8).write(600); // rcWork.bottom
        lpmi.add(9).write(1); // dwFlags = MONITORINFOF_PRIMARY
    }
    1
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_message_box_null_returns_idok() {
        // SAFETY: null pointers are handled gracefully by wide_to_string
        let result = unsafe {
            user32_MessageBoxW(std::ptr::null_mut(), std::ptr::null(), std::ptr::null(), 0)
        };
        assert_eq!(result, IDOK);
    }

    #[test]
    fn test_message_box_with_text() {
        let text: Vec<u16> = "Hello\0".encode_utf16().collect();
        let caption: Vec<u16> = "Title\0".encode_utf16().collect();
        // SAFETY: text and caption are valid null-terminated UTF-16 strings
        let result =
            unsafe { user32_MessageBoxW(std::ptr::null_mut(), text.as_ptr(), caption.as_ptr(), 0) };
        assert_eq!(result, IDOK);
    }

    #[test]
    fn test_register_class_ex_returns_nonzero() {
        // SAFETY: null pointer is passed; the stub does not dereference it
        let atom = unsafe { user32_RegisterClassExW(std::ptr::null()) };
        assert_ne!(atom, 0);
    }

    #[test]
    fn test_create_window_returns_nonnull() {
        // SAFETY: all null pointers; stub does not dereference any of them
        let hwnd = unsafe {
            user32_CreateWindowExW(
                0,
                std::ptr::null(),
                std::ptr::null(),
                0,
                0,
                0,
                800,
                600,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        assert!(!hwnd.is_null());
    }

    #[test]
    fn test_show_window_returns_one() {
        // SAFETY: null HWND; stub does not dereference it
        let result = unsafe { user32_ShowWindow(std::ptr::null_mut(), 1) };
        assert_eq!(result, 1);
    }

    #[test]
    fn test_update_window_returns_one() {
        // SAFETY: null HWND; stub does not dereference it
        let result = unsafe { user32_UpdateWindow(std::ptr::null_mut()) };
        assert_eq!(result, 1);
    }

    #[test]
    fn test_get_message_returns_zero() {
        // SAFETY: all null pointers; stub does not dereference any of them
        let result =
            unsafe { user32_GetMessageW(std::ptr::null_mut(), std::ptr::null_mut(), 0, 0) };
        assert_eq!(result, 0);
    }

    #[test]
    fn test_translate_message_returns_zero() {
        // SAFETY: null pointer; stub does not dereference it
        let result = unsafe { user32_TranslateMessage(std::ptr::null()) };
        assert_eq!(result, 0);
    }

    #[test]
    fn test_dispatch_message_returns_zero() {
        // SAFETY: null pointer; stub does not dereference it
        let result = unsafe { user32_DispatchMessageW(std::ptr::null()) };
        assert_eq!(result, 0);
    }

    #[test]
    fn test_destroy_window_returns_one() {
        // SAFETY: null HWND; stub does not dereference it
        let result = unsafe { user32_DestroyWindow(std::ptr::null_mut()) };
        assert_eq!(result, 1);
    }

    #[test]
    fn test_post_quit_message_does_not_panic() {
        // SAFETY: pure integer argument; always safe.
        unsafe { user32_PostQuitMessage(0) };
    }

    #[test]
    fn test_def_window_proc_returns_zero() {
        // SAFETY: all parameters are integers/null; stub does not dereference.
        let result = unsafe { user32_DefWindowProcW(std::ptr::null_mut(), 0, 0, 0) };
        assert_eq!(result, 0);
    }

    #[test]
    fn test_load_cursor_returns_nonnull() {
        // SAFETY: null instance and null name; stub returns a fake handle.
        let hcursor = unsafe { user32_LoadCursorW(std::ptr::null_mut(), std::ptr::null()) };
        assert!(!hcursor.is_null());
    }

    #[test]
    fn test_load_icon_returns_nonnull() {
        // SAFETY: null instance and null name; stub returns a fake handle.
        let hicon = unsafe { user32_LoadIconW(std::ptr::null_mut(), std::ptr::null()) };
        assert!(!hicon.is_null());
    }

    #[test]
    fn test_get_system_metrics_screen_size() {
        // SM_CXSCREEN = 0, SM_CYSCREEN = 1
        let cx = unsafe { user32_GetSystemMetrics(0) };
        let cy = unsafe { user32_GetSystemMetrics(1) };
        assert_eq!(cx, 800);
        assert_eq!(cy, 600);
    }

    #[test]
    fn test_get_system_metrics_unknown_returns_zero() {
        let result = unsafe { user32_GetSystemMetrics(9999) };
        assert_eq!(result, 0);
    }

    #[test]
    fn test_set_window_long_ptr_returns_zero() {
        // SAFETY: null HWND; stub does not dereference it.
        let result = unsafe { user32_SetWindowLongPtrW(std::ptr::null_mut(), 0, 42) };
        assert_eq!(result, 0);
    }

    #[test]
    fn test_get_window_long_ptr_returns_zero() {
        // SAFETY: null HWND; stub does not dereference it.
        let result = unsafe { user32_GetWindowLongPtrW(std::ptr::null_mut(), 0) };
        assert_eq!(result, 0);
    }

    #[test]
    fn test_send_message_returns_zero() {
        // SAFETY: null HWND; stub does not dereference any param.
        let result = unsafe { user32_SendMessageW(std::ptr::null_mut(), 0, 0, 0) };
        assert_eq!(result, 0);
    }

    #[test]
    fn test_post_message_returns_one() {
        // SAFETY: null HWND; stub does not dereference any param.
        let result = unsafe { user32_PostMessageW(std::ptr::null_mut(), 0, 0, 0) };
        assert_eq!(result, 1);
    }

    #[test]
    fn test_peek_message_returns_zero() {
        // SAFETY: all null pointers; stub does not dereference any param.
        let result =
            unsafe { user32_PeekMessageW(std::ptr::null_mut(), std::ptr::null_mut(), 0, 0, 0) };
        assert_eq!(result, 0);
    }

    #[test]
    fn test_begin_paint_returns_fake_hdc() {
        // SAFETY: null paint_struct; BeginPaint guards with null check.
        let hdc = unsafe { user32_BeginPaint(std::ptr::null_mut(), std::ptr::null_mut()) };
        assert!(!hdc.is_null());
    }

    #[test]
    fn test_begin_paint_zeroes_paint_struct() {
        // SAFETY: paint_struct is a valid 100-byte buffer on the stack.
        let mut paint_struct = [0xFFu8; 100];
        let hdc = unsafe { user32_BeginPaint(std::ptr::null_mut(), paint_struct.as_mut_ptr()) };
        assert!(!hdc.is_null());
        assert!(paint_struct.iter().all(|&b| b == 0));
    }

    #[test]
    fn test_end_paint_returns_one() {
        // SAFETY: null parameters; stub does not dereference them.
        let result = unsafe { user32_EndPaint(std::ptr::null_mut(), std::ptr::null()) };
        assert_eq!(result, 1);
    }

    #[test]
    fn test_get_client_rect_fills_800x600() {
        // SAFETY: rect is a valid 4-i32 buffer.
        let mut rect = [0i32; 4];
        let result = unsafe { user32_GetClientRect(std::ptr::null_mut(), rect.as_mut_ptr()) };
        assert_eq!(result, 1);
        assert_eq!(rect[0], 0); // left
        assert_eq!(rect[1], 0); // top
        assert_eq!(rect[2], 800); // right
        assert_eq!(rect[3], 600); // bottom
    }

    #[test]
    fn test_get_client_rect_null_rect() {
        // SAFETY: null rect; GetClientRect guards with null check.
        let result = unsafe { user32_GetClientRect(std::ptr::null_mut(), std::ptr::null_mut()) };
        assert_eq!(result, 1);
    }

    #[test]
    fn test_invalidate_rect_returns_one() {
        // SAFETY: null parameters; stub does not dereference them.
        let result = unsafe { user32_InvalidateRect(std::ptr::null_mut(), std::ptr::null(), 0) };
        assert_eq!(result, 1);
    }

    #[test]
    fn test_set_timer_returns_zero() {
        // SAFETY: null parameters; stub does not dereference them.
        let result = unsafe { user32_SetTimer(std::ptr::null_mut(), 1, 1000, std::ptr::null()) };
        assert_eq!(result, 0);
    }

    #[test]
    fn test_kill_timer_returns_one() {
        // SAFETY: null HWND; stub does not dereference it.
        let result = unsafe { user32_KillTimer(std::ptr::null_mut(), 1) };
        assert_eq!(result, 1);
    }

    #[test]
    fn test_get_dc_returns_nonnull() {
        // SAFETY: null HWND; stub returns a fake HDC.
        let hdc = unsafe { user32_GetDC(std::ptr::null_mut()) };
        assert!(!hdc.is_null());
    }

    #[test]
    fn test_release_dc_returns_one() {
        // SAFETY: null parameters; stub does not dereference them.
        let result = unsafe { user32_ReleaseDC(std::ptr::null_mut(), std::ptr::null_mut()) };
        assert_eq!(result, 1);
    }

    // ── Phase 27 tests ────────────────────────────────────────────────────
    #[test]
    fn test_char_upper_w_string() {
        let mut s: Vec<u16> = "hello\0".encode_utf16().collect();
        let result = unsafe { user32_CharUpperW(s.as_mut_ptr()) };
        assert!(!result.is_null());
        let upper: String = s
            .iter()
            .take_while(|&&c| c != 0)
            .map(|&c| char::from_u32(u32::from(c)).unwrap_or('?'))
            .collect();
        assert_eq!(upper, "HELLO");
    }

    #[test]
    fn test_char_upper_w_char() {
        let result = unsafe { user32_CharUpperW(u32::from(b'a') as usize as *mut u16) };
        assert_eq!(result as usize, u32::from(b'A') as usize);
    }

    #[test]
    fn test_char_lower_w_char() {
        let result = unsafe { user32_CharLowerW(u32::from(b'Z') as usize as *mut u16) };
        assert_eq!(result as usize, u32::from(b'z') as usize);
    }

    #[test]
    fn test_char_lower_w_string() {
        let mut s: Vec<u16> = "WORLD\0".encode_utf16().collect();
        let result = unsafe { user32_CharLowerW(s.as_mut_ptr()) };
        assert!(!result.is_null());
        let lower: String = s
            .iter()
            .take_while(|&&c| c != 0)
            .map(|&c| char::from_u32(u32::from(c)).unwrap_or('?'))
            .collect();
        assert_eq!(lower, "world");
    }

    #[test]
    fn test_is_char_alpha_w() {
        assert_eq!(unsafe { user32_IsCharAlphaW(u16::from(b'A')) }, 1);
        assert_eq!(unsafe { user32_IsCharAlphaW(u16::from(b'0')) }, 0);
        assert_eq!(unsafe { user32_IsCharAlphaW(u16::from(b'!')) }, 0);
    }

    #[test]
    fn test_is_char_alpha_numeric_w() {
        assert_eq!(unsafe { user32_IsCharAlphaNumericW(u16::from(b'A')) }, 1);
        assert_eq!(unsafe { user32_IsCharAlphaNumericW(u16::from(b'5')) }, 1);
        assert_eq!(unsafe { user32_IsCharAlphaNumericW(u16::from(b'!')) }, 0);
    }

    #[test]
    fn test_is_char_upper_lower_w() {
        assert_eq!(unsafe { user32_IsCharUpperW(u16::from(b'A')) }, 1);
        assert_eq!(unsafe { user32_IsCharUpperW(u16::from(b'a')) }, 0);
        assert_eq!(unsafe { user32_IsCharLowerW(u16::from(b'a')) }, 1);
        assert_eq!(unsafe { user32_IsCharLowerW(u16::from(b'A')) }, 0);
    }

    #[test]
    fn test_headless_window_utilities() {
        let fake_hwnd = 0x1234usize as *mut core::ffi::c_void;
        assert_eq!(unsafe { user32_IsWindow(fake_hwnd) }, 0);
        assert_eq!(unsafe { user32_IsWindowEnabled(fake_hwnd) }, 0);
        assert_eq!(unsafe { user32_IsWindowVisible(fake_hwnd) }, 0);
        assert_eq!(unsafe { user32_EnableWindow(fake_hwnd, 1) }, 0);
        assert_eq!(
            unsafe { user32_SetWindowTextW(fake_hwnd, core::ptr::null()) },
            0
        );
        assert!(unsafe { user32_GetParent(fake_hwnd) }.is_null());
    }

    #[test]
    fn test_get_window_text_w_empty() {
        let fake_hwnd = 0x1234usize as *mut core::ffi::c_void;
        let mut buf = vec![0u16; 64];
        let result = unsafe { user32_GetWindowTextW(fake_hwnd, buf.as_mut_ptr(), 64) };
        assert_eq!(result, 0);
        assert_eq!(buf[0], 0, "Buffer should be null-terminated");
    }

    #[test]
    fn test_window_stubs_phase28() {
        unsafe {
            let null = core::ptr::null_mut::<c_void>();
            assert!(user32_FindWindowW(null, null).is_null());
            assert!(user32_FindWindowExW(null, null, null, null).is_null());
            assert!(user32_GetForegroundWindow().is_null());
            assert_eq!(user32_SetForegroundWindow(null), 0);
            assert_eq!(user32_BringWindowToTop(null), 0);
            let mut rect = [1i32; 4];
            assert_eq!(user32_GetWindowRect(null, rect.as_mut_ptr()), 1);
            assert_eq!(rect, [0i32; 4]);
            assert_eq!(user32_SetWindowPos(null, null, 0, 0, 100, 100, 0), 1);
            assert_eq!(user32_MoveWindow(null, 0, 0, 100, 100, 0), 1);
            let mut pt = [5i32, 10i32];
            assert_eq!(user32_GetCursorPos(pt.as_mut_ptr()), 1);
            assert_eq!(pt, [0i32, 0i32]);
            assert_eq!(user32_SetCursorPos(100, 200), 1);
            assert_eq!(user32_ScreenToClient(null, pt.as_mut_ptr()), 1);
            assert_eq!(user32_ClientToScreen(null, pt.as_mut_ptr()), 1);
            assert_eq!(user32_ShowCursor(1), 1);
            assert!(user32_GetFocus().is_null());
            assert!(user32_SetFocus(null).is_null());
        }
    }

    // ── Phase 45 tests ────────────────────────────────────────────────────
    #[test]
    fn test_register_class_w_returns_nonzero() {
        // SAFETY: null pointer; stub does not dereference it.
        let atom = unsafe { user32_RegisterClassW(std::ptr::null()) };
        assert_ne!(atom, 0);
    }

    #[test]
    fn test_create_window_w_returns_nonnull() {
        // SAFETY: null pointer parameters; stub does not dereference them.
        let hwnd = unsafe {
            user32_CreateWindowW(
                std::ptr::null(),
                std::ptr::null(),
                0,
                0,
                0,
                800,
                600,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        assert!(!hwnd.is_null());
    }

    #[test]
    fn test_dialog_box_param_returns_idcancel() {
        // SAFETY: all null/zero parameters; stub does not dereference them.
        let result = unsafe {
            user32_DialogBoxParamW(
                std::ptr::null_mut(),
                std::ptr::null(),
                std::ptr::null_mut(),
                std::ptr::null(),
                0,
            )
        };
        assert_eq!(result, IDCANCEL as isize);
    }

    #[test]
    fn test_create_dialog_param_returns_nonnull() {
        // SAFETY: null parameters; stub does not dereference them.
        let hwnd = unsafe {
            user32_CreateDialogParamW(
                std::ptr::null_mut(),
                std::ptr::null(),
                std::ptr::null_mut(),
                std::ptr::null(),
                0,
            )
        };
        assert!(!hwnd.is_null());
    }

    #[test]
    fn test_end_dialog_returns_one() {
        // SAFETY: null HWND; stub does not dereference it.
        let result = unsafe { user32_EndDialog(std::ptr::null_mut(), 0) };
        assert_eq!(result, 1);
    }

    #[test]
    fn test_get_dlg_item_returns_nonnull() {
        // SAFETY: null HWND; stub returns a fake HWND.
        let hwnd = unsafe { user32_GetDlgItem(std::ptr::null_mut(), 1001) };
        assert!(!hwnd.is_null());
    }

    #[test]
    fn test_get_dlg_item_text_writes_empty_string() {
        let mut buf = vec![0xFFu16; 64];
        // SAFETY: valid buffer of 64 u16s.
        let result =
            unsafe { user32_GetDlgItemTextW(std::ptr::null_mut(), 1, buf.as_mut_ptr(), 64) };
        assert_eq!(result, 0);
        assert_eq!(buf[0], 0, "should write null terminator");
    }

    #[test]
    fn test_set_dlg_item_text_returns_one() {
        // SAFETY: null parameters; stub does not dereference them.
        let result = unsafe { user32_SetDlgItemTextW(std::ptr::null_mut(), 1, std::ptr::null()) };
        assert_eq!(result, 1);
    }

    #[test]
    fn test_check_dlg_button_returns_one() {
        // SAFETY: null HWND; stub does not dereference it.
        let result = unsafe { user32_CheckDlgButton(std::ptr::null_mut(), 1, 1) };
        assert_eq!(result, 1);
    }

    #[test]
    fn test_is_dlg_button_checked_returns_zero() {
        // SAFETY: null HWND; stub does not dereference it.
        let result = unsafe { user32_IsDlgButtonChecked(std::ptr::null_mut(), 1) };
        assert_eq!(result, 0);
    }

    #[test]
    fn test_draw_text_returns_one() {
        // SAFETY: null parameters; stub does not dereference them.
        let result = unsafe {
            user32_DrawTextW(
                std::ptr::null_mut(),
                std::ptr::null(),
                0,
                std::ptr::null_mut(),
                0,
            )
        };
        assert_eq!(result, 1);
    }

    #[test]
    fn test_adjust_window_rect_ext_returns_one() {
        let mut rect = [0i32; 4];
        // SAFETY: valid 4-i32 buffer.
        let result = unsafe { user32_AdjustWindowRectEx(rect.as_mut_ptr(), 0, 0, 0) };
        assert_eq!(result, 1);
    }

    #[test]
    fn test_menu_apis() {
        unsafe {
            let hmenu = user32_CreateMenu();
            assert!(!hmenu.is_null());
            let popup = user32_CreatePopupMenu();
            assert!(!popup.is_null());
            assert_eq!(user32_AppendMenuW(hmenu, 0, 0, std::ptr::null()), 1);
            assert_eq!(user32_DestroyMenu(hmenu), 1);
            let null = std::ptr::null_mut::<c_void>();
            assert!(!user32_GetMenu(null).is_null());
            assert_eq!(user32_SetMenu(null, null), 1);
            assert_eq!(user32_DrawMenuBar(null), 1);
        }
    }

    #[test]
    fn test_mouse_capture_apis() {
        unsafe {
            let null = std::ptr::null_mut::<c_void>();
            assert!(user32_SetCapture(null).is_null());
            assert_eq!(user32_ReleaseCapture(), 1);
            assert!(user32_GetCapture().is_null());
        }
    }

    #[test]
    fn test_clipboard_apis() {
        unsafe {
            assert_eq!(user32_OpenClipboard(std::ptr::null_mut()), 1);
            assert_eq!(user32_EmptyClipboard(), 1);
            assert!(user32_GetClipboardData(1).is_null()); // CF_TEXT
            assert_eq!(user32_CloseClipboard(), 1);
        }
    }

    #[test]
    fn test_load_string_w_writes_empty_string() {
        let mut buf = vec![0xFFu16; 32];
        // SAFETY: valid buffer of 32 u16s.
        let result = unsafe { user32_LoadStringW(std::ptr::null_mut(), 1, buf.as_mut_ptr(), 32) };
        assert_eq!(result, 0);
        assert_eq!(buf[0], 0, "should write null terminator");
    }

    #[test]
    fn test_monitor_apis() {
        unsafe {
            let null = std::ptr::null_mut::<c_void>();
            assert!(!user32_MonitorFromWindow(null, 0).is_null());
            // MONITORINFO: cbSize (4) + rcMonitor (16) + rcWork (16) + dwFlags (4) = 40 bytes = 10 i32s
            let mut mi = [0i32; 10];
            assert_eq!(user32_GetMonitorInfoW(null, mi.as_mut_ptr()), 1);
            assert_eq!(mi[3], 800); // rcMonitor.right
            assert_eq!(mi[4], 600); // rcMonitor.bottom
        }
    }
}
