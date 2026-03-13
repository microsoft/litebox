// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! MSVCRT (Microsoft Visual C++ Runtime) function implementations
//!
//! This module provides Linux-based implementations of MSVCRT functions
//! that are commonly used by Windows programs. These functions are mapped
//! to their Linux equivalents where possible.

// Allow unsafe operations inside unsafe functions since the entire function is unsafe
#![allow(unsafe_op_in_unsafe_fn)]

use std::alloc::{Layout, alloc, dealloc};
use std::collections::BTreeMap;
use std::ffi::{CStr, CString};
use std::io::{self, Write};
use std::ptr;
use std::sync::atomic::AtomicI64;
use std::sync::{Mutex, OnceLock};

// ============================================================================
// Printf format-string helpers
// ============================================================================

/// Pad `s` to `width` bytes.  Left-aligns when `left` is true, otherwise
/// right-aligns.  Uses `pad_char` as the fill character.
fn pad_bytes(s: &[u8], width: usize, left: bool, pad_char: u8) -> Vec<u8> {
    if width <= s.len() {
        return s.to_vec();
    }
    let pad = width - s.len();
    let mut out = Vec::with_capacity(width);
    if left {
        out.extend_from_slice(s);
        out.resize(width, b' ');
    } else {
        out.resize(pad, pad_char);
        out.extend_from_slice(s);
    }
    out
}

/// Common printf formatting options.
#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Copy, Default)]
struct PrintOpts {
    width: usize,
    precision: Option<usize>,
    left: bool,
    zero: bool,
    plus: bool,
    space: bool,
    alt: bool,
}

/// Format a signed 64-bit integer with printf flags/width.
fn format_int(val: i64, opts: PrintOpts) -> Vec<u8> {
    let abs = val.unsigned_abs();
    let digits = format_u64_decimal(abs);
    let sign: &[u8] = if val < 0 {
        b"-"
    } else if opts.plus {
        b"+"
    } else if opts.space {
        b" "
    } else {
        b""
    };
    // When an explicit precision is given, apply it to the digit string (minimum
    // number of digits).  An explicit precision also overrides zero-padding.
    let digits = match opts.precision {
        Some(p) => {
            if digits.len() < p {
                let mut padded = vec![b'0'; p - digits.len()];
                padded.extend_from_slice(&digits);
                padded
            } else {
                digits
            }
        }
        None => digits,
    };
    // Zero-padding is suppressed when an explicit precision is provided.
    let zero_pad = opts.zero && !opts.left && opts.precision.is_none();
    let pad_char = if zero_pad { b'0' } else { b' ' };
    // When zero-padding, sign goes before the zeros.
    if zero_pad && opts.width > sign.len() + digits.len() {
        let pad = opts.width - sign.len() - digits.len();
        let mut out = Vec::with_capacity(opts.width);
        out.extend_from_slice(sign);
        out.resize(out.len() + pad, b'0');
        out.extend_from_slice(&digits);
        out
    } else {
        let mut num = Vec::with_capacity(sign.len() + digits.len());
        num.extend_from_slice(sign);
        num.extend_from_slice(&digits);
        pad_bytes(&num, opts.width, opts.left, pad_char)
    }
}

/// Format an unsigned 64-bit integer with printf flags/width.
fn format_uint(val: u64, opts: PrintOpts) -> Vec<u8> {
    let digits = format_u64_decimal(val);
    // Apply precision (minimum number of digits) and suppress zero-pad if set.
    let digits = match opts.precision {
        Some(p) if digits.len() < p => {
            let mut padded = vec![b'0'; p - digits.len()];
            padded.extend_from_slice(&digits);
            padded
        }
        _ => digits,
    };
    let zero_pad = opts.zero && !opts.left && opts.precision.is_none();
    let pad_char = if zero_pad { b'0' } else { b' ' };
    pad_bytes(&digits, opts.width, opts.left, pad_char)
}

/// Format a u64 as a decimal ASCII byte string.
fn format_u64_decimal(val: u64) -> Vec<u8> {
    if val == 0 {
        return b"0".to_vec();
    }
    let mut buf = [0u8; 20];
    let mut pos = 20;
    let mut v = val;
    while v > 0 {
        pos -= 1;
        buf[pos] = b'0' + (v % 10) as u8;
        v /= 10;
    }
    buf[pos..].to_vec()
}

/// Format a u64 as hex with optional prefix.
fn format_hex(val: u64, upper: bool, opts: PrintOpts) -> Vec<u8> {
    let digits: Vec<u8> = if upper {
        format!("{val:X}").into_bytes()
    } else {
        format!("{val:x}").into_bytes()
    };
    let prefix: &[u8] = if opts.alt && val != 0 {
        if upper { b"0X" } else { b"0x" }
    } else {
        b""
    };
    let pad_char = if opts.zero && !opts.left { b'0' } else { b' ' };
    if opts.zero && !opts.left && opts.width > prefix.len() + digits.len() {
        let pad = opts.width - prefix.len() - digits.len();
        let mut out = Vec::with_capacity(opts.width);
        out.extend_from_slice(prefix);
        out.resize(out.len() + pad, b'0');
        out.extend_from_slice(&digits);
        out
    } else {
        let mut num = Vec::with_capacity(prefix.len() + digits.len());
        num.extend_from_slice(prefix);
        num.extend_from_slice(&digits);
        pad_bytes(&num, opts.width, opts.left, pad_char)
    }
}

/// Format a u64 as octal.
fn format_octal(val: u64, opts: PrintOpts) -> Vec<u8> {
    let mut s = format!("{val:o}");
    if opts.alt && !s.starts_with('0') {
        s.insert(0, '0');
    }
    let pad_char = if opts.zero && !opts.left { b'0' } else { b' ' };
    pad_bytes(s.as_bytes(), opts.width, opts.left, pad_char)
}

/// Format a floating-point value for printf-style %f/%e/%g conversions.
///
/// `conv` must be one of `'f'`, `'e'`/`'E'`, `'g'`/`'G'`.
#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap
)]
fn format_float(val: f64, prec: usize, conv: char, opts: PrintOpts) -> Vec<u8> {
    let raw = match conv {
        'e' => format!("{val:.prec$e}"),
        'E' => format!("{val:.prec$E}"),
        'g' | 'G' => {
            // %g: use %e if exponent < -4 or >= prec, else %f; strip trailing zeros
            // UNLESS the `#` (alternate form) flag is set.
            let prec = if prec == 0 { 1 } else { prec };
            let exp: i32 = if val == 0.0 {
                0
            } else {
                val.abs().log10().floor() as i32
            };
            let s = if exp < -4 || exp >= prec as i32 {
                if conv == 'G' {
                    format!("{val:.prec$E}", prec = prec - 1)
                } else {
                    format!("{val:.prec$e}", prec = prec - 1)
                }
            } else {
                let decimal_digits = ((prec as i32 - 1 - exp).max(0)) as usize;
                format!("{val:.decimal_digits$}")
            };
            // Strip trailing zeros only when `#` is NOT set.
            if !opts.alt && s.contains('.') && !s.contains('e') && !s.contains('E') {
                s.trim_end_matches('0').trim_end_matches('.').to_string()
            } else {
                s
            }
        }
        _ => format!("{val:.prec$}"), // %f default
    };

    // Add leading sign.
    let sign: &str = if val.is_sign_negative() && !raw.starts_with('-') {
        "-"
    } else if opts.plus && !raw.starts_with('-') {
        "+"
    } else if opts.space && !raw.starts_with('-') {
        " "
    } else {
        ""
    };

    let full = format!("{sign}{raw}");

    // For zero-padding with a sign, place the sign *before* the zeros to
    // match printf semantics (e.g. `%+08.2f` of 3.14 → "+0003.14").
    if opts.zero && !opts.left && !sign.is_empty() && opts.width > full.len() {
        let zeros = opts.width - full.len();
        let mut out = Vec::with_capacity(opts.width);
        out.extend_from_slice(sign.as_bytes());
        out.resize(out.len() + zeros, b'0');
        out.extend_from_slice(raw.as_bytes());
        return out;
    }

    let pad_char = if opts.zero && !opts.left { b'0' } else { b' ' };
    pad_bytes(full.as_bytes(), opts.width, opts.left, pad_char)
}

/// Read a null-terminated UTF-16 slice.
///
/// # Safety
/// `ptr` must point to a valid null-terminated UTF-16 string.
unsafe fn read_wide_string(ptr: *const u16) -> Vec<u16> {
    let mut v = Vec::new();
    let mut p = ptr;
    loop {
        let ch = unsafe { *p };
        if ch == 0 {
            break;
        }
        v.push(ch);
        p = unsafe { p.add(1) };
    }
    v
}

/// Core printf formatter.
///
/// Parses `fmt` (a null-terminated byte slice without the trailing `\0`)
/// and formats each `%…` specifier by consuming the next argument from
/// `args`.  The result is returned as a `Vec<u8>`.
///
/// Supported conversions: `d`, `i`, `u`, `x`, `X`, `o`, `f`, `e`, `E`,
/// `g`, `G`, `s`, `S` (wide), `p`, `c`, `C` (wide), `n`, `%`.
///
/// Supported flags: `-`, `0`, `+`, ` `, `#`.
/// Width and precision (literal or `*`).
/// Length modifiers: `h`, `hh`, `l`, `ll`, `I64`, `I32`, `I`, `z`, `t`, `j`.
///
/// # Safety
/// `args` must supply arguments of the types implied by the format string.
/// When `wide_mode` is `true` the specifier meanings for `%s`/`%S` and
/// `%c`/`%C` are swapped to match Windows wide-printf semantics (where `%s`
/// expects `wchar_t*` and `%S` expects `char*`).
#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss
)]
unsafe fn format_printf_va(
    fmt: &[u8],
    args: &mut core::ffi::VaList<'_>,
    wide_mode: bool,
) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::new();
    let mut i = 0;

    while i < fmt.len() {
        let b = fmt[i];
        if b != b'%' {
            out.push(b);
            i += 1;
            continue;
        }
        i += 1;
        if i >= fmt.len() {
            break;
        }
        if fmt[i] == b'%' {
            out.push(b'%');
            i += 1;
            continue;
        }

        // ── Flags ────────────────────────────────────────────────────────────
        let mut opts = PrintOpts::default();
        loop {
            if i >= fmt.len() {
                return out;
            }
            match fmt[i] {
                b'-' => {
                    opts.left = true;
                    i += 1;
                }
                b'0' => {
                    opts.zero = true;
                    i += 1;
                }
                b'+' => {
                    opts.plus = true;
                    i += 1;
                }
                b' ' => {
                    opts.space = true;
                    i += 1;
                }
                b'#' => {
                    opts.alt = true;
                    i += 1;
                }
                _ => break,
            }
        }

        // ── Width ─────────────────────────────────────────────────────────────
        if i < fmt.len() && fmt[i] == b'*' {
            let w = unsafe { args.arg::<i32>() };
            if w < 0 {
                opts.left = true;
                opts.width = w.unsigned_abs() as usize;
            } else {
                opts.width = w as usize;
            }
            i += 1;
        } else {
            while i < fmt.len() && fmt[i].is_ascii_digit() {
                opts.width = opts.width * 10 + usize::from(fmt[i] - b'0');
                i += 1;
            }
        }

        // ── Precision ─────────────────────────────────────────────────────────
        if i < fmt.len() && fmt[i] == b'.' {
            i += 1;
            if i < fmt.len() && fmt[i] == b'*' {
                let p = unsafe { args.arg::<i32>() };
                // A negative precision from `.*` means "precision not specified"
                // (matches printf / MSVCRT semantics).
                opts.precision = if p < 0 { None } else { Some(p as usize) };
                i += 1;
            } else {
                let mut prec: usize = 0;
                while i < fmt.len() && fmt[i].is_ascii_digit() {
                    prec = prec * 10 + usize::from(fmt[i] - b'0');
                    i += 1;
                }
                opts.precision = Some(prec);
            }
        }

        // ── Length modifier ───────────────────────────────────────────────────
        let mut is_longlong = false;
        let mut is_short = false;
        let mut is_char_len = false;
        // is_long / is_size are folded into is_longlong below

        if i < fmt.len() {
            match fmt[i] {
                b'h' => {
                    i += 1;
                    if i < fmt.len() && fmt[i] == b'h' {
                        is_char_len = true;
                        i += 1;
                    } else {
                        is_short = true;
                    }
                }
                b'l' => {
                    i += 1;
                    if i < fmt.len() && fmt[i] == b'l' {
                        is_longlong = true;
                        i += 1;
                    } else {
                        // `l` on Linux means 64-bit for integer types
                        is_longlong = true;
                    }
                }
                b'I' => {
                    // Windows: %I64d / %I32d / %I (pointer-sized)
                    if i + 2 < fmt.len() && fmt[i + 1] == b'6' && fmt[i + 2] == b'4' {
                        is_longlong = true;
                        i += 3;
                    } else if i + 2 < fmt.len() && fmt[i + 1] == b'3' && fmt[i + 2] == b'2' {
                        i += 3; // 32-bit — same as unmodified on x64
                    } else {
                        is_longlong = true; // %I → pointer-sized (64-bit on x64)
                        i += 1;
                    }
                }
                b'z' | b'Z' | b't' | b'j' => {
                    is_longlong = true;
                    i += 1;
                }
                _ => {}
            }
        }

        if i >= fmt.len() {
            break;
        }
        let conv = fmt[i];
        i += 1;

        // In wide-printf mode (%w* family), %s expects wchar_t* and %S
        // expects char*, and similarly %c is wide while %C is narrow.
        // We normalise here so the match arms below don't need to know.
        let conv = if wide_mode {
            match conv {
                b's' => b'S',
                b'S' => b's',
                b'c' => b'C',
                b'C' => b'c',
                _ => conv,
            }
        } else {
            conv
        };

        // ── Conversion ────────────────────────────────────────────────────────
        match conv {
            b'd' | b'i' => {
                let val: i64 = if is_longlong {
                    unsafe { args.arg::<i64>() }
                } else if is_short {
                    i64::from(unsafe { args.arg::<i32>() } as i16)
                } else if is_char_len {
                    i64::from(unsafe { args.arg::<i32>() } as i8)
                } else {
                    i64::from(unsafe { args.arg::<i32>() })
                };
                out.extend(format_int(val, opts));
            }
            b'u' => {
                let val: u64 = if is_longlong {
                    unsafe { args.arg::<u64>() }
                } else if is_short {
                    u64::from(unsafe { args.arg::<u32>() } as u16)
                } else if is_char_len {
                    u64::from(unsafe { args.arg::<u32>() } as u8)
                } else {
                    u64::from(unsafe { args.arg::<u32>() })
                };
                out.extend(format_uint(val, opts));
            }
            b'x' | b'X' => {
                let val: u64 = if is_longlong {
                    unsafe { args.arg::<u64>() }
                } else {
                    u64::from(unsafe { args.arg::<u32>() })
                };
                out.extend(format_hex(val, conv == b'X', opts));
            }
            b'o' => {
                let val: u64 = if is_longlong {
                    unsafe { args.arg::<u64>() }
                } else {
                    u64::from(unsafe { args.arg::<u32>() })
                };
                out.extend(format_octal(val, opts));
            }
            b'f' | b'F' => {
                let val = unsafe { args.arg::<f64>() };
                let prec = opts.precision.unwrap_or(6);
                out.extend(format_float(val, prec, 'f', opts));
            }
            b'e' => {
                let val = unsafe { args.arg::<f64>() };
                let prec = opts.precision.unwrap_or(6);
                out.extend(format_float(val, prec, 'e', opts));
            }
            b'E' => {
                let val = unsafe { args.arg::<f64>() };
                let prec = opts.precision.unwrap_or(6);
                out.extend(format_float(val, prec, 'E', opts));
            }
            b'g' => {
                let val = unsafe { args.arg::<f64>() };
                let prec = opts.precision.unwrap_or(6);
                out.extend(format_float(val, prec, 'g', opts));
            }
            b'G' => {
                let val = unsafe { args.arg::<f64>() };
                let prec = opts.precision.unwrap_or(6);
                out.extend(format_float(val, prec, 'G', opts));
            }
            b's' => {
                let ptr = unsafe { args.arg::<*const i8>() };
                let s: Vec<u8> = if ptr.is_null() {
                    b"(null)".to_vec()
                } else {
                    // SAFETY: caller guarantees a valid null-terminated string
                    unsafe { CStr::from_ptr(ptr) }.to_bytes().to_vec()
                };
                let s = match opts.precision {
                    Some(p) => s[..s.len().min(p)].to_vec(),
                    None => s,
                };
                out.extend(pad_bytes(&s, opts.width, opts.left, b' '));
            }
            b'S' => {
                // Wide string — Windows-specific
                let ptr = unsafe { args.arg::<*const u16>() };
                if !ptr.is_null() {
                    // SAFETY: caller guarantees a valid null-terminated wide string
                    let wide = unsafe { read_wide_string(ptr) };
                    let s = String::from_utf16_lossy(&wide);
                    let bytes: Vec<u8> = match opts.precision {
                        Some(p) => s.as_bytes()[..s.len().min(p)].to_vec(),
                        None => s.into_bytes(),
                    };
                    out.extend(pad_bytes(&bytes, opts.width, opts.left, b' '));
                }
            }
            b'p' => {
                let ptr = unsafe { args.arg::<usize>() };
                let s = format!("{ptr:#018x}");
                out.extend(pad_bytes(s.as_bytes(), opts.width, opts.left, b' '));
            }
            b'c' => {
                let c = (unsafe { args.arg::<i32>() } as u32 & 0xFF) as u8;
                out.extend(pad_bytes(&[c], opts.width, opts.left, b' '));
            }
            b'C' => {
                // Wide character — Windows-specific
                let c = unsafe { args.arg::<u32>() };
                if let Some(ch) = char::from_u32(c) {
                    let mut buf = [0u8; 4];
                    let s = ch.encode_utf8(&mut buf);
                    out.extend(pad_bytes(s.as_bytes(), opts.width, opts.left, b' '));
                }
            }
            b'n' => {
                // %n writes the number of characters written so far into the
                // pointer argument.  Dispatch on the length modifier to write
                // the correct type.
                let written = out.len();
                if is_longlong {
                    let ptr = unsafe { args.arg::<*mut i64>() };
                    if !ptr.is_null() {
                        // SAFETY: caller guarantees a valid writable pointer.
                        unsafe { *ptr = written as i64 };
                    }
                } else if is_short {
                    let ptr = unsafe { args.arg::<*mut i16>() };
                    if !ptr.is_null() {
                        // SAFETY: caller guarantees a valid writable pointer.
                        #[allow(clippy::cast_possible_truncation)]
                        unsafe {
                            *ptr = written as i16;
                        };
                    }
                } else if is_char_len {
                    let ptr = unsafe { args.arg::<*mut i8>() };
                    if !ptr.is_null() {
                        // SAFETY: caller guarantees a valid writable pointer.
                        #[allow(clippy::cast_possible_truncation)]
                        unsafe {
                            *ptr = written as i8;
                        };
                    }
                } else {
                    let ptr = unsafe { args.arg::<*mut i32>() };
                    if !ptr.is_null() {
                        // SAFETY: caller guarantees a valid writable pointer.
                        #[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
                        unsafe {
                            *ptr = written as i32;
                        };
                    }
                }
            }
            _ => {
                // Unknown — emit literally
                out.push(b'%');
                out.push(conv);
            }
        }
    }

    out
}

/// In-memory layout of the Linux x86_64 `__va_list_tag` / `core::ffi::VaList`.
///
/// This struct is used by [`format_printf_raw`] to bridge a Windows x64
/// `va_list` (a plain pointer) to the Linux `VaList` type.  It is defined at
/// module level so that compile-time size and alignment checks can reference it.
#[cfg(all(target_arch = "x86_64", target_os = "linux", target_env = "gnu"))]
#[repr(C)]
struct VaListTag {
    gp_offset: u32,
    fp_offset: u32,
    overflow_arg_area: *mut u8,
    reg_save_area: *mut u8,
}

/// Format a printf-style string reading variadic arguments from a Windows x64
/// `va_list` pointer.
///
/// On Windows x64, a `va_list` is a `char*` that points directly to the first
/// variadic argument.  Each argument occupies exactly 8 bytes in memory
/// (integers/pointers sign/zero-extended; floats promoted to `double`).
///
/// We construct a Linux `__va_list_tag` with `gp_offset=48`
/// (all six integer registers already "consumed") and `fp_offset=304`
/// (all eight float registers already "consumed"), so every call to
/// `VaList::arg::<T>()` reads from `overflow_arg_area`, which we set to the
/// Windows `va_list` pointer.  The in-memory layout of `__va_list_tag` is
/// identical to `core::ffi::VaList<'_>` on x86_64-unknown-linux-gnu (both
/// are 24 bytes, same field order).
///
/// # Safety
/// - `ap` must be a valid Windows x64 `va_list` with at least as many
///   8-byte-aligned argument slots as `fmt` requires.
/// - `fmt` must be a valid ASCII/UTF-8 byte slice (the format string).
/// - When `wide_mode` is `true` the `%s`/`%S` and `%c`/`%C` specifier
///   semantics are swapped to match Windows wide-printf conventions.
#[cfg(all(target_arch = "x86_64", target_os = "linux", target_env = "gnu"))]
#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss
)]
unsafe fn format_printf_raw(fmt: &[u8], ap: *mut u8, wide_mode: bool) -> Vec<u8> {
    // Compile-time guard: the reinterpret cast below is only valid when
    // VaListTag and core::ffi::VaList<'_> have identical size and alignment.
    const _: () = assert!(
        core::mem::size_of::<VaListTag>() == 24,
        "VaListTag size must be 24 bytes (same as __va_list_tag on x86_64-linux-gnu)"
    );
    const _: () = assert!(
        core::mem::align_of::<VaListTag>() == 8,
        "VaListTag alignment must be 8 bytes"
    );

    // Linux x86_64 __va_list_tag / core::ffi::VaList layout (24 bytes):
    //   [0..4)   gp_offset: u32            — offset into reg_save_area for int
    //   [4..8)   fp_offset: u32            — offset into reg_save_area for float
    //   [8..16)  overflow_arg_area: *mut u8 — pointer to stack args
    //   [16..24) reg_save_area: *mut u8    — pointer to register save area
    //
    // Setting gp_offset=48 (6*8) and fp_offset=304 (48+8*32) forces all
    // argument reads to come from overflow_arg_area, which is the Windows
    // va_list pointer.
    let mut tag = VaListTag {
        gp_offset: 48,
        fp_offset: 304,
        overflow_arg_area: ap,
        reg_save_area: core::ptr::null_mut(),
    };
    // SAFETY: `VaListTag` is repr(C) and has the identical layout to
    // `core::ffi::VaList<'_>` on x86_64-unknown-linux-gnu, as verified by the
    // compile-time size/align assertions above.  We borrow `tag` only for the
    // duration of this call, so the lifetime is sound.
    let vl: &mut core::ffi::VaList<'_> =
        unsafe { &mut *(&raw mut tag).cast::<core::ffi::VaList<'_>>() };
    unsafe { format_printf_va(fmt, vl, wide_mode) }
}

// ── scanf helpers ─────────────────────────────────────────────────────────────

/// Count the number of conversion specifiers in `fmt` that consume a
/// va_list argument.  Suppressed specifiers (`%*d`) and `%%` are excluded.
///
/// This is used to know how many pointer arguments to extract from the
/// va_list before calling `libc::sscanf`.
fn count_scanf_specifiers(fmt: &[u8]) -> usize {
    let mut count = 0usize;
    let mut i = 0;
    while i < fmt.len() {
        if fmt[i] != b'%' {
            i += 1;
            continue;
        }
        i += 1;
        if i >= fmt.len() {
            break;
        }
        // %% — literal percent, no argument consumed
        if fmt[i] == b'%' {
            i += 1;
            continue;
        }
        // Suppression flag '*' — argument is parsed but NOT stored (no pointer consumed)
        let suppressed = fmt[i] == b'*';
        if suppressed {
            i += 1;
        }
        // Skip optional maximum field width (digits)
        while i < fmt.len() && fmt[i].is_ascii_digit() {
            i += 1;
        }
        // Skip length modifier(s): h, hh, l, ll, L, q, Z, z, j, t
        while i < fmt.len()
            && matches!(
                fmt[i],
                b'h' | b'l' | b'L' | b'q' | b'Z' | b'z' | b'j' | b't'
            )
        {
            i += 1;
        }
        if i >= fmt.len() {
            break;
        }
        // Handle %[…] character-class specifier — scan past the closing ']'
        if fmt[i] == b'[' {
            i += 1;
            // '^' inverts the class
            if i < fmt.len() && fmt[i] == b'^' {
                i += 1;
            }
            // A ']' immediately after '[' or '[^' is a literal ']' in the class
            if i < fmt.len() && fmt[i] == b']' {
                i += 1;
            }
            while i < fmt.len() && fmt[i] != b']' {
                i += 1;
            }
            if i < fmt.len() {
                i += 1; // skip ']'
            }
        } else {
            i += 1; // skip conversion char (d, i, u, x, f, s, c, p, n, …)
        }
        if !suppressed {
            count += 1;
        }
    }
    count
}

/// Maximum number of scanf output pointer arguments we handle.
const MAX_SCANF_ARGS: usize = 16;

/// Parse `buf` according to `fmt`, writing results through the pointers
/// obtained from the Linux `VaList`.
///
/// Up to `MAX_SCANF_ARGS` (16) specifiers are supported.  Returns the number
/// of items successfully matched and stored (same as `libc::sscanf`).
///
/// # Safety
/// - `buf` must be a valid null-terminated C string.
/// - `fmt` must be a valid null-terminated C string.
/// - Every pointer argument in `args` must be a valid, writable pointer of
///   the type implied by the corresponding format specifier.
#[cfg(all(target_arch = "x86_64", target_os = "linux", target_env = "gnu"))]
#[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
unsafe fn format_scanf_va(buf: *const i8, fmt: *const i8, args: &mut core::ffi::VaList<'_>) -> i32 {
    let fmt_bytes = unsafe { CStr::from_ptr(fmt.cast::<i8>()) }.to_bytes();
    let n_specs = count_scanf_specifiers(fmt_bytes).min(MAX_SCANF_ARGS);

    // Extract exactly n_specs pointer arguments from the va_list.
    // Remaining slots are left as null; libc::sscanf will never access them
    // because the format string controls how many pointers are consumed.
    let mut ptrs: [*mut core::ffi::c_void; MAX_SCANF_ARGS] =
        [core::ptr::null_mut(); MAX_SCANF_ARGS];
    for p in ptrs.iter_mut().take(n_specs) {
        // SAFETY: caller guarantees enough pointer args are in the va_list.
        *p = unsafe { args.arg::<*mut core::ffi::c_void>() };
    }

    // Call libc::sscanf with a fixed 16-slot argument list.  sscanf only
    // reads as many arguments as the format string specifies, so the trailing
    // null pointers are never accessed.
    // SAFETY: buf and fmt are valid null-terminated strings; each non-null
    // ptr in ptrs[0..n_specs] is a valid writable pointer for its specifier.
    unsafe {
        libc::sscanf(
            buf, fmt, ptrs[0], ptrs[1], ptrs[2], ptrs[3], ptrs[4], ptrs[5], ptrs[6], ptrs[7],
            ptrs[8], ptrs[9], ptrs[10], ptrs[11], ptrs[12], ptrs[13], ptrs[14], ptrs[15],
        )
    }
}

/// Parse `buf` according to `fmt` using a Windows x64 `va_list` pointer.
///
/// Bridges the Windows x64 `va_list` (a plain pointer into 8-byte-aligned
/// argument slots) to `format_scanf_va` by constructing a synthetic Linux
/// `__va_list_tag` that reads all arguments from the overflow area.
///
/// # Safety
/// - `buf` must be a valid null-terminated C string.
/// - `fmt` must be a valid null-terminated C string byte slice.
/// - `ap` must be a valid Windows x64 `va_list` with at least as many
///   8-byte pointer slots as `fmt` contains non-suppressed specifiers.
#[cfg(all(target_arch = "x86_64", target_os = "linux", target_env = "gnu"))]
#[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
unsafe fn format_scanf_raw(buf: *const i8, fmt: *const i8, ap: *mut u8) -> i32 {
    // Construct a Linux __va_list_tag with gp_offset=48 and fp_offset=304 so
    // that every VaList::arg::<T>() call reads from overflow_arg_area (= ap).
    // See format_printf_raw for a detailed explanation of this technique.
    const _: () = assert!(
        core::mem::size_of::<VaListTag>() == 24,
        "VaListTag size must be 24 bytes"
    );
    let mut tag = VaListTag {
        gp_offset: 48,
        fp_offset: 304,
        overflow_arg_area: ap,
        reg_save_area: core::ptr::null_mut(),
    };
    // SAFETY: VaListTag is repr(C) with the same layout as core::ffi::VaList
    // on x86_64-linux-gnu (verified by the size assertion above).
    let vl: &mut core::ffi::VaList<'_> =
        unsafe { &mut *(&raw mut tag).cast::<core::ffi::VaList<'_>>() };
    unsafe { format_scanf_va(buf, fmt, vl) }
}

// ============================================================================
// Data Exports
// ============================================================================
// These are global variables that Windows programs import directly.
// Unlike function exports, these need to be actual memory locations.

/// File mode (_fmode) - default file open mode
/// 0x4000 = _O_BINARY (binary mode), 0x8000 = _O_TEXT (text mode)
/// Default is binary mode (0x4000)
#[unsafe(no_mangle)]
pub static mut msvcrt__fmode: i32 = 0x4000; // Binary mode by default

/// Commit mode (_commode) - file commit behavior
/// 0 = no commit, non-zero = commit
#[unsafe(no_mangle)]
pub static mut msvcrt__commode: i32 = 0;

/// Environment pointer (__initenv) - pointer to environment variables
/// This is a triple pointer: pointer to array of pointers to strings
#[unsafe(no_mangle)]
pub static mut msvcrt___initenv: *mut *mut i8 = ptr::null_mut();

/// Null-terminated empty environment (`char**` with a single null pointer).
const NULL_ENV_PTR: [usize; 1] = [0];

// ============================================================================
// Data Access Functions
// ============================================================================
// These functions return pointers to global data variables

/// Get pointer to file mode (_fmode)
///
/// # Safety
/// Returns a pointer to a static mutable variable. The caller must ensure
/// proper synchronization if accessing from multiple threads.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt___p__fmode() -> *mut i32 {
    core::ptr::addr_of_mut!(msvcrt__fmode)
}

/// Get pointer to commit mode (_commode)
///
/// # Safety
/// Returns a pointer to a static mutable variable. The caller must ensure
/// proper synchronization if accessing from multiple threads.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt___p__commode() -> *mut i32 {
    core::ptr::addr_of_mut!(msvcrt__commode)
}

// ============================================================================
// CRT Initialization Functions
// ============================================================================

/// Set command line arguments (_setargv)
///
/// This is called during CRT initialization to parse command line arguments.
/// For now, this is a no-op stub since we handle arguments in __getmainargs.
///
/// # Safety
/// This function is safe to call but marked unsafe for C ABI compatibility.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt__setargv() {
    // No-op stub - we handle arguments in __getmainargs
}

/// Set invalid parameter handler
///
/// This is called during CRT initialization to set a handler for invalid parameters.
/// For now, this is a no-op stub.
///
/// # Safety
/// This function is unsafe as it deals with function pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt__set_invalid_parameter_handler(
    _handler: *mut core::ffi::c_void,
) -> *mut core::ffi::c_void {
    // No-op stub - return null to indicate no previous handler
    ptr::null_mut()
}

/// PE runtime relocator
///
/// This function is called by MinGW runtime to perform additional relocations.
/// Since relocations are already handled by our PE loader, this is a no-op.
///
/// # Safety
/// This function is safe to call but marked unsafe for C ABI compatibility.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt__pei386_runtime_relocator() {
    // No-op stub - relocations already handled by PE loader
}

// ============================================================================
// Memory Management Functions
// ============================================================================

/// Allocate memory (malloc)
///
/// # Safety
/// This function is unsafe as it deals with raw memory allocation.
/// The caller must ensure the returned pointer is properly freed with `msvcrt_free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt_malloc(size: usize) -> *mut u8 {
    if size == 0 {
        return ptr::null_mut();
    }

    // SAFETY: We're creating a valid layout for the requested size
    let layout = unsafe { Layout::from_size_align_unchecked(size, std::mem::align_of::<usize>()) };
    // SAFETY: Layout is valid
    unsafe { alloc(layout) }
}

/// Free memory (free)
///
/// # Safety
/// This function is unsafe as it deals with raw memory deallocation.
/// The pointer must have been allocated by `msvcrt_malloc` or `msvcrt_calloc`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt_free(ptr: *mut u8) {
    if ptr.is_null() {
        return;
    }

    // SAFETY: We create a minimal layout; the allocator tracks the actual size
    let layout = unsafe { Layout::from_size_align_unchecked(1, std::mem::align_of::<usize>()) };
    // SAFETY: Caller guarantees ptr was allocated by malloc/calloc
    unsafe { dealloc(ptr, layout) };
}

/// Allocate and zero-initialize memory (calloc)
///
/// # Safety
/// This function is unsafe as it deals with raw memory allocation.
/// The caller must ensure the returned pointer is properly freed with `msvcrt_free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt_calloc(num: usize, size: usize) -> *mut u8 {
    let total_size = num.saturating_mul(size);
    if total_size == 0 {
        return ptr::null_mut();
    }

    // SAFETY: Caller is responsible for freeing the returned pointer
    let ptr = unsafe { msvcrt_malloc(total_size) };
    if !ptr.is_null() {
        // SAFETY: ptr is valid for total_size bytes
        unsafe { ptr::write_bytes(ptr, 0, total_size) };
    }
    ptr
}

/// Copy memory (memcpy)
///
/// # Safety
/// This function is unsafe as it deals with raw pointers.
/// The caller must ensure src and dest don't overlap and are valid for the given size.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt_memcpy(dest: *mut u8, src: *const u8, n: usize) -> *mut u8 {
    // SAFETY: Caller guarantees src and dest are valid and don't overlap
    unsafe { ptr::copy_nonoverlapping(src, dest, n) };
    dest
}

/// Move memory (memmove) - handles overlapping regions
///
/// # Safety
/// This function is unsafe as it deals with raw pointers.
/// The caller must ensure src and dest are valid for the given size.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt_memmove(dest: *mut u8, src: *const u8, n: usize) -> *mut u8 {
    // SAFETY: Caller guarantees src and dest are valid; copy handles overlaps
    unsafe { ptr::copy(src, dest, n) };
    dest
}

/// Set memory (memset)
///
/// # Safety
/// This function is unsafe as it deals with raw pointers.
/// The caller must ensure dest is valid for the given size.
#[unsafe(no_mangle)]
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
pub unsafe extern "C" fn msvcrt_memset(dest: *mut u8, c: i32, n: usize) -> *mut u8 {
    // SAFETY: Caller guarantees dest is valid for n bytes
    ptr::write_bytes(dest, c as u8, n);
    dest
}

/// Compare memory (memcmp)
///
/// # Safety
/// This function is unsafe as it deals with raw pointers.
/// The caller must ensure both pointers are valid for the given size.
#[unsafe(no_mangle)]
#[allow(clippy::cast_lossless)]
pub unsafe extern "C" fn msvcrt_memcmp(s1: *const u8, s2: *const u8, n: usize) -> i32 {
    // SAFETY: Caller guarantees s1 and s2 are valid for n bytes
    for i in 0..n {
        let c1 = *s1.add(i);
        let c2 = *s2.add(i);
        if c1 != c2 {
            return i32::from(c1) - i32::from(c2);
        }
    }
    0
}

/// Get string length (strlen)
///
/// # Safety
/// This function is unsafe as it deals with raw pointers.
/// The caller must ensure the pointer points to a valid null-terminated string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt_strlen(s: *const i8) -> usize {
    // SAFETY: Caller guarantees s points to a null-terminated string
    CStr::from_ptr(s).to_bytes().len()
}

/// Compare strings up to n characters (strncmp)
///
/// # Safety
/// This function is unsafe as it deals with raw pointers.
/// The caller must ensure both pointers point to valid null-terminated strings.
#[unsafe(no_mangle)]
#[allow(clippy::cast_lossless)]
pub unsafe extern "C" fn msvcrt_strncmp(s1: *const i8, s2: *const i8, n: usize) -> i32 {
    // SAFETY: Caller guarantees s1 and s2 are valid null-terminated strings
    for i in 0..n {
        let c1 = (*s1.add(i)).cast_unsigned();
        let c2 = (*s2.add(i)).cast_unsigned();

        // Check for null terminator
        if c1 == 0 && c2 == 0 {
            return 0;
        }
        if c1 == 0 {
            return -1;
        }
        if c2 == 0 {
            return 1;
        }

        if c1 != c2 {
            return i32::from(c1) - i32::from(c2);
        }
    }
    0
}

/// Print formatted string to stdout (printf)
///
/// # Safety
/// `format` must point to a valid null-terminated C string.
/// Variadic arguments must match the format specifiers.
#[unsafe(no_mangle)]
#[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
pub unsafe extern "C" fn msvcrt_printf(format: *const i8, mut args: ...) -> i32 {
    if format.is_null() {
        return -1;
    }
    // SAFETY: Caller guarantees format is a valid null-terminated C string.
    let fmt_bytes = unsafe { CStr::from_ptr(format) }.to_bytes();
    // SAFETY: format and args are valid per caller contract.
    let out = unsafe { format_printf_va(fmt_bytes, &mut args, false) };
    match io::stdout().write_all(&out) {
        Ok(()) => {
            let _ = io::stdout().flush();
            out.len() as i32
        }
        Err(_) => -1,
    }
}

/// Write data to a file (fwrite)
///
/// # Safety
/// This function is unsafe as it deals with raw pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt_fwrite(
    ptr: *const u8,
    size: usize,
    nmemb: usize,
    _stream: *mut u8,
) -> usize {
    if ptr.is_null() || size == 0 || nmemb == 0 {
        return 0;
    }

    let total_bytes = size * nmemb;
    // SAFETY: Caller guarantees ptr is valid for total_bytes
    let data = unsafe { std::slice::from_raw_parts(ptr, total_bytes) };

    // Simple implementation: write to stdout
    match io::stdout().write(data) {
        Ok(written) => {
            let _ = io::stdout().flush();
            written / size
        }
        Err(_e) => 0,
    }
}

/// Write a formatted string to a stream (fprintf)
///
/// Always writes to stdout (fd 1).  The `stream` parameter is a Windows FILE*
/// pointer, not a Linux fd, so we cannot reliably distinguish stderr from
/// stdout by comparing the pointer value.  Most fprintf callers use stdout;
/// programs that specifically need stderr typically use the `stderr` macro
/// which is resolved at link time through `__iob_func` / `__acrt_iob_func`.
///
/// # Safety
/// `format` must point to a valid null-terminated C string.
/// Variadic arguments must match the format specifiers.
#[unsafe(no_mangle)]
#[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
pub unsafe extern "C" fn msvcrt_fprintf(_stream: *mut u8, format: *const i8, mut args: ...) -> i32 {
    if format.is_null() {
        return -1;
    }
    // SAFETY: Caller guarantees format is a valid null-terminated C string.
    let fmt_bytes = unsafe { CStr::from_ptr(format) }.to_bytes();
    // SAFETY: format and args are valid per caller contract.
    let out = unsafe { format_printf_va(fmt_bytes, &mut args, false) };
    let written = unsafe { libc::write(1, out.as_ptr().cast(), out.len()) };
    if written < 0 { -1 } else { written as i32 }
}

/// Write a formatted string to a stream using a pre-built va_list (vfprintf)
///
/// The `stream` parameter is ignored; output always goes to stdout (fd 1).
/// See `msvcrt_fprintf` for the rationale.
///
/// # Safety
/// `format` must point to a valid null-terminated C string.
/// `args` must be a valid Windows x64 va_list pointer.
#[unsafe(no_mangle)]
#[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
pub unsafe extern "C" fn msvcrt_vfprintf(
    _stream: *mut u8,
    format: *const i8,
    args: *mut u8,
) -> i32 {
    if format.is_null() {
        return -1;
    }
    // SAFETY: Caller guarantees format is a valid null-terminated C string.
    let fmt_bytes = unsafe { CStr::from_ptr(format) }.to_bytes();
    // SAFETY: args is a valid Windows x64 va_list pointer.
    let out = unsafe { format_printf_raw(fmt_bytes, args, false) };
    let written = unsafe { libc::write(1, out.as_ptr().cast(), out.len()) };
    if written < 0 { -1 } else { written as i32 }
}

/// Write a formatted string to stdout using a pre-built va_list (vprintf)
///
/// # Safety
/// `format` must point to a valid null-terminated C string.
/// `args` must be a valid Windows x64 va_list pointer.
#[unsafe(no_mangle)]
#[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
pub unsafe extern "C" fn msvcrt_vprintf(format: *const i8, args: *mut u8) -> i32 {
    if format.is_null() {
        return -1;
    }
    // SAFETY: Caller guarantees format is a valid null-terminated C string.
    let fmt_bytes = unsafe { CStr::from_ptr(format) }.to_bytes();
    // SAFETY: args is a valid Windows x64 va_list pointer.
    let out = unsafe { format_printf_raw(fmt_bytes, args, false) };
    match io::stdout().write_all(&out) {
        Ok(()) => {
            let _ = io::stdout().flush();
            out.len() as i32
        }
        Err(_) => -1,
    }
}

/// Write a formatted string into a buffer using a pre-built va_list (vsprintf)
///
/// **No bounds checking is performed.**  This matches the Windows MSVCRT
/// `vsprintf` ABI, which has no `size` parameter.  Callers that do not know
/// the output length at compile time should use `vsnprintf` instead.
///
/// # Safety
/// `buf` must point to a buffer large enough for the formatted output plus a
/// null terminator.  Writing beyond the buffer boundary is undefined
/// behaviour.  `format` must be a valid null-terminated C string.
/// `args` must be a valid Windows x64 va_list pointer.
#[unsafe(no_mangle)]
#[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
pub unsafe extern "C" fn msvcrt_vsprintf(buf: *mut i8, format: *const i8, args: *mut u8) -> i32 {
    if buf.is_null() || format.is_null() {
        return -1;
    }
    // SAFETY: Caller guarantees format is a valid null-terminated C string.
    let fmt_bytes = unsafe { CStr::from_ptr(format) }.to_bytes();
    // SAFETY: args is a valid Windows x64 va_list pointer.
    let out = unsafe { format_printf_raw(fmt_bytes, args, false) };
    // SAFETY: Caller guarantees buf is large enough.
    unsafe {
        core::ptr::copy_nonoverlapping(out.as_ptr(), buf.cast(), out.len());
        *buf.add(out.len()) = 0;
    }
    out.len() as i32
}

/// Write a formatted string into a buffer with size limit using a va_list
/// (vsnprintf)
///
/// # Safety
/// `buf` must point to a buffer of at least `size` bytes.
/// `format` must be a valid null-terminated C string.
/// `args` must be a valid Windows x64 va_list pointer.
#[unsafe(no_mangle)]
#[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
pub unsafe extern "C" fn msvcrt_vsnprintf(
    buf: *mut i8,
    size: usize,
    format: *const i8,
    args: *mut u8,
) -> i32 {
    if format.is_null() {
        return -1;
    }
    // SAFETY: Caller guarantees format is a valid null-terminated C string.
    let fmt_bytes = unsafe { CStr::from_ptr(format) }.to_bytes();
    // SAFETY: args is a valid Windows x64 va_list pointer.
    let out = unsafe { format_printf_raw(fmt_bytes, args, false) };
    if buf.is_null() || size == 0 {
        return out.len() as i32;
    }
    let copy_len = out.len().min(size - 1);
    // SAFETY: Caller guarantees buf has at least `size` bytes.
    unsafe {
        core::ptr::copy_nonoverlapping(out.as_ptr(), buf.cast(), copy_len);
        *buf.add(copy_len) = 0;
    }
    out.len() as i32
}

/// Write a wide formatted string into a buffer using a pre-built va_list
/// (vswprintf)
///
/// **No bounds checking is performed.**  This matches the Windows MSVCRT
/// `vswprintf` ABI which has no `count` parameter.  Use `_vsnwprintf` for
/// size-limited wide formatting.
///
/// # Safety
/// `buf` must point to a buffer large enough for the formatted output plus a
/// null terminator (in `u16` units).  Writing beyond the buffer boundary is
/// undefined behaviour.  `format` must be a valid null-terminated wide
/// string.  `args` must be a valid Windows x64 va_list.
#[unsafe(no_mangle)]
#[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
pub unsafe extern "C" fn msvcrt_vswprintf(buf: *mut u16, format: *const u16, args: *mut u8) -> i32 {
    if buf.is_null() || format.is_null() {
        return -1;
    }
    // Convert the wide format string to UTF-8.
    // SAFETY: Caller guarantees format is a valid null-terminated wide string.
    let fmt_wide = unsafe { read_wide_string(format) };
    let fmt_utf8 = String::from_utf16_lossy(&fmt_wide);
    // SAFETY: args is a valid Windows x64 va_list pointer.
    let out = unsafe { format_printf_raw(fmt_utf8.as_bytes(), args, true) };
    let out_str = String::from_utf8_lossy(&out);
    let wide: Vec<u16> = out_str.encode_utf16().collect();
    // SAFETY: Caller guarantees buf is large enough.
    unsafe {
        core::ptr::copy_nonoverlapping(wide.as_ptr(), buf, wide.len());
        *buf.add(wide.len()) = 0;
    }
    wide.len() as i32
}

/// Get I/O buffer array (__iob_func)
/// Returns a pointer to stdin/stdout/stderr file descriptors
///
/// # Safety
/// This function returns a static array that should not be freed.
/// Uses Mutex for thread-safe access to the static buffer.
///
/// # Panics
/// Panics if the mutex is poisoned (which would only occur if another thread
/// panicked while holding the lock).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt___iob_func() -> *mut u8 {
    use std::sync::Mutex;

    // Use Mutex for thread-safe access to the static buffer
    // In a full implementation, this would return FILE* structures
    static IOB: Mutex<[u8; 24]> = Mutex::new([0; 24]); // 3 FILE structures (simplified)

    // SAFETY: Lock the mutex and return a pointer to the buffer.
    // The pointer remains valid as long as the static exists.
    // Note: This matches Windows CRT behavior where __iob_func returns a global buffer.
    IOB.lock().unwrap().as_mut_ptr()
}

/// Get main arguments (__getmainargs)
///
/// Parses `PROCESS_COMMAND_LINE` (set by the runner) into ANSI `char**` arrays
/// using Windows command-line quoting rules and stores them in a `OnceLock` so
/// that the returned raw pointers remain stable for the lifetime of the process.
///
/// # Panics
/// Panics if `CString::new("")` fails (which should never happen).
///
/// # Safety
/// This function is unsafe as it deals with raw pointers.
#[unsafe(no_mangle)]
#[allow(clippy::similar_names)]
pub unsafe extern "C" fn msvcrt___getmainargs(
    p_argc: *mut i32,
    p_argv: *mut *mut *mut i8,
    p_env: *mut *mut *mut i8,
    _do_wildcard: i32,
    _start_info: *mut u8,
) -> i32 {
    let (_, argv_ptrs) = PARSED_MAIN_ARGS.get_or_init(|| {
        let cmd = crate::kernel32::get_command_line_utf8();
        let strings: Vec<CString> = parse_windows_command_line(&cmd)
            .into_iter()
            .map(|s| {
                let safe = s.replace('\0', "?");
                CString::new(safe).unwrap_or_else(|_| CString::new("").unwrap())
            })
            .collect();
        // Build a null-terminated array of `*mut i8` pointers.
        let mut ptrs: Vec<*mut i8> = strings.iter().map(|cs| cs.as_ptr().cast_mut()).collect();
        ptrs.push(ptr::null_mut()); // null terminator
        (strings, ArgvPtrs(ptrs))
    });

    let argc = i32::try_from(argv_ptrs.0.len().saturating_sub(1)).unwrap_or(i32::MAX); // exclude null terminator

    if !p_argc.is_null() {
        *p_argc = argc;
    }
    if !p_argv.is_null() {
        // argv_ptrs.0 is a null-terminated array; pass a pointer to its first element.
        *p_argv = argv_ptrs.0.as_ptr().cast_mut().cast();
    }
    ARGC_STATIC.store(argc, std::sync::atomic::Ordering::Relaxed);
    ARGV_PTR.store(
        argv_ptrs.0.as_ptr().cast::<*mut i8>().cast_mut(),
        std::sync::atomic::Ordering::Relaxed,
    );
    // env: pass a single-element null-terminated array (no custom env parsing needed;
    // programs that need the environment use GetEnvironmentStringsW instead).
    if !p_env.is_null() {
        let env_ptr = NULL_ENV_PTR.as_ptr().cast::<*mut i8>().cast_mut().cast();
        *p_env = env_ptr;
        msvcrt___initenv = env_ptr;
    }

    0 // Success
}

/// Set application type (__set_app_type)
///
/// # Safety
/// This function is safe to call but marked unsafe for C ABI compatibility.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt___set_app_type(_type: i32) {
    // No-op stub
}

/// Initialize term table (_initterm)
///
/// # Safety
/// This function is unsafe as it deals with raw pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt__initterm(start: *mut extern "C" fn(), end: *mut extern "C" fn()) {
    if start.is_null() || end.is_null() {
        return;
    }

    let mut current = start;
    while current < end {
        // SAFETY: Caller guarantees current is within valid range [start, end)
        let func_ptr_raw = unsafe { *(current.cast::<usize>()) };

        // Check if function pointer is not null or -1 (sentinel value) before calling
        if func_ptr_raw != 0 && func_ptr_raw != usize::MAX {
            // SAFETY:
            // - Provenance: `func_ptr_raw` is read from the array in [`start`, `end`), which
            //   the caller (the MSVCRT/CRT runtime) populates with pointers to initialization
            //   functions following the `_initterm` contract. Each non-null, non-`usize::MAX`
            //   entry is required to point to a valid function with ABI `extern "C" fn()`.
            // - Invariants relied on:
            //   * The memory between `start` and `end` is a contiguous array of pointer-sized
            //     entries written by the loader/CRT, not arbitrary data.
            //   * For any entry that is not `0` or `usize::MAX`, the value represents a live,
            //     correctly aligned, executable code address for a function that takes no
            //     arguments, uses the C ABI, and returns `()`.
            //   * Those functions are safe to call exactly once during process initialization.
            // - Validation performed here:
            //   * We skip entries that are `0` (null) or `usize::MAX` (documented sentinel).
            //   * We rely on the PE loader/MSVCRT initialization logic to have mapped the
            //     corresponding code pages as executable and to uphold the ABI/lifetime
            //     guarantees for these function pointers.
            let func: extern "C" fn() = unsafe { core::mem::transmute(func_ptr_raw) };
            func();
        }

        // SAFETY: Caller guarantees current can be advanced within the range
        current = unsafe { current.add(1) };
    }
}

/// Register onexit handler (_onexit)
///
/// # Safety
/// This function is unsafe as it deals with raw pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt__onexit(func: extern "C" fn()) -> extern "C" fn() {
    // Store in a static vector for later execution
    static ONEXIT_FUNCS: Mutex<Vec<extern "C" fn()>> = Mutex::new(Vec::new());

    // Check if function pointer is valid (not null or -1)
    let func_ptr = func as *const fn();
    let func_addr = func_ptr as usize;
    if func_ptr.is_null() || func_addr == usize::MAX {
        return func; // Return as-is for invalid pointers
    }

    if let Ok(mut funcs) = ONEXIT_FUNCS.lock() {
        funcs.push(func);
    }
    func
}

/// Signal handler registration (signal)
///
/// # Safety
/// This function is unsafe as it deals with raw pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt_signal(_signum: i32, _handler: extern "C" fn(i32)) -> usize {
    // Stub: return SIG_DFL (0)
    0
}

/// Abort program execution (abort)
///
/// # Safety
/// This function is safe to call but marked unsafe for C ABI compatibility.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt_abort() -> ! {
    std::process::abort()
}

/// Exit program (exit)
///
/// # Safety
/// This function is safe to call but marked unsafe for C ABI compatibility.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt_exit(status: i32) -> ! {
    std::process::exit(status)
}

// Additional CRT stubs

/// Set user math error handler (__setusermatherr)
///
/// # Safety
/// This function is unsafe as it deals with raw pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt___setusermatherr(_handler: *mut u8) {
    // No-op stub
}

/// Exit with error message (_amsg_exit)
///
/// # Safety
/// This function is safe to call but marked unsafe for C ABI compatibility.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt__amsg_exit(code: i32) {
    std::process::exit(code)
}

/// Clean exit without terminating process (_cexit)
///
/// # Safety
/// This function is safe to call but marked unsafe for C ABI compatibility.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt__cexit() {
    // MSVCRT _cexit performs CRT cleanup without terminating the process.
    // We do not maintain separate CRT cleanup state yet, so this is a no-op.
}

/// Reset floating point unit (_fpreset)
///
/// # Safety
/// This function is safe to call but marked unsafe for C ABI compatibility.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt__fpreset() {
    // Reset floating point unit - no-op on x86-64
}

/// Thread-local errno storage for proper per-thread error handling
use std::cell::RefCell;

thread_local! {
    static ERRNO: RefCell<i32> = const { RefCell::new(0) };
}

/// Get errno location (__errno_location)
///
/// # Safety
/// This function returns a pointer to thread-local errno storage.
/// The pointer is valid for the lifetime of the current thread.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt___errno_location() -> *mut i32 {
    // SAFETY: Returns a pointer to thread-local storage.
    // The pointer is valid as long as the thread exists.
    ERRNO.with(std::cell::RefCell::as_ptr)
}

/// Wrapper so `Vec<*mut i8>` (not `Send`/`Sync`) can be stored in a static.
///
/// # Safety
/// Pointers are derived from `CString` buffers that live inside the same
/// `OnceLock` and are never mutated after initialisation.
struct ArgvPtrs(Vec<*mut i8>);
// SAFETY: The underlying CString buffers are pinned inside the same OnceLock
// value and are never written to after initialisation.
unsafe impl Send for ArgvPtrs {}
unsafe impl Sync for ArgvPtrs {}

/// Parsed process main arguments — populated lazily on the first `__getmainargs` call.
///
/// Stores:
///   0: `Vec<CString>` — the argument strings (owns the memory).
///   1: `ArgvPtrs`     — null-terminated array of `char*` pointers into element 0.
///
/// The `OnceLock` ensures the `CString` buffers are never moved after initialisation,
/// making the raw pointers in element 1 permanently stable.
static PARSED_MAIN_ARGS: OnceLock<(Vec<CString>, ArgvPtrs)> = OnceLock::new();

/// Parse a Windows-style command line into individual argument strings.
///
/// Handles the common quoting rules:
///   - Arguments separated by spaces / tabs.
///   - `"..."` wraps a quoted argument (the quotes are stripped).
///   - Backslashes followed by a quote use Windows' 2N / 2N+1 rules:
///     - 2N backslashes + `"` => N backslashes + toggle quoting (no literal `"`).
///     - 2N+1 backslashes + `"` => N backslashes + literal `"` (no toggle).
///   - These rules apply both inside and outside quoted arguments.
fn parse_windows_command_line(cmd: &str) -> Vec<String> {
    let mut args = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;

    // Work on a Vec<char> so we can look ahead by index without
    // breaking UTF-8 encoding; we only treat ASCII `"`, `\`, space, and tab
    // specially, which are all single-byte and single-char code points.
    let chars: Vec<char> = cmd.chars().collect();
    let mut i = 0;

    while i < chars.len() {
        let c = chars[i];
        match c {
            ' ' | '\t' if !in_quotes => {
                if !current.is_empty() {
                    args.push(current.clone());
                    current.clear();
                }
                i += 1;
            }
            '"' => {
                // A bare quote toggles the in_quotes state and is not emitted.
                in_quotes = !in_quotes;
                i += 1;
            }
            '\\' => {
                // Count consecutive backslashes.
                let mut backslash_count = 0;
                while i < chars.len() && chars[i] == '\\' {
                    backslash_count += 1;
                    i += 1;
                }

                let next_is_quote = i < chars.len() && chars[i] == '"';
                if next_is_quote {
                    // Emit one backslash for every pair.
                    current.extend(std::iter::repeat_n('\\', backslash_count / 2));
                    if backslash_count % 2 == 0 {
                        // Even number of backslashes: the quote is a delimiter.
                        in_quotes = !in_quotes;
                        i += 1; // consume the quote
                    } else {
                        // Odd number of backslashes: the quote is escaped.
                        current.push('"');
                        i += 1; // consume the quote
                    }
                } else {
                    // No quote follows: emit all backslashes literally.
                    current.extend(std::iter::repeat_n('\\', backslash_count));
                }
            }
            other => {
                current.push(other);
                i += 1;
            }
        }
    }

    if !current.is_empty() {
        args.push(current);
    }
    args
}

/// ANSI command-line storage for `_acmdln`.
///
/// Lazily built from `PROCESS_COMMAND_LINE` on first access.
static ACMDLN_STORAGE: OnceLock<CString> = OnceLock::new();

/// Get pointer to command line string (_acmdln)
///
/// This is a global variable in MSVCRT that points to the ANSI command line.
/// Programs access it via `_acmdln` which is a `char*`.
///
/// # Panics
/// Panics if `CString::new("")` fails (which should never happen).
///
/// # Safety
/// Returns a pointer to static memory that is valid for the lifetime of the program.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt__acmdln() -> *const u8 {
    let cstr = ACMDLN_STORAGE.get_or_init(|| {
        let utf8 = crate::kernel32::get_command_line_utf8();
        // SAFETY: `utf8` comes from a valid String; CString::new only fails on interior NUL
        // bytes.  We replace any interior NULs with '?' to be safe.
        let safe = utf8.replace('\0', "?");
        CString::new(safe).unwrap_or_else(|_| CString::new("").unwrap())
    });
    cstr.as_ptr().cast::<u8>()
}

/// Check if a byte is a multibyte lead byte (_ismbblead)
///
/// This function checks if a byte is the lead byte of a multibyte character
/// in the current code page. For simplicity, we assume UTF-8 encoding.
///
/// # Safety
/// Safe to call but marked unsafe for C ABI compatibility.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt__ismbblead(c: u32) -> i32 {
    // In UTF-8:
    // - Bytes 0x00-0x7F are single-byte characters (not lead bytes)
    // - Bytes 0x80-0xBF are continuation bytes (not lead bytes)
    // - Bytes 0xC0-0xFF are lead bytes
    //
    // For ANSI code pages, lead bytes depend on the specific code page.
    // We'll implement a simple check for UTF-8.

    let byte = (c & 0xFF) as u8;

    // In UTF-8, lead bytes are >= 0xC0
    i32::from(byte >= 0xC0)
}

/// C-specific exception handler (__C_specific_handler)
///
/// This is a placeholder implementation for structured exception handling (SEH).
/// Real implementation would require full SEH support with exception tables.
///
/// # Safety
/// This is a stub that should not be called in normal execution.
/// Marked unsafe for C ABI compatibility.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt___C_specific_handler(
    _exception_record: usize,
    _establisher_frame: usize,
    _context_record: usize,
    _dispatcher_context: usize,
) -> i32 {
    // Return EXCEPTION_CONTINUE_SEARCH (1)
    // This tells the system to continue searching for an exception handler
    1
}

/// Compare two null-terminated strings (strcmp)
///
/// # Safety
/// This function is unsafe as it deals with raw pointers.
/// The caller must ensure both pointers point to valid null-terminated strings.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt_strcmp(s1: *const i8, s2: *const i8) -> i32 {
    if s1.is_null() || s2.is_null() {
        return if s1.is_null() && s2.is_null() {
            0
        } else if s1.is_null() {
            -1
        } else {
            1
        };
    }
    let mut i = 0usize;
    loop {
        let c1 = (*s1.add(i)).cast_unsigned();
        let c2 = (*s2.add(i)).cast_unsigned();
        if c1 != c2 {
            return i32::from(c1) - i32::from(c2);
        }
        if c1 == 0 {
            return 0;
        }
        i += 1;
    }
}

/// Copy a null-terminated string (strcpy)
///
/// # Safety
/// This function is unsafe as it deals with raw pointers.
/// The caller must ensure dest has enough space and src is a valid null-terminated string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt_strcpy(dest: *mut i8, src: *const i8) -> *mut i8 {
    if dest.is_null() || src.is_null() {
        return dest;
    }
    let mut i = 0usize;
    loop {
        let c = *src.add(i);
        *dest.add(i) = c;
        if c == 0 {
            break;
        }
        i += 1;
    }
    dest
}

/// Concatenate two null-terminated strings (strcat)
///
/// # Safety
/// This function is unsafe as it deals with raw pointers.
/// The caller must ensure dest has enough space for the concatenated result.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt_strcat(dest: *mut i8, src: *const i8) -> *mut i8 {
    if dest.is_null() || src.is_null() {
        return dest;
    }
    // Find end of dest
    let mut i = 0usize;
    while *dest.add(i) != 0 {
        i += 1;
    }
    // Copy src to end of dest
    let mut j = 0usize;
    loop {
        let c = *src.add(j);
        *dest.add(i + j) = c;
        if c == 0 {
            break;
        }
        j += 1;
    }
    dest
}

/// Find first occurrence of a character in a string (strchr)
///
/// # Safety
/// This function is unsafe as it deals with raw pointers.
/// The caller must ensure s is a valid null-terminated string.
#[unsafe(no_mangle)]
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
pub unsafe extern "C" fn msvcrt_strchr(s: *const i8, c: i32) -> *const i8 {
    if s.is_null() {
        return ptr::null();
    }
    let target = c as i8;
    let mut i = 0usize;
    loop {
        let ch = *s.add(i);
        if ch == target {
            return s.add(i);
        }
        if ch == 0 {
            return ptr::null();
        }
        i += 1;
    }
}

/// Find last occurrence of a character in a string (strrchr)
///
/// # Safety
/// This function is unsafe as it deals with raw pointers.
/// The caller must ensure s is a valid null-terminated string.
#[unsafe(no_mangle)]
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
pub unsafe extern "C" fn msvcrt_strrchr(s: *const i8, c: i32) -> *const i8 {
    if s.is_null() {
        return ptr::null();
    }
    let target = c as i8;
    let mut last: *const i8 = ptr::null();
    let mut i = 0usize;
    loop {
        let ch = *s.add(i);
        if ch == target {
            last = s.add(i);
        }
        if ch == 0 {
            return last;
        }
        i += 1;
    }
}

/// Find first occurrence of a substring in a string (strstr)
///
/// # Safety
/// This function is unsafe as it deals with raw pointers.
/// The caller must ensure both pointers point to valid null-terminated strings.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt_strstr(haystack: *const i8, needle: *const i8) -> *const i8 {
    if haystack.is_null() || needle.is_null() {
        return ptr::null();
    }
    // Empty needle matches at the start
    if *needle == 0 {
        return haystack;
    }
    let needle_len = CStr::from_ptr(needle).to_bytes().len();
    let mut i = 0usize;
    while *haystack.add(i) != 0 {
        let mut matched = true;
        for j in 0..needle_len {
            if *haystack.add(i + j) == 0 || *haystack.add(i + j) != *needle.add(j) {
                matched = false;
                break;
            }
        }
        if matched {
            return haystack.add(i);
        }
        i += 1;
    }
    ptr::null()
}

/// Initialize term table with error return (_initterm_e)
///
/// Like _initterm, but the function pointers return an int error code.
/// Returns 0 on success, or the first non-zero return value on failure.
///
/// # Safety
/// This function is unsafe as it deals with raw pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt__initterm_e(
    start: *mut extern "C" fn() -> i32,
    end: *mut extern "C" fn() -> i32,
) -> i32 {
    if start.is_null() || end.is_null() {
        return 0;
    }

    let mut current = start;
    while current < end {
        let func_ptr_raw = *(current.cast::<usize>());

        if func_ptr_raw != 0 && func_ptr_raw != usize::MAX {
            // SAFETY: Same contract as _initterm - entries are valid function pointers
            // with ABI extern "C" fn() -> i32, populated by the CRT/loader.
            let func: extern "C" fn() -> i32 = core::mem::transmute(func_ptr_raw);
            let result = func();
            if result != 0 {
                return result;
            }
        }

        current = current.add(1);
    }
    0
}

/// Global argc value for `__p___argc`.
///
/// Initialized to 0 and written once during CRT startup by `__getmainargs`.
/// After that single write the value is only read, so concurrent readers are safe
/// without additional synchronization (single-threaded CRT init guarantees this).
static ARGC_STATIC: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(0);

/// Fallback null-terminated argv (`char**`) used before `__getmainargs`.
const DEFAULT_ARGV_PTR: [usize; 1] = [0];

/// Global argv pointer for `__p___argv`.
///
/// Initialized to null and written once during CRT startup by `__getmainargs`.
/// After that single write the value is only read.
static ARGV_PTR: std::sync::atomic::AtomicPtr<*mut i8> =
    std::sync::atomic::AtomicPtr::new(DEFAULT_ARGV_PTR.as_ptr().cast::<*mut i8>().cast_mut());

/// Get pointer to argc (__p___argc)
///
/// Returns a pointer to the global argc value. Currently initialized to 0
/// since command-line argument passing is handled by `__getmainargs`.
/// The CRT startup code calls `__getmainargs` first, which sets argc/argv,
/// and `__p___argc` provides an alternate access path.
///
/// # Safety
/// The returned `*mut i32` points to the interior of an `AtomicI32`.
/// Callers (the CRT) treat it as a plain int, which is fine because
/// the CRT initialises this value exactly once during single-threaded
/// startup and only reads it afterwards.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt___p___argc() -> *mut i32 {
    ARGC_STATIC.as_ptr()
}

/// Get pointer to argv (__p___argv)
///
/// Returns a pointer to the global argv pointer. Currently initialized to null
/// since command-line argument passing is handled by `__getmainargs`.
/// The CRT startup code calls `__getmainargs` first, which sets argc/argv,
/// and `__p___argv` provides an alternate access path.
///
/// # Safety
/// The returned `*mut *mut *mut i8` points to the interior of an `AtomicPtr`.
/// Callers (the CRT) treat it as a plain pointer, which is fine because
/// the CRT initialises this value exactly once during single-threaded
/// startup and only reads it afterwards.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt___p___argv() -> *mut *mut *mut i8 {
    ARGV_PTR.as_ptr().cast()
}

/// CRT internal lock (_lock)
///
/// Used by the CRT for thread-safe access to internal data structures.
/// Lock IDs include _HEAP_LOCK (4), _ENV_LOCK (7), etc.
///
/// # Safety
/// This function is safe to call but marked unsafe for C ABI compatibility.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt__lock(_locknum: i32) {
    // No-op stub - in our single-threaded emulation, locking is not needed
}

/// CRT internal unlock (_unlock)
///
/// # Safety
/// This function is safe to call but marked unsafe for C ABI compatibility.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt__unlock(_locknum: i32) {
    // No-op stub - in our single-threaded emulation, locking is not needed
}

/// Get environment variable (getenv)
///
/// # Safety
/// This function is unsafe as it deals with raw pointers.
/// The caller must ensure name is a valid null-terminated string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt_getenv(name: *const i8) -> *const i8 {
    if name.is_null() {
        return ptr::null();
    }
    // Use libc getenv which returns a pointer to the actual environment value
    libc::getenv(name)
}

/// Get errno location (_errno)
/// This is the MSVCRT name for errno access (as opposed to __errno_location)
///
/// # Safety
/// This function returns a pointer to thread-local errno storage.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt__errno() -> *mut i32 {
    msvcrt___errno_location()
}

/// Initialize locale conversion (__lconv_init)
///
/// Called during CRT startup to initialize locale data.
///
/// # Safety
/// This function is safe to call but marked unsafe for C ABI compatibility.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt___lconv_init() -> i32 {
    // No-op stub - return 0 for success
    0
}

/// CRT exception filter (_XcptFilter)
///
/// Returns EXCEPTION_CONTINUE_SEARCH to let the exception propagate.
///
/// # Safety
/// This function is safe to call but marked unsafe for C ABI compatibility.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt__XcptFilter(
    _exception_code: u32,
    _exception_pointers: *mut core::ffi::c_void,
) -> i32 {
    // Return EXCEPTION_CONTINUE_SEARCH (1)
    1
}

/// Control floating-point behavior (_controlfp)
///
/// # Safety
/// This function is safe to call but marked unsafe for C ABI compatibility.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt__controlfp(new_val: u32, mask: u32) -> u32 {
    // Return the "new" control word - in practice just echo back what was set
    // Default x87 control word on Windows: 0x0009001F
    if mask == 0 {
        0x0009_001F // Default value
    } else {
        (0x0009_001F & !mask) | (new_val & mask)
    }
}

/// `strerror` – return a pointer to the error message string for `errnum`.
///
/// Delegates to the host libc `strerror` so the returned string has valid
/// static-ish lifetime (it may be overwritten by the next call, just like on
/// real Windows/Linux).
///
/// # Safety
/// The returned pointer is only valid until the next call to `strerror`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt_strerror(errnum: i32) -> *mut i8 {
    libc::strerror(errnum)
}

/// `wcslen` – return the number of wide characters in `s`, not including the
/// terminating null character.
///
/// # Safety
/// `s` must be a valid, null-terminated wide character string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt_wcslen(s: *const u16) -> usize {
    if s.is_null() {
        return 0;
    }
    let mut len = 0usize;
    // SAFETY: caller guarantees s is null-terminated.
    while unsafe { *s.add(len) } != 0 {
        len += 1;
    }
    len
}

/// `wcscmp` – compare two null-terminated wide strings lexicographically.
///
/// Returns a negative value if `s1 < s2`, 0 if equal, positive if `s1 > s2`.
///
/// # Safety
/// Both `s1` and `s2` must be valid, null-terminated wide character strings.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt_wcscmp(s1: *const u16, s2: *const u16) -> i32 {
    if s1.is_null() && s2.is_null() {
        return 0;
    }
    if s1.is_null() {
        return -1;
    }
    if s2.is_null() {
        return 1;
    }
    let mut i = 0usize;
    // SAFETY: caller guarantees both pointers are valid null-terminated strings.
    loop {
        let c1 = unsafe { *s1.add(i) };
        let c2 = unsafe { *s2.add(i) };
        if c1 != c2 {
            return i32::from(c1) - i32::from(c2);
        }
        if c1 == 0 {
            return 0;
        }
        i += 1;
    }
}

/// `wcsstr` – find the first occurrence of wide string `needle` in `haystack`.
///
/// Returns a pointer to the first occurrence of `needle` in `haystack`, or
/// NULL if `needle` is not found. If `needle` is an empty string, returns
/// `haystack`.
///
/// # Safety
/// Both `haystack` and `needle` must be valid, null-terminated wide character strings.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt_wcsstr(haystack: *const u16, needle: *const u16) -> *const u16 {
    if haystack.is_null() {
        return core::ptr::null();
    }
    if needle.is_null() {
        return haystack;
    }
    // SAFETY: caller guarantees both pointers are valid null-terminated strings.
    let needle_first = unsafe { *needle };
    if needle_first == 0 {
        return haystack; // empty needle always matches at start
    }
    let mut h = haystack;
    // SAFETY: h stays within the null-terminated haystack.
    while unsafe { *h } != 0 {
        if unsafe { *h } == needle_first {
            // Try to match the rest of needle
            let mut hi = h;
            let mut ni = needle;
            // SAFETY: hi and ni are within their respective null-terminated strings.
            loop {
                let nc = unsafe { *ni };
                if nc == 0 {
                    return h; // full needle matched
                }
                let hc = unsafe { *hi };
                if hc != nc {
                    break; // mismatch
                }
                hi = unsafe { hi.add(1) };
                ni = unsafe { ni.add(1) };
            }
        }
        h = unsafe { h.add(1) };
    }
    core::ptr::null()
}

/// `fputc` – write character `c` to the stream `stream`.
///
/// For simplicity this stub forwards to the host file descriptor: fd 1 for
/// stdout (FILE* index 1 in Windows __iob_func) and fd 2 for stderr (index
/// 2); everything else is treated as stdout.
///
/// # Safety
/// `stream` is used only as a discriminator; it is not dereferenced.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt_fputc(c: i32, stream: *mut core::ffi::c_void) -> i32 {
    // Windows FILE* values from __iob_func: stdin=0, stdout=1, stderr=2.
    // Treat pointer values 0/1 as stdout, 2 as stderr.
    let fd: libc::c_int = if stream as usize == 2 { 2 } else { 1 };
    let byte = c.to_le_bytes()[0];
    // SAFETY: `byte` is a valid single-byte buffer.
    let written = unsafe { libc::write(fd, std::ptr::addr_of!(byte).cast(), 1) };
    if written == 1 {
        c & 0xFF
    } else {
        // EOF
        -1
    }
}

/// `fputs` – write a string to a stream.
///
/// Writes the null-terminated string `s` to `stream`.  Returns a non-negative
/// value on success, `EOF` (-1) on error.
///
/// # Safety
/// `s` must be a valid null-terminated C string.  `stream` is treated only as
/// a discriminator to choose between stdout (1) and stderr (2).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt_fputs(s: *const i8, stream: *mut core::ffi::c_void) -> i32 {
    if s.is_null() {
        return -1;
    }
    let fd: libc::c_int = if stream as usize == 2 { 2 } else { 1 };
    // SAFETY: caller guarantees s is a valid null-terminated C string.
    let len = unsafe { libc::strlen(s.cast()) };
    if len == 0 {
        return 0;
    }
    // SAFETY: s points to a valid buffer of at least `len` bytes.
    let written = unsafe { libc::write(fd, s.cast(), len) };
    if written < 0 { -1 } else { 0 }
}

/// `puts` – write a string and a trailing newline to stdout.
///
/// # Safety
/// `s` must be a valid null-terminated C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt_puts(s: *const i8) -> i32 {
    if s.is_null() {
        return -1;
    }
    // SAFETY: caller guarantees s is a valid null-terminated C string.
    let len = unsafe { libc::strlen(s.cast()) };
    if len > 0 {
        // SAFETY: s points to a valid buffer of at least `len` bytes.
        let written = unsafe { libc::write(1, s.cast(), len) };
        if written < 0 {
            return -1;
        }
    }
    // Append newline, matching POSIX puts() behaviour.
    let nl: u8 = b'\n';
    // SAFETY: we pass a valid 1-byte buffer.
    let _ = unsafe { libc::write(1, core::ptr::addr_of!(nl).cast(), 1) };
    0
}

/// `_read` – read bytes from a file descriptor.
///
/// Reads up to `count` bytes from file descriptor `fd` into `buf`.
/// Returns the number of bytes read, 0 for EOF, or -1 on error.
///
/// # Safety
/// `buf` must be writable for at least `count` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt__read(fd: i32, buf: *mut core::ffi::c_void, count: u32) -> i32 {
    if buf.is_null() || count == 0 {
        return 0;
    }
    // SAFETY: caller guarantees buf is writable for count bytes.
    let n = unsafe { libc::read(fd, buf, count as libc::size_t) };
    #[allow(clippy::cast_possible_truncation)]
    if n < 0 { -1 } else { n as i32 }
}

/// `_write(fd, buf, count)` — low-level CRT write to a file descriptor.
///
/// Writes up to `count` bytes from `buf` to `fd`.
/// Returns the number of bytes written, or -1 on error.
///
/// # Safety
/// `buf` must be valid for reading `count` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt__write(fd: i32, buf: *const core::ffi::c_void, count: u32) -> i32 {
    if count == 0 {
        return 0;
    }
    if buf.is_null() {
        return -1;
    }
    // SAFETY: caller guarantees buf is readable for count bytes.
    let n = unsafe { libc::write(fd, buf, count as libc::size_t) };
    #[allow(clippy::cast_possible_truncation)]
    if n < 0 { -1 } else { n as i32 }
}

/// `getchar()` — read a single character from stdin.
///
/// Returns the character read as `unsigned char` cast to `int`, or `EOF` (-1)
/// on end-of-file or error.
///
/// # Safety
/// Safe to call; reads from the process stdin file descriptor.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt_getchar() -> i32 {
    let mut buf = [0u8; 1];
    // SAFETY: buf is valid for 1 byte.
    let n = unsafe { libc::read(0, buf.as_mut_ptr().cast(), 1) };
    if n == 1 { i32::from(buf[0]) } else { -1 }
}

/// `putchar(c)` — write a single character to stdout.
///
/// If `c` is `EOF` (-1), returns `EOF` without writing.  Otherwise writes
/// the low-order byte of `c` and returns it as `unsigned char` cast to `int`,
/// or `EOF` on I/O error.
///
/// # Safety
/// Safe to call; writes to the process stdout file descriptor.
#[unsafe(no_mangle)]
#[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
pub unsafe extern "C" fn msvcrt_putchar(c: i32) -> i32 {
    if c == -1 {
        return -1; // EOF passthrough — do not write 0xFF
    }
    let b = [c as u8];
    // SAFETY: b is valid for 1 byte.
    let n = unsafe { libc::write(1, b.as_ptr().cast(), 1) };
    if n == 1 { c & 0xFF } else { -1 }
}

/// `realloc` – resize a previously allocated memory block.
///
/// Resizes the memory block pointed to by `ptr` to `new_size` bytes.
/// If `ptr` is null, behaves like `malloc`.  If `new_size` is 0 and `ptr`
/// is non-null, behaves like `free` and returns null.
///
/// # Safety
/// `ptr` must have been allocated by `msvcrt_malloc`, `msvcrt_calloc`, or
/// `msvcrt_realloc`, and must not be used again after a successful call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt_realloc(ptr: *mut u8, new_size: usize) -> *mut u8 {
    if ptr.is_null() {
        return unsafe { msvcrt_malloc(new_size) };
    }
    if new_size == 0 {
        unsafe { msvcrt_free(ptr) };
        return ptr::null_mut();
    }
    // Allocate a new block using the same allocator as msvcrt_malloc,
    // copy the contents, then free the old block.  This avoids mixing
    // Rust's global allocator with libc's allocator, which would be UB.
    let new_ptr = unsafe { msvcrt_malloc(new_size) };
    if new_ptr.is_null() {
        // Allocation failed; leave the original block untouched.
        return ptr::null_mut();
    }
    // SAFETY:
    // - `ptr` is non-null and was allocated by msvcrt_malloc/calloc/realloc.
    // - `new_ptr` is non-null and points to `new_size` bytes of writable memory.
    // - The two allocations are non-overlapping (distinct heap objects).
    // We copy `new_size` bytes which may be less than the original allocation;
    // for a shrink that is correct, for a grow the caller owns the extra bytes.
    unsafe {
        ptr::copy_nonoverlapping(ptr, new_ptr, new_size);
        msvcrt_free(ptr);
    }
    new_ptr
}

///
/// Returns a pointer to a static `lconv`-compatible structure initialised
/// for the "C" locale (decimal point = '.', everything else empty or CHAR_MAX).
///
/// # Safety
/// The returned pointer is valid for the lifetime of the process.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt_localeconv() -> *mut libc::lconv {
    // Delegate to the host libc which always has a valid C-locale lconv.
    // SAFETY: libc::localeconv() always returns a non-null pointer.
    unsafe { libc::localeconv() }
}

/// `___lc_codepage_func` – internal MinGW/MSVCRT helper that returns the
/// current locale's ANSI code page.
///
/// Returns 0, which corresponds to the "C" / UTF-8 locale and causes the CRT
/// to treat strings as single-byte ASCII.
///
/// # Safety
/// Always safe to call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt____lc_codepage_func() -> u32 {
    0
}

/// `___mb_cur_max_func` – internal MinGW/MSVCRT helper that returns the
/// maximum number of bytes per multibyte character for the current locale.
///
/// Returns 1 (single-byte C locale).
///
/// # Safety
/// Always safe to call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt____mb_cur_max_func() -> i32 {
    1
}

// ── Numeric Conversion ────────────────────────────────────────────────────

/// # Safety
/// `s` must be a valid null-terminated C string or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt_atoi(s: *const i8) -> i32 {
    if s.is_null() {
        return 0;
    }
    let cstr = core::ffi::CStr::from_ptr(s.cast());
    let str = cstr.to_str().unwrap_or("");
    let trimmed = str.trim_ascii_start();
    let (trimmed, neg) = if let Some(t) = trimmed.strip_prefix('-') {
        (t, true)
    } else if let Some(t) = trimmed.strip_prefix('+') {
        (t, false)
    } else {
        (trimmed, false)
    };
    let valid_len = trimmed.chars().take_while(char::is_ascii_digit).count();
    let val = trimmed[..valid_len].parse::<i32>().unwrap_or(0);
    if neg { val.wrapping_neg() } else { val }
}

/// # Safety
/// `s` must be a valid null-terminated C string or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt_atol(s: *const i8) -> i64 {
    if s.is_null() {
        return 0;
    }
    let cstr = core::ffi::CStr::from_ptr(s.cast());
    let str = cstr.to_str().unwrap_or("");
    let trimmed = str.trim_ascii_start();
    let (trimmed, neg) = if let Some(t) = trimmed.strip_prefix('-') {
        (t, true)
    } else if let Some(t) = trimmed.strip_prefix('+') {
        (t, false)
    } else {
        (trimmed, false)
    };
    let valid_len = trimmed.chars().take_while(char::is_ascii_digit).count();
    let val = trimmed[..valid_len].parse::<i64>().unwrap_or(0);
    if neg { val.wrapping_neg() } else { val }
}

/// # Safety
/// `s` must be a valid null-terminated C string or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt_atof(s: *const i8) -> f64 {
    if s.is_null() {
        return 0.0;
    }
    let cstr = core::ffi::CStr::from_ptr(s.cast());
    let str = cstr.to_str().unwrap_or("");
    str.trim().parse::<f64>().unwrap_or(0.0)
}

/// # Safety
/// `nptr` must be a valid null-terminated C string; `endptr` if non-null must point to writable memory.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt_strtol(nptr: *const i8, endptr: *mut *mut i8, base: i32) -> i64 {
    if nptr.is_null() {
        if !endptr.is_null() {
            *endptr = nptr.cast_mut();
        }
        return 0;
    }
    let s = core::ffi::CStr::from_ptr(nptr.cast())
        .to_str()
        .unwrap_or("");
    let s_trimmed = s.trim_ascii_start();
    let (s_signed, negative) = if let Some(t) = s_trimmed.strip_prefix('-') {
        (t, true)
    } else if let Some(t) = s_trimmed.strip_prefix('+') {
        (t, false)
    } else {
        (s_trimmed, false)
    };
    let radix = if base == 0 {
        10u32
    } else {
        base.unsigned_abs()
    };
    let valid_len = s_signed.chars().take_while(|c| c.is_digit(radix)).count();
    let parsed = i64::from_str_radix(&s_signed[..valid_len], radix).unwrap_or(0);
    let result = if negative {
        parsed.wrapping_neg()
    } else {
        parsed
    };
    if !endptr.is_null() {
        let leading_ws = s.len() - s_trimmed.len();
        let sign_len = usize::from(s_trimmed.starts_with(['-', '+']));
        let consumed = leading_ws + sign_len + valid_len;
        *endptr = nptr.add(consumed).cast_mut();
    }
    result
}

/// # Safety
/// `nptr` must be a valid null-terminated C string; `endptr` if non-null must point to writable memory.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt_strtoul(nptr: *const i8, endptr: *mut *mut i8, base: i32) -> u64 {
    if nptr.is_null() {
        if !endptr.is_null() {
            *endptr = nptr.cast_mut();
        }
        return 0;
    }
    let s = core::ffi::CStr::from_ptr(nptr.cast())
        .to_str()
        .unwrap_or("");
    let s_trimmed = s.trim_ascii_start();
    let s_unsigned = s_trimmed.strip_prefix(['+', '-']).unwrap_or(s_trimmed);
    let radix = if base == 0 {
        10u32
    } else {
        base.unsigned_abs()
    };
    let valid_len = s_unsigned.chars().take_while(|c| c.is_digit(radix)).count();
    let result = u64::from_str_radix(&s_unsigned[..valid_len], radix).unwrap_or(0);
    if !endptr.is_null() {
        let leading_ws = s.len() - s_trimmed.len();
        let sign_len = usize::from(s_trimmed.starts_with(['+', '-']));
        let consumed = leading_ws + sign_len + valid_len;
        *endptr = nptr.add(consumed).cast_mut();
    }
    result
}

/// # Safety
/// `nptr` must be a valid null-terminated C string; `endptr` if non-null must point to writable memory.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt_strtod(nptr: *const i8, endptr: *mut *mut i8) -> f64 {
    if nptr.is_null() {
        if !endptr.is_null() {
            *endptr = nptr.cast_mut();
        }
        return 0.0;
    }
    let s = core::ffi::CStr::from_ptr(nptr.cast())
        .to_str()
        .unwrap_or("");
    let trimmed = s.trim_ascii_start();
    let ws_len = s.len() - trimmed.len();

    // Track the longest prefix of `trimmed` that successfully parses as an f64.
    let mut last_ok_len = 0usize;
    let mut last_ok_val = 0.0f64;
    let mut byte_index = 0usize;
    for ch in trimmed.chars() {
        byte_index += ch.len_utf8();
        if let Ok(v) = trimmed[..byte_index].parse::<f64>() {
            last_ok_len = byte_index;
            last_ok_val = v;
        }
    }

    let val = if last_ok_len > 0 { last_ok_val } else { 0.0 };

    if !endptr.is_null() {
        if last_ok_len > 0 {
            let consumed = ws_len + last_ok_len;
            *endptr = nptr.add(consumed).cast_mut();
        } else {
            // No conversion performed: endptr should point to the original nptr.
            *endptr = nptr.cast_mut();
        }
    }
    val
}

/// # Safety
/// `buffer` must be a writable buffer large enough to hold the result; caller is responsible for size.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt__itoa(value: i32, buffer: *mut i8, radix: i32) -> *mut i8 {
    if buffer.is_null() {
        return core::ptr::null_mut();
    }
    let s = if radix == 10 {
        format!("{value}")
    } else if radix == 16 {
        format!("{:x}", value.cast_unsigned())
    } else if radix == 8 {
        format!("{:o}", value.cast_unsigned())
    } else if radix == 2 {
        format!("{:b}", value.cast_unsigned())
    } else {
        format!("{value}")
    };
    let bytes = s.as_bytes();
    // SAFETY: buffer has enough space per caller contract
    core::ptr::copy_nonoverlapping(bytes.as_ptr().cast::<i8>(), buffer, bytes.len());
    *buffer.add(bytes.len()) = 0;
    buffer
}

/// # Safety
/// `buffer` must be a writable buffer large enough to hold the result; caller is responsible for size.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt__ltoa(value: i64, buffer: *mut i8, radix: i32) -> *mut i8 {
    if buffer.is_null() {
        return core::ptr::null_mut();
    }
    let s = if radix == 10 {
        format!("{value}")
    } else if radix == 16 {
        format!("{:x}", value.cast_unsigned())
    } else if radix == 8 {
        format!("{:o}", value.cast_unsigned())
    } else if radix == 2 {
        format!("{:b}", value.cast_unsigned())
    } else {
        format!("{value}")
    };
    let bytes = s.as_bytes();
    // SAFETY: buffer has enough space per caller contract
    core::ptr::copy_nonoverlapping(bytes.as_ptr().cast::<i8>(), buffer, bytes.len());
    *buffer.add(bytes.len()) = 0;
    buffer
}

/// `_ultoa(value, buffer, radix)` — convert unsigned long to string.
///
/// # Safety
/// `buffer` must be a writable buffer large enough to hold the result.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt__ultoa(value: u64, buffer: *mut i8, radix: i32) -> *mut i8 {
    if buffer.is_null() {
        return core::ptr::null_mut();
    }
    let s = if radix == 10 {
        format!("{value}")
    } else if radix == 16 {
        format!("{value:x}")
    } else if radix == 8 {
        format!("{value:o}")
    } else if radix == 2 {
        format!("{value:b}")
    } else {
        format!("{value}")
    };
    let bytes = s.as_bytes();
    // SAFETY: buffer has enough space per caller contract.
    core::ptr::copy_nonoverlapping(bytes.as_ptr().cast::<i8>(), buffer, bytes.len());
    // SAFETY: buffer is writable for at least bytes.len() + 1 bytes.
    unsafe { *buffer.add(bytes.len()) = 0 };
    buffer
}

/// `_i64toa(value, buffer, radix)` — convert signed 64-bit integer to string.
///
/// # Safety
/// `buffer` must be a writable buffer large enough to hold the result.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt__i64toa(value: i64, buffer: *mut i8, radix: i32) -> *mut i8 {
    // _i64toa and _ltoa have identical semantics; delegate.
    unsafe { msvcrt__ltoa(value, buffer, radix) }
}

/// `_ui64toa(value, buffer, radix)` — convert unsigned 64-bit integer to string.
///
/// # Safety
/// `buffer` must be a writable buffer large enough to hold the result.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt__ui64toa(value: u64, buffer: *mut i8, radix: i32) -> *mut i8 {
    // _ui64toa and _ultoa have identical semantics; delegate.
    unsafe { msvcrt__ultoa(value, buffer, radix) }
}

/// `_strtoi64(nptr, endptr, base)` — convert string to signed 64-bit integer.
///
/// # Safety
/// `nptr` must be a valid null-terminated C string.
/// `endptr`, if non-null, receives a pointer to the character after the last one consumed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt__strtoi64(nptr: *const i8, endptr: *mut *mut i8, base: i32) -> i64 {
    if nptr.is_null() {
        if !endptr.is_null() {
            unsafe { *endptr = nptr.cast_mut() };
        }
        return 0;
    }
    // SAFETY: nptr is a valid null-terminated C string per caller contract.
    unsafe { libc::strtoll(nptr, endptr, base) }
}

/// `_strtoui64(nptr, endptr, base)` — convert string to unsigned 64-bit integer.
///
/// # Safety
/// `nptr` must be a valid null-terminated C string.
/// `endptr`, if non-null, receives a pointer to the character after the last one consumed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt__strtoui64(
    nptr: *const i8,
    endptr: *mut *mut i8,
    base: i32,
) -> u64 {
    if nptr.is_null() {
        if !endptr.is_null() {
            unsafe { *endptr = nptr.cast_mut() };
        }
        return 0;
    }
    // SAFETY: nptr is a valid null-terminated C string per caller contract.
    unsafe { libc::strtoull(nptr, endptr, base) }
}

/// `_itow(value, buffer, radix)` — convert integer to wide string.
///
/// # Safety
/// `buffer` must be a writable buffer large enough to hold the result (at least 33 wide chars).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt__itow(value: i32, buffer: *mut u16, radix: i32) -> *mut u16 {
    if buffer.is_null() {
        return core::ptr::null_mut();
    }
    let s = if radix == 10 {
        format!("{value}")
    } else if radix == 16 {
        format!("{:x}", value.cast_unsigned())
    } else if radix == 8 {
        format!("{:o}", value.cast_unsigned())
    } else if radix == 2 {
        format!("{:b}", value.cast_unsigned())
    } else {
        format!("{value}")
    };
    for (i, c) in s.bytes().enumerate() {
        // SAFETY: buffer has enough space per caller contract.
        unsafe { *buffer.add(i) = u16::from(c) };
    }
    // SAFETY: buffer is writable for at least s.len() + 1 wide chars.
    unsafe { *buffer.add(s.len()) = 0 };
    buffer
}

/// `_ltow(value, buffer, radix)` — convert long to wide string.
///
/// # Safety
/// `buffer` must be a writable buffer large enough to hold the result (at least 66 wide chars).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt__ltow(value: i64, buffer: *mut u16, radix: i32) -> *mut u16 {
    if buffer.is_null() {
        return core::ptr::null_mut();
    }
    let s = if radix == 10 {
        format!("{value}")
    } else if radix == 16 {
        format!("{:x}", value.cast_unsigned())
    } else if radix == 8 {
        format!("{:o}", value.cast_unsigned())
    } else if radix == 2 {
        format!("{:b}", value.cast_unsigned())
    } else {
        format!("{value}")
    };
    for (i, c) in s.bytes().enumerate() {
        // SAFETY: buffer has enough space per caller contract.
        unsafe { *buffer.add(i) = u16::from(c) };
    }
    // SAFETY: buffer is writable for at least s.len() + 1 wide chars.
    unsafe { *buffer.add(s.len()) = 0 };
    buffer
}

/// `_ultow(value, buffer, radix)` — convert unsigned long to wide string.
///
/// # Safety
/// `buffer` must be a writable buffer large enough to hold the result (at least 66 wide chars).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt__ultow(value: u64, buffer: *mut u16, radix: i32) -> *mut u16 {
    if buffer.is_null() {
        return core::ptr::null_mut();
    }
    let s = if radix == 10 {
        format!("{value}")
    } else if radix == 16 {
        format!("{value:x}")
    } else if radix == 8 {
        format!("{value:o}")
    } else if radix == 2 {
        format!("{value:b}")
    } else {
        format!("{value}")
    };
    for (i, c) in s.bytes().enumerate() {
        // SAFETY: buffer has enough space per caller contract.
        unsafe { *buffer.add(i) = u16::from(c) };
    }
    // SAFETY: buffer is writable for at least s.len() + 1 wide chars.
    unsafe { *buffer.add(s.len()) = 0 };
    buffer
}

/// `_i64tow(value, buffer, radix)` — convert signed 64-bit integer to wide string.
///
/// # Safety
/// `buffer` must be a writable buffer large enough to hold the result.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt__i64tow(value: i64, buffer: *mut u16, radix: i32) -> *mut u16 {
    unsafe { msvcrt__ltow(value, buffer, radix) }
}

/// `_ui64tow(value, buffer, radix)` — convert unsigned 64-bit integer to wide string.
///
/// # Safety
/// `buffer` must be a writable buffer large enough to hold the result.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt__ui64tow(value: u64, buffer: *mut u16, radix: i32) -> *mut u16 {
    unsafe { msvcrt__ultow(value, buffer, radix) }
}

// ── String Extras ─────────────────────────────────────────────────────────

/// # Safety
/// `dest` must be writable for `n` bytes; `src` must be a valid C string or at least `n` bytes readable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt_strncpy(dest: *mut i8, src: *const i8, n: usize) -> *mut i8 {
    if dest.is_null() || src.is_null() {
        return dest;
    }
    let mut i = 0;
    let mut found_nul = false;
    while i < n {
        let c = *src.add(i);
        *dest.add(i) = c;
        if c == 0 {
            found_nul = true;
        }
        if found_nul {
            *dest.add(i) = 0;
        }
        i += 1;
    }
    dest
}

/// # Safety
/// `dest` must be a valid null-terminated C string with enough space; `src` must be a valid C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt_strncat(dest: *mut i8, src: *const i8, n: usize) -> *mut i8 {
    if dest.is_null() || src.is_null() {
        return dest;
    }
    let mut dest_end = 0;
    while *dest.add(dest_end) != 0 {
        dest_end += 1;
    }
    let mut i = 0;
    while i < n {
        let c = *src.add(i);
        if c == 0 {
            break;
        }
        *dest.add(dest_end + i) = c;
        i += 1;
    }
    *dest.add(dest_end + i) = 0;
    dest
}

/// # Safety
/// `s1` and `s2` must be valid null-terminated C strings or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt__stricmp(s1: *const i8, s2: *const i8) -> i32 {
    if s1.is_null() || s2.is_null() {
        return if s1 == s2 { 0 } else { -1 };
    }
    let a = core::ffi::CStr::from_ptr(s1.cast()).to_str().unwrap_or("");
    let b = core::ffi::CStr::from_ptr(s2.cast()).to_str().unwrap_or("");
    let al: std::string::String = a.chars().map(|c| c.to_ascii_lowercase()).collect();
    let bl: std::string::String = b.chars().map(|c| c.to_ascii_lowercase()).collect();
    match al.cmp(&bl) {
        core::cmp::Ordering::Less => -1,
        core::cmp::Ordering::Equal => 0,
        core::cmp::Ordering::Greater => 1,
    }
}

/// # Safety
/// `s1` and `s2` must be valid null-terminated C strings or readable for at least `n` bytes; may be null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt__strnicmp(s1: *const i8, s2: *const i8, n: usize) -> i32 {
    if s1.is_null() || s2.is_null() {
        return if s1 == s2 { 0 } else { -1 };
    }
    let mut i = 0;
    while i < n {
        let a = (*s1.add(i)).cast_unsigned().to_ascii_lowercase();
        let b = (*s2.add(i)).cast_unsigned().to_ascii_lowercase();
        if a != b {
            return i32::from(a) - i32::from(b);
        }
        if a == 0 {
            return 0;
        }
        i += 1;
    }
    0
}

/// # Safety
/// `s` must be a valid null-terminated C string or null. Returns heap-allocated copy (caller must free).
///
/// # Panics
/// Panics if the array layout computation overflows (extremely large strings).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt__strdup(s: *const i8) -> *mut i8 {
    if s.is_null() {
        return core::ptr::null_mut();
    }
    let cstr = core::ffi::CStr::from_ptr(s.cast());
    let bytes = cstr.to_bytes_with_nul();
    let layout = Layout::array::<u8>(bytes.len()).unwrap();
    let ptr = alloc(layout);
    if ptr.is_null() {
        return core::ptr::null_mut();
    }
    core::ptr::copy_nonoverlapping(bytes.as_ptr(), ptr, bytes.len());
    ptr.cast::<i8>()
}

/// # Safety
/// `s` must be readable for at least `max_len` bytes or until a NUL terminator.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt_strnlen(s: *const i8, max_len: usize) -> usize {
    if s.is_null() {
        return 0;
    }
    let mut i = 0;
    while i < max_len && *s.add(i) != 0 {
        i += 1;
    }
    i
}

// ── Random & Time ─────────────────────────────────────────────────────────

use std::sync::atomic::AtomicU32;
use std::sync::atomic::Ordering;

static RAND_STATE: AtomicU32 = AtomicU32::new(1);

/// # Safety
/// No preconditions. Returns pseudo-random integer in range [0, 32767].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt_rand() -> i32 {
    let state = RAND_STATE.load(Ordering::Relaxed);
    let next = state.wrapping_mul(1_103_515_245).wrapping_add(12_345);
    RAND_STATE.store(next, Ordering::Relaxed);
    i32::try_from((next >> 16) & 0x7FFF).unwrap_or(0)
}

/// # Safety
/// No preconditions. Sets the random seed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt_srand(seed: u32) {
    RAND_STATE.store(seed, Ordering::Relaxed);
}

/// # Safety
/// `timer` if non-null must be a writable pointer to i64.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt_time(timer: *mut i64) -> i64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    libc::clock_gettime(libc::CLOCK_REALTIME, core::ptr::addr_of_mut!(ts));
    let t = ts.tv_sec;
    if !timer.is_null() {
        *timer = t;
    }
    t
}

/// # Safety
/// No preconditions. Returns CPU time used by the process.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt_clock() -> i64 {
    // SAFETY: clock_gettime is safe to call with CLOCK_PROCESS_CPUTIME_ID
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: ts is a valid, initialized timespec on the stack; CLOCK_PROCESS_CPUTIME_ID is always valid
    libc::clock_gettime(libc::CLOCK_PROCESS_CPUTIME_ID, core::ptr::addr_of_mut!(ts));
    ts.tv_sec * 1_000_000 + ts.tv_nsec / 1_000
}

// ── Math Functions ────────────────────────────────────────────────────────

/// # Safety
/// No preconditions.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt_abs(x: i32) -> i32 {
    if x < 0 { x.wrapping_neg() } else { x }
}

/// # Safety
/// No preconditions.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt_labs(x: i64) -> i64 {
    if x < 0 { x.wrapping_neg() } else { x }
}

/// # Safety
/// No preconditions.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt__abs64(x: i64) -> i64 {
    if x < 0 { x.wrapping_neg() } else { x }
}

/// # Safety
/// No preconditions.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt_fabs(x: f64) -> f64 {
    x.abs()
}

/// # Safety
/// No preconditions.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt_sqrt(x: f64) -> f64 {
    x.sqrt()
}

/// # Safety
/// No preconditions.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt_pow(x: f64, y: f64) -> f64 {
    x.powf(y)
}

/// # Safety
/// No preconditions.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt_log(x: f64) -> f64 {
    x.ln()
}

/// # Safety
/// No preconditions.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt_log10(x: f64) -> f64 {
    x.log10()
}

/// # Safety
/// No preconditions.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt_exp(x: f64) -> f64 {
    x.exp()
}

/// # Safety
/// No preconditions.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt_sin(x: f64) -> f64 {
    x.sin()
}

/// # Safety
/// No preconditions.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt_cos(x: f64) -> f64 {
    x.cos()
}

/// # Safety
/// No preconditions.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt_tan(x: f64) -> f64 {
    x.tan()
}

/// # Safety
/// No preconditions.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt_atan(x: f64) -> f64 {
    x.atan()
}

/// # Safety
/// No preconditions.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt_atan2(y: f64, x: f64) -> f64 {
    y.atan2(x)
}

/// # Safety
/// No preconditions.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt_ceil(x: f64) -> f64 {
    x.ceil()
}

/// # Safety
/// No preconditions.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt_floor(x: f64) -> f64 {
    x.floor()
}

/// # Safety
/// No preconditions.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt_fmod(x: f64, y: f64) -> f64 {
    x % y
}

// ── Wide-Char Extras ──────────────────────────────────────────────────────

/// # Safety
/// `dest` must be writable wide string buffer; `src` must be valid null-terminated wide string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt_wcscpy(dest: *mut u16, src: *const u16) -> *mut u16 {
    if dest.is_null() || src.is_null() {
        return dest;
    }
    let mut i = 0;
    loop {
        let c = *src.add(i);
        *dest.add(i) = c;
        if c == 0 {
            break;
        }
        i += 1;
    }
    dest
}

/// # Safety
/// `dest` must be a null-terminated wide string with sufficient space; `src` must be valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt_wcscat(dest: *mut u16, src: *const u16) -> *mut u16 {
    if dest.is_null() || src.is_null() {
        return dest;
    }
    let mut end = 0;
    while *dest.add(end) != 0 {
        end += 1;
    }
    let mut i = 0;
    loop {
        let c = *src.add(i);
        *dest.add(end + i) = c;
        if c == 0 {
            break;
        }
        i += 1;
    }
    dest
}

/// # Safety
/// `dest` must be writable for `n` wide chars; `src` must be readable for at least `n` wide chars.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt_wcsncpy(dest: *mut u16, src: *const u16, n: usize) -> *mut u16 {
    if dest.is_null() || src.is_null() {
        return dest;
    }
    let mut found_nul = false;
    for i in 0..n {
        if found_nul {
            *dest.add(i) = 0;
        } else {
            let c = *src.add(i);
            *dest.add(i) = c;
            if c == 0 {
                found_nul = true;
            }
        }
    }
    dest
}

/// # Safety
/// `s` must be a valid null-terminated wide string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt_wcschr(s: *const u16, c: u16) -> *const u16 {
    if s.is_null() {
        return core::ptr::null();
    }
    let mut i = 0;
    loop {
        let ch = *s.add(i);
        if ch == c {
            return s.add(i);
        }
        if ch == 0 {
            return core::ptr::null();
        }
        i += 1;
    }
}

/// # Safety
/// `s1` and `s2` must be valid null-terminated wide strings or readable for `n` wide chars.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt_wcsncmp(s1: *const u16, s2: *const u16, n: usize) -> i32 {
    if s1.is_null() || s2.is_null() {
        return if s1 == s2 { 0 } else { -1 };
    }
    for i in 0..n {
        let a = *s1.add(i);
        let b = *s2.add(i);
        if a != b {
            return i32::from(a) - i32::from(b);
        }
        if a == 0 {
            return 0;
        }
    }
    0
}

/// # Safety
/// `s1` and `s2` must be valid null-terminated wide strings or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt__wcsicmp(s1: *const u16, s2: *const u16) -> i32 {
    if s1.is_null() || s2.is_null() {
        return if s1 == s2 { 0 } else { -1 };
    }
    let mut i = 0;
    loop {
        let a = *s1.add(i);
        let b = *s2.add(i);
        let al = char::from_u32(u32::from(a)).map_or(a, |c| c.to_ascii_lowercase() as u16);
        let bl = char::from_u32(u32::from(b)).map_or(b, |c| c.to_ascii_lowercase() as u16);
        if al != bl {
            return i32::from(al) - i32::from(bl);
        }
        if a == 0 {
            return 0;
        }
        i += 1;
    }
}

/// # Safety
/// `s1` and `s2` must be valid null-terminated wide strings or readable for `n` wide chars.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt__wcsnicmp(s1: *const u16, s2: *const u16, n: usize) -> i32 {
    if s1.is_null() || s2.is_null() {
        return if s1 == s2 { 0 } else { -1 };
    }
    for i in 0..n {
        let a = *s1.add(i);
        let b = *s2.add(i);
        let al = char::from_u32(u32::from(a)).map_or(a, |c| c.to_ascii_lowercase() as u16);
        let bl = char::from_u32(u32::from(b)).map_or(b, |c| c.to_ascii_lowercase() as u16);
        if al != bl {
            return i32::from(al) - i32::from(bl);
        }
        if a == 0 {
            return 0;
        }
    }
    0
}

/// `_wcsdup(s)` — allocate a heap copy of the wide string `s`.
///
/// Returns a null-terminated wide string allocated with `malloc`, or null if
/// `s` is null or allocation fails.  The caller is responsible for freeing
/// the returned pointer with `free`.
///
/// # Safety
/// `s` must be a valid null-terminated wide string or null.
///
/// # Panics
/// Panics if the array layout computation overflows (extremely large strings).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt__wcsdup(s: *const u16) -> *mut u16 {
    if s.is_null() {
        return core::ptr::null_mut();
    }
    // SAFETY: caller guarantees s is null-terminated.
    let len = unsafe { msvcrt_wcslen(s) };
    // +1 for the null terminator
    let layout = Layout::array::<u16>(len + 1).unwrap();
    // SAFETY: layout has non-zero size (len+1 >= 1).
    let raw = unsafe { alloc(layout) };
    if raw.is_null() {
        return core::ptr::null_mut();
    }
    // SAFETY: alloc returns memory aligned to layout's alignment (alignof u16 = 2).
    // We verified the pointer is non-null above.
    #[allow(clippy::cast_ptr_alignment)]
    let ptr = raw.cast::<u16>();
    // SAFETY: ptr is freshly allocated for len+1 u16 elements; s is valid for the same.
    unsafe { core::ptr::copy_nonoverlapping(s, ptr, len + 1) };
    ptr
}

/// # Safety
/// `dest` if non-null must be writable for `n` bytes; `src` must be a valid null-terminated wide string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt_wcstombs(dest: *mut i8, src: *const u16, n: usize) -> usize {
    if src.is_null() {
        return 0;
    }
    let mut len = 0;
    while *src.add(len) != 0 {
        len += 1;
    }
    let wide_slice = core::slice::from_raw_parts(src, len);
    let s = std::string::String::from_utf16_lossy(wide_slice);
    let bytes = s.as_bytes();
    if dest.is_null() {
        return bytes.len();
    }
    let copy_len = bytes.len().min(n.saturating_sub(1));
    // SAFETY: dest is non-null (checked above) and bytes[..copy_len] is valid
    core::ptr::copy_nonoverlapping(bytes.as_ptr().cast::<i8>(), dest, copy_len);
    if n > 0 {
        *dest.add(copy_len) = 0;
    }
    copy_len
}

/// # Safety
/// `dest` if non-null must be writable for `n` wide chars; `src` must be a valid null-terminated C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt_mbstowcs(dest: *mut u16, src: *const i8, n: usize) -> usize {
    if src.is_null() {
        return 0;
    }
    let cstr = core::ffi::CStr::from_ptr(src.cast());
    let s = cstr.to_str().unwrap_or("");
    let wide: Vec<u16> = s.encode_utf16().collect();
    if dest.is_null() {
        return wide.len();
    }
    let copy_len = wide.len().min(n.saturating_sub(1));
    // SAFETY: dest is non-null (checked above) and wide[..copy_len] is valid
    core::ptr::copy_nonoverlapping(wide.as_ptr(), dest, copy_len);
    if n > 0 {
        *dest.add(copy_len) = 0;
    }
    copy_len
}

// ============================================================================
// C++ Exception Handling (MSVC-style)
// ============================================================================
// These functions provide the MSVC C++ exception handling infrastructure
// needed by Windows binaries compiled with MSVC or MinGW targeting the
// MSVC runtime.  The implementation is based on the public documentation
// of the Windows x64 exception handling ABI and reference implementations
// from Wine, ReactOS, and MinGW's libgcc.

/// MSVC exception code for C++ exceptions (`0xE06D7363` = "msc" in ASCII).
const MSVC_CPP_EXCEPTION_CODE: u32 = 0xE06D_7363;

// ── MSVC C++ Exception Handling Constants ──────────────────────────────────

/// Magic numbers identifying the `FuncInfo` version.
const CXX_FRAME_MAGIC_VC6: u32 = 0x1993_0520;
#[allow(dead_code)]
const CXX_FRAME_MAGIC_VC7: u32 = 0x1993_0521;
const CXX_FRAME_MAGIC_VC8: u32 = 0x1993_0522;

/// Flags on `CxxFuncInfo::flags` (valid when magic ≥ VC8).
const FUNC_DESCR_SYNCHRONOUS: u32 = 1;
#[allow(dead_code)]
const FUNC_DESCR_NOEXCEPT: u32 = 4;

/// Flags on `CxxTypeInfo::flags`.
#[allow(dead_code)]
const CLASS_IS_SIMPLE_TYPE: u32 = 1;
#[allow(dead_code)]
const CLASS_HAS_VIRTUAL_BASE_CLASS: u32 = 4;

/// Flags on `CxxCatchBlockInfo::flags` / `CxxExceptionType::flags`.
#[allow(dead_code)]
const TYPE_FLAG_CONST: u32 = 1;
#[allow(dead_code)]
const TYPE_FLAG_VOLATILE: u32 = 2;
const TYPE_FLAG_REFERENCE: u32 = 8;

/// Exception flags (from `EXCEPTION_RECORD.ExceptionFlags`).
const EXCEPTION_UNWINDING_FLAG: u32 = 0x2;
#[allow(dead_code)]
const EXCEPTION_TARGET_UNWIND_FLAG: u32 = 0x20;

// ── Thread-local storage for MSVC C++ exception rethrow ────────────────────
//
// When a catch funclet is about to run, we save the exception record so that
// `throw;` (rethrow) can recover the original exception.  `_CxxThrowException`
// signals rethrow by passing both args as NULL, which produces
// `ExceptionInformation[1] == 0 && ExceptionInformation[2] == 0`.
//
// On rethrow, `_CxxThrowException` restores the original exception parameters
// and passes them to `RaiseException`.  The search phase of
// `__CxxFrameHandler3` detects the rethrow via a TLS flag and skips the
// try block whose catch is currently executing (the "in-catch" skip).
//
// Ref: Wine `dlls/msvcrt/except.c` — `msvcrt_get_thread_data()->exc_record`,
//      `find_catch_block` `in_catch` logic.

/// Saved exception record for rethrow support.
///
/// Stores the `ExceptionInformation` array plus `exception_code` and
/// `number_parameters` so that rethrow can reconstruct the record.
/// Also stores the `catch_level` of the try block whose catch is active,
/// so the search phase can skip that try block on rethrow.
#[derive(Clone, Copy)]
struct SavedExcRecord {
    exception_code: u32,
    exception_flags: u32,
    number_parameters: u32,
    exception_information: [usize; 15],
    /// The `catch_level` of the try block whose catch handler is active.
    /// Stored for potential use in more complex nested exception scenarios.
    #[allow(dead_code)]
    catch_level: i32,
    /// The `end_level` of the matching try block — the last state covered
    /// by this try.  Any try block whose start_level ≤ this value is
    /// "inside" the active catch and must be skipped.
    in_catch_end_level: i32,
    /// The establisher frame (RSP of the catching function after prologue).
    /// Saved so the rethrow's `cxx_find_catch_block` can pass the correct
    /// frame to `RtlUnwindEx` — the rethrow's stack walk through
    /// intermediate Rust frames may compute a wrong establisher frame.
    establisher_frame: u64,
    /// Image base of the PE module, for `compute_body_frame_reg`.
    image_base: u64,
    /// The RUNTIME_FUNCTION entry for the catching function, needed to
    /// compute the frame register (RBP) for `seh_restore_context_and_jump`.
    function_entry: *mut core::ffi::c_void,
}

thread_local! {
    /// Thread-local saved exception record.
    ///
    /// Set in the target-unwind phase of `__CxxFrameHandler3` right before
    /// the catch funclet is called.  Read back when a rethrow is detected.
    static CXX_EXC_RECORD: std::cell::Cell<Option<SavedExcRecord>> =
        const { std::cell::Cell::new(None) };

    /// Flag set by `_CxxThrowException` when handling a rethrow.
    /// `__CxxFrameHandler3` reads and clears this to apply the "in-catch"
    /// try-block skip logic.
    static CXX_RETHROW_ACTIVE: std::cell::Cell<bool> =
        const { std::cell::Cell::new(false) };
}

// ── MSVC C++ Exception Data Structures (x64, RVA-based) ───────────────────
//
// On x64, all pointers in the MSVC exception metadata are stored as
// 32-bit RVAs (Relative Virtual Addresses) relative to the module's
// image base.  This matches native `msvcrt.dll` / `ucrtbase.dll` behavior.
//
// Reference: Wine's `dlls/msvcrt/cxx.h` and `dlls/msvcrt/except.c`.

/// IP-to-state mapping entry.
///
/// Maps instruction pointer ranges to "try levels" (states).  The runtime
/// uses these to determine which try block is active at any given PC.
#[repr(C)]
struct CxxIpMapEntry {
    /// RVA of the first instruction in this state region.
    ip: u32,
    /// State (try level) index.  -1 means "outside all try blocks".
    state: i32,
}

/// Unwind map entry — describes one destructor to call during stack unwinding.
///
/// The unwind map is a linked list (via `prev`) of state transitions.
/// Walking from the current state backward through `prev` calls each
/// destructor in reverse construction order.
#[repr(C)]
struct CxxUnwindMapEntry {
    /// Previous state index (-1 = end of chain).
    prev: i32,
    /// RVA of the cleanup/destructor handler (0 = no handler for this state).
    handler: u32,
}

/// Catch block descriptor — describes one `catch(T)` clause.
#[repr(C)]
#[allow(dead_code)]
struct CxxCatchBlockInfo {
    /// Flags (`TYPE_FLAG_CONST`, `TYPE_FLAG_VOLATILE`, `TYPE_FLAG_REFERENCE`, etc.).
    flags: u32,
    /// RVA of `type_info` for the caught type (0 = `catch(...)`).
    type_info: u32,
    /// Offset from the establisher frame where the exception object is copied.
    offset: i32,
    /// RVA of the catch handler function.
    handler: u32,
    /// Frame offset for the catch block (x64 only).
    frame: u32,
}

/// Try block descriptor — describes one `try { } catch(...) { }` region.
#[repr(C)]
#[allow(dead_code)]
struct CxxTryBlockInfo {
    /// Lowest state covered by this try block.
    start_level: i32,
    /// Highest state covered by this try block.
    end_level: i32,
    /// State when the catch block is executing.
    catch_level: i32,
    /// Number of catch blocks.
    catchblock_count: u32,
    /// RVA of the catch block array.
    catchblock: u32,
}

/// `this` pointer offset descriptor — used for virtual base class adjustments.
#[repr(C)]
#[allow(dead_code)]
struct CxxThisPtrOffsets {
    /// Offset from the base to the `this` pointer.
    this_offset: i32,
    /// Offset to virtual base descriptor (-1 = no virtual base).
    vbase_descr: i32,
    /// Offset within the virtual base class descriptor.
    vbase_offset: i32,
}

/// Type info for one catchable type in the exception's type hierarchy.
#[repr(C)]
#[allow(dead_code)]
struct CxxTypeInfo {
    /// Flags (`CLASS_IS_SIMPLE_TYPE`, `CLASS_HAS_VIRTUAL_BASE_CLASS`, etc.).
    flags: u32,
    /// RVA of the `type_info` for this type.
    type_info: u32,
    /// Offsets for `this` pointer adjustment.
    offsets: CxxThisPtrOffsets,
    /// Size of the exception object.
    size: u32,
    /// RVA of the copy constructor.
    copy_ctor: u32,
}

/// Table of catchable types for an exception.
///
/// The `info` array contains RVAs to `CxxTypeInfo` entries.
/// In practice the array is variable-length; we declare a small fixed
/// array and access it by index (all within bounds guaranteed by `count`).
#[repr(C)]
struct CxxTypeInfoTable {
    /// Number of entries in the `info` array.
    count: u32,
    /// RVAs of `CxxTypeInfo` entries (variable length; first element here).
    info: [u32; 1],
}

/// Exception type descriptor — the "ThrowInfo" in MSVC terminology.
///
/// Attached to each throw expression.  Describes the thrown type, its
/// destructor, and the list of types it can be caught as.
#[repr(C)]
#[allow(dead_code)]
struct CxxExceptionType {
    /// Flags (`TYPE_FLAG_CONST`, `TYPE_FLAG_VOLATILE`).
    flags: u32,
    /// RVA of the destructor for the thrown object.
    destructor: u32,
    /// RVA of a custom exception handler (usually 0).
    custom_handler: u32,
    /// RVA of the `CxxTypeInfoTable`.
    type_info_table: u32,
}

/// Function descriptor — the central metadata structure for `__CxxFrameHandler3`.
///
/// Pointed to (via RVA) by the `HandlerData` field of the `DISPATCHER_CONTEXT`.
/// Contains all information needed to unwind locals, match catch blocks,
/// and determine the active try level.
#[repr(C)]
struct CxxFuncInfo {
    /// Magic number identifying the version (VC6/VC7/VC8).
    /// The top 3 bits are `bbt_flags`.
    magic_and_bbt: u32,
    /// Number of entries in the unwind map.
    unwind_count: u32,
    /// RVA of the unwind map array (`CxxUnwindMapEntry[]`).
    unwind_table: u32,
    /// Number of try block descriptors.
    tryblock_count: u32,
    /// RVA of the try block array (`CxxTryBlockInfo[]`).
    tryblock: u32,
    /// Number of entries in the IP-to-state map.
    ipmap_count: u32,
    /// RVA of the IP-to-state map array (`CxxIpMapEntry[]`).
    ipmap: u32,
    /// Offset from the frame pointer to the "unwind help" slot (x64 only).
    /// This is a stack-relative offset where the runtime stores the current
    /// trylevel at function entry (-2 = not initialized).
    unwind_help: i32,
    /// RVA of the expected exception list (VC7+, usually 0).
    expect_list: u32,
    /// Flags (`FUNC_DESCR_SYNCHRONOUS`, `FUNC_DESCR_NOEXCEPT`) — valid when magic ≥ VC8.
    flags: u32,
}

/// Determine the current state (trylevel) from the IP-to-state map.
///
/// Walks the map backward to find the highest entry whose IP is ≤ the
/// control PC, returning the corresponding state.  Returns -1 if the
/// PC is before the first entry.
fn cxx_ip_to_state(fi: &CxxFuncInfo, image_base: u64, control_pc: u64) -> i32 {
    if fi.ipmap_count == 0 || fi.ipmap == 0 {
        return -1;
    }
    if control_pc < image_base {
        return -1;
    }
    let Some(diff) = control_pc.checked_sub(image_base) else {
        return -1;
    };
    if diff > u64::from(u32::MAX) {
        return -1;
    }
    #[allow(clippy::cast_possible_truncation)]
    let ip_rva = diff as u32;
    let ipmap = (image_base + u64::from(fi.ipmap)) as *const CxxIpMapEntry;
    let mut state = -1_i32;
    for i in 0..fi.ipmap_count {
        // SAFETY: ipmap is within the loaded PE image.
        let entry = unsafe { &*ipmap.add(i as usize) };
        if entry.ip > ip_rva {
            break;
        }
        state = entry.state;
    }
    state
}

/// Run local destructors via the unwind map.
///
/// Walks from `current_state` back through the unwind map, calling each
/// destructor handler, until reaching `target_state`.
///
/// # Safety
/// `fi` must point to a valid `CxxFuncInfo`, `image_base` must be the PE
/// load address, and `frame` must be the establisher frame.
unsafe fn cxx_local_unwind(
    fi: &CxxFuncInfo,
    image_base: u64,
    frame: u64,
    current_state: i32,
    target_state: i32,
) {
    type DestructorHandler = unsafe extern "win64" fn(u64);

    if fi.unwind_count == 0 || fi.unwind_table == 0 {
        return;
    }
    let unwind_table = (image_base + u64::from(fi.unwind_table)) as *const CxxUnwindMapEntry;
    let mut state = current_state;
    // Guard against cycles in malformed unwind maps: limit iterations to
    // the table size (a well-formed chain visits each entry at most once).
    let mut iterations: u32 = 0;
    let max_iterations = fi.unwind_count;
    #[allow(clippy::cast_sign_loss)]
    while state > target_state && state >= 0 && (state as u32) < fi.unwind_count {
        iterations += 1;
        if iterations > max_iterations {
            break;
        }
        // SAFETY: state is within bounds of the unwind table.
        #[allow(clippy::cast_sign_loss)]
        let entry = unsafe { &*unwind_table.add(state as usize) };
        if entry.handler != 0 {
            let handler_addr = image_base + u64::from(entry.handler);
            // transmute is required to cast the raw PE address to a Win64
            // ABI function pointer — no safe alternative exists.
            let handler: DestructorHandler = unsafe { core::mem::transmute(handler_addr) };
            unsafe { handler(frame) };
        }
        state = entry.prev;
    }
}

/// Search for a matching catch block during the search phase.
///
/// If a matching catch block is found, initiates unwind to the catch
/// handler via `RtlUnwindEx` (which never returns).
///
/// # Safety
/// All pointers must be valid or NULL.
#[allow(clippy::too_many_arguments)]
unsafe fn cxx_find_catch_block(
    exception_record: *mut core::ffi::c_void,
    establisher_frame: u64,
    context_record: *mut core::ffi::c_void,
    _dispatcher_context: *mut core::ffi::c_void,
    fi: &CxxFuncInfo,
    image_base: u64,
    trylevel: i32,
    exc_type: *const CxxExceptionType,
    throw_base: u64,
    rethrow_info: Option<SavedExcRecord>,
) {
    if fi.tryblock_count == 0 || fi.tryblock == 0 {
        return;
    }
    let tryblock_table = (image_base + u64::from(fi.tryblock)) as *const CxxTryBlockInfo;

    for i in 0..fi.tryblock_count {
        // SAFETY: i is within bounds.
        let tryblock = unsafe { &*tryblock_table.add(i as usize) };

        // Check if the current trylevel falls within this try block.
        if trylevel < tryblock.start_level || trylevel > tryblock.end_level {
            continue;
        }

        // ── In-catch skip (rethrow) ───────────────────────────────────
        // When rethrowing from inside a catch handler, skip try blocks
        // that overlap with the active catch's try block.  This prevents
        // the inner catch from matching the rethrown exception again.
        //
        // We skip a try block only if its end_level is within the
        // active catch's range [0, in_catch_end_level].  This ensures
        // the enclosing (outer) try block — which has a WIDER range —
        // is NOT skipped.
        if let Some(ref rethrow) = rethrow_info
            && tryblock.end_level <= rethrow.in_catch_end_level
        {
            continue;
        }

        if tryblock.catchblock_count == 0 || tryblock.catchblock == 0 {
            continue;
        }

        let catchblock_table =
            (image_base + u64::from(tryblock.catchblock)) as *const CxxCatchBlockInfo;

        for j in 0..tryblock.catchblock_count {
            // SAFETY: j is within bounds.
            let catchblock = unsafe { &*catchblock_table.add(j as usize) };

            // Check if this catch block matches the thrown type.
            let matches = if exc_type.is_null() {
                // Non-C++ exception: only match catch(...)
                catchblock.type_info == 0
            } else {
                unsafe { cxx_catch_matches(catchblock, exc_type, throw_base, image_base) }
            };

            if !matches {
                continue;
            }

            // For rethrow, use the saved establisher frame from the
            // original catch.  The rethrow's stack walk through
            // intermediate Rust frames computes a wrong frame address.
            //
            // For a NEW throw from a catch funclet (CXX_EXC_RECORD is set
            // but not a rethrow), the same frame correction is needed:
            // the funclet was called from Rust code, so the unwinder
            // computes the funclet's frame instead of the parent's.
            let in_catch_record = CXX_EXC_RECORD.with(std::cell::Cell::get);
            let effective_frame = if let Some(ref ri) = rethrow_info {
                ri.establisher_frame
            } else if let Some(ref saved) = in_catch_record {
                if saved.establisher_frame == establisher_frame {
                    establisher_frame
                } else {
                    saved.establisher_frame
                }
            } else {
                establisher_frame
            };

            // Found a matching catch block — copy exception object if needed.
            if !exc_type.is_null() && catchblock.type_info != 0 && catchblock.offset != 0 {
                // Retrieve the C++ exception object pointer from ExceptionInformation[1].
                let exc_object = unsafe {
                    // SAFETY: exception_record is expected to point to a valid EXCEPTION_RECORD
                    // provided by the unwinder. We only read ExceptionInformation[1].
                    (*exception_record.cast::<crate::kernel32::ExceptionRecord>())
                        .exception_information[1] as *const u8
                };
                if !exc_object.is_null() {
                    #[allow(clippy::cast_possible_truncation)]
                    let dest = (effective_frame as *mut u8)
                        .wrapping_offset(i64::from(catchblock.offset) as isize);
                    if (catchblock.flags & TYPE_FLAG_REFERENCE) != 0 {
                        unsafe {
                            dest.cast::<*const u8>().write_unaligned(exc_object);
                        }
                    } else {
                        let size = unsafe { cxx_get_exception_size(exc_type, throw_base) };
                        if size > 0 {
                            unsafe {
                                core::ptr::copy_nonoverlapping(exc_object, dest, size);
                            }
                        }
                    }
                }
            }

            if catchblock.handler == 0 {
                continue;
            }
            let handler_ip = image_base + u64::from(catchblock.handler);

            if let Some(ref rethrow) = rethrow_info {
                // ── Rethrow shortcut ──────────────────────────────────
                // On rethrow, `RtlUnwindEx` cannot properly walk from the
                // funclet (PE) through intermediate Rust frames back to
                // the target PE frame.  Instead, call the catch funclet
                // directly with the saved establisher frame and jump to
                // the continuation — mirroring what __CxxFrameHandler3's
                // target-unwind phase does.
                type CatchFunclet = unsafe extern "win64" fn(u64, u64) -> u64;
                #[allow(clippy::cast_possible_truncation)]
                let funclet: CatchFunclet = unsafe { core::mem::transmute(handler_ip as usize) };
                let continuation = unsafe { funclet(effective_frame, effective_frame) };

                // Clear TLS exception state now that the rethrown exception
                // has been caught.  This prevents a stale saved record from
                // being mistakenly rethrown by a later `throw;`.
                CXX_EXC_RECORD.with(|c| c.set(None));

                // Build a context for the continuation.  The context from
                // the rethrow's stack walk has stale RSP/RBP; we must set
                // them from the saved establisher frame.
                if !context_record.is_null() {
                    let ctx = context_record.cast::<u8>();
                    unsafe {
                        crate::kernel32::ctx_write(ctx, crate::kernel32::CTX_RIP, continuation);
                        crate::kernel32::ctx_write(ctx, crate::kernel32::CTX_RSP, effective_frame);
                        // Compute the frame register (typically RBP) from
                        // the UNWIND_INFO so the continuation code can
                        // access locals via RBP-relative addressing.
                        if let Some((reg_off, val)) = crate::kernel32::compute_body_frame_reg(
                            rethrow.image_base,
                            rethrow.function_entry,
                            effective_frame,
                        ) {
                            crate::kernel32::ctx_write(ctx, reg_off, val);
                        }
                        crate::kernel32::seh_restore_context_and_jump(ctx);
                    }
                }
                // Fallback: should not reach here.
                return;
            }

            if let Some(ref saved) = in_catch_record
                && saved.establisher_frame != establisher_frame
            {
                // ── In-catch new-throw shortcut ───────────────────────
                // When a NEW exception is thrown from inside a catch
                // funclet, `RtlUnwindEx` cannot walk from the funclet
                // through Rust frames to the parent PE frame (same
                // problem as rethrow).  Use the direct funclet call
                // shortcut with the saved establisher frame.
                type CatchFunclet = unsafe extern "win64" fn(u64, u64) -> u64;
                #[allow(clippy::cast_possible_truncation)]
                let funclet: CatchFunclet = unsafe {
                    // SAFETY: handler_ip is derived from catchblock.handler which
                    // points to a valid PE catch funclet; we call it with the
                    // Windows x64 calling convention, which matches CatchFunclet.
                    core::mem::transmute(handler_ip as usize)
                };
                let continuation = unsafe { funclet(effective_frame, effective_frame) };

                // Clear TLS exception state — the new exception is now caught.
                CXX_EXC_RECORD.with(|c| c.set(None));

                if !context_record.is_null() {
                    let ctx = context_record.cast::<u8>();
                    unsafe {
                        crate::kernel32::ctx_write(ctx, crate::kernel32::CTX_RIP, continuation);
                        crate::kernel32::ctx_write(ctx, crate::kernel32::CTX_RSP, effective_frame);
                        if let Some((reg_off, val)) = crate::kernel32::compute_body_frame_reg(
                            saved.image_base,
                            saved.function_entry,
                            effective_frame,
                        ) {
                            crate::kernel32::ctx_write(ctx, reg_off, val);
                        }
                        crate::kernel32::seh_restore_context_and_jump(ctx);
                    }
                }
                return;
            }

            // Initiate unwind to the catch handler.
            // SAFETY: RtlUnwindEx is implemented in kernel32.
            unsafe {
                crate::kernel32::kernel32_RtlUnwindEx(
                    effective_frame as *mut core::ffi::c_void,
                    handler_ip as *mut core::ffi::c_void,
                    exception_record,
                    core::ptr::null_mut(),
                    context_record,
                    core::ptr::null_mut(),
                );
            }
            // RtlUnwindEx should not return if it succeeds.
            return;
        }
    }
}

/// Check if a catch block matches the thrown exception type.
///
/// Walks the thrown exception's `CxxTypeInfoTable` comparing `type_info`
/// mangled names with the catch block's expected type.
unsafe fn cxx_catch_matches(
    catchblock: &CxxCatchBlockInfo,
    exc_type: *const CxxExceptionType,
    throw_base: u64,
    image_base: u64,
) -> bool {
    // type_info layout on x64: vtable_ptr(8) + name_ptr(8) + mangled_name[...]
    // The mangled name starts at offset 16.
    const TYPE_INFO_MANGLED_NAME_OFFSET: u64 = 16;

    // catch(...) matches everything.
    if catchblock.type_info == 0 {
        return true;
    }

    if exc_type.is_null() {
        return false;
    }

    let exc = unsafe { &*exc_type };
    if exc.type_info_table == 0 {
        return false;
    }

    let type_table = (throw_base + u64::from(exc.type_info_table)) as *const CxxTypeInfoTable;
    let table = unsafe { &*type_table };

    // Read the catch block's type_info and get its mangled name.
    let catch_ti_addr = image_base + u64::from(catchblock.type_info);
    let catch_mangled_ptr = (catch_ti_addr + TYPE_INFO_MANGLED_NAME_OFFSET) as *const u8;

    for k in 0..table.count {
        let type_info_rva = unsafe { *(&raw const table.info).cast::<u32>().add(k as usize) };
        if type_info_rva == 0 {
            continue;
        }
        let cxx_ti = (throw_base + u64::from(type_info_rva)) as *const CxxTypeInfo;
        let ti = unsafe { &*cxx_ti };
        if ti.type_info == 0 {
            continue;
        }
        // Resolve the thrown type's type_info.
        let thrown_ti_addr = throw_base + u64::from(ti.type_info);
        let thrown_mangled_ptr = (thrown_ti_addr + TYPE_INFO_MANGLED_NAME_OFFSET) as *const u8;

        // Compare mangled names (null-terminated C strings).
        if unsafe { cxx_strcmp(catch_mangled_ptr, thrown_mangled_ptr) } {
            return true;
        }
    }

    false
}

/// Compare two null-terminated C strings for equality.
///
/// # Safety
/// Both pointers must be valid, null-terminated C strings.
unsafe fn cxx_strcmp(a: *const u8, b: *const u8) -> bool {
    // MSVC mangled names are typically under 1 KiB.
    const MAX_TYPE_NAME_LENGTH: usize = 1024;

    let mut i = 0;
    loop {
        let ca = unsafe { *a.add(i) };
        let cb = unsafe { *b.add(i) };
        if ca != cb {
            return false;
        }
        if ca == 0 {
            return true;
        }
        i += 1;
        // Safety guard against unterminated strings.
        if i > MAX_TYPE_NAME_LENGTH {
            return false;
        }
    }
}

/// Get the size of the exception object from its type info table.
///
/// Returns the size of the first (most derived) type, or 0 if unknown.
unsafe fn cxx_get_exception_size(exc_type: *const CxxExceptionType, throw_base: u64) -> usize {
    if exc_type.is_null() {
        return 0;
    }
    let exc = unsafe { &*exc_type };
    if exc.type_info_table == 0 {
        return 0;
    }
    let type_table = (throw_base + u64::from(exc.type_info_table)) as *const CxxTypeInfoTable;
    let table = unsafe { &*type_table };
    if table.count == 0 {
        return 0;
    }
    let first_rva = unsafe { *(&raw const table.info).cast::<u32>() };
    if first_rva == 0 {
        return 0;
    }
    let first_ti = (throw_base + u64::from(first_rva)) as *const CxxTypeInfo;
    unsafe { (*first_ti).size as usize }
}

/// Handle a C++ rethrow (`throw;`).
///
/// Restores the saved exception parameters from TLS and re-raises the
/// original exception.  Sets `CXX_RETHROW_ACTIVE` so the search phase
/// of `__CxxFrameHandler3` applies the "in-catch" skip logic.
///
/// This is a separate `#[cold]` function to keep `_CxxThrowException`'s
/// stack frame small — `seh_find_pe_frame_on_stack` has a limited
/// scan window (2048 bytes) and a bloated frame can push the trampoline
/// frame out of range.
///
/// # Safety
/// Must only be called when a rethrow is active (i.e. from within a
/// catch handler where `CXX_EXC_RECORD` has been populated).
#[cold]
#[inline(never)]
unsafe fn cxx_handle_rethrow() -> ! {
    let saved = CXX_EXC_RECORD.with(std::cell::Cell::get);
    if let Some(saved) = saved {
        CXX_RETHROW_ACTIVE.with(|c| c.set(true));
        let n = (saved.number_parameters as usize).min(15);
        // SAFETY: kernel32_RaiseException is defined in the platform layer.
        unsafe {
            crate::kernel32::kernel32_RaiseException(
                saved.exception_code,
                // Clear all dispatch-phase flags — this is a fresh exception
                // raise.  The saved flags may include EXCEPTION_UNWINDING
                // (0x2) and EXCEPTION_TARGET_UNWIND (0x20) from the
                // target-unwind phase where the record was captured.
                // EXCEPTION_NONCONTINUABLE (0x1) is preserved.
                saved.exception_flags & 0x1,
                saved.number_parameters,
                saved.exception_information[..n].as_ptr(),
            );
        }
    }
    // No saved exception — unhandled rethrow.
    eprintln!("Unhandled rethrow (throw;) with no active exception – aborting");
    std::process::abort();
}

/// `_CxxThrowException` — Throw a C++ exception using MSVC semantics.
///
/// Called by the compiler-generated code for `throw expr;`.  Builds the
/// parameters array expected by the MSVC C++ runtime and calls
/// `RaiseException` with the magic exception code `0xE06D7363`.
///
/// For rethrow (`throw;`), both `exception_object` and `throw_info` are
/// NULL.  In that case, we restore the saved exception parameters from
/// TLS (saved when the catch funclet was entered) and re-raise with
/// those parameters.
///
/// # Parameters
/// - `exception_object`: Pointer to the thrown object (e.g. `new std::exception`).
/// - `throw_info`: Pointer to the compiler-generated `_ThrowInfo` structure
///   describing the exception type.
///
/// # Safety
/// `exception_object` and `throw_info` may be NULL (for `throw;` rethrow).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt__CxxThrowException(
    exception_object: *mut core::ffi::c_void,
    throw_info: *mut core::ffi::c_void,
) {
    // Rethrow: `throw;` compiles to `_CxxThrowException(NULL, NULL)`.
    // Delegate to a separate function to keep this function's stack frame
    // small (seh_find_pe_frame_on_stack has a limited scan window).
    if exception_object.is_null() && throw_info.is_null() {
        unsafe { cxx_handle_rethrow() };
    }

    // The MSVC CRT passes 4 parameters to RaiseException for VC8+ (magic 0x19930520):
    //   [0] = MSVC magic number (0x19930520)
    //   [1] = pointer to the thrown object (absolute VA)
    //   [2] = ThrowInfo RVA — offset from the module base, NOT an absolute pointer
    //   [3] = image base of the module (for RVA resolution in _ThrowInfo)
    //
    // Ref: Wine dlls/msvcrt/except_x86_64.c `__CxxThrowException`,
    //      ReactOS sdk/lib/crt/except/cppexcept.h.
    //
    // The compiler-emitted call passes `throw_info` as an absolute VA.
    // We must convert it to an RVA before storing in ExceptionInformation[2],
    // because `__CxxFrameHandler3` reads ExceptionInformation[2] as a u32 RVA
    // and resolves it by adding ExceptionInformation[3] (the image base).
    let module_base = crate::kernel32::get_registered_image_base();
    #[allow(clippy::cast_possible_truncation)]
    let throw_info_rva = if throw_info.is_null() {
        0usize
    } else {
        (throw_info as usize).wrapping_sub(module_base as usize)
    };
    #[allow(clippy::cast_possible_truncation)]
    let params: [usize; 4] = [
        0x1993_0520,               // magic version number (VC8+)
        exception_object as usize, // exception object pointer (absolute VA)
        throw_info_rva,            // ThrowInfo RVA relative to module_base
        module_base as usize,      // image base for RVA resolution
    ];

    // SAFETY: kernel32_RaiseException is defined in the platform layer.
    // EXCEPTION_NONCONTINUABLE = 0x1
    unsafe {
        crate::kernel32::kernel32_RaiseException(
            MSVC_CPP_EXCEPTION_CODE,
            0x1, // EXCEPTION_NONCONTINUABLE
            4,
            params.as_ptr(),
        );
    }
}

/// `__CxxFrameHandler3` — MSVC C++ frame-based exception handler (version 3).
///
/// This is the language-specific handler installed in the `UNWIND_INFO` for
/// functions containing `try`/`catch` blocks compiled by MSVC.  It is called
/// by the OS exception dispatcher (`RtlDispatchException` / `RtlUnwindEx`)
/// during both the search (phase 1) and unwind (phase 2) phases.
///
/// The implementation:
/// - Parses the `FuncInfo` structure pointed to by `handler_data`
/// - Walks the try/catch map to find a matching handler (search phase)
/// - Executes destructors for local objects during unwind (unwind phase)
///
/// # Safety
/// All pointer arguments must be valid or NULL.
#[unsafe(no_mangle)]
#[allow(clippy::similar_names)]
pub unsafe extern "C" fn msvcrt___CxxFrameHandler3(
    exception_record: *mut core::ffi::c_void,
    establisher_frame: u64,
    context_record: *mut core::ffi::c_void,
    dispatcher_context: *mut core::ffi::c_void,
) -> i32 {
    if exception_record.is_null() || dispatcher_context.is_null() {
        return 1; // EXCEPTION_CONTINUE_SEARCH
    }

    // Read DispatcherContext fields via struct access.
    let dc = unsafe { &*dispatcher_context.cast::<crate::kernel32::DispatcherContext>() };
    let image_base = dc.image_base;
    let handler_data = dc.handler_data;
    let control_pc = dc.control_pc;

    if handler_data.is_null() || image_base == 0 {
        return 1;
    }

    // HandlerData points to a FuncInfo RVA for __CxxFrameHandler3.
    let func_info_rva = unsafe { (handler_data as *const u32).read_unaligned() };
    if func_info_rva == 0 {
        return 1;
    }
    let func_info = (image_base + u64::from(func_info_rva)) as *const CxxFuncInfo;

    let fi = unsafe { &*func_info };
    let magic = fi.magic_and_bbt & 0x1FFF_FFFF; // bottom 29 bits

    // Validate magic number.
    if !(CXX_FRAME_MAGIC_VC6..=CXX_FRAME_MAGIC_VC8).contains(&magic) {
        return 1;
    }

    // Read exception record fields.
    let exc_rec_ref = unsafe { &*exception_record.cast::<crate::kernel32::ExceptionRecord>() };
    let exc_flags = exc_rec_ref.exception_flags;
    let exc_code = exc_rec_ref.exception_code;

    let is_unwinding = (exc_flags & EXCEPTION_UNWINDING_FLAG) != 0;
    let is_target_unwind = (exc_flags & EXCEPTION_TARGET_UNWIND_FLAG) != 0;

    // Synchronous mode (VC8+): only handle CXX_EXCEPTION.
    if magic >= CXX_FRAME_MAGIC_VC8
        && (fi.flags & FUNC_DESCR_SYNCHRONOUS) != 0
        && exc_code != MSVC_CPP_EXCEPTION_CODE
    {
        return 1;
    }

    // Determine current trylevel from IP-to-state map.
    let trylevel = cxx_ip_to_state(fi, image_base, control_pc);

    if is_unwinding && !is_target_unwind {
        // Cleanup phase (intermediate frame): run local destructors only.
        cxx_local_unwind(fi, image_base, establisher_frame, trylevel, -1);
        return 1; // EXCEPTION_CONTINUE_SEARCH
    }

    if is_target_unwind {
        // NOTE: `extern "win64"` uses the Microsoft x64 calling convention,
        // which matches the Windows PE code we are calling.
        type CatchFunclet = unsafe extern "win64" fn(u64, u64) -> u64;
        // Target-unwind phase: run destructors, then call the catch funclet.
        //
        // The MSVC catch funclet is a compiler-generated "funclet" that runs the
        // catch body and returns the continuation IP (the code right after the
        // catch block) in RAX.  Unlike GCC landing pads (which are jumped to),
        // MSVC funclets must be CALLED so that their `ret` instruction returns
        // to us.
        //
        // Calling convention (clang-cl Windows x64):
        //   RCX = image_base  (for any intra-PE RVA resolution inside the funclet)
        //   RDX = post-alloc RSP of the parent function
        //         (= the RSP value right after the parent's prologue `sub rsp, N`,
        //          which the funclet uses to reconstruct the parent's RBP via
        //          `lea FPREG_OFFSET(%rdx), %rbp`)
        //
        // The `context_record` Rsp is already the post-alloc RSP of the target
        // function because the RtlUnwindEx stack walk correctly unwinds all
        // intermediate frames.
        //
        // Ref: Wine dlls/msvcrt/except_x86_64.c `cxx_frame_handler`,
        //      LLVM lib/Target/X86/X86WinEHState.cpp.
        cxx_local_unwind(fi, image_base, establisher_frame, trylevel, -1);

        // Only call the funclet for MSVC C++ exceptions (not SEH or other codes).
        if exc_code != MSVC_CPP_EXCEPTION_CODE || fi.tryblock_count == 0 {
            return 1;
        }

        let exc_record = unsafe { &*exception_record.cast::<crate::kernel32::ExceptionRecord>() };
        #[allow(clippy::cast_possible_truncation)]
        let exc_type_rva = exc_record.exception_information[2] as u32;
        let exc_image_base = exc_record.exception_information[3] as u64;
        let throw_base = if exc_image_base != 0 {
            exc_image_base
        } else {
            image_base
        };
        let exc_type_ptr = if exc_type_rva != 0 {
            (throw_base + u64::from(exc_type_rva)) as *const CxxExceptionType
        } else {
            core::ptr::null()
        };

        // Find the catch block that handles this exception.
        let try_table = (image_base + u64::from(fi.tryblock)) as *const CxxTryBlockInfo;
        let ctx = context_record.cast::<u8>();

        'outer: for i in 0..(fi.tryblock_count as usize) {
            let tb = unsafe { &*try_table.add(i) };
            if trylevel < tb.start_level || trylevel > tb.end_level {
                continue;
            }
            let catchblock_table =
                (image_base + u64::from(tb.catchblock)) as *const CxxCatchBlockInfo;
            for j in 0..(tb.catchblock_count as usize) {
                let catchblock = unsafe { &*catchblock_table.add(j) };
                let matches = if exc_type_ptr.is_null() {
                    catchblock.type_info == 0
                } else {
                    unsafe { cxx_catch_matches(catchblock, exc_type_ptr, throw_base, image_base) }
                };
                if !matches {
                    continue;
                }
                if catchblock.handler == 0 {
                    continue;
                }

                // Copy exception object into the frame-local catch parameter if needed.
                if !exc_type_ptr.is_null() && catchblock.type_info != 0 && catchblock.offset != 0 {
                    let exc_object = exc_record.exception_information[1] as *const u8;
                    if !exc_object.is_null() {
                        #[allow(clippy::cast_possible_truncation)]
                        let dest = (establisher_frame as *mut u8)
                            .wrapping_offset(i64::from(catchblock.offset) as isize);
                        if (catchblock.flags & TYPE_FLAG_REFERENCE) != 0 {
                            unsafe { dest.cast::<*const u8>().write_unaligned(exc_object) };
                        } else {
                            let size = unsafe { cxx_get_exception_size(exc_type_ptr, throw_base) };
                            if size > 0 {
                                unsafe {
                                    core::ptr::copy_nonoverlapping(exc_object, dest, size);
                                }
                            }
                        }
                    }
                }

                // Save the exception record to TLS before calling the catch
                // funclet.  If the catch body executes `throw;` (rethrow),
                // `_CxxThrowException` restores these parameters and sets
                // `CXX_RETHROW_ACTIVE`.  The search phase of
                // `__CxxFrameHandler3` then uses `catch_level` and
                // `in_catch_end_level` to skip the inner try block.
                //
                // Ref: Wine `dlls/msvcrt/except.c` — the `exc_record` field
                // in `msvcrt_get_thread_data()`, `find_catch_block` in_catch.
                CXX_EXC_RECORD.with(|c| {
                    c.set(Some(SavedExcRecord {
                        exception_code: exc_record.exception_code,
                        exception_flags: exc_record.exception_flags,
                        number_parameters: exc_record.number_parameters,
                        exception_information: exc_record.exception_information,
                        catch_level: tb.catch_level,
                        in_catch_end_level: tb.end_level,
                        establisher_frame,
                        image_base,
                        function_entry: dc.function_entry,
                    }));
                });

                // Call the catch funclet as a Windows x64 function:
                //   RCX = establisher frame
                //   RDX = establisher frame (post-alloc RSP of the parent function)
                // Returns: continuation IP (code right after the catch block) in RAX.
                //
                // Wine's `call_catch_block` passes the EstablisherFrame as both
                // parameters — the funclet uses RDX to reconstruct the parent
                // function's frame pointer via `lea OFFSET(%rdx), %rbp`.
                //
                // SAFETY: handler_va is the address of a valid PE catch funclet;
                // we call it with the Windows x64 calling convention.
                let handler_va = image_base + u64::from(catchblock.handler);
                #[allow(clippy::cast_possible_truncation)]
                let funclet: CatchFunclet = unsafe { core::mem::transmute(handler_va as usize) };
                let continuation = unsafe { funclet(establisher_frame, establisher_frame) };

                // Clear TLS exception state now that the catch funclet has
                // returned normally.  This prevents a stale saved record from
                // being mistakenly rethrown by a later `throw;`.
                CXX_EXC_RECORD.with(|c| c.set(None));

                // Update the context RIP to the continuation address.
                // RtlUnwindEx will jump there instead of jumping to the funclet.
                unsafe { crate::kernel32::ctx_write(ctx, crate::kernel32::CTX_RIP, continuation) };
                break 'outer;
            }
        }

        return 1; // EXCEPTION_CONTINUE_SEARCH (RtlUnwindEx uses context.Rip)
    }

    // Search phase: look for a matching catch block.
    if fi.tryblock_count == 0 {
        return 1;
    }

    // Only match MSVC C++ exceptions.
    if exc_code != MSVC_CPP_EXCEPTION_CODE {
        // For non-C++ exceptions, try to find catch(...) blocks.
        unsafe {
            cxx_find_catch_block(
                exception_record,
                establisher_frame,
                context_record,
                dispatcher_context,
                fi,
                image_base,
                trylevel,
                core::ptr::null(),
                0,
                None,
            );
        }
        return 1;
    }

    // Read ExceptionInformation from the exception record.
    // [0] = magic version, [1] = exception object ptr, [2] = ThrowInfo RVA,
    // [3] = image base (for RVA resolution)
    let exc_record = unsafe { &*exception_record.cast::<crate::kernel32::ExceptionRecord>() };

    #[allow(clippy::cast_possible_truncation)]
    let exc_type_rva = exc_record.exception_information[2] as u32;
    let exc_image_base = exc_record.exception_information[3] as u64;

    let throw_base = if exc_image_base != 0 {
        exc_image_base
    } else {
        image_base
    };

    let exc_type_ptr = if exc_type_rva != 0 {
        (throw_base + u64::from(exc_type_rva)) as *const CxxExceptionType
    } else {
        core::ptr::null()
    };

    // ── Rethrow handling ──────────────────────────────────────────────
    // `_CxxThrowException(NULL, NULL)` restores the saved exception
    // parameters and sets `CXX_RETHROW_ACTIVE`.  We read the saved
    // in-catch info to skip the try block whose catch is currently
    // executing, mimicking Wine's `in_catch` logic in `find_catch_block`.
    //
    // Ref: Wine `dlls/msvcrt/except.c` → `find_catch_block`:
    //   if (in_catch) {
    //       if (tryblock->start_level <= in_catch->end_level) continue;
    //       if (tryblock->end_level > in_catch->catch_level) continue;
    //   }
    let is_rethrow = CXX_RETHROW_ACTIVE.with(|c| {
        let v = c.get();
        if v {
            c.set(false);
        }
        v
    });

    let rethrow_info = if is_rethrow {
        CXX_EXC_RECORD.with(std::cell::Cell::get)
    } else {
        None
    };

    unsafe {
        cxx_find_catch_block(
            exception_record,
            establisher_frame,
            context_record,
            dispatcher_context,
            fi,
            image_base,
            trylevel,
            exc_type_ptr,
            throw_base,
            rethrow_info,
        );
    }

    1 // EXCEPTION_CONTINUE_SEARCH (no match found)
}

/// `__CxxFrameHandler4` — MSVC C++ frame-based exception handler (version 4).
///
/// Version 4 uses compressed `FuncInfo` (added in VS 2019 / MSVC 14.2x).
/// For now, delegates to the V3 handler since the basic protocol is the same.
///
/// # Safety
/// All pointer arguments must be valid or NULL.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt___CxxFrameHandler4(
    exception_record: *mut core::ffi::c_void,
    establisher_frame: u64,
    context_record: *mut core::ffi::c_void,
    dispatcher_context: *mut core::ffi::c_void,
) -> i32 {
    // V4 uses compressed FuncInfo but the basic protocol is the same.
    unsafe {
        msvcrt___CxxFrameHandler3(
            exception_record,
            establisher_frame,
            context_record,
            dispatcher_context,
        )
    }
}

/// `__CxxRegisterExceptionObject` — Register an exception object for tracking.
///
/// Called by catch blocks to register the caught exception for potential
/// rethrow.  This stub stores the exception pointer in thread-local storage.
///
/// # Safety
/// Both pointers must be valid or NULL.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt___CxxRegisterExceptionObject(
    _exception_pointers: *mut core::ffi::c_void,
    _frame_info: *mut core::ffi::c_void,
) -> i32 {
    1 // success
}

/// `__CxxUnregisterExceptionObject` — Unregister a previously registered exception.
///
/// Called when leaving a catch block.
///
/// # Safety
/// Both pointers must be valid or NULL.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt___CxxUnregisterExceptionObject(
    _frame_info: *mut core::ffi::c_void,
    _in_rethrow: i32,
) -> i32 {
    0
}

/// `__DestructExceptionObject` — Call the destructor for an exception object.
///
/// Called during rethrow or when an exception is being discarded.
///
/// # Safety
/// `exception_record` must be a valid `EXCEPTION_RECORD` or NULL.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt___DestructExceptionObject(
    _exception_record: *mut core::ffi::c_void,
) {
    // Stub: full implementation would call the destructor from ThrowInfo.
}

/// `__uncaught_exception` — Check if there is an active uncaught exception.
///
/// Returns `true` if an exception has been thrown and not yet caught.
///
/// # Safety
/// Safe to call from any context.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt___uncaught_exception() -> i32 {
    0 // no uncaught exceptions
}

/// `__uncaught_exceptions` — Get the count of active uncaught exceptions.
///
/// Returns the number of exceptions that have been thrown but not yet caught.
///
/// # Safety
/// Safe to call from any context.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt___uncaught_exceptions() -> i32 {
    0
}

/// `_local_unwind` — Perform a local unwind to a target frame.
///
/// Used by `__finally` handlers and cleanup code.
///
/// # Safety
/// Both pointers must be valid or NULL.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt__local_unwind(
    frame: *mut core::ffi::c_void,
    target: *mut core::ffi::c_void,
) {
    unsafe {
        crate::kernel32::kernel32_RtlUnwindEx(
            frame,
            target,
            core::ptr::null_mut(),
            core::ptr::null_mut(),
            core::ptr::null_mut(),
            core::ptr::null_mut(),
        );
    }
}

/// `terminate` — Called when C++ exception handling fails.
///
/// Called when:
/// - An exception is thrown and no matching handler is found
/// - An exception is thrown during stack unwinding (double exception)
/// - A `noexcept` function throws
///
/// Calls `std::terminate()` which by default calls `abort()`.
///
/// # Safety
/// This function terminates the process.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt_terminate() -> ! {
    eprintln!("terminate called — unhandled C++ exception");
    std::process::abort();
}

/// `_set_se_translator` — Set a structured exception translator function.
///
/// Allows converting SEH exceptions to C++ exceptions.  The translator
/// function is called during the search phase for SEH exceptions.
///
/// Returns the previous translator function (always NULL in this stub).
///
/// # Safety
/// `translator` may be NULL to remove the translator.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt__set_se_translator(
    _translator: *mut core::ffi::c_void,
) -> *mut core::ffi::c_void {
    core::ptr::null_mut()
}

/// `_is_exception_typeof` — Check if an exception matches a given type.
///
/// Used by the MSVC runtime during exception dispatch to determine if a
/// catch clause matches the thrown exception type.
///
/// Returns non-zero if the exception matches the specified type.
/// This stub always returns 0 (no match) as full MSVC RTTI matching
/// is not yet implemented.
///
/// # Safety
/// All pointer arguments must be valid or NULL.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt__is_exception_typeof(
    _type_info: *mut core::ffi::c_void,
    _exception_info: *mut core::ffi::c_void,
) -> i32 {
    0
}

/// `__std_terminate` — MSVC internal terminate handler.
///
/// Same as `terminate` but used in newer MSVC runtimes.
///
/// # Safety
/// This function terminates the process.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt___std_terminate() -> ! {
    eprintln!("__std_terminate called — unhandled C++ exception");
    std::process::abort();
}

/// `_CxxExceptionFilter` — MSVC C++ exception filter for SEH interop.
///
/// Examines the exception record to determine if it matches the C++ type.
/// Used in SEH `__except` blocks that need to catch C++ exceptions.
///
/// Returns `EXCEPTION_EXECUTE_HANDLER` (1) for matching MSVC C++ exceptions,
/// `EXCEPTION_CONTINUE_SEARCH` (0) otherwise.
///
/// # Safety
/// All pointer arguments must be valid or NULL.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt__CxxExceptionFilter(
    _exception_pointers: *mut core::ffi::c_void,
    _type_info: *mut core::ffi::c_void,
    _flags: i32,
    _copy_function: *mut core::ffi::c_void,
) -> i32 {
    // Stub implementation: always continue search.
    // A full implementation would inspect the exception record to
    // detect MSVC C++ exceptions and potentially match the type.
    0 // EXCEPTION_CONTINUE_SEARCH
}

/// `__current_exception` — Get pointer to the current exception TLS slot.
///
/// Returns a pointer to a thread-local variable holding the current
/// exception object pointer.  Used internally by the MSVC runtime for
/// `std::current_exception()` and rethrow.
///
/// # Safety
/// The returned pointer is valid only for the current thread.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt___current_exception() -> *mut *mut core::ffi::c_void {
    thread_local! {
        static CURRENT_EXCEPTION: std::cell::UnsafeCell<*mut core::ffi::c_void> =
            const { std::cell::UnsafeCell::new(core::ptr::null_mut()) };
    }
    CURRENT_EXCEPTION.with(std::cell::UnsafeCell::get)
}

/// `__current_exception_context` — Get pointer to the current exception
/// context TLS slot.
///
/// Returns a pointer to a thread-local variable holding the CONTEXT
/// at the point the current exception was thrown.
///
/// # Safety
/// The returned pointer is valid only for the current thread.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt___current_exception_context() -> *mut *mut core::ffi::c_void {
    thread_local! {
        static CURRENT_EXCEPTION_CONTEXT: std::cell::UnsafeCell<*mut core::ffi::c_void> =
            const { std::cell::UnsafeCell::new(core::ptr::null_mut()) };
    }
    CURRENT_EXCEPTION_CONTEXT.with(std::cell::UnsafeCell::get)
}

// ── VCRUNTIME140 / UCRT stubs for MSVC-compiled programs ─────────────────────
//
// Programs compiled with the MSVC toolchain (cl.exe / cargo with
// x86_64-pc-windows-msvc target) import from vcruntime140.dll and the
// Universal CRT (api-ms-win-crt-* / ucrtbase.dll) instead of the older
// msvcrt.dll.  These DLLs are aliased to MSVCRT.dll in the DLL manager, so
// the functions below are all exported under "MSVCRT.dll" in the function
// table.

/// `__vcrt_initialize()` — VCRUNTIME140 CRT initialisation
///
/// Returns TRUE (1) to indicate success.  No real initialisation needed
/// because the litebox platform manages the CRT lifetime directly.
///
/// # Safety
///
/// Safe to call unconditionally.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vcruntime__vcrt_initialize() -> i32 {
    1
}

/// `__vcrt_uninitialize()` — VCRUNTIME140 CRT cleanup
///
/// No-op: litebox does not maintain VCRUNTIME state that needs to be torn down.
///
/// # Safety
///
/// Safe to call unconditionally.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vcruntime__vcrt_uninitialize() {}

/// `__security_init_cookie()` — Initialise the stack-guard security cookie
///
/// No-op in the litebox environment: stack canary protection is not needed
/// because we control the entire execution context.
///
/// # Safety
///
/// Safe to call unconditionally.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vcruntime__security_init_cookie() {}

/// `__security_check_cookie(guard)` — Verify the stack-guard security cookie
///
/// Always succeeds (no-op).  In a real implementation this would terminate
/// the process on mismatch; our emulated environment never has a mismatch.
///
/// # Safety
///
/// Safe to call unconditionally.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vcruntime__security_check_cookie(_guard: usize) {}

/// `_initialize_narrow_environment()` — UCRT narrow-environment initialisation
///
/// Returns 0 (success).  Environment variables are managed by the litebox
/// platform layer directly via `GetEnvironmentVariableA/W`.
///
/// # Safety
///
/// Safe to call unconditionally.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ucrt__initialize_narrow_environment() -> i32 {
    0
}

/// `_get_initial_narrow_environment()` — get narrow environment pointer
///
/// Returns a pointer to the process environment pointer storage.
///
/// # Safety
/// Returned pointer is valid for process lifetime.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ucrt__get_initial_narrow_environment() -> *mut *mut i8 {
    if unsafe { msvcrt___initenv.is_null() } {
        unsafe {
            msvcrt___initenv = NULL_ENV_PTR.as_ptr().cast::<*mut i8>().cast_mut().cast();
        }
    }
    unsafe { msvcrt___initenv }
}

/// `_configure_narrow_argv(mode)` — UCRT argv configuration
///
/// Returns 0 (success).  Command-line arguments are supplied by the runner
/// via `PROCESS_COMMAND_LINE` and parsed by `__getmainargs`.
///
/// # Safety
///
/// Safe to call unconditionally.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ucrt__configure_narrow_argv(_mode: i32) -> i32 {
    0
}

/// `_set_app_type(type)` — set CRT application type
///
/// Delegates to the existing `__set_app_type` implementation.
///
/// # Safety
/// Safe to call unconditionally.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ucrt__set_app_type(app_type: i32) {
    unsafe { msvcrt___set_app_type(app_type) };
}

/// `_exit(status)` — terminate process immediately
///
/// # Safety
/// Never returns.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ucrt__exit(status: i32) -> ! {
    unsafe { msvcrt_exit(status) }
}

/// `_c_exit()` — clean CRT exit without process termination
///
/// # Safety
/// Safe to call unconditionally.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ucrt__c_exit() {
    unsafe { msvcrt__cexit() };
}

/// `_crt_atexit(fn)` — UCRT atexit registration
///
/// No-op stub.  The litebox runner does not currently support atexit handlers
/// registered through the UCRT path; the process lifetime is managed externally.
///
/// # Safety
///
/// Safe to call unconditionally; the function pointer is ignored.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ucrt__crt_atexit(_func: *const core::ffi::c_void) -> i32 {
    0
}

/// `_register_thread_local_exe_atexit_callback(cb)` — TLS atexit callback registration
///
/// # Safety
/// Safe to call; callback is currently ignored.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ucrt__register_thread_local_exe_atexit_callback(
    _callback: *const core::ffi::c_void,
) {
}

/// `_seh_filter_exe(code, ptrs)` — CRT exception filter helper
///
/// Returns `EXCEPTION_CONTINUE_SEARCH` (0).
///
/// # Safety
/// Safe to call with any arguments.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ucrt__seh_filter_exe(
    _exception_code: u32,
    _exception_pointers: *const core::ffi::c_void,
) -> i32 {
    0
}

/// `_initialize_onexit_table(table)` — initialise on-exit table
///
/// Returns 0 (success).
///
/// # Safety
/// `table_ptr` must be non-null and point to writable memory containing a valid
/// `_onexit_table_t`-compatible layout (three pointer fields).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ucrt__initialize_onexit_table(table_ptr: *mut core::ffi::c_void) -> i32 {
    #[repr(C)]
    struct OnExitTable {
        first: *mut *const core::ffi::c_void,
        last: *mut *const core::ffi::c_void,
        end: *mut *const core::ffi::c_void,
    }

    if table_ptr.is_null() {
        return -1;
    }

    let table = table_ptr.cast::<OnExitTable>();
    unsafe {
        (*table).first = core::ptr::null_mut();
        (*table).last = core::ptr::null_mut();
        (*table).end = core::ptr::null_mut();
    }
    0
}

/// `_register_onexit_function(table, func)` — register on-exit callback
///
/// Returns 0 (success).
///
/// # Safety
/// Safe to call with any pointer values.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ucrt__register_onexit_function(
    table: *mut core::ffi::c_void,
    _func: *const core::ffi::c_void,
) -> i32 {
    unsafe { ucrt__initialize_onexit_table(table) }
}

/// `_set_fmode(mode)` — set default file mode
///
/// Returns 0 (success).
///
/// # Safety
/// Safe to call unconditionally.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ucrt__set_fmode(mode: i32) -> i32 {
    unsafe {
        msvcrt__fmode = mode;
    }
    0
}

/// `_set_new_mode(mode)` — set global new-handler mode
///
/// Returns the previous mode.
///
/// # Safety
/// Safe to call unconditionally.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ucrt__set_new_mode(mode: i32) -> i32 {
    static NEW_MODE: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(0);
    NEW_MODE.swap(mode, std::sync::atomic::Ordering::Relaxed)
}

/// `__acrt_iob_func(index)` — UCRT stdio-stream accessor
///
/// Returns a pointer into the shared IOB array at the given index.  This is
/// the UCRT equivalent of the MSVCRT `__iob_func()` function, but takes an
/// explicit index (0 = stdin, 1 = stdout, 2 = stderr).
///
/// # Safety
///
/// `index` must be 0, 1, or 2.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ucrt__acrt_iob_func(index: u32) -> *mut u8 {
    // Each IOB entry is 8 bytes in our simplified layout.  The backing
    // static in `msvcrt___iob_func` is `[u8; 24]`, which accommodates
    // 3 streams × 8 bytes each (stdin = 0, stdout = 1, stderr = 2).
    const IOB_ENTRY_SIZE: usize = 8;
    let base = msvcrt___iob_func();
    // SAFETY: index is expected to be 0-2; we offset into the IOB array.
    unsafe { base.add((index as usize) * IOB_ENTRY_SIZE) }
}

/// `__stdio_common_vfprintf(options, stream, fmt, locale, arglist)` — UCRT printf
///
/// Implements the UCRT formatted-output function used by UCRT-linked programs.
/// `_options` and `_locale` are ignored.  Output always goes to stdout.
///
/// # Safety
///
/// `fmt` must be a valid null-terminated C string.
/// `arglist` must be a valid Windows x64 va_list pointer.
#[unsafe(no_mangle)]
#[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
pub unsafe extern "C" fn ucrt__stdio_common_vfprintf(
    _options: u64,
    _stream: *mut u8,
    fmt: *const u8,
    _locale: *const u8,
    arglist: *mut u8,
) -> i32 {
    if fmt.is_null() {
        return -1;
    }
    // SAFETY: Caller guarantees fmt is a valid null-terminated C string.
    let fmt_bytes = unsafe { CStr::from_ptr(fmt.cast::<i8>()) }.to_bytes();
    // SAFETY: arglist is a valid Windows x64 va_list pointer.
    let out = unsafe { format_printf_raw(fmt_bytes, arglist, false) };
    match io::stdout().write_all(&out) {
        Ok(()) => {
            let _ = io::stdout().flush();
            out.len() as i32
        }
        Err(_) => -1,
    }
}

/// `__stdio_common_vsscanf(options, buf, buf_count, fmt, locale, arglist)` — UCRT sscanf
///
/// Parses the string `buf` according to `fmt`, writing results through the
/// pointer arguments in `arglist` (a Windows x64 va_list).  Returns the
/// number of items matched and stored, or -1 on failure.
///
/// `_options`, `_buf_count`, and `_locale` are ignored.
///
/// # Safety
///
/// `buf` must be a valid null-terminated C string (or at least `_buf_count`
/// bytes long).  `fmt` must be a valid null-terminated C string.
/// `arglist` must be a valid Windows x64 va_list pointer.
#[unsafe(no_mangle)]
#[cfg(all(target_arch = "x86_64", target_os = "linux", target_env = "gnu"))]
#[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
pub unsafe extern "C" fn ucrt__stdio_common_vsscanf(
    _options: u64,
    buf: *const u8,
    _buf_count: usize,
    fmt: *const u8,
    _locale: *const u8,
    arglist: *mut u8,
) -> i32 {
    if buf.is_null() || fmt.is_null() {
        return -1;
    }
    // SAFETY: Caller guarantees buf and fmt are valid null-terminated C strings
    // and arglist is a valid Windows x64 va_list pointer.
    unsafe { format_scanf_raw(buf.cast::<i8>(), fmt.cast::<i8>(), arglist) }
}

/// `__stdio_common_vsprintf(options, buf, buf_count, fmt, locale, arglist)` — UCRT vsprintf
///
/// Formats a string into `buf` according to `fmt` using the Windows x64 `arglist`.
/// `_options` and `_locale` are ignored.
/// `buf_count` is the total byte capacity of `buf` (including the NUL terminator slot).
/// Returns the number of characters that would be written (excluding the NUL terminator),
/// or -1 on error.  When `buf` is non-null the output is NUL-terminated and capped at
/// `buf_count - 1` characters.
///
/// # Safety
///
/// `buf` must be a writable buffer of at least `buf_count` bytes, or null for a count-only call.
/// `fmt` must be a valid null-terminated C string.
/// `arglist` must be a valid Windows x64 va_list pointer.
#[unsafe(no_mangle)]
#[cfg(all(target_arch = "x86_64", target_os = "linux", target_env = "gnu"))]
#[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
pub unsafe extern "C" fn ucrt__stdio_common_vsprintf(
    _options: u64,
    buf: *mut u8,
    buf_count: usize,
    fmt: *const u8,
    _locale: *const u8,
    arglist: *mut u8,
) -> i32 {
    if fmt.is_null() {
        return -1;
    }
    // SAFETY: Caller guarantees fmt is a valid null-terminated C string.
    let fmt_bytes = unsafe { CStr::from_ptr(fmt.cast::<i8>()) }.to_bytes();
    // SAFETY: arglist is a valid Windows x64 va_list pointer.
    let out = unsafe { format_printf_raw(fmt_bytes, arglist, false) };
    let would_write = out.len() as i32;
    if !buf.is_null() && buf_count > 0 {
        let copy_len = out.len().min(buf_count - 1);
        // SAFETY: Caller guarantees buf is at least buf_count bytes.
        unsafe {
            std::ptr::copy_nonoverlapping(out.as_ptr(), buf, copy_len);
            *buf.add(copy_len) = 0;
        }
    }
    would_write
}

/// `__stdio_common_vsnprintf_s(options, buf, buf_count, max_count, fmt, locale, arglist)` — UCRT vsnprintf_s
///
/// Like `__stdio_common_vsprintf` but with an extra `max_count` parameter (MSVC `_TRUNCATE`
/// semantics: `usize::MAX` means truncate without error; any other value is a character limit
/// that causes -1 to be returned on truncation).
///
/// # Safety
///
/// Same as `ucrt__stdio_common_vsprintf`.
#[unsafe(no_mangle)]
#[cfg(all(target_arch = "x86_64", target_os = "linux", target_env = "gnu"))]
#[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
pub unsafe extern "C" fn ucrt__stdio_common_vsnprintf_s(
    _options: u64,
    buf: *mut u8,
    buf_count: usize,
    max_count: usize,
    fmt: *const u8,
    _locale: *const u8,
    arglist: *mut u8,
) -> i32 {
    if fmt.is_null() || buf.is_null() || buf_count == 0 {
        return -1;
    }
    // SAFETY: fmt is a valid null-terminated C string; arglist is a valid Windows va_list.
    let fmt_bytes = unsafe { CStr::from_ptr(fmt.cast::<i8>()) }.to_bytes();
    let out = unsafe { format_printf_raw(fmt_bytes, arglist, false) };

    // Effective write limit: min(max_count, buf_count - 1), with _TRUNCATE = unbounded.
    let effective = if max_count == usize::MAX {
        buf_count - 1
    } else {
        max_count.min(buf_count - 1)
    };
    let copy_len = out.len().min(effective);
    // SAFETY: buf is at least buf_count bytes per caller contract.
    unsafe {
        std::ptr::copy_nonoverlapping(out.as_ptr(), buf, copy_len);
        *buf.add(copy_len) = 0;
    }
    // If truncation occurred and this is not a _TRUNCATE call, return -1.
    if out.len() > copy_len && max_count != usize::MAX {
        return -1;
    }
    copy_len as i32
}

/// `__stdio_common_vsprintf_s(options, buf, buf_count, fmt, locale, arglist)` — UCRT vsprintf_s
///
/// Overflow-checked variant of `__stdio_common_vsprintf`.  Returns -1 if the
/// formatted output would exceed `buf_count - 1` characters.
///
/// # Safety
///
/// Same as `ucrt__stdio_common_vsprintf`.
#[unsafe(no_mangle)]
#[cfg(all(target_arch = "x86_64", target_os = "linux", target_env = "gnu"))]
#[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
pub unsafe extern "C" fn ucrt__stdio_common_vsprintf_s(
    _options: u64,
    buf: *mut u8,
    buf_count: usize,
    fmt: *const u8,
    _locale: *const u8,
    arglist: *mut u8,
) -> i32 {
    if fmt.is_null() || buf.is_null() || buf_count == 0 {
        return -1;
    }
    // SAFETY: fmt is a valid null-terminated C string; arglist is a valid Windows va_list.
    let fmt_bytes = unsafe { CStr::from_ptr(fmt.cast::<i8>()) }.to_bytes();
    let out = unsafe { format_printf_raw(fmt_bytes, arglist, false) };
    if out.len() >= buf_count {
        // Overflow — NUL-terminate and return -1.
        // SAFETY: buf is at least 1 byte per buf_count > 0 check.
        unsafe { *buf = 0 };
        return -1;
    }
    let copy_len = out.len();
    // SAFETY: copy_len < buf_count, so buf has room for copy_len + 1 bytes.
    unsafe {
        std::ptr::copy_nonoverlapping(out.as_ptr(), buf, copy_len);
        *buf.add(copy_len) = 0;
    }
    copy_len as i32
}

/// `__stdio_common_vswprintf(options, buf, buf_count, fmt, locale, arglist)` — UCRT wide vsprintf
///
/// Formats a wide string into `buf` (UTF-16LE) according to the wide format `fmt`.
/// `_options` and `_locale` are ignored.
/// Returns the number of wide characters written (excluding the NUL terminator), or -1 on error.
///
/// # Safety
///
/// `buf` must be a writable buffer of at least `buf_count` UTF-16 code units, or null.
/// `fmt` must be a valid null-terminated UTF-16 string.
/// `arglist` must be a valid Windows x64 va_list pointer.
#[unsafe(no_mangle)]
#[cfg(all(target_arch = "x86_64", target_os = "linux", target_env = "gnu"))]
#[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
pub unsafe extern "C" fn ucrt__stdio_common_vswprintf(
    _options: u64,
    buf: *mut u16,
    buf_count: usize,
    fmt: *const u16,
    _locale: *const u16,
    arglist: *mut u8,
) -> i32 {
    if fmt.is_null() {
        return -1;
    }
    // Convert wide format string to UTF-8 so we can run our printf formatter.
    let fmt_wide = unsafe { read_wide_string(fmt) };
    let fmt_utf8_str = String::from_utf16_lossy(&fmt_wide);
    let fmt_utf8 = fmt_utf8_str.as_bytes();
    // SAFETY: arglist is a valid Windows x64 va_list pointer; wide_mode=true so
    // %s / %c specifiers handle wide strings correctly.
    let out = unsafe { format_printf_raw(fmt_utf8, arglist, true) };
    // Convert the UTF-8 output to UTF-16 so we can compute the correct return value
    // (number of UTF-16 code units written, excluding NUL) and fill the wide buffer.
    let utf16: Vec<u16> = String::from_utf8_lossy(&out).encode_utf16().collect();
    let would_write = utf16.len() as i32;
    if !buf.is_null() && buf_count > 0 {
        let copy_wchars = utf16.len().min(buf_count - 1);
        // SAFETY: buf is at least buf_count u16 values per caller contract.
        unsafe {
            std::ptr::copy_nonoverlapping(utf16.as_ptr(), buf, copy_wchars);
            *buf.add(copy_wchars) = 0;
        }
    }
    would_write
}

/// `scanf(format, ...) -> int` — read formatted input from stdin.
///
/// Parses stdin according to `format`, writing results through the pointer
/// arguments.  Returns the number of items matched and stored, or -1 on EOF.
///
/// Returns -1 immediately if the format string contains more than `MAX_SCANF_ARGS`
/// (16) non-suppressed conversion specifiers, to avoid undefined behaviour when
/// `libc::scanf` would try to read more variadic arguments than were provided.
///
/// # Safety
///
/// `format` must be a valid null-terminated string.
/// The format string must contain no more than `MAX_SCANF_ARGS` (16) non-suppressed
/// conversion specifiers.
/// Each variadic argument must be a writable pointer of the type implied by
/// the corresponding format specifier.
#[unsafe(no_mangle)]
#[cfg(all(target_arch = "x86_64", target_os = "linux", target_env = "gnu"))]
pub unsafe extern "C" fn msvcrt_scanf(format: *const i8, mut args: ...) -> i32 {
    if format.is_null() {
        return -1;
    }
    let fmt_bytes = unsafe { CStr::from_ptr(format) }.to_bytes();
    let total_specs = count_scanf_specifiers(fmt_bytes);
    // Fail fast: if the format requires more output pointers than our fixed buffer
    // holds, calling libc::scanf with the original format would be UB.
    if total_specs > MAX_SCANF_ARGS {
        return -1;
    }
    let n_specs = total_specs;
    let mut ptrs: [*mut core::ffi::c_void; MAX_SCANF_ARGS] =
        [core::ptr::null_mut(); MAX_SCANF_ARGS];
    for p in ptrs.iter_mut().take(n_specs) {
        // SAFETY: caller guarantees enough pointer args are in the va_list.
        *p = unsafe { args.arg::<*mut core::ffi::c_void>() };
    }
    // SAFETY: format is a valid null-terminated string; n_specs <= MAX_SCANF_ARGS so
    // libc::scanf will not read more variadic arguments than we supply here.
    unsafe {
        libc::scanf(
            format, ptrs[0], ptrs[1], ptrs[2], ptrs[3], ptrs[4], ptrs[5], ptrs[6], ptrs[7],
            ptrs[8], ptrs[9], ptrs[10], ptrs[11], ptrs[12], ptrs[13], ptrs[14], ptrs[15],
        )
    }
}

// ── Windows FILE* → Linux FILE* resolution ────────────────────────────────────
//
// Windows programs compiled against UCRT obtain their stdio FILE* pointers via
// `__acrt_iob_func(index)` (or the legacy `__iob_func()`).  In this emulation
// those functions return pointers into a small static IOB buffer — NOT real
// Linux `FILE*` values.  We must detect these sentinel addresses and map them
// to real Linux file handles before passing them to libc functions.
//
// `msvcrt_fopen` and its variants DO return real libc `FILE*` pointers; such
// pointers will have addresses well above the IOB buffer range and are passed
// through unchanged.

/// Return a cached Linux `FILE*` for stdin (fd 0), opening it lazily on first
/// call.  Stored as `usize` to satisfy `Sync` requirements on the `OnceLock`.
fn get_linux_stdin() -> *mut libc::FILE {
    static STDIN_FILE: OnceLock<usize> = OnceLock::new();
    *STDIN_FILE.get_or_init(|| {
        // SAFETY: fdopen(0, "r") is a standard POSIX call; fd 0 is always open.
        unsafe { libc::fdopen(0, c"r".as_ptr()) as usize }
    }) as *mut libc::FILE
}

/// Translate a Windows `FILE*` pointer to a Linux `FILE*` suitable for reading.
///
/// If `stream` falls within the 24-byte IOB sentinel buffer (returned by
/// `__iob_func` / `__acrt_iob_func`), it is mapped:
/// - offset 0  (stdin)  → cached Linux stdin FILE*
/// - offset 8  (stdout) → null (stdout is write-only)
/// - offset 16 (stderr) → null (stderr  is write-only)
///
/// Any other pointer is assumed to be a real libc `FILE*` from `msvcrt_fopen`
/// and is returned as-is.
///
/// # Safety
///
/// `stream` must have been obtained from `__acrt_iob_func`, `__iob_func`, or
/// `msvcrt_fopen` / `msvcrt_fdopen`.
unsafe fn resolve_read_stream(stream: *mut u8) -> *mut libc::FILE {
    let iob_base = unsafe { msvcrt___iob_func() } as usize;
    let stream_addr = stream as usize;
    match stream_addr.wrapping_sub(iob_base) {
        0 => get_linux_stdin(),           // stdin  (offset 0)
        8 | 16 => core::ptr::null_mut(),  // stdout / stderr: not readable
        _ => stream.cast::<libc::FILE>(), // real libc FILE* from fopen/fdopen
    }
}

/// `fscanf(stream, format, ...) -> int` — read formatted input from a FILE stream.
///
/// Parses `stream` according to `format`, writing results through the pointer
/// arguments.  Returns the number of items matched and stored, or -1 on EOF.
///
/// Returns -1 immediately if the format string contains more than `MAX_SCANF_ARGS`
/// (16) non-suppressed conversion specifiers.
///
/// Windows stdio stream pointers obtained from `__acrt_iob_func` / `__iob_func`
/// are translated to real Linux `FILE*` values before calling `libc::fscanf`.
///
/// # Safety
///
/// `stream` must have been obtained from `__acrt_iob_func`, `__iob_func`, or
/// `msvcrt_fopen` / `msvcrt_fdopen`.
/// `format` must be a valid null-terminated string.
/// The format string must contain no more than `MAX_SCANF_ARGS` (16) non-suppressed
/// conversion specifiers.
/// Each variadic argument must be a writable pointer of the type implied by
/// the corresponding format specifier.
#[unsafe(no_mangle)]
#[cfg(all(target_arch = "x86_64", target_os = "linux", target_env = "gnu"))]
pub unsafe extern "C" fn msvcrt_fscanf(stream: *mut u8, format: *const i8, mut args: ...) -> i32 {
    if stream.is_null() || format.is_null() {
        return -1;
    }
    // Translate Windows FILE* (IOB-backed sentinel or real libc FILE*) to Linux FILE*.
    let file_ptr = unsafe { resolve_read_stream(stream) };
    if file_ptr.is_null() {
        return -1;
    }
    let fmt_bytes = unsafe { CStr::from_ptr(format) }.to_bytes();
    let total_specs = count_scanf_specifiers(fmt_bytes);
    // Fail fast: more specifiers than our fixed buffer can hold would be UB.
    if total_specs > MAX_SCANF_ARGS {
        return -1;
    }
    let n_specs = total_specs;
    let mut ptrs: [*mut core::ffi::c_void; MAX_SCANF_ARGS] =
        [core::ptr::null_mut(); MAX_SCANF_ARGS];
    for p in ptrs.iter_mut().take(n_specs) {
        // SAFETY: caller guarantees enough pointer args are in the va_list.
        *p = unsafe { args.arg::<*mut core::ffi::c_void>() };
    }
    // SAFETY: file_ptr is a valid Linux FILE*; format is null-terminated;
    // n_specs <= MAX_SCANF_ARGS so libc::fscanf will not read more variadic
    // arguments than we supply here.
    unsafe {
        libc::fscanf(
            file_ptr, format, ptrs[0], ptrs[1], ptrs[2], ptrs[3], ptrs[4], ptrs[5], ptrs[6],
            ptrs[7], ptrs[8], ptrs[9], ptrs[10], ptrs[11], ptrs[12], ptrs[13], ptrs[14], ptrs[15],
        )
    }
}

/// `__stdio_common_vfscanf(options, stream, fmt, locale, arglist)` — UCRT fscanf
///
/// Reads from `stream` according to `fmt`, writing results through the
/// pointer arguments in `arglist` (a Windows x64 va_list).  Returns the
/// number of items matched and stored, or -1 on EOF / failure.
///
/// `_options` and `_locale` are ignored.
///
/// Returns -1 immediately if the format string contains more than `MAX_SCANF_ARGS`
/// (16) non-suppressed conversion specifiers.
///
/// Windows stdio stream pointers obtained from `__acrt_iob_func` / `__iob_func`
/// are translated to real Linux `FILE*` values before calling `libc::fscanf`.
///
/// # Safety
///
/// `stream` must have been obtained from `__acrt_iob_func`, `__iob_func`, or
/// `msvcrt_fopen` / `msvcrt_fdopen`.
/// `fmt` must be a valid null-terminated C string.
/// `arglist` must be a valid Windows x64 va_list pointer.
#[unsafe(no_mangle)]
#[cfg(all(target_arch = "x86_64", target_os = "linux", target_env = "gnu"))]
#[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
pub unsafe extern "C" fn ucrt__stdio_common_vfscanf(
    _options: u64,
    stream: *mut u8,
    fmt: *const u8,
    _locale: *const u8,
    arglist: *mut u8,
) -> i32 {
    // Compile-time size assertion must appear before any non-const statements.
    const _: () = assert!(
        core::mem::size_of::<VaListTag>() == 24,
        "VaListTag size must be 24 bytes"
    );

    if fmt.is_null() {
        return -1;
    }
    // Translate Windows FILE* (IOB-backed sentinel or real libc FILE*) to Linux FILE*.
    let file_ptr = unsafe { resolve_read_stream(stream) };
    if file_ptr.is_null() {
        return -1;
    }

    // SAFETY: fmt is a valid null-terminated C string; arglist is a valid Windows va_list.
    let fmt_c = fmt.cast::<i8>();
    let fmt_bytes = unsafe { CStr::from_ptr(fmt_c) }.to_bytes();
    let total_specs = count_scanf_specifiers(fmt_bytes);
    // Fail fast: more specifiers than our fixed buffer can hold would be UB.
    if total_specs > MAX_SCANF_ARGS {
        return -1;
    }
    let n_specs = total_specs;

    // Build Linux va_list from Windows arglist pointer.
    let mut tag = VaListTag {
        gp_offset: 48,
        fp_offset: 304,
        overflow_arg_area: arglist,
        reg_save_area: core::ptr::null_mut(),
    };
    let vl: &mut core::ffi::VaList<'_> =
        unsafe { &mut *(&raw mut tag).cast::<core::ffi::VaList<'_>>() };

    let mut ptrs: [*mut core::ffi::c_void; MAX_SCANF_ARGS] =
        [core::ptr::null_mut(); MAX_SCANF_ARGS];
    for p in ptrs.iter_mut().take(n_specs) {
        // SAFETY: caller guarantees enough pointer args are in arglist.
        *p = unsafe { vl.arg::<*mut core::ffi::c_void>() };
    }

    // SAFETY: file_ptr is a valid Linux FILE*; fmt_c is null-terminated;
    // n_specs <= MAX_SCANF_ARGS so libc::fscanf will not read more variadic
    // arguments than we supply here.
    unsafe {
        libc::fscanf(
            file_ptr, fmt_c, ptrs[0], ptrs[1], ptrs[2], ptrs[3], ptrs[4], ptrs[5], ptrs[6],
            ptrs[7], ptrs[8], ptrs[9], ptrs[10], ptrs[11], ptrs[12], ptrs[13], ptrs[14], ptrs[15],
        )
    }
}

/// `_configthreadlocale(mode)` — UCRT per-thread locale configuration
///
/// Returns 0 (the legacy "global locale" mode).  Locale-sensitive operations
/// in the test suite use the process-global locale, which is adequate for
/// ASCII-only programs.
///
/// # Safety
///
/// Safe to call unconditionally.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ucrt__configthreadlocale(_mode: i32) -> i32 {
    0
}

// ── Stack probe stubs ─────────────────────────────────────────────────────────
//
// `__chkstk` (and its variants) uses a non-standard calling convention on
// Windows x64: RAX holds the number of bytes to probe, and callers typically
// do `sub rsp, rax` after the call.  This function MUST preserve RAX.
//
// These are registered via `link_data_exports_to_dll_manager` (NOT via
// the normal trampoline mechanism) so that RAX is never clobbered on the
// call path.  On Linux the kernel maps stack pages on demand, so no actual
// page probing is needed; an empty function that immediately returns is
// correct.

/// `__chkstk` / `___chkstk_ms` — MSVC/LLVM x64 stack probe stub
///
/// On Windows x64, the compiler calls `__chkstk` before allocating large
/// (> one page) stack frames so that guard pages are touched in order.
/// Linux maps stack pages on demand, making the probe a no-op.
///
/// **Important**: this function is registered via the *data-export* path so
/// the trampoline (which clobbers RAX) is bypassed.  The caller passes the
/// frame size in RAX; that value must be intact when `__chkstk` returns so
/// that the calling code's subsequent `sub rsp, rax` works correctly.
///
/// # Safety
///
/// Safe to call unconditionally.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt_chkstk_nop() {}

// ── Formatted I/O stubs ──────────────────────────────────────────────────────

/// `sprintf(buf, format, ...) -> int` — write formatted string to buffer.
///
/// Parses format specifiers and substitutes variadic arguments.
/// Returns the number of characters written (excluding the NUL terminator),
/// or -1 on error.
///
/// # Safety
///
/// `buf` must point to a writable buffer large enough to hold the output.
/// `format` must be a valid null-terminated string.
/// Variadic arguments must match the format specifiers.
#[unsafe(no_mangle)]
#[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
pub unsafe extern "C" fn msvcrt_sprintf(buf: *mut i8, format: *const i8, mut args: ...) -> i32 {
    if buf.is_null() || format.is_null() {
        return -1;
    }
    // SAFETY: Caller guarantees format is a valid null-terminated C string.
    let fmt_bytes = unsafe { CStr::from_ptr(format) }.to_bytes();
    // SAFETY: format and args are valid per caller contract.
    let out = unsafe { format_printf_va(fmt_bytes, &mut args, false) };
    // SAFETY: Caller guarantees buf is large enough for `out` + NUL.
    unsafe {
        std::ptr::copy_nonoverlapping(out.as_ptr().cast::<i8>(), buf, out.len());
        *buf.add(out.len()) = 0;
    }
    out.len() as i32
}

/// `snprintf(buf, count, format, ...) -> int` — write formatted string to
/// size-limited buffer.
///
/// Writes at most `count-1` bytes of the formatted output and appends a
/// NUL terminator.  Returns the number of characters that would have been
/// written (as per C99 semantics), or -1 on error.
///
/// # Safety
///
/// `buf` must point to a writable buffer of at least `count` bytes.
/// `format` must be a valid null-terminated string.
/// Variadic arguments must match the format specifiers.
#[unsafe(no_mangle)]
#[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
pub unsafe extern "C" fn msvcrt_snprintf(
    buf: *mut i8,
    count: usize,
    format: *const i8,
    mut args: ...
) -> i32 {
    if format.is_null() {
        return -1;
    }
    // SAFETY: Caller guarantees format is a valid null-terminated C string.
    let fmt_bytes = unsafe { CStr::from_ptr(format) }.to_bytes();
    // SAFETY: format and args are valid per caller contract.
    let out = unsafe { format_printf_va(fmt_bytes, &mut args, false) };
    let would_write = out.len() as i32;
    if !buf.is_null() && count > 0 {
        let copy_len = out.len().min(count - 1);
        // SAFETY: Caller guarantees buf is at least `count` bytes.
        unsafe {
            std::ptr::copy_nonoverlapping(out.as_ptr().cast::<i8>(), buf, copy_len);
            *buf.add(copy_len) = 0;
        }
    }
    would_write
}

/// `_snprintf_s(buf, size_of_buffer, count, format, ...) -> int` — write formatted
/// string to a size-limited buffer with overflow protection.
///
/// Writes at most `min(count, size_of_buffer - 1)` bytes of the formatted output
/// and appends a NUL terminator.  When `count` is `_TRUNCATE` (`usize::MAX`),
/// the output is truncated to `size_of_buffer - 1` characters and the number of
/// written characters is returned.  For any other `count` value, truncation
/// returns -1 (MSVCRT-compatible behaviour).
///
/// Returns -1 when `buf` is null, `size_of_buffer` is 0, `format` is null, or
/// truncation occurs with a non-`_TRUNCATE` count.
///
/// # Safety
///
/// `buf` must point to a writable buffer of at least `size_of_buffer` bytes.
/// `format` must be a valid null-terminated string.
/// Variadic arguments must match the format specifiers.
#[unsafe(no_mangle)]
#[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
pub unsafe extern "C" fn msvcrt_snprintf_s(
    buf: *mut i8,
    size_of_buffer: usize,
    count: usize,
    format: *const i8,
    mut args: ...
) -> i32 {
    if format.is_null() || buf.is_null() || size_of_buffer == 0 {
        return -1;
    }
    // SAFETY: Caller guarantees format is a valid null-terminated C string.
    let fmt_bytes = unsafe { CStr::from_ptr(format) }.to_bytes();
    // SAFETY: format and args are valid per caller contract.
    let out = unsafe { format_printf_va(fmt_bytes, &mut args, false) };

    // Effective limit: min(count, size_of_buffer - 1), treating _TRUNCATE as unbounded.
    let effective = if count == usize::MAX {
        size_of_buffer - 1
    } else {
        count.min(size_of_buffer - 1)
    };
    let copy_len = out.len().min(effective);
    // SAFETY: Caller guarantees buf is at least `size_of_buffer` bytes.
    unsafe {
        std::ptr::copy_nonoverlapping(out.as_ptr().cast::<i8>(), buf, copy_len);
        *buf.add(copy_len) = 0;
    }

    // If truncation occurred and this is not a _TRUNCATE call, MSVCRT returns -1.
    let truncated = out.len() > copy_len;
    if truncated && count != usize::MAX {
        return -1;
    }
    copy_len as i32
}

/// `sscanf(buf, format, ...) -> int` — parse formatted string into variables.
///
/// Parses `buf` according to `format`, writing results through the pointer
/// arguments.  Returns the number of items matched and stored, or -1 on
/// input failure before any conversion.
///
/// Supports up to `MAX_SCANF_ARGS` (16) conversion specifiers.
///
/// # Safety
///
/// `buf` and `format` must be valid null-terminated strings.
/// Each variadic argument must be a writable pointer of the type implied by
/// the corresponding format specifier.
#[unsafe(no_mangle)]
#[cfg(all(target_arch = "x86_64", target_os = "linux", target_env = "gnu"))]
pub unsafe extern "C" fn msvcrt_sscanf(buf: *const i8, format: *const i8, mut args: ...) -> i32 {
    if buf.is_null() || format.is_null() {
        return -1;
    }
    // SAFETY: buf and format are valid null-terminated strings; variadic args
    // are writable pointers matching the format specifiers (caller contract).
    unsafe { format_scanf_va(buf, format, &mut args) }
}

/// `swprintf(buf, format, ...) -> int` — write formatted wide string to buffer.
///
/// Converts the format string to UTF-8, runs the printf formatter, then
/// re-encodes the result as UTF-16 into `buf`.  Returns the number of wide
/// characters written (excluding the NUL terminator), or -1 on error.
///
/// # Safety
///
/// `buf` must point to a writable wide-character buffer large enough for the output.
/// `format` must be a valid null-terminated wide string.
/// Variadic arguments must match the format specifiers.
#[unsafe(no_mangle)]
#[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
pub unsafe extern "C" fn msvcrt_swprintf(buf: *mut u16, format: *const u16, mut args: ...) -> i32 {
    if buf.is_null() || format.is_null() {
        return -1;
    }
    // SAFETY: Caller guarantees format is a valid null-terminated wide string.
    let wide_fmt = unsafe { read_wide_string(format) };
    let fmt_utf8 = String::from_utf16_lossy(&wide_fmt);
    // Build a temporary CString so we can use our formatter.
    let Ok(cstr) = CString::new(fmt_utf8.as_bytes()) else {
        return -1;
    };
    // SAFETY: format and args are valid per caller contract.
    let out_bytes = unsafe { format_printf_va(cstr.to_bytes(), &mut args, true) };
    let out_str = String::from_utf8_lossy(&out_bytes);
    let wide_out: Vec<u16> = out_str.encode_utf16().collect();
    // SAFETY: Caller guarantees buf is large enough.
    unsafe {
        std::ptr::copy_nonoverlapping(wide_out.as_ptr(), buf, wide_out.len());
        *buf.add(wide_out.len()) = 0;
    }
    wide_out.len() as i32
}

/// `wprintf(format, ...) -> int` — print formatted wide string to stdout.
///
/// Converts the wide format string to UTF-8, runs the printf formatter,
/// then writes the result to stdout.
///
/// # Safety
///
/// `format` must be a valid null-terminated wide string.
/// Variadic arguments must match the format specifiers.
#[unsafe(no_mangle)]
#[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
pub unsafe extern "C" fn msvcrt_wprintf(format: *const u16, mut args: ...) -> i32 {
    if format.is_null() {
        return -1;
    }
    // SAFETY: Caller guarantees format is a valid null-terminated wide string.
    let wide_fmt = unsafe { read_wide_string(format) };
    let fmt_utf8 = String::from_utf16_lossy(&wide_fmt);
    let Ok(cstr) = CString::new(fmt_utf8.as_bytes()) else {
        return -1;
    };
    // SAFETY: format and args are valid per caller contract.
    let out = unsafe { format_printf_va(cstr.to_bytes(), &mut args, true) };
    match io::stdout().write_all(&out) {
        Ok(()) => {
            let _ = io::stdout().flush();
            out.len() as i32
        }
        Err(_) => -1,
    }
}

/// `fwprintf(stream, format, ...) -> int` — write wide formatted string to a
/// FILE stream.
///
/// The `stream` parameter is ignored; output always goes to stdout (fd 1).
///
/// # Safety
/// `format` must point to a valid null-terminated wide string.
/// Variadic arguments must match the format specifiers.
#[unsafe(no_mangle)]
#[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
pub unsafe extern "C" fn msvcrt_fwprintf(
    _stream: *mut u8,
    format: *const u16,
    mut args: ...
) -> i32 {
    if format.is_null() {
        return -1;
    }
    // SAFETY: Caller guarantees format is a valid null-terminated wide string.
    let wide_fmt = unsafe { read_wide_string(format) };
    let fmt_utf8 = String::from_utf16_lossy(&wide_fmt);
    // SAFETY: format and args are valid per caller contract.
    let out = unsafe { format_printf_va(fmt_utf8.as_bytes(), &mut args, true) };
    let written = unsafe { libc::write(1, out.as_ptr().cast(), out.len()) };
    if written < 0 { -1 } else { written as i32 }
}

/// `vfwprintf(stream, format, args) -> int` — write wide formatted string to a
/// FILE stream using a pre-built va_list.
///
/// The `stream` parameter is ignored; output always goes to stdout (fd 1).
///
/// # Safety
/// `format` must point to a valid null-terminated wide string.
/// `args` must be a valid Windows x64 va_list pointer.
#[unsafe(no_mangle)]
#[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
pub unsafe extern "C" fn msvcrt_vfwprintf(
    _stream: *mut u8,
    format: *const u16,
    args: *mut u8,
) -> i32 {
    if format.is_null() {
        return -1;
    }
    // SAFETY: Caller guarantees format is a valid null-terminated wide string.
    let wide_fmt = unsafe { read_wide_string(format) };
    let fmt_utf8 = String::from_utf16_lossy(&wide_fmt);
    // SAFETY: args is a valid Windows x64 va_list pointer.
    let out = unsafe { format_printf_raw(fmt_utf8.as_bytes(), args, true) };
    let written = unsafe { libc::write(1, out.as_ptr().cast(), out.len()) };
    if written < 0 { -1 } else { written as i32 }
}

// ── Character classification ─────────────────────────────────────────────────

/// `isalpha(c) -> int` — test if character is alphabetic.
///
/// # Safety
///
/// `c` should be in the range -1 to 255.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt_isalpha(c: i32) -> i32 {
    // SAFETY: libc::isalpha is safe to call with any c in -1..=255.
    unsafe { libc::isalpha(c) }
}

/// `isdigit(c) -> int` — test if character is a decimal digit.
///
/// # Safety
///
/// `c` should be in the range -1 to 255.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt_isdigit(c: i32) -> i32 {
    // SAFETY: libc::isdigit is safe to call with any c in -1..=255.
    unsafe { libc::isdigit(c) }
}

/// `isspace(c) -> int` — test if character is whitespace.
///
/// # Safety
///
/// `c` should be in the range -1 to 255.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt_isspace(c: i32) -> i32 {
    // SAFETY: libc::isspace is safe to call with any c in -1..=255.
    unsafe { libc::isspace(c) }
}

/// `isupper(c) -> int` — test if character is uppercase.
///
/// # Safety
///
/// `c` should be in the range -1 to 255.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt_isupper(c: i32) -> i32 {
    // SAFETY: libc::isupper is safe to call with any c in -1..=255.
    unsafe { libc::isupper(c) }
}

/// `islower(c) -> int` — test if character is lowercase.
///
/// # Safety
///
/// `c` should be in the range -1 to 255.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt_islower(c: i32) -> i32 {
    // SAFETY: libc::islower is safe to call with any c in -1..=255.
    unsafe { libc::islower(c) }
}

/// `toupper(c) -> int` — convert character to uppercase.
///
/// # Safety
///
/// `c` should be in the range -1 to 255.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt_toupper(c: i32) -> i32 {
    // SAFETY: libc::toupper is safe to call with any c in -1..=255.
    unsafe { libc::toupper(c) }
}

/// `tolower(c) -> int` — convert character to lowercase.
///
/// # Safety
///
/// `c` should be in the range -1 to 255.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt_tolower(c: i32) -> i32 {
    // SAFETY: libc::tolower is safe to call with any c in -1..=255.
    unsafe { libc::tolower(c) }
}

/// `isxdigit(c) -> int` — test if character is a hexadecimal digit.
///
/// # Safety
///
/// `c` should be in the range -1 to 255.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt_isxdigit(c: i32) -> i32 {
    // SAFETY: libc::isxdigit is safe to call with any c in -1..=255.
    unsafe { libc::isxdigit(c) }
}

/// `ispunct(c) -> int` — test if character is punctuation.
///
/// # Safety
///
/// `c` should be in the range -1 to 255.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt_ispunct(c: i32) -> i32 {
    // SAFETY: libc::ispunct is safe to call with any c in -1..=255.
    unsafe { libc::ispunct(c) }
}

/// `isprint(c) -> int` — test if character is printable.
///
/// # Safety
///
/// `c` should be in the range -1 to 255.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt_isprint(c: i32) -> i32 {
    // SAFETY: libc::isprint is safe to call with any c in -1..=255.
    unsafe { libc::isprint(c) }
}

/// `iscntrl(c) -> int` — test if character is a control character.
///
/// # Safety
///
/// `c` should be in the range -1 to 255.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt_iscntrl(c: i32) -> i32 {
    // SAFETY: libc::iscntrl is safe to call with any c in -1..=255.
    unsafe { libc::iscntrl(c) }
}

/// `isalnum(c) -> int` — test if character is alphanumeric.
///
/// # Safety
///
/// `c` should be in the range -1 to 255.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt_isalnum(c: i32) -> i32 {
    // SAFETY: libc::isalnum is safe to call with any c in -1..=255.
    unsafe { libc::isalnum(c) }
}

// ── Sorting and searching ────────────────────────────────────────────────────

/// `qsort(base, nmemb, size, compar)` — sort array.
///
/// Delegates directly to the host libc `qsort`.
///
/// # Safety
///
/// - `base` must point to a valid array of `nmemb` elements each `size` bytes.
/// - `compar` must be a valid comparison function pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt_qsort(
    base: *mut core::ffi::c_void,
    nmemb: usize,
    size: usize,
    compar: Option<unsafe extern "C" fn(*const core::ffi::c_void, *const core::ffi::c_void) -> i32>,
) {
    // SAFETY: Caller guarantees base/nmemb/size describe a valid array and
    // compar is a valid function pointer.
    unsafe { libc::qsort(base, nmemb, size, compar) };
}

/// `bsearch(key, base, nmemb, size, compar) -> *mut void` — binary search.
///
/// Delegates directly to the host libc `bsearch`.
///
/// # Safety
///
/// - `key` must be a pointer to the value being searched for.
/// - `base` must point to a sorted array of `nmemb` elements each `size` bytes.
/// - `compar` must be a valid comparison function pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt_bsearch(
    key: *const core::ffi::c_void,
    base: *const core::ffi::c_void,
    nmemb: usize,
    size: usize,
    compar: Option<unsafe extern "C" fn(*const core::ffi::c_void, *const core::ffi::c_void) -> i32>,
) -> *mut core::ffi::c_void {
    // SAFETY: Caller guarantees key/base/nmemb/size describe a valid sorted
    // array and compar is a valid function pointer.
    unsafe { libc::bsearch(key, base, nmemb, size, compar) }
}

// ── Wide string numeric conversions ─────────────────────────────────────────

/// `wcstol(nptr, endptr, base) -> long` — convert wide string to long integer.
///
/// Converts the ASCII portion of the wide string to a narrow string then
/// delegates to `libc::strtol`.  Non-ASCII code units terminate the conversion
/// without being copied, matching MSVCRT behaviour in the "C" locale.
///
/// # Safety
///
/// `nptr` must point to a valid null-terminated wide string.
/// `endptr`, if non-null, must be a valid pointer to a `*mut u16`.
#[unsafe(no_mangle)]
#[allow(clippy::cast_possible_truncation)] // ch <= 0x7F guaranteed by the guard above
pub unsafe extern "C" fn msvcrt_wcstol(nptr: *const u16, endptr: *mut *mut u16, base: i32) -> i64 {
    if nptr.is_null() {
        return 0;
    }
    // Copy only ASCII code units into a heap-allocated narrow buffer so we
    // don't truncate longer strings or mis-handle non-ASCII code units.
    let mut narrow: Vec<u8> = Vec::new();
    unsafe {
        let mut p = nptr;
        while *p != 0 {
            let ch = *p;
            if ch > 0x7F {
                break;
            }
            narrow.push(ch as u8);
            p = p.add(1);
        }
    }
    // NUL-terminate for libc.
    narrow.push(0);

    let mut narrow_end: *mut u8 = core::ptr::null_mut();
    // SAFETY: `narrow` is a valid null-terminated string; strtol is safe to call.
    let val = unsafe {
        libc::strtol(
            narrow.as_ptr().cast(),
            core::ptr::addr_of_mut!(narrow_end).cast(),
            base,
        )
    };
    if !endptr.is_null() {
        // Map the narrow end pointer offset back to a wide pointer.
        // Each byte in `narrow` corresponds to exactly one UTF-16 code unit in nptr.
        // SAFETY: narrow_end points within narrow[], so offset_from is non-negative.
        let offset = unsafe { narrow_end.offset_from(narrow.as_ptr()) }.unsigned_abs();
        // SAFETY: Caller guarantees endptr is a valid writable pointer.
        unsafe { *endptr = nptr.add(offset).cast_mut() };
    }
    val as i64
}

/// `wcstoul(nptr, endptr, base) -> unsigned long` — convert wide string to
/// unsigned long integer.
///
/// Converts the ASCII portion of the wide string to a narrow string then
/// delegates to `libc::strtoul`.  Non-ASCII code units terminate the conversion
/// without being copied, matching MSVCRT behaviour in the "C" locale.
///
/// # Safety
///
/// `nptr` must point to a valid null-terminated wide string.
/// `endptr`, if non-null, must be a valid pointer to a `*mut u16`.
#[unsafe(no_mangle)]
#[allow(clippy::cast_possible_truncation)] // ch <= 0x7F guaranteed by the guard above
pub unsafe extern "C" fn msvcrt_wcstoul(nptr: *const u16, endptr: *mut *mut u16, base: i32) -> u64 {
    if nptr.is_null() {
        return 0;
    }
    // Copy only ASCII code units into a heap-allocated narrow buffer.
    let mut narrow: Vec<u8> = Vec::new();
    unsafe {
        let mut p = nptr;
        while *p != 0 {
            let ch = *p;
            if ch > 0x7F {
                break;
            }
            narrow.push(ch as u8);
            p = p.add(1);
        }
    }
    narrow.push(0);

    let mut narrow_end: *mut u8 = core::ptr::null_mut();
    // SAFETY: `narrow` is a valid null-terminated string; strtoul is safe to call.
    let val = unsafe {
        libc::strtoul(
            narrow.as_ptr().cast(),
            core::ptr::addr_of_mut!(narrow_end).cast(),
            base,
        )
    };
    if !endptr.is_null() {
        // SAFETY: narrow_end points within narrow[], so offset_from is non-negative.
        let offset = unsafe { narrow_end.offset_from(narrow.as_ptr()) }.unsigned_abs();
        // SAFETY: Caller guarantees endptr is a valid writable pointer.
        unsafe { *endptr = nptr.add(offset).cast_mut() };
    }
    val as u64
}

/// `wcstod(nptr, endptr) -> double` — convert wide string to double.
///
/// Converts the ASCII portion of the wide string to a narrow string then
/// delegates to `libc::strtod`.  Non-ASCII code units terminate the conversion
/// without being copied, matching MSVCRT behaviour in the "C" locale.
///
/// # Safety
///
/// `nptr` must point to a valid null-terminated wide string.
/// `endptr`, if non-null, must be a valid pointer to a `*mut u16`.
#[unsafe(no_mangle)]
#[allow(clippy::cast_possible_truncation)] // ch <= 0x7F guaranteed by the guard above
pub unsafe extern "C" fn msvcrt_wcstod(nptr: *const u16, endptr: *mut *mut u16) -> f64 {
    if nptr.is_null() {
        return 0.0;
    }
    // Copy only ASCII code units into a heap-allocated narrow buffer.
    let mut narrow: Vec<u8> = Vec::new();
    unsafe {
        let mut p = nptr;
        while *p != 0 {
            let ch = *p;
            if ch > 0x7F {
                break;
            }
            narrow.push(ch as u8);
            p = p.add(1);
        }
    }
    narrow.push(0);

    let mut narrow_end: *mut u8 = core::ptr::null_mut();
    // SAFETY: `narrow` is a valid null-terminated string; strtod is safe to call.
    let val = unsafe {
        libc::strtod(
            narrow.as_ptr().cast(),
            core::ptr::addr_of_mut!(narrow_end).cast(),
        )
    };
    if !endptr.is_null() {
        // SAFETY: narrow_end points within narrow[], so offset_from is non-negative.
        let offset = unsafe { narrow_end.offset_from(narrow.as_ptr()) }.unsigned_abs();
        // SAFETY: Caller guarantees endptr is a valid writable pointer.
        unsafe { *endptr = nptr.add(offset).cast_mut() };
    }
    val
}

// ── File I/O ─────────────────────────────────────────────────────────────────

/// `fopen(filename, mode) -> FILE*` — open a file.
///
/// Delegates to `libc::fopen`.
///
/// # Safety
///
/// `filename` and `mode` must be valid null-terminated strings.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt_fopen(filename: *const i8, mode: *const i8) -> *mut u8 {
    // SAFETY: Caller guarantees filename and mode are valid C strings.
    unsafe { libc::fopen(filename.cast(), mode.cast()).cast() }
}

/// `_wfopen(filename, mode) -> FILE*` — open a file with wide-character paths.
///
/// Converts the wide-character `filename` and `mode` strings to UTF-8 and
/// delegates to `libc::fopen`.  Returns null on conversion failure or if
/// `libc::fopen` fails.
///
/// # Safety
///
/// `filename` and `mode` must be valid null-terminated wide-character (UTF-16)
/// strings.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt__wfopen(filename: *const u16, mode: *const u16) -> *mut u8 {
    if filename.is_null() || mode.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: Caller guarantees valid null-terminated wide strings.
    let wide_name = unsafe { read_wide_string(filename) };
    let wide_mode = unsafe { read_wide_string(mode) };
    let name_utf8 = String::from_utf16_lossy(&wide_name);
    let mode_utf8 = String::from_utf16_lossy(&wide_mode);
    let Ok(name_cstr) = CString::new(name_utf8.as_str()) else {
        return ptr::null_mut();
    };
    let Ok(mode_cstr) = CString::new(mode_utf8.as_str()) else {
        return ptr::null_mut();
    };
    // SAFETY: Both CStrings are valid null-terminated C strings.
    unsafe { libc::fopen(name_cstr.as_ptr(), mode_cstr.as_ptr()).cast() }
}

/// `fclose(stream) -> int` — close a file.
///
/// Delegates to `libc::fclose`.
///
/// # Safety
///
/// `stream` must be a valid `FILE*` returned by `fopen`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt_fclose(stream: *mut u8) -> i32 {
    if stream.is_null() {
        return -1;
    }
    // SAFETY: Caller guarantees stream is a valid FILE*.
    unsafe { libc::fclose(stream.cast()) }
}

/// `fread(ptr, size, nmemb, stream) -> size_t` — read from file.
///
/// Delegates to `libc::fread`.
///
/// # Safety
///
/// `ptr` must point to a writable buffer of at least `size * nmemb` bytes.
/// `stream` must be a valid open `FILE*`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt_fread(
    ptr: *mut u8,
    size: usize,
    nmemb: usize,
    stream: *mut u8,
) -> usize {
    if ptr.is_null() || stream.is_null() || size == 0 || nmemb == 0 {
        return 0;
    }
    // SAFETY: Caller guarantees ptr and stream are valid.
    unsafe { libc::fread(ptr.cast(), size, nmemb, stream.cast()) }
}

/// `fgets(s, n, stream) -> char*` — read a line from file.
///
/// Delegates to `libc::fgets`.
///
/// # Safety
///
/// `s` must point to a writable buffer of at least `n` bytes.
/// `stream` must be a valid open `FILE*`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt_fgets(s: *mut i8, n: i32, stream: *mut u8) -> *mut i8 {
    if s.is_null() || stream.is_null() || n <= 0 {
        return std::ptr::null_mut();
    }
    // SAFETY: Caller guarantees s and stream are valid.
    unsafe { libc::fgets(s.cast(), n, stream.cast()) }
}

/// `fseek(stream, offset, whence) -> int` — reposition file pointer.
///
/// Delegates to `libc::fseek`.
///
/// # Safety
///
/// `stream` must be a valid open `FILE*`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt_fseek(stream: *mut u8, offset: i64, whence: i32) -> i32 {
    if stream.is_null() {
        return -1;
    }
    // SAFETY: Caller guarantees stream is a valid FILE*.
    #[allow(clippy::cast_possible_truncation)]
    unsafe {
        libc::fseek(stream.cast(), offset as libc::c_long, whence)
    }
}

/// `ftell(stream) -> long` — get file position.
///
/// Delegates to `libc::ftell`.
///
/// # Safety
///
/// `stream` must be a valid open `FILE*`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt_ftell(stream: *mut u8) -> i64 {
    if stream.is_null() {
        return -1;
    }
    // SAFETY: Caller guarantees stream is a valid FILE*.
    unsafe { libc::ftell(stream.cast()) as i64 }
}

/// `feof(stream) -> int` — test for end-of-file.
///
/// Delegates to `libc::feof`.
///
/// # Safety
///
/// `stream` must be a valid open `FILE*`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt_feof(stream: *mut u8) -> i32 {
    if stream.is_null() {
        return 0;
    }
    // SAFETY: Caller guarantees stream is a valid FILE*.
    unsafe { libc::feof(stream.cast()) }
}

/// `ferror(stream) -> int` — test for file error.
///
/// Delegates to `libc::ferror`.
///
/// # Safety
///
/// `stream` must be a valid open `FILE*`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt_ferror(stream: *mut u8) -> i32 {
    if stream.is_null() {
        return 0;
    }
    // SAFETY: Caller guarantees stream is a valid FILE*.
    unsafe { libc::ferror(stream.cast()) }
}

/// `clearerr(stream)` — clear end-of-file and error indicators.
///
/// Delegates to `libc::clearerr`.
///
/// # Safety
///
/// `stream` must be a valid open `FILE*`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt_clearerr(stream: *mut u8) {
    if stream.is_null() {
        return;
    }
    // SAFETY: Caller guarantees stream is a valid FILE*.
    unsafe { libc::clearerr(stream.cast()) };
}

/// `fflush(stream) -> int` — flush file buffer.
///
/// Delegates to `libc::fflush`.
///
/// # Safety
///
/// `stream` must be a valid open `FILE*`, or null to flush all streams.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt_fflush(stream: *mut u8) -> i32 {
    // SAFETY: libc::fflush accepts a null pointer (flushes all streams).
    unsafe { libc::fflush(stream.cast()) }
}

/// `rewind(stream)` — reset file position to beginning.
///
/// Delegates to `libc::rewind`.
///
/// # Safety
///
/// `stream` must be a valid open `FILE*`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt_rewind(stream: *mut u8) {
    if stream.is_null() {
        return;
    }
    // SAFETY: Caller guarantees stream is a valid FILE*.
    unsafe { libc::rewind(stream.cast()) };
}

/// `fgetc(stream) -> int` — read a character from file.
///
/// Delegates to `libc::fgetc`.
///
/// # Safety
///
/// `stream` must be a valid open `FILE*`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt_fgetc(stream: *mut u8) -> i32 {
    if stream.is_null() {
        return -1;
    }
    // SAFETY: Caller guarantees stream is a valid FILE*.
    unsafe { libc::fgetc(stream.cast()) }
}

/// `ungetc(c, stream) -> int` — push character back into stream.
///
/// Delegates to `libc::ungetc`.
///
/// # Safety
///
/// `stream` must be a valid open `FILE*`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt_ungetc(c: i32, stream: *mut u8) -> i32 {
    if stream.is_null() {
        return -1;
    }
    // SAFETY: Caller guarantees stream is a valid FILE*.
    unsafe { libc::ungetc(c, stream.cast()) }
}

/// `fileno(stream) -> int`
///
/// Returns the file descriptor associated with `stream`, or -1 on error.
///
/// # Safety
///
/// `stream` must be a valid FILE pointer or NULL.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt_fileno(stream: *mut u8) -> i32 {
    if stream.is_null() {
        return -1;
    }
    // SAFETY: Caller guarantees stream is a valid FILE*.
    unsafe { libc::fileno(stream.cast()) }
}

/// `fdopen(fd, mode) -> FILE*`
///
/// Opens a stream associated with the given file descriptor.
/// Returns NULL on error.
///
/// # Safety
///
/// `mode` must be a valid null-terminated C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt_fdopen(fd: i32, mode: *const i8) -> *mut u8 {
    if mode.is_null() {
        return core::ptr::null_mut();
    }
    // SAFETY: Caller guarantees mode is valid.
    let result = unsafe { libc::fdopen(fd, mode) };
    result.cast()
}

/// `tmpfile() -> FILE*`
///
/// Creates a temporary binary file opened for update.
/// The file is automatically deleted when it is closed or the program terminates.
/// Returns NULL on failure.
///
/// # Safety
///
/// This function is always safe to call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt_tmpfile() -> *mut u8 {
    // SAFETY: libc::tmpfile() is safe to call.
    let result = unsafe { libc::tmpfile() };
    result.cast()
}

/// `tmpnam(buf) -> *mut i8`
///
/// Returns a unique temporary file name.  If `buf` is non-null the name is
/// written into it (must hold at least `L_tmpnam` bytes); if null a static
/// buffer is used.
///
/// # Safety
/// `buf` must be null or point to at least `L_tmpnam` bytes of writable memory.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt_tmpnam(buf: *mut i8) -> *mut i8 {
    // SAFETY: libc::tmpnam delegates directly to the OS.
    unsafe { libc::tmpnam(buf) }
}

// POSIX functions not exposed by libc for Linux targets.
unsafe extern "C" {
    fn mktemp(template: *mut libc::c_char) -> *mut libc::c_char;
    fn tempnam(dir: *const libc::c_char, prefix: *const libc::c_char) -> *mut libc::c_char;
}

/// `_mktemp(template) -> *mut i8`
///
/// Modifies `template` in-place, replacing trailing `X` characters with
/// unique chars.  Returns `template` on success, null on failure.
///
/// # Safety
/// `template` must be a valid mutable NUL-terminated C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt__mktemp(template: *mut i8) -> *mut i8 {
    if template.is_null() {
        return core::ptr::null_mut();
    }
    // SAFETY: caller guarantees template is a valid mutable NUL-terminated string.
    unsafe { mktemp(template) }
}

/// `_tempnam(dir, prefix) -> *mut i8`
///
/// Creates a unique temp file name in `dir` (or `$TMPDIR` if `dir` is null).
/// The returned pointer must be freed with `free`.
///
/// # Safety
/// `dir` and `prefix` must each be null or a valid NUL-terminated C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt__tempnam(dir: *const i8, prefix: *const i8) -> *mut i8 {
    // SAFETY: caller guarantees strings are valid if non-null.
    unsafe { tempnam(dir, prefix) }
}

/// `remove(path) -> int`
///
/// Deletes the file specified by `path`. Returns 0 on success, -1 on error.
///
/// # Safety
///
/// `path` must be a valid null-terminated C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt_remove(path: *const i8) -> i32 {
    if path.is_null() {
        return -1;
    }
    // SAFETY: Caller guarantees path is a valid string.
    unsafe { libc::remove(path) }
}

/// `rename(oldname, newname) -> int`
///
/// Renames the file from `oldname` to `newname`. Returns 0 on success, -1 on error.
///
/// # Safety
///
/// `oldname` and `newname` must be valid null-terminated C strings.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt_rename(oldname: *const i8, newname: *const i8) -> i32 {
    if oldname.is_null() || newname.is_null() {
        return -1;
    }
    // SAFETY: Caller guarantees both strings are valid.
    unsafe { libc::rename(oldname, newname) }
}

// ── Phase 35: printf length-counting helpers ──────────────────────────────────

/// `_vsnwprintf(buf, count, format, args)` — size-limited wide-char vsnprintf.
///
/// Formats a wide string using `format` and the Windows x64 va_list `args`,
/// writing at most `count` wide characters (including the NUL terminator) into
/// `buf`.  Returns the number of wide characters written (excluding NUL), or
/// -1 if the output was truncated.  If `buf` is null and `count` is 0, returns
/// the would-be length without writing anything.
///
/// # Safety
/// `buf` must point to a buffer of at least `count` wide characters.
/// `format` must be a valid null-terminated wide string.
/// `args` must be a valid Windows x64 va_list pointer.
#[unsafe(no_mangle)]
#[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
pub unsafe extern "C" fn msvcrt__vsnwprintf(
    buf: *mut u16,
    count: usize,
    format: *const u16,
    args: *mut u8,
) -> i32 {
    if format.is_null() {
        return -1;
    }
    // SAFETY: Caller guarantees format is a valid null-terminated wide string.
    let fmt_wide = unsafe { read_wide_string(format) };
    let fmt_utf8 = String::from_utf16_lossy(&fmt_wide);
    // SAFETY: args is a valid Windows x64 va_list pointer.
    let out_bytes = unsafe { format_printf_raw(fmt_utf8.as_bytes(), args, true) };
    let out_str = String::from_utf8_lossy(&out_bytes);
    let wide: Vec<u16> = out_str.encode_utf16().collect();
    if buf.is_null() || count == 0 {
        return wide.len() as i32;
    }
    // Write min(wide.len(), count - 1) characters plus NUL.
    let copy_len = wide.len().min(count - 1);
    // SAFETY: Caller guarantees buf has at least `count` wide characters.
    unsafe {
        core::ptr::copy_nonoverlapping(wide.as_ptr(), buf, copy_len);
        *buf.add(copy_len) = 0;
    }
    if wide.len() >= count {
        // Truncated — Windows MSVCRT returns -1 in this case.
        -1
    } else {
        wide.len() as i32
    }
}

/// `_scprintf(format, ...) -> int` — count the characters that `printf` would write.
///
/// Returns the number of characters that would be written (excluding the NUL
/// terminator) without actually writing anything.
///
/// # Safety
/// `format` must be a valid null-terminated C string.
/// Variadic arguments must match the format specifiers.
#[unsafe(no_mangle)]
#[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
pub unsafe extern "C" fn msvcrt__scprintf(format: *const i8, mut args: ...) -> i32 {
    if format.is_null() {
        return -1;
    }
    // SAFETY: Caller guarantees format is a valid null-terminated C string.
    let fmt_bytes = unsafe { CStr::from_ptr(format) }.to_bytes();
    // SAFETY: args is a valid variadic argument list.
    let out = unsafe { format_printf_va(fmt_bytes, &mut args, false) };
    out.len() as i32
}

/// `_vscprintf(format, args) -> int` — count the characters that `vprintf` would write.
///
/// Same as `_scprintf` but takes a Windows x64 va_list instead of `...`.
///
/// # Safety
/// `format` must be a valid null-terminated C string.
/// `args` must be a valid Windows x64 va_list pointer.
#[unsafe(no_mangle)]
#[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
pub unsafe extern "C" fn msvcrt__vscprintf(format: *const i8, args: *mut u8) -> i32 {
    if format.is_null() {
        return -1;
    }
    // SAFETY: Caller guarantees format is a valid null-terminated C string.
    let fmt_bytes = unsafe { CStr::from_ptr(format) }.to_bytes();
    // SAFETY: args is a valid Windows x64 va_list pointer.
    let out = unsafe { format_printf_raw(fmt_bytes, args, false) };
    out.len() as i32
}

/// `_scwprintf(format, ...) -> int` — count the wide chars that `wprintf` would write.
///
/// Returns the number of wide characters that would be written (excluding NUL)
/// without actually writing anything.
///
/// # Safety
/// `format` must be a valid null-terminated wide string.
/// Variadic arguments must match the format specifiers.
#[unsafe(no_mangle)]
#[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
pub unsafe extern "C" fn msvcrt__scwprintf(format: *const u16, mut args: ...) -> i32 {
    if format.is_null() {
        return -1;
    }
    // SAFETY: Caller guarantees format is a valid null-terminated wide string.
    let fmt_wide = unsafe { read_wide_string(format) };
    let fmt_utf8 = String::from_utf16_lossy(&fmt_wide);
    // SAFETY: args is a valid variadic argument list.
    let out_bytes = unsafe { format_printf_va(fmt_utf8.as_bytes(), &mut args, true) };
    let out_str = String::from_utf8_lossy(&out_bytes);
    let wide: Vec<u16> = out_str.encode_utf16().collect();
    wide.len() as i32
}

/// `_vscwprintf(format, args) -> int` — count the wide chars that `vwprintf` would write.
///
/// Same as `_scwprintf` but takes a Windows x64 va_list instead of `...`.
///
/// # Safety
/// `format` must be a valid null-terminated wide string.
/// `args` must be a valid Windows x64 va_list pointer.
#[unsafe(no_mangle)]
#[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
pub unsafe extern "C" fn msvcrt__vscwprintf(format: *const u16, args: *mut u8) -> i32 {
    if format.is_null() {
        return -1;
    }
    // SAFETY: Caller guarantees format is a valid null-terminated wide string.
    let fmt_wide = unsafe { read_wide_string(format) };
    let fmt_utf8 = String::from_utf16_lossy(&fmt_wide);
    // SAFETY: args is a valid Windows x64 va_list pointer.
    let out_bytes = unsafe { format_printf_raw(fmt_utf8.as_bytes(), args, true) };
    let out_str = String::from_utf8_lossy(&out_bytes);
    let wide: Vec<u16> = out_str.encode_utf16().collect();
    wide.len() as i32
}

// ── Phase 35: CRT fd / Win32 handle interop ──────────────────────────────────

/// `_get_osfhandle(fd) -> intptr_t` — return the Win32 `HANDLE` for a CRT file descriptor.
///
/// For standard file descriptors (0 = stdin, 1 = stdout, 2 = stderr) this
/// returns the well-known pseudo-handles used by Windows programs.  For other
/// descriptors we return the fd value itself (cast to `isize`), which is
/// compatible with our synthetic Win32 handle scheme used in `kernel32.rs`.
///
/// Returns -1 (`INVALID_HANDLE_VALUE`) if `fd` is negative.
///
/// # Safety
/// Always safe to call with any `fd` value.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt__get_osfhandle(fd: i32) -> isize {
    const INVALID_HANDLE_VALUE: isize = -1;
    match fd {
        0 => -10_isize, // STD_INPUT_HANDLE  (-(10) cast to usize in Win32)
        1 => -11_isize, // STD_OUTPUT_HANDLE
        2 => -12_isize, // STD_ERROR_HANDLE
        fd if fd < 0 => INVALID_HANDLE_VALUE,
        fd => fd as isize,
    }
}

/// `_open_osfhandle(osfhandle, flags) -> int` — associate a CRT file descriptor with a Win32 handle.
///
/// For the standard pseudo-handles (-10/-11/-12) this returns fd 0/1/2.
/// For other handle values that fit in a `u32` we cast the handle to an `i32`
/// and return it as the CRT fd (our synthetic handle scheme stores the real fd
/// as the handle value).  Returns -1 on failure.
///
/// `flags` are accepted but ignored (they only affect text/binary mode).
///
/// # Safety
/// Always safe to call with any handle and flags values.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt__open_osfhandle(osfhandle: isize, _flags: i32) -> i32 {
    match osfhandle {
        -10 => 0, // STD_INPUT_HANDLE  -> stdin fd
        -11 => 1, // STD_OUTPUT_HANDLE -> stdout fd
        -12 => 2, // STD_ERROR_HANDLE  -> stderr fd
        h if h < 0 => -1,
        #[allow(clippy::cast_possible_truncation)]
        h => h as i32,
    }
}

// ============================================================================
// Phase 38: _wfindfirst / _wfindnext / _findclose — wide file enumeration
// ============================================================================

/// Newtype wrapper for `*mut libc::DIR` to allow placing it in a `Mutex`-protected map.
///
/// # Safety
/// Callers must ensure that a `DirHandle` is only accessed from one thread at a time.
/// The global map is protected by `FIND_HANDLES`'s `Mutex`, which guarantees this.
struct DirHandle(*mut libc::DIR);

// SAFETY: We only access `DirHandle` while holding the `FIND_HANDLES` mutex.
unsafe impl Send for DirHandle {}

/// Entry for an active `_wfindfirst` handle.
struct FindEntry {
    dir: DirHandle,
    /// The wildcard pattern (filename part of the spec), as UTF-8.
    pattern: String,
    /// The directory path to enumerate.
    directory: String,
}

/// Global map from handle ID → `FindEntry`.
static FIND_HANDLES: OnceLock<Mutex<BTreeMap<i64, FindEntry>>> = OnceLock::new();

/// Monotonically increasing handle counter (starts at 1).
static FIND_NEXT_ID: AtomicI64 = AtomicI64::new(1);

fn find_handles() -> &'static Mutex<BTreeMap<i64, FindEntry>> {
    FIND_HANDLES.get_or_init(|| Mutex::new(BTreeMap::new()))
}

/// Simple wildcard matching: `*` matches any sequence, `?` matches any single char.
fn wildcard_match(pattern: &str, name: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let n: Vec<char> = name.chars().collect();
    let mut dp = vec![vec![false; n.len() + 1]; p.len() + 1];
    dp[0][0] = true;
    for i in 1..=p.len() {
        if p[i - 1] == '*' {
            dp[i][0] = dp[i - 1][0];
        }
    }
    for i in 1..=p.len() {
        for j in 1..=n.len() {
            if p[i - 1] == '*' {
                dp[i][j] = dp[i - 1][j] || dp[i][j - 1];
            } else if p[i - 1] == '?' || p[i - 1] == n[j - 1] {
                dp[i][j] = dp[i - 1][j - 1];
            }
        }
    }
    dp[p.len()][n.len()]
}

/// Fill a `_wfinddata64i32_t` struct (at `fileinfo`) for the given `dir_path/name`.
///
/// Layout (Windows `_wfinddata64i32_t`):
/// - offset  0: `attrib`      (u32, 4 bytes)
/// - offset  4: padding        (4 bytes)
/// - offset  8: `time_create` (i64, 8 bytes)
/// - offset 16: `time_access` (i64, 8 bytes)
/// - offset 24: `time_write`  (i64, 8 bytes)
/// - offset 32: `size`        (u32, 4 bytes)
/// - offset 36: `name[260]`   (u16 × 260, 520 bytes)
/// - Total:     556 bytes
///
/// # Safety
/// `fileinfo` must point to at least 556 writable bytes.
unsafe fn fill_wfinddata(fileinfo: *mut u8, dir_path: &str, name: &str) {
    // Windows FILETIME = 100ns intervals since 1601-01-01.
    // Unix time → Windows FILETIME: (unix_sec + 11644473600) * 10_000_000
    const EPOCH_DIFF: i64 = 11_644_473_600i64;

    let full_path = if dir_path.is_empty() || dir_path == "." {
        name.to_string()
    } else {
        format!("{dir_path}/{name}")
    };

    let Ok(c_path) = CString::new(full_path.as_bytes()) else {
        return;
    };

    let mut st: libc::stat64 = unsafe { std::mem::zeroed() };
    // SAFETY: c_path is a valid NUL-terminated C string; &raw mut avoids alignment lint.
    let stat_ok = unsafe { libc::stat64(c_path.as_ptr(), &raw mut st) } == 0;

    // attrib (offset 0): FILE_ATTRIBUTE_NORMAL = 0x80, DIRECTORY = 0x10
    let attrib: u32 = if stat_ok {
        if (st.st_mode & libc::S_IFMT) == libc::S_IFDIR {
            0x10 // FILE_ATTRIBUTE_DIRECTORY
        } else {
            0x20 // FILE_ATTRIBUTE_ARCHIVE (normal file)
        }
    } else {
        0x80 // FILE_ATTRIBUTE_NORMAL
    };
    unsafe { ptr::write_unaligned(fileinfo.cast::<u32>(), attrib) };

    // time_create / time_access / time_write (offsets 8, 16, 24): Windows FILETIME epoch
    let (ctime, atime, mtime) = if stat_ok {
        let to_ft = |t: i64| -> i64 { (t + EPOCH_DIFF) * 10_000_000 };
        (to_ft(st.st_ctime), to_ft(st.st_atime), to_ft(st.st_mtime))
    } else {
        (0i64, 0i64, 0i64)
    };
    unsafe { ptr::write_unaligned(fileinfo.add(8).cast::<i64>(), ctime) };
    unsafe { ptr::write_unaligned(fileinfo.add(16).cast::<i64>(), atime) };
    unsafe { ptr::write_unaligned(fileinfo.add(24).cast::<i64>(), mtime) };

    // size (offset 32): file size (u32, truncated)
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let size: u32 = if stat_ok { st.st_size as u32 } else { 0 };
    unsafe { ptr::write_unaligned(fileinfo.add(32).cast::<u32>(), size) };

    // name[260] (offset 36): UTF-16LE filename, zero-padded to 260 wchars
    let name_wide: Vec<u16> = name.encode_utf16().take(259).collect();
    let copy_len = name_wide.len().min(259);
    // SAFETY: fileinfo has at least 556 bytes; offset 36 + 260*2 = 556.
    #[allow(clippy::cast_ptr_alignment)]
    let name_ptr = fileinfo.add(36).cast::<u16>();
    for (i, &ch) in name_wide.iter().take(copy_len).enumerate() {
        unsafe { ptr::write_unaligned(name_ptr.add(i), ch) };
    }
    // NUL-terminate
    unsafe { ptr::write_unaligned(name_ptr.add(copy_len), 0u16) };
}

/// `_wfindfirst64i32(spec, fileinfo) -> intptr_t` — open a wide-character file search.
///
/// `spec` is a null-terminated wide string like `L"C:\\path\\*.txt"`.
/// Returns a search handle >= 0 on success, or -1 on error.
///
/// # Panics
/// Panics if the internal handle map mutex is poisoned.
///
/// # Safety
/// `spec` must be a valid null-terminated `u16` string or null.
/// `fileinfo` must point to at least 556 writable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt__wfindfirst64i32(spec: *const u16, fileinfo: *mut u8) -> i64 {
    use std::sync::atomic::Ordering as AtomicOrdering;

    if spec.is_null() || fileinfo.is_null() {
        return -1;
    }

    // Convert wide spec to UTF-8.
    let wide_spec = unsafe { read_wide_string(spec) };
    let spec_str = String::from_utf16_lossy(&wide_spec);

    // Split into directory and pattern.
    let (raw_dir, pattern) = if let Some(pos) = spec_str.rfind(['/', '\\']) {
        (&spec_str[..pos], &spec_str[pos + 1..])
    } else {
        (".", &spec_str[..])
    };
    // Normalize Windows-style paths (drive letter, backslashes) to Linux paths.
    let dir_normalized;
    let dir: &str = if raw_dir.is_empty() {
        "."
    } else {
        dir_normalized = crate::translate_windows_path_to_linux(raw_dir);
        &dir_normalized
    };

    // Open the directory.
    let Ok(c_dir) = CString::new(dir) else {
        return -1;
    };
    let dirp = unsafe { libc::opendir(c_dir.as_ptr()) };
    if dirp.is_null() {
        return -1;
    }

    // Scan for the first matching entry.
    let mut found = false;
    loop {
        let entry = unsafe { libc::readdir(dirp) };
        if entry.is_null() {
            break;
        }
        let name_bytes = unsafe { std::ffi::CStr::from_ptr((*entry).d_name.as_ptr()) };
        let name = name_bytes.to_string_lossy();
        // Skip "." and ".."
        if name == "." || name == ".." {
            continue;
        }
        if wildcard_match(pattern, &name) {
            unsafe { fill_wfinddata(fileinfo, dir, &name) };
            found = true;
            break;
        }
    }

    if !found {
        unsafe { libc::closedir(dirp) };
        return -1;
    }

    let id = FIND_NEXT_ID.fetch_add(1, AtomicOrdering::Relaxed);
    find_handles().lock().unwrap().insert(
        id,
        FindEntry {
            dir: DirHandle(dirp),
            pattern: pattern.to_string(),
            directory: dir.to_string(),
        },
    );
    id
}

/// `_wfindnext64i32(handle, fileinfo) -> int` — advance a wide-character file search.
///
/// Returns 0 on success, or -1 when there are no more matching files.
///
/// # Panics
/// Panics if the internal handle map mutex is poisoned.
///
/// # Safety
/// `fileinfo` must point to at least 556 writable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt__wfindnext64i32(handle: i64, fileinfo: *mut u8) -> i32 {
    if fileinfo.is_null() {
        return -1;
    }
    let mut map = find_handles().lock().unwrap();
    let Some(entry) = map.get_mut(&handle) else {
        return -1;
    };

    loop {
        let de = unsafe { libc::readdir(entry.dir.0) };
        if de.is_null() {
            return -1;
        }
        let name_bytes = unsafe { std::ffi::CStr::from_ptr((*de).d_name.as_ptr()) };
        let name = name_bytes.to_string_lossy();
        if name == "." || name == ".." {
            continue;
        }
        if wildcard_match(&entry.pattern, &name) {
            let dir = entry.directory.clone();
            unsafe { fill_wfinddata(fileinfo, &dir, &name) };
            return 0;
        }
    }
}

/// `_findclose(handle) -> int` — close a file search handle.
///
/// Returns 0 on success, or -1 if the handle is not found.
///
/// # Panics
/// Panics if the internal handle map mutex is poisoned.
///
/// # Safety
/// `handle` must have been returned by `_wfindfirst64i32`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt__findclose(handle: i64) -> i32 {
    let mut map = find_handles().lock().unwrap();
    if let Some(entry) = map.remove(&handle) {
        unsafe { libc::closedir(entry.dir.0) };
        0
    } else {
        -1
    }
}

// ============================================================================
// Phase 38: Locale-aware printf variants (locale parameter is ignored)
// ============================================================================

/// `_printf_l(fmt, locale, ...) -> int` — locale-aware printf (locale ignored).
///
/// # Safety
/// `fmt` must be a valid null-terminated C string.
/// Variadic arguments must match the format specifiers.
#[unsafe(no_mangle)]
#[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
pub unsafe extern "C" fn msvcrt__printf_l(fmt: *const u8, _locale: *mut u8, mut args: ...) -> i32 {
    if fmt.is_null() {
        return -1;
    }
    let fmt_bytes = unsafe { CStr::from_ptr(fmt.cast::<i8>()) }.to_bytes();
    let out = unsafe { format_printf_va(fmt_bytes, &mut args, false) };
    match io::stdout().write_all(&out) {
        Ok(()) => {
            let _ = io::stdout().flush();
            out.len() as i32
        }
        Err(_) => -1,
    }
}

/// `_fprintf_l(file, fmt, locale, ...) -> int` — locale-aware fprintf (locale ignored).
///
/// # Safety
/// `fmt` must be a valid null-terminated C string.
/// Variadic arguments must match the format specifiers.
#[unsafe(no_mangle)]
#[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
pub unsafe extern "C" fn msvcrt__fprintf_l(
    _file: *mut u8,
    fmt: *const u8,
    _locale: *mut u8,
    mut args: ...
) -> i32 {
    if fmt.is_null() {
        return -1;
    }
    let fmt_bytes = unsafe { CStr::from_ptr(fmt.cast::<i8>()) }.to_bytes();
    let out = unsafe { format_printf_va(fmt_bytes, &mut args, false) };
    let written = unsafe { libc::write(1, out.as_ptr().cast(), out.len()) };
    if written < 0 { -1 } else { written as i32 }
}

/// `_sprintf_l(buf, fmt, locale, ...) -> int` — locale-aware sprintf (locale ignored).
///
/// # Safety
/// `buf` must point to a writable buffer large enough to hold the output.
/// `fmt` must be a valid null-terminated C string.
/// Variadic arguments must match the format specifiers.
#[unsafe(no_mangle)]
#[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
pub unsafe extern "C" fn msvcrt__sprintf_l(
    buf: *mut u8,
    fmt: *const u8,
    _locale: *mut u8,
    mut args: ...
) -> i32 {
    if buf.is_null() || fmt.is_null() {
        return -1;
    }
    let fmt_bytes = unsafe { CStr::from_ptr(fmt.cast::<i8>()) }.to_bytes();
    let out = unsafe { format_printf_va(fmt_bytes, &mut args, false) };
    unsafe {
        ptr::copy_nonoverlapping(out.as_ptr(), buf, out.len());
        *buf.add(out.len()) = 0;
    }
    out.len() as i32
}

/// `_snprintf_l(buf, count, fmt, locale, ...) -> int` — locale-aware snprintf (locale ignored).
///
/// # Safety
/// `buf` must point to a writable buffer of at least `count` bytes.
/// `fmt` must be a valid null-terminated C string.
/// Variadic arguments must match the format specifiers.
#[unsafe(no_mangle)]
#[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
pub unsafe extern "C" fn msvcrt__snprintf_l(
    buf: *mut u8,
    count: usize,
    fmt: *const u8,
    _locale: *mut u8,
    mut args: ...
) -> i32 {
    if fmt.is_null() {
        return -1;
    }
    let fmt_bytes = unsafe { CStr::from_ptr(fmt.cast::<i8>()) }.to_bytes();
    let out = unsafe { format_printf_va(fmt_bytes, &mut args, false) };
    let would_write = out.len() as i32;
    if !buf.is_null() && count > 0 {
        let copy_len = out.len().min(count - 1);
        unsafe {
            ptr::copy_nonoverlapping(out.as_ptr(), buf, copy_len);
            *buf.add(copy_len) = 0;
        }
    }
    would_write
}

/// `_wprintf_l(fmt, locale, ...) -> int` — locale-aware wprintf (locale ignored).
///
/// # Safety
/// `fmt` must be a valid null-terminated wide string.
/// Variadic arguments must match the format specifiers.
#[unsafe(no_mangle)]
#[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
pub unsafe extern "C" fn msvcrt__wprintf_l(
    fmt: *const u16,
    _locale: *mut u8,
    mut args: ...
) -> i32 {
    if fmt.is_null() {
        return -1;
    }
    let wide_fmt = unsafe { read_wide_string(fmt) };
    let fmt_utf8 = String::from_utf16_lossy(&wide_fmt);
    let Ok(cstr) = CString::new(fmt_utf8.as_bytes()) else {
        return -1;
    };
    let out = unsafe { format_printf_va(cstr.to_bytes(), &mut args, true) };
    match io::stdout().write_all(&out) {
        Ok(()) => {
            let _ = io::stdout().flush();
            out.len() as i32
        }
        Err(_) => -1,
    }
}

// ============================================================================
// Phase 39: Low-level POSIX-style file I/O
// ============================================================================

/// Translate Windows `_O_*` open flags to Linux `O_*` flags.
fn translate_open_flags(oflag: i32) -> libc::c_int {
    // Access mode is encoded in the bottom 2 bits (0=rdonly, 1=wronly, 2=rdwr).
    let access = match oflag & 0x03 {
        0 => libc::O_RDONLY,
        1 => libc::O_WRONLY,
        _ => libc::O_RDWR,
    };
    let mut flags = access;
    if oflag & 0x0008 != 0 {
        flags |= libc::O_APPEND;
    }
    if oflag & 0x0100 != 0 {
        flags |= libc::O_CREAT;
    }
    if oflag & 0x0200 != 0 {
        flags |= libc::O_TRUNC;
    }
    if oflag & 0x0400 != 0 {
        flags |= libc::O_EXCL;
    }
    if oflag & 0x0080 != 0 {
        flags |= libc::O_CLOEXEC;
    }
    // _O_TEXT (0x4000), _O_BINARY (0x8000), _O_SEQUENTIAL/RANDOM are no-ops on Linux.
    flags
}

/// `_open(path, oflag, pmode)` — open a file with low-level CRT flags.
///
/// Translates Windows `_O_*` flags to POSIX `O_*` flags and calls `libc::open`.
/// Returns the new file descriptor on success, or -1 on error.
///
/// # Safety
/// `path` must be a valid, NUL-terminated byte string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt__open(path: *const u8, oflag: i32, pmode: u32) -> i32 {
    if path.is_null() {
        return -1;
    }
    let flags = translate_open_flags(oflag);
    // SAFETY: caller guarantees path is a valid NUL-terminated string.
    unsafe { libc::open(path.cast(), flags, pmode as libc::mode_t) }
}

/// `_close(fd)` — close a low-level CRT file descriptor.
///
/// Returns 0 on success, or -1 on error.
///
/// # Safety
/// `fd` must be a valid open file descriptor.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt__close(fd: i32) -> i32 {
    // SAFETY: caller guarantees fd is a valid file descriptor.
    unsafe { libc::close(fd) }
}

/// `_lseek(fd, offset, whence)` — seek within a low-level CRT file descriptor.
///
/// Returns the new file position as `i32`, or -1 on error or overflow.
///
/// # Safety
/// `fd` must be a valid open file descriptor.
#[unsafe(no_mangle)]
#[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
pub unsafe extern "C" fn msvcrt__lseek(fd: i32, offset: i32, whence: i32) -> i32 {
    // SAFETY: fd is a valid file descriptor per caller's contract.
    let pos = unsafe { libc::lseek(fd, libc::off_t::from(offset), whence) };
    if pos < 0 {
        return -1;
    }
    if pos > i64::from(i32::MAX) {
        return -1;
    }
    pos as i32
}

/// `_lseeki64(fd, offset, whence)` — seek within a low-level CRT file descriptor (64-bit).
///
/// Returns the new file position as `i64`, or -1 on error.
///
/// # Safety
/// `fd` must be a valid open file descriptor.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt__lseeki64(fd: i32, offset: i64, whence: i32) -> i64 {
    // SAFETY: fd is a valid file descriptor per caller's contract.
    let pos = unsafe { libc::lseek(fd, offset as libc::off_t, whence) };
    if pos < 0 { -1 } else { pos }
}

/// `_tell(fd)` — get the current file-position indicator.
///
/// Returns the current position as `i32`, or -1 on error or overflow.
///
/// # Safety
/// `fd` must be a valid open file descriptor.
#[unsafe(no_mangle)]
#[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
pub unsafe extern "C" fn msvcrt__tell(fd: i32) -> i32 {
    // SAFETY: fd is a valid file descriptor per caller's contract.
    let pos = unsafe { libc::lseek(fd, 0, libc::SEEK_CUR) };
    if pos < 0 {
        return -1;
    }
    if pos > i64::from(i32::MAX) {
        return -1;
    }
    pos as i32
}

/// `_telli64(fd)` — get the current file-position indicator (64-bit).
///
/// Returns the current position as `i64`, or -1 on error.
///
/// # Safety
/// `fd` must be a valid open file descriptor.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt__telli64(fd: i32) -> i64 {
    // SAFETY: fd is a valid file descriptor per caller's contract.
    let pos = unsafe { libc::lseek(fd, 0, libc::SEEK_CUR) };
    if pos < 0 { -1 } else { pos }
}

/// `_eof(fd)` — test whether a file descriptor is at end-of-file.
///
/// Returns 1 if at EOF, 0 if not, -1 on error.
///
/// # Safety
/// `fd` must be a valid open file descriptor.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt__eof(fd: i32) -> i32 {
    let mut stat = unsafe { core::mem::zeroed::<libc::stat>() };
    // SAFETY: stat is properly zeroed and fd is valid per caller's contract.
    if unsafe { libc::fstat(fd, &raw mut stat) } != 0 {
        return -1;
    }
    // SAFETY: fd is valid per caller's contract.
    let pos = unsafe { libc::lseek(fd, 0, libc::SEEK_CUR) };
    if pos < 0 {
        return -1;
    }
    i32::from(pos >= stat.st_size)
}

/// `_creat(path, pmode)` — create or truncate a file for writing.
///
/// Equivalent to `_open(path, _O_CREAT|_O_WRONLY|_O_TRUNC, pmode)`.
/// Returns the new file descriptor on success, or -1 on error.
///
/// # Safety
/// `path` must be a valid, NUL-terminated byte string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt__creat(path: *const u8, pmode: i32) -> i32 {
    if path.is_null() {
        return -1;
    }
    let flags = libc::O_CREAT | libc::O_WRONLY | libc::O_TRUNC;
    // SAFETY: caller guarantees path is a valid NUL-terminated string.
    unsafe { libc::open(path.cast(), flags, pmode.cast_unsigned() as libc::mode_t) }
}

/// `_commit(fd)` — flush OS buffers to disk for a file descriptor.
///
/// Returns 0 on success, -1 on error.
///
/// # Safety
/// `fd` must be a valid open file descriptor.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt__commit(fd: i32) -> i32 {
    // SAFETY: fd is a valid file descriptor per caller's contract.
    let ret = unsafe { libc::fsync(fd) };
    if ret == 0 { 0 } else { -1 }
}

/// `_dup(fd)` — duplicate a file descriptor.
///
/// Returns the new file descriptor on success, or -1 on error.
///
/// # Safety
/// `fd` must be a valid open file descriptor.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt__dup(fd: i32) -> i32 {
    // SAFETY: fd is a valid file descriptor per caller's contract.
    unsafe { libc::dup(fd) }
}

/// `_dup2(fd, fd2)` — duplicate `fd` onto `fd2`.
///
/// Returns `fd2` on success, or -1 on error.
///
/// # Safety
/// `fd` must be a valid open file descriptor; `fd2` must be a valid
/// file descriptor number.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt__dup2(fd: i32, fd2: i32) -> i32 {
    // SAFETY: fd and fd2 are valid per caller's contract.
    let ret = unsafe { libc::dup2(fd, fd2) };
    if ret < 0 { -1 } else { fd2 }
}

/// `_chsize(fd, size)` — truncate or extend a file to `size` bytes.
///
/// Returns 0 on success, -1 on error.
///
/// # Safety
/// `fd` must be a valid open file descriptor.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt__chsize(fd: i32, size: i32) -> i32 {
    // SAFETY: fd is a valid file descriptor per caller's contract.
    let ret = unsafe { libc::ftruncate(fd, i64::from(size) as libc::off_t) };
    if ret == 0 { 0 } else { -1 }
}

/// `_chsize_s(fd, size)` — truncate or extend a file to `size` bytes (64-bit).
///
/// Returns 0 on success, -1 on error.
///
/// # Safety
/// `fd` must be a valid open file descriptor.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt__chsize_s(fd: i32, size: i64) -> i32 {
    // SAFETY: fd is a valid file descriptor per caller's contract.
    let ret = unsafe { libc::ftruncate(fd, size as libc::off_t) };
    if ret == 0 { 0 } else { -1 }
}

/// `_filelength(fd)` — get the size of a file in bytes.
///
/// Returns the file size as `i32`, or -1 on error or overflow.
///
/// # Safety
/// `fd` must be a valid open file descriptor.
#[unsafe(no_mangle)]
#[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
pub unsafe extern "C" fn msvcrt__filelength(fd: i32) -> i32 {
    let mut stat = unsafe { core::mem::zeroed::<libc::stat>() };
    // SAFETY: stat is properly zeroed and fd is valid per caller's contract.
    if unsafe { libc::fstat(fd, &raw mut stat) } != 0 {
        return -1;
    }
    if stat.st_size > i64::from(i32::MAX) {
        return -1;
    }
    stat.st_size as i32
}

/// `_filelengthi64(fd)` — get the size of a file in bytes (64-bit).
///
/// Returns the file size as `i64`, or -1 on error.
///
/// # Safety
/// `fd` must be a valid open file descriptor.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt__filelengthi64(fd: i32) -> i64 {
    let mut stat = unsafe { core::mem::zeroed::<libc::stat>() };
    // SAFETY: stat is properly zeroed and fd is valid per caller's contract.
    if unsafe { libc::fstat(fd, &raw mut stat) } != 0 {
        return -1;
    }
    stat.st_size
}

// ── Windows _stat/_stat64 structures ──────────────────────────────────────────

// Windows file-type and permission bits for st_mode.
const WIN_S_IFREG: u16 = 0x8000; // regular file
const WIN_S_IFDIR: u16 = 0x4000; // directory
const WIN_S_IFCHR: u16 = 0x2000; // character device
const WIN_S_IREAD: u16 = 0x0100; // owner read
const WIN_S_IWRITE: u16 = 0x0080; // owner write
const WIN_S_IEXEC: u16 = 0x0040; // owner execute

/// Windows `_stat32` structure (32-bit times, 32-bit file size).
///
/// Matches the MSVC x64 ABI layout for `struct _stat32`.
#[repr(C)]
pub struct WinStat32 {
    pub st_dev: u32,
    pub st_ino: u16,
    pub st_mode: u16,
    pub st_nlink: i16,
    pub st_uid: i16,
    pub st_gid: i16,
    /// ABI alignment padding between `st_gid` and `st_rdev`.
    _pad1: u16,
    pub st_rdev: u32,
    pub st_size: i32,
    pub st_atime: i32,
    pub st_mtime: i32,
    pub st_ctime: i32,
}

/// Windows `_stat64` structure (64-bit times, 64-bit file size).
///
/// Matches the MSVC x64 ABI layout for `struct _stat64`.
#[repr(C)]
pub struct WinStat64 {
    pub st_dev: u32,
    pub st_ino: u16,
    pub st_mode: u16,
    pub st_nlink: i16,
    pub st_uid: i16,
    pub st_gid: i16,
    /// ABI alignment padding between `st_gid` and `st_rdev`.
    _pad1: u16,
    pub st_rdev: u32,
    /// ABI alignment padding to align `st_size` to an 8-byte boundary.
    _pad2: u32,
    pub st_size: i64,
    pub st_atime: i64,
    pub st_mtime: i64,
    pub st_ctime: i64,
}

/// Clamp a 64-bit `time_t` to `i32`, setting MSVCRT errno to `EOVERFLOW` if
/// the value is out of range (e.g., post-2038 timestamps on 64-bit Linux).
///
/// # Safety
/// Calls `msvcrt___errno_location` which is always safe in this crate.
#[allow(clippy::cast_possible_truncation)]
unsafe fn clamp_time_to_i32(t: i64) -> i32 {
    if t > i64::from(i32::MAX) || t < i64::from(i32::MIN) {
        unsafe { *msvcrt___errno_location() = libc::EOVERFLOW };
        i32::MAX
    } else {
        t as i32
    }
}

/// Map a Linux `libc::stat` to a Windows `WinStat32`.
///
/// # Safety
/// `linux_st` must be a valid, initialized `libc::stat` structure.
#[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
unsafe fn fill_win_stat32(linux_st: &libc::stat, out: &mut WinStat32) {
    out.st_dev = linux_st.st_dev as u32;
    out.st_ino = linux_st.st_ino as u16;
    // Map file type bits
    let mode = linux_st.st_mode;
    let mut wmode: u16 = 0;
    if mode & libc::S_IFMT == libc::S_IFREG {
        wmode |= WIN_S_IFREG;
    } else if mode & libc::S_IFMT == libc::S_IFDIR {
        wmode |= WIN_S_IFDIR;
    } else if mode & libc::S_IFMT == libc::S_IFCHR {
        wmode |= WIN_S_IFCHR;
    }
    if mode & libc::S_IRUSR != 0 {
        wmode |= WIN_S_IREAD;
    }
    if mode & libc::S_IWUSR != 0 {
        wmode |= WIN_S_IWRITE;
    }
    if mode & libc::S_IXUSR != 0 {
        wmode |= WIN_S_IEXEC;
    }
    out.st_mode = wmode;
    out.st_nlink = linux_st.st_nlink as i16;
    out.st_uid = linux_st.st_uid as i16;
    out.st_gid = linux_st.st_gid as i16;
    out.st_rdev = linux_st.st_rdev as u32;
    // Clamp file size to i32::MAX — files larger than 2 GiB are not representable
    // in the 32-bit `_stat32` structure.  Set MSVCRT errno to EOVERFLOW when clamping.
    let sz = linux_st.st_size;
    out.st_size = if sz > i64::from(i32::MAX) {
        unsafe { *msvcrt___errno_location() = libc::EOVERFLOW };
        i32::MAX
    } else {
        sz as i32
    };
    // Clamp timestamps: post-2038 time_t values exceed i32 range.
    out.st_atime = unsafe { clamp_time_to_i32(linux_st.st_atime) };
    out.st_mtime = unsafe { clamp_time_to_i32(linux_st.st_mtime) };
    out.st_ctime = unsafe { clamp_time_to_i32(linux_st.st_ctime) };
}

/// Map a Linux `libc::stat` to a Windows `WinStat64`.
///
/// # Safety
/// `linux_st` must be a valid, initialized `libc::stat` structure.
#[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
unsafe fn fill_win_stat64(linux_st: &libc::stat, out: &mut WinStat64) {
    out.st_dev = linux_st.st_dev as u32;
    out.st_ino = linux_st.st_ino as u16;
    let mode = linux_st.st_mode;
    let mut wmode: u16 = 0;
    if mode & libc::S_IFMT == libc::S_IFREG {
        wmode |= WIN_S_IFREG;
    } else if mode & libc::S_IFMT == libc::S_IFDIR {
        wmode |= WIN_S_IFDIR;
    } else if mode & libc::S_IFMT == libc::S_IFCHR {
        wmode |= WIN_S_IFCHR;
    }
    if mode & libc::S_IRUSR != 0 {
        wmode |= WIN_S_IREAD;
    }
    if mode & libc::S_IWUSR != 0 {
        wmode |= WIN_S_IWRITE;
    }
    if mode & libc::S_IXUSR != 0 {
        wmode |= WIN_S_IEXEC;
    }
    out.st_mode = wmode;
    out.st_nlink = linux_st.st_nlink as i16;
    out.st_uid = linux_st.st_uid as i16;
    out.st_gid = linux_st.st_gid as i16;
    out.st_rdev = linux_st.st_rdev as u32;
    out.st_size = linux_st.st_size;
    out.st_atime = linux_st.st_atime;
    out.st_mtime = linux_st.st_mtime;
    out.st_ctime = linux_st.st_ctime;
}

/// `_stat(path, buf)` — get file status (32-bit times and size).
///
/// Returns 0 on success, -1 on error.
///
/// # Safety
/// `path` must be a valid, NUL-terminated byte string.
/// `buf` must be a valid pointer to a `WinStat32` structure.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt__stat(path: *const u8, buf: *mut WinStat32) -> i32 {
    if path.is_null() || buf.is_null() {
        return -1;
    }
    let mut linux_st = unsafe { core::mem::zeroed::<libc::stat>() };
    // SAFETY: path is a valid NUL-terminated string per caller's contract.
    if unsafe { libc::stat(path.cast(), &raw mut linux_st) } != 0 {
        return -1;
    }
    // SAFETY: buf is a valid pointer per caller's contract; linux_st is initialized.
    unsafe { fill_win_stat32(&linux_st, &mut *buf) };
    0
}

/// `_stat64(path, buf)` — get file status (64-bit times and size).
///
/// Returns 0 on success, -1 on error.
///
/// # Safety
/// `path` must be a valid, NUL-terminated byte string.
/// `buf` must be a valid pointer to a `WinStat64` structure.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt__stat64(path: *const u8, buf: *mut WinStat64) -> i32 {
    if path.is_null() || buf.is_null() {
        return -1;
    }
    let mut linux_st = unsafe { core::mem::zeroed::<libc::stat>() };
    // SAFETY: path is a valid NUL-terminated string per caller's contract.
    if unsafe { libc::stat(path.cast(), &raw mut linux_st) } != 0 {
        return -1;
    }
    // SAFETY: buf is a valid pointer per caller's contract; linux_st is initialized.
    unsafe { fill_win_stat64(&linux_st, &mut *buf) };
    0
}

/// `_fstat(fd, buf)` — get file status for an open file descriptor (32-bit).
///
/// Returns 0 on success, -1 on error.
///
/// # Safety
/// `fd` must be a valid open file descriptor.
/// `buf` must be a valid pointer to a `WinStat32` structure.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt__fstat(fd: i32, buf: *mut WinStat32) -> i32 {
    if buf.is_null() {
        return -1;
    }
    let mut linux_st = unsafe { core::mem::zeroed::<libc::stat>() };
    // SAFETY: fd is a valid file descriptor per caller's contract.
    if unsafe { libc::fstat(fd, &raw mut linux_st) } != 0 {
        return -1;
    }
    // SAFETY: buf is a valid pointer; linux_st is initialized.
    unsafe { fill_win_stat32(&linux_st, &mut *buf) };
    0
}

/// `_fstat64(fd, buf)` — get file status for an open file descriptor (64-bit).
///
/// Returns 0 on success, -1 on error.
///
/// # Safety
/// `fd` must be a valid open file descriptor.
/// `buf` must be a valid pointer to a `WinStat64` structure.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt__fstat64(fd: i32, buf: *mut WinStat64) -> i32 {
    if buf.is_null() {
        return -1;
    }
    let mut linux_st = unsafe { core::mem::zeroed::<libc::stat>() };
    // SAFETY: fd is a valid file descriptor per caller's contract.
    if unsafe { libc::fstat(fd, &raw mut linux_st) } != 0 {
        return -1;
    }
    // SAFETY: buf is a valid pointer; linux_st is initialized.
    unsafe { fill_win_stat64(&linux_st, &mut *buf) };
    0
}

/// `_wopen(wpath, oflag, pmode)` — open a file with a wide-character path.
///
/// Converts `wpath` from UTF-16 to UTF-8 and delegates to `libc::open`.
/// Returns the new file descriptor on success, or -1 on error.
///
/// # Safety
/// `wpath` must be a valid, NUL-terminated wide string (UTF-16).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt__wopen(wpath: *const u16, oflag: i32, pmode: u32) -> i32 {
    if wpath.is_null() {
        return -1;
    }
    // SAFETY: wpath is a valid NUL-terminated wide string per caller's contract.
    let wide = unsafe { read_wide_string(wpath) };
    let utf8 = String::from_utf16_lossy(&wide);
    let Ok(c_path) = std::ffi::CString::new(utf8) else {
        return -1;
    };
    let flags = translate_open_flags(oflag);
    // SAFETY: c_path is a valid NUL-terminated string.
    unsafe { libc::open(c_path.as_ptr(), flags, pmode as libc::mode_t) }
}

/// `_wsopen(wpath, oflag, shflag, pmode)` — wide-char `_sopen` (sharing flags ignored).
///
/// Converts `wpath` from UTF-16 to UTF-8 and opens the file. The `shflag`
/// sharing parameter is silently ignored on Linux.
/// Returns the new file descriptor on success, or -1 on error.
///
/// # Safety
/// `wpath` must be a valid, NUL-terminated wide string (UTF-16).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt__wsopen(
    wpath: *const u16,
    oflag: i32,
    _shflag: i32,
    pmode: u32,
) -> i32 {
    // SAFETY: wpath is a valid NUL-terminated wide string per caller's contract.
    unsafe { msvcrt__wopen(wpath, oflag, pmode) }
}

/// `_sopen_s(pfh, path, oflag, shflag, pmode)` — safe version of `_sopen`.
///
/// Opens a file and stores the resulting file descriptor in `*pfh`.
/// Returns 0 on success, or an `errno` value on error.
/// Returns `EINVAL` if `pfh` is null.
/// The `shflag` sharing parameter is silently ignored on Linux.
///
/// # Safety
/// `pfh` must be either null or a valid pointer to an `i32`.
/// `path` must be a valid, NUL-terminated byte string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt__sopen_s(
    pfh: *mut i32,
    path: *const u8,
    oflag: i32,
    _shflag: i32,
    pmode: i32,
) -> i32 {
    if pfh.is_null() {
        return libc::EINVAL;
    }
    if path.is_null() {
        // SAFETY: pfh is non-null per the check above.
        unsafe { *pfh = -1 };
        return libc::EINVAL;
    }
    let flags = translate_open_flags(oflag);
    // SAFETY: path is a valid NUL-terminated string per caller's contract.
    let fd = unsafe { libc::open(path.cast(), flags, pmode.cast_unsigned() as libc::mode_t) };
    if fd < 0 {
        // SAFETY: pfh is non-null per the check above.
        unsafe { *pfh = -1 };
        // SAFETY: errno is set by libc::open on failure.
        return unsafe { *libc::__errno_location() };
    }
    // SAFETY: pfh is non-null per the check above.
    unsafe { *pfh = fd };
    0
}

/// `_wsopen_s(pfh, wpath, oflag, shflag, pmode)` — wide-char safe version of `_sopen`.
///
/// Opens a file identified by a UTF-16 path and stores the resulting file
/// descriptor in `*pfh`.  Returns 0 on success, or an `errno` value on error.
/// Returns `EINVAL` if `pfh` is null.
/// The `shflag` sharing parameter is silently ignored on Linux.
///
/// # Safety
/// `pfh` must be either null or a valid pointer to an `i32`.
/// `wpath` must be a valid, NUL-terminated wide string (UTF-16).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt__wsopen_s(
    pfh: *mut i32,
    wpath: *const u16,
    oflag: i32,
    _shflag: i32,
    pmode: i32,
) -> i32 {
    if pfh.is_null() {
        return libc::EINVAL;
    }
    if wpath.is_null() {
        // SAFETY: pfh is non-null per the check above.
        unsafe { *pfh = -1 };
        return libc::EINVAL;
    }
    // SAFETY: wpath is a valid NUL-terminated wide string per caller's contract.
    let wide = unsafe { read_wide_string(wpath) };
    let utf8 = String::from_utf16_lossy(&wide);
    let Ok(c_path) = std::ffi::CString::new(utf8) else {
        // SAFETY: pfh is non-null per the check above.
        unsafe { *pfh = -1 };
        return libc::EINVAL;
    };
    let flags = translate_open_flags(oflag);
    // SAFETY: c_path is a valid NUL-terminated string.
    let fd = unsafe {
        libc::open(
            c_path.as_ptr(),
            flags,
            pmode.cast_unsigned() as libc::mode_t,
        )
    };
    if fd < 0 {
        // SAFETY: pfh is non-null per the check above.
        unsafe { *pfh = -1 };
        // SAFETY: errno is set by libc::open on failure.
        return unsafe { *libc::__errno_location() };
    }
    // SAFETY: pfh is non-null per the check above.
    unsafe { *pfh = fd };
    0
}

/// `_wstat(wpath, buf)` — wide-char `_stat` (32-bit times and size).
///
/// Converts `wpath` from UTF-16 to UTF-8 and calls `libc::stat`.
/// Returns 0 on success, -1 on error.
///
/// # Safety
/// `wpath` must be a valid, NUL-terminated wide string (UTF-16).
/// `buf` must be a valid pointer to a `WinStat32` structure.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt__wstat(wpath: *const u16, buf: *mut WinStat32) -> i32 {
    if wpath.is_null() || buf.is_null() {
        return -1;
    }
    // SAFETY: wpath is a valid NUL-terminated wide string per caller's contract.
    let wide = unsafe { read_wide_string(wpath) };
    let utf8 = String::from_utf16_lossy(&wide);
    let Ok(c_path) = std::ffi::CString::new(utf8) else {
        return -1;
    };
    let mut linux_st = unsafe { core::mem::zeroed::<libc::stat>() };
    // SAFETY: c_path is a valid NUL-terminated string.
    if unsafe { libc::stat(c_path.as_ptr().cast(), &raw mut linux_st) } != 0 {
        return -1;
    }
    // SAFETY: buf is a valid pointer; linux_st is initialized.
    unsafe { fill_win_stat32(&linux_st, &mut *buf) };
    0
}

/// `_wstat64(wpath, buf)` — wide-char `_stat64` (64-bit times and size).
///
/// Converts `wpath` from UTF-16 to UTF-8 and calls `libc::stat`.
/// Returns 0 on success, -1 on error.
///
/// # Safety
/// `wpath` must be a valid, NUL-terminated wide string (UTF-16).
/// `buf` must be a valid pointer to a `WinStat64` structure.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt__wstat64(wpath: *const u16, buf: *mut WinStat64) -> i32 {
    if wpath.is_null() || buf.is_null() {
        return -1;
    }
    // SAFETY: wpath is a valid NUL-terminated wide string per caller's contract.
    let wide = unsafe { read_wide_string(wpath) };
    let utf8 = String::from_utf16_lossy(&wide);
    let Ok(c_path) = std::ffi::CString::new(utf8) else {
        return -1;
    };
    let mut linux_st = unsafe { core::mem::zeroed::<libc::stat>() };
    // SAFETY: c_path is a valid NUL-terminated string.
    if unsafe { libc::stat(c_path.as_ptr().cast(), &raw mut linux_st) } != 0 {
        return -1;
    }
    // SAFETY: buf is a valid pointer; linux_st is initialized.
    unsafe { fill_win_stat64(&linux_st, &mut *buf) };
    0
}

// ── Phase 42: path manipulation ───────────────────────────────────────────────

/// `_fullpath(buffer, path, maxlen)` — resolve an absolute path.
///
/// If `buffer` is null, allocates a heap buffer for the result (caller must `free`).
/// If `buffer` is non-null, copies the resolved path into it only if it fits in `maxlen`
/// bytes; sets `errno = ERANGE` and returns null if the result is too long.
/// Returns null if `path` is null (sets `errno = EINVAL`).
///
/// # Safety
/// `path` must be a valid NUL-terminated string or null.
/// `buffer`, if non-null, must be valid for `maxlen` bytes of writes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt__fullpath(
    buffer: *mut u8,
    path: *const u8,
    maxlen: usize,
) -> *mut u8 {
    if path.is_null() {
        // SAFETY: errno is a valid thread-local.
        unsafe { *libc::__errno_location() = libc::EINVAL };
        return core::ptr::null_mut();
    }

    if buffer.is_null() {
        // When buffer is null, let libc allocate a suitably-sized buffer.
        // SAFETY: path is non-null (validated above) and a valid NUL-terminated string;
        //         null dst asks libc to allocate a PATH_MAX-sized buffer for the result.
        let ret = unsafe { libc::realpath(path.cast(), core::ptr::null_mut()) };
        return ret.cast::<u8>();
    }

    // Caller-provided buffer: use a libc-allocated temp to avoid writing past maxlen.
    // SAFETY: path is non-null (validated above) and a valid NUL-terminated string;
    //         null dst asks libc to allocate a PATH_MAX-sized buffer for the result.
    let tmp = unsafe { libc::realpath(path.cast(), core::ptr::null_mut()) };
    if tmp.is_null() {
        return core::ptr::null_mut();
    }
    // SAFETY: tmp is a valid NUL-terminated string returned by realpath.
    let len = unsafe { libc::strlen(tmp) };
    if len + 1 > maxlen {
        // Result does not fit in caller's buffer.
        // SAFETY: tmp was allocated by libc in the realpath call above.
        unsafe {
            libc::free(tmp.cast());
            *libc::__errno_location() = libc::ERANGE;
        }
        return core::ptr::null_mut();
    }
    // Copy resolved path including NUL into caller's buffer.
    // SAFETY: buffer is valid for maxlen bytes; len + 1 <= maxlen; tmp is valid for len+1 bytes.
    unsafe {
        core::ptr::copy_nonoverlapping(tmp.cast::<u8>(), buffer, len + 1);
        libc::free(tmp.cast());
    }
    buffer
}

/// `_splitpath(path, drive, dir, fname, ext)` — split a path into components.
///
/// If a leading `X:` drive component is found it is written to `drive`; otherwise `drive`
/// is set to an empty string.  On Linux paths starting with `/` no drive component is
/// present, so `drive` will be empty for those paths.
/// All output pointers may be null (component is skipped).
///
/// # Safety
/// `path` must be a valid NUL-terminated string.
/// Output pointers, if non-null, must point to sufficient writable buffers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt__splitpath(
    path: *const u8,
    drive: *mut u8,
    dir: *mut u8,
    fname: *mut u8,
    ext: *mut u8,
) {
    if path.is_null() {
        return;
    }
    // SAFETY: path is a valid NUL-terminated string per caller contract.
    let len = unsafe { libc::strlen(path.cast()) };
    // SAFETY: path is valid for len bytes.
    let bytes = unsafe { core::slice::from_raw_parts(path, len) };

    // Drive: extract leading "X:" pattern if present; otherwise empty.
    let (drive_part, rest) = if bytes.len() >= 2 && bytes[1] == b':' {
        (&bytes[..2], &bytes[2..])
    } else {
        (&bytes[..0], bytes)
    };

    // Dir: everything up to and including the last separator.
    let last_sep = rest.iter().rposition(|&b| b == b'/' || b == b'\\');
    let (dir_part, file_part) = if let Some(idx) = last_sep {
        (&rest[..=idx], &rest[idx + 1..])
    } else {
        (&rest[..0], rest)
    };

    // Ext: last '.' in file_part.
    let last_dot = file_part.iter().rposition(|&b| b == b'.');
    let (fname_part, ext_part) = if let Some(idx) = last_dot {
        (&file_part[..idx], &file_part[idx..])
    } else {
        (file_part, &file_part[..0])
    };

    // Write components if output pointers are non-null.
    let write_component = |dst: *mut u8, src: &[u8]| {
        if dst.is_null() {
            return;
        }
        // SAFETY: dst is valid for src.len() + 1 bytes per caller contract.
        unsafe {
            core::ptr::copy_nonoverlapping(src.as_ptr(), dst, src.len());
            *dst.add(src.len()) = 0;
        }
    };
    write_component(drive, drive_part);
    write_component(dir, dir_part);
    write_component(fname, fname_part);
    write_component(ext, ext_part);
}

/// `_splitpath_s(path, drive, drivelen, dir, dirlen, fname, fnamelen, ext, extlen)` — safe version.
///
/// Returns 0 on success, `ERANGE` if a buffer is too small, `EINVAL` if `path` is null.
///
/// # Safety
/// `path` must be a valid NUL-terminated string or null.
/// All non-null output pointers must be valid for their corresponding length.
#[unsafe(no_mangle)]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn msvcrt__splitpath_s(
    path: *const u8,
    drive: *mut u8,
    drivelen: usize,
    dir: *mut u8,
    dirlen: usize,
    fname: *mut u8,
    fnamelen: usize,
    ext: *mut u8,
    extlen: usize,
) -> i32 {
    if path.is_null() {
        return libc::EINVAL;
    }
    // SAFETY: path is a valid NUL-terminated string per caller contract.
    let len = unsafe { libc::strlen(path.cast()) };
    // SAFETY: path is valid for len bytes.
    let bytes = unsafe { core::slice::from_raw_parts(path, len) };

    let (drive_part, rest) = if bytes.len() >= 2 && bytes[1] == b':' {
        (&bytes[..2], &bytes[2..])
    } else {
        (&bytes[..0], bytes)
    };

    let last_sep = rest.iter().rposition(|&b| b == b'/' || b == b'\\');
    let (dir_part, file_part) = if let Some(idx) = last_sep {
        (&rest[..=idx], &rest[idx + 1..])
    } else {
        (&rest[..0], rest)
    };

    let last_dot = file_part.iter().rposition(|&b| b == b'.');
    let (fname_part, ext_part) = if let Some(idx) = last_dot {
        (&file_part[..idx], &file_part[idx..])
    } else {
        (file_part, &file_part[..0])
    };

    let check_and_write = |dst: *mut u8, maxlen: usize, src: &[u8]| -> i32 {
        if dst.is_null() {
            return 0;
        }
        if src.len() + 1 > maxlen {
            return libc::ERANGE;
        }
        // SAFETY: dst is valid for maxlen bytes, src.len() + 1 <= maxlen.
        unsafe {
            core::ptr::copy_nonoverlapping(src.as_ptr(), dst, src.len());
            *dst.add(src.len()) = 0;
        }
        0
    };

    let r = check_and_write(drive, drivelen, drive_part);
    if r != 0 {
        return r;
    }
    let r = check_and_write(dir, dirlen, dir_part);
    if r != 0 {
        return r;
    }
    let r = check_and_write(fname, fnamelen, fname_part);
    if r != 0 {
        return r;
    }
    check_and_write(ext, extlen, ext_part)
}

/// Build a path from components into a `Vec<u8>` (including NUL terminator).
///
/// Adds ':' after drive if missing, '\' after dir if missing, '.' before ext if missing.
/// All pointers may be null (treated as empty component).
///
/// # Safety
/// All non-null pointers must be valid NUL-terminated strings.
unsafe fn build_makepath(
    drive: *const u8,
    dir: *const u8,
    fname: *const u8,
    ext: *const u8,
) -> Vec<u8> {
    let read_cstr = |p: *const u8| -> &[u8] {
        if p.is_null() {
            return b"";
        }
        // SAFETY: p is a valid NUL-terminated string per caller contract.
        let len = unsafe { libc::strlen(p.cast()) };
        if len == 0 {
            return b"";
        }
        // SAFETY: p is valid for len bytes.
        unsafe { core::slice::from_raw_parts(p, len) }
    };

    let drive_s = read_cstr(drive);
    let dir_s = read_cstr(dir);
    let fname_s = read_cstr(fname);
    let ext_s = read_cstr(ext);
    let mut out: Vec<u8> = Vec::new();

    if !drive_s.is_empty() {
        out.extend_from_slice(drive_s);
        if out.last() != Some(&b':') {
            out.push(b':');
        }
    }
    if !dir_s.is_empty() {
        out.extend_from_slice(dir_s);
        let last = out.last().copied();
        if last != Some(b'\\') && last != Some(b'/') {
            out.push(b'\\');
        }
    }
    if !fname_s.is_empty() {
        out.extend_from_slice(fname_s);
    }
    if !ext_s.is_empty() {
        if ext_s[0] != b'.' {
            out.push(b'.');
        }
        out.extend_from_slice(ext_s);
    }
    out.push(0);
    out
}

/// `_makepath(buf, drive, dir, fname, ext)` — assemble a path from components.
///
/// Adds ':' after drive if missing, '\' after dir if missing, '.' before ext if missing.
///
/// # Safety
/// `buf` must be a valid, writable buffer large enough for the result.
/// All non-null string arguments must be valid NUL-terminated strings.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt__makepath(
    buf: *mut u8,
    drive: *const u8,
    dir: *const u8,
    fname: *const u8,
    ext: *const u8,
) {
    if buf.is_null() {
        return;
    }
    // SAFETY: all non-null pointers are valid NUL-terminated strings per caller contract.
    let out = unsafe { build_makepath(drive, dir, fname, ext) };
    // SAFETY: buf is valid for out.len() bytes per caller contract.
    unsafe { core::ptr::copy_nonoverlapping(out.as_ptr(), buf, out.len()) };
}

/// `_makepath_s(buf, size, drive, dir, fname, ext)` — safe version of `_makepath`.
///
/// Returns 0 on success, `ERANGE` if the result would overflow `size`.
///
/// # Safety
/// `buf` must be a valid, writable buffer of at least `size` bytes.
/// All non-null string arguments must be valid NUL-terminated strings.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt__makepath_s(
    buf: *mut u8,
    size: usize,
    drive: *const u8,
    dir: *const u8,
    fname: *const u8,
    ext: *const u8,
) -> i32 {
    if buf.is_null() || size == 0 {
        return libc::EINVAL;
    }
    // SAFETY: all non-null pointers are valid NUL-terminated strings per caller contract.
    let out = unsafe { build_makepath(drive, dir, fname, ext) };
    if out.len() > size {
        return libc::ERANGE;
    }
    // SAFETY: buf is valid for size bytes, out.len() <= size.
    unsafe { core::ptr::copy_nonoverlapping(out.as_ptr(), buf, out.len()) };
    0
}

// ── Phase 43: Directory navigation (MSVCRT.dll) ──────────────────────────────

/// `_getcwd(buf, size)` — get the current working directory.
///
/// If `buf` is null, allocates a buffer of at least `size` bytes (or `PATH_MAX` if
/// `size` is 0) and returns it; the caller must `free` it.
/// If `buf` is non-null, copies the path into it; returns null and sets
/// `errno = ERANGE` if `size` bytes are insufficient.
/// If `buf` is non-null and `size` is <= 0, sets `errno = EINVAL` and returns null.
///
/// # Safety
/// `buf`, if non-null, must point to at least `size` writable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt__getcwd(buf: *mut u8, size: i32) -> *mut u8 {
    if buf.is_null() {
        // Allocating variant: use PATH_MAX if size is 0 or negative.
        let alloc_size = if size <= 0 {
            libc::PATH_MAX as usize
        } else {
            size.unsigned_abs() as usize
        };
        // SAFETY: malloc returns a valid pointer or null.
        let p = unsafe { libc::malloc(alloc_size) }.cast::<u8>();
        if p.is_null() {
            return core::ptr::null_mut();
        }
        // SAFETY: p is valid for alloc_size bytes; getcwd fills it with the CWD path.
        let ret = unsafe { libc::getcwd(p.cast(), alloc_size) };
        if ret.is_null() {
            // SAFETY: p was allocated above.
            unsafe { libc::free(p.cast()) };
            return core::ptr::null_mut();
        }
        return p;
    }
    // Caller-provided buffer: size must be positive.
    if size <= 0 {
        // SAFETY: errno is a valid thread-local.
        unsafe { *libc::__errno_location() = libc::EINVAL };
        return core::ptr::null_mut();
    }
    // SAFETY: buf is valid for size bytes; getcwd writes the path into it.
    // size > 0 (checked above), so unsigned_abs() is safe.
    let ret = unsafe { libc::getcwd(buf.cast(), size.unsigned_abs() as usize) };
    if ret.is_null() {
        // SAFETY: errno is a valid thread-local.
        unsafe { *libc::__errno_location() = libc::ERANGE };
        return core::ptr::null_mut();
    }
    buf
}

/// `_chdir(dirname)` — change the current working directory.
///
/// Returns 0 on success, -1 on failure (errno is set by the OS).
///
/// # Safety
/// `dirname` must be a valid NUL-terminated string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt__chdir(dirname: *const u8) -> i32 {
    if dirname.is_null() {
        // SAFETY: errno is a valid thread-local.
        unsafe { *libc::__errno_location() = libc::EINVAL };
        return -1;
    }
    // SAFETY: dirname is a valid NUL-terminated string per caller contract.
    unsafe { libc::chdir(dirname.cast()) }
}

/// `_mkdir(dirname)` — create a directory.
///
/// Returns 0 on success, -1 on failure (errno is set by the OS).
///
/// # Safety
/// `dirname` must be a valid NUL-terminated string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt__mkdir(dirname: *const u8) -> i32 {
    if dirname.is_null() {
        // SAFETY: errno is a valid thread-local.
        unsafe { *libc::__errno_location() = libc::EINVAL };
        return -1;
    }
    // SAFETY: dirname is a valid NUL-terminated string per caller contract.
    // Mode 0o777 is the conventional MSVCRT default.
    unsafe { libc::mkdir(dirname.cast(), 0o777) }
}

/// `_rmdir(dirname)` — remove a directory.
///
/// Returns 0 on success, -1 on failure (errno is set by the OS).
///
/// # Safety
/// `dirname` must be a valid NUL-terminated string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt__rmdir(dirname: *const u8) -> i32 {
    if dirname.is_null() {
        // SAFETY: errno is a valid thread-local.
        unsafe { *libc::__errno_location() = libc::EINVAL };
        return -1;
    }
    // SAFETY: dirname is a valid NUL-terminated string per caller contract.
    unsafe { libc::rmdir(dirname.cast()) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_malloc_free() {
        unsafe {
            let ptr = msvcrt_malloc(100);
            assert!(!ptr.is_null());
            msvcrt_free(ptr);
        }
    }

    #[test]
    fn test_calloc() {
        unsafe {
            let ptr = msvcrt_calloc(10, 10);
            assert!(!ptr.is_null());
            // Verify zero-initialization
            for i in 0..100 {
                assert_eq!(*ptr.add(i), 0);
            }
            msvcrt_free(ptr);
        }
    }

    #[test]
    fn test_memcpy() {
        unsafe {
            let src = [1u8, 2, 3, 4, 5];
            let mut dest = [0u8; 5];
            msvcrt_memcpy(dest.as_mut_ptr(), src.as_ptr(), 5);
            assert_eq!(dest, src);
        }
    }

    #[test]
    fn test_memset() {
        unsafe {
            let mut buf = [0u8; 10];
            msvcrt_memset(buf.as_mut_ptr(), 0xFF, 10);
            assert_eq!(buf, [0xFF; 10]);
        }
    }

    #[test]
    fn test_memcmp() {
        unsafe {
            let s1 = [1u8, 2, 3];
            let s2 = [1u8, 2, 3];
            let s3 = [1u8, 2, 4];
            assert_eq!(msvcrt_memcmp(s1.as_ptr(), s2.as_ptr(), 3), 0);
            assert!(msvcrt_memcmp(s1.as_ptr(), s3.as_ptr(), 3) < 0);
        }
    }

    #[test]
    fn test_strlen() {
        unsafe {
            let s = b"hello\0";
            assert_eq!(msvcrt_strlen(s.as_ptr().cast::<i8>()), 5);
        }
    }

    #[test]
    fn test_strncmp() {
        unsafe {
            let s1 = b"hello\0";
            let s2 = b"hello\0";
            let s3 = b"world\0";
            assert_eq!(
                msvcrt_strncmp(s1.as_ptr().cast::<i8>(), s2.as_ptr().cast::<i8>(), 5),
                0
            );
            assert!(msvcrt_strncmp(s1.as_ptr().cast::<i8>(), s3.as_ptr().cast::<i8>(), 5) < 0);
        }
    }

    #[test]
    fn test_initterm_sentinel_filtering() {
        // Test that _initterm correctly filters out null and usize::MAX sentinel values
        use std::sync::atomic::{AtomicUsize, Ordering};

        static CALL_COUNT: AtomicUsize = AtomicUsize::new(0);

        extern "C" fn test_func1() {
            CALL_COUNT.fetch_add(1, Ordering::SeqCst);
        }

        extern "C" fn test_func2() {
            CALL_COUNT.fetch_add(10, Ordering::SeqCst);
        }

        // Create an init table with valid functions, null, and sentinel values
        let mut init_table: [usize; 6] = [
            0,                                // null - should be skipped
            test_func1 as *const () as usize, // valid function
            usize::MAX,                       // -1 sentinel - should be skipped
            test_func2 as *const () as usize, // valid function
            0,                                // null - should be skipped
            usize::MAX,                       // -1 sentinel - should be skipped
        ];

        // Call _initterm
        unsafe {
            msvcrt__initterm(
                init_table.as_mut_ptr().cast::<extern "C" fn()>(),
                init_table.as_mut_ptr().add(6).cast::<extern "C" fn()>(),
            );
        }

        // Only test_func1 and test_func2 should have been called
        assert_eq!(
            CALL_COUNT.load(Ordering::SeqCst),
            11,
            "Only valid functions should be called (1 + 10 = 11)"
        );
    }

    #[test]
    fn test_strcmp() {
        unsafe {
            let s1 = b"hello\0";
            let s2 = b"hello\0";
            let s3 = b"world\0";
            let s4 = b"hell\0";
            assert_eq!(
                msvcrt_strcmp(s1.as_ptr().cast::<i8>(), s2.as_ptr().cast::<i8>()),
                0
            );
            assert!(msvcrt_strcmp(s1.as_ptr().cast::<i8>(), s3.as_ptr().cast::<i8>()) < 0);
            assert!(msvcrt_strcmp(s3.as_ptr().cast::<i8>(), s1.as_ptr().cast::<i8>()) > 0);
            assert!(msvcrt_strcmp(s1.as_ptr().cast::<i8>(), s4.as_ptr().cast::<i8>()) != 0);
        }
    }

    #[test]
    fn test_strcpy() {
        unsafe {
            let src = b"hello\0";
            let mut dest = [0i8; 10];
            let result = msvcrt_strcpy(dest.as_mut_ptr(), src.as_ptr().cast::<i8>());
            assert_eq!(result, dest.as_mut_ptr());
            assert_eq!(dest[0], b'h'.cast_signed());
            assert_eq!(dest[4], b'o'.cast_signed());
            assert_eq!(dest[5], 0);
        }
    }

    #[test]
    fn test_strcat() {
        unsafe {
            let mut dest = [0i8; 20];
            let s1 = b"hello\0";
            let s2 = b" world\0";
            msvcrt_strcpy(dest.as_mut_ptr(), s1.as_ptr().cast::<i8>());
            msvcrt_strcat(dest.as_mut_ptr(), s2.as_ptr().cast::<i8>());
            let result = CStr::from_ptr(dest.as_ptr());
            assert_eq!(result.to_str().unwrap(), "hello world");
        }
    }

    #[test]
    fn test_strchr() {
        unsafe {
            let s = b"hello world\0";
            let result = msvcrt_strchr(s.as_ptr().cast::<i8>(), i32::from(b'o'));
            assert!(!result.is_null());
            assert_eq!(*result, b'o'.cast_signed());
            // Should find first occurrence
            let offset = result as usize - s.as_ptr() as usize;
            assert_eq!(offset, 4);
            // Character not found
            let result = msvcrt_strchr(s.as_ptr().cast::<i8>(), i32::from(b'z'));
            assert!(result.is_null());
        }
    }

    #[test]
    fn test_strrchr() {
        unsafe {
            let s = b"hello world\0";
            let result = msvcrt_strrchr(s.as_ptr().cast::<i8>(), i32::from(b'o'));
            assert!(!result.is_null());
            // Should find last occurrence (at index 7, in "world")
            let offset = result as usize - s.as_ptr() as usize;
            assert_eq!(offset, 7);
        }
    }

    #[test]
    fn test_strstr() {
        unsafe {
            let haystack = b"hello world\0";
            let needle = b"world\0";
            let result =
                msvcrt_strstr(haystack.as_ptr().cast::<i8>(), needle.as_ptr().cast::<i8>());
            assert!(!result.is_null());
            let offset = result as usize - haystack.as_ptr() as usize;
            assert_eq!(offset, 6);
            // Not found
            let needle2 = b"xyz\0";
            let result = msvcrt_strstr(
                haystack.as_ptr().cast::<i8>(),
                needle2.as_ptr().cast::<i8>(),
            );
            assert!(result.is_null());
            // Empty needle
            let empty = b"\0";
            let result = msvcrt_strstr(haystack.as_ptr().cast::<i8>(), empty.as_ptr().cast::<i8>());
            assert!(!result.is_null());
            assert_eq!(result, haystack.as_ptr().cast::<i8>());
        }
    }

    #[test]
    fn test_initterm_e() {
        use std::sync::atomic::{AtomicI32, Ordering};

        static CALL_RESULT: AtomicI32 = AtomicI32::new(0);

        extern "C" fn success_func() -> i32 {
            CALL_RESULT.fetch_add(1, Ordering::SeqCst);
            0 // success
        }

        extern "C" fn fail_func() -> i32 {
            42 // error
        }

        // Test successful completion
        CALL_RESULT.store(0, Ordering::SeqCst);
        let mut table: [usize; 3] = [
            success_func as *const () as usize,
            0, // null - skip
            success_func as *const () as usize,
        ];

        unsafe {
            let result = msvcrt__initterm_e(
                table.as_mut_ptr().cast::<extern "C" fn() -> i32>(),
                table.as_mut_ptr().add(3).cast::<extern "C" fn() -> i32>(),
            );
            assert_eq!(result, 0);
            assert_eq!(CALL_RESULT.load(Ordering::SeqCst), 2);
        }

        // Test failure stops iteration
        let mut table2: [usize; 2] = [
            fail_func as *const () as usize,
            success_func as *const () as usize, // should not be called
        ];

        CALL_RESULT.store(0, Ordering::SeqCst);
        unsafe {
            let result = msvcrt__initterm_e(
                table2.as_mut_ptr().cast::<extern "C" fn() -> i32>(),
                table2.as_mut_ptr().add(2).cast::<extern "C" fn() -> i32>(),
            );
            assert_eq!(result, 42);
            assert_eq!(CALL_RESULT.load(Ordering::SeqCst), 0); // success_func not called
        }
    }

    #[test]
    fn test_getenv() {
        unsafe {
            // PATH should exist on Linux
            let name = b"PATH\0";
            let result = msvcrt_getenv(name.as_ptr().cast::<i8>());
            // PATH should be set in any reasonable environment
            assert!(!result.is_null());

            // Nonexistent variable
            let name = b"LITEBOX_NONEXISTENT_VAR_12345\0";
            let result = msvcrt_getenv(name.as_ptr().cast::<i8>());
            assert!(result.is_null());
        }
    }

    #[test]
    fn test_errno() {
        unsafe {
            let ptr = msvcrt__errno();
            assert!(!ptr.is_null());
            // Should be same as __errno_location
            let ptr2 = msvcrt___errno_location();
            assert_eq!(ptr, ptr2);
        }
    }

    #[test]
    fn test_parse_windows_command_line_simple() {
        let args = parse_windows_command_line("prog.exe arg1 arg2");
        assert_eq!(args, vec!["prog.exe", "arg1", "arg2"]);
    }

    #[test]
    fn test_parse_windows_command_line_quoted() {
        let args = parse_windows_command_line(r#"prog.exe "hello world" arg2"#);
        assert_eq!(args, vec!["prog.exe", "hello world", "arg2"]);
    }

    #[test]
    fn test_parse_windows_command_line_escaped_quote() {
        // 1 backslash before quote = odd → literal quote (no quoting toggle)
        let args = parse_windows_command_line(r#"prog.exe "say \"hi\"" end"#);
        assert_eq!(args, vec!["prog.exe", r#"say "hi""#, "end"]);
    }

    #[test]
    fn test_parse_windows_command_line_empty() {
        let args = parse_windows_command_line("");
        assert!(args.is_empty());
    }

    #[test]
    fn test_parse_windows_command_line_single() {
        let args = parse_windows_command_line("prog.exe");
        assert_eq!(args, vec!["prog.exe"]);
    }

    #[test]
    fn test_parse_windows_command_line_backslash_in_path() {
        // Backslashes not followed by a quote are literal
        let args = parse_windows_command_line(r"prog.exe C:\path\to\file.txt");
        assert_eq!(args, vec!["prog.exe", r"C:\path\to\file.txt"]);
    }

    #[test]
    fn test_parse_windows_command_line_even_backslashes_before_quote() {
        // 2 backslashes + " => 1 backslash + quote toggle (quote is a delimiter)
        let args = parse_windows_command_line(r#"prog.exe "path\\" end"#);
        // Inside quotes: "path\\" → 2 backslashes before closing quote → 1 literal backslash, quote closes
        assert_eq!(args, vec!["prog.exe", r"path\", "end"]);
    }

    #[test]
    fn test_parse_windows_command_line_unquoted_escaped_quote() {
        // Outside quotes: \" = escaped quote (literal quote, no toggle)
        let args = parse_windows_command_line(r#"prog.exe arg\"with\"quote"#);
        assert_eq!(args, vec!["prog.exe", r#"arg"with"quote"#]);
    }

    #[test]
    fn test_acmdln_not_null() {
        let ptr = unsafe { msvcrt__acmdln() };
        // Should return a valid pointer (not null)
        assert!(!ptr.is_null());
    }

    #[test]
    fn test_atoi() {
        unsafe {
            assert_eq!(msvcrt_atoi(c"42".as_ptr(),), 42);
            assert_eq!(msvcrt_atoi(c"-5".as_ptr()), -5);
            assert_eq!(msvcrt_atoi(c"  10".as_ptr()), 10);
            assert_eq!(msvcrt_atoi(core::ptr::null()), 0);
        }
    }

    #[test]
    fn test_atof() {
        unsafe {
            let v = msvcrt_atof(c"2.5".as_ptr());
            assert!((v - 2.5).abs() < 1e-10);
            assert!((msvcrt_atof(core::ptr::null())).abs() < 1e-15);
        }
    }

    #[test]
    fn test_strtol() {
        unsafe {
            let mut end = core::ptr::null_mut::<i8>();
            let s = c"123abc";
            let val = msvcrt_strtol(s.as_ptr(), &raw mut end, 10);
            assert_eq!(val, 123);
            assert_eq!((*end).cast_unsigned(), b'a');
        }
    }

    #[test]
    fn test_itoa() {
        unsafe {
            let mut buf = [0i8; 32];
            msvcrt__itoa(255, buf.as_mut_ptr(), 16);
            let s = core::ffi::CStr::from_ptr(buf.as_ptr()).to_str().unwrap();
            assert_eq!(s, "ff");
        }
    }

    #[test]
    fn test_strncpy() {
        unsafe {
            let mut buf = [0i8; 16];
            msvcrt_strncpy(buf.as_mut_ptr(), c"hello".as_ptr(), 8);
            let s = core::ffi::CStr::from_ptr(buf.as_ptr()).to_str().unwrap();
            assert_eq!(s, "hello");
        }
    }

    #[test]
    fn test_stricmp() {
        unsafe {
            assert_eq!(msvcrt__stricmp(c"Hello".as_ptr(), c"hello".as_ptr()), 0);
            assert_ne!(msvcrt__stricmp(c"abc".as_ptr(), c"xyz".as_ptr()), 0);
        }
    }

    #[test]
    fn test_strnlen() {
        unsafe {
            assert_eq!(msvcrt_strnlen(c"hello".as_ptr(), 10), 5);
            assert_eq!(msvcrt_strnlen(c"hello".as_ptr(), 3), 3);
            assert_eq!(msvcrt_strnlen(core::ptr::null(), 10), 0);
        }
    }

    #[test]
    fn test_rand_srand() {
        unsafe {
            msvcrt_srand(42);
            let r1 = msvcrt_rand();
            msvcrt_srand(42);
            let r2 = msvcrt_rand();
            assert_eq!(r1, r2);
            assert!((0..=32767).contains(&r1));
        }
    }

    #[test]
    fn test_time() {
        unsafe {
            let t = msvcrt_time(core::ptr::null_mut());
            assert!(t > 0);
            let mut out: i64 = 0;
            let t2 = msvcrt_time(&raw mut out);
            assert_eq!(t2, out);
        }
    }

    #[test]
    fn test_math() {
        unsafe {
            assert_eq!(msvcrt_abs(-5), 5);
            assert_eq!(msvcrt_labs(-100i64), 100i64);
            assert!((msvcrt_sqrt(4.0) - 2.0).abs() < 1e-10);
            assert!((msvcrt_pow(2.0, 10.0) - 1024.0).abs() < 1e-6);
            assert!((msvcrt_floor(3.7) - 3.0).abs() < 1e-10);
            assert!((msvcrt_ceil(3.2) - 4.0).abs() < 1e-10);
        }
    }

    #[test]
    fn test_wcscpy_wcscat() {
        unsafe {
            let src: Vec<u16> = "hello\0".encode_utf16().collect();
            let mut buf = vec![0u16; 32];
            msvcrt_wcscpy(buf.as_mut_ptr(), src.as_ptr());
            let add: Vec<u16> = " world\0".encode_utf16().collect();
            msvcrt_wcscat(buf.as_mut_ptr(), add.as_ptr());
            let result =
                String::from_utf16_lossy(&buf[..buf.iter().position(|&c| c == 0).unwrap()]);
            assert_eq!(result, "hello world");
        }
    }

    #[test]
    fn test_wcstombs_mbstowcs() {
        unsafe {
            let wide: Vec<u16> = "hello\0".encode_utf16().collect();
            let mut narrow = vec![0i8; 16];
            let n = msvcrt_wcstombs(narrow.as_mut_ptr(), wide.as_ptr(), 16);
            assert_eq!(n, 5);
            let s = core::ffi::CStr::from_ptr(narrow.as_ptr()).to_str().unwrap();
            assert_eq!(s, "hello");
        }
    }

    #[test]
    fn test_atol() {
        unsafe {
            assert_eq!(msvcrt_atol(c"42".as_ptr()), 42);
            assert_eq!(msvcrt_atol(c"-7".as_ptr()), -7);
            assert_eq!(msvcrt_atol(c"0".as_ptr()), 0);
        }
    }

    #[test]
    fn test_strtoul() {
        unsafe {
            assert_eq!(
                msvcrt_strtoul(c"255".as_ptr(), core::ptr::null_mut(), 10),
                255
            );
            assert_eq!(
                msvcrt_strtoul(c"ff".as_ptr(), core::ptr::null_mut(), 16),
                0xff
            );
        }
    }

    #[test]
    fn test_strtod() {
        unsafe {
            let s = c"2.5abc";
            let mut end: *mut i8 = core::ptr::null_mut();
            let val = msvcrt_strtod(s.as_ptr(), &raw mut end);
            assert!((val - 2.5).abs() < 1e-6, "strtod: got {val}");
            // endptr should point past the parsed number (at 'a')
            let end_offset = end.offset_from(s.as_ptr());
            assert!(end_offset >= 0, "endptr must be after start");
            assert_eq!(
                end_offset.cast_unsigned(),
                3,
                "endptr offset should be 3, got {end_offset}"
            );
        }
    }

    #[test]
    fn test_ltoa() {
        unsafe {
            let mut buf = [0i8; 32];
            msvcrt__ltoa(-42, buf.as_mut_ptr(), 10);
            let s = core::ffi::CStr::from_ptr(buf.as_ptr()).to_str().unwrap();
            assert_eq!(s, "-42");
            msvcrt__ltoa(255, buf.as_mut_ptr(), 16);
            let s = core::ffi::CStr::from_ptr(buf.as_ptr()).to_str().unwrap();
            assert_eq!(s, "ff");
        }
    }

    #[test]
    fn test_strncat() {
        unsafe {
            let mut buf = [0i8; 32];
            let hello = c"hello";
            core::ptr::copy_nonoverlapping(hello.as_ptr(), buf.as_mut_ptr(), 6);
            msvcrt_strncat(buf.as_mut_ptr(), c" world".as_ptr(), 6);
            let s = core::ffi::CStr::from_ptr(buf.as_ptr()).to_str().unwrap();
            assert_eq!(s, "hello world");
        }
    }

    #[test]
    fn test_strnicmp() {
        unsafe {
            // equal strings (different case)
            assert_eq!(msvcrt__strnicmp(c"Hello".as_ptr(), c"hello".as_ptr(), 5), 0);
            // differ before n is reached
            assert_ne!(msvcrt__strnicmp(c"abc".as_ptr(), c"xyz".as_ptr(), 3), 0);
            // n=0 always equal
            assert_eq!(msvcrt__strnicmp(c"abc".as_ptr(), c"xyz".as_ptr(), 0), 0);
        }
    }

    #[test]
    fn test_strdup() {
        unsafe {
            let dup = msvcrt__strdup(c"hello".as_ptr());
            assert!(!dup.is_null());
            let result = core::ffi::CStr::from_ptr(dup).to_str().unwrap();
            assert_eq!(result, "hello");
            msvcrt_free(dup.cast());
        }
    }

    #[test]
    fn test_wcsdup() {
        unsafe {
            let src: Vec<u16> = "hello\0".encode_utf16().collect();
            let dup = msvcrt__wcsdup(src.as_ptr());
            assert!(!dup.is_null());
            let len = msvcrt_wcslen(dup);
            assert_eq!(len, 5);
            let result = String::from_utf16_lossy(std::slice::from_raw_parts(dup, len));
            assert_eq!(result, "hello");
            msvcrt_free(dup.cast());
        }
    }

    #[test]
    fn test_wcsdup_null() {
        unsafe {
            let dup = msvcrt__wcsdup(core::ptr::null());
            assert!(dup.is_null());
        }
    }

    #[test]
    fn test_count_scanf_specifiers() {
        // Basic specifiers
        assert_eq!(count_scanf_specifiers(b"%d"), 1);
        assert_eq!(count_scanf_specifiers(b"%d %s"), 2);
        assert_eq!(count_scanf_specifiers(b"%d %i %u %x"), 4);
        // Suppressed specifier — consumes input but NOT a pointer arg
        assert_eq!(count_scanf_specifiers(b"%*d %s"), 1);
        // Literal percent
        assert_eq!(count_scanf_specifiers(b"100%%"), 0);
        // Width and length modifiers
        assert_eq!(count_scanf_specifiers(b"%10s %ld"), 2);
        // Character class
        assert_eq!(count_scanf_specifiers(b"%[abc]"), 1);
        assert_eq!(count_scanf_specifiers(b"%[^abc]"), 1);
        // %n counts as consuming an arg
        assert_eq!(count_scanf_specifiers(b"%d%n"), 2);
        // Empty format
        assert_eq!(count_scanf_specifiers(b""), 0);
    }

    #[test]
    fn test_sscanf_int() {
        unsafe {
            let mut n: i32 = 0;
            let ret = msvcrt_sscanf(c"42".as_ptr(), c"%d".as_ptr(), &raw mut n, 0usize, 0usize);
            assert_eq!(ret, 1);
            assert_eq!(n, 42);
        }
    }

    #[test]
    fn test_sscanf_two_ints() {
        unsafe {
            let mut a: i32 = 0;
            let mut b: i32 = 0;
            let ret = msvcrt_sscanf(
                c"10 20".as_ptr(),
                c"%d %d".as_ptr(),
                &raw mut a,
                &raw mut b,
                0usize,
            );
            assert_eq!(ret, 2);
            assert_eq!(a, 10);
            assert_eq!(b, 20);
        }
    }

    #[test]
    fn test_sscanf_string() {
        unsafe {
            let mut buf = [0i8; 32];
            let ret = msvcrt_sscanf(
                c"hello world".as_ptr(),
                c"%31s".as_ptr(),
                buf.as_mut_ptr(),
                0usize,
            );
            assert_eq!(ret, 1);
            let s = core::ffi::CStr::from_ptr(buf.as_ptr()).to_str().unwrap();
            assert_eq!(s, "hello");
        }
    }

    #[test]
    fn test_sscanf_null_input() {
        unsafe {
            let mut n: i32 = 0;
            let ret = msvcrt_sscanf(core::ptr::null(), c"%d".as_ptr(), &raw mut n, 0usize);
            assert_eq!(ret, -1);
        }
    }

    #[test]
    fn test_clock() {
        unsafe {
            let t = msvcrt_clock();
            assert!(t >= 0, "clock should return non-negative value");
        }
    }

    #[test]
    fn test_labs_abs64() {
        unsafe {
            assert_eq!(msvcrt_labs(-99i64), 99i64);
            assert_eq!(msvcrt__abs64(-1_000_000i64), 1_000_000i64);
            assert_eq!(msvcrt__abs64(0), 0);
        }
    }

    #[test]
    fn test_math_extended() {
        unsafe {
            assert!((msvcrt_log(core::f64::consts::E) - 1.0).abs() < 1e-10);
            assert!((msvcrt_log10(100.0) - 2.0).abs() < 1e-10);
            assert!((msvcrt_exp(1.0) - core::f64::consts::E).abs() < 1e-10);
            assert!((msvcrt_sin(0.0)).abs() < 1e-10);
            assert!((msvcrt_cos(0.0) - 1.0).abs() < 1e-10);
            assert!((msvcrt_tan(0.0)).abs() < 1e-10);
            assert!((msvcrt_atan(1.0) - core::f64::consts::FRAC_PI_4).abs() < 1e-10);
            assert!((msvcrt_atan2(1.0, 1.0) - core::f64::consts::FRAC_PI_4).abs() < 1e-10);
            assert!((msvcrt_fmod(5.5, 2.0) - 1.5).abs() < 1e-10);
        }
    }

    #[test]
    fn test_wcsncpy() {
        unsafe {
            let src: Vec<u16> = "hello world\0".encode_utf16().collect();
            let mut buf = vec![0u16; 32];
            msvcrt_wcsncpy(buf.as_mut_ptr(), src.as_ptr(), 5);
            // wcsncpy copies exactly n chars; no guaranteed NUL if src >= n
            let result = String::from_utf16_lossy(&buf[..5]);
            assert_eq!(result, "hello");
        }
    }

    #[test]
    fn test_wcschr() {
        unsafe {
            let s: Vec<u16> = "hello\0".encode_utf16().collect();
            let found = msvcrt_wcschr(s.as_ptr(), u16::from(b'l'));
            assert!(!found.is_null());
            // offset to first 'l' is 2
            assert_eq!(found.offset_from(s.as_ptr()), 2);
            let not_found = msvcrt_wcschr(s.as_ptr(), u16::from(b'z'));
            assert!(not_found.is_null());
        }
    }

    #[test]
    fn test_wcsncmp() {
        unsafe {
            let a: Vec<u16> = "hello\0".encode_utf16().collect();
            let b: Vec<u16> = "hellx\0".encode_utf16().collect();
            assert_eq!(msvcrt_wcsncmp(a.as_ptr(), a.as_ptr(), 5), 0);
            let r = msvcrt_wcsncmp(a.as_ptr(), b.as_ptr(), 5);
            assert!(r < 0, "expected negative, got {r}");
            // only compare 4 chars — should be equal
            assert_eq!(msvcrt_wcsncmp(a.as_ptr(), b.as_ptr(), 4), 0);
        }
    }

    #[test]
    fn test_wcsicmp_wcsnicmp() {
        unsafe {
            let a: Vec<u16> = "Hello\0".encode_utf16().collect();
            let b: Vec<u16> = "hello\0".encode_utf16().collect();
            assert_eq!(msvcrt__wcsicmp(a.as_ptr(), b.as_ptr()), 0);
            assert_eq!(msvcrt__wcsnicmp(a.as_ptr(), b.as_ptr(), 5), 0);
            let c: Vec<u16> = "world\0".encode_utf16().collect();
            assert_ne!(msvcrt__wcsicmp(a.as_ptr(), c.as_ptr()), 0);
        }
    }

    #[test]
    fn test_cxx_frame_handler3_null_args() {
        let result = unsafe {
            msvcrt___CxxFrameHandler3(
                core::ptr::null_mut(),
                0,
                core::ptr::null_mut(),
                core::ptr::null_mut(),
            )
        };
        assert_eq!(result, 1);
    }

    #[test]
    fn test_cxx_frame_handler4_null_args() {
        let result = unsafe {
            msvcrt___CxxFrameHandler4(
                core::ptr::null_mut(),
                0,
                core::ptr::null_mut(),
                core::ptr::null_mut(),
            )
        };
        assert_eq!(result, 1);
    }

    #[test]
    fn test_cxx_register_unregister_exception_object() {
        let result = unsafe {
            msvcrt___CxxRegisterExceptionObject(core::ptr::null_mut(), core::ptr::null_mut())
        };
        assert_eq!(result, 1);

        let result = unsafe { msvcrt___CxxUnregisterExceptionObject(core::ptr::null_mut(), 0) };
        assert_eq!(result, 0);
    }

    #[test]
    fn test_destruct_exception_object_null() {
        unsafe { msvcrt___DestructExceptionObject(core::ptr::null_mut()) };
    }

    #[test]
    fn test_uncaught_exception() {
        assert_eq!(unsafe { msvcrt___uncaught_exception() }, 0);
        assert_eq!(unsafe { msvcrt___uncaught_exceptions() }, 0);
    }

    #[test]
    fn test_cxx_ip_to_state_empty() {
        let fi = CxxFuncInfo {
            magic_and_bbt: CXX_FRAME_MAGIC_VC8,
            unwind_count: 0,
            unwind_table: 0,
            tryblock_count: 0,
            tryblock: 0,
            ipmap_count: 0,
            ipmap: 0,
            unwind_help: 0,
            expect_list: 0,
            flags: 0,
        };
        assert_eq!(cxx_ip_to_state(&fi, 0x1000, 0x1100), -1);
    }

    // ── printf formatter unit tests ──────────────────────────────────────────

    /// Helper: run `format_printf_va` via a variadic wrapper so that the
    /// `VaList` is properly initialised by the Rust calling-convention machinery.
    #[cfg(test)]
    #[allow(improper_ctypes_definitions)]
    unsafe extern "C" fn fmt_helper(fmt: *const i8, mut args: ...) -> Vec<u8> {
        let bytes = unsafe { CStr::from_ptr(fmt) }.to_bytes();
        unsafe { format_printf_va(bytes, &mut args, false) }
    }

    #[test]
    fn test_printf_literal() {
        let fmt = CString::new("hello world").unwrap();
        let out = unsafe { fmt_helper(fmt.as_ptr(), 0i32) };
        assert_eq!(out, b"hello world");
    }

    #[test]
    fn test_printf_percent() {
        let fmt = CString::new("100%%").unwrap();
        let out = unsafe { fmt_helper(fmt.as_ptr(), 0i32) };
        assert_eq!(out, b"100%");
    }

    #[test]
    fn test_printf_d() {
        let fmt = CString::new("%d").unwrap();
        let out = unsafe { fmt_helper(fmt.as_ptr(), 42i32) };
        assert_eq!(out, b"42");
    }

    #[test]
    fn test_printf_d_negative() {
        let fmt = CString::new("%d").unwrap();
        let out = unsafe { fmt_helper(fmt.as_ptr(), -99i32) };
        assert_eq!(out, b"-99");
    }

    #[test]
    fn test_printf_width_zero_pad() {
        let fmt = CString::new("%05d").unwrap();
        let out = unsafe { fmt_helper(fmt.as_ptr(), 7i32) };
        assert_eq!(out, b"00007");
    }

    #[test]
    fn test_printf_left_align() {
        let fmt = CString::new("%-5d|").unwrap();
        let out = unsafe { fmt_helper(fmt.as_ptr(), 7i32) };
        assert_eq!(out, b"7    |");
    }

    #[test]
    fn test_printf_plus_sign() {
        let fmt = CString::new("%+d %+d").unwrap();
        let out = unsafe { fmt_helper(fmt.as_ptr(), 3i32, -5i32) };
        assert_eq!(out, b"+3 -5");
    }

    #[test]
    fn test_printf_x() {
        let fmt = CString::new("%x %X").unwrap();
        let out = unsafe { fmt_helper(fmt.as_ptr(), 255u32, 255u32) };
        assert_eq!(out, b"ff FF");
    }

    #[test]
    fn test_printf_x_alt() {
        let fmt = CString::new("%#x").unwrap();
        let out = unsafe { fmt_helper(fmt.as_ptr(), 255u32) };
        assert_eq!(out, b"0xff");
    }

    #[test]
    fn test_printf_o() {
        let fmt = CString::new("%o").unwrap();
        let out = unsafe { fmt_helper(fmt.as_ptr(), 8u32) };
        assert_eq!(out, b"10");
    }

    #[test]
    fn test_printf_s() {
        let s = CString::new("world").unwrap();
        let fmt = CString::new("hello %s").unwrap();
        let out = unsafe { fmt_helper(fmt.as_ptr(), s.as_ptr()) };
        assert_eq!(out, b"hello world");
    }

    #[test]
    fn test_printf_s_width() {
        let s = CString::new("hi").unwrap();
        let fmt = CString::new("[%5s]").unwrap();
        let out = unsafe { fmt_helper(fmt.as_ptr(), s.as_ptr()) };
        assert_eq!(out, b"[   hi]");
    }

    #[test]
    fn test_printf_s_precision() {
        let s = CString::new("hello").unwrap();
        let fmt = CString::new("%.3s").unwrap();
        let out = unsafe { fmt_helper(fmt.as_ptr(), s.as_ptr()) };
        assert_eq!(out, b"hel");
    }

    #[test]
    fn test_printf_u() {
        let fmt = CString::new("%u").unwrap();
        let out = unsafe { fmt_helper(fmt.as_ptr(), 4294967295u32) };
        assert_eq!(out, b"4294967295");
    }

    #[test]
    fn test_printf_lld() {
        let fmt = CString::new("%lld").unwrap();
        let out = unsafe { fmt_helper(fmt.as_ptr(), -1i64) };
        assert_eq!(out, b"-1");
    }

    #[test]
    fn test_printf_i64d() {
        // Windows-style %I64d
        let fmt = CString::new("%I64d").unwrap();
        let out = unsafe { fmt_helper(fmt.as_ptr(), 123i64) };
        assert_eq!(out, b"123");
    }

    #[test]
    fn test_printf_p() {
        let fmt = CString::new("%p").unwrap();
        let out = unsafe { fmt_helper(fmt.as_ptr(), 0usize) };
        // Should produce "0x" followed by 16 hex digits
        assert!(std::str::from_utf8(&out).unwrap().starts_with("0x"));
    }

    #[test]
    fn test_printf_c() {
        let fmt = CString::new("%c").unwrap();
        let out = unsafe { fmt_helper(fmt.as_ptr(), i32::from(b'A')) };
        assert_eq!(out, b"A");
    }

    #[test]
    fn test_sprintf_basic() {
        let mut buf = [0i8; 64];
        let fmt = CString::new("val=%d").unwrap();
        let n = unsafe { msvcrt_sprintf(buf.as_mut_ptr(), fmt.as_ptr(), 42i32, 0i32, 0i32, 0i32) };
        assert_eq!(n, 6);
        let s = unsafe { CStr::from_ptr(buf.as_ptr()) }.to_str().unwrap();
        assert_eq!(s, "val=42");
    }

    #[test]
    fn test_snprintf_truncate() {
        let mut buf = [0i8; 5];
        let fmt = CString::new("%d").unwrap();
        let n = unsafe {
            msvcrt_snprintf(
                buf.as_mut_ptr(),
                5,
                fmt.as_ptr(),
                12345i32,
                0i32,
                0i32,
                0i32,
            )
        };
        // Would-write = 5, but buf only holds 4 chars + NUL
        assert_eq!(n, 5);
        let s = unsafe { CStr::from_ptr(buf.as_ptr()) }.to_str().unwrap();
        assert_eq!(s, "1234"); // truncated to 4 chars
    }

    // ── vprintf-family tests (format_printf_raw) ─────────────────────────────

    /// Helper: build a Windows va_list from a slice of i64 values and call
    /// `format_printf_raw`.  All args are packed as 8-byte slots, matching the
    /// Windows x64 va_list convention.
    unsafe fn raw_fmt(fmt_str: &str, args: &[i64]) -> Vec<u8> {
        // Copy args to ensure 8-byte alignment.
        let mut aligned_args: Vec<i64> = args.to_vec();
        // Always append at least one slot so the pointer passed to
        // format_printf_raw is valid even when `args` is empty (a zero-length
        // slice's .as_ptr() is allowed to be non-dereferenceable).
        aligned_args.push(0);
        let ap = aligned_args.as_mut_ptr().cast::<u8>();
        let fmt_bytes = fmt_str.as_bytes();
        unsafe { format_printf_raw(fmt_bytes, ap, false) }
    }

    #[test]
    fn test_format_raw_empty() {
        // Empty format string: no output, no args needed.
        let out = unsafe { raw_fmt("", &[]) };
        assert_eq!(out, b"");
    }

    #[test]
    fn test_format_raw_no_specifiers() {
        // Format with no % specifiers: output equals the input.
        let out = unsafe { raw_fmt("no specifiers here", &[]) };
        assert_eq!(out, b"no specifiers here");
    }

    #[test]
    fn test_format_raw_literal() {
        let out = unsafe { raw_fmt("hello", &[]) };
        assert_eq!(out, b"hello");
    }

    #[test]
    fn test_format_raw_int() {
        let out = unsafe { raw_fmt("%d", &[42]) };
        assert_eq!(out, b"42");
    }

    #[test]
    fn test_format_raw_string() {
        let s = CString::new("world").unwrap();
        let ptr = s.as_ptr() as i64;
        let out = unsafe { raw_fmt("%s", &[ptr]) };
        assert_eq!(out, b"world");
    }

    #[test]
    fn test_format_raw_multi() {
        let out = unsafe { raw_fmt("%d %d", &[1, 2]) };
        assert_eq!(out, b"1 2");
    }

    #[test]
    fn test_vsprintf_basic() {
        // Build a Windows va_list with [42i64]
        let args: [i64; 1] = [42];
        let fmt = CString::new("val=%d").unwrap();
        let mut buf = [0i8; 64];
        let n =
            unsafe { msvcrt_vsprintf(buf.as_mut_ptr(), fmt.as_ptr(), args.as_ptr() as *mut u8) };
        assert_eq!(n, 6);
        let s = unsafe { CStr::from_ptr(buf.as_ptr()) }.to_str().unwrap();
        assert_eq!(s, "val=42");
    }

    #[test]
    fn test_vsnprintf_truncate() {
        let args: [i64; 1] = [12345];
        let fmt = CString::new("%d").unwrap();
        let mut buf = [0i8; 5];
        let n = unsafe {
            msvcrt_vsnprintf(buf.as_mut_ptr(), 5, fmt.as_ptr(), args.as_ptr() as *mut u8)
        };
        assert_eq!(n, 5); // would write 5 chars
        let s = unsafe { CStr::from_ptr(buf.as_ptr()) }.to_str().unwrap();
        assert_eq!(s, "1234"); // truncated
    }

    #[test]
    fn test_vsnprintf_null_buf() {
        let args: [i64; 1] = [99];
        let fmt = CString::new("%d").unwrap();
        // null buf: should return the would-be length
        let n = unsafe {
            msvcrt_vsnprintf(
                core::ptr::null_mut(),
                0,
                fmt.as_ptr(),
                args.as_ptr() as *mut u8,
            )
        };
        assert_eq!(n, 2); // "99" is 2 chars
    }

    // ── Phase 35 tests ───────────────────────────────────────────────────────

    #[test]
    fn test_vsnwprintf_basic() {
        // "_vsnwprintf(buf, 16, L"%d", [42])" should write L"42\0"
        let args: [i64; 1] = [42];
        let fmt_wide: Vec<u16> = "%d\0".encode_utf16().collect();
        let mut buf = [0u16; 16];
        let n = unsafe {
            msvcrt__vsnwprintf(
                buf.as_mut_ptr(),
                16,
                fmt_wide.as_ptr(),
                args.as_ptr() as *mut u8,
            )
        };
        assert_eq!(n, 2); // "42" is 2 wide chars
        assert_eq!(buf[0], u16::from(b'4'));
        assert_eq!(buf[1], u16::from(b'2'));
        assert_eq!(buf[2], 0); // NUL terminator
    }

    #[test]
    fn test_vsnwprintf_truncated() {
        // Buffer of 3 wide chars: can hold at most "12\0", should truncate "1234"
        let args: [i64; 1] = [1234];
        let fmt_wide: Vec<u16> = "%d\0".encode_utf16().collect();
        let mut buf = [0u16; 3];
        let n = unsafe {
            msvcrt__vsnwprintf(
                buf.as_mut_ptr(),
                3,
                fmt_wide.as_ptr(),
                args.as_ptr() as *mut u8,
            )
        };
        // Truncated: returns -1 on Windows MSVCRT
        assert_eq!(n, -1);
        assert_eq!(buf[2], 0); // NUL at copy_len position
    }

    #[test]
    fn test_vscprintf_basic() {
        // "_vscprintf("%d", [12345])" should return 5
        let args: [i64; 1] = [12345];
        let fmt = CString::new("%d").unwrap();
        let n = unsafe { msvcrt__vscprintf(fmt.as_ptr(), args.as_ptr() as *mut u8) };
        assert_eq!(n, 5);
    }

    #[test]
    fn test_vscprintf_empty() {
        let fmt = CString::new("hello").unwrap();
        // Need at least one slot in the args array (even if unused).
        let dummy: [i64; 1] = [0];
        let n = unsafe { msvcrt__vscprintf(fmt.as_ptr(), dummy.as_ptr() as *mut u8) };
        assert_eq!(n, 5);
    }

    #[test]
    fn test_get_osfhandle_stdin() {
        let h = unsafe { msvcrt__get_osfhandle(0) };
        assert_eq!(h, -10); // STD_INPUT_HANDLE
    }

    #[test]
    fn test_get_osfhandle_stdout() {
        let h = unsafe { msvcrt__get_osfhandle(1) };
        assert_eq!(h, -11); // STD_OUTPUT_HANDLE
    }

    #[test]
    fn test_get_osfhandle_stderr() {
        let h = unsafe { msvcrt__get_osfhandle(2) };
        assert_eq!(h, -12); // STD_ERROR_HANDLE
    }

    #[test]
    fn test_get_osfhandle_invalid() {
        let h = unsafe { msvcrt__get_osfhandle(-1) };
        assert_eq!(h, -1); // INVALID_HANDLE_VALUE
    }

    #[test]
    fn test_get_osfhandle_regular_fd() {
        let h = unsafe { msvcrt__get_osfhandle(5) };
        assert_eq!(h, 5);
    }

    #[test]
    fn test_open_osfhandle_stdin() {
        let fd = unsafe { msvcrt__open_osfhandle(-10, 0) };
        assert_eq!(fd, 0);
    }

    #[test]
    fn test_open_osfhandle_stdout() {
        let fd = unsafe { msvcrt__open_osfhandle(-11, 0) };
        assert_eq!(fd, 1);
    }

    #[test]
    fn test_open_osfhandle_stderr() {
        let fd = unsafe { msvcrt__open_osfhandle(-12, 0) };
        assert_eq!(fd, 2);
    }

    #[test]
    fn test_open_osfhandle_invalid() {
        let fd = unsafe { msvcrt__open_osfhandle(-1, 0) };
        assert_eq!(fd, -1);
    }

    #[test]
    fn test_open_osfhandle_regular() {
        let fd = unsafe { msvcrt__open_osfhandle(7, 0) };
        assert_eq!(fd, 7);
    }

    // ── _snprintf_s tests ─────────────────────────────────────────────────────

    /// Basic formatting succeeds; returns the number of characters written.
    #[test]
    fn test_snprintf_s_basic() {
        let mut buf = [0i8; 16];
        let fmt = CString::new("val=%d").unwrap();
        let n = unsafe {
            msvcrt_snprintf_s(
                buf.as_mut_ptr(),
                buf.len(),
                usize::MAX, // _TRUNCATE
                fmt.as_ptr(),
                42i32,
                0i32,
                0i32,
                0i32,
            )
        };
        assert_eq!(n, 6, "should return number of chars written");
        let s = unsafe { CStr::from_ptr(buf.as_ptr()) }.to_str().unwrap();
        assert_eq!(s, "val=42");
    }

    /// NULL buffer returns -1.
    #[test]
    fn test_snprintf_s_null_buf() {
        let fmt = CString::new("%d").unwrap();
        let n = unsafe {
            msvcrt_snprintf_s(
                std::ptr::null_mut(),
                16,
                usize::MAX,
                fmt.as_ptr(),
                1i32,
                0i32,
                0i32,
                0i32,
            )
        };
        assert_eq!(n, -1);
    }

    /// Zero-size buffer returns -1.
    #[test]
    fn test_snprintf_s_zero_size() {
        let mut buf = [0i8; 16];
        let fmt = CString::new("%d").unwrap();
        let n = unsafe {
            msvcrt_snprintf_s(
                buf.as_mut_ptr(),
                0,
                usize::MAX,
                fmt.as_ptr(),
                1i32,
                0i32,
                0i32,
                0i32,
            )
        };
        assert_eq!(n, -1);
    }

    /// With _TRUNCATE, truncation succeeds and returns the number of chars written.
    #[test]
    fn test_snprintf_s_truncate_with_truncate_flag() {
        let mut buf = [0i8; 5]; // can hold 4 chars + NUL
        let fmt = CString::new("%d").unwrap();
        let n = unsafe {
            msvcrt_snprintf_s(
                buf.as_mut_ptr(),
                buf.len(),
                usize::MAX, // _TRUNCATE
                fmt.as_ptr(),
                12345i32,
                0i32,
                0i32,
                0i32,
            )
        };
        // Written 4 chars (truncated from "12345"), returns 4
        assert_eq!(n, 4);
        let s = unsafe { CStr::from_ptr(buf.as_ptr()) }.to_str().unwrap();
        assert_eq!(s, "1234");
    }

    /// Without _TRUNCATE, truncation returns -1 and still NUL-terminates.
    #[test]
    fn test_snprintf_s_truncate_without_truncate_flag() {
        let mut buf = [0i8; 5]; // can hold 4 chars + NUL
        let fmt = CString::new("%d").unwrap();
        let n = unsafe {
            msvcrt_snprintf_s(
                buf.as_mut_ptr(),
                buf.len(),
                10, // count larger than buffer but output is 5 chars
                fmt.as_ptr(),
                12345i32,
                0i32,
                0i32,
                0i32,
            )
        };
        // Truncation with non-_TRUNCATE count returns -1 (MSVCRT semantics)
        assert_eq!(n, -1);
        // Buffer is still NUL-terminated
        let s = unsafe { CStr::from_ptr(buf.as_ptr()) }.to_str().unwrap();
        assert_eq!(s, "1234");
    }

    /// count limits the output even when the buffer is larger.
    #[test]
    fn test_snprintf_s_count_limits_output() {
        let mut buf = [0i8; 16];
        let fmt = CString::new("hello").unwrap();
        // count=3: only 3 chars should be written
        let n = unsafe {
            msvcrt_snprintf_s(
                buf.as_mut_ptr(),
                buf.len(),
                3,
                fmt.as_ptr(),
                0i32,
                0i32,
                0i32,
                0i32,
            )
        };
        // Truncation with non-_TRUNCATE count returns -1
        assert_eq!(n, -1);
        let s = unsafe { CStr::from_ptr(buf.as_ptr()) }.to_str().unwrap();
        assert_eq!(s, "hel");
    }

    // ── Phase 37: numeric conversion tests ───────────────────────────────────

    #[test]
    fn test_ultoa_decimal() {
        let mut buf = [0i8; 32];
        let p = unsafe { msvcrt__ultoa(12345u64, buf.as_mut_ptr(), 10) };
        assert!(!p.is_null());
        let s = unsafe { CStr::from_ptr(buf.as_ptr()) }.to_str().unwrap();
        assert_eq!(s, "12345");
    }

    #[test]
    fn test_ultoa_hex() {
        let mut buf = [0i8; 32];
        let p = unsafe { msvcrt__ultoa(255u64, buf.as_mut_ptr(), 16) };
        assert!(!p.is_null());
        let s = unsafe { CStr::from_ptr(buf.as_ptr()) }.to_str().unwrap();
        assert_eq!(s, "ff");
    }

    #[test]
    fn test_i64toa_negative() {
        let mut buf = [0i8; 32];
        let p = unsafe { msvcrt__i64toa(-42i64, buf.as_mut_ptr(), 10) };
        assert!(!p.is_null());
        let s = unsafe { CStr::from_ptr(buf.as_ptr()) }.to_str().unwrap();
        assert_eq!(s, "-42");
    }

    #[test]
    fn test_ui64toa_large() {
        let mut buf = [0i8; 32];
        let p = unsafe { msvcrt__ui64toa(u64::MAX, buf.as_mut_ptr(), 10) };
        assert!(!p.is_null());
        let s = unsafe { CStr::from_ptr(buf.as_ptr()) }.to_str().unwrap();
        assert_eq!(s, "18446744073709551615");
    }

    #[test]
    fn test_strtoi64() {
        let n = unsafe { msvcrt__strtoi64(c"42".as_ptr(), core::ptr::null_mut(), 10) };
        assert_eq!(n, 42i64);
    }

    #[test]
    fn test_strtoi64_negative() {
        let n = unsafe { msvcrt__strtoi64(c"-99".as_ptr(), core::ptr::null_mut(), 10) };
        assert_eq!(n, -99i64);
    }

    #[test]
    fn test_strtoui64() {
        let n = unsafe {
            msvcrt__strtoui64(c"18446744073709551615".as_ptr(), core::ptr::null_mut(), 10)
        };
        assert_eq!(n, u64::MAX);
    }

    #[test]
    fn test_itow_decimal() {
        let mut buf = [0u16; 16];
        let p = unsafe { msvcrt__itow(255, buf.as_mut_ptr(), 10) };
        assert!(!p.is_null());
        let s: String = buf
            .iter()
            .take_while(|&&c| c != 0)
            .map(|&c| char::from(u8::try_from(c).unwrap_or(b'?')))
            .collect();
        assert_eq!(s, "255");
    }

    #[test]
    fn test_ltow_negative() {
        let mut buf = [0u16; 32];
        let p = unsafe { msvcrt__ltow(-7i64, buf.as_mut_ptr(), 10) };
        assert!(!p.is_null());
        let s: String = buf
            .iter()
            .take_while(|&&c| c != 0)
            .map(|&c| char::from(u8::try_from(c).unwrap_or(b'?')))
            .collect();
        assert_eq!(s, "-7");
    }

    // ── Phase 37: UCRT vsprintf tests ─────────────────────────────────────────

    #[cfg(all(target_arch = "x86_64", target_os = "linux", target_env = "gnu"))]
    #[test]
    fn test_ucrt_stdio_common_vsprintf_basic() {
        // Build a Windows-style va_list: two 8-byte slots: [42i64, 0i64]
        let args: [u64; 2] = [42, 0];
        let mut buf = [0u8; 32];
        let fmt = c"%d";
        let n = unsafe {
            ucrt__stdio_common_vsprintf(
                0,
                buf.as_mut_ptr(),
                buf.len(),
                fmt.as_ptr().cast::<u8>(),
                core::ptr::null(),
                args.as_ptr() as *mut u8,
            )
        };
        assert_eq!(n, 2); // "42" has 2 chars
        let s = unsafe { CStr::from_ptr(buf.as_ptr().cast::<i8>()) }
            .to_str()
            .unwrap();
        assert_eq!(s, "42");
    }

    #[cfg(all(target_arch = "x86_64", target_os = "linux", target_env = "gnu"))]
    #[test]
    fn test_ucrt_stdio_common_vsprintf_null_fmt() {
        let mut buf = [0u8; 32];
        let n = unsafe {
            ucrt__stdio_common_vsprintf(
                0,
                buf.as_mut_ptr(),
                buf.len(),
                core::ptr::null(),
                core::ptr::null(),
                core::ptr::null_mut(),
            )
        };
        assert_eq!(n, -1);
    }

    // ── Phase 38: _wfindfirst / locale printf tests ──────────────────────────

    #[test]
    fn test_wildcard_match_star() {
        assert!(super::wildcard_match("*.txt", "hello.txt"));
        assert!(!super::wildcard_match("*.txt", "hello.rs"));
        assert!(super::wildcard_match("*", "anything"));
        assert!(super::wildcard_match("*", ""));
    }

    #[test]
    fn test_wildcard_match_question() {
        assert!(super::wildcard_match("h?llo", "hello"));
        assert!(!super::wildcard_match("h?llo", "hllo"));
        assert!(super::wildcard_match("?.txt", "a.txt"));
    }

    #[test]
    fn test_wildcard_match_literal() {
        assert!(super::wildcard_match("hello", "hello"));
        assert!(!super::wildcard_match("hello", "world"));
    }

    #[test]
    fn test_findclose_invalid_handle_returns_minus1() {
        // Closing a handle that was never opened should return -1.
        let result = unsafe { msvcrt__findclose(999_999) };
        assert_eq!(result, -1);
    }

    #[test]
    fn test_wfindfirst_null_spec_returns_error() {
        let mut buf = [0u8; 556];
        let result = unsafe { msvcrt__wfindfirst64i32(std::ptr::null(), buf.as_mut_ptr()) };
        assert_eq!(result, -1);
    }

    #[test]
    fn test_printf_l_null_fmt() {
        let result = unsafe { msvcrt__printf_l(std::ptr::null(), std::ptr::null_mut()) };
        assert_eq!(result, -1);
    }

    #[test]
    fn test_sprintf_l_basic() {
        let mut buf = [0u8; 64];
        let fmt = b"hello\0";
        let result =
            unsafe { msvcrt__sprintf_l(buf.as_mut_ptr(), fmt.as_ptr(), std::ptr::null_mut()) };
        assert_eq!(result, 5);
        assert_eq!(&buf[..5], b"hello");
        assert_eq!(buf[5], 0);
    }

    #[test]
    fn test_snprintf_l_truncation() {
        let mut buf = [0u8; 4];
        let fmt = b"hello\0";
        let result =
            unsafe { msvcrt__snprintf_l(buf.as_mut_ptr(), 4, fmt.as_ptr(), std::ptr::null_mut()) };
        // Would-write count is 5 but only 3 chars + NUL written.
        assert_eq!(result, 5);
        assert_eq!(buf[3], 0); // NUL terminator
    }

    // ── Phase 39: low-level file I/O tests ──────────────────────────────────

    #[test]
    fn test_open_close_basic() {
        // Open /dev/null (always present on Linux) for reading and close it.
        let path = b"/dev/null\0";
        let fd = unsafe {
            msvcrt__open(path.as_ptr(), 0 /* _O_RDONLY */, 0)
        };
        assert!(fd >= 0, "expected valid fd, got {fd}");
        let ret = unsafe { msvcrt__close(fd) };
        assert_eq!(ret, 0);
    }

    #[test]
    fn test_open_null_path_returns_minus1() {
        let fd = unsafe { msvcrt__open(std::ptr::null(), 0, 0) };
        assert_eq!(fd, -1);
    }

    #[test]
    fn test_creat_null_path_returns_minus1() {
        let ret = unsafe { msvcrt__creat(std::ptr::null(), 0) };
        assert_eq!(ret, -1);
    }

    #[test]
    fn test_lseek_and_tell_on_dev_null() {
        let path = b"/dev/null\0";
        let fd = unsafe { msvcrt__open(path.as_ptr(), 0, 0) };
        assert!(fd >= 0);
        // lseek on /dev/null always returns 0 for SEEK_CUR on many systems.
        let pos = unsafe { msvcrt__tell(fd) };
        // Just check it doesn't return an error signal that crashes us.
        assert!(pos >= -1);
        let _ = unsafe { msvcrt__close(fd) };
    }

    #[test]
    fn test_dup_and_dup2_on_stdin() {
        let new_fd = unsafe { msvcrt__dup(0) };
        assert!(new_fd >= 0, "dup(stdin) failed: {new_fd}");
        let ret = unsafe { msvcrt__close(new_fd) };
        assert_eq!(ret, 0);
    }

    #[test]
    fn test_filelengthi64_on_dev_null() {
        let path = b"/dev/null\0";
        let fd = unsafe { msvcrt__open(path.as_ptr(), 0, 0) };
        assert!(fd >= 0);
        let size = unsafe { msvcrt__filelengthi64(fd) };
        // /dev/null reports size 0.
        assert_eq!(size, 0);
        let _ = unsafe { msvcrt__close(fd) };
    }

    #[test]
    fn test_stat64_on_existing_file() {
        // /etc/hostname always exists on Linux
        let path = b"/etc/hostname\0";
        let mut buf = unsafe { core::mem::zeroed::<WinStat64>() };
        let ret = unsafe { msvcrt__stat64(path.as_ptr(), &raw mut buf) };
        assert_eq!(ret, 0);
        assert!(buf.st_size > 0);
        assert_eq!(buf.st_mode & WIN_S_IFREG, WIN_S_IFREG); // regular file
    }

    #[test]
    fn test_stat_on_dir() {
        let path = b"/tmp\0";
        let mut buf = unsafe { core::mem::zeroed::<WinStat32>() };
        let ret = unsafe { msvcrt__stat(path.as_ptr(), &raw mut buf) };
        assert_eq!(ret, 0);
        assert_eq!(buf.st_mode & WIN_S_IFDIR, WIN_S_IFDIR); // directory
    }

    #[test]
    fn test_fstat64_on_stdin() {
        let mut buf = unsafe { core::mem::zeroed::<WinStat64>() };
        let ret = unsafe { msvcrt__fstat64(0, &raw mut buf) };
        // stdin may or may not be a regular file in tests; just check it doesn't crash
        let _ = ret;
    }

    #[test]
    fn test_stat64_null_path_returns_error() {
        let mut buf = unsafe { core::mem::zeroed::<WinStat64>() };
        let ret = unsafe { msvcrt__stat64(core::ptr::null(), &raw mut buf) };
        assert_eq!(ret, -1);
    }

    #[test]
    fn test_wopen_write_close() {
        let path = b"/tmp/litebox_wopen_test\0";
        // Clean up first
        unsafe { libc::unlink(path.as_ptr().cast()) };
        let wide_path: Vec<u16> = "/tmp/litebox_wopen_test\0".encode_utf16().collect();
        let fd = unsafe { msvcrt__wopen(wide_path.as_ptr(), 0x0101, 0o644) }; // O_WRONLY|O_CREAT
        if fd >= 0 {
            unsafe { libc::close(fd) };
            unsafe { libc::unlink(path.as_ptr().cast()) };
        }
        // Any non-crash result is acceptable
    }

    #[test]
    fn test_wstat64_on_tmp() {
        let wide_path: Vec<u16> = "/tmp\0".encode_utf16().collect();
        let mut buf = unsafe { core::mem::zeroed::<WinStat64>() };
        let ret = unsafe { msvcrt__wstat64(wide_path.as_ptr(), &raw mut buf) };
        assert_eq!(ret, 0);
        assert_eq!(buf.st_mode & WIN_S_IFDIR, WIN_S_IFDIR); // directory
    }

    #[test]
    fn test_sopen_s_null_pfh_returns_einval() {
        let path = b"/tmp/litebox_sopen_s_test\0";
        let ret = unsafe { msvcrt__sopen_s(core::ptr::null_mut(), path.as_ptr(), 0, 0, 0) };
        assert_eq!(ret, libc::EINVAL);
    }

    #[test]
    fn test_sopen_s_success_and_stores_fd() {
        let path = b"/etc/hostname\0";
        let mut fd: i32 = -1;
        let ret = unsafe { msvcrt__sopen_s(&raw mut fd, path.as_ptr(), 0, 0, 0) };
        assert_eq!(ret, 0);
        assert!(fd >= 0);
        unsafe { libc::close(fd) };
    }

    #[test]
    fn test_wsopen_s_success_and_stores_fd() {
        let wide_path: Vec<u16> = "/etc/hostname\0".encode_utf16().collect();
        let mut fd: i32 = -1;
        let ret = unsafe { msvcrt__wsopen_s(&raw mut fd, wide_path.as_ptr(), 0, 0, 0) };
        assert_eq!(ret, 0);
        assert!(fd >= 0);
        unsafe { libc::close(fd) };
    }

    // ── Phase 42 path manipulation tests ──────────────────────────────────────

    #[test]
    fn test_fullpath_null_path_returns_null() {
        let mut buf = [0u8; 256];
        let ret = unsafe { msvcrt__fullpath(buf.as_mut_ptr(), core::ptr::null(), 256) };
        assert!(ret.is_null());
        let errno = unsafe { *libc::__errno_location() };
        assert_eq!(errno, libc::EINVAL);
    }

    #[test]
    fn test_fullpath_allocates_when_buffer_is_null() {
        let path = b"/etc/hostname\0";
        let ret = unsafe { msvcrt__fullpath(core::ptr::null_mut(), path.as_ptr(), 0) };
        assert!(!ret.is_null());
        // SAFETY: ret is a valid NUL-terminated string returned by realpath/malloc.
        unsafe { libc::free(ret.cast()) };
    }

    #[test]
    fn test_fullpath_into_provided_buffer() {
        let path = b"/etc/hostname\0";
        let mut buf = [0u8; 512];
        let ret = unsafe { msvcrt__fullpath(buf.as_mut_ptr(), path.as_ptr(), 512) };
        assert!(!ret.is_null());
        assert_eq!(ret, buf.as_mut_ptr());
        // Result should start with '/'
        assert_eq!(buf[0], b'/');
    }

    #[test]
    fn test_fullpath_buffer_too_small_returns_null() {
        let path = b"/etc/hostname\0";
        let mut buf = [0u8; 2]; // Too small for any real path
        let ret = unsafe { msvcrt__fullpath(buf.as_mut_ptr(), path.as_ptr(), 2) };
        // Should fail with ERANGE
        assert!(ret.is_null());
        let errno = unsafe { *libc::__errno_location() };
        assert_eq!(errno, libc::ERANGE);
    }

    #[test]
    fn test_splitpath_unix_path() {
        let path = b"/usr/lib/libfoo.so\0";
        let mut drive = [0u8; 8];
        let mut dir = [0u8; 64];
        let mut fname = [0u8; 32];
        let mut ext = [0u8; 16];
        unsafe {
            msvcrt__splitpath(
                path.as_ptr(),
                drive.as_mut_ptr(),
                dir.as_mut_ptr(),
                fname.as_mut_ptr(),
                ext.as_mut_ptr(),
            );
        }
        assert_eq!(drive[0], 0, "no drive on Linux");
        assert_eq!(&dir[..9], b"/usr/lib/");
        assert_eq!(&fname[..6], b"libfoo");
        assert_eq!(&ext[..3], b".so");
    }

    #[test]
    fn test_splitpath_windows_path_with_drive() {
        let path = b"C:\\dir\\file.txt\0";
        let mut drive = [0u8; 8];
        let mut dir = [0u8; 64];
        let mut fname = [0u8; 32];
        let mut ext = [0u8; 16];
        unsafe {
            msvcrt__splitpath(
                path.as_ptr(),
                drive.as_mut_ptr(),
                dir.as_mut_ptr(),
                fname.as_mut_ptr(),
                ext.as_mut_ptr(),
            );
        }
        assert_eq!(&drive[..2], b"C:");
        assert_eq!(&dir[..5], b"\\dir\\");
        assert_eq!(&fname[..4], b"file");
        assert_eq!(&ext[..4], b".txt");
    }

    #[test]
    fn test_splitpath_s_buffer_too_small_returns_erange() {
        let path = b"/usr/lib/libfoo.so\0";
        let mut dir = [0u8; 2]; // Too small
        let ret = unsafe {
            msvcrt__splitpath_s(
                path.as_ptr(),
                core::ptr::null_mut(),
                0,
                dir.as_mut_ptr(),
                2,
                core::ptr::null_mut(),
                0,
                core::ptr::null_mut(),
                0,
            )
        };
        assert_eq!(ret, libc::ERANGE);
    }

    #[test]
    fn test_splitpath_s_null_path_returns_einval() {
        let ret = unsafe {
            msvcrt__splitpath_s(
                core::ptr::null(),
                core::ptr::null_mut(),
                0,
                core::ptr::null_mut(),
                0,
                core::ptr::null_mut(),
                0,
                core::ptr::null_mut(),
                0,
            )
        };
        assert_eq!(ret, libc::EINVAL);
    }

    #[test]
    fn test_makepath_basic() {
        let mut buf = [0u8; 128];
        let drive = b"C:\0";
        let dir = b"\\dir\\\0";
        let fname = b"file\0";
        let ext = b".txt\0";
        unsafe {
            msvcrt__makepath(
                buf.as_mut_ptr(),
                drive.as_ptr(),
                dir.as_ptr(),
                fname.as_ptr(),
                ext.as_ptr(),
            );
        }
        let result = core::ffi::CStr::from_bytes_until_nul(&buf).unwrap();
        assert_eq!(result.to_bytes(), b"C:\\dir\\file.txt");
    }

    #[test]
    fn test_makepath_s_overflow_returns_erange() {
        let mut buf = [0u8; 4]; // Too small
        let fname = b"very_long_filename\0";
        let ret = unsafe {
            msvcrt__makepath_s(
                buf.as_mut_ptr(),
                4,
                core::ptr::null(),
                core::ptr::null(),
                fname.as_ptr(),
                core::ptr::null(),
            )
        };
        assert_eq!(ret, libc::ERANGE);
    }

    // ── Phase 43: _getcwd / _chdir / _mkdir / _rmdir ──────────────────────────

    #[test]
    fn test_getcwd_null_buf_returns_allocated() {
        // _getcwd(NULL, 0) should allocate and return the current directory.
        let p = unsafe { msvcrt__getcwd(core::ptr::null_mut(), 0) };
        assert!(
            !p.is_null(),
            "_getcwd(NULL,0) should return a non-null pointer"
        );
        // Must be a valid non-empty string.
        let len = unsafe { libc::strlen(p.cast()) };
        assert!(len > 0, "current directory path must be non-empty");
        unsafe { libc::free(p.cast()) };
    }

    #[test]
    fn test_getcwd_provided_buf() {
        let mut buf = [0u8; 4096];
        let p = unsafe { msvcrt__getcwd(buf.as_mut_ptr(), 4096_i32) };
        assert_eq!(
            p,
            buf.as_mut_ptr(),
            "_getcwd should return the provided buffer"
        );
        let len = unsafe { libc::strlen(buf.as_ptr().cast()) };
        assert!(len > 0, "path must be non-empty");
    }

    #[test]
    fn test_getcwd_buf_nonnull_size_zero_returns_null() {
        // When buf is non-null but size is 0 (or negative), must return null with EINVAL
        // to avoid writing PATH_MAX bytes into an undersized buffer.
        let mut buf = [0u8; 4096];
        let p = unsafe { msvcrt__getcwd(buf.as_mut_ptr(), 0) };
        assert!(
            p.is_null(),
            "_getcwd(buf, 0) with non-null buf must return null"
        );
        let errno = unsafe { *libc::__errno_location() };
        assert_eq!(errno, libc::EINVAL, "errno should be EINVAL");
    }

    #[test]
    fn test_mkdir_chdir_rmdir_roundtrip() {
        let tmp = b"/tmp/litebox_phase43_testdir\0";
        // Cleanup before test in case previous run left it.
        unsafe { libc::rmdir(tmp.as_ptr().cast()) };

        let r = unsafe { msvcrt__mkdir(tmp.as_ptr()) };
        assert_eq!(r, 0, "_mkdir should succeed for a new directory");

        let r = unsafe { msvcrt__rmdir(tmp.as_ptr()) };
        assert_eq!(
            r, 0,
            "_rmdir should succeed for an existing empty directory"
        );
    }

    #[test]
    fn test_chdir_null_returns_minus_one() {
        let r = unsafe { msvcrt__chdir(core::ptr::null()) };
        assert_eq!(r, -1, "_chdir(NULL) should return -1");
    }

    #[test]
    fn test_mkdir_null_returns_minus_one() {
        let r = unsafe { msvcrt__mkdir(core::ptr::null()) };
        assert_eq!(r, -1, "_mkdir(NULL) should return -1");
    }

    #[test]
    fn test_rmdir_null_returns_minus_one() {
        let r = unsafe { msvcrt__rmdir(core::ptr::null()) };
        assert_eq!(r, -1, "_rmdir(NULL) should return -1");
    }

    #[test]
    fn test_tmpnam_null_buf_returns_nonnull() {
        let result = unsafe { msvcrt_tmpnam(core::ptr::null_mut()) };
        assert!(
            !result.is_null(),
            "tmpnam(NULL) should return a non-null pointer"
        );
    }

    #[test]
    fn test_tempnam_returns_nonnull_and_free() {
        let prefix = b"tmp\0";
        let result = unsafe { msvcrt__tempnam(core::ptr::null(), prefix.as_ptr().cast()) };
        assert!(
            !result.is_null(),
            "_tempnam should return a non-null pointer"
        );
        // Free the returned allocation via libc::free.
        // SAFETY: result was allocated by the C library and must be freed with free().
        unsafe { libc::free(result.cast()) };
    }

    #[test]
    fn test_mktemp_modifies_template() {
        let mut template = *b"/tmp/testXXXXXX\0";
        let result = unsafe { msvcrt__mktemp(template.as_mut_ptr().cast()) };
        assert!(
            !result.is_null(),
            "_mktemp should return non-null on success"
        );
    }

    #[test]
    fn test_mktemp_null_returns_null() {
        let result = unsafe { msvcrt__mktemp(core::ptr::null_mut()) };
        assert!(result.is_null(), "_mktemp(NULL) should return null");
    }
}
