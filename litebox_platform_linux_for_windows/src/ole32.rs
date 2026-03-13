// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! ole32.dll COM initialization function implementations
//!
//! Provides minimal stubs for OLE/COM initialization and object-creation APIs.
//! In the headless Windows-on-Linux emulation environment, full COM support is
//! not available; these functions return appropriate "not implemented" results.

// Allow unsafe operations inside unsafe functions
#![allow(unsafe_op_in_unsafe_fn)]
#![allow(clippy::cast_possible_truncation)]

use core::ptr;

// ── COM HRESULT constants ────────────────────────────────────────────────────

/// S_OK — operation succeeded
const S_OK: u32 = 0;
/// E_NOTIMPL — not implemented
const E_NOTIMPL: u32 = 0x8000_4001;
/// E_FAIL — unspecified failure
const E_FAIL: u32 = 0x8000_4005;
/// CO_E_CLASSSTRING — invalid class string
const CO_E_CLASSSTRING: u32 = 0x8004_01F3;
/// REGDB_E_CLASSNOTREG — class not registered
const REGDB_E_CLASSNOTREG: u32 = 0x8004_0154;

// ── ole32: COM lifecycle ─────────────────────────────────────────────────────

/// `CoInitialize(pvReserved) -> HRESULT`
///
/// In headless mode COM is not supported; this is a no-op that returns `S_OK`.
///
/// # Safety
///
/// `pv_reserved` is ignored; any value (including null) is accepted.
///
/// Reference: <https://learn.microsoft.com/en-us/windows/win32/api/objbase/nf-objbase-coinitialize>
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ole32_co_initialize(_pv_reserved: *mut core::ffi::c_void) -> u32 {
    S_OK
}

/// `CoInitializeEx(pvReserved, dwCoInit) -> HRESULT`
///
/// In headless mode COM is not supported; this is a no-op that returns `S_OK`.
///
/// # Safety
///
/// `pv_reserved` is ignored; any value (including null) is accepted.
///
/// Reference: <https://learn.microsoft.com/en-us/windows/win32/api/combaseapi/nf-combaseapi-coinitializeex>
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ole32_co_initialize_ex(
    _pv_reserved: *mut core::ffi::c_void,
    _dw_co_init: u32,
) -> u32 {
    S_OK
}

/// `CoUninitialize() -> void`
///
/// No-op in headless mode.
///
/// # Safety
///
/// Always safe to call.
///
/// Reference: <https://learn.microsoft.com/en-us/windows/win32/api/combaseapi/nf-combaseapi-couninitialize>
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ole32_co_uninitialize() {}

// ── ole32: object creation ───────────────────────────────────────────────────

/// `CoCreateInstance(rclsid, pUnkOuter, dwClsContext, riid, ppv) -> HRESULT`
///
/// Sets `*ppv = NULL` and returns `E_NOTIMPL`; full COM class activation is
/// not supported in headless mode.
///
/// # Safety
///
/// `ppv`, if non-null, must point to a writable `*mut u8`.
///
/// Reference: <https://learn.microsoft.com/en-us/windows/win32/api/combaseapi/nf-combaseapi-cocreateinstance>
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ole32_co_create_instance(
    _rclsid: *const u8,
    _p_unk_outer: *mut u8,
    _dw_cls_context: u32,
    _riid: *const u8,
    ppv: *mut *mut u8,
) -> u32 {
    if !ppv.is_null() {
        *ppv = ptr::null_mut();
    }
    E_NOTIMPL
}

// ── ole32: GUID helpers ──────────────────────────────────────────────────────

/// `CoCreateGuid(pguid) -> HRESULT`
///
/// Fills the 16-byte buffer at `pguid` with random bytes from `/dev/urandom`.
/// Returns `S_OK` on success, `E_FAIL` if the random source cannot be read.
///
/// # Safety
///
/// `pguid` must point to a writable buffer of at least 16 bytes.
///
/// Reference: <https://learn.microsoft.com/en-us/windows/win32/api/combaseapi/nf-combaseapi-cocreateguid>
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ole32_co_create_guid(pguid: *mut u8) -> u32 {
    use std::io::Read;

    if pguid.is_null() {
        return E_FAIL;
    }
    let buf = unsafe { core::slice::from_raw_parts_mut(pguid, 16) };
    let Ok(mut f) = std::fs::File::open("/dev/urandom") else {
        return E_FAIL;
    };
    if f.read_exact(buf).is_err() {
        return E_FAIL;
    }
    S_OK
}

/// `StringFromGUID2(rguid, lpsz, cchMax) -> int`
///
/// Formats the 16-byte GUID at `rguid` as `{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}\0`
/// into the wide-character buffer `lpsz`.  Returns 39 (including the NUL
/// terminator) on success, or 0 if `cch_max < 39` or any pointer is null.
///
/// # Safety
///
/// - `rguid` must point to a readable 16-byte buffer.
/// - `lpsz` must point to a writable buffer of at least `cch_max` `u16` elements.
///
/// Reference: <https://learn.microsoft.com/en-us/windows/win32/api/combaseapi/nf-combaseapi-stringfromguid2>
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ole32_string_from_guid2(
    rguid: *const u8,
    lpsz: *mut u16,
    cch_max: i32,
) -> i32 {
    // The formatted string is 38 chars + NUL = 39 elements.
    const NEEDED: i32 = 39;
    if rguid.is_null() || lpsz.is_null() || cch_max < NEEDED {
        return 0;
    }
    let g = unsafe { core::slice::from_raw_parts(rguid, 16) };
    // GUID wire layout: Data1(4 LE) Data2(2 LE) Data3(2 LE) Data4(8)
    let d1 = u32::from_le_bytes([g[0], g[1], g[2], g[3]]);
    let d2 = u16::from_le_bytes([g[4], g[5]]);
    let d3 = u16::from_le_bytes([g[6], g[7]]);
    // Build the 38-char GUID string and write it into the output buffer.
    let s = format!(
        "{{{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}}}",
        d1, d2, d3, g[8], g[9], g[10], g[11], g[12], g[13], g[14], g[15],
    );
    let out = unsafe { core::slice::from_raw_parts_mut(lpsz, NEEDED as usize) };
    for (i, ch) in s.encode_utf16().enumerate() {
        out[i] = ch;
    }
    out[NEEDED as usize - 1] = 0; // NUL terminator
    NEEDED
}

/// Parse a single hex nibble from a `u16` wide character.
fn parse_hex_nibble(c: u16) -> Option<u8> {
    match c {
        0x30..=0x39 => Some((c - 0x30) as u8),      // '0'..'9'
        0x61..=0x66 => Some((c - 0x61 + 10) as u8), // 'a'..'f'
        0x41..=0x46 => Some((c - 0x41 + 10) as u8), // 'A'..'F'
        _ => None,
    }
}

/// Parse two consecutive hex wide characters into one byte.
fn parse_hex_byte(hi: u16, lo: u16) -> Option<u8> {
    Some((parse_hex_nibble(hi)? << 4) | parse_hex_nibble(lo)?)
}

/// `CLSIDFromString(lpsz, pclsid) -> HRESULT`
///
/// Parses a GUID string of the braced form `{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}`
/// or the unbraced form `XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX`
/// into the 16-byte buffer at `pclsid`.  Returns `S_OK` on success or
/// `CO_E_CLASSSTRING` if the string is invalid.
///
/// # Safety
///
/// - `lpsz` must point to a valid null-terminated wide string.
/// - `pclsid` must point to a writable buffer of at least 16 bytes.
///
/// Reference: <https://learn.microsoft.com/en-us/windows/win32/api/combaseapi/nf-combaseapi-clsidfromstring>
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ole32_clsid_from_string(lpsz: *const u16, pclsid: *mut u8) -> u32 {
    if lpsz.is_null() || pclsid.is_null() {
        return CO_E_CLASSSTRING;
    }
    // Collect the wide string into a fixed-size buffer.
    // Supported formats:
    //   Braced:   {XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}  (38 chars)
    //   Unbraced:  XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX   (36 chars)
    let mut chars = [0u16; 40];
    let mut len = 0usize;
    let mut p = lpsz;
    loop {
        let ch = unsafe { *p };
        if ch == 0 {
            break;
        }
        if len >= 40 {
            return CO_E_CLASSSTRING;
        }
        chars[len] = ch;
        len += 1;
        p = unsafe { p.add(1) };
    }

    // Determine whether we have the braced or unbraced form and set the
    // offset of the first hex digit within `chars`.
    let (hex_start, dash_offsets) =
        if len == 38 && chars[0] == u16::from(b'{') && chars[37] == u16::from(b'}') {
            // Braced form: dashes at positions 9, 14, 19, 24 (relative to chars[0])
            (1usize, [9usize, 14, 19, 24])
        } else if len == 36 {
            // Unbraced form: dashes at positions 8, 13, 18, 23 (relative to chars[0])
            (0usize, [8usize, 13, 18, 23])
        } else {
            return CO_E_CLASSSTRING;
        };

    // Verify dash positions.
    for &d in &dash_offsets {
        if chars[d] != u16::from(b'-') {
            return CO_E_CLASSSTRING;
        }
    }

    // Helper closure: parse `count` bytes from `chars[off..]`.
    let mut out = [0u8; 16];
    let mut write_idx = 0usize;
    // Positions of hex pairs within the string (after optional `{`):
    // Data1: 4 bytes, big-endian printed as LE u32
    // Data2: 2 bytes, LE u16
    // Data3: 2 bytes, LE u16
    // Data4: 8 bytes
    macro_rules! parse_bytes {
        ($start:expr, $count:expr, $le:expr) => {{
            let mut tmp = [0u8; 8];
            for i in 0..$count {
                let Some(b) = parse_hex_byte(chars[$start + i * 2], chars[$start + i * 2 + 1])
                else {
                    return CO_E_CLASSSTRING;
                };
                tmp[i] = b;
            }
            if $le {
                // Bytes were parsed big-endian; reverse for little-endian storage.
                tmp[0..$count].reverse();
            }
            for i in 0..$count {
                out[write_idx] = tmp[i];
                write_idx += 1;
            }
        }};
    }
    let s = hex_start;
    parse_bytes!(s, 4, true); // Data1 (4 bytes, stored LE)
    parse_bytes!(s + 9, 2, true); // Data2 (2 bytes, stored LE)
    parse_bytes!(s + 14, 2, true); // Data3 (2 bytes, stored LE)
    parse_bytes!(s + 19, 2, false); // Data4[0..2]
    parse_bytes!(s + 24, 6, false); // Data4[2..8]

    // SAFETY: Caller guarantees pclsid points to a 16-byte writable buffer.
    unsafe { core::ptr::copy_nonoverlapping(out.as_ptr(), pclsid, 16) };
    S_OK
}

// ── ole32: task memory (delegates to libc so realloc works correctly) ────────

/// `CoTaskMemAlloc(cb) -> *mut c_void`
///
/// Allocates `cb` bytes using `libc::malloc`.  Returns null if `cb` is zero.
///
/// # Safety
///
/// The returned pointer must be freed with `CoTaskMemFree` / `ole32_co_task_mem_free`.
///
/// Reference: <https://learn.microsoft.com/en-us/windows/win32/api/combaseapi/nf-combaseapi-cotaskmemalloc>
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ole32_co_task_mem_alloc(cb: usize) -> *mut core::ffi::c_void {
    if cb == 0 {
        return ptr::null_mut();
    }
    // SAFETY: `libc::malloc` is safe to call with any non-zero size.
    unsafe { libc::malloc(cb) }
}

/// `CoTaskMemFree(pv) -> void`
///
/// Frees memory previously allocated with `CoTaskMemAlloc`.
///
/// # Safety
///
/// `pv` must be a pointer returned by `ole32_co_task_mem_alloc` / `libc::malloc`,
/// or null (in which case this is a no-op).
///
/// Reference: <https://learn.microsoft.com/en-us/windows/win32/api/combaseapi/nf-combaseapi-cotaskmemfree>
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ole32_co_task_mem_free(pv: *mut core::ffi::c_void) {
    if !pv.is_null() {
        // SAFETY: Caller guarantees `pv` came from `libc::malloc`.
        unsafe { libc::free(pv) };
    }
}

/// `CoTaskMemRealloc(pv, cb) -> *mut c_void`
///
/// Reallocates the block at `pv` to `cb` bytes.  If `pv` is null, behaves
/// like `CoTaskMemAlloc`.  If `cb` is zero, frees `pv` and returns null.
///
/// # Safety
///
/// `pv` must be a pointer returned by `ole32_co_task_mem_alloc` /
/// `ole32_co_task_mem_realloc`, or null.
///
/// Reference: <https://learn.microsoft.com/en-us/windows/win32/api/combaseapi/nf-combaseapi-cotaskmemrealloc>
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ole32_co_task_mem_realloc(
    pv: *mut core::ffi::c_void,
    cb: usize,
) -> *mut core::ffi::c_void {
    if pv.is_null() {
        return ole32_co_task_mem_alloc(cb);
    }
    if cb == 0 {
        // SAFETY: `pv` is non-null and was allocated by libc::malloc.
        unsafe { libc::free(pv) };
        return ptr::null_mut();
    }
    // SAFETY: `pv` is non-null and was allocated by libc::malloc; `cb` > 0.
    unsafe { libc::realloc(pv, cb) }
}

// ── ole32: class object ──────────────────────────────────────────────────────

/// `CoGetClassObject(rclsid, dwClsContext, pServerInfo, riid, ppv) -> HRESULT`
///
/// Returns `REGDB_E_CLASSNOTREG`; no COM server registry is available in
/// headless mode.
///
/// # Safety
///
/// `ppv`, if non-null, must point to a writable `*mut u8`.
///
/// Reference: <https://learn.microsoft.com/en-us/windows/win32/api/combaseapi/nf-combaseapi-cogetclassobject>
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ole32_co_get_class_object(
    _rclsid: *const u8,
    _dw_cls_context: u32,
    _p_server_info: *mut u8,
    _riid: *const u8,
    ppv: *mut *mut u8,
) -> u32 {
    if !ppv.is_null() {
        *ppv = ptr::null_mut();
    }
    REGDB_E_CLASSNOTREG
}

/// `CoSetProxyBlanket(...) -> HRESULT`
///
/// Returns `E_NOTIMPL`; proxy security configuration is not supported in
/// headless mode.
///
/// # Safety
///
/// All pointer arguments are ignored.
///
/// Reference: <https://learn.microsoft.com/en-us/windows/win32/api/combaseapi/nf-combaseapi-cosetproxyblanket>
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ole32_co_set_proxy_blanket(
    _p_proxy: *mut u8,
    _dw_authn_svc: u32,
    _dw_authz_svc: u32,
    _p_server_princ_name: *mut u16,
    _dw_authn_level: u32,
    _dw_imp_level: u32,
    _p_auth_info: *mut u8,
    _dw_capabilities: u32,
) -> u32 {
    E_NOTIMPL
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_co_initialize_returns_s_ok() {
        unsafe { assert_eq!(ole32_co_initialize(ptr::null_mut()), S_OK) }
    }

    #[test]
    fn test_co_initialize_ex_returns_s_ok() {
        unsafe { assert_eq!(ole32_co_initialize_ex(ptr::null_mut(), 0), S_OK) }
    }

    #[test]
    fn test_co_uninitialize_is_noop() {
        unsafe { ole32_co_uninitialize() }
    }

    #[test]
    fn test_co_create_instance_returns_e_notimpl() {
        unsafe {
            let mut ppv: *mut u8 = ptr::null_mut();
            assert_eq!(
                ole32_co_create_instance(
                    ptr::null(),
                    ptr::null_mut(),
                    0,
                    ptr::null(),
                    &raw mut ppv
                ),
                E_NOTIMPL
            );
            assert!(ppv.is_null());
        }
    }

    #[test]
    fn test_co_create_guid() {
        unsafe {
            let mut guid = [0u8; 16];
            let r = ole32_co_create_guid(guid.as_mut_ptr());
            assert_eq!(r, S_OK);
            // guid should be filled with some data (not guaranteed non-zero, but very likely)
        }
    }

    #[test]
    fn test_string_from_guid2() {
        unsafe {
            let guid = [
                0x12u8, 0x34, 0x56, 0x78, 0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB,
                0xCD, 0xEF, 0x01,
            ];
            let mut buf = [0u16; 40];
            let n = ole32_string_from_guid2(guid.as_ptr(), buf.as_mut_ptr(), 40);
            assert_eq!(n, 39);
            // Verify it starts with '{' and ends with '}'
            assert_eq!(buf[0], u16::from(b'{'));
            assert_eq!(buf[37], u16::from(b'}'));
            assert_eq!(buf[38], 0); // NUL terminator
        }
    }

    #[test]
    fn test_string_from_guid2_too_small() {
        unsafe {
            let guid = [0u8; 16];
            let mut buf = [0u16; 10];
            let n = ole32_string_from_guid2(guid.as_ptr(), buf.as_mut_ptr(), 10);
            assert_eq!(n, 0);
        }
    }

    #[test]
    fn test_co_task_mem_alloc_free() {
        unsafe {
            let p = ole32_co_task_mem_alloc(64);
            assert!(!p.is_null());
            ole32_co_task_mem_free(p);
        }
    }

    #[test]
    fn test_co_task_mem_alloc_zero() {
        unsafe {
            let p = ole32_co_task_mem_alloc(0);
            assert!(p.is_null());
        }
    }

    #[test]
    fn test_co_task_mem_realloc() {
        unsafe {
            let p = ole32_co_task_mem_alloc(32);
            assert!(!p.is_null());
            let p2 = ole32_co_task_mem_realloc(p, 64);
            assert!(!p2.is_null());
            ole32_co_task_mem_free(p2);
        }
    }

    #[test]
    fn test_co_task_mem_realloc_null_src() {
        unsafe {
            let p = ole32_co_task_mem_realloc(ptr::null_mut(), 32);
            assert!(!p.is_null());
            ole32_co_task_mem_free(p);
        }
    }

    #[test]
    fn test_co_task_mem_realloc_zero_size() {
        unsafe {
            let p = ole32_co_task_mem_alloc(32);
            assert!(!p.is_null());
            let p2 = ole32_co_task_mem_realloc(p, 0);
            assert!(p2.is_null());
        }
    }

    #[test]
    fn test_co_get_class_object() {
        unsafe {
            let mut ppv: *mut u8 = ptr::null_mut();
            let r = ole32_co_get_class_object(
                ptr::null(),
                0,
                ptr::null_mut(),
                ptr::null(),
                &raw mut ppv,
            );
            assert_eq!(r, REGDB_E_CLASSNOTREG);
            assert!(ppv.is_null());
        }
    }

    #[test]
    fn test_co_set_proxy_blanket_returns_e_notimpl() {
        unsafe {
            let r = ole32_co_set_proxy_blanket(
                ptr::null_mut(),
                0,
                0,
                ptr::null_mut(),
                0,
                0,
                ptr::null_mut(),
                0,
            );
            assert_eq!(r, E_NOTIMPL);
        }
    }

    #[test]
    fn test_string_from_guid2_null_pointers() {
        unsafe {
            let guid = [0u8; 16];
            let mut buf = [0u16; 40];
            assert_eq!(
                ole32_string_from_guid2(ptr::null(), buf.as_mut_ptr(), 40),
                0
            );
            assert_eq!(
                ole32_string_from_guid2(guid.as_ptr(), ptr::null_mut(), 40),
                0
            );
        }
    }

    #[test]
    fn test_clsid_from_string_valid() {
        unsafe {
            // Encode "{78563412-CDAB-01EF-2345-6789ABCDEF01}" as UTF-16
            let s = "{78563412-CDAB-01EF-2345-6789ABCDEF01}";
            let wide: Vec<u16> = s.encode_utf16().chain(Some(0)).collect();
            let mut clsid = [0u8; 16];
            let r = ole32_clsid_from_string(wide.as_ptr(), clsid.as_mut_ptr());
            assert_eq!(r, S_OK);
            // Data1 = 0x78563412 stored LE → bytes [0x12, 0x34, 0x56, 0x78]
            assert_eq!(&clsid[0..4], &[0x12u8, 0x34, 0x56, 0x78]);
        }
    }

    #[test]
    fn test_clsid_from_string_unbraced() {
        unsafe {
            // Windows also accepts the unbraced 36-character form.
            let s = "78563412-CDAB-01EF-2345-6789ABCDEF01";
            let wide: Vec<u16> = s.encode_utf16().chain(Some(0)).collect();
            let mut clsid = [0u8; 16];
            let r = ole32_clsid_from_string(wide.as_ptr(), clsid.as_mut_ptr());
            assert_eq!(r, S_OK);
            // Data1 = 0x78563412 stored LE → bytes [0x12, 0x34, 0x56, 0x78]
            assert_eq!(&clsid[0..4], &[0x12u8, 0x34, 0x56, 0x78]);
        }
    }

    #[test]
    fn test_clsid_from_string_invalid() {
        unsafe {
            let s = "not-a-guid";
            let wide: Vec<u16> = s.encode_utf16().chain(Some(0)).collect();
            let mut clsid = [0u8; 16];
            let r = ole32_clsid_from_string(wide.as_ptr(), clsid.as_mut_ptr());
            assert_eq!(r, CO_E_CLASSSTRING);
        }
    }
}
