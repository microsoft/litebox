// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! ADVAPI32.dll function implementations — Windows Registry
//!
//! This module provides a lightweight in-process Windows Registry emulation
//! backed by an in-memory `HashMap`. All data is kept in process memory for
//! the lifetime of the program; no file-backed persistence is attempted here.
//!
//! Supported APIs:
//! - `RegOpenKeyExW`    — open an existing key (or pre-defined root HKEY)
//! - `RegCreateKeyExW`  — open or create a key
//! - `RegCloseKey`      — release a key handle
//! - `RegQueryValueExW` — read a named value
//! - `RegSetValueExW`   — write a named value
//! - `RegDeleteValueW`  — delete a named value
//! - `RegEnumKeyExW`    — enumerate sub-key names
//! - `RegEnumValueW`    — enumerate value names

// Allow unsafe operations inside unsafe functions
#![allow(unsafe_op_in_unsafe_fn)]
// Allow cast warnings: we're implementing Windows APIs which use specific integer types
#![allow(clippy::cast_possible_truncation)]

use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use libc;

// ── Windows registry error / status codes ─────────────────────────────────────

/// Operation succeeded
const ERROR_SUCCESS: u32 = 0;
/// The system cannot find the file specified
const ERROR_FILE_NOT_FOUND: u32 = 2;
/// The handle is invalid
const ERROR_INVALID_HANDLE: u32 = 6;
/// More data is available
const ERROR_MORE_DATA: u32 = 234;
/// No more items
const ERROR_NO_MORE_ITEMS: u32 = 259;

// ── Registry value types ──────────────────────────────────────────────────────

/// Registry value type: null
const REG_NONE: u32 = 0;
/// Registry value type: Unicode string (null-terminated)
const REG_SZ: u32 = 1;
/// Registry value type: Unicode string with unexpanded references to environment variables
const REG_EXPAND_SZ: u32 = 2;
/// Registry value type: binary data in any form
const REG_BINARY: u32 = 3;
/// Registry value type: 32-bit little-endian number
const REG_DWORD: u32 = 4;
/// Registry value type: 64-bit little-endian number
const REG_QWORD: u32 = 11;

// ── Pre-defined HKEY values ───────────────────────────────────────────────────
//
// Windows defines predefined HKEYs via sign-extension from 32-bit LONG values:
//   #define HKEY_CURRENT_USER ((HKEY)(ULONG_PTR)((LONG)0x80000001))
// On 64-bit Windows, (LONG)0x80000001 sign-extends to 0xFFFF_FFFF_8000_0001.
// We must use these 64-bit forms so that values received from Windows PE code
// (which passes the sign-extended pointer-sized constant) match our checks.

/// HKEY_CLASSES_ROOT
const HKEY_CLASSES_ROOT: usize = 0xFFFF_FFFF_8000_0000;
/// HKEY_CURRENT_USER
const HKEY_CURRENT_USER: usize = 0xFFFF_FFFF_8000_0001;
/// HKEY_LOCAL_MACHINE
const HKEY_LOCAL_MACHINE: usize = 0xFFFF_FFFF_8000_0002;
/// HKEY_USERS
const HKEY_USERS: usize = 0xFFFF_FFFF_8000_0003;
/// HKEY_CURRENT_CONFIG
const HKEY_CURRENT_CONFIG: usize = 0xFFFF_FFFF_8000_0005;

// Base offset for dynamically allocated HKEY handles
const HKEY_HANDLE_BASE: usize = 0x0100_0000;

// ── Registry value storage ────────────────────────────────────────────────────

/// Typed registry value
#[derive(Clone)]
enum RegValue {
    /// REG_SZ / REG_EXPAND_SZ — stored as UTF-8
    String { data: String, expand: bool },
    /// REG_BINARY — stored as raw bytes
    Binary(Vec<u8>),
    /// REG_DWORD
    Dword(u32),
    /// REG_QWORD
    Qword(u64),
    /// REG_NONE — stored as raw bytes
    None(Vec<u8>),
}

impl RegValue {
    /// Return the Windows registry type constant for this value
    fn reg_type(&self) -> u32 {
        match self {
            RegValue::String { expand: false, .. } => REG_SZ,
            RegValue::String { expand: true, .. } => REG_EXPAND_SZ,
            RegValue::Binary(_) => REG_BINARY,
            RegValue::Dword(_) => REG_DWORD,
            RegValue::Qword(_) => REG_QWORD,
            RegValue::None(_) => REG_NONE,
        }
    }

    /// Serialise the value into a Windows-format byte buffer.
    ///
    /// For `REG_SZ` / `REG_EXPAND_SZ` this is the UTF-16LE encoding of the
    /// string including the null terminator.
    fn to_bytes(&self) -> Vec<u8> {
        match self {
            RegValue::String { data, .. } => {
                let mut utf16: Vec<u16> = data.encode_utf16().collect();
                utf16.push(0); // null terminator
                utf16.iter().flat_map(|c| c.to_le_bytes()).collect()
            }
            RegValue::Binary(b) | RegValue::None(b) => b.clone(),
            RegValue::Dword(d) => d.to_le_bytes().to_vec(),
            RegValue::Qword(q) => q.to_le_bytes().to_vec(),
        }
    }
}

// ── Registry key storage ──────────────────────────────────────────────────────

/// A single registry key node
struct RegKey {
    /// Named values stored in this key
    values: HashMap<String, RegValue>, // lower-case name -> value
    /// Display names of values (for enumeration)
    value_names: Vec<String>,
    /// Display names of child keys (for enumeration)
    child_names: Vec<String>,
}

impl RegKey {
    fn new() -> Self {
        Self {
            values: HashMap::new(),
            value_names: Vec::new(),
            child_names: Vec::new(),
        }
    }
}

// ── Global registry state ─────────────────────────────────────────────────────

/// The in-process registry store.
/// Keys are stored as fully-qualified paths (e.g. "HKCU\\Software\\Example").
static REGISTRY: Mutex<Option<HashMap<String, RegKey>>> = Mutex::new(None);

/// Counter for allocating HKEY handles
static HKEY_COUNTER: AtomicUsize = AtomicUsize::new(HKEY_HANDLE_BASE);

/// Maps dynamically allocated HKEY handles to full key paths
static HKEY_HANDLES: Mutex<Option<HashMap<usize, String>>> = Mutex::new(None);

// ── Helper functions ──────────────────────────────────────────────────────────

fn with_registry<R>(f: impl FnOnce(&mut HashMap<String, RegKey>) -> R) -> R {
    let mut guard = REGISTRY.lock().unwrap();
    let registry = guard.get_or_insert_with(HashMap::new);
    f(registry)
}

fn with_hkey_handles<R>(f: impl FnOnce(&mut HashMap<usize, String>) -> R) -> R {
    let mut guard = HKEY_HANDLES.lock().unwrap();
    let handles = guard.get_or_insert_with(HashMap::new);
    f(handles)
}

/// Allocate a new HKEY handle value (not backed by a key yet)
fn alloc_hkey() -> usize {
    HKEY_COUNTER.fetch_add(1, Ordering::Relaxed)
}

/// Convert a pre-defined root HKEY constant to a canonical root-key string.
///
/// The returned strings are lower-case to match the case-insensitive storage
/// convention used throughout the registry implementation.
fn root_hkey_to_path(hkey: usize) -> Option<String> {
    match hkey {
        HKEY_CLASSES_ROOT => Some("hkcr".to_string()),
        HKEY_CURRENT_USER => Some("hkcu".to_string()),
        HKEY_LOCAL_MACHINE => Some("hklm".to_string()),
        HKEY_USERS => Some("hku".to_string()),
        HKEY_CURRENT_CONFIG => Some("hkcc".to_string()),
        _ => None,
    }
}

/// Resolve an HKEY handle to its full key path.
///
/// Returns `None` if the handle is invalid.
fn hkey_to_path(hkey: usize) -> Option<String> {
    // First check pre-defined root keys
    if let Some(root) = root_hkey_to_path(hkey) {
        return Some(root);
    }
    // Then look in the dynamic handle map
    with_hkey_handles(|handles| handles.get(&hkey).cloned())
}

/// Build the full registry path by joining parent path and sub-key name.
///
/// Both the parent and sub-key are lower-cased so that all look-ups are
/// case-insensitive, matching Windows Registry semantics.
fn join_path(parent: &str, subkey: &str) -> String {
    if subkey.is_empty() {
        parent.to_lowercase()
    } else {
        format!("{}\\{}", parent.to_lowercase(), subkey.to_lowercase())
    }
}

// ── Wide-string helper (local copy to avoid cross-module coupling) ─────────────

/// Convert a null-terminated UTF-16 pointer to a `String`.
///
/// # Safety
/// `ptr` must be either null or a valid, non-dangling pointer to a
/// null-terminated UTF-16 string. Reads up to 32 768 code units.
unsafe fn wide_to_string(ptr: *const u16) -> String {
    if ptr.is_null() {
        return String::new();
    }
    let mut len = 0usize;
    // SAFETY: Caller guarantees `ptr` is a valid null-terminated UTF-16 string.
    while len < 32_768 && *ptr.add(len) != 0 {
        len += 1;
    }
    let slice = std::slice::from_raw_parts(ptr, len);
    String::from_utf16_lossy(slice)
}

/// Write a UTF-8 string back into a caller-supplied UTF-16 buffer.
///
/// Returns the number of code units written (excluding null terminator) on
/// success, or the required size (including null terminator) when the buffer is
/// too small.  Writes the null terminator when there is room.
///
/// # Safety
/// `buf` must point to a valid writable buffer of at least `buf_len` `u16`
/// elements, or be null.
unsafe fn copy_string_to_wide(value: &str, buf: *mut u16, buf_len: u32) -> (u32, u32) {
    let utf16: Vec<u16> = value.encode_utf16().collect();
    let required = utf16.len() as u32 + 1; // includes null terminator
    if buf.is_null() || buf_len == 0 {
        return (ERROR_MORE_DATA, required);
    }
    if buf_len < required {
        return (ERROR_MORE_DATA, required);
    }
    for (i, &ch) in utf16.iter().enumerate() {
        // SAFETY: buf_len >= required, so index i is within bounds.
        *buf.add(i) = ch;
    }
    // SAFETY: utf16.len() < required <= buf_len.
    *buf.add(utf16.len()) = 0;
    (ERROR_SUCCESS, utf16.len() as u32)
}

/// Decode a raw UTF-16LE byte buffer (as stored in `REG_SZ`/`REG_EXPAND_SZ`) into a
/// Rust `String`, stripping a trailing null code unit if present.
fn decode_reg_sz_bytes(raw: &[u8]) -> String {
    let code_units: Vec<u16> = raw
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    // Strip a single trailing null terminator if present
    let slice = code_units
        .split_last()
        .map_or(code_units.as_slice(), |(last, rest)| {
            if *last == 0 { rest } else { &code_units }
        });
    String::from_utf16_lossy(slice)
}

// ── API implementations ───────────────────────────────────────────────────────

/// `RegOpenKeyExW` — open an existing registry key.
///
/// Opens the sub-key `lp_sub_key` under `h_key`. If `lp_sub_key` is null or
/// empty, the key itself is re-opened. Returns `ERROR_FILE_NOT_FOUND` if the
/// key does not exist.
///
/// # Safety
/// `lp_sub_key` must be a valid null-terminated UTF-16 string or null.
/// `phk_result` must be a valid writable pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn advapi32_RegOpenKeyExW(
    h_key: usize,
    lp_sub_key: *const u16,
    _ul_options: u32,
    _sam_desired: u32,
    phk_result: *mut usize,
) -> u32 {
    if phk_result.is_null() {
        return ERROR_INVALID_HANDLE;
    }
    let Some(parent_path) = hkey_to_path(h_key) else {
        return ERROR_INVALID_HANDLE;
    };
    let subkey = wide_to_string(lp_sub_key);
    let full_path = join_path(&parent_path, &subkey);

    // A root HKEY with no sub-key is always considered to exist.
    let is_root = root_hkey_to_path(h_key).is_some() && subkey.is_empty();
    let exists = is_root || with_registry(|reg| reg.contains_key(&full_path));
    if !exists {
        return ERROR_FILE_NOT_FOUND;
    }

    let handle = alloc_hkey();
    with_hkey_handles(|handles| {
        handles.insert(handle, full_path);
    });
    // SAFETY: phk_result is non-null (checked above).
    *phk_result = handle;
    ERROR_SUCCESS
}

/// `RegCreateKeyExW` — open or create a registry key.
///
/// Opens `lp_sub_key` under `h_key`, creating the key if it does not already
/// exist. When a new key is created, the immediate parent's `child_names` list
/// is updated so that `RegEnumKeyExW` can enumerate it. Always succeeds.
///
/// # Safety
/// `lp_sub_key` must be a valid null-terminated UTF-16 string or null.
/// `phk_result` must be a valid writable pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn advapi32_RegCreateKeyExW(
    h_key: usize,
    lp_sub_key: *const u16,
    _reserved: u32,
    _lp_class: *mut u16,
    _dw_options: u32,
    _sam_desired: u32,
    _lp_security_attributes: *const u8,
    phk_result: *mut usize,
    lp_disposition: *mut u32,
) -> u32 {
    if phk_result.is_null() {
        return ERROR_INVALID_HANDLE;
    }
    let Some(parent_path) = hkey_to_path(h_key) else {
        return ERROR_INVALID_HANDLE;
    };
    let subkey = wide_to_string(lp_sub_key);
    let full_path = join_path(&parent_path, &subkey);

    // REG_OPENED_EXISTING_KEY = 2, REG_CREATED_NEW_KEY = 1
    let existed = with_registry(|reg| {
        if reg.contains_key(&full_path) {
            true
        } else {
            reg.insert(full_path.clone(), RegKey::new());
            // Update the immediate parent's child_names so RegEnumKeyExW can
            // enumerate the new key.  The immediate parent is derived from
            // full_path by stripping the last path component (not from `h_key`,
            // which may be several levels above when multi-component subkeys are
            // used).  If the immediate parent is not yet in the registry (e.g. the
            // caller skipped intermediate keys) we skip the update silently.
            if let Some(sep) = full_path.rfind('\\') {
                let imm_parent = &full_path[..sep];
                let child_name = &full_path[sep + 1..];
                if let Some(parent_key) = reg.get_mut(imm_parent) {
                    parent_key.child_names.push(child_name.to_string());
                }
            }
            false
        }
    });

    if !lp_disposition.is_null() {
        // SAFETY: lp_disposition is non-null (checked above).
        *lp_disposition = if existed { 2 } else { 1 };
    }

    let handle = alloc_hkey();
    with_hkey_handles(|handles| {
        handles.insert(handle, full_path);
    });
    // SAFETY: phk_result is non-null (checked above).
    *phk_result = handle;
    ERROR_SUCCESS
}

/// `RegCloseKey` — release a key handle.
///
/// Removes the handle from the internal table. Always returns `ERROR_SUCCESS`.
///
/// # Safety
/// `h_key` should be a handle previously returned by `RegOpenKeyExW` or
/// `RegCreateKeyExW`, or one of the pre-defined root HKEYs (which are silently
/// ignored).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn advapi32_RegCloseKey(h_key: usize) -> u32 {
    // Pre-defined root keys don't need cleanup
    if root_hkey_to_path(h_key).is_some() {
        return ERROR_SUCCESS;
    }
    with_hkey_handles(|handles| {
        handles.remove(&h_key);
    });
    ERROR_SUCCESS
}

/// `RegQueryValueExW` — retrieve the type and data for a named registry value.
///
/// Returns the value associated with `lp_value_name` in the key identified by
/// `h_key`. If `lp_data` is null, only the type and required size are
/// returned. Returns `ERROR_MORE_DATA` if the provided buffer is too small.
///
/// # Safety
/// All pointer parameters must be valid or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn advapi32_RegQueryValueExW(
    h_key: usize,
    lp_value_name: *const u16,
    _lp_reserved: *mut u32,
    lp_type: *mut u32,
    lp_data: *mut u8,
    lpcb_data: *mut u32,
) -> u32 {
    let Some(key_path) = hkey_to_path(h_key) else {
        return ERROR_INVALID_HANDLE;
    };
    let value_name = wide_to_string(lp_value_name).to_lowercase();

    let result = with_registry(|reg| {
        let key = reg.get(&key_path)?;
        key.values.get(&value_name).cloned()
    });

    let Some(val) = result else {
        return ERROR_FILE_NOT_FOUND;
    };

    let bytes = val.to_bytes();
    let required = bytes.len() as u32;

    if !lp_type.is_null() {
        // SAFETY: lp_type is non-null.
        *lp_type = val.reg_type();
    }
    if lpcb_data.is_null() {
        // lpcb_data is null — only type query (no data written)
        return ERROR_SUCCESS;
    }
    let provided = *lpcb_data;
    // SAFETY: lpcb_data is non-null.
    *lpcb_data = required;
    if lp_data.is_null() {
        return ERROR_SUCCESS;
    }
    if provided < required {
        return ERROR_MORE_DATA;
    }
    // SAFETY: lp_data points to a buffer of at least `provided` bytes.
    std::ptr::copy_nonoverlapping(bytes.as_ptr(), lp_data, bytes.len());
    ERROR_SUCCESS
}

/// `RegSetValueExW` — set the data and type for a named registry value.
///
/// Stores the value `lp_value_name` in the key identified by `h_key`.
/// Creates the value if it does not exist; overwrites it if it does.
///
/// # Safety
/// All pointer parameters must be valid or null according to the Windows API
/// contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn advapi32_RegSetValueExW(
    h_key: usize,
    lp_value_name: *const u16,
    _reserved: u32,
    dw_type: u32,
    lp_data: *const u8,
    cb_data: u32,
) -> u32 {
    let Some(key_path) = hkey_to_path(h_key) else {
        return ERROR_INVALID_HANDLE;
    };
    let display_name = wide_to_string(lp_value_name);
    let value_name_key = display_name.to_lowercase();

    // Build the typed value from the raw bytes
    let data_len = cb_data as usize;
    // SAFETY: lp_data must be valid for `data_len` bytes per the Windows API contract.
    let raw_bytes: Vec<u8> = if lp_data.is_null() || data_len == 0 {
        Vec::new()
    } else {
        std::slice::from_raw_parts(lp_data, data_len).to_vec()
    };

    let reg_value = match dw_type {
        REG_SZ | REG_EXPAND_SZ => {
            // Decode UTF-16LE bytes to a String, stripping the null terminator if present
            let s = decode_reg_sz_bytes(&raw_bytes);
            RegValue::String {
                data: s,
                expand: dw_type == REG_EXPAND_SZ,
            }
        }
        REG_DWORD => {
            let val = if raw_bytes.len() >= 4 {
                u32::from_le_bytes([raw_bytes[0], raw_bytes[1], raw_bytes[2], raw_bytes[3]])
            } else {
                0
            };
            RegValue::Dword(val)
        }
        REG_QWORD => {
            let val = if raw_bytes.len() >= 8 {
                u64::from_le_bytes([
                    raw_bytes[0],
                    raw_bytes[1],
                    raw_bytes[2],
                    raw_bytes[3],
                    raw_bytes[4],
                    raw_bytes[5],
                    raw_bytes[6],
                    raw_bytes[7],
                ])
            } else {
                0
            };
            RegValue::Qword(val)
        }
        REG_NONE => RegValue::None(raw_bytes),
        _ => RegValue::Binary(raw_bytes),
    };

    with_registry(|reg| {
        // Auto-create the key if it doesn't exist (mirrors Windows behaviour)
        let key = reg.entry(key_path).or_insert_with(RegKey::new);
        if !key.values.contains_key(&value_name_key) {
            key.value_names.push(display_name.clone());
        }
        key.values.insert(value_name_key, reg_value);
    });
    ERROR_SUCCESS
}

/// `RegDeleteValueW` — remove a named value from a registry key.
///
/// Returns `ERROR_FILE_NOT_FOUND` if the value does not exist.
///
/// # Safety
/// `lp_value_name` must be a valid null-terminated UTF-16 string or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn advapi32_RegDeleteValueW(h_key: usize, lp_value_name: *const u16) -> u32 {
    let Some(key_path) = hkey_to_path(h_key) else {
        return ERROR_INVALID_HANDLE;
    };
    let value_name_key = wide_to_string(lp_value_name).to_lowercase();

    let removed = with_registry(|reg| {
        let Some(key) = reg.get_mut(&key_path) else {
            return false;
        };
        if key.values.remove(&value_name_key).is_some() {
            key.value_names
                .retain(|n| n.to_lowercase() != value_name_key);
            true
        } else {
            false
        }
    });

    if removed {
        ERROR_SUCCESS
    } else {
        ERROR_FILE_NOT_FOUND
    }
}

/// `RegEnumKeyExW` — enumerate the sub-keys of an open registry key.
///
/// `dw_index` is the zero-based index of the sub-key to retrieve.
/// Returns `ERROR_NO_MORE_ITEMS` when `dw_index` is out of range.
///
/// # Safety
/// All pointer parameters must be valid or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn advapi32_RegEnumKeyExW(
    h_key: usize,
    dw_index: u32,
    lp_name: *mut u16,
    lpcch_name: *mut u32,
    _lp_reserved: *mut u32,
    _lp_class: *mut u16,
    _lpcch_class: *mut u32,
    _lpft_last_write_time: *mut u64,
) -> u32 {
    if lp_name.is_null() || lpcch_name.is_null() {
        return ERROR_INVALID_HANDLE;
    }
    let Some(key_path) = hkey_to_path(h_key) else {
        return ERROR_INVALID_HANDLE;
    };

    let child_name = with_registry(|reg| {
        reg.get(&key_path)
            .and_then(|k| k.child_names.get(dw_index as usize).cloned())
    });

    let Some(name) = child_name else {
        return ERROR_NO_MORE_ITEMS;
    };

    // SAFETY: lp_name and lpcch_name are non-null (checked above).
    let buf_len = *lpcch_name;
    let (status, written) = copy_string_to_wide(&name, lp_name, buf_len);
    *lpcch_name = written;
    status
}

/// `RegEnumValueW` — enumerate the values of an open registry key.
///
/// `dw_index` is the zero-based index of the value to retrieve.
/// Returns `ERROR_NO_MORE_ITEMS` when `dw_index` is out of range.
///
/// # Safety
/// All pointer parameters must be valid or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn advapi32_RegEnumValueW(
    h_key: usize,
    dw_index: u32,
    lp_value_name: *mut u16,
    lpcch_value_name: *mut u32,
    _lp_reserved: *mut u32,
    lp_type: *mut u32,
    lp_data: *mut u8,
    lpcb_data: *mut u32,
) -> u32 {
    if lp_value_name.is_null() || lpcch_value_name.is_null() {
        return ERROR_INVALID_HANDLE;
    }
    let Some(key_path) = hkey_to_path(h_key) else {
        return ERROR_INVALID_HANDLE;
    };

    // Retrieve the name and value at the given index
    let entry = with_registry(|reg| {
        let key = reg.get(&key_path)?;
        let display_name = key.value_names.get(dw_index as usize)?.clone();
        let value = key.values.get(&display_name.to_lowercase())?.clone();
        Some((display_name, value))
    });

    let Some((name, val)) = entry else {
        return ERROR_NO_MORE_ITEMS;
    };

    // Write the value name
    // SAFETY: lp_value_name and lpcch_value_name are non-null (checked above).
    let name_buf_len = *lpcch_value_name;
    let (name_status, name_written) = copy_string_to_wide(&name, lp_value_name, name_buf_len);
    *lpcch_value_name = name_written;
    if name_status != ERROR_SUCCESS {
        return name_status;
    }

    // Write type
    if !lp_type.is_null() {
        // SAFETY: lp_type is non-null.
        *lp_type = val.reg_type();
    }

    // Write data
    if !lpcb_data.is_null() {
        let bytes = val.to_bytes();
        let required = bytes.len() as u32;
        let provided = *lpcb_data;
        // SAFETY: lpcb_data is non-null.
        *lpcb_data = required;
        if !lp_data.is_null() {
            if provided < required {
                return ERROR_MORE_DATA;
            }
            // SAFETY: lp_data points to a writable buffer of at least `provided` bytes.
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), lp_data, bytes.len());
        }
    }

    ERROR_SUCCESS
}

// ── Phase 26: User Name ────────────────────────────────────────────────────

/// GetUserNameW - Retrieves the name of the user associated with the current thread
///
/// # Safety
/// `buffer` must point to a valid writable buffer of at least `*size` u16 elements;
/// `size` must be a valid non-null pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn advapi32_GetUserNameW(buffer: *mut u16, size: *mut u32) -> i32 {
    if size.is_null() {
        return 0;
    }
    let username = get_username();
    let utf16: Vec<u16> = username.encode_utf16().collect();
    let needed = utf16.len() as u32 + 1;
    // SAFETY: size is checked above
    let buf_size = *size;
    *size = needed;
    if buffer.is_null() || buf_size < needed {
        return 0;
    }
    // SAFETY: caller guarantees valid buffer of buf_size u16s
    for (i, &ch) in utf16.iter().enumerate() {
        *buffer.add(i) = ch;
    }
    *buffer.add(utf16.len()) = 0;
    *size = needed;
    1
}

/// GetUserNameA - Retrieves the name of the user associated with the current thread (ANSI)
///
/// # Safety
/// `buffer` must point to a valid writable buffer of at least `*size` bytes;
/// `size` must be a valid non-null pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn advapi32_GetUserNameA(buffer: *mut u8, size: *mut u32) -> i32 {
    if size.is_null() {
        return 0;
    }
    let username = get_username();
    let bytes = username.as_bytes();
    let needed = bytes.len() as u32 + 1;
    // SAFETY: size is checked above
    let buf_size = *size;
    *size = needed;
    if buffer.is_null() || buf_size < needed {
        return 0;
    }
    // SAFETY: caller guarantees valid buffer of buf_size bytes
    for (i, &b) in bytes.iter().enumerate() {
        *buffer.add(i) = b;
    }
    *buffer.add(bytes.len()) = 0;
    *size = needed;
    1
}

fn get_username() -> String {
    if let Ok(user) = std::env::var("USER")
        && !user.is_empty()
    {
        return user;
    }
    if let Ok(user) = std::env::var("LOGNAME")
        && !user.is_empty()
    {
        return user;
    }
    let login = unsafe { libc::getlogin() };
    if !login.is_null()
        && let Ok(s) = unsafe { std::ffi::CStr::from_ptr(login) }.to_str()
        && !s.is_empty()
    {
        return s.to_owned();
    }
    "user".to_owned()
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #![allow(clippy::borrow_as_ptr)]
    #![allow(clippy::ref_as_ptr)]
    use super::*;

    // Helper: encode a Rust &str as a null-terminated UTF-16 Vec<u16>
    fn to_wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    #[test]
    fn test_create_and_close_key() {
        let subkey = to_wide("Software\\LiteBoxTest\\create_close");
        let mut result_key: usize = 0;
        let mut disposition: u32 = 0;
        // SAFETY: all pointers are valid local variables
        let rc = unsafe {
            advapi32_RegCreateKeyExW(
                HKEY_CURRENT_USER,
                subkey.as_ptr(),
                0,
                std::ptr::null_mut(),
                0,
                0,
                std::ptr::null(),
                &mut result_key as *mut usize,
                &mut disposition as *mut u32,
            )
        };
        assert_eq!(rc, ERROR_SUCCESS);
        assert_ne!(result_key, 0);
        // disposition == 1 means REG_CREATED_NEW_KEY
        assert_eq!(disposition, 1);

        // SAFETY: result_key is a valid handle from the create call above
        let rc = unsafe { advapi32_RegCloseKey(result_key) };
        assert_eq!(rc, ERROR_SUCCESS);
    }

    #[test]
    fn test_open_nonexistent_key_returns_not_found() {
        let subkey = to_wide("Software\\LiteBoxTest\\does_not_exist_xyz");
        let mut result_key: usize = 0;
        // SAFETY: all pointers are valid
        let rc = unsafe {
            advapi32_RegOpenKeyExW(
                HKEY_CURRENT_USER,
                subkey.as_ptr(),
                0,
                0,
                &mut result_key as *mut usize,
            )
        };
        assert_eq!(rc, ERROR_FILE_NOT_FOUND);
    }

    #[test]
    fn test_set_and_query_dword_value() {
        // Create the key first
        let subkey = to_wide("Software\\LiteBoxTest\\dword_test");
        let mut hk: usize = 0;
        // SAFETY: valid local pointers
        unsafe {
            advapi32_RegCreateKeyExW(
                HKEY_CURRENT_USER,
                subkey.as_ptr(),
                0,
                std::ptr::null_mut(),
                0,
                0,
                std::ptr::null(),
                &mut hk as *mut usize,
                std::ptr::null_mut(),
            );
        }

        // Set a DWORD value
        let value_name = to_wide("MyDword");
        let data: u32 = 0x1234_5678;
        let raw = data.to_le_bytes();
        // SAFETY: hk is valid; raw is a 4-byte buffer
        let rc = unsafe {
            advapi32_RegSetValueExW(hk, value_name.as_ptr(), 0, REG_DWORD, raw.as_ptr(), 4)
        };
        assert_eq!(rc, ERROR_SUCCESS);

        // Query it back
        let mut val_type: u32 = 0;
        let mut buf = [0u8; 4];
        let mut buf_size: u32 = 4;
        // SAFETY: hk and all buffers are valid
        let rc = unsafe {
            advapi32_RegQueryValueExW(
                hk,
                value_name.as_ptr(),
                std::ptr::null_mut(),
                &mut val_type as *mut u32,
                buf.as_mut_ptr(),
                &mut buf_size as *mut u32,
            )
        };
        assert_eq!(rc, ERROR_SUCCESS);
        assert_eq!(val_type, REG_DWORD);
        assert_eq!(u32::from_le_bytes(buf), 0x1234_5678);

        // SAFETY: hk is a valid open handle
        unsafe { advapi32_RegCloseKey(hk) };
    }

    #[test]
    fn test_set_and_query_string_value() {
        let subkey = to_wide("Software\\LiteBoxTest\\string_test");
        let mut hk: usize = 0;
        // SAFETY: valid local pointers
        unsafe {
            advapi32_RegCreateKeyExW(
                HKEY_CURRENT_USER,
                subkey.as_ptr(),
                0,
                std::ptr::null_mut(),
                0,
                0,
                std::ptr::null(),
                &mut hk as *mut usize,
                std::ptr::null_mut(),
            );
        }

        // Encode "Hello" as REG_SZ (UTF-16LE including null terminator)
        let hello_wide: Vec<u16> = "Hello\0".encode_utf16().collect();
        let hello_bytes: Vec<u8> = hello_wide.iter().flat_map(|c| c.to_le_bytes()).collect();
        let value_name = to_wide("Greeting");

        // SAFETY: hk is valid; hello_bytes is a valid buffer
        let rc = unsafe {
            advapi32_RegSetValueExW(
                hk,
                value_name.as_ptr(),
                0,
                REG_SZ,
                hello_bytes.as_ptr(),
                hello_bytes.len() as u32,
            )
        };
        assert_eq!(rc, ERROR_SUCCESS);

        // Query back — first ask for size
        let mut val_type: u32 = 0;
        let mut buf_size: u32 = 0;
        // SAFETY: hk is valid; null data pointer is acceptable
        let rc = unsafe {
            advapi32_RegQueryValueExW(
                hk,
                value_name.as_ptr(),
                std::ptr::null_mut(),
                &mut val_type as *mut u32,
                std::ptr::null_mut(),
                &mut buf_size as *mut u32,
            )
        };
        assert_eq!(rc, ERROR_SUCCESS);
        assert_eq!(val_type, REG_SZ);
        assert!(buf_size > 0);

        // Then read the data
        let mut data_buf = vec![0u8; buf_size as usize];
        // SAFETY: hk, val_type, data_buf are all valid
        let rc = unsafe {
            advapi32_RegQueryValueExW(
                hk,
                value_name.as_ptr(),
                std::ptr::null_mut(),
                &mut val_type as *mut u32,
                data_buf.as_mut_ptr(),
                &mut buf_size as *mut u32,
            )
        };
        assert_eq!(rc, ERROR_SUCCESS);

        // Decode the UTF-16LE buffer back to a string using the shared helper
        let s = decode_reg_sz_bytes(&data_buf);
        assert_eq!(s, "Hello");

        // SAFETY: hk is a valid open handle
        unsafe { advapi32_RegCloseKey(hk) };
    }

    #[test]
    fn test_delete_value() {
        let subkey = to_wide("Software\\LiteBoxTest\\delete_value_test");
        let mut hk: usize = 0;
        // SAFETY: valid local pointers
        unsafe {
            advapi32_RegCreateKeyExW(
                HKEY_CURRENT_USER,
                subkey.as_ptr(),
                0,
                std::ptr::null_mut(),
                0,
                0,
                std::ptr::null(),
                &mut hk as *mut usize,
                std::ptr::null_mut(),
            );
        }

        let value_name = to_wide("ToDelete");
        let data: u32 = 42;
        let raw = data.to_le_bytes();
        // SAFETY: hk, value_name, raw are valid
        unsafe {
            advapi32_RegSetValueExW(hk, value_name.as_ptr(), 0, REG_DWORD, raw.as_ptr(), 4);
        }

        // Delete it
        // SAFETY: hk and value_name are valid
        let rc = unsafe { advapi32_RegDeleteValueW(hk, value_name.as_ptr()) };
        assert_eq!(rc, ERROR_SUCCESS);

        // Querying after deletion should return NOT_FOUND
        let mut t: u32 = 0;
        let mut sz: u32 = 4;
        let mut b = [0u8; 4];
        // SAFETY: all pointers are valid
        let rc = unsafe {
            advapi32_RegQueryValueExW(
                hk,
                value_name.as_ptr(),
                std::ptr::null_mut(),
                &mut t,
                b.as_mut_ptr(),
                &mut sz,
            )
        };
        assert_eq!(rc, ERROR_FILE_NOT_FOUND);

        // SAFETY: hk is a valid open handle
        unsafe { advapi32_RegCloseKey(hk) };
    }

    #[test]
    fn test_query_buffer_too_small_returns_more_data() {
        let subkey = to_wide("Software\\LiteBoxTest\\buf_size_test");
        let mut hk: usize = 0;
        // SAFETY: valid local pointers
        unsafe {
            advapi32_RegCreateKeyExW(
                HKEY_CURRENT_USER,
                subkey.as_ptr(),
                0,
                std::ptr::null_mut(),
                0,
                0,
                std::ptr::null(),
                &mut hk as *mut usize,
                std::ptr::null_mut(),
            );
        }

        let hello_wide: Vec<u16> = "Hello\0".encode_utf16().collect();
        let hello_bytes: Vec<u8> = hello_wide.iter().flat_map(|c| c.to_le_bytes()).collect();
        let value_name = to_wide("Val");
        // SAFETY: hk is valid
        unsafe {
            advapi32_RegSetValueExW(
                hk,
                value_name.as_ptr(),
                0,
                REG_SZ,
                hello_bytes.as_ptr(),
                hello_bytes.len() as u32,
            );
        }

        // Provide a 1-byte buffer — too small
        let mut t: u32 = 0;
        let mut sz: u32 = 1;
        let mut tiny = [0u8; 1];
        // SAFETY: hk, tiny buffer are valid
        let rc = unsafe {
            advapi32_RegQueryValueExW(
                hk,
                value_name.as_ptr(),
                std::ptr::null_mut(),
                &mut t,
                tiny.as_mut_ptr(),
                &mut sz,
            )
        };
        assert_eq!(rc, ERROR_MORE_DATA);
        // sz should now hold the required size
        assert!(sz > 1);

        // SAFETY: hk is a valid open handle
        unsafe { advapi32_RegCloseKey(hk) };
    }

    #[test]
    fn test_enum_value() {
        let subkey = to_wide("Software\\LiteBoxTest\\enum_value_test");
        let mut hk: usize = 0;
        // SAFETY: valid local pointers
        unsafe {
            advapi32_RegCreateKeyExW(
                HKEY_CURRENT_USER,
                subkey.as_ptr(),
                0,
                std::ptr::null_mut(),
                0,
                0,
                std::ptr::null(),
                &mut hk as *mut usize,
                std::ptr::null_mut(),
            );
        }

        // Insert two values
        for (name, val) in [("Alpha", 1u32), ("Beta", 2u32)] {
            let wname = to_wide(name);
            let raw = val.to_le_bytes();
            // SAFETY: hk and raw are valid
            unsafe {
                advapi32_RegSetValueExW(hk, wname.as_ptr(), 0, REG_DWORD, raw.as_ptr(), 4);
            }
        }

        // Enumerate index 0
        let mut name_buf = vec![0u16; 64];
        let mut name_len: u32 = name_buf.len() as u32;
        let mut val_type: u32 = 0;
        let mut data_buf = [0u8; 4];
        let mut data_sz: u32 = 4;
        // SAFETY: hk and all buffers are valid
        let rc = unsafe {
            advapi32_RegEnumValueW(
                hk,
                0,
                name_buf.as_mut_ptr(),
                &mut name_len,
                std::ptr::null_mut(),
                &mut val_type,
                data_buf.as_mut_ptr(),
                &mut data_sz,
            )
        };
        assert_eq!(rc, ERROR_SUCCESS);
        assert_eq!(val_type, REG_DWORD);

        // Index 2 should be out of range
        let mut name_buf2 = vec![0u16; 64];
        let mut name_len2: u32 = name_buf2.len() as u32;
        // SAFETY: hk and buffer are valid
        let rc2 = unsafe {
            advapi32_RegEnumValueW(
                hk,
                2,
                name_buf2.as_mut_ptr(),
                &mut name_len2,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        assert_eq!(rc2, ERROR_NO_MORE_ITEMS);

        // SAFETY: hk is a valid open handle
        unsafe { advapi32_RegCloseKey(hk) };
    }

    #[test]
    fn test_create_key_idempotent() {
        let subkey = to_wide("Software\\LiteBoxTest\\idempotent");
        let mut hk1: usize = 0;
        let mut disp1: u32 = 0;
        // SAFETY: valid pointers
        unsafe {
            advapi32_RegCreateKeyExW(
                HKEY_CURRENT_USER,
                subkey.as_ptr(),
                0,
                std::ptr::null_mut(),
                0,
                0,
                std::ptr::null(),
                &mut hk1,
                &mut disp1,
            );
        }
        assert_eq!(disp1, 1); // created new

        let mut hk2: usize = 0;
        let mut disp2: u32 = 0;
        // SAFETY: valid pointers
        unsafe {
            advapi32_RegCreateKeyExW(
                HKEY_CURRENT_USER,
                subkey.as_ptr(),
                0,
                std::ptr::null_mut(),
                0,
                0,
                std::ptr::null(),
                &mut hk2,
                &mut disp2,
            );
        }
        assert_eq!(disp2, 2); // opened existing

        // SAFETY: hk1 and hk2 are valid handles
        unsafe {
            advapi32_RegCloseKey(hk1);
            advapi32_RegCloseKey(hk2);
        }
    }

    #[test]
    fn test_open_existing_key_after_create() {
        let subkey = to_wide("Software\\LiteBoxTest\\open_after_create");
        let mut hk_create: usize = 0;
        // SAFETY: valid pointers
        unsafe {
            advapi32_RegCreateKeyExW(
                HKEY_CURRENT_USER,
                subkey.as_ptr(),
                0,
                std::ptr::null_mut(),
                0,
                0,
                std::ptr::null(),
                &mut hk_create,
                std::ptr::null_mut(),
            );
            advapi32_RegCloseKey(hk_create);
        }

        let mut hk_open: usize = 0;
        // SAFETY: valid pointers
        let rc = unsafe {
            advapi32_RegOpenKeyExW(HKEY_CURRENT_USER, subkey.as_ptr(), 0, 0, &mut hk_open)
        };
        assert_eq!(rc, ERROR_SUCCESS);
        assert_ne!(hk_open, 0);

        // SAFETY: hk_open is a valid handle
        unsafe { advapi32_RegCloseKey(hk_open) };
    }

    #[test]
    fn test_close_predefined_hkey_succeeds() {
        // Closing a pre-defined root key should be a no-op, not an error
        // SAFETY: HKEY_CURRENT_USER is a well-known constant
        let rc = unsafe { advapi32_RegCloseKey(HKEY_CURRENT_USER) };
        assert_eq!(rc, ERROR_SUCCESS);
    }

    #[test]
    fn test_invalid_handle_returns_error() {
        let bogus: usize = 0xDEAD_BEEF;
        let value_name = to_wide("anything");
        let mut hk_out: usize = 0;
        let rc_open =
            unsafe { advapi32_RegOpenKeyExW(bogus, value_name.as_ptr(), 0, 0, &mut hk_out) };
        assert_eq!(rc_open, ERROR_INVALID_HANDLE);

        let mut t: u32 = 0;
        let mut sz: u32 = 0;
        let rc_query = unsafe {
            advapi32_RegQueryValueExW(
                bogus,
                value_name.as_ptr(),
                std::ptr::null_mut(),
                &mut t,
                std::ptr::null_mut(),
                &mut sz,
            )
        };
        assert_eq!(rc_query, ERROR_INVALID_HANDLE);
    }

    #[test]
    fn test_enum_sub_keys() {
        // Create a parent key and two child keys, then enumerate the children.
        let parent_subkey = to_wide("Software\\LiteBoxTest\\enum_subkeys_parent");
        let mut hk_parent: usize = 0;
        // SAFETY: valid local pointers
        unsafe {
            advapi32_RegCreateKeyExW(
                HKEY_CURRENT_USER,
                parent_subkey.as_ptr(),
                0,
                std::ptr::null_mut(),
                0,
                0,
                std::ptr::null(),
                &mut hk_parent,
                std::ptr::null_mut(),
            );
        }

        // Create two children under the parent
        for child in ["ChildA", "ChildB"] {
            let full = format!("Software\\LiteBoxTest\\enum_subkeys_parent\\{child}");
            let wide_full = to_wide(&full);
            let mut hk_child: usize = 0;
            // SAFETY: valid pointers
            unsafe {
                advapi32_RegCreateKeyExW(
                    HKEY_CURRENT_USER,
                    wide_full.as_ptr(),
                    0,
                    std::ptr::null_mut(),
                    0,
                    0,
                    std::ptr::null(),
                    &mut hk_child,
                    std::ptr::null_mut(),
                );
                advapi32_RegCloseKey(hk_child);
            }
        }

        // Enumerate index 0 — should succeed and return a non-empty name
        let mut name_buf = vec![0u16; 64];
        let mut name_len: u32 = name_buf.len() as u32;
        // SAFETY: hk_parent and buffers are valid
        let rc0 = unsafe {
            advapi32_RegEnumKeyExW(
                hk_parent,
                0,
                name_buf.as_mut_ptr(),
                &mut name_len,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        assert_eq!(rc0, ERROR_SUCCESS);
        assert!(name_len > 0);

        // Enumerate index 1 — should also succeed
        let mut name_buf1 = vec![0u16; 64];
        let mut name_len1: u32 = name_buf1.len() as u32;
        // SAFETY: hk_parent and buffers are valid
        let rc1 = unsafe {
            advapi32_RegEnumKeyExW(
                hk_parent,
                1,
                name_buf1.as_mut_ptr(),
                &mut name_len1,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        assert_eq!(rc1, ERROR_SUCCESS);

        // Enumerate index 2 — should return ERROR_NO_MORE_ITEMS
        let mut name_buf2 = vec![0u16; 64];
        let mut name_len2: u32 = name_buf2.len() as u32;
        // SAFETY: hk_parent and buffers are valid
        let rc2 = unsafe {
            advapi32_RegEnumKeyExW(
                hk_parent,
                2,
                name_buf2.as_mut_ptr(),
                &mut name_len2,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        assert_eq!(rc2, ERROR_NO_MORE_ITEMS);

        // SAFETY: hk_parent is a valid open handle
        unsafe { advapi32_RegCloseKey(hk_parent) };
    }

    #[test]
    fn test_open_root_hkey_with_empty_subkey_succeeds() {
        // Opening a pre-defined root HKEY with an empty sub-key should always succeed.
        let empty: Vec<u16> = vec![0u16]; // null-terminated empty string
        let mut hk: usize = 0;
        // SAFETY: valid pointers
        let rc =
            unsafe { advapi32_RegOpenKeyExW(HKEY_LOCAL_MACHINE, empty.as_ptr(), 0, 0, &mut hk) };
        assert_eq!(rc, ERROR_SUCCESS);
        assert_ne!(hk, 0);

        // SAFETY: hk is a valid handle
        unsafe { advapi32_RegCloseKey(hk) };
    }

    #[test]
    fn test_key_lookup_case_insensitive() {
        // Create a key with mixed case; opening it with different case should succeed.
        let create_subkey = to_wide("Software\\LiteBoxTest\\CaseSensitivityTest");
        let mut hk_create: usize = 0;
        // SAFETY: valid pointers
        unsafe {
            advapi32_RegCreateKeyExW(
                HKEY_CURRENT_USER,
                create_subkey.as_ptr(),
                0,
                std::ptr::null_mut(),
                0,
                0,
                std::ptr::null(),
                &mut hk_create,
                std::ptr::null_mut(),
            );
            advapi32_RegCloseKey(hk_create);
        }

        // Open using all-uppercase — should find the same key because both are
        // lowercased to "hkcu\\software\\liteboxtest\\casesensitivitytest".
        let open_subkey = to_wide("SOFTWARE\\LITEBOXTEST\\CASESENSITIVITYTEST");
        let mut hk_open: usize = 0;
        // SAFETY: valid pointers
        let rc = unsafe {
            advapi32_RegOpenKeyExW(HKEY_CURRENT_USER, open_subkey.as_ptr(), 0, 0, &mut hk_open)
        };
        assert_eq!(rc, ERROR_SUCCESS);

        // SAFETY: hk_open is a valid handle
        unsafe { advapi32_RegCloseKey(hk_open) };
    }

    #[test]
    fn test_get_user_name() {
        let mut buf = vec![0u16; 256];
        let mut size: u32 = 256;
        let r = unsafe { advapi32_GetUserNameW(buf.as_mut_ptr(), core::ptr::addr_of_mut!(size)) };
        assert_eq!(r, 1);
        assert!(size > 0);
        let name: String = buf[..size as usize - 1]
            .iter()
            .map(|&c| char::from_u32(u32::from(c)).unwrap_or('?'))
            .collect();
        assert!(!name.is_empty());
    }
}
