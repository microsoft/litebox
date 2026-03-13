// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! MSVCP140.DLL (Microsoft C++ Standard Library) stub implementations
//!
//! This module provides minimal stubs for the most commonly imported
//! symbols from `msvcp140.dll` so that C++ programs compiled with MSVC
//! can load without immediately failing on an unresolved import.
//!
//! The C++ mangled names are registered in `function_table.rs` using the
//! `name` field, while the actual Rust implementations use descriptive names.

// Allow unsafe operations inside unsafe functions since the entire file
// uses C ABI functions that are inherently unsafe.
#![allow(unsafe_op_in_unsafe_fn)]
// Pointer casts from *mut u8 to *mut u16 are intentional: unaligned reads/writes
// use ptr::read_unaligned / ptr::write_unaligned / ptr::copy_nonoverlapping.
#![allow(clippy::cast_ptr_alignment)]

use std::alloc::{Layout, alloc, dealloc};
use std::collections::{BTreeMap, HashMap};
use std::ptr;
use std::sync::Mutex;

// ============================================================================
// Global operator new / delete
// ============================================================================
// Use libc malloc/free so that the allocation and deallocation sites are a
// matched pair regardless of Rust's global allocator internals.

/// `operator new(size)` — allocate `size` bytes.
///
/// Exported as the mangled name `??2@YAPEAX_K@Z`.
///
/// # Safety
/// Returns a valid non-null pointer on success, null on failure.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcp140_operator_new(size: usize) -> *mut u8 {
    // Always allocate at least 1 byte so the returned pointer can safely be
    // passed to `msvcp140_operator_delete`, which always calls `libc::free`.
    let alloc_size = if size == 0 { 1 } else { size };
    // SAFETY: alloc_size > 0.
    unsafe { libc::malloc(alloc_size).cast() }
}

/// `operator delete(ptr)` — free a pointer allocated by `operator new`.
///
/// Exported as the mangled name `??3@YAXPEAX@Z`.
///
/// # Safety
/// `ptr` must have been allocated by `msvcp140_operator_new`, or be null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcp140_operator_delete(ptr: *mut u8) {
    if ptr.is_null() {
        return;
    }
    // SAFETY: ptr was allocated by libc::malloc in msvcp140_operator_new.
    unsafe { libc::free(ptr.cast()) };
}

/// `operator new[](size)` — allocate array.
///
/// Exported as the mangled name `??_U@YAPEAX_K@Z`.
///
/// # Safety
/// See `msvcp140_operator_new`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcp140_operator_new_array(size: usize) -> *mut u8 {
    unsafe { msvcp140_operator_new(size) }
}

/// `operator delete[](ptr)` — free array.
///
/// Exported as the mangled name `??_V@YAXPEAX@Z`.
///
/// # Safety
/// See `msvcp140_operator_delete`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcp140_operator_delete_array(ptr: *mut u8) {
    unsafe { msvcp140_operator_delete(ptr) }
}

// ============================================================================
// Standard-library exception helpers
// ============================================================================
// These helpers are called by MSVC STL code when it needs to throw a standard
// C++ exception.  Because we cannot propagate real C++ exceptions, we abort.

/// `std::_Xbad_alloc()` — called when `std::bad_alloc` should be thrown.
///
/// Exported as the mangled name `?_Xbad_alloc@std@@YAXXZ`.
///
/// # Safety
/// Terminates the process.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcp140__Xbad_alloc() -> ! {
    eprintln!("[litebox] msvcp140: std::bad_alloc thrown — aborting");
    unsafe { libc::abort() }
}

/// `std::_Xlength_error(msg)` — called when `std::length_error` should be thrown.
///
/// Exported as the mangled name `?_Xlength_error@std@@YAXPEBD@Z`.
///
/// # Safety
/// Terminates the process.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcp140__Xlength_error(msg: *const i8) -> ! {
    let m = if msg.is_null() {
        "length_error"
    } else {
        unsafe {
            std::ffi::CStr::from_ptr(msg)
                .to_str()
                .unwrap_or("length_error")
        }
    };
    eprintln!("[litebox] msvcp140: std::length_error({m}) — aborting");
    unsafe { libc::abort() }
}

/// `std::_Xout_of_range(msg)` — called when `std::out_of_range` should be thrown.
///
/// Exported as the mangled name `?_Xout_of_range@std@@YAXPEBD@Z`.
///
/// # Safety
/// Terminates the process.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcp140__Xout_of_range(msg: *const i8) -> ! {
    let m = if msg.is_null() {
        "out_of_range"
    } else {
        unsafe {
            std::ffi::CStr::from_ptr(msg)
                .to_str()
                .unwrap_or("out_of_range")
        }
    };
    eprintln!("[litebox] msvcp140: std::out_of_range({m}) — aborting");
    unsafe { libc::abort() }
}

/// `std::_Xinvalid_argument(msg)`.
///
/// Exported as the mangled name `?_Xinvalid_argument@std@@YAXPEBD@Z`.
///
/// # Safety
/// Terminates the process.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcp140__Xinvalid_argument(msg: *const i8) -> ! {
    let m = if msg.is_null() {
        "invalid_argument"
    } else {
        unsafe {
            std::ffi::CStr::from_ptr(msg)
                .to_str()
                .unwrap_or("invalid_argument")
        }
    };
    eprintln!("[litebox] msvcp140: std::invalid_argument({m}) — aborting");
    unsafe { libc::abort() }
}

/// `std::_Xruntime_error(msg)`.
///
/// Exported as the mangled name `?_Xruntime_error@std@@YAXPEBD@Z`.
///
/// # Safety
/// Terminates the process.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcp140__Xruntime_error(msg: *const i8) -> ! {
    let m = if msg.is_null() {
        "runtime_error"
    } else {
        unsafe {
            std::ffi::CStr::from_ptr(msg)
                .to_str()
                .unwrap_or("runtime_error")
        }
    };
    eprintln!("[litebox] msvcp140: std::runtime_error({m}) — aborting");
    unsafe { libc::abort() }
}

/// `std::_Xoverflow_error(msg)`.
///
/// Exported as the mangled name `?_Xoverflow_error@std@@YAXPEBD@Z`.
///
/// # Safety
/// Terminates the process.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcp140__Xoverflow_error(msg: *const i8) -> ! {
    let m = if msg.is_null() {
        "overflow_error"
    } else {
        unsafe {
            std::ffi::CStr::from_ptr(msg)
                .to_str()
                .unwrap_or("overflow_error")
        }
    };
    eprintln!("[litebox] msvcp140: std::overflow_error({m}) — aborting");
    unsafe { libc::abort() }
}

// ============================================================================
// Locale / facet stubs
// ============================================================================
// These are C++ non-static member functions (`__thiscall` / `QEBA` in mangled
// names), so they receive an implicit `this` pointer as their first argument.

/// `std::_Locinfo::_Getctype()` — returns a pointer to the locale C-type table.
///
/// Exported as `?_Getctype@_Locinfo@std@@QEBAPBU_Ctypevec@@XZ` (mangled).
/// Stub: ignores `this` and returns null.
///
/// # Safety
/// Always safe to call; the return value must not be dereferenced.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcp140__Getctype(_this: *const u8) -> *const u8 {
    ptr::null()
}

/// `std::_Locinfo::_Getdays()` — returns locale day-name string.
///
/// Exported as `?_Getdays@_Locinfo@std@@QEBAPEBDXZ`.
/// Stub: ignores `this` and returns an empty string pointer.
///
/// # Safety
/// Returns a pointer to a static string literal.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcp140__Getdays(_this: *const u8) -> *const i8 {
    c"".as_ptr()
}

/// `std::_Locinfo::_Getmonths()` — returns locale month-name string.
///
/// Exported as `?_Getmonths@_Locinfo@std@@QEBAPEBDXZ`.
/// Stub: ignores `this` and returns an empty string pointer.
///
/// # Safety
/// Returns a pointer to a static string literal.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcp140__Getmonths(_this: *const u8) -> *const i8 {
    c"".as_ptr()
}

// ============================================================================
// Concurrency stubs
// ============================================================================

/// `Concurrency::details::_ReaderWriterLock::_AcquireRead()` stub.
///
/// No-op in our single-threaded environment.
///
/// # Safety
/// Always safe to call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcp140__concurrency_acquire_read(_lock: *mut u8) {}

/// `Concurrency::details::_ReaderWriterLock::_ReleaseRead()` stub.
///
/// # Safety
/// Always safe to call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcp140__concurrency_release_read(_lock: *mut u8) {}

// ============================================================================
// Phase 35: std::exception and additional std:: stubs
// ============================================================================

/// `std::exception::what() const` — returns the exception message.
///
/// Exported as `?what@exception@std@@UEBAPEBDXZ` (mangled MSVC name).
/// Stub: ignores `this` and returns an empty string pointer.
///
/// # Safety
/// Returns a pointer to a static string literal; always safe to call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcp140__exception_what(_this: *const u8) -> *const i8 {
    c"".as_ptr()
}

/// `std::exception::~exception()` — destructor.
///
/// Exported as `??1exception@std@@UEAA@XZ`.
/// Stub: no-op since our exception objects have no owned resources.
///
/// # Safety
/// Always safe to call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcp140__exception_dtor(_this: *mut u8) {}

/// `std::exception::exception()` — default constructor.
///
/// Exported as `??0exception@std@@QEAA@XZ`.
/// Stub: no-op.
///
/// # Safety
/// Always safe to call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcp140__exception_ctor(_this: *mut u8) {}

/// `std::exception::exception(char const*)` — message constructor.
///
/// Exported as `??0exception@std@@QEAA@PEBD@Z`.
/// Stub: no-op (message string is not stored).
///
/// # Safety
/// Always safe to call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcp140__exception_ctor_msg(_this: *mut u8, _msg: *const i8) {}

/// `std::locale::_Getgloballocale()` — returns the global locale object pointer.
///
/// Exported as `?_Getgloballocale@locale@std@@CAPEAV_Lobj@12@XZ`.
/// Stub: returns null; programs that use locale operations will need real
/// locale support in a future phase.
///
/// # Safety
/// Always safe to call; the return value must not be dereferenced.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcp140__Getgloballocale() -> *mut u8 {
    ptr::null_mut()
}

/// `std::_Lockit::_Lockit(int)` — locale lock constructor.
///
/// Exported as `??0_Lockit@std@@QEAA@H@Z`.
/// Stub: no-op (single-threaded environment).
///
/// # Safety
/// Always safe to call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcp140__Lockit_ctor(_this: *mut u8, _kind: i32) {}

/// `std::_Lockit::~_Lockit()` — locale lock destructor.
///
/// Exported as `??1_Lockit@std@@QEAA@XZ`.
/// Stub: no-op.
///
/// # Safety
/// Always safe to call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcp140__Lockit_dtor(_this: *mut u8) {}

/// `std::ios_base::Init::Init()` — `ios` base initializer constructor.
///
/// Exported as `??0Init@ios_base@std@@QEAA@XZ`.
/// Stub: no-op (we don't maintain C++ iostream state).
///
/// # Safety
/// Always safe to call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcp140__ios_base_Init_ctor(_this: *mut u8) {}

/// `std::ios_base::Init::~Init()` — `ios` base initializer destructor.
///
/// Exported as `??1Init@ios_base@std@@QEAA@XZ`.
/// Stub: no-op.
///
/// # Safety
/// Always safe to call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcp140__ios_base_Init_dtor(_this: *mut u8) {}

// ============================================================================
// Phase 37: std::basic_string<char> — MSVC x64 ABI implementation
// ============================================================================
//
// MSVC x64 `std::string` (`basic_string<char>`) internal layout (32 bytes):
//
//   [0..16)  union { char _Buf[16]; char* _Ptr; }   — SSO buffer or heap pointer
//   [16..24) size_t _Mysize                          — current length (excl. NUL)
//   [24..32) size_t _Myres                           — capacity (excl. NUL)
//
// SSO threshold: strings up to 15 chars use the inline buffer (`_Myres == 15`);
// longer strings use a heap allocation via `libc::malloc` / `libc::free`.

/// SSO capacity for MSVC `std::string` (inline buffer size minus NUL byte).
const MSVCRT_STR_SSO_CAP: usize = 15;

/// Read `_Mysize` field from a `basic_string<char>` object at `this`.
///
/// # Safety
/// `this` must point to a valid, initialized `basic_string<char>` (32 bytes).
#[inline]
unsafe fn bstr_mysize(this: *const u8) -> usize {
    // The `basic_string` object is received as a `*const u8` (byte pointer) and
    // its alignment is only guaranteed to be 1-byte aligned from our perspective.
    // Even though the 16-byte union field that precedes `_Mysize` ensures 8-byte
    // natural alignment in practice, `read_unaligned` is used defensively to avoid
    // triggering alignment-related undefined behaviour if the pointer is ever
    // less than 8-byte aligned.
    unsafe { ptr::read_unaligned(this.add(16).cast::<usize>()) }
}

/// Read `_Myres` (capacity) from a `basic_string<char>` object at `this`.
///
/// # Safety
/// `this` must point to a valid, initialized `basic_string<char>` (32 bytes).
#[inline]
unsafe fn bstr_myres(this: *const u8) -> usize {
    // See `bstr_mysize` for the rationale for using `read_unaligned`.
    unsafe { ptr::read_unaligned(this.add(24).cast::<usize>()) }
}

/// Return a pointer to the character data of a `basic_string<char>` object.
///
/// # Safety
/// `this` must point to a valid, initialized `basic_string<char>` (32 bytes).
#[inline]
unsafe fn bstr_data(this: *const u8) -> *const i8 {
    let cap = unsafe { bstr_myres(this) };
    if cap == MSVCRT_STR_SSO_CAP {
        // SSO: data is inline at offset 0.
        this.cast::<i8>()
    } else {
        // Heap: first 8 bytes hold the pointer; may not be pointer-aligned.
        unsafe { ptr::read_unaligned(this.cast::<*const i8>()) }
    }
}

/// `std::basic_string<char>::basic_string()` — default constructor.
///
/// Exported as `??0?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@QEAA@XZ`.
/// Initialises to an empty string using SSO.
///
/// # Safety
/// `this` must point to at least 32 bytes of writable memory.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcp140__basic_string_ctor(this: *mut u8) {
    if this.is_null() {
        return;
    }
    // Zero the SSO buffer and set _Mysize = 0, _Myres = SSO_CAP.
    unsafe {
        ptr::write_bytes(this, 0, 16);
        ptr::write_unaligned(this.add(16).cast::<usize>(), 0);
        ptr::write_unaligned(this.add(24).cast::<usize>(), MSVCRT_STR_SSO_CAP);
    }
}

/// `std::basic_string<char>::basic_string(char const*)` — construct from C string.
///
/// Exported as `??0?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@QEAA@PEBD@Z`.
///
/// # Safety
/// `this` must point to at least 32 bytes of writable memory.
/// `s` must be a valid null-terminated C string or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcp140__basic_string_ctor_cstr(this: *mut u8, s: *const i8) {
    unsafe { msvcp140__basic_string_ctor(this) };
    if s.is_null() {
        return;
    }
    // SAFETY: s is a valid null-terminated C string per caller contract.
    let len = unsafe { libc::strlen(s) };
    unsafe { msvcp140_basic_string_assign_impl(this, s, len) };
}

/// `std::basic_string<char>::basic_string(basic_string const&)` — copy constructor.
///
/// Exported as `??0?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@QEAA@AEBV01@@Z`.
///
/// # Safety
/// `this` must point to at least 32 bytes of writable memory.
/// `other` must point to a valid initialized `basic_string<char>`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcp140__basic_string_copy_ctor(this: *mut u8, other: *const u8) {
    unsafe { msvcp140__basic_string_ctor(this) };
    if other.is_null() {
        return;
    }
    let len = unsafe { bstr_mysize(other) };
    let src = unsafe { bstr_data(other) };
    unsafe { msvcp140_basic_string_assign_impl(this, src, len) };
}

/// `std::basic_string<char>::~basic_string()` — destructor.
///
/// Exported as `??1?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@QEAA@XZ`.
/// Frees the heap buffer if SSO is not active.
///
/// # Safety
/// `this` must point to a valid initialized `basic_string<char>`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcp140__basic_string_dtor(this: *mut u8) {
    if this.is_null() {
        return;
    }
    let cap = unsafe { bstr_myres(this) };
    if cap != MSVCRT_STR_SSO_CAP {
        // Heap allocation: free the pointer stored at offset 0.
        let ptr_val = unsafe { ptr::read_unaligned(this.cast::<*mut u8>()) };
        if !ptr_val.is_null() {
            // SAFETY: ptr_val was allocated by libc::malloc in msvcp140_basic_string_assign_impl.
            unsafe { libc::free(ptr_val.cast()) };
        }
    }
    // Zero the object to prevent use-after-free.
    unsafe { ptr::write_bytes(this, 0, 32) };
}

/// Internal helper: assign `len` bytes from `s` into `this`.
///
/// # Safety
/// `this` must point to a valid (possibly empty) `basic_string<char>`.
/// `s` must point to at least `len` readable bytes.
/// `s` must NOT alias the existing character buffer of `this`; callers that
/// may alias (e.g. self-assignment) must copy `s` to a temporary first.
unsafe fn msvcp140_basic_string_assign_impl(this: *mut u8, s: *const i8, len: usize) {
    if this.is_null() {
        return;
    }
    // Guard against length overflow when computing malloc size.
    let Some(alloc_size) = len.checked_add(1) else {
        // Length overflow — leave the string unchanged.
        return;
    };
    // Free existing heap allocation if any.
    let old_cap = unsafe { bstr_myres(this) };
    if old_cap != MSVCRT_STR_SSO_CAP {
        let old_ptr = unsafe { ptr::read_unaligned(this.cast::<*mut u8>()) };
        if !old_ptr.is_null() {
            unsafe { libc::free(old_ptr.cast()) };
        }
    }

    if len <= MSVCRT_STR_SSO_CAP {
        // Use SSO buffer.
        if !s.is_null() && len > 0 {
            // SAFETY: s points to at least `len` readable bytes; buf is 16 bytes.
            unsafe { ptr::copy_nonoverlapping(s, this.cast::<i8>(), len) };
        }
        // NUL terminate.
        unsafe { *this.add(len).cast::<i8>() = 0 };
        unsafe { ptr::write_unaligned(this.add(16).cast::<usize>(), len) };
        unsafe { ptr::write_unaligned(this.add(24).cast::<usize>(), MSVCRT_STR_SSO_CAP) };
    } else {
        // Heap allocation.
        // SAFETY: alloc_size > 0 (checked above).
        let buf = unsafe { libc::malloc(alloc_size).cast::<i8>() };
        if buf.is_null() {
            // Allocation failed: leave the string in a valid empty SSO state
            // rather than storing a null heap pointer with non-zero size.
            unsafe { ptr::write_bytes(this, 0, 16) };
            unsafe { ptr::write_unaligned(this.add(16).cast::<usize>(), 0) };
            unsafe { ptr::write_unaligned(this.add(24).cast::<usize>(), MSVCRT_STR_SSO_CAP) };
            return;
        }
        if !s.is_null() {
            // SAFETY: s points to at least `len` readable bytes.
            unsafe { ptr::copy_nonoverlapping(s, buf, len) };
        }
        // NUL terminate.
        unsafe { *buf.add(len) = 0 };
        // Store heap pointer at offset 0.
        unsafe { ptr::write_unaligned(this.cast::<*mut i8>(), buf) };
        unsafe { ptr::write_unaligned(this.add(16).cast::<usize>(), len) };
        unsafe { ptr::write_unaligned(this.add(24).cast::<usize>(), len) };
    }
}

/// `std::basic_string<char>::c_str() const` — return null-terminated character pointer.
///
/// Exported as `?c_str@?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@QEBAPEBDXZ`.
///
/// # Safety
/// `this` must point to a valid initialized `basic_string<char>`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcp140__basic_string_c_str(this: *const u8) -> *const i8 {
    if this.is_null() {
        return c"".as_ptr();
    }
    unsafe { bstr_data(this) }
}

/// `std::basic_string<char>::size() const` — return string length.
///
/// Exported as `?size@?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@QEBA_KXZ`.
///
/// # Safety
/// `this` must point to a valid initialized `basic_string<char>`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcp140__basic_string_size(this: *const u8) -> usize {
    if this.is_null() {
        return 0;
    }
    unsafe { bstr_mysize(this) }
}

/// `std::basic_string<char>::empty() const` — return true if string is empty.
///
/// Exported as `?empty@?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@QEBA_NXZ`.
///
/// # Safety
/// `this` must point to a valid initialized `basic_string<char>`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcp140__basic_string_empty(this: *const u8) -> bool {
    unsafe { msvcp140__basic_string_size(this) == 0 }
}

/// `std::basic_string<char>::operator=(basic_string const&)` — copy assignment.
///
/// Exported as
/// `??4?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@QEAAAEAV01@AEBV01@@Z`.
/// Returns `this`.
///
/// # Safety
/// `this` and `other` must each point to valid initialized `basic_string<char>` objects.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcp140__basic_string_assign_op(
    this: *mut u8,
    other: *const u8,
) -> *mut u8 {
    if !other.is_null() {
        // Guard against self-assignment: if this == other and the string is
        // heap-backed, msvcp140_basic_string_assign_impl would free the buffer
        // before copying from it, causing use-after-free.
        if std::ptr::eq(this, other) {
            return this;
        }
        let len = unsafe { bstr_mysize(other) };
        let src = unsafe { bstr_data(other) };
        unsafe { msvcp140_basic_string_assign_impl(this, src, len) };
    }
    this
}

/// `std::basic_string<char>::operator=(char const*)` — assign from C string.
///
/// Exported as
/// `??4?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@QEAAAEAV01@PEBD@Z`.
/// Returns `this`.
///
/// # Safety
/// `this` must point to a valid initialized `basic_string<char>`.
/// `s` must be a valid null-terminated C string or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcp140__basic_string_assign_cstr(
    this: *mut u8,
    s: *const i8,
) -> *mut u8 {
    if !s.is_null() {
        let len = unsafe { libc::strlen(s) };
        unsafe { msvcp140_basic_string_assign_impl(this, s, len) };
    }
    this
}

/// `std::basic_string<char>::append(char const*)` — append a C string.
///
/// Exported as
/// `?append@?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@QEAAAEAV12@PEBD@Z`.
/// Returns `this`.
///
/// # Safety
/// `this` must point to a valid initialized `basic_string<char>`.
/// `s` must be a valid null-terminated C string or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcp140__basic_string_append_cstr(
    this: *mut u8,
    s: *const i8,
) -> *mut u8 {
    if this.is_null() || s.is_null() {
        return this;
    }
    let cur_len = unsafe { bstr_mysize(this) };
    let add_len = unsafe { libc::strlen(s) };

    // Guard against length overflow.
    let Some(new_len) = cur_len.checked_add(add_len) else {
        // Overflow — leave string unchanged.
        return this;
    };
    let Some(alloc_size) = new_len.checked_add(1) else {
        // Allocation size overflow — leave string unchanged.
        return this;
    };

    // Build a temporary buffer with the concatenated result.
    let cur_data = unsafe { bstr_data(this) };
    // SAFETY: alloc_size > 0 and was computed with checked_add.
    let tmp = unsafe { libc::malloc(alloc_size).cast::<i8>() };
    if tmp.is_null() {
        return this;
    }
    if cur_len > 0 {
        // SAFETY: cur_data points to at least cur_len readable bytes.
        unsafe { ptr::copy_nonoverlapping(cur_data, tmp, cur_len) };
    }
    // SAFETY: s points to add_len readable bytes.
    unsafe { ptr::copy_nonoverlapping(s, tmp.add(cur_len), add_len) };
    unsafe { *tmp.add(new_len) = 0 };

    unsafe { msvcp140_basic_string_assign_impl(this, tmp, new_len) };
    // SAFETY: tmp was allocated by libc::malloc above.
    unsafe { libc::free(tmp.cast()) };
    this
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_operator_new_delete() {
        unsafe {
            let p = msvcp140_operator_new(64);
            assert!(!p.is_null());
            msvcp140_operator_delete(p);
        }
    }

    #[test]
    fn test_operator_new_zero() {
        unsafe {
            let p = msvcp140_operator_new(0);
            // Zero-size allocation returns a dangling non-null pointer
            assert!(!p.is_null());
            // Do not free the dangling pointer
        }
    }

    #[test]
    fn test_operator_new_array_delete_array() {
        unsafe {
            let p = msvcp140_operator_new_array(128);
            assert!(!p.is_null());
            msvcp140_operator_delete_array(p);
        }
    }

    #[test]
    fn test_operator_delete_null() {
        // Deleting null must not crash
        unsafe { msvcp140_operator_delete(ptr::null_mut()) };
    }

    #[test]
    fn test_exception_what_returns_nonnull() {
        let p = unsafe { msvcp140__exception_what(ptr::null()) };
        assert!(!p.is_null());
    }

    #[test]
    fn test_exception_ctor_dtor_noop() {
        let mut obj = [0u8; 32];
        unsafe {
            msvcp140__exception_ctor(obj.as_mut_ptr());
            msvcp140__exception_dtor(obj.as_mut_ptr());
        }
    }

    #[test]
    fn test_lockit_ctor_dtor_noop() {
        let mut obj = [0u8; 16];
        unsafe {
            msvcp140__Lockit_ctor(obj.as_mut_ptr(), 0);
            msvcp140__Lockit_dtor(obj.as_mut_ptr());
        }
    }

    #[test]
    fn test_basic_string_default_ctor_is_empty() {
        let mut obj = [0u8; 32];
        unsafe {
            msvcp140__basic_string_ctor(obj.as_mut_ptr());
            assert_eq!(msvcp140__basic_string_size(obj.as_ptr()), 0);
            assert!(msvcp140__basic_string_empty(obj.as_ptr()));
            let cs = msvcp140__basic_string_c_str(obj.as_ptr());
            assert!(!cs.is_null());
            assert_eq!(*cs, 0);
            msvcp140__basic_string_dtor(obj.as_mut_ptr());
        }
    }

    #[test]
    fn test_basic_string_ctor_from_cstr() {
        let mut obj = [0u8; 32];
        let hello = c"hello";
        unsafe {
            msvcp140__basic_string_ctor_cstr(obj.as_mut_ptr(), hello.as_ptr());
            assert_eq!(msvcp140__basic_string_size(obj.as_ptr()), 5);
            assert!(!msvcp140__basic_string_empty(obj.as_ptr()));
            let cs = msvcp140__basic_string_c_str(obj.as_ptr());
            assert!(!cs.is_null());
            assert_eq!(std::ffi::CStr::from_ptr(cs).to_str().unwrap(), "hello");
            msvcp140__basic_string_dtor(obj.as_mut_ptr());
        }
    }

    #[test]
    fn test_basic_string_copy_ctor() {
        let mut src = [0u8; 32];
        let mut dst = [0u8; 32];
        let text = c"copy me";
        unsafe {
            msvcp140__basic_string_ctor_cstr(src.as_mut_ptr(), text.as_ptr());
            msvcp140__basic_string_copy_ctor(dst.as_mut_ptr(), src.as_ptr());
            assert_eq!(msvcp140__basic_string_size(dst.as_ptr()), 7);
            let cs = msvcp140__basic_string_c_str(dst.as_ptr());
            assert_eq!(std::ffi::CStr::from_ptr(cs).to_str().unwrap(), "copy me");
            msvcp140__basic_string_dtor(src.as_mut_ptr());
            msvcp140__basic_string_dtor(dst.as_mut_ptr());
        }
    }

    #[test]
    fn test_basic_string_append() {
        let mut obj = [0u8; 32];
        unsafe {
            msvcp140__basic_string_ctor_cstr(obj.as_mut_ptr(), c"hel".as_ptr());
            msvcp140__basic_string_append_cstr(obj.as_mut_ptr(), c"lo".as_ptr());
            assert_eq!(msvcp140__basic_string_size(obj.as_ptr()), 5);
            let cs = msvcp140__basic_string_c_str(obj.as_ptr());
            assert_eq!(std::ffi::CStr::from_ptr(cs).to_str().unwrap(), "hello");
            msvcp140__basic_string_dtor(obj.as_mut_ptr());
        }
    }

    #[test]
    fn test_basic_string_long_string_uses_heap() {
        let mut obj = [0u8; 32];
        // A 20-char string exceeds the SSO threshold (15 chars).
        let long_str = c"this_is_twenty_chars"; // 20 chars
        unsafe {
            msvcp140__basic_string_ctor_cstr(obj.as_mut_ptr(), long_str.as_ptr());
            assert_eq!(msvcp140__basic_string_size(obj.as_ptr()), 20);
            let cs = msvcp140__basic_string_c_str(obj.as_ptr());
            assert_eq!(
                std::ffi::CStr::from_ptr(cs).to_str().unwrap(),
                "this_is_twenty_chars"
            );
            msvcp140__basic_string_dtor(obj.as_mut_ptr());
        }
    }

    #[test]
    fn test_basic_string_self_assign_does_not_corrupt() {
        // SSO string: self-assignment should be a no-op.
        let mut sso = [0u8; 32];
        unsafe {
            msvcp140__basic_string_ctor_cstr(sso.as_mut_ptr(), c"hello".as_ptr());
            let ret = msvcp140__basic_string_assign_op(sso.as_mut_ptr(), sso.as_ptr());
            assert_eq!(ret, sso.as_mut_ptr());
            assert_eq!(msvcp140__basic_string_size(sso.as_ptr()), 5);
            let cs = msvcp140__basic_string_c_str(sso.as_ptr());
            assert_eq!(std::ffi::CStr::from_ptr(cs).to_str().unwrap(), "hello");
            msvcp140__basic_string_dtor(sso.as_mut_ptr());
        }

        // Heap-backed string: self-assignment must not free the buffer before copying.
        let mut heap = [0u8; 32];
        unsafe {
            // "this_is_twenty_chars" (20 chars) forces heap allocation.
            msvcp140__basic_string_ctor_cstr(heap.as_mut_ptr(), c"this_is_twenty_chars".as_ptr());
            let ret = msvcp140__basic_string_assign_op(heap.as_mut_ptr(), heap.as_ptr());
            assert_eq!(ret, heap.as_mut_ptr());
            assert_eq!(msvcp140__basic_string_size(heap.as_ptr()), 20);
            let cs = msvcp140__basic_string_c_str(heap.as_ptr());
            assert_eq!(
                std::ffi::CStr::from_ptr(cs).to_str().unwrap(),
                "this_is_twenty_chars"
            );
            msvcp140__basic_string_dtor(heap.as_mut_ptr());
        }
    }
}

// ============================================================================
// Phase 38: std::basic_string<wchar_t> — MSVC x64 ABI implementation
// ============================================================================
//
// MSVC x64 `std::wstring` (`basic_string<wchar_t>`) internal layout (32 bytes):
//
//   [0..16)  union { wchar_t _Buf[8]; wchar_t* _Ptr; }  — SSO buffer or heap pointer
//   [16..24) size_t _Mysize                              — current length (excl. NUL)
//   [24..32) size_t _Myres                               — capacity (excl. NUL)
//
// SSO threshold: strings up to 7 wchar_t use the inline buffer (`_Myres == 7`);
// longer strings use a heap allocation.

/// SSO capacity for MSVC `std::wstring` (inline buffer holds 8 wchar_t; SSO cap is 7).
const MSVCRT_WSTR_SSO_CAP: usize = 7;

/// Read `_Mysize` field from a `basic_string<wchar_t>` object at `this`.
///
/// # Safety
/// `this` must point to a valid, initialized `basic_string<wchar_t>` (32 bytes).
#[inline]
unsafe fn wstr_mysize(this: *const u8) -> usize {
    unsafe { ptr::read_unaligned(this.add(16).cast::<usize>()) }
}

/// Read `_Myres` (capacity) from a `basic_string<wchar_t>` object at `this`.
///
/// # Safety
/// `this` must point to a valid, initialized `basic_string<wchar_t>` (32 bytes).
#[inline]
unsafe fn wstr_myres(this: *const u8) -> usize {
    unsafe { ptr::read_unaligned(this.add(24).cast::<usize>()) }
}

/// Return a pointer to the wide character data of a `basic_string<wchar_t>` object.
///
/// # Safety
/// `this` must point to a valid, initialized `basic_string<wchar_t>` (32 bytes).
#[inline]
unsafe fn wstr_data(this: *const u8) -> *const u16 {
    let cap = unsafe { wstr_myres(this) };
    if cap == MSVCRT_WSTR_SSO_CAP {
        // SSO: data is inline at offset 0.
        this.cast::<u16>()
    } else {
        // Heap: first 8 bytes hold the pointer.
        unsafe { ptr::read_unaligned(this.cast::<*const u16>()) }
    }
}

/// `std::basic_string<wchar_t>::basic_string()` — default constructor.
///
/// Exported as `??0?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@2@@std@@QEAA@XZ`.
///
/// # Safety
/// `this` must point to at least 32 bytes of writable memory.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcp140__basic_wstring_ctor(this: *mut u8) {
    if this.is_null() {
        return;
    }
    // Zero the SSO buffer and set _Mysize = 0, _Myres = SSO_CAP.
    unsafe {
        ptr::write_bytes(this, 0, 16);
        ptr::write_unaligned(this.add(16).cast::<usize>(), 0);
        ptr::write_unaligned(this.add(24).cast::<usize>(), MSVCRT_WSTR_SSO_CAP);
    }
}

/// `std::basic_string<wchar_t>::basic_string(wchar_t const*)` — construct from wide C string.
///
/// Exported as
/// `??0?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@2@@std@@QEAA@PEB_W@Z`.
///
/// # Safety
/// `this` must point to at least 32 bytes of writable memory.
/// `s` must be a valid null-terminated wide string or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcp140__basic_wstring_ctor_cstr(this: *mut u8, s: *const u16) {
    unsafe { msvcp140__basic_wstring_ctor(this) };
    if s.is_null() {
        return;
    }
    // Compute wide string length.
    let mut len = 0usize;
    // SAFETY: s is a valid null-terminated wide string per caller contract.
    unsafe {
        while *s.add(len) != 0 {
            len += 1;
        }
    }
    unsafe { msvcp140_basic_wstring_assign_impl(this, s, len) };
}

/// `std::basic_string<wchar_t>::basic_string(basic_string const&)` — copy constructor.
///
/// Exported as
/// `??0?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@2@@std@@QEAA@AEBV01@@Z`.
///
/// # Safety
/// `this` must point to at least 32 bytes of writable memory.
/// `other` must point to a valid initialized `basic_string<wchar_t>`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcp140__basic_wstring_copy_ctor(this: *mut u8, other: *const u8) {
    unsafe { msvcp140__basic_wstring_ctor(this) };
    if other.is_null() {
        return;
    }
    let len = unsafe { wstr_mysize(other) };
    let src = unsafe { wstr_data(other) };
    unsafe { msvcp140_basic_wstring_assign_impl(this, src, len) };
}

/// `std::basic_string<wchar_t>::~basic_string()` — destructor.
///
/// Exported as `??1?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@2@@std@@QEAA@XZ`.
///
/// # Safety
/// `this` must point to a valid initialized `basic_string<wchar_t>`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcp140__basic_wstring_dtor(this: *mut u8) {
    if this.is_null() {
        return;
    }
    let cap = unsafe { wstr_myres(this) };
    if cap != MSVCRT_WSTR_SSO_CAP {
        // Heap allocation: free the pointer stored at offset 0.
        let ptr_val = unsafe { ptr::read_unaligned(this.cast::<*mut u8>()) };
        if !ptr_val.is_null() {
            let layout = unsafe {
                // SAFETY: cap+1 is the allocation size used in assign_impl.
                Layout::array::<u16>(cap + 1).unwrap_unchecked()
            };
            // SAFETY: ptr_val was allocated with this layout in msvcp140_basic_wstring_assign_impl.
            unsafe { dealloc(ptr_val, layout) };
        }
    }
    // Zero the object to prevent use-after-free.
    unsafe { ptr::write_bytes(this, 0, 32) };
}

/// Internal helper: assign `len` wide chars from `s` into `this`.
///
/// # Safety
/// `this` must point to a valid (possibly empty) `basic_string<wchar_t>`.
/// `s` must point to at least `len` readable `u16` values.
/// `s` must NOT alias the existing character buffer of `this`.
unsafe fn msvcp140_basic_wstring_assign_impl(this: *mut u8, s: *const u16, len: usize) {
    if this.is_null() {
        return;
    }
    let Some(alloc_size) = len.checked_add(1) else {
        return;
    };

    // Free existing heap allocation if any.
    let old_cap = unsafe { wstr_myres(this) };
    if old_cap != MSVCRT_WSTR_SSO_CAP {
        let old_ptr = unsafe { ptr::read_unaligned(this.cast::<*mut u8>()) };
        if !old_ptr.is_null() {
            let layout = unsafe { Layout::array::<u16>(old_cap + 1).unwrap_unchecked() };
            // SAFETY: old_ptr was allocated with this layout.
            unsafe { dealloc(old_ptr, layout) };
        }
    }

    if len <= MSVCRT_WSTR_SSO_CAP {
        // Use SSO buffer.
        if !s.is_null() && len > 0 {
            // SAFETY: s points to at least `len` u16 values; SSO buffer is 16 bytes (8 u16).
            unsafe { ptr::copy_nonoverlapping(s, this.cast::<u16>(), len) };
        }
        // NUL terminate.
        // SAFETY: SSO buffer has capacity for 8 u16; len <= 7 so offset len is in bounds.
        unsafe { ptr::write_unaligned(this.cast::<u16>().add(len), 0u16) };
        unsafe { ptr::write_unaligned(this.add(16).cast::<usize>(), len) };
        unsafe { ptr::write_unaligned(this.add(24).cast::<usize>(), MSVCRT_WSTR_SSO_CAP) };
    } else {
        // Heap allocation.
        let Ok(layout) = Layout::array::<u16>(alloc_size) else {
            // Layout error: leave empty SSO state.
            unsafe { ptr::write_bytes(this, 0, 16) };
            unsafe { ptr::write_unaligned(this.add(16).cast::<usize>(), 0) };
            unsafe { ptr::write_unaligned(this.add(24).cast::<usize>(), MSVCRT_WSTR_SSO_CAP) };
            return;
        };
        // SAFETY: layout is valid and non-zero.
        let buf = unsafe { alloc(layout).cast::<u16>() };
        if buf.is_null() {
            // Allocation failed: leave empty SSO state.
            unsafe { ptr::write_bytes(this, 0, 16) };
            unsafe { ptr::write_unaligned(this.add(16).cast::<usize>(), 0) };
            unsafe { ptr::write_unaligned(this.add(24).cast::<usize>(), MSVCRT_WSTR_SSO_CAP) };
            return;
        }
        if !s.is_null() {
            // SAFETY: s points to at least `len` u16 values.
            unsafe { ptr::copy_nonoverlapping(s, buf, len) };
        }
        // NUL terminate.
        unsafe { *buf.add(len) = 0 };
        // Store heap pointer at offset 0.
        unsafe { ptr::write_unaligned(this.cast::<*mut u16>(), buf) };
        unsafe { ptr::write_unaligned(this.add(16).cast::<usize>(), len) };
        unsafe { ptr::write_unaligned(this.add(24).cast::<usize>(), len) };
    }
}

/// `std::basic_string<wchar_t>::c_str() const` — return null-terminated wide char pointer.
///
/// Exported as
/// `?c_str@?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@2@@std@@QEBAPEB_WXZ`.
///
/// # Safety
/// `this` must point to a valid initialized `basic_string<wchar_t>`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcp140__basic_wstring_c_str(this: *const u8) -> *const u16 {
    if this.is_null() {
        // Return a pointer to a static wide NUL character.
        static EMPTY_WIDE: u16 = 0;
        return &raw const EMPTY_WIDE;
    }
    unsafe { wstr_data(this) }
}

/// `std::basic_string<wchar_t>::size() const` — return string length.
///
/// Exported as
/// `?size@?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@2@@std@@QEBA_KXZ`.
///
/// # Safety
/// `this` must point to a valid initialized `basic_string<wchar_t>`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcp140__basic_wstring_size(this: *const u8) -> usize {
    if this.is_null() {
        return 0;
    }
    unsafe { wstr_mysize(this) }
}

/// `std::basic_string<wchar_t>::empty() const` — return true if string is empty.
///
/// Exported as
/// `?empty@?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@2@@std@@QEBA_NXZ`.
///
/// # Safety
/// `this` must point to a valid initialized `basic_string<wchar_t>`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcp140__basic_wstring_empty(this: *const u8) -> bool {
    unsafe { msvcp140__basic_wstring_size(this) == 0 }
}

/// `std::basic_string<wchar_t>::operator=(basic_string const&)` — copy assignment.
///
/// Exported as
/// `??4?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@2@@std@@QEAAAEAV01@AEBV01@@Z`.
/// Returns `this`.
///
/// # Safety
/// `this` and `other` must each point to valid initialized `basic_string<wchar_t>` objects.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcp140__basic_wstring_assign_op(
    this: *mut u8,
    other: *const u8,
) -> *mut u8 {
    if !other.is_null() {
        if std::ptr::eq(this, other) {
            return this;
        }
        let len = unsafe { wstr_mysize(other) };
        let src = unsafe { wstr_data(other) };
        unsafe { msvcp140_basic_wstring_assign_impl(this, src, len) };
    }
    this
}

/// `std::basic_string<wchar_t>::operator=(wchar_t const*)` — assign from wide C string.
///
/// Exported as
/// `??4?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@2@@std@@QEAAAEAV01@PEB_W@Z`.
/// Returns `this`.
///
/// # Safety
/// `this` must point to a valid initialized `basic_string<wchar_t>`.
/// `s` must be a valid null-terminated wide string or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcp140__basic_wstring_assign_cstr(
    this: *mut u8,
    s: *const u16,
) -> *mut u8 {
    if !s.is_null() {
        let mut len = 0usize;
        // SAFETY: s is a valid null-terminated wide string per caller contract.
        unsafe {
            while *s.add(len) != 0 {
                len += 1;
            }
        }
        unsafe { msvcp140_basic_wstring_assign_impl(this, s, len) };
    }
    this
}

/// `std::basic_string<wchar_t>::append(wchar_t const*)` — append a wide C string.
///
/// Exported as
/// `?append@?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@2@@std@@QEAAAEAV12@PEB_W@Z`.
/// Returns `this`.
///
/// # Safety
/// `this` must point to a valid initialized `basic_string<wchar_t>`.
/// `s` must be a valid null-terminated wide string or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcp140__basic_wstring_append_cstr(
    this: *mut u8,
    s: *const u16,
) -> *mut u8 {
    if this.is_null() || s.is_null() {
        return this;
    }
    let cur_len = unsafe { wstr_mysize(this) };
    let mut add_len = 0usize;
    unsafe {
        while *s.add(add_len) != 0 {
            add_len += 1;
        }
    }

    let Some(new_len) = cur_len.checked_add(add_len) else {
        return this;
    };
    let Some(alloc_size) = new_len.checked_add(1) else {
        return this;
    };

    let cur_data = unsafe { wstr_data(this) };
    let Ok(layout) = Layout::array::<u16>(alloc_size) else {
        return this;
    };
    // SAFETY: layout is valid and non-zero.
    let tmp = unsafe { alloc(layout).cast::<u16>() };
    if tmp.is_null() {
        return this;
    }
    if cur_len > 0 {
        // SAFETY: cur_data points to at least cur_len u16 values.
        unsafe { ptr::copy_nonoverlapping(cur_data, tmp, cur_len) };
    }
    // SAFETY: s points to add_len u16 values.
    unsafe { ptr::copy_nonoverlapping(s, tmp.add(cur_len), add_len) };
    unsafe { *tmp.add(new_len) = 0 };

    unsafe { msvcp140_basic_wstring_assign_impl(this, tmp, new_len) };
    // SAFETY: tmp was allocated with this layout above.
    unsafe { dealloc(tmp.cast(), layout) };
    this
}

// ============================================================================
// Phase 39: std::vector<char> (MSVC x64 ABI)
// ============================================================================
//
// MSVC x64 layout for `std::vector<char>` is three consecutive raw pointers
// (each 8 bytes on x64), stored at offsets 0, 8, and 16 in the object:
//
//   offset  0: _Myfirst (*mut i8) — pointer to first element, or null
//   offset  8: _Mylast  (*mut i8) — pointer past the last element
//   offset 16: _Myend   (*mut i8) — pointer past the allocated storage

#[inline]
unsafe fn vec_read_first(this: *const u8) -> *mut i8 {
    // SAFETY: caller guarantees this points to a valid vector<char> object.
    unsafe { core::ptr::read_unaligned(this.cast::<*mut i8>()) }
}
#[inline]
unsafe fn vec_read_last(this: *const u8) -> *mut i8 {
    // SAFETY: caller guarantees this points to a valid vector<char> object.
    unsafe { core::ptr::read_unaligned(this.cast::<*mut i8>().add(1)) }
}
#[inline]
unsafe fn vec_read_end(this: *const u8) -> *mut i8 {
    // SAFETY: caller guarantees this points to a valid vector<char> object.
    unsafe { core::ptr::read_unaligned(this.cast::<*mut i8>().add(2)) }
}
#[inline]
unsafe fn vec_write_first(this: *mut u8, v: *mut i8) {
    // SAFETY: caller guarantees this points to a valid vector<char> object.
    unsafe { core::ptr::write_unaligned(this.cast::<*mut i8>(), v) };
}
#[inline]
unsafe fn vec_write_last(this: *mut u8, v: *mut i8) {
    // SAFETY: caller guarantees this points to a valid vector<char> object.
    unsafe { core::ptr::write_unaligned(this.cast::<*mut i8>().add(1), v) };
}
#[inline]
unsafe fn vec_write_end(this: *mut u8, v: *mut i8) {
    // SAFETY: caller guarantees this points to a valid vector<char> object.
    unsafe { core::ptr::write_unaligned(this.cast::<*mut i8>().add(2), v) };
}

/// `std::vector<char>::vector()` — default constructor.
///
/// Zero-initialises all three internal pointers so the vector is empty with
/// no allocated storage.  Exported as the MSVC mangled name
/// `??0?$vector@DU?$allocator@D@std@@@std@@QEAA@XZ`.
///
/// # Safety
/// `this` must point to at least 24 bytes of writable memory aligned to 8 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcp140__vector_char_ctor(this: *mut u8) {
    // SAFETY: caller guarantees this points to a 24-byte aligned object.
    unsafe {
        vec_write_first(this, core::ptr::null_mut());
        vec_write_last(this, core::ptr::null_mut());
        vec_write_end(this, core::ptr::null_mut());
    }
}

/// `std::vector<char>::~vector()` — destructor.
///
/// Frees the heap buffer if one was allocated.  Exported as
/// `??1?$vector@DU?$allocator@D@std@@@std@@QEAA@XZ`.
///
/// # Safety
/// `this` must point to a valid, previously constructed `vector<char>` object.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcp140__vector_char_dtor(this: *mut u8) {
    // SAFETY: caller guarantees this is a valid vector object.
    let first = unsafe { vec_read_first(this) };
    if !first.is_null() {
        // SAFETY: first was allocated by libc::malloc.
        unsafe { libc::free(first.cast()) };
    }
    unsafe {
        vec_write_first(this, core::ptr::null_mut());
        vec_write_last(this, core::ptr::null_mut());
        vec_write_end(this, core::ptr::null_mut());
    }
}

/// `std::vector<char>::push_back(const char& val)` — append one byte.
///
/// Grows the buffer by 2× when capacity is exhausted.  Exported as
/// `?push_back@?$vector@DU?$allocator@D@std@@@std@@QEAAXAEBD@Z`.
///
/// # Safety
/// `this` must point to a valid `vector<char>` object; `val` must point to a
/// readable `i8`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcp140__vector_char_push_back(this: *mut u8, val: *const i8) {
    // SAFETY: caller guarantees this and val are valid.
    let first = unsafe { vec_read_first(this) };
    let last = unsafe { vec_read_last(this) };
    let end = unsafe { vec_read_end(this) };

    if last == end {
        // Need to grow: double the current capacity (min 8).
        let old_cap = if first.is_null() {
            0usize
        } else {
            // SAFETY: end and first are both within the same allocation.
            unsafe { end.offset_from(first).cast_unsigned() }
        };
        let new_cap = if old_cap == 0 { 8 } else { old_cap * 2 };
        // SAFETY: new_cap > 0.
        let new_buf = unsafe { libc::malloc(new_cap).cast::<i8>() };
        if new_buf.is_null() {
            return;
        }
        let len = if first.is_null() {
            0usize
        } else {
            // SAFETY: last and first are both within the same allocation.
            unsafe { last.offset_from(first).cast_unsigned() }
        };
        if !first.is_null() && len > 0 {
            // SAFETY: first..last is a valid range; new_buf has at least new_cap bytes.
            unsafe { libc::memcpy(new_buf.cast(), first.cast(), len) };
        }
        if !first.is_null() {
            // SAFETY: first was allocated by libc::malloc.
            unsafe { libc::free(first.cast()) };
        }
        // SAFETY: new_buf is valid for new_cap bytes; len <= old_cap < new_cap.
        let new_last = unsafe { new_buf.add(len) };
        let new_end = unsafe { new_buf.add(new_cap) };
        unsafe {
            vec_write_first(this, new_buf);
            vec_write_last(this, new_last);
            vec_write_end(this, new_end);
        }
    }

    // Append the byte.
    // SAFETY: vec_read_last reflects the updated last pointer after potential realloc.
    let cur_last = unsafe { vec_read_last(this) };
    // SAFETY: cur_last < end so there is space for at least one more element.
    unsafe { core::ptr::write(cur_last, *val) };
    unsafe { vec_write_last(this, cur_last.add(1)) };
}

/// `std::vector<char>::size()` — return the number of elements.
///
/// Exported as `?size@?$vector@DU?$allocator@D@std@@@std@@QEBA_KXZ`.
///
/// # Safety
/// `this` must point to a valid `vector<char>` object.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcp140__vector_char_size(this: *const u8) -> usize {
    // SAFETY: caller guarantees this is a valid vector object.
    let first = unsafe { vec_read_first(this) };
    let last = unsafe { vec_read_last(this) };
    if first.is_null() {
        return 0;
    }
    // SAFETY: last and first are within the same allocation.
    unsafe { last.offset_from(first).cast_unsigned() }
}

/// `std::vector<char>::capacity()` — return the allocated capacity.
///
/// Exported as `?capacity@?$vector@DU?$allocator@D@std@@@std@@QEBA_KXZ`.
///
/// # Safety
/// `this` must point to a valid `vector<char>` object.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcp140__vector_char_capacity(this: *const u8) -> usize {
    // SAFETY: caller guarantees this is a valid vector object.
    let first = unsafe { vec_read_first(this) };
    let end = unsafe { vec_read_end(this) };
    if first.is_null() {
        return 0;
    }
    // SAFETY: end and first are within the same allocation.
    unsafe { end.offset_from(first).cast_unsigned() }
}

/// `std::vector<char>::clear()` — remove all elements without freeing storage.
///
/// Sets `_Mylast = _Myfirst`.  Exported as
/// `?clear@?$vector@DU?$allocator@D@std@@@std@@QEAAXXZ`.
///
/// # Safety
/// `this` must point to a valid `vector<char>` object.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcp140__vector_char_clear(this: *mut u8) {
    // SAFETY: caller guarantees this is a valid vector object.
    let first = unsafe { vec_read_first(this) };
    unsafe { vec_write_last(this, first) };
}

/// `std::vector<char>::data()` — return a mutable pointer to the first element.
///
/// Exported as `?data@?$vector@DU?$allocator@D@std@@@std@@QEAAPEADXZ`.
///
/// # Safety
/// `this` must point to a valid `vector<char>` object.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcp140__vector_char_data_mut(this: *mut u8) -> *mut i8 {
    // SAFETY: caller guarantees this is a valid vector object.
    unsafe { vec_read_first(this) }
}

/// `std::vector<char>::data() const` — return a const pointer to the first element.
///
/// Exported as `?data@?$vector@DU?$allocator@D@std@@@std@@QEBAPEBDXZ`.
///
/// # Safety
/// `this` must point to a valid `vector<char>` object.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcp140__vector_char_data_const(this: *const u8) -> *const i8 {
    // SAFETY: caller guarantees this is a valid vector object.
    unsafe { vec_read_first(this) }
}

/// `std::vector<char>::reserve(size_t new_cap)` — ensure capacity >= `new_cap`.
///
/// If the current capacity is already >= `new_cap`, does nothing.  Otherwise
/// allocates a new buffer, copies existing data, and frees the old one.
/// Exported as `?reserve@?$vector@DU?$allocator@D@std@@@std@@QEAAX_K@Z`.
///
/// # Safety
/// `this` must point to a valid `vector<char>` object.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcp140__vector_char_reserve(this: *mut u8, new_cap: usize) {
    // SAFETY: caller guarantees this is a valid vector object.
    let first = unsafe { vec_read_first(this) };
    let last = unsafe { vec_read_last(this) };
    let end = unsafe { vec_read_end(this) };

    let old_cap = if first.is_null() {
        0
    } else {
        // SAFETY: end and first are within the same allocation.
        unsafe { end.offset_from(first).cast_unsigned() }
    };
    if new_cap <= old_cap {
        return;
    }

    let len = if first.is_null() {
        0
    } else {
        // SAFETY: last and first are within the same allocation.
        unsafe { last.offset_from(first).cast_unsigned() }
    };

    // SAFETY: new_cap > 0 since new_cap > old_cap >= 0.
    let new_buf = unsafe { libc::malloc(new_cap).cast::<i8>() };
    if new_buf.is_null() {
        return;
    }
    if !first.is_null() && len > 0 {
        // SAFETY: first..last is valid; new_buf has new_cap >= len bytes.
        unsafe { libc::memcpy(new_buf.cast(), first.cast(), len) };
    }
    if !first.is_null() {
        // SAFETY: first was allocated by libc::malloc.
        unsafe { libc::free(first.cast()) };
    }
    // SAFETY: new_buf is valid for new_cap bytes.
    let new_last = unsafe { new_buf.add(len) };
    let new_end = unsafe { new_buf.add(new_cap) };
    unsafe {
        vec_write_first(this, new_buf);
        vec_write_last(this, new_last);
        vec_write_end(this, new_end);
    }
}

#[cfg(test)]
mod tests_vector_char {
    use super::*;

    #[test]
    fn test_vector_char_ctor_is_empty() {
        let mut obj = [0u8; 24];
        unsafe {
            msvcp140__vector_char_ctor(obj.as_mut_ptr());
            assert_eq!(msvcp140__vector_char_size(obj.as_ptr()), 0);
            assert_eq!(msvcp140__vector_char_capacity(obj.as_ptr()), 0);
            assert!(msvcp140__vector_char_data_const(obj.as_ptr()).is_null());
            msvcp140__vector_char_dtor(obj.as_mut_ptr());
        }
    }

    #[test]
    fn test_vector_char_push_back_and_size() {
        let mut obj = [0u8; 24];
        unsafe {
            msvcp140__vector_char_ctor(obj.as_mut_ptr());
            let a = b'A'.cast_signed();
            let b = b'B'.cast_signed();
            msvcp140__vector_char_push_back(obj.as_mut_ptr(), &raw const a);
            msvcp140__vector_char_push_back(obj.as_mut_ptr(), &raw const b);
            assert_eq!(msvcp140__vector_char_size(obj.as_ptr()), 2);
            let data = msvcp140__vector_char_data_const(obj.as_ptr());
            assert_eq!(*data, b'A'.cast_signed());
            assert_eq!(*data.add(1), b'B'.cast_signed());
            msvcp140__vector_char_dtor(obj.as_mut_ptr());
        }
    }

    #[test]
    fn test_vector_char_clear_does_not_free() {
        let mut obj = [0u8; 24];
        unsafe {
            msvcp140__vector_char_ctor(obj.as_mut_ptr());
            let x = 42i8;
            msvcp140__vector_char_push_back(obj.as_mut_ptr(), &raw const x);
            let cap_before = msvcp140__vector_char_capacity(obj.as_ptr());
            msvcp140__vector_char_clear(obj.as_mut_ptr());
            assert_eq!(msvcp140__vector_char_size(obj.as_ptr()), 0);
            // Capacity should be unchanged after clear.
            assert_eq!(msvcp140__vector_char_capacity(obj.as_ptr()), cap_before);
            msvcp140__vector_char_dtor(obj.as_mut_ptr());
        }
    }

    #[test]
    fn test_vector_char_reserve_increases_capacity() {
        let mut obj = [0u8; 24];
        unsafe {
            msvcp140__vector_char_ctor(obj.as_mut_ptr());
            msvcp140__vector_char_reserve(obj.as_mut_ptr(), 64);
            assert!(msvcp140__vector_char_capacity(obj.as_ptr()) >= 64);
            assert_eq!(msvcp140__vector_char_size(obj.as_ptr()), 0);
            msvcp140__vector_char_dtor(obj.as_mut_ptr());
        }
    }

    #[test]
    fn test_vector_char_dtor_null_first_is_safe() {
        // Calling dtor on a default-constructed (null) vector should not crash.
        let mut obj = [0u8; 24];
        unsafe {
            msvcp140__vector_char_ctor(obj.as_mut_ptr());
            msvcp140__vector_char_dtor(obj.as_mut_ptr());
        }
    }
}

// ============================================================================
// std::map<void*, void*> stub
// ============================================================================

/// Global registry: map_this_ptr → BTreeMap<key_usize, value_usize>
static MAP_REGISTRY: Mutex<Option<HashMap<usize, BTreeMap<usize, usize>>>> = Mutex::new(None);

fn with_map_registry<R>(f: impl FnOnce(&mut HashMap<usize, BTreeMap<usize, usize>>) -> R) -> R {
    let mut guard = MAP_REGISTRY.lock().unwrap();
    let m = guard.get_or_insert_with(HashMap::new);
    f(m)
}

/// `std::map<void*,void*>` default constructor — registers an empty map for `this`.
///
/// # Safety
/// `this` must be a valid, non-null pointer to at least 48 bytes of storage.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcp140__map_ctor(this: *mut u8) {
    with_map_registry(|m| {
        m.insert(this as usize, BTreeMap::new());
    });
}

/// `std::map<void*,void*>` destructor — removes the map entry for `this`.
///
/// # Safety
/// `this` must be a pointer previously passed to `msvcp140__map_ctor`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcp140__map_dtor(this: *mut u8) {
    with_map_registry(|m| {
        m.remove(&(this as usize));
    });
}

/// `std::map<void*,void*>::insert` — inserts `(key, value)` into the map.
///
/// Returns `this` as a non-null sentinel pointer on success, or null if `this`
/// is not registered.
///
/// # Safety
/// `this` must be a pointer previously passed to `msvcp140__map_ctor`.
/// `key` and `value` are stored as raw pointer-sized integers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcp140__map_insert(
    this: *mut u8,
    key: *const u8,
    value: *const u8,
) -> *mut u8 {
    let inserted = with_map_registry(|m| {
        if let Some(map) = m.get_mut(&(this as usize)) {
            map.insert(key as usize, value as usize);
            true
        } else {
            false
        }
    });
    if inserted {
        this
    } else {
        core::ptr::null_mut()
    }
}

/// `std::map<void*,void*>::find` — looks up `key` in the map.
///
/// Returns a pointer to the stored value (as `*mut u8`) if found, or null.
///
/// # Safety
/// `this` must be a pointer previously passed to `msvcp140__map_ctor`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcp140__map_find(this: *mut u8, key: *const u8) -> *mut u8 {
    with_map_registry(|m| {
        m.get(&(this as usize))
            .and_then(|map| map.get(&(key as usize)).copied())
            .map_or(core::ptr::null_mut(), |v| v as *mut u8)
    })
}

/// `std::map<void*,void*>::size` — returns the number of elements in the map.
///
/// # Safety
/// `this` must be a pointer previously passed to `msvcp140__map_ctor`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcp140__map_size(this: *const u8) -> usize {
    with_map_registry(|m| m.get(&(this as usize)).map_or(0, BTreeMap::len))
}

/// `std::map<void*,void*>::clear` — removes all elements from the map.
///
/// # Safety
/// `this` must be a pointer previously passed to `msvcp140__map_ctor`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcp140__map_clear(this: *mut u8) {
    with_map_registry(|m| {
        if let Some(map) = m.get_mut(&(this as usize)) {
            map.clear();
        }
    });
}

// ============================================================================
// std::ostringstream stub
// ============================================================================

/// Global registry: ostringstream_this_ptr → `Vec<u8>` (byte buffer)
static OSS_REGISTRY: Mutex<Option<HashMap<usize, Vec<u8>>>> = Mutex::new(None);

fn with_oss_registry<R>(f: impl FnOnce(&mut HashMap<usize, Vec<u8>>) -> R) -> R {
    let mut guard = OSS_REGISTRY.lock().unwrap();
    let m = guard.get_or_insert_with(HashMap::new);
    f(m)
}

/// `std::ostringstream` default constructor — registers an empty buffer for `this`.
///
/// # Safety
/// `this` must be a valid, non-null pointer to at least 256 bytes of storage.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcp140__ostringstream_ctor(this: *mut u8) {
    with_oss_registry(|m| {
        m.insert(this as usize, Vec::new());
    });
}

/// `std::ostringstream` destructor — removes the buffer entry for `this`.
///
/// # Safety
/// `this` must be a pointer previously passed to `msvcp140__ostringstream_ctor`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcp140__ostringstream_dtor(this: *mut u8) {
    with_oss_registry(|m| {
        m.remove(&(this as usize));
    });
}

/// `std::ostringstream::str()` — returns a malloc'd copy of the buffer as a C string.
///
/// The caller is responsible for freeing the returned pointer with `free()`.
/// Returns null if `this` is not registered or allocation fails.
///
/// # Safety
/// `this` must be a pointer previously passed to `msvcp140__ostringstream_ctor`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcp140__ostringstream_str(this: *const u8) -> *mut u8 {
    let buf_opt = with_oss_registry(|m| m.get(&(this as usize)).cloned());
    let Some(buf) = buf_opt else {
        return core::ptr::null_mut();
    };
    // Allocate buf.len() + 1 bytes for the NUL terminator.
    let len = buf.len();
    // SAFETY: layout has non-zero size (len + 1 >= 1).
    let ptr = unsafe { libc::malloc(len + 1) }.cast::<u8>();
    if ptr.is_null() {
        return core::ptr::null_mut();
    }
    if len > 0 {
        // SAFETY: ptr is valid for len bytes; buf.as_ptr() is valid for len bytes.
        unsafe { core::ptr::copy_nonoverlapping(buf.as_ptr(), ptr, len) };
    }
    // SAFETY: ptr + len is within the allocation.
    unsafe { *ptr.add(len) = 0 };
    ptr
}

/// `std::ostringstream::write(buf, count)` — appends `count` raw bytes to the buffer.
///
/// # Safety
/// `this` must be a pointer previously passed to `msvcp140__ostringstream_ctor`.
/// `buf` must be valid for `count` bytes of reads.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcp140__ostringstream_write(
    this: *mut u8,
    buf: *const u8,
    count: usize,
) {
    if buf.is_null() || count == 0 {
        return;
    }
    // SAFETY: buf is valid for count bytes per caller's contract.
    let slice = unsafe { core::slice::from_raw_parts(buf, count) };
    with_oss_registry(|m| {
        if let Some(v) = m.get_mut(&(this as usize)) {
            v.extend_from_slice(slice);
        }
    });
}

/// `std::ostringstream::tellp()` — returns the current write position (= buffer length).
///
/// # Safety
/// `this` must be a pointer previously passed to `msvcp140__ostringstream_ctor`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcp140__ostringstream_tellp(this: *const u8) -> i64 {
    with_oss_registry(|m| {
        m.get(&(this as usize))
            .map_or(-1, |v| i64::try_from(v.len()).unwrap_or(i64::MAX))
    })
}

/// `std::ostringstream::seekp(pos)` — seeks the write position, truncating if needed.
///
/// If `pos` is beyond the current length, the buffer is extended with NUL bytes.
///
/// # Safety
/// `this` must be a pointer previously passed to `msvcp140__ostringstream_ctor`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcp140__ostringstream_seekp(this: *mut u8, pos: i64) {
    if pos < 0 {
        return;
    }
    let Ok(new_len) = usize::try_from(pos) else {
        return;
    };
    with_oss_registry(|m| {
        if let Some(v) = m.get_mut(&(this as usize)) {
            v.resize(new_len, 0);
        }
    });
}

// ── Phase 42: std::istringstream ──────────────────────────────────────────────

/// Registry for `istringstream` instances: maps `this` pointer → `(buffer, read_pos)`.
type IssEntry = (Vec<u8>, usize);
static ISS_REGISTRY: Mutex<Option<HashMap<usize, IssEntry>>> = Mutex::new(None);

fn with_iss_registry<R>(f: impl FnOnce(&mut HashMap<usize, IssEntry>) -> R) -> R {
    let mut guard = ISS_REGISTRY.lock().unwrap();
    let m = guard.get_or_insert_with(HashMap::new);
    f(m)
}

/// `std::istringstream` default constructor — registers an empty buffer for `this`.
///
/// # Safety
/// `this` must be a valid, non-null pointer to at least 256 bytes of storage.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcp140__istringstream_ctor(this: *mut u8, _mode: i32) {
    with_iss_registry(|m| {
        debug_assert!(
            !m.contains_key(&(this as usize)),
            "istringstream_ctor called twice for same this pointer"
        );
        m.insert(this as usize, (Vec::new(), 0));
    });
}

/// `std::istringstream` constructor from a C string.
///
/// # Safety
/// `this` must be a valid, non-null pointer to at least 256 bytes of storage.
/// `s` must be a valid NUL-terminated string or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcp140__istringstream_ctor_str(this: *mut u8, s: *const u8, _mode: i32) {
    let buf = if s.is_null() {
        Vec::new()
    } else {
        // SAFETY: s is a valid NUL-terminated string per caller contract.
        let len = unsafe { libc::strlen(s.cast()) };
        // SAFETY: s is valid for len bytes.
        unsafe { core::slice::from_raw_parts(s, len) }.to_vec()
    };
    with_iss_registry(|m| {
        debug_assert!(
            !m.contains_key(&(this as usize)),
            "istringstream_ctor_str called twice for same this pointer"
        );
        m.insert(this as usize, (buf, 0));
    });
}

/// `std::istringstream` destructor — removes the buffer entry for `this`.
///
/// # Safety
/// `this` must be a pointer previously passed to one of the `istringstream` constructors.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcp140__istringstream_dtor(this: *mut u8) {
    with_iss_registry(|m| {
        m.remove(&(this as usize));
    });
}

/// `std::istringstream::str()` — returns a malloc'd copy of the buffer as a C string.
///
/// The caller is responsible for freeing the returned pointer with `free()`.
/// Returns null if `this` is not registered or allocation fails.
///
/// # Safety
/// `this` must be a pointer previously passed to one of the `istringstream` constructors.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcp140__istringstream_str(this: *const u8) -> *mut u8 {
    let buf_opt = with_iss_registry(|m| m.get(&(this as usize)).map(|(b, _)| b.clone()));
    let Some(buf) = buf_opt else {
        return core::ptr::null_mut();
    };
    let len = buf.len();
    // SAFETY: len + 1 >= 1.
    let ptr = unsafe { libc::malloc(len + 1) }.cast::<u8>();
    if ptr.is_null() {
        return core::ptr::null_mut();
    }
    if len > 0 {
        // SAFETY: ptr is valid for len bytes; buf.as_ptr() is valid for len bytes.
        unsafe { core::ptr::copy_nonoverlapping(buf.as_ptr(), ptr, len) };
    }
    // SAFETY: ptr + len is within the allocation.
    unsafe { *ptr.add(len) = 0 };
    ptr
}

/// `std::istringstream::str(s)` — sets the buffer from a C string and resets read pos to 0.
///
/// # Safety
/// `this` must be a pointer previously passed to one of the `istringstream` constructors.
/// `s` must be a valid NUL-terminated string or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcp140__istringstream_str_set(this: *mut u8, s: *const u8) {
    let buf = if s.is_null() {
        Vec::new()
    } else {
        // SAFETY: s is a valid NUL-terminated string per caller contract.
        let len = unsafe { libc::strlen(s.cast()) };
        // SAFETY: s is valid for len bytes.
        unsafe { core::slice::from_raw_parts(s, len) }.to_vec()
    };
    with_iss_registry(|m| {
        if let Some(entry) = m.get_mut(&(this as usize)) {
            *entry = (buf, 0);
        }
    });
}

/// `std::istringstream::read(buf, count)` — reads up to `count` bytes from the current position.
///
/// Advances the read position by the number of bytes actually read.
/// Returns `this` (the stream object pointer).
///
/// # Safety
/// `this` must be a pointer previously passed to one of the `istringstream` constructors.
/// `buf` must be valid for `count` bytes of writes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcp140__istringstream_read(
    this: *mut u8,
    buf: *mut u8,
    count: i64,
) -> *mut u8 {
    if buf.is_null() || count <= 0 {
        return this;
    }
    let Ok(count_usize) = usize::try_from(count) else {
        return this;
    };
    with_iss_registry(|m| {
        if let Some((data, pos)) = m.get_mut(&(this as usize)) {
            let available = data.len().saturating_sub(*pos);
            let to_read = count_usize.min(available);
            if to_read > 0 {
                // SAFETY: buf is valid for count bytes; data slice is valid for to_read bytes.
                unsafe { core::ptr::copy_nonoverlapping(data.as_ptr().add(*pos), buf, to_read) };
                *pos += to_read;
            }
        }
    });
    this
}

/// `std::istringstream::seekg(pos)` — seek the read position to `pos`.
///
/// # Safety
/// `this` must be a pointer previously passed to one of the `istringstream` constructors.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcp140__istringstream_seekg(this: *mut u8, pos: i64) {
    if pos < 0 {
        return;
    }
    let Ok(new_pos) = usize::try_from(pos) else {
        return;
    };
    with_iss_registry(|m| {
        if let Some((data, read_pos)) = m.get_mut(&(this as usize)) {
            *read_pos = new_pos.min(data.len());
        }
    });
}

/// `std::istringstream::tellg()` — returns the current read position, or -1 if not registered.
///
/// # Safety
/// `this` must be a pointer previously passed to one of the `istringstream` constructors.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcp140__istringstream_tellg(this: *const u8) -> i64 {
    with_iss_registry(|m| {
        m.get(&(this as usize))
            .map_or(-1, |(_, pos)| i64::try_from(*pos).unwrap_or(i64::MAX))
    })
}

#[cfg(test)]
mod tests_wstring {
    use super::*;

    #[test]
    fn test_basic_wstring_default_ctor_is_empty() {
        let mut obj = [0u8; 32];
        unsafe {
            msvcp140__basic_wstring_ctor(obj.as_mut_ptr());
            assert_eq!(msvcp140__basic_wstring_size(obj.as_ptr()), 0);
            assert!(msvcp140__basic_wstring_empty(obj.as_ptr()));
            let p = msvcp140__basic_wstring_c_str(obj.as_ptr());
            assert!(!p.is_null());
            assert_eq!(*p, 0u16);
            msvcp140__basic_wstring_dtor(obj.as_mut_ptr());
        }
    }

    #[test]
    fn test_basic_wstring_ctor_from_cstr_sso() {
        // "hi" (2 chars) fits in SSO (threshold = 7).
        let wide: [u16; 3] = [u16::from(b'h'), u16::from(b'i'), 0];
        let mut obj = [0u8; 32];
        unsafe {
            msvcp140__basic_wstring_ctor_cstr(obj.as_mut_ptr(), wide.as_ptr());
            assert_eq!(msvcp140__basic_wstring_size(obj.as_ptr()), 2);
            assert!(!msvcp140__basic_wstring_empty(obj.as_ptr()));
            let p = msvcp140__basic_wstring_c_str(obj.as_ptr());
            assert_eq!(*p, u16::from(b'h'));
            assert_eq!(*p.add(1), u16::from(b'i'));
            assert_eq!(*p.add(2), 0u16);
            msvcp140__basic_wstring_dtor(obj.as_mut_ptr());
        }
    }

    #[test]
    fn test_basic_wstring_ctor_from_cstr_heap() {
        // 10 chars > SSO threshold (7), forces heap allocation.
        let wide: Vec<u16> = "helloworld\0".encode_utf16().collect();
        let mut obj = [0u8; 32];
        unsafe {
            msvcp140__basic_wstring_ctor_cstr(obj.as_mut_ptr(), wide.as_ptr());
            assert_eq!(msvcp140__basic_wstring_size(obj.as_ptr()), 10);
            let p = msvcp140__basic_wstring_c_str(obj.as_ptr());
            let result: Vec<u16> = (0..10).map(|i| *p.add(i)).collect();
            let s = String::from_utf16_lossy(&result);
            assert_eq!(s, "helloworld");
            msvcp140__basic_wstring_dtor(obj.as_mut_ptr());
        }
    }

    #[test]
    fn test_basic_wstring_copy_ctor() {
        let wide: Vec<u16> = "copy\0".encode_utf16().collect();
        let mut src = [0u8; 32];
        let mut dst = [0u8; 32];
        unsafe {
            msvcp140__basic_wstring_ctor_cstr(src.as_mut_ptr(), wide.as_ptr());
            msvcp140__basic_wstring_copy_ctor(dst.as_mut_ptr(), src.as_ptr());
            assert_eq!(msvcp140__basic_wstring_size(dst.as_ptr()), 4);
            let p = msvcp140__basic_wstring_c_str(dst.as_ptr());
            let result: Vec<u16> = (0..4).map(|i| *p.add(i)).collect();
            assert_eq!(String::from_utf16_lossy(&result), "copy");
            msvcp140__basic_wstring_dtor(src.as_mut_ptr());
            msvcp140__basic_wstring_dtor(dst.as_mut_ptr());
        }
    }

    #[test]
    fn test_basic_wstring_append_cstr() {
        let hello: Vec<u16> = "hel\0".encode_utf16().collect();
        let lo: Vec<u16> = "lo\0".encode_utf16().collect();
        let mut obj = [0u8; 32];
        unsafe {
            msvcp140__basic_wstring_ctor_cstr(obj.as_mut_ptr(), hello.as_ptr());
            msvcp140__basic_wstring_append_cstr(obj.as_mut_ptr(), lo.as_ptr());
            assert_eq!(msvcp140__basic_wstring_size(obj.as_ptr()), 5);
            let p = msvcp140__basic_wstring_c_str(obj.as_ptr());
            let result: Vec<u16> = (0..5).map(|i| *p.add(i)).collect();
            assert_eq!(String::from_utf16_lossy(&result), "hello");
            msvcp140__basic_wstring_dtor(obj.as_mut_ptr());
        }
    }

    #[test]
    fn test_basic_wstring_self_assign_no_corruption() {
        let wide: Vec<u16> = "test\0".encode_utf16().collect();
        let mut obj = [0u8; 32];
        unsafe {
            msvcp140__basic_wstring_ctor_cstr(obj.as_mut_ptr(), wide.as_ptr());
            let ret = msvcp140__basic_wstring_assign_op(obj.as_mut_ptr(), obj.as_ptr());
            assert_eq!(ret, obj.as_mut_ptr());
            assert_eq!(msvcp140__basic_wstring_size(obj.as_ptr()), 4);
            msvcp140__basic_wstring_dtor(obj.as_mut_ptr());
        }
    }
}

#[cfg(test)]
mod tests_map {
    use super::*;

    #[test]
    fn test_map_ctor_dtor() {
        let mut obj = [0u8; 48];
        unsafe {
            msvcp140__map_ctor(obj.as_mut_ptr());
            assert_eq!(msvcp140__map_size(obj.as_ptr()), 0);
            msvcp140__map_dtor(obj.as_mut_ptr());
        }
    }

    #[test]
    fn test_map_insert_find_clear() {
        let mut obj = [0u8; 48];
        let key = 0x1234usize as *const u8;
        let val = 0x5678usize as *const u8;
        unsafe {
            msvcp140__map_ctor(obj.as_mut_ptr());
            let ret = msvcp140__map_insert(obj.as_mut_ptr(), key, val);
            assert!(!ret.is_null());
            assert_eq!(msvcp140__map_size(obj.as_ptr()), 1);
            let found = msvcp140__map_find(obj.as_mut_ptr(), key);
            assert_eq!(found, val.cast_mut());
            msvcp140__map_clear(obj.as_mut_ptr());
            assert_eq!(msvcp140__map_size(obj.as_ptr()), 0);
            msvcp140__map_dtor(obj.as_mut_ptr());
        }
    }

    #[test]
    fn test_map_find_missing_key_returns_null() {
        let mut obj = [0u8; 48];
        let missing = 0xDEADusize as *const u8;
        unsafe {
            msvcp140__map_ctor(obj.as_mut_ptr());
            let found = msvcp140__map_find(obj.as_mut_ptr(), missing);
            assert!(found.is_null());
            msvcp140__map_dtor(obj.as_mut_ptr());
        }
    }
}

#[cfg(test)]
mod tests_ostringstream {
    use super::*;

    #[test]
    fn test_ostringstream_ctor_dtor() {
        let mut obj = [0u8; 256];
        unsafe {
            msvcp140__ostringstream_ctor(obj.as_mut_ptr());
            assert_eq!(msvcp140__ostringstream_tellp(obj.as_ptr()), 0);
            msvcp140__ostringstream_dtor(obj.as_mut_ptr());
        }
    }

    #[test]
    fn test_ostringstream_write_and_str() {
        let mut obj = [0u8; 256];
        unsafe {
            msvcp140__ostringstream_ctor(obj.as_mut_ptr());
            let data = b"hello";
            msvcp140__ostringstream_write(obj.as_mut_ptr(), data.as_ptr(), data.len());
            assert_eq!(msvcp140__ostringstream_tellp(obj.as_ptr()), 5);
            let s = msvcp140__ostringstream_str(obj.as_ptr());
            assert!(!s.is_null());
            let got = core::ffi::CStr::from_ptr(s.cast());
            assert_eq!(got.to_bytes(), b"hello");
            libc::free(s.cast());
            msvcp140__ostringstream_dtor(obj.as_mut_ptr());
        }
    }

    #[test]
    fn test_ostringstream_seekp_truncates() {
        let mut obj = [0u8; 256];
        unsafe {
            msvcp140__ostringstream_ctor(obj.as_mut_ptr());
            let data = b"abcdef";
            msvcp140__ostringstream_write(obj.as_mut_ptr(), data.as_ptr(), data.len());
            msvcp140__ostringstream_seekp(obj.as_mut_ptr(), 3);
            assert_eq!(msvcp140__ostringstream_tellp(obj.as_ptr()), 3);
            let s = msvcp140__ostringstream_str(obj.as_ptr());
            assert!(!s.is_null());
            let got = core::ffi::CStr::from_ptr(s.cast());
            assert_eq!(got.to_bytes(), b"abc");
            libc::free(s.cast());
            msvcp140__ostringstream_dtor(obj.as_mut_ptr());
        }
    }
}

#[cfg(test)]
mod tests_istringstream {
    use super::*;

    #[test]
    fn test_istringstream_ctor_dtor() {
        let mut obj = [0u8; 256];
        unsafe {
            msvcp140__istringstream_ctor(obj.as_mut_ptr(), 0);
            assert_eq!(msvcp140__istringstream_tellg(obj.as_ptr()), 0);
            msvcp140__istringstream_dtor(obj.as_mut_ptr());
        }
    }

    #[test]
    fn test_istringstream_ctor_str_and_read() {
        let mut obj = [0u8; 256];
        let src = b"hello\0";
        unsafe {
            msvcp140__istringstream_ctor_str(obj.as_mut_ptr(), src.as_ptr(), 0);
            assert_eq!(msvcp140__istringstream_tellg(obj.as_ptr()), 0);
            let mut buf = [0u8; 8];
            msvcp140__istringstream_read(obj.as_mut_ptr(), buf.as_mut_ptr(), 5);
            assert_eq!(&buf[..5], b"hello");
            assert_eq!(msvcp140__istringstream_tellg(obj.as_ptr()), 5);
            msvcp140__istringstream_dtor(obj.as_mut_ptr());
        }
    }

    #[test]
    fn test_istringstream_str_getter() {
        let mut obj = [0u8; 256];
        let src = b"world\0";
        unsafe {
            msvcp140__istringstream_ctor_str(obj.as_mut_ptr(), src.as_ptr(), 0);
            let s = msvcp140__istringstream_str(obj.as_ptr());
            assert!(!s.is_null());
            let got = core::ffi::CStr::from_ptr(s.cast());
            assert_eq!(got.to_bytes(), b"world");
            libc::free(s.cast());
            msvcp140__istringstream_dtor(obj.as_mut_ptr());
        }
    }

    #[test]
    fn test_istringstream_str_set_resets_pos() {
        let mut obj = [0u8; 256];
        let src = b"abc\0";
        unsafe {
            msvcp140__istringstream_ctor(obj.as_mut_ptr(), 0);
            msvcp140__istringstream_str_set(obj.as_mut_ptr(), src.as_ptr());
            assert_eq!(msvcp140__istringstream_tellg(obj.as_ptr()), 0);
            let mut buf = [0u8; 4];
            msvcp140__istringstream_read(obj.as_mut_ptr(), buf.as_mut_ptr(), 3);
            assert_eq!(msvcp140__istringstream_tellg(obj.as_ptr()), 3);
            // str_set should reset position to 0
            msvcp140__istringstream_str_set(obj.as_mut_ptr(), src.as_ptr());
            assert_eq!(msvcp140__istringstream_tellg(obj.as_ptr()), 0);
            msvcp140__istringstream_dtor(obj.as_mut_ptr());
        }
    }

    #[test]
    fn test_istringstream_seekg() {
        let mut obj = [0u8; 256];
        let src = b"abcdef\0";
        unsafe {
            msvcp140__istringstream_ctor_str(obj.as_mut_ptr(), src.as_ptr(), 0);
            msvcp140__istringstream_seekg(obj.as_mut_ptr(), 3);
            assert_eq!(msvcp140__istringstream_tellg(obj.as_ptr()), 3);
            let mut buf = [0u8; 4];
            msvcp140__istringstream_read(obj.as_mut_ptr(), buf.as_mut_ptr(), 3);
            assert_eq!(&buf[..3], b"def");
            msvcp140__istringstream_dtor(obj.as_mut_ptr());
        }
    }

    #[test]
    fn test_istringstream_tellg_unregistered() {
        let obj = [0u8; 256];
        let result = unsafe { msvcp140__istringstream_tellg(obj.as_ptr()) };
        assert_eq!(result, -1);
    }
}

// ── Phase 43: std::stringstream (bidirectional) ───────────────────────────────

/// Registry for `stringstream` instances: maps `this` pointer → `(buffer, read_pos)`.
type SsEntry = (Vec<u8>, usize);
static SS_REGISTRY: Mutex<Option<HashMap<usize, SsEntry>>> = Mutex::new(None);

fn with_ss_registry<R>(f: impl FnOnce(&mut HashMap<usize, SsEntry>) -> R) -> R {
    let mut guard = SS_REGISTRY.lock().unwrap();
    let m = guard.get_or_insert_with(HashMap::new);
    f(m)
}

/// `std::stringstream` default constructor — registers an empty buffer for `this`.
///
/// # Safety
/// `this` must be a valid, non-null pointer to at least 256 bytes of storage.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcp140__stringstream_ctor(this: *mut u8, _mode: i32) {
    with_ss_registry(|m| {
        m.insert(this as usize, (Vec::new(), 0));
    });
}

/// `std::stringstream` constructor from a C string.
///
/// # Safety
/// `this` must be a valid, non-null pointer to at least 256 bytes of storage.
/// `s` must be a valid NUL-terminated string or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcp140__stringstream_ctor_str(this: *mut u8, s: *const u8, _mode: i32) {
    let buf = if s.is_null() {
        Vec::new()
    } else {
        // SAFETY: s is a valid NUL-terminated string per caller contract.
        let len = unsafe { libc::strlen(s.cast()) };
        // SAFETY: s is valid for len bytes.
        unsafe { core::slice::from_raw_parts(s, len) }.to_vec()
    };
    with_ss_registry(|m| {
        m.insert(this as usize, (buf, 0));
    });
}

/// `std::stringstream` destructor — removes the entry for `this`.
///
/// # Safety
/// `this` must be a pointer previously passed to one of the `stringstream` constructors.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcp140__stringstream_dtor(this: *mut u8) {
    with_ss_registry(|m| {
        m.remove(&(this as usize));
    });
}

/// `std::stringstream::str()` — returns a malloc'd copy of the buffer as a C string.
///
/// The caller is responsible for freeing the returned pointer with `free()`.
/// Returns null if `this` is not registered or allocation fails.
///
/// # Safety
/// `this` must be a pointer previously passed to one of the `stringstream` constructors.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcp140__stringstream_str(this: *const u8) -> *mut u8 {
    let buf_opt = with_ss_registry(|m| m.get(&(this as usize)).map(|(b, _)| b.clone()));
    let Some(buf) = buf_opt else {
        return core::ptr::null_mut();
    };
    let len = buf.len();
    // SAFETY: len + 1 >= 1.
    let ptr = unsafe { libc::malloc(len + 1) }.cast::<u8>();
    if ptr.is_null() {
        return core::ptr::null_mut();
    }
    if len > 0 {
        // SAFETY: ptr is valid for len bytes; buf.as_ptr() is valid for len bytes.
        unsafe { core::ptr::copy_nonoverlapping(buf.as_ptr(), ptr, len) };
    }
    // SAFETY: ptr + len is within the allocation.
    unsafe { *ptr.add(len) = 0 };
    ptr
}

/// `std::stringstream::str(s)` — sets the buffer from a C string and resets both positions to 0.
///
/// # Safety
/// `this` must be a pointer previously passed to one of the `stringstream` constructors.
/// `s` must be a valid NUL-terminated string or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcp140__stringstream_str_set(this: *mut u8, s: *const u8) {
    let buf = if s.is_null() {
        Vec::new()
    } else {
        // SAFETY: s is a valid NUL-terminated string per caller contract.
        let len = unsafe { libc::strlen(s.cast()) };
        // SAFETY: s is valid for len bytes.
        unsafe { core::slice::from_raw_parts(s, len) }.to_vec()
    };
    with_ss_registry(|m| {
        if let Some(entry) = m.get_mut(&(this as usize)) {
            *entry = (buf, 0);
        }
    });
}

/// `std::stringstream::read(buf, count)` — reads up to `count` bytes from the current read position.
///
/// Advances the read position by the number of bytes actually read.
/// Returns `this` (the stream object pointer).
///
/// # Safety
/// `this` must be a pointer previously passed to one of the `stringstream` constructors.
/// `buf` must be valid for `count` bytes of writes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcp140__stringstream_read(
    this: *mut u8,
    buf: *mut u8,
    count: i64,
) -> *mut u8 {
    if buf.is_null() || count <= 0 {
        return this;
    }
    let Ok(count_usize) = usize::try_from(count) else {
        return this;
    };
    with_ss_registry(|m| {
        if let Some((data, pos)) = m.get_mut(&(this as usize)) {
            let available = data.len().saturating_sub(*pos);
            let to_read = count_usize.min(available);
            if to_read > 0 {
                // SAFETY: buf is valid for count bytes; data slice is valid for to_read bytes.
                unsafe { core::ptr::copy_nonoverlapping(data.as_ptr().add(*pos), buf, to_read) };
                *pos += to_read;
            }
        }
    });
    this
}

/// `std::stringstream::write(buf, count)` — appends `count` raw bytes to the buffer.
///
/// Returns `this` (the stream object pointer).
///
/// # Safety
/// `this` must be a pointer previously passed to one of the `stringstream` constructors.
/// `buf` must be valid for `count` bytes of reads.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcp140__stringstream_write(
    this: *mut u8,
    buf: *const u8,
    count: usize,
) -> *mut u8 {
    if buf.is_null() || count == 0 {
        return this;
    }
    // SAFETY: buf is valid for count bytes per caller's contract.
    let slice = unsafe { core::slice::from_raw_parts(buf, count) };
    with_ss_registry(|m| {
        if let Some((v, _)) = m.get_mut(&(this as usize)) {
            v.extend_from_slice(slice);
        }
    });
    this
}

/// `std::stringstream::seekg(pos)` — seek the read position to `pos`.
///
/// # Safety
/// `this` must be a pointer previously passed to one of the `stringstream` constructors.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcp140__stringstream_seekg(this: *mut u8, pos: i64) {
    if pos < 0 {
        return;
    }
    let Ok(new_pos) = usize::try_from(pos) else {
        return;
    };
    with_ss_registry(|m| {
        if let Some((data, read_pos)) = m.get_mut(&(this as usize)) {
            *read_pos = new_pos.min(data.len());
        }
    });
}

/// `std::stringstream::tellg()` — returns the current read position, or -1 if not registered.
///
/// # Safety
/// `this` must be a pointer previously passed to one of the `stringstream` constructors.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcp140__stringstream_tellg(this: *const u8) -> i64 {
    with_ss_registry(|m| {
        m.get(&(this as usize))
            .map_or(-1, |(_, pos)| i64::try_from(*pos).unwrap_or(i64::MAX))
    })
}

/// `std::stringstream::seekp(pos)` — sets the write position by resizing the buffer.
///
/// If `pos` is less than the current buffer length, the buffer is truncated.
/// If `pos` is beyond the current buffer length, the buffer is extended with NUL bytes.
///
/// # Safety
/// `this` must be a pointer previously passed to one of the `stringstream` constructors.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcp140__stringstream_seekp(this: *mut u8, pos: i64) {
    if pos < 0 {
        return;
    }
    let Ok(new_len) = usize::try_from(pos) else {
        return;
    };
    with_ss_registry(|m| {
        if let Some((v, _)) = m.get_mut(&(this as usize)) {
            v.resize(new_len, 0);
        }
    });
}

/// `std::stringstream::tellp()` — returns the current write position (= buffer length).
///
/// # Safety
/// `this` must be a pointer previously passed to one of the `stringstream` constructors.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcp140__stringstream_tellp(this: *const u8) -> i64 {
    with_ss_registry(|m| {
        m.get(&(this as usize))
            .map_or(-1, |(v, _)| i64::try_from(v.len()).unwrap_or(i64::MAX))
    })
}

#[cfg(test)]
mod tests_stringstream {
    use super::*;

    #[test]
    fn test_stringstream_ctor_dtor() {
        let mut obj = [0u8; 256];
        unsafe {
            msvcp140__stringstream_ctor(obj.as_mut_ptr(), 0);
            assert_eq!(msvcp140__stringstream_tellg(obj.as_ptr()), 0);
            assert_eq!(msvcp140__stringstream_tellp(obj.as_ptr()), 0);
            msvcp140__stringstream_dtor(obj.as_mut_ptr());
        }
    }

    #[test]
    fn test_stringstream_write_then_read() {
        let mut obj = [0u8; 256];
        unsafe {
            msvcp140__stringstream_ctor(obj.as_mut_ptr(), 0);
            let data = b"hello";
            msvcp140__stringstream_write(obj.as_mut_ptr(), data.as_ptr(), data.len());
            assert_eq!(msvcp140__stringstream_tellp(obj.as_ptr()), 5);
            // Seek read position to beginning then read back.
            msvcp140__stringstream_seekg(obj.as_mut_ptr(), 0);
            let mut buf = [0u8; 8];
            msvcp140__stringstream_read(obj.as_mut_ptr(), buf.as_mut_ptr(), 5);
            assert_eq!(&buf[..5], b"hello");
            msvcp140__stringstream_dtor(obj.as_mut_ptr());
        }
    }

    #[test]
    fn test_stringstream_str_getter() {
        let mut obj = [0u8; 256];
        let src = b"test\0";
        unsafe {
            msvcp140__stringstream_ctor_str(obj.as_mut_ptr(), src.as_ptr(), 0);
            let s = msvcp140__stringstream_str(obj.as_ptr());
            assert!(!s.is_null());
            let got = core::ffi::CStr::from_ptr(s.cast());
            assert_eq!(got.to_bytes(), b"test");
            libc::free(s.cast());
            msvcp140__stringstream_dtor(obj.as_mut_ptr());
        }
    }

    #[test]
    fn test_stringstream_str_set_resets_pos() {
        let mut obj = [0u8; 256];
        let src = b"xyz\0";
        unsafe {
            msvcp140__stringstream_ctor(obj.as_mut_ptr(), 0);
            msvcp140__stringstream_str_set(obj.as_mut_ptr(), src.as_ptr());
            assert_eq!(msvcp140__stringstream_tellg(obj.as_ptr()), 0);
            msvcp140__stringstream_dtor(obj.as_mut_ptr());
        }
    }

    #[test]
    fn test_stringstream_seekp_truncates() {
        let mut obj = [0u8; 256];
        unsafe {
            msvcp140__stringstream_ctor(obj.as_mut_ptr(), 0);
            let data = b"abcdef";
            msvcp140__stringstream_write(obj.as_mut_ptr(), data.as_ptr(), data.len());
            msvcp140__stringstream_seekp(obj.as_mut_ptr(), 3);
            assert_eq!(msvcp140__stringstream_tellp(obj.as_ptr()), 3);
            let s = msvcp140__stringstream_str(obj.as_ptr());
            assert!(!s.is_null());
            let got = core::ffi::CStr::from_ptr(s.cast());
            assert_eq!(got.to_bytes(), b"abc");
            libc::free(s.cast());
            msvcp140__stringstream_dtor(obj.as_mut_ptr());
        }
    }
}

// ── Phase 43: std::unordered_map<void*,void*> ────────────────────────────────

/// Global registry for `unordered_map` instances: maps `this` pointer → inner HashMap.
static UMAP_REGISTRY: Mutex<Option<HashMap<usize, HashMap<usize, usize>>>> = Mutex::new(None);

fn with_umap_registry<R>(f: impl FnOnce(&mut HashMap<usize, HashMap<usize, usize>>) -> R) -> R {
    let mut guard = UMAP_REGISTRY.lock().unwrap();
    let m = guard.get_or_insert_with(HashMap::new);
    f(m)
}

/// `std::unordered_map<void*,void*>` default constructor.
///
/// # Safety
/// `this` must be a valid, non-null pointer to at least 8 bytes of storage.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcp140__unordered_map_ctor(this: *mut u8) {
    with_umap_registry(|m| {
        m.entry(this as usize).or_insert_with(HashMap::new);
    });
}

/// `std::unordered_map<void*,void*>` destructor.
///
/// # Safety
/// `this` must be a pointer previously passed to `msvcp140__unordered_map_ctor`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcp140__unordered_map_dtor(this: *mut u8) {
    with_umap_registry(|m| {
        m.remove(&(this as usize));
    });
}

/// `std::unordered_map<void*,void*>::insert` — inserts `(key, value)` into the map.
///
/// Returns `this` on success, or null if `this` is not registered.
///
/// # Safety
/// `this` must be a pointer previously passed to `msvcp140__unordered_map_ctor`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcp140__unordered_map_insert(
    this: *mut u8,
    key: *const u8,
    value: *const u8,
) -> *mut u8 {
    let inserted = with_umap_registry(|m| {
        if let Some(map) = m.get_mut(&(this as usize)) {
            map.insert(key as usize, value as usize);
            true
        } else {
            false
        }
    });
    if inserted {
        this
    } else {
        core::ptr::null_mut()
    }
}

/// `std::unordered_map<void*,void*>::find` — looks up `key` in the map.
///
/// Returns a pointer to the stored value if found, or null.
///
/// # Safety
/// `this` must be a pointer previously passed to `msvcp140__unordered_map_ctor`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcp140__unordered_map_find(this: *mut u8, key: *const u8) -> *mut u8 {
    with_umap_registry(|m| {
        m.get(&(this as usize))
            .and_then(|map| map.get(&(key as usize)).copied())
            .map_or(core::ptr::null_mut(), |v| v as *mut u8)
    })
}

/// `std::unordered_map<void*,void*>::size` — returns the number of elements.
///
/// # Safety
/// `this` must be a pointer previously passed to `msvcp140__unordered_map_ctor`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcp140__unordered_map_size(this: *const u8) -> usize {
    with_umap_registry(|m| m.get(&(this as usize)).map_or(0, HashMap::len))
}

/// `std::unordered_map<void*,void*>::clear` — removes all elements.
///
/// # Safety
/// `this` must be a pointer previously passed to `msvcp140__unordered_map_ctor`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcp140__unordered_map_clear(this: *mut u8) {
    with_umap_registry(|m| {
        if let Some(map) = m.get_mut(&(this as usize)) {
            map.clear();
        }
    });
}

#[cfg(test)]
mod tests_unordered_map {
    use super::*;

    #[test]
    fn test_unordered_map_ctor_dtor() {
        let mut obj = [0u8; 8];
        unsafe {
            msvcp140__unordered_map_ctor(obj.as_mut_ptr());
            assert_eq!(msvcp140__unordered_map_size(obj.as_ptr()), 0);
            msvcp140__unordered_map_dtor(obj.as_mut_ptr());
        }
    }

    #[test]
    fn test_unordered_map_insert_find_clear() {
        let mut obj = [0u8; 8];
        let key = 0x1234usize as *const u8;
        let val = 0x5678usize as *const u8;
        unsafe {
            msvcp140__unordered_map_ctor(obj.as_mut_ptr());
            let ret = msvcp140__unordered_map_insert(obj.as_mut_ptr(), key, val);
            assert!(!ret.is_null());
            assert_eq!(msvcp140__unordered_map_size(obj.as_ptr()), 1);
            let found = msvcp140__unordered_map_find(obj.as_mut_ptr(), key);
            assert_eq!(found, val.cast_mut());
            msvcp140__unordered_map_clear(obj.as_mut_ptr());
            assert_eq!(msvcp140__unordered_map_size(obj.as_ptr()), 0);
            msvcp140__unordered_map_dtor(obj.as_mut_ptr());
        }
    }

    #[test]
    fn test_unordered_map_find_missing_returns_null() {
        let mut obj = [0u8; 8];
        let missing = 0xDEADusize as *const u8;
        unsafe {
            msvcp140__unordered_map_ctor(obj.as_mut_ptr());
            let found = msvcp140__unordered_map_find(obj.as_mut_ptr(), missing);
            assert!(found.is_null());
            msvcp140__unordered_map_dtor(obj.as_mut_ptr());
        }
    }
}

// ── Phase 44: std::deque<void*> ───────────────────────────────────────────────

static DEQUE_REGISTRY: Mutex<Option<HashMap<usize, std::collections::VecDeque<usize>>>> =
    Mutex::new(None);

fn with_deque_registry<R>(
    f: impl FnOnce(&mut HashMap<usize, std::collections::VecDeque<usize>>) -> R,
) -> R {
    let mut guard = DEQUE_REGISTRY.lock().unwrap();
    let m = guard.get_or_insert_with(HashMap::new);
    f(m)
}

/// `std::deque<void*>::deque()` — construct an empty deque.
///
/// # Safety
/// `this` must be a non-null pointer to at least 1 byte of writable memory.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcp140__deque_ctor(this: *mut u8) {
    with_deque_registry(|m| {
        m.insert(this as usize, std::collections::VecDeque::new());
    });
}

/// `std::deque<void*>::~deque()` — destroy the deque.
///
/// # Safety
/// `this` must be a pointer previously passed to `msvcp140__deque_ctor`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcp140__deque_dtor(this: *mut u8) {
    with_deque_registry(|m| {
        m.remove(&(this as usize));
    });
}

/// `std::deque<void*>::push_back(val)` — append `val` to the back.
///
/// # Safety
/// `this` must be a pointer previously passed to `msvcp140__deque_ctor`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcp140__deque_push_back(this: *mut u8, val: *const u8) {
    with_deque_registry(|m| {
        if let Some(dq) = m.get_mut(&(this as usize)) {
            dq.push_back(val as usize);
        }
    });
}

/// `std::deque<void*>::push_front(val)` — prepend `val` to the front.
///
/// # Safety
/// `this` must be a pointer previously passed to `msvcp140__deque_ctor`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcp140__deque_push_front(this: *mut u8, val: *const u8) {
    with_deque_registry(|m| {
        if let Some(dq) = m.get_mut(&(this as usize)) {
            dq.push_front(val as usize);
        }
    });
}

/// `std::deque<void*>::pop_front()` — remove the front element and return it.
///
/// Note: the real C++ `pop_front()` returns void; this stub returns the removed
/// value as a convenience for callers that need the value after popping.
/// Returns null if the deque is empty.
///
/// # Safety
/// `this` must be a pointer previously passed to `msvcp140__deque_ctor`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcp140__deque_pop_front(this: *mut u8) -> *mut u8 {
    with_deque_registry(|m| {
        m.get_mut(&(this as usize))
            .and_then(std::collections::VecDeque::pop_front)
            .map_or(core::ptr::null_mut(), |v| v as *mut u8)
    })
}

/// `std::deque<void*>::pop_back()` — remove the back element and return it.
///
/// Note: the real C++ `pop_back()` returns void; this stub returns the removed
/// value as a convenience for callers that need the value after popping.
/// Returns null if the deque is empty.
///
/// # Safety
/// `this` must be a pointer previously passed to `msvcp140__deque_ctor`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcp140__deque_pop_back(this: *mut u8) -> *mut u8 {
    with_deque_registry(|m| {
        m.get_mut(&(this as usize))
            .and_then(std::collections::VecDeque::pop_back)
            .map_or(core::ptr::null_mut(), |v| v as *mut u8)
    })
}

/// `std::deque<void*>::front()` — returns a reference (pointer) to the front element.
///
/// Returns a pointer to the stored `void*` element (i.e., `void**`), or null if the
/// deque is empty.  The MSVC mangled name ending in `QEAAAEAPEAXXZ` indicates the C++
/// return type is `void*&`, which is passed as a pointer in the Windows x64 ABI.
///
/// # Safety
/// `this` must be a pointer previously passed to `msvcp140__deque_ctor`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcp140__deque_front(this: *const u8) -> *mut *mut u8 {
    with_deque_registry(|m| {
        m.get_mut(&(this as usize))
            .and_then(|dq| dq.front_mut())
            // SAFETY: usize and *mut u8 have identical size and alignment on all targets.
            .map_or(core::ptr::null_mut(), |slot| {
                core::ptr::from_mut(slot).cast::<*mut u8>()
            })
    })
}

/// `std::deque<void*>::back()` — returns a reference (pointer) to the back element.
///
/// Returns a pointer to the stored `void*` element (i.e., `void**`), or null if the
/// deque is empty.  The MSVC mangled name ending in `QEAAAEAPEAXXZ` indicates the C++
/// return type is `void*&`, which is passed as a pointer in the Windows x64 ABI.
///
/// # Safety
/// `this` must be a pointer previously passed to `msvcp140__deque_ctor`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcp140__deque_back(this: *const u8) -> *mut *mut u8 {
    with_deque_registry(|m| {
        m.get_mut(&(this as usize))
            .and_then(|dq| dq.back_mut())
            // SAFETY: usize and *mut u8 have identical size and alignment on all targets.
            .map_or(core::ptr::null_mut(), |slot| {
                core::ptr::from_mut(slot).cast::<*mut u8>()
            })
    })
}

/// `std::deque<void*>::size()` — return the number of elements.
///
/// # Safety
/// `this` must be a pointer previously passed to `msvcp140__deque_ctor`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcp140__deque_size(this: *const u8) -> usize {
    with_deque_registry(|m| {
        m.get(&(this as usize))
            .map_or(0, std::collections::VecDeque::len)
    })
}

/// `std::deque<void*>::clear()` — remove all elements.
///
/// # Safety
/// `this` must be a pointer previously passed to `msvcp140__deque_ctor`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcp140__deque_clear(this: *mut u8) {
    with_deque_registry(|m| {
        if let Some(dq) = m.get_mut(&(this as usize)) {
            dq.clear();
        }
    });
}

#[cfg(test)]
mod tests_deque {
    use super::*;

    #[test]
    fn test_deque_ctor_dtor() {
        let mut obj = [0u8; 8];
        unsafe {
            msvcp140__deque_ctor(obj.as_mut_ptr());
            assert_eq!(msvcp140__deque_size(obj.as_ptr()), 0);
            msvcp140__deque_dtor(obj.as_mut_ptr());
        }
    }

    #[test]
    fn test_deque_push_back_pop_front() {
        let mut obj = [0u8; 8];
        let a = 0x1111usize as *const u8;
        let b = 0x2222usize as *const u8;
        unsafe {
            msvcp140__deque_ctor(obj.as_mut_ptr());
            msvcp140__deque_push_back(obj.as_mut_ptr(), a);
            msvcp140__deque_push_back(obj.as_mut_ptr(), b);
            assert_eq!(msvcp140__deque_size(obj.as_ptr()), 2);
            assert_eq!(msvcp140__deque_pop_front(obj.as_mut_ptr()), a.cast_mut());
            assert_eq!(msvcp140__deque_pop_front(obj.as_mut_ptr()), b.cast_mut());
            assert_eq!(msvcp140__deque_size(obj.as_ptr()), 0);
            msvcp140__deque_dtor(obj.as_mut_ptr());
        }
    }

    #[test]
    fn test_deque_push_front_pop_back() {
        let mut obj = [0u8; 8];
        let a = 0x3333usize as *const u8;
        let b = 0x4444usize as *const u8;
        unsafe {
            msvcp140__deque_ctor(obj.as_mut_ptr());
            msvcp140__deque_push_front(obj.as_mut_ptr(), a);
            msvcp140__deque_push_front(obj.as_mut_ptr(), b);
            // front = b, back = a; dereference the returned references to get stored values
            let front = msvcp140__deque_front(obj.as_ptr());
            let back = msvcp140__deque_back(obj.as_ptr());
            assert_eq!(*front, b.cast_mut());
            assert_eq!(*back, a.cast_mut());
            assert_eq!(msvcp140__deque_pop_back(obj.as_mut_ptr()), a.cast_mut());
            assert_eq!(msvcp140__deque_pop_back(obj.as_mut_ptr()), b.cast_mut());
            msvcp140__deque_dtor(obj.as_mut_ptr());
        }
    }

    #[test]
    fn test_deque_empty_pops_return_null() {
        let mut obj = [0u8; 8];
        unsafe {
            msvcp140__deque_ctor(obj.as_mut_ptr());
            assert!(msvcp140__deque_pop_front(obj.as_mut_ptr()).is_null());
            assert!(msvcp140__deque_pop_back(obj.as_mut_ptr()).is_null());
            assert!(msvcp140__deque_front(obj.as_ptr()).is_null());
            assert!(msvcp140__deque_back(obj.as_ptr()).is_null());
            msvcp140__deque_dtor(obj.as_mut_ptr());
        }
    }

    #[test]
    fn test_deque_clear() {
        let mut obj = [0u8; 8];
        unsafe {
            msvcp140__deque_ctor(obj.as_mut_ptr());
            msvcp140__deque_push_back(obj.as_mut_ptr(), 0x10usize as *const u8);
            msvcp140__deque_push_back(obj.as_mut_ptr(), 0x20usize as *const u8);
            msvcp140__deque_clear(obj.as_mut_ptr());
            assert_eq!(msvcp140__deque_size(obj.as_ptr()), 0);
            msvcp140__deque_dtor(obj.as_mut_ptr());
        }
    }
}

// ── Phase 44: std::stack<void*> ───────────────────────────────────────────────

static STACK_REGISTRY: Mutex<Option<HashMap<usize, std::collections::VecDeque<usize>>>> =
    Mutex::new(None);

fn with_stack_registry<R>(
    f: impl FnOnce(&mut HashMap<usize, std::collections::VecDeque<usize>>) -> R,
) -> R {
    let mut guard = STACK_REGISTRY.lock().unwrap();
    let m = guard.get_or_insert_with(HashMap::new);
    f(m)
}

/// `std::stack<void*>::stack()` — construct an empty stack.
///
/// # Safety
/// `this` must be a non-null pointer to at least 1 byte of writable memory.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcp140__stack_ctor(this: *mut u8) {
    with_stack_registry(|m| {
        m.insert(this as usize, std::collections::VecDeque::new());
    });
}

/// `std::stack<void*>::~stack()` — destroy the stack.
///
/// # Safety
/// `this` must be a pointer previously passed to `msvcp140__stack_ctor`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcp140__stack_dtor(this: *mut u8) {
    with_stack_registry(|m| {
        m.remove(&(this as usize));
    });
}

/// `std::stack<void*>::push(val)` — push `val` onto the top of the stack.
///
/// # Safety
/// `this` must be a pointer previously passed to `msvcp140__stack_ctor`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcp140__stack_push(this: *mut u8, val: *const u8) {
    with_stack_registry(|m| {
        if let Some(st) = m.get_mut(&(this as usize)) {
            st.push_back(val as usize);
        }
    });
}

/// `std::stack<void*>::pop()` — remove the top element and return it (LIFO).
///
/// Note: the real C++ `std::stack::pop()` returns void; this stub returns the
/// removed value as a convenience for callers that need the value after popping.
/// Returns null if the stack is empty.
///
/// # Safety
/// `this` must be a pointer previously passed to `msvcp140__stack_ctor`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcp140__stack_pop(this: *mut u8) -> *mut u8 {
    with_stack_registry(|m| {
        m.get_mut(&(this as usize))
            .and_then(std::collections::VecDeque::pop_back)
            .map_or(core::ptr::null_mut(), |v| v as *mut u8)
    })
}

/// `std::stack<void*>::top()` — returns a reference (pointer) to the top element.
///
/// Returns a pointer to the stored `void*` element (i.e., `void**`), or null if the
/// stack is empty.  The MSVC mangled name ending in `QEAAAEAPEAXXZ` indicates the C++
/// return type is `void*&`, which is passed as a pointer in the Windows x64 ABI.
///
/// # Safety
/// `this` must be a pointer previously passed to `msvcp140__stack_ctor`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcp140__stack_top(this: *const u8) -> *mut *mut u8 {
    with_stack_registry(|m| {
        m.get_mut(&(this as usize))
            .and_then(|st| st.back_mut())
            // SAFETY: usize and *mut u8 have identical size and alignment on all targets.
            .map_or(core::ptr::null_mut(), |slot| {
                core::ptr::from_mut(slot).cast::<*mut u8>()
            })
    })
}

/// `std::stack<void*>::size()` — return the number of elements.
///
/// # Safety
/// `this` must be a pointer previously passed to `msvcp140__stack_ctor`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcp140__stack_size(this: *const u8) -> usize {
    with_stack_registry(|m| {
        m.get(&(this as usize))
            .map_or(0, std::collections::VecDeque::len)
    })
}

/// `std::stack<void*>::empty()` — return true if the stack has no elements.
///
/// # Safety
/// `this` must be a pointer previously passed to `msvcp140__stack_ctor`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcp140__stack_empty(this: *const u8) -> bool {
    with_stack_registry(|m| {
        m.get(&(this as usize))
            .is_none_or(std::collections::VecDeque::is_empty)
    })
}

#[cfg(test)]
mod tests_stack {
    use super::*;

    #[test]
    fn test_stack_ctor_dtor() {
        let mut obj = [0u8; 8];
        unsafe {
            msvcp140__stack_ctor(obj.as_mut_ptr());
            assert_eq!(msvcp140__stack_size(obj.as_ptr()), 0);
            assert!(msvcp140__stack_empty(obj.as_ptr()));
            msvcp140__stack_dtor(obj.as_mut_ptr());
        }
    }

    #[test]
    fn test_stack_push_pop_lifo() {
        let mut obj = [0u8; 8];
        let a = 0xAAAAusize as *const u8;
        let b = 0xBBBBusize as *const u8;
        unsafe {
            msvcp140__stack_ctor(obj.as_mut_ptr());
            msvcp140__stack_push(obj.as_mut_ptr(), a);
            msvcp140__stack_push(obj.as_mut_ptr(), b);
            // dereference the returned reference to get the stored top value
            let top = msvcp140__stack_top(obj.as_ptr());
            assert_eq!(*top, b.cast_mut());
            assert_eq!(msvcp140__stack_pop(obj.as_mut_ptr()), b.cast_mut());
            assert_eq!(msvcp140__stack_pop(obj.as_mut_ptr()), a.cast_mut());
            assert!(msvcp140__stack_empty(obj.as_ptr()));
            msvcp140__stack_dtor(obj.as_mut_ptr());
        }
    }

    #[test]
    fn test_stack_empty_pop_returns_null() {
        let mut obj = [0u8; 8];
        unsafe {
            msvcp140__stack_ctor(obj.as_mut_ptr());
            assert!(msvcp140__stack_pop(obj.as_mut_ptr()).is_null());
            assert!(msvcp140__stack_top(obj.as_ptr()).is_null());
            msvcp140__stack_dtor(obj.as_mut_ptr());
        }
    }
}

// ── Phase 44: std::queue<void*> ───────────────────────────────────────────────

static QUEUE_REGISTRY: Mutex<Option<HashMap<usize, std::collections::VecDeque<usize>>>> =
    Mutex::new(None);

fn with_queue_registry<R>(
    f: impl FnOnce(&mut HashMap<usize, std::collections::VecDeque<usize>>) -> R,
) -> R {
    let mut guard = QUEUE_REGISTRY.lock().unwrap();
    let m = guard.get_or_insert_with(HashMap::new);
    f(m)
}

/// `std::queue<void*>::queue()` — construct an empty queue.
///
/// # Safety
/// `this` must be a non-null pointer to at least 1 byte of writable memory.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcp140__queue_ctor(this: *mut u8) {
    with_queue_registry(|m| {
        m.insert(this as usize, std::collections::VecDeque::new());
    });
}

/// `std::queue<void*>::~queue()` — destroy the queue.
///
/// # Safety
/// `this` must be a pointer previously passed to `msvcp140__queue_ctor`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcp140__queue_dtor(this: *mut u8) {
    with_queue_registry(|m| {
        m.remove(&(this as usize));
    });
}

/// `std::queue<void*>::push(val)` — enqueue `val` at the back.
///
/// # Safety
/// `this` must be a pointer previously passed to `msvcp140__queue_ctor`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcp140__queue_push(this: *mut u8, val: *const u8) {
    with_queue_registry(|m| {
        if let Some(q) = m.get_mut(&(this as usize)) {
            q.push_back(val as usize);
        }
    });
}

/// `std::queue<void*>::pop()` — dequeue the front element and return it (FIFO).
///
/// Note: the real C++ `std::queue::pop()` returns void; this stub returns the
/// dequeued value as a convenience for callers that need it after popping.
/// Returns null if the queue is empty.
///
/// # Safety
/// `this` must be a pointer previously passed to `msvcp140__queue_ctor`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcp140__queue_pop(this: *mut u8) -> *mut u8 {
    with_queue_registry(|m| {
        m.get_mut(&(this as usize))
            .and_then(std::collections::VecDeque::pop_front)
            .map_or(core::ptr::null_mut(), |v| v as *mut u8)
    })
}

/// `std::queue<void*>::front()` — returns a reference (pointer) to the front element.
///
/// Returns a pointer to the stored `void*` element (i.e., `void**`), or null if the
/// queue is empty.  The MSVC mangled name ending in `QEAAAEAPEAXXZ` indicates the C++
/// return type is `void*&`, which is passed as a pointer in the Windows x64 ABI.
///
/// # Safety
/// `this` must be a pointer previously passed to `msvcp140__queue_ctor`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcp140__queue_front(this: *const u8) -> *mut *mut u8 {
    with_queue_registry(|m| {
        m.get_mut(&(this as usize))
            .and_then(|q| q.front_mut())
            // SAFETY: usize and *mut u8 have identical size and alignment on all targets.
            .map_or(core::ptr::null_mut(), |slot| {
                core::ptr::from_mut(slot).cast::<*mut u8>()
            })
    })
}

/// `std::queue<void*>::back()` — returns a reference (pointer) to the back element.
///
/// Returns a pointer to the stored `void*` element (i.e., `void**`), or null if the
/// queue is empty.  The MSVC mangled name ending in `QEAAAEAPEAXXZ` indicates the C++
/// return type is `void*&`, which is passed as a pointer in the Windows x64 ABI.
///
/// # Safety
/// `this` must be a pointer previously passed to `msvcp140__queue_ctor`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcp140__queue_back(this: *const u8) -> *mut *mut u8 {
    with_queue_registry(|m| {
        m.get_mut(&(this as usize))
            .and_then(|q| q.back_mut())
            // SAFETY: usize and *mut u8 have identical size and alignment on all targets.
            .map_or(core::ptr::null_mut(), |slot| {
                core::ptr::from_mut(slot).cast::<*mut u8>()
            })
    })
}

/// `std::queue<void*>::size()` — return the number of elements.
///
/// # Safety
/// `this` must be a pointer previously passed to `msvcp140__queue_ctor`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcp140__queue_size(this: *const u8) -> usize {
    with_queue_registry(|m| {
        m.get(&(this as usize))
            .map_or(0, std::collections::VecDeque::len)
    })
}

/// `std::queue<void*>::empty()` — return true if the queue has no elements.
///
/// # Safety
/// `this` must be a pointer previously passed to `msvcp140__queue_ctor`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcp140__queue_empty(this: *const u8) -> bool {
    with_queue_registry(|m| {
        m.get(&(this as usize))
            .is_none_or(std::collections::VecDeque::is_empty)
    })
}

#[cfg(test)]
mod tests_queue {
    use super::*;

    #[test]
    fn test_queue_ctor_dtor() {
        let mut obj = [0u8; 8];
        unsafe {
            msvcp140__queue_ctor(obj.as_mut_ptr());
            assert_eq!(msvcp140__queue_size(obj.as_ptr()), 0);
            assert!(msvcp140__queue_empty(obj.as_ptr()));
            msvcp140__queue_dtor(obj.as_mut_ptr());
        }
    }

    #[test]
    fn test_queue_push_pop_fifo() {
        let mut obj = [0u8; 8];
        let a = 0xCCCCusize as *const u8;
        let b = 0xDDDDusize as *const u8;
        unsafe {
            msvcp140__queue_ctor(obj.as_mut_ptr());
            msvcp140__queue_push(obj.as_mut_ptr(), a);
            msvcp140__queue_push(obj.as_mut_ptr(), b);
            // dereference the returned references to get the stored values
            let front = msvcp140__queue_front(obj.as_ptr());
            let back = msvcp140__queue_back(obj.as_ptr());
            assert_eq!(*front, a.cast_mut());
            assert_eq!(*back, b.cast_mut());
            assert_eq!(msvcp140__queue_pop(obj.as_mut_ptr()), a.cast_mut());
            assert_eq!(msvcp140__queue_pop(obj.as_mut_ptr()), b.cast_mut());
            assert!(msvcp140__queue_empty(obj.as_ptr()));
            msvcp140__queue_dtor(obj.as_mut_ptr());
        }
    }

    #[test]
    fn test_queue_empty_pop_returns_null() {
        let mut obj = [0u8; 8];
        unsafe {
            msvcp140__queue_ctor(obj.as_mut_ptr());
            assert!(msvcp140__queue_pop(obj.as_mut_ptr()).is_null());
            assert!(msvcp140__queue_front(obj.as_ptr()).is_null());
            assert!(msvcp140__queue_back(obj.as_ptr()).is_null());
            msvcp140__queue_dtor(obj.as_mut_ptr());
        }
    }
}
