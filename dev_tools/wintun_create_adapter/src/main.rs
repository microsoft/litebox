// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Standalone tool to create a WinTUN adapter.
//!
//! Run this as Administrator *once* to create the adapter before starting the
//! litebox runner.  The adapter persists across reboots until explicitly
//! deleted.
//!
//! Usage:
//!     wintun_create_adapter [ADAPTER_NAME]
//!
//! Defaults to "litebox0" if no name is given.
//! Expects `wintun.dll` next to the executable (or on PATH).

#[cfg(not(windows))]
fn main() {
    eprintln!("This tool only works on Windows.");
    std::process::exit(1);
}

#[cfg(windows)]
fn main() {
    use windows_sys::Win32::Foundation::{GetLastError, HANDLE, HMODULE};
    use windows_sys::Win32::System::LibraryLoader::LoadLibraryW;

    let adapter_name = std::env::args().nth(1).unwrap_or_else(|| "litebox0".into());

    let dll_path = find_wintun_dll();
    eprintln!("Loading {dll_path}");

    let wide = |s: &str| -> Vec<u16> { s.encode_utf16().chain(std::iter::once(0)).collect() };

    // Load wintun.dll
    let module: HMODULE = unsafe { LoadLibraryW(wide(&dll_path).as_ptr()) };
    if module.is_null() {
        let err = unsafe { GetLastError() };
        eprintln!("Failed to load {dll_path}: Win32 error {err}");
        std::process::exit(1);
    }

    // Resolve WintunOpenAdapter and WintunCreateAdapter.
    type OpenFn = unsafe extern "system" fn(*const u16) -> HANDLE;
    type CreateFn = unsafe extern "system" fn(*const u16, *const u16, *const u8) -> HANDLE;
    type CloseFn = unsafe extern "system" fn(HANDLE);

    let open: OpenFn = resolve(module, b"WintunOpenAdapter\0");
    let create: CreateFn = resolve(module, b"WintunCreateAdapter\0");
    let close: CloseFn = resolve(module, b"WintunCloseAdapter\0");

    let w_name = wide(&adapter_name);
    let w_type = wide("litebox");

    // Try opening first.
    let adapter: HANDLE = unsafe { open(w_name.as_ptr()) };
    if !adapter.is_null() {
        eprintln!("Adapter '{adapter_name}' already exists — nothing to do.");
        unsafe { close(adapter) };
        std::process::exit(0);
    }

    // Create.
    let adapter: HANDLE = unsafe { create(w_name.as_ptr(), w_type.as_ptr(), std::ptr::null()) };
    if adapter.is_null() {
        let err = unsafe { GetLastError() };
        eprintln!("WintunCreateAdapter('{adapter_name}') failed: Win32 error {err}");
        eprintln!("Make sure you are running as Administrator.");
        std::process::exit(1);
    }

    eprintln!("Created WinTUN adapter '{adapter_name}' successfully.");
    unsafe { close(adapter) };
}

#[cfg(windows)]
fn find_wintun_dll() -> String {
    // Look next to the executable first.
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let candidate = dir.join("wintun.dll");
            if candidate.exists() {
                return candidate.to_string_lossy().into_owned();
            }
        }
    }
    "wintun.dll".into()
}

#[cfg(windows)]
fn resolve<T: Copy>(module: windows_sys::Win32::Foundation::HMODULE, name: &[u8]) -> T {
    let proc =
        unsafe { windows_sys::Win32::System::LibraryLoader::GetProcAddress(module, name.as_ptr()) };
    match proc {
        Some(p) => unsafe { std::mem::transmute_copy(&p) },
        None => {
            let fn_name = std::str::from_utf8(&name[..name.len() - 1]).unwrap_or("?");
            eprintln!("GetProcAddress failed for {fn_name}");
            std::process::exit(1);
        }
    }
}
