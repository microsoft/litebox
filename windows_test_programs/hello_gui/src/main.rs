// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Simple GUI "Hello World" program for testing Windows-on-Linux platform

#![windows_subsystem = "windows"]

use windows::{
    core::{w, Result},
    Win32::System::LibraryLoader::GetModuleHandleW,
    Win32::UI::WindowsAndMessaging::{MessageBoxW, MB_ICONINFORMATION, MB_OK},
};

fn main() -> Result<()> {
    // SAFETY: Calling Windows API functions (GetModuleHandleW and MessageBoxW)
    // is safe because:
    // 1. GetModuleHandleW(None) returns the handle of the current module
    // 2. MessageBoxW receives valid static string literals via the w! macro
    // 3. Both functions are standard Windows API calls provided by the windows crate
    unsafe {
        let instance = GetModuleHandleW(None)?;
        debug_assert!(!instance.is_invalid());

        let message = w!("Hello LiteBox!\n\nThis is a Windows GUI program running on Linux.");
        let title = w!("LiteBox Test");

        MessageBoxW(None, message, title, MB_OK | MB_ICONINFORMATION);
    }

    Ok(())
}
