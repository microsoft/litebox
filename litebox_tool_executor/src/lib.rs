// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! A sandboxed tool executor built on LiteBox.
//!
//! Runs Linux commands inside LiteBox on Windows, capturing stdout, stderr,
//! exit code, and a structured syscall audit trail. Designed for integration
//! with LLM coding agents.

#![cfg(all(target_os = "windows", target_arch = "x86_64"))]

extern crate alloc;

pub mod protocol;

use anyhow::{Result, anyhow};
use litebox_platform_multiplex::Platform;
use protocol::{ToolRequest, ToolResult};
use std::path::Path;

/// Execute a command inside a LiteBox sandbox.
///
/// `tar_data` is the raw bytes of a `.tar` archive containing syscall-rewritten
/// Linux ELF binaries. `request` specifies the command, environment, and any
/// files to inject. `policy` optionally restricts what the guest may do.
///
/// Returns a [`ToolResult`] with captured output and audit trail.
///
/// # Panics
///
/// May panic if the platform or filesystem setup encounters an unexpected state.
pub fn execute(
    tar_data: Vec<u8>,
    request: &ToolRequest,
    policy: Option<litebox_shim_linux::policy::SandboxPolicy>,
) -> Result<ToolResult> {
    // Disable the Windows console's built-in echo and line-input mode.
    // When running interactively (e.g., via a VS Code terminal), the ConPTY
    // echoes keystrokes by default. But busybox's shell also echoes input,
    // causing double-echo. We switch to raw mode so only the guest's echo
    // is visible, matching how a Linux terminal works (the application
    // controls echo via the tty, not the terminal emulator).
    disable_console_echo();

    // Install the sandbox policy before any guest code runs.
    if let Some(pol) = policy {
        litebox_shim_linux::policy::set_policy(pol);
    }

    // Leak the tar data so it has a 'static lifetime, as required by the
    // read-only filesystem layer. This is acceptable because each execute()
    // call runs a short-lived guest program and then the process exits.
    let tar_data: &'static [u8] = Vec::leak(tar_data);

    // --- Platform & shim setup (mirrors litebox_runner_linux_on_windows_userland::run) ---
    let platform = Platform::new();
    litebox_platform_multiplex::set_platform(platform);
    let shim_builder = litebox_shim_linux::LinuxShimBuilder::new();
    let litebox_instance = shim_builder.litebox();

    // Build the layered filesystem: writable in-mem on top of read-only tar.
    let mut in_mem = litebox::fs::in_mem::FileSystem::new(litebox_instance);
    in_mem.with_root_privileges(|fs| {
        use litebox::fs::FileSystem as _;
        fs.mkdir(
            "/tmp",
            litebox::fs::Mode::RWXU | litebox::fs::Mode::RWXG | litebox::fs::Mode::RWXO,
        )
        .unwrap();
        fs.chown("/tmp", Some(1000), Some(1000)).unwrap();
        fs.mkdir(
            "/workspace",
            litebox::fs::Mode::RWXU | litebox::fs::Mode::RWXG | litebox::fs::Mode::RWXO,
        )
        .unwrap();
        fs.chown("/workspace", Some(1000), Some(1000)).unwrap();
    });

    let tar_ro = litebox::fs::tar_ro::FileSystem::new(litebox_instance, tar_data.into());
    let fs = shim_builder.default_fs(in_mem, tar_ro);

    // --- Inject requested files into the in-memory FS layer ---
    for (path, contents) in &request.files {
        // Ensure parent directories exist.
        if let Some(parent) = Path::new(path).parent() {
            let parent_str = parent.to_str().unwrap_or("/");
            if parent_str != "/" {
                let _ = litebox::fs::FileSystem::mkdir(
                    &fs,
                    parent_str,
                    litebox::fs::Mode::RWXU | litebox::fs::Mode::RWXG | litebox::fs::Mode::RWXO,
                );
            }
        }
        let fd = litebox::fs::FileSystem::open(
            &fs,
            path,
            litebox::fs::OFlags::CREAT | litebox::fs::OFlags::WRONLY,
            litebox::fs::Mode::RWXU | litebox::fs::Mode::RWXG | litebox::fs::Mode::RWXO,
        )
        .map_err(|e| anyhow!("Failed to create file {path}: {e:?}"))?;
        litebox::fs::FileSystem::write(&fs, &fd, contents, None)
            .map_err(|e| anyhow!("Failed to write file {path}: {e:?}"))?;
        litebox::fs::FileSystem::close(&fs, &fd)
            .map_err(|e| anyhow!("Failed to close file {path}: {e:?}"))?;
    }

    let fs = std::sync::Arc::new(fs);

    // --- Prepare argv and envp ---
    if request.command.is_empty() {
        anyhow::bail!("command must not be empty");
    }
    let prog_path = &request.command[0];
    let argv: Vec<_> = request
        .command
        .iter()
        .map(|s| std::ffi::CString::new(s.as_bytes()).unwrap())
        .collect();
    let mut envp: Vec<_> = request
        .env
        .iter()
        .map(|s| std::ffi::CString::new(s.as_bytes()).unwrap())
        .collect();
    // Inject LD_AUDIT for dynamic linker trampoline support.
    let ld_audit = c"LD_AUDIT=/lib/litebox_rtld_audit.so";
    if !envp.iter().any(|v| v.as_c_str() == ld_audit) {
        envp.push(ld_audit.into());
    }

    // --- Load and run the program ---
    let shim = shim_builder.build();
    let program = shim
        .load_program(fs, platform.init_task(), prog_path, argv, envp)
        .map_err(|e| anyhow!("Failed to load program {prog_path}: {e:?}"))?;

    // Safety: run_thread executes the guest program on the current thread.
    // This is the same pattern used by the existing runner.
    unsafe {
        litebox_platform_windows_userland::run_thread(
            program.entrypoints,
            &mut litebox_common_linux::PtRegs::default(),
        );
    }

    let exit_code = program.process.wait();

    // Audit events were emitted to stderr via DebugLogProvider during execution.
    // In this initial version, we don't capture them into the ToolResult —
    // they flow to the host's stderr for external collection.
    // TODO: intercept DebugLogProvider output into a buffer for programmatic access.
    Ok(ToolResult {
        stdout: String::new(), // stdout went directly to host stdout via StdioProvider
        stderr: String::new(), // stderr went directly to host stderr via StdioProvider
        exit_code,
        audit_log: Vec::new(),
        timed_out: false,
    })
}

/// Disable the Windows console's ECHO and LINE_INPUT modes on stdin.
///
/// This prevents the ConPTY from echoing keystrokes (the guest shell handles
/// its own echo) and switches to character-at-a-time input (the guest shell
/// handles its own line editing).
fn disable_console_echo() {
    use std::os::windows::io::AsRawHandle as _;
    use windows_sys::Win32::System::Console::{
        ENABLE_ECHO_INPUT, ENABLE_LINE_INPUT, ENABLE_PROCESSED_INPUT, GetConsoleMode,
        SetConsoleMode,
    };

    let stdin_handle = std::io::stdin().as_raw_handle();
    let mut mode: u32 = 0;
    // Safety: stdin_handle is a valid console handle when running in a terminal.
    // GetConsoleMode will fail (return 0) if stdin is a pipe — harmless.
    let ok = unsafe { GetConsoleMode(stdin_handle, &mut mode) };
    if ok == 0 {
        return; // stdin is not a console (piped input) — nothing to do.
    }
    // Disable echo and line-buffering. Keep ENABLE_PROCESSED_INPUT so Ctrl+C
    // still works.
    let new_mode = (mode & !(ENABLE_ECHO_INPUT | ENABLE_LINE_INPUT)) | ENABLE_PROCESSED_INPUT;
    // Safety: same handle, valid mode bits.
    unsafe {
        SetConsoleMode(stdin_handle, new_mode);
    }
}
