// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Restrict this crate to only work on Windows. For now, we are restricting this to only x86-64
// Windows, but we _may_ allow for more in the future, if we find it useful to do so.
#![cfg(all(target_os = "windows", target_arch = "x86_64"))]

extern crate alloc;

use anyhow::{Context as _, Result};
use clap::Parser;
use litebox_broker_transport_windows_userland::broker;
use litebox_platform_windows_userland::WindowsUserland;
use memmap2::Mmap;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

type HostNtGdiInit2 = unsafe extern "system" fn() -> isize;

#[link(name = "kernel32")]
unsafe extern "system" {
    fn LoadLibraryW(name: *const u16) -> *mut core::ffi::c_void;
    fn GetProcAddress(module: *mut core::ffi::c_void, name: *const u8) -> Option<HostNtGdiInit2>;
}

fn host_nt_gdi_init2(guest_peb: usize) -> usize {
    const PEB_SHARED_DATA_OFFSET: usize = 0xf8;
    static CALLBACK: OnceLock<Option<HostNtGdiInit2>> = OnceLock::new();
    let callback = CALLBACK.get_or_init(|| {
        const USER32_DLL: &[u16] = &[
            b'u' as u16,
            b's' as u16,
            b'e' as u16,
            b'r' as u16,
            b'3' as u16,
            b'2' as u16,
            b'.' as u16,
            b'd' as u16,
            b'l' as u16,
            b'l' as u16,
            0,
        ];
        const WIN32U_DLL: &[u16] = &[
            b'w' as u16,
            b'i' as u16,
            b'n' as u16,
            b'3' as u16,
            b'2' as u16,
            b'u' as u16,
            b'.' as u16,
            b'd' as u16,
            b'l' as u16,
            b'l' as u16,
            0,
        ];
        // SAFETY: `USER32_DLL` is a static, NUL-terminated UTF-16 string.
        // Loading User32 initializes the process kernel callback table used by
        // Win32u services before NtGdiInit2 can trigger a user-mode callback.
        if unsafe { LoadLibraryW(USER32_DLL.as_ptr()) }.is_null() {
            return None;
        }
        // SAFETY: `WIN32U_DLL` is a static, NUL-terminated UTF-16 string.
        let module = unsafe { LoadLibraryW(WIN32U_DLL.as_ptr()) };
        if module.is_null() {
            return None;
        }
        // SAFETY: the module remains loaded for the process lifetime and the
        // export name is a static, NUL-terminated byte string.
        unsafe { GetProcAddress(module, c"NtGdiInit2".as_ptr().cast()) }
    });
    let Some(callback) = callback else {
        litebox_util_log::error!("Failed to resolve host win32u!NtGdiInit2");
        return 0;
    };
    // SAFETY: the cached function was resolved and typed above, and Win32u
    // remains loaded for the lifetime of the process.
    let result = unsafe { callback() }.cast_unsigned();

    let host_peb: usize;
    // SAFETY: on x86-64 Windows, GS points to the host TEB and TEB+0x60 is
    // the current process's PEB pointer.
    unsafe {
        core::arch::asm!(
            "mov {}, gs:[0x60]",
            out(reg) host_peb,
            options(nostack, preserves_flags, readonly),
        );
    }
    // SAFETY: both PEB addresses are valid for the lifetime of their process.
    // NtGdiInit2 initialized the host PEB's SharedData field, which guest
    // GDI32Full expects the syscall to initialize in its own PEB as well.
    unsafe {
        let shared_data = ((host_peb + PEB_SHARED_DATA_OFFSET) as *const usize).read();
        ((guest_peb + PEB_SHARED_DATA_OFFSET) as *mut usize).write(shared_data);
    }

    result
}

fn mmapped_file(path: impl AsRef<Path>) -> Result<&'static [u8]> {
    let path = path.as_ref();
    let file = std::fs::File::open(path)
        .with_context(|| format!("Could not open tar file at {}", path.display()))?;
    let data = {
        // SAFETY: The runner maps the input read-only and does not modify it. The caller must ensure
        // the tar file is not modified externally while the guest is running.
        //
        // Leak the mapping so the borrowed tar data remains valid for the process-lifetime file
        // system.
        Box::leak(Box::new(unsafe { Mmap::map(&file) }.with_context(
            || format!("Could not map tar file at {}", path.display()),
        )?))
    };
    Ok(data)
}

/// Run Windows PE programs with LiteBox on unmodified Windows.
///
/// The program binary and any initial filesystem contents must be provided inside a tar archive via
/// `--initial-files`. The program path refers to a path inside the tar archive.
#[derive(Parser, Debug)]
pub struct CliArgs {
    /// The program and arguments passed to it (e.g., `/app/program.exe --help`).
    ///
    /// The program path refers to a path inside the tar archive provided via `--initial-files`.
    #[arg(required = true, trailing_var_arg = true, value_hint = clap::ValueHint::CommandWithArguments)]
    pub program_and_arguments: Vec<String>,
    /// Environment variables passed to the program (`K=V` pairs; can be invoked multiple times).
    #[arg(long = "env")]
    pub environment_variables: Vec<String>,
    /// Forward the existing environment variables.
    #[arg(long = "forward-env")]
    pub forward_environment_variables: bool,
    /// Allow using unstable options.
    #[arg(short = 'Z', long = "unstable")]
    pub unstable: bool,
    /// Broker-supplied Windows named-pipe path for the local control channel.
    #[arg(
        long = "broker-control-channel",
        value_name = "PIPE_NAME",
        hide = true,
        requires = "unstable",
        help_heading = "Unstable Options"
    )]
    pub broker_control_channel: Option<std::ffi::OsString>,
    /// Tar archive containing the program and its runtime files.
    #[arg(long = "initial-files", value_name = "PATH_TO_TAR", value_hint = clap::ValueHint::FilePath)]
    pub initial_files: PathBuf,
}

/// Run Windows PE programs with LiteBox on unmodified Windows.
///
/// # Panics
///
/// Panics if the initial in-memory file system fails to create `/tmp` — those
/// operations cannot fail against a freshly-constructed file system.
pub fn run(cli_args: CliArgs) -> Result<()> {
    tracing_subscriber::fmt()
        .with_timer(tracing_subscriber::fmt::time::uptime())
        .with_level(true)
        .with_env_filter(
            tracing_subscriber::EnvFilter::builder()
                .with_env_var("LITEBOX_LOG")
                .from_env_lossy(),
        )
        .init();

    let tar_file = &cli_args.initial_files;
    if tar_file.extension().and_then(|x| x.to_str()) != Some("tar") {
        anyhow::bail!("Expected a .tar file, found {}", tar_file.display());
    }
    let tar_data = mmapped_file(tar_file)?;

    let platform = WindowsUserland::new();
    let broker_connection = cli_args
        .broker_control_channel
        .as_deref()
        .map(broker::connect)
        .transpose()?;
    let shim_builder = if let Some(broker_connection) = broker_connection {
        let broker::BrokerConnection {
            local,
            notifications,
        } = broker_connection;
        let litebox = litebox::LiteBox::new_with_broker_local(platform, local);
        broker::start_notification_receiver(
            notifications,
            litebox.broker_notification_dispatcher(),
            litebox.broker_failure_dispatcher(),
        )?;
        litebox_shim_windows::WindowsShimBuilder::new_with_litebox(platform, litebox)
            .with_nt_gdi_init2(host_nt_gdi_init2)
    } else {
        litebox_shim_windows::WindowsShimBuilder::new(platform).with_nt_gdi_init2(host_nt_gdi_init2)
    };
    let litebox = shim_builder.litebox();

    let (program_path, program_args) = cli_args
        .program_and_arguments
        .split_first()
        .context("program path missing — clap should have required at least one argument")?;

    let initial_file_system = {
        let mut in_mem = litebox::fs::in_mem::FileSystem::new(litebox);
        in_mem.with_root_privileges(|fs| {
            use litebox::fs::FileSystem as _;
            fs.mkdir(
                "/tmp",
                litebox::fs::Mode::RWXU | litebox::fs::Mode::RWXG | litebox::fs::Mode::RWXO,
            )
            .expect("/tmp creation cannot fail on a fresh in-memory file system");
            fs.chown("/tmp", Some(1000), Some(1000))
                .expect("/tmp chown cannot fail on a fresh in-memory file system");
        });

        shim_builder.default_fs(in_mem, tar_data.into())
    };
    let initial_file_system = std::sync::Arc::new(initial_file_system);

    let shim = shim_builder.build();
    let argv = std::iter::once(program_path.as_str())
        .chain(program_args.iter().map(String::as_str))
        .map(to_cstring)
        .collect::<Result<Vec<_>>>()
        .context("argv contained an interior NUL byte")?;
    let mut envp = cli_args
        .environment_variables
        .iter()
        .map(|s| to_cstring(s))
        .collect::<Result<Vec<_>>>()
        .context("--env value contained an interior NUL byte")?;
    if cli_args.forward_environment_variables {
        for (key, value) in std::env::vars() {
            envp.push(
                to_cstring(&format!("{key}={value}"))
                    .context("forwarded environment variable contained an interior NUL byte")?,
            );
        }
    }

    let program = shim
        .load_program(initial_file_system, program_path, argv, envp)
        .context("failed to load Windows PE program")?;
    // SAFETY: `WindowsShimEntrypoints::init` populates `rip`/`rsp`/`eflags` inside
    // `run_thread` before the initial guest thread executes, so the `PtRegs::default()`
    // we hand in is fully initialized before any guest instruction runs.
    unsafe {
        litebox_platform_windows_userland::run_thread(
            program.entrypoints,
            &mut litebox_common_linux::PtRegs::default(),
        );
    }
    std::process::exit(program.process.wait())
}

fn to_cstring(s: &str) -> Result<std::ffi::CString> {
    std::ffi::CString::new(s.as_bytes()).map_err(Into::into)
}
