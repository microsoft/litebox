// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Run AArch64 Mach-O programs on Apple Silicon.
#![cfg(all(target_os = "macos", target_arch = "aarch64"))]

use anyhow::{Context as _, Result, bail};
use clap::Parser;
use litebox_common_macos::TaskParams;
use litebox_platform_macos_userland::{GuestAbi, MacosUserland, set_guest_abi};
#[cfg(not(feature = "test-broker"))]
use litebox_shim_macos::MacosShimBuilder;
#[cfg(feature = "test-broker")]
use std::path::PathBuf;
use std::{ffi::CString, io::Read as _};

#[derive(Parser, Debug)]
#[command(
    about = "Run AArch64 Mach-O programs (dynamic loading requires development-only test-broker)"
)]
pub struct CliArgs {
    /// Host path of a thin or universal Mach-O, followed by guest arguments.
    /// Default builds accept only statically linked programs.
    /// Executable-defined thread-local variables are currently unsupported.
    #[arg(required = true, trailing_var_arg = true, value_hint = clap::ValueHint::CommandWithArguments)]
    pub program_and_arguments: Vec<String>,
    /// Guest environment entry (KEY=VALUE). Host environment is not forwarded.
    #[arg(long = "env")]
    pub environment_variables: Vec<String>,
    /// Host Mach-O exposed at /mmap-image for mmap rewriting tests.
    #[cfg(feature = "test-broker")]
    #[arg(long, hide = true, value_hint = clap::ValueHint::FilePath)]
    pub test_mmap_image: Option<PathBuf>,
}

mod isolation;
mod live_cache;
#[cfg(feature = "test-broker")]
mod test_broker;

pub fn run(cli_args: CliArgs) -> Result<i32> {
    set_guest_abi(GuestAbi::Darwin);
    let Some(path) = cli_args.program_and_arguments.first() else {
        bail!("missing program");
    };
    // Bound allocation even if the file grows; one extra byte detects oversized input.
    let mut data = Vec::new();
    std::fs::File::open(path)
        .with_context(|| format!("opening {path}"))?
        .take(litebox_common_macos::loader::MAX_IMAGE_SIZE as u64 + 1)
        .read_to_end(&mut data)
        .with_context(|| format!("reading {path}"))?;
    if data.len() > litebox_common_macos::loader::MAX_IMAGE_SIZE {
        bail!("Mach-O file larger than 256 MiB: {path}");
    }
    let argv = cli_args
        .program_and_arguments
        .iter()
        .map(|s| CString::new(s.as_bytes()))
        .collect::<Result<Vec<_>, _>>()
        .context("NUL in program argument")?;
    let envp = cli_args
        .environment_variables
        .iter()
        .map(|s| CString::new(s.as_bytes()))
        .collect::<Result<Vec<_>, _>>()
        .context("NUL in environment entry")?;
    let parsed = litebox_common_macos::loader::arm64_slice(&data)
        .ok()
        .and_then(|image| litebox_common_macos::loader::MachoParsedFile::parse(image).ok());
    let dynamic = parsed.as_ref().is_some_and(|image| image.uses_dyld);
    #[cfg(not(feature = "test-broker"))]
    if dynamic {
        bail!(
            "dynamic executables require broker support; build with the development-only test-broker feature"
        );
    }
    if parsed.is_some_and(|image| image.has_tlv_descriptors) {
        // The initialized shared cache has working TLVs, but the private dyld
        // skips libSystem initialization and does not set up executable TLVs.
        bail!("executable-defined thread-local variables require unsupported TLV initialization");
    }
    litebox_platform_macos_userland::set_darwin_private_thread_state(dynamic);
    if dynamic {
        // SAFETY: standalone runner startup is single-threaded here, before
        // broker/platform initialization. Only the child modifies the live cache.
        if let Some(status) = unsafe { isolation::fork_and_wait() }? {
            return Ok(status);
        }
    }
    if dynamic {
        unsafe extern "C" {
            static __stdoutp: *mut libc::FILE;
        }
        // The disposable child skips libc process teardown. Keep its C stdout
        // unbuffered so ordinary printf/return-from-main cannot strand output.
        // This is a runner policy, not general host/guest FILE isolation.
        // SAFETY: initialized native stdout, configured before any guest entry.
        if unsafe { libc::setvbuf(__stdoutp, core::ptr::null_mut(), libc::_IONBF, 0) } != 0 {
            bail!("configuring unbuffered guest stdout");
        }
    }
    let platform = MacosUserland::new();
    #[cfg(not(feature = "test-broker"))]
    let builder = MacosShimBuilder::new(platform);
    #[cfg(feature = "test-broker")]
    let (builder, stdio) = {
        let mmap_image = cli_args
            .test_mmap_image
            .as_deref()
            .map(std::fs::read)
            .transpose()
            .context("reading mmap test image")?;
        // Only the dynamic loader also needs a separate view of the executable.
        let executable = if dynamic {
            data.clone()
        } else {
            std::mem::take(&mut data)
        };
        test_broker::setup(platform, executable, mmap_image.as_deref())?
    };
    let shim = builder.build();
    // PID 1 is launchd on Darwin. Dyld gives it process-global responsibilities,
    // including computing shared-cache root policy and publishing commpage flags.
    // A normally launched LiteBox guest must not enter that launchd-only path.
    let task_params = if dynamic {
        TaskParams {
            pid: 2,
            ppid: 1,
            ..TaskParams::default()
        }
    } else {
        TaskParams::default()
    };
    let shared_cache_instance = dynamic
        .then(|| live_cache::PrivateSharedCacheInstance::instantiate(platform))
        .transpose()
        .context("instantiating private dyld cache")?;
    #[cfg(feature = "test-broker")]
    let program = if let Some(cache) = &shared_cache_instance {
        shim.load_program_with_dyld(
            task_params,
            "/executable",
            &data,
            litebox_shim_macos::DyldImage {
                data: &cache.dyld,
                thread_pointer: litebox_shim_macos::DyldThreadPointerMode::Native,
            },
            argv,
            envp,
        )
    } else {
        shim.load_program(task_params, "/executable", argv, envp)
    };
    #[cfg(not(feature = "test-broker"))]
    let program = shim.load_program_from_bytes(task_params, path, &data, argv, envp);
    let program = program.context("loading Mach-O")?;
    if let Some(cache) = &shared_cache_instance {
        let regions: Vec<_> = cache
            .regions
            .iter()
            .map(|region| litebox_shim_macos::SharedCacheRegion {
                range: region.address..region.address + region.length,
                writable_alias: region.alias.address(),
                guest_ranges: &[],
                host_aware_ranges: &region.code_ranges,
                native_thread_pointer_ranges: &region.native_tpidrro_ranges,
            })
            .collect();
        let layout = litebox_shim_macos::SharedCacheLayout {
            range: cache.range.clone(),
            mappings: &cache.mappings,
            executable_regions: &regions,
            trampoline: litebox_shim_macos::SharedCacheTrampoline {
                range: cache.trampoline_address..cache.trampoline_address + cache.trampoline_length,
                writable_alias: cache.trampoline.address(),
            },
        };
        program
            .install_shared_cache(&layout)
            .context("rewriting private dyld cache")?;
    }
    if dynamic {
        litebox_platform_macos_userland::suspend_exception_handlers_for_cache_rewrite()
            .context("suspending exception handlers for cache rewrite")?;
    }
    let tpro_ranges = shared_cache_instance
        .as_ref()
        .map(|cache| cache.tpro_ranges.clone())
        .unwrap_or_default();
    shared_cache_instance
        .map(|cache| {
            // SAFETY: this is the isolated fork child, exception handlers are
            // suspended, and no other thread may enter the cache during publication.
            unsafe { cache.commit() }
        })
        .transpose()
        .context("publishing private dyld cache")?;
    for range in tpro_ranges {
        // SAFETY: the isolated child exclusively controls these cache ranges
        // while handlers and guest execution remain stopped.
        unsafe { litebox_platform_macos_userland::make_shared_cache_range_writable(range) }
            .map_err(|error| anyhow::anyhow!("making dyld TPRO writable: {error:?}"))?;
    }
    if dynamic {
        litebox_platform_macos_userland::enable_rewritten_host_sigreturn();
        // Native thread destructors and shared libdyld may still reference guest
        // storage after join/guest exit. This child is one-shot: keep mappings
        // until raw process exit, while allowing guest task records to retire.
        std::mem::forget(program.retain_runtime_resources());
    }
    let litebox_shim_macos::LoadedProgram {
        entrypoints,
        process,
        mut initial_ctx,
    } = program;
    // SAFETY: the loader owns valid mappings and has finalized Darwin gates;
    // entrypoints retain those mappings until guest execution stops.
    unsafe {
        litebox_platform_macos_userland::run_thread(entrypoints, &mut initial_ctx);
    }
    finish_guest(dynamic, process.exit_status(), || {
        #[cfg(feature = "test-broker")]
        test_broker::flush_output(&stdio)?;
        Ok(())
    })
}

fn finish_guest(
    dynamic: bool,
    status: Option<i32>,
    flush_output: impl FnOnce() -> Result<()>,
) -> Result<i32> {
    // Preserve captured output even when the shim stopped without an exit status.
    let result =
        flush_output().and_then(|()| status.context("guest stopped without an exit status"));
    if dynamic {
        let status = result.unwrap_or_else(|error| {
            eprintln!("finishing macOS guest: {error:#}");
            1
        });
        // SAFETY: this one-shot child cannot run ordinary host teardown after
        // guest execution. Darwin SYS_exit consumes x0 and never returns.
        unsafe {
            core::arch::asm!(
                "svc #0x80",
                in("x0") status,
                in("x16") 1usize,
                options(noreturn),
            );
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_exit_status_still_flushes_output() {
        let flushed = core::cell::Cell::new(false);
        let result = finish_guest(false, None, || {
            flushed.set(true);
            Ok(())
        });
        assert!(flushed.get());
        assert!(result.is_err());
        assert_eq!(finish_guest(false, Some(23), || Ok(())).unwrap(), 23);
    }

    #[test]
    fn dynamic_finish_errors_use_raw_exit() {
        use std::io::Write as _;
        const CHILD: &str = "LITEBOX_TEST_DYNAMIC_FINISH";
        extern "C" fn native_cleanup() {
            let marker = b"unexpected native cleanup";
            // SAFETY: marker is live readable storage and stdout is the parent's capture pipe.
            unsafe { libc::write(1, marker.as_ptr().cast(), marker.len()) };
        }
        if let Ok(mode) = std::env::var(CHILD) {
            // SAFETY: this callback remains valid until this test child exits.
            assert_eq!(unsafe { libc::atexit(native_cleanup) }, 0);
            let result = finish_guest(true, (mode == "flush").then_some(0), || {
                std::io::stdout().write_all(b"captured output")?;
                std::io::stdout().flush()?;
                if mode == "flush" {
                    bail!("test flush failure");
                }
                Ok(())
            });
            panic!("dynamic finish returned: {result:?}");
        }
        for mode in ["status", "flush"] {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "tests::dynamic_finish_errors_use_raw_exit",
                    "--nocapture",
                    "--quiet",
                ])
                .env(CHILD, mode)
                .output()
                .unwrap();
            assert_eq!(output.status.code(), Some(1), "{output:?}");
            let stdout = String::from_utf8(output.stdout).unwrap();
            assert!(stdout.ends_with("captured output"), "{stdout}");
            assert!(!stdout.contains("unexpected native cleanup"), "{stdout}");
        }
    }
}
