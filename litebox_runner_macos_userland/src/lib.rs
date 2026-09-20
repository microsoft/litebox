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
#[command(about = "Run AArch64 Mach-O programs with a private boot-local dyld cache")]
pub struct CliArgs {
    /// Host path of a thin or universal Mach-O, followed by guest arguments.
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
    let mut argv = cli_args
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
    let dynamic = litebox_common_macos::loader::arm64_slice(&data)
        .ok()
        .and_then(|image| litebox_common_macos::loader::MachoParsedFile::parse(image).ok())
        .is_some_and(|image| image.uses_dyld);
    #[cfg(feature = "test-broker")]
    if dynamic {
        argv[0] = CString::new("/executable").context("invalid guest executable path")?;
    }
    litebox_platform_macos_userland::set_darwin_private_thread_state(dynamic);
    if dynamic {
        let pid = unsafe { libc::fork() };
        if pid < 0 {
            return Err(std::io::Error::last_os_error()).context("forking macOS guest runner");
        }
        if pid > 0 {
            let mut status = 0;
            if unsafe { libc::waitpid(pid, &raw mut status, 0) } != pid {
                return Err(std::io::Error::last_os_error())
                    .context("waiting for macOS guest runner");
            }
            if libc::WIFEXITED(status) {
                return Ok(libc::WEXITSTATUS(status));
            }
            if libc::WIFSIGNALED(status) {
                return Ok(128 + libc::WTERMSIG(status));
            }
            bail!("unexpected macOS guest child status {status:#x}");
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
        test_broker::setup(platform, data.clone(), mmap_image.as_deref())?
    };
    let shim = builder.build();
    let shared_cache_instance = dynamic
        .then(live_cache::PrivateSharedCacheInstance::instantiate)
        .transpose()
        .context("instantiating private dyld cache")?;
    #[cfg(feature = "test-broker")]
    let program = if let Some(cache) = &shared_cache_instance {
        shim.load_program_with_dyld(
            TaskParams::default(),
            "/executable",
            &data,
            &cache.dyld,
            argv,
            envp,
        )
    } else {
        shim.load_program(TaskParams::default(), "/executable", argv, envp)
    };
    #[cfg(not(feature = "test-broker"))]
    let program = if let Some(cache) = &shared_cache_instance {
        shim.load_program_with_dyld(TaskParams::default(), path, &data, &cache.dyld, argv, envp)
    } else {
        shim.load_program_from_bytes(TaskParams::default(), path, &data, argv, envp)
    };
    let program = program.context("loading Mach-O")?;
    if let Some(cache) = &shared_cache_instance {
        let regions: Vec<_> = cache
            .regions
            .iter()
            .map(|region| litebox_shim_macos::LiveSharedCacheRegion {
                range: region.address..region.address + region.length,
                writable_alias: region.alias.address(),
                code_ranges: &region.code_ranges,
                native_tpidrro_ranges: &region.native_tpidrro_ranges,
            })
            .collect();
        let layout = litebox_shim_macos::LiveSharedCache {
            range: cache.range.clone(),
            mappings: &cache.mappings,
            executable_regions: &regions,
            trampoline: litebox_shim_macos::LiveSharedCacheTrampoline {
                range: cache.trampoline_address..cache.trampoline_address + cache.trampoline_length,
                writable_alias: cache.trampoline.address(),
            },
        };
        program
            .adopt_live_shared_cache(&layout)
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
    #[cfg(feature = "test-broker")]
    test_broker::flush_output(&stdio)?;
    let status = process
        .exit_status()
        .context("guest stopped without an exit status")?;
    if dynamic {
        unsafe {
            core::arch::asm!(
                "svc #0x80",
                in("x0") status,
                in("x16") 1usize,
                options(noreturn),
            );
        }
    }
    Ok(status)
}
