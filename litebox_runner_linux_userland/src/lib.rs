// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use anyhow::{Context as _, Result, anyhow};
use clap::Parser;
use litebox::fs::{FileSystem as _, FileType, Mode, OFlags};
use litebox_broker_core::socket::BROKER_DNS_IPV4_ADDRESS;
use litebox_platform_linux_userland::LinuxUserland as Platform;
use memmap2::Mmap;
use std::os::linux::fs::MetadataExt as _;
use std::path::{Path, PathBuf};

mod broker;

extern crate alloc;

// Use a stable non-root guest identity instead of mirroring the host user. This keeps shim
// credentials aligned with the in-memory filesystem default user and avoids truncating high host IDs.
const DEFAULT_GUEST_UID: u16 = 1000;
const DEFAULT_GUEST_GID: u16 = 1000;
const MAX_NSSWITCH_SIZE: usize = 64 * 1024;
const GENERATED_NSS_HOSTS: &[u8] = b"hosts: files dns\n";

fn path_is_missing_or_unreachable(error: &litebox::fs::errors::PathError) -> bool {
    matches!(
        error,
        litebox::fs::errors::PathError::NoSuchFileOrDirectory
            | litebox::fs::errors::PathError::MissingComponent
            | litebox::fs::errors::PathError::ComponentNotADirectory
            | litebox::fs::errors::PathError::NoSearchPerms { .. }
    )
}

fn read_lower_nsswitch(
    lower: &litebox_shim_linux::DefaultLowerFS<Platform>,
) -> Result<Option<Vec<u8>>> {
    let status = match lower.file_status("/etc/nsswitch.conf") {
        Ok(status) => status,
        Err(litebox::fs::errors::FileStatusError::PathError(error))
            if path_is_missing_or_unreachable(&error) =>
        {
            return Ok(None);
        }
        Err(error) => {
            return Err(anyhow!(
                "failed to inspect lower /etc/nsswitch.conf: {error}"
            ));
        }
    };
    if status.file_type != FileType::RegularFile {
        return Ok(None);
    }

    let fd = match lower.open("/etc/nsswitch.conf", OFlags::RDONLY, Mode::empty()) {
        Ok(fd) => fd,
        Err(litebox::fs::errors::OpenError::AccessNotAllowed) => return Ok(None),
        Err(litebox::fs::errors::OpenError::PathError(error))
            if path_is_missing_or_unreachable(&error) =>
        {
            return Ok(None);
        }
        Err(error) => return Err(anyhow!("failed to open lower /etc/nsswitch.conf: {error}")),
    };
    if status.size > MAX_NSSWITCH_SIZE {
        lower
            .close(&fd)
            .map_err(|error| anyhow!("failed to close lower /etc/nsswitch.conf: {error}"))?;
        anyhow::bail!("lower /etc/nsswitch.conf exceeds 64 KiB");
    }

    let read_result = (|| {
        let mut contents = Vec::new();
        contents
            .try_reserve_exact(status.size)
            .map_err(|_| anyhow!("failed to allocate lower /etc/nsswitch.conf"))?;
        let mut buffer = [0u8; 4096];
        loop {
            let read = match lower.read(&fd, &mut buffer, None) {
                Ok(read) => read,
                Err(litebox::fs::errors::ReadError::NotAFile) => return Ok(None),
                Err(error) => {
                    return Err(anyhow!("failed to read lower /etc/nsswitch.conf: {error}"));
                }
            };
            if read == 0 {
                break;
            }
            if contents
                .len()
                .checked_add(read)
                .is_none_or(|length| length > MAX_NSSWITCH_SIZE)
            {
                anyhow::bail!("lower /etc/nsswitch.conf exceeds 64 KiB");
            }
            contents
                .try_reserve_exact(read)
                .map_err(|_| anyhow!("failed to grow lower /etc/nsswitch.conf buffer"))?;
            contents.extend_from_slice(&buffer[..read]);
        }
        Ok(Some(contents))
    })();
    lower
        .close(&fd)
        .map_err(|error| anyhow!("failed to close lower /etc/nsswitch.conf: {error}"))?;
    read_result
}

fn is_nss_ascii_whitespace(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t' | 0x0b | 0x0c | b'\r')
}

fn is_hosts_candidate(line: &[u8]) -> bool {
    let line = line
        .iter()
        .position(|byte| !is_nss_ascii_whitespace(*byte))
        .map_or(&[][..], |start| &line[start..]);
    if line.first() == Some(&b'#') {
        return false;
    }
    line.strip_prefix(b"hosts").is_some_and(|remainder| {
        remainder.is_empty()
            || remainder.first() == Some(&b':')
            || remainder
                .first()
                .is_some_and(|byte| is_nss_ascii_whitespace(*byte))
    })
}

fn append_nss_bytes(output: &mut Vec<u8>, bytes: &[u8]) -> Result<()> {
    if output
        .len()
        .checked_add(bytes.len())
        .is_none_or(|length| length > MAX_NSSWITCH_SIZE)
    {
        anyhow::bail!("merged /etc/nsswitch.conf exceeds 64 KiB");
    }
    output.extend_from_slice(bytes);
    Ok(())
}

fn merge_nsswitch(contents: &[u8]) -> Result<Vec<u8>> {
    if contents.len() > MAX_NSSWITCH_SIZE {
        anyhow::bail!("lower /etc/nsswitch.conf exceeds 64 KiB");
    }
    let mut output = Vec::new();
    output
        .try_reserve_exact(MAX_NSSWITCH_SIZE)
        .map_err(|_| anyhow!("failed to allocate merged /etc/nsswitch.conf"))?;

    let mut offset = 0usize;
    let mut active_hosts_seen = false;
    while let Some(relative_newline) = contents[offset..].iter().position(|byte| *byte == b'\n') {
        let line_end = offset + relative_newline;
        let terminated_end = line_end + 1;
        if is_hosts_candidate(&contents[offset..line_end]) {
            if !active_hosts_seen {
                append_nss_bytes(&mut output, GENERATED_NSS_HOSTS)?;
                active_hosts_seen = true;
            }
        } else {
            append_nss_bytes(&mut output, &contents[offset..terminated_end])?;
        }
        offset = terminated_end;
    }

    let tail = &contents[offset..];
    if active_hosts_seen {
        append_nss_bytes(&mut output, tail)?;
    } else {
        append_nss_bytes(&mut output, GENERATED_NSS_HOSTS)?;
        if !tail.is_empty() && !is_hosts_candidate(tail) {
            append_nss_bytes(&mut output, tail)?;
        }
    }
    Ok(output)
}

fn guest_can_search(status: &litebox::fs::FileStatus) -> bool {
    if status.owner.user == DEFAULT_GUEST_UID {
        status.mode.contains(Mode::XUSR)
    } else if status.owner.group == DEFAULT_GUEST_GID {
        status.mode.contains(Mode::XGRP)
    } else {
        status.mode.contains(Mode::XOTH)
    }
}

fn write_broker_network_file(
    fs: &mut litebox::fs::in_mem::FileSystem<Platform>,
    path: &str,
    contents: Vec<u8>,
) -> Result<()> {
    let file_mode = Mode::RUSR | Mode::WUSR | Mode::RGRP | Mode::ROTH;
    let fd = fs
        .open(
            path,
            OFlags::WRONLY | OFlags::CREAT | OFlags::TRUNC,
            file_mode,
        )
        .map_err(|error| anyhow!("failed to create {path}: {error}"))?;
    fs.initialize_primarily_read_heavy_file(&fd, contents.into());
    fs.close(&fd)
        .map_err(|error| anyhow!("failed to close {path}: {error}"))?;
    fs.chmod(path, file_mode)
        .map_err(|error| anyhow!("failed to set mode on {path}: {error}"))?;
    fs.chown(path, Some(0), Some(0))
        .map_err(|error| anyhow!("failed to set owner on {path}: {error}"))?;
    Ok(())
}

fn configure_broker_resolver_files(
    lower: &litebox_shim_linux::DefaultLowerFS<Platform>,
    upper: &mut litebox::fs::in_mem::FileSystem<Platform>,
) -> Result<()> {
    let nsswitch = merge_nsswitch(read_lower_nsswitch(lower)?.as_deref().unwrap_or_default())?;
    let etc_exists = match upper.file_status("/etc") {
        Ok(status) => {
            if status.file_type != FileType::Directory {
                anyhow::bail!("broker-controlled /etc exists but is not a directory");
            }
            if !guest_can_search(&status) {
                anyhow::bail!("broker-controlled /etc is not searchable by the guest");
            }
            true
        }
        Err(litebox::fs::errors::FileStatusError::PathError(
            litebox::fs::errors::PathError::NoSuchFileOrDirectory
            | litebox::fs::errors::PathError::MissingComponent,
        )) => false,
        Err(error) => return Err(anyhow!("failed to inspect broker-controlled /etc: {error}")),
    };

    upper.with_root_privileges(|fs| {
        if !etc_exists {
            let directory_mode = Mode::RWXU | Mode::RGRP | Mode::XGRP | Mode::ROTH | Mode::XOTH;
            fs.mkdir("/etc", directory_mode)
                .map_err(|error| anyhow!("failed to create broker-controlled /etc: {error}"))?;
            fs.chmod("/etc", directory_mode)
                .map_err(|error| anyhow!("failed to set mode on /etc: {error}"))?;
            fs.chown("/etc", Some(0), Some(0))
                .map_err(|error| anyhow!("failed to set owner on /etc: {error}"))?;
        }
        write_broker_network_file(
            fs,
            "/etc/resolv.conf",
            format!("nameserver {BROKER_DNS_IPV4_ADDRESS}\noptions timeout:1 attempts:2\n")
                .into_bytes(),
        )?;
        write_broker_network_file(
            fs,
            "/etc/hosts",
            b"127.0.0.1 localhost\n::1 localhost\n127.0.0.1 litebox\n".to_vec(),
        )?;
        write_broker_network_file(fs, "/etc/nsswitch.conf", nsswitch)
    })
}

#[cfg(test)]
mod resolver_file_tests {
    use super::*;

    #[test]
    fn nss_merge_replaces_all_active_hosts_entries_and_preserves_other_bytes() {
        let lower = b"passwd: files\r\n hosts : files\r\n# keep\nhosts ldap\nshadow: files";
        assert_eq!(
            merge_nsswitch(lower).unwrap(),
            b"passwd: files\r\nhosts: files dns\n# keep\nshadow: files"
        );
        assert_eq!(
            merge_nsswitch(b"hosts: first\nhosts: final").unwrap(),
            b"hosts: files dns\nhosts: final"
        );
    }

    #[test]
    fn nss_merge_replaces_every_unterminated_hosts_candidate() {
        for lower in [
            b"hosts".as_slice(),
            b"hosts: files".as_slice(),
            b"\t hosts ldap".as_slice(),
        ] {
            assert_eq!(merge_nsswitch(lower).unwrap(), GENERATED_NSS_HOSTS);
        }
    }

    #[test]
    fn nss_merge_inserts_before_every_other_unterminated_tail() {
        for tail in [
            b"#tail".as_slice(),
            b" \t\r".as_slice(),
            b"unknown: value".as_slice(),
            b"\0binary".as_slice(),
            b"\xff".as_slice(),
        ] {
            let mut expected = GENERATED_NSS_HOSTS.to_vec();
            expected.extend_from_slice(tail);
            assert_eq!(merge_nsswitch(tail).unwrap(), expected);
        }
    }

    #[test]
    fn nss_merge_appends_only_to_empty_or_newline_terminated_content() {
        assert_eq!(merge_nsswitch(b"").unwrap(), GENERATED_NSS_HOSTS);
        assert_eq!(
            merge_nsswitch(b"passwd: files\n").unwrap(),
            b"passwd: files\nhosts: files dns\n"
        );
    }

    #[test]
    fn nss_merge_enforces_input_and_output_bounds() {
        assert!(merge_nsswitch(&vec![b'x'; MAX_NSSWITCH_SIZE + 1]).is_err());
        assert!(merge_nsswitch(&vec![b'x'; MAX_NSSWITCH_SIZE]).is_err());
    }
}

/// Run Linux programs with LiteBox on unmodified Linux
///
/// Detailed logging can be controlled via the `LITEBOX_LOG` environment variable. For example:
/// - `LITEBOX_LOG=debug` to show debug and higher level logs
/// - `LITEBOX_LOG=litebox=debug,litebox::fs=trace` for multiple filters at different levels
#[derive(Parser, Debug)]
#[allow(clippy::struct_excessive_bools)]
pub struct CliArgs {
    /// The program and arguments passed to it (e.g., `python3 --version`).
    ///
    /// By default this is a path on the host filesystem. When --program-from-tar
    /// is set, it refers to a path inside the tar archive instead.
    #[arg(required = true, trailing_var_arg = true, value_hint = clap::ValueHint::CommandWithArguments)]
    pub program_and_arguments: Vec<String>,
    /// Environment variables passed to the program (`K=V` pairs; can be invoked multiple times)
    #[arg(long = "env")]
    pub environment_variables: Vec<String>,
    /// Forward the existing environment variables
    #[arg(long = "forward-env")]
    pub forward_environment_variables: bool,
    /// Allow using unstable options
    #[arg(short = 'Z', long = "unstable")]
    pub unstable: bool,
    /// Pre-fill files into the initial file system state
    // TODO: Might want to extend this to support full directories at some point?
    #[arg(long = "insert-file", value_hint = clap::ValueHint::FilePath,
          requires = "unstable", help_heading = "Unstable Options")]
    pub insert_files: Vec<PathBuf>,
    /// Pre-fill the files in this tar file into the initial file system state
    #[arg(long = "initial-files", value_name = "PATH_TO_TAR", value_hint = clap::ValueHint::FilePath,
          requires = "unstable", help_heading = "Unstable Options")]
    pub initial_files: Option<PathBuf>,
    /// Apply syscall-rewriter to the ELF file before running it
    ///
    /// This is meant as a convenience feature; real deployments would likely prefer ahead-of-time
    /// rewrite things to amortize costs.
    #[arg(
        long = "rewrite-syscalls",
        requires = "unstable",
        help_heading = "Unstable Options"
    )]
    pub rewrite_syscalls: bool,
    /// Load the program binary from the tar file instead of from the host filesystem.
    ///
    /// When set, the program path refers to a path inside the tar filesystem.
    /// The binary must already be rewritten (incompatible with --rewrite-syscalls).
    /// This is used by `litebox-packager` to create fully self-contained tar bundles.
    #[arg(
        long = "program-from-tar",
        requires_all = ["unstable", "initial_files"],
        conflicts_with = "rewrite_syscalls",
        help_heading = "Unstable Options"
    )]
    pub program_from_tar: bool,
    /// Broker-supplied Unix socket path for the local control channel.
    #[arg(
        long = "broker-control-channel",
        value_name = "PATH",
        value_hint = clap::ValueHint::FilePath,
        hide = true,
        requires = "unstable",
        help_heading = "Unstable Options"
    )]
    pub broker_control_channel: Option<PathBuf>,
}

struct MmappedFile {
    data: &'static [u8],
    abs_path: PathBuf,
}

fn mmapped_file(path: impl AsRef<Path>) -> Result<MmappedFile> {
    let path = path.as_ref();
    let abs_path = std::path::absolute(path)
        .map_err(|e| anyhow!("Could not get absolute path for {}: {}", path.display(), e))?;
    let file = std::fs::File::open(&abs_path)?;
    let data = {
        // SAFETY: We assume that the file given to us is not going to change _externally_ while in
        // the middle of execution. Since we are mapping it as read-only and mapping it only once,
        // we are not planning to change it either. With both these in mind, this call is safe.
        //
        // We need to leak the `Mmap` object, so that it stays alive until the end of the program,
        // rather than being unmapped at function finish (i.e., to get the `'static` lifetime).
        Box::leak(Box::new(unsafe { Mmap::map(&file) }.map_err(|e| {
            anyhow!("Could not read tar file at {}: {}", path.display(), e)
        })?))
    };
    Ok(MmappedFile { data, abs_path })
}

/// Run Linux programs with LiteBox on unmodified Linux
///
/// # Panics
///
/// Can panic if any particulars of the environment are not set up as expected. Ideally, would not
/// panic. If it does actually panic, then ping the authors of LiteBox, and likely a better error
/// message could be thrown instead.
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

    if !cli_args.insert_files.is_empty() {
        unimplemented!(
            "this should (hopefully soon) have a nicer interface to support loading in files"
        )
    }

    // When loading from tar, the program path is a guest-internal path and must
    // be absolute — LiteBox does not resolve programs via PATH.
    if cli_args.program_from_tar && !cli_args.program_and_arguments[0].starts_with('/') {
        anyhow::bail!(
            "--program-from-tar requires an absolute path (e.g., /usr/bin/ls), \
             got: {}",
            cli_args.program_and_arguments[0]
        );
    }

    let broker_connection = match cli_args.broker_control_channel.as_deref() {
        Some(control_socket_path) => Some(broker::connect(control_socket_path)?),
        None => None,
    };
    let broker_controls_dns = broker_connection.as_ref().is_some_and(|connection| {
        connection
            .capabilities
            .contains(litebox_broker_protocol::BrokerCapabilities::BROKER_DNS)
    });

    let mut cow_eligible_regions: Vec<MmappedFile> = Vec::new();

    // When --program-from-tar is set, the program binary is already in the tar file,
    // so we skip reading it from the host filesystem and skip extracting ancestor modes.
    #[allow(clippy::type_complexity)]
    let (ancestor_modes_and_users, prog_data): (
        Vec<(litebox::fs::Mode, u32)>,
        Option<alloc::borrow::Cow<'static, [u8]>>,
    ) = if cli_args.program_from_tar {
        (Vec::new(), None)
    } else {
        let prog = std::path::absolute(Path::new(&cli_args.program_and_arguments[0])).unwrap();
        if !prog.exists() {
            let mut msg = format!("program not found on host filesystem: {}", prog.display());
            if cli_args.initial_files.is_some() {
                msg.push_str(
                    "\nhint: if the program is inside the tar archive, \
                     add --program-from-tar",
                );
            }
            anyhow::bail!(msg);
        }
        let ancestors: Vec<_> = prog.ancestors().collect();
        let modes: Vec<_> = ancestors
            .into_iter()
            .rev()
            .skip(1)
            .map(|path| {
                let metadata = path.metadata().unwrap();
                (
                    litebox::fs::Mode::from_bits(metadata.st_mode()).unwrap(),
                    metadata.st_uid(),
                )
            })
            .collect();
        let file = mmapped_file(&prog)?;
        let data = if cli_args.rewrite_syscalls {
            #[cfg(target_arch = "aarch64")]
            let rewritten = litebox_syscall_rewriter::hook_syscalls_in_elf_with_options(
                file.data,
                None,
                litebox_syscall_rewriter::RewriteOptions::new(
                    litebox_syscall_rewriter::TargetHost::Linux,
                    cfg!(feature = "aarch64_virtualize_x18"),
                ),
            )
            .with_context(|| format!("failed to rewrite {}", prog.display()))?;
            #[cfg(not(target_arch = "aarch64"))]
            let rewritten = litebox_syscall_rewriter::hook_syscalls_in_elf(file.data, None)
                .with_context(|| format!("failed to rewrite {}", prog.display()))?;
            rewritten.into()
        } else {
            let data = file.data.into();
            cow_eligible_regions.push(file);
            data
        };
        (modes, Some(data))
    };
    let tar_data: &'static [u8] = if let Some(tar_file) = cli_args.initial_files.as_ref() {
        if tar_file.extension().and_then(|x| x.to_str()) != Some("tar") {
            anyhow::bail!("Expected a .tar file, found {}", tar_file.display());
        }
        mmapped_file(tar_file)?.data
    } else {
        litebox::fs::tar_ro::EMPTY_TAR_FILE
    };

    // TODO(jb): Clean up platform initialization once we have https://github.com/MSRSSP/litebox/issues/24
    let platform = Platform::new();

    for file in cow_eligible_regions {
        platform.register_cow_region(file.data, file.abs_path);
    }

    let mut broker_positional_io_fds = Vec::new();
    let mut broker_shutdown_fds = Vec::new();
    let shim_builder = if let Some(broker_connection) = broker_connection {
        let broker::BrokerConnection {
            capabilities: _,
            local: broker_local,
            notifications: broker_notifications,
            coordinator: broker_association_coordinator,
            positional_io_fds,
            shutdown_fd,
        } = broker_connection;
        broker_positional_io_fds.extend(positional_io_fds);
        broker_shutdown_fds.push(shutdown_fd);
        let litebox = litebox::LiteBox::new_with_broker_local(platform, broker_local);
        broker_association_coordinator.install_dispatch(litebox.broker_failure_dispatcher());
        broker::start_notification_receiver(
            broker_notifications,
            broker_association_coordinator,
            litebox.broker_notification_dispatcher(),
        )?;
        litebox_shim_linux::LinuxShimBuilder::new_with_litebox(platform, litebox)
    } else {
        litebox_shim_linux::LinuxShimBuilder::new(platform)
    };
    let litebox = shim_builder.litebox();
    // SAFETY: `gettid` takes no pointer arguments and has no Rust-side aliasing requirements.
    let tid = unsafe { libc::syscall(libc::SYS_gettid) }
        .try_into()
        .context("failed to convert gettid result to i32")?;
    // SAFETY: `getppid` takes no arguments and has no Rust-side aliasing requirements.
    let ppid = unsafe { libc::getppid() };
    let task_params = litebox_common_linux::TaskParams {
        pid: tid,
        ppid,
        uid: u32::from(DEFAULT_GUEST_UID),
        euid: u32::from(DEFAULT_GUEST_UID),
        gid: u32::from(DEFAULT_GUEST_GID),
        egid: u32::from(DEFAULT_GUEST_GID),
    };
    let initial_file_system = {
        let mut in_mem = litebox::fs::in_mem::FileSystem::new(litebox);

        // When loading the program from the tar, we don't need to create ancestor
        // directories or write the program binary into the in-memory FS -- the program
        // is already in the tar layer.
        if let Some(prog_data) = prog_data {
            let prog = std::path::absolute(Path::new(&cli_args.program_and_arguments[0])).unwrap();
            let ancestors: Vec<_> = prog.ancestors().collect();
            let chown_to_initial_user = |fs: &mut litebox::fs::in_mem::FileSystem<Platform>,
                                         path: &Path| {
                fs.chown(
                    path.to_str().unwrap(),
                    Some(DEFAULT_GUEST_UID),
                    Some(DEFAULT_GUEST_GID),
                )
                .unwrap();
            };
            let mut prev_user = 0;
            for (path, &mode_and_user) in ancestors
                .into_iter()
                .skip(1)
                .rev()
                .skip(1)
                .zip(&ancestor_modes_and_users)
            {
                if prev_user == 0 {
                    // require root user
                    in_mem.with_root_privileges(|fs| {
                        fs.mkdir(path.to_str().unwrap(), mode_and_user.0).unwrap();
                        if mode_and_user.1 != 0 {
                            chown_to_initial_user(fs, path);
                        }
                    });
                } else {
                    in_mem
                        .mkdir(path.to_str().unwrap(), mode_and_user.0)
                        .unwrap();
                }
                prev_user = mode_and_user.1;
            }

            let open_file = |fs: &mut litebox::fs::in_mem::FileSystem<Platform>, path, mode| {
                let fd = fs
                    .open(
                        path,
                        litebox::fs::OFlags::WRONLY | litebox::fs::OFlags::CREAT,
                        mode,
                    )
                    .unwrap();
                fs.initialize_primarily_read_heavy_file(&fd, prog_data);
                fs.close(&fd).unwrap();
            };
            let last = ancestor_modes_and_users.last().ok_or_else(|| {
                anyhow!("program path has no ancestor directories (is it the root path?)")
            })?;
            if prev_user == 0 {
                in_mem.with_root_privileges(|fs| {
                    open_file(fs, prog.to_str().unwrap(), last.0);
                    if last.1 != 0 {
                        chown_to_initial_user(fs, &prog);
                    }
                });
            } else {
                open_file(&mut in_mem, prog.to_str().unwrap(), last.0);
            }
        }
        in_mem.with_root_privileges(|fs| {
            let mode = Mode::RWXU | Mode::RWXG | Mode::RWXO;
            if let Err(err) = fs.mkdir("/tmp", mode) {
                match err {
                    litebox::fs::errors::MkdirError::AlreadyExists => {
                        fs.chmod("/tmp", mode).expect("Failed to call chmod");
                    }
                    _ => panic!(),
                }
            }
        });

        if broker_controls_dns {
            shim_builder.default_fs_with_hook(
                in_mem,
                tar_data.into(),
                configure_broker_resolver_files,
            )?
        } else {
            shim_builder.default_fs(in_mem, tar_data.into())
        }
    };

    // We need to get the file path before enabling seccomp.
    // For --program-from-tar the path is already validated as absolute above,
    // so use it directly instead of resolving against the host CWD.
    let prog = if cli_args.program_from_tar {
        PathBuf::from(&cli_args.program_and_arguments[0])
    } else {
        std::path::absolute(Path::new(&cli_args.program_and_arguments[0])).unwrap()
    };
    let prog_path = prog.to_str().ok_or_else(|| {
        anyhow!(
            "Could not convert program path {:?} to a string",
            cli_args.program_and_arguments[0]
        )
    })?;

    let initial_file_system = std::sync::Arc::new(initial_file_system);

    let shim = shim_builder.build();

    let argv = cli_args
        .program_and_arguments
        .iter()
        .map(|x| std::ffi::CString::new(x.bytes().collect::<Vec<u8>>()).unwrap())
        .collect();
    let envp: Vec<_> = cli_args
        .environment_variables
        .iter()
        .map(|x| std::ffi::CString::new(x.bytes().collect::<Vec<u8>>()).unwrap())
        .collect();
    let envp = if cli_args.forward_environment_variables {
        envp.into_iter()
            .chain(std::env::vars().map(|(k, v)| {
                std::ffi::CString::new(k.bytes().chain(*b"=").chain(v.bytes()).collect::<Vec<u8>>())
                    .unwrap()
            }))
            .collect()
    } else {
        envp
    };

    litebox_platform_linux_userland::LinuxUserland::enable_seccomp_filter(
        &broker_positional_io_fds,
        &broker_shutdown_fds,
    );

    let program = shim.load_program(initial_file_system, task_params, prog_path, argv, envp)?;

    #[cfg(feature = "lock_tracing")]
    litebox::sync::start_recording();

    unsafe {
        litebox_platform_linux_userland::run_thread(
            program.entrypoints,
            &mut litebox_common_linux::PtRegs::default(),
        );
    }

    #[cfg(feature = "lock_tracing")]
    {
        litebox::sync::stop_recording();
        let events = litebox::sync::flush_to_jsonl();
        if !events.is_empty() {
            use std::io::Write;
            if let Ok(mut file) = std::fs::File::create("/tmp/locks.jsonl") {
                for line in &events {
                    let _ = writeln!(file, "{line}");
                }
            }
        }
    }

    std::process::exit(program.process.wait())
}
