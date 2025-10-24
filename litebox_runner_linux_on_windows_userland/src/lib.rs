// Restrict this crate to only work on Windows. For now, we are restricting this to only x86-64
// Windows, but we _may_ allow for more in the future, if we find it useful to do so.
#![cfg(all(target_os = "windows", target_arch = "x86_64"))]

use windows_sys::Win32::Storage::FileSystem;

use anyhow::{Result, anyhow};
use clap::Parser;
use litebox::fs::FileSystem as _;
use litebox_platform_multiplex::Platform;
use std::os::windows::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};

/// Convert Windows file permissions and owner ID to LiteBox internal
fn get_file_mode_and_uid(metadata: &std::fs::Metadata) -> (litebox::fs::Mode, u32) {
    // On Windows, determine permissions based on file attributes
    let mut mode = litebox::fs::Mode::empty();

    // Check if file is read-only
    let is_readonly = metadata.file_attributes() & FileSystem::FILE_ATTRIBUTE_READONLY != 0;

    // TODO(chuqi): Windows does not use Unix-like permissions to distinguish r-w-x. Windows uses NTFS ACLs
    // and the notion of “execute permission” is tied to file type (.exe, .bat, .cmd) and access-control
    // entries—not a filesystem bit.
    // Rust's (std::fs) Permissions only exposes the `readonly`` attribute on Windows. For now, we do not
    // identify "executable". We may either rely on other crates (is_executable) or use file types.
    if metadata.is_dir() {
        // Directories need full permissions to allow creating subdirectories and files
        // Even if marked read-only, we need write access for directory operations
        mode |= litebox::fs::Mode::RWXU | litebox::fs::Mode::RWXG | litebox::fs::Mode::RWXO;
    } else if !is_readonly {
        // If not read-only, grant full permissions to user/group/other
        mode |= litebox::fs::Mode::RWXU | litebox::fs::Mode::RWXG | litebox::fs::Mode::RWXO;
    } else {
        // If read-only file, grant only read and execute permissions
        mode |= litebox::fs::Mode::RUSR | litebox::fs::Mode::RGRP | litebox::fs::Mode::ROTH;
        mode |= litebox::fs::Mode::XUSR | litebox::fs::Mode::XGRP | litebox::fs::Mode::XOTH;
    }

    // Always use default user ID 1000 on Windows since there's no direct equivalent to Unix UID
    (mode, 1000u32)
}

/// Run Linux programs with LiteBox on unmodified Windows
#[derive(Parser, Debug)]
pub struct CliArgs {
    /// The program and arguments passed to it (e.g., `python3 --version`)
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
}

fn windows_path_to_unix(path: &std::path::Path) -> String {
    let components: Vec<_> = path
        .components()
        .filter_map(|comp| match comp {
            Component::Prefix(_) => None, // Remove drive letter (C:, D:, etc.)
            Component::RootDir => Some("/".to_string()),
            Component::Normal(name) => Some(name.to_string_lossy().to_string()),
            Component::CurDir => Some(".".to_string()),
            Component::ParentDir => Some("..".to_string()),
        })
        .collect();

    if components.is_empty() || components == ["/"] {
        "/".to_string()
    } else if components[0] == "/" {
        format!("/{}", components[1..].join("/"))
    } else {
        components.join("/")
    }
}

/// Run Linux programs with LiteBox on unmodified Windows
///
/// # Panics
///
/// Can panic if any particulars of the environment are not set up as expected. Ideally, would not
/// panic. If it does actually panic, then ping the authors of LiteBox, and likely a better error
/// message could be thrown instead.
pub fn run(cli_args: CliArgs) -> Result<()> {
    if !cli_args.insert_files.is_empty() {
        unimplemented!(
            "this should (hopefully soon) have a nicer interface to support loading in files"
        )
    }

    let (ancestor_modes_and_users, prog_data): (Vec<(litebox::fs::Mode, u32)>, Vec<u8>) = {
        let prog = std::path::absolute(Path::new(&cli_args.program_and_arguments[0]))?;
        let ancestors: Vec<_> = prog.ancestors().collect();
        let modes: Vec<_> = ancestors
            .into_iter()
            .rev()
            .skip(1)
            .map(|path| {
                let metadata = path.metadata().unwrap();
                get_file_mode_and_uid(&metadata)
            })
            .collect();
        let data = std::fs::read(prog).unwrap();
        let data = if cli_args.rewrite_syscalls {
            litebox_syscall_rewriter::hook_syscalls_in_elf(&data, None).unwrap()
        } else {
            data
        };
        (modes, data)
    };
    let tar_data = if let Some(tar_file) = cli_args.initial_files.as_ref() {
        if tar_file.extension().and_then(|x| x.to_str()) != Some("tar") {
            anyhow::bail!("Expected a .tar file, found {}", tar_file.display());
        }
        std::fs::read(tar_file)
            .map_err(|e| anyhow!("Could not read tar file at {}: {}", tar_file.display(), e))?
    } else {
        litebox::fs::tar_ro::EMPTY_TAR_FILE.into()
    };

    let platform = Platform::new();
    litebox_platform_multiplex::set_platform(platform);
    let litebox = litebox_shim_linux::init_process(platform.init_task());
    let prog = std::path::absolute(Path::new(&cli_args.program_and_arguments[0]))?;
    let prog_unix_path = windows_path_to_unix(&prog);
    let initial_file_system = {
        let mut in_mem = litebox::fs::in_mem::FileSystem::new(litebox);
        let ancestors: Vec<_> = prog.ancestors().collect();
        let mut prev_user = 0;
        for (path, &mode_and_user) in ancestors
            .into_iter()
            .skip(1)
            .rev()
            .skip(1)
            .zip(&ancestor_modes_and_users)
        {
            // convert windows's path to unix-style and strip its root
            let unix_path = windows_path_to_unix(path);
            if prev_user == 0 {
                // require root user
                in_mem.with_root_privileges(|fs| {
                    fs.mkdir(unix_path.as_str(), mode_and_user.0).unwrap();
                    if mode_and_user.1 != 0 {
                        // This file is owned by a non-root user, so we need to set the ownership to our default user
                        fs.chown(unix_path.as_str(), Some(1000), Some(1000))
                            .unwrap();
                    }
                });
            } else {
                in_mem.mkdir(unix_path, mode_and_user.0).unwrap();
            }
            prev_user = mode_and_user.1;
        }

        let open_file =
            |fs: &mut litebox::fs::in_mem::FileSystem<litebox_platform_multiplex::Platform>,
             path,
             mode| {
                let fd = fs
                    .open(
                        path,
                        litebox::fs::OFlags::WRONLY | litebox::fs::OFlags::CREAT,
                        mode,
                    )
                    .unwrap();
                let mut data = prog_data.as_slice();
                while !data.is_empty() {
                    let len = fs.write(&fd, data, None).unwrap();
                    data = &data[len..];
                }
                fs.close(&fd).unwrap();
            };
        let last = ancestor_modes_and_users.last().unwrap();
        if prev_user == 0 {
            in_mem.with_root_privileges(|fs| {
                open_file(fs, prog_unix_path.as_str(), last.0);
                if last.1 != 0 {
                    // This file is owned by a non-root user, so we need to set the ownership to our default user
                    fs.chown(prog_unix_path.as_str(), Some(1000), Some(1000))
                        .unwrap();
                }
            });
        } else {
            open_file(&mut in_mem, prog_unix_path.as_str(), last.0);
        }

        let tar_ro = litebox::fs::tar_ro::FileSystem::new(litebox, tar_data.into());
        litebox_shim_linux::default_fs(in_mem, tar_ro)
    };
    litebox_shim_linux::set_fs(initial_file_system);
    platform.register_shim(&litebox_shim_linux::LinuxShim);

    let argv = cli_args
        .program_and_arguments
        .iter()
        .enumerate()
        .map(|(i, x)| {
            if i == 0 {
                std::ffi::CString::new(prog_unix_path.as_bytes()).unwrap()
            } else {
                std::ffi::CString::new(x.bytes().collect::<Vec<u8>>()).unwrap()
            }
        })
        .collect();
    let envp: Vec<_> = cli_args
        .environment_variables
        .iter()
        .map(|x| std::ffi::CString::new(x.bytes().collect::<Vec<u8>>()).unwrap())
        .collect();
    let envp = if cli_args.forward_environment_variables {
        envp.into_iter()
            .chain(std::env::vars().map(|(k, v)| {
                std::ffi::CString::new(
                    k.bytes()
                        .chain([b'='])
                        .chain(v.bytes())
                        .collect::<Vec<u8>>(),
                )
                .unwrap()
            }))
            .collect()
    } else {
        envp
    };

    let mut pt_regs = litebox_shim_linux::load_program(&prog_unix_path, argv, envp).unwrap();
    unsafe { litebox_platform_windows_userland::run_thread(&mut pt_regs) };
    Ok(())
}
