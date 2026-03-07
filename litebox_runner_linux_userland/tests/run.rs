// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

mod cache;
mod common;

use std::{
    ffi::OsString,
    path::{Path, PathBuf},
};

#[allow(dead_code)]
enum Backend {
    Rewriter,
    Seccomp,
}

#[must_use]
struct Runner {
    command: std::process::Command,
    dir_path: PathBuf,
    tar_dir: PathBuf,
    unique_name: String,
    cmd_path: PathBuf,
    cmd_args: Vec<OsString>,
    has_run: bool,
}

impl Runner {
    fn new(backend: Backend, target: &Path, unique_name: &str) -> Self {
        let backend_str = match backend {
            Backend::Rewriter => "rewriter",
            Backend::Seccomp => "seccomp",
        };
        let dir_path = PathBuf::from(std::env::var_os("OUT_DIR").unwrap());
        let path = match backend {
            Backend::Seccomp => target.to_path_buf(),
            Backend::Rewriter => {
                // new path in out_dir with .hooked suffix
                let out_path = dir_path.join(format!(
                    "{}.hooked",
                    target.file_name().unwrap().to_str().unwrap()
                ));
                let success = common::rewrite_with_cache(target, &out_path, &[]);
                assert!(success, "failed to run litebox_syscall_rewriter");
                out_path
            }
        };

        // create tar file containing all dependencies
        let tar_dir = dir_path.join(format!("tar_files_{unique_name}"));
        let dirs_to_create = ["lib64", "lib/x86_64-linux-gnu", "lib32"];
        for dir in dirs_to_create {
            std::fs::create_dir_all(tar_dir.join(dir)).unwrap();
        }
        std::fs::create_dir_all(tar_dir.join("out")).unwrap();
        let libs = common::find_dependencies(target.to_str().unwrap());
        for file in &libs {
            let file_path = std::path::Path::new(file.as_str());
            let dest_path = tar_dir.join(&file[1..]);
            match backend {
                Backend::Seccomp => {
                    println!(
                        "Copying {} to {}",
                        file_path.to_str().unwrap(),
                        dest_path.to_str().unwrap()
                    );
                    std::fs::copy(file_path, dest_path).unwrap();
                }
                Backend::Rewriter => {
                    let success = common::rewrite_with_cache(file_path, &dest_path, &[]);
                    assert!(
                        success,
                        "failed to run litebox_syscall_rewriter for {}",
                        file_path.to_str().unwrap()
                    );
                }
            }
        }

        // Get the path to the litebox_runner_linux_userland binary
        let binary_path = std::env::var("NEXTEST_BIN_EXE_litebox_runner_linux_userland")
            .unwrap_or_else(|_| env!("CARGO_BIN_EXE_litebox_runner_linux_userland").to_string());

        // run litebox_runner_linux_userland with the tar file and the compiled executable
        let mut command = std::process::Command::new(binary_path);
        command.args([
            "--unstable",
            "--interception-backend",
            backend_str,
            // Tell ld where to find the libraries.
            // See https://man7.org/linux/man-pages/man8/ld.so.8.html for how ld works.
            // Alternatively, we could add a `/etc/ld.so.cache` file to the rootfs.
            "--env",
            "LD_LIBRARY_PATH=/lib64:/lib32:/lib",
            "--env",
            "HOME=/",
        ]);

        Self {
            command,
            dir_path,
            tar_dir,
            cmd_path: path,
            cmd_args: Vec::new(),
            has_run: false,
            unique_name: unique_name.to_owned(),
        }
    }

    fn env(&mut self, env: impl AsRef<std::ffi::OsStr>) -> &mut Self {
        self.command.arg("--env").arg(env);
        self
    }

    #[cfg_attr(not(target_arch = "x86_64"), expect(dead_code))]
    fn envs(&mut self, envs: impl IntoIterator<Item = impl AsRef<std::ffi::OsStr>>) -> &mut Self {
        for env in envs {
            self.env(env);
        }
        self
    }

    fn arg(&mut self, arg: impl AsRef<std::ffi::OsStr>) -> &mut Self {
        self.cmd_args.push(arg.as_ref().to_os_string());
        self
    }

    #[cfg_attr(not(target_arch = "x86_64"), expect(dead_code))]
    fn args(&mut self, args: impl IntoIterator<Item = impl AsRef<std::ffi::OsStr>>) -> &mut Self {
        for arg in args {
            self.arg(arg);
        }
        self
    }

    fn tun_device_name(&mut self, tun_name: &str) -> &mut Self {
        self.command.arg("--tun-device-name").arg(tun_name);
        self
    }

    #[cfg_attr(not(target_arch = "x86_64"), expect(dead_code))]
    fn with_fs_path(&mut self, f: impl FnOnce(&Path)) -> &mut Self {
        f(&self.tar_dir);
        self
    }

    fn run(&mut self) {
        self.run_inner(false);
    }

    #[must_use]
    #[cfg_attr(not(target_arch = "x86_64"), expect(dead_code))]
    fn output(&mut self) -> Vec<u8> {
        self.run_inner(true)
    }

    fn run_inner(&mut self, capture_stdout: bool) -> Vec<u8> {
        assert!(!self.has_run);
        self.has_run = true;
        // create tar file using `tar` command with caching
        let tar_file = self
            .dir_path
            .join(format!("rootfs_{}.tar", self.unique_name));
        let tar_success =
            common::create_tar_with_cache(&self.tar_dir, &tar_file, &self.unique_name);
        assert!(tar_success, "failed to create tar file");
        println!("Tar file ready at: {}", tar_file.to_str().unwrap());

        self.command
            .arg("--initial-files")
            .arg(tar_file)
            .arg(&self.cmd_path)
            .args(&self.cmd_args)
            .stderr(std::process::Stdio::inherit());
        if !capture_stdout {
            self.command.stdout(std::process::Stdio::inherit());
        }
        println!("Running `{:?}`", self.command);
        let output = self
            .command
            .output()
            .expect("Failed to run litebox_runner_linux_userland");
        assert!(
            output.status.success(),
            "failed to run litebox_runner_linux_userland: {}",
            output.status
        );
        output.stdout
    }
}

/// Find all C test files in a directory
fn find_c_test_files(dir: &str) -> Vec<PathBuf> {
    let mut files = Vec::new();
    for entry in std::fs::read_dir(dir).unwrap() {
        let entry = entry.unwrap();
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        if let Some("c") = path.extension().and_then(|e| e.to_str()) {
            files.push(path);
        }
    }
    files
}

// our rtld_audit does not support x86 yet
#[cfg(target_arch = "x86_64")]
#[test]
fn test_dynamic_lib_with_rewriter() {
    for path in find_c_test_files("./tests") {
        let stem = path
            .file_stem()
            .and_then(|s| s.to_str())
            .expect("failed to get file stem");
        let unique_name = format!("{stem}_rewriter");
        let target = common::compile(path.to_str().unwrap(), &unique_name, false, false);
        Runner::new(Backend::Rewriter, &target, &unique_name).run();
    }
}

#[test]
fn test_static_exec_with_rewriter() {
    for path in find_c_test_files("./tests") {
        let stem = path
            .file_stem()
            .and_then(|s| s.to_str())
            .expect("failed to get file stem");
        let unique_name = format!("{stem}_exec_rewriter");
        let target = common::compile(path.to_str().unwrap(), &unique_name, true, false);
        Runner::new(Backend::Rewriter, &target, &unique_name).run();
    }
}

#[cfg(target_arch = "x86_64")]
#[test]
#[ignore = "We need to modify seccomp backend to support std in the platform"]
fn test_dynamic_lib_with_seccomp() {
    for path in find_c_test_files("./tests") {
        let stem = path
            .file_stem()
            .and_then(|s| s.to_str())
            .expect("failed to get file stem");
        let unique_name = format!("{stem}_seccomp");
        let target = common::compile(path.to_str().unwrap(), &unique_name, false, false);
        Runner::new(Backend::Seccomp, &target, &unique_name).run();
    }
}

/// Get the path of a program using `which`
#[cfg(target_arch = "x86_64")]
fn run_which(prog: &str) -> std::path::PathBuf {
    let prog_path_str = std::process::Command::new("which")
        .arg(prog)
        .output()
        .expect("Failed to find program binary")
        .stdout;
    let prog_path_str = String::from_utf8(prog_path_str).unwrap().trim().to_string();
    let prog_path = std::path::PathBuf::from(prog_path_str);
    assert!(prog_path.exists(), "Program binary not found",);
    prog_path
}

#[cfg(target_arch = "x86_64")]
#[test]
#[ignore = "We need to modify seccomp backend to support std in the platform"]
fn test_node_with_seccomp() {
    const HELLO_WORLD_JS: &str = r"
const fs = require('node:fs');

const content = 'Hello World!';
console.log(content);
";

    let node_path = run_which("node");
    Runner::new(Backend::Seccomp, &node_path, "hello_node_seccomp")
        .arg("/out/hello_world.js")
        .with_fs_path(|out_dir| {
            // write the test js file to the output directory
            std::fs::write(out_dir.join("out/hello_world.js"), HELLO_WORLD_JS).unwrap();
        })
        .run();
}

#[cfg(target_arch = "x86_64")]
#[test]
fn test_node_with_rewriter() {
    const HELLO_WORLD_JS: &str = r"
const fs = require('node:fs');

const content = 'Hello World!';
console.log(content);
";

    let node_path = run_which("node");
    Runner::new(Backend::Rewriter, &node_path, "hello_node_rewriter")
        .arg("/out/hello_world.js")
        .with_fs_path(|out_dir| {
            // write the test js file to the output directory
            std::fs::write(out_dir.join("out/hello_world.js"), HELLO_WORLD_JS).unwrap();
        })
        .run();
}

#[cfg(target_arch = "x86_64")]
#[test]
fn test_runner_with_ls() {
    let ls_path = run_which("ls");
    let output = Runner::new(Backend::Rewriter, &ls_path, "ls_rewriter")
        .arg("-a")
        .output();

    let output_str = String::from_utf8_lossy(&output);
    let normalized = output_str.split_whitespace().collect::<Vec<_>>();
    for each in [".", "..", "lib", "lib64"] {
        assert!(
            normalized.contains(&each),
            "unexpected ls output:\n{output_str}\n{each} not found",
        );
    }

    // test `ls` subdir
    let output = Runner::new(Backend::Rewriter, &ls_path, "ls_lib_rewriter")
        .args(["-a", "/lib/x86_64-linux-gnu"])
        .output();

    let output_str = String::from_utf8_lossy(&output);
    let normalized = output_str.split_whitespace().collect::<Vec<_>>();
    for each in [".", "..", "libc.so.6", "libpcre2-8.so.0", "libselinux.so.1"] {
        assert!(
            normalized.contains(&each),
            "unexpected ls output:\n{output_str}\n{each} not found",
        );
    }
}

#[cfg(all(target_arch = "x86_64", target_os = "linux"))]
fn run_python(args: &[&str]) -> String {
    let output = std::process::Command::new("python3")
        .args(args)
        .output()
        .expect("Failed to run Python");
    assert!(output.status.success(), "Python script failed");
    String::from_utf8(output.stdout).unwrap()
}

#[cfg(all(target_arch = "x86_64", target_os = "linux"))]
fn has_origin_in_libs(binary_path: &Path) -> bool {
    let output = std::process::Command::new("readelf")
        .args(["-d", binary_path.to_str().unwrap()])
        .output()
        .expect("Failed to run readelf");

    if !output.status.success() {
        eprintln!("Warning: readelf failed for {}", binary_path.display());
        return false;
    }

    let output_str = String::from_utf8_lossy(&output.stdout);
    for line in output_str.lines() {
        // Check for $ORIGIN in NEEDED (shared library) entries
        if line.contains("(NEEDED)") && line.contains("$ORIGIN") {
            return true;
        }
    }
    false
}

#[cfg(all(target_arch = "x86_64", target_os = "linux"))]
#[test]
fn test_runner_with_python() {
    const HELLO_WORLD_PY: &str = "print(\"Hello, World from litebox!\")";
    let python_path = run_which("python3");

    if has_origin_in_libs(&python_path) {
        println!(
            "Skipping test: Python executable at {} uses $ORIGIN in library paths",
            python_path.display()
        );
        return;
    }

    let python_home = run_python(&["-c", "import sys; print(sys.prefix);"]);
    println!("Detected PYTHONHOME: {python_home}");
    let python_sys_path = run_python(&["-c", "import sys; print(':'.join(sys.path))"]);
    println!("Detected PYTHONPATH: {python_sys_path}");
    let python_home = python_home.trim().to_string();
    let python_home_dir = PathBuf::from(&python_home);
    let python_lib_paths = python_sys_path
        .split(':')
        .map(str::trim)
        .filter(|path| !path.is_empty())
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .filter(|path| path.starts_with(&python_home_dir))
        .collect::<Vec<_>>();

    let python_lib_paths_str = python_lib_paths
        .iter()
        .map(|path| path.to_str().unwrap())
        .collect::<Vec<_>>()
        .join(":");

    let mut paths_to_stage = std::collections::BTreeSet::new();
    paths_to_stage.insert(python_home_dir);
    paths_to_stage.extend(python_lib_paths.iter().cloned());

    Runner::new(Backend::Rewriter, &python_path, "python_rewriter")
        .args(["-c", HELLO_WORLD_PY])
        .envs([
            &format!("PYTHONHOME={python_home}"),
            &format!("PYTHONPATH={python_lib_paths_str}"),
            // LiteBox does not support timestamp yet, so pre-compiled .pyc files are not usable.
            // Avoid creating .pyc files as tar filesystem is read-only.
            "PYTHONDONTWRITEBYTECODE=1",
        ])
        .with_fs_path(|out_dir| {
            for source_path in &paths_to_stage {
                if !source_path.exists() {
                    continue;
                }

                if source_path.is_file() {
                    let dest_path = out_dir.join(source_path.strip_prefix("/").unwrap());
                    if !dest_path.exists() {
                        if let Some(parent) = dest_path.parent() {
                            std::fs::create_dir_all(parent).unwrap();
                        }
                        std::fs::copy(source_path, dest_path).unwrap();
                    }
                    continue;
                }

                if source_path.is_dir() {
                    let python_lib_dst = out_dir.join(source_path.strip_prefix("/").unwrap());
                    if !python_lib_dst.exists() {
                        std::fs::create_dir_all(&python_lib_dst).unwrap();
                        println!(
                            "Copying python3 lib from {} to {}",
                            source_path.display(),
                            python_lib_dst.display()
                        );
                        let output = std::process::Command::new("cp")
                            .args([
                                "-rpL", // -r for recursive, -p to preserve attributes, -L to dereference symbolic links
                                source_path.to_str().unwrap(),
                                python_lib_dst.parent().unwrap().to_str().unwrap(),
                            ])
                            .output()
                            .expect("Failed to copy python3 lib");
                        // cp -rpL may report errors for broken symlinks (e.g.,
                        // dangling man-page symlinks under /usr/share/npm) but
                        // still copies the remaining files successfully. Log any
                        // errors as warnings instead of failing the test.
                        if !output.status.success() {
                            let stderr =
                                std::str::from_utf8(output.stderr.as_slice()).unwrap_or("");
                            eprintln!("Warning: cp finished with errors (non-critical):\n{stderr}");
                        }
                    }

                    // Rewrite shared objects (.so, .so.1, .so.1.2.3, etc.) under the python lib directory.
                    for entry in walkdir::WalkDir::new(source_path)
                        .into_iter()
                        .filter_map(std::result::Result::ok)
                        .filter(|e| e.file_type().is_file())
                        .filter(|e| {
                            e.path()
                                .file_name()
                                .and_then(|n| n.to_str())
                                .is_some_and(|name| name.contains(".so"))
                        })
                        // Skip non-ELF files (e.g., linker scripts like libcurses.so)
                        .filter(|e| {
                            let mut magic = [0u8; 4];
                            std::fs::File::open(e.path())
                                .and_then(|mut f| {
                                    use std::io::Read;
                                    f.read_exact(&mut magic)
                                })
                                .is_ok()
                                && magic == *b"\x7fELF"
                        })
                    {
                        let so_file = entry.path();
                        let so_file_dest = out_dir.join(so_file.strip_prefix("/").unwrap());
                        println!(
                            "Rewrite {} to {}",
                            so_file.display(),
                            so_file_dest.display()
                        );
                        let success = common::rewrite_with_cache(so_file, &so_file_dest, &[]);
                        assert!(success, "failed to rewrite {} file", so_file.display());
                    }
                }
            }
        })
        .run();
}

#[test]
fn test_tun_with_tcp_socket() {
    let tcp_server_path = PathBuf::from("./tests/net/tcp_server.c");
    let tcp_client_path = PathBuf::from("./tests/net/tcp_client.c");
    let unique_name = "tcp_server_exec_rewriter";
    let server_target =
        common::compile(tcp_server_path.to_str().unwrap(), unique_name, true, false);
    let client_target = common::compile(
        tcp_client_path.to_str().unwrap(),
        "tcp_client",
        false,
        false,
    );

    let child = std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_secs(2)); // wait for server to start
        std::process::Command::new(client_target.to_str().unwrap())
            .arg("10.0.0.2")
            .arg("12345")
            .status()
            .expect("failed to execute client");
    });
    Runner::new(Backend::Rewriter, &server_target, unique_name)
        .arg("10.0.0.2")
        .arg("12345")
        .tun_device_name("tun99")
        .run();
    child.join().unwrap();
}

// ---------------------------------------------------------------------------
// OCI image tests
// ---------------------------------------------------------------------------

/// Runner for OCI-packaged programs.
///
/// Uses `litebox_packager --oci-image` to pull and package a container image,
/// then invokes `litebox_runner_linux_userland` with `--program-from-tar`.
#[cfg(target_arch = "x86_64")]
struct OciRunner {
    command: std::process::Command,
    tar_path: PathBuf,
    unique_name: String,
    program: String,
    program_args: Vec<OsString>,
    has_run: bool,
}

#[cfg(target_arch = "x86_64")]
impl OciRunner {
    /// Create a new OCI runner for the given image reference.
    ///
    /// `image_ref` is a standard OCI image reference (e.g.,
    /// `docker.io/library/python:3.12-slim`). `program` is the absolute path
    /// to the program inside the container image (e.g.,
    /// `/usr/local/bin/python3.12`).
    fn new(image_ref: &str, program: &str, unique_name: &str) -> Self {
        let dir_path = PathBuf::from(std::env::var_os("OUT_DIR").unwrap());
        let tar_path = dir_path.join(format!("oci_{unique_name}.tar"));

        // Run the packager to produce the tar (uses cargo run).
        let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());

        // Check cache: rebuild if the tar doesn't exist or if the packager
        // binary is newer than the cached tar (i.e., the packager was
        // recompiled since the tar was produced).
        let needs_rebuild = if tar_path.exists() {
            // Build the packager first (no-op if already up-to-date) so we
            // can check its binary mtime.
            let build_output = std::process::Command::new(&cargo)
                .args(["build", "-p", "litebox_packager", "--message-format=short"])
                .stderr(std::process::Stdio::inherit())
                .output()
                .expect("failed to build litebox_packager");
            assert!(
                build_output.status.success(),
                "cargo build -p litebox_packager failed"
            );

            // Find the packager binary in the target directory. It lives next
            // to the runner binary, which we know the path of.
            let runner_bin = std::env::var("NEXTEST_BIN_EXE_litebox_runner_linux_userland")
                .unwrap_or_else(|_| {
                    env!("CARGO_BIN_EXE_litebox_runner_linux_userland").to_string()
                });
            let packager_bin = Path::new(&runner_bin)
                .parent()
                .expect("runner binary has no parent dir")
                .join("litebox_packager");

            if packager_bin.exists() {
                let packager_mtime = std::fs::metadata(&packager_bin)
                    .and_then(|m| m.modified())
                    .ok();
                let tar_mtime = std::fs::metadata(&tar_path).and_then(|m| m.modified()).ok();
                match (packager_mtime, tar_mtime) {
                    (Some(p), Some(t)) => p > t,
                    _ => true, // can't compare, rebuild to be safe
                }
            } else {
                // Can't find the binary — fall through to rebuild.
                true
            }
        } else {
            true
        };

        if needs_rebuild {
            if tar_path.exists() {
                println!("Packager binary is newer than cached tar, re-packaging {unique_name}...");
            }
            println!("Packaging OCI image {image_ref} -> {}", tar_path.display());
            let output = std::process::Command::new(&cargo)
                .args([
                    "run",
                    "-p",
                    "litebox_packager",
                    "--",
                    "--oci-image",
                    image_ref,
                    "-o",
                    tar_path.to_str().unwrap(),
                ])
                .output()
                .expect("failed to run litebox_packager");
            let stderr = String::from_utf8_lossy(&output.stderr);
            eprintln!("{stderr}");
            assert!(
                output.status.success(),
                "litebox_packager failed for {image_ref}: {stderr}"
            );
            println!("Packaged OCI image to {}", tar_path.display());
        } else {
            println!(
                "Using cached OCI tar for {unique_name}: {}",
                tar_path.display()
            );
        }

        // Build the runner command.
        let binary_path = std::env::var("NEXTEST_BIN_EXE_litebox_runner_linux_userland")
            .unwrap_or_else(|_| env!("CARGO_BIN_EXE_litebox_runner_linux_userland").to_string());

        let mut command = std::process::Command::new(binary_path);
        command.args([
            "--unstable",
            "--interception-backend",
            "rewriter",
            "--env",
            "LD_LIBRARY_PATH=/lib64:/lib32:/lib:/usr/lib/x86_64-linux-gnu:/usr/local/lib",
            "--env",
            "HOME=/",
        ]);

        Self {
            command,
            tar_path,
            unique_name: unique_name.to_owned(),
            program: program.to_owned(),
            program_args: Vec::new(),
            has_run: false,
        }
    }

    fn arg(&mut self, arg: impl AsRef<std::ffi::OsStr>) -> &mut Self {
        self.program_args.push(arg.as_ref().to_os_string());
        self
    }

    fn args(&mut self, args: impl IntoIterator<Item = impl AsRef<std::ffi::OsStr>>) -> &mut Self {
        for arg in args {
            self.arg(arg);
        }
        self
    }

    #[allow(dead_code)]
    fn run(&mut self) {
        self.run_inner(false);
    }

    #[must_use]
    fn output(&mut self) -> Vec<u8> {
        self.run_inner(true)
    }

    fn run_inner(&mut self, capture_stdout: bool) -> Vec<u8> {
        assert!(!self.has_run, "OciRunner::run called twice");
        self.has_run = true;

        self.command
            .arg("--initial-files")
            .arg(&self.tar_path)
            .arg("--program-from-tar")
            .arg(&self.program)
            .args(&self.program_args)
            .stderr(std::process::Stdio::inherit());
        if !capture_stdout {
            self.command.stdout(std::process::Stdio::inherit());
        }
        println!(
            "Running OCI test '{}': {:?}",
            self.unique_name, self.command
        );
        let output = self
            .command
            .output()
            .expect("failed to run litebox_runner_linux_userland");
        assert!(
            output.status.success(),
            "litebox_runner_linux_userland failed for OCI test '{}': {}",
            self.unique_name,
            output.status
        );
        output.stdout
    }
}

/// Test running `echo` from an `alpine:latest` OCI image via config_and_run.sh.
///
/// Runs `/bin/sh /litebox/config_and_run.sh echo ...` to validate that the
/// generated config_and_run script correctly exports ENV vars (PATH) and
/// dispatches to the given command via `exec "$@"`.
///
/// Run with:
/// ```
/// cargo test --package litebox_runner_linux_userland --test run --release -- test_alpine_echo_oci --exact --nocapture --ignored
/// ```
#[cfg(target_arch = "x86_64")]
#[test]
#[ignore = "Requires network access to pull OCI image from Docker Hub"]
fn test_alpine_echo_oci() {
    // Run through config_and_run.sh to validate ENV setup and command dispatch.
    let output = OciRunner::new("docker.io/library/alpine:latest", "/bin/sh", "alpine_echo")
        .args([
            "/litebox/config_and_run.sh",
            "echo",
            "Hello from Alpine via LiteBox!",
        ])
        .output();

    let stdout = String::from_utf8_lossy(&output);
    assert_eq!(
        stdout.trim(),
        "Hello from Alpine via LiteBox!",
        "unexpected echo output: {stdout}"
    );
}

/// Test that alpine config_and_run.sh correctly exports PATH from the image config.
///
/// Run with:
/// ```
/// cargo test --package litebox_runner_linux_userland --test run --release -- test_alpine_entrypoint_env_oci --exact --nocapture --ignored
/// ```
#[cfg(target_arch = "x86_64")]
#[test]
#[ignore = "Requires network access to pull OCI image from Docker Hub"]
fn test_alpine_entrypoint_env_oci() {
    let output = OciRunner::new("docker.io/library/alpine:latest", "/bin/sh", "alpine_env")
        .args(["/litebox/config_and_run.sh", "/bin/sh", "-c", "echo $PATH"])
        .output();

    let stdout = String::from_utf8_lossy(&output);
    let path = stdout.trim();
    // Alpine image config sets PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
    assert!(
        path.contains("/usr/local/bin") && path.contains("/usr/sbin"),
        "config_and_run.sh did not export PATH from image config: {path}"
    );
}

/// Test running Python from a `python:3.12-slim` OCI image via config_and_run.sh.
///
/// Runs `/bin/sh /litebox/config_and_run.sh python3 -c ...` to validate that the
/// generated config_and_run script correctly exports ENV vars (PYTHON_VERSION,
/// LANG, PATH, etc.) and dispatches to the given command. The Python script
/// reads `PYTHON_VERSION` from the environment to prove the config_and_run script set it.
///
/// This test pulls the image from Docker Hub, packages it with
/// `litebox_packager --oci-image`, and runs a hello-world script. It requires
/// network access and is slow on first run (~60s to pull + package), so it is
/// ignored by default.
///
/// Run with:
/// ```
/// cargo test --package litebox_runner_linux_userland --test run --release -- test_python_slim_oci --exact --nocapture --ignored
/// ```
#[cfg(target_arch = "x86_64")]
#[test]
#[ignore = "Requires network access to pull OCI image from Docker Hub"]
fn test_python_slim_oci() {
    // Run through config_and_run.sh so ENV vars from the image config are set.
    let output = OciRunner::new(
        "docker.io/library/python:3.12-slim",
        "/bin/sh",
        "python_slim",
    )
    .args([
        "/litebox/config_and_run.sh",
        "python3",
        "-c",
        "import os; v = os.environ.get('PYTHON_VERSION', 'MISSING'); print(f'Hello from Python {v} via LiteBox!')",
    ])
    .output();

    let stdout = String::from_utf8_lossy(&output);
    let trimmed = stdout.trim();
    // The config_and_run.sh exports PYTHON_VERSION from the image config,
    // so the output should contain the actual version, not "MISSING".
    assert!(
        trimmed.starts_with("Hello from Python 3.12") && trimmed.ends_with("via LiteBox!"),
        "unexpected python output (config_and_run.sh may not have exported PYTHON_VERSION): {trimmed}"
    );
}

/// Test network performance with iperf3
///
/// To run it with release build and see output, use:
/// ```
/// cargo test --package litebox_runner_linux_userland --test run --release -- test_tun_and_runner_with_iperf3 --exact --nocapture
/// ```
#[cfg(target_arch = "x86_64")]
#[test]
fn test_tun_and_runner_with_iperf3() {
    const NUM_CLIENTS: usize = 1;
    let iperf3_path = run_which("iperf3");
    let cloned_path = iperf3_path.clone();
    let has_started = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let has_started_clone = has_started.clone();
    std::thread::spawn(move || {
        // Rewrite iperf3 and its dependencies may take some time, wait until it's done.
        while !has_started_clone.load(std::sync::atomic::Ordering::Relaxed) {
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        std::thread::sleep(std::time::Duration::from_secs(5)); // wait a bit more to ensure server is ready
        std::println!("Starting iperf3 client...");
        let mut client = std::process::Command::new(&cloned_path)
            .args(["-c", "10.0.0.2", "-P", NUM_CLIENTS.to_string().as_str()])
            .spawn()
            .expect("Failed to start iperf3 server");
        client.wait().expect("Failed to wait on iperf3 client");
    });
    let mut runner = Runner::new(Backend::Rewriter, &iperf3_path, "iperf3_server_rewriter");
    runner
        .args([
            "-s", // run in server mode
            "-1", // handle one client then exit
            "-B", "10.0.0.2", // bind to this address
        ])
        .tun_device_name("tun99");
    has_started.store(true, std::sync::atomic::Ordering::Relaxed);
    runner.run();
}
