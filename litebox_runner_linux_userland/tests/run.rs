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
    // Tests that require syscalls not yet supported on 32-bit:
    // - _llseek: lseek_test.c, fileio_test.c, preadwrite_test.c, truncate_test.c
    // - pselect6: poll_select.c
    // - timerfd timing issues: timerfd_test.c
    const SKIP_ON_32BIT: &[&str] = &[
        "lseek_test.c",
        "poll_select.c",
        "fileio_test.c",
        "preadwrite_test.c",
        "truncate_test.c",
        "timerfd_test.c",
    ];

    // Check the target architecture at compile time using cfg
    // This will be the target triple's architecture, not the host
    let is_32bit = cfg!(target_arch = "x86") || cfg!(target_pointer_width = "32");

    let mut files = Vec::new();
    for entry in std::fs::read_dir(dir).unwrap() {
        let entry = entry.unwrap();
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        if let Some("c") = path.extension().and_then(|e| e.to_str()) {
            // Skip tests that don't work on 32-bit
            if is_32bit
                && path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|file_name| SKIP_ON_32BIT.contains(&file_name))
            {
                continue;
            }
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
    Runner::new(Backend::Rewriter, &python_path, "python_rewriter")
        .args(["-c", HELLO_WORLD_PY])
        .envs([
            &format!("PYTHONHOME={}", python_home.trim()),
            &format!("PYTHONPATH={}", python_sys_path.trim()),
            // LiteBox does not support timestamp yet, so pre-compiled .pyc files are not usable.
            // Avoid creating .pyc files as tar filesystem is read-only.
            "PYTHONDONTWRITEBYTECODE=1",
        ])
        .with_fs_path(|out_dir| {
            for each in python_sys_path.split(':') {
                if each.is_empty() || !each.starts_with("/usr") {
                    continue;
                }
                let python_lib_src = Path::new(each);
                if python_lib_src.is_dir() {
                    let python_lib_dst = out_dir.join(&each[1..]); // remove leading '/'
                    if !python_lib_dst.exists() {
                        std::fs::create_dir_all(&python_lib_dst).unwrap();
                        println!(
                            "Copying python3 lib from {} to {}",
                            python_lib_src.to_str().unwrap(),
                            python_lib_dst.to_str().unwrap()
                        );
                        let output = std::process::Command::new("cp")
                            .args([
                                "-rpL", // -r for recursive, -p to preserve attributes, -L to dereference symbolic links
                                python_lib_src.to_str().unwrap(),
                                python_lib_dst.parent().unwrap().to_str().unwrap(),
                            ])
                            .output()
                            .expect("Failed to copy python3 lib");
                        assert!(
                            output.status.success(),
                            "failed to copy python3 lib {:?}",
                            std::str::from_utf8(output.stderr.as_slice()).unwrap()
                        );
                    }
                    let known_exts = ["py", "pyc", "txt", "css", "ps1", "rst"];
                    // rewrite all files under the python lib directory except those with known extensions
                    for entry in walkdir::WalkDir::new(python_lib_src)
                        .into_iter()
                        .filter_map(std::result::Result::ok)
                        .filter(|e| {
                            e.path()
                                .extension()
                                .is_some_and(|ext| !known_exts.contains(&ext.to_str().unwrap()))
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
                        if entry.path().extension().is_some_and(|ext| ext == "so") {
                            assert!(success, "failed to rewrite {} file", so_file.display());
                        }
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
