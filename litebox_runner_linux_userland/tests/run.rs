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
        let tar_file_str = tar_file.to_str().unwrap();
        println!("Tar file ready at: {tar_file_str}");

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
fn try_which(prog: &str) -> Option<std::path::PathBuf> {
    let output = std::process::Command::new("which")
        .arg(prog)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let prog_path_str = String::from_utf8(output.stdout).ok()?.trim().to_string();
    if prog_path_str.is_empty() {
        return None;
    }
    let prog_path = std::path::PathBuf::from(prog_path_str);
    if prog_path.exists() {
        Some(prog_path)
    } else {
        None
    }
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
        let binary_path_display = binary_path.display();
        eprintln!("Warning: readelf failed for {binary_path_display}");
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
#[ignore = "Known issue: test hangs indefinitely - TUN networking issue"]
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
    let Some(iperf3_path) = try_which("iperf3") else {
        println!("Skipping test: iperf3 not found");
        println!("  On Debian/Ubuntu: sudo apt install -y iperf3");
        println!("  On RHEL/Fedora: sudo dnf install -y iperf3");
        return;
    };
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

/// Test basic shell execution with /bin/sh
/// This test attempts to run a simple echo command using /bin/sh
#[cfg(all(target_arch = "x86_64", target_os = "linux"))]
#[test]
fn test_runner_with_shell() {
    let sh_path = run_which("sh");

    if has_origin_in_libs(&sh_path) {
        println!(
            "Skipping test: Shell executable at {} uses $ORIGIN in library paths",
            sh_path.display()
        );
        return;
    }

    let sh_path_display = sh_path.display();
    println!("Testing shell execution with: {sh_path_display}");

    // Try to run a simple echo command
    let output = Runner::new(Backend::Rewriter, &sh_path, "shell_rewriter")
        .args(["-c", "echo 'Hello from shell in litebox!'"])
        .output();

    let output_str = String::from_utf8_lossy(&output);
    println!("Shell output: {output_str}");
    assert!(output_str.contains("Hello from shell in litebox!"));
}

/// Test shell script with multiple commands
#[cfg(all(target_arch = "x86_64", target_os = "linux"))]
#[test]
fn test_runner_with_shell_script() {
    let sh_path = run_which("sh");

    if has_origin_in_libs(&sh_path) {
        println!("Skipping test: Shell script test - shell uses $ORIGIN in library paths");
        return;
    }

    println!("Testing shell script with multiple commands");

    // Test a more complex shell script with variables and multiple commands
    let script = r#"
        name="LiteBox"
        echo "Welcome to $name"
        echo "Testing shell features"
        result=$((2 + 2))
        echo "Math result: $result"
    "#;

    let output = Runner::new(Backend::Rewriter, &sh_path, "shell_script_rewriter")
        .args(["-c", script])
        .output();

    let output_str = String::from_utf8_lossy(&output);
    println!("Shell script output:\n{output_str}");

    assert!(output_str.contains("Welcome to LiteBox"));
    assert!(output_str.contains("Testing shell features"));
    assert!(output_str.contains("Math result: 4"));
}

/// Test shell script with ls command
/// This demonstrates script interpreter support
/// Note: Currently requires vfork/fork support to execute external commands from shell
#[cfg(all(target_arch = "x86_64", target_os = "linux"))]
#[test]
#[ignore = "Shell executing external commands requires vfork/fork which needs additional work"]
fn test_runner_with_shell_script_ls() {
    let sh_path = run_which("sh");

    if has_origin_in_libs(&sh_path) {
        println!("Skipping test: Shell script ls test - shell uses $ORIGIN in library paths");
        return;
    }

    // Find ls command
    let ls_path_output = std::process::Command::new("which")
        .arg("ls")
        .output()
        .expect("Failed to find ls");
    let ls_path = String::from_utf8(ls_path_output.stdout)
        .unwrap()
        .trim()
        .to_string();

    if ls_path.is_empty() {
        println!("Skipping test: ls command not found");
        return;
    }

    println!("Testing shell script with ls command from: {ls_path}");

    // Test a shell script that uses ls to list the root directory
    // Keep it simple - just call ls without pipes or redirects
    let script = format!(
        "
        echo \"=== Script Interpreter Test with ls ===\"
        echo \"Calling ls command:\"
        {ls_path} /
        echo \"=== Script test completed ===\"
    "
    );

    let output = Runner::new(Backend::Rewriter, &sh_path, "shell_script_ls_rewriter")
        .args(["-c", &script])
        .output();

    let output_str = String::from_utf8_lossy(&output);
    println!("Shell script with ls output:\n{output_str}");

    // Verify the script executed (the output should contain our markers)
    assert!(
        output_str.contains("Script Interpreter Test with ls"),
        "Script should have started execution"
    );
    assert!(
        output_str.contains("Script test completed"),
        "Script should have completed"
    );
}

/// Test bash shell with advanced features
/// Note: Bash now has basic support with getpgrp implemented. Some ioctl operations may still be missing.
#[cfg(all(target_arch = "x86_64", target_os = "linux"))]
#[test]
fn test_runner_with_bash() {
    let bash_path = run_which("bash");

    if has_origin_in_libs(&bash_path) {
        println!("Skipping test: Bash uses $ORIGIN in library paths");
        return;
    }

    let bash_path_display = bash_path.display();
    println!("Testing bash execution with: {bash_path_display}");

    // Test bash with a simple command first
    let script = r#"echo "Hello from bash in LiteBox""#;

    let output = Runner::new(Backend::Rewriter, &bash_path, "bash_rewriter")
        .args(["-c", script])
        .output();

    let output_str = String::from_utf8_lossy(&output);
    println!("Bash script output:\n{output_str}");

    assert!(output_str.contains("Hello from bash in LiteBox"));
}

/// Test Node.js execution
#[cfg(all(target_arch = "x86_64", target_os = "linux"))]
#[test]
fn test_runner_with_node() {
    let node_path = run_which("node");

    if has_origin_in_libs(&node_path) {
        println!("Skipping test: Node.js uses $ORIGIN in library paths");
        return;
    }

    let node_path_display = node_path.display();
    println!("Testing Node.js execution with: {node_path_display}");

    // Test Node.js with a simple script
    let script = r"console.log('Hello from Node.js in LiteBox!');";

    let output = Runner::new(Backend::Rewriter, &node_path, "node_rewriter")
        .args(["-e", script])
        .output();

    let output_str = String::from_utf8_lossy(&output);
    println!("Node.js script output:\n{output_str}");

    assert!(output_str.contains("Hello from Node.js in LiteBox!"));
}
