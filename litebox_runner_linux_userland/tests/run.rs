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

/// End-to-end test for fork → exec → waitpid lifecycle.
/// Compiled as dynamic (PIE) because child processes get a different VA
/// partition and ET_EXEC binaries have hardcoded addresses in slot 0.
#[cfg(target_arch = "x86_64")]
#[test]
fn test_fork_exec_waitpid() {
    let unique_name = "fork_exec_wait_rewriter";
    let target = common::compile(
        "./tests/multiprocess/fork_exec_wait.c",
        unique_name,
        false, // dynamic (PIE)
        false,
    );
    let output = Runner::new(Backend::Rewriter, &target, unique_name).output();
    let output_str = String::from_utf8_lossy(&output);
    assert!(
        output_str.contains("[OK]"),
        "fork_exec_wait test failed:\n{output_str}",
    );
}

/// End-to-end test for cross-process pipes: parent creates pipe, child
/// writes through it after vfork+exec, parent reads after waitpid.
#[cfg(target_arch = "x86_64")]
#[test]
fn test_pipe_cross_process() {
    let unique_name = "pipe_cross_process_rewriter";
    let target = common::compile(
        "./tests/multiprocess/pipe_cross_process.c",
        unique_name,
        false, // dynamic (PIE)
        false,
    );
    let output = Runner::new(Backend::Rewriter, &target, unique_name).output();
    let output_str = String::from_utf8_lossy(&output);
    assert!(
        output_str.contains("[OK]"),
        "pipe_cross_process test failed:\n{output_str}",
    );
}

/// Verify that pipe2(O_CLOEXEC) fds are properly closed in the child
/// after vfork+exec (i.e., the FD_CLOEXEC metadata is preserved across
/// fork-time fd duplication).
#[cfg(target_arch = "x86_64")]
#[test]
fn test_pipe_cloexec() {
    let unique_name = "pipe_cloexec_rewriter";
    let target = common::compile(
        "./tests/multiprocess/pipe_cloexec.c",
        unique_name,
        false, // dynamic (PIE)
        false,
    );
    let output = Runner::new(Backend::Rewriter, &target, unique_name).output();
    let output_str = String::from_utf8_lossy(&output);
    assert!(
        output_str.contains("[OK]"),
        "pipe_cloexec test failed:\n{output_str}",
    );
}

/// Test vfork child that writes to pipe WITHOUT exec (like bash builtin).
/// The echo child does dup2+write+_exit without execve.
#[cfg(target_arch = "x86_64")]
#[test]
fn test_pipe_vfork_builtin() {
    let unique_name = "pipe_vfork_builtin_rewriter";
    let target = common::compile(
        "./tests/multiprocess/pipe_vfork_builtin.c",
        unique_name,
        true, // static
        false,
    );
    let output = Runner::new(Backend::Rewriter, &target, unique_name).output();
    let output_str = String::from_utf8_lossy(&output);
    assert!(
        output_str.contains("hello-from-vfork"),
        "pipe_vfork_builtin test failed:\n{output_str}",
    );
}

/// End-to-end test for fork-based context switching via synchronized pipe I/O.
/// Parent and child exchange iteration counters through two pipes.  This
/// exercises the delayed-fork path because the child calls read() (a
/// non-pre-exec syscall) before ever calling exec.
#[cfg(target_arch = "x86_64")]
#[test]
fn test_context_switch() {
    let unique_name = "context_switch_rewriter";
    let target = common::compile(
        "./tests/multiprocess/context_switch.c",
        unique_name,
        false, // dynamic (PIE)
        false,
    );
    let output = Runner::new(Backend::Rewriter, &target, unique_name).output();
    let output_str = String::from_utf8_lossy(&output);
    assert!(
        output_str.contains("[OK]"),
        "context_switch test failed:\n{output_str}",
    );
}

/// End-to-end test for bidirectional pipe I/O with a non-PIE child binary.
/// Parent (PIE) creates pipes, forks, child execs a static (non-PIE / ET_EXEC)
/// helper via the remote-exec path.  Data flows through pipes in both
/// directions — parent writes to child stdin and reads child stdout.
/// This exercises the worker-host exec pipe bridging path.
#[cfg(target_arch = "x86_64")]
#[test]
fn test_pipe_nonpie_exec() {
    // Compile the non-PIE helper (static = ET_EXEC).
    let helper_name = "echo_nonpie_helper_rewriter";
    let helper_target = common::compile(
        "./tests/multiprocess/echo_nonpie_helper.c",
        helper_name,
        true, // static (non-PIE)
        false,
    );

    // Compile the PIE parent driver.
    let unique_name = "pipe_nonpie_exec_rewriter";
    let target = common::compile(
        "./tests/multiprocess/pipe_nonpie_exec.c",
        unique_name,
        false, // dynamic (PIE)
        false,
    );

    // Build the runner, inject the non-PIE helper into the guest filesystem,
    // and tell the parent where to find it.
    let helper_guest_path = "/out/echo_nonpie_helper";
    let mut runner = Runner::new(Backend::Rewriter, &target, unique_name);

    // Copy the rewritten helper into the tar filesystem.
    runner.with_fs_path(|tar_dir| {
        let out_path = tar_dir.join("out").join("echo_nonpie_helper");
        let success = common::rewrite_with_cache(&helper_target, &out_path, &[]);
        assert!(success, "failed to rewrite echo_nonpie_helper");
    });

    runner.env(format!("ECHO_HELPER_PATH={helper_guest_path}"));
    let output = runner.output();
    let output_str = String::from_utf8_lossy(&output);
    assert!(
        output_str.contains("[OK]"),
        "pipe_nonpie_exec test failed:\n{output_str}",
    );
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

/// Stage an additional host binary (+ its dependencies, rewritten) into
/// the guest filesystem tar directory. Used to make binaries like `cat`
/// available for bash to exec.
#[cfg(target_arch = "x86_64")]
fn stage_host_binary(tar_dir: &Path, binary_name: &str, guest_path: &str) {
    let host_path = run_which(binary_name);
    let dir_path = PathBuf::from(std::env::var_os("OUT_DIR").unwrap());

    // Rewrite the binary itself.
    let rewritten = dir_path.join(format!("{binary_name}.hooked"));
    let success = common::rewrite_with_cache(&host_path, &rewritten, &[]);
    assert!(success, "failed to rewrite {binary_name}");

    // Copy rewritten binary to guest filesystem.
    let dest = tar_dir.join(&guest_path[1..]); // strip leading '/'
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    std::fs::copy(&rewritten, &dest).unwrap();

    // Rewrite and stage any dependencies not already present.
    let deps = common::find_dependencies(host_path.to_str().unwrap());
    for dep in &deps {
        let dep_path = Path::new(dep.as_str());
        let dep_dest = tar_dir.join(&dep[1..]);
        if dep_dest.exists() {
            continue; // already staged by the main binary
        }
        if let Some(parent) = dep_dest.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        let success = common::rewrite_with_cache(dep_path, &dep_dest, &[]);
        assert!(success, "failed to rewrite dependency {dep}");
    }
}

/// Run bash with a simple echo (builtin). Tests that bash can start and
/// execute a command on LiteBox userland.
#[cfg(target_arch = "x86_64")]
#[test]
fn test_bash_echo() {
    let bash_path = run_which("bash");
    let output = Runner::new(Backend::Rewriter, &bash_path, "bash_echo_rewriter")
        .args(["--norc", "--noprofile", "-c", "echo hello-from-bash"])
        .output();
    let output_str = String::from_utf8_lossy(&output);
    assert!(
        output_str.contains("hello-from-bash"),
        "bash echo test failed:\n{output_str}",
    );
}

/// Signal delivery and return must preserve the full AVX register state on
/// x86_64, not just the legacy FXSAVE subset.
#[cfg(target_arch = "x86_64")]
#[test]
fn test_avx_signal_state_preserved() {
    if !std::arch::is_x86_feature_detected!("avx") {
        eprintln!("Skipping AVX signal test: host CPU does not expose AVX");
        return;
    }

    let target = common::compile("./tests/avx_signal.c", "avx_signal_static", true, false);
    let output = Runner::new(Backend::Rewriter, &target, "avx_signal_state_rewriter").output();
    let output_str = String::from_utf8_lossy(&output);
    assert!(
        output_str.contains("AVX state preserved"),
        "AVX signal preservation test failed:\n{output_str}",
    );
}

/// Run bash piping echo (builtin) into /bin/cat (fork+exec). Tests the
/// full multi-process stack: fork, exec, pipes, waitpid.
#[cfg(target_arch = "x86_64")]
#[test]
fn test_bash_pipe_cat() {
    let bash_path = run_which("bash");
    let output = Runner::new(Backend::Rewriter, &bash_path, "bash_pipe_cat_rewriter")
        .args([
            "--norc",
            "--noprofile",
            "-c",
            "echo hello-pipe-test | /bin/cat",
        ])
        .with_fs_path(|tar_dir| {
            stage_host_binary(tar_dir, "cat", "/bin/cat");
        })
        .output();
    let output_str = String::from_utf8_lossy(&output);
    assert!(
        output_str.contains("hello-pipe-test"),
        "bash pipe+cat test failed:\n{output_str}",
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
        std::println!("Connecting iperf3 client...");
        // Retry with a short connect-timeout instead of a fixed sleep, so we
        // start the transfer as soon as the server is actually listening.
        let mut connected = false;
        for attempt in 1..=50 {
            let status = std::process::Command::new(&cloned_path)
                .args([
                    "-c",
                    "10.0.0.2",
                    "-P",
                    NUM_CLIENTS.to_string().leak(),
                    "--connect-timeout",
                    "50",
                    "--time",
                    "1",
                ])
                .status()
                .expect("Failed to start iperf3 client");
            if status.success() {
                connected = true;
                break;
            }
            std::eprintln!("iperf3 client attempt {attempt} failed, retrying");
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        assert!(
            connected,
            "iperf3 client failed to connect after 50 attempts"
        );
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

#[cfg(target_arch = "x86_64")]
#[test]
fn test_tun_with_curl() {
    use std::io::{Read, Write};
    use std::net::TcpListener;

    const RESPONSE_BODY: &str = "#!/bin/bash\necho 'Hello from litebox!'\n";

    // Bind to an OS-assigned port on all interfaces.
    let listener = TcpListener::bind("0.0.0.0:0").expect("Failed to bind HTTP server");
    let port = listener.local_addr().unwrap().port();

    let server_thread = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("Failed to accept connection");
        let mut buf = [0u8; 4096];
        let n = stream.read(&mut buf).expect("Failed to read request");
        let request = String::from_utf8_lossy(&buf[..n]);
        println!("Received HTTP request:\n{request}");

        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            RESPONSE_BODY.len(),
            RESPONSE_BODY
        );
        stream
            .write_all(response.as_bytes())
            .expect("Failed to send response");
    });

    let curl_path = run_which("curl");
    let url = format!("http://10.0.0.1:{port}/something");
    let output = Runner::new(Backend::Rewriter, &curl_path, "curl_rewriter")
        .args(["-sS", &url])
        .tun_device_name("tun99")
        .output();

    server_thread.join().expect("Server thread panicked");

    let output_str = String::from_utf8_lossy(&output);
    assert!(output_str.contains(RESPONSE_BODY), "Unexpected curl output");
}

/// Test shell pipe with busybox via --program-from-tar.
/// This exercises fork + pipe in the context of a statically-linked
/// multi-call binary (busybox), which is how the LLM sandbox demo works.
#[cfg(target_arch = "x86_64")]
#[test]
fn test_busybox_shell_pipe() {
    // Find busybox on the host.
    let busybox_path = if std::path::Path::new("/bin/busybox").exists() {
        "/bin/busybox"
    } else if std::path::Path::new("/usr/bin/busybox").exists() {
        "/usr/bin/busybox"
    } else {
        eprintln!("busybox not found, skipping test");
        return;
    };

    // Package busybox into a rootfs tar via litebox_packager.
    let packager_path = std::env::var("CARGO_BIN_EXE_litebox_packager").unwrap_or_else(|_| {
        // Fall back to looking in target/debug
        let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
        let workspace = std::path::Path::new(&manifest_dir).parent().unwrap();
        workspace
            .join("target/debug/litebox_packager")
            .to_str()
            .unwrap()
            .to_string()
    });

    let dir_path = PathBuf::from(std::env::var_os("OUT_DIR").unwrap());
    let tar_path = dir_path.join("busybox_pipe_test.tar");

    // Build the rootfs tar (rewrite busybox syscalls).
    let packager_output = std::process::Command::new(&packager_path)
        .args([busybox_path, "-o", tar_path.to_str().unwrap()])
        .output();

    match packager_output {
        Ok(out) if out.status.success() => {}
        Ok(out) => {
            eprintln!(
                "litebox_packager failed ({}): {}",
                out.status,
                String::from_utf8_lossy(&out.stderr)
            );
            eprintln!("skipping test (packager not available)");
            return;
        }
        Err(e) => {
            eprintln!("litebox_packager not found ({e}), skipping test");
            return;
        }
    }

    // Determine the guest path based on the host path used for packaging.
    let guest_busybox = busybox_path; // packager preserves the host path

    // Run: busybox sh -c 'echo hello | cat'
    // Wrap with `timeout` to detect hangs (fork not working = child never runs).
    let runner_path = std::env::var("NEXTEST_BIN_EXE_litebox_runner_linux_userland")
        .unwrap_or_else(|_| env!("CARGO_BIN_EXE_litebox_runner_linux_userland").to_string());

    let output = std::process::Command::new("timeout")
        .args([
            "15",
            &runner_path,
            "--unstable",
            "--initial-files",
            tar_path.to_str().unwrap(),
            "--program-from-tar",
            "--",
            guest_busybox,
            "sh",
            "-c",
            "echo hello | cat",
        ])
        .output()
        .expect("failed to run litebox_runner_linux_userland");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    // timeout exits with 124 when the command times out.
    assert!(
        output.status.code() != Some(124),
        "busybox pipe test TIMED OUT — fork/pipe likely hung.\n\
         stderr (last 500 chars): {}",
        &stderr[stderr.len().saturating_sub(500)..],
    );

    assert!(
        stdout.contains("hello"),
        "busybox pipe test failed — expected 'hello' in stdout.\n\
         exit status: {}\n\
         stdout: {stdout}\n\
         stderr (last 500 chars): {}",
        output.status,
        &stderr[stderr.len().saturating_sub(500)..],
    );
}

/// Verify that the Linux userland platform's delayed-fork model handles
/// multi-process external-command pipelines correctly.
///
/// Under delayed fork (vfork-like semantics), each fork() call blocks the
/// parent until the child exec's. After exec, the child runs as an
/// independent worker process. This means pipeline stages are spawned
/// sequentially but run concurrently once exec'd — so data flows through
/// the pipe even when it exceeds the kernel pipe buffer (64 KiB).
///
/// This test exercises:
/// 1. Large data (>64 KiB) through a 2-stage external pipe
/// 2. A 3-stage external pipeline (seq | head | cat)
/// 3. A classic utility pipeline (ls | sort | uniq)
#[cfg(target_arch = "x86_64")]
#[test]
fn test_multi_external_pipes_on_userland() {
    let bash_path = run_which("bash");

    // --- Test 1: large data through a 2-stage pipe ---
    {
        let output = Runner::new(Backend::Rewriter, &bash_path, "large_pipe_2stage")
            .args([
                "--norc",
                "--noprofile",
                "-c",
                // seq produces ~588 KiB (well over the 64K pipe buffer).
                // If delayed fork can't handle concurrent children, this deadlocks.
                "/usr/bin/seq 1 100000 | /bin/cat > /dev/null && echo large-pipe-ok",
            ])
            .with_fs_path(|tar_dir| {
                stage_host_binary(tar_dir, "cat", "/bin/cat");
                stage_host_binary(tar_dir, "seq", "/usr/bin/seq");
            })
            .output();
        let s = String::from_utf8_lossy(&output);
        assert!(
            s.contains("large-pipe-ok"),
            "large 2-stage pipe failed:\n{s}",
        );
    }

    // --- Test 2: 3-stage external-command pipeline ---
    {
        let output = Runner::new(Backend::Rewriter, &bash_path, "pipe_3stage")
            .args([
                "--norc",
                "--noprofile",
                "-c",
                "/usr/bin/seq 1 100000 | /usr/bin/head -n 10 | /bin/cat",
            ])
            .with_fs_path(|tar_dir| {
                stage_host_binary(tar_dir, "cat", "/bin/cat");
                stage_host_binary(tar_dir, "seq", "/usr/bin/seq");
                stage_host_binary(tar_dir, "head", "/usr/bin/head");
            })
            .output();
        let s = String::from_utf8_lossy(&output);
        // seq 1..10 should appear
        assert!(
            s.contains("10"),
            "3-stage pipe missing expected output:\n{s}"
        );
    }

    // --- Test 3: ls | sort | uniq (classic 3-stage utility pipeline) ---
    {
        let output = Runner::new(Backend::Rewriter, &bash_path, "ls_sort_uniq")
            .args([
                "--norc",
                "--noprofile",
                "-c",
                // Create a few files then list + sort + dedup.
                "echo a > /tmp/a; echo b > /tmp/b; \
                 /bin/ls /tmp | /usr/bin/sort | /usr/bin/uniq",
            ])
            .with_fs_path(|tar_dir| {
                stage_host_binary(tar_dir, "ls", "/bin/ls");
                stage_host_binary(tar_dir, "sort", "/usr/bin/sort");
                stage_host_binary(tar_dir, "uniq", "/usr/bin/uniq");
            })
            .output();
        let s = String::from_utf8_lossy(&output);
        assert!(
            s.contains("a") && s.contains("b"),
            "ls|sort|uniq failed:\n{s}",
        );
    }
}

// ---------------------------------------------------------------------------
// --program-from-tar fork+pipe tests
//
// These exercise bash pipelines with --program-from-tar, which is the mode
// the tool_executor uses. The Runner-based tests above load bash from the
// *host* filesystem; these load everything from a self-contained tar.
//
// Bare-name pipe tests run each case 20 times to expose non-determinism.
// Each reports pass/fail/timeout statistics rather than asserting a single
// expected outcome.
// ---------------------------------------------------------------------------

/// Helper: find the bash-sandbox.tar built by prepare-bash-rootfs.sh.
#[cfg(target_arch = "x86_64")]
fn bash_sandbox_tar() -> Option<PathBuf> {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let workspace = Path::new(&manifest_dir).parent().unwrap();
    let path = workspace.join("target/bash-sandbox.tar");
    if path.exists() { Some(path) } else { None }
}

/// Validate that the bash-sandbox.tar has the expected structure.
/// Catches build issues before they manifest as mysterious test failures.
#[cfg(target_arch = "x86_64")]
fn validate_tar(tar_path: &Path) {
    let output = std::process::Command::new("tar")
        .args(["tf", tar_path.to_str().unwrap()])
        .output()
        .expect("failed to list tar contents");
    let listing = String::from_utf8_lossy(&output.stdout);
    let entries: Vec<&str> = listing.lines().collect();

    // Required binaries (real files in /usr/bin)
    for bin in [
        "./usr/bin/bash",
        "./usr/bin/cat",
        "./usr/bin/ls",
        "./usr/bin/sort",
        "./usr/bin/grep",
    ] {
        assert!(
            entries.iter().any(|e| *e == bin),
            "tar missing required binary: {bin}\n\
             Rebuild with: bash litebox_tool_executor/scripts/prepare-bash-rootfs.sh\n\
             tar has {n} entries",
            n = entries.len(),
        );
    }

    // Required shared libraries
    for lib in ["libc.so", "ld-linux-x86-64.so"] {
        assert!(
            entries.iter().any(|e| e.contains(lib)),
            "tar missing required library matching '{lib}'",
        );
    }

    // /bin/ symlinks must exist
    for link in ["./bin/cat", "./bin/ls", "./bin/sort", "./bin/grep"] {
        assert!(
            entries.iter().any(|e| *e == link),
            "tar missing expected symlink: {link}",
        );
    }

    // Verify symlink targets point to /usr/bin/
    let output = std::process::Command::new("tar")
        .args(["tvf", tar_path.to_str().unwrap()])
        .output()
        .expect("failed to list tar with details");
    let verbose = String::from_utf8_lossy(&output.stdout);
    for name in ["bin/cat", "bin/ls", "bin/sort"] {
        if let Some(line) = verbose
            .lines()
            .find(|l| l.contains(&format!("./{name} -> ")))
        {
            assert!(
                line.contains("/usr/bin/"),
                "/bin symlink ./{name} doesn't point to /usr/bin/: {line}",
            );
        }
    }
}

/// Helper: run a bash command via --program-from-tar with a timeout.
/// Returns (stdout, stderr, exit_code). Exit code 124 = timeout.
#[cfg(target_arch = "x86_64")]
fn run_bash_from_tar(tar_path: &Path, bash_cmd: &str, timeout_secs: &str) -> (String, String, i32) {
    let runner_path = std::env::var("NEXTEST_BIN_EXE_litebox_runner_linux_userland")
        .unwrap_or_else(|_| env!("CARGO_BIN_EXE_litebox_runner_linux_userland").to_string());

    let output = std::process::Command::new("timeout")
        .args([
            timeout_secs,
            &runner_path,
            "--unstable",
            "--initial-files",
            tar_path.to_str().unwrap(),
            "--program-from-tar",
            "--env",
            "LD_LIBRARY_PATH=/lib64:/lib/x86_64-linux-gnu:/lib",
            "--env",
            "HOME=/",
            "--env",
            "PATH=/usr/bin:/bin",
            "--env",
            "TERM=dumb",
            "--",
            "/usr/bin/bash",
            "--norc",
            "--noprofile",
            "-c",
            bash_cmd,
        ])
        .output()
        .expect("failed to spawn runner");

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let code = output.status.code().unwrap_or(-1);
    (stdout, stderr, code)
}

/// Outcome statistics from running a command multiple times.
#[cfg(target_arch = "x86_64")]
#[derive(Debug, Default)]
struct TrialStats {
    pass: u32,
    empty: u32,   // exit 0 but expected output missing
    timeout: u32, // exit 124
    error: u32,   // other non-zero exit
}

#[cfg(target_arch = "x86_64")]
impl std::fmt::Display for TrialStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let total = self.pass + self.empty + self.timeout + self.error;
        write!(
            f,
            "{total} trials: {pass} pass, {empty} empty, {timeout} timeout, {error} error",
            pass = self.pass,
            empty = self.empty,
            timeout = self.timeout,
            error = self.error,
        )
    }
}

/// Run a command N times and collect statistics.
#[cfg(target_arch = "x86_64")]
fn run_trials(
    tar_path: &Path,
    bash_cmd: &str,
    expected_substr: &str,
    n: u32,
    timeout_secs: &str,
) -> TrialStats {
    let mut stats = TrialStats::default();
    for _ in 0..n {
        let (stdout, _stderr, code) = run_bash_from_tar(tar_path, bash_cmd, timeout_secs);
        match code {
            124 => stats.timeout += 1,
            0 if stdout.contains(expected_substr) => stats.pass += 1,
            0 => stats.empty += 1,
            _ => stats.error += 1,
        }
    }
    stats
}

#[cfg(target_arch = "x86_64")]
fn report_bare_pipe_result(label: &str, stats: &TrialStats) {
    let total = stats.pass + stats.empty + stats.timeout + stats.error;
    eprintln!("bare `{label}` via --program-from-tar: {stats}");
    if stats.pass == total {
        eprintln!("  → ALL PASSED — the bug may be fixed!");
    } else if stats.pass > 0 {
        eprintln!("  → FLAKY: passes {}/{total} times", stats.pass);
    } else {
        eprintln!("  → ALWAYS FAILS (0/{total})");
    }
}

// ---------------------------------------------------------------------------
// Tar validation
// ---------------------------------------------------------------------------

/// Validate tar structure before running any --program-from-tar tests.
#[cfg(target_arch = "x86_64")]
#[test]
fn test_tar_validate() {
    let Some(tar) = bash_sandbox_tar() else {
        eprintln!("Skipping: bash-sandbox.tar not found (run prepare-bash-rootfs.sh)");
        return;
    };
    validate_tar(&tar);
}

// ---------------------------------------------------------------------------
// Baselines: these must always pass (10 trials each).
// ---------------------------------------------------------------------------

#[cfg(target_arch = "x86_64")]
#[test]
fn test_tar_baseline_echo() {
    let Some(tar) = bash_sandbox_tar() else {
        return;
    };
    let stats = run_trials(&tar, "echo hello-tar", "hello-tar", 10, "10");
    assert_eq!(stats.pass, 10, "echo should always work. {stats}");
}

#[cfg(target_arch = "x86_64")]
#[test]
fn test_tar_baseline_builtin_pipe_cat() {
    let Some(tar) = bash_sandbox_tar() else {
        return;
    };
    let stats = run_trials(
        &tar,
        "echo hello-pipe | /usr/bin/cat",
        "hello-pipe",
        10,
        "10",
    );
    assert_eq!(
        stats.pass, 10,
        "builtin | /usr/bin/cat should always work. {stats}"
    );
}

#[cfg(target_arch = "x86_64")]
#[test]
fn test_tar_baseline_full_path_echo_pipe_cat() {
    let Some(tar) = bash_sandbox_tar() else {
        return;
    };
    let stats = run_trials(
        &tar,
        "/usr/bin/echo hello-full | /usr/bin/cat",
        "hello-full",
        10,
        "10",
    );
    assert_eq!(
        stats.pass, 10,
        "full-path echo|cat should always work. {stats}"
    );
}

#[cfg(target_arch = "x86_64")]
#[test]
fn test_tar_baseline_full_path_ls_sort() {
    let Some(tar) = bash_sandbox_tar() else {
        return;
    };
    let stats = run_trials(
        &tar,
        "echo a > /tmp/a; echo b > /tmp/b; /usr/bin/ls /tmp | /usr/bin/sort",
        "a",
        10,
        "10",
    );
    assert_eq!(
        stats.pass, 10,
        "full-path ls|sort should always work. {stats}"
    );
}

#[cfg(target_arch = "x86_64")]
#[test]
fn test_tar_baseline_full_path_ls_subshell() {
    let Some(tar) = bash_sandbox_tar() else {
        return;
    };
    let stats = run_trials(&tar, "x=$(/usr/bin/ls /); echo $x", "tmp", 10, "10");
    assert_eq!(
        stats.pass, 10,
        "full-path ls subshell should always work. {stats}"
    );
}

#[cfg(target_arch = "x86_64")]
#[test]
fn test_tar_baseline_bare_ls_subshell() {
    let Some(tar) = bash_sandbox_tar() else {
        return;
    };
    let stats = run_trials(&tar, "x=$(ls /); echo \"LS=$x\"", "tmp", 10, "10");
    eprintln!("bare ls subshell: {stats}");
    // If this is flaky, the non-determinism extends to subshells too.
    assert!(stats.pass > 0, "bare ls subshell never worked. {stats}");
}

// ---------------------------------------------------------------------------
// Bare-name pipe tests: 20 trials each to expose non-determinism.
//
// These document the bug. Each test reports statistics. They do NOT assert
// failure — they report pass rates so we can distinguish:
//   "always broken" vs "flaky" vs "always works"
// ---------------------------------------------------------------------------

#[cfg(target_arch = "x86_64")]
#[test]
fn test_tar_bare_pipe_echo_cat() {
    let Some(tar) = bash_sandbox_tar() else {
        return;
    };
    let stats = run_trials(&tar, "echo works | cat", "works", 20, "5");
    report_bare_pipe_result("echo | cat", &stats);
}

#[cfg(target_arch = "x86_64")]
#[test]
fn test_tar_bare_pipe_echo_sort() {
    let Some(tar) = bash_sandbox_tar() else {
        return;
    };
    let stats = run_trials(&tar, "echo zzz | sort", "zzz", 20, "5");
    report_bare_pipe_result("echo | sort", &stats);
}

#[cfg(target_arch = "x86_64")]
#[test]
fn test_tar_bare_pipe_ls_sort() {
    let Some(tar) = bash_sandbox_tar() else {
        return;
    };
    let stats = run_trials(
        &tar,
        "echo a > /tmp/a; echo b > /tmp/b; ls /tmp | sort",
        "a",
        20,
        "5",
    );
    report_bare_pipe_result("ls | sort", &stats);
}

#[cfg(target_arch = "x86_64")]
#[test]
fn test_tar_bare_pipe_grep() {
    let Some(tar) = bash_sandbox_tar() else {
        return;
    };
    let stats = run_trials(
        &tar,
        "echo hello-grep | grep hello | cat",
        "hello-grep",
        20,
        "5",
    );
    report_bare_pipe_result("echo | grep | cat", &stats);
}

// ---------------------------------------------------------------------------
// Direct comparison: same pipeline, bare vs full paths, 20 trials each.
// Most controlled test — isolates the bug to path resolution in fork+exec.
// ---------------------------------------------------------------------------

#[cfg(target_arch = "x86_64")]
#[test]
fn test_tar_bare_vs_full_path_comparison() {
    let Some(tar) = bash_sandbox_tar() else {
        return;
    };
    let n = 20;

    let full = run_trials(
        &tar,
        "/usr/bin/echo hello-cmp | /usr/bin/cat",
        "hello-cmp",
        n,
        "5",
    );
    let bare = run_trials(&tar, "echo hello-cmp | cat", "hello-cmp", n, "5");

    eprintln!("=== bare vs full path comparison ({n} trials each) ===");
    eprintln!("  full path: {full}");
    eprintln!("  bare name: {bare}");

    assert_eq!(
        full.pass, n,
        "full-path echo|cat should always work. {full}"
    );

    if bare.pass == full.pass {
        eprintln!("  → No difference — bare names work as well as full paths!");
    } else {
        eprintln!(
            "  → BUG CONFIRMED: full paths pass {}/{n} but bare names pass {}/{n}",
            full.pass, bare.pass,
        );
    }
}
