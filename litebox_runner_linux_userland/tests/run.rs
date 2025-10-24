mod cache;
mod common;

use std::{
    os::unix::process::ExitStatusExt as _,
    path::{Path, PathBuf},
};

#[allow(dead_code)]
enum Backend {
    Rewriter,
    Seccomp,
}

fn run_target_program<F: FnOnce(PathBuf)>(
    backend: Backend,
    target: &Path,
    cmd_args: &[&str],
    environments: &[&str],
    install_files: F,
    unique_name: &str,
    tun_name: Option<&str>,
) -> Vec<u8> {
    let backend_str = match backend {
        Backend::Rewriter => "rewriter",
        Backend::Seccomp => "seccomp",
    };
    let dir_path = std::env::var("OUT_DIR").unwrap();
    let path = match backend {
        Backend::Seccomp => target.to_path_buf(),
        Backend::Rewriter => {
            // new path in out_dir with .hooked suffix
            let out_path = std::path::Path::new(dir_path.as_str()).join(format!(
                "{}.hooked",
                target.file_name().unwrap().to_str().unwrap()
            ));
            let success = common::rewrite_with_cache(target, &out_path, &[]);
            assert!(success, "failed to run litebox_syscall_rewriter");
            out_path
        }
    };

    // create tar file containing all dependencies
    let tar_dir = std::path::Path::new(dir_path.as_str()).join(format!("tar_files_{unique_name}"));
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
    install_files(tar_dir.clone());

    // litebox_rtld_audit.so is already built by build.rs and available in OUT_DIR
    if let Backend::Rewriter = backend
        && !libs.is_empty()
    {
        println!(
            "Copying {} to {}",
            std::path::Path::new(dir_path.as_str())
                .join("litebox_rtld_audit.so")
                .to_str()
                .unwrap(),
            tar_dir.join("lib/litebox_rtld_audit.so").to_str().unwrap()
        );
        std::fs::copy(
            std::path::Path::new(dir_path.as_str()).join("litebox_rtld_audit.so"),
            tar_dir.join("lib/litebox_rtld_audit.so"),
        )
        .unwrap();
    }

    // create tar file using `tar` command with caching
    let tar_file =
        std::path::Path::new(dir_path.as_str()).join(format!("rootfs_{unique_name}.tar"));
    let tar_success = common::create_tar_with_cache(&tar_dir, &tar_file, unique_name);
    assert!(tar_success, "failed to create tar file");
    println!("Tar file ready at: {}", tar_file.to_str().unwrap());

    // Get the path to the litebox_runner_linux_userland binary
    let binary_path = std::env::var("NEXTEST_BIN_EXE_litebox_runner_linux_userland")
        .expect("NEXTEST_BIN_EXE_litebox_runner_linux_userland is auto-set by nextest - run tests with `cargo nextest run`, not `cargo test`");

    // run litebox_runner_linux_userland with the tar file and the compiled executable
    let mut args = vec![
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
        "--initial-files",
        tar_file.to_str().unwrap(),
    ];
    for env in environments {
        args.push("--env");
        args.push(env);
    }
    if let Some(tun_name) = tun_name {
        args.push("--tun-device-name");
        args.push(tun_name);
    }
    args.push(path.to_str().unwrap());
    args.extend_from_slice(cmd_args);
    println!("Running `{} {}`", binary_path, args.join(" "));
    let output = std::process::Command::new(&binary_path)
        .args(args)
        .output()
        .expect("Failed to run litebox_runner_linux_userland");
    if !output.status.success() {
        eprintln!("stdout: {}", output.status.code().unwrap_or(-1));
        if let Some(sig) = output.status.signal() {
            eprintln!("terminated by signal: {sig}");
        }
        eprintln!(
            "{}",
            std::string::String::from_utf8_lossy(output.stdout.as_slice())
        );
        eprintln!("stderr:");
        eprintln!(
            "{}",
            std::string::String::from_utf8_lossy(output.stderr.as_slice())
        );
        panic!("failed to run litebox_runner_linux_userland")
    }
    output.stdout
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
        run_target_program(
            Backend::Rewriter,
            &target,
            &[],
            &[],
            |_| {},
            &unique_name,
            None,
        );
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
        run_target_program(
            Backend::Rewriter,
            &target,
            &[],
            &[],
            |_| {},
            &unique_name,
            None,
        );
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
        run_target_program(
            Backend::Seccomp,
            &target,
            &[],
            &[],
            |_| {},
            &unique_name,
            None,
        );
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
    run_target_program(
        Backend::Seccomp,
        &node_path,
        &["/out/hello_world.js"],
        &[],
        |out_dir| {
            // write the test js file to the output directory
            std::fs::write(out_dir.join("out/hello_world.js"), HELLO_WORLD_JS).unwrap();
        },
        "hello_node_seccomp",
        None,
    );
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
    run_target_program(
        Backend::Rewriter,
        &node_path,
        &["/out/hello_world.js"],
        &[],
        |out_dir| {
            // write the test js file to the output directory
            std::fs::write(out_dir.join("out/hello_world.js"), HELLO_WORLD_JS).unwrap();
        },
        "hello_node_rewriter",
        None,
    );
}

#[cfg(target_arch = "x86_64")]
#[test]
fn test_runner_with_ls() {
    let ls_path = run_which("ls");
    let output = run_target_program(
        Backend::Rewriter,
        &ls_path,
        &["-a"],
        &[],
        |_| {},
        "ls_rewriter",
        None,
    );

    let output_str = String::from_utf8_lossy(&output);
    let normalized = output_str.split_whitespace().collect::<Vec<_>>();
    for each in [".", "..", "lib", "lib64"] {
        assert!(
            normalized.contains(&each),
            "unexpected ls output:\n{output_str}\n{each} not found",
        );
    }

    // test `ls` subdir
    let output = run_target_program(
        Backend::Rewriter,
        &ls_path,
        &["-a", "/lib/x86_64-linux-gnu"],
        &[],
        |_| {},
        "ls_lib_rewriter",
        None,
    );

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
#[test]
fn test_runner_with_python() {
    const HELLO_WORLD_PY: &str = "print(\"Hello, World from litebox!\")";
    let python_path = run_which("python3");
    let python_home = run_python(&["-c", "import sys; print(sys.prefix);"]);
    println!("Detected PYTHONHOME: {python_home}");
    let python_sys_path = run_python(&["-c", "import sys; print(':'.join(sys.path))"]);
    println!("Detected PYTHONPATH: {python_sys_path}");
    run_target_program(
        Backend::Rewriter,
        &python_path,
        &["-c", HELLO_WORLD_PY],
        &[
            &format!("PYTHONHOME={}", python_home.trim()),
            &format!("PYTHONPATH={}", python_sys_path.trim()),
            // LiteBox does not support timestamp yet, so pre-compiled .pyc files are not usable.
            // Avoid creating .pyc files as tar filesystem is read-only.
            "PYTHONDONTWRITEBYTECODE=1",
        ],
        |out_dir| {
            for each in python_sys_path.split(':') {
                if each.is_empty() || !each.starts_with("/usr") {
                    continue;
                }
                let python_lib_src = Path::new(each);
                if python_lib_src.is_dir() {
                    let python_lib_dst = out_dir.join(&each[1..]); // remove leading '/'
                    if python_lib_dst.exists() {
                        continue;
                    }
                    std::fs::create_dir_all(&python_lib_dst).unwrap();
                    println!(
                        "Copying python3 lib from {} to {}",
                        python_lib_src.to_str().unwrap(),
                        python_lib_dst.to_str().unwrap()
                    );
                    // TODO: we may also need to rewrite all .so files under the python lib directory
                    let output = std::process::Command::new("cp")
                        .args([
                            "-a",
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
            }
        },
        "python3_rewriter",
        None,
    );
}
