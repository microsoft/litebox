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

#[allow(clippy::too_many_lines)]
fn run_target_program(
    backend: Backend,
    target: &Path,
    cmd_args: &[&str],
    install_files: fn(PathBuf),
    unique_name: &str,
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
    install_files(tar_dir.join("out"));

    #[cfg(target_arch = "x86_64")]
    let target = "--target=x86_64-unknown-linux-gnu";
    #[cfg(target_arch = "x86")]
    let target = "--target=i686-unknown-linux-gnu";

    // build litebox_runner_linux_userland to get the latest `litebox_rtld_audit.so`
    let output = std::process::Command::new("cargo")
        .args(["build", "-p", "litebox_runner_linux_userland", target])
        .output()
        .expect("Failed to build litebox_runner_linux_userland");
    assert!(
        output.status.success(),
        "failed to build litebox_runner_linux_userland {:?}",
        std::str::from_utf8(output.stderr.as_slice()).unwrap()
    );

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

    // run litebox_runner_linux_userland with the tar file and the compiled executable
    let mut args = vec![
        "run",
        "-p",
        "litebox_runner_linux_userland",
        target,
        "--",
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
    args.push(path.to_str().unwrap());
    args.extend_from_slice(cmd_args);
    println!("Running `cargo {}`", args.join(" "));
    let output = std::process::Command::new("cargo")
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
        run_target_program(Backend::Rewriter, &target, &[], |_| {}, &unique_name);
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
        run_target_program(Backend::Rewriter, &target, &[], |_| {}, &unique_name);
    }
}

#[cfg(target_arch = "x86_64")]
#[test]
fn test_dynamic_lib_with_seccomp() {
    for path in find_c_test_files("./tests") {
        let stem = path
            .file_stem()
            .and_then(|s| s.to_str())
            .expect("failed to get file stem");
        let unique_name = format!("{stem}_seccomp");
        let target = common::compile(path.to_str().unwrap(), &unique_name, false, false);
        run_target_program(Backend::Seccomp, &target, &[], |_| {}, &unique_name);
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
#[ignore = "Will add this test back after supporting std::spawn"]
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
        |out_dir| {
            // write the test js file to the output directory
            std::fs::write(out_dir.join("hello_world.js"), HELLO_WORLD_JS).unwrap();
        },
        "hello_node_seccomp",
    );
}

#[cfg(target_arch = "x86_64")]
#[test]
#[ignore = "Rewriting node and its dependencies takes > 5 minutes, so ignore by default"]
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
        |out_dir| {
            // write the test js file to the output directory
            std::fs::write(out_dir.join("hello_world.js"), HELLO_WORLD_JS).unwrap();
        },
        "hello_node_rewriter",
    );
}

#[cfg(target_arch = "x86_64")]
#[test]
fn test_runner_with_ls() {
    let ls_path = run_which("ls");
    let output = run_target_program(Backend::Seccomp, &ls_path, &["-a"], |_| {}, "ls_seccomp");

    let output_str = String::from_utf8_lossy(&output);
    let normalized = output_str.split_whitespace().collect::<Vec<_>>();
    for each in [".", "..", "lib", "lib64", "usr"] {
        assert!(
            normalized.contains(&each),
            "unexpected ls output:\n{output_str}",
        );
    }

    // test `ls` subdir
    let output = run_target_program(
        Backend::Seccomp,
        &ls_path,
        &["-a", "/lib/x86_64-linux-gnu"],
        |_| {},
        "ls_lib_seccomp",
    );

    let output_str = String::from_utf8_lossy(&output);
    let normalized = output_str.split_whitespace().collect::<Vec<_>>();
    for each in [".", "..", "libc.so.6", "libpcre2-8.so.0", "libselinux.so.1"] {
        assert!(
            normalized.contains(&each),
            "unexpected ls output:\n{output_str}",
        );
    }
}
