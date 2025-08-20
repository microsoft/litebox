use std::path::{Path, PathBuf};

const HELLO_WORLD_C: &str = r#"
#include <stdio.h>

int main() {
    printf("Hello, World!\n");
    return 0;
}
"#;

/// Compile C code into an executable
fn compile(source: &str, unique_name: &str, exec_or_lib: bool) -> PathBuf {
    let dir_path = std::env::var("OUT_DIR").unwrap();
    let src_path = std::path::Path::new(dir_path.as_str()).join(format!("{unique_name}.c"));
    std::fs::write(src_path.clone(), source).unwrap();
    let path = std::path::Path::new(dir_path.as_str()).join(unique_name);
    let input = src_path.to_str().unwrap();
    let output = path.to_str().unwrap();

    let mut args = vec!["-o", output, input];
    if exec_or_lib {
        args.push("-static");
    }
    args.push(match std::env::consts::ARCH {
        "x86_64" => "-m64",
        "x86" => "-m32",
        _ => unimplemented!(),
    });
    let output = std::process::Command::new("gcc")
        .args(args)
        .output()
        .expect("Failed to compile hello.c");
    assert!(
        output.status.success(),
        "failed to compile hello.c {:?}",
        std::str::from_utf8(output.stderr.as_slice()).unwrap()
    );
    path
}

#[allow(dead_code)]
enum Backend {
    Rewriter,
    Seccomp,
}

#[allow(clippy::too_many_lines)]
fn test_runner_with_dynamic_lib(
    backend: Backend,
    libs: &[&str],
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
            let output = std::process::Command::new("cargo")
                .args([
                    "run",
                    "-p",
                    "litebox_syscall_rewriter",
                    "--",
                    target.to_str().unwrap(),
                    "-o",
                    out_path.to_str().unwrap(),
                ])
                .output()
                .expect("Failed to run litebox_syscall_rewriter");
            assert!(
                output.status.success(),
                "failed to run litebox_syscall_rewriter {:?}",
                std::str::from_utf8(output.stderr.as_slice()).unwrap()
            );
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
    for file in libs {
        let file_path = std::path::Path::new(file);
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
                println!(
                    "Running `cargo run -p litebox_syscall_rewriter -- -o {} {}`",
                    dest_path.to_str().unwrap(),
                    file_path.to_str().unwrap(),
                );
                let output = std::process::Command::new("cargo")
                    .args([
                        "run",
                        "-p",
                        "litebox_syscall_rewriter",
                        "--",
                        "-o",
                        dest_path.to_str().unwrap(),
                        file_path.to_str().unwrap(),
                    ])
                    .output()
                    .expect("Failed to run litebox_syscall_rewriter");
                assert!(
                    output.status.success(),
                    "failed to run litebox_syscall_rewriter {:?}",
                    std::str::from_utf8(output.stderr.as_slice()).unwrap()
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

    match backend {
        Backend::Rewriter => {
            println!(
                "Copying {} to {}",
                std::path::Path::new(dir_path.as_str())
                    .join("litebox_rtld_audit.so")
                    .to_str()
                    .unwrap(),
                tar_dir
                    .join("lib64/litebox_rtld_audit.so")
                    .to_str()
                    .unwrap()
            );
            std::fs::copy(
                std::path::Path::new(dir_path.as_str()).join("litebox_rtld_audit.so"),
                tar_dir.join("lib64/litebox_rtld_audit.so"),
            )
            .unwrap();
        }
        Backend::Seccomp => {}
    }

    // create tar file using `tar` command
    let tar_file =
        std::path::Path::new(dir_path.as_str()).join(format!("rootfs_{unique_name}.tar"));
    let tar_data = std::process::Command::new("tar")
        .args([
            "-cvf",
            format!("../rootfs_{unique_name}.tar").as_str(),
            "lib",
            "lib32",
            "lib64",
            "out",
        ])
        .current_dir(&tar_dir)
        .output()
        .expect("Failed to create tar file");
    assert!(
        tar_data.status.success(),
        "failed to create tar file {:?}",
        std::str::from_utf8(tar_data.stderr.as_slice()).unwrap()
    );
    println!("Tar file created at: {}", tar_file.to_str().unwrap());

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
        "--initial-files",
        tar_file.to_str().unwrap(),
    ];
    match backend {
        Backend::Rewriter => {
            args.push("--env");
            args.push("LD_AUDIT=/lib64/litebox_rtld_audit.so");
        }
        Backend::Seccomp => {
            // No need to set LD_AUDIT for seccomp backend
        }
    }
    args.push(path.to_str().unwrap());
    args.extend_from_slice(cmd_args);
    println!("Running `cargo {}`", args.join(" "));
    let output = std::process::Command::new("cargo")
        .args(args)
        .output()
        .expect("Failed to run litebox_runner_linux_userland");
    assert!(
        output.status.success(),
        "failed to run litebox_runner_linux_userland {:?}",
        std::str::from_utf8(output.stderr.as_slice()).unwrap()
    );
    output.stdout
}

#[cfg(target_arch = "x86_64")]
const HELLO_WORLD_INIT_FILES: [&str; 2] = [
    "/lib64/ld-linux-x86-64.so.2",
    "/lib/x86_64-linux-gnu/libc.so.6",
];
#[cfg(target_arch = "x86")]
const HELLO_WORLD_INIT_FILES: [&str; 2] = ["/lib/ld-linux.so.2", "/lib32/libc.so.6"];

#[cfg(target_arch = "x86_64")]
#[test]
fn test_runner_with_dynamic_lib_rewriter() {
    let unique_name = "hello_lib_rewriter";
    let target = compile(HELLO_WORLD_C, unique_name, false);
    test_runner_with_dynamic_lib(
        Backend::Rewriter,
        &HELLO_WORLD_INIT_FILES,
        &target,
        &[],
        |_| {},
        unique_name,
    );
}

#[test]
fn test_runner_with_dynamic_lib_seccomp() {
    let unique_name = "hello_lib_seccomp";
    let target = compile(HELLO_WORLD_C, unique_name, false);
    test_runner_with_dynamic_lib(
        Backend::Seccomp,
        &HELLO_WORLD_INIT_FILES,
        &target,
        &[],
        |_| {},
        unique_name,
    );
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
#[ignore = "unknown issue triggers it to fail on CI"]
fn test_runner_with_nodejs() {
    const HELLO_WORLD_JS: &str = r"
const fs = require('node:fs');

const content = 'Hello World!';
console.log(content);
";

    let initial_files = [
        "/lib/x86_64-linux-gnu/libdl.so.2",
        "/lib/x86_64-linux-gnu/libstdc++.so.6",
        "/lib/x86_64-linux-gnu/libm.so.6",
        "/lib/x86_64-linux-gnu/libgcc_s.so.1",
        "/lib/x86_64-linux-gnu/libpthread.so.0",
        "/lib64/ld-linux-x86-64.so.2",
        "/lib/x86_64-linux-gnu/libc.so.6",
    ];
    let node_path = run_which("node");
    test_runner_with_dynamic_lib(
        Backend::Seccomp,
        &initial_files,
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
fn test_runner_with_ls() {
    let ls_path = run_which("ls");
    let output = test_runner_with_dynamic_lib(
        Backend::Seccomp,
        &[
            "/lib/x86_64-linux-gnu/libc.so.6",
            "/lib64/ld-linux-x86-64.so.2",
            "/lib/x86_64-linux-gnu/libselinux.so.1",
            "/lib/x86_64-linux-gnu/libpcre2-8.so.0",
        ],
        &ls_path,
        &["-a"],
        |_| {},
        "ls_seccomp",
    );

    let output_str = String::from_utf8_lossy(&output);
    let normalized = output_str.split_whitespace().collect::<Vec<_>>();
    for each in [".", "..", "lib", "lib64", "usr"] {
        assert!(
            normalized.contains(&each),
            "unexpected ls output:\n{output_str}",
        );
    }

    // test `ls` subdir
    let output = test_runner_with_dynamic_lib(
        Backend::Seccomp,
        &[
            "/lib/x86_64-linux-gnu/libc.so.6",
            "/lib64/ld-linux-x86-64.so.2",
            "/lib/x86_64-linux-gnu/libselinux.so.1",
            "/lib/x86_64-linux-gnu/libpcre2-8.so.0",
        ],
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
