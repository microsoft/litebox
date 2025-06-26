const HELLO_WORLD_C: &str = r#"
#include <stdio.h>

int main() {
    printf("Hello, World!\n");
    return 0;
}
"#;

/// Compile C code into an executable
fn compile(input: &str, output: &str, exec_or_lib: bool) {
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
}

#[test]
fn test_runner_with_dynamic_lib() {
    let dir_path = std::env::var("OUT_DIR").unwrap();
    let src_path = std::path::Path::new(dir_path.as_str()).join("hello_exec.c");
    std::fs::write(src_path.clone(), HELLO_WORLD_C).unwrap();
    let path = std::path::Path::new(dir_path.as_str()).join("hello_dylib");
    compile(src_path.to_str().unwrap(), path.to_str().unwrap(), false);

    // create tar file containing all dependencies
    let tar_dir = std::path::Path::new(dir_path.as_str()).join("tar_files");
    let dirs_to_create = ["lib64", "lib/x86_64-linux-gnu", "lib32"];
    for dir in dirs_to_create {
        std::fs::create_dir_all(tar_dir.join(dir)).unwrap();
    }
    #[cfg(target_arch = "x86_64")]
    let files_to_install = [
        "/lib64/ld-linux-x86-64.so.2",
        "/lib/x86_64-linux-gnu/libc.so.6",
    ];
    #[cfg(target_arch = "x86")]
    let files_to_install = ["/lib/ld-linux.so.2", "/lib32/libc.so.6"];
    for file in files_to_install {
        let file_path = std::path::Path::new(file);
        let dest_path = tar_dir.join(&file[1..]);
        println!(
            "Copying {} to {}",
            file_path.to_str().unwrap(),
            dest_path.to_str().unwrap()
        );
        std::fs::copy(file_path, dest_path).unwrap();
    }
    // create tar file using `tar` command
    let tar_file = std::path::Path::new(dir_path.as_str()).join("rootfs.tar");
    let tar_data = std::process::Command::new("tar")
        .args(["-cvf", "../rootfs.tar", "lib", "lib64"])
        .current_dir(&tar_dir)
        .output()
        .expect("Failed to create tar file");
    assert!(
        tar_data.status.success(),
        "failed to create tar file {:?}",
        std::str::from_utf8(tar_data.stderr.as_slice()).unwrap()
    );
    println!("Tar file created at: {}", tar_file.to_str().unwrap());

    #[cfg(target_arch = "x86_64")]
    let target = ""; // no need to specify target for x86_64
    #[cfg(target_arch = "x86")]
    let target = "--target=i686-unknown-linux-gnu";
    println!(
        "Running `cargo run -p litebox_runner_linux_userland {} -- --unstable --initial-files {} {}`",
        target,
        tar_file.to_str().unwrap(),
        path.to_str().unwrap()
    );
    // run litebox_runner_linux_userland with the tar file and the compiled executable
    let output = std::process::Command::new("cargo")
        .args([
            "run",
            "-p",
            "litebox_runner_linux_userland",
            #[cfg(target_arch = "x86")]
            "--target=i686-unknown-linux-gnu",
            "--",
            "--unstable",
            "--initial-files",
            tar_file.to_str().unwrap(),
            path.to_str().unwrap(),
        ])
        .output()
        .expect("Failed to run litebox_runner_linux_userland");
    assert!(
        output.status.success(),
        "failed to run litebox_runner_linux_userland {:?}",
        std::str::from_utf8(output.stderr.as_slice()).unwrap()
    );
}
