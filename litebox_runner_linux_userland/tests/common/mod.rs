use std::path::PathBuf;

/// Find all dependencies of a given binary via `ldd`
#[allow(dead_code, reason = "not used by loader.rs for x86")]
pub fn find_dependencies(prog: &str) -> Vec<String> {
    let output = std::process::Command::new("ldd")
        .arg(prog)
        .output()
        .expect("Failed to execute ldd");

    let dependencies = String::from_utf8_lossy(&output.stdout);
    println!("Dependencies:\n{dependencies}");

    let mut paths = Vec::new();

    for line in dependencies.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        if let Some(idx) = line.find("=>") {
            // Format: "libc.so.6 => /lib/.../libc.so.6 (0x...)"
            let right = line[idx + 2..].trim();
            // Skip "not found"
            if right.starts_with("not found") {
                println!("Warning: dependency not found: {line}");
                continue;
            }
            // Extract token before whitespace or '('
            if let Some(token) = right.split_whitespace().next()
                && token.starts_with('/')
            {
                paths.push(token.to_string());
            } else {
                println!("Warning: unexpected ldd output line: {line}");
            }
        } else {
            // Format: "/lib64/ld-linux-x86-64.so.2 (0x...)" or "linux-vdso.so.1 (0x...)"
            if let Some(token) = line.split_whitespace().next()
                && token.starts_with('/')
            {
                paths.push(token.to_string());
            }
        }
    }

    println!("Resolved dependency paths: {paths:?}");

    paths
}

/// Compile C code into an executable
pub fn compile(src_path: &str, unique_name: &str, exec_or_lib: bool, nolibc: bool) -> PathBuf {
    let dir_path = std::env::var("OUT_DIR").unwrap();
    let path = std::path::Path::new(dir_path.as_str()).join(unique_name);
    let output = path.to_str().unwrap();

    let mut args = vec!["-o", output, src_path];
    if exec_or_lib {
        args.push("-static");
    }
    if nolibc {
        args.push("-nostdlib");
    }
    args.push(match std::env::consts::ARCH {
        "x86_64" => "-m64",
        "x86" => "-m32",
        _ => unimplemented!(),
    });
    let output = std::process::Command::new("gcc")
        .args(args)
        .output()
        .expect("Failed to compile");
    assert!(
        output.status.success(),
        "failed to compile: {:?}",
        std::str::from_utf8(output.stderr.as_slice()).unwrap()
    );
    path
}
