// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use glob::glob;
use std::path::{Path, PathBuf};

#[cfg(target_os = "linux")]
pub(crate) mod native;
#[cfg(target_os = "linux")]
pub mod pty;
pub(crate) mod runner;

#[cfg(target_arch = "x86_64")]
const MULTIARCH: &str = "x86_64-linux-gnu";
#[cfg(target_arch = "aarch64")]
const MULTIARCH: &str = "aarch64-linux-gnu";

/// Returns the SVE vector length LiteBox offers guests on this host, if any:
/// the host's, if its live `sve_context` fits a signal frame's `__reserved`
/// area.
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
#[allow(dead_code, reason = "not used by every test binary")]
pub fn guest_sve_vl() -> Option<litebox::arch::aarch64::vector::SveVectorLength> {
    use litebox::arch::aarch64::vector::SveVectorLength;
    const PR_SVE_GET_VL: libc::c_int = 51;
    const PR_SVE_VL_LEN_MASK: libc::c_int = 0xffff;

    if !std::arch::is_aarch64_feature_detected!("sve") {
        return None;
    }
    // SAFETY: PR_SVE_GET_VL only reports this thread's vector length.
    let status = unsafe { libc::prctl(PR_SVE_GET_VL) };
    u16::try_from(status & PR_SVE_VL_LEN_MASK)
        .ok()
        .and_then(SveVectorLength::new)
        .filter(|&vl| litebox_common_linux::signal::aarch64::sve_context_fits_reserved(vl))
}

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

    // libgcc_s.so.1 is not always a direct link-time dependency (ldd won't list it), but
    // glibc's pthread_cancel needs it at runtime for forced stack unwinding. Without it the
    // we get SIGABRTs.
    let libgcc_s = std::process::Command::new("gcc")
        .arg("-print-file-name=libgcc_s.so.1")
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|path| PathBuf::from(path.trim()))
        .filter(|path| path.is_absolute() && path.is_file())
        .or_else(|| {
            [
                format!("/usr/lib/{MULTIARCH}/libgcc_s.so.1"),
                format!("/lib/{MULTIARCH}/libgcc_s.so.1"),
                String::from("/usr/lib64/libgcc_s.so.1"),
                String::from("/lib64/libgcc_s.so.1"),
            ]
            .into_iter()
            .map(PathBuf::from)
            .find(|path| path.is_file())
        })
        .expect("libgcc_s.so.1 not found via gcc or known library paths")
        .canonicalize()
        .unwrap()
        .to_string_lossy()
        .into_owned();
    if !paths.contains(&libgcc_s) {
        paths.push(libgcc_s);
    }

    println!("Resolved dependency paths: {paths:?}");

    paths
}

/// Find the rewriter and shared trampoline sources that affect emitted code.
pub(crate) fn find_rewriter_source_files() -> Vec<PathBuf> {
    let mut source_files = Vec::new();

    // Get the absolute path to the workspace root.
    if let Ok(cargo_manifest_dir) = std::env::var("CARGO_MANIFEST_DIR") {
        let workspace_root = std::path::Path::new(&cargo_manifest_dir).parent().unwrap();
        for crate_name in ["litebox_syscall_rewriter", "litebox_trampoline"] {
            let source_dir = workspace_root.join(crate_name);
            let pattern = format!("{}/src/**/*.rs", source_dir.display());

            if let Ok(paths) = glob(&pattern) {
                for path in paths.flatten() {
                    if path.is_file() {
                        source_files.push(path);
                    }
                }
            }
        }
    }

    // Sort for consistent ordering
    source_files.sort();
    source_files
}

/// Compile C code into an executable with caching.
///
/// Tests that compile the same source the same way may share `unique_name`: the output is replaced
/// only once complete, so that no test runs a partly written binary, and rebuilding one that
/// another test runs doesn't fail with `ETXTBSY`.
pub fn compile(src_path: &str, unique_name: &str, exec_or_lib: bool, nolibc: bool) -> PathBuf {
    let dir_path = env!("CARGO_TARGET_TMPDIR").to_string();
    let path = std::path::Path::new(dir_path.as_str()).join(unique_name);
    let output = path.to_str().unwrap();

    let mut flags = vec![src_path];
    if exec_or_lib {
        flags.push("-static");
    }
    if nolibc {
        flags.push("-nostdlib");
    }
    // Select the x86 ABI explicitly; AArch64 gcc rejects both x86 flags.
    match std::env::consts::ARCH {
        "x86_64" => flags.push("-m64"),
        "x86" => flags.push("-m32"),
        "aarch64" => (),
        arch => unimplemented!("no gcc ABI flag known for {arch}"),
    }

    // Create command string for caching
    let mut command_parts = vec!["gcc", "-o", output];
    command_parts.extend_from_slice(&flags);
    let command = command_parts.join(" ");

    // Check cache first. Include any sibling `.h` files in the source's directory
    // so cache invalidation tracks shared headers (e.g. test helper headers).
    let src_path_buf = Path::new(src_path);
    let mut sibling_headers: Vec<PathBuf> = src_path_buf
        .parent()
        .and_then(|d| std::fs::read_dir(d).ok())
        .into_iter()
        .flatten()
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().and_then(|e| e.to_str()) == Some("h"))
        .collect();
    sibling_headers.sort();
    let mut input_paths: Vec<&Path> = vec![src_path_buf];
    input_paths.extend(sibling_headers.iter().map(PathBuf::as_path));

    if let Ok(true) = crate::cache::is_cached_and_valid(&input_paths, &path, &command) {
        println!("Using cached compilation result for: {unique_name}");
        return path;
    }

    println!("Compiling: {src_path} -> {unique_name}");

    // Build beside the output, so that renaming the result into place is atomic.
    let staging = tempfile::Builder::new()
        .prefix(".compile")
        .tempdir_in(path.parent().unwrap())
        .unwrap();
    let staged = staging.path().join(path.file_name().unwrap());
    let output = std::process::Command::new("gcc")
        .arg("-o")
        .arg(&staged)
        .args(flags)
        .output()
        .expect("Failed to compile");
    assert!(
        output.status.success(),
        "failed to compile: {:?}",
        std::str::from_utf8(output.stderr.as_slice()).unwrap()
    );
    std::fs::rename(&staged, &path).unwrap();

    // Create cache entry after successful compilation
    if let Err(e) = crate::cache::create_cache_entry(&input_paths, &path, &command) {
        eprintln!("Warning: Failed to create cache entry for {unique_name}: {e}");
    }

    path
}

/// Compile a `no_std` Rust program into a static executable with caching
#[allow(dead_code, reason = "not used by every test binary")]
pub fn compile_rust(src_path: &str, unique_name: &str) -> PathBuf {
    let dir_path = env!("CARGO_TARGET_TMPDIR").to_string();
    let path = std::path::Path::new(dir_path.as_str()).join(unique_name);
    let output = path.to_str().unwrap();

    let target = match std::env::consts::ARCH {
        "x86_64" => "x86_64-unknown-none",
        "aarch64" => "aarch64-unknown-none",
        arch => unimplemented!("no Rust target known for {arch}"),
    };
    // Static, as nothing applies a static PIE's relocations without libc.
    let args = [
        "--edition=2024",
        "--target",
        target,
        "-C",
        "opt-level=2",
        "-C",
        "relocation-model=static",
        "-o",
        output,
        src_path,
    ];

    let rustc = std::env::var("RUSTC").unwrap_or_else(|_| "rustc".to_string());
    let mut command_parts = vec![rustc.as_str()];
    command_parts.extend_from_slice(&args);
    let command = command_parts.join(" ");

    let input_paths = [Path::new(src_path)];
    if let Ok(true) = crate::cache::is_cached_and_valid(&input_paths, &path, &command) {
        println!("Using cached compilation result for: {unique_name}");
        return path;
    }

    println!("Compiling: {src_path} -> {unique_name}");

    let output = std::process::Command::new(&rustc)
        .args(args)
        .output()
        .expect("Failed to run rustc");
    assert!(
        output.status.success(),
        "failed to compile (is the target installed? `rustup target add {target}`): {}",
        String::from_utf8_lossy(&output.stderr)
    );

    if let Err(e) = crate::cache::create_cache_entry(&input_paths, &path, &command) {
        eprintln!("Warning: Failed to create cache entry for {unique_name}: {e}");
    }

    path
}

pub(crate) fn rewriter_flags() -> Vec<&'static str> {
    vec![
        #[cfg(all(target_arch = "aarch64", feature = "aarch64_virtualize_x18"))]
        "--virtualize-x18",
        #[cfg(all(
            target_os = "linux",
            target_arch = "aarch64",
            feature = "aarch64_pacga"
        ))]
        "--native-tpidr-el0",
    ]
}

/// Run syscall rewriter with caching
pub fn rewrite_with_cache(input_path: &Path, output_path: &Path, extra_args: &[&str]) -> bool {
    use sha2::{Digest as _, Sha256};

    // Keep rewritten files outside the disposable rootfs stage, isolated by destination.
    let cache_dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join("rewrites");
    let cache_key = Sha256::digest(output_path.as_os_str().as_encoded_bytes());
    let cached_path = cache_dir.join(format!("{cache_key:x}"));
    // Include both the input file and all rewriter source files in the cache key
    let mut input_paths = vec![input_path];
    let rewriter_sources = find_rewriter_source_files();
    let rewriter_paths: Vec<&Path> = rewriter_sources
        .iter()
        .map(std::path::PathBuf::as_path)
        .collect();
    input_paths.extend(rewriter_paths);

    let mut args = vec!["run", "-p", "litebox_syscall_rewriter", "--"];
    args.extend(rewriter_flags());
    args.extend_from_slice(extra_args);
    args.push("-o");
    args.push(cached_path.to_str().unwrap());
    args.push(input_path.to_str().unwrap());

    // Create command string for caching
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
    let mut command_parts = vec![cargo.as_str()];
    command_parts.extend_from_slice(&args);
    let command = command_parts.join(" ");

    if let Ok(true) = crate::cache::is_cached_and_valid(&input_paths, &cached_path, &command) {
        println!(
            "Using cached rewriter result for: {} (tracking {} rewriter source files)",
            output_path.display(),
            rewriter_sources.len()
        );
    } else {
        println!(
            "Running rewriter: {} -> {}",
            input_path.display(),
            output_path.display()
        );

        std::fs::create_dir_all(&cache_dir).unwrap();
        if cached_path.exists() {
            std::fs::remove_file(&cached_path).unwrap();
        }

        let output = std::process::Command::new(&cargo)
            .args(args)
            .output()
            .expect("Failed to run litebox_syscall_rewriter");

        let success = output.status.success();
        if !success {
            eprintln!(
                "failed to run litebox_syscall_rewriter {:?}",
                std::str::from_utf8(output.stderr.as_slice()).unwrap()
            );
            return false;
        }

        // Create cache entry after successful rewriting
        if let Err(e) = crate::cache::create_cache_entry(&input_paths, &cached_path, &command) {
            eprintln!(
                "Warning: Failed to create cache entry for {}: {}",
                output_path.display(),
                e
            );
        }
    }

    if let Some(parent) = output_path.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    if output_path.exists() {
        std::fs::remove_file(output_path).unwrap();
    }
    std::fs::copy(&cached_path, output_path).unwrap();
    std::fs::File::open(output_path)
        .unwrap()
        .set_modified(std::fs::metadata(&cached_path).unwrap().modified().unwrap())
        .unwrap();
    true
}

/// Create tar file with caching
#[allow(
    dead_code,
    reason = "unclear why clippy things this might not be used, but also doesn't like an 'expect' here either"
)]
pub(crate) fn create_tar_with_cache(tar_dir: &Path, tar_file: &Path, unique_name: &str) -> bool {
    // For tar files, we need to consider the entire directory tree as input.
    // We'll create a fingerprint of all files in the tar_dir
    let mut all_files = Vec::new();
    if let Ok(entries) = walkdir::WalkDir::new(tar_dir)
        .into_iter()
        .collect::<Result<Vec<_>, _>>()
    {
        for entry in entries {
            if entry.file_type().is_file() {
                let path = entry.path().to_path_buf();
                if path.extension().is_some_and(|ext| ext == "cache-checksum") {
                    continue;
                }
                all_files.push(path);
            }
        }
    } else {
        return false;
    }
    all_files.sort();

    // Convert to Path refs for the caching function
    let input_paths: Vec<&Path> = all_files.iter().map(std::path::PathBuf::as_path).collect();

    // Create command string for caching
    let tar_filename = format!("../rootfs_{unique_name}.tar.tmp");
    let mut args = vec![
        // ustar format allows longer file names
        "--format=ustar",
        "--exclude=*.cache-checksum",
        "-cvf",
        tar_filename.as_str(),
    ];
    // collect all entries in the tar_dir
    let mut all_entries = tar_dir
        .read_dir()
        .expect("Failed to read tar directory")
        .filter_map(|entry| entry.map(|e| e.file_name()).ok())
        .collect::<Vec<_>>();
    all_entries.sort();
    for entry in &all_entries {
        args.push(entry.to_str().unwrap());
    }
    let mut command_parts = vec!["tar"];
    command_parts.extend_from_slice(&args);
    let command = command_parts.join(" ");
    println!("Tar command: {command}");

    if let Ok(true) = crate::cache::is_cached_and_valid(&input_paths, tar_file, &command) {
        println!("Using cached tar file for: {unique_name}");
        std::fs::remove_dir_all(tar_dir).unwrap();
        return true;
    }

    println!("Creating tar file for: {unique_name}");

    // create tar file using `tar` command
    let tar_data = std::process::Command::new("tar")
        .args(args)
        .current_dir(tar_dir)
        .output()
        .expect("Failed to create tar file");

    let success = tar_data.status.success();
    if !success {
        eprintln!(
            "failed to create tar file {:?}",
            std::str::from_utf8(tar_data.stderr.as_slice()).unwrap()
        );
        return false;
    }

    // Readers can still have the old tar mapped when another process rebuilds it.
    std::fs::rename(tar_dir.join(&tar_filename), tar_file).unwrap();

    // Create cache entry after successful tar creation
    if let Err(e) = crate::cache::create_cache_entry(&input_paths, tar_file, &command) {
        eprintln!("Warning: Failed to create cache entry for {unique_name}: {e}");
    }

    std::fs::remove_dir_all(tar_dir).unwrap();
    success
}
