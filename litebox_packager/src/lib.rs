// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Restrict this crate to only work on Linux, as it relies on `ldd` for
// dependency discovery and other Linux-specific functionality.
#![cfg(target_os = "linux")]

#[cfg(target_arch = "x86_64")]
pub mod oci;

use anyhow::{Context, bail};
use clap::Parser;
use rayon::prelude::*;
use std::collections::{BTreeMap, BTreeSet};
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};
use tar::{Builder, Header};

/// Package Linux ELF programs for execution under LiteBox.
///
/// Discovers shared library dependencies, rewrites all ELF files using the
/// syscall rewriter, and produces a .tar suitable for use with
/// `litebox-runner-linux-userland --initial-files`.
///
/// Supports two modes:
/// - **Host mode** (default): Takes local ELF files, discovers dependencies via
///   `ldd`, rewrites syscalls, and produces a tar.
/// - **OCI mode** (`--oci-image`): Pulls a container image from a registry,
///   extracts its rootfs, rewrites all executable ELFs, and produces a tar.
#[derive(Parser, Debug)]
#[command(name = "litebox-packager")]
pub struct CliArgs {
    /// ELF files to package (host mode). Not used in OCI mode.
    #[arg(required_unless_present = "oci_image")]
    pub input_files: Vec<PathBuf>,

    /// Pull and package an OCI container image instead of local files.
    /// Only public (anonymous) registries are currently supported.
    /// Example: docker.io/library/alpine:latest
    #[arg(
        long = "oci-image",
        value_name = "IMAGE_REF",
        conflicts_with = "input_files"
    )]
    pub oci_image: Option<String>,

    /// Output tar file path.
    #[arg(short = 'o', long = "output", default_value = "litebox_packager.tar")]
    pub output: PathBuf,

    /// Include extra files in the tar.
    /// Format: HOST_PATH:TAR_PATH (split on the first colon, so the tar path
    /// may contain colons but the host path must not).
    #[arg(long = "include", value_name = "HOST_PATH:TAR_PATH")]
    pub include: Vec<String>,

    /// Skip rewriting specific files (by their absolute path on the host).
    #[arg(long = "no-rewrite", value_name = "PATH")]
    pub no_rewrite: Vec<PathBuf>,

    /// Print verbose output during packaging.
    #[arg(short = 'v', long = "verbose")]
    pub verbose: bool,
}

/// Parsed `--include` entry.
struct IncludeEntry {
    host_path: PathBuf,
    tar_path: String,
}

fn parse_include(spec: &str) -> anyhow::Result<IncludeEntry> {
    let Some(colon_idx) = spec.find(':') else {
        bail!("invalid --include format: expected HOST_PATH:TAR_PATH, got: {spec}");
    };
    let host_path = PathBuf::from(&spec[..colon_idx]);
    let tar_path = spec[colon_idx + 1..].to_string();
    let tar_path = tar_path.strip_prefix('/').unwrap_or(&tar_path).to_string();
    if tar_path.is_empty() {
        bail!("invalid --include format: TAR_PATH is empty in: {spec}");
    }
    Ok(IncludeEntry {
        host_path,
        tar_path,
    })
}

/// Run the packaging tool.
pub fn run(args: CliArgs) -> anyhow::Result<()> {
    if let Some(ref image_ref) = args.oci_image {
        #[cfg(target_arch = "x86_64")]
        {
            return run_oci(image_ref, &args);
        }
        #[cfg(not(target_arch = "x86_64"))]
        {
            let _ = image_ref;
            bail!("--oci-image is only supported on x86_64");
        }
    }

    // --- Phase 1: Validate inputs ---
    let input_files: Vec<PathBuf> = args
        .input_files
        .iter()
        .map(|p| {
            let abs = std::path::absolute(p)
                .with_context(|| format!("cannot resolve path: {}", p.display()))?;
            if !abs.is_file() {
                bail!(
                    "input file does not exist or is not a regular file: {}",
                    abs.display()
                );
            }
            Ok(abs)
        })
        .collect::<anyhow::Result<Vec<_>>>()?;

    let no_rewrite: BTreeSet<PathBuf> = args
        .no_rewrite
        .iter()
        .map(|p| {
            std::fs::canonicalize(p).unwrap_or_else(|e| {
                eprintln!(
                    "warning: could not resolve --no-rewrite path '{}': {e}; \
                     it may not match any discovered file",
                    p.display()
                );
                p.clone()
            })
        })
        .collect();

    // --- Phase 2: Discover dependencies and build unified file map ---
    eprintln!("Discovering dependencies...");
    let file_map = discover_all_dependencies(&input_files, args.verbose)?;

    eprintln!(
        "Found {} unique files across {} input file(s)",
        file_map.len(),
        input_files.len()
    );

    // --- Phase 3: Rewrite ELFs (parallel) ---
    // The litebox tar RO filesystem does not support symlinks, so each file is
    // placed as a regular file copy at every needed path.
    eprintln!("Rewriting {} unique ELF files...", file_map.len());

    let file_map_vec: Vec<(&PathBuf, &Vec<PathBuf>)> = file_map.iter().collect();
    let verbose = args.verbose;

    let par_results: Vec<anyhow::Result<Vec<TarEntry>>> = file_map_vec
        .into_par_iter()
        .map(|(real_path, tar_paths)| {
            let data = std::fs::read(real_path)
                .with_context(|| format!("failed to read {}", real_path.display()))?;
            let mode = std::fs::metadata(real_path)
                .with_context(|| format!("failed to stat {}", real_path.display()))?
                .mode();

            let rewritten = if no_rewrite.contains(real_path) {
                if verbose {
                    eprintln!("  {} (skipped rewrite)", real_path.display());
                }
                data
            } else {
                rewrite_elf(&data, real_path, verbose)?
            };

            let mut entries = Vec::new();
            for path in tar_paths {
                let tar_path = path
                    .to_str()
                    .with_context(|| format!("non-UTF8 path: {}", path.display()))?;
                let tar_path = tar_path.strip_prefix('/').unwrap_or(tar_path).to_string();
                entries.push(TarEntry {
                    tar_path,
                    data: rewritten.clone(),
                    mode,
                });
            }
            Ok(entries)
        })
        .collect();

    // Flatten results, deduplicating by tar path.
    let mut added_tar_paths = BTreeSet::<String>::new();
    let mut tar_entries: Vec<TarEntry> = Vec::new();
    for result in par_results {
        for entry in result? {
            if added_tar_paths.insert(entry.tar_path.clone()) {
                tar_entries.push(entry);
            }
        }
    }

    finalize_tar(tar_entries, added_tar_paths, &args)?;

    Ok(())
}

/// Run the packager in OCI mode: pull image, extract rootfs, rewrite ELFs, build tar.
#[cfg(target_arch = "x86_64")]
fn run_oci(image_ref: &str, args: &CliArgs) -> anyhow::Result<()> {
    // --- Phase 1: Pull and extract OCI image ---
    eprintln!("Pulling OCI image: {image_ref}");
    let extracted = oci::pull_and_extract(image_ref, args.verbose)?;

    // --- Phase 2: Scan rootfs for files ---
    eprintln!("Scanning rootfs...");
    let file_map = oci::scan_rootfs(&extracted.rootfs_path, args.verbose)?;

    let no_rewrite: BTreeSet<PathBuf> = args
        .no_rewrite
        .iter()
        .map(|p| {
            std::fs::canonicalize(p).unwrap_or_else(|e| {
                eprintln!(
                    "warning: could not resolve --no-rewrite path '{}': {e}; \
                     it may not match any discovered file",
                    p.display()
                );
                p.clone()
            })
        })
        .collect();

    let exec_count = file_map.files.values().filter(|e| e.is_executable).count();
    let total_count = file_map.files.len();
    eprintln!("Found {total_count} files ({exec_count} executables to rewrite)");

    // --- Phase 3: Rewrite ELFs in parallel ---
    eprintln!("Rewriting {exec_count} executable ELF files...");
    let verbose = args.verbose;
    let file_entries: Vec<(PathBuf, oci::RootfsEntry)> = file_map.files.into_iter().collect();

    let par_results: Vec<anyhow::Result<TarEntry>> = file_entries
        .into_par_iter()
        .map(|(_key_path, entry)| {
            let data = std::fs::read(&entry.read_path)
                .with_context(|| format!("failed to read {}", entry.read_path.display()))?;

            let rewritten = if entry.is_executable && !no_rewrite.contains(&entry.read_path) {
                rewrite_elf(&data, &entry.read_path, verbose)?
            } else {
                data
            };

            Ok(TarEntry {
                tar_path: entry.tar_path,
                data: rewritten,
                mode: entry.mode,
            })
        })
        .collect();

    let mut tar_entries: Vec<TarEntry> = Vec::with_capacity(par_results.len());
    for result in par_results {
        tar_entries.push(result?);
    }

    let mut added_tar_paths: BTreeSet<String> =
        tar_entries.iter().map(|e| e.tar_path.clone()).collect();

    // --- Phase 4: Store config.json and generate config_and_run.sh from image config ---

    // Always store the raw OCI config JSON for future use.
    {
        const CONFIG_JSON_TAR_PATH: &str = "litebox/config.json";
        if added_tar_paths.insert(CONFIG_JSON_TAR_PATH.to_string()) {
            if args.verbose {
                eprintln!(
                    "  Storing {CONFIG_JSON_TAR_PATH} ({} bytes)",
                    extracted.config_json.len()
                );
            }
            tar_entries.push(TarEntry {
                tar_path: CONFIG_JSON_TAR_PATH.to_string(),
                data: extracted.config_json,
                mode: 0o644,
            });
        } else {
            eprintln!("warning: tar already contains {CONFIG_JSON_TAR_PATH}, skipping");
        }
    }

    {
        const CONFIG_AND_RUN_TAR_PATH: &str = "litebox/config_and_run.sh";
        let script = oci::generate_config_and_run_script(&extracted.config);
        if added_tar_paths.insert(CONFIG_AND_RUN_TAR_PATH.to_string()) {
            if args.verbose {
                eprintln!("  Generating {CONFIG_AND_RUN_TAR_PATH} from image config");
            }
            tar_entries.push(TarEntry {
                tar_path: CONFIG_AND_RUN_TAR_PATH.to_string(),
                data: script.into_bytes(),
                mode: 0o755,
            });
        } else {
            eprintln!(
                "warning: tar already contains {CONFIG_AND_RUN_TAR_PATH}, skipping generation"
            );
        }
    }

    finalize_tar(tar_entries, added_tar_paths, args)?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Shared finalization: includes, rtld audit injection, tar build, size report
// ---------------------------------------------------------------------------

/// Append `--include` files, inject the rtld audit library, build the output
/// tar, and print a size summary.
///
/// Both host mode and OCI mode call this after producing their rewritten
/// `TarEntry` list.
fn finalize_tar(
    mut tar_entries: Vec<TarEntry>,
    mut added_tar_paths: BTreeSet<String>,
    args: &CliArgs,
) -> anyhow::Result<()> {
    // Parse and append --include files.
    let includes: Vec<IncludeEntry> = args
        .include
        .iter()
        .map(|s| parse_include(s))
        .collect::<anyhow::Result<Vec<_>>>()?;

    for inc in &includes {
        if !inc.host_path.exists() {
            bail!("included file does not exist: {}", inc.host_path.display());
        }
        if !added_tar_paths.insert(inc.tar_path.clone()) {
            bail!(
                "duplicate tar path from --include: '{}' (already present)",
                inc.tar_path
            );
        }
        let data = std::fs::read(&inc.host_path)
            .with_context(|| format!("failed to read included file {}", inc.host_path.display()))?;
        let mode = std::fs::metadata(&inc.host_path).map_or(0o644, |m| m.mode());
        if args.verbose {
            eprintln!(
                "  including {} as {}",
                inc.host_path.display(),
                inc.tar_path
            );
        }
        tar_entries.push(TarEntry {
            tar_path: inc.tar_path.clone(),
            data,
            mode,
        });
    }

    // Include the rtld audit library so the rewriter backend can load it.
    #[cfg(target_arch = "x86_64")]
    {
        const RTLD_AUDIT_TAR_PATH: &str = "lib/litebox_rtld_audit.so";
        if !added_tar_paths.insert(RTLD_AUDIT_TAR_PATH.to_string()) {
            bail!(
                "tar already contains {RTLD_AUDIT_TAR_PATH} -- \
                 remove the conflicting entry or use --no-rewrite"
            );
        }
        tar_entries.push(TarEntry {
            tar_path: RTLD_AUDIT_TAR_PATH.to_string(),
            data: include_bytes!(concat!(env!("OUT_DIR"), "/litebox_rtld_audit.so")).to_vec(),
            mode: 0o755,
        });
    }

    // Build tar.
    eprintln!("Creating {}...", args.output.display());
    build_tar(&tar_entries, &args.output)?;

    let tar_size = std::fs::metadata(&args.output).map_or(0, |m| m.len());
    #[allow(clippy::cast_precision_loss)]
    let tar_size_mb = tar_size as f64 / 1_048_576.0;
    eprintln!(
        "Created {} ({} entries, {:.1} MB)",
        args.output.display(),
        tar_entries.len(),
        tar_size_mb
    );

    Ok(())
}

// ---------------------------------------------------------------------------
// Dependency discovery (via ldd)
// ---------------------------------------------------------------------------

struct ResolvedDep {
    ldd_path: PathBuf,
    real_path: PathBuf,
}

struct DepDiscoveryResult {
    resolved: Vec<ResolvedDep>,
    missing: Vec<String>,
}

/// Run `ldd` on the given ELF and return resolved dependencies.
fn find_dependencies(elf_path: &Path, verbose: bool) -> anyhow::Result<DepDiscoveryResult> {
    let output = std::process::Command::new("ldd")
        .arg(elf_path)
        .output()
        .with_context(|| format!("failed to run ldd on {}", elf_path.display()))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if stderr.contains("not a dynamic executable") || stderr.contains("statically linked") {
            if verbose {
                eprintln!(
                    "  {} is statically linked, no dependencies",
                    elf_path.display()
                );
            }
            return Ok(DepDiscoveryResult {
                resolved: Vec::new(),
                missing: Vec::new(),
            });
        }
        bail!("ldd failed for {}: {}", elf_path.display(), stderr.trim());
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    if verbose {
        eprintln!("  ldd output for {}:\n{stdout}", elf_path.display());
    }

    let mut deps = Vec::new();
    let mut missing = Vec::new();

    for line in stdout.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        let abs_path = if let Some(idx) = line.find("=>") {
            let right = line[idx + 2..].trim();
            if right.starts_with("not found") {
                let lib_name = line[..idx].trim().to_string();
                missing.push(lib_name);
                continue;
            }
            right
                .split_whitespace()
                .next()
                .filter(|token| token.starts_with('/'))
        } else {
            // Format: "/lib64/ld-linux-x86-64.so.2 (0x...)" or "linux-vdso.so.1 (0x...)"
            line.split_whitespace()
                .next()
                .filter(|token| token.starts_with('/'))
        };

        let Some(abs_path) = abs_path else {
            continue;
        };

        let ldd_path = PathBuf::from(abs_path);
        let real_path = match std::fs::canonicalize(&ldd_path) {
            Ok(p) => p,
            Err(e) => {
                if verbose {
                    eprintln!(
                        "  warning: could not canonicalize {}: {e}; using as-is",
                        ldd_path.display()
                    );
                }
                ldd_path.clone()
            }
        };

        deps.push(ResolvedDep {
            ldd_path,
            real_path,
        });
    }

    Ok(DepDiscoveryResult {
        resolved: deps,
        missing,
    })
}

/// Discover all dependencies for a set of input ELFs and build a unified file map.
///
/// Returns a map from canonical (real) path to all the paths where that file should
/// appear in the tar. This includes the input files themselves and all their
/// transitive shared-library dependencies. Deduplicates by canonical path so each
/// file is only read and rewritten once.
fn discover_all_dependencies(
    input_files: &[PathBuf],
    verbose: bool,
) -> anyhow::Result<BTreeMap<PathBuf, Vec<PathBuf>>> {
    let mut file_map: BTreeMap<PathBuf, Vec<PathBuf>> = BTreeMap::new();
    let mut all_missing: BTreeSet<String> = BTreeSet::new();

    // Add input files themselves.
    for input_path in input_files {
        let canonical = std::fs::canonicalize(input_path)
            .with_context(|| format!("could not canonicalize {}", input_path.display()))?;
        let entry = file_map.entry(canonical).or_default();
        if !entry.contains(input_path) {
            entry.push(input_path.clone());
        }
    }

    // Add their transitive dependencies (ldd resolves the full tree).
    for elf_path in input_files {
        if verbose {
            eprintln!("Discovering dependencies for {}...", elf_path.display());
        }
        let result = find_dependencies(elf_path, verbose)?;
        for dep in result.resolved {
            let entry = file_map.entry(dep.real_path).or_default();
            if !entry.contains(&dep.ldd_path) {
                entry.push(dep.ldd_path);
            }
        }
        for lib in result.missing {
            all_missing.insert(lib);
        }
    }

    if !all_missing.is_empty() {
        let list: Vec<&str> = all_missing.iter().map(String::as_str).collect();
        let list = list.join(", ");
        bail!(
            "missing shared library dependencies: {list}\n\
             hint: install the missing libraries before packaging"
        );
    }

    Ok(file_map)
}

// ---------------------------------------------------------------------------
// ELF rewriting
// ---------------------------------------------------------------------------

/// ELF magic bytes: `\x7fELF`.
const ELF_MAGIC: [u8; 4] = [0x7f, b'E', b'L', b'F'];

/// Rewrite an ELF file's syscall instructions using the litebox syscall rewriter.
///
/// Non-ELF files (shell scripts, data files with executable bits, etc.) are
/// detected via a magic-byte check and returned unmodified without being sent
/// through the rewriter. For actual ELF files, benign rewriter errors (already
/// hooked, no syscalls, unsupported object, missing `.text`) are treated as
/// warnings and the original bytes are returned.
fn rewrite_elf(data: &[u8], path: &Path, verbose: bool) -> anyhow::Result<Vec<u8>> {
    // Fast-path: skip the rewriter entirely for non-ELF files.
    if data.len() < 4 || data[..4] != ELF_MAGIC {
        if verbose {
            eprintln!("  {} (not ELF, skipping rewrite)", path.display());
        }
        return Ok(data.to_vec());
    }

    match litebox_syscall_rewriter::hook_syscalls_in_elf(data, None) {
        Ok(rewritten) => {
            if verbose {
                eprintln!("  {} (rewritten)", path.display());
            }
            Ok(rewritten)
        }
        Err(litebox_syscall_rewriter::Error::AlreadyHooked) => {
            eprintln!(
                "  warning: {} is already hooked, using as-is",
                path.display()
            );
            Ok(data.to_vec())
        }
        Err(litebox_syscall_rewriter::Error::NoSyscallInstructionsFound) => {
            if verbose {
                eprintln!(
                    "  warning: {} has no syscall instructions, using as-is",
                    path.display()
                );
            }
            Ok(data.to_vec())
        }
        Err(litebox_syscall_rewriter::Error::UnsupportedObjectFile) => {
            if verbose {
                eprintln!(
                    "  warning: {} is not a supported ELF, including as-is",
                    path.display()
                );
            }
            Ok(data.to_vec())
        }
        Err(litebox_syscall_rewriter::Error::NoTextSectionFound) => {
            if verbose {
                eprintln!(
                    "  warning: {} has no .text section, using as-is",
                    path.display()
                );
            }
            Ok(data.to_vec())
        }
        Err(e) => Err(e).with_context(|| format!("failed to rewrite {}", path.display())),
    }
}

// ---------------------------------------------------------------------------
// Tar archive construction
// ---------------------------------------------------------------------------

struct TarEntry {
    tar_path: String,
    data: Vec<u8>,
    mode: u32,
}

fn build_tar(entries: &[TarEntry], output: &Path) -> anyhow::Result<()> {
    let file = std::fs::File::create(output)
        .with_context(|| format!("failed to create output file {}", output.display()))?;
    let mut builder = Builder::new(file);

    for entry in entries {
        let mut header = Header::new_gnu();
        header.set_size(entry.data.len() as u64);
        // Mask to permission bits only (rwxrwxrwx). The full st_mode from
        // MetadataExt::mode() includes file type bits (e.g., 0o100755) which
        // the litebox tar_ro filesystem's ModeFlags parser cannot handle.
        header.set_mode(entry.mode & 0o777);
        header.set_uid(1000);
        header.set_gid(1000);
        header.set_entry_type(tar::EntryType::Regular);
        header.set_cksum();
        builder
            .append_data(&mut header, &entry.tar_path, entry.data.as_slice())
            .with_context(|| format!("failed to add {} to tar", entry.tar_path))?;
    }

    builder.finish().context("failed to finalize tar archive")?;
    Ok(())
}
