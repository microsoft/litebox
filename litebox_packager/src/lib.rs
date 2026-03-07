// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Restrict this crate to only work on Linux, as it relies on `ldd` for
// dependency discovery and other Linux-specific functionality.
#![cfg(target_os = "linux")]

use anyhow::{Context, bail};
use clap::Parser;
use std::collections::{BTreeMap, BTreeSet};
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};
use tar::{Builder, Header};

/// Package Linux ELF programs for execution under LiteBox.
///
/// Discovers shared library dependencies, rewrites all ELF files using the
/// syscall rewriter, and produces a .tar suitable for use with
/// `litebox-runner-linux-userland --initial-files`.
#[derive(Parser, Debug)]
#[command(name = "litebox-packager")]
pub struct CliArgs {
    /// ELF files to package.
    #[arg(required = true)]
    pub input_files: Vec<PathBuf>,

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

    let includes: Vec<IncludeEntry> = args
        .include
        .iter()
        .map(|s| parse_include(s))
        .collect::<anyhow::Result<Vec<_>>>()?;

    for inc in &includes {
        if !inc.host_path.exists() {
            bail!("included file does not exist: {}", inc.host_path.display());
        }
    }

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

    // --- Phase 3: Rewrite ELFs ---
    // The litebox tar RO filesystem does not support symlinks, so each file is
    // placed as a regular file copy at every needed path.
    eprintln!("Rewriting {} unique ELF files...", file_map.len());
    let mut tar_entries: Vec<TarEntry> = Vec::new();
    let mut added_tar_paths: BTreeSet<String> = BTreeSet::new();

    for (real_path, tar_paths) in &file_map {
        let data = std::fs::read(real_path)
            .with_context(|| format!("failed to read {}", real_path.display()))?;
        let mode = std::fs::metadata(real_path)
            .with_context(|| format!("failed to stat {}", real_path.display()))?
            .mode();

        let rewritten = if no_rewrite.contains(real_path) {
            if args.verbose {
                eprintln!("  {} (skipped rewrite)", real_path.display());
            }
            data
        } else {
            rewrite_elf(&data, real_path, args.verbose)?
        };

        for path in tar_paths {
            let tar_path = path
                .to_str()
                .with_context(|| format!("non-UTF8 path: {}", path.display()))?;
            let tar_path = tar_path.strip_prefix('/').unwrap_or(tar_path).to_string();
            if added_tar_paths.insert(tar_path.clone()) {
                tar_entries.push(TarEntry {
                    tar_path,
                    data: rewritten.clone(),
                    mode,
                });
            }
        }
    }

    // Include extra files (these files will not be rewritten).
    for inc in &includes {
        if !added_tar_paths.insert(inc.tar_path.clone()) {
            bail!(
                "duplicate tar path from --include: '{}' (already present from input files or dependencies)",
                inc.tar_path
            );
        }
        let data = std::fs::read(&inc.host_path)
            .with_context(|| format!("failed to read included file {}", inc.host_path.display()))?;
        let mode = std::fs::metadata(&inc.host_path)
            .map(|m| m.mode())
            .unwrap_or(0o644);
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

    // --- Phase 4: Build tar ---
    eprintln!("Creating {}...", args.output.display());
    build_tar(&tar_entries, &args.output)?;

    let tar_size = std::fs::metadata(&args.output)
        .map(|m| m.len())
        .unwrap_or(0);
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

/// Rewrite an ELF file's syscall instructions using the litebox syscall rewriter.
///
/// If the file is not a supported ELF or has no syscalls, the original bytes are
/// returned with a warning.
fn rewrite_elf(data: &[u8], path: &Path, verbose: bool) -> anyhow::Result<Vec<u8>> {
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
            eprintln!(
                "  warning: {} is not a supported ELF, including as-is",
                path.display()
            );
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
