// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// See the OCI dependency block in Cargo.toml for why these are the hosts
// that can pull images.
#[cfg(any(
    target_arch = "x86_64",
    all(target_arch = "aarch64", target_vendor = "apple")
))]
pub mod oci;

mod musl_x18;

use anyhow::{Context, bail};
use clap::Parser;
use rayon::prelude::*;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::collections::BTreeMap;
use std::collections::BTreeSet;
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
///   `ldd` on Linux (macOS requires statically linked inputs), rewrites
///   syscalls, and produces a tar.
/// - **OCI mode** (`--oci-image`): Pulls a container image from a registry,
///   extracts its rootfs, rewrites all executable ELFs, and produces a tar.
#[derive(Parser, Debug)]
#[command(name = "litebox-packager")]
pub struct CliArgs {
    /// ELF files to package (host mode). Not used in OCI mode.
    #[arg(required_unless_present_any = ["oci_image", "oci_rootfs_tar"])]
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

    /// Package a locally-exported container rootfs tar (`podman export` /
    /// `docker export` output) instead of pulling from a registry -- the path
    /// for locally-built images that exist in no registry. Same pipeline as
    /// `--oci-image` from extraction onward; the container config
    /// (ENTRYPOINT/ENV) is not present in an exported rootfs, so no
    /// `config_and_run.sh` is generated -- name the program to run explicitly
    /// on the runner command line.
    #[arg(
        long = "oci-rootfs-tar",
        value_name = "PATH_TO_TAR",
        conflicts_with_all = ["input_files", "oci_image"]
    )]
    pub oci_rootfs_tar: Option<PathBuf>,

    /// Output tar file path.
    #[arg(short = 'o', long = "output", default_value = "litebox_packager.tar")]
    pub output: PathBuf,

    /// Include extra files in the tar (host mode only).
    /// ELF files are automatically run through the syscall rewriter; non-ELF
    /// files are included as-is.
    /// Format: HOST_PATH:TAR_PATH (split on the first colon, so the tar path
    /// may contain colons but the host path must not).
    #[arg(
        long = "include",
        value_name = "HOST_PATH:TAR_PATH",
        conflicts_with = "oci_image"
    )]
    pub include: Vec<String>,

    /// Skip rewriting specific files (by their absolute path on the host).
    #[arg(long = "no-rewrite", value_name = "PATH")]
    pub no_rewrite: Vec<PathBuf>,

    /// Skip the syscall rewriter entirely for every file (OCI mode) or every
    /// discovered dependency (host mode) and emit stock bytes unchanged.
    ///
    /// For the macOS Hypervisor.framework backend (`--hvf`), guest `SVC #0`
    /// dispatches through a real EL1 monitor with `x18` architecturally
    /// preserved, so unmodified upstream Alpine binaries already run
    /// correctly with no rewriting, no musl substitution, and no x18
    /// reservation -- the entire point of that backend. This flag is the
    /// packaging-side complement: it disables both `rewrite_elf` and the
    /// `musl_x18` cache substitution unconditionally, regardless of
    /// `--no-rewrite`'s per-path list, so a whole rootfs of hundreds of
    /// files does not need every path enumerated individually. Do not
    /// combine with binaries destined for the older native rewriting
    /// backend -- those still require syscall-rewritten (and, on macOS,
    /// x18-fixed) bytes.
    #[arg(long = "no-rewrite-all")]
    pub no_rewrite_all: bool,

    /// Print verbose output during packaging.
    #[arg(short = 'v', long = "verbose")]
    pub verbose: bool,
}

/// Parsed `--include` entry.
#[cfg(any(target_os = "linux", target_os = "macos"))]
struct IncludeEntry {
    host_path: PathBuf,
    tar_path: String,
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
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
    if let Some(ref rootfs_tar) = args.oci_rootfs_tar {
        #[cfg(any(
            target_arch = "x86_64",
            all(target_arch = "aarch64", target_vendor = "apple")
        ))]
        {
            return run_oci_rootfs_tar(rootfs_tar, &args);
        }
        #[cfg(not(any(
            target_arch = "x86_64",
            all(target_arch = "aarch64", target_vendor = "apple")
        )))]
        {
            let _ = rootfs_tar;
            bail!("--oci-rootfs-tar is only supported on x86-64 hosts and Apple Silicon");
        }
    }
    if let Some(ref image_ref) = args.oci_image {
        #[cfg(any(
            target_arch = "x86_64",
            all(target_arch = "aarch64", target_vendor = "apple")
        ))]
        {
            return run_oci(image_ref, &args);
        }
        #[cfg(not(any(
            target_arch = "x86_64",
            all(target_arch = "aarch64", target_vendor = "apple")
        )))]
        {
            let _ = image_ref;
            bail!("--oci-image is only supported on x86-64 hosts and Apple Silicon");
        }
    }

    // Host mode is Linux (ldd-based dependency discovery) and macOS
    // (statically linked inputs only; see `require_statically_linked`).
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        run_host_mode(args)
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        bail!(
            "Host mode (local ELF files) is only supported on Linux and macOS. \
             Use --oci-image to pull a container image instead."
        );
    }
}

/// Host mode: package local ELF files. On Linux, dependencies are discovered
/// via `ldd`; on macOS, inputs must already be statically linked, since
/// dependency discovery isn't implemented there yet (see
/// `require_statically_linked`).
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn run_host_mode(args: CliArgs) -> anyhow::Result<()> {
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
    #[cfg(target_os = "linux")]
    let file_map = discover_all_dependencies(&input_files, args.verbose)?;
    #[cfg(target_os = "macos")]
    let file_map = require_statically_linked(&input_files)?;

    eprintln!(
        "Found {} unique files across {} input file(s)",
        file_map.len(),
        input_files.len()
    );

    // --- Phase 3: Rewrite ELFs (parallel) ---
    eprintln!("Rewriting {} unique ELF files...", file_map.len());

    let file_map_vec: Vec<(&PathBuf, &Vec<PathBuf>)> = file_map.iter().collect();
    let verbose = args.verbose;

    let par_results: Vec<anyhow::Result<Vec<TarEntry>>> = file_map_vec
        .into_par_iter()
        .map(|(real_path, tar_paths): (&PathBuf, &Vec<PathBuf>)| {
            let data = std::fs::read(real_path)
                .with_context(|| format!("failed to read {}", real_path.display()))?;
            let metadata = std::fs::metadata(real_path)
                .with_context(|| format!("failed to stat {}", real_path.display()))?;
            let (mode, uid, gid) = {
                use std::os::unix::fs::MetadataExt as _;
                (
                    metadata.mode(),
                    u64::from(metadata.uid()),
                    u64::from(metadata.gid()),
                )
            };

            let rewritten = if args.no_rewrite_all || no_rewrite.contains(real_path) {
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
                entries.push(TarEntry::regular(
                    tar_path,
                    rewritten.clone(),
                    mode,
                    uid,
                    gid,
                ));
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

    // Append --include files (ELF files are automatically rewritten).
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
        let metadata = std::fs::metadata(&inc.host_path)
            .with_context(|| format!("failed to stat included file {}", inc.host_path.display()))?;
        let (mode, uid, gid) = {
            use std::os::unix::fs::MetadataExt as _;
            (
                metadata.mode(),
                u64::from(metadata.uid()),
                u64::from(metadata.gid()),
            )
        };
        let rewritten = if args.no_rewrite_all {
            data
        } else {
            rewrite_elf(&data, &inc.host_path, args.verbose)?
        };
        if args.verbose {
            eprintln!(
                "  including {} as {}",
                inc.host_path.display(),
                inc.tar_path
            );
        }
        tar_entries.push(TarEntry::regular(
            inc.tar_path.clone(),
            rewritten,
            mode,
            uid,
            gid,
        ));
    }

    finalize_tar(tar_entries, &args)?;

    Ok(())
}

/// Run the packager in OCI mode: pull image, extract rootfs, rewrite ELFs, build tar.
#[cfg(any(
    target_arch = "x86_64",
    all(target_arch = "aarch64", target_vendor = "apple")
))]
fn run_oci(image_ref: &str, args: &CliArgs) -> anyhow::Result<()> {
    // --- Phase 1: Pull and extract OCI image ---
    eprintln!("Pulling OCI image: {image_ref}");
    let extracted = oci::pull_and_extract(image_ref, args.verbose)?;
    package_extracted(&extracted, args)
}

/// Package a locally-exported container rootfs tar: same pipeline as [`run_oci`] from
/// extraction onward, minus the registry pull.
#[cfg(any(
    target_arch = "x86_64",
    all(target_arch = "aarch64", target_vendor = "apple")
))]
fn run_oci_rootfs_tar(rootfs_tar: &Path, args: &CliArgs) -> anyhow::Result<()> {
    eprintln!("Extracting rootfs tar: {}", rootfs_tar.display());
    let extracted = oci::extract_rootfs_tar(rootfs_tar, args.verbose)?;
    package_extracted(&extracted, args)
}

/// The shared post-extraction packaging pipeline: scan, rewrite, config, tar.
#[cfg(any(
    target_arch = "x86_64",
    all(target_arch = "aarch64", target_vendor = "apple")
))]
fn package_extracted(extracted: &oci::ExtractedImage, args: &CliArgs) -> anyhow::Result<()> {
    const GENERATED_UID: u64 = 1000;
    const GENERATED_GID: u64 = 1000;
    const LITEBOX_TAR_PATH: &str = "litebox";

    // --- Phase 2: Scan rootfs for files ---
    eprintln!("Scanning rootfs...");
    let file_map = oci::scan_rootfs(
        &extracted.rootfs_path,
        &extracted.symlink_map,
        &extracted.ownership,
        &extracted.permissions,
        args.verbose,
    )?;

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

    let exec_count = file_map
        .files
        .values()
        .filter(|entry| {
            matches!(
                &entry.kind,
                oci::RootfsEntryKind::Regular {
                    is_executable: true,
                    ..
                }
            )
        })
        .count();
    let total_count = file_map.files.len();
    eprintln!("Found {total_count} entries ({exec_count} executable regular files to rewrite)");

    // --- Phase 3: Rewrite ELFs in parallel ---
    if args.no_rewrite_all {
        eprintln!(
            "Skipping the syscall rewriter for all {exec_count} executable files \
             (--no-rewrite-all): emitting stock bytes unchanged."
        );
    } else {
        eprintln!("Rewriting {exec_count} executable ELF files...");
    }
    let verbose = args.verbose;
    let no_rewrite_all = args.no_rewrite_all;
    let file_entries: Vec<(PathBuf, oci::RootfsEntry)> = file_map.files.into_iter().collect();

    let par_results: Vec<anyhow::Result<TarEntry>> = file_entries
        .into_par_iter()
        .map(|(_key_path, entry)| {
            let oci::RootfsEntry {
                tar_path,
                kind,
                mode,
                uid,
                gid,
            } = entry;
            match kind {
                oci::RootfsEntryKind::Regular {
                    read_path,
                    is_executable,
                } => {
                    let data = std::fs::read(&read_path)
                        .with_context(|| format!("failed to read {}", read_path.display()))?;
                    let data =
                        if is_executable && !no_rewrite_all && !no_rewrite.contains(&read_path) {
                            rewrite_elf(&data, &read_path, verbose)?
                        } else {
                            data
                        };
                    Ok(TarEntry::regular(tar_path, data, mode, uid, gid))
                }
                oci::RootfsEntryKind::Symlink { link_target } => {
                    Ok(TarEntry::symlink(tar_path, link_target, mode, uid, gid))
                }
                oci::RootfsEntryKind::Directory => {
                    Ok(TarEntry::directory(tar_path, mode, uid, gid))
                }
            }
        })
        .collect();

    let mut tar_entries: Vec<TarEntry> = Vec::with_capacity(par_results.len());
    for result in par_results {
        tar_entries.push(result?);
    }

    let mut added_tar_paths: BTreeSet<String> =
        tar_entries.iter().map(|e| e.tar_path.clone()).collect();

    // --- Phase 4: Store config.json and generate config_and_run.sh from image config ---

    if added_tar_paths.insert(LITEBOX_TAR_PATH.to_string()) {
        tar_entries.push(TarEntry::directory(
            LITEBOX_TAR_PATH.to_string(),
            0o755,
            GENERATED_UID,
            GENERATED_GID,
        ));
    }

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
            tar_entries.push(TarEntry::regular(
                CONFIG_JSON_TAR_PATH.to_string(),
                extracted.config_json.clone(),
                0o644,
                GENERATED_UID,
                GENERATED_GID,
            ));
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
            tar_entries.push(TarEntry::regular(
                CONFIG_AND_RUN_TAR_PATH.to_string(),
                script.into_bytes(),
                0o755,
                GENERATED_UID,
                GENERATED_GID,
            ));
        } else {
            eprintln!(
                "warning: tar already contains {CONFIG_AND_RUN_TAR_PATH}, skipping generation"
            );
        }
    }

    finalize_tar(tar_entries, args)?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Shared finalization: tar build, size report
// ---------------------------------------------------------------------------

/// Build the output tar and print a size summary.
fn finalize_tar(tar_entries: Vec<TarEntry>, args: &CliArgs) -> anyhow::Result<()> {
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

#[cfg(target_os = "linux")]
struct ResolvedDep {
    ldd_path: PathBuf,
    real_path: PathBuf,
}

#[cfg(target_os = "linux")]
struct DepDiscoveryResult {
    resolved: Vec<ResolvedDep>,
    missing: Vec<String>,
}

/// Run `ldd` on the given ELF and return resolved dependencies.
#[cfg(target_os = "linux")]
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
#[cfg(target_os = "linux")]
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
// Dependency discovery (macOS: statically linked inputs only)
// ---------------------------------------------------------------------------

/// Returns `Some(true)` if the ELF has no `PT_INTERP` program header and no
/// `DT_NEEDED` dynamic entries, i.e. nothing a dependency resolver would need
/// to find. Returns `Some(false)` if it has either, and `None` if `data`
/// cannot be parsed as an ELF file.
#[cfg(target_os = "macos")]
fn elf_is_statically_linked(data: &[u8]) -> Option<bool> {
    use object::read::elf::{Dyn as _, FileHeader, ProgramHeader as _};

    fn has_dynamic_deps<Elf: FileHeader<Endian = object::Endianness>>(
        header: &Elf,
        data: &[u8],
    ) -> Option<bool> {
        let endian = header.endian().ok()?;
        for phdr in header.program_headers(endian, data).ok()? {
            if phdr.p_type(endian) == object::elf::PT_INTERP {
                return Some(true);
            }
            if let Some(entries) = phdr.dynamic(endian, data).ok()?
                && entries
                    .iter()
                    .any(|entry| entry.tag32(endian) == Some(object::elf::DT_NEEDED))
            {
                return Some(true);
            }
        }
        Some(false)
    }

    let dynamic = if let Ok(header) = object::elf::FileHeader64::<object::Endianness>::parse(data) {
        has_dynamic_deps(header, data)
    } else if let Ok(header) = object::elf::FileHeader32::<object::Endianness>::parse(data) {
        has_dynamic_deps(header, data)
    } else {
        None
    }?;
    Some(!dynamic)
}

/// Host mode without `ldd`: every input must already be a statically linked
/// ELF, so the file map is just each input mapped to itself. Dependency
/// discovery for dynamically linked guests is not implemented on macOS yet.
#[cfg(target_os = "macos")]
fn require_statically_linked(
    input_files: &[PathBuf],
) -> anyhow::Result<BTreeMap<PathBuf, Vec<PathBuf>>> {
    let mut file_map: BTreeMap<PathBuf, Vec<PathBuf>> = BTreeMap::new();

    for input_path in input_files {
        let data = std::fs::read(input_path)
            .with_context(|| format!("failed to read {}", input_path.display()))?;
        match elf_is_statically_linked(&data) {
            Some(true) => {}
            Some(false) => bail!(
                "{} is dynamically linked; host mode on macOS only supports statically \
                 linked binaries, since ldd-based dependency discovery is Linux-only and \
                 not yet implemented here",
                input_path.display()
            ),
            None => bail!("{} is not a valid ELF file", input_path.display()),
        }

        let canonical = std::fs::canonicalize(input_path)
            .with_context(|| format!("could not canonicalize {}", input_path.display()))?;
        let entry = file_map.entry(canonical).or_default();
        if !entry.contains(input_path) {
            entry.push(input_path.clone());
        }
    }

    Ok(file_map)
}

// ---------------------------------------------------------------------------
// ELF rewriting
// ---------------------------------------------------------------------------

/// ELF magic bytes: `\x7fELF`.
const ELF_MAGIC: [u8; 4] = [0x7f, b'E', b'L', b'F'];

/// ELF e_machine value for x86_64.
const EM_X86_64: u16 = 62;
/// ELF e_machine value for AArch64.
const EM_AARCH64: u16 = 183;

/// Read the ELF e_machine field using the `object` crate for proper header parsing.
fn elf_machine(data: &[u8]) -> Option<u16> {
    use object::read::elf::FileHeader;
    if let Ok(header) = object::elf::FileHeader64::<object::Endianness>::parse(data) {
        let endian = header.endian().ok()?;
        Some(header.e_machine(endian))
    } else if let Ok(header) = object::elf::FileHeader32::<object::Endianness>::parse(data) {
        let endian = header.endian().ok()?;
        Some(header.e_machine(endian))
    } else {
        None
    }
}

/// Returns the expected ELF e_machine value for the current target architecture.
fn target_elf_machine() -> u16 {
    if cfg!(target_arch = "x86_64") {
        EM_X86_64
    } else if cfg!(target_arch = "aarch64") {
        EM_AARCH64
    } else {
        0 // Unknown — skip arch check
    }
}

/// The syscall rewriter's AArch64 host anchor to target: whichever OS is
/// actually going to run the packaged guest, which -- since packaging happens
/// on that same host in this project's usage model -- is the OS this packager
/// binary is itself running on. `TPIDR_EL0` (the `Host::Linux` anchor) does
/// not survive a context switch on macOS, so packaging a Linux-anchored
/// AArch64 binary there would silently produce gates that fault the guest the
/// first time it is rescheduled.
///
/// `Host::MacOs`'s gates anchor on `TPIDRRO_EL0` and address the guest
/// thread-pointer slot at a runtime-reserved *pthread TSD slot*
/// (`MACOS_GUEST_TPIDR_TSD_SLOT`), not a raw offset into Apple's own pthread
/// structure -- so this no longer risks corrupting libpthread state. The
/// macOS runtime must reserve that exact slot with `pthread_key_create`
/// before running a guest; the guest-entry side of that is still unimplemented
/// (see `docs/roadmap.md`), so a macOS-packaged binary is not yet *runnable*,
/// but it is now correctly *anchored*.
fn rewrite_host() -> litebox_syscall_rewriter::Host {
    if cfg!(target_os = "macos") {
        litebox_syscall_rewriter::Host::MacOs
    } else {
        litebox_syscall_rewriter::Host::Linux
    }
}

/// Rewrite an ELF file's syscall instructions using the litebox syscall rewriter.
///
/// Non-ELF files (shell scripts, data files with executable bits, etc.) are
/// detected via a magic-byte check and returned unmodified without being sent
/// through the rewriter. An actual ELF must match the host architecture, and
/// every error returned by the rewriter is fatal. Benign cases such as an
/// already-hooked binary or one with no rewrite sites remain successful when
/// the rewriter returns them unchanged.
fn rewrite_elf(data: &[u8], path: &Path, verbose: bool) -> anyhow::Result<Vec<u8>> {
    // Fast-path: skip the rewriter entirely for non-ELF files.
    if data.len() < 4 || data[..4] != ELF_MAGIC {
        if verbose {
            eprintln!("  {} (not ELF, skipping rewrite)", path.display());
        }
        return Ok(data.to_vec());
    }

    // A different-architecture ELF cannot be rewritten into something LiteBox
    // can execute natively, so emitting its original bytes would create a
    // package that fails only at run time.
    let target_machine = target_elf_machine();
    if target_machine != 0
        && let Some(machine) = elf_machine(data)
        && machine != target_machine
    {
        bail!(
            "cannot rewrite executable ELF {}: e_machine {machine} does not match host e_machine {target_machine}",
            path.display()
        );
    }

    let host = rewrite_host();

    // musl's dynamic-linker relocation bootstrap holds a live value in `x18`
    // across a boundary XNU zeroes it at, so a guest built for ordinary Linux
    // (where `x18` is an allocatable register) crashes early under a macOS
    // host -- see `musl_x18`'s module doc comment and `docs/roadmap.md`'s
    // "XNU destroys a live guest x18" section. Substituting a cached,
    // `-ffixed-x18`-rebuilt replacement before rewriting closes that gap for
    // any macOS-targeted package containing a standard Alpine musl. A cache
    // miss warns and continues rewriting the original musl input unless the
    // caller sets `LITEBOX_REQUIRE_MUSL_X18=1`, which makes the missing
    // validated generation fatal.
    let data = if matches!(host, litebox_syscall_rewriter::Host::MacOs)
        && musl_x18::is_musl_libc_filename(path)
    {
        if let Some(patched) = musl_x18::lookup_patched_musl(data) {
            if verbose {
                eprintln!(
                    "  {} (substituting cached -ffixed-x18 musl before rewriting)",
                    path.display()
                );
            }
            patched
        } else {
            musl_x18::warn_missing_patch(path, data);
            if musl_x18::patch_is_required() {
                bail!(
                    "validated x18-safe musl cache entry is required for {}",
                    path.display()
                );
            }
            data.to_vec()
        }
    } else {
        data.to_vec()
    };
    let data = data.as_slice();

    let rewritten = litebox_syscall_rewriter::hook_syscalls_in_elf_for_host(data, None, host)
        .map_err(|error| {
            anyhow::anyhow!(
                "failed to rewrite executable ELF {}: {error}",
                path.display()
            )
        })?;
    if verbose {
        eprintln!("  {} (rewritten)", path.display());
    }
    Ok(rewritten)
}

// ---------------------------------------------------------------------------
// Tar archive construction
// ---------------------------------------------------------------------------

enum TarEntryKind {
    Regular(Vec<u8>),
    Symlink(Vec<u8>),
    Directory,
}

struct TarEntry {
    tar_path: String,
    kind: TarEntryKind,
    mode: u32,
    uid: u64,
    gid: u64,
}

impl TarEntry {
    fn regular(tar_path: String, data: Vec<u8>, mode: u32, uid: u64, gid: u64) -> Self {
        Self {
            tar_path,
            kind: TarEntryKind::Regular(data),
            mode,
            uid,
            gid,
        }
    }

    fn symlink(tar_path: String, link_target: Vec<u8>, mode: u32, uid: u64, gid: u64) -> Self {
        Self {
            tar_path,
            kind: TarEntryKind::Symlink(link_target),
            mode,
            uid,
            gid,
        }
    }

    fn directory(tar_path: String, mode: u32, uid: u64, gid: u64) -> Self {
        Self {
            tar_path,
            kind: TarEntryKind::Directory,
            mode,
            uid,
            gid,
        }
    }
}

const USTAR_MAX_FILE_SIZE: u64 = (1_u64 << 33) - 1;
const USTAR_MAX_ID: u64 = (1_u64 << 21) - 1;

fn ustar_header(entry: &TarEntry) -> anyhow::Result<Header> {
    let mut header = Header::new_ustar();
    header
        .set_path(&entry.tar_path)
        .with_context(|| format!("failed to encode ustar path {}", entry.tar_path))?;
    header.set_mode(entry.mode & 0o7777);
    if entry.uid > USTAR_MAX_ID {
        bail!(
            "uid {} for {} exceeds pure ustar's maximum numeric id {USTAR_MAX_ID}",
            entry.uid,
            entry.tar_path
        );
    }
    if entry.gid > USTAR_MAX_ID {
        bail!(
            "gid {} for {} exceeds pure ustar's maximum numeric id {USTAR_MAX_ID}",
            entry.gid,
            entry.tar_path
        );
    }
    header.set_uid(entry.uid);
    header.set_gid(entry.gid);

    match &entry.kind {
        TarEntryKind::Regular(data) => {
            let size = u64::try_from(data.len())
                .with_context(|| format!("file size cannot fit u64 for {}", entry.tar_path))?;
            if size > USTAR_MAX_FILE_SIZE {
                bail!(
                    "regular file {} is {size} bytes, exceeding pure ustar's {USTAR_MAX_FILE_SIZE}-byte limit",
                    entry.tar_path
                );
            }
            header.set_entry_type(tar::EntryType::Regular);
            header.set_size(size);
        }
        TarEntryKind::Symlink(link_target) => {
            header.set_entry_type(tar::EntryType::Symlink);
            header.set_size(0);
            header.set_link_name_literal(link_target).with_context(|| {
                format!(
                    "failed to encode ustar link target for {} -> {}",
                    entry.tar_path,
                    String::from_utf8_lossy(link_target)
                )
            })?;
        }
        TarEntryKind::Directory => {
            header.set_entry_type(tar::EntryType::Directory);
            header.set_size(0);
        }
    }
    header.set_cksum();
    Ok(header)
}

fn build_tar(entries: &[TarEntry], output: &Path) -> anyhow::Result<()> {
    let headers = entries
        .iter()
        .map(ustar_header)
        .collect::<anyhow::Result<Vec<_>>>()?;
    let file = std::fs::File::create(output)
        .with_context(|| format!("failed to create output file {}", output.display()))?;
    let mut builder = Builder::new(file);

    for (entry, header) in entries.iter().zip(&headers) {
        let append_result = match &entry.kind {
            TarEntryKind::Regular(data) => builder.append(header, data.as_slice()),
            TarEntryKind::Symlink(_) | TarEntryKind::Directory => {
                builder.append(header, std::io::empty())
            }
        };
        append_result.with_context(|| format!("failed to add {} to tar", entry.tar_path))?;
    }

    builder.finish().context("failed to finalize tar archive")?;
    Ok(())
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::*;

    fn elf64_header(e_phoff: u64, e_phnum: u16) -> Vec<u8> {
        let mut buf = vec![0u8; 64];
        buf[0..4].copy_from_slice(&ELF_MAGIC);
        buf[4] = 2; // ELFCLASS64
        buf[5] = 1; // ELFDATA2LSB
        buf[6] = 1; // EV_CURRENT
        buf[16..18].copy_from_slice(&2u16.to_le_bytes()); // e_type = ET_EXEC
        buf[18..20].copy_from_slice(&EM_X86_64.to_le_bytes());
        buf[20..24].copy_from_slice(&1u32.to_le_bytes()); // e_version
        buf[32..40].copy_from_slice(&e_phoff.to_le_bytes());
        buf[52..54].copy_from_slice(&64u16.to_le_bytes()); // e_ehsize
        buf[54..56].copy_from_slice(&56u16.to_le_bytes()); // e_phentsize == size_of::<Elf64_Phdr>()
        buf[56..58].copy_from_slice(&e_phnum.to_le_bytes());
        buf
    }

    fn append_phdr(buf: &mut Vec<u8>, p_type: u32, p_offset: u64, p_filesz: u64) {
        buf.extend_from_slice(&p_type.to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes()); // p_flags
        buf.extend_from_slice(&p_offset.to_le_bytes());
        buf.extend_from_slice(&0u64.to_le_bytes()); // p_vaddr
        buf.extend_from_slice(&0u64.to_le_bytes()); // p_paddr
        buf.extend_from_slice(&p_filesz.to_le_bytes());
        buf.extend_from_slice(&0u64.to_le_bytes()); // p_memsz
        buf.extend_from_slice(&0u64.to_le_bytes()); // p_align
    }

    #[test]
    fn elf_is_statically_linked_true_with_no_program_headers() {
        let elf = elf64_header(0, 0);
        assert_eq!(elf_is_statically_linked(&elf), Some(true));
    }

    #[test]
    fn elf_is_statically_linked_false_with_pt_interp() {
        let mut elf = elf64_header(64, 1);
        append_phdr(&mut elf, object::elf::PT_INTERP, 0, 0);
        assert_eq!(elf_is_statically_linked(&elf), Some(false));
    }

    #[test]
    fn elf_is_statically_linked_false_with_dt_needed() {
        let mut elf = elf64_header(64, 1);
        let dynamic_offset = elf.len() as u64 + 56;
        append_phdr(&mut elf, object::elf::PT_DYNAMIC, dynamic_offset, 16);
        elf.extend_from_slice(&u64::from(object::elf::DT_NEEDED).to_le_bytes()); // d_tag
        elf.extend_from_slice(&0u64.to_le_bytes()); // d_val
        assert_eq!(elf_is_statically_linked(&elf), Some(false));
    }

    #[test]
    fn elf_is_statically_linked_none_for_non_elf_data() {
        assert_eq!(elf_is_statically_linked(b"not an elf file"), None);
    }
}
