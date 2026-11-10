// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

pub mod oci;

use anyhow::{Context, bail};
use clap::{Parser, ValueEnum};
use rayon::prelude::*;
#[cfg(target_os = "linux")]
use std::collections::BTreeSet;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tar::{Builder, Header};

/// Package Linux ELF programs for execution under LiteBox.
///
/// Discovers shared library dependencies, rewrites all ELF files using the
/// syscall rewriter, and produces a .tar suitable for use with
/// `litebox-broker-userland --fs-initial-files`.
///
/// Supports two modes:
/// - **Host mode** (default): Takes local ELF files, discovers dependencies via
///   `ldd`, rewrites syscalls, and produces a tar.
/// - **OCI mode** (`--oci-image`): Pulls a container image from a registry,
///   merges its layers, rewrites all executable ELFs, and produces a tar that
///   keeps the image's directories, symlinks and hard links.
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

    /// Skip rewriting specific files: by their absolute path on the host in
    /// host mode, or in OCI mode by an absolute path in the image that resolves
    /// to them through any symlinks, e.g. `/usr/bin/foo`; all their hard link
    /// names are then skipped.
    #[arg(long = "no-rewrite", value_name = "PATH")]
    pub no_rewrite: Vec<PathBuf>,

    /// Host ABI expected by packaged AArch64 binaries; ignored for x86-64 binaries.
    #[arg(long, value_enum, default_value_t)]
    pub target_host: CliTargetHost,

    /// CPU architecture of binaries selected and rewritten for the package.
    /// Cross-architecture packaging is supported only with `--oci-image`.
    #[arg(long, value_enum, default_value_t)]
    pub target_arch: CliTargetArch,

    /// Virtualize x18 in packaged AArch64 binaries targeting Linux; ignored for
    /// x86-64 binaries and always enabled for macOS and Windows host ABIs.
    /// Requires the runner's `aarch64_virtualize_x18` feature.
    #[arg(long = "virtualize-x18")]
    pub virtualize_x18: bool,

    /// Leave guest AArch64 `TPIDR_EL0` accesses native for a runner that gives
    /// the guest the physical register. Requires --target-arch aarch64 and
    /// --target-host linux.
    #[arg(long, conflicts_with = "virtualize_x18")]
    pub native_tpidr_el0: bool,

    /// Print verbose output during packaging.
    #[arg(short = 'v', long = "verbose")]
    pub verbose: bool,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum CliTargetHost {
    Linux,
    Macos,
    Windows,
}

impl Default for CliTargetHost {
    fn default() -> Self {
        if cfg!(target_os = "macos") {
            Self::Macos
        } else if cfg!(target_os = "windows") {
            Self::Windows
        } else {
            Self::Linux
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum CliTargetArch {
    #[value(name = "x86-64")]
    X86_64,
    Aarch64,
}

impl CliTargetArch {
    fn elf_machine(self) -> u16 {
        match self {
            Self::X86_64 => EM_X86_64,
            Self::Aarch64 => EM_AARCH64,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::X86_64 => "x86-64",
            Self::Aarch64 => "aarch64",
        }
    }

    fn oci_arch(self) -> oci_spec::image::Arch {
        match self {
            Self::X86_64 => oci_spec::image::Arch::Amd64,
            Self::Aarch64 => oci_spec::image::Arch::ARM64,
        }
    }
}

impl Default for CliTargetArch {
    fn default() -> Self {
        if cfg!(target_arch = "aarch64") {
            Self::Aarch64
        } else {
            Self::X86_64
        }
    }
}

impl CliArgs {
    fn rewrite_options(&self) -> anyhow::Result<litebox_syscall_rewriter::RewriteOptions> {
        // Validate before dependency discovery or OCI pulls: rewrite failures
        // otherwise fall back to including the original file.
        if self.native_tpidr_el0
            && (self.target_arch != CliTargetArch::Aarch64
                || !matches!(self.target_host, CliTargetHost::Linux)
                || self.virtualize_x18)
        {
            bail!(
                "--native-tpidr-el0 requires --target-arch aarch64 and --target-host linux \
                 without --virtualize-x18"
            );
        }
        let target_host = match self.target_host {
            CliTargetHost::Linux => litebox_trampoline::TargetHost::Linux,
            CliTargetHost::Macos => litebox_trampoline::TargetHost::MacOs,
            CliTargetHost::Windows => litebox_trampoline::TargetHost::Windows,
        };
        let options =
            litebox_syscall_rewriter::RewriteOptions::new(target_host, self.virtualize_x18);
        Ok(if self.native_tpidr_el0 {
            options.with_native_tpidr_el0()
        } else {
            options
        })
    }
}

/// Parsed `--include` entry.
#[cfg(target_os = "linux")]
struct IncludeEntry {
    host_path: PathBuf,
    tar_path: String,
}

#[cfg(target_os = "linux")]
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
    let rewrite_options = args.rewrite_options()?;
    if let Some(ref image_ref) = args.oci_image {
        return run_oci(image_ref, &args, rewrite_options);
    }

    validate_host_target_arch(args.target_arch)?;

    // Host mode (local ELF files + ldd dependency discovery) is Linux-only.
    #[cfg(target_os = "linux")]
    {
        run_host_mode(args, rewrite_options)
    }

    #[cfg(not(target_os = "linux"))]
    {
        bail!(
            "Host mode (local ELF files) is only supported on Linux. \
             Use --oci-image to pull a container image instead."
        );
    }
}

/// Host mode: package local ELF files with ldd-based dependency discovery.
#[cfg(target_os = "linux")]
fn run_host_mode(
    args: CliArgs,
    rewrite_options: litebox_syscall_rewriter::RewriteOptions,
) -> anyhow::Result<()> {
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
    // Each file is placed as a regular file copy at every path it was found at.
    eprintln!("Rewriting {} unique ELF files...", file_map.len());

    let file_map_vec: Vec<(&PathBuf, &Vec<PathBuf>)> = file_map.iter().collect();
    let verbose = args.verbose;

    let par_results: Vec<anyhow::Result<Vec<(String, FileObject)>>> = file_map_vec
        .into_par_iter()
        .map(|(real_path, tar_paths): (&PathBuf, &Vec<PathBuf>)| {
            let data = std::fs::read(real_path)
                .with_context(|| format!("failed to read {}", real_path.display()))?;
            let mode = {
                use std::os::unix::fs::MetadataExt as _;
                std::fs::metadata(real_path)
                    .with_context(|| format!("failed to stat {}", real_path.display()))?
                    .mode()
            };

            let rewritten = if no_rewrite.contains(real_path) {
                if verbose {
                    eprintln!("  {} (skipped rewrite)", real_path.display());
                }
                data
            } else {
                rewrite_elf(&data, real_path, verbose, rewrite_options, args.target_arch)
                    .unwrap_or(data)
            };

            let mut entries = Vec::new();
            for path in tar_paths {
                let tar_path = path
                    .to_str()
                    .with_context(|| format!("non-UTF8 path: {}", path.display()))?;
                let tar_path = tar_path.strip_prefix('/').unwrap_or(tar_path).to_string();
                entries.push((
                    tar_path,
                    FileObject {
                        data: rewritten.clone(),
                        mode,
                    },
                ));
            }
            Ok(entries)
        })
        .collect();

    // Flatten results, deduplicating by tar path.
    let mut nodes = BTreeMap::<String, RootfsNode>::new();
    for result in par_results {
        for (tar_path, file) in result? {
            nodes
                .entry(tar_path)
                .or_insert_with(|| RootfsNode::File(Arc::new(file)));
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
        if nodes.contains_key(&inc.tar_path) {
            bail!(
                "duplicate tar path from --include: '{}' (already present)",
                inc.tar_path
            );
        }
        let data = std::fs::read(&inc.host_path)
            .with_context(|| format!("failed to read included file {}", inc.host_path.display()))?;
        let mode = {
            use std::os::unix::fs::MetadataExt as _;
            std::fs::metadata(&inc.host_path).map_or(0o755, |m| m.mode())
        };
        let rewritten = rewrite_elf(
            &data,
            &inc.host_path,
            args.verbose,
            rewrite_options,
            args.target_arch,
        )
        .unwrap_or(data);
        if args.verbose {
            eprintln!(
                "  including {} as {}",
                inc.host_path.display(),
                inc.tar_path
            );
        }
        nodes.insert(
            inc.tar_path.clone(),
            RootfsNode::File(Arc::new(FileObject {
                data: rewritten,
                mode,
            })),
        );
    }

    finalize_tar(&nodes, &args)?;

    Ok(())
}

/// Run the packager in OCI mode: pull image, merge layers, rewrite ELFs, build tar.
fn run_oci(
    image_ref: &str,
    args: &CliArgs,
    rewrite_options: litebox_syscall_rewriter::RewriteOptions,
) -> anyhow::Result<()> {
    // --- Phase 1: Pull and merge the OCI image ---
    eprintln!("Pulling OCI image: {image_ref}");
    let oci::PulledImage {
        mut rootfs,
        config,
        config_json,
    } = oci::pull_image(image_ref, args.target_arch, args.verbose)?;

    // --- Phase 2: Rewrite ELFs in parallel ---
    rewrite_executables(
        &mut rootfs,
        &args.no_rewrite,
        args.verbose,
        rewrite_options,
        args.target_arch,
    );

    // --- Phase 3: Store config.json and generate config_and_run.sh from image config ---

    // Always store the raw OCI config JSON for future use.
    {
        const CONFIG_JSON_TAR_PATH: &str = "litebox/config.json";
        if args.verbose {
            eprintln!(
                "  Storing {CONFIG_JSON_TAR_PATH} ({} bytes)",
                config_json.len()
            );
        }
        let file = FileObject {
            data: config_json,
            mode: 0o644,
        };
        if !rootfs.add_file(CONFIG_JSON_TAR_PATH, file) {
            eprintln!(
                "warning: {CONFIG_JSON_TAR_PATH} already exists or a parent does not resolve to a directory, skipping"
            );
        }
    }

    {
        const CONFIG_AND_RUN_TAR_PATH: &str = "litebox/config_and_run.sh";
        if args.verbose {
            eprintln!("  Generating {CONFIG_AND_RUN_TAR_PATH} from image config");
        }
        let file = FileObject {
            data: oci::generate_config_and_run_script(&config).into_bytes(),
            mode: 0o755,
        };
        if !rootfs.add_file(CONFIG_AND_RUN_TAR_PATH, file) {
            eprintln!(
                "warning: {CONFIG_AND_RUN_TAR_PATH} already exists or a parent does not resolve to a directory, skipping generation"
            );
        }
    }

    finalize_tar(&rootfs.nodes, args)?;

    Ok(())
}

/// Rewrite every executable regular file in `rootfs` once, however many names
/// it has, unless a `no_rewrite` path resolves to it within the rootfs.
fn rewrite_executables(
    rootfs: &mut oci::Rootfs,
    no_rewrite: &[PathBuf],
    verbose: bool,
    rewrite_options: litebox_syscall_rewriter::RewriteOptions,
    target_arch: CliTargetArch,
) {
    let mut kept: HashSet<*const FileObject> = HashSet::new();
    for path in no_rewrite {
        let path = path.to_string_lossy();
        match rootfs
            .resolve(&path)
            .and_then(|resolved| rootfs.nodes.get(&resolved))
        {
            Some(RootfsNode::File(file)) => {
                kept.insert(Arc::as_ptr(file));
            }
            _ => eprintln!(
                "warning: --no-rewrite path '{path}' does not name a regular file in the image"
            ),
        }
    }

    // Executables by identity, each with its first name, and whether to rewrite it.
    let mut executables: Vec<(&str, Arc<FileObject>, bool)> = Vec::new();
    let mut executable_indices: HashMap<*const FileObject, usize> = HashMap::new();
    for (path, node) in &rootfs.nodes {
        if let RootfsNode::File(file) = node
            && file.mode & 0o111 != 0
        {
            executable_indices
                .entry(Arc::as_ptr(file))
                .or_insert_with(|| {
                    let rewrite = !kept.contains(&Arc::as_ptr(file));
                    executables.push((path, file.clone(), rewrite));
                    executables.len() - 1
                });
        }
    }

    let file_path_count = rootfs
        .nodes
        .values()
        .filter(|node| matches!(node, RootfsNode::File(_)))
        .count();
    let rewrite_count = executables
        .iter()
        .filter(|(_, _, rewrite)| *rewrite)
        .count();
    eprintln!(
        "Found {file_path_count} regular file paths ({rewrite_count} unique executables to rewrite)"
    );

    eprintln!("Rewriting {rewrite_count} executable ELF files...");
    // The replacement for each executable whose data changed.
    let rewritten: Vec<Option<Arc<FileObject>>> = executables
        .into_par_iter()
        .map(|(path, file, rewrite)| {
            if !rewrite {
                if verbose {
                    eprintln!("  /{path} (skipped rewrite)");
                }
                return None;
            }
            let data = rewrite_elf(
                &file.data,
                Path::new(&format!("/{path}")),
                verbose,
                rewrite_options,
                target_arch,
            )?;
            Some(Arc::new(FileObject {
                data,
                mode: file.mode,
            }))
        })
        .collect();

    for node in rootfs.nodes.values_mut() {
        if let RootfsNode::File(file) = node
            && let Some(&index) = executable_indices.get(&Arc::as_ptr(file))
            && let Some(rewritten) = &rewritten[index]
        {
            *file = rewritten.clone();
        }
    }
}

// ---------------------------------------------------------------------------
// Shared finalization: tar build, size report
// ---------------------------------------------------------------------------

/// Build the output tar and print a size summary.
fn finalize_tar(nodes: &BTreeMap<String, RootfsNode>, args: &CliArgs) -> anyhow::Result<()> {
    // Build tar.
    eprintln!("Creating {}...", args.output.display());
    let file = std::fs::File::create(&args.output)
        .with_context(|| format!("failed to create output file {}", args.output.display()))?;
    build_tar(nodes, std::io::BufWriter::new(file))?;

    let tar_size = std::fs::metadata(&args.output).map_or(0, |m| m.len());
    #[allow(clippy::cast_precision_loss)]
    let tar_size_mb = tar_size as f64 / 1_048_576.0;
    eprintln!(
        "Created {} ({} entries, {:.1} MB)",
        args.output.display(),
        nodes.len(),
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

/// Reject cross-architecture dependency discovery in host mode.
fn validate_host_target_arch(target_arch: CliTargetArch) -> anyhow::Result<()> {
    let build_arch = CliTargetArch::default();
    if target_arch != build_arch {
        bail!(
            "host mode cannot target {} from {} build; use --oci-image for cross-architecture packaging",
            target_arch.name(),
            build_arch.name()
        );
    }
    Ok(())
}

/// Rewrite an ELF file's syscall instructions using the litebox syscall rewriter,
/// returning `None` if the file is to be included unchanged.
///
/// Non-ELF files (shell scripts, data files with executable bits, etc.) are
/// detected via a magic-byte check and not sent through the rewriter. For
/// actual ELF files, benign rewriter errors (already hooked, no syscalls,
/// unsupported object, missing `.text`) are treated as warnings. ELF files for
/// other target architectures are included unchanged.
fn rewrite_elf(
    data: &[u8],
    path: &Path,
    verbose: bool,
    options: litebox_syscall_rewriter::RewriteOptions,
    target_arch: CliTargetArch,
) -> Option<Vec<u8>> {
    // Fast-path: skip the rewriter entirely for non-ELF files.
    if data.len() < 4 || data[..4] != ELF_MAGIC {
        if verbose {
            eprintln!("  {} (not ELF, skipping rewrite)", path.display());
        }
        return None;
    }

    // Skip ELF files whose architecture doesn't match the target. OCI images
    // may contain cross-architecture binaries (e.g., aarch64 in an x86_64
    // image), which are not part of the selected guest architecture.
    if elf_machine(data).is_some_and(|machine| machine != target_arch.elf_machine()) {
        if verbose {
            eprintln!(
                "  {} (wrong ELF architecture, skipping rewrite)",
                path.display()
            );
        }
        return None;
    }

    match litebox_syscall_rewriter::hook_syscalls_in_elf_with_options(data, None, options) {
        Ok(rewritten) => {
            if verbose {
                eprintln!("  {} (rewritten)", path.display());
            }
            Some(rewritten)
        }
        Err(e) => {
            // Include the file as-is when rewriting fails. This can happen for
            // ELFs with unsupported architectures (e.g., aarch64 binaries in an
            // x86_64 image) or unusual ELF layouts. The runtime patcher or
            // platform syscall interception will handle these at execution time.
            eprintln!(
                "  warning: failed to rewrite {}: {e}; including as-is",
                path.display()
            );
            None
        }
    }
}

// ---------------------------------------------------------------------------
// Tar archive construction
// ---------------------------------------------------------------------------

/// A regular file; hard links are several names for one shared `FileObject`.
pub struct FileObject {
    pub data: Vec<u8>,
    /// Unix permission bits.
    pub mode: u32,
}

/// A node of a packaged filesystem.
pub enum RootfsNode {
    Dir { mode: u32 },
    File(Arc<FileObject>),
    Symlink { target: String },
}

/// Write `nodes` as a tar for the LiteBox read-only tar filesystem.
///
/// Entries are sorted by path, so parents precede their children and a file's
/// first name precedes the hard links to it. Names and link targets too long
/// for the ustar header get raw GNU `L`/`K` records through `append_literal`.
fn build_tar(nodes: &BTreeMap<String, RootfsNode>, output: impl Write) -> anyhow::Result<()> {
    let mut builder = Builder::new(output);
    let mut first_names: HashMap<*const FileObject, &str> = HashMap::new();

    for (path, node) in nodes {
        let mut header = Header::new_ustar();
        // The default guest user owns everything.
        header.set_uid(1000);
        header.set_gid(1000);
        header.set_size(0);
        let result = match node {
            RootfsNode::Dir { mode } => {
                header.set_entry_type(tar::EntryType::Directory);
                header.set_mode(mode & 0o777);
                append_literal(&mut builder, &mut header, path, None, &[])
            }
            RootfsNode::Symlink { target } => {
                header.set_entry_type(tar::EntryType::Symlink);
                header.set_mode(0o777);
                append_literal(&mut builder, &mut header, path, Some(target), &[])
            }
            RootfsNode::File(file) => {
                header.set_mode(file.mode & 0o777);
                if let Some(first_name) = first_names.get(&Arc::as_ptr(file)) {
                    header.set_entry_type(tar::EntryType::Link);
                    append_literal(&mut builder, &mut header, path, Some(first_name), &[])
                } else {
                    first_names.insert(Arc::as_ptr(file), path);
                    header.set_entry_type(tar::EntryType::Regular);
                    header.set_size(file.data.len() as u64);
                    append_literal(&mut builder, &mut header, path, None, &file.data)
                }
            }
        };
        result.with_context(|| format!("failed to add {path} to tar"))?;
    }

    builder
        .into_inner()
        .context("failed to finalize tar archive")?
        .flush()
        .context("failed to write tar archive")?;
    Ok(())
}

/// Append the ustar `header` named `path`, with the link target `link` and the content `data`,
/// writing both strings byte for byte.
///
/// The `tar` crate's name and link setters parse them as host `Path`s, normalizing them (`foo/.`
/// becomes `foo`) and, on Windows, turning `\` into `/`; links would then no longer name their
/// archived targets.
fn append_literal(
    builder: &mut Builder<impl Write>,
    header: &mut Header,
    path: &str,
    link: Option<&str>,
    data: &[u8],
) -> std::io::Result<()> {
    // Both checks are what the `tar` crate's setters enforced; host mode's `--include` names are
    // user input.
    if path.split('/').any(|component| component == "..")
        || path.contains('\0')
        || link.is_some_and(|link| link.contains('\0'))
    {
        return Err(std::io::Error::other(
            "invalid tar name or link target: a `..` component or a NUL byte",
        ));
    }
    // libarchive misreads an entry whose own field is empty even when a GNU long record holds the
    // full string, so the field gets a truncated copy.
    if let Some(link) = link {
        let field = &mut header.as_old_mut().linkname;
        if link.len() > field.len() {
            append_gnu_long_record(builder, tar::EntryType::GNULongLink, link)?;
        }
        let len = link.len().min(field.len());
        field[..len].copy_from_slice(&link.as_bytes()[..len]);
    }
    let ustar = header.as_ustar_mut().expect("a ustar header");
    let (name_len, prefix_len) = (ustar.name.len(), ustar.prefix.len());
    // As in the `tar` crate, a longer path is split at a `/` into the prefix and name fields.
    let split = if path.len() <= name_len {
        Some(("", path))
    } else {
        path.as_bytes()[..path.len().min(prefix_len + 1)]
            .iter()
            .rposition(|&byte| byte == b'/')
            .map(|slash| (&path[..slash], &path[slash + 1..]))
            .filter(|(prefix, name)| !prefix.is_empty() && name.len() <= name_len)
    };
    if let Some((prefix, name)) = split {
        ustar.prefix[..prefix.len()].copy_from_slice(prefix.as_bytes());
        ustar.name[..name.len()].copy_from_slice(name.as_bytes());
    } else {
        append_gnu_long_record(builder, tar::EntryType::GNULongName, path)?;
        ustar.name.copy_from_slice(&path.as_bytes()[..name_len]);
    }
    header.set_cksum();
    builder.append(header, data)
}

/// Append a GNU `L` or `K` record holding `value`, laid out as the `tar` crate writes them.
fn append_gnu_long_record(
    builder: &mut Builder<impl Write>,
    entry_type: tar::EntryType,
    value: &str,
) -> std::io::Result<()> {
    let mut header = Header::new_gnu();
    let name = b"././@LongLink";
    header.as_old_mut().name[..name.len()].copy_from_slice(name);
    header.set_mode(0o644);
    header.set_uid(0);
    header.set_gid(0);
    header.set_mtime(0);
    // GNU tar NUL-terminates the value.
    header.set_size(value.len() as u64 + 1);
    header.set_entry_type(entry_type);
    header.set_cksum();
    builder.append(&header, [value.as_bytes(), b"\0"].concat().as_slice())
}

#[cfg(test)]
mod tests {
    use super::*;

    const AARCH64_ELF: &[u8] = include_bytes!("../../litebox_syscall_rewriter/tests/hello-aarch64");

    fn parse_mode(oci: bool, extra: &[&str]) -> CliArgs {
        let mut args = vec![
            "litebox-packager",
            "--target-arch",
            "aarch64",
            "--target-host",
            "linux",
        ];
        if oci {
            args.extend(["--oci-image", "example.invalid/fixture:latest"]);
        } else {
            args.push("/nonexistent/fixture");
        }
        args.extend_from_slice(extra);
        CliArgs::try_parse_from(args).unwrap()
    }

    fn file_object(data: &[u8], mode: u32) -> Arc<FileObject> {
        Arc::new(FileObject {
            data: data.to_vec(),
            mode,
        })
    }

    fn finalize_patch_count(binary: &mut [u8]) -> usize {
        let header = &binary[binary.len() - 32..];
        let start = usize::try_from(u64::from_le_bytes(header[8..16].try_into().unwrap())).unwrap();
        let size = usize::try_from(u64::from_le_bytes(header[24..32].try_into().unwrap())).unwrap();
        litebox_trampoline::aarch64::finalize_trampoline_gates(&mut binary[start..start + size], 96)
            .unwrap()
    }

    #[test]
    fn native_tpidr_el0_is_forwarded_in_host_and_oci_modes() {
        for oci in [false, true] {
            let default_args = parse_mode(oci, &[]);
            let native_args = parse_mode(oci, &["--native-tpidr-el0"]);
            let defaults = default_args.rewrite_options().unwrap();
            let native = native_args.rewrite_options().unwrap();
            assert!(!defaults.uses_native_tpidr_el0());
            assert!(native.uses_native_tpidr_el0());
            assert_eq!(native.target_host(), litebox_trampoline::TargetHost::Linux);
            assert!(!native.virtualizes_x18());
            let rewrite = |options| {
                rewrite_elf(
                    AARCH64_ELF,
                    Path::new("fixture"),
                    false,
                    options,
                    native_args.target_arch,
                )
                .unwrap()
            };
            let mut virtualized = rewrite(defaults);
            let mut native_binary = rewrite(native);
            assert!(finalize_patch_count(&mut virtualized) > 0);
            assert_eq!(finalize_patch_count(&mut native_binary), 0);
            assert_ne!(
                native_binary, AARCH64_ELF,
                "SVC sites must still be rewritten"
            );
        }
    }

    #[test]
    fn rewrite_executables_rewrites_each_file_once() {
        let elf = |mode| file_object(AARCH64_ELF, mode);
        let mut x86_64_elf = AARCH64_ELF.to_vec();
        x86_64_elf[18..20].copy_from_slice(&EM_X86_64.to_le_bytes());
        let (shared, kept, kept_by_alias) = (elf(0o755), elf(0o755), elf(0o755));
        let unchanged = [
            ("bin/d", elf(0o644)),
            ("bin/script", file_object(b"#!/bin/sh\n", 0o755)),
            ("bin/x86_64", file_object(&x86_64_elf, 0o755)),
        ];
        let mut rootfs = oci::Rootfs {
            nodes: [
                ("bin", RootfsNode::Dir { mode: 0o755 }),
                ("bin/a", RootfsNode::File(shared.clone())),
                ("bin/b", RootfsNode::File(shared)),
                ("bin/c", RootfsNode::File(kept)),
                ("bin/e", RootfsNode::File(kept_by_alias.clone())),
                ("bin/f", RootfsNode::File(kept_by_alias)),
                ("bin/link", RootfsNode::Symlink { target: "f".into() }),
                (
                    "sbin",
                    RootfsNode::Symlink {
                        target: "/bin".into(),
                    },
                ),
            ]
            .into_iter()
            .chain(
                unchanged
                    .iter()
                    .map(|(path, file)| (*path, RootfsNode::File(file.clone()))),
            )
            .map(|(path, node)| (path.to_owned(), node))
            .collect(),
        };
        let no_rewrite = ["/sbin/c", "/sbin/../bin/link"].map(PathBuf::from);
        rewrite_executables(
            &mut rootfs,
            &no_rewrite,
            false,
            parse_mode(true, &[]).rewrite_options().unwrap(),
            CliTargetArch::Aarch64,
        );
        let file = |path: &str| match &rootfs.nodes[path] {
            RootfsNode::File(file) => file.clone(),
            _ => unreachable!(),
        };
        assert!(Arc::ptr_eq(&file("bin/a"), &file("bin/b")));
        assert_ne!(file("bin/a").data, AARCH64_ELF);
        assert_eq!(file("bin/a").mode, 0o755);
        for path in ["bin/c", "bin/e"] {
            assert_eq!(file(path).data, AARCH64_ELF, "{path}");
        }
        assert!(Arc::ptr_eq(&file("bin/e"), &file("bin/f")));
        for (path, original) in &unchanged {
            assert!(Arc::ptr_eq(&file(path), original), "{path}");
        }
    }

    #[test]
    fn build_tar_output_round_trips_through_tar_core() {
        use std::fmt::Write as _;
        use tar_core::parse::{Limits, ParseEvent, Parser};

        let long_dir = "d".repeat(150);
        let long_path = format!("{long_dir}/{}", "f".repeat(150));
        // Fits the ustar prefix and name fields.
        let split_path = format!("{long_dir}/{}", "s".repeat(90));
        let long_target = format!("/{long_path}");
        // Long paths with long targets, archived before short-target links: libarchive loses
        // these links and corrupts later ones unless the main header carries a linkname.
        let long_hard_link = format!("{long_dir}/{}", "h".repeat(150));
        let long_symlink = format!("{long_dir}/{}", "l".repeat(150));
        // Targets that host `Path` parsing would rewrite.
        let literal_targets = [
            "/".to_string(),
            "foo/.".into(),
            "a//b".into(),
            format!("{}\\x/./y", "b".repeat(100)),
        ];
        let (shared, long_file) = (file_object(b"shared", 0o4755), file_object(b"long", 0o644));
        // A name that Windows `Path` parsing would rewrite, with aliases at each name length:
        // links to it must keep naming it.
        let backslash_file = file_object(b"backslash", 0o644);
        let backslash_split = format!("{long_dir}/x\\y");
        let backslash_long = format!("{long_dir}/{}\\t", "t".repeat(150));
        let nodes: BTreeMap<String, RootfsNode> = [
            ("a\\b".into(), RootfsNode::File(backslash_file.clone())),
            ("a\\c".into(), RootfsNode::File(backslash_file.clone())),
            (
                "a\\s".into(),
                RootfsNode::Symlink {
                    target: "a\\b".into(),
                },
            ),
            (
                backslash_split.clone(),
                RootfsNode::File(backslash_file.clone()),
            ),
            (
                backslash_long.clone(),
                RootfsNode::Symlink {
                    target: "../a\\b".into(),
                },
            ),
            ("usr/bin/b".into(), RootfsNode::File(shared.clone())),
            ("usr/bin/a".into(), RootfsNode::File(shared)),
            ("usr".into(), RootfsNode::Dir { mode: 0o1777 }),
            ("usr/bin".into(), RootfsNode::Dir { mode: 0o755 }),
            (long_dir.clone(), RootfsNode::Dir { mode: 0o700 }),
            (long_path.clone(), RootfsNode::File(long_file.clone())),
            (long_hard_link.clone(), RootfsNode::File(long_file.clone())),
            (
                long_symlink.clone(),
                RootfsNode::Symlink {
                    target: long_target.clone(),
                },
            ),
            (split_path.clone(), RootfsNode::Dir { mode: 0o755 }),
            ("z".into(), RootfsNode::File(long_file)),
            (
                "link".into(),
                RootfsNode::Symlink {
                    target: long_target.clone(),
                },
            ),
        ]
        .into_iter()
        .chain(literal_targets.iter().enumerate().map(|(index, target)| {
            (
                format!("literal{index}"),
                RootfsNode::Symlink {
                    target: target.clone(),
                },
            )
        }))
        .collect();
        let mut archive = Vec::new();
        build_tar(&nodes, &mut archive).unwrap();

        let mut parsed = Vec::new();
        let mut parser = Parser::new(Limits::default());
        let mut offset = 0;
        loop {
            match parser.parse(&archive[offset..]).unwrap() {
                ParseEvent::Entry { consumed, entry } => {
                    let start = offset + consumed;
                    let size = usize::try_from(entry.size).unwrap();
                    assert_eq!((entry.uid, entry.gid), (1000, 1000));
                    // The header holds the name itself, or a truncated copy of a GNU long name.
                    let name = entry.header.as_old().name.split(|&byte| byte == 0).next();
                    let name = name.unwrap();
                    match entry.header.prefix().filter(|prefix| !prefix.is_empty()) {
                        Some(prefix) => assert_eq!(*entry.path, [prefix, b"/", name].concat()),
                        None => assert_eq!(name, &entry.path[..entry.path.len().min(name.len())]),
                    }
                    if *entry.path == *split_path.as_bytes() {
                        assert_eq!(entry.header.prefix(), Some(long_dir.as_bytes()));
                    }
                    if let Some(target) = &entry.link_target {
                        let len = target.len().min(entry.header.as_old().linkname.len());
                        assert_eq!(entry.header.link_name_bytes(), &target[..len]);
                    }
                    let mut description = format!(
                        "{:?} {} {:o}",
                        entry.entry_type,
                        String::from_utf8(entry.path.to_vec()).unwrap(),
                        entry.mode
                    );
                    if let Some(target) = entry.link_target_lossy() {
                        write!(description, " -> {target}").unwrap();
                    }
                    if size > 0 {
                        let data = String::from_utf8_lossy(&archive[start..start + size]);
                        write!(description, " = {data}").unwrap();
                    }
                    parsed.push(description);
                    offset = start + usize::try_from(entry.padded_size()).unwrap();
                }
                ParseEvent::End { .. } => break,
                event => panic!("unexpected {event:?}"),
            }
        }
        let mut expected = vec![
            "Regular a\\b 644 = backslash".into(),
            "Link a\\c 644 -> a\\b".into(),
            "Symlink a\\s 777 -> a\\b".into(),
            format!("Directory {long_dir} 700"),
            format!("Regular {long_path} 644 = long"),
            format!("Link {long_hard_link} 644 -> {long_path}"),
            format!("Symlink {long_symlink} 777 -> {long_target}"),
            format!("Directory {split_path} 755"),
            format!("Symlink {backslash_long} 777 -> ../a\\b"),
            format!("Link {backslash_split} 644 -> a\\b"),
            format!("Symlink link 777 -> {long_target}"),
        ];
        for (index, target) in literal_targets.iter().enumerate() {
            expected.push(format!("Symlink literal{index} 777 -> {target}"));
        }
        expected.extend([
            "Directory usr 777".into(),
            "Directory usr/bin 755".into(),
            "Regular usr/bin/a 755 = shared".into(),
            "Link usr/bin/b 755 -> usr/bin/a".into(),
            format!("Link z 644 -> {long_path}"),
        ]);
        assert_eq!(parsed, expected);
    }

    #[test]
    fn native_tpidr_el0_conflicts_with_virtualize_x18() {
        let error = CliArgs::try_parse_from([
            "litebox-packager",
            "fixture",
            "--native-tpidr-el0",
            "--virtualize-x18",
        ])
        .unwrap_err();
        assert_eq!(error.kind(), clap::error::ErrorKind::ArgumentConflict);
    }

    #[test]
    fn native_tpidr_el0_invalid_configuration_fails_before_io_in_both_modes() {
        for oci in [false, true] {
            for (host, arch, x18) in [
                (CliTargetHost::Macos, CliTargetArch::Aarch64, false),
                (CliTargetHost::Windows, CliTargetArch::Aarch64, false),
                (CliTargetHost::Linux, CliTargetArch::X86_64, false),
                // Also validate programmatic callers that bypass clap.
                (CliTargetHost::Linux, CliTargetArch::Aarch64, true),
            ] {
                let mut args = parse_mode(oci, &["--native-tpidr-el0"]);
                args.target_host = host;
                args.target_arch = arch;
                args.virtualize_x18 = x18;
                let error = run(args).unwrap_err().to_string();
                assert!(error.contains("--native-tpidr-el0 requires"), "{error}");
                assert!(error.contains("without --virtualize-x18"), "{error}");
            }
        }
    }

    #[test]
    fn native_tpidr_el0_uses_normal_flag_and_value_parsing() {
        for args in [
            vec!["litebox-packager", "fixture", "--native-tpidr-el0=true"],
            vec!["litebox-packager", "fixture", "--target-arch", "unknown"],
            vec!["litebox-packager", "fixture", "--target-host", "unknown"],
            vec!["litebox-packager", "--native-tpidr-el0"],
        ] {
            assert!(CliArgs::try_parse_from(args).is_err());
        }
    }
}
