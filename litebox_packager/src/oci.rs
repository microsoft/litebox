// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! OCI image pulling and rootfs extraction.
//!
//! Pulls an OCI container image from a registry (e.g., Docker Hub, GHCR),
//! extracts its filesystem layers into a temporary rootfs directory, then
//! walks the rootfs to discover all ELF files for syscall rewriting.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::Read;
use std::path::{Path, PathBuf};

use anyhow::Context;
use oci_client::client::{ClientConfig, ClientProtocol, ImageData};
use oci_client::config::ConfigFile;
use oci_client::secrets::RegistryAuth;
use oci_client::{Client, Reference};

/// Parsed OCI image execution configuration (ENTRYPOINT, CMD, ENV, WORKDIR).
#[derive(Debug, Default)]
pub struct ImageConfig {
    pub entrypoint: Option<Vec<String>>,
    pub cmd: Option<Vec<String>>,
    pub env: Option<Vec<String>>,
    pub working_dir: Option<String>,
}

/// Result of pulling and extracting an OCI image.
pub struct ExtractedImage {
    /// Temporary directory holding the extracted rootfs.
    /// Cleaned up when this struct is dropped.
    pub tempdir: tempfile::TempDir,
    /// Path to the rootfs inside the temp directory.
    pub rootfs_path: PathBuf,
    /// Parsed image config (ENTRYPOINT, CMD, ENV, WORKDIR).
    pub config: ImageConfig,
    /// Raw OCI image config JSON blob (the full config descriptor data).
    pub config_json: Vec<u8>,
    /// Symlinks collected during layer extraction (used for cross-platform
    /// resolution since OS symlinks may not work on all platforms).
    pub symlinks: Vec<DeferredSymlink>,
}

/// Result of scanning an extracted rootfs for files to package.
pub struct RootfsFileMap {
    /// Map from host path (inside the extracted rootfs) to the tar path
    /// (the path the file should appear at inside the output tar).
    /// Files with executable permission bits are candidates for rewriting.
    pub files: BTreeMap<PathBuf, RootfsEntry>,
}

/// A single file discovered in the rootfs.
pub struct RootfsEntry {
    /// Path inside the tar archive (relative, no leading `/`).
    pub tar_path: String,
    /// Host path to read the file data from.
    /// For regular files this equals the map key; for symlinks this is the
    /// resolved target path (which may differ from the map key).
    pub read_path: PathBuf,
    /// Whether the file has executable permission bits set.
    pub is_executable: bool,
    /// Unix permission mode (lower 12 bits).
    pub mode: u32,
}

/// Pull an OCI image from a registry and extract its layers into a temp directory.
///
/// Supports standard image references like:
/// - `docker.io/library/alpine:latest`
/// - `alpine:latest` (defaults to docker.io/library/)
/// - `ghcr.io/org/repo:tag`
///
/// Layers are applied in order (bottom-up), handling whiteout files for
/// layer deletions per the OCI image spec.
///
/// # Authentication
///
/// Currently only anonymous (unauthenticated) pulls are supported. Private
/// registries or images that require credentials will fail with an
/// authorization error from the registry.
pub fn pull_and_extract(image_ref: &str, verbose: bool) -> anyhow::Result<ExtractedImage> {
    // Parse the image reference
    let reference: Reference = image_ref
        .parse()
        .with_context(|| format!("invalid OCI image reference: {image_ref}"))?;

    if verbose {
        eprintln!("Pulling image: {reference}");
    }

    // Create async runtime for the OCI client (which is async-based)
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("failed to create tokio runtime")?;

    let image_data = rt.block_on(async {
        let config = ClientConfig {
            protocol: ClientProtocol::Https,
            // Always pull linux/amd64 images regardless of host platform.
            platform_resolver: Some(Box::new(|entries| {
                entries
                    .iter()
                    .find(|entry| {
                        entry.platform.as_ref().is_some_and(|p| {
                            p.os == "linux".into() && p.architecture == "amd64".into()
                        })
                    })
                    .map(|e| e.digest.clone())
            })),
            ..Default::default()
        };
        let client = Client::new(config);

        // Authenticate (anonymous for public images)
        let auth = RegistryAuth::Anonymous;

        if verbose {
            eprintln!("  Fetching manifest...");
        }

        // Pull the full image (manifest + all layers)
        let image_data: ImageData = client
            .pull(
                &reference,
                &auth,
                vec![
                    oci_client::manifest::IMAGE_LAYER_GZIP_MEDIA_TYPE,
                    oci_client::manifest::IMAGE_LAYER_MEDIA_TYPE,
                    oci_client::manifest::IMAGE_DOCKER_LAYER_GZIP_MEDIA_TYPE,
                ],
            )
            .await
            .with_context(|| format!("failed to pull image {reference}"))?;

        if verbose {
            eprintln!("  Pulled {} layer(s)", image_data.layers.len());
        }

        Ok::<_, anyhow::Error>(image_data)
    })?;

    // Create temp directory for extraction
    let tempdir = tempfile::tempdir().context("failed to create temporary directory for rootfs")?;
    let rootfs_path = tempdir.path().join("rootfs");
    std::fs::create_dir_all(&rootfs_path).context("failed to create rootfs directory")?;

    // Extract layers in order (bottom layer first)
    let mut symlinks: Vec<DeferredSymlink> = Vec::new();
    for (i, layer) in image_data.layers.iter().enumerate() {
        if verbose {
            eprintln!(
                "  Extracting layer {}/{} ({} bytes)...",
                i + 1,
                image_data.layers.len(),
                layer.data.len()
            );
        }
        extract_layer(&layer.data, &layer.media_type, &rootfs_path, &mut symlinks)
            .with_context(|| format!("failed to extract layer {}", i + 1))?;
    }

    // Materialize symlinks cross-platform: resolve chains through the in-memory
    // map and copy target files (or create directories) instead of OS symlinks.
    if verbose {
        eprintln!("  Resolving {} symlinks...", symlinks.len());
    }
    materialize_symlinks(&symlinks, &rootfs_path, verbose)?;

    if verbose {
        eprintln!("  Rootfs extracted to {}", rootfs_path.display());
    }

    // Save the raw config JSON before parsing (try_from consumes it).
    let config_json = image_data.config.data.to_vec();

    // Parse image config for ENTRYPOINT, CMD, ENV, WORKDIR.
    let config = match ConfigFile::try_from(image_data.config) {
        Ok(cf) => {
            let exec_config = cf.config.as_ref();
            let ic = ImageConfig {
                entrypoint: exec_config.and_then(|c| c.entrypoint.clone()),
                cmd: exec_config.and_then(|c| c.cmd.clone()),
                env: exec_config.and_then(|c| c.env.clone()),
                working_dir: exec_config.and_then(|c| c.working_dir.clone()),
            };
            if verbose {
                eprintln!(
                    "  Image config: ENTRYPOINT={:?} CMD={:?} WORKDIR={:?} ENV=({} vars)",
                    ic.entrypoint,
                    ic.cmd,
                    ic.working_dir,
                    ic.env.as_ref().map_or(0, Vec::len)
                );
            }
            ic
        }
        Err(e) => {
            eprintln!(
                "warning: failed to parse image config: {e}; config_and_run.sh will not be generated"
            );
            ImageConfig::default()
        }
    };

    Ok(ExtractedImage {
        tempdir,
        rootfs_path,
        config,
        config_json,
        symlinks,
    })
}

/// Generate a `litebox/config_and_run.sh` shell script from the OCI image config.
///
/// The script:
/// 1. Exports all `ENV` variables from the image config
/// 2. `cd`s to `WORKDIR` (defaults to `/`)
/// 3. If the caller passes arguments (`"$@"`), executes them directly
/// 4. Otherwise falls back to the image's ENTRYPOINT/CMD as the default command
///
/// This allows the runner to either pass a command explicitly:
///   `/litebox/config_and_run.sh python3 -c 'print("hi")'`
/// or rely on the image default:
///   `/litebox/config_and_run.sh`
///
/// Always generates a script — even if the image has no ENV, WORKDIR,
/// ENTRYPOINT, or CMD, the script will simply `exec "$@"` so callers can
/// use `config_and_run.sh` uniformly without checking whether it exists.
pub fn generate_config_and_run_script(config: &ImageConfig) -> String {
    use std::fmt::Write as _;

    let has_entrypoint = config.entrypoint.as_ref().is_some_and(|v| !v.is_empty());
    let has_cmd = config.cmd.as_ref().is_some_and(|v| !v.is_empty());

    let mut script = String::from("#!/bin/sh\n");

    // Export ENV vars.
    if let Some(env_vars) = &config.env {
        for var in env_vars {
            // Each var is "KEY=VALUE". Shell-quote the value.
            if let Some(eq_idx) = var.find('=') {
                let key = &var[..eq_idx];
                let value = &var[eq_idx + 1..];
                let _ = writeln!(script, "export {key}='{}'", shell_escape(value));
            }
        }
    }

    // cd to WORKDIR.
    let workdir = config
        .working_dir
        .as_deref()
        .filter(|w| !w.is_empty())
        .unwrap_or("/");
    let _ = writeln!(script, "cd '{}'", shell_escape(workdir));

    // Build the exec line.
    //
    // If the caller passes arguments, run those as the command.
    // Otherwise fall back to the image's ENTRYPOINT + CMD.
    let quote = |args: &[String]| -> String {
        args.iter()
            .map(|a| format!("'{}'", shell_escape(a)))
            .collect::<Vec<_>>()
            .join(" ")
    };

    // Build the default command from ENTRYPOINT and/or CMD.
    let default_cmd = if has_entrypoint && has_cmd {
        let ep = config.entrypoint.as_deref().unwrap_or_default();
        let cmd = config.cmd.as_deref().unwrap_or_default();
        format!("{} {}", quote(ep), quote(cmd))
    } else if has_entrypoint {
        quote(config.entrypoint.as_deref().unwrap_or_default())
    } else if has_cmd {
        quote(config.cmd.as_deref().unwrap_or_default())
    } else {
        String::new()
    };

    if default_cmd.is_empty() {
        // No default command — just exec whatever the caller passes.
        let _ = writeln!(script, "exec \"$@\"");
    } else {
        let _ = write!(
            script,
            "if [ $# -gt 0 ]; then\n  exec \"$@\"\nelse\n  exec {default_cmd}\nfi\n",
        );
    }

    script
}

/// Escape single quotes for use inside single-quoted shell strings.
fn shell_escape(s: &str) -> String {
    s.replace('\'', "'\\''")
}

/// Extract a single OCI layer (tar or tar+gzip) into the rootfs directory.
///
/// Handles OCI whiteout files (`.wh.*` prefixed entries) which indicate
/// files deleted in upper layers. Symlinks are collected into `symlinks` for
/// cross-platform resolution after all layers are extracted.
fn extract_layer(
    data: &[u8],
    media_type: &str,
    rootfs: &Path,
    symlinks: &mut Vec<DeferredSymlink>,
) -> anyhow::Result<()> {
    // Determine if the layer is gzipped
    let is_gzip = media_type.contains("gzip") || is_gzip_data(data);

    if is_gzip {
        let decoder = flate2::read::GzDecoder::new(data);
        extract_tar(decoder, rootfs, symlinks)
    } else {
        extract_tar(data, rootfs, symlinks)
    }
}

/// Check if data starts with the gzip magic bytes.
fn is_gzip_data(data: &[u8]) -> bool {
    data.len() >= 2 && data[0] == 0x1f && data[1] == 0x8b
}

/// A hard link whose target was not yet extracted when encountered.
struct DeferredHardLink {
    /// Destination path inside the rootfs (where the hard link should be created).
    target: PathBuf,
    /// Source path inside the rootfs (the file the hard link points to).
    link_source: PathBuf,
}

/// Tracked symlink from a container image layer.
pub struct DeferredSymlink {
    /// Relative path inside the rootfs (e.g., `usr/lib64/ld-linux-x86-64.so.2`).
    rel_path: PathBuf,
    /// Symlink target as stored in the tar (Unix-style, may be relative or absolute).
    link_target: PathBuf,
}

/// Extract a tar archive into the rootfs, handling OCI whiteout files.
///
/// Symlinks are NOT created as OS symlinks. Instead they are tracked in
/// `symlinks` so the caller can resolve them cross-platform after all layers
/// are extracted. Hard links whose targets appear later in the archive are
/// collected during the first pass and resolved after all regular entries
/// have been extracted.
fn extract_tar<R: Read>(
    reader: R,
    rootfs: &Path,
    symlinks: &mut Vec<DeferredSymlink>,
) -> anyhow::Result<()> {
    let mut archive = tar::Archive::new(reader);
    archive.set_preserve_permissions(true);
    archive.set_unpack_xattrs(true);

    let mut deferred_links: Vec<DeferredHardLink> = Vec::new();

    for entry_result in archive.entries()? {
        let mut entry = entry_result.context("failed to read tar entry")?;
        let path = entry.path()?.into_owned();
        let path_str = path.to_string_lossy();

        // Handle OCI whiteout files
        if let Some(file_name) = path.file_name().and_then(|n| n.to_str()) {
            if file_name == ".wh..wh..opq" {
                // Opaque whiteout: clear the entire parent directory contents
                if let Some(parent) = path.parent() {
                    let target = rootfs.join(parent);
                    if target.exists() {
                        // Remove all children but keep the directory itself
                        for child in std::fs::read_dir(&target)? {
                            let child = child?;
                            let ft = child.file_type()?;
                            if ft.is_dir() {
                                std::fs::remove_dir_all(child.path())?;
                            } else {
                                std::fs::remove_file(child.path())?;
                            }
                        }
                    }
                }
                continue;
            }
            if let Some(target_name) = file_name.strip_prefix(".wh.") {
                // Regular whiteout: delete the specific file/directory
                if let Some(parent) = path.parent() {
                    let target = rootfs.join(parent).join(target_name);
                    if target.is_dir() {
                        let _ = std::fs::remove_dir_all(&target);
                    } else {
                        let _ = std::fs::remove_file(&target);
                    }
                }
                continue;
            }
        }

        let target = rootfs.join(&path);

        // Ensure parent directory exists
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let entry_type = entry.header().entry_type();

        // Handle hard links: copy the link target instead of creating an OS
        // hard link. The tar crate's unpack() tries std::fs::hard_link which
        // can fail if the target hasn't been extracted yet (ordering issue),
        // and the litebox filesystem doesn't support hard links anyway.
        if entry_type == tar::EntryType::Link {
            let link_name = entry
                .link_name()?
                .context("hard link entry has no link name")?
                .into_owned();
            let link_source = rootfs.join(&link_name);
            if link_source.exists() {
                std::fs::copy(&link_source, &target).with_context(|| {
                    format!(
                        "failed to copy hard link target {} -> {}",
                        link_source.display(),
                        target.display()
                    )
                })?;
            } else {
                // Target hasn't been extracted yet — defer to second pass.
                deferred_links.push(DeferredHardLink {
                    target,
                    link_source,
                });
            }
            continue;
        }

        // Track symlinks in memory instead of creating OS symlinks.
        // OS symlinks on Windows require special privileges and don't handle
        // Unix-style relative paths reliably, so we resolve them ourselves
        // after all layers are extracted.
        if entry_type == tar::EntryType::Symlink {
            let link_target = entry
                .link_name()?
                .context("symlink entry has no link name")?
                .into_owned();
            // A later layer may override this symlink, so remove any stale
            // entry with the same rel_path.
            symlinks.retain(|s| s.rel_path != path);
            symlinks.push(DeferredSymlink {
                rel_path: path.clone(),
                link_target,
            });
            continue;
        }

        // Normal file/directory: use the standard unpack
        entry
            .unpack(&target)
            .with_context(|| format!("failed to unpack entry: {path_str}"))?;
    }

    // Second pass: resolve deferred hard links now that all entries are extracted.
    for link in &deferred_links {
        if link.link_source.exists() {
            if let Some(parent) = link.target.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::copy(&link.link_source, &link.target).with_context(|| {
                format!(
                    "failed to copy deferred hard link {} -> {}",
                    link.link_source.display(),
                    link.target.display()
                )
            })?;
        } else {
            // Target still doesn't exist after the full layer extraction —
            // this is unusual but not fatal; warn and skip.
            eprintln!(
                "  warning: hard link target {} not found after full extraction, skipping {}",
                link.link_source.display(),
                link.target.display()
            );
        }
    }

    Ok(())
}

/// Resolve a symlink target within the rootfs using the symlink map.
///
/// Handles both absolute targets (e.g., `/lib/x86_64-linux-gnu/ld.so`) and
/// relative targets (e.g., `../lib/x86_64-linux-gnu/ld.so`). Follows symlink
/// chains up to `max_depth` hops.
fn resolve_symlink_in_rootfs(
    rel_path: &Path,
    rootfs: &Path,
    symlink_map: &HashMap<PathBuf, PathBuf>,
    max_depth: u32,
) -> Option<PathBuf> {
    if max_depth == 0 {
        return None;
    }

    // Check if this rel_path is itself a symlink
    if let Some(link_target) = symlink_map.get(rel_path) {
        // Resolve the target to a new rel_path
        let resolved_rel = if is_unix_absolute(link_target) {
            strip_unix_root(link_target)
        } else {
            // Relative target: resolve from parent of the symlink
            let parent = rel_path.parent().unwrap_or(Path::new(""));
            normalize_path(&parent.join(link_target))
        };
        // Recurse to follow chains
        return resolve_symlink_in_rootfs(&resolved_rel, rootfs, symlink_map, max_depth - 1);
    }

    // Not a symlink — check if any ancestor is a symlink (e.g., `lib64/foo` where
    // `lib64` → `usr/lib64`).
    let components: Vec<_> = rel_path.components().collect();
    for i in 1..components.len() {
        let prefix: PathBuf = components[..i].iter().collect();
        if let Some(link_target) = symlink_map.get(&prefix) {
            let resolved_prefix = if is_unix_absolute(link_target) {
                strip_unix_root(link_target)
            } else {
                let parent = prefix.parent().unwrap_or(Path::new(""));
                normalize_path(&parent.join(link_target))
            };
            let suffix: PathBuf = components[i..].iter().collect();
            let new_rel = resolved_prefix.join(suffix);
            return resolve_symlink_in_rootfs(&new_rel, rootfs, symlink_map, max_depth - 1);
        }
    }

    let host_path = rootfs.join(rel_path);
    if host_path.exists() {
        Some(host_path)
    } else {
        None
    }
}

/// Check if a path starts with `/` (Unix-style absolute).
///
/// On Windows, `Path::is_absolute()` requires a drive letter, so Unix-style
/// paths like `/lib/foo` are not detected as absolute. This helper checks
/// the raw string instead.
fn is_unix_absolute(path: &Path) -> bool {
    path.as_os_str()
        .to_str()
        .is_some_and(|s| s.starts_with('/'))
        || path.is_absolute()
}

/// Strip the leading `/` from a Unix-style absolute path to make it
/// rootfs-relative. Returns the path unchanged if it doesn't start with `/`.
fn strip_unix_root(path: &Path) -> PathBuf {
    if let Some(stripped) = path.as_os_str().to_str().and_then(|s| s.strip_prefix('/')) {
        return PathBuf::from(stripped);
    }
    path.strip_prefix("/").unwrap_or(path).to_path_buf()
}

/// Normalize a path by resolving `.` and `..` components without touching the
/// filesystem (no symlink resolution, no existence checks). Strips any root
/// component so the result is always a relative path.
fn normalize_path(path: &Path) -> PathBuf {
    let mut result = Vec::new();
    for component in path.components() {
        match component {
            std::path::Component::ParentDir => {
                result.pop();
            }
            std::path::Component::CurDir | std::path::Component::RootDir => {}
            c @ (std::path::Component::Prefix(_) | std::path::Component::Normal(_)) => {
                result.push(c);
            }
        }
    }
    result.iter().collect()
}

/// Materialize all deferred symlinks by copying or creating directories.
///
/// This is called after all OCI layers have been extracted, so every real file
/// should be on disk. Symlinks are resolved through the in-memory map (handling
/// chains like `lib64` → `usr/lib64` → real dir) and then:
/// - File symlinks: the target file is copied to the symlink location.
/// - Directory symlinks: an empty directory is created (its contents will be
///   expanded by `scan_rootfs`'s dir-symlink logic).
fn materialize_symlinks(
    symlinks: &[DeferredSymlink],
    rootfs: &Path,
    verbose: bool,
) -> anyhow::Result<()> {
    // Build a map for O(1) lookup during resolution.
    let symlink_map: HashMap<PathBuf, PathBuf> = symlinks
        .iter()
        .map(|s| (s.rel_path.clone(), s.link_target.clone()))
        .collect();

    for sym in symlinks {
        let host_path = rootfs.join(&sym.rel_path);
        if host_path.exists() {
            // A later layer may have replaced the symlink with a real file.
            continue;
        }

        if let Some(resolved) = resolve_symlink_in_rootfs(
            &sym.rel_path,
            rootfs,
            &symlink_map,
            32, // max chain depth
        ) {
            if let Some(parent) = host_path.parent() {
                std::fs::create_dir_all(parent)?;
            }

            if resolved.is_dir() {
                // Directory symlink: create directory placeholder.
                // scan_rootfs will discover this is a "dir symlink" and expand
                // it through the symlink_map.
                std::fs::create_dir_all(&host_path)?;
                if verbose {
                    eprintln!(
                        "  [symlink→dir] {} -> {}",
                        sym.rel_path.display(),
                        sym.link_target.display()
                    );
                }
            } else if resolved.is_file() {
                std::fs::copy(&resolved, &host_path).with_context(|| {
                    format!(
                        "failed to materialize symlink {} -> {}",
                        sym.rel_path.display(),
                        resolved.display()
                    )
                })?;
                if verbose {
                    eprintln!(
                        "  [symlink→file] {} -> {}",
                        sym.rel_path.display(),
                        sym.link_target.display()
                    );
                }
            }
        } else if verbose {
            eprintln!(
                "  [symlink-broken] {} -> {} (unresolvable)",
                sym.rel_path.display(),
                sym.link_target.display()
            );
        }
    }

    Ok(())
}

/// Scan an extracted rootfs directory and build a file map for packaging.
///
/// Walks the rootfs directory tree and collects all regular files with their
/// paths and permission bits. After `materialize_symlinks` has been called,
/// file symlinks are already materialized as regular file copies on disk.
///
/// `deferred_symlinks` provides the original symlink map from extraction so
/// that **directory symlinks** (e.g., `lib64` → `usr/lib64`) can be expanded:
/// all files under the target directory are duplicated under the symlink's
/// path prefix so that paths like `lib64/ld-linux-x86-64.so.2` exist in the tar.
pub fn scan_rootfs(
    rootfs: &Path,
    deferred_symlinks: &[DeferredSymlink],
    verbose: bool,
) -> anyhow::Result<RootfsFileMap> {
    let mut files = BTreeMap::new();

    // Build the symlink map for resolution.
    let symlink_map: HashMap<PathBuf, PathBuf> = deferred_symlinks
        .iter()
        .map(|s| (s.rel_path.clone(), s.link_target.clone()))
        .collect();

    // Identify directory symlinks and their resolved targets on disk.
    let mut dir_symlinks: Vec<(PathBuf, PathBuf)> = Vec::new();
    for sym in deferred_symlinks {
        let host_path = rootfs.join(&sym.rel_path);
        if host_path.is_dir() {
            // This dir symlink was materialized as an empty directory.
            // Resolve the target to find the real directory to expand from.
            if let Some(resolved) =
                resolve_symlink_in_rootfs(&sym.rel_path, rootfs, &symlink_map, 32)
                    .filter(|r| r.is_dir())
            {
                if verbose {
                    eprintln!(
                        "  [dir-symlink] {} -> {}",
                        sym.rel_path.display(),
                        sym.link_target.display()
                    );
                }
                dir_symlinks.push((host_path, resolved));
            }
        }
    }

    for entry in walkdir::WalkDir::new(rootfs)
        .follow_links(false)
        .into_iter()
        .filter_map(std::result::Result::ok)
    {
        let rel_path = entry.path().strip_prefix(rootfs).unwrap_or(entry.path());

        // Skip the root itself
        if rel_path == Path::new("") {
            continue;
        }

        let tar_path = rel_path.to_string_lossy().to_string();
        // Normalize path separators to Unix-style for the tar archive.
        let tar_path = tar_path.replace('\\', "/");

        if entry.file_type().is_file() {
            let metadata = entry.metadata()?;
            let mode = super::file_mode(&metadata) & 0o7777;
            let is_executable = mode & 0o111 != 0;

            if verbose && is_executable {
                eprintln!("  [exec] {tar_path}");
            }

            files.insert(
                entry.path().to_path_buf(),
                RootfsEntry {
                    tar_path,
                    read_path: entry.path().to_path_buf(),
                    is_executable,
                    mode,
                },
            );
        } else if entry.file_type().is_symlink() {
            // On platforms that still have OS symlinks (Linux), resolve them.
            if let Some(resolved) = resolve_in_rootfs(entry.path(), rootfs, 16) {
                if resolved.is_file() {
                    let metadata = std::fs::metadata(&resolved)?;
                    let mode = super::file_mode(&metadata) & 0o7777;
                    let is_executable = mode & 0o111 != 0;

                    files.insert(
                        entry.path().to_path_buf(),
                        RootfsEntry {
                            tar_path,
                            read_path: resolved.clone(),
                            is_executable,
                            mode,
                        },
                    );
                } else if resolved.is_dir() {
                    if verbose {
                        eprintln!("  [dir-symlink] {tar_path} -> {}", resolved.display());
                    }
                    dir_symlinks.push((entry.path().to_path_buf(), resolved));
                }
            } else if verbose {
                eprintln!("  [skip] broken symlink: {tar_path}");
            }
        }
        // Directories are created implicitly by the tar builder
    }

    // Expand directory symlinks: walk the resolved target directory and create
    // additional tar entries under the symlink's path prefix. For example, if
    // `lib64` → `usr/lib64`, then `usr/lib64/ld-linux-x86-64.so.2` also
    // appears as `lib64/ld-linux-x86-64.so.2` in the tar.

    // Build a set of existing tar paths for O(1) duplicate checks.
    let mut tar_paths: HashSet<String> = files.values().map(|e| e.tar_path.clone()).collect();

    for (symlink_host_path, resolved_dir) in &dir_symlinks {
        let symlink_rel = symlink_host_path
            .strip_prefix(rootfs)
            .unwrap_or(symlink_host_path);

        for entry in walkdir::WalkDir::new(resolved_dir)
            .follow_links(false)
            .into_iter()
            .filter_map(std::result::Result::ok)
        {
            if !entry.file_type().is_file() && !entry.file_type().is_symlink() {
                continue;
            }

            // Determine the host path to read from and whether it's a file.
            let (read_path, is_file) = if entry.file_type().is_symlink() {
                if let Some(resolved) = resolve_in_rootfs(entry.path(), rootfs, 16) {
                    let is_file = resolved.is_file();
                    (resolved, is_file)
                } else {
                    continue;
                }
            } else {
                (entry.path().to_path_buf(), true)
            };

            if !is_file {
                continue;
            }

            // Build the tar path: replace the resolved_dir prefix with symlink_rel.
            let entry_rel = entry
                .path()
                .strip_prefix(resolved_dir)
                .unwrap_or(entry.path());
            let tar_path = symlink_rel.join(entry_rel).to_string_lossy().to_string();
            // Normalize path separators to Unix-style for the tar archive.
            let tar_path = tar_path.replace('\\', "/");

            // Use symlink_host_path-based key to avoid colliding with the
            // original entry under the resolved directory.
            let map_key = symlink_host_path.join(entry_rel);

            // Skip if we already have this tar path.
            if !tar_paths.insert(tar_path.clone()) {
                continue;
            }

            let metadata = std::fs::metadata(&read_path)?;
            let mode = super::file_mode(&metadata) & 0o7777;
            let is_executable = mode & 0o111 != 0;

            if verbose {
                eprintln!("  [dir-symlink-expand] {tar_path}");
            }

            files.insert(
                map_key,
                RootfsEntry {
                    tar_path,
                    read_path,
                    is_executable,
                    mode,
                },
            );
        }
    }

    if verbose {
        let exec_count = files.values().filter(|e| e.is_executable).count();
        eprintln!("  Found {} files ({} executables)", files.len(), exec_count);
    }

    Ok(RootfsFileMap { files })
}

/// Resolve a symlink within the rootfs context, handling absolute symlinks
/// that would otherwise escape the rootfs boundary.
fn resolve_in_rootfs(path: &Path, rootfs: &Path, max_depth: u32) -> Option<PathBuf> {
    if max_depth == 0 {
        return None;
    }

    let metadata = path.symlink_metadata().ok()?;
    if !metadata.file_type().is_symlink() {
        return if path.exists() {
            Some(path.to_path_buf())
        } else {
            None
        };
    }

    let link_target = std::fs::read_link(path).ok()?;
    let resolved = if is_unix_absolute(&link_target) {
        // Absolute symlink: resolve within rootfs
        rootfs.join(strip_unix_root(&link_target))
    } else {
        // Relative symlink
        path.parent()?.join(&link_target)
    };

    resolve_in_rootfs(&resolved, rootfs, max_depth - 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_gzip_data() {
        assert!(is_gzip_data(&[0x1f, 0x8b, 0x08]));
        assert!(!is_gzip_data(&[0x00, 0x00]));
        assert!(!is_gzip_data(&[0x1f]));
        assert!(!is_gzip_data(&[]));
    }

    #[test]
    fn test_resolve_in_rootfs_non_symlink() {
        // Non-existent path returns None
        let result = resolve_in_rootfs(Path::new("/nonexistent"), Path::new("/tmp"), 16);
        assert!(result.is_none());
    }

    #[test]
    fn test_resolve_in_rootfs_max_depth_zero() {
        let result = resolve_in_rootfs(Path::new("/tmp"), Path::new("/tmp"), 0);
        assert!(result.is_none());
    }
}
