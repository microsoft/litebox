// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! OCI image pulling and rootfs extraction.
//!
//! Pulls an OCI container image from a registry via `skopeo` into a
//! temporary OCI Image Layout directory, then parses the layout using
//! `oci-spec` and extracts the filesystem layers into a temporary rootfs
//! directory for syscall rewriting.

use std::collections::{BTreeMap, HashSet};
use std::io::Read;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};

use anyhow::{Context, bail};
use oci_spec::image::{Arch, ImageConfiguration, ImageIndex, ImageManifest, MediaType, Os};

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
/// Uses `skopeo copy` to fetch the image into a temporary OCI Image Layout
/// directory, then parses the layout with `oci-spec` and extracts layers.
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
/// Authentication is delegated to `skopeo` (which reads the system
/// credential helpers and Docker config).
pub fn pull_and_extract(image_ref: &str, verbose: bool) -> anyhow::Result<ExtractedImage> {
    // Pull with skopeo into a temp directory.
    if verbose {
        eprintln!("Pulling image via skopeo: {image_ref}");
    }
    let skopeo_dir = tempfile::tempdir().context("failed to create temp directory for skopeo")?;
    let oci_dest = format!("oci:{}:latest", skopeo_dir.path().display());

    let status = std::process::Command::new("skopeo")
        .args(["copy", &format!("docker://{image_ref}"), &oci_dest])
        .status()
        .context(
            "failed to execute skopeo — is it installed? \
             (install with: apt-get install skopeo)",
        )?;

    if !status.success() {
        bail!(
            "skopeo copy failed (exit {}). Make sure the image reference \
             is valid and the registry is reachable: {image_ref}",
            status.code().unwrap_or(-1),
        );
    }

    let layout_dir = skopeo_dir.path();

    // --- Parse the OCI Image Layout ---
    let index_path = layout_dir.join("index.json");
    let index = ImageIndex::from_file(&index_path)
        .with_context(|| format!("failed to parse {}", index_path.display()))?;

    // Resolve the image manifest for linux/amd64.
    let manifest_path = resolve_manifest_path(layout_dir, &index, verbose)?;
    let manifest = ImageManifest::from_file(&manifest_path)
        .with_context(|| format!("failed to parse manifest {}", manifest_path.display()))?;

    if verbose {
        eprintln!("  Manifest has {} layer(s)", manifest.layers().len());
    }

    // Read the raw config JSON blob.
    let config_blob_path = blob_path(layout_dir, manifest.config().digest().as_ref());
    let config_json = std::fs::read(&config_blob_path)
        .with_context(|| format!("failed to read config blob {}", config_blob_path.display()))?;

    // Create temp directory for rootfs extraction.
    let tempdir = tempfile::tempdir().context("failed to create temporary directory for rootfs")?;
    let rootfs_path = tempdir.path().join("rootfs");
    std::fs::create_dir_all(&rootfs_path).context("failed to create rootfs directory")?;

    // Extract layers in order (bottom layer first).
    for (i, layer_desc) in manifest.layers().iter().enumerate() {
        let layer_blob = blob_path(layout_dir, layer_desc.digest().as_ref());
        let data = std::fs::read(&layer_blob)
            .with_context(|| format!("failed to read layer blob {}", layer_blob.display()))?;

        if verbose {
            eprintln!(
                "  Extracting layer {}/{} ({} bytes, {})...",
                i + 1,
                manifest.layers().len(),
                data.len(),
                layer_desc.media_type(),
            );
        }

        let media_type_str = layer_desc.media_type().to_string();
        extract_layer(&data, &media_type_str, &rootfs_path)
            .with_context(|| format!("failed to extract layer {}", i + 1))?;
    }

    if verbose {
        eprintln!("  Rootfs extracted to {}", rootfs_path.display());
    }

    // Parse image config for ENTRYPOINT, CMD, ENV, WORKDIR.
    let config = match ImageConfiguration::from_reader(config_json.as_slice()) {
        Ok(ic) => {
            let exec_config = ic.config();
            let parsed = ImageConfig {
                entrypoint: exec_config.as_ref().and_then(|c| c.entrypoint().clone()),
                cmd: exec_config.as_ref().and_then(|c| c.cmd().clone()),
                env: exec_config.as_ref().and_then(|c| c.env().clone()),
                working_dir: exec_config.as_ref().and_then(|c| c.working_dir().clone()),
            };
            if verbose {
                eprintln!(
                    "  Image config: ENTRYPOINT={:?} CMD={:?} WORKDIR={:?} ENV=({} vars)",
                    parsed.entrypoint,
                    parsed.cmd,
                    parsed.working_dir,
                    parsed.env.as_ref().map_or(0, Vec::len)
                );
            }
            parsed
        }
        Err(e) => {
            eprintln!(
                "warning: failed to parse image config: {e}; \
                 config_and_run.sh will not be generated"
            );
            ImageConfig::default()
        }
    };

    Ok(ExtractedImage {
        tempdir,
        rootfs_path,
        config,
        config_json,
    })
}

/// Resolve the path to the linux/amd64 image manifest blob within an OCI
/// Image Layout directory.
///
/// The `index.json` may reference:
/// 1. A single `ImageManifest` directly.
/// 2. An `ImageIndex` (multi-arch / fat manifest) that in turn contains
///    per-platform `ImageManifest` descriptors.
///
/// In case (2) we pick the `linux/amd64` entry.
fn resolve_manifest_path(
    layout_dir: &Path,
    index: &ImageIndex,
    verbose: bool,
) -> anyhow::Result<PathBuf> {
    let manifests = index.manifests();
    if manifests.is_empty() {
        bail!("OCI index.json has no manifests");
    }

    for desc in manifests {
        let mt = desc.media_type();
        let path = blob_path(layout_dir, desc.digest().as_ref());

        if *mt == MediaType::ImageManifest {
            // Direct image manifest — use it (assume correct platform for
            // single-manifest indexes produced by skopeo with a platform
            // filter or local builds).
            if verbose {
                eprintln!("  Using manifest blob {}", desc.digest());
            }
            return Ok(path);
        }

        if *mt == MediaType::ImageIndex {
            // Nested image index (fat manifest) — look inside for linux/amd64.
            if verbose {
                eprintln!("  Resolving nested image index {}", desc.digest());
            }
            let nested_index = ImageIndex::from_file(&path).with_context(|| {
                format!("failed to parse nested image index {}", path.display())
            })?;
            return resolve_platform_manifest(layout_dir, &nested_index, verbose);
        }

        // Docker manifest list uses a different media type string.
        let mt_str = mt.to_string();
        if mt_str.contains("manifest.list") || mt_str.contains("manifest.v2") {
            // Treat manifest.list as an image index, and manifest.v2 as an
            // image manifest (Docker V2 Schema 2).
            if mt_str.contains("manifest.list") {
                if verbose {
                    eprintln!(
                        "  Resolving Docker manifest list {} ({})",
                        desc.digest(),
                        mt_str
                    );
                }
                let nested_index = ImageIndex::from_file(&path).with_context(|| {
                    format!("failed to parse Docker manifest list {}", path.display())
                })?;
                return resolve_platform_manifest(layout_dir, &nested_index, verbose);
            }
            if verbose {
                eprintln!(
                    "  Using Docker manifest blob {} ({})",
                    desc.digest(),
                    mt_str
                );
            }
            return Ok(path);
        }
    }

    // Fallback: use the first manifest entry regardless of media type.
    let first = &manifests[0];
    let path = blob_path(layout_dir, first.digest().as_ref());
    if verbose {
        eprintln!(
            "  Falling back to first manifest entry {} ({})",
            first.digest(),
            first.media_type()
        );
    }
    Ok(path)
}

/// Pick the linux/amd64 manifest from a multi-platform image index.
fn resolve_platform_manifest(
    layout_dir: &Path,
    index: &ImageIndex,
    verbose: bool,
) -> anyhow::Result<PathBuf> {
    for desc in index.manifests() {
        if let Some(platform) = desc.platform()
            && *platform.architecture() == Arch::Amd64
            && *platform.os() == Os::Linux
        {
            let path = blob_path(layout_dir, desc.digest().as_ref());
            if verbose {
                eprintln!("  Selected linux/amd64 manifest {}", desc.digest());
            }
            return Ok(path);
        }
    }
    bail!(
        "no linux/amd64 manifest found in image index (available platforms: {})",
        index
            .manifests()
            .iter()
            .filter_map(|d| d.platform().as_ref().map(|p| format!(
                "{}/{}",
                p.os(),
                p.architecture()
            )))
            .collect::<Vec<_>>()
            .join(", ")
    );
}

/// Return the blob path for a given digest string (e.g. `sha256:abcdef...`
/// → `<layout_dir>/blobs/sha256/abcdef...`).
fn blob_path(layout_dir: &Path, digest: &str) -> PathBuf {
    // Digest format is "algorithm:hex", e.g. "sha256:abc123..."
    let (algo, hex) = digest.split_once(':').unwrap_or(("sha256", digest));
    layout_dir.join("blobs").join(algo).join(hex)
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
/// files deleted in upper layers.
fn extract_layer(data: &[u8], media_type: &str, rootfs: &Path) -> anyhow::Result<()> {
    // Determine if the layer is gzipped
    let is_gzip = media_type.contains("gzip") || is_gzip_data(data);

    if is_gzip {
        let decoder = flate2::read::GzDecoder::new(data);
        extract_tar(decoder, rootfs)
    } else {
        extract_tar(data, rootfs)
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

/// Extract a tar archive into the rootfs, handling OCI whiteout files.
///
/// Hard links whose targets appear later in the archive are collected during
/// the first pass and resolved after all regular entries have been extracted.
fn extract_tar<R: Read>(reader: R, rootfs: &Path) -> anyhow::Result<()> {
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

        // Handle hard links: copy the link target instead of creating an OS
        // hard link. The tar crate's unpack() tries std::fs::hard_link which
        // can fail if the target hasn't been extracted yet (ordering issue),
        // and the litebox filesystem doesn't support hard links anyway.
        let entry_type = entry.header().entry_type();
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

        // Normal file/directory/symlink: use the standard unpack
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

/// Scan an extracted rootfs directory and build a file map for packaging.
///
/// Walks the rootfs directory tree and collects all regular files with their
/// paths and permission bits. Symlinks are resolved within the rootfs context
/// and flattened into regular file copies (the litebox tar RO filesystem does
/// not support symlinks).
///
/// **Directory symlinks** (e.g., `/lib64` → `/usr/lib64`) are expanded: all
/// files under the target directory are duplicated under the symlink's path
/// prefix so that paths like `/lib64/ld-linux-x86-64.so.2` exist in the tar.
pub fn scan_rootfs(rootfs: &Path, verbose: bool) -> anyhow::Result<RootfsFileMap> {
    let mut files = BTreeMap::new();
    // Collect directory symlinks to expand after the initial walk.
    let mut dir_symlinks: Vec<(PathBuf, PathBuf)> = Vec::new();

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

        if entry.file_type().is_file() {
            let metadata = entry.metadata()?;
            let mode = metadata.permissions().mode() & 0o7777;
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
            // Resolve symlink within rootfs and flatten to a regular file copy.
            // Use the symlink's own path as the map key so that every symlink
            // produces its own tar entry (multiple symlinks that resolve to the
            // same target each get their own copy in the tar, matching the
            // behaviour expected by the litebox filesystem which has no symlinks).
            if let Some(resolved) = resolve_in_rootfs(entry.path(), rootfs, 16) {
                if resolved.is_file() {
                    let metadata = std::fs::metadata(&resolved)?;
                    let mode = metadata.permissions().mode() & 0o7777;
                    let is_executable = mode & 0o111 != 0;

                    files.insert(
                        entry.path().to_path_buf(),
                        RootfsEntry {
                            tar_path,
                            read_path: resolved,
                            is_executable,
                            mode,
                        },
                    );
                } else if resolved.is_dir() {
                    // Directory symlink: record for expansion below.
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

            // Use symlink_host_path-based key to avoid colliding with the
            // original entry under the resolved directory.
            let map_key = symlink_host_path.join(entry_rel);

            // Skip if we already have this tar path.
            if !tar_paths.insert(tar_path.clone()) {
                continue;
            }

            let metadata = std::fs::metadata(&read_path)?;
            let mode = metadata.permissions().mode() & 0o7777;
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
    let resolved = if link_target.is_absolute() {
        // Absolute symlink: resolve within rootfs
        rootfs.join(link_target.strip_prefix("/").unwrap_or(&link_target))
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
