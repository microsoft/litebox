// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! OCI image pulling and rootfs extraction.
//!
//! Pulls an OCI container image from a registry (e.g., Docker Hub, GHCR),
//! extracts its filesystem layers into a temporary rootfs directory, then
//! walks the rootfs to discover all ELF files for syscall rewriting.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::ffi::OsString;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use anyhow::{Context, bail};
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
    /// Symlink map from layer extraction. Targets are retained exactly as they
    /// appeared in the source tar, including dangling and absolute targets.
    pub symlink_map: HashMap<PathBuf, Vec<u8>>,
    /// Numeric Unix ownership captured from tar headers during extraction.
    /// Keyed by relative path inside the rootfs.
    pub ownership: HashMap<PathBuf, (u64, u64)>,
    /// Unix permission modes captured from tar headers during extraction.
    /// Keyed by relative path inside the rootfs. Used instead of querying
    /// filesystem metadata, which loses Unix mode bits on non-Unix hosts.
    pub permissions: HashMap<PathBuf, u32>,
}

/// Result of scanning an extracted rootfs for package entries.
pub struct RootfsFileMap {
    pub files: BTreeMap<PathBuf, RootfsEntry>,
}

/// The payload represented by a rootfs entry.
pub enum RootfsEntryKind {
    Regular {
        read_path: PathBuf,
        is_executable: bool,
    },
    Symlink {
        link_target: Vec<u8>,
    },
    Directory,
}

/// A regular file, symlink, or explicit directory discovered in the rootfs.
pub struct RootfsEntry {
    /// Path inside the tar archive (relative, no leading `/`).
    pub tar_path: String,
    pub kind: RootfsEntryKind,
    /// Unix permission mode (lower 12 bits).
    pub mode: u32,
    pub uid: u64,
    pub gid: u64,
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
    #[allow(
        clippy::items_after_statements,
        reason = "kept next to its only caller below"
    )]
    /// The OCI architecture name for the host LiteBox is running on.
    fn host_image_arch() -> oci_spec::image::Arch {
        if cfg!(target_arch = "aarch64") {
            oci_spec::image::Arch::ARM64
        } else {
            oci_spec::image::Arch::Amd64
        }
    }

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("failed to create tokio runtime")?;

    let image_data = rt.block_on(async {
        let config = ClientConfig {
            protocol: ClientProtocol::Https,
            // Pull the Linux image whose architecture matches the host. LiteBox
            // runs guest instructions natively rather than emulating them, so a
            // guest of any other architecture could not execute here -- pulling
            // one would only defer the failure to run time.
            platform_resolver: Some(Box::new(|entries| {
                entries
                    .iter()
                    .find(|entry| {
                        entry.platform.as_ref().is_some_and(|p| {
                            p.os == oci_spec::image::Os::Linux
                                && p.architecture == host_image_arch()
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
    let mut symlink_map: HashMap<PathBuf, Vec<u8>> = HashMap::new();
    let mut ownership: HashMap<PathBuf, (u64, u64)> = HashMap::new();
    let mut permissions: HashMap<PathBuf, u32> = HashMap::new();
    for (i, layer) in image_data.layers.iter().enumerate() {
        if verbose {
            eprintln!(
                "  Extracting layer {}/{} ({} bytes)...",
                i + 1,
                image_data.layers.len(),
                layer.data.len()
            );
        }
        extract_layer(
            &layer.data,
            &layer.media_type,
            &rootfs_path,
            &mut symlink_map,
            &mut ownership,
            &mut permissions,
            true,
        )
        .with_context(|| format!("failed to extract layer {}", i + 1))?;
    }

    if verbose {
        eprintln!(
            "  Rootfs extracted to {} ({} symlinks)",
            rootfs_path.display(),
            symlink_map.len()
        );
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
        symlink_map,
        ownership,
        permissions,
    })
}

/// Extract a locally-exported container rootfs tar (`podman export` / `docker export` output).
/// The export is a final filesystem rather than an OCI layer changeset, so `.wh.*` names are
/// retained as ordinary filesystem entries instead of being interpreted as whiteouts. The
/// container config (ENTRYPOINT/CMD/ENV) is not part of an exported rootfs, so
/// [`ExtractedImage::config`] is default-empty and `config_json` is an empty JSON object.
pub fn extract_rootfs_tar(tar_path: &Path, verbose: bool) -> anyhow::Result<ExtractedImage> {
    let data = std::fs::read(tar_path)
        .with_context(|| format!("failed to read rootfs tar {}", tar_path.display()))?;

    let tempdir = tempfile::tempdir().context("failed to create temporary directory for rootfs")?;
    let rootfs_path = tempdir.path().join("rootfs");
    std::fs::create_dir_all(&rootfs_path).context("failed to create rootfs directory")?;

    let mut symlink_map: HashMap<PathBuf, Vec<u8>> = HashMap::new();
    let mut ownership: HashMap<PathBuf, (u64, u64)> = HashMap::new();
    let mut permissions: HashMap<PathBuf, u32> = HashMap::new();
    if verbose {
        eprintln!("  Extracting rootfs tar ({} bytes)...", data.len());
    }
    extract_layer(
        &data,
        "",
        &rootfs_path,
        &mut symlink_map,
        &mut ownership,
        &mut permissions,
        false,
    )
    .context("failed to extract rootfs tar")?;

    if verbose {
        eprintln!("  Preserved {} symlinks", symlink_map.len());
    }

    Ok(ExtractedImage {
        tempdir,
        rootfs_path,
        config: ImageConfig::default(),
        config_json: b"{}".to_vec(),
        symlink_map,
        ownership,
        permissions,
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
/// files deleted in upper layers. Symlinks remain first-class entries and are
/// consulted while applying later layer paths. Permission modes from tar headers
/// are recorded in `permissions` for cross-platform use.
fn extract_layer(
    data: &[u8],
    media_type: &str,
    rootfs: &Path,
    symlinks: &mut HashMap<PathBuf, Vec<u8>>,
    ownership: &mut HashMap<PathBuf, (u64, u64)>,
    permissions: &mut HashMap<PathBuf, u32>,
    interpret_whiteouts: bool,
) -> anyhow::Result<()> {
    // Determine if the layer is gzipped
    let is_gzip = media_type.contains("gzip") || is_gzip_data(data);

    if is_gzip {
        let decoder = flate2::read::GzDecoder::new(data);
        extract_tar(
            decoder,
            rootfs,
            symlinks,
            ownership,
            permissions,
            interpret_whiteouts,
        )
    } else {
        extract_tar(
            data,
            rootfs,
            symlinks,
            ownership,
            permissions,
            interpret_whiteouts,
        )
    }
}

/// Check if data starts with the gzip magic bytes.
fn is_gzip_data(data: &[u8]) -> bool {
    data.len() >= 2 && data[0] == 0x1f && data[1] == 0x8b
}

/// A hard link whose target was not yet extracted when encountered.
struct DeferredHardLink {
    target_rel: PathBuf,
    link_source_rel: PathBuf,
}

const MAX_SYMLINK_FOLLOWS: usize = 40;

#[derive(Clone)]
enum UnixComponent {
    Root,
    Parent,
    Normal(OsString),
}

fn unix_components(path: &Path) -> VecDeque<UnixComponent> {
    path.components()
        .filter_map(|component| match component {
            std::path::Component::Prefix(_) | std::path::Component::RootDir => {
                Some(UnixComponent::Root)
            }
            std::path::Component::CurDir => None,
            std::path::Component::ParentDir => Some(UnixComponent::Parent),
            std::path::Component::Normal(name) => Some(UnixComponent::Normal(name.to_os_string())),
        })
        .collect()
}

#[allow(
    clippy::unnecessary_wraps,
    reason = "the non-Unix implementation validates that the raw component is UTF-8"
)]
fn tar_bytes_to_os_string(bytes: Vec<u8>) -> anyhow::Result<OsString> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStringExt as _;
        Ok(OsString::from_vec(bytes))
    }
    #[cfg(not(unix))]
    {
        Ok(OsString::from(String::from_utf8(bytes).context(
            "non-UTF-8 Unix path component cannot be represented on this host",
        )?))
    }
}

#[cfg(windows)]
fn validate_windows_path_component(component: &std::ffi::OsStr) -> anyhow::Result<()> {
    let name = component
        .to_str()
        .context("Unix path component cannot be represented as Windows UTF-16")?;
    let has_forbidden_character = name.chars().any(|character| {
        character < '\u{20}'
            || matches!(
                character,
                '<' | '>' | ':' | '"' | '/' | '\\' | '|' | '?' | '*'
            )
    });
    let has_forbidden_suffix = name.ends_with(' ') || name.ends_with('.');
    let basename = name
        .split('.')
        .next()
        .unwrap_or(name)
        .trim_end_matches(|character| character == ' ' || character == '.');
    let uppercase = basename.to_ascii_uppercase();
    let numbered_device = uppercase.as_bytes().get(3).is_some_and(|digit| {
        uppercase.len() == 4
            && (uppercase.starts_with("COM") || uppercase.starts_with("LPT"))
            && (b'1'..=b'9').contains(digit)
    });
    let superscript_device = (uppercase.starts_with("COM") || uppercase.starts_with("LPT"))
        && uppercase.chars().count() == 4
        && uppercase
            .chars()
            .nth(3)
            .is_some_and(|digit| matches!(digit, '¹' | '²' | '³'));
    let named_device = matches!(
        uppercase.as_str(),
        "CON" | "PRN" | "AUX" | "NUL" | "CLOCK$" | "CONIN$" | "CONOUT$"
    );
    if has_forbidden_character
        || has_forbidden_suffix
        || numbered_device
        || superscript_device
        || named_device
    {
        bail!(
            "Unix path component cannot be represented safely on Windows: {}",
            name
        );
    }
    Ok(())
}

fn tar_bytes_to_path_component(bytes: Vec<u8>) -> anyhow::Result<OsString> {
    let component = tar_bytes_to_os_string(bytes)?;
    let mut components = Path::new(&component).components();
    if matches!(components.next(), Some(std::path::Component::Normal(_)))
        && components.next().is_none()
    {
        #[cfg(windows)]
        validate_windows_path_component(&component)?;
        Ok(component)
    } else {
        bail!(
            "Unix path component cannot be represented safely on this host: {}",
            component.to_string_lossy()
        )
    }
}

fn unix_link_components(link_target: &[u8]) -> anyhow::Result<VecDeque<UnixComponent>> {
    let mut components = VecDeque::new();
    if link_target.starts_with(b"/") {
        components.push_back(UnixComponent::Root);
    }
    for component in link_target.split(|byte| *byte == b'/') {
        match component {
            b"" | b"." => {}
            b".." => components.push_back(UnixComponent::Parent),
            name => components.push_back(UnixComponent::Normal(tar_bytes_to_path_component(
                name.to_vec(),
            )?)),
        }
    }
    Ok(components)
}

fn unix_file_name_bytes(path: &[u8]) -> Option<&[u8]> {
    path.rsplit(|byte| *byte == b'/')
        .find(|component| !component.is_empty() && *component != b".")
}

fn validate_utf8_member_path(path: &[u8]) -> anyhow::Result<()> {
    if let Err(error) = std::str::from_utf8(path) {
        bail!(
            "cannot package non-UTF-8 tar member path with the current pure-ustar path model: invalid UTF-8 begins at byte {}",
            error.valid_up_to()
        );
    }
    Ok(())
}

fn os_str_to_tar_bytes(value: &std::ffi::OsStr) -> Vec<u8> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt as _;
        value.as_bytes().to_vec()
    }
    #[cfg(not(unix))]
    {
        value.to_string_lossy().into_owned().into_bytes()
    }
}

fn resolve_components(
    mut pending: VecDeque<UnixComponent>,
    symlinks: &HashMap<PathBuf, Vec<u8>>,
    followed: &mut usize,
) -> anyhow::Result<PathBuf> {
    let mut resolved = PathBuf::new();

    while let Some(component) = pending.pop_front() {
        match component {
            UnixComponent::Root => resolved.clear(),
            UnixComponent::Parent => {
                resolved.pop();
            }
            UnixComponent::Normal(name) => {
                let candidate = resolved.join(&name);
                let Some(link_target) = symlinks.get(&candidate).cloned() else {
                    resolved.push(name);
                    continue;
                };

                *followed += 1;
                if *followed > MAX_SYMLINK_FOLLOWS {
                    bail!(
                        "too many symlinks while resolving {} (limit {MAX_SYMLINK_FOLLOWS})",
                        candidate.display()
                    );
                }
                if link_target.is_empty() {
                    bail!("empty symlink target at {}", candidate.display());
                }

                let mut target_components = unix_link_components(&link_target)?;
                while let Some(target_component) = target_components.pop_back() {
                    pending.push_front(target_component);
                }
            }
        }
    }

    Ok(resolved)
}

fn resolve_parent_path(
    path: &[u8],
    symlinks: &HashMap<PathBuf, Vec<u8>>,
) -> anyhow::Result<(PathBuf, usize)> {
    let mut components = unix_link_components(path)?;
    let Some(UnixComponent::Normal(file_name)) = components.pop_back() else {
        bail!(
            "tar entry has no file name: {}",
            String::from_utf8_lossy(path)
        );
    };
    let mut followed = 0;
    Ok((
        resolve_components(components, symlinks, &mut followed)?.join(file_name),
        followed,
    ))
}

fn resolve_parent_link_name(
    link_name: &[u8],
    symlinks: &HashMap<PathBuf, Vec<u8>>,
) -> anyhow::Result<PathBuf> {
    let mut components = unix_link_components(link_name)?;
    let Some(UnixComponent::Normal(file_name)) = components.pop_back() else {
        bail!(
            "hard link has no file name: {}",
            String::from_utf8_lossy(link_name)
        );
    };
    let mut followed = 0;
    Ok(resolve_components(components, symlinks, &mut followed)?.join(file_name))
}

fn resolve_full_path(
    path: &Path,
    symlinks: &HashMap<PathBuf, Vec<u8>>,
    followed: &mut usize,
) -> anyhow::Result<PathBuf> {
    resolve_components(unix_components(path), symlinks, followed)
}

#[cfg(unix)]
fn make_staging_entry_accessible(path: &Path, is_directory: bool) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt as _;

    let mut permissions = std::fs::symlink_metadata(path)?.permissions();
    let required = if is_directory { 0o700 } else { 0o600 };
    permissions.set_mode(permissions.mode() | required);
    std::fs::set_permissions(path, permissions)?;
    Ok(())
}

#[cfg(not(unix))]
fn make_staging_entry_accessible(_path: &Path, _is_directory: bool) -> anyhow::Result<()> {
    Ok(())
}

fn remove_disk_entry(path: &Path) -> anyhow::Result<()> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    if metadata.is_dir() && !metadata.file_type().is_symlink() {
        std::fs::remove_dir_all(path)?;
    } else {
        std::fs::remove_file(path)?;
    }
    Ok(())
}

fn remove_rootfs_entry(
    rel_path: &Path,
    rootfs: &Path,
    symlinks: &mut HashMap<PathBuf, Vec<u8>>,
    ownership: &mut HashMap<PathBuf, (u64, u64)>,
    permissions: &mut HashMap<PathBuf, u32>,
) -> anyhow::Result<()> {
    if rel_path.as_os_str().is_empty() {
        bail!("refusing to remove the rootfs root");
    }
    remove_disk_entry(&rootfs.join(rel_path))?;
    symlinks.retain(|path, _| path != rel_path && !path.starts_with(rel_path));
    ownership.retain(|path, _| path != rel_path && !path.starts_with(rel_path));
    permissions.retain(|path, _| path != rel_path && !path.starts_with(rel_path));
    Ok(())
}

fn clear_rootfs_directory(
    rel_path: &Path,
    rootfs: &Path,
    symlinks: &mut HashMap<PathBuf, Vec<u8>>,
    ownership: &mut HashMap<PathBuf, (u64, u64)>,
    permissions: &mut HashMap<PathBuf, u32>,
) -> anyhow::Result<()> {
    let target = rootfs.join(rel_path);
    match std::fs::read_dir(&target) {
        Ok(children) => {
            for child in children {
                remove_disk_entry(&child?.path())?;
            }
        }
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
            ) => {}
        Err(error) => return Err(error.into()),
    }
    symlinks.retain(|path, _| path == rel_path || !path.starts_with(rel_path));
    ownership.retain(|path, _| path == rel_path || !path.starts_with(rel_path));
    permissions.retain(|path, _| path == rel_path || !path.starts_with(rel_path));
    Ok(())
}

/// Extract a tar archive into the rootfs, handling OCI whiteout files.
fn extract_tar<R: Read>(
    mut reader: R,
    rootfs: &Path,
    symlinks: &mut HashMap<PathBuf, Vec<u8>>,
    ownership: &mut HashMap<PathBuf, (u64, u64)>,
    permissions: &mut HashMap<PathBuf, u32>,
    interpret_whiteouts: bool,
) -> anyhow::Result<()> {
    if !interpret_whiteouts {
        return extract_tar_entries(reader, rootfs, symlinks, ownership, permissions, false);
    }

    let mut staged_tar = tempfile::tempfile().context("failed to stage OCI layer tar")?;
    std::io::copy(&mut reader, &mut staged_tar).context("failed to stage OCI layer tar")?;
    let resolver_symlinks = symlinks.clone();

    staged_tar.seek(SeekFrom::Start(0))?;
    apply_tar_whiteouts(
        &mut staged_tar,
        rootfs,
        &resolver_symlinks,
        symlinks,
        ownership,
        permissions,
    )?;
    staged_tar.seek(SeekFrom::Start(0))?;
    extract_tar_entries(
        &mut staged_tar,
        rootfs,
        symlinks,
        ownership,
        permissions,
        true,
    )
}

fn apply_tar_whiteouts<R: Read>(
    reader: R,
    rootfs: &Path,
    resolver_symlinks: &HashMap<PathBuf, Vec<u8>>,
    symlinks: &mut HashMap<PathBuf, Vec<u8>>,
    ownership: &mut HashMap<PathBuf, (u64, u64)>,
    permissions: &mut HashMap<PathBuf, u32>,
) -> anyhow::Result<()> {
    let mut archive = tar::Archive::new(reader);
    for entry_result in archive.entries()? {
        let entry = entry_result.context("failed to read tar entry")?;
        let archive_path = entry.path_bytes().into_owned();
        validate_utf8_member_path(&archive_path)?;
        let Some(file_name) = unix_file_name_bytes(&archive_path) else {
            continue;
        };

        if file_name == b".wh..wh..opq" {
            let (path, _) =
                resolve_parent_path(&archive_path, resolver_symlinks).with_context(|| {
                    format!(
                        "failed to resolve opaque whiteout {}",
                        String::from_utf8_lossy(&archive_path)
                    )
                })?;
            let parent = path.parent().unwrap_or(Path::new(""));
            clear_rootfs_directory(parent, rootfs, symlinks, ownership, permissions).with_context(
                || {
                    format!(
                        "failed to apply opaque whiteout {}",
                        String::from_utf8_lossy(&archive_path)
                    )
                },
            )?;
            continue;
        }

        let Some(target_name) = file_name.strip_prefix(b".wh.") else {
            continue;
        };
        let target_name = tar_bytes_to_path_component(target_name.to_vec()).with_context(|| {
            format!(
                "invalid OCI whiteout name {}",
                String::from_utf8_lossy(&archive_path)
            )
        })?;
        let (path, _) =
            resolve_parent_path(&archive_path, resolver_symlinks).with_context(|| {
                format!(
                    "failed to resolve whiteout {}",
                    String::from_utf8_lossy(&archive_path)
                )
            })?;
        let parent = path.parent().unwrap_or(Path::new(""));
        let whiteout_rel = parent.join(target_name);
        remove_rootfs_entry(&whiteout_rel, rootfs, symlinks, ownership, permissions).with_context(
            || {
                format!(
                    "failed to apply whiteout {}",
                    String::from_utf8_lossy(&archive_path)
                )
            },
        )?;
    }
    Ok(())
}

fn tar_header_ownership(header: &tar::Header, archive_path: &[u8]) -> anyhow::Result<(u64, u64)> {
    let uid = header.uid().with_context(|| {
        format!(
            "invalid uid in tar entry {}",
            String::from_utf8_lossy(archive_path)
        )
    })?;
    let gid = header.gid().with_context(|| {
        format!(
            "invalid gid in tar entry {}",
            String::from_utf8_lossy(archive_path)
        )
    })?;
    Ok((uid, gid))
}

fn extract_tar_entries<R: Read>(
    reader: R,
    rootfs: &Path,
    symlinks: &mut HashMap<PathBuf, Vec<u8>>,
    ownership: &mut HashMap<PathBuf, (u64, u64)>,
    permissions: &mut HashMap<PathBuf, u32>,
    skip_whiteouts: bool,
) -> anyhow::Result<()> {
    let mut archive = tar::Archive::new(reader);
    let mut deferred_links: Vec<DeferredHardLink> = Vec::new();

    for entry_result in archive.entries()? {
        let mut entry = entry_result.context("failed to read tar entry")?;
        let entry_type = entry.header().entry_type();
        let archive_path = entry.path_bytes().into_owned();
        validate_utf8_member_path(&archive_path)?;
        let has_file_name = unix_link_components(&archive_path)?
            .iter()
            .any(|component| matches!(component, UnixComponent::Normal(_)));
        if !has_file_name && entry_type == tar::EntryType::Directory {
            continue;
        }
        if skip_whiteouts
            && unix_file_name_bytes(&archive_path).is_some_and(|file_name| {
                file_name == b".wh..wh..opq" || file_name.starts_with(b".wh.")
            })
        {
            continue;
        }

        let (path, mut followed) =
            resolve_parent_path(&archive_path, symlinks).with_context(|| {
                format!(
                    "failed to resolve tar entry path {}",
                    String::from_utf8_lossy(&archive_path)
                )
            })?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(rootfs.join(parent)).with_context(|| {
                format!(
                    "failed to create parent for {}",
                    String::from_utf8_lossy(&archive_path)
                )
            })?;
        }
        let target = rootfs.join(&path);

        if entry_type == tar::EntryType::Link {
            let link_name = entry
                .link_name_bytes()
                .context("hard link entry has no link name")?
                .into_owned();
            let link_source_rel =
                resolve_parent_link_name(&link_name, symlinks).with_context(|| {
                    format!(
                        "failed to resolve hard link target {}",
                        String::from_utf8_lossy(&link_name)
                    )
                })?;
            let link_target = symlinks.get(&link_source_rel).cloned();
            let source_owner = ownership.get(&link_source_rel).copied().unwrap_or((0, 0));
            let source_mode = permissions.get(&link_source_rel).copied();

            remove_rootfs_entry(&path, rootfs, symlinks, ownership, permissions)?;
            if let Some(link_target) = link_target {
                symlinks.insert(path.clone(), link_target);
                ownership.insert(path.clone(), source_owner);
                permissions.insert(path, source_mode.unwrap_or(0o777));
            } else if rootfs.join(&link_source_rel).is_file() {
                std::fs::copy(rootfs.join(&link_source_rel), &target).with_context(|| {
                    format!(
                        "failed to copy hard link target {} -> {}",
                        link_source_rel.display(),
                        path.display()
                    )
                })?;
                make_staging_entry_accessible(&target, false)?;
                ownership.insert(path.clone(), source_owner);
                permissions.insert(path, source_mode.unwrap_or(0o644));
            } else {
                deferred_links.push(DeferredHardLink {
                    target_rel: path,
                    link_source_rel,
                });
            }
            continue;
        }

        if entry_type == tar::EntryType::Symlink {
            let link_target = entry
                .link_name_bytes()
                .context("symlink entry has no link name")?
                .into_owned();
            let mode = entry.header().mode().unwrap_or(0o777);
            let owner = tar_header_ownership(entry.header(), &archive_path)?;
            remove_rootfs_entry(&path, rootfs, symlinks, ownership, permissions)?;
            symlinks.insert(path.clone(), link_target);
            ownership.insert(path.clone(), owner);
            permissions.insert(path, mode);
            continue;
        }

        if entry_type == tar::EntryType::Directory {
            let directory_owner = tar_header_ownership(entry.header(), &archive_path)?;
            let directory_path = if symlinks.contains_key(&path) {
                let resolved =
                    resolve_full_path(&path, symlinks, &mut followed).with_context(|| {
                        format!(
                            "failed to resolve directory entry {}",
                            String::from_utf8_lossy(&archive_path)
                        )
                    })?;
                if rootfs.join(&resolved).is_dir() {
                    resolved
                } else {
                    remove_rootfs_entry(&path, rootfs, symlinks, ownership, permissions)?;
                    path.clone()
                }
            } else {
                if target.exists() && !target.is_dir() {
                    remove_rootfs_entry(&path, rootfs, symlinks, ownership, permissions)?;
                }
                path.clone()
            };
            let directory_target = rootfs.join(&directory_path);
            if let Some(parent) = directory_target.parent() {
                std::fs::create_dir_all(parent)?;
            }
            entry.unpack(&directory_target).with_context(|| {
                format!(
                    "failed to unpack directory {}",
                    String::from_utf8_lossy(&archive_path)
                )
            })?;
            make_staging_entry_accessible(&directory_target, true)?;
            ownership.insert(directory_path.clone(), directory_owner);
            if let Ok(mode) = entry.header().mode() {
                permissions.insert(directory_path, mode);
            }
            continue;
        }

        let owner = tar_header_ownership(entry.header(), &archive_path)?;
        remove_rootfs_entry(&path, rootfs, symlinks, ownership, permissions)?;
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent)?;
        }
        entry.unpack(&target).with_context(|| {
            format!(
                "failed to unpack entry: {}",
                String::from_utf8_lossy(&archive_path)
            )
        })?;
        make_staging_entry_accessible(&target, false)?;
        ownership.insert(path.clone(), owner);
        if let Ok(mode) = entry.header().mode() {
            permissions.insert(path, mode);
        }
    }

    while !deferred_links.is_empty() {
        let mut unresolved = Vec::new();
        let mut progressed = false;

        for link in deferred_links {
            let target = rootfs.join(&link.target_rel);
            if symlinks.contains_key(&link.target_rel) || std::fs::symlink_metadata(&target).is_ok()
            {
                progressed = true;
                continue;
            }
            if let Some(link_target) = symlinks.get(&link.link_source_rel).cloned() {
                let owner = ownership
                    .get(&link.link_source_rel)
                    .copied()
                    .unwrap_or((0, 0));
                let mode = permissions
                    .get(&link.link_source_rel)
                    .copied()
                    .unwrap_or(0o777);
                symlinks.insert(link.target_rel.clone(), link_target);
                ownership.insert(link.target_rel.clone(), owner);
                permissions.insert(link.target_rel, mode);
                progressed = true;
                continue;
            }

            let link_source = rootfs.join(&link.link_source_rel);
            if !link_source.is_file() {
                unresolved.push(link);
                continue;
            }
            if let Some(parent) = target.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::copy(&link_source, &target).with_context(|| {
                format!(
                    "failed to copy deferred hard link {} -> {}",
                    link.link_source_rel.display(),
                    link.target_rel.display()
                )
            })?;
            make_staging_entry_accessible(&target, false)?;
            let owner = ownership
                .get(&link.link_source_rel)
                .copied()
                .unwrap_or((0, 0));
            let mode = permissions
                .get(&link.link_source_rel)
                .copied()
                .unwrap_or(0o644);
            ownership.insert(link.target_rel.clone(), owner);
            permissions.insert(link.target_rel, mode);
            progressed = true;
        }

        if unresolved.is_empty() {
            break;
        }
        if !progressed {
            let link = &unresolved[0];
            bail!(
                "hard link target {} not found for {}",
                link.link_source_rel.display(),
                link.target_rel.display()
            );
        }
        deferred_links = unresolved;
    }

    Ok(())
}

fn lookup_mode(rel_path: &Path, permissions: &HashMap<PathBuf, u32>, default_mode: u32) -> u32 {
    permissions.get(rel_path).copied().unwrap_or(default_mode) & 0o7777
}

fn rootfs_tar_path(rel_path: &Path) -> anyhow::Result<String> {
    let path = rel_path.to_str().context(
        "cannot package non-UTF-8 rootfs member path with the current pure-ustar path model",
    )?;

    #[cfg(windows)]
    {
        Ok(path.replace('\\', "/"))
    }
    #[cfg(not(windows))]
    {
        Ok(path.to_owned())
    }
}

/// Scan an extracted rootfs into regular-file, symlink, and explicit-directory entries.
#[allow(clippy::implicit_hasher)]
pub fn scan_rootfs(
    rootfs: &Path,
    symlink_map: &HashMap<PathBuf, Vec<u8>>,
    ownership: &HashMap<PathBuf, (u64, u64)>,
    permissions: &HashMap<PathBuf, u32>,
    verbose: bool,
) -> anyhow::Result<RootfsFileMap> {
    let mut files = BTreeMap::new();

    for entry_result in walkdir::WalkDir::new(rootfs).follow_links(false) {
        let entry = entry_result.context("failed to walk extracted rootfs")?;
        let rel_path = entry.path().strip_prefix(rootfs).unwrap_or(entry.path());
        if rel_path.as_os_str().is_empty() || symlink_map.contains_key(rel_path) {
            continue;
        }

        let tar_path = rootfs_tar_path(rel_path)?;
        let kind = if entry.file_type().is_file() {
            let is_executable = lookup_mode(rel_path, permissions, 0o644) & 0o111 != 0;
            if verbose && is_executable {
                eprintln!("  [exec] {tar_path}");
            }
            RootfsEntryKind::Regular {
                read_path: entry.path().to_path_buf(),
                is_executable,
            }
        } else if entry.file_type().is_dir() {
            RootfsEntryKind::Directory
        } else if entry.file_type().is_symlink() {
            let link_target = std::fs::read_link(entry.path())
                .with_context(|| format!("failed to read symlink {}", entry.path().display()))?;
            RootfsEntryKind::Symlink {
                link_target: os_str_to_tar_bytes(link_target.as_os_str()),
            }
        } else {
            continue;
        };
        let default_mode = match &kind {
            RootfsEntryKind::Regular { .. } => 0o644,
            RootfsEntryKind::Symlink { .. } => 0o777,
            RootfsEntryKind::Directory => 0o755,
        };
        let (uid, gid) = ownership.get(rel_path).copied().unwrap_or((0, 0));
        files.insert(
            rel_path.to_path_buf(),
            RootfsEntry {
                tar_path,
                kind,
                mode: lookup_mode(rel_path, permissions, default_mode),
                uid,
                gid,
            },
        );
    }

    for (rel_path, link_target) in symlink_map {
        let tar_path = rootfs_tar_path(rel_path)?;
        let (uid, gid) = ownership.get(rel_path).copied().unwrap_or((0, 0));
        files.insert(
            rel_path.clone(),
            RootfsEntry {
                tar_path,
                kind: RootfsEntryKind::Symlink {
                    link_target: link_target.clone(),
                },
                mode: lookup_mode(rel_path, permissions, 0o777),
                uid,
                gid,
            },
        );
    }

    if verbose {
        let executable_count = files
            .values()
            .filter(|entry| {
                matches!(
                    &entry.kind,
                    RootfsEntryKind::Regular {
                        is_executable: true,
                        ..
                    }
                )
            })
            .count();
        eprintln!(
            "  Found {} entries ({executable_count} executable regular files)",
            files.len()
        );
    }

    Ok(RootfsFileMap { files })
}
