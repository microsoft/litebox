// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! OCI image pulling and in-memory rootfs merging.
//!
//! Pulls an OCI container image from a registry and merges its filesystem
//! layers into a single in-memory rootfs that keeps directories, symlinks and
//! hard links, for syscall rewriting and packaging.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::io::Read;
use std::sync::Arc;

use anyhow::Context;
use oci_client::client::{ClientConfig, ClientProtocol, ImageData};
use oci_client::config::ConfigFile;
use oci_client::secrets::RegistryAuth;
use oci_client::{Client, Reference};

use crate::{CliTargetArch, FileObject, RootfsNode};

/// Select the Linux manifest for the requested guest architecture.
fn select_manifest(
    entries: &[oci_client::manifest::ImageIndexEntry],
    target_arch: CliTargetArch,
) -> Option<String> {
    let architecture = target_arch.oci_arch();
    entries
        .iter()
        .find(|entry| {
            entry.platform.as_ref().is_some_and(|platform| {
                platform.os == oci_spec::image::Os::Linux && platform.architecture == architecture
            })
        })
        .map(|entry| entry.digest.clone())
}

/// Parsed OCI image execution configuration (ENTRYPOINT, CMD, ENV, WORKDIR).
#[derive(Debug, Default)]
pub struct ImageConfig {
    pub entrypoint: Option<Vec<String>>,
    pub cmd: Option<Vec<String>>,
    pub env: Option<Vec<String>>,
    pub working_dir: Option<String>,
}

/// Result of pulling an OCI image.
pub struct PulledImage {
    /// The image's layers, merged.
    pub rootfs: Rootfs,
    /// Parsed image config (ENTRYPOINT, CMD, ENV, WORKDIR).
    pub config: ImageConfig,
    /// Raw OCI image config JSON blob (the full config descriptor data).
    pub config_json: Vec<u8>,
}

/// Pull an OCI image from a registry and merge its layers into a [`Rootfs`].
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
pub fn pull_image(
    image_ref: &str,
    target_arch: CliTargetArch,
    verbose: bool,
) -> anyhow::Result<PulledImage> {
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
            // oci-client 0.16 returns layers in download-completion order.
            // Download sequentially to preserve manifest order for merging.
            max_concurrent_download: 1,
            platform_resolver: Some(Box::new(move |entries| {
                select_manifest(entries, target_arch)
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
            .with_context(|| {
                format!(
                    "failed to pull image {reference} for linux/{}",
                    target_arch.name()
                )
            })?;

        if verbose {
            eprintln!("  Pulled {} layer(s)", image_data.layers.len());
        }

        Ok::<_, anyhow::Error>(image_data)
    })?;

    let config_json = image_data.config.data.to_vec();
    let config_file = ConfigFile::try_from(image_data.config);
    if let Ok(config_file) = &config_file
        && (config_file.os != oci_spec::image::Os::Linux
            || config_file.architecture != target_arch.oci_arch())
    {
        anyhow::bail!(
            "pulled OCI image targets {}/{}, expected linux/{}",
            config_file.os,
            config_file.architecture,
            target_arch.name(),
        );
    }

    // Merge layers in order (bottom layer first)
    let mut rootfs = Rootfs::default();
    for (i, layer) in image_data.layers.iter().enumerate() {
        if verbose {
            eprintln!(
                "  Merging layer {}/{} ({} bytes)...",
                i + 1,
                image_data.layers.len(),
                layer.data.len()
            );
        }
        rootfs
            .apply_layer(&layer.data, &layer.media_type, verbose)
            .with_context(|| format!("failed to merge layer {}", i + 1))?;
    }

    // Parse image config for ENTRYPOINT, CMD, ENV, WORKDIR.
    let config = match config_file {
        Ok(config_file) => {
            let exec_config = config_file.config.as_ref();
            ImageConfig {
                entrypoint: exec_config.and_then(|c| c.entrypoint.clone()),
                cmd: exec_config.and_then(|c| c.cmd.clone()),
                env: exec_config.and_then(|c| c.env.clone()),
                working_dir: exec_config.and_then(|c| c.working_dir.clone()),
            }
        }
        Err(e) => {
            eprintln!(
                "warning: failed to parse image config: {e}; config_and_run.sh will use defaults"
            );
            ImageConfig::default()
        }
    };
    if verbose {
        eprintln!(
            "  Image config: ENTRYPOINT={:?} CMD={:?} WORKDIR={:?} ENV=({} vars)",
            config.entrypoint,
            config.cmd,
            config.working_dir,
            config.env.as_ref().map_or(0, Vec::len)
        );
    }

    Ok(PulledImage {
        rootfs,
        config,
        config_json,
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

/// Mode of directories that are only implied by the paths beneath them.
const IMPLICIT_DIR_MODE: u32 = 0o755;

/// Linux's limit on symlink expansions within one path resolution.
const MAX_SYMLINK_EXPANSIONS: usize = 40;

/// A flattened container rootfs.
#[derive(Default)]
pub struct Rootfs {
    /// Every node but the root directory, keyed by its normalized path: relative,
    /// `/`-separated, without `.` or `..` components. A node's ancestors are all
    /// directories in the map.
    pub nodes: BTreeMap<String, RootfsNode>,
}

/// One change that a layer makes to the rootfs.
enum LayerChange {
    /// Remove the path and anything beneath it.
    Whiteout,
    /// Remove everything beneath the directory at the path that the layer has not written.
    OpaqueWhiteout,
    /// Place this node at the path.
    Node(RootfsNode),
    /// Give the path the node at this (normalized) path.
    HardLink(String),
}

impl Rootfs {
    /// Apply an OCI layer (tar, optionally gzipped) over the rootfs.
    ///
    /// Entries apply in archive order, as containerd applies layers, so that each resolves its
    /// parent symlinks against what earlier entries left. An opaque whiteout keeps what this layer
    /// has written, so it removes only lower layers' entries. Like containerd, this assumes that a
    /// directory's own entry precedes the whiteouts inside it.
    fn apply_layer(&mut self, data: &[u8], media_type: &str, verbose: bool) -> anyhow::Result<()> {
        let changes = if media_type.contains("gzip") || is_gzip_data(data) {
            read_layer(flate2::read::GzDecoder::new(data), verbose)?
        } else {
            read_layer(data, verbose)?
        };
        // The resolved paths this layer has written.
        let mut written = BTreeSet::new();
        // Hard links whose target the layer archives after them, retried once it is applied.
        let mut forward_links = Vec::new();
        for (path, change) in changes {
            if let Some(target) = self.apply(&path, change, &mut written) {
                forward_links.push((path, target));
            }
        }
        for (path, target) in forward_links {
            if self
                .apply(&path, LayerChange::HardLink(target.clone()), &mut written)
                .is_some()
            {
                eprintln!("  warning: hard link target {target} not found, skipping {path}");
            }
        }
        Ok(())
    }

    /// Apply one change of a layer. Returns the target of a hard link that does not (yet) name a
    /// file or symlink, leaving the link unapplied.
    fn apply(
        &mut self,
        path: &str,
        change: LayerChange,
        written: &mut BTreeSet<String>,
    ) -> Option<String> {
        let resolved = match change {
            LayerChange::OpaqueWhiteout => self.resolve_dir(path),
            _ => self.resolve_parent(path),
        };
        let Some(resolved) = resolved else {
            eprintln!("  warning: skipping {path}: a parent is not a directory or loops");
            return None;
        };
        let node = match change {
            LayerChange::Whiteout => {
                self.remove(&resolved);
                return None;
            }
            LayerChange::OpaqueWhiteout => {
                let mut children = self.split_off_children(&resolved);
                children.retain(|child, _| {
                    // Keep what this layer wrote, and its ancestors.
                    let descendants = format!("{child}/");
                    written.contains(child)
                        || written
                            .range(descendants.clone()..)
                            .next()
                            .is_some_and(|path| path.starts_with(&descendants))
                });
                self.nodes.append(&mut children);
                return None;
            }
            LayerChange::Node(node) => node,
            LayerChange::HardLink(target) => {
                let node = self
                    .resolve_parent(&target)
                    .and_then(|target| self.nodes.get(&target));
                match node {
                    Some(RootfsNode::File(file)) => RootfsNode::File(file.clone()),
                    Some(RootfsNode::Symlink { target }) => RootfsNode::Symlink {
                        target: target.clone(),
                    },
                    Some(RootfsNode::Dir { .. }) | None => return Some(target),
                }
            }
        };
        written.insert(resolved.clone());
        self.insert(resolved, node);
        None
    }

    /// Add a regular file at `path` unless something already exists there, or a
    /// parent is not a directory. Returns whether the file was added.
    pub fn add_file(&mut self, path: &str, file: FileObject) -> bool {
        match self.resolve_parent(&normalize_path(path)) {
            Some(resolved) if !self.nodes.contains_key(&resolved) => {
                self.insert(resolved, RootfsNode::File(Arc::new(file)));
                true
            }
            _ => false,
        }
    }

    /// Place `node` at the parent-resolved `path`, merging a directory into an
    /// existing directory and otherwise replacing whatever was there.
    fn insert(&mut self, path: String, node: RootfsNode) {
        if path.is_empty() {
            // The root directory always exists, and its metadata is not packaged.
            return;
        }
        for (end, _) in path.match_indices('/') {
            self.nodes
                .entry(path[..end].to_owned())
                .or_insert(RootfsNode::Dir {
                    mode: IMPLICIT_DIR_MODE,
                });
        }
        if let (Some(RootfsNode::Dir { mode }), RootfsNode::Dir { mode: new_mode }) =
            (self.nodes.get_mut(&path), &node)
        {
            *mode = *new_mode;
            return;
        }
        self.remove(&path);
        self.nodes.insert(path, node);
    }

    fn remove(&mut self, path: &str) {
        // Only a directory has nodes beneath it, as every node's ancestors are directories.
        if let Some(RootfsNode::Dir { .. }) = self.nodes.remove(path) {
            self.split_off_children(path);
        }
    }

    /// Remove and return the nodes beneath the directory `dir`.
    fn split_off_children(&mut self, dir: &str) -> BTreeMap<String, RootfsNode> {
        if dir.is_empty() {
            return std::mem::take(&mut self.nodes);
        }
        // Paths beneath `dir` sort contiguously after `dir/` and before `dir0`.
        let mut children = self.nodes.split_off(format!("{dir}/").as_str());
        let mut after = children.split_off(format!("{dir}0").as_str());
        self.nodes.append(&mut after);
        children
    }

    /// `path` with the symlinks among its parent components expanded within the
    /// rootfs, or `None` if a parent is a non-directory or symlinks loop.
    fn resolve_parent(&self, path: &str) -> Option<String> {
        let (parent, name) = path.rsplit_once('/').unwrap_or(("", path));
        let parent = self.resolve_dir(parent)?;
        Some(if parent.is_empty() {
            name.to_owned()
        } else {
            format!("{parent}/{name}")
        })
    }

    /// [`Self::resolve`], but `None` if `path` names a non-directory.
    fn resolve_dir(&self, path: &str) -> Option<String> {
        self.resolve(path)
            .filter(|resolved| !matches!(self.nodes.get(resolved), Some(RootfsNode::File(_))))
    }

    /// `path` with all its symlinks expanded within the rootfs, as containerd
    /// does when applying layers: absolute targets start at the rootfs root and
    /// `..` stops there. `None` if a non-final component is a non-directory or
    /// symlinks loop; components that do not exist yet are kept.
    pub(crate) fn resolve(&self, path: &str) -> Option<String> {
        let mut resolved: Vec<&str> = Vec::new();
        let mut pending: VecDeque<&str> = path.split('/').collect();
        let mut expansions = 0;
        while let Some(component) = pending.pop_front() {
            match component {
                "" | "." => {}
                ".." => {
                    resolved.pop();
                }
                _ => {
                    resolved.push(component);
                    match self.nodes.get(&resolved.join("/")) {
                        Some(RootfsNode::Symlink { target }) => {
                            expansions += 1;
                            if expansions > MAX_SYMLINK_EXPANSIONS {
                                return None;
                            }
                            resolved.pop();
                            if target.starts_with('/') {
                                resolved.clear();
                            }
                            for part in target.split('/').rev() {
                                pending.push_front(part);
                            }
                        }
                        Some(RootfsNode::File(_)) if !pending.is_empty() => return None,
                        Some(RootfsNode::Dir { .. } | RootfsNode::File(_)) | None => {}
                    }
                }
            }
        }
        Some(resolved.join("/"))
    }
}

/// Read the changes of a layer, in archive order.
fn read_layer(reader: impl Read, verbose: bool) -> anyhow::Result<Vec<(String, LayerChange)>> {
    let mut archive = tar::Archive::new(reader);
    let mut changes = Vec::new();
    for entry in archive.entries()? {
        let mut entry = entry.context("failed to read tar entry")?;
        let Ok(path) = String::from_utf8(entry.path_bytes().into_owned()) else {
            eprintln!(
                "  warning: skipping non-UTF-8 path {}",
                String::from_utf8_lossy(&entry.path_bytes())
            );
            continue;
        };
        let path = normalize_path(&path);
        let (parent, name) = path.rsplit_once('/').unwrap_or(("", &path));
        if name == ".wh..wh..opq" {
            changes.push((parent.to_owned(), LayerChange::OpaqueWhiteout));
            continue;
        }
        if let Some(removed) = name.strip_prefix(".wh.") {
            let removed = if parent.is_empty() {
                removed.to_owned()
            } else {
                format!("{parent}/{removed}")
            };
            changes.push((removed, LayerChange::Whiteout));
            continue;
        }
        let entry_type = entry.header().entry_type();
        let mode = || {
            let mode = entry.header().mode();
            mode.map(|mode| mode & 0o7777)
                .with_context(|| format!("invalid mode for {path}"))
        };
        let change = match entry_type {
            tar::EntryType::Directory => LayerChange::Node(RootfsNode::Dir { mode: mode()? }),
            tar::EntryType::Symlink | tar::EntryType::Link => {
                let target = entry
                    .link_name_bytes()
                    .with_context(|| format!("link entry {path} has no target"))?;
                let Ok(target) = String::from_utf8(target.into_owned()) else {
                    eprintln!("  warning: skipping {path}: its link target is not UTF-8");
                    continue;
                };
                if entry_type == tar::EntryType::Link {
                    LayerChange::HardLink(normalize_path(&target))
                } else {
                    LayerChange::Node(RootfsNode::Symlink { target })
                }
            }
            tar::EntryType::Regular | tar::EntryType::Continuous | tar::EntryType::GNUSparse => {
                let mode = mode()?;
                let mut data = Vec::new();
                entry
                    .read_to_end(&mut data)
                    .with_context(|| format!("failed to read {path}"))?;
                LayerChange::Node(RootfsNode::File(Arc::new(FileObject { data, mode })))
            }
            tar::EntryType::Fifo | tar::EntryType::Char | tar::EntryType::Block => {
                if verbose {
                    eprintln!("  [skip] {path}: unsupported entry type {entry_type:?}");
                }
                // The unpackaged node still replaces what lower layers have at the path.
                LayerChange::Whiteout
            }
            other => {
                if verbose {
                    eprintln!("  [skip] {path}: unsupported entry type {other:?}");
                }
                continue;
            }
        };
        changes.push((path, change));
    }
    Ok(changes)
}

/// Check if data starts with the gzip magic bytes.
fn is_gzip_data(data: &[u8]) -> bool {
    data.len() >= 2 && data[0] == 0x1f && data[1] == 0x8b
}

/// Normalize a `/`-separated path relative to the rootfs root without
/// consulting the rootfs: drop empty and `.` components, and resolve `..`
/// lexically, stopping at the root.
fn normalize_path(path: &str) -> String {
    let mut components = Vec::new();
    for component in path.split('/') {
        match component {
            "" | "." => {}
            ".." => {
                components.pop();
            }
            component => components.push(component),
        }
    }
    components.join("/")
}

#[cfg(test)]
mod tests {
    use super::*;

    const LAYER_MEDIA_TYPE: &str = "application/vnd.oci.image.layer.v1.tar";

    /// An entry of a test layer.
    enum Entry<'a> {
        /// An entry of another type, without data.
        Other(&'a str, tar::EntryType),
        Dir(&'a str, u32),
        File(&'a str, &'a [u8]),
        Symlink(&'a str, &'a str),
        HardLink(&'a str, &'a str),
    }

    fn layer(entries: &[Entry<'_>]) -> Vec<u8> {
        let mut builder = tar::Builder::new(Vec::new());
        for entry in entries {
            let mut header = tar::Header::new_gnu();
            header.set_size(0);
            match *entry {
                Entry::Dir(path, mode) => {
                    header.set_entry_type(tar::EntryType::Directory);
                    header.set_mode(mode);
                    builder.append_data(&mut header, path, std::io::empty())
                }
                Entry::File(path, data) => {
                    header.set_mode(0o755);
                    header.set_size(data.len() as u64);
                    builder.append_data(&mut header, path, data)
                }
                Entry::Symlink(path, target) => {
                    header.set_entry_type(tar::EntryType::Symlink);
                    builder.append_link(&mut header, path, target)
                }
                Entry::HardLink(path, target) => {
                    header.set_entry_type(tar::EntryType::Link);
                    builder.append_link(&mut header, path, target)
                }
                Entry::Other(path, entry_type) => {
                    header.set_entry_type(entry_type);
                    builder.append_data(&mut header, path, std::io::empty())
                }
            }
            .unwrap();
        }
        builder.into_inner().unwrap()
    }

    fn merge(layers: &[&[Entry<'_>]]) -> Rootfs {
        let mut rootfs = Rootfs::default();
        for entries in layers {
            rootfs
                .apply_layer(&layer(entries), LAYER_MEDIA_TYPE, false)
                .unwrap();
        }
        rootfs
    }

    /// Each node of `rootfs`, as a path and a description of the node.
    fn describe(rootfs: &Rootfs) -> Vec<(&str, String)> {
        rootfs
            .nodes
            .iter()
            .map(|(path, node)| {
                let description = match node {
                    RootfsNode::Dir { mode } => format!("dir {mode:o}"),
                    RootfsNode::File(file) => {
                        format!("file {}", String::from_utf8_lossy(&file.data))
                    }
                    RootfsNode::Symlink { target } => format!("symlink {target}"),
                };
                (path.as_str(), description)
            })
            .collect()
    }

    #[test]
    fn whiteouts_remove_paths_and_opaque_whiteouts_keep_this_layers_writes() {
        let mut rootfs = merge(&[
            &[
                Entry::File("a/lower", b"1"),
                Entry::File("b/c/d", b"2"),
                Entry::File("keep", b"3"),
            ],
            &[
                Entry::File("a/upper", b"4"),
                Entry::File("./b/new", b"5"),
                Entry::File("a/.wh..wh..opq", b""),
                Entry::File("b/.wh.c", b""),
                Entry::File(".wh.missing", b""),
            ],
        ]);
        assert_eq!(
            describe(&rootfs),
            [
                ("a", "dir 755".into()),
                ("a/upper", "file 4".into()),
                ("b", "dir 755".into()),
                ("b/new", "file 5".into()),
                ("keep", "file 3".into()),
            ]
        );

        let root_layer = layer(&[
            Entry::Dir("./", 0o700),
            Entry::File("b/newer", b"6"),
            Entry::File(".wh..wh..opq", b""),
        ]);
        rootfs
            .apply_layer(&root_layer, LAYER_MEDIA_TYPE, false)
            .unwrap();
        assert_eq!(
            describe(&rootfs),
            [("b", "dir 755".into()), ("b/newer", "file 6".into())]
        );
    }

    #[test]
    fn whiteouts_beneath_a_replaced_symlink_keep_its_target() {
        for target in ["usr/lib", "/"] {
            for whiteout in ["lib/.wh..wh..opq", "lib/.wh.libc.so"] {
                let rootfs = merge(&[
                    &[
                        Entry::File("etc/hosts", b"hosts"),
                        Entry::File("usr/lib/libc.so", b"libc"),
                        Entry::Symlink("lib", target),
                    ],
                    &[
                        Entry::Dir("lib", 0o755),
                        Entry::File(whiteout, b""),
                        Entry::File("lib/new", b"new"),
                    ],
                ]);
                assert_eq!(
                    describe(&rootfs),
                    [
                        ("etc", "dir 755".into()),
                        ("etc/hosts", "file hosts".into()),
                        ("lib", "dir 755".into()),
                        ("lib/new", "file new".into()),
                        ("usr", "dir 755".into()),
                        ("usr/lib", "dir 755".into()),
                        ("usr/lib/libc.so", "file libc".into()),
                    ],
                    "{target} {whiteout}"
                );
            }
        }
    }

    #[test]
    fn upper_entries_replace_or_merge_with_lower_ones() {
        let rootfs = merge(&[
            &[
                Entry::File("lib/libc.so", b"libc"),
                Entry::File("usr/bin/python3.12", b"elf"),
                Entry::Symlink("usr/bin/python3", "python3.12"),
                Entry::Dir("etc", 0o755),
                Entry::File("etc/conf/a", b"a"),
                Entry::File("dev/null", b"null"),
                Entry::File("dev/sda", b"sda"),
                Entry::File("run/fifo/a", b"a"),
                Entry::File("keep", b"keep"),
            ],
            &[
                Entry::Symlink("lib", "usr/lib"),
                Entry::Dir("usr/bin", 0o700),
                Entry::Symlink("usr/bin/python", "python3"),
                Entry::File("etc/conf", b"conf"),
                Entry::Other("dev/null", tar::EntryType::Char),
                Entry::Other("dev/sda", tar::EntryType::Block),
                Entry::Other("run/fifo", tar::EntryType::Fifo),
                Entry::Other("keep", tar::EntryType::XGlobalHeader),
            ],
        ]);
        assert_eq!(
            describe(&rootfs),
            [
                ("dev", "dir 755".into()),
                ("etc", "dir 755".into()),
                ("etc/conf", "file conf".into()),
                ("keep", "file keep".into()),
                ("lib", "symlink usr/lib".into()),
                ("run", "dir 755".into()),
                ("usr", "dir 755".into()),
                ("usr/bin", "dir 700".into()),
                ("usr/bin/python", "symlink python3".into()),
                ("usr/bin/python3", "symlink python3.12".into()),
                ("usr/bin/python3.12", "file elf".into()),
            ]
        );
    }

    #[test]
    fn hard_links_share_their_file() {
        let rootfs = merge(&[
            &[
                Entry::File("bin/a", b"old"),
                Entry::HardLink("bin/b", "bin/a"),
                Entry::HardLink("bin/c", "./bin/a"),
                Entry::Symlink("bin/s", "a"),
                Entry::HardLink("bin/t", "bin/s"),
                Entry::HardLink("bin/missing", "bin/nowhere"),
                // Archived before its target.
                Entry::HardLink("bin/early", "bin/late"),
                Entry::File("bin/late", b"late"),
            ],
            &[
                Entry::File("bin/a", b"new"),
                Entry::File("bin/.wh.c", b""),
                Entry::HardLink("bin/d", "bin/b"),
            ],
        ]);
        assert_eq!(
            describe(&rootfs),
            [
                ("bin", "dir 755".into()),
                ("bin/a", "file new".into()),
                ("bin/b", "file old".into()),
                ("bin/d", "file old".into()),
                ("bin/early", "file late".into()),
                ("bin/late", "file late".into()),
                ("bin/s", "symlink a".into()),
                ("bin/t", "symlink a".into()),
            ]
        );
        let [
            RootfsNode::File(b),
            RootfsNode::File(d),
            RootfsNode::File(early),
            RootfsNode::File(late),
        ] = ["bin/b", "bin/d", "bin/early", "bin/late"].map(|path| &rootfs.nodes[path])
        else {
            panic!("hard-linked names are not files");
        };
        assert!(Arc::ptr_eq(b, d) && Arc::ptr_eq(early, late));
    }

    #[test]
    fn parent_symlinks_resolve_within_the_rootfs() {
        let rootfs = merge(&[
            &[
                Entry::Dir("usr/lib", 0o755),
                Entry::Symlink("lib", "/usr/lib"),
                Entry::Symlink("usr/up", "../../.."),
                Entry::Symlink("loop", "loop"),
                Entry::File("file", b"file"),
            ],
            &[
                Entry::File("lib/libfoo.so", b"foo"),
                Entry::File("usr/up/etc/hosts", b"hosts"),
                Entry::HardLink("usr/lib/alias", "lib/libfoo.so"),
                Entry::File("loop/x", b"x"),
                Entry::File("file/x", b"x"),
            ],
            &[Entry::File("lib/.wh.alias", b"")],
        ]);
        assert_eq!(
            describe(&rootfs),
            [
                ("etc", "dir 755".into()),
                ("etc/hosts", "file hosts".into()),
                ("file", "file file".into()),
                ("lib", "symlink /usr/lib".into()),
                ("loop", "symlink loop".into()),
                ("usr", "dir 755".into()),
                ("usr/lib", "dir 755".into()),
                ("usr/lib/libfoo.so", "file foo".into()),
                ("usr/up", "symlink ../../..".into()),
            ]
        );
    }
}
