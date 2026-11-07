// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! The container's root archive, which the broker serves (`--fs-initial-files`), and the
//! symlinks that the guest service creates over it: the broker's tar file system holds regular
//! files only, implies directories from their paths, and owns `/` as root. Everything else is the
//! guest user's ([`GUEST_ID`]), which every guest process runs as.
//!
//! The image's paths are untrusted: they are read without following symlinks, beneath each
//! layer's root, and only regular files are read.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs::File;
use std::io::{self, BufWriter, Read};
use std::net::IpAddr;
use std::os::fd::OwnedFd;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};

use containerd_shim::protos::types::mount::Mount;
use rustix::fs::{AtFlags, FileType, Mode, OFlags};
use rustix::io::Errno;

use crate::spec::{Bind, SERVED_PATHS};
use crate::{Result, internal, invalid, unsupported};

/// The guest user and group, which own everything in the archive.
pub const GUEST_ID: u32 = 1000;
/// Where the archive holds the guest service, the broker's root process.
pub const GUEST_SERVICE_PATH: &str = "/.litebox/guest-service";
/// The file that keeps an otherwise empty directory in the archive.
const PLACEHOLDER: &str = ".litebox-empty-dir";
/// Top-level directories the broker creates itself, which need no placeholder.
const BROKER_DIRECTORIES: [&str; 2] = ["tmp", "registry"];
/// Bounds the symlinks followed while resolving one path, as Linux does.
const MAX_SYMLINKS: usize = 40;
/// Bounds how deep below its root an image's directories nest, and so [`RootFs::scan`]'s
/// recursion and the directories it holds open: far beyond real images.
const MAX_IMAGE_DEPTH: usize = 256;

/// The image of a container: the host directories of its layers, topmost first.
#[derive(Debug, PartialEq, Eq)]
pub struct Image {
    layers: Vec<PathBuf>,
    /// For an overlay, the xattr that marks an opaque directory.
    opaque_xattr: Option<&'static str>,
}

impl Image {
    /// The image of containerd's root file system mounts `rootfs`: none (the spec's `root`, in
    /// `bundle`), a bind of a directory, or an overlay, which is read as overlayfs merges it.
    pub fn new(bundle: &Path, root: &Path, rootfs: &[Mount]) -> Result<Self> {
        let mount = match rootfs {
            [] => {
                return Ok(Self {
                    layers: vec![bundle.join(root)],
                    opaque_xattr: None,
                });
            }
            [mount] => mount,
            _ => return Err(unsupported("more than one root file system mount")),
        };
        if mount.type_ == "bind" || mount.options.iter().any(|o| o == "bind" || o == "rbind") {
            let layers = vec![PathBuf::from(&mount.source)];
            return Ok(Self {
                layers,
                opaque_xattr: None,
            });
        }
        if mount.type_ != "overlay" {
            return Err(unsupported(format!(
                "{:?} root file system mounts",
                mount.type_
            )));
        }
        let (mut upper, mut lower, mut xattr) = (Vec::new(), Vec::new(), "trusted.overlay.opaque");
        for option in &mount.options {
            match option.split_once('=') {
                Some(("upperdir", value)) => upper = split_escaped(value),
                Some(("lowerdir", value)) => lower = split_escaped(value),
                _ if option == "userxattr" => xattr = "user.overlay.opaque",
                _ => {}
            }
        }
        let layers: Vec<PathBuf> = upper.into_iter().chain(lower).map(PathBuf::from).collect();
        if layers.is_empty() || layers.iter().any(|layer| !layer.is_absolute()) {
            return Err(invalid(
                "the overlay root file system mount needs absolute layers",
            ));
        }
        Ok(Self {
            layers,
            opaque_xattr: Some(xattr),
        })
    }
}

/// The paths of overlayfs's option `value`, separated by `:`, each `\` escaping what follows.
fn split_escaped(value: &str) -> Vec<String> {
    let mut paths = vec![String::new()];
    let mut characters = value.chars();
    while let Some(character) = characters.next() {
        let current = paths.last_mut().expect("never empty");
        match character {
            '\\' => current.extend(characters.next()),
            ':' => paths.push(String::new()),
            character => current.push(character),
        }
    }
    paths.retain(|path| !path.is_empty());
    paths
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Node {
    Directory,
    File { source: Source, mode: u32 },
    Symlink(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Source {
    /// The file at this path in this layer.
    Layer(usize, String),
    /// A host file, the operator's: a bind source or the guest service.
    Host(PathBuf),
    Data(Vec<u8>),
}

/// The guest's file system, by path relative to `/`.
#[derive(Debug, Default)]
pub struct RootFs {
    nodes: BTreeMap<String, Node>,
    layers: Vec<OwnedFd>,
    /// The directory binds, which the broker serves (`--mount`, or `--mount-ro` if read-only), at
    /// their resolved destinations: relative to `/` while `build` runs, absolute once it returns.
    pub binds: Vec<Bind>,
    /// The init process's working directory, resolved as runc resolves it.
    pub cwd: String,
    /// The guest's `/etc/passwd`, for `HOME`.
    pub passwd: Vec<u8>,
}

/// `parent/name`, relative.
fn join(parent: &str, name: &str) -> String {
    if parent.is_empty() {
        name.to_owned()
    } else {
        format!("{parent}/{name}")
    }
}

fn parent(path: &str) -> &str {
    path.rsplit_once('/').map_or("", |(parent, _)| parent)
}

fn is_at_or_below(path: &str, base: &str) -> bool {
    path.strip_prefix(base)
        .is_some_and(|rest| rest.is_empty() || rest.starts_with('/'))
}

fn components(path: &str) -> impl DoubleEndedIterator<Item = &str> {
    path.split('/')
        .filter(|component| !component.is_empty() && *component != ".")
}

/// The relative symlink target from the directory `from` to `to`.
fn relative_target(from: &str, to: &str) -> String {
    let (from, to): (Vec<&str>, Vec<&str>) = (components(from).collect(), components(to).collect());
    let common = from.iter().zip(&to).take_while(|(a, b)| a == b).count();
    let mut parts = vec![".."; from.len() - common];
    parts.extend_from_slice(&to[common..]);
    if parts.is_empty() {
        ".".to_owned()
    } else {
        parts.join("/")
    }
}

fn errno(what: &str) -> impl Fn(Errno) -> crate::ttrpc::Error + '_ {
    move |error| internal(format!("{what}: {error}"))
}

/// Opens the directory `name` in `directory`, never through a symlink.
fn open_directory(directory: &OwnedFd, name: &str) -> rustix::io::Result<OwnedFd> {
    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    rustix::fs::openat(directory, name, flags, Mode::empty())
}

impl RootFs {
    /// The guest's file system: `image`, the guest service, the spec's `binds`, and the working
    /// directory `cwd`, which is created as runc creates it, with the symlinks in `/` replaced
    /// (see [`RootFs::replace_root_symlinks`]).
    pub fn build(image: &Image, guest_service: &Path, binds: &[Bind], cwd: &str) -> Result<Self> {
        let mut fs = Self::default();
        let mut roots = Vec::new();
        for (index, layer) in image.layers.iter().enumerate() {
            let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC;
            let root = rustix::fs::open(layer, flags, Mode::empty()).map_err(errno(&format!(
                "cannot read the image layer {}",
                layer.display()
            )))?;
            roots.push((index, root));
        }
        fs.scan("", &roots, image.opaque_xattr)?;
        fs.layers = roots.into_iter().map(|(_, root)| root).collect();
        fs.remove_below(".litebox");
        fs.nodes.insert(".litebox".to_owned(), Node::Directory);
        let source = Source::Host(guest_service.to_owned());
        fs.nodes.insert(
            GUEST_SERVICE_PATH[1..].to_owned(),
            Node::File {
                source,
                mode: 0o755,
            },
        );
        for bind in binds {
            fs.bind(bind)?;
        }
        fs.cwd = fs.resolve(cwd, true)?;
        if fs.bind_above(&fs.cwd).is_none()
            && let Err(error) = fs.create_directories(&fs.cwd.clone())
        {
            log::warn!("cannot create the working directory: {error:?}");
        }
        fs.passwd = fs.read_passwd();
        fs.replace_root_symlinks();
        fs.cwd.insert(0, '/');
        for bind in &mut fs.binds {
            bind.destination.insert(0, '/');
        }
        Ok(fs)
    }

    /// The content of `/etc/passwd`, if it is a file.
    fn read_passwd(&self) -> Vec<u8> {
        let mut passwd = Vec::new();
        if let Ok(path) = self.resolve("/etc/passwd", true)
            && let Some(Node::File { source, .. }) = self.nodes.get(&path)
            && let Ok((mut file, ..)) = self.open(source)
        {
            let _ = file.read_to_end(&mut passwd);
        }
        passwd
    }

    /// Indexes the directory `path` of the image, and below it, from its parts `parts` in the
    /// layers, topmost first (see [`RootFs::index`]).
    fn scan(&mut self, path: &str, parts: &[(usize, OwnedFd)], opaque: Option<&str>) -> Result<()> {
        if components(path).count() > MAX_IMAGE_DEPTH {
            return Err(unsupported(format!(
                "the image's directories are nested deeper than {MAX_IMAGE_DEPTH} levels"
            )));
        }
        let failed = errno("cannot read the image");
        for (name, merged) in self.index(path, parts, opaque)? {
            let mut subparts = Vec::new();
            for part in merged {
                let (layer, directory) = &parts[part];
                let subdirectory = match open_directory(directory, &name) {
                    Err(Errno::ACCESS) => continue,
                    subdirectory => subdirectory.map_err(&failed)?,
                };
                let is_opaque = opaque.is_some_and(|xattr| {
                    let mut value = [0u8; 1];
                    rustix::fs::fgetxattr(&subdirectory, xattr, &mut value[..]) == Ok(1)
                        && value == *b"y"
                });
                subparts.push((*layer, subdirectory));
                if is_opaque {
                    break;
                }
            }
            self.scan(&join(path, &name), &subparts, opaque)?;
        }
        Ok(())
    }

    /// Indexes the entries of the directory `path` from its parts `parts`, as overlayfs merges
    /// them: the highest layer with a name decides what it is; a whiteout (a character device
    /// 0:0) hides it below; directories merge down to an opaque one, or to a non-directory.
    /// Returns the subdirectories, with the parts that merge them. Apart from [`RootFs::scan`]
    /// so that its recursion's frames stay small.
    fn index(
        &mut self,
        path: &str,
        parts: &[(usize, OwnedFd)],
        opaque: Option<&str>,
    ) -> Result<Vec<(String, Vec<usize>)>> {
        let failed = errno("cannot read the image");
        // By name: the parts below that a subdirectory merges, unless a non-directory ended it.
        let mut seen: HashMap<String, Option<(Vec<usize>, bool)>> = HashMap::new();
        let mut subdirectories = Vec::new();
        for (part, (layer, directory)) in parts.iter().enumerate() {
            let entries = match rustix::fs::Dir::read_from(directory) {
                Err(Errno::ACCESS) => continue,
                entries => entries.map_err(&failed)?,
            };
            for entry in entries {
                let entry = entry.map_err(&failed)?;
                let Ok(name) = entry.file_name().to_str() else {
                    continue;
                };
                if name == "." || name == ".." {
                    continue;
                }
                // What the broker serves itself, or LiteBox lacks, keeps none of the image's.
                if path.is_empty() && SERVED_PATHS.iter().any(|served| served[1..] == *name) {
                    self.nodes.insert(name.to_owned(), Node::Directory);
                    continue;
                }
                let status = match rustix::fs::statat(directory, name, AtFlags::SYMLINK_NOFOLLOW) {
                    Err(Errno::ACCESS) => continue,
                    status => status.map_err(&failed)?,
                };
                let file_type = FileType::from_raw_mode(status.st_mode);
                if let Some(decided) = seen.get_mut(name) {
                    if let Some((merged, ended)) = decided
                        && !*ended
                    {
                        if file_type == FileType::Directory {
                            merged.push(part);
                        } else {
                            *ended = true;
                        }
                    }
                    continue;
                }
                let child = join(path, name);
                let mut decided = None;
                match file_type {
                    FileType::CharacterDevice if opaque.is_some() && status.st_rdev == 0 => {}
                    FileType::Directory => {
                        self.nodes.insert(child, Node::Directory);
                        subdirectories.push(name.to_owned());
                        decided = Some((vec![part], false));
                    }
                    FileType::RegularFile => {
                        let source = Source::Layer(*layer, child.clone());
                        self.nodes.insert(
                            child,
                            Node::File {
                                source,
                                mode: status.st_mode & 0o777,
                            },
                        );
                    }
                    FileType::Symlink if name != PLACEHOLDER => {
                        let target =
                            rustix::fs::readlinkat(directory, name, Vec::new()).map_err(&failed)?;
                        if let Ok(target) = target.into_string() {
                            self.nodes.insert(child, Node::Symlink(target));
                        }
                    }
                    _ => {}
                }
                seen.insert(name.to_owned(), decided);
            }
        }
        let merged = subdirectories
            .into_iter()
            .filter_map(|name| match seen.remove(&name) {
                Some(Some((merged, _))) => Some((name, merged)),
                _ => None,
            });
        Ok(merged.collect())
    }

    /// Resolves the guest path `path` as runc resolves mount destinations: symlinks are followed
    /// in every component but the last (and in the last with `follow_last`), `..` is physical,
    /// and missing components stay as they are. Returns the path relative to `/`.
    fn resolve(&self, path: &str, follow_last: bool) -> Result<String> {
        let mut resolved: Vec<String> = Vec::new();
        let mut pending: Vec<String> = components(path).rev().map(str::to_owned).collect();
        let mut links = 0;
        while let Some(component) = pending.pop() {
            if component == ".." {
                resolved.pop();
                continue;
            }
            resolved.push(component);
            if let Some(Node::Symlink(target)) = self.nodes.get(&resolved.join("/"))
                && (follow_last || !pending.is_empty())
            {
                links += 1;
                if links > MAX_SYMLINKS {
                    return Err(invalid(format!("too many levels of symlinks in {path:?}")));
                }
                resolved.pop();
                if target.starts_with('/') {
                    resolved.clear();
                }
                pending.extend(components(target).rev().map(str::to_owned));
            }
        }
        Ok(resolved.join("/"))
    }

    /// The directory bind at or above the relative path `path`.
    fn bind_above(&self, path: &str) -> Option<&Bind> {
        self.binds
            .iter()
            .find(|bind| is_at_or_below(path, &bind.destination))
    }

    /// Creates the missing directories of the relative path `path`, as runc does.
    fn create_directories(&mut self, path: &str) -> Result<()> {
        let mut directory = String::new();
        for component in components(path) {
            directory = join(&directory, component);
            match self
                .nodes
                .entry(directory.clone())
                .or_insert(Node::Directory)
            {
                Node::Directory => {}
                _ => {
                    return Err(invalid(format!(
                        "{:?} is not a directory",
                        format!("/{directory}")
                    )));
                }
            }
        }
        Ok(())
    }

    fn remove_below(&mut self, path: &str) {
        self.nodes.retain(|key, _| !is_at_or_below(key, path));
    }

    /// Applies `bind`: a directory is served by the broker over what the image has there; a
    /// file is copied, `/etc/resolv.conf` rewritten (see [`rewrite_resolv_conf`]).
    fn bind(&mut self, bind: &Bind) -> Result<()> {
        let at = &bind.destination;
        let metadata = std::fs::metadata(&bind.source).map_err(|error| {
            invalid(format!(
                "cannot inspect the source of the bind at {at}: {error}"
            ))
        })?;
        let resolved = self.resolve(at, metadata.is_dir())?;
        let reserved = resolved.is_empty()
            || is_at_or_below(&resolved, ".litebox")
            || SERVED_PATHS
                .iter()
                .any(|served| is_at_or_below(&resolved, &served[1..]));
        // The broker serves a directory bind over everything below it, even a later bind above it.
        let overlaps = self.binds.iter().any(|bound| {
            is_at_or_below(&resolved, &bound.destination)
                || is_at_or_below(&bound.destination, &resolved)
        });
        if reserved || overlaps {
            return Err(unsupported(format!(
                "the bind at {at} resolves to {:?}, which is reserved or overlaps a directory bind",
                format!("/{resolved}")
            )));
        }
        if metadata.is_dir() {
            self.create_directories(&resolved)?;
            self.remove_below(&resolved);
            self.nodes.insert(resolved.clone(), Node::Directory);
            self.binds.push(Bind {
                destination: resolved,
                ..bind.clone()
            });
        } else if metadata.is_file() {
            if self.nodes.get(&resolved) == Some(&Node::Directory) {
                return Err(invalid(format!(
                    "the file bound at {at} would replace a directory"
                )));
            }
            self.create_directories(parent(&resolved))?;
            let resolv_conf = self.resolve("/etc/resolv.conf", false);
            let source = if resolv_conf.is_ok_and(|path| path == resolved) {
                let content = std::fs::read(&bind.source).map_err(|error| {
                    internal(format!("cannot read {}: {error}", bind.source.display()))
                })?;
                let fallback =
                    || std::fs::read("/run/systemd/resolve/resolv.conf").unwrap_or_default();
                Source::Data(rewrite_resolv_conf(&content, fallback))
            } else {
                Source::Host(bind.source.clone())
            };
            // A read-only bind's copy has no write permission.
            let mode = metadata.mode() & if bind.read_only { 0o555 } else { 0o777 };
            self.nodes.insert(resolved, Node::File { source, mode });
        } else {
            return Err(unsupported(format!(
                "the source of the bind at {at} is no directory nor regular file"
            )));
        }
        Ok(())
    }

    /// Replaces the image's symlinks in `/`, which the guest service cannot create there (`/` is
    /// root's). One whose target is a directory below `/` is reversed: `/bin -> usr/bin` becomes
    /// a directory `/bin` holding `usr/bin`, and `/usr/bin -> ../bin`. One whose target is
    /// something else becomes a copy of it; one that resolves to nothing is left out. Links named
    /// after their target's last component go first.
    // TODO: drop this once the broker serves symlinks from the archive.
    fn replace_root_symlinks(&mut self) {
        let mut links: Vec<(String, String)> = self
            .nodes
            .iter()
            .filter_map(|(path, node)| match node {
                Node::Symlink(target) if !path.contains('/') => {
                    Some((path.clone(), target.clone()))
                }
                _ => None,
            })
            .collect();
        links.sort_by_key(|(link, target)| target.rsplit('/').next() != Some(link.as_str()));
        for (link, _) in links {
            let resolved = self.resolve(&link, true);
            self.nodes.remove(&link);
            let Ok(target) = resolved else { continue };
            let reversible = target.contains('/') && !is_at_or_below(&target, ".litebox");
            let movable = !target.is_empty()
                && self.bind_above(&target).is_none()
                && !BROKER_DIRECTORIES
                    .iter()
                    .any(|directory| is_at_or_below(&target, directory));
            match self.nodes.get(&target) {
                Some(Node::Directory) if movable && reversible => {
                    self.relocate(&target, &link, true);
                    let back = relative_target(parent(&target), &link);
                    self.nodes.insert(target.clone(), Node::Symlink(back));
                    log::info!("reversed {link:?} -> {target:?}");
                }
                Some(Node::Directory | Node::File { .. }) if movable => {
                    self.relocate(&target, &link, false);
                    log::info!("copied {target:?} to {link:?}");
                }
                _ => log::info!("left {link:?} out: it names nothing the guest can have"),
            }
        }
    }

    /// Moves (or copies) everything at and below `from` to `to`, the working directory (or not)
    /// and the directory binds (or copies of them) included, rewriting the relative symlinks that
    /// lead out of `from`, so that they name what they named. Paths are read lexically.
    fn relocate(&mut self, from: &str, to: &str, remove: bool) {
        let moved = |path: &str| format!("{to}{}", &path[from.len()..]);
        if remove && is_at_or_below(&self.cwd, from) {
            self.cwd = moved(&self.cwd);
        }
        for index in 0..self.binds.len() {
            let bind = &self.binds[index];
            if is_at_or_below(&bind.destination, from) {
                let bind = Bind {
                    destination: moved(&bind.destination),
                    ..bind.clone()
                };
                if remove {
                    self.binds[index] = bind;
                } else {
                    self.binds.push(bind);
                }
            }
        }
        let depth = components(from).count();
        let entries: Vec<(String, Node)> = self
            .nodes
            .iter()
            .filter(|(path, _)| is_at_or_below(path, from))
            .map(|(path, node)| (path.clone(), node.clone()))
            .collect();
        for (path, mut node) in entries {
            let new_path = moved(&path);
            if let Node::Symlink(target) = &mut node
                && !target.starts_with('/')
            {
                let mut named: Vec<&str> = components(parent(&path)).collect();
                let mut escapes = false;
                for component in components(target) {
                    if component == ".." {
                        named.pop();
                        escapes |= named.len() < depth;
                    } else {
                        named.push(component);
                    }
                }
                if escapes {
                    *target = relative_target(parent(&new_path), &named.join("/"));
                }
            }
            if remove {
                self.nodes.remove(&path);
            }
            self.nodes.insert(new_path, node);
        }
    }

    /// The symlinks for the guest service to create, parents first: absolute path, target.
    // TODO: write them to the archive once the broker serves symlinks from it.
    pub fn symlinks(&self) -> Vec<(String, String)> {
        self.nodes
            .iter()
            .filter_map(|(path, node)| match node {
                Node::Symlink(target) => Some((format!("/{path}"), target.clone())),
                _ => None,
            })
            .collect()
    }

    /// Opens a file's content: an image file beneath its layer's root, never through a symlink,
    /// and only if it is a regular file. Returns it with its size and modification time.
    fn open<'a>(&'a self, source: &'a Source) -> io::Result<(Box<dyn Read + 'a>, u64, i64)> {
        let file = match source {
            Source::Data(data) => return Ok((Box::new(data.as_slice()), data.len() as u64, 0)),
            Source::Host(path) => File::open(path)?,
            Source::Layer(layer, path) => {
                let (parents, name) = path.rsplit_once('/').unwrap_or(("", path));
                let mut directory = None;
                for component in components(parents) {
                    let flags =
                        OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
                    let at = directory.as_ref().unwrap_or(&self.layers[*layer]);
                    directory = Some(rustix::fs::openat(at, component, flags, Mode::empty())?);
                }
                let flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC;
                let at = directory.as_ref().unwrap_or(&self.layers[*layer]);
                File::from(rustix::fs::openat(at, name, flags, Mode::empty())?)
            }
        };
        let metadata = file.metadata()?;
        if !metadata.is_file() {
            return Err(io::Error::other("not a regular file"));
        }
        Ok((Box::new(file), metadata.len(), metadata.mtime()))
    }

    /// Writes the archive to `output`: every regular file (owned by [`GUEST_ID`]) whose path
    /// ustar can hold, and a placeholder in each directory that would otherwise hold none.
    pub fn write_archive(&self, output: &Path) -> Result<()> {
        let failed =
            |error: io::Error| internal(format!("cannot write {}: {error}", output.display()));
        let file = File::create(output).map_err(failed)?;
        let mut builder = tar::Builder::new(BufWriter::new(file));
        let mut filled: HashSet<&str> = HashSet::new();
        let mut left_out = 0;
        for (path, node) in &self.nodes {
            let Node::File { source, mode } = node else {
                continue;
            };
            let (content, size, mtime) = match self.open(source) {
                Ok(opened) => opened,
                Err(error) => {
                    log::warn!("left {path:?} out of the root archive: {error}");
                    continue;
                }
            };
            if append(&mut builder, path, *mode, content, (size, mtime)).map_err(failed)? {
                filled.extend(path.match_indices('/').map(|(index, _)| &path[..index]));
            } else {
                left_out += 1;
            }
        }
        // Children come before their parents in reverse order.
        for (path, node) in self.nodes.iter().rev() {
            if *node != Node::Directory
                || filled.contains(path.as_str())
                || BROKER_DIRECTORIES.contains(&path.as_str())
            {
                continue;
            }
            let placeholder = join(path, PLACEHOLDER);
            let content = Box::new(io::empty());
            if append(&mut builder, &placeholder, 0o644, content, (0, 0)).map_err(failed)? {
                filled.insert(path);
                filled.extend(path.match_indices('/').map(|(index, _)| &path[..index]));
            } else {
                left_out += 1;
            }
        }
        if left_out > 0 {
            log::warn!("left {left_out} paths that ustar cannot hold out of the root archive");
        }
        let writer = builder.into_inner().map_err(failed)?;
        writer
            .into_inner()
            .map_err(io::IntoInnerError::into_error)
            .map_err(failed)?;
        Ok(())
    }
}

/// Appends a regular file of exactly `size` bytes of `content` (so that a file that changed
/// cannot corrupt the archive); `false` if ustar cannot hold `path`.
fn append(
    builder: &mut tar::Builder<BufWriter<File>>,
    path: &str,
    mode: u32,
    content: Box<dyn Read + '_>,
    (size, mtime): (u64, i64),
) -> io::Result<bool> {
    let mut header = tar::Header::new_ustar();
    if header.set_path(path).is_err() {
        return Ok(false);
    }
    header.set_mode(mode);
    header.set_uid(u64::from(GUEST_ID));
    header.set_gid(u64::from(GUEST_ID));
    header.set_size(size);
    header.set_mtime(u64::try_from(mtime).unwrap_or(0));
    header.set_cksum();
    builder.append(&header, content.take(size).chain(io::repeat(0)).take(size))?;
    Ok(true)
}

/// The home directory of `uid` in `passwd`, or `/`.
pub fn home(passwd: &[u8], uid: u32) -> String {
    String::from_utf8_lossy(passwd)
        .lines()
        .map(|line| line.split(':').collect::<Vec<_>>())
        .find(|fields| fields.get(2).and_then(|field| field.parse().ok()) == Some(uid))
        .map_or_else(
            || "/".to_owned(),
            |fields| fields.get(5).copied().unwrap_or_default().to_owned(),
        )
}

/// The guest's copy of a bound `resolv.conf`: without the loopback and unspecified nameservers,
/// which would be the broker's own; with those of `fallback` (systemd-resolved's list) if none is
/// left; and with options for glibc: TCP, since LiteBox refuses `IP_RECVERR`, which glibc's UDP
/// needs, and no IPv6, which guests lack.
// TODO: drop the options once LiteBox's guest sockets take `IP_RECVERR` and have IPv6.
fn rewrite_resolv_conf(content: &[u8], fallback: impl FnOnce() -> Vec<u8>) -> Vec<u8> {
    let nameserver = |line: &str| -> Option<IpAddr> {
        let mut words = line.split_whitespace();
        (words.next()? == "nameserver").then_some(())?;
        words.next()?.split('%').next()?.parse().ok()
    };
    let reachable = |ip: IpAddr| !ip.is_loopback() && !ip.is_unspecified();
    let mut rewritten = String::new();
    let mut kept = 0;
    for line in String::from_utf8_lossy(content).lines() {
        match nameserver(line) {
            Some(ip) if !reachable(ip) => continue,
            // glibc and musl read only the lines that start with the keyword, and musl only those
            // that its 256-byte buffer holds whole.
            Some(_) if line.starts_with("nameserver") && line.len() < 255 => kept += 1,
            _ => {}
        }
        rewritten.push_str(line);
        rewritten.push('\n');
    }
    if kept == 0 {
        for line in String::from_utf8_lossy(&fallback()).lines() {
            if nameserver(line).is_some_and(reachable) {
                rewritten.push_str(line.trim());
                rewritten.push('\n');
            }
        }
    }
    rewritten.push_str(
        "# Added by the LiteBox shim: TCP and IPv4 only, for glibc.\noptions use-vc no-aaaa\n",
    );
    rewritten.into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn files(root: &Path, paths: &[&str]) {
        for path in paths {
            std::fs::create_dir_all(root.join(path).parent().unwrap()).unwrap();
            std::fs::write(root.join(path), path).unwrap();
        }
    }

    fn paths(fs: &RootFs) -> Vec<&str> {
        fs.nodes
            .keys()
            .map(String::as_str)
            .filter(|path| !path.starts_with(".litebox"))
            .collect()
    }

    #[test]
    fn overlay_layers_merge_as_overlayfs_merges_them() {
        let dir = tempfile::tempdir().unwrap();
        let (upper, lower) = (dir.path().join("upper"), dir.path().join("lower"));
        files(
            &lower,
            &[
                "a/kept", "a/hidden", "b/file", "c/file", "e/old", "dev/null",
            ],
        );
        files(&upper, &["a/new", "b", "e/new"]);
        let whiteout = rustix::fs::mknodat(
            rustix::fs::CWD,
            upper.join("a/hidden"),
            FileType::CharacterDevice,
            Mode::empty(),
            0,
        );
        let opaque = rustix::fs::setxattr(
            upper.join("e"),
            "user.overlay.opaque",
            b"y",
            rustix::fs::XattrFlags::empty(),
        );
        if whiteout.is_err() || opaque.is_err() {
            eprintln!("skipped: unprivileged whiteouts or user xattrs are not supported here");
            return;
        }
        let mount = Mount {
            type_: "overlay".to_owned(),
            options: vec![
                "userxattr".to_owned(),
                format!("upperdir={}", upper.display()),
                format!("lowerdir={}", lower.display()),
            ],
            ..Default::default()
        };
        let image = Image::new(dir.path(), Path::new("rootfs"), &[mount]).unwrap();
        let fs = RootFs::build(&image, Path::new("/dev/null"), &[], "/").unwrap();
        // A whiteout hides, a non-directory ends the merge, an opaque directory hides what is
        // below it, and `/dev` is the broker's.
        let merged = [
            "a", "a/kept", "a/new", "b", "c", "c/file", "dev", "e", "e/new",
        ];
        assert_eq!(paths(&fs), merged);
        assert!(matches!(
            &fs.nodes["a/kept"],
            Node::File {
                source: Source::Layer(1, _),
                ..
            }
        ));
    }

    #[test]
    fn symlinks_in_root_are_reversed_copied_or_left_out() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("rootfs");
        files(&root, &["usr/bin/tool", "usr/lib/x", "usr/new/f"]);
        for (link, target) in [
            ("bin", "usr/bin"),
            ("sbin", "/usr/bin"),
            ("lib", "usr/lib"),
            ("etc", "usr/etc"),
            ("gone", "nowhere"),
            ("usr/bin/rel", "../lib/x"),
            ("usr/bin/local", "tool"),
        ] {
            std::os::unix::fs::symlink(target, root.join(link)).unwrap();
        }
        let image = Image::new(dir.path(), Path::new("rootfs"), &[]).unwrap();
        let bind = |source: PathBuf, destination: &str| Bind {
            source,
            destination: destination.to_owned(),
            read_only: false,
        };
        std::fs::write(dir.path().join("resolv"), "nameserver 192.0.2.1\n").unwrap();
        let binds = [
            Bind {
                read_only: true,
                ..bind(dir.path().to_owned(), "/usr/bin/data")
            },
            // The guest's `/etc/resolv.conf`, through `/etc -> usr/etc`: rewritten.
            bind(dir.path().join("resolv"), "/usr/etc/resolv.conf"),
        ];
        let fs = RootFs::build(&image, Path::new("/dev/null"), &binds, "/bin/../new").unwrap();
        let link = |path: &str| match &fs.nodes[path] {
            Node::Symlink(target) => target.clone(),
            node => panic!("{path} is {node:?}"),
        };
        assert_eq!(link("usr/bin"), "../bin");
        assert_eq!(link("usr/lib"), "../lib");
        // What led out of the moved directory still names what it named.
        assert_eq!(link("bin/rel"), "../usr/lib/x");
        assert_eq!(link("bin/local"), "tool");
        // `/sbin` names a directory that `/bin` took: a copy.
        assert_eq!(link("sbin/local"), "tool");
        assert!(matches!(fs.nodes["sbin/tool"], Node::File { .. }));
        // A directory bind moves with its tree, and is copied with it, read-only as it was.
        let destinations: Vec<(&str, bool)> = fs
            .binds
            .iter()
            .map(|bind| (bind.destination.as_str(), bind.read_only))
            .collect();
        assert_eq!(destinations, [("/bin/data", true), ("/sbin/data", true)]);
        assert!(!fs.nodes.contains_key("gone"));
        assert!(matches!(
            &fs.nodes["etc/resolv.conf"],
            Node::File {
                source: Source::Data(_),
                ..
            }
        ));
        // `..` is physical, in the image.
        assert_eq!(fs.cwd, "/usr/new");
        assert!(
            fs.symlinks()
                .contains(&("/usr/bin".to_owned(), "../bin".to_owned()))
        );
    }

    #[test]
    fn an_image_nested_too_deep_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let deepest = dir.path().join("rootfs").join("d/".repeat(MAX_IMAGE_DEPTH));
        std::fs::create_dir_all(&deepest).unwrap();
        let image = Image::new(dir.path(), Path::new("rootfs"), &[]).unwrap();
        RootFs::build(&image, Path::new("/dev/null"), &[], "/").unwrap();
        std::fs::create_dir(deepest.join("d")).unwrap();
        let Err(crate::ttrpc::Error::RpcStatus(status)) =
            RootFs::build(&image, Path::new("/dev/null"), &[], "/")
        else {
            panic!("an image nested too deep was built");
        };
        assert_eq!(status.code(), crate::ttrpc::Code::UNIMPLEMENTED);
        let expected = format!("deeper than {MAX_IMAGE_DEPTH} levels");
        assert!(status.message.contains(&expected), "{status:?}");
    }

    #[test]
    fn a_resolv_conf_loses_its_loopback_nameservers() {
        let options =
            "# Added by the LiteBox shim: TCP and IPv4 only, for glibc.\noptions use-vc no-aaaa\n";
        let kept = rewrite_resolv_conf(
            b"search x\nnameserver 127.0.0.53\nnameserver 192.0.2.1\n",
            || unreachable!(),
        );
        assert_eq!(
            String::from_utf8(kept).unwrap(),
            format!("search x\nnameserver 192.0.2.1\n{options}")
        );
        // Without any left, systemd-resolved's.
        let fallback = || b"nameserver ::1\nnameserver 192.0.2.2 # upstream\n".to_vec();
        let replaced = rewrite_resolv_conf(b"nameserver 0.0.0.0", fallback);
        assert_eq!(
            String::from_utf8(replaced).unwrap(),
            format!("nameserver 192.0.2.2 # upstream\n{options}")
        );
        // Lines that guests' resolvers ignore leave none either.
        let long = format!("nameserver 192.0.2.1 #{}", "x".repeat(240));
        for ignored in [" nameserver 192.0.2.1", long.as_str()] {
            let replaced = rewrite_resolv_conf(format!("{ignored}\n").as_bytes(), fallback);
            assert_eq!(
                String::from_utf8(replaced).unwrap(),
                format!("{ignored}\nnameserver 192.0.2.2 # upstream\n{options}")
            );
        }
    }
}
