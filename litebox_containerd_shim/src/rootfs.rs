// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Repackages an image for the broker, assigning ownership to the fixed guest user ([`GUEST_ID`]).
//! Windows requires a tar to preserve Linux metadata. On Unix, directory images are read beneath
//! their root without following host symlinks.

use std::collections::{BTreeMap, HashMap};
use std::fs::File;
use std::io::{self, BufWriter, Read, Write};
use std::net::IpAddr;
#[cfg(unix)]
use std::os::fd::OwnedFd;
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
use std::path::{Path, PathBuf};

#[cfg(unix)]
use rustix::fs::{AtFlags, FileType, Mode, OFlags};
#[cfg(unix)]
use rustix::io::Errno;
use tar_core::EntryType;
use tar_core::builder::EntryBuilder;

use crate::spec::{Bind, SERVED_PATHS};
use crate::{Result, internal, invalid, unsupported};

/// The guest user and group, which own everything in the archive.
pub const GUEST_ID: u32 = 1000;
/// Where the archive holds the guest service, the broker's root process.
pub const GUEST_SERVICE_PATH: &str = "/.litebox/guest-service";
/// A directory the shim creates, with the mode runc's `MkdirAll` gives it.
const NEW_DIRECTORY: Node = Node::Directory { mode: 0o755 };
/// Bounds the symlinks followed while resolving one path, as Linux does.
const MAX_SYMLINKS: usize = 40;
/// Caps open directories during traversal and parent paths created per tar entry.
const MAX_IMAGE_DEPTH: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq)]
enum Node {
    Directory { mode: u32 },
    File { source: Source, mode: u32 },
    Symlink(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Source {
    /// The file at this path in the image.
    #[cfg(unix)]
    Image(String),
    Archive {
        offset: u64,
        size: u64,
    },
    /// A host file, the operator's: a bind source or the guest service.
    Host(PathBuf),
    Data(Vec<u8>),
}

#[derive(Debug)]
enum Image {
    #[cfg(unix)]
    Directory(OwnedFd),
    Archive(File),
}

#[cfg(unix)]
fn host_mode(metadata: &std::fs::Metadata) -> u32 {
    metadata.mode()
}

/// Host files on Windows have no execute bit to preserve.
#[cfg(windows)]
fn host_mode(metadata: &std::fs::Metadata) -> u32 {
    if metadata.permissions().readonly() {
        0o555
    } else {
        0o755
    }
}

/// The guest's file system, by path relative to `/`.
#[derive(Debug)]
pub struct RootFs {
    nodes: BTreeMap<String, Node>,
    image: Image,
    /// The directory binds, read-only, which the broker serves (`--mount-ro`), at their resolved
    /// destinations: relative to `/` while `build` runs, absolute once it returns.
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

fn check_depth(path: &str) -> Result<()> {
    if components(path).count() > MAX_IMAGE_DEPTH {
        return Err(unsupported(format!(
            "the image's directories are nested deeper than {MAX_IMAGE_DEPTH} levels"
        )));
    }
    Ok(())
}

#[cfg(unix)]
fn errno(what: &str) -> impl Fn(Errno) -> crate::ttrpc::Error + '_ {
    move |error| internal(format!("{what}: {error}"))
}

/// Opens the directory `name` in `directory`, never through a symlink.
#[cfg(unix)]
fn open_directory(directory: &OwnedFd, name: &str) -> rustix::io::Result<OwnedFd> {
    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    rustix::fs::openat(directory, name, flags, Mode::empty())
}

/// Indexes the image's directory `directory`, at `path`, and below it.
#[cfg(unix)]
fn scan(nodes: &mut BTreeMap<String, Node>, path: &str, directory: &OwnedFd) -> Result<()> {
    check_depth(path)?;
    let failed = errno("cannot read the image");
    let entries = match rustix::fs::Dir::read_from(directory) {
        Err(Errno::ACCESS) => return Ok(()),
        entries => entries.map_err(&failed)?,
    };
    let mut subdirectories = Vec::new();
    for entry in entries {
        let entry = entry.map_err(&failed)?;
        let Ok(name) = entry.file_name().to_str() else {
            continue;
        };
        if name == "." || name == ".." {
            continue;
        }
        let child = join(path, name);
        // What the broker serves itself, or LiteBox lacks, keeps none of the image's.
        if path.is_empty() && SERVED_PATHS.iter().any(|served| served[1..] == *name) {
            nodes.insert(child, NEW_DIRECTORY);
            continue;
        }
        let status = match rustix::fs::statat(directory, name, AtFlags::SYMLINK_NOFOLLOW) {
            Err(Errno::ACCESS) => continue,
            status => status.map_err(&failed)?,
        };
        match FileType::from_raw_mode(status.st_mode) {
            FileType::Directory => {
                // The guest user owns everything and stands in for the image's root, which runc
                // does not hold to the owner bits: RHEL-family images ship `/root` 0550 and
                // `/usr/bin` 0555.
                let mode = (status.st_mode & 0o777) | 0o700;
                nodes.insert(child, Node::Directory { mode });
                subdirectories.push(name.to_owned());
            }
            FileType::RegularFile => {
                let mode = status.st_mode & 0o777;
                let source = Source::Image(child.clone());
                nodes.insert(child, Node::File { source, mode });
            }
            FileType::Symlink => {
                let target =
                    rustix::fs::readlinkat(directory, name, Vec::new()).map_err(&failed)?;
                if let Ok(target) = target.into_string() {
                    nodes.insert(child, Node::Symlink(target));
                }
            }
            _ => {}
        }
    }
    // With the entries closed: the recursion holds one directory per level.
    for name in subdirectories {
        let subdirectory = match open_directory(directory, &name) {
            Err(Errno::ACCESS) => continue,
            subdirectory => subdirectory.map_err(&failed)?,
        };
        scan(nodes, &join(path, &name), &subdirectory)?;
    }
    Ok(())
}

fn open_image(path: &Path, nodes: &mut BTreeMap<String, Node>) -> Result<Image> {
    #[cfg(unix)]
    if std::fs::metadata(path)
        .map_err(|error| internal(format!("cannot read the image {}: {error}", path.display())))?
        .is_dir()
    {
        return open_image_directory(path, nodes);
    }
    let archive = open_archive(path)?;
    scan_archive(nodes, &archive)?;
    Ok(Image::Archive(archive))
}

fn open_archive(path: &Path) -> Result<File> {
    let failed =
        |error: io::Error| internal(format!("cannot read the image {}: {error}", path.display()));
    let archive = open_host(path).map_err(failed)?;
    let metadata = archive.metadata().map_err(failed)?;
    #[cfg(windows)]
    if metadata.is_dir() {
        return Err(unsupported(format!(
            "the image {} is a directory, whose files lost their Linux modes and symlinks on \
             Windows: use a tar archive of the image instead",
            path.display()
        )));
    }
    if !metadata.is_file() {
        return Err(failed(io::Error::other("not a regular file")));
    }
    Ok(archive)
}

/// For a path the spec names: it never waits for a FIFO's writer (Unix), nor lets a pipe server
/// impersonate the shim (Windows).
fn open_host(path: &Path) -> io::Result<File> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::custom_flags(&mut options, libc::O_NONBLOCK);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt as _;
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_FLAG_BACKUP_SEMANTICS, SECURITY_IDENTIFICATION,
        };
        options
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
            .security_qos_flags(SECURITY_IDENTIFICATION);
    }
    options.open(path)
}

fn host_metadata(path: &Path) -> io::Result<std::fs::Metadata> {
    #[cfg(unix)]
    return std::fs::metadata(path);
    #[cfg(windows)]
    return open_host(path)?.metadata();
}

#[cfg(unix)]
fn open_image_directory(path: &Path, nodes: &mut BTreeMap<String, Node>) -> Result<Image> {
    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC;
    let directory = rustix::fs::open(path, flags, Mode::empty())
        .map_err(errno(&format!("cannot read the image {}", path.display())))?;
    scan(nodes, "", &directory)?;
    Ok(Image::Directory(directory))
}

fn unreadable(error: impl std::fmt::Display) -> crate::ttrpc::Error {
    internal(format!("cannot read the image's archive: {error}"))
}

/// Does not follow symlink parents or resolve forward hard links.
fn scan_archive(nodes: &mut BTreeMap<String, Node>, archive: &File) -> Result<()> {
    // The tar crate ends quietly where a truncated archive ends.
    let length = archive.metadata().map_err(unreadable)?.len();
    let mut entries = tar::Archive::new(archive);
    for entry in entries.entries_with_seek().map_err(unreadable)? {
        add(nodes, &entry.map_err(unreadable)?, length)?;
    }
    Ok(())
}

fn add(
    nodes: &mut BTreeMap<String, Node>,
    entry: &tar::Entry<'_, impl Read>,
    length: u64,
) -> Result<()> {
    let raw = entry.path_bytes();
    let Some(path) = std::str::from_utf8(&raw).ok().and_then(normalize) else {
        let raw = String::from_utf8_lossy(&raw);
        log::warn!("left {raw:?} out of the root archive: it is not UTF-8, or leaves the root");
        return Ok(());
    };
    let Some(top) = components(&path).next() else {
        return Ok(());
    };
    if SERVED_PATHS.iter().any(|served| served[1..] == *top) {
        nodes.insert(top.to_owned(), NEW_DIRECTORY);
        return Ok(());
    }
    let header = entry.header();
    let directory = if header.entry_type().is_dir() {
        path.as_str()
    } else {
        parent(&path)
    };
    check_depth(directory)?;
    let mode = header.mode().map_err(unreadable)? & 0o777;
    let link_name = || {
        let name = entry.link_name_bytes()?.into_owned();
        String::from_utf8(name).ok()
    };
    let node = match header.entry_type() {
        // The unprivileged guest user needs to traverse directories owned by root in the image.
        tar::EntryType::Directory => Ok(Node::Directory { mode: mode | 0o700 }),
        tar::EntryType::Regular | tar::EntryType::Continuous => {
            let (offset, size) = (entry.raw_file_position(), entry.size());
            // A PAX header sets `size` to any `u64`.
            if offset.checked_add(size).is_none_or(|end| end > length) {
                return Err(unreadable("it is truncated"));
            }
            let source = Source::Archive { offset, size };
            Ok(Node::File { source, mode })
        }
        tar::EntryType::Symlink => link_name()
            .map(Node::Symlink)
            .ok_or_else(|| "its target is not UTF-8".to_owned()),
        tar::EntryType::Link => link_name()
            .as_deref()
            .and_then(normalize)
            .and_then(|target| nodes.get(&target))
            .filter(|node| matches!(node, Node::File { .. } | Node::Symlink(_)))
            .cloned()
            .ok_or_else(|| "it links to no earlier file".to_owned()),
        tar::EntryType::XGlobalHeader => return Ok(()),
        other => Err(format!("it is a {other:?} entry")),
    };
    match node {
        Ok(node) if create_parents(nodes, &path) => {
            let replaces_directory = matches!(nodes.get(&path), Some(Node::Directory { .. }));
            if replaces_directory && !matches!(node, Node::Directory { .. }) {
                nodes.retain(|key, _| !is_at_or_below(key, &path));
            }
            nodes.insert(path, node);
        }
        Ok(_) => {}
        Err(why) => {
            // Unsupported entries still shadow earlier entries.
            log::warn!("left {path:?} out of the root archive: {why}");
            nodes.retain(|key, _| !is_at_or_below(key, &path));
        }
    }
    Ok(())
}

fn create_parents(nodes: &mut BTreeMap<String, Node>, path: &str) -> bool {
    let mut directory = String::new();
    for component in components(parent(path)) {
        directory = join(&directory, component);
        if !matches!(
            nodes.entry(directory.clone()).or_insert(NEW_DIRECTORY),
            Node::Directory { .. }
        ) {
            log::warn!("left {path:?} out of the root archive: {directory:?} is no directory");
            return false;
        }
    }
    true
}

fn normalize(path: &str) -> Option<String> {
    let mut normalized: Vec<&str> = Vec::new();
    for component in components(path) {
        if component == ".." {
            return None;
        }
        normalized.push(component);
    }
    Some(normalized.join("/"))
}

fn read_at(file: &File, buffer: &mut [u8], offset: u64) -> io::Result<usize> {
    #[cfg(unix)]
    return std::os::unix::fs::FileExt::read_at(file, buffer, offset);
    #[cfg(windows)]
    return std::os::windows::fs::FileExt::seek_read(file, buffer, offset);
}

struct Slice<'file> {
    file: &'file File,
    offset: u64,
    left: u64,
}

impl Read for Slice<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let length = usize::try_from(self.left).map_or(buffer.len(), |left| left.min(buffer.len()));
        if length == 0 {
            return Ok(0);
        }
        let read = read_at(self.file, &mut buffer[..length], self.offset)?;
        self.offset += read as u64;
        self.left -= read as u64;
        Ok(read)
    }
}

impl RootFs {
    /// `cwd` is created as runc creates it.
    pub fn build(image: &Path, guest_service: &Path, binds: &[Bind], cwd: &str) -> Result<Self> {
        let mut nodes = BTreeMap::new();
        let image = open_image(image, &mut nodes)?;
        let mut fs = Self {
            nodes,
            image,
            binds: Vec::new(),
            cwd: String::new(),
            passwd: Vec::new(),
        };
        fs.remove_below(".litebox");
        fs.nodes.insert(".litebox".to_owned(), NEW_DIRECTORY);
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

    /// Resolves the guest path `path`: symlinks are followed in every component but the last (and
    /// in the last with `follow_last`), `..` is physical, and missing components stay as they are.
    /// Returns the path relative to `/`.
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
            match self.nodes.entry(directory.clone()).or_insert(NEW_DIRECTORY) {
                Node::Directory { .. } => {}
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
    /// file is copied, `/etc/resolv.conf` rewritten (see [`rewrite_resolv_conf`]). A directory
    /// bind follows a symlink at its destination, as runc does; a file bind replaces it instead,
    /// deliberately: the image does not choose where a host file lands, and reading the old path
    /// still gives the bound content.
    fn bind(&mut self, bind: &Bind) -> Result<()> {
        let at = &bind.destination;
        let metadata = host_metadata(&bind.source).map_err(|error| {
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
        let overlaps = self.binds.iter().any(|bound| {
            is_at_or_below(&resolved, &bound.destination)
                || is_at_or_below(&bound.destination, &resolved)
        });
        if reserved || overlaps {
            // TODO: nest binds in directory binds once the broker can: it serves a directory bind
            // over everything below it, even a later bind above it.
            let why = if reserved {
                "is reserved"
            } else {
                "overlaps a directory bind, which is not supported yet"
            };
            return Err(unsupported(format!(
                "the bind at {at} resolves to {:?}, which {why}",
                format!("/{resolved}")
            )));
        }
        if metadata.is_dir() {
            // TODO: serve writable ones once the broker's `LocalFs` is confined to its root: a guest
            // that renames entries within a writable bind can make it follow a host symlink.
            if !bind.read_only {
                return Err(unsupported(format!(
                    "the writable directory bind at {at} is not supported yet: bind it read-only"
                )));
            }
            self.create_directories(&resolved)?;
            self.remove_below(&resolved);
            self.nodes.insert(resolved.clone(), NEW_DIRECTORY);
            self.binds.push(Bind {
                destination: resolved,
                ..bind.clone()
            });
        } else if metadata.is_file() {
            if matches!(self.nodes.get(&resolved), Some(Node::Directory { .. })) {
                return Err(invalid(format!(
                    "the file bound at {at} would replace a directory"
                )));
            }
            self.create_directories(parent(&resolved))?;
            let resolv_conf = self.resolve("/etc/resolv.conf", false);
            let source = if resolv_conf.is_ok_and(|path| path == resolved) {
                let mut content = Vec::new();
                open_host(&bind.source)
                    .and_then(|mut file| file.read_to_end(&mut content))
                    .map_err(|error| {
                        internal(format!("cannot read {}: {error}", bind.source.display()))
                    })?;
                let fallback =
                    || std::fs::read("/run/systemd/resolve/resolv.conf").unwrap_or_default();
                Source::Data(rewrite_resolv_conf(&content, fallback))
            } else {
                Source::Host(bind.source.clone())
            };
            // A read-only bind's copy has no write permission.
            let mode = host_mode(&metadata) & if bind.read_only { 0o555 } else { 0o777 };
            self.nodes.insert(resolved, Node::File { source, mode });
        } else {
            return Err(unsupported(format!(
                "the source of the bind at {at} is no directory nor regular file"
            )));
        }
        Ok(())
    }

    /// An image directory's file is opened beneath its root, never through a symlink, and only if
    /// it is a regular file. Returns it with its size.
    fn open<'a>(&'a self, source: &'a Source) -> io::Result<(Box<dyn Read + 'a>, u64)> {
        let file = match source {
            Source::Data(data) => return Ok((Box::new(data.as_slice()), data.len() as u64)),
            Source::Archive { offset, size } => {
                #[cfg(unix)]
                let Image::Archive(file) = &self.image else {
                    return Err(io::Error::other("the image is no archive"));
                };
                #[cfg(windows)]
                let Image::Archive(file) = &self.image;
                let slice = Slice {
                    file,
                    offset: *offset,
                    left: *size,
                };
                return Ok((Box::new(slice), *size));
            }
            Source::Host(path) => open_host(path)?,
            #[cfg(unix)]
            Source::Image(path) => {
                let Image::Directory(image) = &self.image else {
                    return Err(io::Error::other("the image is no directory"));
                };
                let (parents, name) = path.rsplit_once('/').unwrap_or(("", path));
                let mut directory = None;
                for component in components(parents) {
                    let flags =
                        OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
                    let at = directory.as_ref().unwrap_or(image);
                    directory = Some(rustix::fs::openat(at, component, flags, Mode::empty())?);
                }
                let flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC;
                let at = directory.as_ref().unwrap_or(image);
                File::from(rustix::fs::openat(at, name, flags, Mode::empty())?)
            }
        };
        let metadata = file.metadata()?;
        if !metadata.is_file() {
            return Err(io::Error::other("not a regular file"));
        }
        Ok((Box::new(file), metadata.len()))
    }

    /// Writes the archive to `output`: every node, parents first (`/` itself is not archived).
    /// Returns it open for reading too, as `output` may name another file once written.
    pub fn write_archive(&self, output: &Path) -> Result<File> {
        let failed =
            |error: io::Error| internal(format!("cannot write {}: {error}", output.display()));
        // Never through a symlink: the broker's user may own the directory.
        let mut options = File::options();
        options.read(true).write(true).create_new(true);
        // The daemon's alone, whatever the umask, until granted.
        #[cfg(unix)]
        options.mode(0o600);
        let file = options.open(output).map_err(failed)?;
        let mut writer = BufWriter::new(file);
        // An image's hard links write their content once, under the first name; the broker still
        // gives each name an inode of its own, with its target's mode.
        let mut payloads = HashMap::new();
        for (path, node) in &self.nodes {
            let mut entry = EntryBuilder::new_gnu();
            entry.path(path);
            let empty = || Box::new(io::empty());
            let payload = match node {
                Node::File {
                    source: Source::Archive { offset, .. },
                    mode,
                } => Some((*offset, *mode)),
                _ => None,
            };
            let first = payload.and_then(|payload| payloads.get(&payload).copied());
            let (entry_type, mode, content, size): (_, _, Box<dyn Read>, _) = match (node, first) {
                (Node::Directory { mode }, _) => (EntryType::Directory, *mode, empty(), 0),
                (Node::Symlink(target), _) => {
                    entry.link_name(target);
                    (EntryType::Symlink, 0o777, empty(), 0)
                }
                (Node::File { mode, .. }, Some(first)) => {
                    entry.link_name(first);
                    (EntryType::Link, *mode, empty(), 0)
                }
                (Node::File { source, mode }, None) => match self.open(source) {
                    Ok((content, size)) => {
                        if let Some(payload) = payload {
                            payloads.insert(payload, path.as_str());
                        }
                        (EntryType::Regular, *mode, content, size)
                    }
                    // The host's files, the guest service and file binds, are no image's to lose.
                    Err(error) if matches!(source, Source::Host(_)) => {
                        return Err(internal(format!("cannot archive {path:?}: {error}")));
                    }
                    Err(error) => {
                        log::warn!("left {path:?} out of the root archive: {error}");
                        continue;
                    }
                },
            };
            entry.entry_type(entry_type);
            append(&mut writer, &mut entry, mode, content, size).map_err(failed)?;
        }
        finish(writer).map_err(failed)
    }
}

/// Appends `entry`, owned by the guest user, with exactly `size` bytes of `content` (so that a
/// file that changed cannot corrupt the archive), padded to a whole block.
pub(crate) fn append(
    writer: &mut impl Write,
    entry: &mut EntryBuilder,
    mode: u32,
    content: Box<dyn Read + '_>,
    size: u64,
) -> io::Result<()> {
    entry
        .mode(mode)
        .and_then(|entry| entry.uid(GUEST_ID.into()))
        .and_then(|entry| entry.gid(GUEST_ID.into()))
        .and_then(|entry| entry.size(size))
        .map_err(io::Error::other)?;
    writer.write_all(&entry.finish_bytes())?;
    let padded = size.next_multiple_of(512);
    io::copy(
        &mut content.take(size).chain(io::repeat(0)).take(padded),
        writer,
    )?;
    Ok(())
}

/// Ends the archive on `writer` with its end-of-archive marker, and flushes it.
pub(crate) fn finish(mut writer: BufWriter<File>) -> io::Result<File> {
    writer.write_all(&[0; 1024])?;
    writer.into_inner().map_err(io::IntoInnerError::into_error)
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
/// which would be the broker's own, and the IPv6 ones, which guests cannot reach yet; with those
/// of `fallback` (systemd-resolved's list) if none is left; and with glibc's option for no IPv6.
// TODO: drop the option once LiteBox's guest sockets have IPv6.
fn rewrite_resolv_conf(content: &[u8], fallback: impl FnOnce() -> Vec<u8>) -> Vec<u8> {
    let nameserver = |line: &str| -> Option<IpAddr> {
        let mut words = line.split_whitespace();
        (words.next()? == "nameserver").then_some(())?;
        words.next()?.split('%').next()?.parse().ok()
    };
    let reachable = |ip: IpAddr| ip.is_ipv4() && !ip.is_loopback() && !ip.is_unspecified();
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
    rewritten.push_str("# Added by the LiteBox shim: IPv4 only, for glibc.\noptions no-aaaa\n");
    rewritten.into_bytes()
}

#[cfg(test)]
mod tests {
    use tar_core::parse::{Limits, ParseEvent, Parser};

    use super::*;

    #[cfg(unix)]
    fn files(root: &Path, paths: &[&str]) {
        for path in paths {
            std::fs::create_dir_all(root.join(path).parent().unwrap()).unwrap();
            std::fs::write(root.join(path), path).unwrap();
        }
    }

    fn code<T: std::fmt::Debug>(result: Result<T>) -> crate::ttrpc::Code {
        match result {
            Err(crate::ttrpc::Error::RpcStatus(status)) => status.code(),
            other => panic!("not a failed status: {other:?}"),
        }
    }

    type Entry = (String, EntryType, u32, Option<String>, Vec<u8>);

    fn entry(path: &str, entry_type: EntryType, mode: u32, content: &[u8]) -> Entry {
        (path.to_owned(), entry_type, mode, None, content.to_vec())
    }

    fn link(path: &str, entry_type: EntryType, target: &str) -> Entry {
        (
            path.to_owned(),
            entry_type,
            0o777,
            Some(target.to_owned()),
            Vec::new(),
        )
    }

    fn archive(entries: &[Entry]) -> Vec<u8> {
        let mut data = Vec::new();
        for (path, entry_type, mode, target, content) in entries {
            let mut builder = EntryBuilder::new_gnu();
            builder.path(path).entry_type(*entry_type);
            if let Some(target) = target {
                builder.link_name(target);
            }
            let size = content.len() as u64;
            append(&mut data, &mut builder, *mode, Box::new(&content[..]), size).unwrap();
        }
        data.extend_from_slice(&[0; 1024]);
        data
    }

    fn entries(data: &[u8]) -> Vec<Entry> {
        let (mut parser, mut offset, mut entries) = (Parser::new(Limits::default()), 0, Vec::new());
        while let ParseEvent::Entry { consumed, entry } = parser.parse(&data[offset..]).unwrap() {
            assert_eq!((entry.uid, entry.gid), (1000, 1000));
            let text = |bytes: &[u8]| String::from_utf8(bytes.to_vec()).unwrap();
            let target = entry.link_target.as_deref().map(text);
            let content = &data[offset + consumed..][..usize::try_from(entry.size).unwrap()];
            let path = text(&entry.path);
            entries.push((path, entry.entry_type, entry.mode, target, content.to_vec()));
            offset += consumed + usize::try_from(entry.size.next_multiple_of(512)).unwrap();
        }
        entries
    }

    #[test]
    fn an_archive_image_is_taken_as_extracting_it_would_create_it() {
        use EntryType::{Char, Directory, Link, Regular, Symlink};
        let dir = tempfile::tempdir().unwrap();
        let image = dir.path().join("image.tar");
        let passwd = b"root:x:0:0::/root:/bin/sh\n";
        let image_entries = [
            entry("./", Directory, 0o755, b""),
            // The guest user stands in for root (see `scan`).
            entry("./usr/", Directory, 0o500, b""),
            entry("./usr/bin/tool", Regular, 0o755, b"tool"),
            link("bin", Symlink, "usr/bin"),
            link("usr/bin/again", Link, "./usr/bin/tool"),
            entry("../escape", Regular, 0o644, b"x"),
            entry("usr/../../escape", Regular, 0o644, b"x"),
            entry("dev/null", Char, 0o666, b""),
            entry("old/gone", Regular, 0o644, b"gone"),
            entry("old", Regular, 0o600, b"new"),
            entry("bin/below", Regular, 0o644, b"x"),
            link("early", Link, "etc/passwd"),
            entry("etc/passwd", Regular, 0o644, passwd),
        ];
        std::fs::write(&image, archive(&image_entries)).unwrap();
        let guest = dir.path().join("guest");
        std::fs::write(&guest, "guest").unwrap();
        let fs = RootFs::build(&image, &guest, &[], "/bin/work").unwrap();
        assert_eq!(fs.cwd, "/usr/bin/work");
        assert_eq!(home(&fs.passwd, 0), "/root");
        let output = dir.path().join("rootfs.tar");
        fs.write_archive(&output).unwrap();
        assert_eq!(
            entries(&std::fs::read(&output).unwrap()),
            [
                entry(".litebox", Directory, 0o755, b""),
                entry(".litebox/guest-service", Regular, 0o755, b"guest"),
                link("bin", Symlink, "usr/bin"),
                entry("dev", Directory, 0o755, b""),
                entry("etc", Directory, 0o755, b""),
                entry("etc/passwd", Regular, 0o644, passwd),
                entry("old", Regular, 0o600, b"new"),
                entry("usr", Directory, 0o700, b""),
                entry("usr/bin", Directory, 0o755, b""),
                entry("usr/bin/again", Regular, 0o755, b"tool"),
                (
                    "usr/bin/tool".to_owned(),
                    Link,
                    0o755,
                    Some("usr/bin/again".to_owned()),
                    Vec::new()
                ),
                entry("usr/bin/work", Directory, 0o755, b""),
            ]
        );
    }

    #[test]
    fn a_truncated_archive_image_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let (image, guest) = (dir.path().join("image.tar"), dir.path().join("guest"));
        std::fs::write(&guest, "guest").unwrap();
        let data = archive(&[entry("file", EntryType::Regular, 0o644, &[1; 1000])]);
        // Without its end-of-archive marker, it is whole.
        std::fs::write(&image, &data[..512 + 1024]).unwrap();
        RootFs::build(&image, &guest, &[], "/").unwrap();
        // Without some of its content, or of its header, it is not.
        for length in [512 + 100, 300] {
            std::fs::write(&image, &data[..length]).unwrap();
            let built = RootFs::build(&image, &guest, &[], "/");
            assert_eq!(code(built), crate::ttrpc::Code::INTERNAL, "{length}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn the_archive_holds_the_images_directories_symlinks_and_files() {
        use std::os::unix::fs::{PermissionsExt as _, symlink};
        let dir = tempfile::tempdir().unwrap();
        let image = dir.path().join("rootfs");
        let long = format!("usr/{}/f", "d".repeat(100));
        files(&image, &["usr/bin/tool", &long, "usr/etc/hostname"]);
        for empty in ["empty", "locked"] {
            std::fs::create_dir_all(image.join(empty)).unwrap();
        }
        std::fs::create_dir_all(dir.path().join("data")).unwrap();
        let far = format!("/{long}");
        for (link, target) in [("bin", "usr/bin"), ("etc", "usr/etc"), ("far", &far)] {
            symlink(target, image.join(link)).unwrap();
        }
        let chmod = |path: &Path, mode| {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
        };
        let modes = [
            ("empty", 0o700),
            ("locked", 0o555),
            ("usr", 0o750),
            ("usr/bin", 0o751),
            ("usr/etc", 0o755),
            (&long[..104], 0o755),
            ("usr/bin/tool", 0o755),
            (&long, 0o640),
            ("usr/etc/hostname", 0o644),
        ];
        for (path, mode) in modes {
            chmod(&image.join(path), mode);
        }
        let resolv = dir.path().join("resolv");
        std::fs::write(&resolv, "nameserver 192.0.2.1\n").unwrap();
        chmod(&resolv, 0o604);
        let bind = |source: PathBuf, destination: &str| Bind {
            source,
            destination: destination.to_owned(),
            read_only: true,
        };
        let binds = [
            // Through `/etc -> usr/etc`: rewritten.
            bind(resolv, "/etc/resolv.conf"),
            bind(dir.path().join("data"), "/bin/data"),
        ];
        let guest = dir.path().join("guest");
        File::create(&guest).unwrap();
        let fs = RootFs::build(&image, &guest, &binds, "/bin/../new").unwrap();
        // `..` is physical, in the image.
        assert_eq!(fs.cwd, "/usr/new");
        assert_eq!(fs.binds[0].destination, "/usr/bin/data");
        let archive = dir.path().join("rootfs.tar");
        fs.write_archive(&archive).unwrap();
        let mode = std::fs::metadata(&archive).unwrap().mode();
        assert_eq!(mode & 0o777, 0o600);
        let data = std::fs::read(&archive).unwrap();
        let (mut parser, mut offset, mut entries) = (Parser::new(Limits::default()), 0, Vec::new());
        while let ParseEvent::Entry { consumed, entry } = parser.parse(&data[offset..]).unwrap() {
            assert_eq!((entry.uid, entry.gid), (1000, 1000));
            let text = |bytes: &[u8]| String::from_utf8(bytes.to_vec()).unwrap();
            let target = entry.link_target.as_deref().map(text);
            let content = &data[offset + consumed..][..usize::try_from(entry.size).unwrap()];
            if entry.path.ends_with(b"resolv.conf") {
                assert!(text(content).ends_with("options no-aaaa\n"));
            }
            entries.push((text(&entry.path), entry.entry_type, entry.mode, target));
            offset += consumed + usize::try_from(entry.size.next_multiple_of(512)).unwrap();
        }
        let node = |path: &str, entry_type, mode| (path.to_owned(), entry_type, mode, None);
        let link = |path: &str, target: &str| {
            let target = Some(target.to_owned());
            (path.to_owned(), EntryType::Symlink, 0o777, target)
        };
        let (directory, file) = (EntryType::Directory, EntryType::Regular);
        assert_eq!(
            entries,
            [
                node(".litebox", directory, 0o755),
                node(".litebox/guest-service", file, 0o755),
                link("bin", "usr/bin"),
                node("empty", directory, 0o700),
                link("etc", "usr/etc"),
                link("far", &far),
                node("locked", directory, 0o755),
                node("usr", directory, 0o750),
                node("usr/bin", directory, 0o751),
                node("usr/bin/data", directory, 0o755),
                node("usr/bin/tool", file, 0o755),
                node(&long[..104], directory, 0o755),
                node(&long, file, 0o640),
                node("usr/etc", directory, 0o755),
                node("usr/etc/hostname", file, 0o644),
                node("usr/etc/resolv.conf", file, 0o404),
                node("usr/new", directory, 0o755),
            ]
        );
    }

    #[cfg(unix)]
    #[test]
    fn an_image_nested_too_deep_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let image = dir.path().join("rootfs");
        let deepest = image.join("d/".repeat(MAX_IMAGE_DEPTH));
        std::fs::create_dir_all(&deepest).unwrap();
        RootFs::build(&image, Path::new("/dev/null"), &[], "/").unwrap();
        std::fs::create_dir(deepest.join("d")).unwrap();
        let built = RootFs::build(&image, Path::new("/dev/null"), &[], "/");
        assert_eq!(code(built), crate::ttrpc::Code::UNIMPLEMENTED);
    }

    #[cfg(unix)]
    #[test]
    fn a_file_bind_that_cannot_be_read_fails_the_archive() {
        let dir = tempfile::tempdir().unwrap();
        files(&dir.path().join("rootfs"), &["etc/hostname"]);
        let source = dir.path().join("hosts");
        std::fs::write(&source, "hosts\n").unwrap();
        let bind = Bind {
            source: source.clone(),
            destination: "/etc/hosts".to_owned(),
            read_only: true,
        };
        let image = dir.path().join("rootfs");
        let guest = dir.path().join("guest");
        File::create(&guest).unwrap();
        let fs = RootFs::build(&image, &guest, &[bind], "/").unwrap();
        std::fs::remove_file(&source).unwrap();
        let Err(crate::ttrpc::Error::RpcStatus(status)) =
            fs.write_archive(&dir.path().join("rootfs.tar"))
        else {
            panic!("a file bind that cannot be read was left out");
        };
        assert!(status.message.contains("etc/hosts"), "{status:?}");
    }

    #[cfg(unix)]
    #[test]
    fn binds_cannot_resolve_to_reserved_paths() {
        let dir = tempfile::tempdir().unwrap();
        let image = dir.path().join("rootfs");
        std::fs::create_dir(&image).unwrap();
        std::os::unix::fs::symlink("/.litebox", image.join("svc")).unwrap();
        std::os::unix::fs::symlink("../..", image.join("up")).unwrap();
        let (file, data) = (dir.path().join("file"), dir.path().to_owned());
        std::fs::write(&file, "x").unwrap();
        for (source, at) in [
            (&file, "/svc/guest-service"),
            (&data, "/up"),
            (&file, "/.litebox/x"),
            (&data, "/proc/x"),
        ] {
            let bind = Bind {
                source: source.clone(),
                destination: at.to_owned(),
                read_only: true,
            };
            let built = RootFs::build(&image, &file, &[bind], "/");
            assert_eq!(code(built), crate::ttrpc::Code::UNIMPLEMENTED, "{at}");
        }
    }

    #[test]
    fn a_resolv_conf_loses_its_loopback_nameservers() {
        let options = "# Added by the LiteBox shim: IPv4 only, for glibc.\noptions no-aaaa\n";
        let kept = rewrite_resolv_conf(
            b"search x\nnameserver 127.0.0.53\nnameserver 192.0.2.1\n",
            || unreachable!(),
        );
        assert_eq!(
            String::from_utf8(kept).unwrap(),
            format!("search x\nnameserver 192.0.2.1\n{options}")
        );
        // Without any left (guests have no IPv6 yet), systemd-resolved's.
        let fallback = || {
            b"nameserver ::1\nnameserver 2001:db8::2\nnameserver 192.0.2.2 # upstream\n".to_vec()
        };
        let replaced = rewrite_resolv_conf(b"nameserver 0.0.0.0\nnameserver 2001:db8::1", fallback);
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
