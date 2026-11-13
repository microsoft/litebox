// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! The container's root archive, which the broker serves (`--fs-initial-files`): the image's
//! directories, symlinks and regular files, the guest service and the file binds, all owned by the
//! container's user ([`User`]), which every guest process runs as.
//!
//! The image is one directory: the spec's root, or where the shim mounted containerd's root file
//! system. Its paths are untrusted: they are read without following symlinks, beneath its root,
//! and only regular files are read.

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{self, BufWriter, Read, Write};
use std::net::IpAddr;
use std::os::fd::OwnedFd;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};

use rustix::fs::{AtFlags, FileType, Mode, OFlags};
use rustix::io::Errno;
use tar_core::EntryType;
use tar_core::builder::EntryBuilder;

use crate::spec::{Bind, SERVED_PATHS, User};
use crate::{Result, internal, invalid, unsupported};

/// Where the archive holds the guest service, the broker's root process.
pub const GUEST_SERVICE_PATH: &str = "/.litebox/guest-service";
/// A directory the shim creates, with the mode runc's `MkdirAll` gives it.
const NEW_DIRECTORY: Node = Node::Directory { mode: 0o755 };
/// Bounds the symlinks followed while resolving one path, as Linux does.
const MAX_SYMLINKS: usize = 40;
/// Bounds how deep below its root an image's directories nest, and so [`scan`]'s recursion and
/// the directories it holds open: far beyond real images.
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
    Image(String),
    /// A host file, the operator's: a bind source or the guest service.
    Host(PathBuf),
    Data(Vec<u8>),
}

/// The guest's file system, by path relative to `/`.
#[derive(Debug)]
pub struct RootFs {
    nodes: BTreeMap<String, Node>,
    image: OwnedFd,
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

fn errno(what: &str) -> impl Fn(Errno) -> crate::ttrpc::Error + '_ {
    move |error| internal(format!("{what}: {error}"))
}

/// Opens the directory `name` in `directory`, never through a symlink.
fn open_directory(directory: &OwnedFd, name: &str) -> rustix::io::Result<OwnedFd> {
    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    rustix::fs::openat(directory, name, flags, Mode::empty())
}

/// Indexes the image's directory `directory`, at `path`, and below it.
fn scan(nodes: &mut BTreeMap<String, Node>, path: &str, directory: &OwnedFd) -> Result<()> {
    if components(path).count() > MAX_IMAGE_DEPTH {
        return Err(unsupported(format!(
            "the image's directories are nested deeper than {MAX_IMAGE_DEPTH} levels"
        )));
    }
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
                // The container's user owns everything and stands in for the image's root, which
                // runc does not hold to the owner bits: RHEL-family images ship `/root` 0550 and
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

impl RootFs {
    /// The guest's file system: the image in the directory `image`, the guest service, the spec's
    /// `binds`, and the working directory `cwd`, which is created as runc creates it.
    pub fn build(image: &Path, guest_service: &Path, binds: &[Bind], cwd: &str) -> Result<Self> {
        let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC;
        let image = rustix::fs::open(image, flags, Mode::empty())
            .map_err(errno(&format!("cannot read the image {}", image.display())))?;
        let mut nodes = BTreeMap::new();
        scan(&mut nodes, "", &image)?;
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

    /// Opens a file's content: an image file beneath the image's root, never through a symlink,
    /// and only if it is a regular file. Returns it with its size.
    fn open<'a>(&'a self, source: &'a Source) -> io::Result<(Box<dyn Read + 'a>, u64)> {
        let file = match source {
            Source::Data(data) => return Ok((Box::new(data.as_slice()), data.len() as u64)),
            Source::Host(path) => File::open(path)?,
            Source::Image(path) => {
                let (parents, name) = path.rsplit_once('/').unwrap_or(("", path));
                let mut directory = None;
                for component in components(parents) {
                    let flags =
                        OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
                    let at = directory.as_ref().unwrap_or(&self.image);
                    directory = Some(rustix::fs::openat(at, component, flags, Mode::empty())?);
                }
                let flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC;
                let at = directory.as_ref().unwrap_or(&self.image);
                File::from(rustix::fs::openat(at, name, flags, Mode::empty())?)
            }
        };
        let metadata = file.metadata()?;
        if !metadata.is_file() {
            return Err(io::Error::other("not a regular file"));
        }
        Ok((Box::new(file), metadata.len()))
    }

    /// Writes the archive to `output`: every node, parents first (`/` itself is not archived), all
    /// owned by `owner`.
    pub fn write_archive(&self, output: &Path, owner: User) -> Result<()> {
        let failed =
            |error: io::Error| internal(format!("cannot write {}: {error}", output.display()));
        let mut writer = BufWriter::new(File::create(output).map_err(failed)?);
        for (path, node) in &self.nodes {
            let mut entry = EntryBuilder::new_gnu();
            entry.path(path);
            let empty = || Box::new(io::empty());
            let (entry_type, mode, content, size): (_, _, Box<dyn Read>, _) = match node {
                Node::Directory { mode } => (EntryType::Directory, *mode, empty(), 0),
                Node::Symlink(target) => {
                    entry.link_name(target);
                    (EntryType::Symlink, 0o777, empty(), 0)
                }
                Node::File { source, mode } => match self.open(source) {
                    Ok((content, size)) => (EntryType::Regular, *mode, content, size),
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
            append(&mut writer, &mut entry, owner, mode, content, size).map_err(failed)?;
        }
        // The end-of-archive marker.
        writer.write_all(&[0; 1024]).map_err(failed)?;
        writer
            .into_inner()
            .map_err(io::IntoInnerError::into_error)
            .map_err(failed)?;
        Ok(())
    }
}

/// Appends `entry` with exactly `size` bytes of `content` (so that a file that changed cannot
/// corrupt the archive), padded to a whole block.
fn append(
    writer: &mut impl Write,
    entry: &mut EntryBuilder,
    owner: User,
    mode: u32,
    content: Box<dyn Read + '_>,
    size: u64,
) -> io::Result<()> {
    entry
        .mode(mode)
        .and_then(|entry| entry.uid(owner.uid.into()))
        .and_then(|entry| entry.gid(owner.gid.into()))
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
    use super::*;

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

    #[test]
    fn the_archive_holds_the_images_directories_symlinks_and_files() {
        use std::os::unix::fs::{PermissionsExt as _, symlink};
        use tar_core::parse::{Limits, ParseEvent, Parser};
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
        let owner = User {
            uid: 1001,
            gid: 1002,
        };
        fs.write_archive(&archive, owner).unwrap();
        let data = std::fs::read(&archive).unwrap();
        let (mut parser, mut offset, mut entries) = (Parser::new(Limits::default()), 0, Vec::new());
        while let ParseEvent::Entry { consumed, entry } = parser.parse(&data[offset..]).unwrap() {
            assert_eq!((entry.uid, entry.gid), (1001, 1002));
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
            fs.write_archive(&dir.path().join("rootfs.tar"), User { uid: 0, gid: 0 })
        else {
            panic!("a file bind that cannot be read was left out");
        };
        assert!(status.message.contains("etc/hosts"), "{status:?}");
    }

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
