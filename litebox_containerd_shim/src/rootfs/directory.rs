// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Directory images, which keep their Linux metadata only on a Unix host. They are read beneath
//! their root, never through a host symlink.

use std::collections::BTreeMap;
use std::fs::File;
use std::io;
use std::os::fd::OwnedFd;

use rustix::fs::{AtFlags, FileType, Mode, OFlags};
use rustix::io::Errno;

use super::{NEW_DIRECTORY, Node, Source, check_depth, components, join};
use crate::spec::SERVED_PATHS;
use crate::{Result, internal};

#[derive(Debug)]
pub(super) struct Directory(OwnedFd);

impl Directory {
    /// Indexes the image directory `root` into `nodes`.
    pub(super) fn scan(root: File, nodes: &mut BTreeMap<String, Node>) -> Result<Self> {
        let root = OwnedFd::from(root);
        scan_at(nodes, "", &root)?;
        Ok(Self(root))
    }

    /// Opens the image's file at the relative `path`.
    pub(super) fn open(&self, path: &str) -> io::Result<File> {
        let (parents, name) = path.rsplit_once('/').unwrap_or(("", path));
        let mut directory = None;
        for component in components(parents) {
            let flags = OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
            let at = directory.as_ref().unwrap_or(&self.0);
            directory = Some(rustix::fs::openat(at, component, flags, Mode::empty())?);
        }
        let flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC;
        let at = directory.as_ref().unwrap_or(&self.0);
        Ok(File::from(rustix::fs::openat(
            at,
            name,
            flags,
            Mode::empty(),
        )?))
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

/// Indexes the image's directory `directory`, at `path`, and below it.
fn scan_at(nodes: &mut BTreeMap<String, Node>, path: &str, directory: &OwnedFd) -> Result<()> {
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
        scan_at(nodes, &join(path, &name), &subdirectory)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _, symlink};
    use std::path::{Path, PathBuf};

    use tar_core::EntryType;
    use tar_core::parse::{Limits, ParseEvent, Parser};

    use crate::rootfs::tests::code;
    use crate::rootfs::{MAX_IMAGE_DEPTH, RootFs};
    use crate::spec::{Bind, Network};

    fn files(root: &Path, paths: &[&str]) {
        for path in paths {
            std::fs::create_dir_all(root.join(path).parent().unwrap()).unwrap();
            std::fs::write(root.join(path), path).unwrap();
        }
    }

    #[test]
    fn the_archive_holds_the_images_directories_symlinks_and_files() {
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
        let fs = RootFs::build(&image, &guest, &binds, "/bin/../new", &Network::Daemon).unwrap();
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

    #[test]
    fn an_image_nested_too_deep_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let image = dir.path().join("rootfs");
        let deepest = image.join("d/".repeat(MAX_IMAGE_DEPTH));
        std::fs::create_dir_all(&deepest).unwrap();
        RootFs::build(&image, Path::new("/dev/null"), &[], "/", &Network::Daemon).unwrap();
        std::fs::create_dir(deepest.join("d")).unwrap();
        let built = RootFs::build(&image, Path::new("/dev/null"), &[], "/", &Network::Daemon);
        assert_eq!(code(built), crate::ttrpc::Code::UNIMPLEMENTED);
    }
}
