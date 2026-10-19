// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! FUSE filesystem semantics, exercised against an in-process passthrough server.
//!
//! These tests drive the broker-core resolver over the [`Fuse`] backend, so they cover the
//! client's protocol handling and the resolver semantics layered on it. The server ([`Server`])
//! serves a temporary host directory, as `virtiofsd` would, and keeps the books on lookups and
//! open handles, so tests can check that the client forgets and releases everything it took.

use alloc::vec::Vec;
use std::collections::HashMap;
use std::fs::{File, Metadata};
use std::os::unix::fs::{FileExt as _, MetadataExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};

use crate::fs::errors::{
    FileStatusError, MkdirError, OpenError, ReadDirError, ReadError, RmdirError, SeekError,
    TruncateError, UnlinkError, WriteError,
};
use crate::fs::inode_allocator::InodeAllocator;
use crate::fs::resolver::Resolver;
use crate::fs::{FileType, Mode, OFlags, SeekWhence};
use crate::test_platform::TestPlatform;

use super::Fuse;
use super::abi::{self, Opcode, Reader};
use super::transport::{Transport, TransportError};

const USER: crate::fs::UserInfo = crate::fs::UserInfo {
    user: 1000,
    group: 1000,
};

/// The transport's message size: small enough that large reads and writes take several requests.
const MAX_MESSAGE_SIZE: usize = 64 * 1024;

// ---------------------------------------------------------------------------
// Passthrough FUSE server
// ---------------------------------------------------------------------------

/// How the server behaves.
#[derive(Clone, Copy)]
struct Config {
    /// Whether the server accepts `FUSE_ATOMIC_O_TRUNC`.
    atomic_o_trunc: bool,
    /// The `max_write` the server answers `FUSE_INIT` with.
    max_write: u32,
    /// Whether `FUSE_READ` replies fill all the room the client offers, whatever size it asked
    /// for, as virtiofsd 1.10 does.
    fill_reads: bool,
    /// The protocol minor version the server answers `FUSE_INIT` with.
    minor: u32,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            atomic_o_trunc: true,
            max_write: 32 * 1024,
            fill_reads: false,
            minor: abi::KERNEL_MINOR_VERSION,
        }
    }
}

/// A file or directory the client looked up.
struct NodeState {
    path: PathBuf,
    /// Lookups not yet forgotten.
    nlookup: u64,
}

enum OpenState {
    File(File),
    Dir(PathBuf),
}

/// A FUSE server passing requests through to a host directory.
struct Server {
    config: Config,
    export_dir: tempfile::TempDir,
    nodes: HashMap<u64, NodeState>,
    next_nodeid: u64,
    opens: HashMap<u64, OpenState>,
    next_fh: u64,
    /// Every request's opcode and credentials, in order.
    log: Vec<(Opcode, abi::Credentials)>,
    /// Protocol violations by the client.
    violations: Vec<std::string::String>,
}

const ENOENT: i32 = 2;
const EBADF: i32 = 9;
const EINVAL: i32 = 22;
const ENOSYS: i32 = 38;

impl Server {
    fn new(config: Config) -> Self {
        let export_dir = tempfile::tempdir().expect("failed to create temp dir");
        let mut nodes = HashMap::new();
        nodes.insert(
            abi::ROOT_ID,
            NodeState {
                path: export_dir.path().to_path_buf(),
                // The root is never forgotten.
                nlookup: 1,
            },
        );
        Self {
            config,
            export_dir,
            nodes,
            next_nodeid: abi::ROOT_ID + 1,
            opens: HashMap::new(),
            next_fh: 1,
            log: Vec::new(),
            violations: Vec::new(),
        }
    }

    fn export_path(&self) -> &Path {
        self.export_dir.path()
    }

    /// Handle one request, with `room` for its reply; its reply, if it has one.
    fn handle(&mut self, request: &[u8], room: usize) -> Option<Vec<u8>> {
        let mut r = Reader::new(request);
        let len = r.u32().unwrap();
        let opcode = r.u32().unwrap();
        let unique = r.u64().unwrap();
        let nodeid = r.u64().unwrap();
        let uid = r.u32().unwrap();
        let gid = r.u32().unwrap();
        r.skip(8).unwrap(); // pid, total_extlen, padding
        if len as usize != request.len() {
            self.violations
                .push(std::format!("length {len} for {}", request.len()));
        }
        let opcode = match opcode {
            1 => Opcode::Lookup,
            2 => Opcode::Forget,
            3 => Opcode::Getattr,
            4 => Opcode::Setattr,
            9 => Opcode::Mkdir,
            10 => Opcode::Unlink,
            11 => Opcode::Rmdir,
            14 => Opcode::Open,
            15 => Opcode::Read,
            16 => Opcode::Write,
            18 => Opcode::Release,
            26 => Opcode::Init,
            27 => Opcode::Opendir,
            28 => Opcode::Readdir,
            29 => Opcode::Releasedir,
            35 => Opcode::Create,
            42 => Opcode::BatchForget,
            _ => return Some(reply(unique, Err(ENOSYS))),
        };
        self.log.push((opcode, abi::Credentials { uid, gid }));
        if opcode == Opcode::Forget {
            self.forget(nodeid, r.u64().unwrap());
            return None;
        }
        if opcode == Opcode::BatchForget {
            let count = r.u32().unwrap();
            r.skip(4).unwrap();
            for _ in 0..count {
                let nodeid = r.u64().unwrap();
                self.forget(nodeid, r.u64().unwrap());
            }
            return None;
        }
        let result = if opcode == Opcode::Init {
            Ok(self.init(&mut r))
        } else if let Some(node) = self.nodes.get(&nodeid) {
            let path = node.path.clone();
            self.dispatch(opcode, &path, &mut r, room)
        } else {
            self.violations
                .push(std::format!("{opcode:?} on unknown node {nodeid}"));
            Err(ENOENT)
        };
        Some(reply(unique, result))
    }

    fn dispatch(
        &mut self,
        opcode: Opcode,
        path: &Path,
        r: &mut Reader<'_>,
        room: usize,
    ) -> Result<Vec<u8>, i32> {
        match opcode {
            Opcode::Lookup => {
                let path = path.join(name(r));
                let metadata = std::fs::symlink_metadata(&path).map_err(errno)?;
                Ok(self.entry(path, &metadata))
            }
            Opcode::Getattr => {
                let flags = r.u32().unwrap();
                r.skip(4).unwrap();
                let fh = r.u64().unwrap();
                let metadata = if flags & abi::GETATTR_FH == 0 {
                    std::fs::symlink_metadata(path).map_err(errno)?
                } else {
                    match self.opens.get(&fh) {
                        Some(OpenState::File(file)) => file.metadata().map_err(errno)?,
                        Some(OpenState::Dir(path)) => std::fs::metadata(path).map_err(errno)?,
                        None => return Err(EBADF),
                    }
                };
                Ok(attr_out(&metadata))
            }
            Opcode::Setattr => {
                let valid = r.u32().unwrap();
                r.skip(4).unwrap();
                let fh = r.u64().unwrap();
                let size = r.u64().unwrap();
                r.skip(8 * 4 + 4 * 3).unwrap();
                let mode = r.u32().unwrap();
                r.skip(4).unwrap();
                let uid = r.u32().unwrap();
                let gid = r.u32().unwrap();
                if valid & abi::fattr::FH != 0 && !self.opens.contains_key(&fh) {
                    return Err(EBADF);
                }
                if valid & abi::fattr::SIZE != 0 {
                    File::options()
                        .write(true)
                        .open(path)
                        .and_then(|file| file.set_len(size))
                        .map_err(errno)?;
                }
                if valid & abi::fattr::MODE != 0 {
                    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
                        .map_err(errno)?;
                }
                if valid & (abi::fattr::UID | abi::fattr::GID) != 0 {
                    std::os::unix::fs::chown(
                        path,
                        (valid & abi::fattr::UID != 0).then_some(uid),
                        (valid & abi::fattr::GID != 0).then_some(gid),
                    )
                    .map_err(errno)?;
                }
                Ok(attr_out(&std::fs::symlink_metadata(path).map_err(errno)?))
            }
            Opcode::Mkdir => {
                let mode = r.u32().unwrap();
                r.skip(4).unwrap();
                let path = path.join(name(r));
                std::fs::create_dir(&path).map_err(errno)?;
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode))
                    .map_err(errno)?;
                let metadata = std::fs::symlink_metadata(&path).map_err(errno)?;
                Ok(self.entry(path, &metadata))
            }
            Opcode::Unlink => std::fs::remove_file(path.join(name(r)))
                .map(|()| Vec::new())
                .map_err(errno),
            Opcode::Rmdir => std::fs::remove_dir(path.join(name(r)))
                .map(|()| Vec::new())
                .map_err(errno),
            Opcode::Open => {
                let flags = r.u32().unwrap();
                if flags & OFlags::CREAT.bits() != 0 || flags & OFlags::EXCL.bits() != 0 {
                    self.violations.push(std::format!("open flags {flags:#x}"));
                }
                let file = open_options(flags).open(path).map_err(errno)?;
                Ok(self.open(OpenState::File(file)))
            }
            Opcode::Opendir => {
                if !std::fs::metadata(path).map_err(errno)?.is_dir() {
                    return Err(20); // ENOTDIR
                }
                Ok(self.open(OpenState::Dir(path.to_path_buf())))
            }
            Opcode::Read | Opcode::Readdir => {
                let fh = r.u64().unwrap();
                let offset = r.u64().unwrap();
                let mut size = r.u32().unwrap() as usize;
                if self.config.fill_reads && opcode == Opcode::Read {
                    size = room.saturating_sub(abi::OUT_HEADER_SIZE);
                }
                match (opcode, self.opens.get(&fh)) {
                    (Opcode::Read, Some(OpenState::File(file))) => {
                        let mut buf = alloc::vec![0; size];
                        let n = file.read_at(&mut buf, offset).map_err(errno)?;
                        buf.truncate(n);
                        Ok(buf)
                    }
                    (Opcode::Readdir, Some(OpenState::Dir(path))) => readdir(path, offset, size),
                    _ => Err(EBADF),
                }
            }
            Opcode::Write => {
                let fh = r.u64().unwrap();
                let offset = r.u64().unwrap();
                let size = r.u32().unwrap() as usize;
                r.skip(4 + 8 + 4 + 4).unwrap();
                let data = r.rest();
                if data.len() != size || size > self.config.max_write as usize {
                    self.violations.push(std::format!("write of {size}"));
                }
                let Some(OpenState::File(file)) = self.opens.get(&fh) else {
                    return Err(EBADF);
                };
                let n = file.write_at(data, offset).map_err(errno)?;
                Ok(u32::try_from(n)
                    .unwrap()
                    .to_le_bytes()
                    .into_iter()
                    .chain([0; 4])
                    .collect())
            }
            Opcode::Release | Opcode::Releasedir => {
                let fh = r.u64().unwrap();
                match (opcode, self.opens.remove(&fh)) {
                    (Opcode::Release, Some(OpenState::File(_)))
                    | (Opcode::Releasedir, Some(OpenState::Dir(_))) => Ok(Vec::new()),
                    _ => {
                        self.violations.push(std::format!("{opcode:?} of {fh}"));
                        Err(EBADF)
                    }
                }
            }
            Opcode::Create => {
                let flags = r.u32().unwrap();
                let mode = r.u32().unwrap();
                r.skip(8).unwrap();
                let path = path.join(name(r));
                let mut options = open_options(flags);
                options.create_new(true);
                std::os::unix::fs::OpenOptionsExt::mode(&mut options, mode & 0o7777);
                let file = options.open(&path).map_err(errno)?;
                let metadata = file.metadata().map_err(errno)?;
                let mut out = self.entry(path, &metadata);
                out.extend(self.open(OpenState::File(file)));
                Ok(out)
            }
            Opcode::Forget | Opcode::BatchForget | Opcode::Init => unreachable!(),
        }
    }

    fn init(&mut self, r: &mut Reader<'_>) -> Vec<u8> {
        let major = r.u32().unwrap();
        let minor = r.u32().unwrap();
        let _max_readahead = r.u32().unwrap();
        let flags = r.u32().unwrap();
        assert_eq!((major, minor), (7, abi::KERNEL_MINOR_VERSION));
        let supported = if self.config.atomic_o_trunc {
            abi::INIT_ATOMIC_O_TRUNC
        } else {
            0
        };
        let mut out = Vec::new();
        let minor = minor.min(self.config.minor);
        for word in [7, minor, 0, flags & supported] {
            out.extend(u32::to_le_bytes(word));
        }
        out.extend([0; 4]); // max_background, congestion_threshold
        out.extend(self.config.max_write.to_le_bytes());
        out.extend([0; 64 - 24]);
        out
    }

    /// Counts a lookup of `path`; its `fuse_entry_out`.
    fn entry(&mut self, path: PathBuf, metadata: &Metadata) -> Vec<u8> {
        let nodeid = if let Some((&nodeid, node)) =
            self.nodes.iter_mut().find(|(_, node)| node.path == path)
        {
            node.nlookup += 1;
            nodeid
        } else {
            let nodeid = self.next_nodeid;
            self.next_nodeid += 1;
            self.nodes.insert(nodeid, NodeState { path, nlookup: 1 });
            nodeid
        };
        let mut out = Vec::new();
        out.extend(nodeid.to_le_bytes());
        out.extend([0; 8 * 3 + 4 * 2]); // generation, validity
        attr(metadata, &mut out);
        out
    }

    fn forget(&mut self, nodeid: u64, nlookup: u64) {
        let Some(node) = self.nodes.get_mut(&nodeid) else {
            self.violations
                .push(std::format!("forget of unknown {nodeid}"));
            return;
        };
        let Some(left) = node
            .nlookup
            .checked_sub(nlookup)
            .filter(|_| nodeid != abi::ROOT_ID)
        else {
            self.violations
                .push(std::format!("over-forget of {nodeid}"));
            return;
        };
        node.nlookup = left;
        if left == 0 {
            self.nodes.remove(&nodeid);
        }
    }

    /// A new handle; its `fuse_open_out`.
    fn open(&mut self, open: OpenState) -> Vec<u8> {
        let fh = self.next_fh;
        self.next_fh += 1;
        self.opens.insert(fh, open);
        let mut out = fh.to_le_bytes().to_vec();
        out.extend([0; 8]);
        out
    }

    /// The client forgot every lookup and released every handle, and broke no rules.
    fn assert_clean(&self) {
        assert_eq!(self.violations, [] as [std::string::String; 0]);
        let leaked: Vec<_> = self
            .nodes
            .iter()
            .filter(|&(&nodeid, _)| nodeid != abi::ROOT_ID)
            .map(|(_, node)| &node.path)
            .collect();
        assert!(leaked.is_empty(), "nodes not forgotten: {leaked:?}");
        assert!(
            self.opens.is_empty(),
            "{} handles not released",
            self.opens.len()
        );
    }
}

fn reply(unique: u64, result: Result<Vec<u8>, i32>) -> Vec<u8> {
    let (error, body) = match result {
        Ok(body) => (0, body),
        Err(errno) => (-errno, Vec::new()),
    };
    let mut out = Vec::new();
    out.extend(
        u32::try_from(abi::OUT_HEADER_SIZE + body.len())
            .unwrap()
            .to_le_bytes(),
    );
    out.extend(error.to_le_bytes());
    out.extend(unique.to_le_bytes());
    out.extend(body);
    out
}

fn errno(error: std::io::Error) -> i32 {
    error.raw_os_error().unwrap_or(EINVAL)
}

/// A NUL-terminated name argument.
fn name(r: &mut Reader<'_>) -> std::string::String {
    let rest = r.rest();
    let (name, nul) = rest.split_at(rest.len() - 1);
    assert_eq!(nul, [0]);
    std::string::String::from_utf8(name.to_vec()).unwrap()
}

fn open_options(flags: u32) -> std::fs::OpenOptions {
    let mut options = File::options();
    match flags & 3 {
        0 => options.read(true),
        1 => options.write(true),
        _ => options.read(true).write(true),
    };
    options.truncate(flags & OFlags::TRUNC.bits() != 0);
    options
}

fn attr(metadata: &Metadata, out: &mut Vec<u8>) {
    for word in [metadata.ino(), metadata.size(), metadata.blocks(), 0, 0, 0] {
        out.extend(word.to_le_bytes());
    }
    out.extend([0; 4 * 3]);
    for word in [
        metadata.mode(),
        u32::try_from(metadata.nlink()).unwrap(),
        metadata.uid(),
        metadata.gid(),
        u32::try_from(metadata.rdev()).unwrap(),
        u32::try_from(metadata.blksize()).unwrap(),
        0,
    ] {
        out.extend(word.to_le_bytes());
    }
}

fn attr_out(metadata: &Metadata) -> Vec<u8> {
    let mut out = alloc::vec![0; 16];
    attr(metadata, &mut out);
    out
}

/// `.`, `..`, then the directory's entries, from index `offset`, as fits in `size`.
fn readdir(path: &Path, offset: u64, size: usize) -> Result<Vec<u8>, i32> {
    let mut entries = alloc::vec![
        (".".into(), std::fs::metadata(path).map_err(errno)?),
        ("..".into(), std::fs::metadata(path).map_err(errno)?),
    ];
    let mut children = std::fs::read_dir(path)
        .map_err(errno)?
        .map(|entry| {
            let entry = entry.unwrap();
            (entry.file_name(), entry.metadata().unwrap())
        })
        .collect::<Vec<_>>();
    children.sort_by(|a, b| a.0.cmp(&b.0));
    entries.extend(children);
    let mut out = Vec::new();
    for (index, (name, metadata)) in entries
        .iter()
        .enumerate()
        .skip(usize::try_from(offset).unwrap())
    {
        let name = name.as_encoded_bytes();
        let record = (24 + name.len()).next_multiple_of(8);
        if out.len() + record > size {
            break;
        }
        out.extend(metadata.ino().to_le_bytes());
        out.extend((index as u64 + 1).to_le_bytes());
        out.extend(u32::try_from(name.len()).unwrap().to_le_bytes());
        out.extend(u32::to_le_bytes(if metadata.is_dir() { 4 } else { 8 }));
        out.extend(name);
        out.resize(out.len().next_multiple_of(8), 0);
    }
    Ok(out)
}

/// A transport to a [`Server`], which may break after a number of round trips.
struct ServerTransport {
    server: Arc<Mutex<Server>>,
    /// Round trips left before the transport breaks; `None` for never.
    remaining: Option<usize>,
}

impl ServerTransport {
    fn check_alive(&mut self) -> Result<(), TransportError> {
        match &mut self.remaining {
            Some(0) => Err(TransportError),
            _ => Ok(()),
        }
    }
}

impl Transport for ServerTransport {
    fn max_message_size(&self) -> usize {
        MAX_MESSAGE_SIZE
    }

    fn round_trip(&mut self, request: &[u8], response: &mut [u8]) -> Result<usize, TransportError> {
        self.check_alive()?;
        if let Some(remaining) = &mut self.remaining {
            *remaining -= 1;
        }
        let mut server = self.server.lock().unwrap_or_else(PoisonError::into_inner);
        let Some(reply) = server.handle(request, response.len()) else {
            server.violations.push("round trip without a reply".into());
            return Err(TransportError);
        };
        let n = reply.len().min(response.len());
        response[..n].copy_from_slice(&reply[..n]);
        Ok(reply.len())
    }

    fn send(&mut self, request: &[u8]) -> Result<(), TransportError> {
        self.check_alive()?;
        let mut server = self.server.lock().unwrap_or_else(PoisonError::into_inner);
        if server.handle(request, 0).is_some() {
            server.violations.push("send with a reply".into());
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

type FuseFs = Resolver<TestPlatform, Fuse<TestPlatform, ServerTransport>>;

/// A resolver over a FUSE backend, and the server it talks to.
struct Harness {
    fs: Option<FuseFs>,
    server: Arc<Mutex<Server>>,
}

impl Harness {
    fn new() -> Self {
        Self::with(Config::default(), None)
    }

    /// A harness whose transport breaks after `round_trips` round trips (including `FUSE_INIT`).
    fn broken(round_trips: usize) -> Self {
        Self::with(Config::default(), Some(round_trips))
    }

    fn with(config: Config, remaining: Option<usize>) -> Self {
        let server = Arc::new(Mutex::new(Server::new(config)));
        let transport = ServerTransport {
            server: Arc::clone(&server),
            remaining,
        };
        let backend = Fuse::new(transport, InodeAllocator::standalone())
            .expect("failed to create FUSE filesystem");
        Self {
            fs: Some(Resolver::new(backend)),
            server,
        }
    }

    fn fs(&self) -> &FuseFs {
        self.fs.as_ref().unwrap()
    }

    fn host_path(&self, path: &str) -> PathBuf {
        self.server.lock().unwrap().export_path().join(path)
    }

    /// Drops the filesystem, checking that the client cleaned up after itself.
    fn finish(mut self) {
        drop(self.fs.take());
        self.server.lock().unwrap().assert_clean();
    }
}

fn create(fs: &FuseFs, path: &str, data: &[u8]) {
    let mut fd = fs
        .open(USER, path, OFlags::CREAT | OFlags::WRONLY, Mode::RWXU)
        .expect("failed to create file");
    assert_eq!(fs.write(&mut fd, data, None).unwrap(), data.len());
}

fn read_all(fs: &FuseFs, path: &str) -> Vec<u8> {
    let mut fd = fs
        .open(USER, path, OFlags::RDONLY, Mode::empty())
        .expect("failed to open file for reading");
    let mut out = Vec::new();
    let mut buf = alloc::vec![0u8; 4096];
    loop {
        let n = fs.read(&mut fd, &mut buf, None).expect("read failed");
        if n == 0 {
            return out;
        }
        out.extend_from_slice(&buf[..n]);
    }
}

fn names(fs: &FuseFs, path: &str) -> Vec<std::string::String> {
    let fd = fs
        .open(
            USER,
            path,
            OFlags::RDONLY | OFlags::DIRECTORY,
            Mode::empty(),
        )
        .expect("failed to open dir");
    let mut names: Vec<_> = fs
        .read_dir(&fd)
        .expect("failed to readdir")
        .into_iter()
        .map(|entry| entry.name)
        // The resolver adds these itself.
        .filter(|name| !matches!(name.as_str(), "." | ".."))
        .collect();
    names.sort();
    names
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn test_fuse_create_and_read_file() {
    let h = Harness::new();
    create(h.fs(), "/hello.txt", b"Hello from litebox FUSE!");
    assert_eq!(
        std::fs::read_to_string(h.host_path("hello.txt")).unwrap(),
        "Hello from litebox FUSE!"
    );
    assert_eq!(read_all(h.fs(), "/hello.txt"), b"Hello from litebox FUSE!");
    h.finish();
}

#[test]
fn test_fuse_create_uses_credentials() {
    let h = Harness::new();
    create(h.fs(), "/owned.txt", b"");
    h.fs().mkdir(USER, "/owned_dir", Mode::RWXU).unwrap();
    {
        let server = h.server.lock().unwrap();
        for opcode in [Opcode::Create, Opcode::Mkdir] {
            let (_, credentials) = server.log.iter().find(|(op, _)| *op == opcode).unwrap();
            assert_eq!(
                (credentials.uid, credentials.gid),
                (USER.user.into(), USER.group.into())
            );
        }
    }
    h.finish();
}

#[test]
fn test_fuse_mkdir_and_readdir() {
    let h = Harness::new();
    let fs = h.fs();
    fs.mkdir(USER, "/subdir", Mode::RWXU).unwrap();
    fs.mkdir(USER, "/subdir/nested", Mode::RWXU).unwrap();
    create(fs, "/subdir/file.txt", b"nested content");

    assert_eq!(names(fs, "/"), ["subdir"]);
    assert_eq!(names(fs, "/subdir"), ["file.txt", "nested"]);
    assert!(h.host_path("subdir/nested").is_dir());
    h.finish();
}

#[test]
fn test_fuse_readdir_many_entries() {
    let h = Harness::new();
    for i in 0..3000 {
        std::fs::write(
            h.host_path(&std::format!("entry_with_a_long_name_{i:05}")),
            "",
        )
        .unwrap();
    }
    // More than one `FUSE_READDIR` reply's worth.
    let names = names(h.fs(), "/");
    assert_eq!(names.len(), 3000);
    assert_eq!(names[0], "entry_with_a_long_name_00000");
    assert_eq!(names[2999], "entry_with_a_long_name_02999");
    h.finish();
}

#[test]
fn test_fuse_unlink_and_rmdir() {
    let h = Harness::new();
    let fs = h.fs();
    create(fs, "/to_delete.txt", b"");
    fs.unlink(USER, "/to_delete.txt").expect("unlink failed");
    assert!(!h.host_path("to_delete.txt").exists());
    assert!(matches!(
        fs.unlink(USER, "/to_delete.txt"),
        Err(UnlinkError::PathError(_))
    ));

    fs.mkdir(USER, "/dir", Mode::RWXU).unwrap();
    create(fs, "/dir/file", b"");
    assert!(matches!(fs.rmdir(USER, "/dir"), Err(RmdirError::NotEmpty)));
    fs.unlink(USER, "/dir/file").unwrap();
    fs.rmdir(USER, "/dir").expect("rmdir failed");
    assert!(!h.host_path("dir").exists());
    h.finish();
}

#[test]
fn test_fuse_open_missing_and_through_file() {
    let h = Harness::new();
    let fs = h.fs();
    create(fs, "/file", b"");
    assert!(matches!(
        fs.open(USER, "/missing", OFlags::RDONLY, Mode::empty()),
        Err(OpenError::PathError(_))
    ));
    assert!(matches!(
        fs.open(USER, "/file/below", OFlags::RDONLY, Mode::empty()),
        Err(OpenError::PathError(_))
    ));
    assert!(matches!(
        fs.open(USER, "/file", OFlags::CREAT | OFlags::EXCL, Mode::RWXU),
        Err(OpenError::AlreadyExists)
    ));
    h.finish();
}

#[test]
fn test_fuse_file_status() {
    let h = Harness::new();
    let fs = h.fs();
    create(fs, "/status_test.txt", b"1234567890");
    let status = fs.file_status(USER, "/status_test.txt").unwrap();
    assert_eq!(status.file_type, FileType::RegularFile);
    assert_eq!(status.size, 10);
    let host = std::fs::metadata(h.host_path("status_test.txt")).unwrap();
    assert_eq!(status.node_info.ino, host.ino());

    fs.mkdir(USER, "/stat_dir", Mode::RWXU).unwrap();
    let status = fs.file_status(USER, "/stat_dir").unwrap();
    assert_eq!(status.file_type, FileType::Directory);
    let status = fs.file_status(USER, "/").unwrap();
    assert_eq!(status.file_type, FileType::Directory);
    h.finish();
}

#[test]
fn test_fuse_handle_status() {
    let h = Harness::new();
    let fs = h.fs();
    create(fs, "/fd_stat_test.txt", b"hello fd_stat");
    let fd = fs
        .open(USER, "/fd_stat_test.txt", OFlags::RDONLY, Mode::empty())
        .unwrap();
    let status = fs.handle_status(&fd).unwrap();
    assert_eq!(status.file_type, FileType::RegularFile);
    assert_eq!(status.size, 13);
    drop(fd);

    let fd = fs
        .open(USER, "/", OFlags::RDONLY | OFlags::DIRECTORY, Mode::empty())
        .unwrap();
    assert_eq!(
        fs.handle_status(&fd).unwrap().file_type,
        FileType::Directory
    );
    drop(fd);
    h.finish();
}

#[test]
fn test_fuse_seek_and_partial_read() {
    let h = Harness::new();
    let fs = h.fs();
    create(fs, "/seek_test.txt", b"ABCDEFGHIJ");
    let mut fd = fs
        .open(USER, "/seek_test.txt", OFlags::RDONLY, Mode::empty())
        .unwrap();
    assert_eq!(
        fs.seek(&mut fd, 5, SeekWhence::RelativeToBeginning)
            .unwrap(),
        5
    );
    let mut buf = alloc::vec![0u8; 10];
    let n = fs.read(&mut fd, &mut buf, None).unwrap();
    assert_eq!(&buf[..n], b"FGHIJ");
    assert_eq!(fs.seek(&mut fd, -2, SeekWhence::RelativeToEnd).unwrap(), 8);
    drop(fd);
    h.finish();
}

#[test]
fn test_fuse_truncate() {
    let h = Harness::new();
    let fs = h.fs();
    let mut fd = fs
        .open(
            USER,
            "/trunc_test.txt",
            OFlags::CREAT | OFlags::RDWR,
            Mode::RWXU,
        )
        .unwrap();
    fs.write(&mut fd, b"Hello, World!", None).unwrap();
    fs.truncate(&mut fd, 5, true).expect("truncate failed");
    drop(fd);
    assert_eq!(
        std::fs::read_to_string(h.host_path("trunc_test.txt")).unwrap(),
        "Hello"
    );
    h.finish();
}

fn open_truncates(config: Config) {
    let h = Harness::with(config, None);
    std::fs::write(h.host_path("file"), "contents").unwrap();
    let fd = h
        .fs()
        .open(USER, "/file", OFlags::WRONLY | OFlags::TRUNC, Mode::empty())
        .unwrap();
    drop(fd);
    assert_eq!(std::fs::read_to_string(h.host_path("file")).unwrap(), "");
    h.finish();
}

#[test]
fn test_fuse_open_truncates() {
    open_truncates(Config::default());
}

#[test]
fn test_fuse_open_truncates_without_atomic_o_trunc() {
    open_truncates(Config {
        atomic_o_trunc: false,
        ..Config::default()
    });
}

#[test]
fn test_fuse_host_files_visible() {
    let h = Harness::new();
    std::fs::write(h.host_path("host_file.txt"), "from host").unwrap();
    std::fs::create_dir(h.host_path("host_dir")).unwrap();
    std::fs::write(h.host_path("host_dir/inner.txt"), "inner content").unwrap();
    assert_eq!(read_all(h.fs(), "/host_file.txt"), b"from host");
    assert_eq!(read_all(h.fs(), "/host_dir/inner.txt"), b"inner content");
    assert_eq!(names(h.fs(), "/host_dir"), ["inner.txt"]);
    h.finish();
}

#[test]
fn test_fuse_deep_path_walk() {
    use core::fmt::Write as _;

    let h = Harness::new();
    let fs = h.fs();
    let mut path = std::string::String::new();
    for i in 0..20 {
        write!(path, "/d{i}").unwrap();
        fs.mkdir(USER, &path, Mode::RWXU).unwrap();
    }
    let file_path = path + "/deep_file.txt";
    create(fs, &file_path, b"deep content");
    assert_eq!(read_all(fs, &file_path), b"deep content");
    let status = fs.file_status(USER, &file_path).unwrap();
    assert_eq!(status.file_type, FileType::RegularFile);
    assert_eq!(status.size, 12);
    h.finish();
}

#[test]
fn test_fuse_chmod() {
    let h = Harness::new();
    let fs = h.fs();
    create(fs, "/chmod_test.txt", b"");
    fs.chmod(USER, "/chmod_test.txt", Mode::RUSR)
        .expect("chmod failed");
    let host = std::fs::metadata(h.host_path("chmod_test.txt")).unwrap();
    assert_eq!(host.permissions().mode() & 0o777, 0o400);
    let status = fs.file_status(USER, "/chmod_test.txt").unwrap();
    assert!(status.mode.contains(Mode::RUSR));
    assert!(!status.mode.contains(Mode::WUSR));
    h.finish();
}

#[test]
fn test_fuse_chown() {
    let h = Harness::new();
    let fs = h.fs();
    create(fs, "/chown_test.txt", b"");
    let before = fs.file_status(USER, "/chown_test.txt").unwrap();
    // Chowning to a different owner requires root.
    fs.chown(
        USER,
        "/chown_test.txt",
        Some(before.owner.user),
        Some(before.owner.group),
    )
    .expect("chown failed");
    let after = fs.file_status(USER, "/chown_test.txt").unwrap();
    assert_eq!(after.owner.user, before.owner.user);
    assert_eq!(after.owner.group, before.owner.group);
    h.finish();
}

#[test]
fn test_fuse_large_read_write() {
    let h = Harness::new();
    let fs = h.fs();
    // Larger than the server's `max_write` and the transport's messages: the backend takes as
    // many requests as it needs (the server flags any over its `max_write`), so one call
    // transfers it all.
    let data: Vec<u8> = (0..200_000usize)
        .map(|i| u8::try_from(i % 251).unwrap())
        .collect();
    let mut fd = fs
        .open(
            USER,
            "/large_test.bin",
            OFlags::CREAT | OFlags::RDWR,
            Mode::RWXU,
        )
        .unwrap();
    assert_eq!(fs.write(&mut fd, &data, None).unwrap(), data.len());
    drop(fd);

    let mut fd = fs
        .open(USER, "/large_test.bin", OFlags::RDONLY, Mode::empty())
        .unwrap();
    // Room for more than the file: the read stops at its end.
    let mut read_buf = alloc::vec![0u8; data.len() + 1000];
    assert_eq!(fs.read(&mut fd, &mut read_buf, None).unwrap(), data.len());
    assert_eq!(&read_buf[..data.len()], data);
    assert_eq!(fs.read(&mut fd, &mut read_buf, None).unwrap(), 0);
    drop(fd);

    let server = h.server.lock().unwrap();
    let count = |opcode| server.log.iter().filter(|(op, _)| *op == opcode).count();
    // Whole pages per request: 32 KiB writes, and reads of the message size, less a page (and
    // one more, at the end of the file).
    assert_eq!(count(Opcode::Write), 200_000_usize.div_ceil(32 * 1024));
    assert_eq!(
        count(Opcode::Read),
        200_000_usize.div_ceil(MAX_MESSAGE_SIZE - 4096) + 1
    );
    drop(server);
    h.finish();
}

/// Opens (and so looks up and forgets) `files` files in the root.
fn open_many(h: &Harness, files: usize) {
    for i in 0..files {
        std::fs::write(h.host_path(&std::format!("f{i}")), "").unwrap();
    }
    for i in 0..files {
        let fd = h
            .fs()
            .open(USER, &std::format!("/f{i}"), OFlags::RDONLY, Mode::empty())
            .unwrap();
        drop(fd);
    }
}

#[test]
fn test_fuse_forgets_are_batched() {
    let h = Harness::new();
    open_many(&h, 200);
    {
        let server = h.server.lock().unwrap();
        let count = |opcode| server.log.iter().filter(|(op, _)| *op == opcode).count();
        assert_eq!(count(Opcode::Forget), 0);
        assert_eq!(
            count(Opcode::BatchForget),
            200 / super::client::FORGET_BATCH
        );
        // Forgets held back are bounded: the root, and fewer than a batch.
        assert!(server.nodes.len() <= 1 + super::client::FORGET_BATCH);
    }
    // The rest go when the client does.
    h.finish();
}

#[test]
fn test_fuse_forgets_without_batch_forget() {
    let h = Harness::with(
        Config {
            minor: abi::BATCH_FORGET_MINOR_VERSION - 1,
            ..Config::default()
        },
        None,
    );
    open_many(&h, 100);
    {
        let server = h.server.lock().unwrap();
        let count = |opcode| server.log.iter().filter(|(op, _)| *op == opcode).count();
        assert_eq!(count(Opcode::BatchForget), 0);
        assert_eq!(count(Opcode::Forget), super::client::FORGET_BATCH);
    }
    h.finish();
}

#[test]
fn test_fuse_small_reads_from_a_server_filling_its_room() {
    let h = Harness::with(
        Config {
            fill_reads: true,
            ..Config::default()
        },
        None,
    );
    let data: Vec<u8> = (0..100_000usize)
        .map(|i| u8::try_from(i % 251).unwrap())
        .collect();
    std::fs::write(h.host_path("file"), &data).unwrap();
    let mut fd = h
        .fs()
        .open(USER, "/file", OFlags::RDONLY, Mode::empty())
        .unwrap();
    // Small and odd-sized reads get exactly what they asked for, not the whole reply room.
    let mut read = Vec::new();
    let mut buf = [0u8; 999];
    loop {
        let n = h.fs().read(&mut fd, &mut buf, None).unwrap();
        if n == 0 {
            break;
        }
        read.extend_from_slice(&buf[..n]);
    }
    assert_eq!(read, data);
    drop(fd);
    h.finish();
}

#[test]
fn test_fuse_explicit_offset_read_write() {
    let h = Harness::new();
    let fs = h.fs();
    let mut fd = fs
        .open(
            USER,
            "/offset_test.txt",
            OFlags::CREAT | OFlags::RDWR,
            Mode::RWXU,
        )
        .unwrap();
    fs.write(&mut fd, b"AAAAAAAAAA", None).unwrap();
    assert_eq!(fs.write(&mut fd, b"BBBBB", Some(5)).unwrap(), 5);
    fs.write(&mut fd, b"C", None).unwrap();
    drop(fd);
    assert_eq!(
        std::fs::read_to_string(h.host_path("offset_test.txt")).unwrap(),
        "AAAAABBBBBC"
    );

    let mut fd = fs
        .open(USER, "/offset_test.txt", OFlags::RDONLY, Mode::empty())
        .unwrap();
    let mut buf = alloc::vec![0u8; 5];
    assert_eq!(fs.read(&mut fd, &mut buf, Some(5)).unwrap(), 5);
    assert_eq!(&buf, b"BBBBB");
    let mut buf = alloc::vec![0u8; 11];
    let n = fs.read(&mut fd, &mut buf, None).unwrap();
    assert_eq!(&buf[..n], b"AAAAABBBBBC");
    drop(fd);
    h.finish();
}

#[test]
fn test_fuse_append_mode_changes_after_open() {
    let h = Harness::new();
    let fs = h.fs();
    let host_path = h.host_path("append.txt");
    std::fs::write(&host_path, "ab").unwrap();
    let mut fd = fs
        .open(
            USER,
            "/append.txt",
            OFlags::WRONLY | OFlags::APPEND,
            Mode::empty(),
        )
        .unwrap();
    fs.write(&mut fd, b"c", None).unwrap();
    assert_eq!(std::fs::read_to_string(&host_path).unwrap(), "abc");
    fd.set_append(false);
    fs.seek(&mut fd, 0, SeekWhence::RelativeToBeginning)
        .unwrap();
    fs.write(&mut fd, b"x", None).unwrap();
    assert_eq!(std::fs::read_to_string(&host_path).unwrap(), "xbc");
    drop(fd);
    h.finish();
}

#[test]
fn test_fuse_path_only_handles() {
    let h = Harness::new();
    let fs = h.fs();
    create(fs, "/file", b"data");
    let before = h.server.lock().unwrap().log.len();
    let mut fd = fs.open(USER, "/file", OFlags::PATH, Mode::empty()).unwrap();
    assert_eq!(fs.handle_status(&fd).unwrap().size, 4);
    let mut buf = [0; 4];
    assert!(matches!(
        fs.read(&mut fd, &mut buf, None),
        Err(ReadError::NotForReading)
    ));
    drop(fd);
    // Path-only handles are never opened server-side.
    let opened = h.server.lock().unwrap().log[before..]
        .iter()
        .any(|(op, _)| matches!(op, Opcode::Open | Opcode::Release));
    assert!(!opened);
    h.finish();
}

// ---------------------------------------------------------------------------
// Broken-transport failure tests
// ---------------------------------------------------------------------------

#[test]
fn test_fuse_broken_init() {
    let server = Arc::new(Mutex::new(Server::new(Config::default())));
    let transport = ServerTransport {
        server,
        remaining: Some(0),
    };
    assert!(matches!(
        Fuse::<TestPlatform, _>::new(transport, InodeAllocator::standalone()),
        Err(super::Error::Io)
    ));
}

#[test]
fn test_fuse_broken_open() {
    // 1 round trip: init. The lookup fails.
    let h = Harness::broken(1);
    let result = h
        .fs()
        .open(USER, "/anything.txt", OFlags::RDONLY, Mode::empty());
    assert!(matches!(result, Err(OpenError::Io)));
}

#[test]
fn test_fuse_broken_create() {
    let h = Harness::broken(1);
    let result = h
        .fs()
        .open(USER, "/new.txt", OFlags::CREAT | OFlags::WRONLY, Mode::RWXU);
    assert!(matches!(result, Err(OpenError::Io)));
}

#[test]
fn test_fuse_broken_read() {
    let h = Harness::broken(3);
    std::fs::write(h.host_path("read_me.txt"), b"data").unwrap();
    // 3 round trips: init + lookup + open. Then the read fails.
    let mut fd = h
        .fs()
        .open(USER, "/read_me.txt", OFlags::RDONLY, Mode::empty())
        .expect("open should succeed before break");
    let mut buf = alloc::vec![0u8; 64];
    assert!(matches!(
        h.fs().read(&mut fd, &mut buf, None),
        Err(ReadError::Io)
    ));
}

#[test]
fn test_fuse_broken_write() {
    // 3 round trips: init + lookup (which reports the file as missing) + create.
    let h = Harness::broken(3);
    let mut fd = h
        .fs()
        .open(
            USER,
            "/write_me.txt",
            OFlags::CREAT | OFlags::WRONLY,
            Mode::RWXU,
        )
        .expect("create should succeed before break");
    assert!(matches!(
        h.fs().write(&mut fd, b"data", None),
        Err(WriteError::Io)
    ));
}

#[test]
fn test_fuse_broken_mkdir() {
    let h = Harness::broken(1);
    assert!(matches!(
        h.fs().mkdir(USER, "/broken_dir", Mode::RWXU),
        Err(MkdirError::Io)
    ));
}

#[test]
fn test_fuse_broken_readdir() {
    // 2 round trips: init + opendir of the root.
    let h = Harness::broken(2);
    let fd = h
        .fs()
        .open(USER, "/", OFlags::RDONLY | OFlags::DIRECTORY, Mode::empty())
        .expect("open dir should succeed before break");
    assert!(matches!(h.fs().read_dir(&fd), Err(ReadDirError::Io)));
}

#[test]
fn test_fuse_broken_unlink() {
    let h = Harness::broken(1);
    std::fs::write(h.host_path("to_unlink.txt"), b"").unwrap();
    assert!(matches!(
        h.fs().unlink(USER, "/to_unlink.txt"),
        Err(UnlinkError::Io)
    ));
}

#[test]
fn test_fuse_broken_rmdir() {
    let h = Harness::broken(1);
    std::fs::create_dir(h.host_path("to_rmdir")).unwrap();
    assert!(matches!(
        h.fs().rmdir(USER, "/to_rmdir"),
        Err(RmdirError::Io)
    ));
}

#[test]
fn test_fuse_broken_file_status() {
    let h = Harness::broken(1);
    assert!(matches!(
        h.fs().file_status(USER, "/"),
        Err(FileStatusError::Io)
    ));
}

#[test]
fn test_fuse_broken_truncate() {
    let h = Harness::broken(3);
    std::fs::write(h.host_path("to_trunc.txt"), b"some data").unwrap();
    let mut fd = h
        .fs()
        .open(USER, "/to_trunc.txt", OFlags::RDWR, Mode::empty())
        .expect("open should succeed before break");
    assert!(matches!(
        h.fs().truncate(&mut fd, 0, true),
        Err(TruncateError::Io)
    ));
}

#[test]
fn test_fuse_broken_seek() {
    let h = Harness::broken(3);
    std::fs::write(h.host_path("to_seek.txt"), b"data").unwrap();
    let mut fd = h
        .fs()
        .open(USER, "/to_seek.txt", OFlags::RDONLY, Mode::empty())
        .expect("open should succeed before break");
    assert!(matches!(
        h.fs().seek(&mut fd, -1, SeekWhence::RelativeToEnd),
        Err(SeekError::Io)
    ));
}

// ---------------------------------------------------------------------------
// Backend-level tests
// ---------------------------------------------------------------------------

#[test]
fn test_fuse_lookup_at() {
    use crate::fs::backend::Backend as _;

    let server = Arc::new(Mutex::new(Server::new(Config::default())));
    std::fs::write(server.lock().unwrap().export_path().join("file"), "").unwrap();
    let transport = ServerTransport {
        server: Arc::clone(&server),
        remaining: None,
    };
    let backend = Fuse::<TestPlatform, _>::new(transport, InodeAllocator::standalone()).unwrap();
    let root = backend.owned_dir_at(backend.root(), OFlags::PATH).unwrap();
    let entry = backend.lookup_at(&root, "file").unwrap().unwrap();
    assert_eq!(entry.name, "file");
    assert_eq!(entry.file_type, FileType::RegularFile);
    assert!(backend.lookup_at(&root, "missing").unwrap().is_none());
    assert!(backend.lookup_at(&root, "..").unwrap().is_none());
    drop((root, backend));
    server.lock().unwrap().assert_clean();
}

#[test]
fn test_fuse_rejects_bad_replies() {
    /// Answers `FUSE_INIT`, then replies with the wrong `unique`.
    struct Confused(Server);
    impl Transport for Confused {
        fn max_message_size(&self) -> usize {
            MAX_MESSAGE_SIZE
        }
        fn round_trip(
            &mut self,
            request: &[u8],
            response: &mut [u8],
        ) -> Result<usize, TransportError> {
            let mut reply = self.0.handle(request, response.len()).unwrap();
            if !self.0.log.is_empty() && self.0.log.last().unwrap().0 != Opcode::Init {
                reply[8] ^= 1;
            }
            response[..reply.len()].copy_from_slice(&reply);
            Ok(reply.len())
        }
        fn send(&mut self, _request: &[u8]) -> Result<(), TransportError> {
            Ok(())
        }
    }
    let fs = Resolver::<TestPlatform, _>::new(
        Fuse::<TestPlatform, _>::new(
            Confused(Server::new(Config::default())),
            InodeAllocator::standalone(),
        )
        .unwrap(),
    );
    assert!(matches!(
        fs.file_status(USER, "/"),
        Err(FileStatusError::Io)
    ));
}
