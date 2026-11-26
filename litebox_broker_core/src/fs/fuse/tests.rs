// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! The [`Fuse`] backend under the resolver, against an in-process passthrough server ([`Server`])
//! over a temporary directory. The server flags protocol violations, and [`Harness::finish`]
//! checks that the client forgot every lookup and released every handle.

use alloc::vec::Vec;
use std::collections::HashMap;
use std::fs::{File, Metadata};
use std::os::unix::fs::{FileExt as _, MetadataExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::string::String;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use litebox_platform::buffer::RawBytes;

use crate::fs::backend::Caller;
use crate::fs::errors::{
    FileStatusError, MkdirError, OpenError, PathError, ReadDirError, ReadError, RmdirError,
    SeekError, SymlinkError, TruncateError, UnlinkError, WalkError, WriteError,
};
use crate::fs::inode_allocator::{InodeAllocator, InodeAllocators};
use crate::fs::resolver::{Resolver, ResolverEntry};
use crate::fs::{FileTimeUpdate, FileTimestamp, FileType, Mode, OFlags, SeekWhence, SetFileTimes};
use crate::test_platform::TestPlatform;
use crate::test_support::FaultingBuffer;

use super::abi::{self, Opcode, Reader};
use super::transport::{OUT_HEADER_SIZE, Reply, Transport, TransportError};
use super::{Error, Fuse};

/// The server enforces permissions as the host user it runs as, whatever the guest's.
const USER: crate::fs::UserInfo = crate::fs::UserInfo {
    user: 1000,
    group: 1000,
};

/// Small enough that large transfers take several requests.
const MAX_PAYLOAD_SIZE: usize = 64 * 1024;
const MAX_REQUEST_SIZE: usize = super::transport::MIN_REQUEST_SIZE;
/// The server's `fuse_init_out::max_write`.
const MAX_WRITE: usize = 32 * 1024;
const PAGE_SIZE: usize = 4096;
/// Linux's, without `FUSE_MAX_PAGES`.
const DEFAULT_MAX_PAGES: usize = 32;

/// Offsets in a `fuse_attr`.
const ATTR_SIZE_OFFSET: usize = 8;
const ATTR_ATIMENSEC_OFFSET: usize = 48;
const ATTR_MODE_OFFSET: usize = 60;
/// Where the `fuse_attr` is in a `fuse_entry_out` reply, and in a `fuse_attr_out` one.
const ENTRY_ATTR: usize = OUT_HEADER_SIZE + 40;
const ATTR_OUT_ATTR: usize = OUT_HEADER_SIZE + 16;
/// Replies' lengths, header included.
const ENTRY_REPLY: usize = OUT_HEADER_SIZE + abi::ENTRY_OUT_SIZE;
const CREATE_REPLY: usize = ENTRY_REPLY + abi::OPEN_OUT_SIZE;
const ATTR_REPLY: usize = OUT_HEADER_SIZE + abi::ATTR_OUT_SIZE;
const WRITE_REPLY: usize = OUT_HEADER_SIZE + abi::WRITE_OUT_SIZE;

const EPERM: i32 = 1;
const ENOENT: i32 = 2;
const EIO: i32 = 5;
const EBADF: i32 = 9;
const EACCES: i32 = 13;
const EINVAL: i32 = 22;
const ENOSYS: i32 = 38;
const DT_CHR: u32 = 2;

type Tamper = fn(&mut Vec<u8>);

#[derive(Clone, Copy)]
struct Config {
    atomic_o_trunc: bool,
    /// The `max_pages` the server accepts `FUSE_MAX_PAGES` with.
    max_pages: u16,
    /// The version the server answers `FUSE_INIT` with.
    major: u32,
    minor: u32,
    /// Directory entries are `DT_UNKNOWN`, with inode number 0: only lookups tell.
    unknown_types: bool,
    /// A name whose `FUSE_LOOKUP` fails with an errno.
    failing_lookup: Option<(&'static str, i32)>,
    readdir_cookies: ReaddirCookies,
    /// The `FOPEN_*` flags of files' opens and creations.
    open_flags: u32,
    /// The inode number of a file reported as a character device, which the server cannot make.
    char_device: Option<u64>,
    /// Changes the replies of these lengths.
    tamper: Option<(&'static [usize], Tamper)>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            atomic_o_trunc: true,
            max_pages: 32,
            major: abi::KERNEL_VERSION,
            minor: abi::KERNEL_MINOR_VERSION,
            unknown_types: false,
            failing_lookup: None,
            readdir_cookies: ReaddirCookies::Indices,
            open_flags: 0,
            char_device: None,
            tamper: None,
        }
    }
}

/// What each `FUSE_READDIR` entry's `off` is.
#[derive(Clone, Copy)]
enum ReaddirCookies {
    /// The next entry's index.
    Indices,
    /// The next entry's index, bits reversed: not increasing.
    Reversed,
    /// The offset the batch was asked from.
    Stalled,
    /// 2 in a batch asked from 1, else 1: the offsets read from go 0, 1, 2, 1, ...
    Cycling,
}

/// By object, as `virtiofsd` keeps them: a node found at another path moves there.
struct NodeState {
    path: PathBuf,
    /// Device and inode numbers.
    object: (u64, u64),
    nlookup: u64,
}

enum OpenState {
    File(File),
    Dir(PathBuf),
}

struct Server {
    config: Config,
    export_dir: tempfile::TempDir,
    nodes: HashMap<u64, NodeState>,
    next_nodeid: u64,
    opens: HashMap<u64, OpenState>,
    next_fh: u64,
    /// Every request's opcode.
    log: Vec<Opcode>,
    /// By the client.
    violations: Vec<String>,
    /// As `FUSE_INIT` negotiated them.
    max_read: usize,
    max_write: usize,
    readdir_offsets: Vec<u64>,
    transfer_offsets: Vec<(Opcode, u64)>,
    /// Each `FUSE_SETATTR`'s owner and group, if it sets them; recorded, not applied, as the
    /// unprivileged server could set them only to what they are.
    owner_changes: Vec<(Option<u32>, Option<u32>)>,
    /// Before the transport fails; `None` for never.
    round_trips_left: Option<usize>,
}

impl Server {
    fn shared(config: Config) -> Arc<Mutex<Self>> {
        let export_dir = tempfile::tempdir().expect("failed to create temp dir");
        let metadata = std::fs::metadata(export_dir.path()).unwrap();
        let root = NodeState {
            path: export_dir.path().to_path_buf(),
            object: (metadata.dev(), metadata.ino()),
            nlookup: 1,
        };
        Arc::new(Mutex::new(Self {
            config,
            export_dir,
            nodes: HashMap::from([(abi::ROOT_ID, root)]),
            next_nodeid: abi::ROOT_ID + 1,
            opens: HashMap::new(),
            next_fh: 1,
            log: Vec::new(),
            violations: Vec::new(),
            max_read: 0,
            max_write: 0,
            readdir_offsets: Vec::new(),
            transfer_offsets: Vec::new(),
            owner_changes: Vec::new(),
            round_trips_left: None,
        }))
    }

    fn count(&self, opcode: Opcode) -> usize {
        self.log.iter().filter(|&&op| op == opcode).count()
    }

    /// Handles a request, its payload included; its reply, if it has one.
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
        if (uid, gid) != (0, 0) {
            self.violations
                .push(std::format!("credentials {uid}:{gid}"));
        }
        let opcode = match opcode {
            1 => Opcode::Lookup,
            2 => Opcode::Forget,
            3 => Opcode::Getattr,
            4 => Opcode::Setattr,
            5 => Opcode::Readlink,
            6 => Opcode::Symlink,
            9 => Opcode::Mkdir,
            10 => Opcode::Unlink,
            11 => Opcode::Rmdir,
            12 => Opcode::Rename,
            14 => Opcode::Open,
            15 => Opcode::Read,
            16 => Opcode::Write,
            18 => Opcode::Release,
            26 => Opcode::Init,
            27 => Opcode::Opendir,
            28 => Opcode::Readdir,
            29 => Opcode::Releasedir,
            34 => Opcode::Access,
            35 => Opcode::Create,
            42 => Opcode::BatchForget,
            _ => return Some(reply(unique, Err(ENOSYS))),
        };
        self.log.push(opcode);
        match opcode {
            Opcode::Forget => {
                self.forget(nodeid, r.u64().unwrap());
                return None;
            }
            Opcode::BatchForget => {
                let count = r.u32().unwrap();
                r.skip(4).unwrap();
                for _ in 0..count {
                    let nodeid = r.u64().unwrap();
                    self.forget(nodeid, r.u64().unwrap());
                }
                return None;
            }
            _ => {}
        }
        let result = if opcode == Opcode::Init {
            Ok(self.init(&mut r))
        } else if self.nodes.contains_key(&nodeid) {
            let path = self.locate(nodeid);
            self.dispatch(opcode, &path, &mut r, room)
        } else {
            self.violations
                .push(std::format!("{opcode:?} on unknown node {nodeid}"));
            Err(ENOENT)
        };
        if let Ok(body) = &result
            && body.len() > room
        {
            self.violations.push(std::format!(
                "{opcode:?} reply of {}, room {room}",
                body.len()
            ));
        }
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
                let name = name(r);
                // A server need not resolve them, as `virtiofsd` does not.
                let path = match name.as_str() {
                    "." | ".." => {
                        self.violations
                            .push(std::format!("lookup of {name} in {}", path.display()));
                        return Err(EINVAL);
                    }
                    _ => path.join(&name),
                };
                if let Some((failing, errno)) = self.config.failing_lookup
                    && failing == name
                {
                    return Err(errno);
                }
                let metadata = std::fs::symlink_metadata(&path).map_err(errno)?;
                Ok(self.entry(path, &metadata))
            }
            Opcode::Access => {
                unsafe extern "C" {
                    fn access(path: *const core::ffi::c_char, mode: i32) -> i32;
                }
                let mask = r.u32().unwrap();
                let path = path.as_os_str().as_encoded_bytes();
                let path = std::ffi::CString::new(path).unwrap();
                // SAFETY: a NUL-terminated path.
                if unsafe { access(path.as_ptr(), mask.cast_signed()) } == 0 {
                    Ok(Vec::new())
                } else {
                    Err(errno(std::io::Error::last_os_error()))
                }
            }
            Opcode::Getattr => {
                let flags = r.u32().unwrap();
                r.skip(4).unwrap();
                let fh = r.u64().unwrap();
                let metadata = if flags & abi::GETATTR_FH == 0 {
                    std::fs::symlink_metadata(path)
                } else if let Some(OpenState::File(file)) = self.opens.get(&fh) {
                    file.metadata()
                } else {
                    // Linux sends only files' handles.
                    self.violations.push(std::format!("getattr of handle {fh}"));
                    return Err(EBADF);
                };
                Ok(self.attr_out(&metadata.map_err(errno)?))
            }
            Opcode::Setattr => {
                use abi::fattr::{ATIME, ATIME_NOW, FH, GID, MODE, MTIME, MTIME_NOW, SIZE, UID};
                let valid = r.u32().unwrap();
                r.skip(4).unwrap();
                let fh = r.u64().unwrap();
                let size = r.u64().unwrap();
                r.skip(8).unwrap(); // lock_owner
                let atime = r.u64().unwrap().cast_signed();
                let mtime = r.u64().unwrap().cast_signed();
                r.skip(8).unwrap(); // ctime
                let atimensec = r.u32().unwrap();
                let mtimensec = r.u32().unwrap();
                r.skip(4).unwrap(); // ctimensec
                let mode = r.u32().unwrap();
                r.skip(4).unwrap(); // unused4
                let uid = r.u32().unwrap();
                let gid = r.u32().unwrap();
                let owner_bits = UID | GID;
                if valid & !(SIZE | FH | ATIME | MTIME | ATIME_NOW | MTIME_NOW | MODE | owner_bits)
                    != 0
                {
                    self.violations.push(std::format!("setattr {valid:#x}"));
                }
                if valid & owner_bits != 0 {
                    self.owner_changes.push((
                        (valid & UID != 0).then_some(uid),
                        (valid & GID != 0).then_some(gid),
                    ));
                }
                if valid & MODE != 0 {
                    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
                        .map_err(errno)?;
                }
                if valid & SIZE != 0 {
                    if valid & FH == 0 {
                        File::options()
                            .write(true)
                            .open(path)
                            .and_then(|file| file.set_len(size))
                            .map_err(errno)?;
                    } else {
                        // Through the handle's own descriptor, as a passthrough server does: a
                        // read-only one cannot truncate.
                        let Some(OpenState::File(file)) = self.opens.get(&fh) else {
                            return Err(EBADF);
                        };
                        file.set_len(size).map_err(errno)?;
                    }
                }
                let time = |set, now, seconds, nanoseconds| {
                    (valid & set != 0).then(|| {
                        if valid & now != 0 {
                            SystemTime::now()
                        } else {
                            system_time(seconds, nanoseconds)
                        }
                    })
                };
                let mut times = std::fs::FileTimes::new();
                if let Some(atime) = time(ATIME, ATIME_NOW, atime, atimensec) {
                    times = times.set_accessed(atime);
                }
                if let Some(mtime) = time(MTIME, MTIME_NOW, mtime, mtimensec) {
                    times = times.set_modified(mtime);
                }
                if valid & (ATIME | MTIME) != 0 {
                    File::open(path)
                        .and_then(|file| file.set_times(times))
                        .map_err(errno)?;
                }
                Ok(self.attr_out(&std::fs::symlink_metadata(path).map_err(errno)?))
            }
            Opcode::Readlink => Ok(std::fs::read_link(path)
                .map_err(errno)?
                .into_os_string()
                .into_encoded_bytes()),
            Opcode::Symlink => {
                let name = c_string(r);
                let target = c_string(r);
                let path = path.join(name);
                std::os::unix::fs::symlink(target, &path).map_err(errno)?;
                let metadata = std::fs::symlink_metadata(&path).map_err(errno)?;
                Ok(self.entry(path, &metadata))
            }
            Opcode::Mkdir => {
                let mode = r.u32().unwrap();
                r.skip(4).unwrap(); // umask
                let path = path.join(name(r));
                std::fs::create_dir(&path).map_err(errno)?;
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode))
                    .map_err(errno)?;
                let metadata = std::fs::symlink_metadata(&path).map_err(errno)?;
                Ok(self.entry(path, &metadata))
            }
            Opcode::Rename => {
                let new_parent = &self.nodes[&r.u64().unwrap()].path;
                let old = path.join(c_string(r));
                let new = new_parent.join(c_string(r));
                std::fs::rename(&old, &new).map_err(errno)?;
                self.moved(&old, &new);
                Ok(Vec::new())
            }
            Opcode::Open => {
                let flags = r.u32().unwrap();
                if flags & (OFlags::CREAT | OFlags::EXCL | OFlags::APPEND).bits() != 0
                    || (flags & OFlags::TRUNC.bits() != 0 && !self.config.atomic_o_trunc)
                {
                    self.violations.push(std::format!("open flags {flags:#x}"));
                }
                if !std::fs::symlink_metadata(path).map_err(errno)?.is_file() {
                    // Opening a FIFO would block.
                    self.violations
                        .push(std::format!("open of {}", path.display()));
                    return Err(EINVAL);
                }
                let file = open_options(flags).open(path).map_err(errno)?;
                Ok(self.open(OpenState::File(file)))
            }
            Opcode::Opendir => Ok(self.open(OpenState::Dir(path.to_path_buf()))),
            Opcode::Read => {
                let (fh, offset, size) = read_in(r);
                self.check_transfer(opcode, offset, size, self.max_read);
                if size != room {
                    self.violations
                        .push(std::format!("read of {size} with room {room}"));
                }
                let Some(OpenState::File(file)) = self.opens.get(&fh) else {
                    return Err(EBADF);
                };
                let mut buf = alloc::vec![0; size];
                let n = file.read_at(&mut buf, offset).map_err(errno)?;
                buf.truncate(n);
                Ok(buf)
            }
            Opcode::Readdir => {
                let (fh, offset, size) = read_in(r);
                self.readdir_offsets.push(offset);
                let Some(OpenState::Dir(path)) = self.opens.get(&fh) else {
                    return Err(EBADF);
                };
                readdir(path, offset, size, &self.config)
            }
            Opcode::Write => {
                let (fh, offset, size) = read_in(r);
                let data = r.rest();
                if data.len() != size {
                    self.violations
                        .push(std::format!("write of {size} with {} bytes", data.len()));
                }
                self.check_transfer(opcode, offset, size, self.max_write);
                let Some(OpenState::File(file)) = self.opens.get(&fh) else {
                    return Err(EBADF);
                };
                let n = file.write_at(data, offset).map_err(errno)?;
                Ok([u32::try_from(n).unwrap(), 0]
                    .map(u32::to_le_bytes)
                    .concat())
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
            Opcode::Unlink => {
                std::fs::remove_file(path.join(name(r))).map_err(errno)?;
                Ok(Vec::new())
            }
            Opcode::Rmdir => {
                std::fs::remove_dir(path.join(name(r))).map_err(errno)?;
                Ok(Vec::new())
            }
            Opcode::Forget | Opcode::BatchForget | Opcode::Init => unreachable!(),
        }
    }

    fn init(&mut self, r: &mut Reader<'_>) -> Vec<u8> {
        let major = r.u32().unwrap();
        let minor = r.u32().unwrap();
        r.skip(4).unwrap(); // max_readahead
        let flags = r.u32().unwrap();
        assert_eq!((major, minor), (7, abi::KERNEL_MINOR_VERSION));
        let minor = minor.min(self.config.minor);
        let mut supported = abi::INIT_BIG_WRITES;
        if self.config.atomic_o_trunc {
            supported |= abi::INIT_ATOMIC_O_TRUNC;
        }
        if minor >= abi::MAX_PAGES_MINOR_VERSION {
            supported |= abi::INIT_MAX_PAGES;
        }
        let flags = flags & supported;
        let max_pages = if flags & abi::INIT_MAX_PAGES == 0 {
            DEFAULT_MAX_PAGES
        } else {
            usize::from(self.config.max_pages.max(1))
        };
        self.max_read = max_pages * PAGE_SIZE;
        self.max_write = MAX_WRITE.min(self.max_read);
        let max_write = u32::try_from(MAX_WRITE).unwrap();
        init_out(
            self.config.major,
            minor,
            flags,
            max_write,
            self.config.max_pages,
        )
    }

    /// Flags a transfer over `max`, or past the largest file offset.
    fn check_transfer(&mut self, opcode: Opcode, offset: u64, size: usize, max: usize) {
        self.transfer_offsets.push((opcode, offset));
        if size > max || offset.saturating_add(size as u64) > i64::MAX.cast_unsigned() {
            self.violations
                .push(std::format!("{opcode:?} of {size} at {offset}, max {max}"));
        }
    }

    /// Appends a file's `fuse_attr` to `out`.
    fn attr(&self, metadata: &Metadata, out: &mut Vec<u8>) {
        let start = out.len();
        attr(metadata, out);
        if self.config.char_device == Some(metadata.ino()) {
            let mode = metadata.mode() & !abi::S_IFMT | abi::S_IFCHR;
            out[start + ATTR_MODE_OFFSET..][..4].copy_from_slice(&mode.to_le_bytes());
        }
    }

    fn attr_out(&self, metadata: &Metadata) -> Vec<u8> {
        let mut out = alloc::vec![0; 16]; // attr_valid, attr_valid_nsec, dummy
        self.attr(metadata, &mut out);
        out
    }

    /// Counts a lookup of `path`.
    fn entry(&mut self, path: PathBuf, metadata: &Metadata) -> Vec<u8> {
        let object = (metadata.dev(), metadata.ino());
        let found = (self.nodes.iter_mut()).find(|(_, node)| node.object == object);
        let nodeid = if let Some((&nodeid, node)) = found {
            node.nlookup += 1;
            let old = core::mem::replace(&mut node.path, path.clone());
            if old != path {
                self.moved(&old, &path);
            }
            nodeid
        } else {
            let nodeid = self.next_nodeid;
            self.next_nodeid += 1;
            let node = NodeState {
                path,
                object,
                nlookup: 1,
            };
            self.nodes.insert(nodeid, node);
            nodeid
        };
        let mut out = nodeid.to_le_bytes().to_vec();
        out.extend([0; 8 * 3 + 4 * 2]); // generation, validity
        self.attr(metadata, &mut out);
        out
    }

    /// The path of the node `nodeid`'s object, found anew if the host moved it; its old one if the
    /// object is gone.
    fn locate(&mut self, nodeid: u64) -> PathBuf {
        let node = &self.nodes[&nodeid];
        let at = |path: &Path| {
            let metadata = std::fs::symlink_metadata(path).ok()?;
            Some((metadata.dev(), metadata.ino()))
        };
        if at(&node.path) == Some(node.object) {
            return node.path.clone();
        }
        let (old, object) = (node.path.clone(), node.object);
        let mut pending = alloc::vec![self.export_dir.path().to_path_buf()];
        while let Some(dir) = pending.pop() {
            for entry in std::fs::read_dir(&dir).into_iter().flatten().flatten() {
                let path = entry.path();
                if at(&path) == Some(object) {
                    self.moved(&old, &path);
                    return path;
                }
                if entry.file_type().is_ok_and(|t| t.is_dir()) {
                    pending.push(path);
                }
            }
        }
        old
    }

    /// Moves the nodes and open directories at or below `old` to `new`.
    fn moved(&mut self, old: &Path, new: &Path) {
        let dirs = self.opens.values_mut().filter_map(|open| match open {
            OpenState::Dir(path) => Some(path),
            OpenState::File(_) => None,
        });
        for moved in (self.nodes.values_mut().map(|node| &mut node.path)).chain(dirs) {
            if let Ok(rest) = moved.strip_prefix(old) {
                *moved = new.join(rest);
            }
        }
    }

    fn forget(&mut self, nodeid: u64, nlookup: u64) {
        // The root keeps the lookup it starts with.
        let min = u64::from(nodeid == abi::ROOT_ID);
        let left = self
            .nodes
            .get(&nodeid)
            .and_then(|node| node.nlookup.checked_sub(nlookup))
            .filter(|&left| left >= min);
        match left {
            None => self.violations.push(std::format!("forget of {nodeid}")),
            Some(0) => drop(self.nodes.remove(&nodeid)),
            Some(left) => self.nodes.get_mut(&nodeid).unwrap().nlookup = left,
        }
    }

    fn open(&mut self, open: OpenState) -> Vec<u8> {
        let fh = self.next_fh;
        self.next_fh += 1;
        let open_flags = match open {
            OpenState::File(_) => self.config.open_flags,
            OpenState::Dir(_) => 0,
        };
        self.opens.insert(fh, open);
        let mut out = fh.to_le_bytes().to_vec();
        out.extend([open_flags, 0].map(u32::to_le_bytes).concat());
        out
    }

    fn assert_clean(&self) {
        assert_eq!(self.violations, [] as [String; 0]);
        let leaked: Vec<_> = self
            .nodes
            .iter()
            .filter(|&(&nodeid, _)| nodeid != abi::ROOT_ID)
            .map(|(_, node)| &node.path)
            .collect();
        assert!(leaked.is_empty(), "nodes not forgotten: {leaked:?}");
        assert_eq!(
            self.nodes[&abi::ROOT_ID].nlookup,
            1,
            "root lookups not forgotten"
        );
        assert_eq!(self.opens.len(), 0, "handles not released");
    }
}

fn system_time(seconds: i64, nanoseconds: u32) -> SystemTime {
    let whole = Duration::from_secs(seconds.unsigned_abs());
    let at = if seconds < 0 {
        UNIX_EPOCH - whole
    } else {
        UNIX_EPOCH + whole
    };
    at + Duration::from_nanos(nanoseconds.into())
}

fn reply(unique: u64, result: Result<Vec<u8>, i32>) -> Vec<u8> {
    let (error, body) = result.map_or_else(|errno| (-errno, Vec::new()), |body| (0, body));
    let len = u32::try_from(OUT_HEADER_SIZE + body.len()).unwrap();
    let parts = [
        &len.to_le_bytes()[..],
        &error.to_le_bytes(),
        &unique.to_le_bytes(),
        &body,
    ];
    parts.concat()
}

fn errno(error: std::io::Error) -> i32 {
    error.raw_os_error().unwrap_or(EINVAL)
}

fn c_string(r: &mut Reader<'_>) -> String {
    let rest = r.rest();
    let len = rest.iter().position(|&b| b == 0).expect("NUL-terminated");
    *r = Reader::new(&rest[len + 1..]);
    String::from_utf8(rest[..len].to_vec()).unwrap()
}

/// The last argument.
fn name(r: &mut Reader<'_>) -> String {
    let name = c_string(r);
    assert!(r.rest().is_empty(), "a name is the last argument");
    name
}

/// `fuse_read_in`'s handle, offset, and size.
fn read_in(r: &mut Reader<'_>) -> (u64, u64, usize) {
    let fields = (
        r.u64().unwrap(),
        r.u64().unwrap(),
        r.u32().unwrap() as usize,
    );
    r.skip(4 + 8 + 4 + 4).unwrap();
    fields
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
    let m = metadata;
    let times = [m.atime(), m.mtime(), m.ctime()].map(i64::cast_unsigned);
    for word in [m.ino(), m.size(), m.blocks()].into_iter().chain(times) {
        out.extend(word.to_le_bytes());
    }
    let nanoseconds = [m.atime_nsec(), m.mtime_nsec(), m.ctime_nsec()];
    for word in nanoseconds.map(|ns| u32::try_from(ns).unwrap()) {
        out.extend(word.to_le_bytes());
    }
    let (nlink, rdev, blksize) = (m.nlink(), m.rdev(), m.blksize());
    let rest = [nlink, rdev, blksize].map(|word| u32::try_from(word).unwrap());
    for word in [m.mode(), rest[0], m.uid(), m.gid(), rest[1], rest[2], 0] {
        out.extend(word.to_le_bytes());
    }
}

/// A `fuse_init_out` (the fields the client reads; the others zero).
fn init_out(major: u32, minor: u32, flags: u32, max_write: u32, max_pages: u16) -> Vec<u8> {
    let mut out = [major, minor, 0, flags, 0, max_write, 0]
        .map(u32::to_le_bytes)
        .concat();
    out.extend(max_pages.to_le_bytes());
    out.resize(abi::INIT_OUT_SIZE, 0);
    out
}

/// `.`, `..`, then the directory's entries, from the one at `offset`, as fit in `size`.
fn readdir(path: &Path, offset: u64, size: usize, config: &Config) -> Result<Vec<u8>, i32> {
    let start = match config.readdir_cookies {
        ReaddirCookies::Reversed => offset.reverse_bits(),
        ReaddirCookies::Indices | ReaddirCookies::Stalled | ReaddirCookies::Cycling => offset,
    };
    let dir = std::fs::metadata(path).map_err(errno)?;
    let mut entries = alloc::vec![(".".into(), dir.clone()), ("..".into(), dir)];
    let mut children: Vec<_> = std::fs::read_dir(path)
        .map_err(errno)?
        .map(|entry| {
            let entry = entry.unwrap();
            (entry.file_name(), entry.metadata().unwrap())
        })
        .collect();
    children.sort_by(|a, b| a.0.cmp(&b.0));
    entries.extend(children);
    let mut out = Vec::new();
    let start = usize::try_from(start).unwrap();
    for (index, (name, metadata)) in entries.iter().enumerate().skip(start) {
        let name = name.as_encoded_bytes();
        if out.len() + (24 + name.len()).next_multiple_of(8) > size {
            break;
        }
        let (ino, typ) = if config.unknown_types {
            (0, 0)
        } else if config.char_device == Some(metadata.ino()) {
            (metadata.ino(), DT_CHR)
        } else {
            // Linux's `IFTODT`.
            (metadata.ino(), (metadata.mode() & abi::S_IFMT) >> 12)
        };
        let next = index as u64 + 1;
        let cookie = match config.readdir_cookies {
            ReaddirCookies::Indices => next,
            ReaddirCookies::Reversed => next.reverse_bits(),
            ReaddirCookies::Stalled => offset,
            ReaddirCookies::Cycling if offset == 1 => 2,
            ReaddirCookies::Cycling => 1,
        };
        out.extend(ino.to_le_bytes());
        out.extend(cookie.to_le_bytes());
        out.extend(u32::try_from(name.len()).unwrap().to_le_bytes());
        out.extend(typ.to_le_bytes());
        out.extend(name);
        out.resize(out.len().next_multiple_of(8), 0);
    }
    Ok(out)
}

struct ServerTransport {
    server: Arc<Mutex<Server>>,
    payload: Vec<u8>,
    reply: Vec<u8>,
}

impl ServerTransport {
    fn server(&self) -> std::sync::MutexGuard<'_, Server> {
        self.server.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl Transport for ServerTransport {
    fn max_request_size(&self) -> usize {
        MAX_REQUEST_SIZE
    }

    fn max_payload_size(&self) -> usize {
        MAX_PAYLOAD_SIZE
    }

    fn payload(&mut self) -> Option<RawBytes<'_>> {
        Some(RawBytes::from(self.payload.as_mut_slice()))
    }

    fn round_trip(
        &mut self,
        request: &[u8],
        payload: usize,
        room: usize,
    ) -> Result<Reply<'_>, TransportError> {
        assert!(request.len() <= MAX_REQUEST_SIZE && room <= MAX_PAYLOAD_SIZE);
        assert!(payload == 0 || room <= super::transport::SMALL_MESSAGE_SIZE);
        let mut message = request.to_vec();
        message.extend_from_slice(&self.payload[..payload]);
        let mut server = self.server();
        match &mut server.round_trips_left {
            Some(0) => return Err(TransportError),
            Some(left) => *left -= 1,
            None => {}
        }
        let Some(mut reply) = server.handle(&message, room) else {
            server.violations.push("round trip without a reply".into());
            return Err(TransportError);
        };
        if let Some((lens, tamper)) = server.config.tamper
            && lens.contains(&reply.len())
        {
            tamper(&mut reply);
        }
        drop(server);
        // As a device does, the transport keeps to the room it offered.
        reply.truncate(OUT_HEADER_SIZE + room);
        let len = reply.len();
        let mut header = [0; OUT_HEADER_SIZE];
        let header_len = len.min(OUT_HEADER_SIZE);
        header[..header_len].copy_from_slice(&reply[..header_len]);
        self.reply = reply.split_off(header_len);
        Ok(Reply {
            len,
            header,
            body: RawBytes::from(self.reply.as_mut_slice()),
        })
    }

    fn send(&mut self, request: &[u8]) -> Result<(), TransportError> {
        let mut server = self.server();
        if server.handle(request, 0).is_some() {
            server.violations.push("send with a reply".into());
        }
        Ok(())
    }
}

macro_rules! assert_err {
    ($result:expr, $error:pat) => {
        assert!(matches!($result, Err($error)))
    };
}

type FuseFs = Resolver<TestPlatform, Fuse<TestPlatform, ServerTransport>>;

fn connect(server: &Arc<Mutex<Server>>) -> Result<Fuse<TestPlatform, ServerTransport>, Error> {
    connect_with(server, InodeAllocators::new().next())
}

fn connect_with(
    server: &Arc<Mutex<Server>>,
    allocator: InodeAllocator,
) -> Result<Fuse<TestPlatform, ServerTransport>, Error> {
    let transport = ServerTransport {
        server: Arc::clone(server),
        payload: alloc::vec![0; MAX_PAYLOAD_SIZE],
        reply: Vec::new(),
    };
    Fuse::new(transport, allocator)
}

struct Harness {
    fs: FuseFs,
    server: Arc<Mutex<Server>>,
}

impl Harness {
    fn new() -> Self {
        Self::with(Config::default())
    }

    fn with(config: Config) -> Self {
        let server = Server::shared(config);
        let backend = connect(&server).expect("failed to create FUSE filesystem");
        Self {
            fs: Resolver::new(backend),
            server,
        }
    }

    fn host_path(&self, path: &str) -> PathBuf {
        self.server.lock().unwrap().export_dir.path().join(path)
    }

    fn requests(&self, opcode: Opcode) -> usize {
        self.server.lock().unwrap().count(opcode)
    }

    /// Drops the filesystem, checking that the client cleaned up after itself.
    fn finish(self) {
        let Self { fs, server } = self;
        drop(fs);
        server.lock().unwrap().assert_clean();
    }
}

fn open_dir(fs: &FuseFs, path: &str) -> ResolverEntry<Fuse<TestPlatform, ServerTransport>> {
    fs.open(
        USER,
        None,
        path,
        OFlags::RDONLY | OFlags::DIRECTORY,
        Mode::empty(),
    )
    .expect("failed to open dir")
}

fn read_all(fs: &FuseFs, path: &str) -> Vec<u8> {
    let mut fd = fs
        .open(USER, None, path, OFlags::RDONLY, Mode::empty())
        .unwrap();
    let mut out = Vec::new();
    let mut buf = alloc::vec![0u8; 4096];
    loop {
        match fs.read(&mut fd, &mut buf, None).unwrap() {
            0 => return out,
            n => out.extend_from_slice(&buf[..n]),
        }
    }
}

/// The directory's entries but `.` and `..`, by name: names, types, and inode numbers.
fn list(fs: &FuseFs, path: &str) -> Result<Vec<(String, FileType, u64)>, ReadDirError> {
    let mut entries: Vec<_> = fs
        .read_dir(Caller::default(), &open_dir(fs, path))?
        .into_iter()
        .filter(|entry| !matches!(entry.name.as_str(), "." | ".."))
        .map(|entry| (entry.name, entry.file_type, entry.ino_info.unwrap().ino))
        .collect();
    entries.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(entries)
}

fn pattern(len: usize) -> Vec<u8> {
    (0..len).map(|i| u8::try_from(i % 251).unwrap()).collect()
}

fn ino(path: &Path) -> u64 {
    std::fs::symlink_metadata(path).unwrap().ino()
}

/// Transfers take as many requests as the negotiated sizes need, and a short read at the end of the
/// file ends one.
#[test]
fn test_fuse_read_write() {
    let h = Harness::new();
    let fs = &h.fs;
    let data = pattern(200_000);
    let mut fd = fs
        .open(
            USER,
            None,
            "/file",
            OFlags::CREAT | OFlags::RDWR,
            Mode::RWXU,
        )
        .unwrap();
    assert_eq!(fs.write(&mut fd, &data, None).unwrap(), data.len());
    drop(fd);
    assert_eq!(std::fs::read(h.host_path("file")).unwrap(), data);

    let mut fd = fs
        .open(USER, None, "/file", OFlags::RDONLY, Mode::empty())
        .unwrap();
    let mut buf = alloc::vec![0u8; data.len() + 1000];
    assert_eq!(fs.read(&mut fd, &mut buf, None).unwrap(), data.len());
    assert_eq!(buf[..data.len()], data);
    assert_eq!(fs.read(&mut fd, &mut buf, None).unwrap(), 0);
    assert_eq!(h.requests(Opcode::Write), data.len().div_ceil(MAX_WRITE));
    let reads = data.len().div_ceil(MAX_PAYLOAD_SIZE) + 1;
    assert_eq!(h.requests(Opcode::Read), reads);
    let mut odd = [0u8; 1001];
    assert_eq!(fs.read(&mut fd, &mut odd, Some(1000)).unwrap(), odd.len());
    assert_eq!(odd, data[1000..][..odd.len()]);
    drop(fd);
    h.finish();
}

/// As on Linux: whole pages, 32 without `FUSE_MAX_PAGES`, one per write without `FUSE_BIG_WRITES`.
#[test]
fn test_fuse_io_sizes() {
    const MAX_PAYLOAD: usize = 1 << 20;
    const MAX_PAGES_OFFSET: usize = 28;
    const DEFAULT: usize = DEFAULT_MAX_PAGES * PAGE_SIZE;
    let both = abi::INIT_BIG_WRITES | abi::INIT_MAX_PAGES;
    let full = abi::INIT_OUT_SIZE;
    let minor = abi::KERNEL_MINOR_VERSION;
    let old = abi::MAX_PAGES_MINOR_VERSION - 1;
    for (minor, flags, max_pages, len, expected) in [
        (minor, both, 256, full, (MAX_PAYLOAD, MAX_PAYLOAD)),
        (minor, abi::INIT_BIG_WRITES, 256, full, (DEFAULT, DEFAULT)),
        (old, both, 256, full, (DEFAULT, DEFAULT)),
        (minor, both, 256, MAX_PAGES_OFFSET + 1, (DEFAULT, DEFAULT)),
        (minor, both, 0, full, (PAGE_SIZE, PAGE_SIZE)),
        (
            minor,
            abi::INIT_MAX_PAGES,
            256,
            full,
            (MAX_PAYLOAD, PAGE_SIZE),
        ),
    ] {
        let mut out = init_out(abi::KERNEL_VERSION, minor, flags, 16 << 20, max_pages);
        out.truncate(len);
        let init = abi::InitOut::decode(&mut Reader::new(&out)).unwrap();
        assert_eq!(
            super::client::io_sizes(&init, MAX_PAYLOAD),
            expected,
            "minor {minor}, flags {flags:#x}, max_pages {max_pages}, {len} bytes"
        );
    }
}

/// Forgets are held back and sent in batches: `FUSE_BATCH_FORGET`s, or, below 7.16, as many
/// `FUSE_FORGET`s; the rest go with the client.
#[test]
fn test_fuse_forgets_are_batched() {
    use super::client::FORGET_BATCH;

    const FILES: usize = 200;
    let batches = FILES / FORGET_BATCH;
    let old = abi::BATCH_FORGET_MINOR_VERSION - 1;
    for (minor, batch_forgets, forgets) in [
        (abi::KERNEL_MINOR_VERSION, batches, 0),
        (old, 0, batches * FORGET_BATCH),
    ] {
        let h = Harness::with(Config {
            minor,
            ..Config::default()
        });
        for i in 0..FILES {
            std::fs::write(h.host_path(&std::format!("f{i}")), "").unwrap();
        }
        for i in 0..FILES {
            let path = std::format!("/f{i}");
            drop(
                h.fs.open(USER, None, &path, OFlags::RDONLY, Mode::empty())
                    .unwrap(),
            );
        }
        {
            let server = h.server.lock().unwrap();
            assert_eq!(server.count(Opcode::BatchForget), batch_forgets);
            assert_eq!(server.count(Opcode::Forget), forgets);
            assert!(server.nodes.len() <= 1 + FORGET_BATCH);
        }
        h.finish();
    }
}

/// Links resolve in the guest's namespace (this fixture mounts the share at `/`).
#[test]
fn test_fuse_symlinks() {
    let h = Harness::new();
    std::fs::create_dir(h.host_path("dir")).unwrap();
    std::fs::write(h.host_path("dir/file"), "target").unwrap();
    for (target, link) in [
        ("file", "dir/rel"),
        ("/dir", "abs"),
        ("../../../../../../etc", "escape"),
    ] {
        std::os::unix::fs::symlink(target, h.host_path(link)).unwrap();
    }
    let fs = &h.fs;

    assert_eq!(read_all(fs, "/dir/rel"), b"target");
    assert_eq!(read_all(fs, "/abs/file"), b"target");
    assert_eq!(fs.read_link(USER, None, "/abs").unwrap(), "/dir");
    assert_err!(
        fs.open(USER, None, "/escape/passwd", OFlags::RDONLY, Mode::empty()),
        OpenError::PathError(_)
    );
    let rel = ino(&h.host_path("dir/rel"));
    assert!(
        list(fs, "/dir")
            .unwrap()
            .contains(&("rel".into(), FileType::SymbolicLink, rel))
    );

    fs.symlink(USER, "dir/file", None, "/made").unwrap();
    let made = std::fs::read_link(h.host_path("made")).unwrap();
    assert_eq!(made, Path::new("dir/file"));
    assert_err!(
        fs.symlink(USER, "file", None, "/made"),
        SymlinkError::AlreadyExists
    );
    h.finish();
}

/// As the userland broker's host files, special files are hidden: not listed, whether the listing
/// gives their types or their lookups do, and `EINVAL` to look up, so never opened. `O_PATH` opens
/// send no `FUSE_OPEN` either.
#[test]
fn test_fuse_special_files_are_hidden() {
    unsafe extern "C" {
        fn mkfifo(path: *const core::ffi::c_char, mode: u32) -> i32;
    }
    let h = Harness::new();
    std::fs::write(h.host_path("file"), "data").unwrap();
    std::fs::write(h.host_path("device"), "").unwrap();
    h.server.lock().unwrap().config.char_device = Some(ino(&h.host_path("device")));
    let fifo = h.host_path("fifo").into_os_string().into_encoded_bytes();
    let fifo = std::ffi::CString::new(fifo).unwrap();
    // SAFETY: a NUL-terminated path.
    assert_eq!(unsafe { mkfifo(fifo.as_ptr(), 0o666) }, 0);
    let fs = &h.fs;

    let file = (
        "file".into(),
        FileType::RegularFile,
        ino(&h.host_path("file")),
    );
    for unknown_types in [false, true] {
        h.server.lock().unwrap().config.unknown_types = unknown_types;
        assert_eq!(list(fs, "/").unwrap(), core::slice::from_ref(&file));
    }
    for path in ["/device", "/fifo"] {
        let status = fs.file_status(USER, None, path, true);
        assert_err!(
            status,
            FileStatusError::PathError(PathError::InvalidPathname)
        );
        let opened = fs.open(USER, None, path, OFlags::RDONLY, Mode::empty());
        assert_err!(opened, OpenError::PathError(PathError::InvalidPathname));
    }
    let fd = fs
        .open(USER, None, "/file", OFlags::PATH, Mode::empty())
        .unwrap();
    assert_eq!(fs.handle_status(Caller::default(), &fd).unwrap().size, 4);
    drop(fd);
    assert_eq!(h.requests(Opcode::Open), 0);
    h.finish();
}

/// Directories are read in batches, from each batch's last cookie. Cookies are opaque, so need not
/// increase, but batches that do not move on, or come back to an offset, are rejected: they would
/// be read forever.
#[test]
fn test_fuse_readdir_cookies() {
    for cookies in [
        ReaddirCookies::Indices,
        ReaddirCookies::Reversed,
        ReaddirCookies::Stalled,
        ReaddirCookies::Cycling,
    ] {
        let h = Harness::with(Config {
            readdir_cookies: cookies,
            // A page per batch.
            max_pages: 1,
            ..Config::default()
        });
        let files = match cookies {
            ReaddirCookies::Indices | ReaddirCookies::Reversed => 200,
            ReaddirCookies::Stalled => 0,
            // For a batch from offset 2.
            ReaddirCookies::Cycling => 1,
        };
        for i in 0..files {
            let name = std::format!("entry_with_a_long_name_{i:05}");
            std::fs::write(h.host_path(&name), "").unwrap();
        }
        let listing = list(&h.fs, "/");
        let offsets = h.server.lock().unwrap().readdir_offsets.clone();
        match cookies {
            ReaddirCookies::Indices | ReaddirCookies::Reversed => {
                let listing = listing.unwrap();
                assert_eq!(listing.len(), 200);
                assert_eq!(listing[199].0, "entry_with_a_long_name_00199");
                assert!(offsets.len() > 2);
                if matches!(cookies, ReaddirCookies::Reversed) {
                    let unordered = offsets.windows(3).any(|w| w[0] < w[1] && w[1] > w[2]);
                    assert!(unordered, "{offsets:?}");
                }
            }
            ReaddirCookies::Stalled => {
                assert_err!(listing, ReadDirError::Io);
                assert_eq!(offsets, [0]);
            }
            ReaddirCookies::Cycling => {
                assert_err!(listing, ReadDirError::Io);
                assert_eq!(offsets, [0, 1, 2]);
            }
        }
        h.finish();
    }
}

/// A held directory is walked by node id, so a rename does not lose it; `..` is its current
/// parent, looked up on the server, but never from the root. Its search permission is the server's
/// to check (`FUSE_ACCESS`). FUSE cannot name it, so it keeps the name it was opened by, until it
/// is removed: then it has none, and reading it fails with `ENOENT`, as Linux's `getdents`.
#[test]
fn test_fuse_held_directories() {
    let h = Harness::new();
    let fs = &h.fs;
    std::fs::create_dir_all(h.host_path("d/sub")).unwrap();
    let root = fs
        .open(USER, None, "/", OFlags::PATH, Mode::empty())
        .unwrap();
    assert_eq!(fs.handle_path(Caller::default(), &root, fs).unwrap(), "/");
    let sub = open_dir(fs, "/d/sub");
    fs.rename(USER, None, "/d", None, "/e").unwrap();
    assert_eq!(
        fs.handle_path(Caller::default(), &sub, fs).unwrap(),
        "/d/sub"
    );
    let flags = OFlags::CREAT | OFlags::WRONLY;
    drop(
        fs.open(USER, Some(sub.anchor()), "f", flags, Mode::RWXU)
            .unwrap(),
    );
    assert!(h.host_path("e/sub/f").exists());
    let e = fs.file_status(USER, None, "/e", true).unwrap().node_info;
    for (anchor, path) in [(&sub, ".."), (&sub, "../../e"), (&root, "../e")] {
        let parent = fs.open(
            USER,
            Some(anchor.anchor()),
            path,
            OFlags::PATH,
            Mode::empty(),
        );
        assert_eq!(
            fs.handle_status(Caller::default(), &parent.unwrap())
                .unwrap()
                .node_info,
            e
        );
    }

    let permissions = |mode| std::fs::Permissions::from_mode(mode);
    std::fs::set_permissions(h.host_path("e/sub"), permissions(0o000)).unwrap();
    // As the server's user may: root may search anyway.
    let host_allows_search = std::fs::metadata(h.host_path("e/sub/.")).is_ok();
    let status = fs.file_status(USER, Some(sub.anchor()), ".", true);
    std::fs::set_permissions(h.host_path("e/sub"), permissions(0o755)).unwrap();
    if host_allows_search {
        assert!(status.is_ok());
    } else {
        assert_err!(status, FileStatusError::PathError(PathError::NoSearchPerms));
    }

    std::fs::remove_file(h.host_path("e/sub/f")).unwrap();
    std::fs::remove_dir(h.host_path("e/sub")).unwrap();
    assert_err!(fs.read_dir(Caller::default(), &sub), ReadDirError::Removed);
    assert_err!(
        fs.handle_path(Caller::default(), &sub, fs),
        WalkError::PathError(PathError::NoSuchFileOrDirectory)
    );
    drop((root, sub));
    h.finish();
}

/// A held directory's `..` follows its renames, and its moves on the host once looked up; a lookup
/// that would make a directory its own ancestor fails with `ELOOP`.
#[test]
fn test_fuse_parents_follow_moves() {
    let h = Harness::new();
    let fs = &h.fs;
    for dir in ["a/b", "x", "y", "p/q"] {
        std::fs::create_dir_all(h.host_path(dir)).unwrap();
    }
    let status = |path| fs.file_status(USER, None, path, true).unwrap().node_info;
    let open_at = |dir: &ResolverEntry<_>, path| {
        fs.open(USER, Some(dir.anchor()), path, OFlags::PATH, Mode::empty())
    };
    let parent = |dir: &ResolverEntry<_>| {
        let parent = open_at(dir, "..").unwrap();
        fs.handle_status(Caller::default(), &parent).unwrap()
    };

    let b = open_dir(fs, "/a/b");
    assert_eq!(parent(&b).node_info, status("/a"));
    fs.rename(USER, None, "/a/b", None, "/x/b").unwrap();
    assert_eq!(parent(&b).node_info, status("/x"));
    std::fs::rename(h.host_path("x/b"), h.host_path("y/b")).unwrap();
    drop(open_dir(fs, "/y/b"));
    assert_eq!(parent(&b).node_info, status("/y"));

    // `q` keeps `p` as its parent while the host moves `q` to the root and `p` into it.
    let (p, q) = (open_dir(fs, "/p"), open_dir(fs, "/p/q"));
    std::fs::rename(h.host_path("p/q"), h.host_path("q")).unwrap();
    std::fs::rename(h.host_path("p"), h.host_path("q/p")).unwrap();
    assert_err!(
        open_at(&q, "p"),
        OpenError::PathError(PathError::TooManySymlinks)
    );
    drop(open_dir(fs, "/q"));
    drop(open_at(&q, "p").unwrap());
    assert_eq!(parent(&p).node_info, status("/q"));
    assert_eq!(parent(&q).node_info, status("/"));
    drop((b, p, q));
    h.finish();
}

/// Without recursion: relative walks can make a chain deeper than the kernel's stack allows.
#[test]
fn test_fuse_deep_ancestors_drop_iteratively() {
    type Node = super::Node<TestPlatform, ServerTransport>;
    let server = Server::shared(Config::default());
    let fuse = connect(&server).unwrap();
    let mut dir: Option<Arc<Node>> = None;
    for id in 0..100_000 {
        dir = Some(Arc::new(Node {
            id: abi::ROOT_ID + 1 + id,
            // Never looked up: nothing to forget.
            lookups: core::sync::atomic::AtomicU64::new(0),
            file_type: abi::S_IFDIR,
            parent: litebox_platform::sync::Mutex::new(dir),
            dirs: None,
            client: Arc::clone(&fuse.client),
        }));
    }
    std::thread::Builder::new()
        .stack_size(128 << 10)
        .spawn(move || drop(dir))
        .unwrap()
        .join()
        .unwrap();
    drop(fuse);
    server.lock().unwrap().assert_clean();
}

/// `DT_UNKNOWN` entries take their lookup's type and inode number, or are skipped; names that are
/// not UTF-8 are skipped without a lookup.
#[test]
fn test_fuse_readdir_of_unknown_types() {
    use std::os::unix::ffi::OsStrExt as _;

    for errno in [ENOENT, EACCES, EPERM, EIO] {
        let h = Harness::with(Config {
            unknown_types: true,
            failing_lookup: Some(("hidden", errno)),
            ..Config::default()
        });
        let bad = std::ffi::OsStr::from_bytes(b"bad\xff");
        std::fs::write(h.host_path("").join(bad), "").unwrap();
        std::fs::create_dir(h.host_path("dir")).unwrap();
        std::fs::write(h.host_path("hidden"), "").unwrap();
        std::os::unix::fs::symlink("dir", h.host_path("link")).unwrap();
        let listing = list(&h.fs, "/");
        if errno == EIO {
            assert_err!(listing, ReadDirError::Io);
        } else {
            let dir = ("dir".into(), FileType::Directory, ino(&h.host_path("dir")));
            let link = (
                "link".into(),
                FileType::SymbolicLink,
                ino(&h.host_path("link")),
            );
            assert_eq!(listing.unwrap(), [dir, link], "errno {errno}");
            assert_eq!(h.requests(Opcode::Lookup), 3);
        }
        h.finish();
    }
}

/// Sets a reply's length, header included, and its header's.
fn set_len(reply: &mut Vec<u8>, len: usize) {
    reply.resize(len, 0);
    reply[..4].copy_from_slice(&u32::try_from(len).unwrap().to_le_bytes());
}

/// Changes the mode of the `fuse_attr` at `attr`.
fn change_mode(reply: &mut [u8], attr: usize, change: impl FnOnce(u32) -> u32) {
    let mode = &mut reply[attr + ATTR_MODE_OFFSET..][..4];
    let changed = change(u32::from_le_bytes((&*mode).try_into().unwrap()));
    mode.copy_from_slice(&changed.to_le_bytes());
}

/// Of a `fuse_entry_out` reply.
fn set_node_id(reply: &mut [u8], id: u64) {
    reply[OUT_HEADER_SIZE..][..8].copy_from_slice(&id.to_le_bytes());
}

/// Turns an error into a negative entry, with attributes that would be invalid.
fn negative_entry(reply: &mut Vec<u8>) {
    set_len(reply, ENTRY_REPLY);
    reply[4..8].fill(0);
    reply[ENTRY_ATTR + ATTR_SIZE_OFFSET..][..8].fill(0xff);
    reply[ENTRY_ATTR + ATTR_ATIMENSEC_OFFSET..][..4].fill(0xff);
}

/// The server is not trusted: replies it could not have meant fail the request, as on Linux. A
/// corrupt positive entry can leave a lookup outstanding, so those rows check violations rather
/// than leaks.
#[test]
fn test_fuse_rejects_bad_replies() {
    type Check = fn(&Harness);
    const ENTRIES: &[usize] = &[ENTRY_REPLY];
    const ATTRS: &[usize] = &[ATTR_REPLY];
    const ERRORS: &[usize] = &[OUT_HEADER_SIZE];
    // `FUSE_MKDIR`'s, `FUSE_SYMLINK`'s, and `FUSE_CREATE`'s, as the lookups before them fail.
    const CREATED: &[usize] = &[ENTRY_REPLY, CREATE_REPLY];
    fn status_fails(h: &Harness) {
        assert_err!(
            h.fs.file_status(USER, None, "/file", true),
            FileStatusError::Io
        );
    }
    fn missing_fails(h: &Harness) {
        assert_err!(
            h.fs.file_status(USER, None, "/missing", true),
            FileStatusError::Io
        );
    }
    fn missing_is_missing(h: &Harness) {
        let status = h.fs.file_status(USER, None, "/missing", true);
        assert_err!(
            status,
            FileStatusError::PathError(PathError::NoSuchFileOrDirectory)
        );
    }
    fn types_fail(h: &Harness) {
        let fs = &h.fs;
        let mut fd = fs
            .open(USER, None, "/file", OFlags::RDWR, Mode::empty())
            .unwrap();
        assert_err!(
            fs.handle_status(Caller::default(), &fd),
            FileStatusError::Io
        );
        assert_err!(fs.truncate(&mut fd, 0, true), TruncateError::Io);
        drop(fd);
        assert_err!(
            fs.handle_status(Caller::default(), &open_dir(fs, "/")),
            FileStatusError::Io
        );
        assert_err!(fs.file_status(USER, None, "/", true), FileStatusError::Io);
    }
    fn permissions_are_taken(h: &Harness) {
        let permissions = std::fs::Permissions::from_mode(0o640);
        std::fs::set_permissions(h.host_path("file"), permissions).unwrap();
        let fd =
            h.fs.open(USER, None, "/file", OFlags::RDONLY, Mode::empty());
        let status = h.fs.handle_status(Caller::default(), &fd.unwrap()).unwrap();
        assert_eq!(status.mode.bits() & 0o777, 0o647);
    }
    fn creations_fail(h: &Harness) {
        let fs = &h.fs;
        let created = fs.open(
            USER,
            None,
            "/new",
            OFlags::CREAT | OFlags::WRONLY,
            Mode::RWXU,
        );
        assert_err!(created, OpenError::Io);
        assert_err!(fs.mkdir(USER, None, "/dir", Mode::RWXU), MkdirError::Io);
        assert_err!(fs.symlink(USER, "file", None, "/link"), SymlinkError::Io);
    }
    fn write_fails(h: &Harness) {
        let fd =
            h.fs.open(USER, None, "/file", OFlags::WRONLY, Mode::empty());
        assert_err!(h.fs.write(&mut fd.unwrap(), b"data", None), WriteError::Io);
    }
    // Whether the client can still forget and release all it holds, for the leak check.
    let cases: [(&str, &'static [usize], Tamper, Check, bool); 14] = [
        (
            "another request's",
            ENTRIES,
            |r| r[8] ^= 1,
            status_fails,
            false,
        ),
        (
            "longer than written",
            ENTRIES,
            |r| r.truncate(ENTRY_REPLY - 1),
            status_fails,
            false,
        ),
        (
            "a short body",
            ENTRIES,
            |r| set_len(r, 24),
            status_fails,
            false,
        ),
        (
            "an error with a body",
            ERRORS,
            |r| set_len(r, 24),
            missing_fails,
            true,
        ),
        (
            "a size beyond i64::MAX",
            ENTRIES,
            |r| r[ENTRY_ATTR + ATTR_SIZE_OFFSET + 7] = 0x80,
            status_fails,
            false,
        ),
        (
            "an undefined file type",
            ENTRIES,
            |r| change_mode(r, ENTRY_ATTR, |mode| mode & !abi::S_IFMT | 0o030_000),
            status_fails,
            false,
        ),
        (
            "another type (directories and files swapped)",
            ATTRS,
            |r| {
                change_mode(r, ATTR_OUT_ATTR, |mode| {
                    mode ^ (abi::S_IFDIR | abi::S_IFREG)
                });
            },
            types_fail,
            true,
        ),
        (
            "other permissions, which are taken",
            ATTRS,
            |r| change_mode(r, ATTR_OUT_ATTR, |mode| mode ^ 0o007),
            permissions_are_taken,
            true,
        ),
        (
            "the root as a child",
            ENTRIES,
            |r| set_node_id(r, abi::ROOT_ID),
            status_fails,
            false,
        ),
        (
            "a created FIFO",
            CREATED,
            |r| change_mode(r, ENTRY_ATTR, |mode| mode & !abi::S_IFMT | 0o010_000),
            creations_fail,
            true,
        ),
        (
            "a created node 0",
            CREATED,
            |r| set_node_id(r, 0),
            creations_fail,
            false,
        ),
        (
            "a created root",
            CREATED,
            |r| set_node_id(r, abi::ROOT_ID),
            creations_fail,
            false,
        ),
        (
            "a short write",
            &[WRITE_REPLY],
            |r| set_len(r, WRITE_REPLY - 4),
            write_fails,
            true,
        ),
        (
            "a negative entry",
            ERRORS,
            negative_entry,
            missing_is_missing,
            true,
        ),
    ];
    for (case, lens, tamper, check, leak_checked) in cases {
        let h = Harness::with(Config {
            tamper: Some((lens, tamper)),
            ..Config::default()
        });
        std::fs::write(h.host_path("file"), "data").unwrap();
        check(&h);
        if leak_checked {
            h.finish();
            continue;
        }
        let Harness { fs, server } = h;
        drop(fs);
        let violations = server.lock().unwrap().violations.clone();
        assert_eq!(violations, [] as [String; 0], "{case}");
    }
}

/// Each record has a name of 1 to `FUSE_NAME_MAX` bytes, without a `/` or NUL, within the reply,
/// and is padded to 8 bytes, the last one included.
#[test]
fn test_fuse_dirent_decode_rejects_malformed_records() {
    let record = |name: &[u8], namelen: usize| {
        let namelen = u32::try_from(namelen).unwrap();
        let mut data = [1, 1].map(u64::to_le_bytes).concat(); // ino, off
        data.extend([namelen, abi::DT_REG].map(u32::to_le_bytes).concat());
        data.extend(name);
        data.resize(data.len().next_multiple_of(8), 0);
        data
    };
    assert_eq!(
        abi::Dirent::decode_all(&record(b"abc", 3)).unwrap().len(),
        1
    );
    let long = alloc::vec![b'x'; abi::FUSE_NAME_MAX + 1];
    let mut unpadded = record(b"abc", 3);
    unpadded.pop();
    for data in [
        record(b"", 0),
        record(b"a/b", 3),
        record(b"a\0b", 3),
        record(b"abc", 100),
        record(&long, long.len()),
        unpadded,
    ] {
        assert_err!(abi::Dirent::decode_all(&data), Error::InvalidResponse);
    }
}

/// Servers of another major version, or older than 7.12, whose layouts differ, are not used.
#[test]
fn test_fuse_init_rejects_other_versions() {
    let (major, minor) = (abi::KERNEL_VERSION, abi::KERNEL_MINOR_VERSION);
    for (major, minor) in [
        (major - 1, minor),
        (major + 1, minor),
        (major, abi::MIN_MINOR_VERSION - 1),
    ] {
        let server = Server::shared(Config {
            major,
            minor,
            ..Config::default()
        });
        assert_err!(connect(&server), Error::InvalidResponse);
    }
}

/// Once the transport fails, later requests fail with an I/O error without being sent, but a read
/// that made progress returns what it read.
#[test]
fn test_fuse_broken_transport() {
    let server = Server::shared(Config::default());
    server.lock().unwrap().round_trips_left = Some(0);
    assert_err!(connect(&server), Error::Io);

    let h = Harness::new();
    let data = pattern(100_000);
    std::fs::write(h.host_path("file"), &data).unwrap();
    let fs = &h.fs;
    let mut fd = fs
        .open(USER, None, "/file", OFlags::RDONLY, Mode::empty())
        .unwrap();
    h.server.lock().unwrap().round_trips_left = Some(1);
    let mut buf = alloc::vec![0u8; data.len()];
    assert_eq!(fs.read(&mut fd, &mut buf, None).unwrap(), MAX_PAYLOAD_SIZE);
    assert_eq!(buf[..MAX_PAYLOAD_SIZE], data[..MAX_PAYLOAD_SIZE]);
    let requests = h.server.lock().unwrap().log.len();
    h.server.lock().unwrap().round_trips_left = None;
    assert_err!(fs.read(&mut fd, &mut buf, None), ReadError::Io);
    assert_eq!(h.server.lock().unwrap().log.len(), requests);
}

/// A fault copying to or from the caller's buffer fails the call, even after progress; the faulting
/// write chunk is not sent.
#[test]
fn test_fuse_faulting_read_and_write() {
    let h = Harness::new();
    let data = pattern(200_000);
    std::fs::write(h.host_path("file"), &data).unwrap();
    let fs = &h.fs;
    let mut fd = fs
        .open(USER, None, "/file", OFlags::RDWR, Mode::empty())
        .unwrap();
    let mut faulting = FaultingBuffer::new(data.len(), MAX_PAYLOAD_SIZE + 10);
    assert_err!(fs.read(&mut fd, &mut faulting, None), ReadError::Broker(_));
    let writes = h.requests(Opcode::Write);
    let faulting = FaultingBuffer::new(100, 0);
    assert_err!(fs.write(&mut fd, &faulting, Some(0)), WriteError::Broker(_));
    assert_eq!(h.requests(Opcode::Write), writes);
    drop(fd);
    assert_eq!(std::fs::read(h.host_path("file")).unwrap(), data);
    h.finish();
}

/// Without `FUSE_ATOMIC_O_TRUNC` (which the server checks), an open truncates by node, as the
/// handle may be read-only (`O_RDONLY | O_TRUNC`).
#[test]
fn test_fuse_open_truncates() {
    for (atomic_o_trunc, flags) in [(true, OFlags::WRONLY), (false, OFlags::RDONLY)] {
        let h = Harness::with(Config {
            atomic_o_trunc,
            ..Config::default()
        });
        std::fs::write(h.host_path("file"), "contents").unwrap();
        let fd =
            h.fs.open(USER, None, "/file", flags | OFlags::TRUNC, Mode::empty());
        drop(fd.unwrap());
        assert_eq!(std::fs::read_to_string(h.host_path("file")).unwrap(), "");
        h.finish();
    }
}

#[test]
fn test_fuse_set_times() {
    let h = Harness::new();
    std::fs::write(h.host_path("file"), b"data").unwrap();
    let fs = &h.fs;
    let accessed = FileTimestamp {
        seconds: -123,
        nanoseconds: 987_654_321,
    };
    let modified = FileTimestamp {
        seconds: 456,
        nanoseconds: 123_456_789,
    };
    let set_times = |access, modify| {
        fs.set_times_at(USER, "/file", true, &SetFileTimes { access, modify })
            .unwrap();
        fs.file_status(USER, None, "/file", true)
            .unwrap()
            .times
            .unwrap()
    };
    let times = set_times(FileTimeUpdate::Set(accessed), FileTimeUpdate::Set(modified));
    assert_eq!((times.accessed, times.modified), (accessed, modified));
    let times = set_times(FileTimeUpdate::Omit, FileTimeUpdate::Now);
    assert_eq!(times.accessed, accessed);
    assert!(times.modified.seconds > modified.seconds);
    h.finish();
}

/// As for the userland broker's host files, the guest makes no setuid or setgid files.
#[test]
fn test_fuse_setuid_and_setgid_bits_are_dropped() {
    let h = Harness::new();
    let fs = &h.fs;
    let mode = Mode::SUID | Mode::SGID | Mode::RWXU;
    let file = fs.open(USER, None, "/file", OFlags::CREAT | OFlags::WRONLY, mode);
    drop(file.unwrap());
    fs.mkdir(USER, None, "/dir", mode).unwrap();
    let host_mode = |path| {
        let metadata = std::fs::metadata(h.host_path(path)).unwrap();
        metadata.permissions().mode() & 0o7777
    };
    assert_eq!((host_mode("file"), host_mode("dir")), (0o700, 0o700));
    fs.chmod(USER, None, "/file", mode).unwrap();
    fs.chmod(USER, None, "/dir", mode).unwrap();
    assert_eq!((host_mode("file"), host_mode("dir")), (0o700, 0o700));
    h.finish();
}

/// A file opened as not seekable (`FOPEN_NONSEEKABLE`) cannot be seeked, but is read and written
/// at its position, which transfers of several requests continue from each one's end.
#[test]
fn test_fuse_nonseekable_opens() {
    // A page per request.
    let h = Harness::with(Config {
        open_flags: abi::fopen::NONSEEKABLE,
        max_pages: 1,
        ..Config::default()
    });
    std::fs::write(h.host_path("file"), b"ABCDEFGHIJ").unwrap();
    let fs = &h.fs;
    let mut fd = fs
        .open(USER, None, "/file", OFlags::RDWR, Mode::empty())
        .unwrap();
    let seek = fs.seek(&mut fd, 0, SeekWhence::RelativeToBeginning);
    assert_err!(seek, SeekError::NonSeekable);
    let mut buf = [0u8; 3];
    assert_eq!(fs.read(&mut fd, &mut buf, None).unwrap(), 3);
    assert_eq!(&buf, b"ABC");
    assert_eq!(fs.write(&mut fd, b"xy", None).unwrap(), 2);
    fd.set_append(true);
    assert_eq!(fs.write(&mut fd, b"kl", None).unwrap(), 2);
    drop(fd);
    assert_eq!(std::fs::read(h.host_path("file")).unwrap(), b"ABCxyFGHIJkl");

    let contents = pattern(3 * PAGE_SIZE);
    std::fs::write(h.host_path("big"), &contents).unwrap();
    let mut fd = fs
        .open(USER, None, "/big", OFlags::RDWR, Mode::empty())
        .unwrap();
    assert_eq!(fs.read(&mut fd, &mut buf, None).unwrap(), 3);
    h.server.lock().unwrap().transfer_offsets.clear();
    let mut big = alloc::vec![0u8; 2 * PAGE_SIZE];
    assert_eq!(fs.read(&mut fd, &mut big, None).unwrap(), 2 * PAGE_SIZE);
    assert_eq!(big, contents[3..][..2 * PAGE_SIZE]);
    assert_eq!(fs.write(&mut fd, &big, None).unwrap(), 2 * PAGE_SIZE);
    drop(fd);
    let page = PAGE_SIZE as u64;
    assert_eq!(
        h.server.lock().unwrap().transfer_offsets,
        [
            (Opcode::Read, 3),
            (Opcode::Read, 3 + page),
            (Opcode::Write, 3 + 2 * page),
            (Opcode::Write, 3 + 3 * page),
        ]
    );
    h.finish();
}

/// A file opened or created as a stream (`FOPEN_STREAM`, which overrides `FOPEN_NONSEEKABLE`)
/// cannot be seeked and has no position: every request is at offset 0, which the server ignores.
#[test]
fn test_fuse_stream_opens() {
    use abi::fopen::{NONSEEKABLE, STREAM};

    for open_flags in [STREAM, STREAM | NONSEEKABLE] {
        // A page per request.
        let h = Harness::with(Config {
            open_flags,
            max_pages: 1,
            ..Config::default()
        });
        std::fs::write(h.host_path("file"), pattern(2 * PAGE_SIZE)).unwrap();
        let fs = &h.fs;
        let mut fd = fs
            .open(USER, None, "/file", OFlags::RDWR, Mode::empty())
            .unwrap();
        let seek = fs.seek(&mut fd, 0, SeekWhence::RelativeToBeginning);
        assert_err!(seek, SeekError::NonSeekable);
        let mut big = alloc::vec![0u8; 2 * PAGE_SIZE];
        assert_eq!(fs.read(&mut fd, &mut big, None).unwrap(), 2 * PAGE_SIZE);
        let mut buf = [0u8; 3];
        assert_eq!(fs.read(&mut fd, &mut buf, None).unwrap(), 3);
        assert_eq!(fs.write(&mut fd, &big, None).unwrap(), 2 * PAGE_SIZE);
        drop(fd);

        let created = fs.open(
            USER,
            None,
            "/new",
            OFlags::CREAT | OFlags::WRONLY,
            Mode::RWXU,
        );
        let mut fd = created.unwrap();
        let seek = fs.seek(&mut fd, 0, SeekWhence::RelativeToCurrentOffset);
        assert_err!(seek, SeekError::NonSeekable);
        assert_eq!(fs.write(&mut fd, b"abc", None).unwrap(), 3);
        drop(fd);
        let transfers = h.server.lock().unwrap().transfer_offsets.clone();
        assert_eq!(transfers.len(), 6);
        assert!(transfers.iter().all(|&(_, offset)| offset == 0));
        h.finish();
    }
}

#[test]
fn test_fuse_resolved_status_reuses_lookup_attrs() {
    let h = Harness::new();
    std::fs::create_dir(h.host_path("dir")).unwrap();
    std::fs::write(h.host_path("dir/file"), "data").unwrap();
    assert_eq!(
        h.fs.file_status(USER, None, "/dir/file", true)
            .unwrap()
            .size,
        4
    );
    let dir = h.fs.file_status(USER, None, "/dir", true).unwrap();
    assert_eq!(dir.file_type, FileType::Directory);
    assert_eq!(h.requests(Opcode::Getattr), 0);
    h.finish();
}

/// Nothing goes past the largest file offset, `i64::MAX`: reads there find the end of the file
/// without a request, writes there and lengths above it are rejected without sending a request, and
/// a read just short of it asks only for what lies before it (which the server checks).
#[test]
fn test_fuse_offsets_stop_at_i64_max() {
    let h = Harness::new();
    std::fs::write(h.host_path("file"), "data").unwrap();
    let fs = &h.fs;
    let mut fd = fs
        .open(USER, None, "/file", OFlags::RDWR, Mode::empty())
        .unwrap();
    let max = usize::try_from(i64::MAX).unwrap();
    let mut buf = [0; 10];
    for offset in [max, max + 1, usize::MAX] {
        assert_eq!(fs.read(&mut fd, &mut buf, Some(offset)).unwrap(), 0);
        assert!(fs.write(&mut fd, &buf, Some(offset)).is_err());
        if offset > max {
            assert!(fs.truncate(&mut fd, offset, true).is_err());
        }
    }
    for opcode in [Opcode::Read, Opcode::Write, Opcode::Setattr] {
        assert_eq!(h.requests(opcode), 0);
    }
    assert_eq!(fs.read(&mut fd, &mut buf, Some(max - 1)).unwrap(), 0);
    assert_eq!(h.requests(Opcode::Read), 1);
    drop(fd);
    assert_eq!(std::fs::read(h.host_path("file")).unwrap(), b"data");
    h.finish();
}

/// `FUSE_RENAME` carries the new parent and both names.
#[test]
fn test_fuse_rename() {
    let h = Harness::new();
    std::fs::create_dir(h.host_path("a")).unwrap();
    std::fs::create_dir(h.host_path("b")).unwrap();
    std::fs::write(h.host_path("a/file"), "moved").unwrap();
    h.fs.rename(USER, None, "/a/file", None, "/b/renamed")
        .unwrap();
    assert!(!h.host_path("a/file").exists());
    let renamed = std::fs::read_to_string(h.host_path("b/renamed")).unwrap();
    assert_eq!(renamed, "moved");
    h.finish();
}

/// Directories made through the share hold files, list them, and are removed: `unlink` refuses a
/// directory and `rmdir` a file, and both leave the host without the name.
#[test]
fn test_fuse_mkdir_unlink_and_rmdir() {
    let h = Harness::new();
    let fs = &h.fs;
    fs.mkdir(USER, None, "/dir", Mode::RWXU).unwrap();
    fs.mkdir(USER, None, "/dir/nested", Mode::RWXU).unwrap();
    let mut fd = fs
        .open(
            USER,
            None,
            "/dir/file",
            OFlags::CREAT | OFlags::WRONLY,
            Mode::RWXU,
        )
        .unwrap();
    fs.write(&mut fd, b"nested content", None).unwrap();
    drop(fd);
    let names = |path| {
        let entries = list(fs, path).unwrap();
        entries
            .into_iter()
            .map(|(name, file_type, _)| (name, file_type))
            .collect::<Vec<_>>()
    };
    assert_eq!(names("/"), [("dir".into(), FileType::Directory)]);
    assert_eq!(
        names("/dir"),
        [
            ("file".into(), FileType::RegularFile),
            ("nested".into(), FileType::Directory)
        ]
    );

    assert_err!(
        fs.unlink(USER, None, "/dir/nested"),
        UnlinkError::IsADirectory
    );
    assert_err!(fs.rmdir(USER, None, "/dir/file"), RmdirError::NotADirectory);
    assert_err!(fs.rmdir(USER, None, "/dir"), RmdirError::NotEmpty);
    fs.unlink(USER, None, "/dir/file").unwrap();
    assert!(!h.host_path("dir/file").exists());
    let gone = fs.open(USER, None, "/dir/file", OFlags::RDONLY, Mode::empty());
    assert_err!(gone, OpenError::PathError(PathError::NoSuchFileOrDirectory));
    fs.rmdir(USER, None, "/dir/nested").unwrap();
    fs.rmdir(USER, None, "/dir").unwrap();
    assert!(!h.host_path("dir").exists());
    assert_eq!(names("/"), []);
    h.finish();
}

/// `chown` sends the owner and group it changes, and only those.
#[test]
fn test_fuse_chown() {
    let h = Harness::new();
    std::fs::write(h.host_path("file"), "data").unwrap();
    let fs = &h.fs;
    fs.chown(USER, None, "/file", Some(41), Some(42)).unwrap();
    fs.chown(USER, None, "/file", None, Some(42)).unwrap();
    fs.chown(USER, None, "/file", Some(41), None).unwrap();
    assert_eq!(
        h.server.lock().unwrap().owner_changes,
        [(Some(41), Some(42)), (None, Some(42)), (Some(41), None)]
    );
    h.finish();
}

/// An overlay checks the guest's permissions on its lower layer's files even when that layer, as
/// a FUSE server does, enforces only its host user's: the server would let any guest user in.
#[test]
fn test_fuse_overlay_authorizes_logical_targets() {
    use crate::fs::UserInfo;
    use crate::fs::errors::{ChmodError, ChownError};
    use crate::fs::in_mem::{InMem, InitialNode};
    use crate::fs::overlay::Overlay;

    let server = Server::shared(Config::default());
    let export = server.lock().unwrap().export_dir.path().to_path_buf();
    let file = export.join("private-file");
    std::fs::write(&file, b"server-owned data").unwrap();
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
    let dir = export.join("private-dir");
    std::fs::create_dir(&dir).unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::write(dir.join("hidden"), b"hidden").unwrap();
    let metadata = std::fs::metadata(&file).unwrap();
    // Neither root nor the files' owner or group, whatever the host's IDs.
    let other = |id: u32| if id == 1 { 2 } else { 1 };
    let user = UserInfo {
        user: other(metadata.uid()),
        group: other(metadata.gid()),
    };
    // Directly, the server lets this other user read the file.
    let direct: FuseFs = Resolver::new(connect(&server).unwrap());
    drop(
        direct
            .open(user, None, "/private-file", OFlags::RDONLY, Mode::empty())
            .unwrap(),
    );
    drop(direct);

    let allocators = InodeAllocators::new();
    let upper = InMem::<TestPlatform>::new_initialized(
        [(
            "/",
            InitialNode::Directory {
                mode: Mode::RWXU | Mode::RWXG | Mode::RWXO,
                owner: UserInfo::ROOT,
            },
        )],
        allocators.next(),
    );
    let lower = connect_with(&server, allocators.next()).unwrap();
    let fs = Resolver::<TestPlatform, _>::new(Overlay::<TestPlatform>::new(
        upper,
        lower,
        allocators.next(),
    ));
    for flags in [OFlags::RDONLY, OFlags::WRONLY | OFlags::TRUNC] {
        assert_err!(
            fs.open(user, None, "/private-file", flags, Mode::empty()),
            OpenError::AccessNotAllowed
        );
    }
    assert_err!(
        fs.open(user, None, "/private-dir", OFlags::RDONLY, Mode::empty()),
        OpenError::AccessNotAllowed
    );
    assert_err!(
        fs.open(
            user,
            None,
            "/private-dir/hidden",
            OFlags::PATH,
            Mode::empty()
        ),
        OpenError::PathError(PathError::NoSearchPerms)
    );
    assert_err!(
        fs.chmod(user, None, "/private-file", Mode::RWXU),
        ChmodError::NotTheOwner
    );
    assert_err!(
        fs.chown(user, None, "/private-file", Some(user.user), None),
        ChownError::NotTheOwner
    );
    let fd = fs
        .open(user, None, "/private-file", OFlags::PATH, Mode::empty())
        .unwrap();
    assert_eq!(fs.handle_status(Caller::default(), &fd).unwrap().size, 17);
    drop(fd);
    drop(fs);
    assert_eq!(std::fs::read(&file).unwrap(), b"server-owned data");
    server.lock().unwrap().assert_clean();
}
