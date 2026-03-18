// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! 9P2000.L server implementation for the file broker.
//!
//! Handles incoming 9P protocol messages, translating them to host filesystem
//! operations with policy enforcement and optional ELF syscall rewriting.
//!
//! Security design:
//! - Component-by-component path walk with lexical containment checks.
//! - `resolve_and_check` canonicalizes paths before every host FS operation,
//!   preventing symlink-based jail escapes.
//! - Policy checks BEFORE file creation (no O_CREAT bypass in Tlopen).
//! - Per-connection FID namespace with configurable limits.
//! - Path containment: all walks are rooted and cannot escape the root directory.
//! - Incoming message sizes are bounded by the negotiated msize.

use std::borrow::Cow;
use std::collections::HashMap;
use std::fs;
use std::io::{Read as _, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::SystemTime;

use super::fs_compat::{self, FileExt, MetadataExt, OpenOptionsExt};

use tracing::{debug, trace, warn};

use super::fcall::{self, Fcall, FcallStr, TaggedFcall};
use super::transport::{self, Read, Write};
use crate::policy::{Action, Decision, Policy};

/// Maximum number of FIDs per connection to prevent resource exhaustion.
const MAX_FIDS: usize = 8192;

/// Linux `AT_REMOVEDIR` flag for `Tunlinkat`.
const AT_REMOVEDIR: u32 = 0x200;

/// State for a single FID (file identifier) in the 9P server.
struct FidState {
    /// Host-side path this FID refers to. After a successful walk, this
    /// is the fully canonicalized (symlinks resolved) path.
    path: PathBuf,
    /// Open host file handle, if opened via `Tlopen` or `Tlcreate`.
    file: Option<fs::File>,
    /// If the file was ELF-patched, the full rewritten content.
    patched_data: Option<Arc<Vec<u8>>>,
    /// Current read offset within `patched_data`.
    patched_offset: u64,
    /// QID for this FID.
    qid: fcall::Qid,
    /// Whether this FID has been opened (Tlopen/Tlcreate called).
    is_open: bool,
    /// True when `path` was set by walk and is already canonical.
    /// Allows lopen/lcreate to skip redundant re-canonicalization.
    is_canonical: bool,
}

/// 9P2000.L server that serves files from a host directory.
pub struct Server {
    /// Root directory on the host filesystem.
    root: PathBuf,
    /// Policy engine for access control.
    policy: Arc<dyn Policy>,
    /// FID → state mapping for this connection.
    fids: HashMap<u32, FidState>,
    /// Negotiated maximum message size.
    msize: u32,
    /// Whether to rewrite syscall instructions in ELF files.
    rewrite_syscalls: bool,
    /// Cache of patched ELF data, keyed by canonical path.
    /// Stores `(mtime_secs, patched_data)` to invalidate when the file changes.
    elf_cache: HashMap<PathBuf, (i64, Arc<Vec<u8>>)>,
}

impl Server {
    /// Create a new 9P server.
    ///
    /// # Arguments
    /// * `root` - Root directory to serve
    /// * `policy` - Policy engine for access control
    /// * `rewrite_syscalls` - Whether to patch ELF files with syscall trampolines
    pub fn new(root: PathBuf, policy: Arc<dyn Policy>, rewrite_syscalls: bool) -> Self {
        Self {
            root,
            policy,
            fids: HashMap::new(),
            msize: 4 * 1024 * 1024,
            rewrite_syscalls,
            elf_cache: HashMap::new(),
        }
    }

    /// Canonicalize `path` and verify it is contained within the server root.
    ///
    /// Returns the canonical path on success, or an `EPERM` error response
    /// value when the resolved path escapes the root directory (e.g. via a
    /// symlink pointing outside the jail).
    fn resolve_and_check(&self, path: &Path) -> Result<PathBuf, u32> {
        let canonical = fs::canonicalize(path).map_err(io_errno)?;
        if canonical.starts_with(&self.root) {
            Ok(canonical)
        } else {
            Err(libc::EPERM as u32)
        }
    }

    /// Fast containment check when the path is already canonical (from walk).
    /// Falls back to full canonicalization when `is_canonical` is false.
    ///
    /// # Safety assumption
    ///
    /// The `is_canonical` shortcut assumes the host filesystem under the
    /// export root does not change between the walk that set the flag and
    /// this check (e.g. no external process replaces a directory with a
    /// symlink pointing outside the root). This is a standard TOCTOU
    /// trade-off: the walk already canonicalized the path, so re-doing it
    /// on every open/stat would be redundant in the normal case and costly.
    /// If the export tree is mutated concurrently by untrusted code, this
    /// shortcut should be disabled.
    fn resolve_fid_path(&self, path: &Path, is_canonical: bool) -> Result<PathBuf, u32> {
        if is_canonical {
            if path.starts_with(&self.root) {
                Ok(path.to_path_buf())
            } else {
                Err(libc::EPERM as u32)
            }
        } else {
            self.resolve_and_check(path)
        }
    }

    /// Run the server loop, reading requests and sending responses.
    ///
    /// Returns when the connection is closed or an unrecoverable I/O error occurs.
    pub fn serve<T: Read + Write>(&mut self, transport: &mut T) {
        let mut rbuf = Vec::with_capacity(self.msize as usize);
        let mut wbuf = Vec::with_capacity(self.msize as usize);

        // Before version negotiation we don't know the client's msize yet.
        // Use a safe upper bound (1 MiB) for the very first message.
        const INITIAL_MAX_SIZE: u32 = 1_048_576;
        let mut current_max = INITIAL_MAX_SIZE;

        let mut request_count: u64 = 0;
        let mut op_counts: std::collections::HashMap<&str, u64> = std::collections::HashMap::new();

        loop {
            // Read the raw message bytes, bounded by the negotiated msize
            if let Err(e) = transport::read_to_buf(transport, &mut rbuf, current_max) {
                let mut sorted: Vec<_> = op_counts.iter().collect();
                sorted.sort_by(|a, b| b.1.cmp(a.1));
                let breakdown: String = sorted
                    .iter()
                    .map(|(k, v)| format!("{}={}", k, v))
                    .collect::<Vec<_>>()
                    .join(", ");
                debug!(
                    "9P connection closed after {} requests: {:?}\n  ops: {}",
                    request_count, e, breakdown
                );
                return;
            }

            // After version negotiation, enforce the negotiated msize
            current_max = self.msize;

            // Decode and convert to owned request (releases borrow on rbuf)
            let (tag, request) = match TaggedFcall::decode(&rbuf) {
                Ok(msg) => (msg.tag, OwnedRequest::from_fcall(msg.fcall)),
                Err(_) => {
                    warn!(
                        "9P decode error after {} requests (buf len={}), closing connection",
                        request_count,
                        rbuf.len()
                    );
                    return;
                }
            };

            request_count += 1;

            // Count per-operation type for profiling.
            let op_name = match &request {
                OwnedRequest::Version { .. } => "version",
                OwnedRequest::Attach { .. } => "attach",
                OwnedRequest::Walk { .. } => "walk",
                OwnedRequest::Lopen { .. } => "lopen",
                OwnedRequest::Lcreate { .. } => "lcreate",
                OwnedRequest::Read { .. } => "read",
                OwnedRequest::Write { .. } => "write",
                OwnedRequest::Getattr { .. } => "getattr",
                OwnedRequest::Setattr { .. } => "setattr",
                OwnedRequest::Readdir { .. } => "readdir",
                OwnedRequest::Mkdir { .. } => "mkdir",
                OwnedRequest::Unlinkat { .. } => "unlinkat",
                OwnedRequest::Rename { .. } => "rename",
                OwnedRequest::Renameat { .. } => "renameat",
                OwnedRequest::Statfs { .. } => "statfs",
                OwnedRequest::Fsync { .. } => "fsync",
                OwnedRequest::Clunk { .. } => "clunk",
                OwnedRequest::Remove { .. } => "remove",
                OwnedRequest::Flush => "flush",
                OwnedRequest::Readlink { .. } => "readlink",
                OwnedRequest::Statpath { .. } => "statpath",
                OwnedRequest::Openpath { .. } => "openpath",
                OwnedRequest::Readlinkpath { .. } => "readlinkpath",
                OwnedRequest::Unknown => "unknown",
            };
            *op_counts.entry(op_name).or_insert(0) += 1;

            let response = self.dispatch(request);

            // Log error responses at debug level
            if let Fcall::Rlerror(ref e) = response {
                debug!(
                    "9P error response: errno={} (request #{})",
                    e.ecode, request_count
                );
            }

            let reply = TaggedFcall {
                tag,
                fcall: response,
            };
            if transport::write_message(transport, &mut wbuf, reply).is_err() {
                warn!(
                    "9P write error after {} requests, closing connection",
                    request_count
                );
                return;
            }
        }
    }

    /// Dispatch a single 9P request to the appropriate handler.
    fn dispatch<'a>(&mut self, request: OwnedRequest) -> Fcall<'a> {
        match request {
            OwnedRequest::Version { msize, version } => self.handle_version(msize, version),
            OwnedRequest::Attach { fid, aname } => self.handle_attach(fid, aname),
            OwnedRequest::Walk {
                fid,
                new_fid,
                wnames,
            } => self.handle_walk(fid, new_fid, wnames),
            OwnedRequest::Lopen { fid, flags } => self.handle_lopen(fcall::Tlopen { fid, flags }),
            OwnedRequest::Lcreate {
                fid,
                name,
                flags,
                mode,
                gid,
            } => self.handle_lcreate(fid, name, flags, mode, gid),
            OwnedRequest::Read { fid, offset, count } => {
                self.handle_read(fcall::Tread { fid, offset, count })
            }
            OwnedRequest::Write { fid, offset, data } => self.handle_write(fid, offset, data),
            OwnedRequest::Getattr { fid, req_mask } => {
                self.handle_getattr(fcall::Tgetattr { fid, req_mask })
            }
            OwnedRequest::Setattr { fid, valid, stat } => {
                self.handle_setattr(fcall::Tsetattr { fid, valid, stat })
            }
            OwnedRequest::Readdir { fid, offset, count } => {
                self.handle_readdir(fcall::Treaddir { fid, offset, count })
            }
            OwnedRequest::Mkdir {
                dfid,
                name,
                mode,
                gid,
            } => self.handle_mkdir(dfid, name, mode, gid),
            OwnedRequest::Unlinkat { dfid, name, flags } => self.handle_unlinkat(dfid, name, flags),
            OwnedRequest::Rename { fid, dfid, name } => self.handle_rename(fid, dfid, name),
            OwnedRequest::Renameat {
                olddfid,
                oldname,
                newdfid,
                newname,
            } => self.handle_renameat(olddfid, oldname, newdfid, newname),
            OwnedRequest::Statfs { fid } => self.handle_statfs(fid),
            OwnedRequest::Fsync { fid, datasync } => {
                self.handle_fsync(fcall::Tfsync { fid, datasync })
            }
            OwnedRequest::Clunk { fid } => self.handle_clunk(fcall::Tclunk { fid }),
            OwnedRequest::Remove { fid } => self.handle_remove(fcall::Tremove { fid }),
            OwnedRequest::Flush => Fcall::Rflush(fcall::Rflush {}),
            OwnedRequest::Readlink { fid } => self.handle_readlink(fid),
            OwnedRequest::Statpath {
                fid,
                req_mask,
                wnames,
            } => self.handle_statpath(fid, req_mask, wnames),
            OwnedRequest::Openpath {
                fid,
                new_fid,
                flags,
                wnames,
            } => self.handle_openpath(fid, new_fid, flags, wnames),
            OwnedRequest::Readlinkpath { fid, wnames } => self.handle_readlinkpath(fid, wnames),
            OwnedRequest::Unknown => error_response(libc::ENOSYS as u32),
        }
    }

    // ========================================================================
    // Version & attach
    // ========================================================================

    fn handle_version<'a>(&mut self, msize: u32, version: Vec<u8>) -> Fcall<'a> {
        if version != b"9P2000.L" {
            return error_response(libc::ENOTSUP as u32);
        }

        // Negotiate msize: use the smaller of client's and our max
        let max_msize = 4 * 1024 * 1024;
        self.msize = msize.min(max_msize);

        Fcall::Rversion(fcall::Rversion {
            msize: self.msize,
            version: Cow::Owned(b"9P2000.L".to_vec()),
        })
    }

    fn handle_attach<'a>(&mut self, fid: u32, aname: String) -> Fcall<'a> {
        if self.fids.contains_key(&fid) {
            return error_response(libc::EEXIST as u32);
        }
        if self.fids.len() >= MAX_FIDS {
            return error_response(libc::ENOMEM as u32);
        }

        // Resolve the attach path relative to root, preventing traversal attacks
        let path = if aname.is_empty() || aname == "/" {
            self.root.clone()
        } else {
            let relative = aname.trim_start_matches('/');
            let candidate = self.root.join(relative);
            match candidate.canonicalize() {
                Ok(canonical) if canonical.starts_with(&self.root) => canonical,
                _ => return error_response(libc::EPERM as u32),
            }
        };

        let qid = match path_to_qid(&path) {
            Ok(qid) => qid,
            Err(errno) => return error_response(errno),
        };

        self.fids.insert(
            fid,
            FidState {
                path,
                file: None,
                patched_data: None,
                patched_offset: 0,
                qid,
                is_open: false,
                is_canonical: true,
            },
        );

        Fcall::Rattach(fcall::Rattach { qid })
    }

    // ========================================================================
    // Walk
    // ========================================================================

    fn handle_walk<'a>(&mut self, fid: u32, new_fid: u32, wnames: Vec<Vec<u8>>) -> Fcall<'a> {
        let src_fid = match self.fids.get(&fid) {
            Some(f) => f,
            None => return error_response(libc::EBADF as u32),
        };

        if self.fids.contains_key(&new_fid) && fid != new_fid {
            return error_response(libc::EEXIST as u32);
        }
        if self.fids.len() >= MAX_FIDS && !self.fids.contains_key(&new_fid) {
            return error_response(libc::ENOMEM as u32);
        }

        let mut current_path = src_fid.path.clone();
        let mut wqids = Vec::new();

        // Empty walk = clone the fid
        if wnames.is_empty() {
            let qid = src_fid.qid;
            let is_canonical = src_fid.is_canonical;
            if fid != new_fid {
                self.fids.insert(
                    new_fid,
                    FidState {
                        path: current_path,
                        file: None,
                        patched_data: None,
                        patched_offset: 0,
                        qid,
                        is_open: false,
                        is_canonical,
                    },
                );
            }
            return Fcall::Rwalk(fcall::Rwalk { wqids });
        }

        // Component-by-component walk with containment check.
        // Symlinks are resolved transparently: we canonicalize after each
        // step so the stored path always points at the real location.
        for name in &wnames {
            let component = match std::str::from_utf8(name) {
                Ok(s) => s,
                Err(_) => break,
            };

            // Prevent path escapes
            if component.contains('/') || component.contains('\0') {
                break;
            }

            // Handle . and ..
            let next = if component == "." {
                current_path.clone()
            } else if component == ".." {
                // Don't go above root
                if current_path == self.root {
                    current_path.clone()
                } else {
                    current_path.parent().unwrap_or(&self.root).to_path_buf()
                }
            } else {
                current_path.join(component)
            };

            // Canonicalize to follow symlinks. This resolves the real path
            // so subsequent walk steps work correctly even through symlinks.
            let resolved = match fs::canonicalize(&next) {
                Ok(p) => p,
                Err(_) => break,
            };

            // Containment check on the resolved (real) path
            if !resolved.starts_with(&self.root) {
                break;
            }

            // Use metadata (follows symlinks) for the QID so the client sees
            // the target type (dir/file), not the symlink itself.
            match fs::metadata(&resolved) {
                Ok(meta) => {
                    wqids.push(metadata_to_qid(&meta));
                    current_path = resolved;
                }
                Err(_) => break,
            }
        }

        // Per 9P spec: if no names were walked, return error
        if wqids.is_empty() && !wnames.is_empty() {
            return error_response(libc::ENOENT as u32);
        }

        // Only update FID if ALL components were walked
        if wqids.len() == wnames.len() {
            let qid = *wqids.last().unwrap();
            if fid == new_fid {
                // In-place update
                if let Some(state) = self.fids.get_mut(&fid) {
                    state.path = current_path;
                    state.qid = qid;
                    state.file = None;
                    state.patched_data = None;
                    state.is_open = false;
                    state.is_canonical = true;
                }
            } else {
                self.fids.insert(
                    new_fid,
                    FidState {
                        path: current_path,
                        file: None,
                        patched_data: None,
                        patched_offset: 0,
                        qid,
                        is_open: false,
                        is_canonical: true,
                    },
                );
            }
        }

        Fcall::Rwalk(fcall::Rwalk { wqids })
    }

    // ========================================================================
    // Open / Create
    // ========================================================================

    fn handle_lopen<'a>(&mut self, req: fcall::Tlopen) -> Fcall<'a> {
        // Extract what we need from fid state with an immutable borrow first
        let (is_open, path, is_canonical) = match self.fids.get(&req.fid) {
            Some(s) => (s.is_open, s.path.clone(), s.is_canonical),
            None => return error_response(libc::EBADF as u32),
        };

        trace!(
            "lopen fid={} path={} flags={:?}",
            req.fid,
            path.display(),
            req.flags
        );

        if is_open {
            return error_response(libc::EIO as u32);
        }

        // If the path was already canonicalized by walk, skip the
        // expensive re-canonicalization and just verify containment.
        // Otherwise, resolve symlinks before opening.
        let resolved = match self.resolve_fid_path(&path, is_canonical) {
            Ok(p) => p,
            Err(errno) => return error_response(errno),
        };

        // Policy check using the full canonical path
        if self.policy.check(Action::Open, Some(&resolved)) == Decision::Deny {
            return error_response(libc::EPERM as u32);
        }

        let flags = req.flags;
        let is_write = flags.intersects(
            fcall::LOpenFlags::O_WRONLY | fcall::LOpenFlags::O_RDWR | fcall::LOpenFlags::O_TRUNC,
        );
        if is_write && self.policy.check(Action::Write, Some(&resolved)) == Decision::Deny {
            return error_response(libc::EPERM as u32);
        }

        let mut opts = fs::OpenOptions::new();
        configure_open_options(&mut opts, flags);

        match opts.open(&resolved) {
            Ok(mut file) => {
                let meta = match file.metadata() {
                    Ok(m) => m,
                    Err(e) => return io_error_response(e),
                };
                let qid = metadata_to_qid(&meta);

                // Try ELF patching for read-only opens (no conflicting borrow now)
                let is_read_only =
                    !flags.intersects(fcall::LOpenFlags::O_WRONLY | fcall::LOpenFlags::O_RDWR);
                let patched = self.try_patch_elf(&mut file, &path, is_read_only);

                // Now get mutable access to update the state
                let state = self.fids.get_mut(&req.fid).unwrap();
                state.file = Some(file);
                state.patched_data = patched;
                state.patched_offset = 0;
                state.qid = qid;
                state.is_open = true;

                Fcall::Rlopen(fcall::Rlopen {
                    qid,
                    iounit: self.msize - fcall::IOHDRSZ,
                })
            }
            Err(e) => io_error_response(e),
        }
    }

    fn handle_lcreate<'a>(
        &mut self,
        fid: u32,
        name: String,
        flags: fcall::LOpenFlags,
        mode: u32,
        _gid: u32,
    ) -> Fcall<'a> {
        // Extract what we need before taking a mutable borrow later.
        let (parent_path, is_canonical) = match self.fids.get(&fid) {
            Some(s) => (s.path.clone(), s.is_canonical),
            None => return error_response(libc::EBADF as u32),
        };

        // Validate name
        if name.contains('/') || name.contains('\0') || name == "." || name == ".." {
            return error_response(libc::EINVAL as u32);
        }

        let target = parent_path.join(&name);

        // Containment check — resolve the parent directory to catch symlink escapes.
        // Skip re-canonicalization if walk already produced a canonical path.
        let resolved_parent = match self.resolve_fid_path(&parent_path, is_canonical) {
            Ok(p) => p,
            _ => return error_response(libc::EPERM as u32),
        };
        let resolved_target = resolved_parent.join(&name);
        if !resolved_target.starts_with(&self.root) {
            return error_response(libc::EPERM as u32);
        }

        // Policy check BEFORE file creation using full canonical path
        if self
            .policy
            .check(Action::Open, Some(resolved_target.as_path()))
            == Decision::Deny
        {
            return error_response(libc::EPERM as u32);
        }
        if self
            .policy
            .check(Action::Write, Some(resolved_target.as_path()))
            == Decision::Deny
        {
            return error_response(libc::EPERM as u32);
        }

        let mut opts = fs::OpenOptions::new();
        opts.read(true).write(true).create(true);
        if flags.contains(fcall::LOpenFlags::O_EXCL) {
            opts.create_new(true);
        }
        if flags.contains(fcall::LOpenFlags::O_TRUNC) {
            opts.truncate(true);
        }
        if flags.contains(fcall::LOpenFlags::O_APPEND) {
            opts.append(true);
        }
        opts.mode(mode);

        match opts.open(&resolved_target) {
            Ok(file) => {
                let meta = match file.metadata() {
                    Ok(m) => m,
                    Err(e) => return io_error_response(e),
                };
                let qid = metadata_to_qid(&meta);

                // After create, the fid now represents the new file (not the parent dir)
                let state = self.fids.get_mut(&fid).unwrap();
                state.path = target;
                state.file = Some(file);
                state.patched_data = None;
                state.patched_offset = 0;
                state.qid = qid;
                state.is_open = true;
                state.is_canonical = false;

                Fcall::Rlcreate(fcall::Rlcreate {
                    qid,
                    iounit: self.msize - fcall::IOHDRSZ,
                })
            }
            Err(e) => io_error_response(e),
        }
    }

    // ========================================================================
    // Read / Write
    // ========================================================================

    fn handle_read<'a>(&mut self, req: fcall::Tread) -> Fcall<'a> {
        let state = match self.fids.get_mut(&req.fid) {
            Some(s) => s,
            None => return error_response(libc::EBADF as u32),
        };

        let max_count = (self.msize - fcall::IOHDRSZ) as usize;
        let count = (req.count as usize).min(max_count);

        // For patched ELFs, serve from cached patched data
        if let Some(ref data) = state.patched_data {
            let offset = req.offset;
            let data_len = data.len() as u64;
            if offset >= data_len {
                return Fcall::Rread(fcall::Rread {
                    data: Cow::Owned(vec![]),
                });
            }
            let available = (data_len - offset) as usize;
            let n = count.min(available);
            let buf = data[offset as usize..offset as usize + n].to_vec();
            return Fcall::Rread(fcall::Rread {
                data: Cow::Owned(buf),
            });
        }

        let file = match state.file.as_ref() {
            Some(f) => f,
            None => return error_response(libc::EBADF as u32),
        };

        let mut buf = vec![0u8; count];
        match file.read_at(&mut buf, req.offset) {
            Ok(n) => {
                buf.truncate(n);
                Fcall::Rread(fcall::Rread {
                    data: Cow::Owned(buf),
                })
            }
            Err(e) => io_error_response(e),
        }
    }

    fn handle_write<'a>(&mut self, fid: u32, offset: u64, data: Vec<u8>) -> Fcall<'a> {
        let state = match self.fids.get_mut(&fid) {
            Some(s) => s,
            None => return error_response(libc::EBADF as u32),
        };

        // Policy check for write using the full path
        if self.policy.check(Action::Write, Some(&state.path)) == Decision::Deny {
            return error_response(libc::EPERM as u32);
        }

        let file = match state.file.as_ref() {
            Some(f) => f,
            None => return error_response(libc::EBADF as u32),
        };

        match file.write_at(&data, offset) {
            Ok(n) => Fcall::Rwrite(fcall::Rwrite { count: n as u32 }),
            Err(e) => io_error_response(e),
        }
    }

    // ========================================================================
    // Stat / Setattr
    // ========================================================================

    /// Walk a sequence of path components from a starting fid, returning
    /// the resolved path. When `follow_final` is false, the last component
    /// is not canonicalized (used by readlink to avoid following the
    /// symlink it wants to read).
    fn walk_path_components(
        &self,
        fid: u32,
        wnames: &[Vec<u8>],
        follow_final: bool,
    ) -> Result<PathBuf, u32> {
        let src_fid = self.fids.get(&fid).ok_or(libc::EBADF as u32)?;
        let mut current_path = src_fid.path.clone();

        for (i, name) in wnames.iter().enumerate() {
            let component = std::str::from_utf8(name).map_err(|_| libc::ENOENT as u32)?;
            if component.contains('/') || component.contains('\0') {
                return Err(libc::ENOENT as u32);
            }

            let next = if component == "." {
                current_path.clone()
            } else if component == ".." {
                if current_path == self.root {
                    current_path.clone()
                } else {
                    current_path.parent().unwrap_or(&self.root).to_path_buf()
                }
            } else {
                current_path.join(component)
            };

            let is_final = i == wnames.len() - 1;
            if !is_final || follow_final {
                let resolved = fs::canonicalize(&next).map_err(io_errno)?;
                if !resolved.starts_with(&self.root) {
                    return Err(libc::EACCES as u32);
                }
                current_path = resolved;
            } else {
                current_path = next;
            }
        }

        Ok(current_path)
    }

    /// Combined walk + getattr + (implicit) clunk in one RPC.
    /// Walks the path components from `fid`, stats the target, and returns
    /// both the qid and attributes without allocating a client-visible fid.
    fn handle_statpath<'a>(
        &self,
        fid: u32,
        req_mask: fcall::GetattrMask,
        wnames: Vec<Vec<u8>>,
    ) -> Fcall<'a> {
        let current_path = match self.walk_path_components(fid, &wnames, true) {
            Ok(p) => p,
            Err(errno) => return error_response(errno),
        };

        // Get attributes on the final path.
        let meta = match fs::symlink_metadata(&current_path) {
            Ok(m) => m,
            Err(e) => return io_error_response(e),
        };

        let qid = metadata_to_qid(&meta);

        Fcall::Rstatpath(fcall::Rstatpath {
            valid: req_mask,
            qid,
            stat: fcall::Stat {
                mode: meta.mode(),
                uid: meta.uid(),
                gid: meta.gid(),
                nlink: meta.nlink(),
                rdev: meta.rdev(),
                size: meta.len(),
                blksize: meta.blksize(),
                blocks: meta.blocks(),
                atime: new_time(meta.atime() as u64, meta.atime_nsec() as u64),
                mtime: new_time(meta.mtime() as u64, meta.mtime_nsec() as u64),
                ctime: new_time(meta.ctime() as u64, meta.ctime_nsec() as u64),
                btime: fcall::Time::default(),
                generation: 0,
                data_version: 0,
            },
        })
    }

    /// Combined walk + lopen in one RPC.
    /// Walks the path components from `fid`, opens the target, and assigns
    /// the opened file to `new_fid`.
    fn handle_openpath<'a>(
        &mut self,
        fid: u32,
        new_fid: u32,
        flags: fcall::LOpenFlags,
        wnames: Vec<Vec<u8>>,
    ) -> Fcall<'a> {
        if self.fids.contains_key(&new_fid) && fid != new_fid {
            return error_response(libc::EEXIST as u32);
        }
        if self.fids.len() >= MAX_FIDS && !self.fids.contains_key(&new_fid) {
            return error_response(libc::ENOMEM as u32);
        }

        let current_path = match self.walk_path_components(fid, &wnames, true) {
            Ok(p) => p,
            Err(errno) => return error_response(errno),
        };

        // Policy checks (same as handle_lopen).
        if self.policy.check(Action::Open, Some(&current_path)) == Decision::Deny {
            return error_response(libc::EPERM as u32);
        }
        let is_write = flags.intersects(
            fcall::LOpenFlags::O_WRONLY | fcall::LOpenFlags::O_RDWR | fcall::LOpenFlags::O_TRUNC,
        );
        if is_write && self.policy.check(Action::Write, Some(&current_path)) == Decision::Deny {
            return error_response(libc::EPERM as u32);
        }

        let mut opts = fs::OpenOptions::new();
        configure_open_options(&mut opts, flags);

        match opts.open(&current_path) {
            Ok(mut file) => {
                let meta = match file.metadata() {
                    Ok(m) => m,
                    Err(e) => return io_error_response(e),
                };
                let qid = metadata_to_qid(&meta);

                let is_read_only =
                    !flags.intersects(fcall::LOpenFlags::O_WRONLY | fcall::LOpenFlags::O_RDWR);
                let patched = self.try_patch_elf(&mut file, &current_path, is_read_only);

                self.fids.insert(
                    new_fid,
                    FidState {
                        path: current_path,
                        file: Some(file),
                        patched_data: patched,
                        patched_offset: 0,
                        qid,
                        is_open: true,
                        is_canonical: true,
                    },
                );

                Fcall::Ropenpath(fcall::Ropenpath {
                    qid,
                    iounit: self.msize - fcall::IOHDRSZ,
                })
            }
            Err(e) => io_error_response(e),
        }
    }

    fn handle_getattr<'a>(&mut self, req: fcall::Tgetattr) -> Fcall<'a> {
        let state = match self.fids.get(&req.fid) {
            Some(s) => s,
            None => return error_response(libc::EBADF as u32),
        };

        // Use fd-based metadata if available (more accurate for open files)
        let meta = if let Some(ref file) = state.file {
            match file.metadata() {
                Ok(m) => m,
                Err(e) => return io_error_response(e),
            }
        } else {
            // Use symlink_metadata to not follow symlinks
            match fs::symlink_metadata(&state.path) {
                Ok(m) => m,
                Err(e) => return io_error_response(e),
            }
        };

        let qid = metadata_to_qid(&meta);
        let mut size = meta.len();

        // For patched ELFs, report patched size
        if let Some(ref data) = state.patched_data {
            size = data.len() as u64;
        }

        Fcall::Rgetattr(fcall::Rgetattr {
            valid: req.req_mask,
            qid,
            stat: fcall::Stat {
                mode: meta.mode(),
                uid: meta.uid(),
                gid: meta.gid(),
                nlink: meta.nlink(),
                rdev: meta.rdev(),
                size,
                blksize: meta.blksize(),
                blocks: meta.blocks(),
                atime: new_time(meta.atime() as u64, meta.atime_nsec() as u64),
                mtime: new_time(meta.mtime() as u64, meta.mtime_nsec() as u64),
                ctime: new_time(meta.ctime() as u64, meta.ctime_nsec() as u64),
                btime: fcall::Time::default(),
                generation: 0,
                data_version: 0,
            },
        })
    }

    fn handle_setattr<'a>(&mut self, req: fcall::Tsetattr) -> Fcall<'a> {
        // Extract path/canonical info before mutable borrow for file handle.
        let (path, is_canonical) = match self.fids.get(&req.fid) {
            Some(s) => (s.path.clone(), s.is_canonical),
            None => return error_response(libc::EBADF as u32),
        };

        // chmod
        if req.valid.contains(fcall::SetattrMask::MODE) {
            let resolved = match self.resolve_fid_path(&path, is_canonical) {
                Ok(p) => p,
                Err(errno) => return error_response(errno),
            };
            if self.policy.check(Action::Chmod, Some(&resolved)) == Decision::Deny {
                return error_response(libc::EPERM as u32);
            }
            let perms = fs_compat::permissions_from_mode(req.stat.mode);
            if let Err(e) = fs::set_permissions(&resolved, perms) {
                return io_error_response(e);
            }
        }

        // chown — no-op for sandbox compatibility (glibc expects success)
        // uid and gid set requests are silently accepted

        // truncate
        if req.valid.contains(fcall::SetattrMask::SIZE) {
            let resolved = match self.resolve_fid_path(&path, is_canonical) {
                Ok(p) => p,
                Err(errno) => return error_response(errno),
            };
            if self.policy.check(Action::Truncate, Some(&resolved)) == Decision::Deny {
                return error_response(libc::EPERM as u32);
            }
            // Re-borrow mutably only for the file handle access.
            let state = self.fids.get_mut(&req.fid).unwrap();
            if let Some(ref file) = state.file {
                if let Err(e) = file.set_len(req.stat.size) {
                    return io_error_response(e);
                }
            } else if let Err(e) = fs::OpenOptions::new()
                .write(true)
                .open(&resolved)
                .and_then(|f| f.set_len(req.stat.size))
            {
                return io_error_response(e);
            }
        }

        Fcall::Rsetattr(fcall::Rsetattr {})
    }

    // ========================================================================
    // Directory operations
    // ========================================================================

    fn handle_readdir<'a>(&mut self, req: fcall::Treaddir) -> Fcall<'a> {
        let state = match self.fids.get(&req.fid) {
            Some(s) => s,
            None => return error_response(libc::EBADF as u32),
        };

        let read_dir = match fs::read_dir(&state.path) {
            Ok(rd) => rd,
            Err(e) => return io_error_response(e),
        };

        let max_bytes = req.count as u64;
        let mut entries = Vec::new();
        let mut total_size: u64 = 0;
        let mut offset_counter = req.offset + 1;

        // Skip entries up to the requested offset
        let skip_count = req.offset as usize;

        for (i, dir_entry) in read_dir.enumerate() {
            if i < skip_count {
                offset_counter = (i + 2) as u64;
                continue;
            }

            let dir_entry = match dir_entry {
                Ok(e) => e,
                Err(_) => continue,
            };

            let name_bytes = dir_entry
                .file_name()
                .to_string_lossy()
                .into_owned()
                .into_bytes();
            let meta = dir_entry.metadata().ok();
            let qid = meta.as_ref().map(metadata_to_qid).unwrap_or(fcall::Qid {
                typ: fcall::QidType::FILE,
                version: 0,
                path: 0,
            });

            let typ = if qid.typ.contains(fcall::QidType::DIR) {
                fs_compat::DT_DIR
            } else if qid.typ.contains(fcall::QidType::SYMLINK) {
                fs_compat::DT_LNK
            } else {
                fs_compat::DT_REG
            };

            let entry = fcall::DirEntry {
                qid,
                offset: offset_counter,
                typ,
                name: FcallStr::Owned(name_bytes),
            };

            // Check if adding this entry would exceed the limit
            let entry_size = entry.size();
            if total_size + entry_size > max_bytes && !entries.is_empty() {
                break;
            }

            total_size += entry_size;
            entries.push(entry);
            offset_counter += 1;
        }

        Fcall::Rreaddir(fcall::Rreaddir {
            data: fcall::DirEntryData { data: entries },
        })
    }

    fn handle_mkdir<'a>(&mut self, dfid: u32, name: String, mode: u32, _gid: u32) -> Fcall<'a> {
        let state = match self.fids.get(&dfid) {
            Some(s) => s,
            None => return error_response(libc::EBADF as u32),
        };

        if name.contains('/') || name.contains('\0') || name == "." || name == ".." {
            return error_response(libc::EINVAL as u32);
        }

        // Resolve parent directory to catch symlink escapes
        let resolved_parent = match self.resolve_fid_path(&state.path, state.is_canonical) {
            Ok(p) => p,
            Err(errno) => return error_response(errno),
        };
        let target = resolved_parent.join(&name);
        if !target.starts_with(&self.root) {
            return error_response(libc::EPERM as u32);
        }

        if self.policy.check(Action::Mkdir, Some(&target)) == Decision::Deny {
            return error_response(libc::EPERM as u32);
        }

        if let Err(e) = fs::create_dir(&target) {
            return io_error_response(e);
        }

        // Apply permissions
        if mode != 0 {
            let perms = fs_compat::permissions_from_mode(mode);
            let _ = fs::set_permissions(&target, perms);
        }

        match path_to_qid(&target) {
            Ok(qid) => Fcall::Rmkdir(fcall::Rmkdir { qid }),
            Err(errno) => error_response(errno),
        }
    }

    fn handle_unlinkat<'a>(&mut self, dfid: u32, name: String, flags: u32) -> Fcall<'a> {
        let state = match self.fids.get(&dfid) {
            Some(s) => s,
            None => return error_response(libc::EBADF as u32),
        };

        if name.contains('/') || name.contains('\0') || name == "." || name == ".." {
            return error_response(libc::EINVAL as u32);
        }

        // Resolve parent directory to catch symlink escapes
        let resolved_parent = match self.resolve_fid_path(&state.path, state.is_canonical) {
            Ok(p) => p,
            Err(errno) => return error_response(errno),
        };
        let target = resolved_parent.join(&name);
        if !target.starts_with(&self.root) {
            return error_response(libc::EPERM as u32);
        }

        let is_rmdir = flags & AT_REMOVEDIR != 0;

        let action = if is_rmdir {
            Action::Rmdir
        } else {
            Action::Unlink
        };
        if self.policy.check(action, Some(&target)) == Decision::Deny {
            return error_response(libc::EPERM as u32);
        }

        let result = if is_rmdir {
            fs::remove_dir(&target)
        } else {
            fs::remove_file(&target)
        };

        match result {
            Ok(()) => Fcall::Runlinkat(fcall::Runlinkat {}),
            Err(e) => io_error_response(e),
        }
    }

    // ========================================================================
    // Rename
    // ========================================================================

    fn handle_rename<'a>(&mut self, fid: u32, dfid: u32, name: String) -> Fcall<'a> {
        // Validate destination name
        if name.contains('/') || name.contains('\0') || name == "." || name == ".." {
            return error_response(libc::EINVAL as u32);
        }

        let (src_path, src_canonical, dst_dir_path, dst_canonical) = {
            let src = match self.fids.get(&fid) {
                Some(s) => s,
                None => return error_response(libc::EBADF as u32),
            };
            let dst_dir = match self.fids.get(&dfid) {
                Some(s) => s,
                None => return error_response(libc::EBADF as u32),
            };
            (
                src.path.clone(),
                src.is_canonical,
                dst_dir.path.clone(),
                dst_dir.is_canonical,
            )
        };

        // Resolve symlinks on both source and destination
        let resolved_src = match self.resolve_fid_path(&src_path, src_canonical) {
            Ok(p) => p,
            Err(errno) => return error_response(errno),
        };
        let resolved_dst_dir = match self.resolve_fid_path(&dst_dir_path, dst_canonical) {
            Ok(p) => p,
            Err(errno) => return error_response(errno),
        };
        let dst = resolved_dst_dir.join(&name);
        if !dst.starts_with(&self.root) {
            return error_response(libc::EPERM as u32);
        }

        // Policy checks on both source and destination
        if self.policy.check(Action::Write, Some(&resolved_src)) == Decision::Deny {
            return error_response(libc::EPERM as u32);
        }
        if self.policy.check(Action::Write, Some(&dst)) == Decision::Deny {
            return error_response(libc::EPERM as u32);
        }

        match fs::rename(&resolved_src, &dst) {
            Ok(()) => {
                // Update the FID's path to the new location
                if let Some(state) = self.fids.get_mut(&fid) {
                    state.path = dst;
                }
                Fcall::Rrename(fcall::Rrename {})
            }
            Err(e) => io_error_response(e),
        }
    }

    fn handle_renameat<'a>(
        &mut self,
        olddfid: u32,
        oldname: String,
        newdfid: u32,
        newname: String,
    ) -> Fcall<'a> {
        // Validate both names
        if oldname.contains('/') || oldname.contains('\0') || oldname == "." || oldname == ".." {
            return error_response(libc::EINVAL as u32);
        }
        if newname.contains('/') || newname.contains('\0') || newname == "." || newname == ".." {
            return error_response(libc::EINVAL as u32);
        }

        let (old_dir_path, old_canonical, new_dir_path, new_canonical) = {
            let old_dir = match self.fids.get(&olddfid) {
                Some(s) => s,
                None => return error_response(libc::EBADF as u32),
            };
            let new_dir = match self.fids.get(&newdfid) {
                Some(s) => s,
                None => return error_response(libc::EBADF as u32),
            };
            (
                old_dir.path.clone(),
                old_dir.is_canonical,
                new_dir.path.clone(),
                new_dir.is_canonical,
            )
        };

        // Resolve symlinks on both parent directories
        let resolved_old_dir = match self.resolve_fid_path(&old_dir_path, old_canonical) {
            Ok(p) => p,
            Err(errno) => return error_response(errno),
        };
        let resolved_new_dir = match self.resolve_fid_path(&new_dir_path, new_canonical) {
            Ok(p) => p,
            Err(errno) => return error_response(errno),
        };

        let src = resolved_old_dir.join(&oldname);
        let dst = resolved_new_dir.join(&newname);

        if !src.starts_with(&self.root) || !dst.starts_with(&self.root) {
            return error_response(libc::EPERM as u32);
        }

        // Policy checks on both source and destination
        if self.policy.check(Action::Write, Some(&src)) == Decision::Deny {
            return error_response(libc::EPERM as u32);
        }
        if self.policy.check(Action::Write, Some(&dst)) == Decision::Deny {
            return error_response(libc::EPERM as u32);
        }

        match fs::rename(&src, &dst) {
            Ok(()) => Fcall::Rrenameat(fcall::Rrenameat {}),
            Err(e) => io_error_response(e),
        }
    }

    // ========================================================================
    // Statfs / Fsync / Clunk / Remove
    // ========================================================================

    fn handle_statfs<'a>(&mut self, _fid: u32) -> Fcall<'a> {
        // Return a generic statfs suitable for most operations
        Fcall::Rstatfs(new_rstatfs(fcall::Statfs {
            typ: 0x01021997, // V9FS_MAGIC
            bsize: 4096,
            blocks: 1_000_000,
            bfree: 500_000,
            bavail: 500_000,
            files: 1_000_000,
            ffree: 500_000,
            fsid: 0,
            namelen: 255,
        }))
    }

    fn handle_fsync<'a>(&mut self, req: fcall::Tfsync) -> Fcall<'a> {
        let state = match self.fids.get(&req.fid) {
            Some(s) => s,
            None => return error_response(libc::EBADF as u32),
        };

        if let Some(ref file) = state.file {
            if req.datasync != 0 {
                if let Err(e) = file.sync_data() {
                    return io_error_response(e);
                }
            } else if let Err(e) = file.sync_all() {
                return io_error_response(e);
            }
        }

        Fcall::Rfsync(fcall::Rfsync {})
    }

    fn handle_clunk<'a>(&mut self, req: fcall::Tclunk) -> Fcall<'a> {
        // Remove the FID; the file handle (if any) is dropped automatically
        self.fids.remove(&req.fid);
        Fcall::Rclunk(fcall::Rclunk {})
    }

    fn handle_remove<'a>(&mut self, req: fcall::Tremove) -> Fcall<'a> {
        // Remove always clunks the fid, even on error
        let state = match self.fids.remove(&req.fid) {
            Some(s) => s,
            None => return error_response(libc::EBADF as u32),
        };

        // Resolve symlinks to prevent jail escape
        let resolved = match self.resolve_fid_path(&state.path, state.is_canonical) {
            Ok(p) => p,
            Err(errno) => return error_response(errno),
        };

        let is_dir = state.qid.typ.contains(fcall::QidType::DIR);
        let action = if is_dir {
            Action::Rmdir
        } else {
            Action::Unlink
        };
        if self.policy.check(action, Some(&resolved)) == Decision::Deny {
            return error_response(libc::EPERM as u32);
        }

        let result = if is_dir {
            fs::remove_dir(&resolved)
        } else {
            fs::remove_file(&resolved)
        };

        match result {
            Ok(()) => Fcall::Rremove(fcall::Rremove {}),
            Err(e) => io_error_response(e),
        }
    }

    fn handle_readlink<'a>(&self, fid: u32) -> Fcall<'a> {
        let state = match self.fids.get(&fid) {
            Some(s) => s,
            None => return error_response(libc::EBADF as u32),
        };

        match fs::read_link(&state.path) {
            Ok(target) => Fcall::Rreadlink(fcall::Rreadlink {
                target: Cow::Owned(target.as_os_str().as_encoded_bytes().to_vec()),
            }),
            Err(e) => io_error_response(e),
        }
    }

    /// Combined walk + readlink in one RPC.
    /// Walks the path components from `fid` and reads the symlink target
    /// of the final path without creating a client-visible fid.
    fn handle_readlinkpath<'a>(&self, fid: u32, wnames: Vec<Vec<u8>>) -> Fcall<'a> {
        // Don't follow the final symlink — we want to read it, not its target.
        let current_path = match self.walk_path_components(fid, &wnames, false) {
            Ok(p) => p,
            Err(errno) => return error_response(errno),
        };

        match fs::read_link(&current_path) {
            Ok(target) => Fcall::Rreadlinkpath(fcall::Rreadlinkpath {
                target: Cow::Owned(target.as_os_str().as_encoded_bytes().to_vec()),
            }),
            Err(e) => io_error_response(e),
        }
    }

    // ========================================================================
    // ELF patching
    // ========================================================================

    /// Attempt to patch an ELF file with syscall trampolines.
    ///
    /// Only patches read-only opens when syscall rewriting is enabled.
    /// The cache is keyed by path and invalidated when mtime changes.
    fn try_patch_elf(
        &mut self,
        file: &mut fs::File,
        path: &Path,
        is_read_only: bool,
    ) -> Option<Arc<Vec<u8>>> {
        if !self.rewrite_syscalls || !is_read_only {
            return None;
        }

        // Get current mtime for cache validation
        let current_mtime = file
            .metadata()
            .ok()?
            .modified()
            .ok()?
            .duration_since(SystemTime::UNIX_EPOCH)
            .ok()?
            .as_secs() as i64;

        // Check cache with mtime validation
        if let Some((cached_mtime, cached_data)) = self.elf_cache.get(path)
            && *cached_mtime == current_mtime
        {
            return Some(Arc::clone(cached_data));
        }

        // Read the full file
        let mut content = Vec::new();
        file.seek(SeekFrom::Start(0)).ok()?;
        file.read_to_end(&mut content).ok()?;

        // Quick ELF magic check
        if content.len() < 18 || &content[..4] != b"\x7fELF" {
            let _ = file.seek(SeekFrom::Start(0));
            return None;
        }

        // Skip relocatable object files (.o) — they are linker input, not
        // executable code. Patching them would corrupt the data the linker
        // reads and can also cause panics that kill this 9P service thread.
        let e_type = u16::from_le_bytes([content[16], content[17]]);
        if e_type == 1 {
            // ET_REL
            let _ = file.seek(SeekFrom::Start(0));
            return None;
        }

        let patched = match litebox_syscall_rewriter::hook_syscalls_in_elf(&content, None) {
            Ok(p) => p,
            Err(_) => {
                let _ = file.seek(SeekFrom::Start(0));
                return None;
            }
        };

        debug!(
            path = %path.display(),
            original_size = content.len(),
            patched_size = patched.len(),
            "patched ELF with syscall trampolines"
        );

        let arc = Arc::new(patched);
        self.elf_cache
            .insert(path.to_owned(), (current_mtime, Arc::clone(&arc)));
        Some(arc)
    }
}

// ============================================================================
// Owned request type for borrow-checker-safe dispatch
// ============================================================================

/// Owned version of 9P request data, used to break the borrow on the read
/// buffer before calling `&mut self` handler methods.
enum OwnedRequest {
    Version {
        msize: u32,
        version: Vec<u8>,
    },
    Attach {
        fid: u32,
        aname: String,
    },
    Walk {
        fid: u32,
        new_fid: u32,
        wnames: Vec<Vec<u8>>,
    },
    Lopen {
        fid: u32,
        flags: fcall::LOpenFlags,
    },
    Lcreate {
        fid: u32,
        name: String,
        flags: fcall::LOpenFlags,
        mode: u32,
        gid: u32,
    },
    Read {
        fid: u32,
        offset: u64,
        count: u32,
    },
    Write {
        fid: u32,
        offset: u64,
        data: Vec<u8>,
    },
    Getattr {
        fid: u32,
        req_mask: fcall::GetattrMask,
    },
    Setattr {
        fid: u32,
        valid: fcall::SetattrMask,
        stat: fcall::SetAttr,
    },
    Readdir {
        fid: u32,
        offset: u64,
        count: u32,
    },
    Mkdir {
        dfid: u32,
        name: String,
        mode: u32,
        gid: u32,
    },
    Unlinkat {
        dfid: u32,
        name: String,
        flags: u32,
    },
    Rename {
        fid: u32,
        dfid: u32,
        name: String,
    },
    Renameat {
        olddfid: u32,
        oldname: String,
        newdfid: u32,
        newname: String,
    },
    Statfs {
        fid: u32,
    },
    Fsync {
        fid: u32,
        datasync: u32,
    },
    Clunk {
        fid: u32,
    },
    Remove {
        fid: u32,
    },
    Flush,
    Readlink {
        fid: u32,
    },
    Statpath {
        fid: u32,
        req_mask: fcall::GetattrMask,
        wnames: Vec<Vec<u8>>,
    },
    Openpath {
        fid: u32,
        new_fid: u32,
        flags: fcall::LOpenFlags,
        wnames: Vec<Vec<u8>>,
    },
    Readlinkpath {
        fid: u32,
        wnames: Vec<Vec<u8>>,
    },
    Unknown,
}

impl OwnedRequest {
    /// Convert a borrowed `Fcall` into an `OwnedRequest` with fully owned data.
    fn from_fcall(fcall: Fcall<'_>) -> Self {
        match fcall {
            Fcall::Tversion(r) => OwnedRequest::Version {
                msize: r.msize,
                version: r.version.into_owned(),
            },
            Fcall::Tattach(r) => OwnedRequest::Attach {
                fid: r.fid,
                aname: String::from_utf8_lossy(&r.aname).into_owned(),
            },
            Fcall::Twalk(r) => OwnedRequest::Walk {
                fid: r.fid,
                new_fid: r.new_fid,
                wnames: r.wnames.into_iter().map(|w| w.into_owned()).collect(),
            },
            Fcall::Tlopen(r) => OwnedRequest::Lopen {
                fid: r.fid,
                flags: r.flags,
            },
            Fcall::Tlcreate(r) => OwnedRequest::Lcreate {
                fid: r.fid,
                name: String::from_utf8_lossy(&r.name).into_owned(),
                flags: r.flags,
                mode: r.mode,
                gid: r.gid,
            },
            Fcall::Tread(r) => OwnedRequest::Read {
                fid: r.fid,
                offset: r.offset,
                count: r.count,
            },
            Fcall::Twrite(r) => OwnedRequest::Write {
                fid: r.fid,
                offset: r.offset,
                data: r.data.into_owned(),
            },
            Fcall::Tgetattr(r) => OwnedRequest::Getattr {
                fid: r.fid,
                req_mask: r.req_mask,
            },
            Fcall::Tsetattr(r) => OwnedRequest::Setattr {
                fid: r.fid,
                valid: r.valid,
                stat: r.stat,
            },
            Fcall::Treaddir(r) => OwnedRequest::Readdir {
                fid: r.fid,
                offset: r.offset,
                count: r.count,
            },
            Fcall::Tmkdir(r) => OwnedRequest::Mkdir {
                dfid: r.dfid,
                name: String::from_utf8_lossy(&r.name).into_owned(),
                mode: r.mode,
                gid: r.gid,
            },
            Fcall::Tunlinkat(r) => OwnedRequest::Unlinkat {
                dfid: r.dfid,
                name: String::from_utf8_lossy(&r.name).into_owned(),
                flags: r.flags,
            },
            Fcall::Trename(r) => OwnedRequest::Rename {
                fid: r.fid,
                dfid: r.dfid,
                name: String::from_utf8_lossy(&r.name).into_owned(),
            },
            Fcall::Trenameat(r) => OwnedRequest::Renameat {
                olddfid: r.olddfid,
                oldname: String::from_utf8_lossy(&r.oldname).into_owned(),
                newdfid: r.newdfid,
                newname: String::from_utf8_lossy(&r.newname).into_owned(),
            },
            Fcall::Tstatfs(_) => OwnedRequest::Statfs { fid: 0 },
            Fcall::Tfsync(r) => OwnedRequest::Fsync {
                fid: r.fid,
                datasync: r.datasync,
            },
            Fcall::Tclunk(r) => OwnedRequest::Clunk { fid: r.fid },
            Fcall::Tremove(r) => OwnedRequest::Remove { fid: r.fid },
            Fcall::Tflush(_) => OwnedRequest::Flush,
            Fcall::Treadlink(r) => OwnedRequest::Readlink { fid: r.fid },
            Fcall::Tstatpath(r) => OwnedRequest::Statpath {
                fid: r.fid,
                req_mask: r.req_mask,
                wnames: r.wnames.into_iter().map(|w| w.into_owned()).collect(),
            },
            Fcall::Topenpath(r) => OwnedRequest::Openpath {
                fid: r.fid,
                new_fid: r.new_fid,
                flags: r.flags,
                wnames: r.wnames.into_iter().map(|w| w.into_owned()).collect(),
            },
            Fcall::Treadlinkpath(r) => OwnedRequest::Readlinkpath {
                fid: r.fid,
                wnames: r.wnames.into_iter().map(|w| w.into_owned()).collect(),
            },
            _ => OwnedRequest::Unknown,
        }
    }
}

// ============================================================================
// Helper functions
// ============================================================================

/// Create a QID from a file path.
fn path_to_qid(path: &Path) -> Result<fcall::Qid, u32> {
    let meta = fs::symlink_metadata(path).map_err(io_errno)?;
    Ok(metadata_to_qid(&meta))
}

/// Create a QID from file metadata.
fn metadata_to_qid(meta: &fs::Metadata) -> fcall::Qid {
    let typ = if meta.is_dir() {
        fcall::QidType::DIR
    } else if meta.file_type().is_symlink() {
        fcall::QidType::SYMLINK
    } else {
        fcall::QidType::FILE
    };

    fcall::Qid {
        typ,
        version: meta.mtime() as u32,
        path: meta.ino(),
    }
}

/// Create an Rlerror response.
fn error_response<'a>(errno: u32) -> Fcall<'a> {
    Fcall::Rlerror(fcall::Rlerror { ecode: errno })
}

/// Convert an `io::Error` to an Rlerror response.
fn io_error_response<'a>(e: std::io::Error) -> Fcall<'a> {
    error_response(io_errno(e))
}

/// Extract OS errno from an `io::Error`, defaulting to EIO.
fn io_errno(e: std::io::Error) -> u32 {
    e.raw_os_error().unwrap_or(libc::EIO) as u32
}

/// Configure `OpenOptions` from 9P LOpenFlags.
///
/// Used only by `handle_lopen` — `O_CREAT` and `O_EXCL` are intentionally
/// omitted because Tlopen must not create files (that is Tlcreate's job).
fn configure_open_options(opts: &mut fs::OpenOptions, flags: fcall::LOpenFlags) {
    let access = flags.bits() & 0x3;
    match access {
        0 => {
            opts.read(true);
        }
        1 => {
            opts.write(true);
        }
        2 => {
            opts.read(true).write(true);
        }
        _ => {
            opts.read(true);
        }
    }

    if flags.contains(fcall::LOpenFlags::O_TRUNC) {
        opts.truncate(true);
    }
    if flags.contains(fcall::LOpenFlags::O_APPEND) {
        opts.append(true);
    }
}

/// Construct a `fcall::Time` from seconds and nanoseconds.
fn new_time(sec: u64, nsec: u64) -> fcall::Time {
    fcall::Time { sec, nsec }
}

/// Construct a `fcall::Rstatfs` wrapping a `Statfs` value.
fn new_rstatfs(statfs: fcall::Statfs) -> fcall::Rstatfs {
    fcall::Rstatfs { statfs }
}
