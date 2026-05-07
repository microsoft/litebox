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
use std::os::unix::ffi::OsStrExt;
use std::panic::{self, AssertUnwindSafe};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, RwLock, RwLockReadGuard, RwLockWriteGuard};
use std::time::SystemTime;

use super::fs_compat::{self, FileExt, MetadataExt, OpenOptionsExt};

use tracing::{debug, error, trace, warn};

use super::fcall::{self, Fcall, FcallStr, TaggedFcall};
use super::transport::{self, Read, Write};
use crate::policy::{Action, Decision, Policy};

/// Maximum number of FIDs per connection to prevent resource exhaustion.
const MAX_FIDS: usize = 8192;

/// Linux `AT_REMOVEDIR` flag for `Tunlinkat`.
const AT_REMOVEDIR: u32 = 0x200;

/// Cache of patched ELF data, keyed by canonical path.
/// Stores `(mtime_secs, patched_data)` to invalidate when the file changes.
pub type ElfCache = HashMap<PathBuf, (i64, Arc<Vec<u8>>)>;

/// State for a single FID (file identifier) in the 9P server.
struct FidState {
    /// Host-side path this FID refers to. After a successful walk, this
    /// is the fully canonicalized (symlinks resolved) path.
    path: PathBuf,
    /// Unresolved final symlink path from the last successful walk, if any.
    readlink_path: Option<PathBuf>,
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
    /// FID → state mapping for this connection (two-level locking for interior mutability).
    fids: RwLock<HashMap<u32, Arc<RwLock<FidState>>>>,
    /// Negotiated maximum message size (set once during version negotiation).
    msize: AtomicU32,
    /// Whether to rewrite syscall instructions in ELF files.
    rewrite_syscalls: bool,
    /// Cache of patched ELF data, keyed by canonical path.
    elf_cache: Arc<Mutex<ElfCache>>,
    /// Cache of canonical path resolutions. Maps raw path → (canonical path, qid).
    /// Avoids repeated `fs::canonicalize` + `fs::metadata` calls in `handle_walk`.
    /// Invalidated on mutations (unlink, rename, mkdir, symlink, write).
    canonical_cache: Mutex<HashMap<PathBuf, (PathBuf, fcall::Qid)>>,
    /// Optional audit log for structured policy events.
    audit_log: Option<crate::audit::AuditLog>,
}

impl Server {
    fn get_fid(&self, fid: u32) -> Result<Arc<RwLock<FidState>>, u32> {
        let fids = read_lock(&self.fids, "fids");
        fids.get(&fid).cloned().ok_or(libc::EBADF as u32)
    }

    /// Create a new 9P server.
    ///
    /// # Arguments
    /// * `root` - Root directory to serve
    /// * `policy` - Policy engine for access control
    /// * `rewrite_syscalls` - Whether to patch ELF files with syscall trampolines
    pub fn new(root: PathBuf, policy: Arc<dyn Policy>, rewrite_syscalls: bool) -> Self {
        Self::with_elf_cache(
            root,
            policy,
            rewrite_syscalls,
            Arc::new(Mutex::new(HashMap::new())),
        )
    }

    /// Create a new 9P server sharing an existing ELF patch cache.
    ///
    /// Use this when multiple server instances serve the same root directory
    /// so that expensive ELF patching work is shared across connections.
    pub fn with_elf_cache(
        root: PathBuf,
        policy: Arc<dyn Policy>,
        rewrite_syscalls: bool,
        elf_cache: Arc<Mutex<ElfCache>>,
    ) -> Self {
        Self {
            root,
            policy,
            fids: RwLock::new(HashMap::new()),
            msize: AtomicU32::new(4 * 1024 * 1024),
            rewrite_syscalls,
            elf_cache,
            canonical_cache: Mutex::new(HashMap::new()),
            audit_log: None,
        }
    }

    /// Set the audit log for structured policy events.
    pub fn set_audit_log(&mut self, audit_log: crate::audit::AuditLog) {
        self.audit_log = Some(audit_log);
    }

    /// Create a shared ELF cache that can be passed to multiple server instances.
    pub fn new_elf_cache() -> Arc<Mutex<ElfCache>> {
        Arc::new(Mutex::new(HashMap::new()))
    }

    /// Pre-warm the ELF cache by rewriting the specified binaries in a
    /// background thread.  This is called at broker startup so that the
    /// first worker connection doesn't pay the ~3s rewriting cost for
    /// shared libraries like libc.
    pub fn pre_warm_elf_cache(elf_cache: &Arc<Mutex<ElfCache>>, root: &Path, paths: &[&str]) {
        use std::io::{Read, Seek, SeekFrom};

        for rel_path in paths {
            let full = root.join(rel_path.trim_start_matches('/'));
            let resolved = match fs::canonicalize(&full) {
                Ok(p) => p,
                Err(_) => continue,
            };
            let mut file = match fs::File::open(&resolved) {
                Ok(f) => f,
                Err(_) => continue,
            };

            // Check ELF magic
            let mut magic = [0u8; 4];
            if file.read_exact(&mut magic).is_err() || &magic != b"\x7fELF" {
                continue;
            }
            let _ = file.seek(SeekFrom::Start(0));

            let current_mtime = match file
                .metadata()
                .ok()
                .and_then(|m| m.modified().ok())
                .and_then(|t| t.duration_since(SystemTime::UNIX_EPOCH).ok())
            {
                Some(d) => d.as_secs() as i64,
                None => continue,
            };

            // Already cached?
            {
                let cache = mutex_lock(elf_cache, "elf_cache");
                if let Some((mtime, _)) = cache.get(&resolved) {
                    if *mtime == current_mtime {
                        continue;
                    }
                }
            }

            // Quick check for already-patched binary
            let file_len = file.metadata().map(|m| m.len()).unwrap_or(0);
            if file_len >= 32 {
                let mut trailer = [0u8; 8];
                if file.seek(SeekFrom::End(-32)).is_ok()
                    && file.read_exact(&mut trailer).is_ok()
                    && &trailer == litebox_syscall_rewriter::TRAMPOLINE_MAGIC
                {
                    let _ = file.seek(SeekFrom::Start(0));
                    continue;
                }
                let _ = file.seek(SeekFrom::Start(0));
            }

            // Read and rewrite
            let mut content = Vec::new();
            if file.read_to_end(&mut content).is_err() {
                continue;
            }

            let mut skipped_addrs = Vec::new();
            if let Ok(patched) =
                litebox_syscall_rewriter::hook_syscalls_in_elf(&content, None, &mut skipped_addrs)
            {
                let arc = Arc::new(patched);
                let mut cache = mutex_lock(elf_cache, "elf_cache");
                cache.insert(resolved.clone(), (current_mtime, Arc::clone(&arc)));
                eprintln!(
                    "[broker] pre-warmed ELF cache: {} ({} bytes)",
                    resolved.display(),
                    arc.len(),
                );
            }
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

    /// Invalidate canonical path cache entries at or under `path`.
    /// Called on mutations (unlink, rename, mkdir, symlink, write).
    fn invalidate_canonical_cache(&self, path: &Path) {
        let mut cache = mutex_lock(&self.canonical_cache, "canonical_cache");
        cache.retain(|k, _| !k.starts_with(path));
    }

    /// Cached canonicalize + metadata lookup for walk steps.
    /// Returns (canonical_path, qid) or None on failure.
    fn cached_canonicalize(&self, raw_path: &Path) -> Option<(PathBuf, fcall::Qid)> {
        // Check cache first
        {
            let cache = mutex_lock(&self.canonical_cache, "canonical_cache");
            if let Some((canonical, qid)) = cache.get(raw_path) {
                return Some((canonical.clone(), *qid));
            }
        }

        // Cache miss — do the real work
        let canonical = fs::canonicalize(raw_path).ok()?;
        if !canonical.starts_with(&self.root) {
            return None;
        }
        let meta = fs::metadata(&canonical).ok()?;
        let qid = metadata_to_qid(&meta);

        // Store in cache
        let mut cache = mutex_lock(&self.canonical_cache, "canonical_cache");
        // Limit cache size to prevent unbounded growth
        if cache.len() < 10_000 {
            cache.insert(raw_path.to_path_buf(), (canonical.clone(), qid));
        }
        Some((canonical, qid))
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
    pub fn serve<T: Read + Write>(&self, transport: &mut T) {
        let initial_capacity = self.msize.load(Ordering::Acquire) as usize;
        let mut rbuf = Vec::with_capacity(initial_capacity);
        let mut wbuf = Vec::with_capacity(initial_capacity);

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
            current_max = self.msize.load(Ordering::Acquire);

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
                OwnedRequest::Symlink { .. } => "symlink",
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

    /// Run the server loop with concurrent request dispatch.
    ///
    /// Bootstrap (version + attach) runs single-threaded on the calling thread.
    /// After bootstrap, requests are dispatched to `num_workers` threads.
    /// Returns when the connection is closed or an unrecoverable I/O error occurs.
    pub fn serve_threaded<R: Read, W: Write + Send + 'static>(
        server: Arc<Self>,
        mut reader: R,
        mut writer: W,
        num_workers: usize,
    ) {
        const INITIAL_MAX_SIZE: u32 = 1_048_576;

        let mut rbuf = Vec::with_capacity(1_048_576);
        let mut wbuf = Vec::with_capacity(1_048_576);
        let mut current_max = INITIAL_MAX_SIZE;

        // Process version and attach synchronously before spawning workers.
        for phase in ["version", "attach"] {
            if transport::read_to_buf(&mut reader, &mut rbuf, current_max).is_err() {
                debug!("9P connection closed during {} bootstrap", phase);
                return;
            }
            current_max = {
                let m = server.msize.load(Ordering::Acquire);
                if m > 0 { m } else { current_max }
            };
            let (tag, request) = match TaggedFcall::decode(&rbuf) {
                Ok(msg) => (msg.tag, OwnedRequest::from_fcall(msg.fcall)),
                Err(_) => {
                    warn!("9P decode error during bootstrap");
                    return;
                }
            };
            let expected = match phase {
                "version" => matches!(&request, OwnedRequest::Version { .. }),
                "attach" => matches!(&request, OwnedRequest::Attach { .. }),
                _ => false,
            };
            if !expected {
                warn!(
                    "unexpected 9P {} bootstrap request, closing connection",
                    phase
                );
                let reply = TaggedFcall {
                    tag,
                    fcall: error_response(libc::EPROTO as u32),
                };
                let _ = transport::write_message(&mut writer, &mut wbuf, reply);
                return;
            }
            let response = server.dispatch(request);
            let bootstrap_ok = matches!(
                (phase, &response),
                ("version", Fcall::Rversion(_)) | ("attach", Fcall::Rattach(_))
            );
            let reply = TaggedFcall {
                tag,
                fcall: response,
            };
            if transport::write_message(&mut writer, &mut wbuf, reply).is_err() {
                warn!("9P write error during bootstrap");
                return;
            }
            if !bootstrap_ok {
                warn!("9P {} bootstrap failed, closing connection", phase);
                return;
            }
            current_max = {
                let m = server.msize.load(Ordering::Acquire);
                if m > 0 { m } else { current_max }
            };
        }

        if num_workers == 0 {
            warn!("serve_threaded called with zero workers; falling back to inline dispatch");
            loop {
                if transport::read_to_buf(&mut reader, &mut rbuf, current_max).is_err() {
                    break;
                }
                current_max = server.msize.load(Ordering::Acquire);
                let (tag, request) = match TaggedFcall::decode(&rbuf) {
                    Ok(msg) => (msg.tag, OwnedRequest::from_fcall(msg.fcall)),
                    Err(_) => break,
                };
                let response = server.dispatch(request);
                let reply = TaggedFcall {
                    tag,
                    fcall: response,
                };
                if transport::write_message(&mut writer, &mut wbuf, reply).is_err() {
                    break;
                }
            }
            return;
        }

        // Concurrent phase: spawn worker threads and dispatch via channel.
        let writer = Arc::new(std::sync::Mutex::new(writer));
        let shutdown = Arc::new(AtomicBool::new(false));
        let (tx, rx) = std::sync::mpsc::sync_channel::<(u16, OwnedRequest)>(num_workers * 4);
        let rx = Arc::new(std::sync::Mutex::new(rx));

        let mut workers = Vec::with_capacity(num_workers);
        for i in 0..num_workers {
            let server = Arc::clone(&server);
            let rx = Arc::clone(&rx);
            let writer = Arc::clone(&writer);
            let shutdown = Arc::clone(&shutdown);
            match std::thread::Builder::new()
                .name(format!("9p-worker-{i}"))
                .spawn(move || {
                    let msize = server.msize.load(Ordering::Acquire) as usize;
                    let mut wbuf = Vec::with_capacity(msize);
                    loop {
                        let (tag, request) = match mutex_lock(&rx, "threaded_rx").recv() {
                            Ok(item) => item,
                            Err(_) => break,
                        };
                        let response = match panic::catch_unwind(AssertUnwindSafe(|| {
                            server.dispatch(request)
                        })) {
                            Ok(response) => response,
                            Err(e) => {
                                let msg = if let Some(s) = e.downcast_ref::<&str>() {
                                    s.to_string()
                                } else if let Some(s) = e.downcast_ref::<String>() {
                                    s.clone()
                                } else {
                                    "unknown panic".to_string()
                                };
                                error!(tag, "9P worker panicked: {}", msg);
                                error_response(libc::EIO as u32)
                            }
                        };
                        let reply = TaggedFcall {
                            tag,
                            fcall: response,
                        };
                        let write_result = panic::catch_unwind(AssertUnwindSafe(|| {
                            let mut w = mutex_lock(&writer, "threaded_writer");
                            transport::write_message(&mut *w, &mut wbuf, reply)
                        }));
                        match write_result {
                            Ok(Ok(())) => {}
                            Ok(Err(_)) => {
                                shutdown.store(true, Ordering::Release);
                                break;
                            }
                            Err(_) => {
                                shutdown.store(true, Ordering::Release);
                                warn!(tag, "9P worker panicked while writing response");
                                break;
                            }
                        }
                    }
                }) {
                Ok(worker) => workers.push(worker),
                Err(e) => warn!(worker = i, error = %e, "failed to spawn 9P worker thread"),
            }
        }

        if workers.is_empty() {
            warn!("failed to spawn any 9P workers; falling back to inline dispatch");
            drop(tx);
            loop {
                if transport::read_to_buf(&mut reader, &mut rbuf, current_max).is_err() {
                    break;
                }
                current_max = server.msize.load(Ordering::Acquire);
                let (tag, request) = match TaggedFcall::decode(&rbuf) {
                    Ok(msg) => (msg.tag, OwnedRequest::from_fcall(msg.fcall)),
                    Err(_) => break,
                };
                let response = server.dispatch(request);
                let reply = TaggedFcall {
                    tag,
                    fcall: response,
                };
                let mut w = mutex_lock(&writer, "threaded_writer");
                if transport::write_message(&mut *w, &mut wbuf, reply).is_err() {
                    break;
                }
            }
            return;
        }

        // Reader loop: read requests and dispatch to workers.
        'reader: loop {
            if shutdown.load(Ordering::Acquire) {
                break;
            }
            if transport::read_to_buf(&mut reader, &mut rbuf, current_max).is_err() {
                break;
            }
            current_max = server.msize.load(Ordering::Acquire);
            let (tag, request) = match TaggedFcall::decode(&rbuf) {
                Ok(msg) => (msg.tag, OwnedRequest::from_fcall(msg.fcall)),
                Err(_) => break,
            };
            let mut pending = (tag, request);
            loop {
                match tx.try_send(pending) {
                    Ok(()) => break,
                    Err(std::sync::mpsc::TrySendError::Full(item)) => {
                        if shutdown.load(Ordering::Acquire) {
                            break 'reader;
                        }
                        pending = item;
                        std::thread::yield_now();
                    }
                    Err(std::sync::mpsc::TrySendError::Disconnected(_)) => break 'reader,
                }
            }
        }

        // Shutdown: close channel, wait for workers.
        drop(tx);
        for w in workers {
            let worker_name = w.thread().name().unwrap_or("9p-worker").to_string();
            if w.join().is_err() {
                warn!(worker = %worker_name, "9P worker thread panicked during shutdown");
            }
        }
    }

    /// Dispatch a single 9P request to the appropriate handler.
    fn dispatch<'a>(&self, request: OwnedRequest) -> Fcall<'a> {
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
            OwnedRequest::Symlink {
                fid,
                name,
                symtgt,
                gid,
            } => self.handle_symlink(fid, name, symtgt, gid),
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
            OwnedRequest::Unknown => error_response(libc::ENOSYS as u32),
        }
    }

    // ========================================================================
    // Version & attach
    // ========================================================================

    fn handle_version<'a>(&self, msize: u32, version: Vec<u8>) -> Fcall<'a> {
        if version != b"9P2000.L" {
            return error_response(libc::ENOTSUP as u32);
        }
        if msize < fcall::IOHDRSZ {
            return error_response(libc::EINVAL as u32);
        }

        // Negotiate msize: use the smaller of client's and our max
        let max_msize = 4 * 1024 * 1024;
        let negotiated = msize.min(max_msize);
        self.msize.store(negotiated, Ordering::Release);

        Fcall::Rversion(fcall::Rversion {
            msize: negotiated,
            version: Cow::Owned(b"9P2000.L".to_vec()),
        })
    }

    fn handle_attach<'a>(&self, fid: u32, aname: String) -> Fcall<'a> {
        {
            let fids = read_lock(&self.fids, "fids");
            if fids.contains_key(&fid) {
                return error_response(libc::EEXIST as u32);
            }
            if fids.len() >= MAX_FIDS {
                return error_response(libc::ENOMEM as u32);
            }
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

        let mut fids = write_lock(&self.fids, "fids");
        if fids.contains_key(&fid) {
            return error_response(libc::EEXIST as u32);
        }
        if fids.len() >= MAX_FIDS {
            return error_response(libc::ENOMEM as u32);
        }
        fids.insert(
            fid,
            Arc::new(RwLock::new(FidState {
                path,
                readlink_path: None,
                file: None,
                patched_data: None,
                patched_offset: 0,
                qid,
                is_open: false,
                is_canonical: true,
            })),
        );

        Fcall::Rattach(fcall::Rattach { qid })
    }

    // ========================================================================
    // Walk
    // ========================================================================

    fn handle_walk<'a>(&self, fid: u32, new_fid: u32, wnames: Vec<Vec<u8>>) -> Fcall<'a> {
        // Phase 1: Read source fid data, validate fid constraints
        let (src_path, src_qid, src_is_canonical, src_readlink_path) = {
            let fids = read_lock(&self.fids, "fids");
            let fid_arc = match fids.get(&fid) {
                Some(arc) => Arc::clone(arc),
                None => return error_response(libc::EBADF as u32),
            };

            if fids.contains_key(&new_fid) && fid != new_fid {
                return error_response(libc::EEXIST as u32);
            }
            if fids.len() >= MAX_FIDS && !fids.contains_key(&new_fid) {
                return error_response(libc::ENOMEM as u32);
            }
            drop(fids);

            let state = read_lock(&fid_arc, "fid");
            (
                state.path.clone(),
                state.qid,
                state.is_canonical,
                state.readlink_path.clone(),
            )
        };

        let mut current_path = src_path;
        let mut current_is_canonical = src_is_canonical;
        let mut wqids = Vec::new();
        let mut readlink_path = None;

        // Empty walk = clone the fid
        if wnames.is_empty() {
            let qid = src_qid;
            let is_canonical = src_is_canonical;
            let readlink_path = src_readlink_path;
            if fid != new_fid {
                let mut fids = write_lock(&self.fids, "fids");
                if fids.contains_key(&new_fid) {
                    return error_response(libc::EEXIST as u32);
                }
                if fids.len() >= MAX_FIDS {
                    return error_response(libc::ENOMEM as u32);
                }
                fids.insert(
                    new_fid,
                    Arc::new(RwLock::new(FidState {
                        path: current_path,
                        readlink_path,
                        file: None,
                        patched_data: None,
                        patched_offset: 0,
                        qid,
                        is_open: false,
                        is_canonical,
                    })),
                );
            }
            return Fcall::Rwalk(fcall::Rwalk { wqids });
        }

        // Phase 2: Walk I/O — no locks held
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

            let is_final = wqids.len() + 1 == wnames.len();
            if is_final
                && let Ok(meta) = fs::symlink_metadata(&next)
                && meta.file_type().is_symlink()
            {
                if !next.starts_with(&self.root) {
                    break;
                }
                readlink_path = Some(next.clone());
                wqids.push(metadata_to_qid(&meta));
                current_path = next;
                current_is_canonical = false;
                continue;
            }

            // Canonicalize to follow symlinks. This resolves the real path
            // so subsequent walk steps work correctly even through symlinks.
            // Uses the canonical cache to avoid repeated host FS calls.
            let (resolved, qid) = match self.cached_canonicalize(&next) {
                Some(r) => r,
                None => break,
            };

            // Containment check on the resolved (real) path
            if !resolved.starts_with(&self.root) {
                break;
            }

            wqids.push(qid);
            current_path = resolved;
            current_is_canonical = true;
        }

        // Per 9P spec: if no names were walked, return error
        if wqids.is_empty() && !wnames.is_empty() {
            return error_response(libc::ENOENT as u32);
        }

        // Phase 3: Write result — only update FID if ALL components were walked
        if wqids.len() == wnames.len() {
            let qid = *wqids.last().unwrap();
            if fid == new_fid {
                // In-place update
                let fids = read_lock(&self.fids, "fids");
                if let Some(fid_arc) = fids.get(&fid) {
                    let fid_arc = Arc::clone(fid_arc);
                    drop(fids);
                    let mut state = write_lock(&fid_arc, "fid");
                    state.path = current_path;
                    state.readlink_path = readlink_path;
                    state.qid = qid;
                    state.file = None;
                    state.patched_data = None;
                    state.patched_offset = 0;
                    state.is_open = false;
                    state.is_canonical = current_is_canonical;
                }
            } else {
                let mut fids = write_lock(&self.fids, "fids");
                if fids.contains_key(&new_fid) {
                    return error_response(libc::EEXIST as u32);
                }
                if fids.len() >= MAX_FIDS {
                    return error_response(libc::ENOMEM as u32);
                }
                fids.insert(
                    new_fid,
                    Arc::new(RwLock::new(FidState {
                        path: current_path,
                        readlink_path,
                        file: None,
                        patched_data: None,
                        patched_offset: 0,
                        qid,
                        is_open: false,
                        is_canonical: current_is_canonical,
                    })),
                );
            }
        }

        Fcall::Rwalk(fcall::Rwalk { wqids })
    }

    // ========================================================================
    // Open / Create
    // ========================================================================

    fn handle_lopen<'a>(&self, req: fcall::Tlopen) -> Fcall<'a> {
        // Phase 1: Get fid Arc and extract state
        let fid_arc = match self.get_fid(req.fid) {
            Ok(fid_arc) => fid_arc,
            Err(errno) => return error_response(errno),
        };

        let (is_open, path, is_canonical) = {
            let state = read_lock(&fid_arc, "fid");
            (state.is_open, state.path.clone(), state.is_canonical)
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

        // Phase 2: I/O — no fid locks held
        // If the path was already canonicalized by walk, skip the
        // expensive re-canonicalization and just verify containment.
        // Otherwise, resolve symlinks before opening.
        let resolved = match self.resolve_fid_path(&path, is_canonical) {
            Ok(p) => p,
            Err(errno) => return error_response(errno),
        };

        // Policy check using the full canonical path
        if self.policy.check(Action::Open, Some(&resolved)) == Decision::Deny {
            if let Some(ref al) = self.audit_log {
                al.fs_denied(resolved.to_str().unwrap_or("?"), "open");
            }
            return error_response(libc::EPERM as u32);
        }

        let flags = req.flags;
        let is_write = flags.intersects(
            fcall::LOpenFlags::O_WRONLY | fcall::LOpenFlags::O_RDWR | fcall::LOpenFlags::O_TRUNC,
        );
        if is_write && self.policy.check(Action::Write, Some(&resolved)) == Decision::Deny {
            if let Some(ref al) = self.audit_log {
                al.fs_denied(resolved.to_str().unwrap_or("?"), "write");
            }
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

                // Try ELF patching for read-only opens unless the shim is only
                // opening the ELF for its own loader metadata path.
                let is_read_only =
                    !flags.intersects(fcall::LOpenFlags::O_WRONLY | fcall::LOpenFlags::O_RDWR);
                let skip_elf_patch = flags.contains(fcall::LOpenFlags::LITEBOX_NO_ELF_PATCH);
                let patched =
                    self.try_patch_elf(&mut file, &resolved, is_read_only && !skip_elf_patch);

                // Phase 3: Update fid state via inner write lock
                let mut state = write_lock(&fid_arc, "fid");
                state.file = Some(file);
                state.patched_data = patched;
                state.patched_offset = 0;
                state.qid = qid;
                state.is_open = true;
                state.readlink_path = None;

                let msize = self.msize.load(Ordering::Acquire);
                Fcall::Rlopen(fcall::Rlopen {
                    qid,
                    iounit: msize - fcall::IOHDRSZ,
                })
            }
            Err(e) => io_error_response(e),
        }
    }

    fn handle_lcreate<'a>(
        &self,
        fid: u32,
        name: String,
        flags: fcall::LOpenFlags,
        mode: u32,
        _gid: u32,
    ) -> Fcall<'a> {
        // Phase 1: Get fid Arc and extract state
        let fid_arc = match self.get_fid(fid) {
            Ok(fid_arc) => fid_arc,
            Err(errno) => return error_response(errno),
        };

        let (parent_path, is_canonical) = {
            let state = read_lock(&fid_arc, "fid");
            (state.path.clone(), state.is_canonical)
        };

        // Validate name
        if name.contains('/') || name.contains('\0') || name == "." || name == ".." {
            return error_response(libc::EINVAL as u32);
        }

        let target = parent_path.join(&name);

        // Phase 2: I/O — no fid locks held
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

                // Phase 3: Update fid state — after create, the fid now represents
                // the new file (not the parent dir)
                let mut state = write_lock(&fid_arc, "fid");
                state.path = target;
                state.file = Some(file);
                state.patched_data = None;
                state.patched_offset = 0;
                state.qid = qid;
                state.is_open = true;
                state.is_canonical = false;
                state.readlink_path = None;

                let msize = self.msize.load(Ordering::Acquire);
                self.invalidate_canonical_cache(&resolved_target);
                Fcall::Rlcreate(fcall::Rlcreate {
                    qid,
                    iounit: msize - fcall::IOHDRSZ,
                })
            }
            Err(e) => io_error_response(e),
        }
    }

    fn handle_symlink<'a>(&self, fid: u32, name: String, symtgt: Vec<u8>, _gid: u32) -> Fcall<'a> {
        let fid_arc = match self.get_fid(fid) {
            Ok(fid_arc) => fid_arc,
            Err(errno) => return error_response(errno),
        };

        if name.contains('/') || name.contains('\0') || name == "." || name == ".." {
            return error_response(libc::EINVAL as u32);
        }
        if symtgt.contains(&0) {
            return error_response(libc::EINVAL as u32);
        }

        let (parent_path, is_canonical) = {
            let state = read_lock(&fid_arc, "fid");
            (state.path.clone(), state.is_canonical)
        };

        let resolved_parent = match self.resolve_fid_path(&parent_path, is_canonical) {
            Ok(p) => p,
            Err(errno) => return error_response(errno),
        };
        let target = resolved_parent.join(&name);
        if !target.starts_with(&self.root) {
            return error_response(libc::EPERM as u32);
        }

        if self.policy.check(Action::Write, Some(&target)) == Decision::Deny {
            return error_response(libc::EPERM as u32);
        }

        let link_target = std::ffi::OsStr::from_bytes(&symtgt);
        match std::os::unix::fs::symlink(Path::new(link_target), &target) {
            Ok(()) => match path_to_qid(&target) {
                Ok(qid) => {
                    self.invalidate_canonical_cache(&target);
                    Fcall::Rsymlink(fcall::Rsymlink { qid })
                }
                Err(errno) => error_response(errno),
            },
            Err(e) => io_error_response(e),
        }
    }

    // ========================================================================
    // Read / Write
    // ========================================================================

    fn handle_read<'a>(&self, req: fcall::Tread) -> Fcall<'a> {
        let fid_arc = match self.get_fid(req.fid) {
            Ok(fid_arc) => fid_arc,
            Err(errno) => return error_response(errno),
        };

        let msize = self.msize.load(Ordering::Acquire);
        let max_count = (msize - fcall::IOHDRSZ) as usize;
        let count = (req.count as usize).min(max_count);

        let (patched_data, file) = {
            let state = read_lock(&fid_arc, "fid");
            let patched_data = state.patched_data.clone();
            let file = if patched_data.is_some() {
                None
            } else {
                match state.file.as_ref() {
                    Some(file) => match file.try_clone() {
                        Ok(file) => Some(file),
                        Err(e) => return io_error_response(e),
                    },
                    None => None,
                }
            };
            (patched_data, file)
        };

        // For patched ELFs, serve from cached patched data
        if let Some(data) = patched_data {
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

        let file = match file {
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

    fn handle_write<'a>(&self, fid: u32, offset: u64, data: Vec<u8>) -> Fcall<'a> {
        let fid_arc = match self.get_fid(fid) {
            Ok(fid_arc) => fid_arc,
            Err(errno) => return error_response(errno),
        };

        let (path, file) = {
            let state = read_lock(&fid_arc, "fid");
            let file = match state.file.as_ref() {
                Some(file) => match file.try_clone() {
                    Ok(file) => Some(file),
                    Err(e) => return io_error_response(e),
                },
                None => None,
            };
            (state.path.clone(), file)
        };

        // Policy check for write using the full path
        if self.policy.check(Action::Write, Some(&path)) == Decision::Deny {
            if let Some(ref al) = self.audit_log {
                al.fs_denied(path.to_str().unwrap_or("?"), "write");
            }
            return error_response(libc::EPERM as u32);
        }

        let file = match file {
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

    fn handle_getattr<'a>(&self, req: fcall::Tgetattr) -> Fcall<'a> {
        let fid_arc = match self.get_fid(req.fid) {
            Ok(fid_arc) => fid_arc,
            Err(errno) => return error_response(errno),
        };

        let (file, path, patched_size) = {
            let state = read_lock(&fid_arc, "fid");
            let file = match state.file.as_ref() {
                Some(file) => match file.try_clone() {
                    Ok(file) => Some(file),
                    Err(e) => return io_error_response(e),
                },
                None => None,
            };
            let patched_size = state.patched_data.as_ref().map(|data| data.len() as u64);
            (file, state.path.clone(), patched_size)
        };

        // Use fd-based metadata if available (more accurate for open files)
        let meta = if let Some(file) = file {
            match file.metadata() {
                Ok(m) => m,
                Err(e) => return io_error_response(e),
            }
        } else {
            // Use symlink_metadata to not follow symlinks
            match fs::symlink_metadata(&path) {
                Ok(m) => m,
                Err(e) => return io_error_response(e),
            }
        };

        let qid = metadata_to_qid(&meta);
        let mut size = meta.len();

        // For patched ELFs, report patched size
        if let Some(patched_size) = patched_size {
            size = patched_size;
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

    fn handle_setattr<'a>(&self, req: fcall::Tsetattr) -> Fcall<'a> {
        // Get fid Arc and extract path/canonical info
        let fid_arc = match self.get_fid(req.fid) {
            Ok(fid_arc) => fid_arc,
            Err(errno) => return error_response(errno),
        };

        let (path, is_canonical) = {
            let state = read_lock(&fid_arc, "fid");
            (state.path.clone(), state.is_canonical)
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
            let open_file = {
                let state = read_lock(&fid_arc, "fid");
                match state.file.as_ref() {
                    Some(file) => match file.try_clone() {
                        Ok(file) => Some(file),
                        Err(e) => return io_error_response(e),
                    },
                    None => None,
                }
            };
            if let Some(file) = open_file {
                if let Err(e) = file.set_len(req.stat.size) {
                    return io_error_response(e);
                }
            } else {
                if let Err(e) = fs::OpenOptions::new()
                    .write(true)
                    .open(&resolved)
                    .and_then(|f| f.set_len(req.stat.size))
                {
                    return io_error_response(e);
                }
            }
        }

        Fcall::Rsetattr(fcall::Rsetattr {})
    }

    // ========================================================================
    // Directory operations
    // ========================================================================

    fn handle_readdir<'a>(&self, req: fcall::Treaddir) -> Fcall<'a> {
        let fid_arc = match self.get_fid(req.fid) {
            Ok(fid_arc) => fid_arc,
            Err(errno) => return error_response(errno),
        };
        let path = read_lock(&fid_arc, "fid").path.clone();

        let read_dir = match fs::read_dir(&path) {
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

    fn handle_mkdir<'a>(&self, dfid: u32, name: String, mode: u32, _gid: u32) -> Fcall<'a> {
        let fid_arc = match self.get_fid(dfid) {
            Ok(fid_arc) => fid_arc,
            Err(errno) => return error_response(errno),
        };

        if name.contains('/') || name.contains('\0') || name == "." || name == ".." {
            return error_response(libc::EINVAL as u32);
        }

        let (dir_path, is_canonical) = {
            let state = read_lock(&fid_arc, "fid");
            (state.path.clone(), state.is_canonical)
        };

        // Resolve parent directory to catch symlink escapes
        let resolved_parent = match self.resolve_fid_path(&dir_path, is_canonical) {
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
            // EEXIST is benign when the directory already exists — callers
            // like rustup do `mkdir` unconditionally and expect success.
            if e.kind() != std::io::ErrorKind::AlreadyExists {
                return io_error_response(e);
            }
        }

        // Apply permissions
        if mode != 0 {
            let perms = fs_compat::permissions_from_mode(mode);
            let _ = fs::set_permissions(&target, perms);
        }

        match path_to_qid(&target) {
            Ok(qid) => {
                self.invalidate_canonical_cache(&target);
                Fcall::Rmkdir(fcall::Rmkdir { qid })
            }
            Err(errno) => error_response(errno),
        }
    }

    fn handle_unlinkat<'a>(&self, dfid: u32, name: String, flags: u32) -> Fcall<'a> {
        let fid_arc = match self.get_fid(dfid) {
            Ok(fid_arc) => fid_arc,
            Err(errno) => return error_response(errno),
        };

        if name.contains('/') || name.contains('\0') || name == "." || name == ".." {
            return error_response(libc::EINVAL as u32);
        }

        let (dir_path, is_canonical) = {
            let state = read_lock(&fid_arc, "fid");
            (state.path.clone(), state.is_canonical)
        };

        // Resolve parent directory to catch symlink escapes
        let resolved_parent = match self.resolve_fid_path(&dir_path, is_canonical) {
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
            Ok(()) => {
                self.invalidate_canonical_cache(&target);
                Fcall::Runlinkat(fcall::Runlinkat {})
            }
            Err(e) => io_error_response(e),
        }
    }

    // ========================================================================
    // Rename
    // ========================================================================

    fn handle_rename<'a>(&self, fid: u32, dfid: u32, name: String) -> Fcall<'a> {
        // Validate destination name
        if name.contains('/') || name.contains('\0') || name == "." || name == ".." {
            return error_response(libc::EINVAL as u32);
        }

        let (src_arc, dst_arc) = {
            let fids = read_lock(&self.fids, "fids");
            let src_arc = match fids.get(&fid) {
                Some(arc) => Arc::clone(arc),
                None => return error_response(libc::EBADF as u32),
            };
            let dst_arc = match fids.get(&dfid) {
                Some(arc) => Arc::clone(arc),
                None => return error_response(libc::EBADF as u32),
            };
            (src_arc, dst_arc)
        };

        let (src_path, src_canonical) = {
            let src = read_lock(&src_arc, "fid");
            (src.path.clone(), src.is_canonical)
        };
        let (dst_dir_path, dst_canonical) = {
            let dst = read_lock(&dst_arc, "fid");
            (dst.path.clone(), dst.is_canonical)
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
                let mut state = write_lock(&src_arc, "fid");
                state.path = dst.clone();
                self.invalidate_canonical_cache(&resolved_src);
                self.invalidate_canonical_cache(&dst);
                Fcall::Rrename(fcall::Rrename {})
            }
            Err(e) => io_error_response(e),
        }
    }

    fn handle_renameat<'a>(
        &self,
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

        let (old_arc, new_arc) = {
            let fids = read_lock(&self.fids, "fids");
            let old_arc = match fids.get(&olddfid) {
                Some(arc) => Arc::clone(arc),
                None => return error_response(libc::EBADF as u32),
            };
            let new_arc = match fids.get(&newdfid) {
                Some(arc) => Arc::clone(arc),
                None => return error_response(libc::EBADF as u32),
            };
            (old_arc, new_arc)
        };

        let (old_dir_path, old_canonical) = {
            let old = read_lock(&old_arc, "fid");
            (old.path.clone(), old.is_canonical)
        };
        let (new_dir_path, new_canonical) = {
            let new = read_lock(&new_arc, "fid");
            (new.path.clone(), new.is_canonical)
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
            Ok(()) => {
                self.invalidate_canonical_cache(&src);
                self.invalidate_canonical_cache(&dst);
                Fcall::Rrenameat(fcall::Rrenameat {})
            }
            Err(e) => io_error_response(e),
        }
    }

    // ========================================================================
    // Statfs / Fsync / Clunk / Remove
    // ========================================================================

    fn handle_statfs<'a>(&self, _fid: u32) -> Fcall<'a> {
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

    fn handle_fsync<'a>(&self, req: fcall::Tfsync) -> Fcall<'a> {
        let fid_arc = match self.get_fid(req.fid) {
            Ok(fid_arc) => fid_arc,
            Err(errno) => return error_response(errno),
        };

        let file = {
            let state = read_lock(&fid_arc, "fid");
            match state.file.as_ref() {
                Some(file) => match file.try_clone() {
                    Ok(file) => Some(file),
                    Err(e) => return io_error_response(e),
                },
                None => None,
            }
        };

        if let Some(file) = file {
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

    fn handle_clunk<'a>(&self, req: fcall::Tclunk) -> Fcall<'a> {
        // Remove the FID; the file handle (if any) is dropped automatically
        let mut fids = write_lock(&self.fids, "fids");
        fids.remove(&req.fid);
        Fcall::Rclunk(fcall::Rclunk {})
    }

    fn handle_remove<'a>(&self, req: fcall::Tremove) -> Fcall<'a> {
        // Remove always clunks the fid, even on error
        let fid_arc = {
            let mut fids = write_lock(&self.fids, "fids");
            match fids.remove(&req.fid) {
                Some(arc) => arc,
                None => return error_response(libc::EBADF as u32),
            }
        };

        let (path, is_canonical, qid) = {
            let state = read_lock(&fid_arc, "fid");
            (state.path.clone(), state.is_canonical, state.qid)
        };

        // Resolve symlinks to prevent jail escape
        let resolved = match self.resolve_fid_path(&path, is_canonical) {
            Ok(p) => p,
            Err(errno) => return error_response(errno),
        };

        let is_dir = qid.typ.contains(fcall::QidType::DIR);
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
        let fid_arc = match self.get_fid(fid) {
            Ok(fid_arc) => fid_arc,
            Err(errno) => return error_response(errno),
        };

        let readlink_path = {
            let state = read_lock(&fid_arc, "fid");
            state
                .readlink_path
                .clone()
                .unwrap_or_else(|| state.path.clone())
        };
        match fs::read_link(&readlink_path) {
            Ok(target) => Fcall::Rreadlink(fcall::Rreadlink {
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
        &self,
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
        {
            let cache = mutex_lock(&self.elf_cache, "elf_cache");
            if let Some((cached_mtime, cached_data)) = cache.get(path)
                && *cached_mtime == current_mtime
            {
                return Some(Arc::clone(cached_data));
            }
        }

        // Quick check: if the binary is already patched (has LITEBOX0 magic
        // trailer), skip the expensive full-file read + scan. Pre-rewritten
        // binaries on disk are served as-is through 9P.
        let file_len = file.metadata().ok()?.len();
        if file_len >= 32 {
            let mut trailer = [0u8; 8];
            if file.seek(SeekFrom::End(-32)).is_ok()
                && file.read_exact(&mut trailer).is_ok()
                && &trailer == litebox_syscall_rewriter::TRAMPOLINE_MAGIC
            {
                let _ = file.seek(SeekFrom::Start(0));
                return None;
            }
            let _ = file.seek(SeekFrom::Start(0));
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

        let mut skipped_addrs = Vec::new();
        let start = std::time::Instant::now();
        let patched = match litebox_syscall_rewriter::hook_syscalls_in_elf(
            &content,
            None,
            &mut skipped_addrs,
        ) {
            Ok(p) => p,
            Err(_) => {
                let _ = file.seek(SeekFrom::Start(0));
                return None;
            }
        };
        let elapsed = start.elapsed();

        // Write timing to diagnostic log.
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open("/tmp/rst-diag.log")
        {
            use std::io::Write;
            let _ = writeln!(
                f,
                "[perf] broker hook_syscalls_in_elf({}, {} bytes): {}.{:03}s",
                path.display(),
                content.len(),
                elapsed.as_secs(),
                elapsed.subsec_millis(),
            );
        }

        debug!(
            path = %path.display(),
            original_size = content.len(),
            patched_size = patched.len(),
            skipped_syscalls = skipped_addrs.len(),
            "patched ELF with syscall trampolines"
        );

        let arc = Arc::new(patched);
        let mut cache = mutex_lock(&self.elf_cache, "elf_cache");
        cache.insert(path.to_owned(), (current_mtime, Arc::clone(&arc)));
        Some(arc)
    }
}

// ============================================================================
// Owned request type for borrow-checker-safe dispatch
// ============================================================================

/// Owned version of 9P request data, used to break the borrow on the read
/// buffer before calling `&self` handler methods.
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
    Symlink {
        fid: u32,
        name: String,
        symtgt: Vec<u8>,
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
            Fcall::Tsymlink(r) => OwnedRequest::Symlink {
                fid: r.fid,
                name: String::from_utf8_lossy(&r.name).into_owned(),
                symtgt: r.symtgt.into_owned(),
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
            Fcall::Tstatfs(r) => OwnedRequest::Statfs { fid: r.fid },
            Fcall::Tfsync(r) => OwnedRequest::Fsync {
                fid: r.fid,
                datasync: r.datasync,
            },
            Fcall::Tclunk(r) => OwnedRequest::Clunk { fid: r.fid },
            Fcall::Tremove(r) => OwnedRequest::Remove { fid: r.fid },
            Fcall::Tflush(_) => OwnedRequest::Flush,
            Fcall::Treadlink(r) => OwnedRequest::Readlink { fid: r.fid },
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

fn read_lock<'a, T>(lock: &'a RwLock<T>, name: &str) -> RwLockReadGuard<'a, T> {
    match lock.read() {
        Ok(guard) => guard,
        Err(poisoned) => {
            warn!(lock = name, "recovering from poisoned read lock");
            poisoned.into_inner()
        }
    }
}

fn write_lock<'a, T>(lock: &'a RwLock<T>, name: &str) -> RwLockWriteGuard<'a, T> {
    match lock.write() {
        Ok(guard) => guard,
        Err(poisoned) => {
            warn!(lock = name, "recovering from poisoned write lock");
            poisoned.into_inner()
        }
    }
}

fn mutex_lock<'a, T>(lock: &'a Mutex<T>, name: &str) -> MutexGuard<'a, T> {
    match lock.lock() {
        Ok(guard) => guard,
        Err(poisoned) => {
            warn!(lock = name, "recovering from poisoned mutex");
            poisoned.into_inner()
        }
    }
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
