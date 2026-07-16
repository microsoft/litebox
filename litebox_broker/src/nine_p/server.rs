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

// TODO(#15): convert legacy wildcard enum dispatch in this file to explicit arms.
#![allow(clippy::wildcard_enum_match_arm)]

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
use crate::inotify_dispatcher::InotifyDispatcher;
use crate::policy::{Action, Decision, Policy};

#[cfg(test)]
static REGISTER_FID_BEFORE_WRITE_LOCK_HOOK: Mutex<Option<Arc<std::sync::Barrier>>> =
    Mutex::new(None);

/// Maximum number of FIDs per connection to prevent resource exhaustion.
const MAX_FIDS: usize = 8192;
const IN_MODIFY: u32 = 0x0000_0002;
const IN_MOVED_FROM: u32 = 0x0000_0040;
const IN_MOVED_TO: u32 = 0x0000_0080;
const IN_CREATE: u32 = 0x0000_0100;
const IN_DELETE: u32 = 0x0000_0200;

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
    /// Legacy-pipes Phase 3 (D3): if this fid was materialised by a
    /// `CloneOfd` op (worker side) — or marked by a `RegisterOfd`
    /// op (parent side) — this field carries the broker-global
    /// [`OpenFileId`] for the underlying open file description. On
    /// `Tclunk`, the handler calls
    /// [`OfdRegistry::release`][crate::ofd_registry::OfdRegistry::release]
    /// with this id so the registry's refcount tracks the live
    /// inheriting fids exactly.
    ///
    /// `None` means the fid was created the usual way (Tlopen,
    /// Tlcreate, Twalk-clone) and the registry has no entry to
    /// release on clunk.
    open_file_id: Option<crate::ofd_registry::OpenFileId>,
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
    /// Broker-global inotify fan-out for filesystem mutations.
    inotify_dispatcher: Arc<InotifyDispatcher>,
    /// Legacy-pipes Phase 3 (D3): broker-global registry of open
    /// file descriptions that fork-restored workers can clone to
    /// inherit POSIX shared-position semantics from the parent.
    /// Shared across every per-connection `Server` instance so a
    /// `RegisterOfd` on the parent's connection and a `CloneOfd` on
    /// the worker's connection see the same id space.
    ///
    /// `None` for legacy bring-up paths (test fixtures that don't
    /// exercise OFD inheritance); production wiring in
    /// `litebox_broker/src/main.rs` always supplies a real registry.
    ofd_registry: Option<Arc<crate::ofd_registry::OfdRegistry>>,
    /// Legacy-pipes Phase 3 (D3 step 2d.2): monotone broker-assigned
    /// per-9P-connection identifier. Mirrors fd-token-socket's
    /// `ConnState::conn_id` family. Used as the lookup key in the
    /// broker-global `nine_p_session_registry` so that an
    /// fd-token-socket connection can issue
    /// `BindNinePSession(this_conn_id)` to pair its
    /// `ConnState::nine_p_server` slot with this Server. Default `0`
    /// for test fixtures that don't go through the production
    /// accept-loop wiring.
    conn_id: u64,
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
    pub fn new(
        root: PathBuf,
        policy: Arc<dyn Policy>,
        rewrite_syscalls: bool,
        inotify_dispatcher: Arc<InotifyDispatcher>,
    ) -> Self {
        Self::with_elf_cache(
            root,
            policy,
            rewrite_syscalls,
            Arc::new(Mutex::new(HashMap::new())),
            inotify_dispatcher,
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
        inotify_dispatcher: Arc<InotifyDispatcher>,
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
            inotify_dispatcher,
            ofd_registry: None,
            conn_id: 0,
        }
    }

    /// Set the broker-assigned 9P connection id. Called once by the
    /// accept loop in `main.rs` after `with_elf_cache` returns,
    /// before the per-conn `serve` thread starts. Tests can leave
    /// the default `0`.
    pub fn set_conn_id(&mut self, conn_id: u64) {
        self.conn_id = conn_id;
    }

    /// Returns the broker-assigned 9P connection id (0 for tests
    /// that didn't call `set_conn_id`).
    pub fn conn_id(&self) -> u64 {
        self.conn_id
    }

    /// Set the broker-global OFD registry handle for legacy-pipes
    /// Phase 3 (D3) `RegisterOfd` / `CloneOfd` plumbing. Production
    /// wiring in `litebox_broker/src/main.rs` calls this after
    /// constructing the `Server`; tests that don't exercise OFD
    /// inheritance can leave it `None`.
    pub fn set_ofd_registry(&mut self, registry: Arc<crate::ofd_registry::OfdRegistry>) {
        self.ofd_registry = Some(registry);
    }

    /// Returns the broker-global OFD registry handle, if any. Used
    /// by D3 state-service handlers; `None` for legacy bring-up
    /// paths.
    pub fn ofd_registry(&self) -> Option<&Arc<crate::ofd_registry::OfdRegistry>> {
        self.ofd_registry.as_ref()
    }

    /// Legacy-pipes Phase 3 (D3): register the open file underlying
    /// 9P fid `fid` in the broker-global OFD registry. Mutates the
    /// fid's [`FidState::open_file_id`] to remember the assignment,
    /// so the parent's clunk later releases the registry entry.
    ///
    /// # Errors
    ///
    /// - `libc::EBADF as u32` if `fid` is unknown or not yet opened
    ///   (`is_open && file.is_some()`).
    /// - `libc::ENOTSUP as u32` if no OFD registry is bound (the
    ///   server was constructed without `set_ofd_registry`).
    /// - `libc::EIO as u32` if the underlying `dup(2)` fails.
    pub fn register_fid_in_ofd_registry(
        &self,
        fid: u32,
    ) -> Result<crate::ofd_registry::OpenFileId, u32> {
        let registry = self.ofd_registry.as_ref().ok_or(libc::ENOTSUP as u32)?;
        let fid_arc = self.get_fid(fid)?;
        #[cfg(test)]
        if let Some(barrier) = {
            mutex_lock(&REGISTER_FID_BEFORE_WRITE_LOCK_HOOK, "register_hook")
                .as_ref()
                .cloned()
        } {
            barrier.wait();
        }

        let mut state = write_lock(&fid_arc, "fid");
        if !state.is_open || state.file.is_none() {
            return Err(libc::EBADF as u32);
        }
        // Idempotent: if the fid already has an id, return it.
        if let Some(existing) = state.open_file_id {
            return Ok(existing);
        }
        {
            let fids = read_lock(&self.fids, "fids");
            match fids.get(&fid) {
                Some(current) if Arc::ptr_eq(current, &fid_arc) => {}
                _ => return Err(libc::EBADF as u32),
            }
        }
        let path = state.path.clone();
        let file = state.file.as_ref().ok_or(libc::EBADF as u32)?;
        let id = registry
            .register(file, path)
            .map_err(|_| libc::EIO as u32)?;
        state.open_file_id = Some(id);
        Ok(id)
    }

    /// Legacy-pipes Phase 3 (D3): clone a previously-registered
    /// open file description into a fresh 9P fid on this server's
    /// own connection. Increments the registry entry's refcount.
    ///
    /// The resulting `FidState` is marked open and canonical (the
    /// path was canonicalized when the parent originally walked to
    /// it), and carries `open_file_id = Some(id)` so the worker's
    /// eventual Tclunk releases the registry entry.
    ///
    /// # Errors
    ///
    /// - `libc::ENOTSUP as u32` if no OFD registry is bound.
    /// - `libc::EBADF as u32` if `id` is unknown / already-released
    ///   in the registry, or if the underlying `dup(2)` fails.
    /// - `libc::EEXIST as u32` if `new_fid` is already in use.
    /// - `libc::ENOMEM as u32` if the fid table is full.
    pub fn clone_ofd_into_fid(
        &self,
        id: crate::ofd_registry::OpenFileId,
        new_fid: u32,
    ) -> Result<(), u32> {
        self.clone_ofd_into_fid_with_qid(id, new_fid, |file| {
            file.metadata().map(|meta| metadata_to_qid(&meta))
        })
    }

    fn clone_ofd_into_fid_with_qid(
        &self,
        id: crate::ofd_registry::OpenFileId,
        new_fid: u32,
        qid_for: impl FnOnce(&fs::File) -> std::io::Result<fcall::Qid>,
    ) -> Result<(), u32> {
        let registry = self.ofd_registry.as_ref().ok_or(libc::ENOTSUP as u32)?;
        let cloned = registry.clone_for(id).map_err(|e| match e {
            crate::ofd_registry::OfdRegistryError::UnknownId => libc::EBADF as u32,
            crate::ofd_registry::OfdRegistryError::Io(_) => libc::EBADF as u32,
        })?;
        // Synthesize a Qid from the cloned file's metadata so the
        // worker sees a consistent type bit.
        let qid = match qid_for(&cloned.file) {
            Ok(qid) => qid,
            Err(_) => {
                let _ = registry.release(id);
                return Err(libc::EIO as u32);
            }
        };
        let new_state = FidState {
            path: cloned.path,
            readlink_path: None,
            file: Some(cloned.file),
            patched_data: None,
            patched_offset: 0,
            qid,
            is_open: true,
            is_canonical: true,
            open_file_id: Some(id),
        };
        let mut fids = write_lock(&self.fids, "fids");
        if fids.contains_key(&new_fid) {
            // Release the just-incremented refcount: the clone
            // succeeded but the install can't proceed. The
            // worker should pick a different new_fid.
            drop(fids);
            let _ = registry.release(id);
            return Err(libc::EEXIST as u32);
        }
        if fids.len() >= MAX_FIDS {
            drop(fids);
            let _ = registry.release(id);
            return Err(libc::ENOMEM as u32);
        }
        fids.insert(new_fid, Arc::new(RwLock::new(new_state)));
        Ok(())
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
    ///
    /// Honours `LITEBOX_BROKER_ELF_CACHE_DIR` for cross-broker
    /// amortisation: if the env var points at an existing directory,
    /// rewritten ELF bytes are persisted there keyed by
    /// `(canonical path, mtime)`. Subsequent broker invocations
    /// (sharing that directory via a bind mount, for example) populate
    /// the in-memory cache from disk and skip the (~300 ms / lib)
    /// rewriting step entirely.
    pub fn pre_warm_elf_cache(elf_cache: &Arc<Mutex<ElfCache>>, root: &Path, paths: &[&str]) {
        use std::io::{Read, Seek, SeekFrom};

        let disk_cache_dir: Option<PathBuf> =
            std::env::var_os("LITEBOX_BROKER_ELF_CACHE_DIR").map(PathBuf::from);
        if let Some(ref d) = disk_cache_dir {
            let _ = fs::create_dir_all(d);
        }

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

            // Already cached in-memory?
            {
                let cache = mutex_lock(elf_cache, "elf_cache");
                if let Some((mtime, _)) = cache.get(&resolved) {
                    if *mtime == current_mtime {
                        continue;
                    }
                }
            }

            // Try the persistent disk cache before doing any work.
            if let Some(ref d) = disk_cache_dir {
                let key = disk_cache_key(&resolved, current_mtime);
                let cache_path = d.join(&key);
                if let Ok(bytes) = fs::read(&cache_path) {
                    let arc = Arc::new(bytes);
                    let mut cache = mutex_lock(elf_cache, "elf_cache");
                    cache.insert(resolved.clone(), (current_mtime, Arc::clone(&arc)));
                    eprintln!(
                        "[broker] pre-warmed ELF cache HIT (disk): {} ({} bytes)",
                        resolved.display(),
                        arc.len(),
                    );
                    continue;
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
            // PE.14: catch iced-x86 v1.21's ptr-truncation panic
            // (decoder.rs:1421). Pre-warm path: on panic, just skip
            // caching this entry; subsequent on-demand load will
            // re-attempt and catch again if needed.
            let pw_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                litebox_syscall_rewriter::hook_syscalls_in_elf(&content, None, &mut skipped_addrs)
            }));
            if let Ok(Ok(patched)) = pw_result {
                // Persist to disk cache before populating in-memory so
                // the next broker process sees it. Atomic via tmp +
                // rename. Best-effort: failures don't block the
                // in-memory cache population.
                if let Some(ref d) = disk_cache_dir {
                    let key = disk_cache_key(&resolved, current_mtime);
                    let cache_path = d.join(&key);
                    let tmp = d.join(format!("{key}.tmp.{}", std::process::id()));
                    if fs::write(&tmp, &patched).is_ok() && fs::rename(&tmp, &cache_path).is_ok() {
                        eprintln!(
                            "[broker] pre-warmed ELF cache MISS → wrote {} ({} bytes)",
                            cache_path.display(),
                            patched.len(),
                        );
                    } else {
                        let _ = fs::remove_file(&tmp);
                    }
                }
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

    fn guest_path_for_host(&self, path: &Path) -> String {
        let stripped = path.strip_prefix(&self.root).unwrap_or(path);
        let s = stripped.to_string_lossy();
        if s.is_empty() {
            "/".to_string()
        } else {
            format!("/{}", s.trim_start_matches('/'))
        }
    }

    fn notify_inotify_parent(&self, parent: &Path, mask: u32, cookie: u32, name: &str) {
        let guest_parent = self.guest_path_for_host(parent);
        self.inotify_dispatcher
            .dispatch(&guest_parent, mask, cookie, name);
    }

    fn notify_inotify_path(&self, path: &Path, mask: u32, cookie: u32) {
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or_default();
        let parent = path.parent().unwrap_or(&self.root);
        self.notify_inotify_parent(parent, mask, cookie, name);
        if mask == IN_MODIFY {
            let guest_path = self.guest_path_for_host(path);
            self.inotify_dispatcher
                .dispatch(&guest_path, mask, cookie, "");
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
                open_file_id: None,
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
                        open_file_id: None,
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
                        open_file_id: None,
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

        // Access authorized — record the first touch of this path for the
        // "allowed" frontier (de-duplicated inside the audit log).
        if let Some(ref al) = self.audit_log {
            al.fs_allowed(
                resolved.to_str().unwrap_or("?"),
                if is_write { "write" } else { "read" },
            );
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
            if let Some(ref al) = self.audit_log {
                al.fs_denied(resolved_target.to_str().unwrap_or("?"), "create");
            }
            return error_response(libc::EPERM as u32);
        }
        if self
            .policy
            .check(Action::Write, Some(resolved_target.as_path()))
            == Decision::Deny
        {
            if let Some(ref al) = self.audit_log {
                al.fs_denied(resolved_target.to_str().unwrap_or("?"), "write");
            }
            return error_response(libc::EPERM as u32);
        }

        // Create authorized — record the allowed write for the frontier
        // (de-duplicated inside the audit log), symmetric with the fs_denied
        // paths above so the "allowed" tree shows creations, not just opens.
        if let Some(ref al) = self.audit_log {
            al.fs_allowed(resolved_target.to_str().unwrap_or("?"), "create");
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
                self.notify_inotify_parent(&resolved_parent, IN_CREATE, 0, &name);
                Fcall::Rlcreate(fcall::Rlcreate {
                    qid,
                    iounit: msize - fcall::IOHDRSZ,
                })
            }
            Err(e) => {
                let denied = e.kind() == std::io::ErrorKind::PermissionDenied
                    || e.raw_os_error().is_some_and(|errno| {
                        errno == libc::EACCES || errno == libc::EPERM || errno == libc::EROFS
                    });
                if denied && let Some(ref al) = self.audit_log {
                    al.fs_denied(resolved_target.to_str().unwrap_or("?"), "write");
                }
                io_error_response(e)
            }
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
            if let Some(ref al) = self.audit_log {
                al.fs_denied(target.to_str().unwrap_or("?"), "symlink");
            }
            return error_response(libc::EPERM as u32);
        }

        if let Some(ref al) = self.audit_log {
            al.fs_allowed(target.to_str().unwrap_or("?"), "symlink");
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
            Ok(n) => {
                if n > 0 {
                    self.notify_inotify_path(&path, IN_MODIFY, 0);
                }
                Fcall::Rwrite(fcall::Rwrite { count: n as u32 })
            }
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
                if let Some(ref al) = self.audit_log {
                    al.fs_denied(resolved.to_str().unwrap_or("?"), "chmod");
                }
                return error_response(libc::EPERM as u32);
            }
            if let Some(ref al) = self.audit_log {
                al.fs_allowed(resolved.to_str().unwrap_or("?"), "chmod");
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
                if let Some(ref al) = self.audit_log {
                    al.fs_denied(resolved.to_str().unwrap_or("?"), "truncate");
                }
                return error_response(libc::EPERM as u32);
            }
            if let Some(ref al) = self.audit_log {
                al.fs_allowed(resolved.to_str().unwrap_or("?"), "truncate");
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
            self.notify_inotify_path(&resolved, IN_MODIFY, 0);
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
            if let Some(ref al) = self.audit_log {
                al.fs_denied(target.to_str().unwrap_or("?"), "mkdir");
            }
            return error_response(libc::EPERM as u32);
        }

        if let Some(ref al) = self.audit_log {
            al.fs_allowed(target.to_str().unwrap_or("?"), "mkdir");
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
                self.notify_inotify_parent(&resolved_parent, IN_CREATE, 0, &name);
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
                self.notify_inotify_parent(&resolved_parent, IN_DELETE, 0, &name);
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
            if let Some(ref al) = self.audit_log {
                al.fs_denied(resolved_src.to_str().unwrap_or("?"), "rename");
            }
            return error_response(libc::EPERM as u32);
        }
        if self.policy.check(Action::Write, Some(&dst)) == Decision::Deny {
            if let Some(ref al) = self.audit_log {
                al.fs_denied(dst.to_str().unwrap_or("?"), "rename");
            }
            return error_response(libc::EPERM as u32);
        }

        if let Some(ref al) = self.audit_log {
            al.fs_allowed(dst.to_str().unwrap_or("?"), "rename");
        }

        match fs::rename(&resolved_src, &dst) {
            Ok(()) => {
                // Update the FID's path to the new location
                let mut state = write_lock(&src_arc, "fid");
                state.path = dst.clone();
                self.invalidate_canonical_cache(&resolved_src);
                self.invalidate_canonical_cache(&dst);
                let cookie = self.inotify_dispatcher.next_cookie();
                self.notify_inotify_path(&resolved_src, IN_MOVED_FROM, cookie);
                self.notify_inotify_parent(&resolved_dst_dir, IN_MOVED_TO, cookie, &name);
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
            if let Some(ref al) = self.audit_log {
                al.fs_denied(src.to_str().unwrap_or("?"), "rename");
            }
            return error_response(libc::EPERM as u32);
        }
        if self.policy.check(Action::Write, Some(&dst)) == Decision::Deny {
            if let Some(ref al) = self.audit_log {
                al.fs_denied(dst.to_str().unwrap_or("?"), "rename");
            }
            return error_response(libc::EPERM as u32);
        }

        if let Some(ref al) = self.audit_log {
            al.fs_allowed(dst.to_str().unwrap_or("?"), "rename");
        }

        match fs::rename(&src, &dst) {
            Ok(()) => {
                self.invalidate_canonical_cache(&src);
                self.invalidate_canonical_cache(&dst);
                let cookie = self.inotify_dispatcher.next_cookie();
                self.notify_inotify_parent(&resolved_old_dir, IN_MOVED_FROM, cookie, &oldname);
                self.notify_inotify_parent(&resolved_new_dir, IN_MOVED_TO, cookie, &newname);
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
        // Remove the FID; the file handle (if any) is dropped automatically.
        // Legacy-pipes Phase 3 (D3): if the fid carries an
        // `open_file_id` (set by `CloneOfd` on the worker side, and
        // by `RegisterOfd` on the parent side if we ever wire the
        // parent's own clunk into the release flow), decrement the
        // broker-global OFD registry refcount so the kernel OFD is
        // freed when the last inheriting fid clunks.
        let removed = {
            let mut fids = write_lock(&self.fids, "fids");
            fids.remove(&req.fid)
        };
        if let Some(fid_arc) = removed
            && let Some(registry) = self.ofd_registry.as_ref()
        {
            let open_file_id = {
                let state = read_lock(&fid_arc, "fid");
                state.open_file_id
            };
            if let Some(id) = open_file_id {
                // `release` returns None for an unknown id (race
                // with connection-close cleanup); intentionally
                // ignored.
                let _ = registry.release(id);
            }
        }
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
            Ok(()) => {
                self.invalidate_canonical_cache(&resolved);
                self.notify_inotify_path(&resolved, IN_DELETE, 0);
                Fcall::Rremove(fcall::Rremove {})
            }
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
    ///
    /// Coverage limit: this only fires for files served by the broker
    /// over 9P from the rootfs the broker is responsible for. Files
    /// reached through separate kernel mount points inside the
    /// container — e.g. docker bind-mounts like `/opt/litebox/` in
    /// the test harness setup — are read by the runner directly from
    /// the host filesystem and never reach this code. See the design
    /// note in `litebox_tool_executor/rootfs/Dockerfile` (Stage 2a)
    /// for the rationale.
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

        // Persistent (cross-broker) disk cache: integration tests set
        // `LITEBOX_BROKER_ELF_CACHE_DIR` and may pre-populate entries
        // from setup() so the very first request never pays the
        // rewriter cost. Mtime-validated via the key itself.
        let disk_cache_dir: Option<PathBuf> =
            std::env::var_os("LITEBOX_BROKER_ELF_CACHE_DIR").map(PathBuf::from);
        if let Some(ref d) = disk_cache_dir {
            let key = disk_cache_key(path, current_mtime);
            let cache_path = d.join(&key);
            if let Ok(bytes) = fs::read(&cache_path) {
                let arc = Arc::new(bytes);
                let mut cache = mutex_lock(&self.elf_cache, "elf_cache");
                cache.insert(path.to_owned(), (current_mtime, Arc::clone(&arc)));
                return Some(arc);
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
        // PE.14: wrap the rewriter call in catch_unwind. iced-x86 v1.21
        // has a known panic in `decoder.rs:1421` ("attempt to subtract
        // with overflow") when buffer pointers cross a 32-bit boundary.
        // Fires non-deterministically based on ASLR. Without this catch
        // the 9p-worker thread dies and subsequent fs ops on the same
        // worker stall — a much worse outcome than failing this single
        // file's syscall hook (which falls back to unhooked exec).
        let patched_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            litebox_syscall_rewriter::hook_syscalls_in_elf(&content, None, &mut skipped_addrs)
        }));
        let patched = match patched_result {
            Ok(Ok(p)) => p,
            Ok(Err(_)) => {
                let _ = file.seek(SeekFrom::Start(0));
                return None;
            }
            Err(panic_payload) => {
                let msg = if let Some(s) = panic_payload.downcast_ref::<&'static str>() {
                    (*s).to_string()
                } else if let Some(s) = panic_payload.downcast_ref::<String>() {
                    s.clone()
                } else {
                    "<non-string panic>".to_string()
                };
                if let Ok(mut f) = std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open("/tmp/rst-diag.log")
                {
                    use std::io::Write;
                    let _ = writeln!(
                        f,
                        "[PE.14-diag] iced-x86 panic recovered: hook_syscalls_in_elf({}, {} bytes) panicked: {msg} — falling back to unhooked binary",
                        path.display(),
                        content.len(),
                    );
                }
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

        // Persist to disk cache so the *next* broker process (same
        // host, different container) skips the rewriter for this
        // file. Atomic via tmp + rename. Best-effort.
        if let Some(ref d) = disk_cache_dir {
            let key = disk_cache_key(path, current_mtime);
            let cache_path = d.join(&key);
            let tmp = d.join(format!("{key}.tmp.{}", std::process::id()));
            if fs::write(&tmp, &patched).is_ok() && fs::rename(&tmp, &cache_path).is_ok() {
                // ok
            } else {
                let _ = fs::remove_file(&tmp);
            }
        }

        // Emit a marker per in-band runtime rewrite. Integration
        // tests assert this count is zero (everything should be
        // pre-populated by setup() or pre_warm_elf_cache).
        // Encode the path in the marker name so the failure message
        // can name what wasn't primed. The value is the rewrite
        // duration in ns, which is the only numeric we have handy
        // (litebox_timing's marker format is `name=u64\n`).
        let path_key = sanitize_path_for_marker(path);
        litebox_timing::emit(&format!("broker_runtime_rewrite:{path_key}"));

        let arc = Arc::new(patched);
        let mut cache = mutex_lock(&self.elf_cache, "elf_cache");
        cache.insert(path.to_owned(), (current_mtime, Arc::clone(&arc)));
        Some(arc)
    }
}

/// Replace path separators and non-ASCII-alphanumeric chars so the
/// path is safe to embed in a `name=value` litebox_timing marker line.
/// Mirrors `disk_cache_key`'s sanitisation rules (sans the mtime
/// suffix) so cross-referencing is straightforward.
fn sanitize_path_for_marker(p: &Path) -> String {
    let mut out = String::new();
    for c in p.as_os_str().to_string_lossy().chars() {
        match c {
            '/' => out.push('_'),
            c if c.is_ascii_alphanumeric() || c == '-' || c == '.' => out.push(c),
            _ => out.push('-'),
        }
    }
    out
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

/// Filesystem-safe disk-cache filename for `(resolved_path, mtime)`.
///
/// Used by `pre_warm_elf_cache` and `try_patch_elf` to persist
/// rewritten ELF bytes across broker process invocations, and by the
/// integration test harness to pre-populate the cache from `setup()`
/// (see `litebox_test_harness/tests/integration.rs`).
///
/// The key has to round-trip safely across any host filesystem; we
/// drop the leading `/`, replace path separators with `_`, and append
/// the mtime. Two different paths that collapse to the same key would
/// be unsafe — we mitigate that in practice by always using the
/// resolved (canonicalised) absolute path, which is unique on the host.
pub fn disk_cache_key(resolved: &Path, mtime: i64) -> String {
    let mut key = String::new();
    for part in resolved.as_os_str().to_string_lossy().chars() {
        match part {
            '/' => key.push('_'),
            c if c.is_ascii_alphanumeric() || c == '-' || c == '.' => key.push(c),
            _ => key.push('-'),
        }
    }
    format!("{key}.{mtime}.elf")
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Error, Write};
    use std::thread;

    fn temp_root() -> tempfile::TempDir {
        let base = std::env::current_dir()
            .expect("current dir")
            .join("target/litebox_broker_server_tests");
        fs::create_dir_all(&base).expect("create test temp base");
        tempfile::Builder::new()
            .prefix("server-")
            .tempdir_in(base)
            .expect("tempdir")
    }

    fn server_with_registry(
        root: PathBuf,
        registry: Arc<crate::ofd_registry::OfdRegistry>,
    ) -> Server {
        let mut server = Server::new(
            root,
            Arc::new(crate::policy::AllowAllPolicy),
            false,
            Arc::new(InotifyDispatcher::new()),
        );
        server.set_ofd_registry(registry);
        server
    }

    fn insert_open_fid(server: &Server, fid: u32, path: &Path) {
        let mut file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .expect("open fid file");
        file.write_all(b"data").expect("seed fid file");
        let qid = metadata_to_qid(&file.metadata().expect("fid metadata"));
        let state = FidState {
            path: path.to_path_buf(),
            readlink_path: None,
            file: Some(file),
            patched_data: None,
            patched_offset: 0,
            qid,
            is_open: true,
            is_canonical: true,
            open_file_id: None,
        };
        write_lock(&server.fids, "fids").insert(fid, Arc::new(RwLock::new(state)));
    }

    fn insert_closed_fid(server: &Server, fid: u32, path: &Path) {
        let qid = metadata_to_qid(&fs::metadata(path).expect("fid metadata"));
        let state = FidState {
            path: path.to_path_buf(),
            readlink_path: None,
            file: None,
            patched_data: None,
            patched_offset: 0,
            qid,
            is_open: false,
            is_canonical: true,
            open_file_id: None,
        };
        write_lock(&server.fids, "fids").insert(fid, Arc::new(RwLock::new(state)));
    }

    #[test]
    fn lcreate_policy_denial_emits_fs_denied_audit_event() {
        let root = temp_root();
        let audit_path = root.path().join("audit.jsonl");
        let mut server = Server::new(
            root.path().to_path_buf(),
            Arc::new(crate::policy::ReadOnlyPolicy),
            false,
            Arc::new(InotifyDispatcher::new()),
        );
        server.set_audit_log(crate::audit::AuditLog::open(&audit_path).expect("open audit log"));
        insert_closed_fid(&server, 1, root.path());

        assert!(matches!(
            server.handle_lcreate(
                1,
                "denied".to_string(),
                fcall::LOpenFlags::O_WRONLY,
                0o644,
                0
            ),
            Fcall::Rlerror(fcall::Rlerror { ecode }) if ecode == libc::EPERM as u32
        ));

        let audit = fs::read_to_string(&audit_path).expect("read audit log");
        assert!(
            audit.contains(r#""event":"fs_denied""#)
                && audit.contains(r#""action":"write""#)
                && audit.contains("denied"),
            "missing create/write denial audit event: {audit}"
        );
    }

    #[test]
    fn lcreate_policy_allow_emits_fs_allowed_audit_event() {
        let root = temp_root();
        let audit_path = root.path().join("audit.jsonl");
        let mut server = Server::new(
            root.path().to_path_buf(),
            Arc::new(crate::policy::AllowAllPolicy),
            false,
            Arc::new(InotifyDispatcher::new()),
        );
        server.set_audit_log(crate::audit::AuditLog::open(&audit_path).expect("open audit log"));
        insert_closed_fid(&server, 1, root.path());

        assert!(matches!(
            server.handle_lcreate(
                1,
                "created".to_string(),
                fcall::LOpenFlags::O_WRONLY,
                0o644,
                0
            ),
            Fcall::Rlcreate(_)
        ));

        // An allowed create must surface on the "allowed" frontier symmetrically
        // with the denial case above — otherwise a `touch newfile` (a create that
        // is never subsequently opened) would be invisible in the tree.
        let audit = fs::read_to_string(&audit_path).expect("read audit log");
        assert!(
            audit.contains(r#""event":"fs_allowed""#)
                && audit.contains(r#""action":"create""#)
                && audit.contains("created"),
            "missing allowed create audit event: {audit}"
        );
    }

    #[test]
    fn register_racing_clunk_does_not_leave_orphan_registry_entries() {
        const N: usize = 4;

        let root = temp_root();
        let registry = Arc::new(crate::ofd_registry::OfdRegistry::new());
        let server = Arc::new(server_with_registry(
            root.path().to_path_buf(),
            Arc::clone(&registry),
        ));
        let barrier = Arc::new(std::sync::Barrier::new(N + 1));
        *mutex_lock(&REGISTER_FID_BEFORE_WRITE_LOCK_HOOK, "register_hook") =
            Some(Arc::clone(&barrier));

        for i in 0..N {
            let fid = u32::try_from(i).expect("test fid fits u32");
            let path = root.path().join(format!("fid-{i}"));
            fs::write(&path, b"").expect("create fid file");
            insert_open_fid(&server, fid, &path);
        }

        let handles: Vec<_> = (0..N)
            .map(|i| {
                let fid = u32::try_from(i).expect("test fid fits u32");
                let server = Arc::clone(&server);
                thread::spawn(move || server.register_fid_in_ofd_registry(fid))
            })
            .collect();

        barrier.wait();
        for i in 0..N {
            let fid = u32::try_from(i).expect("test fid fits u32");
            assert!(matches!(
                server.handle_clunk(fcall::Tclunk { fid }),
                Fcall::Rclunk(_)
            ));
        }
        *mutex_lock(&REGISTER_FID_BEFORE_WRITE_LOCK_HOOK, "register_hook") = None;

        for handle in handles {
            let _ = handle.join().expect("register thread join");
        }
        assert_eq!(registry.len(), 0, "clunk/register race leaked OFD entries");
    }

    #[test]
    fn clone_ofd_metadata_error_releases_refcount() {
        let root = temp_root();
        let registry = Arc::new(crate::ofd_registry::OfdRegistry::new());
        let server = server_with_registry(root.path().to_path_buf(), Arc::clone(&registry));
        let path = root.path().join("parent");
        fs::write(&path, b"data").expect("create parent file");
        let parent = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .expect("open parent");
        let id = registry.register(&parent, &path).expect("register parent");
        assert_eq!(registry.refcount_of(id), Some(1));

        let err = server
            .clone_ofd_into_fid_with_qid(id, 42, |_| Err(Error::from_raw_os_error(libc::EBADF)))
            .expect_err("metadata failure should return EIO");

        assert_eq!(err, libc::EIO as u32);
        assert_eq!(
            registry.refcount_of(id),
            Some(1),
            "failed metadata must release clone_for refcount"
        );
    }
}
