// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Broker-global open-file-description (OFD) registry.
//!
//! # Purpose
//!
//! Phase 3 D3: implements cross-connection OFD sharing for inherited
//! filesystem fds, giving POSIX inherited-fd shared-position semantics
//! that match the native gold standard per
//! `litebox_test_harness/CLAUDE.md`. Two processes (parent + a
//! delayed-fork worker) running against the broker each have their
//! own 9P connection with its own `fids` HashMap, so they cannot
//! reach each other's per-connection state. The registry is the
//! broker-global sidecar that lets the parent "register" an open
//! file under a broker-scoped [`OpenFileId`] and the worker "clone"
//! against that id to obtain its own host `fs::File` that shares the
//! underlying kernel OFD with the parent's file.
//!
//! # Why `Arc<fs::File>` is the right primitive
//!
//! The session-4 sketch for option A framed this as a "9P fid
//! registry refactor" because it followed the brief's
//! "extend Twalk" recipe. That recipe was wrong:
//!
//! - The host [`fs::File`] **is** the kernel OFD wrapper.
//! - [`fs::File::try_clone`] is `dup(2)` → returns a fresh fd
//!   referring to the **same** kernel OFD → POSIX shared-position
//!   for free, no userland offset mutex, no 9P message extension.
//! - Reads/writes through the cloned `File` go through the same
//!   per-OFD position cursor the parent sees.
//!
//! Concretely: `RegisterOfd` does `file.try_clone()`, stashes the
//! clone in this registry under a fresh [`OpenFileId`] with
//! refcount=1. `CloneOfd` looks up the id, increments refcount,
//! `try_clone()`s the stashed `File` to produce the worker's fresh
//! handle. Both the parent's original `File` and the worker's clone
//! and the registry's stash all refer to the same kernel OFD.
//!
//! Refcount drops on `release` (called from the inheriting
//! `FidState`'s `handle_clunk`). The registry entry — and the
//! stashed `File` — drop when refcount reaches zero, closing the
//! broker's dup. The parent and the worker each still hold their
//! own dups, which they close on their own schedule.
//!
//! # Lifetime sketch
//!
//! ```text
//! parent: opens /etc/foo                  parent_file [OFD A]
//!         RegisterOfd { fid } -> id       registry[id] = clone(A); rc=1
//!                                                                       │
//!         (parent uses parent_file)                                     │
//!                                                                       │
//! worker: CloneOfd { id, new_fid }        registry[id].rc=2; worker_file = clone(A)
//!         worker writes to worker_file    (kernel OFD A pos advances; parent sees it)
//!                                                                       │
//! parent: clunk(fid)                                                    │
//!         (parent_file dropped; OFD A     registry[id] still holds dup; rc still 2
//!          refcount-1, but registry's                                   │
//!          dup keeps it alive)                                          │
//!                                                                       │
//! worker: clunk(new_fid)                  registry[id] released (rc -> 1)
//!         (worker_file dropped; OFD A      registry's dup is the last;
//!          refcount-1)                     entry removed (rc -> 0);
//!                                          dup closed; kernel OFD A
//!                                          finally freed.
//! ```

use std::collections::HashMap;
use std::fs;
use std::io;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};

/// Broker-scoped identifier for an entry in the OFD registry.
///
/// Allocated by [`OfdRegistry::register`]; references the entry
/// across the worker's `CloneOfd` and the eventual `release`. Not a
/// 9P fid — distinct namespace, lives only in the registry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct OpenFileId(pub u64);

impl OpenFileId {
    /// Raw u64 representation (for wire encoding by the
    /// fd-token-protocol handlers).
    #[must_use]
    pub fn as_u64(self) -> u64 {
        self.0
    }

    /// Construct from a wire-decoded u64.
    #[must_use]
    pub fn from_u64(raw: u64) -> Self {
        Self(raw)
    }
}

/// Internal entry. Wraps the broker's stashed dup of the kernel OFD,
/// the original host path (carried so the worker's reconstructed
/// `FidState` can populate its own `path` field), and a refcount
/// covering every outstanding "inheriting" reference (the registry's
/// own stash counts as well — it is removed by [`OfdRegistry::release`]
/// when the last user releases).
#[derive(Debug)]
struct OfdEntry {
    file: Arc<fs::File>,
    path: PathBuf,
    refcount: AtomicUsize,
}

/// Errors returned by [`OfdRegistry`] ops.
#[derive(Debug, thiserror::Error)]
pub enum OfdRegistryError {
    /// The requested [`OpenFileId`] is not present in the registry
    /// (never registered, or already released).
    #[error("unknown OpenFileId")]
    UnknownId,
    /// A host syscall failed (e.g., `try_clone`/`dup` returned ENFILE
    /// or EMFILE). The wrapped error preserves the underlying
    /// [`io::Error`] for callers that want to surface a specific
    /// errno on the wire.
    #[error("host I/O error: {0}")]
    Io(#[from] io::Error),
}

/// Broker-global, lock-protected registry of inherited OFDs.
///
/// Instantiate once at broker startup and share via `Arc<OfdRegistry>`
/// to every per-connection 9P [`Server`][crate::nine_p::server::Server]
/// (alongside the existing `ElfCache` sharing pattern).
#[derive(Debug, Default)]
pub struct OfdRegistry {
    entries: RwLock<HashMap<OpenFileId, Arc<OfdEntry>>>,
    next_id: AtomicU64,
}

/// Result of [`OfdRegistry::clone_for`]: the freshly-dup'd `File`
/// the caller should install into its `FidState`, plus the original
/// host path so the caller can populate `FidState.path` consistently
/// with what the parent saw.
#[derive(Debug)]
pub struct ClonedOfd {
    pub file: fs::File,
    pub path: PathBuf,
}

impl OfdRegistry {
    /// Construct an empty registry. Typical usage:
    /// `Arc::new(OfdRegistry::new())`.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a parent-side open `File` for inheritance.
    ///
    /// Performs a [`fs::File::try_clone`] (== `dup(2)`) so the
    /// registry's stash and the caller's original `File` are
    /// independent host fds against the **same** kernel OFD.
    /// Returns the freshly-allocated [`OpenFileId`].
    ///
    /// The registry's stash counts as one refcount unit; an explicit
    /// [`release`][Self::release] call (matching what
    /// `handle_clunk` does for an inheriting fid) decrements it.
    /// The parent's clunk on its original fid does NOT release the
    /// registry entry — the original `File` and the registry's stash
    /// are independent host fds.
    ///
    /// # Errors
    ///
    /// Returns [`OfdRegistryError::Io`] if the underlying `dup(2)`
    /// fails (typically EMFILE / ENFILE under fd-table exhaustion).
    ///
    /// # Panics
    ///
    /// Panics if the internal `RwLock` has been poisoned by another
    /// thread (only possible if a holder of the writer lock panicked
    /// — registry mutations are infallible aside from the `dup`
    /// above, so this is treated as a process-fatal invariant).
    pub fn register(
        &self,
        file: &fs::File,
        path: impl Into<PathBuf>,
    ) -> Result<OpenFileId, OfdRegistryError> {
        let dup = file.try_clone()?;
        let id = OpenFileId(self.next_id.fetch_add(1, Ordering::Relaxed));
        let entry = Arc::new(OfdEntry {
            file: Arc::new(dup),
            path: path.into(),
            refcount: AtomicUsize::new(1),
        });
        let mut entries = self
            .entries
            .write()
            .expect("OfdRegistry::entries poisoned (writer)");
        let prev = entries.insert(id, entry);
        debug_assert!(
            prev.is_none(),
            "next_id collision in OfdRegistry::register (id={id:?})"
        );
        Ok(id)
    }

    /// Clone an existing OFD for a worker connection.
    ///
    /// Increments the entry's refcount and `try_clone`s the stashed
    /// `File` to produce a fresh host fd for the caller — same
    /// kernel OFD, distinct fd-table slot. Returns the cloned
    /// `File` plus the original host path the parent registered
    /// with so the caller can build a worker-side `FidState`.
    ///
    /// # Errors
    ///
    /// - [`OfdRegistryError::UnknownId`] if `id` was never registered
    ///   or has already been fully released. Mapped on the wire to
    ///   `EBADF` by the protocol handler.
    /// - [`OfdRegistryError::Io`] if the dup fails. The refcount is
    ///   NOT incremented in that case (the entry is left untouched).
    ///
    /// # Panics
    ///
    /// Panics if the internal `RwLock` has been poisoned.
    pub fn clone_for(&self, id: OpenFileId) -> Result<ClonedOfd, OfdRegistryError> {
        let entry = {
            let entries = self
                .entries
                .read()
                .expect("OfdRegistry::entries poisoned (reader)");
            entries
                .get(&id)
                .cloned()
                .ok_or(OfdRegistryError::UnknownId)?
        };
        let cloned = entry.file.try_clone()?;
        // Only bump the refcount after the dup succeeded; otherwise
        // an ENFILE/EMFILE would leave a phantom inheriting reference
        // that no Tclunk would ever release.
        entry.refcount.fetch_add(1, Ordering::AcqRel);
        Ok(ClonedOfd {
            file: cloned,
            path: entry.path.clone(),
        })
    }

    /// Release one outstanding reference to the entry.
    ///
    /// Returns the resulting refcount (post-decrement). If the count
    /// reached zero, the entry is removed from the registry and its
    /// stashed `File` is dropped — closing the broker's dup of the
    /// kernel OFD. (The kernel OFD itself is freed only after every
    /// other holder — the parent's original, any worker clones not
    /// yet clunked — also drops.)
    ///
    /// Calling `release` for an unknown id is a no-op and returns
    /// `None` (rather than `Err`) because the typical caller is a
    /// `handle_clunk` cleanup path that should be tolerant of races
    /// (e.g., if the worker exits abruptly between two writes the
    /// connection close and the explicit clunk can both fire).
    ///
    /// # Panics
    ///
    /// Panics if the internal `RwLock` has been poisoned.
    pub fn release(&self, id: OpenFileId) -> Option<usize> {
        let (remaining, drop_now) = {
            let entries = self
                .entries
                .read()
                .expect("OfdRegistry::entries poisoned (reader)");
            let entry = entries.get(&id)?;
            let prev = entry.refcount.fetch_sub(1, Ordering::AcqRel);
            debug_assert!(
                prev >= 1,
                "OfdRegistry::release underflow (id={id:?}, prev={prev})"
            );
            let remaining = prev.saturating_sub(1);
            (remaining, remaining == 0)
        };
        if drop_now {
            let mut entries = self
                .entries
                .write()
                .expect("OfdRegistry::entries poisoned (writer)");
            // Re-check under the writer lock: another release that
            // raced this one could have already removed the entry,
            // or a concurrent clone_for could have re-incremented
            // the refcount before we acquired the writer lock.
            if let Some(entry) = entries.get(&id)
                && entry.refcount.load(Ordering::Acquire) == 0
            {
                entries.remove(&id);
            }
        }
        Some(remaining)
    }

    /// Test-only: number of live entries. Not stable API; reserved
    /// for unit tests / health checks.
    #[doc(hidden)]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Test-only: number of live entries. Not stable API; reserved
    /// for unit tests / health checks.
    ///
    /// # Panics
    ///
    /// Panics if the internal `RwLock` has been poisoned.
    #[doc(hidden)]
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries
            .read()
            .expect("OfdRegistry::entries poisoned (reader)")
            .len()
    }

    /// Test-only: peek the refcount of an entry without modifying.
    ///
    /// # Panics
    ///
    /// Panics if the internal `RwLock` has been poisoned.
    #[doc(hidden)]
    #[must_use]
    pub fn refcount_of(&self, id: OpenFileId) -> Option<usize> {
        let entries = self
            .entries
            .read()
            .expect("OfdRegistry::entries poisoned (reader)");
        entries.get(&id).map(|e| e.refcount.load(Ordering::Acquire))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Seek, SeekFrom, Write};
    use std::path::Path;
    use std::sync::Barrier;
    use std::thread;

    fn temp_file(initial: &[u8]) -> (tempfile::NamedTempFile, PathBuf) {
        let mut tf = tempfile::NamedTempFile::new().expect("tempfile");
        if !initial.is_empty() {
            tf.write_all(initial).expect("seed write");
            tf.as_file().sync_all().ok();
        }
        let path = tf.path().to_path_buf();
        (tf, path)
    }

    fn open_rw(path: &Path) -> fs::File {
        fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .expect("open rw")
    }

    #[test]
    fn register_then_clone_shares_kernel_offset() {
        // POSIX inherited-fd shared-position is what makes the
        // registry useful: this test asserts the property end to
        // end (matches the plan's
        // `register_ofd then clone_ofd; write 100 + 100` recipe).
        let registry = OfdRegistry::new();
        let (_tf, path) = temp_file(b"");
        let parent_file = open_rw(&path);
        let id = registry.register(&parent_file, &path).expect("register");

        // Worker-side clone: same kernel OFD as the registry stash
        // (and so transitively as the parent's `parent_file`).
        let ClonedOfd {
            file: mut worker_file,
            path: returned_path,
        } = registry.clone_for(id).expect("clone");
        assert_eq!(returned_path, path);

        // Parent writes 100 bytes ("AAAA…"), worker writes 100
        // ("BBBB…"). Because the OFD is shared, worker's write
        // appends after the parent's, not at offset 0.
        let a = vec![b'A'; 100];
        let b = vec![b'B'; 100];
        let mut parent_file_handle = parent_file;
        parent_file_handle.write_all(&a).expect("parent write");
        worker_file.write_all(&b).expect("worker write");

        // Read the file's full contents back. Should be A*100 then
        // B*100 if the OFD is shared (worker's write picked up the
        // post-parent-write position). If OFDs were separate, the
        // worker would have started at offset 0 and overwritten or
        // truncated the parent's bytes.
        let mut reader = fs::File::open(&path).expect("reopen for read");
        let mut full = Vec::new();
        reader.read_to_end(&mut full).expect("read all");
        assert_eq!(full.len(), 200, "expected 200 bytes; OFD not shared?");
        assert!(full[..100].iter().all(|&c| c == b'A'));
        assert!(full[100..].iter().all(|&c| c == b'B'));
    }

    #[test]
    fn parent_clunk_first_keeps_worker_usable() {
        let registry = OfdRegistry::new();
        let (_tf, path) = temp_file(b"");
        let parent_file = open_rw(&path);
        let id = registry.register(&parent_file, &path).expect("register");
        let ClonedOfd {
            file: mut worker_file,
            ..
        } = registry.clone_for(id).expect("clone");

        // Parent "clunks" — drop its handle. The registry's stash
        // keeps the OFD alive; worker writes still succeed.
        drop(parent_file);
        worker_file
            .write_all(b"hello")
            .expect("post-parent-clunk write");
        worker_file.seek(SeekFrom::Start(0)).expect("seek");
        let mut buf = [0u8; 5];
        worker_file.read_exact(&mut buf).expect("post-write read");
        assert_eq!(&buf, b"hello");
    }

    #[test]
    fn worker_clunk_last_drops_entry() {
        let registry = OfdRegistry::new();
        let (_tf, path) = temp_file(b"data");
        let parent_file = open_rw(&path);
        let id = registry.register(&parent_file, &path).expect("register");
        let _ = registry.clone_for(id).expect("clone");
        assert_eq!(registry.refcount_of(id), Some(2));
        assert_eq!(registry.release(id), Some(1));
        assert_eq!(registry.refcount_of(id), Some(1));
        assert_eq!(registry.release(id), Some(0));
        // Entry removed; further refcount queries return None.
        assert!(registry.refcount_of(id).is_none());
        assert_eq!(registry.len(), 0);
    }

    #[test]
    fn release_unknown_is_noop() {
        let registry = OfdRegistry::new();
        assert!(registry.release(OpenFileId(9999)).is_none());
    }

    #[test]
    fn clone_unknown_returns_unknown_id() {
        let registry = OfdRegistry::new();
        match registry.clone_for(OpenFileId(9999)) {
            Err(OfdRegistryError::UnknownId) => {}
            other => panic!("expected UnknownId, got {other:?}"),
        }
    }

    #[test]
    fn clone_after_release_returns_unknown() {
        let registry = OfdRegistry::new();
        let (_tf, path) = temp_file(b"");
        let parent_file = open_rw(&path);
        let id = registry.register(&parent_file, &path).expect("register");
        assert_eq!(registry.release(id), Some(0));
        match registry.clone_for(id) {
            Err(OfdRegistryError::UnknownId) => {}
            other => panic!("expected UnknownId after release, got {other:?}"),
        }
    }

    #[test]
    fn concurrent_clones_refcount_correctly() {
        // N threads each clone_for + release exactly once; the
        // initial register's refcount remains. After joins, the
        // final refcount is 1; releasing once more drops the entry.
        // N=8 keeps test runner load bounded (see
        // `next_id_monotonic_under_concurrent_register` rationale).
        const N: usize = 8;
        let registry = Arc::new(OfdRegistry::new());
        let (_tf, path) = temp_file(b"");
        let parent_file = open_rw(&path);
        let id = registry.register(&parent_file, &path).expect("register");
        let barrier = Arc::new(Barrier::new(N));
        let mut handles = Vec::with_capacity(N);
        for _ in 0..N {
            let registry = Arc::clone(&registry);
            let barrier = Arc::clone(&barrier);
            handles.push(thread::spawn(move || {
                barrier.wait();
                let _ = registry.clone_for(id).expect("concurrent clone");
                let _ = registry.release(id).expect("concurrent release");
            }));
        }
        for h in handles {
            h.join().expect("thread join");
        }
        assert_eq!(
            registry.refcount_of(id),
            Some(1),
            "after N matched clone+release pairs, only the register ref remains"
        );
        assert_eq!(registry.release(id), Some(0));
        assert_eq!(registry.len(), 0);
    }

    #[test]
    fn next_id_monotonic_under_concurrent_register() {
        // 8 threads is sufficient to expose any race in `next_id`
        // allocation without flooding the test runner's fd table or
        // contending excessively with neighbouring parallel tests
        // (`cargo test` defaults to one test thread per core).
        const N: usize = 8;
        let registry = Arc::new(OfdRegistry::new());
        let barrier = Arc::new(Barrier::new(N));
        let mut handles = Vec::with_capacity(N);
        for _ in 0..N {
            let registry = Arc::clone(&registry);
            let barrier = Arc::clone(&barrier);
            handles.push(thread::spawn(move || {
                let (_tf, path) = temp_file(b"");
                let f = open_rw(&path);
                barrier.wait();
                registry.register(&f, &path).expect("register")
            }));
        }
        let mut ids: Vec<OpenFileId> = handles
            .into_iter()
            .map(|h| h.join().expect("join"))
            .collect();
        ids.sort();
        ids.dedup();
        assert_eq!(
            ids.len(),
            N,
            "all registered OpenFileIds should be unique under concurrent register"
        );
        assert_eq!(registry.len(), N);
    }

    #[test]
    fn drop_registry_closes_stashed_fds() {
        // Smoke test that dropping the registry without explicit
        // release does not leak the stashed dup. Compares
        // /proc/self/fd snapshot deltas before/after. We allow some
        // slack because the test runner (rayon-style worker pool,
        // tempfile cleanup, /proc readdir state) opens and closes
        // its own descriptors concurrently — strict equality is
        // racy. The relevant signal is "the delta is bounded and
        // does not scale with N".
        let baseline = count_proc_fds();
        for _ in 0..10 {
            let registry = OfdRegistry::new();
            let (_tf, path) = temp_file(b"");
            let parent_file = open_rw(&path);
            let _id = registry.register(&parent_file, &path).expect("register");
            // Drop everything (registry stash + parent file +
            // tempfile) at end of iteration. If `register`'s stash
            // leaked, fd count would grow by 1 per iteration.
        }
        let after = count_proc_fds();
        assert!(
            after <= baseline + 5,
            "registry drop leaked fds across 10 iterations (baseline={baseline}, after={after}); \
             expected ≤ baseline+5 slack for test-runner fd churn"
        );
    }

    fn count_proc_fds() -> usize {
        fs::read_dir("/proc/self/fd")
            .map(|it| it.count())
            .unwrap_or(0)
    }
}
