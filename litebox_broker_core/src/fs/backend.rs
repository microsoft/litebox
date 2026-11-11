// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! [`Backend`] for filesystems supported by [`super::resolver`]

use alloc::boxed::Box;
use alloc::string::String;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::any::{Any, TypeId};
use core::marker::PhantomData;

use litebox_platform::buffer::{ReadBuffer, WriteBuffer};

use super::errors::{
    ChmodError, ChownError, FileStatusError, MapSharedError, MkdirError, OpenError, ReadDirError,
    ReadError, RenameError, ResolutionError, RmdirError, SetTimesError, SymlinkError,
    TruncateError, UnlinkError, WalkError, WriteError,
};
use super::shared_storage::SharedFile;
use super::{DirEntry, FileStatus, FileType, Mode, OFlags, SetFileTimes, UserInfo};
use crate::readiness::ReadinessSource;
use crate::terminal::TerminalEndpoint;

/// Broker-authenticated identity of the process performing a filesystem lookup.
///
/// The numeric ID is a namespace-visible name; the key identifies this process even when
/// numeric IDs are reused. Neither field is taken from a file request's payload.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FileCaller {
    /// Non-reusable broker process identity.
    pub process_key: crate::ProcessKey,
    /// Namespace-visible process ID.
    pub process_id: litebox_broker_protocol::ProcessId,
}

impl FileCaller {
    /// The caller that `process`, in its current incarnation, is.
    #[must_use]
    pub fn for_process(process: &crate::BrokerProcess) -> Self {
        Self {
            process_key: process.key(),
            process_id: process.id(),
        }
    }
}

/// Explicit context for a filesystem path walk.
///
/// Direct backend/resolver users may have no broker process. A provider that needs one
/// must reject that case rather than guessing a current process.
#[derive(Clone, Copy, Debug)]
pub struct LookupContext {
    /// Acting filesystem credentials, with the same trust contract as other file operations.
    pub user: UserInfo,
    /// Process authenticated by the broker, if this walk originated in a broker association.
    pub caller: Option<FileCaller>,
}

impl LookupContext {
    /// A walk by root on behalf of no process, as the caller-unaware backend methods make.
    pub const UNATTRIBUTED: Self = Self {
        user: UserInfo::ROOT,
        caller: None,
    };

    pub(crate) fn for_process(process: &crate::BrokerProcess, user: UserInfo) -> Self {
        Self {
            user,
            caller: Some(FileCaller::for_process(process)),
        }
    }
}

/// A retained read-only regular-file capability, independent of its directory entry.
///
/// The backend is weakly held so a provider mounted in that same backend cannot form a
/// reference cycle. An open made through this target upgrades it for that open's lifetime.
#[derive(Clone)]
pub struct FileTarget {
    pub(super) backend: Weak<dyn Backend>,
    pub(super) handle: FileHandle,
    pub(super) location: Arc<spin::RwLock<FileLocation>>,
}

pub(super) struct FileLocation {
    pub path: String,
    pub unlinked: bool,
}

impl FileTarget {
    /// The object's last namespace path, updated by resolver-managed renames.
    /// This is for display, never authority to reopen the object.
    #[must_use]
    pub fn display_path(&self) -> String {
        self.location.read().path.clone()
    }

    /// Whether the object's directory entry has been removed or replaced.
    #[must_use]
    pub fn is_unlinked(&self) -> bool {
        self.location.read().unlinked
    }

    pub(super) fn status(&self) -> Result<FileStatus, super::errors::FileStatusError> {
        self.backend
            .upgrade()
            .ok_or(super::errors::FileStatusError::Io)?
            .status(HandleRef::File(&self.handle))
    }
}

/// An object a process publishes to a [`FilePublisher`].
pub enum PublishedObject {
    /// A retained read-only regular file.
    File(FileTarget),
    /// A directory, identified by its absolute path with symbolic links resolved, as of when it
    /// was opened.
    ///
    /// This is a path snapshot, not object identity: it goes stale if the directory or an
    /// ancestor is later renamed or replaced.
    Directory {
        /// The directory's absolute path.
        path: String,
    },
}

/// A configured consumer of authenticated, process-scoped file capabilities.
///
/// Keys and their meaning belong to the consumer, not the broker. Implementations must
/// reject unknown keys and must not retain a strong reference back to their namespace.
pub trait FilePublisher: Send + Sync {
    /// Atomically replace one process-state object. An error must leave its old value intact.
    fn publish_file(
        &self,
        caller: FileCaller,
        key: u64,
        object: PublishedObject,
    ) -> super::FileResult<()>;

    /// Atomically replace one process-state value with `data`. An error must leave its old value
    /// intact. Consumers that accept no data keep the default, which rejects every key.
    fn publish_data(&self, _caller: FileCaller, _key: u64, _data: &[u8]) -> super::FileResult<()> {
        Err(litebox_broker_protocol::fs::FileError::NotSupported)
    }
}

/// How a followed link continues the authoritative namespace walk.
pub enum LinkTarget {
    /// An ordinary relative or absolute symbolic-link target.
    Path(String),
    /// A retained file object. Only read-only and path-only opens are supported.
    File(FileTarget),
}

// This duplicates the cloneable type-erasure support from `litebox::utilities::anymap` because
// broker core cannot depend on LiteBox. Keep it local unless broader reuse justifies a common home.
trait AnyCloneSendSync: Any + Send + Sync {
    fn clone_to_any(&self) -> Box<dyn AnyCloneSendSync>;
}

impl<T: Any + Clone + Send + Sync> AnyCloneSendSync for T {
    fn clone_to_any(&self) -> Box<dyn AnyCloneSendSync> {
        Box::new(self.clone())
    }
}

impl Clone for Box<dyn AnyCloneSendSync> {
    fn clone(&self) -> Self {
        (**self).clone_to_any()
    }
}

/// The terminal that an open file refers to.
#[derive(Clone)]
pub enum FileTerminal {
    /// A terminal that the file refers to whoever opens it.
    Fixed(Arc<dyn TerminalEndpoint>),
    /// The controlling terminal of the opener's session, which the resolver
    /// binds when the file is opened and through which the file's I/O then
    /// goes.
    OpenersControlling,
}

/// How a backend file handle participates in seek.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum SeekBehavior {
    /// Seek should fail with `SeekError::NonSeekable`.
    NonSeekable,
    /// Seek should always succeed and report offset zero.
    ZeroPosition,
    /// Seek should be resolved against normal resolver-owned file position state.
    PositionBased,
    /// Like [`Self::PositionBased`], for content of unknown size, such as text generated when
    /// read: seeks may set any position from the start or the current position, but not from
    /// the end.
    UnsizedPosition,
}

/// A backend that can be used to support a (full or subset of) a LiteBox filesystem.
pub trait Backend: Send + Sync + Any {
    /// Register filesystem state for the newly allocated `process`, before its runner starts.
    ///
    /// The returned resource lasts through image replacement and is dropped on exit, startup
    /// failure, or final cleanup. Its destructor must not call back into broker process state.
    /// A backend may keep a weak reference to `process` to query generic process state while
    /// serving files, but must not hold its own locks while doing so. `parent` identifies the
    /// creator's incarnation, not a possibly reused numeric ID.
    fn process_created(
        &self,
        _process: &Arc<crate::BrokerProcess>,
        _parent: Option<FileCaller>,
    ) -> crate::Result<Box<dyn Send + Sync>> {
        Ok(Box::new(()))
    }

    /// Resolve the root directory.
    fn root(&self) -> Result<ResolvedDir<'_>, WalkError>;

    /// Resolve the root for a particular caller. Ordinary backends ignore caller identity.
    fn root_with_context(&self, _context: &LookupContext) -> Result<ResolvedDir<'_>, WalkError> {
        self.root()
    }

    /// Resolve `components` without opening the target.
    ///
    /// Before looking up a child, backends reporting [`PermissionCheck::ByResolver`] must invoke
    /// `authorize_dir_lookup` on its parent directory. Callback failure stops resolution immediately,
    /// before inspecting the child. Self-enforcing backends omit the callback.
    ///
    /// The final component does not invoke `authorize_dir_lookup` upon itself, only its parent.
    /// An empty sequence resolves to the starting directory without checking its permissions.
    ///
    /// Backends never follow symlinks. A non-directory (including a symlink) before the final
    /// component fails with [`super::errors::PathError::ComponentNotADirectory`], with the error's
    /// component index naming the next child (`non_directory_index + 1`). Only a missing final name
    /// returns [`Resolution::MissingFinal`]; missing intermediate names are errors. An existing final
    /// name that must be neither opened nor created may fail with
    /// [`super::errors::PathError::NoSuchFileOrDirectory`] at its own index.
    fn resolve<'a>(
        &'a self,
        from: ResolvedDir<'a>,
        components: &[&str],
        authorize_dir_lookup: &dyn Fn(&PermissionInfo) -> Result<(), WalkError>,
    ) -> Result<Resolution<'a>, ResolutionError>;

    /// Resolve components with explicit caller identity and acting credentials.
    fn resolve_with_context<'a>(
        &'a self,
        _context: &LookupContext,
        from: ResolvedDir<'a>,
        components: &[&str],
        authorize_dir_lookup: &dyn Fn(&PermissionInfo) -> Result<(), WalkError>,
    ) -> Result<Resolution<'a>, ResolutionError> {
        self.resolve(from, components, authorize_dir_lookup)
    }

    /// Read the unexpanded target of the symlink `name` in `dir`.
    fn read_link_at(&self, dir: &ResolvedDir<'_>, name: &str) -> Result<String, WalkError>;

    /// Read a link whose target may depend on the task accessing the namespace.
    fn read_link_at_with_context(
        &self,
        _context: &LookupContext,
        dir: &ResolvedDir<'_>,
        name: &str,
    ) -> Result<String, WalkError> {
        self.read_link_at(dir, name)
    }

    /// Follow a link, keeping object authority separate from its readlink display text.
    fn follow_link_at(
        &self,
        context: &LookupContext,
        dir: &ResolvedDir<'_>,
        name: &str,
    ) -> Result<LinkTarget, WalkError> {
        self.read_link_at_with_context(context, dir, name)
            .map(LinkTarget::Path)
    }

    /// Open the already-resolved directory after resolver authorization, validating `flags`.
    fn open_dir(&self, dir: ResolvedDir<'_>, flags: OFlags) -> Result<DirHandle, OpenError>;

    /// Obtain a resolved directory from an existing owned directory handle, without opening it.
    ///
    /// This operation always succeeds and returns a `Some` _unless_ on a networked backend where
    /// owned handles can go stale.
    ///
    /// XXX(jayb): We will likely migrate away from `Option` here when we do a bit of an overhaul of
    /// the `errors` module in order to more consistently support stale errors everywhere.
    fn walking_dir_at<'a>(&'a self, dir: &DirHandle) -> Option<ResolvedDir<'a>>;

    /// Open the already-resolved file after resolver authorization, validating `flags`.
    fn open_file(&self, file: ResolvedFile<'_>, flags: OFlags) -> Result<FileHandle, OpenError>;

    /// Opens an independent description of the retained object, without resolving its old path.
    /// Backends with per-open state must initialize that state afresh.
    fn reopen_file(&self, _file: &FileHandle, _flags: OFlags) -> Result<FileHandle, OpenError> {
        Err(OpenError::NoSuchDevice)
    }

    /// Read directory entries at `dir`.
    fn list_dir_at(&self, handle: DirHandle) -> Result<Vec<DirEntry>, ReadDirError>;

    /// Look up the single entry `name` at `dir`, as [`Self::list_dir_at`] would report it.
    ///
    /// The default implementation scans the full listing; backends that can find one entry more
    /// cheaply should override it.
    fn lookup_at(&self, dir: &DirHandle, name: &str) -> Result<Option<DirEntry>, ReadDirError> {
        Ok(self
            .list_dir_at(dir.clone())?
            .into_iter()
            .find(|entry| entry.name == name))
    }

    /// Read at `offset` into the start of `buf` (see [`crate::transfer`]), returning the number of
    /// bytes read.
    ///
    /// Backends do not have an internal notion of offsets; instead the resolver maintains offsets
    /// as needed. For files with non-position-based [`SeekBehavior`], such as `stdin`, the resolver
    /// passes zero and the backend should ignore the offset.
    fn read(
        &self,
        h: &FileHandle,
        buf: &mut dyn ReadBuffer,
        offset: usize,
    ) -> Result<usize, ReadError>;

    /// Optional performance hook: get static backing data for a file, if available and supported.
    ///
    /// This method returns the (entire) underlying static byte slice if the file's contents are
    /// backed by borrowed static data.
    ///
    /// Returns `None` if indicating no static backing data is available/supported.
    #[expect(unused_variables, reason = "default body, non-underscored param names")]
    fn get_static_backing_data(&self, h: &FileHandle) -> Option<&'static [u8]> {
        None
    }

    /// Returns the host shared object that holds the file's contents.
    ///
    /// After this succeeds, the backend must keep the file's contents in that object, so that
    /// every mapping and every read, write, and truncation see the same bytes, and must return
    /// the same object for every later call on the same file.
    ///
    /// The default implementation returns [`MapSharedError::Unsupported`].
    #[expect(unused_variables, reason = "default body with unused parameter")]
    fn map_shared(&self, h: &FileHandle) -> Result<Arc<SharedFile>, MapSharedError> {
        Err(MapSharedError::Unsupported)
    }

    /// Write `buf` into the file, based on `offset` (see [`crate::transfer`]), returning the number
    /// of bytes written from its start.
    ///
    /// See [`Self::read`] on internal offset storage for backends.
    // XXX(jayb): I need to think more about how we set up some sort of "intend to write" flag that
    // we can use to obtain the ability to support writes to an `O_APPEND` file, but without making
    // it ugly on the interface side here. It would be very ugly for us to pass in extra flags, or
    // indeed even need to maintain/handle seeking on every backend; mostly we need some sort of
    // nicer locking discipline, but I don't want to block the MVP for this just yet.
    fn write(
        &self,
        h: &FileHandle,
        buf: &dyn WriteBuffer,
        offset: usize,
    ) -> Result<usize, WriteError>;

    /// Truncate the file to the specified length.
    ///
    /// If shorter than existing size, extra data is lost. If longer than existing size, resize by
    /// adding `\0`s.
    fn truncate(&self, h: &FileHandle, length: usize) -> Result<(), TruncateError>;

    /// Describe seek behavior for an open file handle.
    fn seek_behavior(&self, h: &FileHandle) -> SeekBehavior;

    /// Status of an open file or directory handle.
    fn status(&self, h: HandleRef<'_>) -> Result<FileStatus, FileStatusError>;

    /// Query metadata without consuming or opening the resolved target.
    fn resolved_status(&self, target: &ResolvedTarget<'_>) -> Result<FileStatus, FileStatusError>;

    /// The terminal that an open file handle refers to. A file is a terminal
    /// exactly when it refers to one.
    #[expect(unused_variables, reason = "default body, non-underscored param names")]
    fn terminal(&self, h: &FileHandle) -> Option<FileTerminal> {
        None
    }

    /// Readiness of an open file handle whose reads or writes can fail with `WouldBlock`, or
    /// `None` if they always make progress.
    #[expect(unused_variables, reason = "default body, non-underscored param names")]
    fn readiness_source(&self, h: &FileHandle) -> Option<Arc<dyn ReadinessSource>> {
        None
    }

    /// Create a new file within `parent`.
    fn create_file_at(
        &self,
        parent: ResolvedDir<'_>,
        name: &str,
        metadata: CreationMetadata,
    ) -> Result<FileHandle, OpenError>;

    /// Create a symbolic link storing `target` verbatim at `dir` with the given `name` and metadata.
    fn symlink_at(
        &self,
        dir: ResolvedDir<'_>,
        name: &str,
        target: &str,
        metadata: CreationMetadata,
    ) -> Result<(), SymlinkError>;

    /// Create a new directory within `parent`.
    fn mkdir_at(
        &self,
        parent: ResolvedDir<'_>,
        name: &str,
        metadata: CreationMetadata,
    ) -> Result<DirHandle, MkdirError>;

    /// Remove `name` after the resolver authorizes search and write access to `parent`.
    fn unlink_at(&self, parent: ResolvedDir<'_>, name: &str) -> Result<(), UnlinkError>;

    /// Remove the directory `name` at `parent`.
    // XXX(jayb): I don't like that unlink and rmdir exist separately, we should probably merge them.
    fn rmdir_at(&self, parent: ResolvedDir<'_>, name: &str) -> Result<(), RmdirError>;

    /// Atomically move an entry, replacing a compatible destination without following final
    /// symbolic links. Backends must reject directory cycles and preserve open file contents.
    /// Directory handles retain the backend's documented object or path-locator semantics.
    fn rename_at(
        &self,
        old_dir: DirHandle,
        old_name: &str,
        new_dir: DirHandle,
        new_name: &str,
    ) -> Result<(), RenameError>;

    /// Update timestamps after resolver authorization, without following symbolic links.
    fn set_times(
        &self,
        target: ResolvedTarget<'_>,
        times: &SetFileTimes,
    ) -> Result<(), SetTimesError>;

    /// Update a resolved target's permissions.
    fn chmod(&self, h: ResolvedTarget<'_>, mode: Mode) -> Result<(), ChmodError>;

    /// Change permissions on the open object, even after rename or unlink.
    ///
    /// Resolver-authorized backends must check that `user` owns the object or is root.
    /// Self-enforcing backends use their native descriptor authorization instead.
    /// This must never reopen the object's remembered pathname. A backend that cannot change an
    /// open file itself returns [`ChmodError::Unsupported`], after which the resolver changes it
    /// through its opened path while that path still names the same node.
    fn chmod_handle(
        &self,
        _h: HandleRef<'_>,
        _user: UserInfo,
        _mode: Mode,
    ) -> Result<(), ChmodError> {
        Err(ChmodError::Unsupported)
    }

    /// Update a resolved target's owner/group.
    fn chown(
        &self,
        h: ResolvedTarget<'_>,
        user: Option<u16>,
        group: Option<u16>,
    ) -> Result<(), ChownError>;
}

/// Concrete handle types used by a backend.
///
/// This trait is intentionally separate from [`Backend`]: the dyn-safe [`Backend`] interface keeps
/// using erased handle wrappers, while concrete backend implementations can use these associated
/// types at their own boundaries instead of spelling out manual erased-handle downcasts.
pub trait BackendHandles {
    /// Scoped state identifying an unopened directory.
    type ResolvedDir<'a>: 'a;
    /// Scoped state identifying an unopened non-directory target.
    type ResolvedFile<'a>: 'a;
    /// An owned handle to an open file
    type FileHandle: Clone + Send + Sync + 'static;
    /// An owned handle to an open directory
    type DirHandle: Clone + Send + Sync + 'static;
}

/// A resolved, unopened directory, including permission metadata for resolver authorization.
pub struct ResolvedDir<'a> {
    /// How permissions on this directory should be checked.
    pub permissions: PermissionCheck,
    raw: ErasedResolved<'a, DirKind>,
}

/// A resolved, unopened non-directory target, including permission metadata for authorization.
pub struct ResolvedFile<'a> {
    /// How permissions on this target should be checked.
    pub permissions: PermissionCheck,
    /// Lets the resolver detect symlinks, which it (not the backend) expands.
    pub file_type: FileType,
    raw: ErasedResolved<'a, FileKind>,
}

/// A resolved target.
pub enum ResolvedTarget<'a> {
    /// A directory target.
    Dir(ResolvedDir<'a>),
    /// A non-directory target.
    File(ResolvedFile<'a>),
}

/// An owned handle to an open file
#[derive(Clone)]
pub struct FileHandle {
    raw: Box<dyn AnyCloneSendSync>,
}

/// An owned handle to an open directory
#[derive(Clone)]
pub struct DirHandle {
    raw: Box<dyn AnyCloneSendSync>,
}

/// An owned handle to an open file or directory.
#[derive(Clone)]
pub enum Handle {
    /// A handle to an open file
    File(FileHandle),
    /// A handle to an open directory
    Dir(DirHandle),
}

impl Handle {
    /// Borrow this handle, for passing to the object-addressed [`Backend`] operations.
    #[must_use]
    pub fn as_ref(&self) -> HandleRef<'_> {
        match self {
            Handle::File(handle) => HandleRef::File(handle),
            Handle::Dir(handle) => HandleRef::Dir(handle),
        }
    }
}

/// A borrowed handle to an open file or directory.
#[derive(Clone, Copy)]
pub enum HandleRef<'a> {
    /// A handle to an open file
    File(&'a FileHandle),
    /// A handle to an open directory
    Dir(&'a DirHandle),
}

trait ErasedResolvedHandle {
    fn as_raw(&self) -> *const ();
    fn into_raw(self: Box<Self>) -> *mut ();
}

impl<H> ErasedResolvedHandle for H {
    fn as_raw(&self) -> *const () {
        core::ptr::from_ref(self).cast()
    }

    fn into_raw(self: Box<Self>) -> *mut () {
        Box::into_raw(self).cast()
    }
}

/// Selects which [`BackendHandles`] resolved type an [`ErasedResolved`] stores.
trait ResolvedKind {
    type Handle<'a, B: BackendHandles + 'static>: 'a;
}

struct DirKind;
impl ResolvedKind for DirKind {
    type Handle<'a, B: BackendHandles + 'static> = B::ResolvedDir<'a>;
}

struct FileKind;
impl ResolvedKind for FileKind {
    type Handle<'a, B: BackendHandles + 'static> = B::ResolvedFile<'a>;
}

/// A type-erased `K::Handle<'a, B>`, recoverable only with the same `B`.
struct ErasedResolved<'a, K: ResolvedKind> {
    backend_type: TypeId,
    raw: Box<dyn ErasedResolvedHandle + 'a>,
    _kind: PhantomData<K>,
    _invariant: PhantomData<fn(&'a ()) -> &'a ()>,
}

impl<'a, K: ResolvedKind> ErasedResolved<'a, K> {
    fn new<B: BackendHandles + 'static>(handle: K::Handle<'a, B>) -> Self {
        Self {
            backend_type: TypeId::of::<B>(),
            raw: Box::new(handle),
            _kind: PhantomData,
            _invariant: PhantomData,
        }
    }

    fn check<B: BackendHandles + 'static>(&self) {
        assert_eq!(
            self.backend_type,
            TypeId::of::<B>(),
            "backend resolved handle type mismatch"
        );
    }

    fn get<B: BackendHandles + 'static>(&self) -> &K::Handle<'a, B> {
        self.check::<B>();
        // SAFETY: `new::<B>` stored a `K::Handle<'a, B>`: `K` is fixed by this type, `B` is
        // checked above, and `'a` is invariant. The reference borrows `self`, which owns the box.
        unsafe { &*(*self.raw).as_raw().cast::<K::Handle<'a, B>>() }
    }

    fn into_inner<B: BackendHandles + 'static>(self) -> K::Handle<'a, B> {
        self.check::<B>();
        // SAFETY: as in `get`, the allocation holds a `K::Handle<'a, B>`.
        unsafe { *Box::from_raw(self.raw.into_raw().cast::<K::Handle<'a, B>>()) }
    }
}

impl<'a> ResolvedDir<'a> {
    /// Erase a concrete resolved directory and its permission metadata.
    pub fn from_typed<B: BackendHandles + 'static>(
        handle: B::ResolvedDir<'a>,
        permissions: PermissionCheck,
    ) -> Self {
        Self {
            permissions,
            raw: ErasedResolved::new::<B>(handle),
        }
    }

    /// Borrow the concrete resolved directory stored in this handle.
    ///
    /// # Panics
    ///
    /// Panics if `B` is not the backend type used to create this handle.
    pub fn get_typed<B: BackendHandles + 'static>(&self) -> &B::ResolvedDir<'a> {
        self.raw.get::<B>()
    }

    /// Recover scoped directory state passed back to the same backend.
    ///
    /// # Panics
    ///
    /// Panics if `B` is not the backend type used to create this handle.
    pub fn into_typed<B: BackendHandles + 'static>(self) -> B::ResolvedDir<'a> {
        self.raw.into_inner::<B>()
    }
}

impl<'a> ResolvedFile<'a> {
    /// Erase a concrete resolved file and its permission metadata and type.
    pub fn from_typed<B: BackendHandles + 'static>(
        handle: B::ResolvedFile<'a>,
        permissions: PermissionCheck,
        file_type: FileType,
    ) -> Self {
        Self {
            permissions,
            file_type,
            raw: ErasedResolved::new::<B>(handle),
        }
    }

    /// Borrow the concrete resolved file stored in this handle.
    ///
    /// # Panics
    ///
    /// Panics if `B` is not the backend type used to create this handle.
    pub fn get_typed<B: BackendHandles + 'static>(&self) -> &B::ResolvedFile<'a> {
        self.raw.get::<B>()
    }

    /// Recover scoped file state passed back to the same backend.
    ///
    /// # Panics
    ///
    /// Panics if `B` is not the backend type used to create this handle.
    pub fn into_typed<B: BackendHandles + 'static>(self) -> B::ResolvedFile<'a> {
        self.raw.into_inner::<B>()
    }
}

impl FileHandle {
    /// Erase the concrete type of the handle.
    pub fn from_typed<B: BackendHandles>(handle: B::FileHandle) -> Self {
        Self {
            raw: Box::new(handle),
        }
    }

    /// Borrow the concrete handle stored in this erased handle.
    ///
    /// Intended to be called by backend implementations as `handle.get_typed::<Self>()` on handles
    /// that the resolver passed back to the same backend.
    ///
    /// # Panics
    ///
    /// Panics if the stored handle's concrete type is not `B::FileHandle`.
    pub fn get_typed<B: BackendHandles>(&self) -> &B::FileHandle {
        (&*self.raw as &dyn Any)
            .downcast_ref::<B::FileHandle>()
            .expect("backend file handle type mismatch")
    }
}

impl DirHandle {
    /// Erase a concrete directory handle.
    pub fn from_typed<B: BackendHandles>(handle: B::DirHandle) -> Self {
        Self {
            raw: Box::new(handle),
        }
    }

    /// Borrow the concrete handle stored in this erased handle.
    ///
    /// Intended to be called by backend implementations as `handle.get_typed::<Self>()` on handles
    /// that the resolver passed back to the same backend.
    ///
    /// # Panics
    ///
    /// Panics if the stored handle's concrete type is not `B::DirHandle`.
    pub fn get_typed<B: BackendHandles>(&self) -> &B::DirHandle {
        (&*self.raw as &dyn Any)
            .downcast_ref::<B::DirHandle>()
            .expect("backend directory handle type mismatch")
    }

    /// Recover the concrete handle stored in this erased handle.
    ///
    /// Intended to be called by backend implementations as `handle.into_typed::<Self>()` on
    /// handles that the resolver passed back to the same backend.
    ///
    /// # Panics
    ///
    /// Panics if the stored handle's concrete type is not `B::DirHandle`.
    pub fn into_typed<B: BackendHandles>(self) -> B::DirHandle {
        let raw: Box<dyn Any> = self.raw;
        *raw.downcast::<B::DirHandle>()
            .expect("backend directory handle type mismatch")
    }
}

/// The result of [`Backend::resolve`]ing a component sequence.
#[must_use]
pub enum Resolution<'a> {
    /// The target exists, including when an empty sequence names the starting directory.
    Found(ResolvedTarget<'a>),
    /// Only the final component is missing. A missing parent results in a [`ResolutionError`].
    MissingFinal {
        /// The directory containing the missing name.
        parent: ResolvedDir<'a>,
    },
}

/// The metadata a backend stamps onto a newly created file or directory.
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub struct CreationMetadata {
    /// Permission bits for the new node.
    pub mode: Mode,
    /// Owner of the new node.
    pub owner: UserInfo,
}

/// Whether a resolved component should be permission-checked by the resolver.
#[derive(Clone, Debug)]
#[must_use]
pub enum PermissionCheck {
    /// The backend is self-enforcing permissions for this item.
    ByBackend,
    /// The resolver should check this permission metadata.
    ByResolver(PermissionInfo),
}

/// Permission information for a particular component of the walk.
#[derive(Clone, Debug)]
pub struct PermissionInfo {
    /// Permission bits for the component.
    pub mode: Mode,
    /// Owner of the component.
    pub owner: UserInfo,
    /// Whether the filesystem rejects writes, so writable file opens and directory entry changes
    /// report EROFS whatever the mode; unlink, rmdir and rename report it before name lookup.
    /// Self-enforcing backends order their own errors through [`PermissionCheck::ByBackend`].
    // TODO(jayb): consider a top-level "is read-only fs" backend method instead of a per-node flag.
    pub on_read_only_fs: bool,
}

#[cfg(test)]
mod tests {
    use super::Backend;

    #[test]
    fn backend_is_dyn_safe() {
        fn assert_dyn_safe(_: Option<&dyn Backend>) {}

        assert_dyn_safe(None);
    }
}
