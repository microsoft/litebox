// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! [`Backend`] for filesystems supported by [`super::resolver`]

use alloc::boxed::Box;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::any::{Any, TypeId};
use core::marker::PhantomData;

use litebox_platform::buffer::{ReadBuffer, WriteBuffer};

use litebox_broker_protocol::authority::{DomainId, Principal};

use super::errors::{
    ChmodError, ChownError, FileStatusError, MapSharedError, MkdirError, OpenError, ReadDirError,
    ReadError, RenameError, ResolutionError, RmdirError, SetSecurityError, SetTimesError,
    SymlinkError, TruncateError, UnlinkError, WalkError, WriteError,
};
use super::shared_storage::SharedFile;
use super::{DirEntry, FileStatus, FileType, Mode, OFlags, SetFileTimes, UserInfo};
use crate::descriptor::{FileKind as DescriptorKind, SecurityDescriptor};
use crate::readiness::ReadinessSource;
use crate::terminal::TerminalEndpoint;

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
}

/// A backend that can be used to support a (full or subset of) a LiteBox filesystem.
pub trait Backend: Send + Sync + Any {
    /// Resolve the root directory.
    fn root(&self) -> Result<ResolvedDir<'_>, WalkError>;

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

    /// Read the unexpanded target of the symlink `name` in `dir`.
    fn read_link_at(&self, dir: &ResolvedDir<'_>, name: &str) -> Result<String, WalkError>;

    /// Reads the target of this pinned symbolic link without looking it up by name again.
    /// Credentialed resolution does not fall back to a name-based read.
    fn read_resolved_link(&self, _file: &ResolvedFile<'_>) -> Result<String, WalkError> {
        Err(WalkError::Io)
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

    /// Update a resolved target's owner/group.
    fn chown(
        &self,
        h: ResolvedTarget<'_>,
        user: Option<u16>,
        group: Option<u16>,
    ) -> Result<(), ChownError>;

    // The `*_checked` operations below serve credential-enabled resolvers. Each runs its
    // `authorize` callback on the descriptors of the objects it is about to change while holding
    // the lock that makes the change atomic, so the check and the change act on the same objects.
    // The callbacks only evaluate descriptors and never call back into the backend.
    //
    // Backends whose nodes report `PermissionCheck::ByResolver` must implement all of them; the
    // defaults fail closed for backends that cannot yet pin what they check.

    /// Create a new file named `name` within `parent`, failing with
    /// [`OpenError::AlreadyExists`] if the name exists. `authorize` receives `parent`'s current
    /// descriptor and returns the new file's.
    #[expect(unused_variables, reason = "default body, non-underscored param names")]
    fn create_file_checked(
        &self,
        parent: ResolvedDir<'_>,
        name: &str,
        authorize: &dyn Fn(&SecurityDescriptor) -> Result<SecurityDescriptor, OpenError>,
    ) -> Result<FileHandle, OpenError> {
        Err(OpenError::Io)
    }

    /// Like [`Self::create_file_checked`], but creates a symbolic link storing `target`.
    #[expect(unused_variables, reason = "default body, non-underscored param names")]
    fn symlink_checked(
        &self,
        dir: ResolvedDir<'_>,
        name: &str,
        target: &str,
        authorize: &dyn Fn(&SecurityDescriptor) -> Result<SecurityDescriptor, SymlinkError>,
    ) -> Result<(), SymlinkError> {
        Err(SymlinkError::Io)
    }

    /// Like [`Self::create_file_checked`], but creates a directory.
    #[expect(unused_variables, reason = "default body, non-underscored param names")]
    fn mkdir_checked(
        &self,
        parent: ResolvedDir<'_>,
        name: &str,
        authorize: &dyn Fn(&SecurityDescriptor) -> Result<SecurityDescriptor, MkdirError>,
    ) -> Result<DirHandle, MkdirError> {
        Err(MkdirError::Io)
    }

    /// Like [`Self::unlink_at`], but `authorize`s the removal of the entry that `name` names
    /// when it is removed.
    #[expect(unused_variables, reason = "default body, non-underscored param names")]
    fn unlink_checked(
        &self,
        parent: ResolvedDir<'_>,
        name: &str,
        authorize: &dyn Fn(&EntryRemoval<'_>) -> Result<(), UnlinkError>,
    ) -> Result<(), UnlinkError> {
        Err(UnlinkError::Io)
    }

    /// Like [`Self::rmdir_at`], but `authorize`s the removal of the directory that `name` names
    /// when it is removed.
    #[expect(unused_variables, reason = "default body, non-underscored param names")]
    fn rmdir_checked(
        &self,
        parent: ResolvedDir<'_>,
        name: &str,
        authorize: &dyn Fn(&EntryRemoval<'_>) -> Result<(), RmdirError>,
    ) -> Result<(), RmdirError> {
        Err(RmdirError::Io)
    }

    /// Like [`Self::rename_at`], but `authorize`s the move, and any replacement, of the entries
    /// that the names name when they are changed.
    #[expect(unused_variables, reason = "default body, non-underscored param names")]
    fn rename_checked(
        &self,
        old_dir: DirHandle,
        old_name: &str,
        new_dir: DirHandle,
        new_name: &str,
        authorize: &dyn Fn(&EntryRename<'_>) -> Result<(), RenameError>,
    ) -> Result<(), RenameError> {
        Err(RenameError::Io)
    }

    /// Like [`Self::set_times`], but `authorize`s the change against the target's descriptor
    /// when it is applied.
    #[expect(unused_variables, reason = "default body, non-underscored param names")]
    fn set_times_checked(
        &self,
        target: ResolvedTarget<'_>,
        times: &SetFileTimes,
        authorize: &dyn Fn(&SecurityDescriptor) -> Result<(), SetTimesError>,
    ) -> Result<(), SetTimesError> {
        Err(SetTimesError::Io)
    }

    /// Replace a resolved target's descriptor with what `update` computes from its current one,
    /// without following symbolic links. The backend stores the result exactly or fails.
    #[expect(unused_variables, reason = "default body, non-underscored param names")]
    fn update_security(
        &self,
        target: ResolvedTarget<'_>,
        update: &dyn Fn(&SecurityDescriptor) -> Result<SecurityDescriptor, SetSecurityError>,
    ) -> Result<(), SetSecurityError> {
        Err(SetSecurityError::Io)
    }

    // The content-changing operations below likewise serve credential-enabled resolvers. Each
    // applies `content_change` to the file's stored descriptor under the same lock as the change
    // to its contents, and only when that change succeeds, so no reader of the descriptor sees
    // the new contents with the old descriptor. They must not otherwise change the descriptor.

    /// Like [`Self::open_file`], but first passes the file's current descriptor to
    /// [`OpenChecks::admit`] under the lock that keeps that descriptor current, and holds that lock
    /// until the open completes, so no change to the descriptor races the admission. If `flags`
    /// truncate the file, applies [`OpenChecks::content_change`] to its descriptor with the
    /// truncation. Objects that the open creates take their owners from [`OpenChecks::opener`].
    #[expect(unused_variables, reason = "default body, non-underscored param names")]
    fn open_file_checked(
        &self,
        file: ResolvedFile<'_>,
        flags: OFlags,
        checks: &OpenChecks<'_>,
    ) -> Result<FileHandle, OpenError> {
        Err(OpenError::Io)
    }

    /// Like [`Self::write`], but applies `content_change` to the file's descriptor if the write
    /// writes anything.
    #[expect(unused_variables, reason = "default body, non-underscored param names")]
    fn write_checked(
        &self,
        h: &FileHandle,
        buf: &dyn WriteBuffer,
        offset: usize,
        content_change: &dyn Fn(&mut SecurityDescriptor),
    ) -> Result<usize, WriteError> {
        Err(WriteError::Io)
    }

    /// Like [`Self::truncate`], but applies `content_change` to the file's descriptor if the
    /// truncation succeeds, even if the length is unchanged (as Linux does).
    #[expect(unused_variables, reason = "default body, non-underscored param names")]
    fn truncate_checked(
        &self,
        h: &FileHandle,
        length: usize,
        content_change: &dyn Fn(&mut SecurityDescriptor),
    ) -> Result<(), TruncateError> {
        Err(TruncateError::Io)
    }
}

/// The objects a checked entry removal changes, as [`Backend::unlink_checked`] and
/// [`Backend::rmdir_checked`] find them when committing.
pub struct EntryRemoval<'a> {
    /// The directory holding the entry.
    pub parent: &'a SecurityDescriptor,
    /// The object the entry names.
    pub entry: &'a SecurityDescriptor,
}

/// A [`Backend::unlink_checked`] or [`Backend::rmdir_checked`] callback, for backends sharing
/// their implementation with the unchecked operations.
pub(crate) type AuthorizeRemoval<'a, E> = &'a dyn Fn(&EntryRemoval<'_>) -> Result<(), E>;

/// A [`Backend::rename_checked`] callback, for backends sharing its implementation with
/// [`Backend::rename_at`].
pub(crate) type AuthorizeRename<'a> = &'a dyn Fn(&EntryRename<'_>) -> Result<(), RenameError>;

/// A content-change callback of [`Backend::write_checked`] and its kin, for backends sharing
/// their implementation with the unchecked operations.
pub(crate) type ContentChange<'a> = &'a dyn Fn(&mut SecurityDescriptor);

/// What [`Backend::open_file_checked`] checks and applies for a credential-enabled resolver.
#[derive(Clone, Copy)]
pub struct OpenChecks<'a> {
    /// Who opens the file and owns objects that the open creates, such as a pseudo-terminal pair.
    pub opener: Opener,
    /// Admits the open against the file's current descriptor.
    pub admit: &'a dyn Fn(&SecurityDescriptor) -> Result<(), OpenError>,
    /// Applied to the file's descriptor with a truncation, as by [`Backend::write_checked`].
    pub content_change: &'a dyn Fn(&mut SecurityDescriptor),
}

/// The identity with which a file is opened, for objects that opening it creates.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Opener {
    /// The owner of the opener's Access subject.
    pub owner: Principal,
    /// The group of the opener's Access subject.
    pub group: Principal,
}

/// The objects a checked rename changes, as [`Backend::rename_checked`] finds them when
/// committing.
pub struct EntryRename<'a> {
    /// The directory the entry leaves.
    pub old_parent: &'a SecurityDescriptor,
    /// The directory the entry joins.
    pub new_parent: &'a SecurityDescriptor,
    /// Whether both directories are the same object.
    pub same_parent: bool,
    /// The moved object.
    pub source: &'a SecurityDescriptor,
    /// The object whose entry the move replaces, if any.
    pub replaced: Option<&'a SecurityDescriptor>,
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

impl ResolvedTarget<'_> {
    /// How permissions on this target should be checked.
    #[must_use]
    pub fn permissions(&self) -> &PermissionCheck {
        match self {
            Self::Dir(dir) => &dir.permissions,
            Self::File(file) => &file.permissions,
        }
    }
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
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct CreationMetadata {
    /// Permission bits for the new node; the projection of `descriptor` for backends that store
    /// only POSIX metadata.
    pub mode: Mode,
    /// The new node's descriptor, which backends that store descriptors store exactly. Backends
    /// that store only POSIX metadata take the owner and group from it, and fail rather than
    /// substitute one they cannot store.
    pub descriptor: SecurityDescriptor,
}

impl CreationMetadata {
    /// Metadata for a node of `file_type` owned by `owner` with access `mode`.
    pub fn posix(file_type: FileType, mode: Mode, owner: UserInfo) -> Self {
        Self {
            mode,
            descriptor: posix_descriptor(file_type, mode, owner),
        }
    }

    /// Metadata storing `descriptor`, with its POSIX mode (see [`status_mode`]).
    pub fn new(descriptor: SecurityDescriptor) -> Self {
        Self {
            mode: status_mode(&descriptor),
            descriptor,
        }
    }
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
    /// `None` marks a directory of a self-enforcing backend that a backend combining others (such
    /// as [`super::composer::Composer`]) is about to search; see [`Self::backend_enforced`].
    descriptor: Option<SecurityDescriptor>,
    /// Whether the broker owns `descriptor`, rather than it being the projection of metadata that
    /// a self-enforcing backend reported; see [`Self::reported_posix`].
    broker_owned: bool,
    on_read_only_fs: bool,
}

impl PermissionInfo {
    /// Permission information for an object protected by `descriptor`.
    ///
    /// `on_read_only_fs` says whether the filesystem rejects writes, so writable file opens and
    /// directory entry changes report EROFS whatever the descriptor grants; unlink, rmdir and
    /// rename report it before name lookup. Self-enforcing backends order their own errors
    /// through [`PermissionCheck::ByBackend`].
    // TODO(jayb): consider a top-level "is read-only fs" backend method instead of a per-node flag.
    pub fn new(descriptor: SecurityDescriptor, on_read_only_fs: bool) -> Self {
        Self {
            descriptor: Some(descriptor),
            broker_owned: true,
            on_read_only_fs,
        }
    }

    /// Permission information projected from the status that a self-enforcing backend reports,
    /// for backends that layer over one (such as [`super::overlay::Overlay`]). Legacy resolvers
    /// check it like [`Self::posix`]; resolvers that authorize credentials refuse it, as the
    /// broker does not own that metadata.
    #[must_use]
    pub fn reported_posix(status: &FileStatus, on_read_only_fs: bool) -> Self {
        Self {
            broker_owned: false,
            ..Self::new(status_descriptor(status), on_read_only_fs)
        }
    }

    /// Permission information for a POSIX-owned object (see [`posix_descriptor`]).
    pub fn posix(file_type: FileType, mode: Mode, owner: UserInfo, on_read_only_fs: bool) -> Self {
        Self::new(posix_descriptor(file_type, mode, owner), on_read_only_fs)
    }

    /// Reported to `authorize_dir_lookup` before a backend that combines others searches a
    /// directory whose backend reports [`PermissionCheck::ByBackend`] (which it otherwise would
    /// not report), so that resolvers that never trust a self-enforcing backend can refuse the
    /// lookup.
    #[must_use]
    pub fn backend_enforced() -> Self {
        Self {
            descriptor: None,
            broker_owned: false,
            on_read_only_fs: false,
        }
    }

    /// The descriptor protecting the object, or `None` for [`Self::backend_enforced`].
    #[must_use]
    pub fn descriptor(&self) -> Option<&SecurityDescriptor> {
        self.descriptor.as_ref()
    }

    /// The descriptor protecting the object if the broker owns it, so that it may authorize
    /// credentials; `None` for [`Self::backend_enforced`] and [`Self::reported_posix`].
    #[must_use]
    pub fn broker_descriptor(&self) -> Option<&SecurityDescriptor> {
        self.descriptor.as_ref().filter(|_| self.broker_owned)
    }

    /// Whether the object is on a filesystem that rejects writes.
    #[must_use]
    pub fn on_read_only_fs(&self) -> bool {
        self.on_read_only_fs
    }

    /// Mark the object as being on a filesystem that rejects writes.
    pub fn set_read_only_fs(&mut self) {
        self.on_read_only_fs = true;
    }
}

/// The descriptor that a node of `file_type` owned by `owner`, with access `mode`, stores for
/// legacy (POSIX user) callers and initial contents. Mode bits outside
/// [`Mode::SUPPORTED`] are ignored.
#[must_use]
pub fn posix_descriptor(file_type: FileType, mode: Mode, owner: UserInfo) -> SecurityDescriptor {
    mode_descriptor(
        file_type,
        mode,
        owner.user_principal(),
        owner.group_principal(),
    )
}

/// The descriptor that a node of `file_type` owned by `owner` and `group`, with access `mode`,
/// stores. Mode bits outside [`Mode::SUPPORTED`] are ignored.
///
/// # Panics
///
/// Never: every mode within [`Mode::SUPPORTED`] forms a descriptor.
#[must_use]
pub fn mode_descriptor(
    file_type: FileType,
    mode: Mode,
    owner: Principal,
    group: Principal,
) -> SecurityDescriptor {
    let kind = if file_type == FileType::Directory {
        DescriptorKind::Directory
    } else {
        DescriptorKind::File
    };
    SecurityDescriptor::from_mode(kind, owner, group, mode & Mode::SUPPORTED)
        .expect("supported mode bits form a valid descriptor")
}

/// The descriptor that `status` reports, for an object whose backend does not store one: its
/// mode, owner and group, which are kept exactly.
#[must_use]
pub fn status_descriptor(status: &FileStatus) -> SecurityDescriptor {
    mode_descriptor(status.file_type, status.mode, status.owner, status.group)
}

/// The POSIX mode reported in [`FileStatus`] for `descriptor`; empty for an ACL descriptor.
// TODO: report a mode approximating an ACL descriptor's grants.
#[must_use]
pub fn status_mode(descriptor: &SecurityDescriptor) -> Mode {
    descriptor.mode().unwrap_or(Mode::empty())
}

/// The POSIX id that `principal` names in `domain`, if any.
pub(crate) fn posix_id(principal: Principal, domain: DomainId) -> Option<u16> {
    if principal.domain != domain {
        return None;
    }
    u16::try_from(principal.id).ok()
}

/// `descriptor` with its owner and group replaced, keeping its access; `None` if that is not a
/// valid descriptor.
#[must_use]
pub fn with_owners(
    descriptor: &SecurityDescriptor,
    owner: Principal,
    group: Principal,
) -> Option<SecurityDescriptor> {
    match (descriptor.mode(), descriptor.acl()) {
        (Some(mode), _) => {
            SecurityDescriptor::from_mode(descriptor.kind(), owner, group, mode).ok()
        }
        (None, Some(entries)) => SecurityDescriptor::from_acl(
            descriptor.kind(),
            owner,
            group,
            descriptor.directory_flags(),
            descriptor.elevation_grants(),
            entries.to_vec(),
        )
        .ok(),
        (None, None) => None,
    }
}
