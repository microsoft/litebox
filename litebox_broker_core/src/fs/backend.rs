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

use super::errors::{
    ChmodError, ChownError, FileStatusError, MkdirError, OpenError, ReadDirError, ReadError,
    RenameError, ResolutionError, RmdirError, SymlinkError, TruncateError, UnlinkError, WalkError,
    WriteError,
};
use super::{DirEntry, FileStatus, FileType, Mode, OFlags, UserInfo};
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

    /// Update a resolved target's permissions.
    fn chmod(&self, h: ResolvedTarget<'_>, mode: Mode) -> Result<(), ChmodError>;

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
    /// Whether the filesystem rejects writes, so file opens report EROFS before mode-based denial.
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
