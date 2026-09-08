// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! [`Backend`] for filesystems supported by [`super::resolver`]

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::any::{Any, TypeId};

use core::marker::PhantomData;

use crate::utilities::anymap::AnyCloneSendSync;

use super::errors::{
    ChmodError, ChownError, FileStatusError, MkdirError, OpenError, ReadDirError, ReadError,
    ResolutionError, RmdirError, TruncateError, UnlinkError, WalkError, WriteError,
};
use super::{DirEntry, FileStatus, Mode, OFlags, UserInfo};

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

/// A private module (private to the filesystem subsystem), to help support writing sealed traits.
/// This module should _itself_ not be made public.
pub(super) mod private {
    /// A trait to help seal the main `Backend` trait.
    ///
    /// This trait is explicitly public, but unnameable, thereby preventing code outside this crate
    /// from implementing this trait.
    ///
    /// XXX(jayb): We may (in the future) de-restrict backends to allow other crates to also
    /// introduce backends, but while we migrate the file-system subsystem over from the old
    /// approach to the new one, we will not allow other crates to introduce backends.
    pub trait Sealed {}
}

/// A backend that can be used to support a (full or subset of) a LiteBox filesystem.
pub trait Backend: private::Sealed + Send + Sync + Any {
    /// Resolve the root directory.
    fn root(&self) -> Result<ResolvedDir<'_>, WalkError>;

    /// Resolve `components` without opening the target.
    ///
    /// Before looking up a child, resolver-enforced backends invoke `authorize_dir_lookup` on its
    /// parent directory. Callback failure stops resolution immediately. Self-enforcing backends
    /// omit the callback.
    ///
    /// The final component of the `components` (independent of whether it is directory or not) does
    /// not invoke `authorize_dir_lookup` upon it, only its parent is invoked as such (since the
    /// parent must be looked into to resolve it).
    fn resolve<'a>(
        &'a self,
        from: ResolvedDir<'a>,
        components: &[&str],
        authorize_dir_lookup: &dyn Fn(&PermissionInfo) -> Result<(), WalkError>,
    ) -> Result<Resolution<'a>, ResolutionError>;

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
    // XXX(jayb): Maybe it is best to prevent creation / truncation here, and handle purely at resolver?
    fn open_file(&self, file: ResolvedFile<'_>, flags: OFlags) -> Result<FileHandle, OpenError>;

    /// Read directory entries at `dir`.
    fn list_dir_at(&self, handle: DirHandle) -> Result<Vec<DirEntry>, ReadDirError>;

    /// Read at `offset` into `buf`, returning the number of bytes read.
    ///
    /// Backends do not have an internal notion of offsets; instead the resolver maintains offsets
    /// as needed. For files with non-position-based [`SeekBehavior`], such as `stdin`, the resolver
    /// passes zero and the backend should ignore the offset.
    fn read(&self, h: &FileHandle, buf: &mut [u8], offset: usize) -> Result<usize, ReadError>;

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

    /// Write `buf` into the file, based on `offset`, returning the number of bytes written.
    ///
    /// See [`Self::read`] on internal offset storage for backends.
    // XXX(jayb): I need to think more about how we set up some sort of "intend to write" flag that
    // we can use to obtain the ability to support writes to an `O_APPEND` file, but without making
    // it ugly on the interface side here. It would be very ugly for us to pass in extra flags, or
    // indeed even need to maintain/handle seeking on every backend; mostly we need some sort of
    // nicer locking discipline, but I don't want to block the MVP for this just yet.
    fn write(&self, h: &FileHandle, buf: &[u8], offset: usize) -> Result<usize, WriteError>;

    /// Truncate the file to the specified length.
    ///
    /// If shorter than existing size, extra data is lost. If longer than existing size, resize by
    /// adding `\0`s.
    fn truncate(&self, h: &FileHandle, length: usize) -> Result<(), TruncateError>;

    /// Describe seek behavior for an open file handle.
    fn seek_behavior(&self, h: &FileHandle) -> SeekBehavior;

    /// Status of an open file or directory handle.
    fn status(&self, h: HandleRef<'_>) -> Result<FileStatus, FileStatusError>;

    /// Create a new file within `parent`.
    fn create_file_at(
        &self,
        parent: ResolvedDir<'_>,
        name: &str,
        metadata: CreationMetadata,
    ) -> Result<FileHandle, OpenError>;

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
pub(crate) trait BackendHandles {
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
    pub(super) permissions: PermissionCheck,
    backend_type: TypeId,
    raw: Box<dyn ErasedResolvedHandle + 'a>,
    _invariant: PhantomData<fn(&'a ()) -> &'a ()>,
}

/// A resolved, unopened non-directory target, including permission metadata for resolver authorization.
pub struct ResolvedFile<'a> {
    pub(super) permissions: PermissionCheck,
    backend_type: TypeId,
    raw: Box<dyn ErasedResolvedHandle + 'a>,
    _invariant: PhantomData<fn(&'a ()) -> &'a ()>,
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
    fn into_raw(self: Box<Self>) -> *mut ();
}

impl<H> ErasedResolvedHandle for H {
    fn into_raw(self: Box<Self>) -> *mut () {
        Box::into_raw(self).cast()
    }
}

impl<'a> ResolvedDir<'a> {
    pub(super) fn from_typed<B: BackendHandles + 'static>(
        handle: B::ResolvedDir<'a>,
        permissions: PermissionCheck,
    ) -> Self {
        Self {
            permissions,
            backend_type: TypeId::of::<B>(),
            raw: Box::new(handle),
            _invariant: PhantomData,
        }
    }

    /// Recover scoped directory state passed back to the same backend.
    pub(super) fn into_typed<B: BackendHandles + 'static>(self) -> B::ResolvedDir<'a> {
        assert_eq!(
            self.backend_type,
            TypeId::of::<B>(),
            "backend resolved directory type mismatch"
        );
        // SAFETY: `from_typed::<B>` records the backend type and stores a `B::ResolvedDir<'a>`.
        // The type check and lifetime invariance ensure the original allocation type is recovered.
        unsafe { *Box::from_raw(self.raw.into_raw().cast::<B::ResolvedDir<'a>>()) }
    }
}

impl<'a> ResolvedFile<'a> {
    pub(super) fn from_typed<B: BackendHandles + 'static>(
        handle: B::ResolvedFile<'a>,
        permissions: PermissionCheck,
    ) -> Self {
        Self {
            permissions,
            backend_type: TypeId::of::<B>(),
            raw: Box::new(handle),
            _invariant: PhantomData,
        }
    }

    /// Recover scoped file state passed back to the same backend.
    pub(super) fn into_typed<B: BackendHandles + 'static>(self) -> B::ResolvedFile<'a> {
        assert_eq!(
            self.backend_type,
            TypeId::of::<B>(),
            "backend resolved file type mismatch"
        );
        // SAFETY: `from_typed::<B>` records the backend type and stores a `B::ResolvedFile<'a>`.
        // The type check and lifetime invariance ensure the original allocation type is recovered.
        unsafe { *Box::from_raw(self.raw.into_raw().cast::<B::ResolvedFile<'a>>()) }
    }
}

impl FileHandle {
    pub(super) fn from_typed<B: BackendHandles>(handle: B::FileHandle) -> Self {
        Self {
            raw: Box::new(handle),
        }
    }

    /// Borrow the concrete handle stored in this erased handle.
    ///
    /// Intended to be called by backend implementations as `handle.get_typed::<Self>()` on handles
    /// that the resolver passed back to the same backend; it may panic otherwise.
    pub(super) fn get_typed<B: BackendHandles>(&self) -> &B::FileHandle {
        (&*self.raw as &dyn Any)
            .downcast_ref::<B::FileHandle>()
            .expect("backend file handle type mismatch")
    }
}

impl DirHandle {
    pub(super) fn from_typed<B: BackendHandles>(handle: B::DirHandle) -> Self {
        Self {
            raw: Box::new(handle),
        }
    }

    /// Borrow the concrete handle stored in this erased handle.
    ///
    /// Intended to be called by backend implementations as `handle.get_typed::<Self>()` on handles
    /// that the resolver passed back to the same backend; it may panic otherwise.
    pub(super) fn get_typed<B: BackendHandles>(&self) -> &B::DirHandle {
        (&*self.raw as &dyn Any)
            .downcast_ref::<B::DirHandle>()
            .expect("backend directory handle type mismatch")
    }

    /// Recover the concrete handle stored in this erased handle.
    ///
    /// Intended to be called by backend implementations as `handle.into_typed::<Self>()` on
    /// handles that the resolver passed back to the same backend; it may panic otherwise.
    pub(super) fn into_typed<B: BackendHandles>(self) -> B::DirHandle {
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
    /// Only the final component is missing. If any element beyond the parent were missing, that
    /// results in a [`ResolutionError`].
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
pub(super) enum PermissionCheck {
    /// The backend is self-enforcing permissions for this item.
    ByBackend,
    /// The resolver should check this permission metadata.
    ByResolver(PermissionInfo),
}

/// Permission information for a particular component of the walk.
#[derive(Clone, Debug)]
pub(super) struct PermissionInfo {
    pub(super) mode: Mode,
    pub(super) owner: UserInfo,
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
