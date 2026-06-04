// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! [`Backend`] for filesystems supported by [`super::resolver`]

use alloc::vec::Vec;

use super::errors::{
    ChmodError, ChownError, FileStatusError, MkdirError, OpenError, ReadDirError, ReadError,
    RmdirError, TruncateError, UnlinkError, WalkError, WriteError,
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
pub trait Backend: private::Sealed + Send + Sync + 'static {
    /// Supporting walk through the backend
    type WalkingDirHandle<'a>: 'a;

    /// An owned handle to an open file
    type FileHandle: Clone + Send + Sync + 'static;

    /// An owned handle to an open directory
    type DirHandle: Clone + Send + Sync + 'static;

    /// Obtain access to the root directory of the backend.
    fn root(&self) -> Self::WalkingDirHandle<'_>;

    /// Walk one or more `components` starting from the `from` handle.
    ///
    /// `components` must be non-empty. Backends may panic if called with an empty slice.
    ///
    /// This function explicitly does not walk into files. If the next component exists but is not a
    /// directory, the backend should stop at its parent and return
    /// `WalkStopReason::StoppedAtNonDirectory`.
    fn walk_directories<'a>(
        &'a self,
        from: Self::WalkingDirHandle<'a>,
        components: &[&str],
    ) -> Result<WalkOutcome<Self::WalkingDirHandle<'a>>, WalkError>;

    /// Take an owned handle to a `dir` found via a walk.
    fn owned_dir_at(&self, dir: Self::WalkingDirHandle<'_>) -> Self::DirHandle;

    /// Obtain a walking handle to an existing owned dir.
    ///
    /// This operation always succeeds and returns a `Some` _unless_ on a networked backend where
    /// owned handles can go stale.
    ///
    /// XXX(jayb): We will likely migrate away from `Option` here when we do a bit of an overhaul of
    /// the `errors` module in order to more consistently support stale errors everywhere.
    fn walking_dir_at<'a>(&'a self, dir: &Self::DirHandle) -> Option<Self::WalkingDirHandle<'a>>;

    /// Open an (existing) file at `dir`.
    ///
    /// To create a file, you need [`Self::create_file_at`].
    fn open_file_at(
        &self,
        dir: Self::WalkingDirHandle<'_>,
        name: &str,
        flags: OFlags,
    ) -> Result<Permissioned<Self::FileHandle>, OpenError>;

    /// Read directory entries at `dir`.
    fn list_dir_at(&self, handle: Self::DirHandle) -> Result<Vec<DirEntry>, ReadDirError>;

    /// Read at `offset` into `buf`, returning the number of bytes read.
    ///
    /// Backends do not have an internal notion of offsets; instead the resolver maintains offsets
    /// as needed. For files with non-position-based [`SeekBehavior`], such as `stdin`, the resolver
    /// passes zero and the backend should ignore the offset.
    fn read(&self, h: &Self::FileHandle, buf: &mut [u8], offset: usize)
    -> Result<usize, ReadError>;

    /// Optional performance hook: get static backing data for a file, if available and supported.
    ///
    /// This method returns the (entire) underlying static byte slice if the file's contents are
    /// backed by borrowed static data.
    ///
    /// Returns `None` if indicating no static backing data is available/supported.
    #[expect(unused_variables, reason = "default body, non-underscored param names")]
    fn get_static_backing_data(&self, h: &Self::FileHandle) -> Option<&'static [u8]> {
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
    fn write(&self, h: &Self::FileHandle, buf: &[u8], offset: usize) -> Result<usize, WriteError>;

    /// Truncate the file to the specified length.
    ///
    /// If shorter than existing size, extra data is lost. If longer than existing size, resize by
    /// adding `\0`s.
    fn truncate(&self, h: &Self::FileHandle, length: usize) -> Result<(), TruncateError>;

    /// Describe seek behavior for an open file handle.
    fn seek_behavior(&self, h: &Self::FileHandle) -> SeekBehavior;

    /// Status of an open file handle.
    fn file_status(&self, h: &Self::FileHandle) -> Result<FileStatus, FileStatusError>;

    /// Status of an open directory handle.
    fn dir_status(&self, h: &Self::DirHandle) -> Result<FileStatus, FileStatusError>;

    /// Create a new file at `parent` with the given `name` and `mode`.
    fn create_file_at(
        &self,
        dir: Self::DirHandle,
        name: &str,
        mode: Mode,
    ) -> Result<Self::FileHandle, OpenError>;

    /// Create a new directory at `parent` with the given `name` and `mode`.
    fn mkdir_at(
        &self,
        dir: Self::DirHandle,
        name: &str,
        mode: Mode,
    ) -> Result<Self::DirHandle, MkdirError>;

    /// Remove the file `name` at `parent`.
    fn unlink_at(&self, dir: Self::DirHandle, name: &str) -> Result<(), UnlinkError>;

    /// Remove the directory `name` at `parent`.
    // XXX(jayb): I don't like that unlink and rmdir exist separately, we should probably merge them.
    fn rmdir_at(&self, dir: Self::DirHandle, name: &str) -> Result<(), RmdirError>;

    /// Update the permissions for the file/dir `name` at `parent`.
    fn chmod_at(&self, dir: Self::DirHandle, name: &str, mode: Mode) -> Result<(), ChmodError>;

    /// Update the owner/group for the file/dir `name` at `parent`.
    fn chown_at(
        &self,
        dir: Self::DirHandle,
        name: &str,
        user: Option<u16>,
        group: Option<u16>,
    ) -> Result<(), ChownError>;
}

/// A successful walk of directories through the backend
pub struct WalkOutcome<Walking> {
    /// A component per walked element.
    ///
    /// This vector can be empty when the first input component is a non-directory element.
    ///
    /// Components are in natural order (i.e., the last element is the last component visited thus
    /// far).
    pub(super) components: Vec<WalkedComponent>,
    /// The last handle of the walk thus far.
    ///
    pub(super) last: Walking,
    /// Why this walk stopped at `last`.
    pub(super) stop_reason: WalkStopReason,
}

/// Why a backend directory walk stopped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use]
pub(super) enum WalkStopReason {
    /// All requested components were walked, and `last` is the requested directory.
    CompleteDirectory,
    /// The next requested component exists but is not a directory; `last` is its parent directory.
    StoppedAtNonDirectory,
    /// The backend stopped early; the resolver should continue walking from `last`.
    #[expect(dead_code, reason = "no backend currently returns partial walks")]
    Continue,
}

/// A backend item plus permission metadata for resolver-side checks.
pub struct Permissioned<H> {
    pub(super) item: H,
    pub(super) permissions: PermissionCheck,
}

/// Whether a resolved component should be permission-checked by the resolver.
#[derive(Clone, Debug)]
#[must_use]
pub(super) enum PermissionCheck {
    /// The backend is self-enforcing permissions for this item.
    ByBackend,
    /// The resolver should check this permission metadata.
    #[expect(
        dead_code,
        reason = "only backend-self-enforced devices exist during migration"
    )]
    ByResolver(PermissionInfo),
}

/// Per-component status returned by a backend walk
#[derive(Clone, Debug)]
#[must_use]
pub(super) struct WalkedComponent {
    /// How permissions for this component should be checked.
    pub(super) permissions: PermissionCheck,
}

/// Permission information for a particular component of the walk.
#[derive(Clone, Debug)]
pub(super) struct PermissionInfo {
    pub(super) mode: Mode,
    pub(super) owner: UserInfo,
}
