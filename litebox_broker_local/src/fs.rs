// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use alloc::string::String;
use alloc::vec::Vec;

use litebox_broker_protocol::ObjectHandle;
use litebox_broker_protocol::error::ErrorCode;
use litebox_broker_protocol::fs::{
    ChangeDirectoryRequest, ChmodFileRequest, ChownFileRequest, DirectoryPayloadError,
    DirectoryTransferError, FileAccessMode, FileDirectoryEntry, FileError, FileMode, FileOpenFlags,
    FilePathResponse, FileSeekWhence, FileStatus, FileUser, GetWorkingDirectoryRequest,
    HandleFilePathRequest, HandleFileStatusRequest, IsTerminalFileRequest, MAX_FILE_TRANSFER_SIZE,
    MkdirFileRequest, OpenFileRequest, PathContext, PathFileStatusRequest, PathStart,
    ReadDirectoryRequest, ReadFileRequest, ReadLinkFileRequest, RenameFileRequest,
    ResolvePathFileRequest, RmdirFileRequest, SeekFileRequest, SymlinkFileRequest,
    TerminalControlFileRequest, TruncateFileRequest, UnlinkFileRequest, WriteFileRequest,
    try_decode_directory_entries,
};
use litebox_broker_protocol::message::{BrokerOperation, BrokerResult, FileRequest, FileResponse};
use litebox_broker_protocol::mount::{
    ChangeRootRequest, MountInfo, MountInfoRequest, MountRequest, MountSource, NodeMount,
    PivotRootRequest, SetReadOnlyRequest, UnmountRequest,
};
use litebox_broker_protocol::shared_buffer::{SHARED_BUFFER_SLOT_SIZE, SharedBufferSequence};
use litebox_broker_protocol::terminal::{TerminalOperation, TerminalResponse};
use litebox_broker_transport::channel::LocalCallChannel;
use litebox_platform::buffer::{ReadBuffer, WriteBuffer};

use crate::{BrokerLocal, BrokerLocalError, Result};

type FileOperationResult<T> = core::result::Result<T, FileError>;
type DirectoryReadResult = FileOperationResult<(Vec<FileDirectoryEntry>, Option<u64>)>;

impl<Channel: LocalCallChannel> BrokerLocal<Channel> {
    /// Opens `path` from `start`.
    ///
    /// # Panics
    ///
    /// Panics if the buffer sequence is inconsistent or the broker returns
    /// a response for another file operation.
    #[expect(clippy::too_many_arguments, reason = "mirrors the open request")]
    pub fn open_file(
        &self,
        path_buffer: SharedBufferSequence,
        start: PathStart,
        path: &str,
        user: FileUser,
        access: FileAccessMode,
        flags: FileOpenFlags,
        mode: FileMode,
    ) -> Result<FileOperationResult<ObjectHandle>, Channel::Error> {
        self.write_file_buffer(path_buffer, path.as_bytes(), SHARED_BUFFER_SLOT_SIZE)?;
        match self.request_file(FileRequest::Open(OpenFileRequest {
            path: path_buffer,
            start,
            user,
            access,
            flags,
            mode,
        }))? {
            FileResponse::Open(response) => Ok(Ok(response.handle)),
            FileResponse::Failed(error) => Ok(Err(error)),
            response => panic!("broker returned unexpected file open response: {response:?}"),
        }
    }

    /// Reads from an open file.
    ///
    /// # Panics
    ///
    /// Panics if the buffer sequence is inconsistent or the broker returns
    /// an invalid response.
    pub fn read_file(
        &self,
        handle: ObjectHandle,
        buffer: SharedBufferSequence,
        destination: &mut dyn ReadBuffer,
        offset: Option<u64>,
    ) -> Result<FileOperationResult<usize>, Channel::Error> {
        self.validate_file_buffer(buffer, destination.len(), MAX_FILE_TRANSFER_SIZE)?;
        match self.request_file(FileRequest::Read(ReadFileRequest {
            handle,
            buffer,
            offset,
        }))? {
            FileResponse::Read(response) => {
                assert!(
                    response.read <= buffer.length(),
                    "broker returned oversized file read"
                );
                let read = response.read as usize;
                self.copy_from_shared_buffer(buffer, read, destination)?;
                Ok(Ok(read))
            }
            FileResponse::Failed(error) => Ok(Err(error)),
            response => panic!("broker returned unexpected file read response: {response:?}"),
        }
    }

    /// Writes to an open file.
    ///
    /// # Panics
    ///
    /// Panics if the buffer sequence is inconsistent or the broker returns
    /// an invalid response.
    pub fn write_file(
        &self,
        handle: ObjectHandle,
        buffer: SharedBufferSequence,
        data: &dyn WriteBuffer,
        offset: Option<u64>,
    ) -> Result<FileOperationResult<usize>, Channel::Error> {
        self.validate_file_buffer(buffer, data.len(), MAX_FILE_TRANSFER_SIZE)?;
        self.copy_to_shared_buffer(buffer, 0, data)?;
        match self.request_file(FileRequest::Write(WriteFileRequest {
            handle,
            buffer,
            offset,
        }))? {
            FileResponse::Write(response) => {
                assert!(
                    response.written <= buffer.length(),
                    "broker returned oversized file write"
                );
                Ok(Ok(response.written as usize))
            }
            FileResponse::Failed(error) => Ok(Err(error)),
            response => panic!("broker returned unexpected file write response: {response:?}"),
        }
    }

    /// Repositions an open file.
    ///
    /// # Panics
    ///
    /// Panics if the broker returns a response for another file operation.
    pub fn seek_file(
        &self,
        handle: ObjectHandle,
        offset: i64,
        whence: FileSeekWhence,
    ) -> Result<FileOperationResult<u64>, Channel::Error> {
        match self.request_file(FileRequest::Seek(SeekFileRequest {
            handle,
            offset,
            whence,
        }))? {
            FileResponse::Seek(response) => Ok(Ok(response.offset)),
            FileResponse::Failed(error) => Ok(Err(error)),
            response => panic!("broker returned unexpected file seek response: {response:?}"),
        }
    }

    /// Truncates an open file.
    ///
    /// # Panics
    ///
    /// Panics if the broker returns a response for another file operation.
    pub fn truncate_file(
        &self,
        handle: ObjectHandle,
        length: u64,
        reset_offset: bool,
    ) -> Result<FileOperationResult<()>, Channel::Error> {
        match self.request_file(FileRequest::Truncate(TruncateFileRequest {
            handle,
            length,
            reset_offset,
        }))? {
            FileResponse::Truncate => Ok(Ok(())),
            FileResponse::Failed(error) => Ok(Err(error)),
            response => panic!("broker returned unexpected file truncate response: {response:?}"),
        }
    }

    /// Reads one encoded page of directory entries.
    ///
    /// # Panics
    ///
    /// Panics if the buffer sequence is inconsistent or the broker returns
    /// an invalid response or directory payload.
    pub fn read_directory(
        &self,
        handle: ObjectHandle,
        buffer: SharedBufferSequence,
        start_index: u64,
    ) -> Result<DirectoryReadResult, Channel::Error> {
        self.validate_file_buffer(buffer, buffer.length() as usize, SHARED_BUFFER_SLOT_SIZE)?;
        match self.request_file(FileRequest::ReadDirectory(ReadDirectoryRequest {
            handle,
            buffer,
            start_index,
        }))? {
            FileResponse::ReadDirectory(response) => {
                assert!(
                    response.length <= buffer.length(),
                    "broker returned oversized file directory payload"
                );
                let mut payload = Vec::new();
                payload
                    .try_reserve_exact(response.length as usize)
                    .map_err(|_| BrokerLocalError::Broker(ErrorCode::OutOfMemory))?;
                payload.resize(response.length as usize, 0);
                self.read_shared_buffer(buffer, &mut payload);
                let entries = match try_decode_directory_entries(&payload) {
                    Ok(entries) => entries,
                    Err(DirectoryTransferError::OutOfMemory) => {
                        return Err(BrokerLocalError::Broker(ErrorCode::OutOfMemory));
                    }
                    Err(DirectoryTransferError::Payload(
                        DirectoryPayloadError::Malformed | DirectoryPayloadError::TooLarge,
                    )) => panic!("broker returned malformed file directory payload"),
                    Err(error) => {
                        panic!("broker returned unsupported file directory payload error: {error}")
                    }
                };
                if let Some(next_index) = response.next_index {
                    let expected_next_index = start_index
                        .checked_add(u64::try_from(entries.len()).unwrap())
                        .expect("file directory index overflow");
                    assert!(
                        !entries.is_empty() && next_index == expected_next_index,
                        "broker returned inconsistent file directory continuation"
                    );
                }
                Ok(Ok((entries, response.next_index)))
            }
            FileResponse::Failed(error) => Ok(Err(error)),
            response => {
                panic!("broker returned unexpected file directory response: {response:?}")
            }
        }
    }

    /// Returns status for `path` from `start`; with `allow_empty_path`, an
    /// empty path names where it starts.
    ///
    /// # Panics
    ///
    /// Panics if the buffer sequence is inconsistent or the broker returns
    /// a response for another file operation.
    pub fn path_file_status(
        &self,
        path_buffer: SharedBufferSequence,
        start: PathStart,
        path: &str,
        user: FileUser,
        follow_symlinks: bool,
        allow_empty_path: bool,
    ) -> Result<FileOperationResult<FileStatus>, Channel::Error> {
        self.write_file_buffer(path_buffer, path.as_bytes(), SHARED_BUFFER_SLOT_SIZE)?;
        match self.request_file(FileRequest::PathStatus(PathFileStatusRequest {
            path: path_buffer,
            start,
            user,
            follow_symlinks,
            allow_empty_path,
        }))? {
            FileResponse::PathStatus(status) => Ok(Ok(status)),
            FileResponse::Failed(error) => Ok(Err(error)),
            response => {
                panic!("broker returned unexpected file path-status response: {response:?}")
            }
        }
    }

    /// Returns status for an open file.
    ///
    /// # Panics
    ///
    /// Panics if the broker returns a response for another file operation.
    pub fn handle_file_status(
        &self,
        handle: ObjectHandle,
    ) -> Result<FileOperationResult<FileStatus>, Channel::Error> {
        match self.request_file(FileRequest::HandleStatus(HandleFileStatusRequest {
            handle,
        }))? {
            FileResponse::HandleStatus(status) => Ok(Ok(status)),
            FileResponse::Failed(error) => Ok(Err(error)),
            response => {
                panic!("broker returned unexpected file handle-status response: {response:?}")
            }
        }
    }

    /// Determines whether an open file is connected to a terminal.
    ///
    /// # Panics
    ///
    /// Panics if the broker returns a response for another file operation.
    pub fn is_terminal_file(
        &self,
        handle: ObjectHandle,
    ) -> Result<FileOperationResult<bool>, Channel::Error> {
        match self.request_file(FileRequest::IsTerminal(IsTerminalFileRequest { handle }))? {
            FileResponse::IsTerminal(is_terminal) => Ok(Ok(is_terminal)),
            FileResponse::Failed(error) => Ok(Err(error)),
            response => {
                panic!("broker returned unexpected file terminal-query response: {response:?}")
            }
        }
    }

    /// Controls the shared terminal backing an open file.
    ///
    /// # Panics
    ///
    /// Panics if the broker returns a response for another file operation.
    pub fn terminal_control(
        &self,
        handle: ObjectHandle,
        operation: TerminalOperation,
    ) -> Result<FileOperationResult<TerminalResponse>, Channel::Error> {
        match self.request_file(FileRequest::TerminalControl(TerminalControlFileRequest {
            handle,
            operation,
        }))? {
            FileResponse::TerminalControl(response) => Ok(Ok(response)),
            FileResponse::Failed(error) => Ok(Err(error)),
            response => {
                panic!("broker returned unexpected file terminal-control response: {response:?}")
            }
        }
    }

    /// Changes mode bits for `path` from `start`.
    ///
    /// # Panics
    ///
    /// Panics if the buffer sequence is inconsistent or the broker returns
    /// a response for another file operation.
    pub fn chmod_file(
        &self,
        path_buffer: SharedBufferSequence,
        start: PathStart,
        path: &str,
        user: FileUser,
        mode: FileMode,
    ) -> Result<FileOperationResult<()>, Channel::Error> {
        self.write_file_buffer(path_buffer, path.as_bytes(), SHARED_BUFFER_SLOT_SIZE)?;
        match self.request_file(FileRequest::Chmod(ChmodFileRequest {
            path: path_buffer,
            start,
            user,
            mode,
        }))? {
            FileResponse::Chmod => Ok(Ok(())),
            FileResponse::Failed(error) => Ok(Err(error)),
            response => panic!("broker returned unexpected file chmod response: {response:?}"),
        }
    }

    /// Changes ownership for `path` from `start`.
    ///
    /// # Panics
    ///
    /// Panics if the buffer sequence is inconsistent or the broker returns
    /// a response for another file operation.
    pub fn chown_file(
        &self,
        path_buffer: SharedBufferSequence,
        start: PathStart,
        path: &str,
        acting_user: FileUser,
        user: Option<u16>,
        group: Option<u16>,
    ) -> Result<FileOperationResult<()>, Channel::Error> {
        self.write_file_buffer(path_buffer, path.as_bytes(), SHARED_BUFFER_SLOT_SIZE)?;
        match self.request_file(FileRequest::Chown(ChownFileRequest {
            path: path_buffer,
            start,
            acting_user,
            user,
            group,
        }))? {
            FileResponse::Chown => Ok(Ok(())),
            FileResponse::Failed(error) => Ok(Err(error)),
            response => panic!("broker returned unexpected file chown response: {response:?}"),
        }
    }

    /// Removes a file at `path` from `start`.
    ///
    /// # Panics
    ///
    /// Panics if the buffer sequence is inconsistent or the broker returns
    /// a response for another file operation.
    pub fn unlink_file(
        &self,
        path_buffer: SharedBufferSequence,
        start: PathStart,
        path: &str,
        user: FileUser,
    ) -> Result<FileOperationResult<()>, Channel::Error> {
        self.write_file_buffer(path_buffer, path.as_bytes(), SHARED_BUFFER_SLOT_SIZE)?;
        match self.request_file(FileRequest::Unlink(UnlinkFileRequest {
            path: path_buffer,
            start,
            user,
        }))? {
            FileResponse::Unlink => Ok(Ok(())),
            FileResponse::Failed(error) => Ok(Err(error)),
            response => panic!("broker returned unexpected file unlink response: {response:?}"),
        }
    }

    /// Renames a file or directory from `old_path` from `old_start` to
    /// `new_path` from `new_start`.
    ///
    /// # Panics
    ///
    /// Panics if the buffer sequence is inconsistent or the broker returns
    /// a response for another file operation.
    pub fn rename_file(
        &self,
        paths_buffer: SharedBufferSequence,
        old_start: PathStart,
        old_path: &str,
        new_start: PathStart,
        new_path: &str,
        user: FileUser,
    ) -> Result<FileOperationResult<()>, Channel::Error> {
        let length = old_path
            .len()
            .checked_add(new_path.len())
            .ok_or(BrokerLocalError::Broker(ErrorCode::ResourceExhausted))?;
        self.validate_file_buffer(paths_buffer, length, SHARED_BUFFER_SLOT_SIZE)?;
        let old_path_length = u32::try_from(old_path.len())
            .map_err(|_| BrokerLocalError::Broker(ErrorCode::ResourceExhausted))?;
        self.write_shared_buffer_at(paths_buffer, 0, old_path.as_bytes());
        self.write_shared_buffer_at(paths_buffer, old_path.len(), new_path.as_bytes());
        match self.request_file(FileRequest::Rename(RenameFileRequest {
            paths: paths_buffer,
            old_path_length,
            old_start,
            new_start,
            user,
        }))? {
            FileResponse::Rename => Ok(Ok(())),
            FileResponse::Failed(error) => Ok(Err(error)),
            response => panic!("broker returned unexpected file rename response: {response:?}"),
        }
    }

    /// Creates a directory at `path` from `start`.
    ///
    /// # Panics
    ///
    /// Panics if the buffer sequence is inconsistent or the broker returns
    /// a response for another file operation.
    pub fn mkdir_file(
        &self,
        path_buffer: SharedBufferSequence,
        start: PathStart,
        path: &str,
        user: FileUser,
        mode: FileMode,
    ) -> Result<FileOperationResult<()>, Channel::Error> {
        self.write_file_buffer(path_buffer, path.as_bytes(), SHARED_BUFFER_SLOT_SIZE)?;
        match self.request_file(FileRequest::Mkdir(MkdirFileRequest {
            path: path_buffer,
            start,
            user,
            mode,
        }))? {
            FileResponse::Mkdir => Ok(Ok(())),
            FileResponse::Failed(error) => Ok(Err(error)),
            response => panic!("broker returned unexpected file mkdir response: {response:?}"),
        }
    }

    /// Removes a directory at `path` from `start`.
    ///
    /// # Panics
    ///
    /// Panics if the buffer sequence is inconsistent or the broker returns
    /// a response for another file operation.
    pub fn rmdir_file(
        &self,
        path_buffer: SharedBufferSequence,
        start: PathStart,
        path: &str,
        user: FileUser,
    ) -> Result<FileOperationResult<()>, Channel::Error> {
        self.write_file_buffer(path_buffer, path.as_bytes(), SHARED_BUFFER_SLOT_SIZE)?;
        match self.request_file(FileRequest::Rmdir(RmdirFileRequest {
            path: path_buffer,
            start,
            user,
        }))? {
            FileResponse::Rmdir => Ok(Ok(())),
            FileResponse::Failed(error) => Ok(Err(error)),
            response => panic!("broker returned unexpected file rmdir response: {response:?}"),
        }
    }

    /// Creates a symbolic link at `linkpath` from `start`, storing `target` verbatim.
    ///
    /// `buffer` must exactly fit the linkpath followed by the target, within one slot.
    ///
    /// # Panics
    ///
    /// Panics if the buffer sequence is inconsistent or the broker returns
    /// a response for another file operation.
    pub fn symlink_file(
        &self,
        buffer: SharedBufferSequence,
        target: &str,
        start: PathStart,
        linkpath: &str,
        user: FileUser,
    ) -> Result<FileOperationResult<()>, Channel::Error> {
        let length = linkpath
            .len()
            .checked_add(target.len())
            .filter(|length| *length <= SHARED_BUFFER_SLOT_SIZE as usize)
            .ok_or(BrokerLocalError::Broker(ErrorCode::ResourceExhausted))?;
        self.validate_file_buffer(buffer, length, SHARED_BUFFER_SLOT_SIZE)?;
        let path_length =
            u32::try_from(linkpath.len()).expect("linkpath fits one shared-buffer slot");
        self.write_shared_buffer_at(buffer, 0, linkpath.as_bytes());
        self.write_shared_buffer_at(buffer, linkpath.len(), target.as_bytes());
        match self.request_file(FileRequest::Symlink(SymlinkFileRequest {
            buffer,
            path_length,
            start,
            user,
        }))? {
            FileResponse::Symlink => Ok(Ok(())),
            FileResponse::Failed(error) => Ok(Err(error)),
            response => panic!("broker returned unexpected file symlink response: {response:?}"),
        }
    }

    /// Reads the target of the symbolic link at `path` from `start`.
    ///
    /// `buffer` carries the path to the broker and the target back, so it must fit both.
    ///
    /// # Panics
    ///
    /// Panics if the buffer sequence is inconsistent or the broker returns
    /// a response for another file operation or an invalid target.
    pub fn read_link_file(
        &self,
        buffer: SharedBufferSequence,
        start: PathStart,
        path: &str,
        user: FileUser,
    ) -> Result<FileOperationResult<String>, Channel::Error> {
        let path_length = self.write_path_query_buffer(buffer, path)?;
        match self.request_file(FileRequest::ReadLink(ReadLinkFileRequest {
            buffer,
            path_length,
            start,
            user,
        }))? {
            FileResponse::ReadLink(response) => {
                Ok(Ok(self.read_path_response_buffer(buffer, response)?))
            }
            FileResponse::Failed(error) => Ok(Err(error)),
            response => panic!("broker returned unexpected file read-link response: {response:?}"),
        }
    }

    /// Resolves `path` from `start` to its physical location from the root, following symbolic
    /// links.
    ///
    /// `buffer` carries the path to the broker and the resolved path back, so it must fit both.
    ///
    /// # Panics
    ///
    /// Panics if the buffer sequence is inconsistent or the broker returns
    /// a response for another file operation or an invalid path.
    pub fn resolve_file_path(
        &self,
        buffer: SharedBufferSequence,
        start: PathStart,
        path: &str,
        user: FileUser,
    ) -> Result<FileOperationResult<String>, Channel::Error> {
        let path_length = self.write_path_query_buffer(buffer, path)?;
        match self.request_file(FileRequest::ResolvePath(ResolvePathFileRequest {
            buffer,
            path_length,
            start,
            user,
        }))? {
            FileResponse::ResolvePath(response) => {
                Ok(Ok(self.read_path_response_buffer(buffer, response)?))
            }
            FileResponse::Failed(error) => Ok(Err(error)),
            response => {
                panic!("broker returned unexpected file resolve-path response: {response:?}")
            }
        }
    }

    /// Changes the working directory of `start`'s context to the directory at `path` from
    /// `start`, or to `start`'s base itself if `path` is empty.
    ///
    /// # Panics
    ///
    /// Panics if the buffer sequence is inconsistent or the broker returns
    /// a response for another file operation.
    pub fn change_directory(
        &self,
        path_buffer: SharedBufferSequence,
        start: PathStart,
        path: &str,
        user: FileUser,
    ) -> Result<FileOperationResult<()>, Channel::Error> {
        self.write_file_buffer(path_buffer, path.as_bytes(), SHARED_BUFFER_SLOT_SIZE)?;
        match self.request_file(FileRequest::ChangeDirectory(ChangeDirectoryRequest {
            path: path_buffer,
            start,
            user,
        }))? {
            FileResponse::ChangeDirectory => Ok(Ok(())),
            FileResponse::Failed(error) => Ok(Err(error)),
            response => {
                panic!("broker returned unexpected change-directory response: {response:?}")
            }
        }
    }

    /// Reads the working directory of the context `context`: its path, and whether that is from
    /// the context's root (or else from the root of its mount tree).
    ///
    /// # Panics
    ///
    /// Panics if the buffer sequence is inconsistent or the broker returns
    /// a response for another file operation or an invalid path.
    pub fn working_directory(
        &self,
        buffer: SharedBufferSequence,
        context: PathContext,
    ) -> Result<FileOperationResult<(String, bool)>, Channel::Error> {
        if buffer.length() > SHARED_BUFFER_SLOT_SIZE {
            return Err(BrokerLocalError::Broker(ErrorCode::ResourceExhausted));
        }
        match self.request_file(FileRequest::GetWorkingDirectory(
            GetWorkingDirectoryRequest { context, buffer },
        ))? {
            FileResponse::GetWorkingDirectory(response) => {
                let path = self.read_path_response_buffer(
                    buffer,
                    FilePathResponse {
                        length: response.length,
                    },
                )?;
                Ok(Ok((path, response.reachable)))
            }
            FileResponse::Failed(error) => Ok(Err(error)),
            response => {
                panic!("broker returned unexpected working-directory response: {response:?}")
            }
        }
    }

    /// Mounts `source` on the node at `path` from `start`, as `user`.
    ///
    /// `buffer` must exactly fit `path` followed by `source`'s encoding, within one slot.
    ///
    /// # Panics
    ///
    /// Panics if the buffer sequence is inconsistent or the broker returns
    /// a response for another file operation.
    pub fn mount(
        &self,
        buffer: SharedBufferSequence,
        start: PathStart,
        path: &str,
        user: FileUser,
        source: &MountSource,
    ) -> Result<FileOperationResult<()>, Channel::Error> {
        let source = source
            .encode()
            .ok_or(BrokerLocalError::Broker(ErrorCode::ResourceExhausted))?;
        let length = path
            .len()
            .checked_add(source.len())
            .filter(|length| *length <= SHARED_BUFFER_SLOT_SIZE as usize)
            .ok_or(BrokerLocalError::Broker(ErrorCode::ResourceExhausted))?;
        self.validate_file_buffer(buffer, length, SHARED_BUFFER_SLOT_SIZE)?;
        let path_length = u32::try_from(path.len()).expect("path fits one shared-buffer slot");
        self.write_shared_buffer_at(buffer, 0, path.as_bytes());
        self.write_shared_buffer_at(buffer, path.len(), &source);
        match self.request_file(FileRequest::Mount(MountRequest {
            buffer,
            path_length,
            start,
            user,
        }))? {
            FileResponse::Mount => Ok(Ok(())),
            FileResponse::Failed(error) => Ok(Err(error)),
            response => panic!("broker returned unexpected mount response: {response:?}"),
        }
    }

    /// Makes writes through the mount whose root is at `path` from `start` fail, or succeed again.
    ///
    /// # Panics
    ///
    /// Panics if the buffer sequence is inconsistent or the broker returns
    /// a response for another file operation.
    pub fn set_mount_read_only(
        &self,
        path_buffer: SharedBufferSequence,
        start: PathStart,
        path: &str,
        user: FileUser,
        read_only: bool,
    ) -> Result<FileOperationResult<()>, Channel::Error> {
        self.write_file_buffer(path_buffer, path.as_bytes(), SHARED_BUFFER_SLOT_SIZE)?;
        match self.request_file(FileRequest::SetReadOnly(SetReadOnlyRequest {
            path: path_buffer,
            start,
            user,
            read_only,
        }))? {
            FileResponse::SetReadOnly => Ok(Ok(())),
            FileResponse::Failed(error) => Ok(Err(error)),
            response => panic!("broker returned unexpected set-read-only response: {response:?}"),
        }
    }

    /// Unmounts the topmost mount stacked on the node at `path` from `start`, following a final
    /// symbolic link if `follow_final`; with `detach`, also the mounts under it, even if busy.
    ///
    /// # Panics
    ///
    /// Panics if the buffer sequence is inconsistent or the broker returns
    /// a response for another file operation.
    pub fn unmount(
        &self,
        path_buffer: SharedBufferSequence,
        start: PathStart,
        path: &str,
        user: FileUser,
        detach: bool,
        follow_final: bool,
    ) -> Result<FileOperationResult<()>, Channel::Error> {
        self.write_file_buffer(path_buffer, path.as_bytes(), SHARED_BUFFER_SLOT_SIZE)?;
        match self.request_file(FileRequest::Unmount(UnmountRequest {
            path: path_buffer,
            start,
            user,
            detach,
            follow_final,
        }))? {
            FileResponse::Unmount => Ok(Ok(())),
            FileResponse::Failed(error) => Ok(Err(error)),
            response => panic!("broker returned unexpected unmount response: {response:?}"),
        }
    }

    /// Makes the mount at `new_root` from `start` the root of `start`'s context's mount
    /// namespace, moving the old root mount to `put_old`.
    ///
    /// `buffer` must exactly fit `new_root` followed by `put_old`, within one slot.
    ///
    /// # Panics
    ///
    /// Panics if the buffer sequence is inconsistent or the broker returns
    /// a response for another file operation.
    pub fn pivot_root(
        &self,
        buffer: SharedBufferSequence,
        start: PathStart,
        new_root: &str,
        put_old: &str,
        user: FileUser,
    ) -> Result<FileOperationResult<()>, Channel::Error> {
        let length = new_root
            .len()
            .checked_add(put_old.len())
            .ok_or(BrokerLocalError::Broker(ErrorCode::ResourceExhausted))?;
        self.validate_file_buffer(buffer, length, SHARED_BUFFER_SLOT_SIZE)?;
        let new_root_length = u32::try_from(new_root.len())
            .map_err(|_| BrokerLocalError::Broker(ErrorCode::ResourceExhausted))?;
        self.write_shared_buffer_at(buffer, 0, new_root.as_bytes());
        self.write_shared_buffer_at(buffer, new_root.len(), put_old.as_bytes());
        match self.request_file(FileRequest::PivotRoot(PivotRootRequest {
            paths: buffer,
            new_root_length,
            start,
            user,
        }))? {
            FileResponse::PivotRoot => Ok(Ok(())),
            FileResponse::Failed(error) => Ok(Err(error)),
            response => panic!("broker returned unexpected pivot-root response: {response:?}"),
        }
    }

    /// Changes the root of `start`'s context to the directory at `path` from `start`.
    ///
    /// # Panics
    ///
    /// Panics if the buffer sequence is inconsistent or the broker returns
    /// a response for another file operation.
    pub fn change_root(
        &self,
        path_buffer: SharedBufferSequence,
        start: PathStart,
        path: &str,
        user: FileUser,
    ) -> Result<FileOperationResult<()>, Channel::Error> {
        self.write_file_buffer(path_buffer, path.as_bytes(), SHARED_BUFFER_SLOT_SIZE)?;
        match self.request_file(FileRequest::ChangeRoot(ChangeRootRequest {
            path: path_buffer,
            start,
            user,
        }))? {
            FileResponse::ChangeRoot => Ok(Ok(())),
            FileResponse::Failed(error) => Ok(Err(error)),
            response => panic!("broker returned unexpected change-root response: {response:?}"),
        }
    }

    /// Describes the mount that the node at `path` from `start` is on, following a final symbolic
    /// link if `follow_final`.
    ///
    /// `buffer` carries the path to the broker and the mount's info back, so it must fit both.
    ///
    /// # Panics
    ///
    /// Panics if the buffer sequence is inconsistent or the broker returns
    /// a response for another file operation or an invalid info.
    pub fn mount_info(
        &self,
        buffer: SharedBufferSequence,
        start: PathStart,
        path: &str,
        user: FileUser,
        follow_final: bool,
    ) -> Result<FileOperationResult<NodeMount>, Channel::Error> {
        let path_length = self.write_path_query_buffer(buffer, path)?;
        match self.request_file(FileRequest::MountInfo(MountInfoRequest {
            buffer,
            path_length,
            start,
            user,
            follow_final,
        }))? {
            FileResponse::MountInfo(response) => {
                assert!(
                    response.length <= buffer.length(),
                    "broker returned oversized mount info"
                );
                let mut info = Vec::new();
                info.try_reserve_exact(response.length as usize)
                    .map_err(|_| BrokerLocalError::Broker(ErrorCode::OutOfMemory))?;
                info.resize(response.length as usize, 0);
                self.read_shared_buffer(buffer, &mut info);
                Ok(Ok(NodeMount {
                    info: MountInfo::decode(&info).expect("broker returned an invalid mount info"),
                    read_only: response.read_only,
                    at_root: response.at_root,
                    in_namespace: response.in_namespace,
                }))
            }
            FileResponse::Failed(error) => Ok(Err(error)),
            response => panic!("broker returned unexpected mount-info response: {response:?}"),
        }
    }

    /// Reads the absolute path of an open file, with symbolic links resolved, as of when it was
    /// opened.
    ///
    /// # Panics
    ///
    /// Panics if the buffer sequence is inconsistent or the broker returns
    /// a response for another file operation or an invalid path.
    pub fn handle_file_path(
        &self,
        handle: ObjectHandle,
        buffer: SharedBufferSequence,
    ) -> Result<FileOperationResult<String>, Channel::Error> {
        if buffer.length() > SHARED_BUFFER_SLOT_SIZE {
            return Err(BrokerLocalError::Broker(ErrorCode::ResourceExhausted));
        }
        match self.request_file(FileRequest::HandlePath(HandleFilePathRequest {
            handle,
            buffer,
        }))? {
            FileResponse::HandlePath(response) => {
                Ok(Ok(self.read_path_response_buffer(buffer, response)?))
            }
            FileResponse::Failed(error) => Ok(Err(error)),
            response => {
                panic!("broker returned unexpected file handle-path response: {response:?}")
            }
        }
    }

    fn write_path_query_buffer(
        &self,
        buffer: SharedBufferSequence,
        path: &str,
    ) -> Result<u32, Channel::Error> {
        if buffer.length() > SHARED_BUFFER_SLOT_SIZE {
            return Err(BrokerLocalError::Broker(ErrorCode::ResourceExhausted));
        }
        self.write_shared_buffer_at(buffer, 0, path.as_bytes());
        Ok(u32::try_from(path.len()).expect("path fits its shared-buffer sequence"))
    }

    fn read_path_response_buffer(
        &self,
        buffer: SharedBufferSequence,
        response: FilePathResponse,
    ) -> Result<String, Channel::Error> {
        assert!(
            response.length <= buffer.length(),
            "broker returned oversized file path"
        );
        let mut path = Vec::new();
        path.try_reserve_exact(response.length as usize)
            .map_err(|_| BrokerLocalError::Broker(ErrorCode::OutOfMemory))?;
        path.resize(response.length as usize, 0);
        self.read_shared_buffer(buffer, &mut path);
        Ok(String::from_utf8(path).expect("broker returned a non-UTF-8 file path"))
    }

    fn validate_file_buffer(
        &self,
        buffer: SharedBufferSequence,
        expected_length: usize,
        max_length: u32,
    ) -> Result<(), Channel::Error> {
        if buffer.length() > max_length {
            return Err(BrokerLocalError::Broker(ErrorCode::ResourceExhausted));
        }
        assert_eq!(
            expected_length,
            buffer.length() as usize,
            "shared data must match its buffer sequence"
        );
        let _ = buffer
            .descriptors(self.shared_buffers.layout())
            .expect("shared buffer sequence must identify valid slot ranges");
        Ok(())
    }

    fn write_file_buffer(
        &self,
        buffer: SharedBufferSequence,
        data: &[u8],
        max_length: u32,
    ) -> Result<(), Channel::Error> {
        if buffer.length() > max_length {
            return Err(BrokerLocalError::Broker(ErrorCode::ResourceExhausted));
        }
        self.write_shared_buffer(buffer, data);
        Ok(())
    }

    fn request_file(&self, request: FileRequest) -> Result<FileResponse, Channel::Error> {
        match self.request(BrokerOperation::File(request))? {
            BrokerResult::File(response) => Ok(response),
            BrokerResult::Error(error) => Err(BrokerLocalError::Broker(error)),
            response => panic!("broker returned unexpected file response: {response:?}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::sync::Arc;
    use core::{cell::RefCell, convert::Infallible};
    use litebox_broker_protocol::fs::{
        FileNodeInfo, FileType, OpenFileResponse, ReadDirectoryResponse, ReadFileResponse,
        SeekFileResponse, WriteFileResponse, encode_directory_entries,
    };
    use litebox_broker_protocol::message::{BrokerRequest, BrokerResponse};
    use litebox_broker_protocol::shared_buffer::{
        SHARED_BUFFER_POOL_SIZE, SHARED_BUFFER_SLOT_SIZE, SharedBufferSlotIndex,
    };
    use litebox_broker_transport::shared_memory::{SharedMemory, SharedMemoryError};
    use std::collections::VecDeque;
    use std::sync::Mutex;

    use crate::test_support::test_broker_local;

    const ROOT: FileUser = FileUser { user: 0, group: 0 };

    #[test]
    fn file_calls_stage_shared_data_and_preserve_file_errors() {
        let handle = ObjectHandle(7);
        let status = FileStatus {
            file_type: FileType::RegularFile,
            mode: FileMode::from_bits(0o600).unwrap(),
            size: 3,
            owner: ROOT,
            node_info: FileNodeInfo {
                dev: 1,
                ino: 2,
                rdev: None,
            },
            blksize: 4096,
        };
        let entries = [FileDirectoryEntry {
            name: "file".into(),
            file_type: FileType::RegularFile,
            ino_info: None,
        }];
        let directory_payload = encode_directory_entries(&entries).unwrap();
        let channel = ScriptedChannel::new([
            BrokerResult::File(FileResponse::Open(OpenFileResponse { handle })),
            BrokerResult::File(FileResponse::Write(WriteFileResponse { written: 3 })),
            BrokerResult::File(FileResponse::Read(ReadFileResponse { read: 2 })),
            BrokerResult::File(FileResponse::Seek(SeekFileResponse { offset: 0 })),
            BrokerResult::File(FileResponse::PathStatus(status)),
            BrokerResult::File(FileResponse::ReadDirectory(ReadDirectoryResponse {
                length: u32::try_from(directory_payload.len()).unwrap(),
                next_index: None,
            })),
            BrokerResult::File(FileResponse::Failed(FileError::NotForReading)),
            BrokerResult::File(FileResponse::IsTerminal(true)),
        ]);
        let memory = Arc::new(TestSharedMemory::new(SHARED_BUFFER_POOL_SIZE));
        memory
            .write(2 * SHARED_BUFFER_SLOT_SIZE as usize, &[4, 5])
            .unwrap();
        memory
            .write(4 * SHARED_BUFFER_SLOT_SIZE as usize, &directory_payload)
            .unwrap();
        let local = test_broker_local(channel, memory.clone());

        assert_eq!(
            local
                .open_file(
                    sequence([0], 5),
                    PathStart::PROCESS,
                    "/file",
                    ROOT,
                    FileAccessMode::ReadWrite,
                    FileOpenFlags::CREATE,
                    FileMode::from_bits(0o600).unwrap(),
                )
                .unwrap(),
            Ok(handle)
        );
        assert_eq!(
            local
                .write_file(handle, sequence([1], 3), b"abc", None)
                .unwrap(),
            Ok(3)
        );
        let mut staged = [0; 3];
        memory
            .read(SHARED_BUFFER_SLOT_SIZE as usize, &mut staged)
            .unwrap();
        assert_eq!(staged, *b"abc");

        let mut output = [0; 2];
        assert_eq!(
            local
                .read_file(handle, sequence([2], 2), &mut output, Some(1))
                .unwrap(),
            Ok(2)
        );
        assert_eq!(output, [4, 5]);
        assert_eq!(
            local
                .seek_file(handle, 0, FileSeekWhence::RelativeToBeginning)
                .unwrap(),
            Ok(0)
        );
        assert_eq!(
            local
                .path_file_status(
                    sequence([3], 5),
                    PathStart::PROCESS,
                    "/file",
                    ROOT,
                    true,
                    false
                )
                .unwrap(),
            Ok(status)
        );
        assert_eq!(
            local
                .read_directory(
                    handle,
                    sequence([4], u32::try_from(directory_payload.len()).unwrap()),
                    0,
                )
                .unwrap(),
            Ok((entries.into(), None))
        );
        assert_eq!(
            local.handle_file_status(handle).unwrap(),
            Err(FileError::NotForReading)
        );
        assert_eq!(local.is_terminal_file(handle).unwrap(), Ok(true));

        assert!(matches!(
            local.channel.sent_operations.borrow().as_slice(),
            [
                BrokerOperation::File(FileRequest::Open(_)),
                BrokerOperation::File(FileRequest::Write(_)),
                BrokerOperation::File(FileRequest::Read(_)),
                BrokerOperation::File(FileRequest::Seek(_)),
                BrokerOperation::File(FileRequest::PathStatus(_)),
                BrokerOperation::File(FileRequest::ReadDirectory(_)),
                BrokerOperation::File(FileRequest::HandleStatus(_)),
                BrokerOperation::File(FileRequest::IsTerminal(IsTerminalFileRequest {
                    handle: sent_handle,
                })),
            ] if *sent_handle == handle
        ));
    }

    #[test]
    fn working_directory_reads_the_path_the_broker_wrote() {
        let channel =
            ScriptedChannel::new([BrokerResult::File(FileResponse::GetWorkingDirectory(
                litebox_broker_protocol::fs::WorkingDirectoryResponse {
                    length: 4,
                    reachable: false,
                },
            ))]);
        let memory = Arc::new(TestSharedMemory::new(SHARED_BUFFER_POOL_SIZE));
        memory
            .write(5 * SHARED_BUFFER_SLOT_SIZE as usize, b"/dir")
            .unwrap();
        let local = test_broker_local(channel, memory);
        let context = PathContext::Thread(litebox_broker_protocol::ThreadId(3));
        assert_eq!(
            local.working_directory(sequence([5], 64), context).unwrap(),
            Ok((String::from("/dir"), false))
        );
        assert!(matches!(
            local.channel.sent_operations.borrow().as_slice(),
            [BrokerOperation::File(FileRequest::GetWorkingDirectory(
                GetWorkingDirectoryRequest { context: sent, .. }
            ))] if *sent == context
        ));
    }

    #[test]
    fn mount_calls_stage_their_values() {
        let info = MountInfo {
            fs_type: "tmpfs".into(),
            source: "none".into(),
            options: String::new(),
        };
        let encoded = info.encode().unwrap();
        let channel = ScriptedChannel::new([
            BrokerResult::File(FileResponse::Mount),
            BrokerResult::File(FileResponse::MountInfo(
                litebox_broker_protocol::mount::MountInfoResponse {
                    length: u32::try_from(encoded.len()).unwrap(),
                    read_only: true,
                    at_root: false,
                    in_namespace: true,
                },
            )),
        ]);
        let memory = Arc::new(TestSharedMemory::new(SHARED_BUFFER_POOL_SIZE));
        memory
            .write(2 * SHARED_BUFFER_SLOT_SIZE as usize, &encoded)
            .unwrap();
        let local = test_broker_local(channel, memory.clone());
        let source = MountSource::Bind {
            base: Some(ObjectHandle(4)),
            path: "dir".into(),
            recursive: true,
        };
        let length = 4 + source.encode().unwrap().len();
        assert_eq!(
            local
                .mount(
                    sequence([1], u32::try_from(length).unwrap()),
                    PathStart::PROCESS,
                    "/mnt",
                    ROOT,
                    &source,
                )
                .unwrap(),
            Ok(())
        );
        let mut staged = alloc::vec![0; length];
        memory
            .read(SHARED_BUFFER_SLOT_SIZE as usize, &mut staged)
            .unwrap();
        assert_eq!(&staged[..4], b"/mnt");
        assert_eq!(MountSource::decode(&staged[4..]), Ok(source));

        // The broker writes the info over the (here empty) path.
        let base = PathStart {
            context: PathContext::Process,
            base: Some(ObjectHandle(4)),
        };

        assert_eq!(
            local
                .mount_info(sequence([2], 64), base, "", ROOT, false)
                .unwrap(),
            Ok(NodeMount {
                info,
                read_only: true,
                at_root: false,
                in_namespace: true,
            })
        );
        assert!(matches!(
            local.channel.sent_operations.borrow().as_slice(),
            [
                BrokerOperation::File(FileRequest::Mount(MountRequest { path_length: 4, .. })),
                BrokerOperation::File(FileRequest::MountInfo(MountInfoRequest {
                    path_length: 0,
                    start,
                    follow_final: false,
                    ..
                })),
            ] if *start == base
        ));
    }

    #[test]
    fn file_calls_reject_oversized_transfers_before_request() {
        let channel = ScriptedChannel::new([]);
        let memory = Arc::new(TestSharedMemory::new(SHARED_BUFFER_POOL_SIZE));
        let local = test_broker_local(channel, memory);
        let oversized = sequence([0], MAX_FILE_TRANSFER_SIZE + 1);

        assert!(matches!(
            local.read_file(ObjectHandle(1), oversized, &mut [], None),
            Err(BrokerLocalError::Broker(ErrorCode::ResourceExhausted))
        ));
        assert!(matches!(
            local.write_file(ObjectHandle(1), oversized, &[], None),
            Err(BrokerLocalError::Broker(ErrorCode::ResourceExhausted))
        ));
        assert!(local.channel.sent_operations.borrow().is_empty());
    }

    #[test]
    fn file_calls_stage_noncontiguous_multi_slot_data_in_order() {
        let length = SHARED_BUFFER_SLOT_SIZE as usize + 3;
        let channel = ScriptedChannel::new([
            BrokerResult::File(FileResponse::Write(WriteFileResponse {
                written: u32::try_from(length).unwrap(),
            })),
            BrokerResult::File(FileResponse::Read(ReadFileResponse {
                read: u32::try_from(length).unwrap(),
            })),
        ]);
        let memory = Arc::new(TestSharedMemory::new(SHARED_BUFFER_POOL_SIZE));
        let local = test_broker_local(channel, memory.clone());
        let data = (0..length)
            .map(|index| u8::try_from(index % 251).unwrap())
            .collect::<std::vec::Vec<_>>();
        let buffer = sequence([1, 3], u32::try_from(length).unwrap());

        assert_eq!(
            local
                .write_file(ObjectHandle(1), buffer, &data, None)
                .unwrap(),
            Ok(length)
        );
        let mut first_slot = std::vec![0; SHARED_BUFFER_SLOT_SIZE as usize];
        memory
            .read(SHARED_BUFFER_SLOT_SIZE as usize, &mut first_slot)
            .unwrap();
        assert_eq!(first_slot, data[..SHARED_BUFFER_SLOT_SIZE as usize]);
        let mut second_slot = [0; 3];
        memory
            .read(3 * SHARED_BUFFER_SLOT_SIZE as usize, &mut second_slot)
            .unwrap();
        assert_eq!(second_slot, data[SHARED_BUFFER_SLOT_SIZE as usize..]);

        memory
            .write(
                4 * SHARED_BUFFER_SLOT_SIZE as usize,
                &data[..SHARED_BUFFER_SLOT_SIZE as usize],
            )
            .unwrap();
        memory
            .write(
                7 * SHARED_BUFFER_SLOT_SIZE as usize,
                &data[SHARED_BUFFER_SLOT_SIZE as usize..],
            )
            .unwrap();
        let mut output = std::vec![0; length];
        assert_eq!(
            local
                .read_file(
                    ObjectHandle(1),
                    sequence([4, 7], u32::try_from(length).unwrap()),
                    &mut output,
                    None,
                )
                .unwrap(),
            Ok(length)
        );
        assert_eq!(output, data);
    }

    fn sequence<const N: usize>(slots: [u32; N], length: u32) -> SharedBufferSequence {
        let slots = slots.map(SharedBufferSlotIndex);
        SharedBufferSequence::new(&slots, length).unwrap()
    }

    #[derive(Clone)]
    struct TestSharedMemory(Arc<Mutex<std::vec::Vec<u8>>>);

    impl TestSharedMemory {
        fn new(length: usize) -> Self {
            Self(Arc::new(Mutex::new(std::vec![0; length])))
        }
    }

    impl SharedMemory for TestSharedMemory {
        fn len(&self) -> usize {
            self.0.lock().unwrap().len()
        }

        fn read(
            &self,
            offset: usize,
            destination: &mut [u8],
        ) -> core::result::Result<(), SharedMemoryError> {
            let memory = self.0.lock().unwrap();
            let end = offset
                .checked_add(destination.len())
                .ok_or(SharedMemoryError::InvalidRange)?;
            destination.copy_from_slice(
                memory
                    .get(offset..end)
                    .ok_or(SharedMemoryError::InvalidRange)?,
            );
            Ok(())
        }

        fn write(
            &self,
            offset: usize,
            source: &[u8],
        ) -> core::result::Result<(), SharedMemoryError> {
            let mut memory = self.0.lock().unwrap();
            let end = offset
                .checked_add(source.len())
                .ok_or(SharedMemoryError::InvalidRange)?;
            memory
                .get_mut(offset..end)
                .ok_or(SharedMemoryError::InvalidRange)?
                .copy_from_slice(source);
            Ok(())
        }
    }

    struct ScriptedChannel {
        results: RefCell<VecDeque<BrokerResult>>,
        sent_operations: RefCell<std::vec::Vec<BrokerOperation>>,
    }

    impl ScriptedChannel {
        fn new(results: impl IntoIterator<Item = BrokerResult>) -> Self {
            Self {
                results: RefCell::new(results.into_iter().collect()),
                sent_operations: RefCell::new(std::vec::Vec::new()),
            }
        }
    }

    impl LocalCallChannel for ScriptedChannel {
        type Error = Infallible;

        fn call(
            &self,
            request: BrokerRequest,
        ) -> core::result::Result<BrokerResponse, Self::Error> {
            self.sent_operations.borrow_mut().push(request.operation);
            Ok(BrokerResponse {
                request_id: request.request_id,
                result: self.results.borrow_mut().pop_front().unwrap(),
            })
        }
    }
}
