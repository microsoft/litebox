// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use alloc::vec::Vec;

use litebox_broker_protocol::ObjectHandle;
use litebox_broker_protocol::error::ErrorCode;
use litebox_broker_protocol::filesystem::{
    ChmodFileRequest, ChownFileRequest, FilesystemDirectoryEntry, FilesystemError,
    FilesystemFileStatus, FilesystemNamespace, FilesystemSeekWhence, FilesystemUser,
    HandleFileStatusRequest, MAX_FILESYSTEM_TRANSFER_SIZE, MkdirFileRequest, OpenFileRequest,
    PathFileStatusRequest, ReadDirectoryRequest, ReadFileRequest, RmdirFileRequest,
    SeekFileRequest, TruncateFileRequest, UnlinkFileRequest, WriteFileRequest,
    decode_directory_entries,
};
use litebox_broker_protocol::message::{
    BrokerOperation, BrokerResult, FilesystemRequest, FilesystemResponse,
};
use litebox_broker_protocol::shared_buffer::SharedBufferDescriptor;
use litebox_broker_transport::channel::LocalCallChannel;

use crate::{BrokerLocal, BrokerLocalError, Result};

type FilesystemResult<T> = core::result::Result<T, FilesystemError>;
type DirectoryReadResult = FilesystemResult<(Vec<FilesystemDirectoryEntry>, Option<u64>)>;

impl<Channel: LocalCallChannel> BrokerLocal<Channel> {
    /// Opens an absolute filesystem path.
    ///
    /// # Panics
    ///
    /// Panics if the buffer descriptor is inconsistent or the broker returns
    /// a response for another filesystem operation.
    pub fn open_file(
        &self,
        namespace: FilesystemNamespace,
        path_buffer: SharedBufferDescriptor,
        path: &[u8],
        user: FilesystemUser,
        flags: u32,
        mode: u32,
    ) -> Result<FilesystemResult<ObjectHandle>, Channel::Error> {
        self.write_filesystem_buffer(path_buffer, path)?;
        match self.request_filesystem(FilesystemRequest::Open(OpenFileRequest {
            namespace,
            path: path_buffer,
            user,
            flags,
            mode,
        }))? {
            FilesystemResponse::Open(response) => Ok(Ok(response.handle)),
            FilesystemResponse::Failed(error) => Ok(Err(error)),
            response => panic!("broker returned unexpected filesystem open response: {response:?}"),
        }
    }

    /// Reads from an open filesystem object.
    ///
    /// # Panics
    ///
    /// Panics if the buffer descriptor is inconsistent or the broker returns
    /// an invalid response.
    pub fn read_file(
        &self,
        handle: ObjectHandle,
        buffer: SharedBufferDescriptor,
        destination: &mut [u8],
        offset: Option<u64>,
    ) -> Result<FilesystemResult<usize>, Channel::Error> {
        self.validate_filesystem_buffer(buffer, destination.len())?;
        match self.request_filesystem(FilesystemRequest::Read(ReadFileRequest {
            handle,
            buffer,
            offset,
        }))? {
            FilesystemResponse::Read(response) => {
                assert!(
                    response.read <= buffer.length,
                    "broker returned oversized filesystem read"
                );
                let read = response.read as usize;
                self.shared_buffers
                    .read(buffer.slot_index, &mut destination[..read])
                    .expect("validated shared filesystem read range must be accessible");
                Ok(Ok(read))
            }
            FilesystemResponse::Failed(error) => Ok(Err(error)),
            response => panic!("broker returned unexpected filesystem read response: {response:?}"),
        }
    }

    /// Writes to an open filesystem object.
    ///
    /// # Panics
    ///
    /// Panics if the buffer descriptor is inconsistent or the broker returns
    /// an invalid response.
    pub fn write_file(
        &self,
        handle: ObjectHandle,
        buffer: SharedBufferDescriptor,
        data: &[u8],
        offset: Option<u64>,
    ) -> Result<FilesystemResult<usize>, Channel::Error> {
        self.write_filesystem_buffer(buffer, data)?;
        match self.request_filesystem(FilesystemRequest::Write(WriteFileRequest {
            handle,
            buffer,
            offset,
        }))? {
            FilesystemResponse::Write(response) => {
                assert!(
                    response.written <= buffer.length,
                    "broker returned oversized filesystem write"
                );
                Ok(Ok(response.written as usize))
            }
            FilesystemResponse::Failed(error) => Ok(Err(error)),
            response => {
                panic!("broker returned unexpected filesystem write response: {response:?}")
            }
        }
    }

    /// Repositions an open filesystem object.
    ///
    /// # Panics
    ///
    /// Panics if the broker returns a response for another filesystem
    /// operation.
    pub fn seek_file(
        &self,
        handle: ObjectHandle,
        offset: i64,
        whence: FilesystemSeekWhence,
    ) -> Result<FilesystemResult<u64>, Channel::Error> {
        match self.request_filesystem(FilesystemRequest::Seek(SeekFileRequest {
            handle,
            offset,
            whence,
        }))? {
            FilesystemResponse::Seek(response) => Ok(Ok(response.offset)),
            FilesystemResponse::Failed(error) => Ok(Err(error)),
            response => panic!("broker returned unexpected filesystem seek response: {response:?}"),
        }
    }

    /// Truncates an open filesystem object.
    ///
    /// # Panics
    ///
    /// Panics if the broker returns a response for another filesystem
    /// operation.
    pub fn truncate_file(
        &self,
        handle: ObjectHandle,
        length: u64,
        reset_offset: bool,
    ) -> Result<FilesystemResult<()>, Channel::Error> {
        match self.request_filesystem(FilesystemRequest::Truncate(TruncateFileRequest {
            handle,
            length,
            reset_offset,
        }))? {
            FilesystemResponse::Truncate => Ok(Ok(())),
            FilesystemResponse::Failed(error) => Ok(Err(error)),
            response => {
                panic!("broker returned unexpected filesystem truncate response: {response:?}")
            }
        }
    }

    /// Reads one encoded chunk of directory entries.
    ///
    /// # Panics
    ///
    /// Panics if the buffer descriptor is inconsistent or the broker returns
    /// an invalid response or directory payload.
    pub fn read_directory(
        &self,
        handle: ObjectHandle,
        buffer: SharedBufferDescriptor,
        start_index: u64,
    ) -> Result<DirectoryReadResult, Channel::Error> {
        self.validate_filesystem_buffer(buffer, buffer.length as usize)?;
        match self.request_filesystem(FilesystemRequest::ReadDirectory(ReadDirectoryRequest {
            handle,
            buffer,
            start_index,
        }))? {
            FilesystemResponse::ReadDirectory(response) => {
                assert!(
                    response.length <= buffer.length,
                    "broker returned oversized filesystem directory payload"
                );
                let mut payload = Vec::new();
                payload
                    .try_reserve_exact(response.length as usize)
                    .map_err(|_| BrokerLocalError::Broker(ErrorCode::OutOfMemory))?;
                payload.resize(response.length as usize, 0);
                self.shared_buffers
                    .read(buffer.slot_index, &mut payload)
                    .expect("validated shared filesystem directory range must be accessible");
                let entries = decode_directory_entries(&payload)
                    .expect("broker returned malformed filesystem directory payload");
                if let Some(next_index) = response.next_index {
                    let expected_next_index = start_index
                        .checked_add(u64::try_from(entries.len()).unwrap())
                        .expect("filesystem directory index overflow");
                    assert!(
                        !entries.is_empty() && next_index == expected_next_index,
                        "broker returned inconsistent filesystem directory continuation"
                    );
                }
                Ok(Ok((entries, response.next_index)))
            }
            FilesystemResponse::Failed(error) => Ok(Err(error)),
            response => {
                panic!("broker returned unexpected filesystem directory response: {response:?}")
            }
        }
    }

    /// Returns status for an absolute path.
    ///
    /// # Panics
    ///
    /// Panics if the buffer descriptor is inconsistent or the broker returns
    /// a response for another filesystem operation.
    pub fn path_file_status(
        &self,
        namespace: FilesystemNamespace,
        path_buffer: SharedBufferDescriptor,
        path: &[u8],
        user: FilesystemUser,
    ) -> Result<FilesystemResult<FilesystemFileStatus>, Channel::Error> {
        self.write_filesystem_buffer(path_buffer, path)?;
        match self.request_filesystem(FilesystemRequest::PathStatus(PathFileStatusRequest {
            namespace,
            path: path_buffer,
            user,
        }))? {
            FilesystemResponse::Status(status) => Ok(Ok(status)),
            FilesystemResponse::Failed(error) => Ok(Err(error)),
            response => {
                panic!("broker returned unexpected filesystem path-status response: {response:?}")
            }
        }
    }

    /// Returns status for an open filesystem object.
    ///
    /// # Panics
    ///
    /// Panics if the broker returns a response for another filesystem
    /// operation.
    pub fn handle_file_status(
        &self,
        handle: ObjectHandle,
    ) -> Result<FilesystemResult<FilesystemFileStatus>, Channel::Error> {
        match self.request_filesystem(FilesystemRequest::HandleStatus(HandleFileStatusRequest {
            handle,
        }))? {
            FilesystemResponse::Status(status) => Ok(Ok(status)),
            FilesystemResponse::Failed(error) => Ok(Err(error)),
            response => {
                panic!("broker returned unexpected filesystem handle-status response: {response:?}")
            }
        }
    }

    /// Changes mode bits for an absolute path.
    ///
    /// # Panics
    ///
    /// Panics if the buffer descriptor is inconsistent or the broker returns
    /// a response for another filesystem operation.
    pub fn chmod_file(
        &self,
        namespace: FilesystemNamespace,
        path_buffer: SharedBufferDescriptor,
        path: &[u8],
        user: FilesystemUser,
        mode: u32,
    ) -> Result<FilesystemResult<()>, Channel::Error> {
        self.write_filesystem_buffer(path_buffer, path)?;
        match self.request_filesystem(FilesystemRequest::Chmod(ChmodFileRequest {
            namespace,
            path: path_buffer,
            user,
            mode,
        }))? {
            FilesystemResponse::Chmod => Ok(Ok(())),
            FilesystemResponse::Failed(error) => Ok(Err(error)),
            response => {
                panic!("broker returned unexpected filesystem chmod response: {response:?}")
            }
        }
    }

    /// Changes ownership for an absolute path.
    ///
    /// # Panics
    ///
    /// Panics if the buffer descriptor is inconsistent or the broker returns
    /// a response for another filesystem operation.
    pub fn chown_file(
        &self,
        namespace: FilesystemNamespace,
        path_buffer: SharedBufferDescriptor,
        path: &[u8],
        acting_user: FilesystemUser,
        user: Option<u16>,
        group: Option<u16>,
    ) -> Result<FilesystemResult<()>, Channel::Error> {
        self.write_filesystem_buffer(path_buffer, path)?;
        match self.request_filesystem(FilesystemRequest::Chown(ChownFileRequest {
            namespace,
            path: path_buffer,
            acting_user,
            user,
            group,
        }))? {
            FilesystemResponse::Chown => Ok(Ok(())),
            FilesystemResponse::Failed(error) => Ok(Err(error)),
            response => {
                panic!("broker returned unexpected filesystem chown response: {response:?}")
            }
        }
    }

    /// Removes a file at an absolute path.
    ///
    /// # Panics
    ///
    /// Panics if the buffer descriptor is inconsistent or the broker returns
    /// a response for another filesystem operation.
    pub fn unlink_file(
        &self,
        namespace: FilesystemNamespace,
        path_buffer: SharedBufferDescriptor,
        path: &[u8],
        user: FilesystemUser,
    ) -> Result<FilesystemResult<()>, Channel::Error> {
        self.write_filesystem_buffer(path_buffer, path)?;
        match self.request_filesystem(FilesystemRequest::Unlink(UnlinkFileRequest {
            namespace,
            path: path_buffer,
            user,
        }))? {
            FilesystemResponse::Unlink => Ok(Ok(())),
            FilesystemResponse::Failed(error) => Ok(Err(error)),
            response => {
                panic!("broker returned unexpected filesystem unlink response: {response:?}")
            }
        }
    }

    /// Creates a directory at an absolute path.
    ///
    /// # Panics
    ///
    /// Panics if the buffer descriptor is inconsistent or the broker returns
    /// a response for another filesystem operation.
    pub fn mkdir_file(
        &self,
        namespace: FilesystemNamespace,
        path_buffer: SharedBufferDescriptor,
        path: &[u8],
        user: FilesystemUser,
        mode: u32,
    ) -> Result<FilesystemResult<()>, Channel::Error> {
        self.write_filesystem_buffer(path_buffer, path)?;
        match self.request_filesystem(FilesystemRequest::Mkdir(MkdirFileRequest {
            namespace,
            path: path_buffer,
            user,
            mode,
        }))? {
            FilesystemResponse::Mkdir => Ok(Ok(())),
            FilesystemResponse::Failed(error) => Ok(Err(error)),
            response => {
                panic!("broker returned unexpected filesystem mkdir response: {response:?}")
            }
        }
    }

    /// Removes a directory at an absolute path.
    ///
    /// # Panics
    ///
    /// Panics if the buffer descriptor is inconsistent or the broker returns
    /// a response for another filesystem operation.
    pub fn rmdir_file(
        &self,
        namespace: FilesystemNamespace,
        path_buffer: SharedBufferDescriptor,
        path: &[u8],
        user: FilesystemUser,
    ) -> Result<FilesystemResult<()>, Channel::Error> {
        self.write_filesystem_buffer(path_buffer, path)?;
        match self.request_filesystem(FilesystemRequest::Rmdir(RmdirFileRequest {
            namespace,
            path: path_buffer,
            user,
        }))? {
            FilesystemResponse::Rmdir => Ok(Ok(())),
            FilesystemResponse::Failed(error) => Ok(Err(error)),
            response => {
                panic!("broker returned unexpected filesystem rmdir response: {response:?}")
            }
        }
    }

    fn validate_filesystem_buffer(
        &self,
        buffer: SharedBufferDescriptor,
        expected_length: usize,
    ) -> Result<(), Channel::Error> {
        if buffer.length > MAX_FILESYSTEM_TRANSFER_SIZE {
            return Err(BrokerLocalError::Broker(ErrorCode::ResourceExhausted));
        }
        assert_eq!(
            expected_length, buffer.length as usize,
            "shared filesystem data must match its descriptor"
        );
        self.shared_buffers
            .layout()
            .range(buffer.slot_index, expected_length)
            .expect("shared filesystem descriptor must identify a valid slot range");
        Ok(())
    }

    fn write_filesystem_buffer(
        &self,
        buffer: SharedBufferDescriptor,
        data: &[u8],
    ) -> Result<(), Channel::Error> {
        self.validate_filesystem_buffer(buffer, data.len())?;
        self.shared_buffers
            .write(buffer.slot_index, data)
            .expect("validated shared filesystem write range must be accessible");
        Ok(())
    }

    fn request_filesystem(
        &self,
        request: FilesystemRequest,
    ) -> Result<FilesystemResponse, Channel::Error> {
        match self.request(BrokerOperation::Filesystem(request))? {
            BrokerResult::Filesystem(response) => Ok(response),
            BrokerResult::Error(error) => Err(BrokerLocalError::Broker(error)),
            response => panic!("broker returned unexpected filesystem response: {response:?}"),
        }
    }
}
