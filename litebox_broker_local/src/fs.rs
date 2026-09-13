// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use alloc::vec::Vec;

use litebox_broker_protocol::ObjectHandle;
use litebox_broker_protocol::error::ErrorCode;
use litebox_broker_protocol::fs::{
    ChmodFileRequest, ChownFileRequest, DirectoryPayloadError, DirectoryTransferError,
    FileAccessMode, FileDirectoryEntry, FileError, FileMode, FileOpenFlags, FileSeekWhence,
    FileStatus, FileUser, HandleFileStatusRequest, MAX_FILE_TRANSFER_SIZE, MkdirFileRequest,
    OpenFileRequest, PathFileStatusRequest, ReadDirectoryRequest, ReadFileRequest,
    RmdirFileRequest, SeekFileRequest, TruncateFileRequest, UnlinkFileRequest, WriteFileRequest,
    try_decode_directory_entries,
};
use litebox_broker_protocol::message::{BrokerOperation, BrokerResult, FileRequest, FileResponse};
use litebox_broker_protocol::shared_buffer::SharedBufferDescriptor;
use litebox_broker_transport::channel::LocalCallChannel;

use crate::{BrokerLocal, BrokerLocalError, Result};

type FileOperationResult<T> = core::result::Result<T, FileError>;
type DirectoryReadResult = FileOperationResult<(Vec<FileDirectoryEntry>, Option<u64>)>;

impl<Channel: LocalCallChannel> BrokerLocal<Channel> {
    /// Opens an absolute fs path.
    ///
    /// # Panics
    ///
    /// Panics if the buffer descriptor is inconsistent or the broker returns
    /// a response for another file operation.
    pub fn open_file(
        &self,
        path_buffer: SharedBufferDescriptor,
        path: &str,
        user: FileUser,
        access: FileAccessMode,
        flags: FileOpenFlags,
        mode: FileMode,
    ) -> Result<FileOperationResult<ObjectHandle>, Channel::Error> {
        self.write_file_buffer(path_buffer, path.as_bytes())?;
        match self.request_file(FileRequest::Open(OpenFileRequest {
            path: path_buffer,
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
    /// Panics if the buffer descriptor is inconsistent or the broker returns
    /// an invalid response.
    pub fn read_file(
        &self,
        handle: ObjectHandle,
        buffer: SharedBufferDescriptor,
        destination: &mut [u8],
        offset: Option<u64>,
    ) -> Result<FileOperationResult<usize>, Channel::Error> {
        self.validate_file_buffer(buffer, destination.len())?;
        match self.request_file(FileRequest::Read(ReadFileRequest {
            handle,
            buffer,
            offset,
        }))? {
            FileResponse::Read(response) => {
                assert!(
                    response.read <= buffer.length,
                    "broker returned oversized file read"
                );
                let read = response.read as usize;
                self.shared_buffers
                    .read(buffer.slot_index, &mut destination[..read])
                    .expect("validated shared file read range must be accessible");
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
    /// Panics if the buffer descriptor is inconsistent or the broker returns
    /// an invalid response.
    pub fn write_file(
        &self,
        handle: ObjectHandle,
        buffer: SharedBufferDescriptor,
        data: &[u8],
        offset: Option<u64>,
    ) -> Result<FileOperationResult<usize>, Channel::Error> {
        self.write_file_buffer(buffer, data)?;
        match self.request_file(FileRequest::Write(WriteFileRequest {
            handle,
            buffer,
            offset,
        }))? {
            FileResponse::Write(response) => {
                assert!(
                    response.written <= buffer.length,
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
    /// Panics if the buffer descriptor is inconsistent or the broker returns
    /// an invalid response or directory payload.
    pub fn read_directory(
        &self,
        handle: ObjectHandle,
        buffer: SharedBufferDescriptor,
        start_index: u64,
    ) -> Result<DirectoryReadResult, Channel::Error> {
        self.validate_file_buffer(buffer, buffer.length as usize)?;
        match self.request_file(FileRequest::ReadDirectory(ReadDirectoryRequest {
            handle,
            buffer,
            start_index,
        }))? {
            FileResponse::ReadDirectory(response) => {
                assert!(
                    response.length <= buffer.length,
                    "broker returned oversized file directory payload"
                );
                let mut payload = Vec::new();
                payload
                    .try_reserve_exact(response.length as usize)
                    .map_err(|_| BrokerLocalError::Broker(ErrorCode::OutOfMemory))?;
                payload.resize(response.length as usize, 0);
                self.shared_buffers
                    .read(buffer.slot_index, &mut payload)
                    .expect("validated shared file directory range must be accessible");
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

    /// Returns status for an absolute path.
    ///
    /// # Panics
    ///
    /// Panics if the buffer descriptor is inconsistent or the broker returns
    /// a response for another file operation.
    pub fn path_file_status(
        &self,
        path_buffer: SharedBufferDescriptor,
        path: &str,
        user: FileUser,
    ) -> Result<FileOperationResult<FileStatus>, Channel::Error> {
        self.write_file_buffer(path_buffer, path.as_bytes())?;
        match self.request_file(FileRequest::PathStatus(PathFileStatusRequest {
            path: path_buffer,
            user,
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

    /// Changes mode bits for an absolute path.
    ///
    /// # Panics
    ///
    /// Panics if the buffer descriptor is inconsistent or the broker returns
    /// a response for another file operation.
    pub fn chmod_file(
        &self,
        path_buffer: SharedBufferDescriptor,
        path: &str,
        user: FileUser,
        mode: FileMode,
    ) -> Result<FileOperationResult<()>, Channel::Error> {
        self.write_file_buffer(path_buffer, path.as_bytes())?;
        match self.request_file(FileRequest::Chmod(ChmodFileRequest {
            path: path_buffer,
            user,
            mode,
        }))? {
            FileResponse::Chmod => Ok(Ok(())),
            FileResponse::Failed(error) => Ok(Err(error)),
            response => panic!("broker returned unexpected file chmod response: {response:?}"),
        }
    }

    /// Changes ownership for an absolute path.
    ///
    /// # Panics
    ///
    /// Panics if the buffer descriptor is inconsistent or the broker returns
    /// a response for another file operation.
    pub fn chown_file(
        &self,
        path_buffer: SharedBufferDescriptor,
        path: &str,
        acting_user: FileUser,
        user: Option<u16>,
        group: Option<u16>,
    ) -> Result<FileOperationResult<()>, Channel::Error> {
        self.write_file_buffer(path_buffer, path.as_bytes())?;
        match self.request_file(FileRequest::Chown(ChownFileRequest {
            path: path_buffer,
            acting_user,
            user,
            group,
        }))? {
            FileResponse::Chown => Ok(Ok(())),
            FileResponse::Failed(error) => Ok(Err(error)),
            response => panic!("broker returned unexpected file chown response: {response:?}"),
        }
    }

    /// Removes a file at an absolute path.
    ///
    /// # Panics
    ///
    /// Panics if the buffer descriptor is inconsistent or the broker returns
    /// a response for another file operation.
    pub fn unlink_file(
        &self,
        path_buffer: SharedBufferDescriptor,
        path: &str,
        user: FileUser,
    ) -> Result<FileOperationResult<()>, Channel::Error> {
        self.write_file_buffer(path_buffer, path.as_bytes())?;
        match self.request_file(FileRequest::Unlink(UnlinkFileRequest {
            path: path_buffer,
            user,
        }))? {
            FileResponse::Unlink => Ok(Ok(())),
            FileResponse::Failed(error) => Ok(Err(error)),
            response => panic!("broker returned unexpected file unlink response: {response:?}"),
        }
    }

    /// Creates a directory at an absolute path.
    ///
    /// # Panics
    ///
    /// Panics if the buffer descriptor is inconsistent or the broker returns
    /// a response for another file operation.
    pub fn mkdir_file(
        &self,
        path_buffer: SharedBufferDescriptor,
        path: &str,
        user: FileUser,
        mode: FileMode,
    ) -> Result<FileOperationResult<()>, Channel::Error> {
        self.write_file_buffer(path_buffer, path.as_bytes())?;
        match self.request_file(FileRequest::Mkdir(MkdirFileRequest {
            path: path_buffer,
            user,
            mode,
        }))? {
            FileResponse::Mkdir => Ok(Ok(())),
            FileResponse::Failed(error) => Ok(Err(error)),
            response => panic!("broker returned unexpected file mkdir response: {response:?}"),
        }
    }

    /// Removes a directory at an absolute path.
    ///
    /// # Panics
    ///
    /// Panics if the buffer descriptor is inconsistent or the broker returns
    /// a response for another file operation.
    pub fn rmdir_file(
        &self,
        path_buffer: SharedBufferDescriptor,
        path: &str,
        user: FileUser,
    ) -> Result<FileOperationResult<()>, Channel::Error> {
        self.write_file_buffer(path_buffer, path.as_bytes())?;
        match self.request_file(FileRequest::Rmdir(RmdirFileRequest {
            path: path_buffer,
            user,
        }))? {
            FileResponse::Rmdir => Ok(Ok(())),
            FileResponse::Failed(error) => Ok(Err(error)),
            response => panic!("broker returned unexpected file rmdir response: {response:?}"),
        }
    }

    fn validate_file_buffer(
        &self,
        buffer: SharedBufferDescriptor,
        expected_length: usize,
    ) -> Result<(), Channel::Error> {
        if buffer.length > MAX_FILE_TRANSFER_SIZE {
            return Err(BrokerLocalError::Broker(ErrorCode::ResourceExhausted));
        }
        assert_eq!(
            expected_length, buffer.length as usize,
            "shared file data must match its descriptor"
        );
        self.shared_buffers
            .layout()
            .range(buffer.slot_index, expected_length)
            .expect("shared file descriptor must identify a valid slot range");
        Ok(())
    }

    fn write_file_buffer(
        &self,
        buffer: SharedBufferDescriptor,
        data: &[u8],
    ) -> Result<(), Channel::Error> {
        self.validate_file_buffer(buffer, data.len())?;
        self.shared_buffers
            .write(buffer.slot_index, data)
            .expect("validated shared file write range must be accessible");
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
    use litebox_broker_protocol::BROKER_PROTOCOL_VERSION;
    use litebox_broker_protocol::fs::{
        FileNodeInfo, FileType, OpenFileResponse, ReadDirectoryResponse, ReadFileResponse,
        SeekFileResponse, WriteFileResponse, encode_directory_entries,
    };
    use litebox_broker_protocol::message::{
        BrokerHandshakeRequest, BrokerHandshakeResponse, BrokerRequest, BrokerResponse,
    };
    use litebox_broker_protocol::shared_buffer::{
        SHARED_BUFFER_POOL_SIZE, SHARED_BUFFER_SLOT_SIZE, SharedBufferSlotIndex,
    };
    use litebox_broker_transport::channel::LocalSetupChannel;
    use litebox_broker_transport::shared_memory::{SharedMemory, SharedMemoryError};
    use std::collections::VecDeque;
    use std::sync::Mutex;

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
        ]);
        let memory = Arc::new(TestSharedMemory::new(SHARED_BUFFER_POOL_SIZE));
        memory
            .write(2 * SHARED_BUFFER_SLOT_SIZE as usize, &[4, 5])
            .unwrap();
        memory
            .write(4 * SHARED_BUFFER_SLOT_SIZE as usize, &directory_payload)
            .unwrap();
        let (local, ()) =
            BrokerLocal::negotiate(channel, |channel| Ok((channel, memory.clone(), ()))).unwrap();

        assert_eq!(
            local
                .open_file(
                    descriptor(0, 5),
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
                .write_file(handle, descriptor(1, 3), b"abc", None)
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
                .read_file(handle, descriptor(2, 2), &mut output, Some(1))
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
                .path_file_status(descriptor(3, 5), "/file", ROOT)
                .unwrap(),
            Ok(status)
        );
        assert_eq!(
            local
                .read_directory(
                    handle,
                    descriptor(4, u32::try_from(directory_payload.len()).unwrap()),
                    0,
                )
                .unwrap(),
            Ok((entries.into(), None))
        );
        assert_eq!(
            local.handle_file_status(handle).unwrap(),
            Err(FileError::NotForReading)
        );

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
            ]
        ));
    }

    #[test]
    fn file_calls_reject_oversized_transfers_before_request() {
        let channel = ScriptedChannel::new([]);
        let memory = Arc::new(TestSharedMemory::new(SHARED_BUFFER_POOL_SIZE));
        let (local, ()) =
            BrokerLocal::negotiate(channel, |channel| Ok((channel, memory, ()))).unwrap();
        let oversized = descriptor(0, MAX_FILE_TRANSFER_SIZE + 1);

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

    const fn descriptor(slot: u32, length: u32) -> SharedBufferDescriptor {
        SharedBufferDescriptor {
            slot_index: SharedBufferSlotIndex(slot),
            length,
        }
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

    impl LocalSetupChannel for ScriptedChannel {
        type Error = Infallible;

        fn send_handshake_request(
            &mut self,
            request: &BrokerHandshakeRequest,
        ) -> core::result::Result<(), Self::Error> {
            assert_eq!(request.protocol_version, BROKER_PROTOCOL_VERSION);
            Ok(())
        }

        fn recv_handshake_response(
            &mut self,
        ) -> core::result::Result<Option<BrokerHandshakeResponse>, Self::Error> {
            Ok(Some(BrokerHandshakeResponse::Negotiated {
                broker_protocol_version: BROKER_PROTOCOL_VERSION,
            }))
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
