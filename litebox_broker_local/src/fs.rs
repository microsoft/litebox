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
use litebox_broker_protocol::shared_buffer::{SHARED_BUFFER_SLOT_SIZE, SharedBufferSequence};
use litebox_broker_transport::channel::LocalCallChannel;

use crate::{BrokerLocal, BrokerLocalError, Result};

type FileOperationResult<T> = core::result::Result<T, FileError>;
type DirectoryReadResult = FileOperationResult<(Vec<FileDirectoryEntry>, Option<u64>)>;

impl<Channel: LocalCallChannel> BrokerLocal<Channel> {
    /// Opens an absolute fs path.
    ///
    /// # Panics
    ///
    /// Panics if the buffer sequence is inconsistent or the broker returns
    /// a response for another file operation.
    pub fn open_file(
        &self,
        path_buffer: SharedBufferSequence,
        path: &str,
        user: FileUser,
        access: FileAccessMode,
        flags: FileOpenFlags,
        mode: FileMode,
    ) -> Result<FileOperationResult<ObjectHandle>, Channel::Error> {
        self.write_file_buffer(path_buffer, path.as_bytes(), SHARED_BUFFER_SLOT_SIZE)?;
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
    /// Panics if the buffer sequence is inconsistent or the broker returns
    /// an invalid response.
    pub fn read_file(
        &self,
        handle: ObjectHandle,
        buffer: SharedBufferSequence,
        destination: &mut [u8],
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
                self.read_shared_buffer(buffer, &mut destination[..read]);
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
        data: &[u8],
        offset: Option<u64>,
    ) -> Result<FileOperationResult<usize>, Channel::Error> {
        self.write_file_buffer(buffer, data, MAX_FILE_TRANSFER_SIZE)?;
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

    /// Returns status for an absolute path.
    ///
    /// # Panics
    ///
    /// Panics if the buffer sequence is inconsistent or the broker returns
    /// a response for another file operation.
    pub fn path_file_status(
        &self,
        path_buffer: SharedBufferSequence,
        path: &str,
        user: FileUser,
    ) -> Result<FileOperationResult<FileStatus>, Channel::Error> {
        self.write_file_buffer(path_buffer, path.as_bytes(), SHARED_BUFFER_SLOT_SIZE)?;
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
    /// Panics if the buffer sequence is inconsistent or the broker returns
    /// a response for another file operation.
    pub fn chmod_file(
        &self,
        path_buffer: SharedBufferSequence,
        path: &str,
        user: FileUser,
        mode: FileMode,
    ) -> Result<FileOperationResult<()>, Channel::Error> {
        self.write_file_buffer(path_buffer, path.as_bytes(), SHARED_BUFFER_SLOT_SIZE)?;
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
    /// Panics if the buffer sequence is inconsistent or the broker returns
    /// a response for another file operation.
    pub fn chown_file(
        &self,
        path_buffer: SharedBufferSequence,
        path: &str,
        acting_user: FileUser,
        user: Option<u16>,
        group: Option<u16>,
    ) -> Result<FileOperationResult<()>, Channel::Error> {
        self.write_file_buffer(path_buffer, path.as_bytes(), SHARED_BUFFER_SLOT_SIZE)?;
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
    /// Panics if the buffer sequence is inconsistent or the broker returns
    /// a response for another file operation.
    pub fn unlink_file(
        &self,
        path_buffer: SharedBufferSequence,
        path: &str,
        user: FileUser,
    ) -> Result<FileOperationResult<()>, Channel::Error> {
        self.write_file_buffer(path_buffer, path.as_bytes(), SHARED_BUFFER_SLOT_SIZE)?;
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
    /// Panics if the buffer sequence is inconsistent or the broker returns
    /// a response for another file operation.
    pub fn mkdir_file(
        &self,
        path_buffer: SharedBufferSequence,
        path: &str,
        user: FileUser,
        mode: FileMode,
    ) -> Result<FileOperationResult<()>, Channel::Error> {
        self.write_file_buffer(path_buffer, path.as_bytes(), SHARED_BUFFER_SLOT_SIZE)?;
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
    /// Panics if the buffer sequence is inconsistent or the broker returns
    /// a response for another file operation.
    pub fn rmdir_file(
        &self,
        path_buffer: SharedBufferSequence,
        path: &str,
        user: FileUser,
    ) -> Result<FileOperationResult<()>, Channel::Error> {
        self.write_file_buffer(path_buffer, path.as_bytes(), SHARED_BUFFER_SLOT_SIZE)?;
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
                    sequence([0], 5),
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
                .path_file_status(sequence([3], 5), "/file", ROOT)
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
        let (local, ()) =
            BrokerLocal::negotiate(channel, |channel| Ok((channel, memory.clone(), ()))).unwrap();
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
                process_id: litebox_broker_protocol::ProcessId(1),
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
