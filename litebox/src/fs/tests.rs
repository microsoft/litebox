// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Guest-facing file API tests.
//!
//! Filesystem resolution, backend, and 9P semantics belong to `litebox_broker_core` and are tested
//! there. What LiteBox owns is the guest side of the boundary: resolving paths against a
//! [`Context`], converting between guest and protocol values, mapping broker errors onto guest
//! error types, and tying broker-owned files to guest descriptors. These tests script broker
//! responses over a local channel, so no broker core, policy engine, or host transport is
//! involved.

extern crate std;

use alloc::collections::VecDeque;
use alloc::string::{String, ToString as _};
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use std::sync::Mutex;

use litebox_broker_local::BrokerLocal;
use litebox_broker_protocol::fs::{
    FileAccessMode, FileDirectoryEntry, FileError, FileMode, FileNodeInfo, FileOpenFlags,
    FileSeekWhence, FileStatus as BrokerFileStatus, FileType as BrokerFileType, FileUser,
    MAX_FILE_TRANSFER_SIZE, OpenFileResponse, ReadDirectoryResponse, ReadFileResponse,
    SeekFileResponse, WriteFileResponse, encode_directory_entries_chunk,
};
use litebox_broker_protocol::message::{
    BrokerHandshakeRequest, BrokerHandshakeResponse, BrokerOperation, BrokerRequest,
    BrokerResponse, BrokerResult, FileRequest, FileResponse,
};
use litebox_broker_protocol::shared_buffer::{
    SHARED_BUFFER_LAYOUT, SHARED_BUFFER_POOL_SIZE, SharedBufferDescriptor,
};
use litebox_broker_protocol::{BROKER_PROTOCOL_VERSION, ObjectHandle};
use litebox_broker_transport::channel::{LocalCallChannel, LocalSetupChannel};
use litebox_broker_transport::shared_memory::{SharedBufferPool, SharedMemory, SharedMemoryError};

use crate::fs::errors::{
    OpenError, PathError, ReadDirError, ReadError, RmdirError, UnlinkError, WriteError,
};
use crate::fs::{Context, FileType, Mode, OFlags, SeekWhence, UserInfo};
use crate::platform::mock::MockPlatform;

/// The handle the scripted broker hands out for every successful open.
const FILE_HANDLE: ObjectHandle = ObjectHandle(7);

/// One broker request LiteBox issued, with any shared-buffer payload copied out.
#[derive(Debug, PartialEq, Eq)]
enum Call {
    Open {
        path: String,
        user: FileUser,
        access: FileAccessMode,
        flags: FileOpenFlags,
        mode: FileMode,
    },
    Read {
        handle: ObjectHandle,
        length: u32,
        offset: Option<u64>,
    },
    Write {
        handle: ObjectHandle,
        data: Vec<u8>,
        offset: Option<u64>,
    },
    Seek {
        handle: ObjectHandle,
        offset: i64,
        whence: FileSeekWhence,
    },
    ReadDirectory {
        handle: ObjectHandle,
        start_index: u64,
    },
    PathStatus {
        path: String,
        user: FileUser,
    },
    Unlink {
        path: String,
        user: FileUser,
    },
    Rmdir {
        path: String,
        user: FileUser,
    },
    Close(ObjectHandle),
}

/// One scripted broker answer.
enum Scripted {
    /// Reply with this file response verbatim.
    Reply(FileResponse),
    /// Stage `data` in the request's shared buffer and report it as read.
    Read(Vec<u8>),
    /// Answer directory reads from `entries`, at most `page_bytes` of them per response.
    Directory {
        entries: Vec<FileDirectoryEntry>,
        page_bytes: usize,
    },
}

/// A broker that records requests and answers them from a script.
struct ScriptedBroker {
    buffers: SharedBufferPool<Arc<TestSharedMemory>>,
    calls: Mutex<Vec<Call>>,
    script: Mutex<VecDeque<Scripted>>,
}

impl ScriptedBroker {
    fn new(script: impl IntoIterator<Item = Scripted>) -> Arc<Self> {
        let memory = Arc::new(TestSharedMemory::new());
        Arc::new(Self {
            buffers: SharedBufferPool::new(memory, SHARED_BUFFER_LAYOUT).unwrap(),
            calls: Mutex::new(Vec::new()),
            script: Mutex::new(script.into_iter().collect()),
        })
    }

    /// Every request observed so far, oldest first.
    fn calls(&self) -> std::sync::MutexGuard<'_, Vec<Call>> {
        self.calls.lock().unwrap()
    }

    fn record(&self, call: Call) {
        self.calls.lock().unwrap().push(call);
    }

    /// The UTF-8 path staged in `descriptor` by the guest.
    fn staged_path(&self, descriptor: SharedBufferDescriptor) -> String {
        let mut bytes = vec![0; descriptor.length as usize];
        self.buffers
            .read(descriptor.slot_index, &mut bytes)
            .unwrap();
        String::from_utf8(bytes).expect("guest must stage a UTF-8 path")
    }

    fn staged_data(&self, descriptor: SharedBufferDescriptor) -> Vec<u8> {
        let mut bytes = vec![0; descriptor.length as usize];
        self.buffers
            .read(descriptor.slot_index, &mut bytes)
            .unwrap();
        bytes
    }

    fn next_scripted(&self) -> Scripted {
        self.script
            .lock()
            .unwrap()
            .pop_front()
            .expect("test script must answer every file request")
    }

    fn file_response(&self, request: FileRequest) -> FileResponse {
        match request {
            FileRequest::Open(request) => {
                self.record(Call::Open {
                    path: self.staged_path(request.path),
                    user: request.user,
                    access: request.access,
                    flags: request.flags,
                    mode: request.mode,
                });
                self.reply()
            }
            FileRequest::Read(request) => {
                self.record(Call::Read {
                    handle: request.handle,
                    length: request.buffer.length,
                    offset: request.offset,
                });
                match self.next_scripted() {
                    Scripted::Reply(response) => response,
                    Scripted::Read(data) => {
                        assert!(data.len() <= request.buffer.length as usize);
                        self.buffers
                            .write(request.buffer.slot_index, &data)
                            .unwrap();
                        FileResponse::Read(ReadFileResponse {
                            read: u32::try_from(data.len()).unwrap(),
                        })
                    }
                    Scripted::Directory { .. } => panic!("scripted directory answer for a read"),
                }
            }
            FileRequest::Write(request) => {
                self.record(Call::Write {
                    handle: request.handle,
                    data: self.staged_data(request.buffer),
                    offset: request.offset,
                });
                self.reply()
            }
            FileRequest::Seek(request) => {
                self.record(Call::Seek {
                    handle: request.handle,
                    offset: request.offset,
                    whence: request.whence,
                });
                self.reply()
            }
            FileRequest::ReadDirectory(request) => {
                self.record(Call::ReadDirectory {
                    handle: request.handle,
                    start_index: request.start_index,
                });
                let scripted = self.next_scripted();
                let Scripted::Directory {
                    entries,
                    page_bytes,
                } = scripted
                else {
                    let Scripted::Reply(response) = scripted else {
                        panic!("scripted read answer for a directory read")
                    };
                    return response;
                };
                let (payload, next_index) = encode_directory_entries_chunk(
                    &entries,
                    usize::try_from(request.start_index).unwrap(),
                    page_bytes.min(request.buffer.length as usize),
                )
                .expect("directory entries must encode");
                self.buffers
                    .write(request.buffer.slot_index, &payload)
                    .unwrap();
                if next_index.is_some() {
                    // The guest asks again from the continuation index, so keep answering.
                    self.script.lock().unwrap().push_front(Scripted::Directory {
                        entries,
                        page_bytes,
                    });
                }
                FileResponse::ReadDirectory(ReadDirectoryResponse {
                    length: u32::try_from(payload.len()).unwrap(),
                    next_index,
                })
            }
            FileRequest::PathStatus(request) => {
                self.record(Call::PathStatus {
                    path: self.staged_path(request.path),
                    user: request.user,
                });
                self.reply()
            }
            FileRequest::Unlink(request) => {
                self.record(Call::Unlink {
                    path: self.staged_path(request.path),
                    user: request.user,
                });
                self.reply()
            }
            FileRequest::Rmdir(request) => {
                self.record(Call::Rmdir {
                    path: self.staged_path(request.path),
                    user: request.user,
                });
                self.reply()
            }
            request => panic!("unscripted file request: {request:?}"),
        }
    }

    fn reply(&self) -> FileResponse {
        match self.next_scripted() {
            Scripted::Reply(response) => response,
            Scripted::Read(_) | Scripted::Directory { .. } => {
                panic!("scripted payload answer for a request that carries none")
            }
        }
    }
}

/// The local end of the scripted broker connection.
struct ScriptedChannel(Arc<ScriptedBroker>);

impl LocalSetupChannel for ScriptedChannel {
    type Error = core::convert::Infallible;

    fn send_handshake_request(
        &mut self,
        request: &BrokerHandshakeRequest,
    ) -> Result<(), Self::Error> {
        assert_eq!(request.protocol_version, BROKER_PROTOCOL_VERSION);
        Ok(())
    }

    fn recv_handshake_response(&mut self) -> Result<Option<BrokerHandshakeResponse>, Self::Error> {
        Ok(Some(BrokerHandshakeResponse::Negotiated {
            broker_protocol_version: BROKER_PROTOCOL_VERSION,
        }))
    }
}

impl LocalCallChannel for ScriptedChannel {
    type Error = core::convert::Infallible;

    fn call(&self, request: BrokerRequest) -> Result<BrokerResponse, Self::Error> {
        let result = match request.operation {
            BrokerOperation::File(file) => BrokerResult::File(self.0.file_response(file)),
            BrokerOperation::CloseObject(handle) => {
                self.0.record(Call::Close(handle));
                BrokerResult::ObjectClosed
            }
            operation => panic!("unscripted broker operation: {operation:?}"),
        };
        Ok(BrokerResponse {
            request_id: request.request_id,
            result,
        })
    }
}

/// Shared memory backed by an ordinary allocation, since no peer process observes it.
struct TestSharedMemory(Mutex<Vec<u8>>);

impl TestSharedMemory {
    fn new() -> Self {
        Self(Mutex::new(vec![0; SHARED_BUFFER_POOL_SIZE]))
    }
}

impl SharedMemory for TestSharedMemory {
    fn len(&self) -> usize {
        SHARED_BUFFER_POOL_SIZE
    }

    fn read(&self, offset: usize, destination: &mut [u8]) -> Result<(), SharedMemoryError> {
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

    fn write(&self, offset: usize, source: &[u8]) -> Result<(), SharedMemoryError> {
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

/// Build a LiteBox whose broker answers from `script`.
fn scripted_fs(
    script: impl IntoIterator<Item = Scripted>,
) -> (Arc<ScriptedBroker>, crate::LiteBox<MockPlatform>) {
    let broker = ScriptedBroker::new(script);
    let memory = Arc::clone(broker.buffers.memory());
    let (local, ()) = BrokerLocal::negotiate(ScriptedChannel(Arc::clone(&broker)), |channel| {
        Ok((channel, memory as Arc<dyn SharedMemory>, ()))
    })
    .unwrap();
    (
        broker,
        crate::LiteBox::new_with_broker_local(MockPlatform::new(), local),
    )
}

fn opened() -> Scripted {
    Scripted::Reply(FileResponse::Open(OpenFileResponse {
        handle: FILE_HANDLE,
    }))
}

fn user(context: &Context) -> FileUser {
    FileUser {
        user: context.acting_user().user,
        group: context.acting_user().group,
    }
}

#[test]
fn context_resolves_paths_against_the_cwd() {
    let mut context = Context::new();
    assert_eq!(context.cwd().to_string(), "/");
    assert_eq!(context.resolve("a/b/../c").unwrap().to_string(), "/a/c");

    context.set_cwd(context.resolve("/work/dir").unwrap());
    assert_eq!(context.cwd().to_string(), "/work/dir");
    assert_eq!(
        context.resolve("./file").unwrap().to_string(),
        "/work/dir/file"
    );
    assert_eq!(
        context.resolve("../file").unwrap().to_string(),
        "/work/file"
    );
    assert_eq!(
        context.resolve("/etc//passwd").unwrap().to_string(),
        "/etc/passwd"
    );
}

#[test]
fn open_sends_the_resolved_path_and_translated_flags() {
    let mut context = Context::new();
    context.set_cwd(context.resolve("/work").unwrap());
    context.set_acting_user(UserInfo { user: 7, group: 9 });
    let (broker, fs) = scripted_fs([opened()]);

    let fd = fs
        .open_file(
            &context,
            "sub/../file.txt",
            OFlags::CREAT | OFlags::WRONLY | OFlags::APPEND,
            Mode::RWXU,
        )
        .expect("open should succeed");

    assert_eq!(
        *broker.calls(),
        vec![Call::Open {
            path: String::from("/work/file.txt"),
            user: FileUser { user: 7, group: 9 },
            access: FileAccessMode::WriteOnly,
            flags: FileOpenFlags::CREATE | FileOpenFlags::APPEND,
            mode: FileMode::from_bits(0o700).unwrap(),
        }]
    );
    fs.close_file(&fd).expect("close should succeed");
}

#[test]
fn read_and_write_transfer_payloads_through_the_broker() {
    let context = Context::new();
    let (broker, fs) = scripted_fs([
        opened(),
        Scripted::Reply(FileResponse::Write(WriteFileResponse { written: 5 })),
        Scripted::Read(b"broker".to_vec()),
        Scripted::Reply(FileResponse::Seek(SeekFileResponse { offset: 3 })),
    ]);

    let fd = fs
        .open_file(&context, "/file", OFlags::RDWR, Mode::empty())
        .expect("open should succeed");

    assert_eq!(fs.write_file(&fd, b"hello", None).unwrap(), 5);

    let mut buffer = vec![0; 16];
    let read = fs.read_file(&fd, &mut buffer, Some(2)).unwrap();
    assert_eq!(&buffer[..read], b"broker");

    assert_eq!(fs.seek_file(&fd, -3, SeekWhence::RelativeToEnd).unwrap(), 3);
    fs.close_file(&fd).expect("close should succeed");

    let calls = broker.calls();
    assert_eq!(
        calls[1],
        Call::Write {
            handle: FILE_HANDLE,
            data: b"hello".to_vec(),
            offset: None,
        }
    );
    assert_eq!(
        calls[2],
        Call::Read {
            handle: FILE_HANDLE,
            length: 16,
            offset: Some(2),
        }
    );
    assert_eq!(
        calls[3],
        Call::Seek {
            handle: FILE_HANDLE,
            offset: -3,
            whence: FileSeekWhence::End,
        }
    );
    assert_eq!(calls[4], Call::Close(FILE_HANDLE));
}

#[test]
fn closing_releases_the_broker_object_and_the_descriptor() {
    let context = Context::new();
    let (broker, fs) = scripted_fs([opened()]);

    let fd = fs
        .open_file(&context, "/file", OFlags::RDONLY, Mode::empty())
        .expect("open should succeed");
    fs.close_file(&fd).expect("close should succeed");
    assert_eq!(broker.calls()[1], Call::Close(FILE_HANDLE));

    // The descriptor no longer names a broker file, so operations on it report a closed fd
    // instead of reaching the broker.
    let mut buffer = [0; 4];
    assert!(matches!(
        fs.read_file(&fd, &mut buffer, None),
        Err(ReadError::ClosedFd)
    ));
    assert!(matches!(
        fs.write_file(&fd, b"x", None),
        Err(WriteError::ClosedFd)
    ));
    assert_eq!(broker.calls().len(), 2);
}

#[test]
fn path_status_converts_broker_values() {
    let context = Context::new();
    let (broker, fs) = scripted_fs([Scripted::Reply(FileResponse::PathStatus(
        BrokerFileStatus {
            file_type: BrokerFileType::CharacterDevice,
            mode: FileMode::from_bits(0o644).unwrap(),
            size: 12,
            owner: FileUser { user: 1, group: 2 },
            node_info: FileNodeInfo {
                dev: 3,
                ino: 4,
                rdev: Some(5),
            },
            block_size: 4096,
        },
    ))]);

    let status = fs
        .path_file_status(&context, "/dev/null")
        .expect("status should succeed");

    assert_eq!(status.file_type, FileType::CharacterDevice);
    assert_eq!(status.mode, Mode::from_bits(0o644).unwrap());
    assert_eq!(status.size, 12);
    assert_eq!(status.owner.user, 1);
    assert_eq!(status.owner.group, 2);
    assert_eq!(status.node_info.dev, 3);
    assert_eq!(status.node_info.ino, 4);
    assert_eq!(
        status.node_info.rdev.map(core::num::NonZeroUsize::get),
        Some(5)
    );
    assert_eq!(status.blksize, 4096);
    assert_eq!(
        *broker.calls(),
        vec![Call::PathStatus {
            path: String::from("/dev/null"),
            user: user(&context),
        }]
    );
}

#[test]
fn read_dir_reassembles_paged_broker_entries() {
    let context = Context::new();
    let entries = vec![
        FileDirectoryEntry {
            name: String::from("one"),
            file_type: BrokerFileType::RegularFile,
            node_info: Some(FileNodeInfo {
                dev: 1,
                ino: 2,
                rdev: None,
            }),
        },
        FileDirectoryEntry {
            name: String::from("two"),
            file_type: BrokerFileType::Directory,
            node_info: None,
        },
    ];
    // A page that holds one entry, so the guest has to follow the continuation index.
    let page_bytes =
        encode_directory_entries_chunk(&entries[..1], 0, MAX_FILE_TRANSFER_SIZE as usize)
            .unwrap()
            .0
            .len();
    let (broker, fs) = scripted_fs([
        opened(),
        Scripted::Directory {
            entries,
            page_bytes,
        },
    ]);

    let fd = fs
        .open_file(
            &context,
            "/dir",
            OFlags::RDONLY | OFlags::DIRECTORY,
            Mode::empty(),
        )
        .expect("open should succeed");
    let entries = fs
        .read_file_directory(&fd)
        .expect("read_dir should succeed");
    fs.close_file(&fd).expect("close should succeed");

    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].name, "one");
    assert_eq!(entries[0].file_type, FileType::RegularFile);
    assert_eq!(entries[0].ino_info.as_ref().map(|node| node.ino), Some(2));
    assert_eq!(entries[1].name, "two");
    assert_eq!(entries[1].file_type, FileType::Directory);
    assert!(entries[1].ino_info.is_none());

    let calls = broker.calls();
    assert_eq!(
        calls[1],
        Call::ReadDirectory {
            handle: FILE_HANDLE,
            start_index: 0,
        }
    );
    assert_eq!(
        calls[2],
        Call::ReadDirectory {
            handle: FILE_HANDLE,
            start_index: 1,
        }
    );
}

#[test]
fn broker_file_errors_map_to_guest_errors() {
    let context = Context::new();
    let (broker, fs) = scripted_fs([
        Scripted::Reply(FileResponse::Failed(FileError::NoSuchFileOrDirectory)),
        Scripted::Reply(FileResponse::Failed(FileError::AccessNotAllowed)),
        Scripted::Reply(FileResponse::Failed(FileError::NoWritePermissions)),
        Scripted::Reply(FileResponse::Failed(FileError::NotEmpty)),
        opened(),
        Scripted::Reply(FileResponse::Failed(FileError::NotForReading)),
        Scripted::Reply(FileResponse::Failed(FileError::NotDirectory)),
    ]);

    assert!(matches!(
        fs.open_file(&context, "/missing", OFlags::RDONLY, Mode::empty()),
        Err(OpenError::PathError(PathError::NoSuchFileOrDirectory))
    ));
    assert!(matches!(
        fs.open_file(&context, "/secret", OFlags::RDONLY, Mode::empty()),
        Err(OpenError::AccessNotAllowed)
    ));
    assert!(matches!(
        fs.unlink_file(&context, "/locked/file"),
        Err(UnlinkError::NoWritePerms)
    ));
    assert!(matches!(
        fs.rmdir_file(&context, "/full"),
        Err(RmdirError::NotEmpty)
    ));

    let fd = fs
        .open_file(&context, "/file", OFlags::WRONLY, Mode::empty())
        .expect("open should succeed");
    let mut buffer = [0; 4];
    assert!(matches!(
        fs.read_file(&fd, &mut buffer, None),
        Err(ReadError::NotForReading)
    ));
    assert!(matches!(
        fs.read_file_directory(&fd),
        Err(ReadDirError::NotADirectory)
    ));
    fs.close_file(&fd).expect("close should succeed");

    assert_eq!(broker.calls().len(), 8);
}
