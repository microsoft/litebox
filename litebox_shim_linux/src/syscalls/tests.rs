// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use litebox::fs::{Mode, OFlags};
use litebox_broker_core::{
    AssociationCancellation, BrokerCore, BrokerError, BrokerSession, CallerCredential,
    ObjectRights, PolicyEngine, SessionId,
    random::{RandomProvider, RandomProviderError},
    readiness::ReadinessRegistration,
    socket::{PlatformSocket, SocketProvider},
    stdio::{StdioProvider, StdioProviderError},
};
use litebox_broker_local::BrokerLocal;
use litebox_broker_protocol::{
    BROKER_PROTOCOL_VERSION,
    message::{
        BrokerHandshakeRequest, BrokerHandshakeResponse, BrokerOperation, BrokerRequest,
        BrokerResponse, BrokerResult, PipeRequest, PipeResponse, StdioRequest, StdioResponse,
    },
    pipe::{CreatePipeResponse, ReadPipeResponse, WritePipeResponse},
    shared_buffer::{SHARED_BUFFER_LAYOUT, SHARED_BUFFER_POOL_SIZE},
    socket::CreateSocketRequest,
    stdio::{IsTerminalStdioResponse, StdioOutputStream, StdioStream},
};
use litebox_broker_transport::{
    channel::{LocalCallChannel, LocalSetupChannel},
    shared_memory::{SharedBufferPool, SharedMemory, SharedMemoryError},
};
use litebox_common_linux::{AtFlags, EfdFlags, FcntlArg, FileDescriptorFlags, errno::Errno};
use zerocopy::FromBytes as _;

use crate::UserPtrMut;

use litebox::shim::{Exception, ExceptionInfo};
use litebox_common_linux::PtRegs;
#[cfg(target_arch = "x86_64")]
use litebox_common_linux::signal::FPE_INTDIV;
use litebox_common_linux::signal::{ILL_ILLOPN, SI_KERNEL, SiginfoData, Signal};

extern crate std;

const TEST_TAR_FILE: &[u8] = include_bytes!("../../../litebox/src/fs/test.tar");

/// The concrete platform used by the shim's unit tests.
///
/// This is selected by the build target so the tests can run against whichever
/// userland platform matches the host (Linux or Windows) rather than being
/// hard-wired to one.
#[cfg(target_os = "linux")]
pub(crate) use litebox_platform_linux_userland::LinuxUserland as TestPlatform;
#[cfg(target_os = "windows")]
pub(crate) use litebox_platform_windows_userland::WindowsUserland as TestPlatform;

/// Returns the process-wide test platform, initializing it once.
pub(crate) fn test_platform() -> &'static TestPlatform {
    static PLATFORM: std::sync::OnceLock<&'static TestPlatform> = std::sync::OnceLock::new();
    PLATFORM.get_or_init(TestPlatform::new)
}

fn test_broker() -> &'static BrokerCore {
    static BROKER: std::sync::OnceLock<BrokerCore> = std::sync::OnceLock::new();
    BROKER.get_or_init(|| {
        BrokerCore::new(
            PolicyEngine::with_unauthenticated_rights(ObjectRights::all()),
            alloc::sync::Arc::new(PipeOnlySocketProvider),
            alloc::sync::Arc::new(UnusedRandomProvider),
            alloc::sync::Arc::new(TestStdioProvider),
        )
        .unwrap()
    })
}

struct TestStdioProvider;

impl StdioProvider for TestStdioProvider {
    fn read(
        &self,
        _cancellation: &AssociationCancellation,
        _output: &mut [u8],
    ) -> core::result::Result<usize, StdioProviderError> {
        Err(StdioProviderError::Unsupported)
    }

    fn write(
        &self,
        _cancellation: &AssociationCancellation,
        _stream: StdioOutputStream,
        _input: &[u8],
    ) -> core::result::Result<usize, StdioProviderError> {
        Err(StdioProviderError::Unsupported)
    }

    fn is_terminal(&self, stream: StdioStream) -> core::result::Result<bool, StdioProviderError> {
        Ok(stream == StdioStream::Stdout)
    }
}

#[must_use]
pub(crate) fn init_platform() -> crate::Task<TestPlatform> {
    let platform = test_platform();

    init_platform_with_builder(crate::LinuxShimBuilder::new(platform))
}

#[must_use]
pub(crate) fn init_platform_with_pipe_broker() -> crate::Task<TestPlatform> {
    let platform = test_platform();
    let setup = PipeBrokerSetup::new();
    let (broker_local, ()) = BrokerLocal::negotiate(setup, |setup| {
        let memory: alloc::sync::Arc<dyn SharedMemory> = setup.memory.clone();
        Ok((setup.activate(), memory, ()))
    })
    .unwrap();
    let litebox = litebox::LiteBox::new_with_broker_local(platform, broker_local);
    init_platform_with_builder(crate::LinuxShimBuilder::new_with_litebox(platform, litebox))
}

fn init_platform_with_builder(
    shim_builder: crate::LinuxShimBuilder<TestPlatform>,
) -> crate::Task<TestPlatform> {
    let in_mem = litebox::fs::in_mem::InMem::new_initialized([(
        "/",
        litebox::fs::in_mem::InitialNode::Directory {
            mode: Mode::RWXU | Mode::RWXG | Mode::RWXO,
            owner: litebox::fs::UserInfo::ROOT,
        },
    )]);
    let fs = alloc::sync::Arc::new(shim_builder.default_fs(in_mem, TEST_TAR_FILE.into()));
    shim_builder.build().0.new_test_task(fs)
}

struct PipeBrokerSetup {
    memory: alloc::sync::Arc<TestSharedMemory>,
    session: BrokerSession,
}

impl PipeBrokerSetup {
    fn new() -> Self {
        Self {
            memory: alloc::sync::Arc::new(TestSharedMemory::new()),
            session: test_broker()
                .create_session(CallerCredential::Unauthenticated)
                .unwrap(),
        }
    }

    fn activate(self) -> PipeBrokerChannel {
        let shared_buffers = SharedBufferPool::new(self.memory, SHARED_BUFFER_LAYOUT).unwrap();
        PipeBrokerChannel {
            session: self.session,
            shared_buffers,
        }
    }
}

impl LocalSetupChannel for PipeBrokerSetup {
    type Error = core::convert::Infallible;

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

struct PipeBrokerChannel {
    session: BrokerSession,
    shared_buffers: SharedBufferPool<alloc::sync::Arc<TestSharedMemory>>,
}

impl PipeBrokerChannel {
    fn execute(&self, operation: BrokerOperation) -> litebox_broker_core::Result<BrokerResult> {
        match operation {
            BrokerOperation::CloseObject(handle) => self
                .session
                .close_object_reference(handle)
                .map(|()| BrokerResult::ObjectClosed),
            BrokerOperation::CheckReadiness(handle) => self
                .session
                .check_readiness(handle)
                .map(BrokerResult::Readiness),
            BrokerOperation::Pipe(PipeRequest::Create(request)) => {
                litebox_broker_core::pipe::create(
                    &self.session,
                    request.capacity,
                    request.atomic_write_size,
                )
                .map(|(read_handle, write_handle)| {
                    BrokerResult::Pipe(PipeResponse::Create(CreatePipeResponse {
                        read_handle,
                        write_handle,
                    }))
                })
            }
            BrokerOperation::Pipe(PipeRequest::Read(request)) => {
                let data = litebox_broker_core::pipe::read(
                    &self.session,
                    request.handle,
                    request.buffer.length,
                )?;
                self.shared_buffers
                    .write(request.buffer.slot_index, &data)
                    .expect("pipe broker read must use a valid shared buffer");
                Ok(BrokerResult::Pipe(PipeResponse::Read(ReadPipeResponse {
                    read: u32::try_from(data.len()).unwrap(),
                })))
            }
            BrokerOperation::Pipe(PipeRequest::Write(request)) => {
                let mut data = std::vec![0; request.buffer.length as usize];
                self.shared_buffers
                    .read(request.buffer.slot_index, &mut data)
                    .expect("pipe broker write must use a valid shared buffer");
                litebox_broker_core::pipe::write(&self.session, request.handle, &data).map(
                    |written| {
                        BrokerResult::Pipe(PipeResponse::Write(WritePipeResponse {
                            written: u32::try_from(written).unwrap(),
                        }))
                    },
                )
            }
            BrokerOperation::Stdio(StdioRequest::IsTerminal(request)) => {
                litebox_broker_core::stdio::is_terminal(&self.session, request.stream).map(
                    |is_terminal| {
                        BrokerResult::Stdio(StdioResponse::IsTerminal(IsTerminalStdioResponse {
                            is_terminal,
                        }))
                    },
                )
            }
            operation => panic!("unexpected pipe test broker operation: {operation:?}"),
        }
    }
}

impl LocalCallChannel for PipeBrokerChannel {
    type Error = core::convert::Infallible;

    fn call(&self, request: BrokerRequest) -> core::result::Result<BrokerResponse, Self::Error> {
        let result = self
            .execute(request.operation)
            .unwrap_or_else(|error| BrokerResult::Error(error.into()));
        Ok(BrokerResponse {
            request_id: request.request_id,
            result,
        })
    }
}

struct TestSharedMemory(std::sync::Mutex<std::vec::Vec<u8>>);

impl TestSharedMemory {
    fn new() -> Self {
        Self(std::sync::Mutex::new(std::vec![
            0;
            SHARED_BUFFER_POOL_SIZE
        ]))
    }
}

impl SharedMemory for TestSharedMemory {
    fn len(&self) -> usize {
        SHARED_BUFFER_POOL_SIZE
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
        let source = memory
            .get(offset..end)
            .ok_or(SharedMemoryError::InvalidRange)?;
        destination.copy_from_slice(source);
        Ok(())
    }

    fn write(&self, offset: usize, source: &[u8]) -> core::result::Result<(), SharedMemoryError> {
        let mut memory = self.0.lock().unwrap();
        let end = offset
            .checked_add(source.len())
            .ok_or(SharedMemoryError::InvalidRange)?;
        let destination = memory
            .get_mut(offset..end)
            .ok_or(SharedMemoryError::InvalidRange)?;
        destination.copy_from_slice(source);
        Ok(())
    }
}

struct PipeOnlySocketProvider;

impl SocketProvider for PipeOnlySocketProvider {
    fn create(
        &self,
        _session_id: SessionId,
        _request: CreateSocketRequest,
        _readiness: ReadinessRegistration,
    ) -> litebox_broker_core::Result<alloc::sync::Arc<dyn PlatformSocket>> {
        Err(BrokerError::UnsupportedOperation)
    }

    fn close_session(&self, _session_id: SessionId) {}
}

struct UnusedRandomProvider;

impl RandomProvider for UnusedRandomProvider {
    fn fill(&self, _output: &mut [u8]) -> core::result::Result<(), RandomProviderError> {
        Err(RandomProviderError)
    }
}

#[cfg(target_arch = "x86_64")]
#[test]
fn exceptions_queue_their_corresponding_signals() {
    const FAULT_PC: usize = 0x4444_0000;

    let task = init_platform();
    let ctx = PtRegs {
        rip: FAULT_PC,
        ..Default::default()
    };

    for (exception, signal, code, addr) in [
        (
            Exception::DIVIDE_ERROR,
            Signal::SIGFPE,
            FPE_INTDIV,
            FAULT_PC,
        ),
        (Exception::BREAKPOINT, Signal::SIGTRAP, SI_KERNEL, 0),
        (
            Exception::INVALID_OPCODE,
            Signal::SIGILL,
            ILL_ILLOPN,
            FAULT_PC,
        ),
    ] {
        task.handle_exception_request(
            &ExceptionInfo {
                exception,
                error_code: 0,
                cr2: 0,
                kernel_mode: false,
            },
            &ctx,
        );

        let siginfo = task.take_pending_siginfo(signal);
        assert_eq!(siginfo.code, code);
        let actual_data = siginfo.data.pad;
        let expected_data = SiginfoData::new_addr(addr).pad;
        assert_eq!(actual_data, expected_data);
    }
}

#[cfg(target_arch = "aarch64")]
#[test]
fn exceptions_queue_their_corresponding_signals() {
    const FAULT_PC: usize = 0x4444_0000;
    const FAULT_ADDRESS: usize = 0x5555_0000;

    let task = init_platform();
    let ctx = PtRegs {
        pc: FAULT_PC,
        ..Default::default()
    };

    for (exception, signal, code, addr) in [
        (Exception::BRK64, Signal::SIGTRAP, SI_KERNEL, 0),
        (
            Exception::INSTRUCTION_ABORT_LOWER_EL,
            Signal::SIGILL,
            ILL_ILLOPN,
            FAULT_PC,
        ),
        (
            Exception::DATA_ABORT_LOWER_EL,
            Signal::SIGSEGV,
            SI_KERNEL,
            FAULT_ADDRESS,
        ),
    ] {
        task.handle_exception_request(
            &ExceptionInfo {
                exception,
                fault_address: FAULT_ADDRESS,
                esr: u64::from(exception.0) << 26,
                kernel_mode: false,
            },
            &ctx,
        );

        let siginfo = task.take_pending_siginfo(signal);
        assert_eq!(siginfo.code, code);
        let actual_data = siginfo.data.pad;
        let expected_data = SiginfoData::new_addr(addr).pad;
        assert_eq!(actual_data, expected_data);
    }
}

#[test]
fn test_fcntl() {
    let task = init_platform_with_pipe_broker();

    let check = |fd: i32, flags1: OFlags, flags2: OFlags| {
        assert_eq!(
            task.sys_fcntl(fd, FcntlArg::GETFD).unwrap(),
            FileDescriptorFlags::FD_CLOEXEC.bits()
        );

        assert_eq!(task.sys_fcntl(fd, FcntlArg::GETFL).unwrap(), flags1.bits());

        task.sys_fcntl(fd, FcntlArg::SETFD(FileDescriptorFlags::empty()))
            .unwrap();
        assert_eq!(task.sys_fcntl(fd, FcntlArg::GETFD).unwrap(), 0);

        // OFlags::RDWR should be ignored
        task.sys_fcntl(fd, FcntlArg::SETFL(OFlags::RDWR)).unwrap();
        assert_eq!(task.sys_fcntl(fd, FcntlArg::GETFL).unwrap(), flags2.bits());
    };

    // Test pipe
    let (read_fd, write_fd) = task
        .sys_pipe2(OFlags::CLOEXEC | OFlags::NONBLOCK)
        .expect("Failed to create pipe");
    let read_fd = i32::try_from(read_fd).unwrap();
    check(read_fd, OFlags::RDONLY | OFlags::NONBLOCK, OFlags::RDONLY);
    let write_fd = i32::try_from(write_fd).unwrap();
    check(write_fd, OFlags::WRONLY | OFlags::NONBLOCK, OFlags::WRONLY);

    // Eventfd requires broker control in this shim configuration.
    let brokerless_task = init_platform();
    assert_eq!(
        brokerless_task.sys_eventfd2(
            0,
            EfdFlags::CLOEXEC | EfdFlags::SEMAPHORE | EfdFlags::NONBLOCK,
        ),
        Err(Errno::EIO)
    );

    // Test fcntl with DUPFD
    let fd = task
        .sys_open("/dev/stdin", OFlags::RDONLY, Mode::empty())
        .unwrap();
    let fd = i32::try_from(fd).unwrap();

    let min_fd = fd + 10;
    let duplicated = task
        .sys_fcntl(
            fd,
            FcntlArg::DUPFD {
                cloexec: false,
                min_fd: u32::try_from(min_fd).unwrap(),
            },
        )
        .unwrap();
    let duplicated = i32::try_from(duplicated).unwrap();

    assert_eq!(duplicated, min_fd);
}

#[test]
fn test_pipe2_requires_broker() {
    let task = init_platform();

    assert_eq!(task.sys_pipe2(OFlags::empty()), Err(Errno::EIO));
}

#[test]
fn test_pipe2_race_with_concurrent_close() {
    let task = init_platform_with_pipe_broker();
    task.files.borrow().set_max_fd(4);

    let stop = alloc::sync::Arc::new(core::sync::atomic::AtomicBool::new(false));
    let stop_closer = stop.clone();
    let closer = task.spawn_clone_for_test(move |task| {
        while !stop_closer.load(core::sync::atomic::Ordering::Relaxed) {
            let _ = task.sys_close(3);
        }
    });

    for iter in 0..50_000 {
        assert_eq!(
            task.sys_pipe2(OFlags::empty()),
            Err(Errno::EMFILE),
            "failed at iteration {iter}"
        );
    }

    stop.store(true, core::sync::atomic::Ordering::Relaxed);
    closer.join().unwrap();
}

#[test]
fn test_dup() {
    let task = init_platform();

    let fd = task
        .sys_open("/dev/stdin", OFlags::RDONLY, Mode::empty())
        .unwrap();
    let fd = i32::try_from(fd).unwrap();
    // test dup
    let fd2 = task.sys_dup(fd, None, None).unwrap();
    let fd2 = i32::try_from(fd2).unwrap();
    assert_eq!(fd + 1, fd2);

    // test dup2
    let fd3 = task.sys_dup(fd2, Some(fd2 + 10), None).unwrap();
    let fd3 = i32::try_from(fd3).unwrap();
    assert_eq!(fd2 + 10, fd3);

    // test dup3
    assert_eq!(
        task.sys_dup(fd3, Some(fd3), Some(OFlags::CLOEXEC)),
        Err(Errno::EINVAL)
    );
    let fd4 = task
        .sys_dup(fd2, Some(fd2 + 10), Some(OFlags::CLOEXEC))
        .unwrap();
    let fd4 = i32::try_from(fd4).unwrap();
    assert_eq!(fd2 + 10, fd4);
}

// Note the test was generated by copilot with minor fixes.
#[test]
fn test_getdent64() {
    let task = init_platform();

    // Create test files in root directory for testing
    let file1_fd = task
        .sys_open(
            "/test_file1.txt",
            OFlags::CREAT | OFlags::WRONLY,
            Mode::RUSR | Mode::WUSR,
        )
        .expect("Failed to create test_file1.txt");
    task.sys_close(file1_fd.try_into().unwrap())
        .expect("Failed to close test_file1.txt");

    let file2_fd = task
        .sys_open(
            "/test_file2.txt",
            OFlags::CREAT | OFlags::WRONLY,
            Mode::RUSR | Mode::WUSR,
        )
        .expect("Failed to create test_file2.txt");
    task.sys_close(file2_fd.try_into().unwrap())
        .expect("Failed to close test_file2.txt");

    // Open the root directory for testing
    let dir_fd = task
        .sys_open("/", OFlags::RDONLY, Mode::empty())
        .expect("Failed to open root directory");
    let dir_fd = dir_fd.try_into().unwrap();

    // Test 1: Basic functionality - read directory entries
    let mut buffer = alloc::vec![0u8; 4096];
    let bytes_read = task
        .sys_getdirent64(
            dir_fd,
            UserPtrMut::from_usize(buffer.as_mut_ptr() as usize),
            buffer.len(),
        )
        .expect("Failed to read directory entries");

    assert!(bytes_read > 0, "Should have read some directory entries");
    assert!(
        bytes_read <= buffer.len(),
        "Should not read more than buffer size"
    );

    // Parse the returned entries to verify they are correct
    let mut offset = 0;
    let mut found_entries = alloc::vec::Vec::new();

    while offset < bytes_read {
        let (dirent, _) =
            litebox_common_linux::LinuxDirent64::read_from_prefix(&buffer[offset..]).unwrap();

        // Validate the entry length
        assert!(dirent.len > 0, "Directory entry length must be positive");
        assert!(
            offset + dirent.len as usize <= bytes_read,
            "Entry should not exceed buffer"
        );

        let name_bytes = {
            let start = offset + core::mem::offset_of!(litebox_common_linux::LinuxDirent64, __name);
            let end = offset + dirent.len as usize;
            &buffer[start..end]
        };

        // Find the null terminator
        let null_pos = name_bytes
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(name_bytes.len());
        let name =
            core::str::from_utf8(&name_bytes[..null_pos]).expect("Invalid UTF-8 in filename");

        found_entries.push((alloc::string::String::from(name), dirent.typ, dirent.ino));
        offset += dirent.len as usize;
    }

    assert!(
        !found_entries.is_empty(),
        "Should find at least some directory entries"
    );

    // Check that our test files appear in the directory listing
    let mut entry_names: alloc::vec::Vec<alloc::string::String> = found_entries
        .iter()
        .map(|(name, _, _)| name.clone())
        .collect();
    entry_names.sort();
    assert_eq!(
        entry_names,
        alloc::vec![
            ".",
            "..",
            "bar",
            "dev",
            "foo",
            "test_file1.txt",
            "test_file2.txt"
        ]
    );

    // Verify that our test files have the correct type (regular file)
    for (name, typ, _) in &found_entries {
        if name == "test_file1.txt" || name == "test_file2.txt" {
            assert_eq!(
                *typ,
                litebox_common_linux::DirentType::Regular as u8,
                "Test files should have Regular type"
            );
        }
    }

    assert_eq!(
        task.sys_getdirent64(
            dir_fd,
            UserPtrMut::from_usize(buffer.as_mut_ptr() as usize),
            buffer.len()
        )
        .expect("Failed to read directory entries"),
        0,
        "should have read all entries in the previous call"
    );
    task.sys_close(dir_fd).expect("Failed to close directory");

    // Test 2: Small buffer (should handle partial reads gracefully)
    let dir_fd = task
        .sys_open("/", OFlags::RDONLY, Mode::empty())
        .expect("Failed to open root directory");
    let dir_fd = dir_fd.try_into().unwrap();
    let mut small_buffer = [0u8; 64];
    let bytes = task
        .sys_getdirent64(
            dir_fd,
            UserPtrMut::from_usize(small_buffer.as_mut_ptr() as usize),
            small_buffer.len(),
        )
        .expect("Failed to read directory entries");

    // Should either succeed with partial data or return 0 if no entry fits
    assert!(bytes <= small_buffer.len(), "Should not exceed buffer size");
    // If bytes > 0, verify the structure is valid
    if bytes > 0 {
        let (dirent, _) =
            litebox_common_linux::LinuxDirent64::read_from_prefix(&small_buffer[..bytes]).unwrap();
        assert!(
            dirent.len as usize <= bytes,
            "First entry length should fit in returned bytes"
        );
        assert!(dirent.len > 0, "Entry length should be positive");
    }

    // Test 3: Invalid file descriptor
    let result = task.sys_getdirent64(
        -1,
        UserPtrMut::from_usize(buffer.as_mut_ptr() as usize),
        buffer.len(),
    );
    assert_eq!(
        result,
        Err(Errno::EBADF),
        "Should return EBADF for invalid fd"
    );

    // Test 4: File descriptor pointing to a regular file (not a directory)
    let file1_fd = task
        .sys_open("/test_file1.txt", OFlags::RDONLY, Mode::empty())
        .expect("Failed to open test_file1.txt");
    let file1_fd = file1_fd.try_into().unwrap();

    let result = task.sys_getdirent64(
        file1_fd,
        UserPtrMut::from_usize(buffer.as_mut_ptr() as usize),
        buffer.len(),
    );
    assert_eq!(
        result,
        Err(Errno::ENOTDIR),
        "Should return ENOTDIR for non-directory fd"
    );
    task.sys_close(file1_fd).expect("Failed to close file");

    // Test 5: Zero-length buffer
    let result = task.sys_getdirent64(
        dir_fd,
        UserPtrMut::from_usize(buffer.as_mut_ptr() as usize),
        0,
    );
    assert_eq!(
        result,
        Err(Errno::EINVAL),
        "Should return EINVAL for zero-length buffer"
    );

    task.sys_close(dir_fd).expect("Failed to close directory");

    // Test 6: Multiple reads (test directory offset tracking)
    // Reopen directory to reset position
    let dir_fd2 = task
        .sys_open("/", OFlags::RDONLY, Mode::empty())
        .expect("Failed to reopen root directory");
    let dir_fd2 = dir_fd2.try_into().unwrap();

    // Read entries in smaller chunks to test offset tracking
    let mut all_entries = alloc::vec::Vec::new();

    loop {
        let mut chunk_buffer = [0u8; 64];
        let bytes_read = task
            .sys_getdirent64(
                dir_fd2,
                UserPtrMut::from_usize(chunk_buffer.as_mut_ptr() as usize),
                chunk_buffer.len(),
            )
            .expect("Failed to read directory chunk");

        if bytes_read == 0 {
            break; // End of directory
        }

        // Parse entries from this chunk
        let mut offset = 0;
        while offset < bytes_read {
            let (dirent, _) = litebox_common_linux::LinuxDirent64::read_from_prefix(
                &chunk_buffer[offset..bytes_read],
            )
            .unwrap();

            assert!(dirent.len > 0, "Entry length must be positive");
            assert!(
                offset + dirent.len as usize <= bytes_read,
                "Entry should fit in chunk"
            );

            let name_bytes = {
                let start =
                    offset + core::mem::offset_of!(litebox_common_linux::LinuxDirent64, __name);
                let end = offset + dirent.len as usize;
                &chunk_buffer[start..end]
            };

            let null_pos = name_bytes
                .iter()
                .position(|&b| b == 0)
                .unwrap_or(name_bytes.len());
            let name =
                core::str::from_utf8(&name_bytes[..null_pos]).expect("Invalid UTF-8 in filename");

            all_entries.push(alloc::string::String::from(name));
            offset += dirent.len as usize;
        }
    }

    // Verify we still got our expected entries through chunked reading
    all_entries.sort();
    assert_eq!(
        all_entries,
        alloc::vec![
            ".",
            "..",
            "bar",
            "dev",
            "foo",
            "test_file1.txt",
            "test_file2.txt"
        ]
    );
}

#[test]
fn test_umask_behavior() {
    let task = init_platform();

    // 1. Capture original mask without changing final state.
    let orig = task.sys_umask(0).bits(); // sets mask to 0, returns previous
    let _ = task.sys_umask(orig); // restore original

    // We expect the default (from implementation) to be 0o022.
    assert_eq!(orig, 0o022, "Default umask should be 022 (got {orig:03o})");

    // 2. Set a new umask (e.g., 0o077) and verify file creation honors it.
    let prev = task.sys_umask(0o077).bits();
    assert_eq!(prev, orig, "Setting umask should return previous value");

    // Create a file with mode 0o666; with umask 0o077 it should become 0o600.
    let file_mode = Mode::RUSR | Mode::WUSR | Mode::RGRP | Mode::WGRP | Mode::ROTH | Mode::WOTH; // 0o666
    let test_file = "/umask_rs_test_file_perm.txt";
    let fd = task
        .sys_open(test_file, OFlags::CREAT | OFlags::WRONLY, file_mode)
        .expect("Failed to create test file with O_CREAT");
    // Close it (ignore errors)
    let _ = task.sys_close(i32::try_from(fd).unwrap());

    let stat_file = task.sys_stat(test_file).expect("stat failed on test file");
    let actual_file_perm = stat_file.st_mode & 0o777;
    assert_eq!(
        actual_file_perm, 0o600,
        "File permission should respect umask (expected 600 got {actual_file_perm:03o})",
    );

    // 3. Create a directory with mode 0o777; with umask 0o077 should become 0o700.
    let dir_mode = (Mode::RWXU | Mode::RWXG | Mode::RWXO).bits();
    let test_dir = "/umask_rs_test_dir";
    task.sys_mkdirat(litebox_common_linux::AT_FDCWD, test_dir, dir_mode)
        .expect("Failed to create test directory");

    let stat_dir = task
        .sys_stat(test_dir)
        .expect("stat failed on test directory");
    let actual_dir_perm = stat_dir.st_mode & 0o777;
    assert_eq!(
        actual_dir_perm, 0o700,
        "Directory permission should respect umask (expected 700 got {actual_dir_perm:03o})",
    );

    // 4. High bits are ignored: set mask with bits beyond 0o777.
    // Current mask is 0o077; now set 0o1777 -> stored low 9 bits = 0o777.
    let prev2 = task.sys_umask(0o1777).bits();
    assert_eq!(prev2, 0o077, "Returned previous mask should be 077");
    let prev3 = task.sys_umask(0).bits(); // fetch current (0o777) and set to 0
    assert_eq!(
        prev3, 0o777,
        "Only low 9 bits should be retained (expected 777)"
    );
    // Restore to original
    let _ = task.sys_umask(orig);
}

#[test]
fn test_rlimit_nofile() {
    use litebox_common_linux::{Rlimit, RlimitResource, errno::Errno};

    let task = crate::syscalls::tests::init_platform();

    // 1. Get the current NOFILE limit.
    let cur_lim = task
        .do_prlimit(RlimitResource::NOFILE, None)
        .expect("sys_getrlimit(NOFILE) failed");
    assert!(cur_lim.rlim_max >= cur_lim.rlim_cur, "expected max >= cur");

    // 2. Try to raise hard limit by 1 (should be EPERM and not change state).
    let raise = Rlimit {
        rlim_cur: cur_lim.rlim_cur,
        rlim_max: cur_lim.rlim_max.saturating_add(1),
    };
    let err = task
        .do_prlimit(RlimitResource::NOFILE, Some(raise))
        .expect_err("raising NOFILE hard limit should fail");
    assert_eq!(err, Errno::EPERM);

    // 3. Try cur > max (EINVAL).
    let bad_order = Rlimit {
        rlim_cur: cur_lim.rlim_max + 1,
        rlim_max: cur_lim.rlim_max,
    };
    let err = task
        .do_prlimit(RlimitResource::NOFILE, Some(bad_order))
        .expect_err("cur > max should be invalid");
    assert_eq!(err, Errno::EINVAL);

    // 4. Lower soft limit
    let probe_fd = task.sys_dup(0, None, None).expect("probe dup failed");
    let new_lim = Rlimit {
        rlim_cur: probe_fd as usize + 1,
        rlim_max: cur_lim.rlim_max,
    };
    task.do_prlimit(RlimitResource::NOFILE, Some(new_lim))
        .expect("lowering NOFILE cur limit should succeed");
    assert_eq!(
        task.sys_dup(0, None, None)
            .expect_err("dup should fail due to new cur limit"),
        Errno::EMFILE,
    );
    assert_eq!(
        task.sys_open("/prlimit_file", OFlags::CREAT | OFlags::RDONLY, Mode::RWXU)
            .expect_err("open should fail due to new cur limit"),
        Errno::EMFILE,
    );
}

#[test]
fn test_unlinkat() {
    let task = init_platform();

    // 1. Create a regular file and unlink it.
    let file_path = "/unlink_test_file.txt";
    let fd = task
        .sys_open(
            file_path,
            OFlags::CREAT | OFlags::WRONLY,
            Mode::RUSR | Mode::WUSR,
        )
        .expect("Failed to create test file for unlink");
    task.sys_close(i32::try_from(fd).unwrap())
        .expect("Failed to close test file");
    task.sys_unlinkat(0, file_path, AtFlags::empty())
        .expect("unlinkat should succeed on regular file");
    assert_eq!(
        task.sys_stat(file_path),
        Err(Errno::ENOENT),
        "File should no longer exist after unlink"
    );

    // 2. Create a directory and attempt to unlink without AT_REMOVEDIR -> EISDIR.
    let dir_path = "/unlink_dir";
    let dir_mode = (Mode::RWXU | Mode::RWXG | Mode::RWXO).bits();
    task.sys_mkdirat(litebox_common_linux::AT_FDCWD, dir_path, dir_mode)
        .expect("Failed to create directory");
    assert_eq!(
        task.sys_unlinkat(0, dir_path, AtFlags::empty()),
        Err(Errno::EISDIR),
        "Unlinking a directory without AT_REMOVEDIR should return EISDIR"
    );

    // 3. Create a non-empty directory and remove with AT_REMOVEDIR -> ENOTEMPTY.
    let nonempty_dir = "/unlink_dir_nonempty";
    task.sys_mkdirat(litebox_common_linux::AT_FDCWD, nonempty_dir, dir_mode)
        .expect("Failed to create non-empty directory");
    let inner_file_fd = task
        .sys_open(
            "/unlink_dir_nonempty/inner.txt",
            OFlags::CREAT | OFlags::WRONLY,
            Mode::RUSR | Mode::WUSR,
        )
        .expect("Failed to create inner file");
    task.sys_close(i32::try_from(inner_file_fd).unwrap())
        .expect("Failed to close inner file");
    assert_eq!(
        task.sys_unlinkat(0, nonempty_dir, AtFlags::AT_REMOVEDIR),
        Err(Errno::ENOTEMPTY),
        "Removing a non-empty directory with AT_REMOVEDIR should return ENOTEMPTY"
    );

    // 4. Invalid flag combination: AT_REMOVEDIR | (any other flag) -> EINVAL.
    assert_eq!(
        task.sys_unlinkat(
            0,
            dir_path,
            AtFlags::AT_REMOVEDIR | AtFlags::AT_SYMLINK_NOFOLLOW
        ),
        Err(Errno::EINVAL),
        "Invalid extra flags with AT_REMOVEDIR should return EINVAL"
    );

    // 5. Successfully remove previously created empty directory with AT_REMOVEDIR.
    task.sys_unlinkat(0, dir_path, AtFlags::AT_REMOVEDIR)
        .expect("Should remove empty directory with AT_REMOVEDIR");
    assert_eq!(
        task.sys_stat(dir_path),
        Err(Errno::ENOENT),
        "Directory should no longer exist after removal"
    );

    // 6. Create and remove another empty directory to ensure repeatability.
    let empty_dir2 = "/unlink_empty_dir";
    task.sys_mkdirat(litebox_common_linux::AT_FDCWD, empty_dir2, dir_mode)
        .expect("Failed to create second empty directory");
    task.sys_unlinkat(0, empty_dir2, AtFlags::AT_REMOVEDIR)
        .expect("Should remove second empty directory");
    assert_eq!(
        task.sys_stat(empty_dir2),
        Err(Errno::ENOENT),
        "Second directory should no longer exist after removal"
    );
}

/// Regression test for a bug where readers can be permanently starved on
/// platforms where `wake_one` does not report whether it actually woke a thread
/// (e.g. Windows with `WakeByAddressSingle`).
#[test]
fn test_rwlock_readers_not_starved_after_writer_handoff() {
    fn join_with_timeout<T>(
        handle: std::thread::JoinHandle<T>,
        timeout: std::time::Duration,
        thread_name: &str,
    ) -> T {
        let start = std::time::Instant::now();
        while !handle.is_finished() {
            assert!(
                start.elapsed() < timeout,
                "{thread_name} timed out after {timeout:?}"
            );
            std::thread::sleep(std::time::Duration::from_millis(1));
        }

        handle.join().expect("{thread_name} panicked")
    }

    // Initialize the platform (reuses the global Once-based init).
    let _task = init_platform();
    let join_timeout = std::time::Duration::from_secs(5);

    // We run the test many times to increase the probability of hitting the
    // exact interleaving, since we rely on sleep-based synchronization.
    for _ in 0..200 {
        let lock = alloc::sync::Arc::new(litebox::sync::RwLock::<TestPlatform, u32>::new(0));
        // Step 1: W1 acquires the write lock on the main thread.
        let mut w1_guard = lock.write();

        // Step 2: Spawn a reader that will block (READERS_WAITING).
        let lock_r = lock.clone();
        let reader_handle = std::thread::spawn(move || {
            let r = lock_r.read();
            drop(r);
        });

        // Step 3: Spawn W2 that will block (WRITERS_WAITING + other_writers_waiting).
        let lock_w2 = lock.clone();
        let writer_handle = std::thread::spawn(move || {
            let mut w = lock_w2.write();
            *w += 1;
            // Hold briefly so reader stays blocked during our unlock.
            drop(w);
        });

        // Give both threads time to block and set their waiting bits.
        std::thread::sleep(std::time::Duration::from_millis(10));

        // Step 4: W1 unlocks. This triggers wake_writer_or_readers which
        // should eventually lead to both W2 and R being served.
        *w1_guard = 42;
        drop(w1_guard);

        join_with_timeout(writer_handle, join_timeout, "writer");
        join_with_timeout(reader_handle, join_timeout, "reader");
    }
}
