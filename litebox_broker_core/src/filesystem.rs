// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Broker-authoritative filesystem operations.

use alloc::{sync::Arc, vec::Vec};

use litebox_broker_protocol::ObjectHandle;
use litebox_broker_protocol::filesystem::{
    FilesystemDirectoryEntry, FilesystemError, FilesystemFileStatus, FilesystemNamespace,
    FilesystemSeekWhence, FilesystemUser, MAX_FILESYSTEM_TRANSFER_SIZE,
};

use crate::session::{ObjectEntry, ObjectRights};
use crate::{AssociationCancellation, BrokerError, BrokerSession, Result};

type FilesystemResult<T> = core::result::Result<T, FilesystemError>;
type DirectoryPage = (Vec<FilesystemDirectoryEntry>, Option<u64>);

/// Broker-wide filesystem namespace provider.
pub trait FilesystemProvider: Send + Sync {
    /// Opens an absolute path and returns one broker-owned open-file description.
    fn open(
        &self,
        cancellation: &AssociationCancellation,
        namespace: FilesystemNamespace,
        path: &str,
        user: FilesystemUser,
        flags: u32,
        mode: u32,
    ) -> core::result::Result<Arc<dyn OpenFileDescription>, FilesystemError>;

    /// Returns status for an absolute path.
    fn path_status(
        &self,
        cancellation: &AssociationCancellation,
        namespace: FilesystemNamespace,
        path: &str,
        user: FilesystemUser,
    ) -> core::result::Result<FilesystemFileStatus, FilesystemError>;

    /// Changes mode bits for an absolute path.
    fn chmod(
        &self,
        cancellation: &AssociationCancellation,
        namespace: FilesystemNamespace,
        path: &str,
        user: FilesystemUser,
        mode: u32,
    ) -> core::result::Result<(), FilesystemError>;

    /// Changes ownership for an absolute path.
    fn chown(
        &self,
        cancellation: &AssociationCancellation,
        namespace: FilesystemNamespace,
        path: &str,
        acting_user: FilesystemUser,
        user: Option<u16>,
        group: Option<u16>,
    ) -> core::result::Result<(), FilesystemError>;

    /// Removes a file at an absolute path.
    fn unlink(
        &self,
        cancellation: &AssociationCancellation,
        namespace: FilesystemNamespace,
        path: &str,
        user: FilesystemUser,
    ) -> core::result::Result<(), FilesystemError>;

    /// Creates a directory at an absolute path.
    fn mkdir(
        &self,
        cancellation: &AssociationCancellation,
        namespace: FilesystemNamespace,
        path: &str,
        user: FilesystemUser,
        mode: u32,
    ) -> core::result::Result<(), FilesystemError>;

    /// Removes a directory at an absolute path.
    fn rmdir(
        &self,
        cancellation: &AssociationCancellation,
        namespace: FilesystemNamespace,
        path: &str,
        user: FilesystemUser,
    ) -> core::result::Result<(), FilesystemError>;
}

/// Filesystem provider for broker configurations that intentionally expose no filesystem.
pub struct UnsupportedFilesystemProvider;

impl FilesystemProvider for UnsupportedFilesystemProvider {
    fn open(
        &self,
        _cancellation: &AssociationCancellation,
        _namespace: FilesystemNamespace,
        _path: &str,
        _user: FilesystemUser,
        _flags: u32,
        _mode: u32,
    ) -> core::result::Result<Arc<dyn OpenFileDescription>, FilesystemError> {
        Err(FilesystemError::Io)
    }

    fn path_status(
        &self,
        _cancellation: &AssociationCancellation,
        _namespace: FilesystemNamespace,
        _path: &str,
        _user: FilesystemUser,
    ) -> core::result::Result<FilesystemFileStatus, FilesystemError> {
        Err(FilesystemError::Io)
    }

    fn chmod(
        &self,
        _cancellation: &AssociationCancellation,
        _namespace: FilesystemNamespace,
        _path: &str,
        _user: FilesystemUser,
        _mode: u32,
    ) -> core::result::Result<(), FilesystemError> {
        Err(FilesystemError::Io)
    }

    fn chown(
        &self,
        _cancellation: &AssociationCancellation,
        _namespace: FilesystemNamespace,
        _path: &str,
        _acting_user: FilesystemUser,
        _user: Option<u16>,
        _group: Option<u16>,
    ) -> core::result::Result<(), FilesystemError> {
        Err(FilesystemError::Io)
    }

    fn unlink(
        &self,
        _cancellation: &AssociationCancellation,
        _namespace: FilesystemNamespace,
        _path: &str,
        _user: FilesystemUser,
    ) -> core::result::Result<(), FilesystemError> {
        Err(FilesystemError::Io)
    }

    fn mkdir(
        &self,
        _cancellation: &AssociationCancellation,
        _namespace: FilesystemNamespace,
        _path: &str,
        _user: FilesystemUser,
        _mode: u32,
    ) -> core::result::Result<(), FilesystemError> {
        Err(FilesystemError::Io)
    }

    fn rmdir(
        &self,
        _cancellation: &AssociationCancellation,
        _namespace: FilesystemNamespace,
        _path: &str,
        _user: FilesystemUser,
    ) -> core::result::Result<(), FilesystemError> {
        Err(FilesystemError::Io)
    }
}

/// One broker-owned open-file description.
pub trait OpenFileDescription: Send + Sync {
    /// Reads bytes, optionally at an explicit offset.
    fn read(
        &self,
        cancellation: &AssociationCancellation,
        output: &mut [u8],
        offset: Option<u64>,
    ) -> core::result::Result<usize, FilesystemError>;

    /// Writes bytes, optionally at an explicit offset.
    fn write(
        &self,
        cancellation: &AssociationCancellation,
        input: &[u8],
        offset: Option<u64>,
    ) -> core::result::Result<usize, FilesystemError>;

    /// Repositions the shared file offset.
    fn seek(
        &self,
        cancellation: &AssociationCancellation,
        offset: i64,
        whence: FilesystemSeekWhence,
    ) -> core::result::Result<u64, FilesystemError>;

    /// Truncates the open file.
    fn truncate(
        &self,
        cancellation: &AssociationCancellation,
        length: u64,
        reset_offset: bool,
    ) -> core::result::Result<(), FilesystemError>;

    /// Returns one bounded page of directory entries.
    fn read_directory(
        &self,
        cancellation: &AssociationCancellation,
        start_index: u64,
        maximum_encoded_length: usize,
    ) -> core::result::Result<(Vec<FilesystemDirectoryEntry>, Option<u64>), FilesystemError>;

    /// Returns status for the open object.
    fn status(
        &self,
        cancellation: &AssociationCancellation,
    ) -> core::result::Result<FilesystemFileStatus, FilesystemError>;
}

/// Opens a filesystem object and installs its open-file description in the session.
pub fn open(
    session: &BrokerSession,
    namespace: FilesystemNamespace,
    path: &str,
    user: FilesystemUser,
    flags: u32,
    mode: u32,
) -> Result<core::result::Result<ObjectHandle, FilesystemError>> {
    let rights = session
        .core
        .policy
        .principal_object_rights(session.caller_credential)?;
    if !rights.contains(ObjectRights::WAIT | ObjectRights::WRITE) {
        return Err(BrokerError::PolicyDenied);
    }
    let reference = session.reserve_object_reference(rights)?;
    let description = match session.core.filesystem_provider.open(
        &session.cancellation,
        namespace,
        path,
        user,
        flags,
        mode,
    ) {
        Ok(description) => description,
        Err(error) => return Ok(Err(error)),
    };
    reference
        .commit(ObjectEntry::Filesystem(description))
        .map(Ok)
}

/// Reads from a broker-owned open-file description.
pub fn read(
    session: &BrokerSession,
    handle: ObjectHandle,
    output: &mut [u8],
    offset: Option<u64>,
) -> Result<core::result::Result<usize, FilesystemError>> {
    if output.len() > MAX_FILESYSTEM_TRANSFER_SIZE as usize {
        return Err(BrokerError::ResourceExhausted);
    }
    let description = open_file_description(session, handle, ObjectRights::WAIT)?;
    let read = match description.read(&session.cancellation, output, offset) {
        Ok(read) => read,
        Err(error) => return Ok(Err(error)),
    };
    if read > output.len() {
        return Err(BrokerError::Internal);
    }
    Ok(Ok(read))
}

/// Writes to a broker-owned open-file description.
pub fn write(
    session: &BrokerSession,
    handle: ObjectHandle,
    input: &[u8],
    offset: Option<u64>,
) -> Result<core::result::Result<usize, FilesystemError>> {
    if input.len() > MAX_FILESYSTEM_TRANSFER_SIZE as usize {
        return Err(BrokerError::ResourceExhausted);
    }
    let description = open_file_description(session, handle, ObjectRights::WRITE)?;
    let written = match description.write(&session.cancellation, input, offset) {
        Ok(written) => written,
        Err(error) => return Ok(Err(error)),
    };
    if written > input.len() {
        return Err(BrokerError::Internal);
    }
    Ok(Ok(written))
}

/// Repositions a broker-owned open-file description.
pub fn seek(
    session: &BrokerSession,
    handle: ObjectHandle,
    offset: i64,
    whence: FilesystemSeekWhence,
) -> Result<core::result::Result<u64, FilesystemError>> {
    let description = open_file_description(session, handle, ObjectRights::WAIT)?;
    Ok(description.seek(&session.cancellation, offset, whence))
}

/// Truncates a broker-owned open-file description.
pub fn truncate(
    session: &BrokerSession,
    handle: ObjectHandle,
    length: u64,
    reset_offset: bool,
) -> Result<core::result::Result<(), FilesystemError>> {
    let description = open_file_description(session, handle, ObjectRights::WRITE)?;
    Ok(description.truncate(&session.cancellation, length, reset_offset))
}

/// Reads one bounded page from a broker-owned open directory.
pub fn read_directory(
    session: &BrokerSession,
    handle: ObjectHandle,
    start_index: u64,
    maximum_encoded_length: usize,
) -> Result<FilesystemResult<DirectoryPage>> {
    let description = open_file_description(session, handle, ObjectRights::WAIT)?;
    let page =
        description.read_directory(&session.cancellation, start_index, maximum_encoded_length);
    if let Ok((entries, Some(next_index))) = &page {
        let expected_next_index = start_index
            .checked_add(u64::try_from(entries.len()).map_err(|_| BrokerError::Internal)?)
            .ok_or(BrokerError::Internal)?;
        if entries.is_empty() || *next_index != expected_next_index {
            return Err(BrokerError::Internal);
        }
    }
    Ok(page)
}

/// Returns status for a broker-owned open-file description.
pub fn handle_status(
    session: &BrokerSession,
    handle: ObjectHandle,
) -> Result<core::result::Result<FilesystemFileStatus, FilesystemError>> {
    let description = open_file_description(session, handle, ObjectRights::WAIT)?;
    Ok(description.status(&session.cancellation))
}

/// Returns status for an absolute path.
pub fn path_status(
    session: &BrokerSession,
    namespace: FilesystemNamespace,
    path: &str,
    user: FilesystemUser,
) -> Result<core::result::Result<FilesystemFileStatus, FilesystemError>> {
    authorize_filesystem_operation(session, ObjectRights::WAIT)?;
    Ok(session
        .core
        .filesystem_provider
        .path_status(&session.cancellation, namespace, path, user))
}

/// Changes mode bits for an absolute path.
pub fn chmod(
    session: &BrokerSession,
    namespace: FilesystemNamespace,
    path: &str,
    user: FilesystemUser,
    mode: u32,
) -> Result<core::result::Result<(), FilesystemError>> {
    authorize_filesystem_operation(session, ObjectRights::WRITE)?;
    Ok(session
        .core
        .filesystem_provider
        .chmod(&session.cancellation, namespace, path, user, mode))
}

/// Changes ownership for an absolute path.
pub fn chown(
    session: &BrokerSession,
    namespace: FilesystemNamespace,
    path: &str,
    acting_user: FilesystemUser,
    user: Option<u16>,
    group: Option<u16>,
) -> Result<core::result::Result<(), FilesystemError>> {
    authorize_filesystem_operation(session, ObjectRights::WRITE)?;
    Ok(session.core.filesystem_provider.chown(
        &session.cancellation,
        namespace,
        path,
        acting_user,
        user,
        group,
    ))
}

/// Removes a file at an absolute path.
pub fn unlink(
    session: &BrokerSession,
    namespace: FilesystemNamespace,
    path: &str,
    user: FilesystemUser,
) -> Result<core::result::Result<(), FilesystemError>> {
    authorize_filesystem_operation(session, ObjectRights::WRITE)?;
    Ok(session
        .core
        .filesystem_provider
        .unlink(&session.cancellation, namespace, path, user))
}

/// Creates a directory at an absolute path.
pub fn mkdir(
    session: &BrokerSession,
    namespace: FilesystemNamespace,
    path: &str,
    user: FilesystemUser,
    mode: u32,
) -> Result<core::result::Result<(), FilesystemError>> {
    authorize_filesystem_operation(session, ObjectRights::WRITE)?;
    Ok(session
        .core
        .filesystem_provider
        .mkdir(&session.cancellation, namespace, path, user, mode))
}

/// Removes a directory at an absolute path.
pub fn rmdir(
    session: &BrokerSession,
    namespace: FilesystemNamespace,
    path: &str,
    user: FilesystemUser,
) -> Result<core::result::Result<(), FilesystemError>> {
    authorize_filesystem_operation(session, ObjectRights::WRITE)?;
    Ok(session
        .core
        .filesystem_provider
        .rmdir(&session.cancellation, namespace, path, user))
}

fn open_file_description(
    session: &BrokerSession,
    handle: ObjectHandle,
    required_rights: ObjectRights,
) -> Result<Arc<dyn OpenFileDescription>> {
    let object = session.authorized_object(handle, required_rights)?;
    let object = object.read();
    match &*object {
        ObjectEntry::Filesystem(description) => Ok(Arc::clone(description)),
        ObjectEntry::Event(_) | ObjectEntry::Pipe(_) | ObjectEntry::Socket(_) => {
            Err(BrokerError::InvalidRights)
        }
        ObjectEntry::Reserved => Err(BrokerError::Internal),
    }
}

fn authorize_filesystem_operation(
    session: &BrokerSession,
    required_rights: ObjectRights,
) -> Result<()> {
    let rights = session
        .core
        .policy
        .principal_object_rights(session.caller_credential)?;
    if rights.contains(required_rights) {
        Ok(())
    } else {
        Err(BrokerError::PolicyDenied)
    }
}

#[cfg(test)]
mod tests {
    use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    use super::*;
    use crate::socket::BrokerSocketPorts;
    use crate::{BrokerCore, BrokerCoreLimits, CallerCredential, PolicyEngine};
    use hashbrown::HashMap;
    use spin::RwLock;

    const USER: FilesystemUser = FilesystemUser { user: 1, group: 2 };

    #[derive(Default)]
    struct TestFilesystemProvider {
        open_calls: AtomicUsize,
        path_status_calls: AtomicUsize,
        mutation_calls: AtomicUsize,
        overreport_reads: AtomicBool,
    }

    impl FilesystemProvider for TestFilesystemProvider {
        fn open(
            &self,
            _cancellation: &AssociationCancellation,
            _namespace: FilesystemNamespace,
            _path: &str,
            _user: FilesystemUser,
            _flags: u32,
            _mode: u32,
        ) -> core::result::Result<Arc<dyn OpenFileDescription>, FilesystemError> {
            self.open_calls.fetch_add(1, Ordering::Relaxed);
            Ok(Arc::new(TestOpenFile {
                overreport_reads: self.overreport_reads.load(Ordering::Relaxed),
            }))
        }

        fn path_status(
            &self,
            _cancellation: &AssociationCancellation,
            _namespace: FilesystemNamespace,
            _path: &str,
            _user: FilesystemUser,
        ) -> core::result::Result<FilesystemFileStatus, FilesystemError> {
            self.path_status_calls.fetch_add(1, Ordering::Relaxed);
            Err(FilesystemError::Io)
        }

        fn chmod(
            &self,
            _cancellation: &AssociationCancellation,
            _namespace: FilesystemNamespace,
            _path: &str,
            _user: FilesystemUser,
            _mode: u32,
        ) -> core::result::Result<(), FilesystemError> {
            self.mutation_calls.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }

        fn chown(
            &self,
            _cancellation: &AssociationCancellation,
            _namespace: FilesystemNamespace,
            _path: &str,
            _acting_user: FilesystemUser,
            _user: Option<u16>,
            _group: Option<u16>,
        ) -> core::result::Result<(), FilesystemError> {
            self.mutation_calls.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }

        fn unlink(
            &self,
            _cancellation: &AssociationCancellation,
            _namespace: FilesystemNamespace,
            _path: &str,
            _user: FilesystemUser,
        ) -> core::result::Result<(), FilesystemError> {
            self.mutation_calls.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }

        fn mkdir(
            &self,
            _cancellation: &AssociationCancellation,
            _namespace: FilesystemNamespace,
            _path: &str,
            _user: FilesystemUser,
            _mode: u32,
        ) -> core::result::Result<(), FilesystemError> {
            self.mutation_calls.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }

        fn rmdir(
            &self,
            _cancellation: &AssociationCancellation,
            _namespace: FilesystemNamespace,
            _path: &str,
            _user: FilesystemUser,
        ) -> core::result::Result<(), FilesystemError> {
            self.mutation_calls.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }
    }

    struct TestOpenFile {
        overreport_reads: bool,
    }

    impl OpenFileDescription for TestOpenFile {
        fn read(
            &self,
            _cancellation: &AssociationCancellation,
            output: &mut [u8],
            _offset: Option<u64>,
        ) -> core::result::Result<usize, FilesystemError> {
            Ok(if self.overreport_reads {
                output.len() + 1
            } else {
                0
            })
        }

        fn write(
            &self,
            _cancellation: &AssociationCancellation,
            input: &[u8],
            _offset: Option<u64>,
        ) -> core::result::Result<usize, FilesystemError> {
            Ok(input.len())
        }

        fn seek(
            &self,
            _cancellation: &AssociationCancellation,
            _offset: i64,
            _whence: FilesystemSeekWhence,
        ) -> core::result::Result<u64, FilesystemError> {
            Ok(0)
        }

        fn truncate(
            &self,
            _cancellation: &AssociationCancellation,
            _length: u64,
            _reset_offset: bool,
        ) -> core::result::Result<(), FilesystemError> {
            Ok(())
        }

        fn read_directory(
            &self,
            _cancellation: &AssociationCancellation,
            _start_index: u64,
            _maximum_encoded_length: usize,
        ) -> core::result::Result<(Vec<FilesystemDirectoryEntry>, Option<u64>), FilesystemError>
        {
            Ok((Vec::new(), None))
        }

        fn status(
            &self,
            _cancellation: &AssociationCancellation,
        ) -> core::result::Result<FilesystemFileStatus, FilesystemError> {
            Err(FilesystemError::Io)
        }
    }

    fn test_broker(
        rights: ObjectRights,
        max_references: usize,
        filesystem_provider: Arc<TestFilesystemProvider>,
    ) -> BrokerCore {
        BrokerCore {
            policy: Arc::new(PolicyEngine::with_unauthenticated_rights(rights)),
            limits: BrokerCoreLimits::new(max_references, 0),
            next_session_id: Arc::new(RwLock::new(1)),
            next_reference_handle: Arc::new(RwLock::new(1)),
            references: Arc::new(RwLock::new(HashMap::new())),
            pending_references: Arc::new(AtomicUsize::new(0)),
            reserved_pipe_capacity: Arc::new(AtomicUsize::new(0)),
            reserved_sockets: Arc::new(AtomicUsize::new(0)),
            random_provider: Arc::new(crate::random::TestRandomProvider),
            stdio_provider: Arc::new(crate::stdio::UnsupportedStdioProvider),
            socket_provider: Arc::new(crate::socket::UnsupportedSocketProvider),
            filesystem_provider,
            socket_ports: BrokerSocketPorts::default(),
        }
    }

    #[test]
    fn filesystem_policy_is_checked_before_calling_the_provider() {
        let wait_provider = Arc::new(TestFilesystemProvider::default());
        let wait_broker = test_broker(ObjectRights::WAIT, 2, Arc::clone(&wait_provider));
        let wait_session = wait_broker
            .create_session(CallerCredential::Unauthenticated)
            .unwrap();

        assert_eq!(
            open(
                &wait_session,
                FilesystemNamespace::Guest,
                "/file",
                USER,
                0,
                0
            ),
            Err(BrokerError::PolicyDenied)
        );
        assert_eq!(wait_provider.open_calls.load(Ordering::Relaxed), 0);
        assert_eq!(
            mkdir(&wait_session, FilesystemNamespace::Guest, "/dir", USER, 0),
            Err(BrokerError::PolicyDenied)
        );
        assert_eq!(wait_provider.mutation_calls.load(Ordering::Relaxed), 0);
        assert_eq!(
            path_status(&wait_session, FilesystemNamespace::Guest, "/file", USER),
            Ok(Err(FilesystemError::Io))
        );
        assert_eq!(wait_provider.path_status_calls.load(Ordering::Relaxed), 1);

        let write_provider = Arc::new(TestFilesystemProvider::default());
        let write_broker = test_broker(ObjectRights::WRITE, 1, Arc::clone(&write_provider));
        let write_session = write_broker
            .create_session(CallerCredential::Unauthenticated)
            .unwrap();
        assert_eq!(
            path_status(&write_session, FilesystemNamespace::Guest, "/file", USER),
            Err(BrokerError::PolicyDenied)
        );
        assert_eq!(write_provider.path_status_calls.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn filesystem_open_reserves_reference_before_provider_side_effects() {
        let provider = Arc::new(TestFilesystemProvider::default());
        let broker = test_broker(ObjectRights::all(), 1, Arc::clone(&provider));
        let session = broker
            .create_session(CallerCredential::Unauthenticated)
            .unwrap();
        let event = crate::event::create(&session, 0).unwrap();

        assert_eq!(
            open(&session, FilesystemNamespace::Guest, "/file", USER, 0, 0),
            Err(BrokerError::ResourceExhausted)
        );
        assert_eq!(provider.open_calls.load(Ordering::Relaxed), 0);
        assert_eq!(session.close_object_reference(event), Ok(()));
    }

    #[test]
    fn filesystem_operations_enforce_attenuated_reference_rights() {
        let provider = Arc::new(TestFilesystemProvider::default());
        let broker = test_broker(ObjectRights::all(), 2, provider);
        let source = broker
            .create_session(CallerCredential::Unauthenticated)
            .unwrap();
        let target = broker
            .create_session(CallerCredential::Unauthenticated)
            .unwrap();
        let handle = open(&source, FilesystemNamespace::Guest, "/file", USER, 0, 0)
            .unwrap()
            .unwrap();
        let read_only = source
            .duplicate_object_reference_to(handle, &target, ObjectRights::WAIT)
            .unwrap();

        assert_eq!(read(&target, read_only, &mut [0; 1], None), Ok(Ok(0)));
        assert_eq!(
            write(&target, read_only, &[1], None),
            Err(BrokerError::InvalidRights)
        );
    }

    #[test]
    fn filesystem_operations_reject_wrong_types_and_provider_overreporting() {
        let provider = Arc::new(TestFilesystemProvider::default());
        provider.overreport_reads.store(true, Ordering::Relaxed);
        let broker = test_broker(ObjectRights::all(), 2, provider);
        let session = broker
            .create_session(CallerCredential::Unauthenticated)
            .unwrap();
        let event = crate::event::create(&session, 0).unwrap();

        assert_eq!(
            read(&session, event, &mut [0; 1], None),
            Err(BrokerError::InvalidRights)
        );

        let file = open(&session, FilesystemNamespace::Guest, "/file", USER, 0, 0)
            .unwrap()
            .unwrap();
        assert_eq!(
            read(&session, file, &mut [0; 1], None),
            Err(BrokerError::Internal)
        );
    }
}
