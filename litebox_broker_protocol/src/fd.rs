// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Linux guest descriptor-table operations. Other object clients use handles directly.

use core::net::SocketAddrV4;

use crate::event::CreateEventRequest;
use crate::fs::{FileError, FileOpenFlags, OpenFileRequest};
use crate::pipe::CreatePipeRequest;
use crate::process::OpenProcessHandleRequest;
use crate::shared_buffer::{
    MAX_SHARED_BUFFER_SEQUENCE_SLOTS, SHARED_BUFFER_SLOT_SIZE, SharedBufferSequence,
};
use crate::socket::{AcceptSocketRequest, CreateSocketRequest, SocketError, SocketType};
use crate::timer::CreateTimerRequest;
use crate::unix_socket::{AcceptUnixSocketRequest, CreateUnixSocketRequest, UnixSocketError};
use crate::vsock_socket::{CreateVsockSocketRequest, VsockAddress};
use crate::wire::{Decoder, Encoder, Wire, WireError};
use crate::{ObjectHandle, ProcessId};
use alloc::vec::Vec;

wire_enum! {
    /// Type information needed to build a shim-side view of a broker object.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum FdKind {
        File,
        PipeRead,
        PipeWrite,
        Inet(SocketType),
        Unix(SocketType),
        Vsock,
        Event,
        Timer,
        Epoll,
        Pidfd,
    }
}

wire_struct! {
    /// One installed descriptor and its (non-owning) handle for object operations.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct FdInfo {
        pub number: u32,
        pub handle: ObjectHandle,
        pub kind: FdKind,
    }
}

/// The byte stride of entries in a list response, including padding.
pub const FD_LIST_STRIDE: usize = FdInfo::MAX_SIZE;
/// Maximum number of entries which can be returned in one descriptor snapshot.
// XXX: The fork-time list must fit one shared buffer, which caps open fds well below
// RLIMIT_NOFILE; page the list.
pub const MAX_FD_ENTRIES: usize = FD_LIST_BUFFER_SIZE as usize / FD_LIST_STRIDE;
/// Maximum byte size of a descriptor snapshot.
#[expect(
    clippy::cast_possible_truncation,
    reason = "the buffer layout bounds the slot count"
)]
pub const FD_LIST_BUFFER_SIZE: u32 =
    SHARED_BUFFER_SLOT_SIZE * MAX_SHARED_BUFFER_SEQUENCE_SLOTS as u32;

impl FdInfo {
    /// Encodes the snapshot into a preallocated buffer.
    #[must_use]
    pub fn encode_list(entries: impl IntoIterator<Item = Self>, bytes: Vec<u8>) -> Vec<u8> {
        let mut encoder = Encoder { bytes };
        for entry in entries {
            let end = encoder.bytes.len() + FD_LIST_STRIDE;
            entry.encode(&mut encoder);
            encoder.bytes.resize(end, 0);
        }
        encoder.bytes
    }

    /// Reads one descriptor from a shared-buffer snapshot.
    pub fn read(bytes: &[u8]) -> Result<Self, WireError> {
        Self::decode(&mut Decoder::new(bytes))
    }
}

wire_enum! {
    /// Placement of a duplicate.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum DupTarget {
        Lowest,
        AtLeast(u32),
        Exact { number: u32, distinct: bool },
    }
}

wire_enum! {
    /// Request that creates and installs one or two descriptors as one operation.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum FdCreate {
        Open(OpenFileRequest),
        Pipe(CreatePipeRequest),
        Inet(CreateSocketRequest),
        Unix(CreateUnixSocketRequest),
        UnixPair(CreateUnixSocketRequest),
        Vsock(CreateVsockSocketRequest),
        AcceptInet(AcceptSocketRequest),
        AcceptUnix { request: AcceptUnixSocketRequest, kind: SocketType, name: Option<SharedBufferSequence> },
        AcceptVsock { handle: ObjectHandle, flags: FileOpenFlags },
        Event(CreateEventRequest),
        Timer(CreateTimerRequest),
        Epoll,
        Pidfd(OpenProcessHandleRequest),
        Import(ObjectHandle),
    }
}

wire_enum! {
    /// Operations on one broker descriptor table.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum FdOperation {
        Create { object: FdCreate, cloexec: bool },
        Close(u32),
        Rollback { first: u32, second: Option<u32>, installed: u64 },
        CloseRange { first: u32, last: u32, cloexec: bool },
        Duplicate { fd: u32, target: DupTarget, cloexec: bool },
        GetCloexec(u32),
        SetCloexec { fd: u32, cloexec: bool },
        List(SharedBufferSequence),
        Exec(Option<SharedBufferSequence>),
    }
}

wire_struct! {
    /// A vfork child specifies its pending process instead of the caller's table.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct FdRequest {
        pub pending_child: Option<ProcessId>,
        pub operation: FdOperation,
    }
}

wire_enum! {
    /// Address returned by an accept request.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum FdPeer {
        Inet(SocketAddrV4),
        Vsock(VsockAddress),
        Unix(u8),
    }
}

wire_enum! {
    /// Result of a descriptor operation.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum FdResponse {
        Installed { revision: u64, first: FdInfo, second: Option<FdInfo>, peer: Option<FdPeer> },
        Changed(u64),
        Cloexec(bool),
        PidfdMissing { thread: bool },
        Listed { revision: u64, entries: u32 },
        RolledBack { revision: u64, first: bool, second: bool },
        FileFailed(FileError),
        SocketFailed(SocketError),
        UnixFailed(UnixSocketError),
    }
}
