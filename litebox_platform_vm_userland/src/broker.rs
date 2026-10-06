// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Broker association with the kernel's broker host: control messages in
//! kernel calls, payloads in the startup info's broker shared memory.

use alloc::sync::Arc;
use litebox::utils::TruncateExt as _;
use litebox_broker_local::BrokerLocal;
use litebox_broker_protocol::message::{
    BrokerHandshakeRequest, BrokerHandshakeResponse, BrokerRequest, BrokerResponse,
};
use litebox_broker_protocol::wire::{self, WireError};
use litebox_broker_transport::channel::{LocalCallChannel, LocalSetupChannel};
use litebox_broker_transport::shared_memory::{SharedMemory, SharedMemoryError};
use litebox_common_vm_abi::{
    BrokerHandshakeFrame, BrokerRequestFrame, Status, UserRange, WireFrame,
};

#[derive(Debug)]
pub enum ChannelError {
    Kernel(Status),
    Wire(WireError),
    Oversized,
    NoRequest,
}

impl core::fmt::Display for ChannelError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Kernel(status) => write!(f, "kernel rejected the broker call: {status:?}"),
            Self::Wire(error) => write!(f, "malformed broker frame: {error}"),
            Self::Oversized => f.write_str("broker frame too large"),
            Self::NoRequest => f.write_str("no handshake request was sent"),
        }
    }
}

impl core::error::Error for ChannelError {}

fn frame(bytes: &[u8]) -> Result<WireFrame, ChannelError> {
    WireFrame::new(bytes).ok_or(ChannelError::Oversized)
}

fn payload(frame: &WireFrame) -> Result<&[u8], ChannelError> {
    frame.as_slice().ok_or(ChannelError::Oversized)
}

#[derive(Default)]
pub struct KernelBrokerSetup {
    request: Option<WireFrame>,
}

impl LocalSetupChannel for KernelBrokerSetup {
    type Error = ChannelError;

    fn send_handshake_request(
        &mut self,
        request: &BrokerHandshakeRequest,
    ) -> Result<(), ChannelError> {
        self.request = Some(frame(&wire::encode_handshake_request(request.clone()))?);
        Ok(())
    }

    fn recv_handshake_response(&mut self) -> Result<Option<BrokerHandshakeResponse>, ChannelError> {
        let request = self.request.take().ok_or(ChannelError::NoRequest)?;
        let response =
            crate::kcall::call(&BrokerHandshakeFrame(request)).map_err(ChannelError::Kernel)?;
        wire::decode_handshake_response(payload(&response)?)
            .map(Some)
            .map_err(ChannelError::Wire)
    }
}

pub struct KernelBrokerChannel(());

impl LocalCallChannel for KernelBrokerChannel {
    type Error = ChannelError;

    fn call(&self, request: BrokerRequest) -> Result<BrokerResponse, ChannelError> {
        let request = frame(&wire::encode_request(request))?;
        let response =
            crate::kcall::call(&BrokerRequestFrame(request)).map_err(ChannelError::Kernel)?;
        wire::decode_response(payload(&response)?).map_err(ChannelError::Wire)
    }
}

struct KernelSharedMemory {
    region: UserRange,
}

impl KernelSharedMemory {
    fn range(&self, offset: usize, len: usize) -> Result<*mut u8, SharedMemoryError> {
        let end = offset
            .checked_add(len)
            .ok_or(SharedMemoryError::InvalidRange)?;
        if end > self.len() {
            return Err(SharedMemoryError::InvalidRange);
        }
        let start: usize = self.region.start.trunc();
        Ok((start + offset) as *mut u8)
    }
}

impl SharedMemory for KernelSharedMemory {
    fn len(&self) -> usize {
        usize::try_from(self.region.len).unwrap_or(0)
    }

    fn read(&self, offset: usize, destination: &mut [u8]) -> Result<(), SharedMemoryError> {
        let source = self.range(offset, destination.len())?;
        // Safety: in bounds of a region mapped for the process's lifetime;
        // the kernel touches it only during this thread's broker calls.
        unsafe {
            core::ptr::copy_nonoverlapping(source, destination.as_mut_ptr(), destination.len());
        }
        Ok(())
    }

    fn write(&self, offset: usize, source: &[u8]) -> Result<(), SharedMemoryError> {
        let destination = self.range(offset, source.len())?;
        // Safety: as in `read`.
        unsafe { core::ptr::copy_nonoverlapping(source.as_ptr(), destination, source.len()) };
        Ok(())
    }
}

/// Call at most once per process.
///
/// # Errors
///
/// The kernel rejects the association or negotiation fails.
pub fn connect(
    shared_memory: UserRange,
) -> litebox_broker_local::Result<BrokerLocal<KernelBrokerChannel>, ChannelError> {
    let (local, _startup, ()) = BrokerLocal::negotiate(KernelBrokerSetup::default(), |_setup| {
        let memory: Arc<dyn SharedMemory> = Arc::new(KernelSharedMemory {
            region: shared_memory,
        });
        Ok((KernelBrokerChannel(()), memory, ()))
    })?;
    Ok(local)
}
