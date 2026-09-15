// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use alloc::vec::Vec;

use crate::shared_buffer::{
    MAX_SHARED_BUFFER_SEQUENCE_SLOTS, SharedBufferSequence, SharedBufferSlotIndex,
};
use crate::{ObjectHandle, ProcessId, ProtocolVersion, RequestId, ThreadId};

use super::WireError;

#[derive(Default)]
pub(super) struct Encoder {
    bytes: Vec<u8>,
}

impl Encoder {
    pub(super) fn finish(self) -> Vec<u8> {
        self.bytes
    }

    pub(super) fn u8(&mut self, value: u8) {
        self.bytes.push(value);
    }

    pub(super) fn u16(&mut self, value: u16) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    pub(super) fn u32(&mut self, value: u32) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    pub(super) fn u64(&mut self, value: u64) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    pub(super) fn protocol_version(&mut self, version: ProtocolVersion) {
        self.u16(version.0);
    }

    pub(super) fn process_id(&mut self, process_id: ProcessId) {
        self.u32(process_id.0);
    }

    pub(super) fn thread_id(&mut self, thread_id: ThreadId) {
        self.u32(thread_id.0);
    }

    pub(super) fn handle(&mut self, handle: ObjectHandle) {
        self.u64(handle.0);
    }

    pub(super) fn request_id(&mut self, request_id: RequestId) {
        self.u64(request_id.0);
    }

    pub(super) fn shared_buffer_sequence(&mut self, sequence: SharedBufferSequence) {
        self.u8(u8::try_from(sequence.slot_indices().len())
            .expect("shared-buffer sequence length must fit in u8"));
        for slot_index in sequence.slot_indices() {
            self.u32(slot_index.0);
        }
        self.u32(sequence.length());
    }
}

pub(super) struct Decoder<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Decoder<'a> {
    pub(super) const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    pub(super) fn finish(&self) -> Result<(), WireError> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(WireError::TrailingBytes)
        }
    }

    pub(super) fn u8(&mut self) -> Result<u8, WireError> {
        let bytes = self.take(1)?;
        Ok(bytes[0])
    }

    pub(super) fn u16(&mut self) -> Result<u16, WireError> {
        let bytes = self.take(2)?;
        Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
    }

    pub(super) fn u32(&mut self) -> Result<u32, WireError> {
        let bytes = self.take(4)?;
        Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    pub(super) fn u64(&mut self) -> Result<u64, WireError> {
        let bytes = self.take(8)?;
        Ok(u64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]))
    }

    pub(super) fn protocol_version(&mut self) -> Result<ProtocolVersion, WireError> {
        Ok(ProtocolVersion(self.u16()?))
    }

    pub(super) fn process_id(&mut self) -> Result<ProcessId, WireError> {
        Ok(ProcessId(self.u32()?))
    }

    pub(super) fn thread_id(&mut self) -> Result<ThreadId, WireError> {
        Ok(ThreadId(self.u32()?))
    }

    pub(super) fn handle(&mut self) -> Result<ObjectHandle, WireError> {
        Ok(ObjectHandle(self.u64()?))
    }

    pub(super) fn request_id(&mut self) -> Result<RequestId, WireError> {
        Ok(RequestId(self.u64()?))
    }

    pub(super) fn shared_buffer_sequence(&mut self) -> Result<SharedBufferSequence, WireError> {
        let slot_count = usize::from(self.u8()?);
        if slot_count > MAX_SHARED_BUFFER_SEQUENCE_SLOTS {
            return Err(WireError::InvalidTag);
        }
        let mut slot_indices = [SharedBufferSlotIndex::default(); MAX_SHARED_BUFFER_SEQUENCE_SLOTS];
        for slot_index in &mut slot_indices[..slot_count] {
            *slot_index = SharedBufferSlotIndex(self.u32()?);
        }
        SharedBufferSequence::new(&slot_indices[..slot_count], self.u32()?)
            .map_err(|_| WireError::InvalidTag)
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], WireError> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or(WireError::OffsetOverflow)?;
        let bytes = self
            .bytes
            .get(self.offset..end)
            .ok_or(WireError::TruncatedFrame)?;
        self.offset = end;
        Ok(bytes)
    }
}
