// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use alloc::vec::Vec;

use crate::{ObjectHandle, ProtocolVersion, RequestId};

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

    pub(super) fn handle(&mut self, handle: ObjectHandle) {
        self.u64(handle.0);
    }

    pub(super) fn request_id(&mut self, request_id: RequestId) {
        self.u64(request_id.0);
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

    pub(super) fn handle(&mut self) -> Result<ObjectHandle, WireError> {
        Ok(ObjectHandle(self.u64()?))
    }

    pub(super) fn request_id(&mut self) -> Result<RequestId, WireError> {
        Ok(RequestId(self.u64()?))
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
