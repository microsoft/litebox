// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use alloc::vec::Vec;

use crate::{ObjectHandle, ObjectReferenceGeneration, ObjectReferenceId, ProtocolVersion};

use super::WireError;

#[derive(Default)]
pub(super) struct Encoder {
    bytes: Vec<u8>,
}

impl Encoder {
    pub(super) fn finish(self) -> Vec<u8> {
        self.bytes
    }

    pub(super) fn bool(&mut self, value: bool) {
        self.u8(u8::from(value));
    }

    pub(super) fn u8(&mut self, value: u8) {
        self.bytes.push(value);
    }

    pub(super) fn u16(&mut self, value: u16) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    pub(super) fn u64(&mut self, value: u64) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    pub(super) fn protocol_version(&mut self, version: ProtocolVersion) {
        self.u16(version.major);
        self.u16(version.minor);
    }

    pub(super) fn handle(&mut self, handle: ObjectHandle) {
        self.u64(handle.reference_id.get());
        self.u64(handle.reference_generation.get());
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

    pub(super) fn bool(&mut self) -> Result<bool, WireError> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(WireError::InvalidBoolean),
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

    pub(super) fn u64(&mut self) -> Result<u64, WireError> {
        let bytes = self.take(8)?;
        Ok(u64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]))
    }

    pub(super) fn protocol_version(&mut self) -> Result<ProtocolVersion, WireError> {
        Ok(ProtocolVersion::new(self.u16()?, self.u16()?))
    }

    pub(super) fn handle(&mut self) -> Result<ObjectHandle, WireError> {
        let reference_id = ObjectReferenceId::new(self.u64()?);
        let reference_generation = ObjectReferenceGeneration::new(self.u64()?);

        Ok(ObjectHandle::new(reference_id, reference_generation))
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
