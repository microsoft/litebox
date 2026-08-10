// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! One Vec-backed foreign-memory domain representing the harness process.

use core::marker::PhantomData;
use std::ffi::CString;
use std::sync::Arc;

use litebox::foreign_memory::domains::uncoop_user_fault::{
    UncoopFaultDomain, UncoopUserFaultRegistration,
};
use litebox::foreign_memory::domains::{ExportedPointer, ForeignMemoryRuntime};
use true_tales::fmem::backing::TransactionalVec;

use crate::platform::HarnessPlatform;

const PROCESS_BASE: usize = 0x1_0000;

/// A typed address in the harness process's modeled userspace.
pub struct ProcessPointer<T> {
    pointer: ExportedPointer<UncoopFaultDomain>,
    offset: usize,
    _pointee: PhantomData<fn() -> T>,
}

impl<T> Clone for ProcessPointer<T> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<T> Copy for ProcessPointer<T> {}

impl<T> core::fmt::Debug for ProcessPointer<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ProcessPointer")
            .field("offset", &self.offset)
            .finish_non_exhaustive()
    }
}

/// The single address space shared by every thread in a [`crate::HarnessRunner`].
pub(crate) struct ProcessMemory {
    runtime: ForeignMemoryRuntime,
    registration: Option<UncoopUserFaultRegistration>,
    base: ExportedPointer<UncoopFaultDomain>,
    backing: Option<Arc<TransactionalVec>>,
    len: usize,
}

impl ProcessMemory {
    pub(crate) fn new(runtime: ForeignMemoryRuntime, backing: Vec<u8>) -> Arc<Self> {
        let len = backing.len();
        let (registration, backing) =
            runtime.inject_uncoop_user_fault_modeled(PROCESS_BASE, backing);
        let base = registration.pointer();
        Arc::new(Self {
            runtime,
            registration: Some(registration),
            base,
            backing: Some(backing),
            len,
        })
    }

    pub(crate) fn pointer<T>(&self, offset: usize) -> Option<ProcessPointer<T>> {
        if offset > self.len {
            return None;
        }
        Some(ProcessPointer {
            pointer: self.base.checked_advance(offset)?,
            offset,
            _pointee: PhantomData,
        })
    }

    pub(crate) fn read<T>(
        &self,
        hardware_threads: &HarnessPlatform,
        pointer: ProcessPointer<T>,
        len: usize,
    ) -> Result<Vec<u8>, ProcessMemoryError> {
        let end = pointer
            .offset
            .checked_add(len)
            .ok_or(ProcessMemoryError::OutOfRange)?;
        if end > self.len {
            return Err(ProcessMemoryError::OutOfRange);
        }
        let mut bytes = vec![0; len];
        self.runtime
            .copy_from_uncoop_user(hardware_threads, &mut bytes, pointer.pointer)
            .map_err(|_| ProcessMemoryError::Copy)?;
        Ok(bytes)
    }

    pub(crate) fn write<T>(
        &self,
        hardware_threads: &HarnessPlatform,
        pointer: ProcessPointer<T>,
        bytes: &[u8],
    ) -> Result<(), ProcessMemoryError> {
        let end = pointer
            .offset
            .checked_add(bytes.len())
            .ok_or(ProcessMemoryError::OutOfRange)?;
        if end > self.len {
            return Err(ProcessMemoryError::OutOfRange);
        }
        self.runtime
            .copy_to_uncoop_user(hardware_threads, pointer.pointer, bytes)
            .map_err(|_| ProcessMemoryError::Copy)
    }

    pub(crate) fn read_c_string(
        &self,
        hardware_threads: &HarnessPlatform,
        pointer: ProcessPointer<i8>,
    ) -> Result<CString, ProcessMemoryError> {
        let remaining = self
            .len
            .checked_sub(pointer.offset)
            .ok_or(ProcessMemoryError::OutOfRange)?;
        let mut bytes = self.read(hardware_threads, pointer, remaining)?;
        let nul = bytes
            .iter()
            .position(|byte| *byte == 0)
            .ok_or(ProcessMemoryError::MissingNul)?;
        bytes.truncate(nul + 1);
        CString::from_vec_with_nul(bytes).map_err(|_| ProcessMemoryError::MissingNul)
    }
}

impl Drop for ProcessMemory {
    fn drop(&mut self) {
        let registration = self
            .registration
            .take()
            .expect("process-memory registration was already retired");
        let retired = registration
            .retire()
            .expect("failed to retire process-memory registration");
        assert!(
            retired.is_dead(),
            "process memory still has in-flight operations at teardown"
        );
        let backing = self
            .backing
            .take()
            .expect("process-memory backing was already reclaimed");
        let Some(backing) = Arc::into_inner(backing) else {
            panic!("process-memory backing still has outstanding owners");
        };
        drop(backing.into_backing());
    }
}

#[derive(Debug)]
pub(crate) enum ProcessMemoryError {
    OutOfRange,
    MissingNul,
    Copy,
}

impl core::fmt::Display for ProcessMemoryError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::OutOfRange => f.write_str("process-memory range is out of bounds"),
            Self::MissingNul => f.write_str("process-memory string is not NUL-terminated"),
            Self::Copy => f.write_str("True Tales process-memory copy failed"),
        }
    }
}

impl std::error::Error for ProcessMemoryError {}
