// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Loader utilities for the BSD shim.

use alloc::ffi::CString;
use alloc::vec::Vec;
use litebox::mm::PageManager;
use litebox::mm::linux::{
    CreatePagesFlags, MappingError, NonZeroAddress, NonZeroPageSize, PAGE_SIZE,
};
use litebox::platform::{RawConstPointer as _, RawMutPointer as _};
use litebox_common_bsd::loader::{MapMemory, ReadAt};
use litebox_platform_multiplex::Platform;

/// A simple reader that reads from a byte slice.
pub struct SliceReader<'a> {
    data: &'a [u8],
}

impl<'a> SliceReader<'a> {
    /// Create a new slice reader.
    pub fn new(data: &'a [u8]) -> Self {
        Self { data }
    }
}

impl ReadAt for SliceReader<'_> {
    type Error = MappingError;

    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<(), Self::Error> {
        let start = offset as usize;
        let end = start + buf.len();
        if end > self.data.len() {
            return Err(MappingError::OutOfMemory);
        }
        buf.copy_from_slice(&self.data[start..end]);
        Ok(())
    }
}

/// A mapper that uses PageManager to map memory.
pub struct PageManagerMapper<'a> {
    pm: &'a PageManager<Platform, PAGE_SIZE>,
}

impl<'a> PageManagerMapper<'a> {
    /// Create a new mapper.
    pub fn new(pm: &'a PageManager<Platform, PAGE_SIZE>) -> Self {
        Self { pm }
    }
}

type MutPtr<T> = <Platform as litebox::platform::RawPointerProvider>::RawMutPointer<T>;

impl MapMemory for PageManagerMapper<'_> {
    type Error = MappingError;

    fn map_anon(&mut self, addr: usize, len: usize) -> Result<*mut u8, Self::Error> {
        let aligned_len = len.next_multiple_of(PAGE_SIZE);
        let nz_addr = NonZeroAddress::new(addr).ok_or(MappingError::UnAligned)?;
        let nz_len = NonZeroPageSize::new(aligned_len).ok_or(MappingError::UnAligned)?;

        // SAFETY: We're mapping at a fixed address as requested by the Mach-O loader
        let ptr = unsafe {
            self.pm.create_writable_pages(
                Some(nz_addr),
                nz_len,
                CreatePagesFlags::FIXED_ADDR,
                |_ptr| Ok(0),
            )?
        };
        Ok(ptr.as_usize() as *mut u8)
    }

    fn map_exec(&mut self, addr: usize, len: usize, data: &[u8]) -> Result<(), Self::Error> {
        let aligned_len = len.next_multiple_of(PAGE_SIZE);
        let nz_addr = NonZeroAddress::new(addr).ok_or(MappingError::UnAligned)?;
        let nz_len = NonZeroPageSize::new(aligned_len).ok_or(MappingError::UnAligned)?;

        // SAFETY: We're mapping at a fixed address as requested by the Mach-O loader
        unsafe {
            self.pm.create_executable_pages(
                Some(nz_addr),
                nz_len,
                CreatePagesFlags::FIXED_ADDR,
                |ptr| {
                    ptr.copy_from_slice(0, data)
                        .ok_or(MappingError::OutOfMemory)?;
                    Ok(0)
                },
            )?;
        }
        Ok(())
    }

    fn map_data(&mut self, addr: usize, len: usize, data: &[u8]) -> Result<(), Self::Error> {
        let aligned_len = len.next_multiple_of(PAGE_SIZE);
        let nz_addr = NonZeroAddress::new(addr).ok_or(MappingError::UnAligned)?;
        let nz_len = NonZeroPageSize::new(aligned_len).ok_or(MappingError::UnAligned)?;

        // SAFETY: We're mapping at a fixed address as requested by the Mach-O loader
        unsafe {
            self.pm.create_writable_pages(
                Some(nz_addr),
                nz_len,
                CreatePagesFlags::FIXED_ADDR,
                |ptr| {
                    ptr.copy_from_slice(0, data)
                        .ok_or(MappingError::OutOfMemory)?;
                    Ok(0)
                },
            )?;
        }
        Ok(())
    }
}

/// Create a stack and set up argc/argv/envp.
///
/// Returns the initial stack pointer (pointing at argc).
///
/// Stack layout (growing down):
/// ```text
/// [strings]      <- string data
/// [padding]
/// [NULL]         <- envp terminator  
/// [envp[n-1]]
/// ...
/// [envp[0]]
/// [NULL]         <- argv terminator
/// [argv[n-1]]
/// ...
/// [argv[0]]
/// [argc]         <- RSP points here
/// ```
pub fn create_stack(
    pm: &PageManager<Platform, PAGE_SIZE>,
    stack_size: usize,
    argv: &[CString],
    envp: &[CString],
) -> Option<usize> {
    // Stack size must be page-aligned
    let aligned_stack_size = stack_size.next_multiple_of(PAGE_SIZE);
    let nz_stack_size = NonZeroPageSize::new(aligned_stack_size)?;

    // Create the stack pages
    let stack_flags = CreatePagesFlags::empty();
    // SAFETY: We're creating new stack pages at a kernel-chosen address
    let stack_base = unsafe {
        pm.create_stack_pages(None, nz_stack_size, stack_flags)
            .ok()?
    };
    let stack_base_addr = stack_base.as_usize();
    let stack_top = stack_base_addr + aligned_stack_size;

    // We'll write from the top of the stack downward
    let ptr: MutPtr<u8> = MutPtr::from_usize(stack_base_addr);

    // Current position, working down from the top
    let mut pos = aligned_stack_size;

    // Helper to push bytes
    let push_bytes = |ptr: MutPtr<u8>, pos: &mut usize, bytes: &[u8]| -> Option<usize> {
        *pos = pos.checked_sub(bytes.len())?;
        ptr.copy_from_slice(*pos, bytes)?;
        Some(*pos)
    };

    // Helper to push a usize
    let push_usize = |stack_base_addr: usize, pos: &mut usize, val: usize| -> Option<()> {
        *pos = pos.checked_sub(core::mem::size_of::<usize>())?;
        let ptr_at_pos: MutPtr<usize> = MutPtr::from_usize(stack_base_addr + *pos);
        ptr_at_pos.write_at_offset(0, val)?;
        Some(())
    };

    // Push string data and collect their addresses
    // First, push a null terminator at the very end
    push_bytes(ptr, &mut pos, &[0])?;

    // Push environment strings (in reverse order so they appear in order)
    let mut envp_addrs: Vec<usize> = Vec::with_capacity(envp.len());
    for env in envp.iter().rev() {
        let bytes = env.as_bytes_with_nul();
        let addr = push_bytes(ptr, &mut pos, bytes)?;
        envp_addrs.push(stack_base_addr + addr);
    }
    envp_addrs.reverse();

    // Push argument strings (in reverse order so they appear in order)
    let mut argv_addrs: Vec<usize> = Vec::with_capacity(argv.len());
    for arg in argv.iter().rev() {
        let bytes = arg.as_bytes_with_nul();
        let addr = push_bytes(ptr, &mut pos, bytes)?;
        argv_addrs.push(stack_base_addr + addr);
    }
    argv_addrs.reverse();

    // Align to 16 bytes
    pos &= !0xF;

    // Calculate how many usize values we need to push
    // argc + argv pointers + NULL + envp pointers + NULL
    let num_items = 1 + argv.len() + 1 + envp.len() + 1;
    let items_size = num_items * core::mem::size_of::<usize>();

    // Make sure the final position is 16-byte aligned after pushing all items
    pos = pos.checked_sub(items_size)?;
    pos &= !0xF;
    // Recalculate position for pushing
    let _final_pos = pos;
    pos = aligned_stack_size - (stack_top - (stack_base_addr + pos));

    // Now push in order (from high to low addresses):
    // envp NULL terminator, envp[n-1], ..., envp[0]
    // argv NULL terminator, argv[n-1], ..., argv[0]
    // argc

    // Push envp NULL terminator
    push_usize(stack_base_addr, &mut pos, 0)?;

    // Push envp pointers (in reverse order)
    for &addr in envp_addrs.iter().rev() {
        push_usize(stack_base_addr, &mut pos, addr)?;
    }

    // Push argv NULL terminator
    push_usize(stack_base_addr, &mut pos, 0)?;

    // Push argv pointers (in reverse order)
    for &addr in argv_addrs.iter().rev() {
        push_usize(stack_base_addr, &mut pos, addr)?;
    }

    // Push argc
    push_usize(stack_base_addr, &mut pos, argv.len())?;

    Some(stack_base_addr + pos)
}
