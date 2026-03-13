// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Trampoline generation and executable memory management
//!
//! This module provides functionality to:
//! - Allocate executable memory for function trampolines
//! - Generate trampolines that bridge Windows x64 calling convention to System V AMD64
//! - Manage the lifetime of executable memory allocations

use crate::{PlatformError, Result};
use std::collections::HashMap;
use std::sync::Mutex;

/// Executable memory region for trampolines
struct ExecutableMemory {
    /// Base address of the allocated memory
    base: usize,
    /// Size of the allocated memory
    size: usize,
    /// Current offset for next allocation
    offset: usize,
}

impl ExecutableMemory {
    /// Allocate a new executable memory region
    ///
    /// # Safety
    /// Creates memory with PROT_READ | PROT_WRITE | PROT_EXEC permissions
    unsafe fn new(size: usize) -> Result<Self> {
        use libc::{MAP_ANONYMOUS, MAP_PRIVATE, PROT_EXEC, PROT_READ, PROT_WRITE, mmap};

        // Allocate memory with read, write, and execute permissions
        // SAFETY: We're requesting executable memory which is inherently dangerous.
        // The caller must ensure only valid machine code is written to this memory.
        let ptr = unsafe {
            mmap(
                core::ptr::null_mut(),
                size,
                PROT_READ | PROT_WRITE | PROT_EXEC,
                MAP_PRIVATE | MAP_ANONYMOUS,
                -1,
                0,
            )
        };

        if ptr == libc::MAP_FAILED {
            return Err(PlatformError::MemoryError(
                "Failed to allocate executable memory".to_string(),
            ));
        }

        Ok(Self {
            base: ptr as usize,
            size,
            offset: 0,
        })
    }

    /// Allocate space within this memory region
    fn allocate(&mut self, size: usize) -> Option<usize> {
        if self.offset + size > self.size {
            return None;
        }

        let addr = self.base + self.offset;
        self.offset += size;
        Some(addr)
    }
}

impl Drop for ExecutableMemory {
    fn drop(&mut self) {
        // SAFETY: We're unmapping memory that we previously allocated with mmap.
        // This is safe as long as no code is currently executing in this region.
        unsafe {
            libc::munmap(self.base as *mut libc::c_void, self.size);
        }
    }
}

/// Manager for executable memory and trampolines
pub struct TrampolineManager {
    /// Allocated memory regions
    regions: Mutex<Vec<ExecutableMemory>>,
    /// Map of function name to trampoline address
    trampolines: Mutex<HashMap<String, usize>>,
}

impl TrampolineManager {
    /// Default size for each executable memory region (64KB)
    const DEFAULT_REGION_SIZE: usize = 64 * 1024;

    /// Create a new trampoline manager
    pub fn new() -> Self {
        Self {
            regions: Mutex::new(Vec::new()),
            trampolines: Mutex::new(HashMap::new()),
        }
    }

    /// Allocate executable memory for a trampoline
    ///
    /// Returns the address where the trampoline code should be written.
    ///
    /// # Safety
    /// The returned address points to executable memory. The caller must ensure
    /// only valid machine code is written to this address.
    ///
    /// # Panics
    /// Panics if the internal mutex is poisoned.
    pub unsafe fn allocate_trampoline(&self, name: String, code: &[u8]) -> Result<usize> {
        let mut regions = self.regions.lock().unwrap();
        let mut trampolines = self.trampolines.lock().unwrap();

        // Check if already allocated
        if let Some(&addr) = trampolines.get(&name) {
            return Ok(addr);
        }

        // Try to allocate from existing region
        for region in regions.iter_mut() {
            if let Some(addr) = region.allocate(code.len()) {
                // Write the trampoline code
                // SAFETY: We just allocated this memory and have exclusive access
                unsafe {
                    core::ptr::copy_nonoverlapping(code.as_ptr(), addr as *mut u8, code.len());
                }
                trampolines.insert(name, addr);
                return Ok(addr);
            }
        }

        // Need to allocate a new region
        let size = Self::DEFAULT_REGION_SIZE.max(code.len());
        // SAFETY: We're allocating executable memory for trampolines
        let mut region = unsafe { ExecutableMemory::new(size)? };

        let addr = region.allocate(code.len()).ok_or_else(|| {
            PlatformError::MemoryError("Failed to allocate trampoline".to_string())
        })?;

        // Write the trampoline code
        // SAFETY: We just allocated this memory and have exclusive access
        unsafe {
            core::ptr::copy_nonoverlapping(code.as_ptr(), addr as *mut u8, code.len());
        }

        regions.push(region);
        trampolines.insert(name, addr);

        Ok(addr)
    }

    /// Get the address of a previously allocated trampoline
    ///
    /// # Panics
    /// Panics if the internal mutex is poisoned.
    pub fn get_trampoline(&self, name: &str) -> Option<usize> {
        self.trampolines.lock().unwrap().get(name).copied()
    }

    /// Get statistics about allocated memory
    ///
    /// Returns (total_allocated, total_used) in bytes.
    ///
    /// # Panics
    /// Panics if the internal mutex is poisoned.
    pub fn stats(&self) -> (usize, usize) {
        let regions = self.regions.lock().unwrap();
        let total_allocated: usize = regions.iter().map(|r| r.size).sum();
        let total_used: usize = regions.iter().map(|r| r.offset).sum();
        (total_allocated, total_used)
    }
}

impl Default for TrampolineManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trampoline_manager_creation() {
        let manager = TrampolineManager::new();
        let (allocated, used) = manager.stats();
        assert_eq!(allocated, 0);
        assert_eq!(used, 0);
    }

    #[test]
    fn test_allocate_trampoline() {
        let manager = TrampolineManager::new();

        // Simple NOP sled for testing
        let code = vec![0x90, 0x90, 0x90, 0xC3]; // NOP NOP NOP RET

        // SAFETY: We're allocating test code
        let addr1 = unsafe { manager.allocate_trampoline("test_func".to_string(), &code) };
        assert!(addr1.is_ok());

        // Allocating the same function again should return the same address
        let addr2 = unsafe { manager.allocate_trampoline("test_func".to_string(), &code) };
        assert_eq!(addr1.unwrap(), addr2.unwrap());

        // Stats should show some allocation
        let (allocated, used) = manager.stats();
        assert!(allocated > 0);
        assert!(used >= code.len());
    }

    #[test]
    fn test_get_trampoline() {
        let manager = TrampolineManager::new();
        let code = vec![0xC3]; // RET

        // SAFETY: We're allocating test code
        let addr = unsafe {
            manager
                .allocate_trampoline("func".to_string(), &code)
                .unwrap()
        };

        assert_eq!(manager.get_trampoline("func"), Some(addr));
        assert_eq!(manager.get_trampoline("nonexistent"), None);
    }

    #[test]
    fn test_multiple_trampolines() {
        let manager = TrampolineManager::new();

        let code1 = vec![0xC3]; // RET
        let code2 = vec![0x90, 0xC3]; // NOP RET
        let code3 = vec![0x90, 0x90, 0xC3]; // NOP NOP RET

        // SAFETY: We're allocating test code
        let addr1 = unsafe {
            manager
                .allocate_trampoline("func1".to_string(), &code1)
                .unwrap()
        };
        let addr2 = unsafe {
            manager
                .allocate_trampoline("func2".to_string(), &code2)
                .unwrap()
        };
        let addr3 = unsafe {
            manager
                .allocate_trampoline("func3".to_string(), &code3)
                .unwrap()
        };

        // All addresses should be different
        assert_ne!(addr1, addr2);
        assert_ne!(addr2, addr3);
        assert_ne!(addr1, addr3);

        // All should be retrievable
        assert_eq!(manager.get_trampoline("func1"), Some(addr1));
        assert_eq!(manager.get_trampoline("func2"), Some(addr2));
        assert_eq!(manager.get_trampoline("func3"), Some(addr3));
    }
}
