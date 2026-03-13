// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Windows execution context structures and entry point invocation
//!
//! This module implements stub versions of Windows Thread Environment Block (TEB)
//! and Process Environment Block (PEB) structures, along with the machinery to
//! invoke PE entry points with proper ABI translation.

use crate::{Result, WindowsShimError};

/// Thread Environment Block (TEB) - Minimal stub version
///
/// The TEB is a Windows-internal structure that contains thread-specific information.
/// Windows programs access it via the GS segment register.
/// The PEB pointer MUST be at offset 0x60 for x64 Windows compatibility.
/// TLS slots MUST be at offset 0x1480 for x64 Windows compatibility.
///
/// Reference: Windows Internals, Part 1, 7th Edition
#[repr(C)]
#[derive(Debug, Clone)]
pub struct ThreadEnvironmentBlock {
    /// Pointer to the exception list (offset 0x00)
    pub exception_list: u64,
    /// Stack base address (offset 0x08)
    pub stack_base: u64,
    /// Stack limit address (offset 0x10)
    pub stack_limit: u64,
    /// SubSystem TIB (offset 0x18)
    pub sub_system_tib: u64,
    /// Fiber data or version (offset 0x20)
    pub fiber_data: u64,
    /// Arbitrary data slot (offset 0x28)
    pub arbitrary_user_pointer: u64,
    /// Pointer to self - this TEB (offset 0x30)
    pub self_pointer: u64,
    /// Environment pointer (offset 0x38)
    pub environment_pointer: u64,
    /// Client ID - [process ID, thread ID] (offset 0x40)
    pub client_id: [u64; 2],
    /// Active RPC handle (offset 0x50)
    pub active_rpc_handle: u64,
    /// ThreadLocalStoragePointer (offset 0x58)
    pub thread_local_storage_pointer: u64,
    /// Pointer to PEB - MUST be at offset 0x60 for x64 Windows
    pub peb_pointer: u64,
    /// Reserved fields to reach TLS slots (offset 0x68 to 0x1480)
    /// Size calculation: (0x1480 - 0x68) / 8 = 0x1418 / 8 = 643 u64s
    _reserved2: [u64; 643],
    /// TLS slots - MUST be at offset 0x1480 for x64 Windows (64 slots)
    pub tls_slots: [u64; 64],
}

impl ThreadEnvironmentBlock {
    /// Create a new TEB with the given stack range and PEB pointer
    pub fn new(stack_base: u64, stack_size: u64, peb_pointer: u64) -> Self {
        Self {
            exception_list: 0,
            stack_base,
            stack_limit: stack_base.saturating_sub(stack_size),
            sub_system_tib: 0,
            fiber_data: 0,
            arbitrary_user_pointer: 0,
            self_pointer: 0, // Will be set after allocation
            environment_pointer: 0,
            client_id: [0; 2], // [process_id, thread_id]
            active_rpc_handle: 0,
            thread_local_storage_pointer: 0,
            peb_pointer,
            _reserved2: [0; 643], // Reserved space to reach TLS slots at 0x1480
            tls_slots: [0; 64],   // TLS slots initialized to null
        }
    }

    /// Get the size of the TEB structure in bytes
    pub fn size() -> usize {
        std::mem::size_of::<Self>()
    }
}

/// Process Environment Block (PEB) - Minimal stub version
///
/// The PEB is a Windows-internal structure that contains process-wide information.
/// Windows programs access it via the TEB (at offset 0x60).
///
/// Reference: Windows Internals, Part 1, 7th Edition
#[repr(C)]
#[derive(Debug, Clone)]
pub struct ProcessEnvironmentBlock {
    /// Inherited address space (offset 0x00)
    pub inherited_address_space: u8,
    /// Read image file exec options (offset 0x01)
    pub read_image_file_exec_options: u8,
    /// Being debugged flag (offset 0x02)
    pub being_debugged: u8,
    /// Bit field flags (offset 0x03)
    pub bit_field: u8,
    /// Reserved padding (offset 0x04-0x07)
    _padding: [u8; 4],
    /// Mutant (offset 0x08)
    pub mutant: u64,
    /// Image base address (offset 0x10)
    pub image_base_address: u64,
    /// Loader data pointer (offset 0x18) - initialized to non-null to prevent crashes
    pub ldr: u64,
    /// Process parameters pointer (offset 0x20) - initialized to non-null
    pub process_parameters: u64,
    /// SubSystemData (offset 0x28) - not used
    pub sub_system_data: u64,
    /// Process heap handle (offset 0x30) - MUST be non-null for CRT initialization
    pub process_heap: u64,
    /// FastPebLock pointer (offset 0x38) - not used
    pub fast_peb_lock: u64,
    /// Additional reserved fields (offset 0x40+)
    _reserved: [u64; 47],
}

/// PEB_LDR_DATA - Minimal stub for module loader information
///
/// This structure contains information about loaded modules.
/// We provide a minimal stub to prevent crashes when CRT accesses it.
#[repr(C)]
#[derive(Debug, Clone)]
pub struct PebLdrData {
    /// Length of this structure
    pub length: u32,
    /// Initialized flag
    pub initialized: u32,
    /// SS handle (not used)
    pub ss_handle: u64,
    /// In load order module list (LIST_ENTRY)
    pub in_load_order_module_list: [u64; 2],
    /// In memory order module list (LIST_ENTRY)
    pub in_memory_order_module_list: [u64; 2],
    /// In initialization order module list (LIST_ENTRY)
    pub in_initialization_order_module_list: [u64; 2],
    /// Entry in progress (not used)
    pub entry_in_progress: u64,
}

impl PebLdrData {
    /// Create a new minimal PEB_LDR_DATA structure
    ///
    /// # Arguments
    /// * `self_address` - Address where this structure will be stored (for LIST_ENTRY)
    pub fn new_with_address(self_address: u64) -> Self {
        // Calculate offsets for the list heads
        // in_load_order_module_list starts at offset 0x10 (16)
        let load_order_offset = 0x10u64;
        let memory_order_offset = 0x20u64;
        let init_order_offset = 0x30u64;

        Self {
            #[allow(clippy::cast_possible_truncation)]
            length: std::mem::size_of::<Self>() as u32,
            initialized: 1, // Mark as initialized
            ss_handle: 0,
            // Initialize list heads to point to themselves (empty circular list)
            // Format: [Flink, Blink] where both point to the list head itself
            in_load_order_module_list: [
                self_address + load_order_offset,
                self_address + load_order_offset,
            ],
            in_memory_order_module_list: [
                self_address + memory_order_offset,
                self_address + memory_order_offset,
            ],
            in_initialization_order_module_list: [
                self_address + init_order_offset,
                self_address + init_order_offset,
            ],
            entry_in_progress: 0,
        }
    }
}

impl Default for PebLdrData {
    /// Create a new minimal PEB_LDR_DATA structure with null lists
    ///
    /// Use this when the address is not yet known
    fn default() -> Self {
        Self {
            #[allow(clippy::cast_possible_truncation)]
            length: std::mem::size_of::<Self>() as u32,
            initialized: 1, // Mark as initialized
            ss_handle: 0,
            // Initialize list heads to zero (will be updated later if needed)
            in_load_order_module_list: [0, 0],
            in_memory_order_module_list: [0, 0],
            in_initialization_order_module_list: [0, 0],
            entry_in_progress: 0,
        }
    }
}

/// LDR_DATA_TABLE_ENTRY - Module information entry
///
/// Each loaded module has an entry in the PEB_LDR_DATA linked lists.
/// CRT code may walk these lists to find module information such as the
/// DllBase, SizeOfImage, or module name.
///
/// We provide a minimal entry for the main executable module.
#[repr(C)]
#[derive(Debug, Clone)]
pub struct LdrDataTableEntry {
    /// InLoadOrderLinks (LIST_ENTRY) [Flink, Blink] (offset 0x00)
    pub in_load_order_links: [u64; 2],
    /// InMemoryOrderLinks (LIST_ENTRY) [Flink, Blink] (offset 0x10)
    pub in_memory_order_links: [u64; 2],
    /// InInitializationOrderLinks (LIST_ENTRY) [Flink, Blink] (offset 0x20)
    pub in_initialization_order_links: [u64; 2],
    /// DllBase - base address of the module (offset 0x30)
    pub dll_base: u64,
    /// EntryPoint - entry point of the module (offset 0x38)
    pub entry_point: u64,
    /// SizeOfImage (offset 0x40)
    pub size_of_image: u64,
    /// FullDllName (UNICODE_STRING stub) - [Length, MaxLength, padding, Buffer] (offset 0x48)
    pub full_dll_name: [u64; 2],
    /// BaseDllName (UNICODE_STRING stub) - [Length, MaxLength, padding, Buffer] (offset 0x58)
    pub base_dll_name: [u64; 2],
    /// Reserved fields to prevent crashes during list traversal (offset 0x68+)
    _reserved: [u64; 8],
}

impl LdrDataTableEntry {
    /// Create a new LDR_DATA_TABLE_ENTRY for the main module
    ///
    /// # Arguments
    /// * `dll_base` - Base address of the loaded module
    /// * `entry_point` - Entry point address
    /// * `size_of_image` - Size of the module in memory
    pub fn new(dll_base: u64, entry_point: u64, size_of_image: u64) -> Self {
        Self {
            in_load_order_links: [0, 0],           // Will be patched by caller
            in_memory_order_links: [0, 0],         // Will be patched by caller
            in_initialization_order_links: [0, 0], // Will be patched by caller
            dll_base,
            entry_point,
            size_of_image,
            full_dll_name: [0, 0], // Empty UNICODE_STRING
            base_dll_name: [0, 0], // Empty UNICODE_STRING
            _reserved: [0; 8],
        }
    }
}

/// RTL_USER_PROCESS_PARAMETERS - Minimal stub for process parameters
///
/// Contains command line, environment, and other process startup information.
#[repr(C)]
#[derive(Debug, Clone)]
pub struct RtlUserProcessParameters {
    /// Maximum length
    pub maximum_length: u32,
    /// Length
    pub length: u32,
    /// Flags
    pub flags: u32,
    /// Debug flags
    pub debug_flags: u32,
    /// Console handle
    pub console_handle: u64,
    /// Console flags
    pub console_flags: u32,
    /// Padding
    _padding: u32,
    /// Standard input handle
    pub standard_input: u64,
    /// Standard output handle
    pub standard_output: u64,
    /// Standard error handle  
    pub standard_error: u64,
    /// Additional fields (simplified)
    _reserved: [u64; 20],
}

impl Default for RtlUserProcessParameters {
    /// Create a new minimal RTL_USER_PROCESS_PARAMETERS structure
    fn default() -> Self {
        Self {
            #[allow(clippy::cast_possible_truncation)]
            maximum_length: std::mem::size_of::<Self>() as u32,
            #[allow(clippy::cast_possible_truncation)]
            length: std::mem::size_of::<Self>() as u32,
            flags: 0,
            debug_flags: 0,
            console_handle: 0,
            console_flags: 0,
            _padding: 0,
            standard_input: 0,
            standard_output: 0,
            standard_error: 0,
            _reserved: [0; 20],
        }
    }
}

impl ProcessEnvironmentBlock {
    /// Create a new PEB with the given image base address
    ///
    /// Initializes PEB with minimal stubs for Ldr and ProcessParameters
    /// to prevent crashes when CRT code accesses these fields.
    ///
    /// # Arguments
    /// * `image_base_address` - Base address where the PE image is loaded
    /// * `ldr` - Pointer to PEB_LDR_DATA structure
    /// * `process_parameters` - Pointer to RTL_USER_PROCESS_PARAMETERS structure
    /// * `process_heap` - Process heap handle (must be non-null for CRT)
    pub fn new(
        image_base_address: u64,
        ldr: u64,
        process_parameters: u64,
        process_heap: u64,
    ) -> Self {
        Self {
            inherited_address_space: 0,
            read_image_file_exec_options: 0,
            being_debugged: 0,
            bit_field: 0,
            _padding: [0; 4],
            mutant: 0,
            image_base_address,
            ldr,
            process_parameters,
            sub_system_data: 0,
            process_heap,
            fast_peb_lock: 0,
            _reserved: [0; 47],
        }
    }

    /// Get the size of the PEB structure in bytes
    pub fn size() -> usize {
        std::mem::size_of::<Self>()
    }
}

/// Windows entry point function signature
///
/// DLL entry points have the signature:
/// ```c
/// BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved);
/// ```
///
/// EXE entry points have various signatures, but typically:
/// ```c
/// int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow);
/// int wmain(int argc, wchar_t *argv[]);
/// int main(int argc, char *argv[]);
/// ```
///
/// For simplicity, we'll treat the entry point as a function that takes no arguments
/// and returns an integer exit code.
pub type EntryPointFn = unsafe extern "C" fn() -> i32;

/// Execution context for a Windows program
///
/// This structure holds all the state needed to execute a Windows PE binary,
/// including the TEB, PEB, and stack information.
#[derive(Debug)]
pub struct ExecutionContext {
    /// Thread Environment Block
    pub teb: Box<ThreadEnvironmentBlock>,
    /// Process Environment Block
    pub peb: Box<ProcessEnvironmentBlock>,
    /// PEB Loader Data
    pub ldr: Box<PebLdrData>,
    /// Main module LDR entry (linked into the PEB_LDR_DATA lists)
    pub main_module_entry: Box<LdrDataTableEntry>,
    /// Process Parameters
    pub process_parameters: Box<RtlUserProcessParameters>,
    /// TEB address in memory (for self-pointer)
    pub teb_address: u64,
    /// Stack base address
    pub stack_base: u64,
    /// Stack size in bytes
    pub stack_size: u64,
    /// Pointer to allocated stack memory (for cleanup)
    stack_ptr: Option<*mut u8>,
    /// TLS data pointer (for cleanup)
    tls_data_ptr: Option<*mut u8>,
    /// TLS data size
    tls_data_size: usize,
}

impl ExecutionContext {
    /// Create a new execution context with the given parameters
    ///
    /// # Arguments
    /// * `image_base` - Base address where the PE image is loaded
    /// * `stack_size` - Size of the stack to allocate (default 1MB if 0)
    ///
    /// # Returns
    /// A new ExecutionContext with allocated TEB and PEB
    ///
    /// # Safety
    /// This function uses mmap to allocate stack memory. The caller must ensure
    /// the ExecutionContext is properly dropped to free the allocated memory.
    pub fn new(image_base: u64, stack_size: u64) -> Result<Self> {
        let stack_size = if stack_size == 0 {
            1024 * 1024 // Default 1MB stack
        } else {
            stack_size
        };

        // Allocate actual stack memory using mmap
        // SAFETY: We're calling mmap with valid parameters to allocate memory
        // for the stack. The memory will be freed in the Drop implementation.
        #[allow(clippy::cast_possible_truncation)]
        let stack_ptr = unsafe {
            libc::mmap(
                core::ptr::null_mut(),
                stack_size as libc::size_t,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };

        if stack_ptr == libc::MAP_FAILED {
            return Err(WindowsShimError::MemoryAllocationFailed(
                "Failed to allocate stack memory".to_string(),
            ));
        }

        // Stack grows downward, so stack_base is at the top of the allocated region
        // SAFETY: We just allocated this memory successfully, so it's a valid pointer
        #[allow(clippy::cast_sign_loss)]
        #[allow(clippy::cast_possible_truncation)]
        let stack_base = unsafe { stack_ptr.add(stack_size as usize) }.addr() as u64;

        // Create PEB Loader Data - first without address
        let mut ldr = Box::<PebLdrData>::default();
        let ldr_address = &raw const *ldr as u64;

        // Now update with proper circular list pointers
        *ldr = PebLdrData::new_with_address(ldr_address);

        // Create main module LDR entry and link it into the lists
        let mut main_module_entry = Box::new(LdrDataTableEntry::new(image_base, 0, 0));
        let entry_address = &raw const *main_module_entry as u64;

        // Link the entry into all three circular lists
        // The list heads in PebLdrData point to the LIST_ENTRY within the entry,
        // and the entry's LIST_ENTRY points back to the list head.
        //
        // PEB_LDR_DATA list heads are at offsets 0x10, 0x20, 0x30 from ldr_address
        // LDR_DATA_TABLE_ENTRY list links are at offsets 0x00, 0x10, 0x20 from entry_address
        let load_order_head = ldr_address + 0x10;
        let memory_order_head = ldr_address + 0x20;
        let init_order_head = ldr_address + 0x30;

        // InLoadOrderLinks: entry at offset 0x00
        main_module_entry.in_load_order_links = [load_order_head, load_order_head];
        ldr.in_load_order_module_list = [entry_address, entry_address];

        // InMemoryOrderLinks: entry at offset 0x10
        let entry_memory_links = entry_address + 0x10;
        main_module_entry.in_memory_order_links = [memory_order_head, memory_order_head];
        ldr.in_memory_order_module_list = [entry_memory_links, entry_memory_links];

        // InInitializationOrderLinks: entry at offset 0x20
        let entry_init_links = entry_address + 0x20;
        main_module_entry.in_initialization_order_links = [init_order_head, init_order_head];
        ldr.in_initialization_order_module_list = [entry_init_links, entry_init_links];

        // Create Process Parameters
        let process_parameters = Box::<RtlUserProcessParameters>::default();
        let process_parameters_address = &raw const *process_parameters as u64;

        // Create PEB with pointers to Ldr and ProcessParameters
        // Use 0x7FFE_0000 as a fake process heap handle (same as kernel32_GetProcessHeap)
        let process_heap = 0x7FFE_0000u64;
        let peb = Box::new(ProcessEnvironmentBlock::new(
            image_base,
            ldr_address,
            process_parameters_address,
            process_heap,
        ));
        let peb_address = &raw const *peb as u64;

        // Create TEB with pointer to PEB
        let mut teb = Box::new(ThreadEnvironmentBlock::new(
            stack_base,
            stack_size,
            peb_address,
        ));

        // Set TEB self-pointer
        let teb_address = &raw const *teb as u64;
        teb.self_pointer = teb_address;
        teb.thread_local_storage_pointer = teb.tls_slots.as_ptr() as u64;

        // Set thread and process IDs in TEB client_id
        // client_id[0] = process ID, client_id[1] = thread ID
        // SAFETY: getpid is a safe syscall; SYS_gettid returns the thread ID
        let pid = unsafe { libc::getpid() };
        let tid = unsafe { libc::syscall(libc::SYS_gettid) };
        #[allow(clippy::cast_sign_loss)]
        {
            teb.client_id = [pid as u64, tid as u64];
        }

        Ok(Self {
            teb,
            peb,
            ldr,
            main_module_entry,
            process_parameters,
            teb_address,
            stack_base,
            stack_size,
            stack_ptr: Some(stack_ptr.cast::<u8>()),
            tls_data_ptr: None,
            tls_data_size: 0,
        })
    }

    /// Get a pointer to the TEB
    pub fn teb_ptr(&self) -> *const ThreadEnvironmentBlock {
        &raw const *self.teb
    }

    /// Get a pointer to the PEB
    pub fn peb_ptr(&self) -> *const ProcessEnvironmentBlock {
        &raw const *self.peb
    }

    /// Initialize TLS (Thread Local Storage) data
    ///
    /// This allocates memory for TLS data, copies the template data, and sets up
    /// the TLS slot in the TEB to point to the allocated data.
    ///
    /// # Arguments
    /// * `image_base` - Base address where the PE image is loaded (unused, for future use)
    /// * `tls_start_va` - Virtual address of TLS data start (from TLS directory)
    /// * `tls_end_va` - Virtual address of TLS data end (from TLS directory)
    /// * `tls_index_va` - Virtual address of TLS index variable (from TLS directory)
    /// * `size_of_zero_fill` - Size of zero-filled data after the template
    ///
    /// # Safety
    /// This function is unsafe because it:
    /// - Reads from arbitrary memory addresses (the TLS template)
    /// - Writes to arbitrary memory addresses (TLS index, TLS slot)
    /// - Uses mmap to allocate memory
    ///
    /// The caller must ensure:
    /// - The TLS template addresses are valid and readable
    /// - The TLS index address is valid and writable
    /// - All addresses are properly relocated if needed
    pub unsafe fn initialize_tls(
        &mut self,
        _image_base: u64,
        tls_start_va: u64,
        tls_end_va: u64,
        tls_index_va: u64,
        size_of_zero_fill: u32,
    ) -> Result<()> {
        // Calculate size of TLS template data
        #[allow(clippy::cast_possible_truncation)]
        let template_size = tls_end_va.checked_sub(tls_start_va).ok_or_else(|| {
            WindowsShimError::InvalidParameter(format!(
                "Invalid TLS range: start 0x{tls_start_va:X} >= end 0x{tls_end_va:X}"
            ))
        })? as usize;

        // Total TLS data size includes template + zero fill
        let total_size = template_size
            .checked_add(size_of_zero_fill as usize)
            .ok_or_else(|| {
                WindowsShimError::InvalidParameter("TLS data size overflow".to_string())
            })?;

        if total_size == 0 {
            // No TLS data to initialize
            return Ok(());
        }

        // Allocate memory for TLS data
        // SAFETY: We're calling mmap with valid parameters to allocate memory.
        // The memory will be freed in the Drop implementation.
        #[allow(clippy::cast_possible_truncation)]
        let tls_data_ptr = unsafe {
            libc::mmap(
                core::ptr::null_mut(),
                total_size as libc::size_t,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };

        if tls_data_ptr == libc::MAP_FAILED {
            return Err(WindowsShimError::MemoryAllocationFailed(
                "Failed to allocate TLS data memory".to_string(),
            ));
        }

        // Copy template data from the image
        if template_size > 0 {
            // SAFETY: Caller guarantees tls_start_va is valid and readable.
            // We just allocated tls_data_ptr and it's valid for total_size bytes.
            unsafe {
                core::ptr::copy_nonoverlapping(
                    tls_start_va as *const u8,
                    tls_data_ptr.cast::<u8>(),
                    template_size,
                );
            }
        }

        // Zero-fill the remaining space
        if size_of_zero_fill > 0 {
            // SAFETY: tls_data_ptr is valid for total_size bytes
            unsafe {
                let zero_fill_ptr = tls_data_ptr.cast::<u8>().add(template_size);
                core::ptr::write_bytes(zero_fill_ptr, 0, size_of_zero_fill as usize);
            }
        }

        // Set the TLS index to 0 (we only support one TLS index for now)
        // SAFETY: Caller guarantees tls_index_va is valid and writable
        unsafe {
            let index_ptr = tls_index_va as *mut u32;
            index_ptr.write_unaligned(0);
        }

        // Set TLS slot[0] in the TEB to point to the allocated TLS data
        self.teb.tls_slots[0] = tls_data_ptr.addr() as u64;

        // Store for cleanup
        self.tls_data_ptr = Some(tls_data_ptr.cast::<u8>());
        self.tls_data_size = total_size;

        Ok(())
    }
}

impl Drop for ExecutionContext {
    fn drop(&mut self) {
        // Clean up allocated TLS data memory
        if let Some(tls_data_ptr) = self.tls_data_ptr
            && self.tls_data_size > 0
        {
            // SAFETY: This memory was allocated by mmap in initialize_tls,
            // so it's safe to unmap it here.
            #[allow(clippy::cast_possible_truncation)]
            unsafe {
                libc::munmap(
                    tls_data_ptr.cast::<libc::c_void>(),
                    self.tls_data_size as libc::size_t,
                );
            }
        }

        // Clean up allocated stack memory
        if let Some(stack_ptr) = self.stack_ptr {
            // SAFETY: This memory was allocated by mmap in the constructor,
            // so it's safe to unmap it here. We use the original stack_ptr
            // (not stack_base) because munmap expects the address returned by mmap.
            #[allow(clippy::cast_possible_truncation)]
            unsafe {
                libc::munmap(
                    stack_ptr.cast::<libc::c_void>(),
                    self.stack_size as libc::size_t,
                );
            }
        }
    }
}

/// Call a Windows PE entry point with proper ABI setup
///
/// This function handles the ABI translation between Linux (System V AMD64) and
/// Windows (Microsoft x64 calling convention). It sets up a proper stack and
/// calls the entry point with the Windows ABI.
///
/// # Safety
/// This function is unsafe because:
/// - It calls a function pointer at an arbitrary memory address
/// - It assumes the entry point is valid code
/// - It assumes the memory is executable
/// - It switches to a different stack during execution
/// - No validation is performed on the entry point
///
/// The caller must ensure:
/// - The entry point address points to valid, executable code
/// - The PE binary has been properly loaded and relocated
/// - All imports have been resolved
/// - The execution context is properly initialized
/// - The GS register has been set to point to the TEB
///
/// # Arguments
/// * `entry_point_address` - Address of the entry point to call (base + RVA)
/// * `context` - Execution context with TEB/PEB and allocated stack
///
/// # Returns
/// The exit code returned by the entry point, or an error if execution fails
pub unsafe fn call_entry_point(
    entry_point_address: usize,
    context: &ExecutionContext,
) -> Result<i32> {
    unsafe {
        let page = 0x0040_0000usize as *mut libc::c_void;
        let mapped = libc::mmap(
            page,
            4096,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED_NOREPLACE,
            -1,
            0,
        );
        if mapped == page {
            // SAFETY: `mapped` is a writable page we just mapped at `page`.
            *(mapped.cast::<u8>()) = 0xC3; // ret

            // SAFETY: `mapped` points to a valid mapping of length 4096 we just created.
            let rc = libc::mprotect(mapped, 4096, libc::PROT_READ | libc::PROT_EXEC);
            if rc != 0 {
                let _ = libc::munmap(mapped, 4096);
            }
        } else if mapped != libc::MAP_FAILED {
            let _ = libc::munmap(mapped, 4096);
        }
    }

    // Validate entry point is not null
    if entry_point_address == 0 {
        return Err(WindowsShimError::InvalidParameter(
            "Entry point address is null".to_string(),
        ));
    }

    // Windows x64 calling convention requires RSP to be 16-byte aligned
    // BEFORE the call instruction executes. The call instruction then pushes
    // an 8-byte return address, resulting in RSP being misaligned by 8 bytes
    // at function entry (this is correct per the ABI).
    //
    // The stack grows downward, so stack_base is the highest address.
    // We need to reserve "shadow space" (32 bytes minimum) required by the
    // Windows x64 calling convention for the first 4 register parameters.

    let stack_top = context.stack_base;

    // Align to 16 bytes (BEFORE call instruction)
    let aligned_stack = stack_top & !0xF;

    // Reserve shadow space (32 bytes) - required by Windows x64 ABI
    // After subtracting 32, RSP is still 16-byte aligned (32 is multiple of 16)
    let stack_with_shadow = aligned_stack - 32;

    // Call the entry point with proper stack setup
    // We use inline assembly to:
    // 1. Save current RSP
    // 2. Switch to the new stack
    // 3. Call the entry point
    // 4. Restore the original RSP
    // 5. Return the result
    //
    // SAFETY: We're switching stacks and calling arbitrary code. The caller must
    // ensure the entry point is valid code and all imports are resolved.
    let exit_code: i32;
    unsafe {
        core::arch::asm!(
            // Save the current stack pointer
            "push rbp",
            "mov rbp, rsp",

            // Switch to the new stack (already properly aligned)
            "mov rsp, {new_stack}",

            // Call the entry point
            // Note: The entry point might be mainCRTStartup or similar, which
            // expects no parameters. Windows x64 ABI requires shadow space to be
            // allocated by caller even if no parameters are passed.
            "call {entry_point}",

            // Restore the original stack
            "mov rsp, rbp",
            "pop rbp",

            entry_point = in(reg) entry_point_address,
            new_stack = in(reg) stack_with_shadow,
            lateout("rax") exit_code,

            // Explicitly list clobbered registers instead of using clobber_abi
            // The Windows x64 calling convention can clobber: rax, rcx, rdx, r8-r11, xmm0-xmm5
            // We preserve: rbx, rbp, rdi, rsi, rsp, r12-r15, xmm6-xmm15
            out("rcx") _,
            out("rdx") _,
            out("r8") _,
            out("r9") _,
            out("r10") _,
            out("r11") _,
        );
    }

    Ok(exit_code)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_teb_creation() {
        let stack_base = 0x7FFF_FFFF_0000u64;
        let stack_size = 1024 * 1024; // 1MB
        let peb_ptr = 0x1234_5678u64;

        let teb = ThreadEnvironmentBlock::new(stack_base, stack_size, peb_ptr);

        assert_eq!(teb.stack_base, stack_base);
        assert_eq!(teb.stack_limit, stack_base - stack_size);
        assert_eq!(teb.peb_pointer, peb_ptr);
    }

    #[test]
    fn test_peb_creation() {
        let image_base = 0x0000_0001_4000_0000u64;
        let ldr_address = 0x7FFF_0000_0000u64;
        let process_params_address = 0x7FFF_0001_0000u64;
        let process_heap = 0x7FFE_0000u64;
        let peb = ProcessEnvironmentBlock::new(
            image_base,
            ldr_address,
            process_params_address,
            process_heap,
        );

        assert_eq!(peb.image_base_address, image_base);
        assert_eq!(peb.ldr, ldr_address);
        assert_eq!(peb.process_parameters, process_params_address);
        assert_eq!(peb.process_heap, process_heap);
        assert_eq!(peb.being_debugged, 0);
    }

    #[test]
    fn test_execution_context_creation() {
        let image_base = 0x0000_0001_4000_0000u64;
        let stack_size = 2 * 1024 * 1024; // 2MB

        let context = ExecutionContext::new(image_base, stack_size).unwrap();

        assert_eq!(context.peb.image_base_address, image_base);
        assert_eq!(context.stack_size, stack_size);
        assert_ne!(context.teb_address, 0);
    }

    #[test]
    fn test_execution_context_default_stack() {
        let image_base = 0x0000_0001_4000_0000u64;

        let context = ExecutionContext::new(image_base, 0).unwrap();

        assert_eq!(context.stack_size, 1024 * 1024); // Default 1MB
    }

    #[test]
    fn test_teb_tls_offset() {
        // Verify that TLS slots are at the correct offset (0x1480) for x64 Windows
        use std::mem::{offset_of, size_of};

        // Check PEB pointer is at offset 0x60
        assert_eq!(offset_of!(ThreadEnvironmentBlock, peb_pointer), 0x60);

        // Check TLS slots are at offset 0x1480
        assert_eq!(offset_of!(ThreadEnvironmentBlock, tls_slots), 0x1480);

        println!("TEB size: 0x{:X}", size_of::<ThreadEnvironmentBlock>());
    }

    #[test]
    fn test_tls_initialization() {
        let image_base = 0x0000_0001_4000_0000u64;
        let mut context = ExecutionContext::new(image_base, 0).unwrap();

        // Create a mock TLS data template
        let tls_template = vec![0x11u8, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];

        // Allocate memory for TLS template and index
        let template_ptr = tls_template.as_ptr() as u64;
        let template_end = template_ptr + tls_template.len() as u64;

        // Allocate space for TLS index
        let mut tls_index: u32 = 0xFFFFFFFF;
        let index_ptr = &raw mut tls_index as u64;

        // Initialize TLS with our test data
        unsafe {
            context
                .initialize_tls(
                    image_base,
                    template_ptr,
                    template_end,
                    index_ptr,
                    0, // No zero fill
                )
                .unwrap();
        }

        // Verify TLS index was set to 0
        assert_eq!(tls_index, 0);

        // Verify TLS slot[0] is not null
        assert_ne!(context.teb.tls_slots[0], 0);

        // Verify the data was copied correctly
        unsafe {
            let tls_data = core::slice::from_raw_parts(
                context.teb.tls_slots[0] as *const u8,
                tls_template.len(),
            );
            assert_eq!(tls_data, tls_template.as_slice());
        }
    }

    #[test]
    fn test_peb_field_offsets() {
        use std::mem::offset_of;

        // Verify critical PEB field offsets match Windows x64 layout
        assert_eq!(
            offset_of!(ProcessEnvironmentBlock, inherited_address_space),
            0x00
        );
        assert_eq!(offset_of!(ProcessEnvironmentBlock, being_debugged), 0x02);
        assert_eq!(offset_of!(ProcessEnvironmentBlock, mutant), 0x08);
        assert_eq!(
            offset_of!(ProcessEnvironmentBlock, image_base_address),
            0x10
        );
        assert_eq!(offset_of!(ProcessEnvironmentBlock, ldr), 0x18);
        assert_eq!(
            offset_of!(ProcessEnvironmentBlock, process_parameters),
            0x20
        );
        assert_eq!(offset_of!(ProcessEnvironmentBlock, process_heap), 0x30);
    }

    #[test]
    fn test_execution_context_has_process_heap() {
        let image_base = 0x0000_0001_4000_0000u64;
        let context = ExecutionContext::new(image_base, 0).unwrap();

        // Verify process heap is non-null (required for CRT initialization)
        assert_ne!(context.peb.process_heap, 0);
        assert_eq!(context.peb.process_heap, 0x7FFE_0000);
    }

    #[test]
    fn test_teb_client_id_set() {
        let image_base = 0x0000_0001_4000_0000u64;
        let context = ExecutionContext::new(image_base, 0).unwrap();

        // Verify client_id (process/thread IDs) are set
        assert_ne!(context.teb.client_id[0], 0); // Process ID
        assert_ne!(context.teb.client_id[1], 0); // Thread ID
    }
}
