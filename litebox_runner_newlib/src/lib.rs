//! LiteBox Runner for Newlib
//!
//! This crate provides a runtime environment for applications using Newlib's static libc (libc.a)
//! with LiteBox. It initializes the platform, filesystem, and registers the syscall handler.
//! 
//! This crate is compiled as a static library called liblitebox_newlib.a, which contains
//! C syscall function backends (read and write) that leverage litebox_shim_linux's
//! handle_syscall_request to process the syscalls.


#![cfg_attr(feature = "platform_mock_nostd", no_std)]
#![no_main]
// #![feature(linkage)]

extern crate alloc;
use core::arch::asm;
use core::ffi;
use syscalls::{syscall, Sysno};

#[expect(clippy::inline_always)]
#[inline(always)]
pub fn hlt_loop() -> ! {
    loop {
        unsafe {
            asm!("hlt");
        }
    }
}

/// Print formatted arguments to console output by writing to stdout
#[doc(hidden)]
pub fn print(args: core::fmt::Arguments) {
    let formatted = alloc::format!("{}", args);
    let bytes = formatted.as_bytes();
    unsafe {
        let _ = syscall!(Sysno::write, 1, bytes.as_ptr(), bytes.len());
    }
}

#[macro_export]
macro_rules! newlib_print {
    ($($arg:tt)*) => ($crate::print(format_args!($($arg)*)));
}

#[macro_export]
macro_rules! newlib_println {
    () => ($crate::newlib_print!("\n"));
    ($($arg:tt)*) => ($crate::newlib_print!("{}\n", format_args!($($arg)*)));
}


#[cfg(feature = "platform_mock_nostd")]
#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    newlib_println!("newlib-runtime panic: {}", info);
    hlt_loop()
}

use litebox::LiteBox;
use litebox_common_linux::{SyscallRequest, errno::Errno};
use litebox_platform_multiplex::Platform;

/// Entry point for x86_64 ELF executables with newlib
/// 
/// This is called by crt0.S with argc and argv as parameters:
/// - argc: number of command line arguments
/// - argv: array of pointers to argument strings
/// 
/// This function:
/// 1. Calculates envp from argc and argv
/// 2. Initializes the runtime environment
/// 3. Calls newlib's __libc_init_array() and main()
/// 4. Exits with the return value
///
/// Stack layout when called:
/// - argc is passed in %rdi (first parameter)
/// - argv is passed in %rsi (second parameter)
/// - envp is calculated as argv + (argc + 1)
#[unsafe(no_mangle)]
pub unsafe extern "C" fn _start(argc: ffi::c_int, argv: *const *const ffi::c_char) -> ! {
    // Calculate envp pointer (argv + (argc + 1))
    // envp starts after argv array + null terminator
    let envp = argv.add((argc + 1) as usize) as *const *const ffi::c_char;
    
    // Initialize the LiteBox environment
    __init_litebox_runtime();
    
    // // Call newlib's initialization functions
    // __libc_init_array();
    
    // Call main function
    unsafe extern "C" {
        // fn _init();
        fn main(argc: ffi::c_int, argv: *const *const ffi::c_char, envp: *const *const ffi::c_char) -> ffi::c_int;
        // fn _fini();
    }

    unsafe {
        // _init();
        let exit_code = main(argc, argv, envp);
        // _fini();
        
        //todo(chuqi): remove debug log
        newlib_println!("main returned: {}", exit_code);
    }
    // Exit with the return code
    // _exit(exit_code);
    // don't exit for now
    panic!("finish!");
}


static CURRENT_BRK : core::sync::atomic::AtomicPtr<u8> = 
    core::sync::atomic::AtomicPtr::new(core::ptr::null_mut()); 

/// Initialize the LiteBox runtime environment
/// 
/// This function initializes the platform, filesystem, and registers the syscall handler.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __init_litebox_runtime() {
    // Initialize platform (will be MockNoStdPlatform if feature "platform_mock_nostd" is enabled)
    let platform = Platform::new(None);
    
    let litebox = LiteBox::new(platform);

    // Initialize filesystem
    let in_mem = litebox::fs::in_mem::FileSystem::new(&litebox);
    let tar_ro = litebox::fs::tar_ro::FileSystem::new(&litebox, litebox::fs::tar_ro::empty_tar_file());
    let dev_stdio = litebox::fs::devices::stdio::FileSystem::new(&litebox);
    
    // Create layered filesystem
    let initial_file_system = litebox::fs::layered::FileSystem::new(
        &litebox,
        in_mem,
        litebox::fs::layered::FileSystem::new(
            &litebox,
            dev_stdio,
            tar_ro,
            litebox::fs::layered::LayeringSemantics::LowerLayerReadOnly,
        ),
        litebox::fs::layered::LayeringSemantics::LowerLayerWritableFiles,
    );
    
    // Set up filesystem and platform
    litebox_shim_linux::set_fs(initial_file_system);
    litebox_platform_multiplex::set_platform(platform);
    
    // Register syscall handler
    // chuqi: I don't think this is necessary for newlib, as we don't hook real syscall
    //        instructions; instead, we provide our own implementations. 
    // platform.register_syscall_handler(litebox_shim_linux::handle_syscall_request);

    // Initialize the program's brk
    let mut current_brk = CURRENT_BRK.load(core::sync::atomic::Ordering::Relaxed);
    if current_brk.is_null() {
        // If this is the first call, initialize the current break pointer
        // Use _end symbol from linker script (end of all data sections)
        unsafe extern "C" {
            static _end: u8;
        }
        
        // Set initial brk to the end of data sections
        let heap_start_raw = &_end as *const u8 as *mut u8;
        
        // Align heap start to page boundary (4KB) for better memory management
        const PAGE_SIZE: usize = 4096;
        let heap_start_aligned = (heap_start_raw as usize + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
        let heap_start = heap_start_aligned as *mut u8;

        current_brk = match _do_syscall_shim(12, &[heap_start as usize]) {
            neg_value if neg_value < 0 => {
                panic!("Initial brk syscall failed with error {}", neg_value);
            }
            brk => {
                newlib_println!("[_start] Initial brk set to {:p}", brk as *mut u8);
                brk as *mut u8
            }
        };
        
        // Store the initial brk
        CURRENT_BRK.store(current_brk, core::sync::atomic::Ordering::Relaxed);
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __prog_exit() {
    // do nothing for now
}


/// Handles the common logic of creating a SyscallRequest and calling the handler.
fn _do_syscall_shim(sys_id: usize, args: &[usize]) -> isize {
    // todo(chuqi): lazy but a bad way of using an additional memory-copy
    //        we should use a fixed-size array instead to avoid this costly copy.
    let mut padded_args = [0usize; 6];
    let copy_len = args.len().min(6);
    padded_args[..copy_len].copy_from_slice(&args[..copy_len]);

    // todo(chuqi): remove debug log
    // Log syscall information using our no-alloc debug macro
    newlib_println!(
        "Syscall: sys_id = {}, args = [{}, {}, {}, {}, {}]",
        sys_id,
        padded_args[0],
        padded_args[1],
        padded_args[2],
        padded_args[3],
        padded_args[4]
    );

    match SyscallRequest::try_from_raw(sys_id, &padded_args) {
        Ok(request) => {
            litebox_shim_linux::handle_syscall_request(request)
        }
        Err(e) => {
            e.as_neg() as isize
        }
    }
}

/// Read from a file descriptor
///
/// This function implements the POSIX read() syscall for newlib.
/// It translates the call to litebox_shim_linux's handle_syscall_request function.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn read(fd: i32, buf: *mut u8, count: usize) -> isize {
    if buf.is_null() {
        return Errno::EFAULT.as_neg() as isize;
    }
    
    _do_syscall_shim(0, &[fd as usize, buf as usize, count])
}

/// Write to a file descriptor
///
/// This function implements the POSIX write() syscall for newlib.
/// It translates the call to litebox_shim_linux's handle_syscall_request function.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn write(fd: i32, buf: *const u8, count: usize) -> isize {
    if buf.is_null() {
        return Errno::EFAULT.as_neg() as isize;
    }
    
    _do_syscall_shim(1, &[fd as usize, buf as usize, count])
}

/// Exit the program with the given status code
/// 
/// This is called by newlib's exit() function and should never return.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn _exit(status: ffi::c_int) -> ! {
    // Perform any cleanup
    __prog_exit();
    
    // In a real implementation, this would terminate the process
    // For now, we'll halt the CPU
    hlt_loop()
}

/// Get the current process ID (stub implementation)
#[unsafe(no_mangle)]
pub unsafe extern "C" fn getpid() -> i32 {
    1  // Always return PID 1 for our simple environment
}

/// Kill a process (stub implementation)
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kill(pid: i32, sig: i32) -> i32 {
    if pid == 1 && sig == 9 {
        // SIGKILL to our own process - exit
        _exit(1);
    }
    // For other cases, just return success
    0
}

/// Link/unlink file operations (stub implementations)
#[unsafe(no_mangle)]
pub unsafe extern "C" fn link(oldpath: *const ffi::c_char, newpath: *const ffi::c_char) -> i32 {
    // Not supported in our minimal environment
    Errno::ENOSYS.as_neg() as i32
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn unlink(pathname: *const ffi::c_char) -> i32 {
    // Not supported in our minimal environment
    Errno::ENOSYS.as_neg() as i32
}

/// Open file (basic implementation)
#[unsafe(no_mangle)]
pub unsafe extern "C" fn open(pathname: *const ffi::c_char, flags: i32) -> i32 {
    if pathname.is_null() {
        return Errno::EFAULT.as_neg() as i32;
    }
    
    let result = _do_syscall_shim(2, &[pathname as usize, flags as usize, 0]);
    result as i32
}

/// Get file status (extended implementation)
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stat(pathname: *const ffi::c_char, statbuf: *mut u8) -> i32 {
    if pathname.is_null() || statbuf.is_null() {
        return Errno::EFAULT.as_neg() as i32;
    }
    
    let result = _do_syscall_shim(4, &[pathname as usize, statbuf as usize]);
    result as i32
}

/// Memory management helper: get heap info (for debugging)
#[unsafe(no_mangle)]
pub unsafe extern "C" fn close(fd: i32) -> i32 {
    let result = _do_syscall_shim(3, &[fd as usize]);
    result as i32
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn lseek(fd: i32, offset: isize, whence: i32) -> isize {
    _do_syscall_shim(8, &[fd as usize, offset as usize, whence as usize])
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn fstat(fd: i32, statbuf: *mut u8) -> i32 {
    if statbuf.is_null() {
        return Errno::EFAULT.as_neg() as i32;
    }
    let result = _do_syscall_shim(5, &[fd as usize, statbuf as usize]);
    result as i32
}




#[unsafe(no_mangle)]
pub unsafe extern "C" fn sbrk(increment: isize) -> *mut u8 {
    let current_brk = CURRENT_BRK.load(core::sync::atomic::Ordering::Relaxed);
    
    // Initialize on first call if needed
    if current_brk.is_null() {
        panic!("sbrk: CURRENT_BRK not initialized, this should not happen!");
    }

    // Handle increment = 0 (just return current brk)
    if increment == 0 {
        return current_brk;
    }

    // Align increment to page boundary (4KB) for better memory management
    const PAGE_SIZE: usize = 4096;
    let aligned_increment = if increment > 0 {
        // Round up positive increments to next page boundary
        let abs_increment = increment as usize;
        ((abs_increment + PAGE_SIZE - 1) & !(PAGE_SIZE - 1)) as isize
    } else {
        // Round up negative increments (in absolute value) to next page boundary
        let abs_increment = (-increment) as usize;
        let aligned_abs = (abs_increment + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
        -(aligned_abs as isize)
    };

    // Calculate new brk address
    let new_brk_addr = if aligned_increment > 0 {
        // Growing heap - add the aligned increment
        (current_brk as usize).wrapping_add(aligned_increment as usize) as *mut u8
    } else {
        // Shrinking heap - check bounds first
        let abs_decrement = (-aligned_increment) as usize;
        if (current_brk as usize) < abs_decrement {
            panic!("sbrk: cannot shrink below heap start");
        }
        // Calculate new address after decrement
        (current_brk as usize).wrapping_sub(abs_decrement) as *mut u8
    };

    // Call brk syscall to set new break
    let old_brk = current_brk;
    match _do_syscall_shim(12, &[new_brk_addr as usize]) {
        neg_value if neg_value < 0 => {
            newlib_println!("sbrk: brk syscall failed with error {}", neg_value);
            (-1isize) as *mut u8
        }
        actual_brk => {
            // Update the current break pointer
            CURRENT_BRK.store(actual_brk as *mut u8, core::sync::atomic::Ordering::Relaxed);
            newlib_println!("sbrk: increment={} (aligned to {}), old_brk={:p}, new_brk={:p}", 
                increment, aligned_increment, old_brk, actual_brk as *mut u8);
            // Return the old break (standard sbrk behavior)
            old_brk
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn isatty(fd: i32) -> i32 {
    // Check if file descriptor refers to a terminal
    // For our LiteBox environment, we'll consider stdin/stdout/stderr as TTYs
    // and everything else as not a TTY
    match fd {
        0 | 1 | 2 => 1,  // stdin, stdout, stderr are TTYs
        _ => 0,          // everything else is not a TTY
    }
}

/// Memory mapping - map files or devices into memory
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mmap(
    addr: *mut ffi::c_void,
    length: usize,
    prot: i32,
    flags: i32,
    fd: i32,
    offset: isize,
) -> *mut ffi::c_void {
    if length == 0 {
        return (-1isize) as *mut ffi::c_void;
    }
    
    let result = _do_syscall_shim(9, &[
        addr as usize,
        length,
        prot as usize,
        flags as usize,
        fd as usize,
        offset as usize,
    ]);
    
    // mmap returns MAP_FAILED (-1) on error, or the mapped address on success
    if result < 0 {
        (-1isize) as *mut ffi::c_void
    } else {
        result as *mut ffi::c_void
    }
}

/// Memory unmapping - unmap files or devices from memory
#[unsafe(no_mangle)]
pub unsafe extern "C" fn munmap(addr: *mut ffi::c_void, length: usize) -> i32 {
    if addr.is_null() || length == 0 {
        return Errno::EINVAL.as_neg() as i32;
    }
    
    let result = _do_syscall_shim(11, &[addr as usize, length]);
    result as i32
}
