//! LiteBox Runner for Newlib
//!
//! This crate provides a runtime environment for applications using Newlib's static libc (libc.a)
//! with LiteBox. It initializes the platform, filesystem, and registers the syscall handler.
//! 
//! This crate is compiled as a static library called liblitebox_newlib.a, which contains
//! C syscall function backends (read and write) that leverage litebox_shim_linux's
//! handle_syscall_request to process the syscalls.

#![no_std]
#![no_main]

// extern crate alloc;

use litebox::LiteBox;
// use litebox::platform::DebugLogProvider;
use litebox_common_linux::{SyscallRequest, errno::Errno};
use litebox_platform_multiplex::Platform;


// chuqi: an ugly debug log

/// A macro for debug logging that doesn't allocate memory.
/// This macro formats the message using a fixed-size buffer and then
/// prints it using the platform's debug_log_print method.
// macro_rules! debug_log_println {
//     ($($arg:tt)*) => {{
//         use core::fmt::Write;
        
//         // Get the platform instance
//         let platform = litebox_platform_multiplex::platform();
        
//         // Create a fixed-size buffer for formatting
//         let mut buffer = [0u8; 256];
//         let mut pos = 0;
        
//         // Create a writer that writes to the buffer
//         struct BufferWriter<'a> {
//             buffer: &'a mut [u8],
//             pos: &'a mut usize,
//         }
        
//         impl<'a> core::fmt::Write for BufferWriter<'a> {
//             fn write_str(&mut self, s: &str) -> core::fmt::Result {
//                 let bytes = s.as_bytes();
//                 let remaining = self.buffer.len() - *self.pos;
                
//                 if bytes.len() > remaining {
//                     // If it doesn't fit, truncate
//                     let copy_len = remaining;
//                     if copy_len > 0 {
//                         self.buffer[*self.pos..*self.pos + copy_len].copy_from_slice(&bytes[..copy_len]);
//                         *self.pos += copy_len;
//                     }
//                 } else {
//                     // Copy the bytes to our buffer
//                     self.buffer[*self.pos..*self.pos + bytes.len()].copy_from_slice(bytes);
//                     *self.pos += bytes.len();
//                 }
                
//                 Ok(())
//             }
//         }
        
//         // Format the message
//         let mut writer = BufferWriter { buffer: &mut buffer, pos: &mut pos };
//         let _ = write!(writer, $($arg)*);
//         let _ = write!(writer, "\n"); // Add newline
        
//         // Print the message
//         if let Ok(s) = core::str::from_utf8(&buffer[..pos]) {
//             platform.debug_log_print(s);
//         }
//     }};
// }

/// Initialize the LiteBox environment
///
/// This function is called at program startup (by newlib libc.a's crt0)
/// to initialize the platform, filesystem, and register the syscall handler.
/// todo(chuqi): simply assume LinuxUserland + layered filesystem for now.
/// 
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __init_liblitebox_newlib() {
    // Initialize platform
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

    // chuqi: I don't think this is necessary actually. We don't need a platform here.
    litebox_platform_multiplex::set_platform(platform);
    
    // Register syscall handler
    // chuqi: I don't think this is necessary for newlib, as we don't hook real syscall
    //        instructions; instead, we provide our own implementations. 
    // platform.register_syscall_handler(litebox_shim_linux::handle_syscall_request);
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
    // match copy_len {
    //     0 => debug_log_println!("_do_syscall_shim called with sys_id: {}, args: []", sys_id),
    //     1 => debug_log_println!("_do_syscall_shim called with sys_id: {}, args: [{:#x}]", 
    //             sys_id, args[0]),
    //     2 => debug_log_println!("_do_syscall_shim called with sys_id: {}, args: [{:#x}, {:#x}]", 
    //             sys_id, args[0], args[1]),
    //     3 => debug_log_println!("_do_syscall_shim called with sys_id: {}, args: [{:#x}, {:#x}, {:#x}]", 
    //             sys_id, args[0], args[1], args[2]),
    //     4 => debug_log_println!("_do_syscall_shim called with sys_id: {}, args: [{:#x}, {:#x}, {:#x}, {:#x}]", 
    //             sys_id, args[0], args[1], args[2], args[3]),
    //     5 => debug_log_println!("_do_syscall_shim called with sys_id: {}, args: [{:#x}, {:#x}, {:#x}, {:#x}, {:#x}]", 
    //             sys_id, args[0], args[1], args[2], args[3], args[4]),
    //     _ => debug_log_println!("_do_syscall_shim called with sys_id: {}, args: [{:#x}, {:#x}, {:#x}, {:#x}, {:#x}, {:#x}]", 
    //             sys_id, args[0], args[1], args[2], args[3], args[4], args[5]),
    // }

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
