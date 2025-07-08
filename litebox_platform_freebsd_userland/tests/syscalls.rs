use litebox_platform_freebsd_userland::syscall_raw::{SyscallTable, syscalls};
use std::ffi::CString;

#[test]
fn test_syscall_open_nonexistent_file() {
    // Try to open a file that doesn't exist
    let nonexistent_path = CString::new("/this/file/does/not/exist").unwrap();

    let result = unsafe {
        syscalls::syscall3(
            SyscallTable::Open,
            nonexistent_path.as_ptr() as usize,
            libc::O_RDONLY as usize,
            0,
        )
    };

    // This should fail with an error
    match result {
        Ok(_fd) => {
            panic!("Opening a non-existent file should have failed!");
        }
        Err(errno) => {
            // The errno should be a positive value (like ENOENT = 2)
            assert!(errno > 0, "Error code should be positive, got: {}", errno);

            // On FreeBSD, ENOENT (No such file or directory) is typically 2
            println!("Successfully caught error: errno = {}", errno);

            // Common error codes we might expect:
            // ENOENT = 2 (No such file or directory)
            // EACCES = 13 (Permission denied)
            // ENOTDIR = 20 (Not a directory)
            assert!(
                errno == 2 || errno == 13 || errno == 20,
                "Expected ENOENT (2), EACCES (13), or ENOTDIR (20), got: {}",
                errno
            );
        }
    }
}

#[test]
fn test_syscall_getpid() {
    // getpid() should always succeed and return a positive PID
    let result = unsafe { syscalls::syscall0(SyscallTable::Getpid) };

    match result {
        Ok(pid) => {
            assert!(pid > 0, "PID should be positive, got: {}", pid);
            println!("Current PID: {}", pid);
        }
        Err(errno) => {
            panic!("getpid() should never fail, but got errno: {}", errno);
        }
    }
}

#[test]
fn test_syscall_getuid() {
    // getuid() should always succeed and return a UID (could be 0 for root)
    let result = unsafe { syscalls::syscall0(SyscallTable::Getuid) };

    match result {
        Ok(uid) => {
            // UID can be 0 (root) or any positive value
            println!("Current UID: {}", uid);
        }
        Err(errno) => {
            panic!("getuid() should never fail, but got errno: {}", errno);
        }
    }
}

#[test]
fn test_syscall_close_invalid_fd() {
    // Try to close an invalid file descriptor
    let invalid_fd = 99999;

    let result = unsafe { syscalls::syscall1(SyscallTable::Close, invalid_fd) };

    // This should fail with EBADF (Bad file descriptor)
    match result {
        Ok(_) => {
            panic!("Closing an invalid file descriptor should have failed!");
        }
        Err(errno) => {
            assert!(errno > 0, "Error code should be positive, got: {}", errno);

            // EBADF (Bad file descriptor) is typically 9 on FreeBSD
            println!("Successfully caught close error: errno = {}", errno);

            // We expect EBADF = 9
            assert_eq!(errno, 9, "Expected EBADF (9), got: {}", errno);
        }
    }
}

#[test]
fn test_syscall_read_invalid_fd() {
    // Try to read from an invalid file descriptor
    let invalid_fd = 99999;
    let mut buffer = [0u8; 10];

    let result = unsafe {
        syscalls::syscall3(
            SyscallTable::Read,
            invalid_fd,
            buffer.as_mut_ptr() as usize,
            buffer.len(),
        )
    };

    // This should fail with EBADF (Bad file descriptor)
    match result {
        Ok(_) => {
            panic!("Reading from an invalid file descriptor should have failed!");
        }
        Err(errno) => {
            assert!(errno > 0, "Error code should be positive, got: {}", errno);

            // EBADF (Bad file descriptor) is typically 9 on FreeBSD
            println!("Successfully caught read error: errno = {}", errno);

            // We expect EBADF = 9
            assert_eq!(errno, 9, "Expected EBADF (9), got: {}", errno);
        }
    }
}

#[test]
fn test_syscall_write_to_stderr() {
    // Write a test message to stderr (file descriptor 2)
    let message = b"Test message from FreeBSD syscall write to stderr\n";

    let result = unsafe {
        syscalls::syscall3(
            SyscallTable::Write,
            2, // stderr file descriptor
            message.as_ptr() as usize,
            message.len(),
        )
    };

    // This should succeed and return the number of bytes written
    match result {
        Ok(bytes_written) => {
            assert_eq!(
                bytes_written,
                message.len(),
                "Should have written {} bytes, but wrote {}",
                message.len(),
                bytes_written
            );
            println!("Successfully wrote {} bytes to stderr", bytes_written);
        }
        Err(errno) => {
            panic!(
                "Writing to stderr should have succeeded, but got errno: {}",
                errno
            );
        }
    }
}
