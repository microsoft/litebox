// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Cross-platform filesystem compatibility for the 9P server.
//!
//! On Unix, the standard `std::os::unix::fs` extensions provide positional I/O,
//! metadata, and permissions. On Windows, this module synthesizes equivalent
//! behaviour from the available APIs.

// Re-export dirent type constants used by readdir.
pub const DT_DIR: u8 = 4;
pub const DT_LNK: u8 = 10;
pub const DT_REG: u8 = 8;

// ---------------------------------------------------------------------------
// Unix: thin re-exports
// ---------------------------------------------------------------------------
#[cfg(unix)]
pub use std::os::unix::fs::{FileExt, MetadataExt, OpenOptionsExt};

/// Create a `Permissions` from a Unix mode value.
#[cfg(unix)]
pub fn permissions_from_mode(mode: u32) -> std::fs::Permissions {
    use std::os::unix::fs::PermissionsExt;
    std::fs::Permissions::from_mode(mode)
}

// ---------------------------------------------------------------------------
// Windows: compatibility implementations
// ---------------------------------------------------------------------------

#[cfg(windows)]
pub trait FileExt {
    fn read_at(&self, buf: &mut [u8], offset: u64) -> std::io::Result<usize>;
    fn write_at(&self, buf: &[u8], offset: u64) -> std::io::Result<usize>;
}

#[cfg(windows)]
impl FileExt for std::fs::File {
    fn read_at(&self, buf: &mut [u8], offset: u64) -> std::io::Result<usize> {
        use std::os::windows::fs::FileExt as WinFileExt;
        self.seek_read(buf, offset)
    }

    fn write_at(&self, buf: &[u8], offset: u64) -> std::io::Result<usize> {
        use std::os::windows::fs::FileExt as WinFileExt;
        self.seek_write(buf, offset)
    }
}

/// Synthesize Unix-style metadata from Windows `std::fs::Metadata`.
///
/// Many 9P fields have no direct Windows equivalent, so we return sensible
/// defaults (uid/gid = 0, nlink = 1, rdev = 0, blksize = 4096).
#[cfg(windows)]
pub trait MetadataExt {
    fn mode(&self) -> u32;
    fn uid(&self) -> u32;
    fn gid(&self) -> u32;
    fn nlink(&self) -> u64;
    fn rdev(&self) -> u64;
    fn ino(&self) -> u64;
    fn blksize(&self) -> u64;
    fn blocks(&self) -> u64;
    fn atime(&self) -> i64;
    fn atime_nsec(&self) -> i64;
    fn mtime(&self) -> i64;
    fn mtime_nsec(&self) -> i64;
    fn ctime(&self) -> i64;
    fn ctime_nsec(&self) -> i64;
}

#[cfg(windows)]
impl MetadataExt for std::fs::Metadata {
    fn mode(&self) -> u32 {
        if self.is_dir() {
            0o40755
        } else if self.permissions().readonly() {
            0o100444
        } else {
            0o100644
        }
    }
    fn uid(&self) -> u32 {
        0
    }
    fn gid(&self) -> u32 {
        0
    }
    fn nlink(&self) -> u64 {
        1
    }
    fn rdev(&self) -> u64 {
        0
    }
    fn ino(&self) -> u64 {
        use std::hash::{Hash, Hasher};
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        if let Ok(modified) = self.modified() {
            modified.hash(&mut hasher);
        }
        self.len().hash(&mut hasher);
        hasher.finish()
    }
    fn blksize(&self) -> u64 {
        4096
    }
    fn blocks(&self) -> u64 {
        self.len().div_ceil(512)
    }
    fn atime(&self) -> i64 {
        system_time_to_unix_secs(self.accessed().ok())
    }
    fn atime_nsec(&self) -> i64 {
        system_time_to_unix_nsecs(self.accessed().ok())
    }
    fn mtime(&self) -> i64 {
        system_time_to_unix_secs(self.modified().ok())
    }
    fn mtime_nsec(&self) -> i64 {
        system_time_to_unix_nsecs(self.modified().ok())
    }
    fn ctime(&self) -> i64 {
        system_time_to_unix_secs(self.created().ok())
    }
    fn ctime_nsec(&self) -> i64 {
        system_time_to_unix_nsecs(self.created().ok())
    }
}

#[cfg(windows)]
fn system_time_to_unix_secs(t: Option<std::time::SystemTime>) -> i64 {
    t.and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(windows)]
fn system_time_to_unix_nsecs(t: Option<std::time::SystemTime>) -> i64 {
    t.and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.subsec_nanos() as i64)
        .unwrap_or(0)
}

/// Compatibility trait for `OpenOptions::mode()`.
///
/// On Unix this sets the file creation mode. On Windows it's a no-op.
#[cfg(windows)]
pub trait OpenOptionsExt {
    fn mode(&mut self, mode: u32) -> &mut Self;
}

#[cfg(windows)]
impl OpenOptionsExt for std::fs::OpenOptions {
    fn mode(&mut self, _mode: u32) -> &mut Self {
        self
    }
}

/// Create a `Permissions` from a Unix mode value.
///
/// On Windows, maps to readonly if no write bits are set.
#[cfg(windows)]
pub fn permissions_from_mode(mode: u32) -> std::fs::Permissions {
    // The only portable permission concept on Windows is readonly.
    // Create a Permissions from the "." directory, then adjust.
    let mut perms = std::fs::metadata(".")
        .map(|m| m.permissions())
        .unwrap_or_else(|_| std::fs::metadata("C:\\").unwrap().permissions());
    perms.set_readonly(mode & 0o222 == 0);
    perms
}
