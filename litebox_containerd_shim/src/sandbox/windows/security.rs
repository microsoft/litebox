// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use std::ffi::OsStr;
use std::fs::{File, OpenOptions};
use std::io;
use std::os::windows::ffi::OsStrExt as _;
use std::os::windows::fs::{MetadataExt as _, OpenOptionsExt as _};
use std::os::windows::io::{AsRawHandle as _, FromRawHandle as _, OwnedHandle};
use std::path::Path;
use std::ptr::{null, null_mut};

use windows_sys::Win32::Foundation::{
    ERROR_ALREADY_EXISTS, GENERIC_ALL, GENERIC_WRITE, INVALID_HANDLE_VALUE, LocalFree,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityInfo,
    SDDL_REVISION_1, SE_FILE_OBJECT, SetSecurityInfo,
};
use windows_sys::Win32::Security::{
    ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, DACL_SECURITY_INFORMATION, EqualSid, GetAce,
    GetSecurityDescriptorDacl, GetTokenInformation, IsWellKnownSid, OWNER_SECURITY_INFORMATION,
    PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, SECURITY_ATTRIBUTES,
    TOKEN_ACCESS_MASK, TOKEN_ELEVATION, TOKEN_INFORMATION_CLASS, TOKEN_QUERY, TOKEN_USER,
    TokenElevation, TokenUser, WinBuiltinAdministratorsSid, WinCreatorOwnerRightsSid,
    WinCreatorOwnerSid, WinLocalSystemSid,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateDirectoryW, DELETE, FILE_APPEND_DATA, FILE_ATTRIBUTE_REPARSE_POINT, FILE_DELETE_CHILD,
    FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_DELETE, FILE_SHARE_READ,
    FILE_SHARE_WRITE, FILE_WRITE_ATTRIBUTES, FILE_WRITE_DATA, FILE_WRITE_EA, READ_CONTROL,
    ReOpenFile, WRITE_DAC, WRITE_OWNER,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

use super::{is, size_u32, win32_result};

/// Rights that let their holder change a directory's contents, or who may.
const WRITE_RIGHTS: u32 = FILE_WRITE_DATA
    | FILE_APPEND_DATA
    | FILE_WRITE_EA
    | FILE_DELETE_CHILD
    | FILE_WRITE_ATTRIBUTES
    | DELETE
    | WRITE_DAC
    | WRITE_OWNER
    | GENERIC_WRITE
    | GENERIC_ALL;
/// `ACCESS_ALLOWED_ACE_TYPE` and `ACCESS_ALLOWED_CALLBACK_ACE_TYPE` (`winnt.h`), both laid out as
/// an `ACCESS_ALLOWED_ACE`.
const ALLOWED_ACE_TYPES: [u8; 2] = [0, 9];
/// `ACCESS_DENIED_ACE_TYPE` and its object, callback, and callback object variants.
const DENIED_ACE_TYPES: [u8; 4] = [1, 6, 10, 12];

/// Reject an unsafe existing DACL: repairing it would not authenticate existing files.
pub fn private_root(root: &Path) -> io::Result<()> {
    let user = User::current()?;
    let sid = user.sid_string()?;
    let descriptor = SecurityDescriptor::parse(&format!("O:{sid}D:P(A;OICI;FA;;;{sid})"))?;
    if let Some(parent) = root.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let attributes = descriptor.attributes();
    // SAFETY: the path is NUL-terminated, and `attributes` and its descriptor outlive the call.
    if unsafe { CreateDirectoryW(wide(root.as_os_str()).as_ptr(), &raw const attributes) } == 0 {
        let error = io::Error::last_os_error();
        if !is(&error, ERROR_ALREADY_EXISTS) {
            return Err(error);
        }
    }
    let directory = OpenOptions::new()
        .access_mode(READ_CONTROL | WRITE_DAC)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(root)?;
    let metadata = directory.metadata()?;
    if !metadata.is_dir()
        || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || !is_private(&directory, &user)?
    {
        return Err(io::Error::other(format!(
            "the state root {} is not a private directory of this user's: remove it",
            root.display()
        )));
    }
    set_dacl(&directory, &descriptor)
}

pub(super) fn share_with(directory: &Path, ace: &str) -> io::Result<()> {
    // Shares the write access of the state directory's lock.
    let directory = OpenOptions::new()
        .access_mode(READ_CONTROL | WRITE_DAC)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(directory)?;
    set_dacl(&directory, &shared("OICI", ace)?)
}

/// Through a handle of its own, as `file`'s may lack `WRITE_DAC`, and a path may name another file.
pub(super) fn share_file(file: &File, ace: &str) -> io::Result<()> {
    let share = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
    // SAFETY: `file` is open, and the call returns a handle of its own, or none.
    let handle = unsafe { ReOpenFile(file.as_raw_handle(), READ_CONTROL | WRITE_DAC, share, 0) };
    if handle == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the call succeeded, so this owns `handle`.
    let file = File::from(unsafe { OwnedHandle::from_raw_handle(handle) });
    set_dacl(&file, &shared("", ace)?)
}

/// Protected: the user and SYSTEM, with full control, then `ace`.
fn shared(inheritance: &str, ace: &str) -> io::Result<SecurityDescriptor> {
    let sid = User::current()?.sid_string()?;
    SecurityDescriptor::parse(&format!(
        "D:P(A;{inheritance};FA;;;{sid})(A;{inheritance};FA;;;SY){ace}"
    ))
}

/// `file` must be open with `READ_CONTROL` and `WRITE_DAC`: without the former, `SetSecurityInfo`
/// fails with `ERROR_ACCESS_DENIED`.
fn set_dacl(file: &File, descriptor: &SecurityDescriptor) -> io::Result<()> {
    let dacl = descriptor.dacl()?;
    // SAFETY: `file` is open with `READ_CONTROL` and `WRITE_DAC`, and `dacl` lives in
    // `descriptor`.
    win32_result(unsafe {
        SetSecurityInfo(
            file.as_raw_handle(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            null_mut(),
            null_mut(),
            dacl,
            null(),
        )
    })
}

/// False if unknown.
pub fn is_elevated() -> bool {
    let Ok(token) = process_token(TOKEN_QUERY) else {
        return false;
    };
    let mut elevation = TOKEN_ELEVATION::default();
    let mut length = 0;
    // SAFETY: `token` is open with `TOKEN_QUERY`, and `elevation` and `length` outlive the call,
    // which writes at most the given size of `elevation`.
    let read = unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenElevation,
            (&raw mut elevation).cast(),
            size_u32::<TOKEN_ELEVATION>(),
            &raw mut length,
        )
    };
    read != 0 && elevation.TokenIsElevated != 0
}

fn process_token(access: TOKEN_ACCESS_MASK) -> io::Result<OwnedHandle> {
    let mut token = null_mut();
    // SAFETY: the process pseudo-handle needs no closing, and `token` outlives the call.
    if unsafe { OpenProcessToken(GetCurrentProcess(), access, &raw mut token) } == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the call succeeded, so this owns `token`.
    Ok(unsafe { OwnedHandle::from_raw_handle(token) })
}

/// As `u64`s, for the alignment of what it holds; `token` needs `TOKEN_QUERY`.
fn token_information(token: &OwnedHandle, class: TOKEN_INFORMATION_CLASS) -> io::Result<Vec<u64>> {
    let mut length = 0;
    // SAFETY: with no buffer, the call writes only `length`, and fails for want of room.
    unsafe { GetTokenInformation(token.as_raw_handle(), class, null_mut(), 0, &raw mut length) };
    let mut information = vec![0u64; (length as usize).div_ceil(size_of::<u64>())];
    // SAFETY: `information` holds `length` bytes, and both outlive the call, which writes only them.
    if unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            class,
            information.as_mut_ptr().cast(),
            length,
            &raw mut length,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(information)
}

/// `file` must be open with `READ_CONTROL`.
fn is_private(file: &File, user: &User) -> io::Result<bool> {
    let (mut owner, mut dacl): (PSID, *mut ACL) = (null_mut(), null_mut());
    let mut descriptor: PSECURITY_DESCRIPTOR = null_mut();
    // SAFETY: `file` is open with `READ_CONTROL`, and the pointers outlive the call.
    win32_result(unsafe {
        GetSecurityInfo(
            file.as_raw_handle(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &raw mut owner,
            null_mut(),
            &raw mut dacl,
            null_mut(),
            &raw mut descriptor,
        )
    })?;
    // SAFETY: `owner` and `dacl` point into `descriptor`, which is freed only after.
    let is_private = unsafe { EqualSid(owner, user.sid()) != 0 && writable_only_by(dacl, user) };
    // SAFETY: `GetSecurityInfo` allocated `descriptor` for the caller to free.
    unsafe { LocalFree(descriptor) };
    Ok(is_private)
}

/// Inherit-only ACEs count: they grant on what the directory will hold. An ACE type this cannot
/// read refuses, and a NULL DACL grants everyone everything.
///
/// # Safety
///
/// `dacl` is null or points to a valid ACL.
unsafe fn writable_only_by(dacl: *const ACL, user: &User) -> bool {
    // SAFETY: the caller's.
    let Some(acl) = (unsafe { dacl.as_ref() }) else {
        return false;
    };
    (0..u32::from(acl.AceCount)).all(|index| {
        let mut ace = null_mut();
        // SAFETY: `dacl` is valid, `index` is within it, and `ace` outlives the call.
        if unsafe { GetAce(dacl, index, &raw mut ace) } == 0 {
            return false;
        }
        // SAFETY: every ACE starts with its header.
        let kind = unsafe { ace.cast::<ACE_HEADER>().read_unaligned() }.AceType;
        if !ALLOWED_ACE_TYPES.contains(&kind) {
            return DENIED_ACE_TYPES.contains(&kind);
        }
        // SAFETY: an ACE of these types is an `ACCESS_ALLOWED_ACE`, whose SID starts at
        // `SidStart` and is valid in a valid ACL.
        let (mask, sid) = unsafe {
            let mask = ace.cast::<ACCESS_ALLOWED_ACE>().read_unaligned().Mask;
            (
                mask,
                ace.byte_add(std::mem::offset_of!(ACCESS_ALLOWED_ACE, SidStart)),
            )
        };
        mask & WRITE_RIGHTS == 0 || is_trusted(sid, user)
    })
}

/// `sid` must be valid.
fn is_trusted(sid: PSID, user: &User) -> bool {
    let trusted = [
        WinLocalSystemSid,
        WinBuiltinAdministratorsSid,
        WinCreatorOwnerSid,
        WinCreatorOwnerRightsSid,
    ];
    // SAFETY: both SIDs are valid.
    let is_user = unsafe { EqualSid(sid, user.sid()) } != 0;
    // SAFETY: `sid` is valid.
    is_user
        || trusted
            .into_iter()
            .any(|kind| unsafe { IsWellKnownSid(sid, kind) } != 0)
}

pub(super) struct User {
    /// A `TOKEN_USER` and the SID it points to, as `u64`s for alignment.
    token_user: Vec<u64>,
}

impl User {
    pub(super) fn current() -> io::Result<Self> {
        let token = process_token(TOKEN_QUERY)?;
        Ok(Self {
            token_user: token_information(&token, TokenUser)?,
        })
    }

    /// Borrowed from `self`.
    pub(super) fn sid(&self) -> PSID {
        // SAFETY: `token_user` holds a `TOKEN_USER` (see `current`), whose SID points into it.
        unsafe { (*self.token_user.as_ptr().cast::<TOKEN_USER>()).User.Sid }
    }

    pub(super) fn sid_string(&self) -> io::Result<String> {
        let mut string = null_mut();
        // SAFETY: the SID is valid, and `string` outlives the call.
        if unsafe { ConvertSidToStringSidW(self.sid(), &raw mut string) } == 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: the call returned a NUL-terminated string for the caller to free.
        let sid = unsafe {
            let sid = from_wide(string);
            LocalFree(string.cast());
            sid
        };
        Ok(sid)
    }
}

pub(super) struct SecurityDescriptor(PSECURITY_DESCRIPTOR);

impl SecurityDescriptor {
    pub(super) fn parse(sddl: &str) -> io::Result<Self> {
        let mut descriptor = null_mut();
        // SAFETY: the SDDL is NUL-terminated, and `descriptor` outlives the call.
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                wide(OsStr::new(sddl)).as_ptr(),
                SDDL_REVISION_1,
                &raw mut descriptor,
                null_mut(),
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(Self(descriptor))
    }

    /// `self` must outlive the attributes.
    pub(super) fn attributes(&self) -> SECURITY_ATTRIBUTES {
        SECURITY_ATTRIBUTES {
            nLength: size_u32::<SECURITY_ATTRIBUTES>(),
            lpSecurityDescriptor: self.0,
            bInheritHandle: 0,
        }
    }

    /// Borrowed from `self`.
    fn dacl(&self) -> io::Result<*mut ACL> {
        let (mut present, mut defaulted, mut dacl) = (0, 0, null_mut());
        // SAFETY: the descriptor is valid, and the pointers outlive the call.
        if unsafe {
            GetSecurityDescriptorDacl(self.0, &raw mut present, &raw mut dacl, &raw mut defaulted)
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        if present == 0 {
            return Err(io::Error::other("the security descriptor has no DACL"));
        }
        Ok(dacl)
    }
}

impl Drop for SecurityDescriptor {
    fn drop(&mut self) {
        // SAFETY: the conversion allocated the descriptor for the caller to free.
        unsafe { LocalFree(self.0) };
    }
}

pub(super) fn wide(text: &OsStr) -> Vec<u16> {
    text.encode_wide().chain([0]).collect()
}

/// # Safety
///
/// `text` is a NUL-terminated string.
pub(super) unsafe fn from_wide(text: *const u16) -> String {
    let mut length = 0;
    // SAFETY: the caller's: every unit up to the NUL is readable.
    unsafe {
        while *text.add(length) != 0 {
            length += 1;
        }
        String::from_utf16_lossy(std::slice::from_raw_parts(text, length))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Unlike a symlink, a junction needs no privilege.
    fn junction(target: &Path, link: &Path) {
        let output = std::process::Command::new("cmd")
            .args(["/c", "mklink", "/j"])
            .arg(link)
            .arg(target)
            .output()
            .unwrap();
        assert!(output.status.success(), "mklink /j: {output:?}");
    }

    #[test]
    fn a_state_root_must_be_a_private_directory_of_its_users() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("parent").join("root");
        private_root(&root).unwrap();
        private_root(&root).unwrap();
        std::fs::create_dir(root.join("below")).unwrap();
        std::fs::write(root.join("below").join("file"), "x").unwrap();
        let file = dir.path().join("file");
        std::fs::write(&file, "x").unwrap();
        assert!(private_root(&file).is_err(), "a file");
        let link = dir.path().join("link");
        junction(&root, &link);
        assert!(private_root(&link).is_err(), "a junction");
    }
}
