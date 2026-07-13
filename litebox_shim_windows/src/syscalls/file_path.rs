// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use alloc::string::String;

use litebox_common_windows::nt_status::NtStatus;

use crate::syscalls::condrv::CondrvObject;
use crate::syscalls::object_manager::{FileDeviceObject, ObjectManager};

#[derive(Debug, Eq, PartialEq)]
pub(crate) enum FileTarget {
    Filesystem(String),
    Condrv(CondrvObject),
}

pub(crate) enum FilePathRoot<'a> {
    Namespace,
    Filesystem { path: &'a str, is_directory: bool },
    Condrv(CondrvObject),
}

pub(crate) struct FilePathResolver<'a, Platform: crate::ShimPlatform> {
    object_manager: &'a ObjectManager<Platform>,
}

impl<'a, Platform: crate::ShimPlatform> FilePathResolver<'a, Platform> {
    pub(crate) fn new(object_manager: &'a ObjectManager<Platform>) -> Self {
        Self { object_manager }
    }

    pub(crate) fn resolve(
        &self,
        root: FilePathRoot<'_>,
        name: &str,
    ) -> Result<FileTarget, NtStatus> {
        match root {
            FilePathRoot::Condrv(parent) => parent.relative_child(name).map(FileTarget::Condrv),
            FilePathRoot::Namespace => self.resolve_absolute(name),
            FilePathRoot::Filesystem { .. } if is_absolute_windows_path(name) => {
                self.resolve_absolute(name)
            }
            FilePathRoot::Filesystem {
                is_directory: false,
                ..
            } => Err(NtStatus::NOT_A_DIRECTORY),
            FilePathRoot::Filesystem { path, .. } => {
                join_absolute_components(path, name).map(FileTarget::Filesystem)
            }
        }
    }

    fn resolve_absolute(&self, name: &str) -> Result<FileTarget, NtStatus> {
        if name.starts_with('/') {
            return join_absolute_components("/", name).map(FileTarget::Filesystem);
        }
        if !is_absolute_windows_path(name) {
            return Err(NtStatus::OBJECT_PATH_SYNTAX_BAD);
        }

        let object_path = absolute_windows_file_name_to_object_path(name);
        let (device, remaining) = self.object_manager.resolve_file_device(&object_path)?;
        file_device_path_to_file_target(device, &remaining)
    }
}

fn absolute_windows_file_name_to_object_path(name: &str) -> String {
    if let Some(rest) = strip_case_insensitive_prefix(name, "\\\\?\\") {
        return alloc::format!(r"\??\{}", normalize_file_name_separators(rest));
    }
    if name.starts_with('\\') {
        return normalize_file_name_separators(name);
    }
    alloc::format!(r"\??\{}", normalize_file_name_separators(name))
}

fn normalize_file_name_separators(name: &str) -> String {
    name.replace('/', "\\")
}

fn file_device_path_to_file_target(
    device: FileDeviceObject,
    remaining: &str,
) -> Result<FileTarget, NtStatus> {
    match device {
        FileDeviceObject::Filesystem { root_path } => {
            join_absolute_components(&root_path, remaining).map(FileTarget::Filesystem)
        }
        FileDeviceObject::ConsoleDriver => {
            CondrvObject::from_device_name(remaining).map(FileTarget::Condrv)
        }
    }
}

fn join_absolute_components(root_path: &str, components: &str) -> Result<String, NtStatus> {
    let mut path = String::from(root_path.trim_end_matches('/'));
    if path.is_empty() {
        path.push('/');
    }
    for component in components.split(['\\', '/']) {
        if component.is_empty() || component == "." {
            continue;
        }
        if component == ".." {
            return Err(NtStatus::INVALID_PARAMETER);
        }
        if !path.ends_with('/') {
            path.push('/');
        }
        path.push_str(component);
    }
    Ok(path)
}

fn strip_case_insensitive_prefix<'a>(value: &'a str, prefix: &str) -> Option<&'a str> {
    value
        .get(..prefix.len())
        .is_some_and(|head| head.eq_ignore_ascii_case(prefix))
        .then(|| &value[prefix.len()..])
}

fn is_absolute_windows_path(name: &str) -> bool {
    name.starts_with(['\\', '/']) || is_absolute_windows_drive_path(name)
}

fn is_absolute_windows_drive_path(name: &str) -> bool {
    name.as_bytes()
        .get(1..3)
        .is_some_and(|bytes| bytes[0] == b':' && matches!(bytes[1], b'\\' | b'/'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn namespace_paths_resolve_through_the_object_manager() {
        let task = crate::tests::test_task();
        let resolver = FilePathResolver::new(&task.process.object_manager);
        let resolve = |name| resolver.resolve(FilePathRoot::Namespace, name);
        let resolve_path = |name| {
            resolve(name).map(|target| match target {
                FileTarget::Filesystem(path) => path,
                FileTarget::Condrv(object) => String::from(object.handle_path()),
            })
        };

        assert_eq!(
            resolve_path(r"\??\C:\Windows\System32\ntdll.dll").unwrap(),
            "/Windows/System32/ntdll.dll"
        );
        assert_eq!(
            resolve_path(r"\??\c:\windows\system32\KERNEL32.DLL").unwrap(),
            "/windows/system32/KERNEL32.DLL"
        );
        assert_eq!(
            resolve_path(r"\Device\HarddiskVolume1\Windows\System32\c_1252.NLS").unwrap(),
            "/Windows/System32/c_1252.NLS"
        );
        assert_eq!(
            resolve_path(r"\SystemRoot\System32\kernel32.dll").unwrap(),
            "/Windows/System32/kernel32.dll"
        );
        assert_eq!(
            resolve_path(r"\Device\ConDrv\Output").unwrap(),
            "/dev/stdout"
        );
        assert_eq!(
            resolve_path(r"\Device\ConDrv\Reference"),
            Err(NtStatus::INVALID_HANDLE)
        );
        assert_eq!(
            resolve_path(r"\Device\ConDrv\Connect"),
            Err(NtStatus::OBJECT_TYPE_MISMATCH)
        );
        assert_eq!(
            resolve(r"\Missing\file.txt"),
            Err(NtStatus::OBJECT_PATH_NOT_FOUND)
        );
        assert_eq!(
            resolve("/tmp/compatibility-path.txt"),
            Ok(FileTarget::Filesystem(String::from(
                "/tmp/compatibility-path.txt"
            )))
        );
        assert_eq!(
            resolve("/SystemRoot/not-an-object-path"),
            Ok(FileTarget::Filesystem(String::from(
                "/SystemRoot/not-an-object-path"
            )))
        );
        assert_eq!(
            resolve("relative.txt"),
            Err(NtStatus::OBJECT_PATH_SYNTAX_BAD)
        );
    }

    #[test]
    fn root_kind_controls_relative_path_resolution() {
        let task = crate::tests::test_task();
        let resolver = FilePathResolver::new(&task.process.object_manager);

        assert_eq!(
            resolver.resolve(
                FilePathRoot::Filesystem {
                    path: "/tmp/root",
                    is_directory: true,
                },
                r"child\file.txt",
            ),
            Ok(FileTarget::Filesystem(String::from(
                "/tmp/root/child/file.txt"
            )))
        );
        assert_eq!(
            resolver.resolve(
                FilePathRoot::Filesystem {
                    path: "/tmp/root",
                    is_directory: true,
                },
                r"C:\Windows\System32\ntdll.dll",
            ),
            Ok(FileTarget::Filesystem(String::from(
                "/Windows/System32/ntdll.dll"
            )))
        );
        assert_eq!(
            resolver.resolve(
                FilePathRoot::Filesystem {
                    path: "/tmp/root",
                    is_directory: true,
                },
                r"MixedCase\File.TXT",
            ),
            Ok(FileTarget::Filesystem(String::from(
                "/tmp/root/MixedCase/File.TXT"
            )))
        );
        assert_eq!(
            resolver.resolve(
                FilePathRoot::Filesystem {
                    path: "/tmp/root.txt",
                    is_directory: false,
                },
                "child.txt",
            ),
            Err(NtStatus::NOT_A_DIRECTORY)
        );
        assert_eq!(
            resolver.resolve(FilePathRoot::Condrv(CondrvObject::Reference), r"\Connect"),
            Ok(FileTarget::Condrv(CondrvObject::Connect))
        );
    }
}
