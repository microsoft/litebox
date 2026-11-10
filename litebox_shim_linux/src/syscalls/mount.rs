// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Mount syscalls: `mount`, `umount2`, `pivot_root` and `chroot`.
//!
//! The broker keeps each thread's mount namespace, root and working directory; these decode
//! Linux's arguments into its mount requests, which resolve paths in the task's file-system
//! context. Each needs the effective root user, which stands in for `CAP_SYS_ADMIN` (and
//! `CAP_SYS_CHROOT`).
//!
//! Differences from Linux:
//! - `mount` makes only `tmpfs` file systems and binds (other types fail with `ENODEV`), and moves
//!   nothing (`MS_MOVE` fails with `EINVAL`).
//! - `MS_REMOUNT` without `MS_BIND` makes only the mount read-only or writable, not the file
//!   system; the other per-mount flags (`MS_NOSUID`, `MS_NODEV`, `MS_NOEXEC`, the access-time
//!   flags, `MS_NOSYMFOLLOW`) and the file-system flags (`MS_SYNCHRONOUS`, `MS_DIRSYNC`,
//!   `MS_MANDLOCK`, `MS_LAZYTIME`, `MS_POSIXACL`, `MS_I_VERSION`) are recorded for a new mount
//!   where Linux shows them, and otherwise ignored, never enforced. Like Linux, `mount` ignores
//!   flags it doesn't know and those only the kernel sets, such as `MS_KERNMOUNT`.
//! - Mounts don't propagate: a propagation change succeeds, doing nothing, only on a mount's root
//!   in the caller's namespace, and fails with `EINVAL` elsewhere.
//! - A `tmpfs` takes only `mode`, `uid` and `gid` options, ids below 65536; the others are recorded,
//!   not applied, and its size is unlimited.
//! - `umount2` with `MNT_EXPIRE` fails with `EINVAL`; `MNT_FORCE` is ignored.
//! - `EPERM`, and `EINVAL` for flags, are reported before the paths are resolved, where Linux
//!   resolves the `mount`, `umount2` and `chroot` target first.

use alloc::string::String;
use alloc::vec::Vec;
use core::ffi::c_char;

use litebox_broker_protocol::fs::{FileMode, FileUser};
use litebox_broker_protocol::mount::{MountInfo, MountSource};
use litebox_common_linux::errno::Errno;
use litebox_common_linux::{AT_FDCWD, MountFlags, UmountFlags};

use crate::{ShimPlatform, Task, UserPtr};

/// The most of `mount`'s `data` that Linux reads: a page, whose last byte it replaces with a NUL.
const MOUNT_DATA_SIZE: usize = 4096;

/// The flags that change a mount's propagation type.
const PROPAGATION_FLAGS: MountFlags = MountFlags::SHARED
    .union(MountFlags::PRIVATE)
    .union(MountFlags::SLAVE)
    .union(MountFlags::UNBINDABLE);

/// The file-system and per-mount flags a new mount records, with their names in Linux's mount
/// options, in the order it shows them.
const RECORDED_FLAGS: [(MountFlags, &str); 12] = [
    (MountFlags::SYNCHRONOUS, "sync"),
    (MountFlags::DIRSYNC, "dirsync"),
    (MountFlags::MANDLOCK, "mand"),
    (MountFlags::LAZYTIME, "lazytime"),
    (MountFlags::NOSUID, "nosuid"),
    (MountFlags::NODEV, "nodev"),
    (MountFlags::NOEXEC, "noexec"),
    (MountFlags::NOATIME, "noatime"),
    (MountFlags::NODIRATIME, "nodiratime"),
    (MountFlags::RELATIME, "relatime"),
    (MountFlags::STRICTATIME, "strictatime"),
    (MountFlags::NOSYMFOLLOW, "nosymfollow"),
];

/// What a `mount` call asks for, by its flags.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MountOperation {
    /// Make the target's mount read-only, or writable (`MS_REMOUNT`, with or without `MS_BIND`).
    SetReadOnly(bool),
    /// Bind the node the source names on the target (`MS_BIND`), with the mounts below it if
    /// `recursive` (`MS_REC`).
    Bind { recursive: bool },
    /// Change the propagation type of the target's mount (`MS_SHARED`, `MS_PRIVATE`, `MS_SLAVE` or
    /// `MS_UNBINDABLE`).
    Propagation,
    /// Mount a new file system on the target.
    New,
}

impl MountOperation {
    /// Decodes `flags`, without the magic number, in the order of Linux's `path_mount`, which
    /// ignores the flags of later branches in earlier ones, and flags it doesn't use.
    fn decode(flags: MountFlags) -> Result<Self, Errno> {
        if flags.contains(MountFlags::NOUSER) {
            return Err(Errno::EINVAL);
        }
        if flags.contains(MountFlags::REMOUNT) {
            Ok(Self::SetReadOnly(flags.contains(MountFlags::RDONLY)))
        } else if flags.contains(MountFlags::BIND) {
            Ok(Self::Bind {
                recursive: flags.contains(MountFlags::REC),
            })
        } else if flags.intersects(PROPAGATION_FLAGS) {
            // Exactly one type, and no other flags but these, as Linux's
            // `flags_to_propagation_type` requires.
            let kind = flags - (MountFlags::REC | MountFlags::SILENT);
            if kind.bits().count_ones() != 1 {
                return Err(Errno::EINVAL);
            }
            Ok(Self::Propagation)
        } else if flags.contains(MountFlags::MOVE) {
            log_unsupported!("mount with MS_MOVE");
            Err(Errno::EINVAL)
        } else {
            Ok(Self::New)
        }
    }
}

/// Reads `mount`'s `data`, if given, as a string, as Linux copies it: up to a NUL byte, the last
/// byte of a page, or the first byte that can't be read, failing with `EFAULT` if that is the
/// first. The options of the file systems LiteBox mounts are text, and others' are ignored, so
/// bytes that aren't UTF-8 are replaced.
pub(crate) fn read_mount_data<Platform: ShimPlatform>(
    data: UserPtr<c_char>,
) -> Result<Option<String>, Errno> {
    if data.is_null() {
        return Ok(None);
    }
    let data = data.cast::<u8>();
    let mut bytes = Vec::new();
    for offset in 0..MOUNT_DATA_SIZE - 1 {
        match data.read_at_offset::<Platform>(offset.cast_signed()) {
            Some(0) => break,
            Some(byte) => bytes.push(byte),
            None if offset == 0 => return Err(Errno::EFAULT),
            None => break,
        }
    }
    Ok(Some(String::from_utf8_lossy(&bytes).into_owned()))
}

/// The root directory a `tmpfs` gets from the options in `data`: its mode (`mode=`, in octal) and
/// owner (`uid=` and `gid=`), by default `01777` and `user`. Fails with `EINVAL` for an invalid
/// value.
fn tmpfs_root(data: &str, user: FileUser) -> Result<(FileMode, FileUser), Errno> {
    let mut mode = FileMode::RWXU | FileMode::RWXG | FileMode::RWXO | FileMode::SVTX;
    let mut owner = user;
    for option in data.split(',') {
        let Some((name, value)) = option.split_once('=') else {
            continue;
        };
        match name {
            "mode" => {
                let bits = u32::from_str_radix(value, 8).map_err(|_| Errno::EINVAL)?;
                mode = FileMode::from_u32_bits_truncate(bits);
            }
            "uid" => owner.user = value.parse().map_err(|_| Errno::EINVAL)?,
            "gid" => owner.group = value.parse().map_err(|_| Errno::EINVAL)?,
            _ => {}
        }
    }
    Ok((mode, owner))
}

/// The options a new mount records: the names of the per-mount flags in `flags`, then `data`.
fn mount_options(flags: MountFlags, data: &str) -> String {
    let mut options = String::new();
    let names = RECORDED_FLAGS
        .iter()
        .filter(|(flag, _)| flags.contains(*flag))
        .map(|(_, name)| *name);
    for option in names.chain((!data.is_empty()).then_some(data)) {
        if !options.is_empty() {
            options.push(',');
        }
        options.push_str(option);
    }
    options
}

impl<Platform: ShimPlatform> Task<Platform> {
    /// Handles syscall `mount`, whose `source`, `fstype` and `data` may be absent.
    pub(crate) fn sys_mount(
        &self,
        source: Option<&str>,
        target: &str,
        fstype: Option<&str>,
        flags: MountFlags,
        data: Option<&str>,
    ) -> Result<(), Errno> {
        self.check_sys_admin()?;
        let operation = MountOperation::decode(flags)?;
        let origin = self.path_origin(AT_FDCWD, target)?;
        let user = self.file_user();
        let litebox = &self.global.litebox;
        match operation {
            MountOperation::SetReadOnly(read_only) => {
                litebox.set_mount_read_only(origin.start, target, user, read_only)?;
            }
            MountOperation::Bind { recursive } => {
                let source = source
                    .filter(|source| !source.is_empty())
                    .ok_or(Errno::EINVAL)?;
                let source = MountSource::Bind {
                    base: None,
                    path: source.into(),
                    recursive,
                };
                litebox.mount(origin.start, target, user, &source)?;
            }
            MountOperation::Propagation => {
                let mount = litebox.mount_info(origin.start, target, user, true)?;
                if !mount.at_root || !mount.in_namespace {
                    return Err(Errno::EINVAL);
                }
            }
            MountOperation::New => {
                let fstype = fstype.ok_or(Errno::EINVAL)?;
                if fstype != "tmpfs" {
                    log_unsupported!("mount of file-system type {fstype}");
                    return Err(Errno::ENODEV);
                }
                let data = data.unwrap_or_default();
                let (mode, owner) = tmpfs_root(data, user)?;
                let source = MountSource::NewTmpfs {
                    mode,
                    owner,
                    info: MountInfo {
                        fs_type: fstype.into(),
                        source: source.unwrap_or("none").into(),
                        options: mount_options(flags, data),
                    },
                    read_only: flags.contains(MountFlags::RDONLY),
                };
                litebox.mount(origin.start, target, user, &source)?;
            }
        }
        Ok(())
    }

    /// Handles syscall `umount2`.
    pub(crate) fn sys_umount2(&self, target: &str, flags: UmountFlags) -> Result<(), Errno> {
        let known =
            UmountFlags::FORCE | UmountFlags::DETACH | UmountFlags::EXPIRE | UmountFlags::NOFOLLOW;
        if !known.contains(flags) {
            return Err(Errno::EINVAL);
        }
        self.check_sys_admin()?;
        if flags.contains(UmountFlags::EXPIRE) {
            log_unsupported!("umount2 with MNT_EXPIRE");
            return Err(Errno::EINVAL);
        }
        let origin = self.path_origin(AT_FDCWD, target)?;
        Ok(self.global.litebox.unmount(
            origin.start,
            target,
            self.file_user(),
            flags.contains(UmountFlags::DETACH),
            !flags.contains(UmountFlags::NOFOLLOW),
        )?)
    }

    /// Handles syscall `pivot_root`.
    pub(crate) fn sys_pivot_root(&self, new_root: &str, put_old: &str) -> Result<(), Errno> {
        self.check_sys_admin()?;
        let origin = self.path_origin(AT_FDCWD, new_root)?;
        // Both paths start in the same context, without a base.
        self.path_origin(AT_FDCWD, put_old)?;
        Ok(self
            .global
            .litebox
            .pivot_root(origin.start, new_root, put_old, self.file_user())?)
    }

    /// Handles syscall `chroot`.
    pub(crate) fn sys_chroot(&self, path: &str) -> Result<(), Errno> {
        self.check_sys_admin()?;
        let origin = self.path_origin(AT_FDCWD, path)?;
        Ok(self
            .global
            .litebox
            .change_root(origin.start, path, self.file_user())?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `statfs`'s flag for a read-only mount.
    const ST_RDONLY: i64 = 1;

    const USER: FileUser = FileUser {
        user: 1000,
        group: 100,
    };

    #[test]
    fn mount_flags_decode_in_linux_order() {
        let decode = |flags: MountFlags| MountOperation::decode(flags);
        // runc's read-only remount of a bind.
        assert_eq!(
            decode(
                MountFlags::REMOUNT
                    | MountFlags::BIND
                    | MountFlags::REC
                    | MountFlags::RDONLY
                    | MountFlags::NOSUID
            ),
            Ok(MountOperation::SetReadOnly(true))
        );
        assert_eq!(
            decode(MountFlags::REMOUNT | MountFlags::PRIVATE),
            Ok(MountOperation::SetReadOnly(false))
        );
        assert_eq!(
            decode(MountFlags::BIND | MountFlags::REC | MountFlags::RDONLY),
            Ok(MountOperation::Bind { recursive: true })
        );
        assert_eq!(
            decode(MountFlags::SLAVE | MountFlags::REC | MountFlags::SILENT),
            Ok(MountOperation::Propagation)
        );
        assert_eq!(
            decode(MountFlags::NOSUID | MountFlags::NODEV | MountFlags::RDONLY),
            Ok(MountOperation::New)
        );
        // Linux ignores the flags it doesn't use.
        assert_eq!(
            decode(
                MountFlags::SYNCHRONOUS
                    | MountFlags::DIRSYNC
                    | MountFlags::MANDLOCK
                    | MountFlags::KERNMOUNT
                    | MountFlags::from_bits_retain(1 << 40)
            ),
            Ok(MountOperation::New)
        );
        assert_eq!(
            decode(MountFlags::REMOUNT | MountFlags::BIND | MountFlags::I_VERSION),
            Ok(MountOperation::SetReadOnly(false))
        );
    }

    #[test]
    fn mount_flags_refuse_what_linux_or_litebox_refuses() {
        for flags in [
            // One propagation type, with no other flags but `MS_REC` and `MS_SILENT`.
            MountFlags::PRIVATE | MountFlags::SHARED,
            MountFlags::PRIVATE | MountFlags::NOSUID,
            MountFlags::SLAVE | MountFlags::SYNCHRONOUS,
            MountFlags::MOVE,
            MountFlags::BIND | MountFlags::NOUSER,
        ] {
            assert_eq!(
                MountOperation::decode(flags),
                Err(Errno::EINVAL),
                "{flags:?}"
            );
        }
    }

    #[test]
    fn tmpfs_options_give_the_root_mode_and_owner() {
        let sticky = FileMode::from_u32_bits_truncate(0o1777);
        assert_eq!(tmpfs_root("", USER), Ok((sticky, USER)));
        assert_eq!(
            tmpfs_root("size=1m,mode=0755,uid=0,gid=5,inode64", USER),
            Ok((
                FileMode::from_u32_bits_truncate(0o755),
                FileUser { user: 0, group: 5 }
            ))
        );
        for data in ["mode=9", "uid=-1", "gid=65536", "mode="] {
            assert_eq!(tmpfs_root(data, USER), Err(Errno::EINVAL), "{data}");
        }
    }

    #[test]
    fn mounts_change_what_paths_and_statfs_show() {
        use crate::syscalls::tests::{create_directory, init_platform};

        let task = init_platform();
        create_directory(&task, "/mount_test");
        let tmpfs =
            |flags| task.sys_mount(None, "/mount_test", Some("tmpfs"), flags, Some("mode=700"));
        assert_eq!(tmpfs(MountFlags::NOSUID), Ok(()));
        assert_eq!(
            task.sys_stat("/mount_test").unwrap().st_mode & 0o7777,
            0o700
        );
        create_directory(&task, "/mount_test/sub");
        let statfs = task.sys_statfs("/mount_test/sub").unwrap();
        assert_eq!(
            (statfs.f_type, statfs.f_flags & ST_RDONLY),
            (0x0102_1994, 0)
        );

        // Propagation changes do nothing, but only on a mount's root.
        let propagation = |path| task.sys_mount(None, path, None, MountFlags::PRIVATE, None);
        assert_eq!(propagation("/mount_test"), Ok(()));
        assert_eq!(propagation("/mount_test/sub"), Err(Errno::EINVAL));

        let read_only = MountFlags::REMOUNT | MountFlags::BIND | MountFlags::RDONLY;
        assert_eq!(
            task.sys_mount(None, "/mount_test", None, read_only, None),
            Ok(())
        );
        let fd = task
            .sys_open(
                "/mount_test/sub",
                litebox_common_linux::OFlags::RDONLY,
                FileMode::empty(),
            )
            .unwrap();
        let fd = i32::try_from(fd).unwrap();
        assert_eq!(task.sys_fstatfs(fd).unwrap().f_flags & ST_RDONLY, ST_RDONLY);
        assert_eq!(
            task.sys_mkdirat(AT_FDCWD, "/mount_test/new", 0o777),
            Err(Errno::EROFS)
        );
        task.sys_close(fd).unwrap();

        assert_eq!(
            task.sys_umount2("/mount_test", UmountFlags::empty()),
            Ok(())
        );
        assert_eq!(
            task.sys_umount2("/mount_test", UmountFlags::empty()),
            Err(Errno::EINVAL)
        );
        assert_eq!(tmpfs(MountFlags::MOVE), Err(Errno::EINVAL));
        assert_eq!(
            task.sys_mount(None, "/mount_test", Some("proc"), MountFlags::empty(), None),
            Err(Errno::ENODEV)
        );
    }

    #[test]
    fn mount_namespaces_need_root_but_contexts_do_not() {
        use crate::syscalls::tests::init_platform;
        use alloc::sync::Arc;
        use litebox_common_linux::CloneFlags;

        let mut task = init_platform();
        let root = Arc::clone(&task.credentials);
        task.credentials = Arc::new(crate::syscalls::process::Credentials {
            euid: 1000,
            ..*root
        });
        assert_eq!(
            task.sys_mount(None, "/", Some("tmpfs"), MountFlags::empty(), None),
            Err(Errno::EPERM)
        );
        assert_eq!(
            task.sys_umount2("/", UmountFlags::DETACH),
            Err(Errno::EPERM)
        );
        assert_eq!(task.sys_pivot_root("/", "/"), Err(Errno::EPERM));
        assert_eq!(task.sys_chroot("/"), Err(Errno::EPERM));
        assert_eq!(task.sys_unshare(CloneFlags::NEWNS), Err(Errno::EPERM));

        // Unsharing the context also gives the task its own umask.
        let shared = Arc::clone(&task.fs.borrow());
        assert_eq!(task.sys_unshare(CloneFlags::FS), Ok(0));
        assert!(!Arc::ptr_eq(&shared, &task.fs.borrow()));

        task.credentials = root;
        let mut clone = <litebox_common_linux::CloneArgs as zerocopy::FromZeros>::new_zeroed();
        clone.flags = CloneFlags::NEWNS | CloneFlags::FS;
        assert_eq!(
            task.sys_clone(&mut litebox_common_linux::PtRegs::default(), &clone),
            Err(Errno::EINVAL)
        );
        clone.flags = CloneFlags::VM
            | CloneFlags::SIGHAND
            | CloneFlags::FILES
            | CloneFlags::THREAD
            | CloneFlags::NEWNS;
        assert_eq!(
            task.sys_clone(&mut litebox_common_linux::PtRegs::default(), &clone),
            Err(Errno::EINVAL)
        );
        assert_eq!(task.sys_unshare(CloneFlags::NEWNS), Ok(0));
    }

    #[test]
    fn new_mounts_record_their_flags_and_data() {
        assert_eq!(mount_options(MountFlags::RDONLY, ""), "");
        assert_eq!(
            mount_options(
                MountFlags::NOSUID | MountFlags::NODEV | MountFlags::SYNCHRONOUS,
                "mode=755"
            ),
            "sync,nosuid,nodev,mode=755"
        );
    }
}
