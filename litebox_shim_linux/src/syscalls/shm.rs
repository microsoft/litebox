// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! System V shared memory.
//!
//! Supports keyed and private segments, read-only and read-write attaches, address rounding,
//! and the `IPC_STAT`, `IPC_SET`, and `IPC_RMID` control operations. Huge pages, executable
//! attaches, and forced address replacement are not supported. Segments are scoped to the
//! guest IPC namespace; none are published in the host's System V IPC namespace.

use crate::{ShimPlatform, Task, UserPtrMut};
use litebox::segment::SegmentError;
use litebox_broker_protocol::{ProcessId, fs::FileUser};
use litebox_common_linux::{
    IPC_CREAT, IPC_EXCL, IPC_RMID, IPC_SET, IPC_STAT, IpcPerm, PAGE_SIZE, SHM_DEST, SHM_EXEC,
    SHM_RDONLY, SHM_REMAP, SHM_RND, ShmidDs, errno::Errno, vmem::SharedObjectMapping,
};

impl<Platform: ShimPlatform> Task<Platform> {
    pub(super) fn new_segment_namespace(&self, target: ProcessId) -> Result<(), Errno> {
        match self.global.litebox.new_segment_namespace(target) {
            // Without the segment service, both namespaces are necessarily empty.
            Ok(()) | Err(SegmentError::Unavailable) => Ok(()),
            Err(error) => Err(error.into()),
        }
    }

    fn check_segment_context(&self) -> Result<(), Errno> {
        // A vfork child has the parent's address space and service association until exec.
        // Don't let it operate in its parent's name or modify its attachment records.
        if self.vfork.borrow().is_some() {
            Err(Errno::ENOSYS)
        } else {
            Ok(())
        }
    }

    pub(crate) fn sys_shmget(&self, key: i32, size: usize, flags: i32) -> Result<usize, Errno> {
        const SHM_HUGETLB: i32 = 0o4000;
        self.check_segment_context()?;
        if flags & SHM_HUGETLB != 0 {
            return Err(Errno::EOPNOTSUPP);
        }
        let id = self.global.litebox.get_segment(
            key,
            size as u64,
            (flags.cast_unsigned() & 0o777) as u16,
            flags & IPC_CREAT != 0,
            flags & IPC_EXCL != 0,
        )?;
        Ok(id as usize)
    }

    pub(crate) fn sys_shmat(
        &self,
        shmid: i32,
        addr: usize,
        flags: i32,
    ) -> Result<UserPtrMut<u8>, Errno> {
        self.check_segment_context()?;
        let id = u32::try_from(shmid).map_err(|_| Errno::EINVAL)?;
        if flags & SHM_REMAP != 0 && addr == 0 {
            return Err(Errno::EINVAL);
        }
        // Refuse rather than replacing an unrelated VMA or permitting execution of data pages.
        if flags & (SHM_REMAP | SHM_EXEC) != 0 {
            return Err(Errno::EOPNOTSUPP);
        }
        let address = match addr {
            0 => None,
            addr if addr.is_multiple_of(PAGE_SIZE) => Some(addr),
            addr if flags & SHM_RND != 0 && addr >= PAGE_SIZE => Some(addr & !(PAGE_SIZE - 1)),
            _ => return Err(Errno::EINVAL),
        };
        let readonly = flags & SHM_RDONLY != 0;
        let (file, size) = self.global.litebox.attach_segment::<_, PAGE_SIZE>(
            self.global.platform,
            id,
            !readonly,
        )?;
        let mapped = usize::try_from(size)
            .map_err(|_| Errno::ENOMEM)
            .and_then(|len| {
                self.global.mm.attach_sysv(
                    address,
                    len,
                    readonly,
                    SharedObjectMapping { file, offset: 0 },
                    id,
                )
            });
        if mapped.is_err() {
            self.global.litebox.detach_segment(id)?;
        }
        mapped
    }

    pub(crate) fn sys_shmdt(&self, addr: usize) -> Result<(), Errno> {
        self.check_segment_context()?;
        self.global.mm.detach_sysv(addr)
    }

    pub(crate) fn sys_shmctl(
        &self,
        shmid: i32,
        cmd: i32,
        buf: UserPtrMut<ShmidDs>,
    ) -> Result<usize, Errno> {
        self.check_segment_context()?;
        let id = u32::try_from(shmid).map_err(|_| Errno::EINVAL)?;
        let segments = &self.global.litebox;
        match cmd {
            IPC_RMID => segments.delete_segment(id)?,
            IPC_SET => {
                let ds = buf.read_at_offset::<Platform>(0).ok_or(Errno::EFAULT)?;
                let owner = FileUser {
                    user: ds.shm_perm.uid.try_into().map_err(|_| Errno::EINVAL)?,
                    group: ds.shm_perm.gid.try_into().map_err(|_| Errno::EINVAL)?,
                };
                segments.set_segment(id, owner, (ds.shm_perm.mode & 0o777) as u16)?;
            }
            IPC_STAT => {
                let status = segments.segment_status(id)?;
                let ds = ShmidDs {
                    shm_perm: IpcPerm {
                        key: status.key,
                        uid: status.owner.user.into(),
                        gid: status.owner.group.into(),
                        cuid: status.creator.user.into(),
                        cgid: status.creator.group.into(),
                        mode: u32::from(status.mode)
                            | if status.removed {
                                SHM_DEST.cast_unsigned()
                            } else {
                                0
                            },
                        ..IpcPerm::default()
                    },
                    shm_segsz: status.size,
                    shm_atime: status.attached.cast_signed(),
                    shm_dtime: status.detached.cast_signed(),
                    shm_ctime: status.created.cast_signed(),
                    shm_cpid: status.creator_pid.cast_signed(),
                    shm_lpid: status.last_pid.cast_signed(),
                    shm_nattch: status.attachments,
                    ..ShmidDs::default()
                };
                buf.write_at_offset::<Platform>(0, ds)
                    .ok_or(Errno::EFAULT)?;
            }
            _ => return Err(Errno::EINVAL),
        }
        Ok(0)
    }
}
