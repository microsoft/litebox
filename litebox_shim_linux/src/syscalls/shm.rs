// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! System V shared memory.
//!
//! Supports keyed and private segments, read-only and read-write attaches, address rounding,
//! and the `IPC_STAT`, `IPC_SET`, and `IPC_RMID` control operations. Huge pages, executable
//! attaches, and forced address replacement are not supported. Segments are scoped to the
//! guest IPC namespace; none are published in the host's System V IPC namespace.

use crate::{ShimPlatform, Task, UserPtrMut};
use litebox::segment::{PreparedAttach, SegmentError};
use litebox_broker_protocol::fs::FileUser;
use litebox_broker_protocol::segment::{GetSegmentRequest, SegmentId, SetSegmentRequest};
use litebox_common_linux::{
    IpcPerm, PAGE_SIZE, SHM_DEST, ShmatFlags, ShmctlCmd, ShmgetFlags, ShmidDs, errno::Errno,
    vmem::SharedObjectMapping,
};

impl<Platform: ShimPlatform> Task<Platform> {
    /// Fails with `EINVAL` in a `vfork` child, which has its parent's address space and broker
    /// association until it execs: it must not act in its parent's name or change the parent's
    /// attachment records.
    fn einval_in_vfork_child(&self) -> Result<(), Errno> {
        if self.vfork.borrow().is_some() {
            log_unsupported!("SysV shared memory in a vfork child");
            Err(Errno::EINVAL)
        } else {
            Ok(())
        }
    }

    pub(crate) fn sys_shmget(
        &self,
        key: i32,
        size: usize,
        flags: ShmgetFlags,
    ) -> Result<usize, Errno> {
        self.einval_in_vfork_child()?;
        if flags.contains(ShmgetFlags::SHM_HUGETLB) {
            return Err(Errno::EOPNOTSUPP);
        }
        let id = self.global.litebox.get_segment(GetSegmentRequest {
            key,
            size: size as u64,
            mode: (flags.bits().cast_unsigned() & 0o777) as u16,
            create: flags.contains(ShmgetFlags::IPC_CREAT),
            exclusive: flags.contains(ShmgetFlags::IPC_EXCL),
        })?;
        Ok(id.0 as usize)
    }

    pub(crate) fn sys_shmat(
        &self,
        shmid: i32,
        addr: usize,
        flags: ShmatFlags,
    ) -> Result<UserPtrMut<u8>, Errno> {
        self.einval_in_vfork_child()?;
        let id = SegmentId(u32::try_from(shmid).map_err(|_| Errno::EINVAL)?);
        if flags.contains(ShmatFlags::SHM_REMAP) && addr == 0 {
            return Err(Errno::EINVAL);
        }
        // Refuse rather than replacing an unrelated VMA or permitting execution of data pages.
        if flags.intersects(ShmatFlags::SHM_REMAP | ShmatFlags::SHM_EXEC) {
            return Err(Errno::EOPNOTSUPP);
        }
        let address = match addr {
            0 => None,
            addr if addr.is_multiple_of(PAGE_SIZE) => Some(addr),
            addr if flags.contains(ShmatFlags::SHM_RND) => match addr & !(PAGE_SIZE - 1) {
                // Linux maps the rounded address 0, below the lowest address it maps.
                0 => return Err(Errno::EPERM),
                rounded => Some(rounded),
            },
            _ => return Err(Errno::EINVAL),
        };
        let readonly = flags.contains(ShmatFlags::SHM_RDONLY);
        let PreparedAttach {
            object,
            size,
            reservation,
        } = self
            .global
            .litebox
            .prepare_segment_attach::<_, PAGE_SIZE>(self.global.platform, id, !readonly)
            .map_err(|error| match error {
                // `shmat` reports any lack of resources as ENOMEM; ENOSPC is `shmget`'s.
                SegmentError::NoSpace => Errno::ENOMEM,
                error => error.into(),
            })?;
        let len = usize::try_from(size).map_err(|_| Errno::ENOMEM)?;
        // SAFETY: This only creates a guest VMA at a previously unmapped range. Host code does
        // not borrow from the new VMA: guest pointer access uses fault-aware copies, and VMA
        // users under the MM lock cannot see it before confirmation. Other views of the backing
        // object are independent mappings.
        //
        // A mapping that fails, or is never confirmed, drops the reservation, which cancels it
        // without recording an attach or detach.
        unsafe {
            self.global.mm.attach_sysv(
                address,
                len,
                readonly,
                SharedObjectMapping {
                    file: object,
                    offset: 0,
                },
                id,
                || reservation.confirm().map_err(Errno::from),
            )
        }
    }

    pub(crate) fn sys_shmdt(&self, addr: usize) -> Result<(), Errno> {
        self.einval_in_vfork_child()?;
        // SAFETY: As for `munmap`, the host reaches guest pages only through fault-aware copies
        // and holds no borrow of them, so sibling threads that still use the detached pages fault
        // as on Linux.
        unsafe { self.global.mm.detach_sysv(addr) }
    }

    pub(crate) fn sys_shmctl(
        &self,
        shmid: i32,
        cmd: ShmctlCmd,
        buf: UserPtrMut<ShmidDs>,
    ) -> Result<usize, Errno> {
        self.einval_in_vfork_child()?;
        let id = SegmentId(u32::try_from(shmid).map_err(|_| Errno::EINVAL)?);
        let litebox = &self.global.litebox;
        match cmd {
            ShmctlCmd::Remove => litebox.remove_segment(id)?,
            ShmctlCmd::Set => {
                let ds = buf.read_at_offset::<Platform>(0).ok_or(Errno::EFAULT)?;
                let owner = FileUser {
                    user: ds.shm_perm.uid.try_into().map_err(|_| Errno::EINVAL)?,
                    group: ds.shm_perm.gid.try_into().map_err(|_| Errno::EINVAL)?,
                };
                litebox.set_segment(SetSegmentRequest {
                    id,
                    owner,
                    mode: (ds.shm_perm.mode & 0o777) as u16,
                })?;
            }
            ShmctlCmd::Stat => {
                let status = litebox.segment_status(id)?;
                let ds = ShmidDs {
                    shm_perm: IpcPerm {
                        key: status.key,
                        uid: status.owner.user.into(),
                        gid: status.owner.group.into(),
                        cuid: status.creator.user.into(),
                        cgid: status.creator.group.into(),
                        mode: u32::from(status.mode) | if status.removed { SHM_DEST } else { 0 },
                        ..IpcPerm::default()
                    },
                    shm_segsz: status.size,
                    shm_atime: status.attach_time.cast_signed(),
                    shm_dtime: status.detach_time.cast_signed(),
                    shm_ctime: status.change_time.cast_signed(),
                    shm_cpid: status.creator_pid.cast_signed(),
                    shm_lpid: status.last_pid.cast_signed(),
                    shm_nattch: status.attachments,
                    ..ShmidDs::default()
                };
                buf.write_at_offset::<Platform>(0, ds)
                    .ok_or(Errno::EFAULT)?;
            }
        }
        Ok(0)
    }
}
