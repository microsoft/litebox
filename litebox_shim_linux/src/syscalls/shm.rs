// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! System V shared memory.
//!
//! Supports keyed and private segments; read-only, read-write and executable attaches; address
//! rounding and replacement; and the `IPC_STAT`, `IPC_SET`, `IPC_RMID`, `IPC_INFO`, `SHM_INFO`,
//! `SHM_STAT` and `SHM_STAT_ANY` control operations. `SHM_HUGETLB` is ignored: segments use
//! ordinary pages. Segments are scoped to the guest IPC namespace; none are published in the
//! host's System V IPC namespace.

use crate::{ShimPlatform, Task, UserPtrMut};
use litebox::segment::{PreparedAttach, SegmentError};
use litebox_broker_protocol::fs::FileUser;
use litebox_broker_protocol::segment::{
    GetSegmentRequest, PrepareSegmentAttachRequest, SEGMENT_PAGE_SIZE, SegmentId, SegmentInfo,
    SegmentStatus, SetSegmentRequest,
};
use litebox_common_linux::{
    IpcPerm, PAGE_SIZE, ProtFlags, SHM_DEST, ShmLimits, ShmUsage, ShmatFlags, ShmctlCmd,
    ShmgetFlags, ShmidDs, errno::Errno, mm::SysvAddress, vmem::SharedObjectMapping,
};

// The broker bounds attachment counts by segment pages, each of which `shmat` maps as a guest page.
const _: () = assert!(SEGMENT_PAGE_SIZE == PAGE_SIZE as u64);

fn shmid_ds(status: &SegmentStatus) -> ShmidDs {
    ShmidDs {
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
    }
}

/// Returns what `IPC_INFO` and `SHM_INFO` return: the highest index in use, or zero if none is.
fn highest_index(info: &SegmentInfo) -> usize {
    info.highest_slot.map_or(0, |slot| slot as usize)
}

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
        let remap = flags.contains(ShmatFlags::SHM_REMAP);
        let address = if addr == 0 {
            if remap {
                return Err(Errno::EINVAL);
            }
            SysvAddress::Any
        } else {
            let addr = if addr.is_multiple_of(PAGE_SIZE) {
                addr
            } else if flags.contains(ShmatFlags::SHM_RND) {
                addr & !(PAGE_SIZE - 1)
            } else {
                return Err(Errno::EINVAL);
            };
            match addr {
                // Linux refuses to replace from the rounded address 0, and otherwise fails to map
                // there, below `mmap_min_addr`.
                0 if remap => return Err(Errno::EINVAL),
                0 => return Err(Errno::EPERM),
                addr if remap => SysvAddress::Replace(addr),
                addr => SysvAddress::Free(addr),
            }
        };
        let writable = !flags.contains(ShmatFlags::SHM_RDONLY);
        let executable = flags.contains(ShmatFlags::SHM_EXEC);
        let mut prot = ProtFlags::PROT_READ;
        prot.set(ProtFlags::PROT_WRITE, writable);
        prot.set(ProtFlags::PROT_EXEC, executable);
        let request = PrepareSegmentAttachRequest {
            id,
            writable,
            executable,
        };
        let PreparedAttach {
            object,
            size,
            reservation,
        } = self
            .global
            .litebox
            .prepare_segment_attach::<_, PAGE_SIZE>(self.global.platform, request)
            .map_err(|error| match error {
                // `shmat` reports any lack of resources as ENOMEM; ENOSPC is `shmget`'s.
                SegmentError::NoSpace => Errno::ENOMEM,
                error => error.into(),
            })?;
        let len = usize::try_from(size).map_err(|_| Errno::ENOMEM)?;
        // SAFETY: This creates a guest VMA at an unmapped range or, with `SHM_REMAP`, replaces
        // guest VMAs as `MAP_FIXED` does. Host code does not borrow from guest VMAs: guest
        // pointer access uses fault-aware copies, and VMA users under the MM lock cannot see the
        // new one before confirmation. Other views of the backing object are independent
        // mappings.
        //
        // A mapping that fails, or is never confirmed, drops the reservation, which cancels it
        // without recording an attach or detach.
        unsafe {
            self.global.mm.attach_sysv(
                address,
                len,
                prot,
                SharedObjectMapping {
                    file: object,
                    offset: 0,
                },
                id,
                |count| reservation.confirm(count).map_err(Errno::from),
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
        // Linux rejects a negative `shmid` even for commands that ignore it.
        let number = u32::try_from(shmid).map_err(|_| Errno::EINVAL)?;
        let id = SegmentId(number);
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
                let ds = shmid_ds(&litebox.segment_status(id)?);
                buf.write_at_offset::<Platform>(0, ds)
                    .ok_or(Errno::EFAULT)?;
            }
            // Indexes are the broker's slots, which enumerate the namespace's segments as
            // Linux's IPC indexes do.
            ShmctlCmd::StatIndex | ShmctlCmd::StatIndexAny => {
                let found = litebox.segment_slot_status(number, cmd == ShmctlCmd::StatIndex)?;
                buf.write_at_offset::<Platform>(0, shmid_ds(&found.status))
                    .ok_or(Errno::EFAULT)?;
                return Ok(found.id.0 as usize);
            }
            ShmctlCmd::Limits => {
                let info = litebox.segment_info()?;
                let segments = u64::from(info.max_segments);
                let limits = ShmLimits {
                    shmmax: info.max_segment_size,
                    shmmin: 1,
                    shmmni: segments,
                    // Linux bounds a process's attached segments only by `shmmni`.
                    shmseg: segments,
                    shmall: info.max_total_bytes / SEGMENT_PAGE_SIZE,
                    ..ShmLimits::default()
                };
                buf.cast::<ShmLimits>()
                    .write_at_offset::<Platform>(0, limits)
                    .ok_or(Errno::EFAULT)?;
                return Ok(highest_index(&info));
            }
            ShmctlCmd::Usage => {
                let info = litebox.segment_info()?;
                let pages = info.bytes / SEGMENT_PAGE_SIZE;
                let usage = ShmUsage {
                    used_ids: i32::try_from(info.segments).unwrap_or(i32::MAX),
                    shm_tot: pages,
                    // The host doesn't report which pages are resident, so count every page,
                    // which no swap holds.
                    shm_rss: pages,
                    ..ShmUsage::default()
                };
                buf.cast::<ShmUsage>()
                    .write_at_offset::<Platform>(0, usage)
                    .ok_or(Errno::EFAULT)?;
                return Ok(highest_index(&info));
            }
        }
        Ok(0)
    }
}
