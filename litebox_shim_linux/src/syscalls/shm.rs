// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! System V shared memory.
//!
//! Supports keyed and private segments and the `IPC_STAT`, `IPC_SET`, `IPC_RMID`, `IPC_INFO`,
//! `SHM_INFO`, `SHM_STAT` and `SHM_STAT_ANY` control operations; attaching segments is not
//! supported yet. `SHM_HUGETLB` is ignored: segments use ordinary pages. Segments are scoped to
//! the guest IPC namespace; none are published in the host's System V IPC namespace.
//!
//! Segments have no owner yet: every caller may use and control every segment in its namespace,
//! and each sees itself as a segment's owner and creator.

use crate::{ShimPlatform, Task, UserPtrMut};
use litebox_broker_protocol::segment::{
    GetSegmentRequest, SEGMENT_PAGE_SIZE, SegmentId, SegmentInfo, SegmentStatus, SetSegmentRequest,
};
use litebox_common_linux::{
    IpcPerm, PAGE_SIZE, SHM_DEST, ShmLimits, ShmUsage, ShmctlCmd, ShmgetFlags, ShmidDs,
    errno::Errno,
};

// Segment byte totals count broker pages, which `IPC_INFO` and `SHM_INFO` report as guest pages.
const _: () = assert!(SEGMENT_PAGE_SIZE == PAGE_SIZE as u64);

/// `status` as a `shmid_ds`, owned and created by `uid` and `gid`.
fn shmid_ds(status: &SegmentStatus, uid: u32, gid: u32) -> ShmidDs {
    ShmidDs {
        shm_perm: IpcPerm {
            key: status.key,
            uid,
            gid,
            cuid: uid,
            cgid: gid,
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
    /// association until it execs: it must not act in its parent's name.
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
                if (ds.shm_perm.uid, ds.shm_perm.gid)
                    != (self.credentials.euid, self.credentials.egid)
                {
                    log_unsupported!("shmctl(IPC_SET) giving a segment to another owner");
                }
                litebox.set_segment(SetSegmentRequest {
                    id,
                    mode: (ds.shm_perm.mode & 0o777) as u16,
                })?;
            }
            ShmctlCmd::Stat => {
                let ds = shmid_ds(
                    &litebox.segment_status(id)?,
                    self.credentials.euid,
                    self.credentials.egid,
                );
                buf.write_at_offset::<Platform>(0, ds)
                    .ok_or(Errno::EFAULT)?;
            }
            // Indexes are the broker's slots, which enumerate the namespace's segments as
            // Linux's IPC indexes do.
            ShmctlCmd::StatIndex | ShmctlCmd::StatIndexAny => {
                let found = litebox.segment_slot_status(number)?;
                let ds = shmid_ds(&found.status, self.credentials.euid, self.credentials.egid);
                buf.write_at_offset::<Platform>(0, ds)
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
