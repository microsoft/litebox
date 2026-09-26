// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! A [LiteBox platform](../litebox/platform/index.html) for running LiteBox on
//! userland macOS running on Apple Silicon.
//!
//! # Why aarch64 only
//!
//! There is no x86-64 variant of this platform. Running an x86-64 guest on an
//! Apple Silicon host would mean instruction emulation, which is exactly what
//! LiteBox exists to avoid: the whole point of the "South" platform interface is
//! that the guest's instructions are the host's instructions and only the
//! *system* interface is virtualized. An aarch64 Linux guest on an aarch64 macOS
//! host needs no emulation at all -- just this platform plus the aarch64 syscall
//! rewriting that `litebox_syscall_rewriter` already performs.
//!
//! # How Darwin differs from the other userland platforms
//!
//! * **16 KiB pages.** Apple Silicon's page size is 16 KiB, not 4 KiB, so every
//!   fixed mapping and every protection change must be 16 KiB aligned. This is
//!   why `litebox::mm::vmem::PAGE_SIZE` is target-dependent; the guest learns
//!   the same value through `AT_PAGESZ`.
//! * **A 4 GiB `__PAGEZERO`.** The first 4 GiB of an arm64 Mach-O process is
//!   reserved and permanently unmapped, so no guest mapping can live below it.
//!   `MacOsUserland`'s `TASK_ADDR_MIN` reflects that, which in turn means
//!   guest images have to be position-independent or linked above 4 GiB.
//! * **W^X.** Anonymous memory cannot be both writable and executable, and
//!   memory that was ever writable cannot later become executable. The supported
//!   escape hatch is `MAP_JIT`, which requires the host process to be signed with
//!   the `com.apple.security.cs.allow-jit` entitlement and requires writes to be
//!   bracketed by `pthread_jit_write_protect_np`. Executable guest mappings
//!   therefore go through `jit_write_protect`.
//! * **No futex.** Darwin's equivalent is `__ulock_wait`/`__ulock_wake`, which
//!   provides the same compare-and-wait contract.
//! * **No `MAP_FIXED_NOREPLACE`, no `MAP_POPULATE`, no `MAP_GROWSDOWN`.** The
//!   first is emulated with an atomic `mach_vm_allocate` reservation, the second
//!   with `madvise(MADV_WILLNEED)`, and the third has no equivalent.
//! * **No vDSO.** `SystemInfoProvider::get_vdso_address` reports `None`, which
//!   means a guest signal handler must supply its own `sa_restorer`.
//! * **Seatbelt instead of seccomp.** The second line of defense behind
//!   LiteBox's own guest/host boundary is a `(deny default)` Seatbelt profile
//!   installed by `enable_seatbelt_sandbox`, the counterpart of the Linux
//!   platform's seccomp filter. Its source module (`src/seatbelt.rs`) documents
//!   what it denies, what it deliberately cannot deny, and why a failure to
//!   install it is fatal rather than a warning.
//!
//! # Residual risk after `enable_seatbelt_sandbox`
//!
//! Seatbelt mediates *operations*, not syscalls, and it only mediates the
//! operations it has hooks for. Code that has already subverted the shim or this
//! platform still keeps, inside the sandbox: full read/write on every descriptor
//! that was open when the profile was installed (stdin, stdout, stderr, and the
//! `utun` device when guest networking is on -- which is a raw L3 tap onto the
//! host's network stack); the whole `mmap`/`mprotect`/`munmap`/`MAP_JIT` surface,
//! so it can map and execute arbitrary native code in-process; every byte of this
//! process's own address space, including the guest images and any key material
//! the platform holds; the ability to read every `sysctl`; and the ability to
//! crash or hang the process. What it loses is the ability to reach *outside*
//! this process: no host file may be opened, `stat`ed, created or unlinked; no
//! socket may be bound or connected and no new `utun` may be opened; no host
//! program may be executed; and no other process may be signalled. Note that
//! plain `socket()` creation still succeeds -- it is `bind`/`connect` that are
//! refused -- so "no sockets exist" is not the guarantee; "no socket can be
//! attached to an endpoint" is.

// Restrict this crate to macOS on Apple Silicon. See the module docs for why
// there is deliberately no x86-64 variant.
#![cfg(all(target_os = "macos", target_arch = "aarch64"))]

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use core::time::Duration;
use std::io::IsTerminal as _;
use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd};
use std::sync::{Arc, Condvar, Mutex, OnceLock};

use litebox::platform::page_mgmt::{
    AllocationError, DeallocationError, FixedAddressBehavior, MemoryRegionPermissions,
    PermissionUpdateError, RemapError, SharedPageIoError,
};
use litebox::platform::{ImmediatelyWokenUp, UnblockedOrTimedOut};
use litebox::utils::TruncateExt as _;
use zerocopy::{FromBytes, IntoBytes};

extern crate alloc;

mod darwin;
mod guest;
mod hvf;
mod hvf_backend;
mod hvf_backing;
mod hvf_memory;
mod hvf_vcpu;
mod hvf_vcpu_diagnostic;
// Rootless guest NAT engine, wired into `MacOsUserland`'s
// `IPInterfaceProvider` bodies by `enable_nat_engine`.
mod nat;
mod net;
mod seatbelt;

pub(crate) trait HvfCompletionCapability {
    fn validate_hvf_completion(&self, vm: &hvf::HvfVm) -> Result<(), hvf::HvfError>;
}

pub use hvf::{
    HvfArchitecturalState, HvfBoundaryReport, HvfEl1State, HvfError, HvfExceptionExit,
    HvfFeatureRegister, HvfFeatureRegisters, HvfMonitor, HvfPublishedPanicOperation,
    HvfPublishedPanicReport, HvfSdkResidualReport, HvfSimd128, HvfSmokeCleanupFailure,
    HvfSmokeCleanupReport, HvfSmokeError, HvfSmokeReport, HvfSmokeResidualReport,
    HvfSmokeResourceReport, HvfSmokeResourceState, HvfStageOneRegisterReport, HvfVcpuCancellation,
    HvfVcpuExit, HvfVmReport, hvf_boundary_probe, hvf_published_panic_probe, hvf_smoke_probe,
    hvf_smoke_retry_residual, publish_hvf_executable_bytes,
};
pub use hvf_backend::{
    HvfBackendError, HvfLaneReplacementReport, HvfLaneStarvationReport, HvfSchedulerLatencyReport,
    HvfSchedulerScalingLevel, HvfSchedulerScalingReport, hvf_lane_replacement_probe,
    hvf_lane_starvation_probe, hvf_sandbox_probe, hvf_scheduler_latency_probe,
    hvf_scheduler_scaling_probe,
};
pub use hvf_backing::{
    HvfHostBackingError, HvfHostBackingReport, HvfHostResourceReport, hvf_host_backing_probe,
    hvf_host_begin_recovery_wave, hvf_host_resource_report, hvf_host_retry_residual,
};
pub use hvf_memory::{
    HvfAddressSpace, HvfAddressSpaceDestroyTicket, HvfAddressSpaceId, HvfAddressSpaceReport,
    HvfAliasPanicFailureReport, HvfAliasRaceReport, HvfAsid, HvfBackingIdentity, HvfCallbackOutput,
    HvfClaim, HvfExecutableGeneration, HvfForkResult, HvfGuestPermissions, HvfLedgerEntry,
    HvfMemory, HvfMemoryError, HvfMemoryFailureReport, HvfMemoryLimits, HvfMemoryReport,
    HvfMemoryUsage, HvfMirroredViewReport, HvfMutation, HvfParticipantRecoveryReceipt,
    HvfPoisonConcurrencyReport, HvfPublicationEpoch, HvfPublicationTicket,
    HvfQuarantineRetryReport, HvfRangeMutation, HvfRegisterFailureReport, HvfRetirementReport,
    HvfRetirementTicket, HvfRootGeneration, HvfSharedBackingKey, HvfSharing, HvfTlbiGeneration,
    HvfTranslationRegime, HvfUnmapFailureReport, HvfUnmapResult, HvfVcpuMemorySnapshot,
    HvfVcpuParticipant, HvfVcpuParticipantId, HvfVcpuRunAttachment, HvfWriteEpoch,
    hvf_alias_panic_failure_probe, hvf_alias_race_probe, hvf_memory_failure_probe,
    hvf_memory_probe, hvf_mirrored_view_probe, hvf_poison_concurrency_probe,
    hvf_register_failure_probe, hvf_unmap_failure_probe, with_hvf_memory_failure_probe,
    with_hvf_memory_probe,
};
pub use hvf_vcpu::{
    HvfOwnerSynchronizationProof, HvfSynchronizationRequest, HvfVcpuCancellationReceipt,
    HvfVcpuExitState, HvfVcpuLane, HvfVcpuLaneCancellation, HvfVcpuLaneCloseReport,
    HvfVcpuLaneError, HvfVcpuLaneHandle, HvfVcpuLaneParticipantCapability, HvfVcpuRegistry,
    HvfVcpuRunResult, HvfVtimerState,
};
pub use hvf_vcpu_diagnostic::{
    HvfVcpuCustodyReport, HvfVcpuDiagnosticError, HvfVcpuDiagnosticReport, HvfVcpuFailureReport,
    HvfVcpuTotalityReport, hvf_vcpu_custody_probe, hvf_vcpu_diagnostic_probe,
    hvf_vcpu_failure_probe, hvf_vcpu_totality_probe,
};
pub use seatbelt::{enable_seatbelt_sandbox, enable_seatbelt_sandbox_with_outbound_network};

use darwin::{
    MAP_JIT, ReservationError, mach_vm_region_iter, release_reservation, remap_to_fixed,
    reserve_fixed, ulock_wait, ulock_wake,
};

/// The host signal LiteBox reserves for interrupting a thread out of guest
/// execution. Darwin has no realtime signals, so this has to come out of the
/// small fixed set; `SIGUSR2` is the least likely to be wanted elsewhere in a
/// process that is already dedicating itself to hosting a sandbox.
const INTERRUPT_SIGNAL: libc::c_int = libc::SIGUSR2;

/// Serializes every native guest page-management mutation in this process.
/// Multiple independent `MacOsUserland` instances can coexist, so neither the
/// upper per-instance page-manager lock nor `shared_page_registry` is broad
/// enough to make reserve/replace and MAP_JIT migration transactions exclusive.
static NATIVE_VM_MUTATION_LOCK: Mutex<()> = Mutex::new(());

fn lock_native_vm_mutation() -> std::sync::MutexGuard<'static, ()> {
    match NATIVE_VM_MUTATION_LOCK.lock() {
        Ok(guard) => guard,
        Err(_) => std::process::abort(),
    }
}

/// The userland macOS platform.
///
/// This implements the main [`litebox::platform::Provider`] trait, i.e.,
/// implements all platform traits.
pub struct MacOsUserland {
    /// Host mappings that already exist and must not be handed to a guest.
    reserved_pages: alloc::vec::Vec<core::ops::Range<usize>>,
    /// The boot session identifier, if
    /// [`Self::initialize_boot_specific_kdf_support`] has been run. It is stable
    /// across processes but changes on every boot.
    boot_id: OnceLock<alloc::vec::Vec<u8>>,
    /// Whether each of stdin/stdout/stderr is a terminal, sampled once at
    /// startup so the guest cannot observe a redirect mid-flight.
    stdio_is_tty: [bool; 3],
    /// Real, non-blocking-observable stdin, fed by a background host thread spawned in
    /// [`Self::new`]. See [`litebox::platform::StdinPump`].
    stdin_pump: litebox::platform::StdinPump,
    /// Doorbell the stdin-pump background thread notifies after every push/EOF, so
    /// `StdioProvider::read_from_stdin`'s blocking path can sleep instead of busy-polling.
    stdin_doorbell: (std::sync::Mutex<()>, Condvar),
    /// When set, host-stdin EOF does NOT mark the pump EOF: another producer (the runner's VNC
    /// keyboard bridge via [`Self::inject_stdin`]) can still deliver guest stdin, so the guest
    /// must keep seeing an open (momentarily empty) stream. See `spawn_stdin_pump_thread`.
    stdin_held_open: core::sync::atomic::AtomicBool,
    /// Serializes real host writes to stdout, so concurrent guest threads' `write()` calls to the
    /// same stream don't interleave mid-write.
    stdout_lock: std::sync::Mutex<()>,
    /// Serializes real host writes to stderr; see [`Self::stdout_lock`].
    stderr_lock: std::sync::Mutex<()>,
    /// One unlinked sparse host file, opened before Seatbelt is installed, whose disjoint extents
    /// provide coherent physical storage for guest shared mappings. Keeping one descriptor open
    /// avoids any host-filesystem operation after sandbox entry.
    shared_page_file: OwnedFd,
    /// Logical-backing-to-sparse-file extents and currently installed aliases.
    shared_page_registry: std::sync::Mutex<SharedPageRegistry>,
    /// Wakes mappings waiting for a concurrent first-time backing initialization to finish.
    shared_page_init_condvar: Condvar,
    /// The `utun` socket used for guest networking, if one was requested.
    tun: Option<std::os::fd::OwnedFd>,
    /// The rootless guest NAT engine, once [`Self::enable_nat_engine`] has
    /// installed it. Consulted by the `IPInterfaceProvider` bodies only when
    /// no `utun` device is attached. The engine's entry points take `&mut
    /// self`; the mutex is what makes them sound to call through the shared
    /// platform reference.
    nat: OnceLock<Mutex<nat::NatEngine>>,
    /// CoW-eligible memory regions registered via [`Self::register_cow_region`].
    /// Maps the start address of the static slice to the info needed to re-mmap
    /// the backing file. Mirrors `litebox_platform_linux_userland`'s identical
    /// mechanism.
    cow_regions: std::sync::RwLock<alloc::collections::BTreeMap<usize, CowRegionInfo>>,
}

/// Information about a CoW-eligible memory region backed by a host file.
struct CowRegionInfo {
    /// The path to the backing file on the host filesystem.
    file_path: std::path::PathBuf,
    /// Length of the backing file's registered slice.
    file_length: usize,
}

#[derive(Clone)]
struct SharedPageExtent {
    logical_range: core::ops::Range<usize>,
    file_offset: usize,
}

#[derive(Clone)]
struct SharedPageAlias {
    virtual_range: core::ops::Range<usize>,
    backing_identity: usize,
    backing_offset: usize,
}

#[derive(Default)]
struct SharedPageRegistry {
    backings: alloc::collections::BTreeMap<usize, alloc::vec::Vec<SharedPageExtent>>,
    initialized: alloc::collections::BTreeMap<usize, alloc::vec::Vec<core::ops::Range<usize>>>,
    initializing: alloc::collections::BTreeMap<usize, alloc::vec::Vec<core::ops::Range<usize>>>,
    aliases: alloc::vec::Vec<SharedPageAlias>,
    next_file_offset: usize,
}

impl SharedPageRegistry {
    fn ensure_extents(
        &mut self,
        fd: libc::c_int,
        backing_identity: usize,
        logical_range: core::ops::Range<usize>,
    ) -> Result<alloc::vec::Vec<(core::ops::Range<usize>, usize)>, AllocationError> {
        let existing = self.backings.entry(backing_identity).or_default();
        existing.sort_by_key(|extent| extent.logical_range.start);

        let mut gaps = alloc::vec::Vec::new();
        let mut cursor = logical_range.start;
        for extent in existing.iter() {
            if extent.logical_range.end <= cursor {
                continue;
            }
            if extent.logical_range.start >= logical_range.end {
                break;
            }
            if extent.logical_range.start > cursor {
                gaps.push(cursor..extent.logical_range.start.min(logical_range.end));
            }
            cursor = cursor.max(extent.logical_range.end).min(logical_range.end);
            if cursor == logical_range.end {
                break;
            }
        }
        if cursor < logical_range.end {
            gaps.push(cursor..logical_range.end);
        }

        let mut next_file_offset = self.next_file_offset;
        let mut additions = alloc::vec::Vec::with_capacity(gaps.len());
        for gap in gaps {
            let file_offset = next_file_offset;
            next_file_offset = next_file_offset
                .checked_add(gap.len())
                .ok_or(AllocationError::OutOfMemory)?;
            additions.push(SharedPageExtent {
                logical_range: gap,
                file_offset,
            });
        }
        let file_len =
            libc::off_t::try_from(next_file_offset).map_err(|_| AllocationError::OutOfMemory)?;
        if next_file_offset != self.next_file_offset {
            // SAFETY: `fd` is the platform-owned sparse backing file and remains open for the
            // platform's lifetime. Growing an unlinked sparse file allocates no data blocks until
            // a mapped page is written.
            if unsafe { libc::ftruncate(fd, file_len) } != 0 {
                return Err(AllocationError::OutOfMemory);
            }
            self.next_file_offset = next_file_offset;
            existing.extend(additions);
            existing.sort_by_key(|extent| extent.logical_range.start);
        }

        let mut result = alloc::vec::Vec::new();
        for extent in existing.iter() {
            let start = extent.logical_range.start.max(logical_range.start);
            let end = extent.logical_range.end.min(logical_range.end);
            if start < end {
                result.push((
                    start..end,
                    extent.file_offset + (start - extent.logical_range.start),
                ));
            }
        }
        Ok(result)
    }

    fn gaps_excluding(
        requested: core::ops::Range<usize>,
        mut covered: alloc::vec::Vec<core::ops::Range<usize>>,
    ) -> alloc::vec::Vec<core::ops::Range<usize>> {
        covered.sort_by_key(|range| range.start);
        let mut gaps = alloc::vec::Vec::new();
        let mut cursor = requested.start;
        for range in covered {
            if range.end <= cursor {
                continue;
            }
            if range.start >= requested.end {
                break;
            }
            if range.start > cursor {
                gaps.push(cursor..range.start.min(requested.end));
            }
            cursor = cursor.max(range.end).min(requested.end);
            if cursor == requested.end {
                break;
            }
        }
        if cursor < requested.end {
            gaps.push(cursor..requested.end);
        }
        gaps
    }

    fn uninitialized_ranges(
        &self,
        backing_identity: usize,
        requested: core::ops::Range<usize>,
    ) -> alloc::vec::Vec<core::ops::Range<usize>> {
        Self::gaps_excluding(
            requested,
            self.initialized
                .get(&backing_identity)
                .cloned()
                .unwrap_or_default(),
        )
    }

    fn claimable_initialization_ranges(
        &self,
        backing_identity: usize,
        requested: core::ops::Range<usize>,
    ) -> alloc::vec::Vec<core::ops::Range<usize>> {
        let mut covered = self
            .initialized
            .get(&backing_identity)
            .cloned()
            .unwrap_or_default();
        if let Some(initializing) = self.initializing.get(&backing_identity) {
            covered.extend(initializing.iter().cloned());
        }
        Self::gaps_excluding(requested, covered)
    }

    fn insert_merged_range(
        ranges: &mut alloc::collections::BTreeMap<usize, alloc::vec::Vec<core::ops::Range<usize>>>,
        backing_identity: usize,
        new_range: core::ops::Range<usize>,
    ) {
        let ranges = ranges.entry(backing_identity).or_default();
        ranges.push(new_range);
        ranges.sort_by_key(|range| range.start);
        let old = core::mem::take(ranges);
        for range in old {
            if let Some(last) = ranges.last_mut()
                && range.start <= last.end
            {
                last.end = last.end.max(range.end);
            } else {
                ranges.push(range);
            }
        }
    }

    fn mark_initialized(
        &mut self,
        backing_identity: usize,
        initialized_range: core::ops::Range<usize>,
    ) {
        Self::insert_merged_range(&mut self.initialized, backing_identity, initialized_range);
    }

    fn mark_initializing(
        &mut self,
        backing_identity: usize,
        initializing_range: core::ops::Range<usize>,
    ) {
        Self::insert_merged_range(&mut self.initializing, backing_identity, initializing_range);
    }

    fn finish_initializing(&mut self, backing_identity: usize, finished: &core::ops::Range<usize>) {
        let Some(ranges) = self.initializing.get_mut(&backing_identity) else {
            return;
        };
        let old = core::mem::take(ranges);
        for range in old {
            if range.end <= finished.start || range.start >= finished.end {
                ranges.push(range);
                continue;
            }
            if range.start < finished.start {
                ranges.push(range.start..finished.start);
            }
            if range.end > finished.end {
                ranges.push(finished.end..range.end);
            }
        }
        if ranges.is_empty() {
            self.initializing.remove(&backing_identity);
        }
    }

    fn initialization_in_progress(
        &self,
        backing_identity: usize,
        range: &core::ops::Range<usize>,
    ) -> bool {
        self.initializing
            .get(&backing_identity)
            .is_some_and(|ranges| {
                ranges.iter().any(|initializing| {
                    initializing.start < range.end && range.start < initializing.end
                })
            })
    }

    fn existing_extents(
        &self,
        backing_identity: usize,
        logical_range: &core::ops::Range<usize>,
    ) -> alloc::vec::Vec<(core::ops::Range<usize>, usize)> {
        let mut result = alloc::vec::Vec::new();
        let Some(extents) = self.backings.get(&backing_identity) else {
            return result;
        };
        for extent in extents {
            let start = extent.logical_range.start.max(logical_range.start);
            let end = extent.logical_range.end.min(logical_range.end);
            if start < end {
                result.push((
                    start..end,
                    extent.file_offset + (start - extent.logical_range.start),
                ));
            }
        }
        result
    }

    fn forget_aliases(&mut self, removed: &core::ops::Range<usize>) {
        let old = core::mem::take(&mut self.aliases);
        for alias in old {
            if alias.virtual_range.end <= removed.start || alias.virtual_range.start >= removed.end
            {
                self.aliases.push(alias);
                continue;
            }
            if alias.virtual_range.start < removed.start {
                self.aliases.push(SharedPageAlias {
                    virtual_range: alias.virtual_range.start..removed.start,
                    backing_identity: alias.backing_identity,
                    backing_offset: alias.backing_offset,
                });
            }
            if alias.virtual_range.end > removed.end {
                self.aliases.push(SharedPageAlias {
                    virtual_range: removed.end..alias.virtual_range.end,
                    backing_identity: alias.backing_identity,
                    backing_offset: alias.backing_offset
                        + (removed.end - alias.virtual_range.start),
                });
            }
        }
    }
}

fn create_shared_page_file() -> OwnedFd {
    let mut path = *b"/private/tmp/litebox-shared-pages.XXXXXX\0";
    // SAFETY: `path` is a writable, NUL-terminated mkstemp template with six trailing X bytes.
    let fd = unsafe { libc::mkstemp(path.as_mut_ptr().cast::<libc::c_char>()) };
    assert!(
        fd >= 0,
        "failed to create shared-page backing file: {}",
        std::io::Error::last_os_error()
    );
    // The descriptor, not the pathname, is the durable capability. Unlink before Seatbelt is
    // installed so no guest operation can name or reopen the host object.
    // SAFETY: `path` is still the NUL-terminated path mkstemp filled in.
    let unlink_result = unsafe { libc::unlink(path.as_ptr().cast::<libc::c_char>()) };
    if unlink_result != 0 {
        // SAFETY: `fd` was returned by mkstemp and has not been transferred into OwnedFd yet.
        unsafe { libc::close(fd) };
        panic!(
            "failed to unlink shared-page backing file: {}",
            std::io::Error::last_os_error()
        );
    }
    // SAFETY: ownership of this newly opened descriptor transfers exactly once.
    unsafe { OwnedFd::from_raw_fd(fd) }
}

fn pread_all(
    fd: libc::c_int,
    mut data: &mut [u8],
    mut offset: usize,
) -> Result<(), SharedPageIoError> {
    while !data.is_empty() {
        let file_offset =
            libc::off_t::try_from(offset).map_err(|_| SharedPageIoError::OutOfRange)?;
        // SAFETY: `data` is writable for its complete length and `fd` remains open.
        let result = unsafe {
            libc::pread(
                fd,
                data.as_mut_ptr().cast::<libc::c_void>(),
                data.len(),
                file_offset,
            )
        };
        if result < 0 {
            if std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(SharedPageIoError::Io);
        }
        let count = usize::try_from(result).map_err(|_| SharedPageIoError::Io)?;
        if count == 0 {
            return Err(SharedPageIoError::Io);
        }
        offset = offset
            .checked_add(count)
            .ok_or(SharedPageIoError::OutOfRange)?;
        data = &mut data[count..];
    }
    Ok(())
}

fn pwrite_all(
    fd: libc::c_int,
    mut data: &[u8],
    mut offset: usize,
) -> Result<(), SharedPageIoError> {
    while !data.is_empty() {
        let file_offset =
            libc::off_t::try_from(offset).map_err(|_| SharedPageIoError::OutOfRange)?;
        // SAFETY: `data` is readable for its complete length and `fd` remains open.
        let result = unsafe {
            libc::pwrite(
                fd,
                data.as_ptr().cast::<libc::c_void>(),
                data.len(),
                file_offset,
            )
        };
        if result < 0 {
            if std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(SharedPageIoError::Io);
        }
        let count = usize::try_from(result).map_err(|_| SharedPageIoError::Io)?;
        if count == 0 {
            return Err(SharedPageIoError::Io);
        }
        offset = offset
            .checked_add(count)
            .ok_or(SharedPageIoError::OutOfRange)?;
        data = &data[count..];
    }
    Ok(())
}

impl core::fmt::Debug for MacOsUserland {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("MacOsUserland").finish_non_exhaustive()
    }
}

impl MacOsUserland {
    /// Create a new userland-macOS platform for use in LiteBox.
    ///
    /// `tun_device_name` optionally names a `utun` interface (such as `"utun3"`)
    /// to connect guest networking to; networking is disabled when it is `None`.
    ///
    /// # Panics
    ///
    /// Panics if the requested `utun` device cannot be opened, if the fault
    /// handlers that make guest-memory accesses fallible cannot be installed,
    /// or if reserving a pthread TSD key for the guest thread pointer fails.
    pub fn new(tun_device_name: Option<&str>) -> &'static Self {
        Self::new_with_options(tun_device_name, false)
    }

    /// [`Self::new`], with `hold_stdin_open` additionally controlling whether host-stdin EOF is
    /// forwarded to the guest: a runner that bridges another input source into guest stdin (the
    /// VNC keyboard) passes `true` so a closed or redirected host stdin doesn't read as EOF to
    /// a guest whose real keyboard is the bridge. Set at construction rather than after because
    /// a redirected host stdin hits EOF in the pump thread within microseconds of spawn.
    ///
    /// # Panics
    ///
    /// Panics under the same conditions as [`Self::new`].
    pub fn new_with_options(tun_device_name: Option<&str>, hold_stdin_open: bool) -> &'static Self {
        Self::construct(tun_device_name, hold_stdin_open, false)
            .unwrap_or_else(|error| panic!("failed to construct the platform: {error}"))
    }

    /// [`Self::new_with_options`] with the Hypervisor.framework guest backend
    /// installed first: unchanged stock AArch64 Linux code then executes at
    /// EL0 on real vCPUs (no syscall rewriting, no native `run_thread`), with
    /// every guest mapping mirrored into the host view at its own address.
    /// Must be called before the shim maps anything, and the executable must
    /// carry the `com.apple.security.hypervisor` entitlement.
    ///
    /// # Errors
    ///
    /// Returns the backend's typed error if the process VM, address space,
    /// vCPU lanes or sigreturn trampoline cannot be established; nothing is
    /// left half-installed.
    ///
    /// # Panics
    ///
    /// Panics under the same conditions as [`Self::new`].
    pub fn new_with_hvf(
        tun_device_name: Option<&str>,
        hold_stdin_open: bool,
    ) -> Result<&'static Self, HvfBackendError> {
        Self::construct(tun_device_name, hold_stdin_open, true)
    }

    fn construct(
        tun_device_name: Option<&str>,
        hold_stdin_open: bool,
        hvf: bool,
    ) -> Result<&'static Self, HvfBackendError> {
        install_fault_handlers();
        install_async_signal_handlers();
        reserve_guest_tpidr_tsd_slot();
        raise_nofile_limit();

        // Before the host maps are read, so the VM's own host mappings and
        // the guest trampoline page are both reserved from the shim.
        let backend = if hvf {
            Some(hvf_backend::install()?)
        } else {
            None
        };

        let tun = tun_device_name.map(|name| {
            net::open_utun(name).unwrap_or_else(|e| panic!("failed to open {name}: {e}"))
        });

        let mut reserved_pages = read_memory_maps();
        if let Some(backend) = backend {
            reserved_pages.extend(backend.reserved_ranges());
        }

        let platform = Self {
            reserved_pages,
            boot_id: OnceLock::new(),
            stdio_is_tty: [
                std::io::stdin().is_terminal(),
                std::io::stdout().is_terminal(),
                std::io::stderr().is_terminal(),
            ],
            stdin_pump: litebox::platform::StdinPump::new(
                litebox::platform::stdin_pump::DEFAULT_CAPACITY,
            ),
            stdin_doorbell: (std::sync::Mutex::new(()), Condvar::new()),
            stdin_held_open: core::sync::atomic::AtomicBool::new(hold_stdin_open),
            stdout_lock: std::sync::Mutex::new(()),
            stderr_lock: std::sync::Mutex::new(()),
            shared_page_file: create_shared_page_file(),
            shared_page_registry: std::sync::Mutex::new(SharedPageRegistry::default()),
            shared_page_init_condvar: Condvar::new(),
            tun,
            nat: OnceLock::new(),
            cow_regions: std::sync::RwLock::new(alloc::collections::BTreeMap::new()),
        };

        // A platform must outlive every guest thread that can reach it, so
        // leaking is the cheapest way to get a `'static` without reference
        // counting on every access. Runners construct one; tests may construct
        // more, and every process-global facility is initialized only once.
        let platform: &'static Self = alloc::boxed::Box::leak(alloc::boxed::Box::new(platform));
        spawn_stdin_pump_thread(platform);
        Ok(platform)
    }

    /// Populate the root key used by [`litebox::platform::DerivedKeyProvider`].
    ///
    /// The key is Darwin's boot session UUID: stable for every process in a boot
    /// and freshly generated by the kernel on the next one, which is exactly the
    /// "persistent across LiteBox invocations, reset by a true reboot" guarantee
    /// the trait describes.
    ///
    /// Must be called *before* `enable_seatbelt_sandbox`: `kern.bootsessionuuid`
    /// sits outside the `hw.optional.` prefix that profile admits, so afterwards
    /// this returns `EPERM` rather than a key. No macOS runner calls it today;
    /// one that does must do so during start-up, alongside the other host
    /// resources acquired before the sandbox goes up.
    ///
    /// # Errors
    ///
    /// Returns the `sysctl` error if the boot session UUID cannot be read.
    pub fn initialize_boot_specific_kdf_support(&self) -> Result<(), std::io::Error> {
        if self.boot_id.get().is_some() {
            return Ok(());
        }
        let uuid = darwin::sysctl_string(c"kern.bootsessionuuid")?;
        // Ignore a concurrent initializer winning the race; both wrote the same
        // value.
        let _ = self.boot_id.set(uuid.into_bytes());
        Ok(())
    }

    /// Register a CoW-eligible memory region backed by a file.
    ///
    /// `data` must be a slice that was `mmap`'d in from `file_path` (typically
    /// by the initial file system's static-backing-data loader). Once
    /// registered, [`litebox::platform::PageManagementProvider::try_allocate_cow_pages`]
    /// can remap any sub-slice of `data` into the guest's address space by
    /// re-`mmap`ing the same file region `MAP_PRIVATE`, instead of allocating
    /// fresh pages and copying `data` into them.
    ///
    /// # Panics
    ///
    /// Panics if an overlapping region is already registered.
    pub fn register_cow_region(
        &self,
        data: &'static [u8],
        file_path: impl Into<std::path::PathBuf>,
    ) {
        let start = data.as_ptr() as usize;
        let info = CowRegionInfo {
            file_path: file_path.into(),
            file_length: data.len(),
        };
        let mut regions = self.cow_regions.write().unwrap();
        assert!(
            regions.range(start..start + data.len()).next().is_none(),
            "attempting to register an overlapping CoW region"
        );
        let old = regions.insert(start, info);
        assert!(old.is_none());
    }

    /// Looks up the file backing a static slice for CoW mapping.
    ///
    /// Returns `Some((file_path, offset_in_file))` if `source_data` falls
    /// entirely within a registered region, `None` otherwise.
    fn lookup_cow_region(&self, source_data: &'static [u8]) -> Option<(std::path::PathBuf, usize)> {
        let slice_start = source_data.as_ptr() as usize;
        let slice_end = slice_start.checked_add(source_data.len())?;

        let regions = self.cow_regions.read().unwrap();
        let (&region_start, info) = regions.range(..=slice_start).next_back()?;
        let region_end = region_start.checked_add(info.file_length)?;

        (slice_start >= region_start && slice_end <= region_end)
            .then(|| (info.file_path.clone(), slice_start - region_start))
    }

    /// The task parameters a runner should start the initial guest thread with.
    pub fn init_task(&self) -> litebox_common_linux::TaskParams {
        // TODO: these are synthetic, matching the other userland platforms.
        // Passing the host's real identity through is a separate decision about
        // what the guest is allowed to observe.
        litebox_common_linux::TaskParams {
            pid: 1000,
            ppid: 0,
            uid: 1000,
            gid: 1000,
            euid: 1000,
            egid: 1000,
        }
    }
}

impl litebox::platform::Provider for MacOsUserland {}

// ---------------------------------------------------------------------------
// Memory
// ---------------------------------------------------------------------------

/// Translate LiteBox permissions into Darwin `PROT_*` bits.
fn prot_flags(permissions: MemoryRegionPermissions) -> libc::c_int {
    let mut prot = libc::PROT_NONE;
    if permissions.contains(MemoryRegionPermissions::READ) {
        prot |= libc::PROT_READ;
    }
    if permissions.contains(MemoryRegionPermissions::WRITE) {
        prot |= libc::PROT_WRITE;
    }
    if permissions.contains(MemoryRegionPermissions::EXEC) {
        prot |= libc::PROT_EXEC;
    }
    prot
}

/// Whether a mapping with these permissions needs `MAP_JIT`.
///
/// Darwin refuses to make anonymous memory executable through the ordinary
/// path, and refuses to add `PROT_EXEC` to anything that was ever writable.
/// `MAP_JIT` is the supported way to get an executable mapping the process can
/// also write to, at the cost of an entitlement and of having to bracket writes
/// with [`jit_write_protect`].
fn needs_jit(permissions: MemoryRegionPermissions) -> bool {
    permissions.contains(MemoryRegionPermissions::EXEC)
}

/// Registry of live `MAP_JIT` region bounds, read from [`fault_handler`] to
/// implement fault-driven W^X toggling for a guest that writes its own code
/// (a JIT engine like V8).
///
/// Darwin makes a `MAP_JIT` mapping writable *or* executable per thread, never
/// both -- switched by [`jit_write_protect`]. LiteBox brackets its *own* writes
/// into guest code, but a guest JIT writes machine code into its code range
/// with plain stores and then jumps to it, never calling
/// `pthread_jit_write_protect_np`, because on a real Linux host that memory is
/// simply RWX. Under this host the guest's store faults (page is
/// execute-only for the thread) and its jump-to-freshly-written-code faults
/// (page is writable-only). [`fault_handler`] resolves both transparently:
/// a write fault at a JIT address toggles the thread to writable, an
/// instruction abort at a JIT address toggles it back to executable, and the
/// faulting instruction re-runs. No guest signal is delivered.
///
/// The registry is a small fixed array of `(start, end)` atomic pairs so it
/// can be scanned from inside the signal handler without a lock or allocation
/// (both async-signal-unsafe). V8 uses a single large code range plus a
/// handful of small ranges, so the capacity is generous; an overflow is
/// logged once and simply means faults in the overflow region are delivered
/// to the guest as before (correct, just un-toggled).
const JIT_REGISTRY_CAP: usize = 64;

/// Everything [`fault_handler`] consults to service a JIT-related or
/// `CTR_EL0` trap, folded into one static: a POSIX signal handler receives no
/// user-data pointer and may not lock, allocate, or touch TLS, so this state
/// must be static-reachable, and it is process-wide (V8 threads execute code
/// other threads wrote), so per-thread `GuestThreadState` is the wrong home.
/// Fields rather than separate `static`s, so the scaffolding costs exactly
/// one global (the `PROBE_ALLOCATOR` accounting; see `dev_tests`' ratchet).
struct JitFaultGlobals {
    /// Live `MAP_JIT` `(start, end)` bounds; `start == 0` marks a free slot.
    regions: [(AtomicUsize, AtomicUsize); JIT_REGISTRY_CAP],
    /// Warn-once flag for registry overflow.
    registry_overflowed: AtomicBool,
    /// The synthetic `CTR_EL0` served to a guest `mrs Xt, CTR_EL0`; computed
    /// once by [`init_synthetic_ctr_el0`].
    synthetic_ctr_el0: AtomicU64,
}
static JIT_FAULT: JitFaultGlobals = JitFaultGlobals {
    regions: [const { (AtomicUsize::new(0), AtomicUsize::new(0)) }; JIT_REGISTRY_CAP],
    registry_overflowed: AtomicBool::new(false),
    synthetic_ctr_el0: AtomicU64::new(0),
};

/// Records `[start, start+len)` as a `MAP_JIT` region for the fault handler.
fn register_jit_region(start: usize, len: usize) {
    let end = start + len;
    for (s, e) in &JIT_FAULT.regions {
        // Claim a free slot (start == 0) atomically. `Relaxed` is enough: the
        // only reader is this process's own signal handler, always on a thread
        // that is strictly later than the `mmap`/`mprotect` that produced the
        // region, so the store is already visible by the time any fault in it
        // can occur.
        if s.compare_exchange(0, start, Ordering::AcqRel, Ordering::Relaxed)
            .is_ok()
        {
            e.store(end, Ordering::Release);
            return;
        }
    }
    if !JIT_FAULT.registry_overflowed.swap(true, Ordering::Relaxed) {
        litebox_util_log::warn!(
            cap:? = JIT_REGISTRY_CAP;
            "MAP_JIT region registry full; further JIT regions will not get \
             fault-driven write-protect toggling (guest self-modifying code in \
             them will fault to the guest instead of resuming transparently)"
        );
    }
}

/// Whether `addr` falls in any registered `MAP_JIT` region. Async-signal-safe:
/// plain atomic loads, no lock or allocation.
fn addr_in_jit_region(addr: usize) -> bool {
    for (s, e) in &JIT_FAULT.regions {
        let start = s.load(Ordering::Acquire);
        if start != 0 && addr >= start && addr < e.load(Ordering::Acquire) {
            return true;
        }
    }
    false
}

/// Drops any registered `MAP_JIT` region that overlaps `[start, start+len)`,
/// so an address the guest has unmapped and the kernel may later hand back for
/// something else cannot keep matching in [`fault_handler`]. Called from
/// `deallocate_pages`.
fn unregister_jit_region(start: usize, len: usize) {
    let end = start + len;
    for (s, e) in &JIT_FAULT.regions {
        let rs = s.load(Ordering::Acquire);
        if rs != 0 && rs < end && start < e.load(Ordering::Acquire) {
            // Free the slot. `start`-first: a concurrent reader either sees the
            // old (still-valid, about-to-be-freed) bounds or a zeroed start it
            // skips -- never a torn half-updated pair it would treat as live.
            s.store(0, Ordering::Release);
            e.store(0, Ordering::Release);
        }
    }
}

/// Enable or disable write access to this thread's `MAP_JIT` mappings.
///
/// Darwin makes `MAP_JIT` memory writable *or* executable per thread, never
/// both at once. Pass `false` to write to a JIT mapping and `true` to execute
/// from it again. This must bracket every write LiteBox makes into guest code
/// pages -- loading segments, and applying the rewriter's patches.
///
/// # Safety
///
/// Toggling write protection off makes every `MAP_JIT` mapping in the process
/// writable and non-executable for this thread, so no code may be executed out
/// of a JIT mapping until protection is restored.
pub unsafe fn jit_write_protect(executable: bool) {
    // SAFETY: the call has no preconditions beyond the ones the caller of this
    // function is documented to uphold.
    unsafe { darwin::pthread_jit_write_protect_np(libc::c_int::from(executable)) }
}

/// Mirrors `<MacOsUserland as PageManagementProvider<ALIGN>>::TASK_ADDR_MIN`
/// (the trait impl's associated const is defined in terms of this, not the
/// other way around) so free functions outside that `impl` block --
/// `allocate_jit_pages`'s and `try_allocate_cow_pages`'s `Hint`-correction
/// bounds checks -- can see it without a `Self` to qualify through (`Self`
/// would need `ALIGN` pinned to a concrete value, which these call sites
/// have no reason to do). The value genuinely does not depend on `ALIGN`, so
/// one constant correctly serves both the associated const and these.
///
/// Set to 1 TiB, not the 4 GiB `__PAGEZERO` floor alone, to keep this whole
/// process's *own* heap and thread stacks out of the guest's claimed range --
/// they are not disjoint by default. `reserved_pages` (this platform's
/// `PageManagementProvider::reserved_pages`) is a one-time startup snapshot
/// of `read_memory_maps()`; it protects a *guest* allocation from landing on
/// memory the host already had mapped at that instant, but has no visibility
/// into allocations the host's own global allocator makes *later*, while a
/// guest is already running. Measured directly on this host: 200,000 ordinary
/// heap allocations and 50 real `std::thread::spawn` stacks landed at
/// addresses from ~4 GiB up to ~39 GiB, 100% inside the old `[4 GiB, 64 TiB)`
/// range -- unsurprising, since 4 GiB is approximately where an ordinary
/// 64-bit process's own heap begins, immediately adjacent to where the guest
/// was also claiming its very first pages. A long-running guest (Node's own
/// startup alone touches this host's tracing/logging/syscall-dispatch code
/// hundreds of times) gives this collision window a great deal of time to
/// find a `malloc` or thread stack landing exactly where the guest's own
/// memory already lives, or will next expand into -- a real, demonstrated
/// risk this closes on its own merits. It was tested directly as a candidate
/// cause of the further-crash investigation in `docs/roadmap.md` and ruled
/// out there (the crash reproduces byte-for-byte identically with this fix
/// in place), so it is not, in the end, that bug -- but the collision window
/// itself was real regardless of that specific crash, and closing it is not
/// contingent on explaining it. 1 TiB is roughly 25x the worst address
/// measured, on top of the existing 64 TiB ceiling leaving 63 TiB of guest
/// headroom -- both numbers with wide margin, not tuned to just barely clear
/// what was measured.
const GUEST_ADDR_MIN: usize = 0x0100_0000_0000;
/// See [`GUEST_ADDR_MIN`]; mirrors `TASK_ADDR_MAX` the same way.
const GUEST_ADDR_MAX: usize = 0x0000_4000_0000_0000;

/// Allocate a `MAP_JIT` mapping, honoring `fixed_address_behavior` despite
/// Darwin refusing to combine `MAP_FIXED` with `MAP_JIT` in one `mmap` call.
///
/// For a [`FixedAddressBehavior::Hint`] request, `suggested_range.start` is
/// offered to `mmap` as an advisory address -- mirroring what
/// `MacOsUserland::allocate_pages`'s non-JIT `Hint` branch does -- so Darwin
/// gets a real chance to place the mapping there directly instead of this
/// function relying solely on the correction below. `Replace`/`NoReplace`
/// instead always request a kernel-chosen address here: both finish with an
/// exact `reserve_fixed`+[`darwin::remap_to_fixed`] pass a few lines down, and
/// if the hint got honored in this initial call, that reservation would
/// collide with the very mapping this call just created at the same address.
///
/// Whatever address the kernel actually returns is the answer -- *unless* it
/// falls outside `[TASK_ADDR_MIN, TASK_ADDR_MAX)` for a `Hint` request, in
/// which case it is relocated to `suggested_range.start` with
/// [`darwin::remap_to_fixed`] the same way `NoReplace` always is. See the
/// matching comment in `allocate_pages`'s non-JIT branch for why `Hint` needs
/// this correction (real Darwin does not reliably honor an advisory hint near
/// the top of the guest's address range) and why it is applied only when the
/// kernel-chosen address is actually out of range rather than
/// unconditionally.
fn allocate_jit_pages(
    suggested_range: &core::ops::Range<usize>,
    initial_permissions: MemoryRegionPermissions,
    fixed_address_behavior: FixedAddressBehavior,
) -> Result<*mut libc::c_void, AllocationError> {
    // Only `Hint` may offer the suggested address as a hint here -- see this
    // function's doc comment for why `Replace`/`NoReplace` must not.
    let hint = if fixed_address_behavior == FixedAddressBehavior::Hint {
        suggested_range.start as *mut libc::c_void
    } else {
        core::ptr::null_mut()
    };
    // SAFETY: `MAP_JIT` cannot be combined with `MAP_FIXED`, so `hint` is only
    // ever advisory -- Darwin remains free to place the mapping elsewhere --
    // and there is no caller-owned range to validate here beyond what `mmap`
    // itself checks.
    let kernel_chosen = unsafe {
        libc::mmap(
            hint,
            suggested_range.len(),
            prot_flags(initial_permissions),
            libc::MAP_PRIVATE | libc::MAP_ANON | MAP_JIT,
            -1,
            0,
        )
    };
    if kernel_chosen == libc::MAP_FAILED {
        return Err(match std::io::Error::last_os_error().raw_os_error() {
            Some(libc::EINVAL) => AllocationError::Unaligned,
            _ => AllocationError::OutOfMemory,
        });
    }

    let must_reserve = fixed_address_behavior == FixedAddressBehavior::NoReplace;
    let needs_correction = fixed_address_behavior == FixedAddressBehavior::Hint && {
        let start = kernel_chosen as usize;
        let end = start + suggested_range.len();
        start < GUEST_ADDR_MIN || end > GUEST_ADDR_MAX
    };
    let fixed_mode_requires_remap = fixed_address_behavior != FixedAddressBehavior::Hint;
    let reserved = if must_reserve || needs_correction {
        // `remap_to_fixed`'s `VM_FLAGS_OVERWRITE` silently replaces whatever
        // already occupies the destination, so `NoReplace` has to check
        // first -- exactly like the non-JIT path does with a plain
        // `mmap(MAP_FIXED)`. The reservation itself then occupies the
        // destination until the remap overwrites it.
        match reserve_fixed(suggested_range) {
            Ok(()) => true,
            Err(e) if must_reserve => {
                // SAFETY: `kernel_chosen` is the mapping just created above,
                // still solely owned by this function.
                unsafe { libc::munmap(kernel_chosen, suggested_range.len()) };
                return Err(match e {
                    ReservationError::AddressInUse => AllocationError::AddressInUse,
                    ReservationError::OutOfMemory => AllocationError::OutOfMemory,
                });
            }
            Err(e) => {
                unsafe { libc::munmap(kernel_chosen, suggested_range.len()) };
                return Err(match e {
                    ReservationError::AddressInUse => AllocationError::AddressInUse,
                    ReservationError::OutOfMemory => AllocationError::OutOfMemory,
                });
            }
        }
    } else {
        false
    };
    let must_remap = fixed_mode_requires_remap || reserved;

    if !must_remap {
        return Ok(kernel_chosen);
    }

    // SAFETY: `kernel_chosen` is a live mapping of exactly this length,
    // created above and not otherwise in use yet.
    let remap_result = unsafe {
        remap_to_fixed(
            kernel_chosen as usize,
            suggested_range.len(),
            suggested_range.start,
        )
    };

    // `remap_to_fixed` COW-duplicates rather than aliases: `kernel_chosen` is
    // still a live, now-redundant mapping of its own after a successful remap,
    // and a pointless one after a failed one either way. Drop it now so it
    // never leaks; the destination is an independent copy and is unaffected.
    // SAFETY: `kernel_chosen` is still a valid mapping owned by this function.
    unsafe { libc::munmap(kernel_chosen, suggested_range.len()) };

    match remap_result {
        Ok(()) => Ok(suggested_range.start as *mut libc::c_void),
        Err(e) => {
            if reserved {
                release_reservation(suggested_range);
            }
            Err(match e {
                ReservationError::AddressInUse => AllocationError::AddressInUse,
                ReservationError::OutOfMemory => AllocationError::OutOfMemory,
            })
        }
    }
}

/// `allocate_jit_pages`'s `Hint` branch has to actually offer
/// `suggested_range.start` to `mmap`, not silently discard it for a
/// kernel-chosen address (`macos-allocate-jit-pages-hint-discarded`).
///
/// A single free candidate cannot distinguish "the hint was honored" from
/// "the kernel's own unhinted choice happened to coincide with it": on this
/// hardware a bare `mmap(NULL, ...)` deterministically reuses the
/// most-recently-freed address of matching size, so a naive probe-then-free
/// address would come back from an unhinted call too, passing regardless of
/// whether the fix is present. Instead this creates two disjoint free
/// candidates, `low` and `high` (kept apart by `spacer`, still mapped, so
/// their free regions cannot coalesce), and confirms first that an unhinted
/// `mmap` of this size lands at `low` -- the kernel's natural choice -- never
/// `high`. Requesting `high` as the `Hint` must then still land exactly at
/// `high`, which is only possible if the hint was actually passed through.
#[cfg(test)]
#[test]
fn allocate_jit_pages_hint_honors_the_suggested_address() {
    const MAX_ATTEMPTS: u32 = 25;

    // This test's core guarantee -- `low`/`high` stay free across several
    // mmap/munmap round trips -- cannot be made airtight against every
    // possible source of host address-space churn: Rust's own parallel test
    // harness spawns and joins OS threads for other, unrelated tests the
    // whole time this one runs, and each thread needs a real mmap'd stack
    // from libSystem/pthread internals that this crate's own code has no way
    // to serialize against. Serializing against this crate's OWN
    // mmap/munmap-doing tests (via `TEST_SERIAL`, shared with `guest::tests`
    // and `with_signal_alt_stack_actually_registers_one`) closes the sources
    // this crate controls, but not the harness's own thread churn -- so
    // instead of a single-shot assertion, this retries: a mismatch is only
    // treated as a real bug if it reproduces across every attempt, since a
    // genuine regression (the hint never being passed through) would fail
    // every attempt identically, while a harness-thread race would not.
    let _serial = guest::tests::TEST_SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);

    let len = litebox::mm::vmem::PAGE_SIZE;

    // SAFETY: each anonymous mapping with no fixed-address request has no
    // precondition beyond what `mmap` itself checks.
    //
    // Hinted at `GUEST_ADDR_MIN`, not `NULL`: this probe needs a free
    // candidate *inside* the guest range to exercise anything, but an
    // unhinted `mmap(NULL, ...)` no longer reliably lands there by chance --
    // that range was deliberately widened away from where the host's own
    // ordinary allocations land (see `GUEST_ADDR_MIN`'s own doc comment).
    // The hint is still only advisory, so this remains a real probe of
    // wherever the kernel actually places it, not an assumption; the
    // in-range check below still gates every attempt on that.
    let mmap_anon = || unsafe {
        libc::mmap(
            GUEST_ADDR_MIN as *mut libc::c_void,
            len,
            libc::PROT_NONE,
            libc::MAP_PRIVATE | libc::MAP_ANON,
            -1,
            0,
        )
    };

    let mut last_inconclusive_reason = String::new();

    for attempt in 0..MAX_ATTEMPTS {
        let low = mmap_anon();
        let spacer = mmap_anon();
        let high = mmap_anon();
        assert_ne!(low, libc::MAP_FAILED, "low probe mmap failed");
        assert_ne!(spacer, libc::MAP_FAILED, "spacer probe mmap failed");
        assert_ne!(high, libc::MAP_FAILED, "high probe mmap failed");

        // SAFETY: `low`/`high` are the mappings just created above, still
        // solely owned here, and each is freed exactly once; `spacer` stays
        // mapped for the rest of this attempt so `low`'s and `high`'s
        // now-free regions stay disjoint instead of coalescing into one.
        unsafe {
            libc::munmap(low, len);
            libc::munmap(high, len);
        }

        let low = low as usize;
        let high = high as usize;

        // SAFETY: `spacer` is the mapping created above, unmapped exactly
        // once on every exit path from this closure.
        let free_spacer = || unsafe {
            libc::munmap(spacer, len);
        };

        if !((GUEST_ADDR_MIN..GUEST_ADDR_MAX).contains(&low)
            && (GUEST_ADDR_MIN..GUEST_ADDR_MAX).contains(&high))
        {
            last_inconclusive_reason = format!(
                "attempt {attempt}: probe addresses low={low:#x} high={high:#x} fell \
                 outside the guest range, so this attempt could not exercise the \
                 ordinary (non-correction) Hint path"
            );
            free_spacer();
            continue;
        }

        // Confirm the kernel's natural, unhinted choice really is `low`, not
        // `high` -- otherwise the check below would not actually
        // discriminate a passed-through hint from coincidence.
        let natural = mmap_anon();
        if natural as usize != low {
            last_inconclusive_reason = format!(
                "attempt {attempt}: an unhinted mmap landed at {:#x}, not the lower \
                 free candidate low={low:#x} -- something else raced this attempt's \
                 free window, so it cannot tell a passed-through hint from a lucky \
                 coincidence",
                natural as usize
            );
            // SAFETY: `natural` is the mapping just created above, still
            // solely owned here.
            unsafe { libc::munmap(natural, len) };
            free_spacer();
            continue;
        }
        // SAFETY: `natural` is the mapping just created above, still solely
        // owned here.
        unsafe { libc::munmap(natural, len) };

        let suggested_range = high..high + len;
        let result = allocate_jit_pages(
            &suggested_range,
            MemoryRegionPermissions::READ | MemoryRegionPermissions::WRITE,
            FixedAddressBehavior::Hint,
        );
        let ptr = result.expect("allocate_jit_pages should succeed for a free, in-range hint");

        if ptr as usize == high {
            // SAFETY: `ptr` is the mapping just created above, still solely
            // owned here, unmapped exactly once.
            unsafe { libc::munmap(ptr, len) };
            free_spacer();
            return;
        }

        last_inconclusive_reason = format!(
            "attempt {attempt}: Hint placed the MAP_JIT mapping at {:#x} instead of \
             the caller's suggested address high={high:#x} -- either the hint was \
             silently discarded, or something else raced `high` free between the \
             precondition check above and this call",
            ptr as usize
        );
        // SAFETY: `ptr` is the mapping just created above, still solely
        // owned here, unmapped exactly once.
        unsafe { libc::munmap(ptr, len) };
        free_spacer();
    }

    panic!(
        "allocate_jit_pages did not honor the suggested Hint address in any of \
         {MAX_ATTEMPTS} attempts -- this many consecutive misses is not \
         explainable by test-harness thread-stack races alone, and points at a \
         real regression. Last attempt's reason: {last_inconclusive_reason}"
    );
}

/// Move `range`'s contents onto a fresh `MAP_JIT` mapping so the range can
/// gain `PROT_EXEC`, then apply `new_permissions`.
///
/// See `update_permissions` for why this exists: `MAP_JIT`-ness is decided at
/// mapping creation, so an ordinary mapping that later needs `EXEC` has to be
/// replaced, not re-protected. The replacement preserves contents (only the
/// pages that are actually resident) and address (via `remap_to_fixed`),
/// which together make it look like the `mprotect` simply succeeded.
///
/// Two properties make this cheap even for V8's 256 MiB code-range promotion,
/// which is a single `mprotect(->EXEC)` over a `PROT_NONE`/`MAP_NORESERVE`
/// reservation:
///
/// * **Only resident pages are copied.** An empty reservation has none, so
///   the copy is skipped entirely -- no 256 MiB `memcpy`, no forced commit.
///   A real RW-then-RX code page (the common per-method JIT transition, and
///   the loader's own segment flip) copies exactly its committed bytes.
/// * **The remap is copy-on-write** (`remap_to_fixed` uses `copy=TRUE`; see
///   its doc for why `copy=FALSE` is impossible for a `MAP_JIT` source), so
///   even the fresh JIT reservation and its placement at `range.start` stay
///   lazy until the guest touches a page.
///
/// On failure the range may be left readable-only rather than with its
/// original permissions -- the original protection is not known here, and
/// every failure below is one the caller treats as the mapping being gone.
///
/// # Safety
///
/// As for `update_permissions`: the caller guarantees `range` is a live
/// mapping whose contents are not concurrently in use, and that the
/// permission change does not conflict with any active use.
unsafe fn migrate_range_to_jit(
    range: &core::ops::Range<usize>,
    new_permissions: MemoryRegionPermissions,
) -> Result<(), PermissionUpdateError> {
    // Any resident contents have to be readable to copy out. The caller asked
    // for this range's permissions to change anyway, so a temporary read-only
    // view is within its guarantee. (Also makes the `mincore` residency read
    // below well-defined for a range that was `PROT_NONE`.)
    // SAFETY: forwarded caller guarantee, per this function's safety doc.
    let rc = unsafe {
        libc::mprotect(
            range.start as *mut libc::c_void,
            range.len(),
            libc::PROT_READ,
        )
    };
    if rc != 0 {
        return Err(PermissionUpdateError::Unallocated);
    }

    // A fresh JIT reservation of the same size. RWX-tagged; the per-thread
    // write-protect (`jit_write_protect`) decides which of write/execute is
    // live. Untouched pages cost nothing until written.
    // SAFETY: an anonymous mapping at a kernel-chosen address has nothing to
    // validate beyond what `mmap` itself checks.
    let jit = unsafe {
        libc::mmap(
            core::ptr::null_mut(),
            range.len(),
            libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
            libc::MAP_PRIVATE | libc::MAP_ANON | MAP_JIT,
            -1,
            0,
        )
    };
    if jit == libc::MAP_FAILED {
        return Err(PermissionUpdateError::Unallocated);
    }

    // Copy only the pages that are actually resident in the source. For an
    // empty reservation this loop finds nothing and does no work at all;
    // for a written code page it transfers exactly the live bytes.
    // SAFETY: `sysconf(_SC_PAGESIZE)` takes no arguments and cannot fault.
    let page = {
        let p = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        // `_SC_PAGESIZE` is always a positive power of two on this platform;
        // fall back to Apple Silicon's 16 KiB if the query ever fails.
        usize::try_from(p).ok().filter(|&p| p > 0).unwrap_or(16384)
    };
    let n_pages = range.len().div_ceil(page);
    let mut resident = alloc::vec![0u8; n_pages];
    // SAFETY: `range` is readable (mprotect above) and `resident` is sized to
    // one byte per page of it.
    let mincore_rc = unsafe {
        libc::mincore(
            range.start as *mut libc::c_void,
            range.len(),
            resident.as_mut_ptr().cast::<libc::c_char>(),
        )
    };
    // A `mincore` failure is not fatal -- fall back to treating every page as
    // resident (copy all), which is merely slower, never wrong.
    let copy_all = mincore_rc != 0;
    // SAFETY: no code is executed out of a JIT mapping between the toggles;
    // the copies below run ordinary host code.
    unsafe { jit_write_protect(false) };
    for (i, &r) in resident.iter().enumerate() {
        if copy_all || (r & 1) != 0 {
            let off = i * page;
            // SAFETY: `off + page <= range.len()`, both mappings span
            // `range.len()`, `range` is readable, `jit` is writable under the
            // toggle, and they do not overlap (`jit` is fresh pages).
            unsafe {
                core::ptr::copy_nonoverlapping(
                    (range.start + off) as *const u8,
                    jit.cast::<u8>().add(off),
                    page,
                );
            }
        }
    }
    // SAFETY: write access was only needed for the copies above.
    unsafe { jit_write_protect(true) };

    // SAFETY: `jit` is a live mapping of exactly this length that only this
    // function references.
    let remapped = unsafe { remap_to_fixed(jit as usize, range.len(), range.start) };
    // The remap COW-duplicated `jit` onto `range.start`; `jit` itself is now a
    // redundant copy (and the only copy after a failed remap). Drop it either
    // way so it never leaks; the destination is independent.
    // SAFETY: still a live mapping owned by this function.
    unsafe { libc::munmap(jit, range.len()) };
    if remapped.is_err() {
        return Err(PermissionUpdateError::Unallocated);
    }

    // No final `mprotect`. `remap_to_fixed`'s copy-on-write remap already
    // established the destination at `cur_protection = RWX` (measured), which
    // for a `MAP_JIT` mapping means "executable now, writable when this
    // thread's write-protect is toggled off" -- exactly the executable range
    // the guest asked for. Any `mprotect` on a remapped `MAP_JIT` region is
    // refused with `EPERM` (measured, for R|X and R|W|X alike), so calling one
    // here would fail a migration that has otherwise fully succeeded. The
    // guest's own code writes into this range are served by the per-thread
    // write-protect toggle: bracketed around every write LiteBox itself makes
    // into guest code, and, for a guest that writes its own code (a JIT like
    // V8), by the fault-driven toggle in `fault_handler`.
    let _ = new_permissions;

    // The bytes now executable at `range` were written through a different
    // virtual address (the `jit` mapping), so the instruction cache has no
    // reason to be coherent for them. Invalidate here rather than relying on
    // a caller: not every path that lands in `update_permissions` goes
    // through a shim-level choke point that flushes.
    // SAFETY: the range was just made executable and is mapped.
    unsafe { darwin::sys_icache_invalidate(range.start as *mut libc::c_void, range.len()) };

    // This range is now `MAP_JIT`-backed. Register it so a guest that writes
    // its own code into it (V8) gets fault-driven write-protect toggling; see
    // `register_jit_region`.
    register_jit_region(range.start, range.len());
    Ok(())
}

impl<const ALIGN: usize> litebox::platform::PageManagementProvider<ALIGN> for MacOsUserland {
    /// The first 4 GiB of an arm64 Mach-O process is the `__PAGEZERO` segment:
    /// reserved, unmapped, and impossible to map over. Every guest address has
    /// to start above it, which is a real constraint on guest images -- an
    /// `ET_EXEC` binary linked at the customary `0x400000` cannot be loaded at
    /// its preferred address on this host.
    const TASK_ADDR_MIN: usize = GUEST_ADDR_MIN;

    /// Deliberately conservative. The user half of an Apple Silicon address
    /// space is 47 bits wide, but the exact ceiling is a kernel implementation
    /// detail (`MACH_VM_MAX_ADDRESS`) rather than a stable interface, so this
    /// stops a bit below 2^46 -- 64 TiB of guest address space, comfortably
    /// inside any plausible limit.
    const TASK_ADDR_MAX: usize = GUEST_ADDR_MAX;

    fn allocate_pages(
        &self,
        suggested_range: core::ops::Range<usize>,
        initial_permissions: MemoryRegionPermissions,
        _can_grow_down: bool,
        populate_pages_immediately: bool,
        fixed_address_behavior: FixedAddressBehavior,
    ) -> Result<Self::RawMutPointer<u8>, AllocationError> {
        // `MemoryRegionPermissions::SHARED` needs no special handling here. It used to be refused
        // outright on the theory that `MAP_SHARED|MAP_ANON` on Darwin "gives a per-process object,
        // not one that survives into a child" -- measured false on real hardware (a mapping created
        // with `MAP_ANON|MAP_SHARED` *before* `fork(2)` is fully coherent with the child: a shared
        // counter incremented 100000 times by each of a parent and its child read back 200000, not
        // 100000). It is also moot for this platform's actual fork model regardless: guest processes
        // never get a second host address space to diverge from in the first place, they take turns
        // owning the one host process's single address space (see `litebox_shim_linux::syscalls::
        // process`'s address-space handoff). What makes a guest `MAP_SHARED` region behave correctly
        // across a guest `fork` is `Task::save_address_space` skipping any `VmFlags::VM_SHARED`
        // mapping when it parks a process's private memory -- bookkeeping the shim already tracks
        // from the guest's own `mmap` flags, independent of whatever flags this function passes to
        // the host `mmap`. So a `MAP_PRIVATE` host mapping is correct here today, and stays correct
        // if a future host-level fork model needs to distinguish them: nothing below this comment
        // treats `SHARED` differently already.
        if let Some(backend) = hvf_backend::active() {
            return backend
                .allocate_pages(suggested_range, initial_permissions, fixed_address_behavior)
                .map(|start| UserMutPtr::from_ptr(start as *mut u8));
        }
        if !suggested_range.start.is_multiple_of(ALIGN)
            || !suggested_range.len().is_multiple_of(ALIGN)
        {
            return Err(AllocationError::Unaligned);
        }
        let _mutation = lock_native_vm_mutation();

        let ptr = if needs_jit(initial_permissions) {
            // See `allocate_jit_pages`: `MAP_FIXED` and `MAP_JIT` cannot be
            // combined in one `mmap` call on real Darwin.
            let p = allocate_jit_pages(
                &suggested_range,
                initial_permissions,
                fixed_address_behavior,
            )?;
            // Born `MAP_JIT`; register for fault-driven write-protect toggling
            // (a guest that mmaps executable memory directly and then writes
            // its own code into it, e.g. a JIT that skips the mprotect dance).
            register_jit_region(p as usize, suggested_range.len());
            p
        } else {
            // `MAP_FIXED_NOREPLACE` has no Darwin equivalent, so claim the
            // range through the Mach VM API first: this fails with
            // `KERN_NO_SPACE` when any part of the range is already mapped,
            // which is exactly the semantics being emulated. The `mmap` below
            // then replaces the reservation in place; if it fails, the
            // reservation is released so a failed allocation never
            // permanently claims the range.
            let reserved = fixed_address_behavior == FixedAddressBehavior::NoReplace;
            if reserved {
                reserve_fixed(&suggested_range).map_err(|e| match e {
                    ReservationError::AddressInUse => AllocationError::AddressInUse,
                    ReservationError::OutOfMemory => AllocationError::OutOfMemory,
                })?;
            }

            let mut flags = libc::MAP_PRIVATE | libc::MAP_ANON;
            if fixed_address_behavior != FixedAddressBehavior::Hint {
                flags |= libc::MAP_FIXED;
            }

            // SAFETY: an anonymous mapping has no file backing to validate,
            // and `MAP_FIXED` only replaces a range the caller has told us it
            // owns.
            let ptr = unsafe {
                libc::mmap(
                    suggested_range.start as *mut libc::c_void,
                    suggested_range.len(),
                    prot_flags(initial_permissions),
                    flags,
                    -1,
                    0,
                )
            };
            if ptr == libc::MAP_FAILED {
                if reserved {
                    release_reservation(&suggested_range);
                }
                // `EINVAL` from `mmap` here means a misaligned address or
                // length, since every other argument is fixed by this
                // function. Everything else -- `ENOMEM` included -- is
                // reported as exhaustion.
                return Err(match std::io::Error::last_os_error().raw_os_error() {
                    Some(libc::EINVAL) => AllocationError::Unaligned,
                    _ => AllocationError::OutOfMemory,
                });
            }

            // `Hint`'s bare, unenforced `mmap(addr)` above is not reliable on
            // real Darwin: observed on real Apple Silicon hardware, a hint
            // near the top of the guest's address range (e.g. the initial
            // stack, hinted at `TASK_ADDR_MAX - 8 MiB`) is silently placed by
            // the kernel at an unrelated, kernel-chosen address instead
            // (consistently `TASK_ADDR_MAX`-relative but off by several
            // MiB) -- routinely landing the mapping *above* `TASK_ADDR_MAX`,
            // an invariant every other part of this platform and the shim
            // above it assumes holds. This is the confirmed mechanism behind
            // `macos-concurrent-guest-entry-sigsegv`'s intermittent real
            // guest `SIGSEGV`s (worse under concurrent host memory pressure,
            // which shifts exactly which address Darwin's own chooser picks)
            // -- the crash lands in a dynamic linker's own self-relocation
            // bootstrap, exactly the code most sensitive to its own placement
            // being wrong.
            //
            // Every caller in this tree reaches `Hint` only after
            // `Vmem::get_unmmaped_area` has already searched for and vetted
            // `suggested_range` against this process's own address-space
            // bookkeeping (see `litebox::mm::vmem::Vmem::create_mapping`,
            // whose non-fixed path always resolves a concrete candidate
            // *before* calling down here), so when the address Darwin
            // actually chose disagrees with that already-vetted candidate,
            // retrying with an exact reservation is not a reinterpretation of
            // `Hint` -- it is honoring what the caller already committed to.
            // This retry is intentionally the exception rather than the
            // default: attempting it unconditionally regressed the common
            // case instead of only fixing the broken one -- observed on the
            // same hardware, `mach_vm_allocate(VM_FLAGS_FIXED)` refuses
            // exactly `TASK_ADDR_MIN` (the address immediately above
            // `__PAGEZERO`, where the main executable's own low-address image
            // is conventionally placed) with `KERN_INVALID_ADDRESS`, and an
            // *attempted-but-refused* fixed reservation there measurably
            // perturbs Darwin's own address-hint state for the *following*
            // hint-based `mmap` (real, reproduced on this hardware: the very
            // next allocation then lands *inside* an already-live mapping
            // instead of a free gap next to it, something no other observed
            // sequence produced) -- so the exact-reservation path below only
            // ever runs when the bare attempt already provably failed, never
            // speculatively ahead of it.
            if fixed_address_behavior == FixedAddressBehavior::Hint {
                let start = ptr as usize;
                let end = start + suggested_range.len();
                if start < GUEST_ADDR_MIN || end > GUEST_ADDR_MAX {
                    // SAFETY: `ptr` is the mapping just created above, still
                    // solely owned by this function.
                    unsafe { libc::munmap(ptr, suggested_range.len()) };
                    reserve_fixed(&suggested_range).map_err(|e| match e {
                        ReservationError::AddressInUse => AllocationError::AddressInUse,
                        ReservationError::OutOfMemory => AllocationError::OutOfMemory,
                    })?;
                    // SAFETY: `reserve_fixed` just confirmed `suggested_range`
                    // is free, so `MAP_FIXED` only replaces that reservation.
                    let fixed_ptr = unsafe {
                        libc::mmap(
                            suggested_range.start as *mut libc::c_void,
                            suggested_range.len(),
                            prot_flags(initial_permissions),
                            libc::MAP_PRIVATE | libc::MAP_ANON | libc::MAP_FIXED,
                            -1,
                            0,
                        )
                    };
                    if fixed_ptr == libc::MAP_FAILED {
                        release_reservation(&suggested_range);
                        return Err(match std::io::Error::last_os_error().raw_os_error() {
                            Some(libc::EINVAL) => AllocationError::Unaligned,
                            _ => AllocationError::OutOfMemory,
                        });
                    }
                    fixed_ptr
                } else {
                    ptr
                }
            } else {
                ptr
            }
        };

        if populate_pages_immediately {
            // The closest Darwin has to `MAP_POPULATE`. It is advisory, so a
            // failure only costs later faults and is not worth reporting.
            // SAFETY: the range was just mapped.
            unsafe { libc::madvise(ptr, suggested_range.len(), libc::MADV_WILLNEED) };
        }

        Ok(UserMutPtr::from_ptr(ptr.cast::<u8>()))
    }

    fn allocate_shared_pages(
        &self,
        backing_identity: usize,
        backing_offset: usize,
        suggested_range: core::ops::Range<usize>,
        initial_permissions: MemoryRegionPermissions,
        _can_grow_down: bool,
        populate_pages_immediately: bool,
        fixed_address_behavior: FixedAddressBehavior,
    ) -> Result<Self::RawMutPointer<u8>, AllocationError> {
        if let Some(backend) = hvf_backend::active() {
            return backend
                .allocate_shared_pages(
                    backing_identity,
                    backing_offset,
                    suggested_range,
                    initial_permissions,
                    fixed_address_behavior,
                )
                .map(|start| UserMutPtr::from_ptr(start as *mut u8));
        }
        if !suggested_range.start.is_multiple_of(ALIGN)
            || !suggested_range.len().is_multiple_of(ALIGN)
            || !backing_offset.is_multiple_of(ALIGN)
        {
            return Err(AllocationError::Unaligned);
        }
        let logical_end = backing_offset
            .checked_add(suggested_range.len())
            .ok_or(AllocationError::OutOfMemory)?;
        let logical_range = backing_offset..logical_end;
        let _mutation = lock_native_vm_mutation();

        let mut registry = self.shared_page_registry.lock().unwrap();
        let extents = registry.ensure_extents(
            self.shared_page_file.as_raw_fd(),
            backing_identity,
            logical_range.clone(),
        )?;
        let mut extent_plan = Vec::new();
        extent_plan
            .try_reserve_exact(extents.len())
            .map_err(|_| AllocationError::OutOfMemory)?;
        let mut planned_end = 0usize;
        for (extent_range, file_offset) in extents {
            let relative_start = extent_range
                .start
                .checked_sub(backing_offset)
                .ok_or(AllocationError::OutOfMemory)?;
            let relative_end = extent_range
                .end
                .checked_sub(backing_offset)
                .ok_or(AllocationError::OutOfMemory)?;
            if relative_start != planned_end
                || relative_start >= relative_end
                || relative_end > suggested_range.len()
            {
                return Err(AllocationError::OutOfMemory);
            }
            let offset =
                libc::off_t::try_from(file_offset).map_err(|_| AllocationError::OutOfMemory)?;
            planned_end = relative_end;
            extent_plan.push((relative_start..relative_end, offset));
        }
        if planned_end != suggested_range.len() {
            return Err(AllocationError::OutOfMemory);
        }
        registry
            .aliases
            .try_reserve(1)
            .map_err(|_| AllocationError::OutOfMemory)?;

        // Reserve one contiguous destination first. Each sparse-file extent can then replace its
        // matching subrange with MAP_FIXED without a gap being claimed by an unrelated host mmap.
        let target_start = match fixed_address_behavior {
            FixedAddressBehavior::Hint => {
                // SAFETY: this is a temporary anonymous reservation at an advisory address.
                let reservation = unsafe {
                    libc::mmap(
                        suggested_range.start as *mut libc::c_void,
                        suggested_range.len(),
                        libc::PROT_NONE,
                        libc::MAP_PRIVATE | libc::MAP_ANON,
                        -1,
                        0,
                    )
                };
                if reservation == libc::MAP_FAILED {
                    return Err(AllocationError::OutOfMemory);
                }
                let start = reservation as usize;
                let Some(end) = start.checked_add(suggested_range.len()) else {
                    // SAFETY: `reservation` is the temporary mapping just created above.
                    unsafe { libc::munmap(reservation, suggested_range.len()) };
                    return Err(AllocationError::OutOfMemory);
                };
                if start < GUEST_ADDR_MIN || end > GUEST_ADDR_MAX {
                    // SAFETY: `reservation` is the temporary mapping just created above.
                    unsafe { libc::munmap(reservation, suggested_range.len()) };
                    reserve_fixed(&suggested_range).map_err(|error| match error {
                        ReservationError::AddressInUse => AllocationError::AddressInUse,
                        ReservationError::OutOfMemory => AllocationError::OutOfMemory,
                    })?;
                    suggested_range.start
                } else {
                    start
                }
            }
            FixedAddressBehavior::NoReplace => {
                reserve_fixed(&suggested_range).map_err(|error| match error {
                    ReservationError::AddressInUse => AllocationError::AddressInUse,
                    ReservationError::OutOfMemory => AllocationError::OutOfMemory,
                })?;
                suggested_range.start
            }
            FixedAddressBehavior::Replace => suggested_range.start,
        };
        let Some(target_end) = target_start.checked_add(suggested_range.len()) else {
            if !matches!(fixed_address_behavior, FixedAddressBehavior::Replace) {
                // SAFETY: the non-replacing paths own this complete reservation.
                unsafe { libc::munmap(target_start as *mut libc::c_void, suggested_range.len()) };
            }
            return Err(AllocationError::OutOfMemory);
        };
        let target_range = target_start..target_end;
        let owns_reservation = !matches!(fixed_address_behavior, FixedAddressBehavior::Replace);
        let mut published = false;

        for (relative_range, offset) in extent_plan {
            let virtual_start = target_start + relative_range.start;
            // SAFETY: the sparse file is live for the platform lifetime, this extent lies within
            // its ftruncate'd length, and the complete destination was reserved above (or the
            // caller explicitly requested replacement).
            let ptr = unsafe {
                libc::mmap(
                    virtual_start as *mut libc::c_void,
                    relative_range.len(),
                    prot_flags(initial_permissions),
                    libc::MAP_SHARED | libc::MAP_FIXED,
                    self.shared_page_file.as_raw_fd(),
                    offset,
                )
            };
            if ptr == libc::MAP_FAILED {
                let error = match std::io::Error::last_os_error().raw_os_error() {
                    Some(libc::EINVAL) => AllocationError::Unaligned,
                    _ => AllocationError::OutOfMemory,
                };
                if published {
                    // At least one MAP_FIXED has already replaced its destination. Returning a
                    // recoverable error would leave the caller's VMA metadata describing bytes
                    // that no longer exist, and the displaced mappings cannot be reconstructed.
                    std::process::abort();
                }
                if owns_reservation {
                    // SAFETY: no extent was installed, so this is still the complete temporary
                    // reservation owned by the non-replacing operation.
                    unsafe {
                        libc::munmap(target_range.start as *mut libc::c_void, target_range.len())
                    };
                }
                return Err(error);
            }
            if ptr as usize != virtual_start {
                std::process::abort();
            }
            published = true;
        }

        registry.forget_aliases(&target_range);
        registry.aliases.push(SharedPageAlias {
            virtual_range: target_range.clone(),
            backing_identity,
            backing_offset,
        });
        drop(registry);

        if populate_pages_immediately {
            // SAFETY: the complete destination is now mapped.
            unsafe {
                libc::madvise(
                    target_range.start as *mut libc::c_void,
                    target_range.len(),
                    libc::MADV_WILLNEED,
                )
            };
        }

        Ok(UserMutPtr::from_ptr(target_range.start as *mut u8))
    }

    fn initialize_shared_pages<E>(
        &self,
        backing_identity: usize,
        backing_offset: usize,
        length: usize,
        mut initialize: impl FnMut(core::ops::Range<usize>) -> Result<(), E>,
    ) -> Result<(), E> {
        if let Some(backend) = hvf_backend::active() {
            return backend.initialize_shared_pages(
                backing_identity,
                backing_offset,
                length,
                initialize,
            );
        }
        let requested = backing_offset
            ..backing_offset
                .checked_add(length)
                .expect("validated shared mapping range cannot overflow");
        loop {
            let mut registry = self.shared_page_registry.lock().unwrap();
            if registry
                .uninitialized_ranges(backing_identity, requested.clone())
                .is_empty()
            {
                return Ok(());
            }
            let Some(claim) = registry
                .claimable_initialization_ranges(backing_identity, requested.clone())
                .into_iter()
                .next()
            else {
                // Every missing byte is being initialized by another mapping. Wait without holding
                // the registry, then re-derive the gaps; a failed peer leaves them claimable again.
                registry = self.shared_page_init_condvar.wait(registry).unwrap();
                drop(registry);
                continue;
            };
            registry.mark_initializing(backing_identity, claim.clone());
            drop(registry);

            let relative = (claim.start - backing_offset)..(claim.end - backing_offset);
            let result = initialize(relative);

            let mut registry = self.shared_page_registry.lock().unwrap();
            registry.finish_initializing(backing_identity, &claim);
            if result.is_ok() {
                registry.mark_initialized(backing_identity, claim);
            }
            self.shared_page_init_condvar.notify_all();
            drop(registry);
            result?;
        }
    }

    fn read_shared_pages(
        &self,
        backing_identity: usize,
        backing_offset: usize,
        data: &mut [u8],
    ) -> Result<(), SharedPageIoError> {
        if let Some(backend) = hvf_backend::active() {
            return backend.read_shared_pages(backing_identity, backing_offset, data);
        }
        let end = backing_offset
            .checked_add(data.len())
            .ok_or(SharedPageIoError::OutOfRange)?;
        let requested = backing_offset..end;
        let mut registry = self.shared_page_registry.lock().unwrap();
        while registry.initialization_in_progress(backing_identity, &requested) {
            registry = self.shared_page_init_condvar.wait(registry).unwrap();
        }
        let initialized = registry
            .initialized
            .get(&backing_identity)
            .cloned()
            .unwrap_or_default();
        let extents = registry.existing_extents(backing_identity, &requested);
        for (extent, file_offset) in extents {
            for initialized_range in &initialized {
                let start = extent.start.max(initialized_range.start);
                let end = extent.end.min(initialized_range.end);
                if start >= end {
                    continue;
                }
                let output_start = start - backing_offset;
                let physical_start = file_offset + (start - extent.start);
                pread_all(
                    self.shared_page_file.as_raw_fd(),
                    &mut data[output_start..output_start + (end - start)],
                    physical_start,
                )?;
            }
        }
        Ok(())
    }

    fn write_shared_pages(
        &self,
        backing_identity: usize,
        backing_offset: usize,
        data: &[u8],
    ) -> Result<(), SharedPageIoError> {
        if let Some(backend) = hvf_backend::active() {
            return backend.write_shared_pages(backing_identity, backing_offset, data);
        }
        let end = backing_offset
            .checked_add(data.len())
            .ok_or(SharedPageIoError::OutOfRange)?;
        let requested = backing_offset..end;
        let mut registry = self.shared_page_registry.lock().unwrap();
        while registry.initialization_in_progress(backing_identity, &requested) {
            registry = self.shared_page_init_condvar.wait(registry).unwrap();
        }
        let extents = registry.existing_extents(backing_identity, &requested);
        for (extent, file_offset) in extents {
            let input_start = extent.start - backing_offset;
            pwrite_all(
                self.shared_page_file.as_raw_fd(),
                &data[input_start..input_start + extent.len()],
                file_offset,
            )?;
            registry.mark_initialized(backing_identity, extent);
        }
        Ok(())
    }

    fn zero_shared_pages(
        &self,
        backing_identity: usize,
        backing_range: core::ops::Range<usize>,
    ) -> Result<(), SharedPageIoError> {
        if let Some(backend) = hvf_backend::active() {
            return backend.zero_shared_pages(backing_identity, backing_range);
        }
        if backing_range.is_empty() {
            return Ok(());
        }
        let mut registry = self.shared_page_registry.lock().unwrap();
        while registry.initialization_in_progress(backing_identity, &backing_range) {
            registry = self.shared_page_init_condvar.wait(registry).unwrap();
        }
        let extents = registry.existing_extents(backing_identity, &backing_range);
        let zeroes = [0u8; 16384];
        for (extent, file_offset) in extents {
            let mut written = 0;
            while written < extent.len() {
                let count = (extent.len() - written).min(zeroes.len());
                pwrite_all(
                    self.shared_page_file.as_raw_fd(),
                    &zeroes[..count],
                    file_offset + written,
                )?;
                written += count;
            }
            registry.mark_initialized(backing_identity, extent);
        }
        Ok(())
    }

    unsafe fn remap_shared_pages(
        &self,
        backing_identity: usize,
        backing_offset: usize,
        old_range: core::ops::Range<usize>,
        new_range: core::ops::Range<usize>,
        permissions: MemoryRegionPermissions,
    ) -> Result<Self::RawMutPointer<u8>, RemapError> {
        if let Some(backend) = hvf_backend::active() {
            return backend
                .remap_shared_pages(
                    backing_identity,
                    backing_offset,
                    old_range,
                    new_range,
                    permissions,
                )
                .map(|start| UserMutPtr::from_ptr(start as *mut u8));
        }
        if !old_range.start.is_multiple_of(ALIGN)
            || !old_range.len().is_multiple_of(ALIGN)
            || !new_range.start.is_multiple_of(ALIGN)
            || !new_range.len().is_multiple_of(ALIGN)
            || !backing_offset.is_multiple_of(ALIGN)
        {
            return Err(RemapError::Unaligned);
        }
        if old_range.start.max(new_range.start) < old_range.end.min(new_range.end) {
            return Err(RemapError::Overlapping);
        }
        if new_range.len() < old_range.len() {
            return Err(RemapError::OutOfMemory);
        }

        let new_ptr =
            <Self as litebox::platform::PageManagementProvider<ALIGN>>::allocate_shared_pages(
                self,
                backing_identity,
                backing_offset,
                new_range.clone(),
                permissions,
                false,
                true,
                FixedAddressBehavior::NoReplace,
            )
            .map_err(|error| match error {
                AllocationError::AddressInUse | AllocationError::AddressInUseByPlatform => {
                    RemapError::AlreadyAllocated
                }
                AllocationError::Unaligned => RemapError::Unaligned,
                // `OutOfMemory`, and a destination below/above the task range or partially
                // in use.
                _ => RemapError::OutOfMemory,
            })?;

        // The destination already aliases the same physical bytes, so no copy is required.
        // SAFETY: forwarded caller guarantee; the source is no longer needed after this move.
        if unsafe {
            <Self as litebox::platform::PageManagementProvider<ALIGN>>::deallocate_pages(
                self, old_range,
            )
        }
        .is_err()
        {
            // SAFETY: `new_range` was allocated solely by this operation and has not escaped.
            let _ = unsafe {
                <Self as litebox::platform::PageManagementProvider<ALIGN>>::deallocate_pages(
                    self, new_range,
                )
            };
            return Err(RemapError::AlreadyUnallocated);
        }
        Ok(new_ptr)
    }

    unsafe fn deallocate_pages(
        &self,
        range: core::ops::Range<usize>,
    ) -> Result<(), DeallocationError> {
        if let Some(backend) = hvf_backend::active() {
            return backend.deallocate_pages(range);
        }
        if !range.start.is_multiple_of(ALIGN) || !range.len().is_multiple_of(ALIGN) {
            return Err(DeallocationError::Unaligned);
        }
        let _mutation = lock_native_vm_mutation();
        // SAFETY: the caller guarantees the range is no longer in use.
        let rc = unsafe { libc::munmap(range.start as *mut libc::c_void, range.len()) };
        if rc == 0 {
            self.shared_page_registry
                .lock()
                .unwrap()
                .forget_aliases(&range);
            // Drop any JIT-region registration for this address so a later,
            // unrelated mapping at the same address is not mistaken for JIT by
            // the fault handler.
            unregister_jit_region(range.start, range.len());
            Ok(())
        } else {
            Err(DeallocationError::AlreadyUnallocated)
        }
    }

    fn has_transactional_permission_updates(&self) -> bool {
        // The HVF backend either changes the complete logical range or aborts
        // after any lower publication. Native Darwin mappings retain their
        // per-region path because MAP_JIT migration has backing boundaries.
        hvf_backend::active().is_some()
    }

    unsafe fn update_permissions(
        &self,
        range: core::ops::Range<usize>,
        new_permissions: MemoryRegionPermissions,
    ) -> Result<(), PermissionUpdateError> {
        if let Some(backend) = hvf_backend::active() {
            return backend.update_permissions(range, new_permissions);
        }
        if !range.start.is_multiple_of(ALIGN) || !range.len().is_multiple_of(ALIGN) {
            return Err(PermissionUpdateError::Unaligned);
        }
        let _mutation = lock_native_vm_mutation();
        // SAFETY: the caller guarantees the new permissions do not conflict with
        // any active use of the range.
        let rc = unsafe {
            libc::mprotect(
                range.start as *mut libc::c_void,
                range.len(),
                prot_flags(new_permissions),
            )
        };
        if rc == 0 {
            return Ok(());
        }
        if new_permissions.contains(MemoryRegionPermissions::EXEC) {
            // Adding `PROT_EXEC` to an ordinary mapping is exactly the case
            // Darwin's W^X policy refuses: only a `MAP_JIT` mapping may become
            // executable, and `MAP_JIT`-ness can only be chosen at creation.
            // Every RW-then-RX code path in LiteBox (`create_executable_pages`
            // allocates RW and flips to RX after the loader writes the bytes,
            // and a JIT-ing guest's own mmap(RW)/mprotect(RX) does the same)
            // lands here, so this is the load-bearing path for executable
            // pages on this host, not an obscure fallback.
            //
            // SAFETY: forwarded caller guarantee, as above.
            return unsafe { migrate_range_to_jit(&range, new_permissions) };
        }
        Err(PermissionUpdateError::Unallocated)
    }

    fn reserved_pages(&self) -> impl Iterator<Item = &core::ops::Range<usize>> {
        self.reserved_pages.iter()
    }

    unsafe fn jit_write_protect(&self, executable: bool) {
        // Under HVF there are no `MAP_JIT` host mappings: guest-executable
        // pages are host read-only mirrors, so there is nothing to toggle.
        if hvf_backend::active().is_some() {
            return;
        }
        // SAFETY: forwarded caller guarantee; see the trait method's docs,
        // which describe exactly this platform's `MAP_JIT` semantics.
        unsafe { darwin::pthread_jit_write_protect_np(libc::c_int::from(executable)) }
    }

    /// Maps a registered CoW region straight from its backing file via
    /// `mmap(MAP_PRIVATE)`, instead of the default (allocate-and-memcpy)
    /// behavior. Mirrors `litebox_platform_linux_userland`'s implementation of
    /// the same trait method; see [`Self::register_cow_region`] for how a
    /// region becomes eligible.
    fn try_allocate_cow_pages(
        &self,
        suggested_start: usize,
        source_data: &'static [u8],
        permissions: MemoryRegionPermissions,
        fixed_address_behavior: FixedAddressBehavior,
    ) -> Result<Self::RawMutPointer<u8>, litebox::platform::page_mgmt::CowAllocationError> {
        use litebox::platform::page_mgmt::CowAllocationError;

        if hvf_backend::active().is_some() {
            // The compact HVF manager owns every backing page; the memcpy
            // fallback path lands in it through `allocate_pages`.
            return Err(CowAllocationError::UnsupportedSourceRegion);
        }
        if permissions.contains(MemoryRegionPermissions::EXEC) {
            // A file-backed `PROT_EXEC` mapping on Apple Silicon must pass
            // code-signature validation, which an unsigned Linux guest image
            // cannot. The memcpy fallback path handles executable segments
            // instead: it allocates anonymous pages (which become `MAP_JIT`
            // when they gain `EXEC`) and copies the bytes in.
            return Err(CowAllocationError::UnsupportedSourceRegion);
        }

        let Some((file_path, file_offset)) = self.lookup_cow_region(source_data) else {
            return Err(CowAllocationError::UnsupportedSourceRegion);
        };
        if !file_offset.is_multiple_of(ALIGN) || !suggested_start.is_multiple_of(ALIGN) {
            return Err(CowAllocationError::Unaligned);
        }
        let Some(mapped_end) = suggested_start.checked_add(source_data.len()) else {
            return Err(CowAllocationError::InternalFailure);
        };
        let mapped_range = suggested_start..mapped_end;
        let _mutation = lock_native_vm_mutation();

        let reserved = fixed_address_behavior == FixedAddressBehavior::NoReplace;
        if reserved && reserve_fixed(&mapped_range).is_err() {
            return Err(CowAllocationError::InternalFailure);
        }

        let Ok(file_path_cstr) = std::ffi::CString::new(file_path.as_os_str().as_encoded_bytes())
        else {
            if reserved {
                release_reservation(&mapped_range);
            }
            return Err(CowAllocationError::InternalFailure);
        };
        // SAFETY: `file_path_cstr` is a live, NUL-terminated path.
        let fd = unsafe { libc::open(file_path_cstr.as_ptr(), libc::O_RDONLY) };
        if fd < 0 {
            if reserved {
                release_reservation(&mapped_range);
            }
            // The backing file changing out from under a running LiteBox
            // instance is not a condition normal operation can recover from --
            // matches `litebox_platform_linux_userland`'s identical assumption.
            panic!(
                "CoW-registered file should remain unchanged on host: {}",
                file_path.display()
            );
        }

        let Ok(offset) = libc::off_t::try_from(file_offset) else {
            // SAFETY: `fd` is open and not used past this point.
            unsafe { libc::close(fd) };
            if reserved {
                release_reservation(&mapped_range);
            }
            return Err(CowAllocationError::InternalFailure);
        };

        let mut flags = libc::MAP_PRIVATE;
        if fixed_address_behavior != FixedAddressBehavior::Hint {
            flags |= libc::MAP_FIXED;
        }

        // SAFETY: `fd` was just opened read-only from a path this platform
        // itself registered, and `MAP_FIXED` only replaces a range the caller
        // (or the reservation above) has claimed for this mapping.
        let ptr = unsafe {
            libc::mmap(
                suggested_start as *mut libc::c_void,
                source_data.len(),
                prot_flags(permissions),
                flags,
                fd,
                offset,
            )
        };
        if ptr == libc::MAP_FAILED {
            // SAFETY: `fd` is open and not used past this point.
            unsafe { libc::close(fd) };
            if reserved {
                release_reservation(&mapped_range);
            }
            return Err(CowAllocationError::InternalFailure);
        }

        // See the matching comment in `MacOsUserland::allocate_pages`'s
        // non-JIT branch for why a `Hint` result that landed outside the
        // guest's range gets one corrective retry at the exact candidate,
        // applied only when the bare attempt already provably produced an
        // out-of-range address (not unconditionally, and not speculatively
        // ahead of it).
        if fixed_address_behavior == FixedAddressBehavior::Hint {
            let start = ptr as usize;
            let end = start + source_data.len();
            if start < GUEST_ADDR_MIN || end > GUEST_ADDR_MAX {
                // SAFETY: `ptr` is the mapping just created above, still
                // solely owned by this function.
                unsafe { libc::munmap(ptr, source_data.len()) };
                if reserve_fixed(&mapped_range).is_err() {
                    // SAFETY: `fd` is open and not used past this point.
                    unsafe { libc::close(fd) };
                    return Err(CowAllocationError::InternalFailure);
                }
                // SAFETY: `reserve_fixed` just confirmed `mapped_range` is
                // free, `fd` is still the same read-only file opened above,
                // and `MAP_FIXED` only replaces that fresh reservation.
                let fixed_ptr = unsafe {
                    libc::mmap(
                        suggested_start as *mut libc::c_void,
                        source_data.len(),
                        prot_flags(permissions),
                        libc::MAP_PRIVATE | libc::MAP_FIXED,
                        fd,
                        offset,
                    )
                };
                // SAFETY: `fd` is open and not used past this point.
                unsafe { libc::close(fd) };
                if fixed_ptr == libc::MAP_FAILED {
                    release_reservation(&mapped_range);
                    return Err(CowAllocationError::InternalFailure);
                }
                return Ok(UserMutPtr::from_ptr(fixed_ptr.cast::<u8>()));
            }
        }
        // SAFETY: `fd` is open and not used past this point.
        unsafe { libc::close(fd) };
        Ok(UserMutPtr::from_ptr(ptr.cast::<u8>()))
    }
}

/// Enumerate the process's existing mappings so the guest is never offered an
/// address that dyld, the shared cache or the host heap already owns.
///
/// This is the Mach counterpart of the Windows platform's `VirtualQuery` walk.
fn read_memory_maps() -> alloc::vec::Vec<core::ops::Range<usize>> {
    mach_vm_region_iter().collect()
}

// ---------------------------------------------------------------------------
// Locking
// ---------------------------------------------------------------------------

impl litebox::platform::RawMutexProvider for MacOsUserland {
    type RawMutex = RawMutex;
}

/// A futex-equivalent built on Darwin's `ulock` compare-and-wait primitives.
pub struct RawMutex {
    inner: AtomicU32,
}

impl litebox::platform::RawMutex for RawMutex {
    const INIT: Self = Self {
        inner: AtomicU32::new(0),
    };

    fn underlying_atomic(&self) -> &AtomicU32 {
        &self.inner
    }

    fn wake_many(&self, n: usize) -> usize {
        if n == 0 {
            return 0;
        }
        // `ulock` can wake exactly one waiter or all of them, with nothing in
        // between, so anything above one wakes all. The trait permits this: a
        // wake is allowed to be spurious, and the return value is allowed to be
        // zero on a platform that cannot count what it woke -- which Darwin
        // cannot.
        ulock_wake(&self.inner, n > 1);
        0
    }

    fn block(&self, val: u32) -> Result<(), ImmediatelyWokenUp> {
        match self.block_inner(val, None) {
            Ok(UnblockedOrTimedOut::Unblocked) => Ok(()),
            Ok(UnblockedOrTimedOut::TimedOut) => {
                unreachable!("a wait with no deadline cannot time out")
            }
            Err(ImmediatelyWokenUp) => Err(ImmediatelyWokenUp),
        }
    }

    fn block_or_timeout(
        &self,
        val: u32,
        time: Duration,
    ) -> Result<UnblockedOrTimedOut, ImmediatelyWokenUp> {
        self.block_inner(val, Some(time))
    }
}

impl RawMutex {
    fn block_inner(
        &self,
        val: u32,
        timeout: Option<Duration>,
    ) -> Result<UnblockedOrTimedOut, ImmediatelyWokenUp> {
        match ulock_wait(&self.inner, val, timeout) {
            darwin::UlockWaitResult::Woken => Ok(UnblockedOrTimedOut::Unblocked),
            darwin::UlockWaitResult::TimedOut => Ok(UnblockedOrTimedOut::TimedOut),
            darwin::UlockWaitResult::ValueChanged => Err(ImmediatelyWokenUp),
        }
    }
}

// ---------------------------------------------------------------------------
// Time
// ---------------------------------------------------------------------------

/// A point on Darwin's monotonic clock, in nanoseconds.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Instant(u64);

impl litebox::platform::Instant for Instant {
    fn checked_duration_since(&self, earlier: &Self) -> Option<Duration> {
        self.0.checked_sub(earlier.0).map(Duration::from_nanos)
    }

    fn checked_add(&self, duration: Duration) -> Option<Self> {
        u64::try_from(duration.as_nanos())
            .ok()
            .and_then(|nanos| self.0.checked_add(nanos))
            .map(Self)
    }
}

/// A point on Darwin's wall clock, relative to the Unix epoch.
pub struct SystemTime {
    nanos_since_epoch: i128,
}

impl litebox::platform::SystemTime for SystemTime {
    const UNIX_EPOCH: Self = Self {
        nanos_since_epoch: 0,
    };

    fn duration_since(&self, earlier: &Self) -> Result<Duration, Duration> {
        let delta = self.nanos_since_epoch - earlier.nanos_since_epoch;
        let magnitude = Duration::from_nanos(delta.unsigned_abs().try_into().unwrap_or(u64::MAX));
        if delta < 0 {
            Err(magnitude)
        } else {
            Ok(magnitude)
        }
    }
}

impl litebox::platform::TimeProvider for MacOsUserland {
    type Instant = Instant;
    type SystemTime = SystemTime;

    fn now(&self) -> Self::Instant {
        // `CLOCK_MONOTONIC_RAW` is unaffected by NTP slewing or wall-clock
        // adjustment, which is all `Instant` requires: monotonic, with no
        // particular relationship to wall time. (Its exact behavior across
        // system sleep is a separate question the trait does not depend on.)
        Instant(darwin::clock_gettime_nanos(libc::CLOCK_MONOTONIC_RAW))
    }

    fn current_time(&self) -> Self::SystemTime {
        SystemTime {
            nanos_since_epoch: i128::from(darwin::clock_gettime_nanos(libc::CLOCK_REALTIME)),
        }
    }

    fn thread_cpu_time(&self) -> core::time::Duration {
        // Real per-thread CPU-time accounting from the host: Darwin's `clock_gettime` has
        // supported `CLOCK_THREAD_CPUTIME_ID` since macOS 10.12, and it genuinely stops
        // advancing while the calling thread is not scheduled on a CPU (verified: it does not
        // advance during a blocking sleep, and does advance under a busy loop).
        core::time::Duration::from_nanos(darwin::clock_gettime_nanos(libc::CLOCK_THREAD_CPUTIME_ID))
    }

    fn process_cpu_time(&self) -> core::time::Duration {
        // As above, but `CLOCK_PROCESS_CPUTIME_ID` sums CPU time across every thread of the
        // process.
        core::time::Duration::from_nanos(darwin::clock_gettime_nanos(
            libc::CLOCK_PROCESS_CPUTIME_ID,
        ))
    }
}

// ---------------------------------------------------------------------------
// Architecture-specific state
// ---------------------------------------------------------------------------

impl litebox::platform::ArchSpecificProvider for MacOsUserland {
    fn get_arch_specific_register(
        &self,
        reg: &litebox::platform::ArchSpecificRegister,
    ) -> Result<usize, litebox::platform::ArchSpecificError> {
        match reg {
            litebox::platform::ArchSpecificRegister::TpidrEl0 => {
                if hvf_backend::active().is_some() {
                    return Ok(hvf_backend::thread_tpidr_el0());
                }
                let key = guest_tp_tsd_key()
                    .ok_or(litebox::platform::ArchSpecificError::RegisterUnsupported)?;
                // SAFETY: `key` was reserved by `reserve_guest_tpidr_tsd_slot` via
                // `pthread_key_create`, which this process never invalidates; a
                // thread that never called `set_arch_specific_register` reads
                // back the `pthread_key_create`-guaranteed null default.
                Ok(unsafe { libc::pthread_getspecific(key) } as usize)
            }
            _ => Err(litebox::platform::ArchSpecificError::RegisterUnsupported),
        }
    }

    fn set_arch_specific_register(
        &self,
        reg: &litebox::platform::ArchSpecificRegister,
        val: usize,
    ) -> Result<(), litebox::platform::ArchSpecificError> {
        match reg {
            litebox::platform::ArchSpecificRegister::TpidrEl0 => {
                if hvf_backend::active().is_some() {
                    hvf_backend::set_thread_tpidr_el0(val);
                    return Ok(());
                }
                let key = guest_tp_tsd_key()
                    .ok_or(litebox::platform::ArchSpecificError::RegisterUnsupported)?;
                // This must land in the SAME pthread TSD slot the rewriter's
                // MRS/MSR gates address directly via `[TPIDRRO_EL0 + offset]`
                // (see `guest_tp_slot_byte_offset`) -- otherwise a guest thread's
                // clone(CLONE_SETTLS)-supplied thread pointer would be invisible
                // to its own later `MRS TPIDR_EL0`. No range check is needed on
                // `val`: the value never reaches a hardware register, so an
                // invalid one can only fault the guest that dereferences it.
                //
                // SAFETY: `key` was reserved by `reserve_guest_tpidr_tsd_slot`,
                // and storing an opaque `usize` as a TSD value has no
                // precondition beyond a valid key.
                let rc = unsafe { libc::pthread_setspecific(key, val as *const libc::c_void) };
                // POSIX defines only `EINVAL` for an invalid key here, which
                // `key` cannot be (it was just reserved above) -- so a nonzero
                // `rc` means host-level corruption. Every caller in this tree
                // (`litebox_shim_linux`'s execve/clone paths) already treats a
                // failure here as fatal, so propagating the error keeps that
                // boundary in one place instead of duplicating it here too.
                if rc == 0 {
                    Ok(())
                } else {
                    Err(litebox::platform::ArchSpecificError::RegisterUnsupported)
                }
            }
            _ => Err(litebox::platform::ArchSpecificError::RegisterUnsupported),
        }
    }
}

// ---------------------------------------------------------------------------
// Pointers
// ---------------------------------------------------------------------------

type UserConstPtr<T> = litebox::platform::common_providers::userspace_pointers::UserConstPtr<
    litebox::platform::common_providers::userspace_pointers::NoValidation,
    T,
>;
type UserMutPtr<T> = litebox::platform::common_providers::userspace_pointers::UserMutPtr<
    litebox::platform::common_providers::userspace_pointers::NoValidation,
    T,
>;

impl litebox::platform::RawPointerProvider for MacOsUserland {
    type RawConstPointer<T: FromBytes> = UserConstPtr<T>;
    type RawMutPointer<T: FromBytes + IntoBytes> = UserMutPtr<T>;
}

// ---------------------------------------------------------------------------
// Standard I/O
// ---------------------------------------------------------------------------

/// Spawns the single background host thread that blockingly reads the real stdin and feeds
/// [`MacOsUserland::stdin_pump`], notifying [`MacOsUserland::stdin_doorbell`] after every push or
/// EOF so `StdioProvider::read_from_stdin`'s blocking path wakes promptly instead of polling.
///
/// Spawned unconditionally in [`MacOsUserland::new`] -- real host stdin (whether an interactive
/// terminal, a pipe, or a redirected file) always needs pumping so both blocking reads and
/// non-blocking/epoll-observed reads get real data, matching how `/dev/stdin` behaves on real
/// Linux regardless of what it's actually backed by.
fn spawn_stdin_pump_thread(platform: &'static MacOsUserland) {
    std::thread::Builder::new()
        .name("litebox-stdin-pump".to_owned())
        .spawn(move || {
            let mut buf = [0u8; 4096];
            loop {
                // SAFETY: `buf` is a valid writable stack buffer for the duration of this call.
                let n = unsafe {
                    libc::read(
                        libc::STDIN_FILENO,
                        buf.as_mut_ptr().cast::<libc::c_void>(),
                        buf.len(),
                    )
                };
                if n <= 0 {
                    if n < 0
                        && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted
                    {
                        continue;
                    }
                    // EOF (n == 0) or a real error: real stdin will never produce more
                    // data. Unless another producer holds the stream open (the VNC keyboard
                    // bridge), mark EOF; either way this pump is done.
                    if !platform
                        .stdin_held_open
                        .load(core::sync::atomic::Ordering::Relaxed)
                    {
                        platform.stdin_pump.mark_eof();
                        platform.notify_stdin_doorbell();
                    }
                    break;
                }
                let mut data = &buf[..n.unsigned_abs()];
                while !data.is_empty() {
                    let pushed = platform.stdin_pump.push(data);
                    platform.notify_stdin_doorbell();
                    if pushed == 0 {
                        // Ring buffer is full because the guest hasn't drained it yet; back off
                        // briefly rather than busy-spinning until it does.
                        std::thread::sleep(Duration::from_millis(1));
                        continue;
                    }
                    data = &data[pushed..];
                }
            }
        })
        .expect("failed to spawn the stdin-pump background thread");
}

impl MacOsUserland {
    /// Deliver `bytes` to the guest's stdin as if they had been typed on the host terminal:
    /// pushed through the same pump `spawn_stdin_pump_thread` feeds, so blocking reads,
    /// non-blocking reads, and poll/select observers all see them identically. This producer is
    /// deliberately non-blocking: when the guest has stopped draining stdin and the ring is full,
    /// the complete terminal sequence is dropped rather than stalling the input-client reader or
    /// exposing a truncated escape sequence. Returns whether the bytes were accepted.
    pub fn inject_stdin(&self, bytes: &[u8]) -> bool {
        let accepted = self.stdin_pump.try_push_all(bytes);
        if accepted && !bytes.is_empty() {
            self.notify_stdin_doorbell();
        }
        accepted
    }

    /// Wakes any thread parked in `StdioProvider::read_from_stdin`'s blocking wait.
    fn notify_stdin_doorbell(&self) {
        let (lock, cvar) = &self.stdin_doorbell;
        drop(lock.lock().unwrap());
        cvar.notify_all();
    }
}

impl litebox::platform::StdioProvider for MacOsUserland {
    fn read_from_stdin(&self, buf: &mut [u8]) -> Result<usize, litebox::platform::StdioReadError> {
        loop {
            if let Some(n) = self.stdin_pump.try_read(buf) {
                return Ok(n);
            }
            // No data yet and not at EOF: park until the pump thread notifies. The bounded
            // timeout is a safety net against a lost wakeup in the (check, then wait) window
            // above, not the primary wakeup path.
            let (lock, cvar) = &self.stdin_doorbell;
            let guard = lock.lock().unwrap();
            let _ = cvar.wait_timeout(guard, Duration::from_millis(50)).unwrap();
        }
    }

    fn write_to(
        &self,
        stream: litebox::platform::StdioOutStream,
        buf: &[u8],
    ) -> Result<usize, litebox::platform::StdioWriteError> {
        let (fd, lock) = match stream {
            litebox::platform::StdioOutStream::Stdout => (libc::STDOUT_FILENO, &self.stdout_lock),
            litebox::platform::StdioOutStream::Stderr => (libc::STDERR_FILENO, &self.stderr_lock),
        };
        // Holding this for the whole (potentially multi-syscall) write below is what makes one
        // guest `write()` call atomic w.r.t. other guest threads' writes to the same stream.
        let _guard = lock.lock().unwrap();
        let mut written = 0usize;
        while written < buf.len() {
            // SAFETY: `buf[written..]` is a valid readable slice of the given length.
            let n = unsafe {
                libc::write(
                    fd,
                    buf[written..].as_ptr().cast::<libc::c_void>(),
                    buf.len() - written,
                )
            };
            if n < 0 {
                if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                if written > 0 {
                    // Real `write(2)` semantics: a short write due to a later error still
                    // reports the bytes actually written, and lets the caller retry the rest.
                    return Ok(written);
                }
                return Err(litebox::platform::StdioWriteError::Closed);
            }
            if n == 0 {
                break;
            }
            written += n.unsigned_abs();
        }
        Ok(written)
    }

    fn is_a_tty(&self, stream: litebox::platform::StdioStream) -> bool {
        self.stdio_is_tty[stream as usize]
    }

    fn stdin_pollable(&self) -> Option<&dyn litebox::event::IOPollable> {
        Some(&self.stdin_pump)
    }

    fn set_terminal_raw_mode(&self, stream: litebox::platform::StdioStream, raw: bool, echo: bool) {
        self.set_terminal_raw_mode_with_action(
            stream,
            raw,
            echo,
            litebox::platform::TerminalSetAction::Now,
        );
    }

    fn set_terminal_raw_mode_with_action(
        &self,
        stream: litebox::platform::StdioStream,
        raw: bool,
        echo: bool,
        action: litebox::platform::TerminalSetAction,
    ) {
        // Only stdin's line discipline affects how input bytes arrive at the pump thread.
        if stream != litebox::platform::StdioStream::Stdin
            || !self.stdio_is_tty[litebox::platform::StdioStream::Stdin as usize]
        {
            return;
        }
        let host_action = match action {
            litebox::platform::TerminalSetAction::Now => libc::TCSANOW,
            litebox::platform::TerminalSetAction::Drain => libc::TCSADRAIN,
            litebox::platform::TerminalSetAction::Flush => libc::TCSAFLUSH,
        };
        // SAFETY: `STDIN_FILENO` is valid for the process lifetime; `term` is fully initialized
        // by `tcgetattr` before any field is read or written.
        unsafe {
            let mut term: libc::termios = core::mem::zeroed();
            if libc::tcgetattr(libc::STDIN_FILENO, &raw mut term) != 0 {
                return;
            }
            if raw {
                term.c_lflag &= !(libc::ICANON as libc::tcflag_t);
                term.c_cc[libc::VMIN] = 1;
                term.c_cc[libc::VTIME] = 0;
            } else {
                term.c_lflag |= libc::ICANON as libc::tcflag_t;
            }
            if echo {
                term.c_lflag |= libc::ECHO as libc::tcflag_t;
            } else {
                term.c_lflag &= !(libc::ECHO as libc::tcflag_t);
            }
            let _ = libc::tcsetattr(libc::STDIN_FILENO, host_action, &raw const term);
        }
        // The host `TCSAFLUSH` above only discards bytes still sitting in the host tty driver's
        // own input queue; it cannot see bytes this pump's background reader thread has already
        // pulled off that queue and pushed into the ring, so those need a separate discard,
        // performed strictly after the host flush call returns.
        if action == litebox::platform::TerminalSetAction::Flush {
            self.stdin_pump.discard_buffered();
        }
    }

    fn tty_window_size(&self) -> Option<(u16, u16)> {
        if !self.stdio_is_tty[litebox::platform::StdioStream::Stdout as usize] {
            return None;
        }
        // SAFETY: `STDOUT_FILENO` is valid for the process lifetime; `ws` is fully initialized
        // by the kernel before any field is read, or the call fails and `ws` is left unread.
        let ws = unsafe {
            let mut ws: libc::winsize = core::mem::zeroed();
            if libc::ioctl(libc::STDOUT_FILENO, libc::TIOCGWINSZ, &raw mut ws) != 0 {
                return None;
            }
            ws
        };
        if ws.ws_row == 0 || ws.ws_col == 0 {
            return None;
        }
        Some((ws.ws_row, ws.ws_col))
    }
}

// ---------------------------------------------------------------------------
// System information
// ---------------------------------------------------------------------------

impl litebox::platform::SystemInfoProvider for MacOsUserland {
    fn get_syscall_entry_point(&self) -> usize {
        // Stock code under HVF executes real `SVC #0` at EL0 through the EL1
        // monitor; zero tells the loader never to parse or patch trampolines.
        if hvf_backend::active().is_some() {
            return 0;
        }
        // Not a single fixed function address: this platform's syscall callback
        // has to resolve the calling thread's own guest-entry state with the
        // one register the rewriter's `SVC` gate leaves free, which it does by
        // there being one entry stub per possible pthread TSD slot. See
        // `guest::syscall_entry_point`.
        guest::syscall_entry_point()
    }

    fn get_vdso_address(&self) -> Option<usize> {
        // A Linux guest's vDSO would have to be a LiteBox-provided image; the
        // host's own `commpage` is not one. Reporting `None` means the guest
        // falls back to real syscalls, which is what the shim wants anyway --
        // but it also means a guest signal handler needs its own `sa_restorer`,
        // because the kernel's fallback trampoline lives in the vDSO.
        None
    }

    fn get_guest_tp_slot_offset(&self) -> Option<usize> {
        // Under HVF `TPIDR_EL0` is a real register on the vCPU.
        if hvf_backend::active().is_some() {
            return None;
        }
        // `Host::MacOs` gates read this offset from the trampoline rather than
        // carrying it as an immediate, because the TSD key backing it is handed
        // out by `pthread_key_create` in this process and is not knowable to the
        // rewriter that packaged the image.
        guest_tp_slot_byte_offset()
    }

    fn get_sigreturn_trampoline_address(&self) -> Option<usize> {
        // A vCPU cannot execute host code: under HVF the trampoline is a
        // guest-executable page the backend installed before loading.
        if let Some(backend) = hvf_backend::active() {
            return Some(backend.trampoline_address());
        }
        // See `get_vdso_address`: this platform has no vDSO to fall back to for
        // a guest handler installed without `SA_RESTORER`, so it provides its
        // own trampoline instead -- `guest::sigreturn_trampoline`'s own doc
        // comment covers why this is safe despite there being no vDSO.
        Some(guest::sigreturn_trampoline as *const () as usize)
    }

    fn get_hwcap(&self) -> (u64, u64) {
        arm_hwcap()
    }
}

/// Darwin `hw.optional.*` sysctl name, and the Linux `AT_HWCAP`/`AT_HWCAP2` bit it maps to.
///
/// `true` selects `AT_HWCAP2`; `false` selects `AT_HWCAP`. Only features that (a) the CPU
/// genuinely implements and (b) do not change how guest code is expected to run (unlike, say,
/// pointer authentication or branch-target identification, which could interact with this
/// platform's own guest-entry control flow) are included -- see `SystemInfoProvider::get_hwcap`'s
/// doc comment for why any *included* bit is always safe to report.
const HWCAP_SYSCTLS: &[(&str, u8, bool)] = &[
    ("hw.optional.floatingpoint", 0, false),     // HWCAP_FP
    ("hw.optional.neon", 1, false),              // HWCAP_ASIMD
    ("hw.optional.arm.FEAT_AES", 3, false),      // HWCAP_AES
    ("hw.optional.arm.FEAT_PMULL", 4, false),    // HWCAP_PMULL
    ("hw.optional.arm.FEAT_SHA1", 5, false),     // HWCAP_SHA1
    ("hw.optional.arm.FEAT_SHA256", 6, false),   // HWCAP_SHA2
    ("hw.optional.arm.FEAT_CRC32", 7, false),    // HWCAP_CRC32
    ("hw.optional.arm.FEAT_LSE", 8, false),      // HWCAP_ATOMICS
    ("hw.optional.arm.FEAT_FP16", 9, false),     // HWCAP_FPHP
    ("hw.optional.neon_hpfp", 10, false),        // HWCAP_ASIMDHP
    ("hw.optional.arm.FEAT_RDM", 12, false),     // HWCAP_ASIMDRDM
    ("hw.optional.arm.FEAT_JSCVT", 13, false),   // HWCAP_JSCVT
    ("hw.optional.arm.FEAT_FCMA", 14, false),    // HWCAP_FCMA
    ("hw.optional.arm.FEAT_LRCPC", 15, false),   // HWCAP_LRCPC
    ("hw.optional.arm.FEAT_DPB", 16, false),     // HWCAP_DCPOP
    ("hw.optional.arm.FEAT_SHA3", 17, false),    // HWCAP_SHA3
    ("hw.optional.arm.FEAT_DotProd", 20, false), // HWCAP_ASIMDDP
    ("hw.optional.arm.FEAT_SHA512", 21, false),  // HWCAP_SHA512
    ("hw.optional.arm.FEAT_FHM", 23, false),     // HWCAP_ASIMDFHM
    ("hw.optional.arm.FEAT_DIT", 24, false),     // HWCAP_DIT
    ("hw.optional.arm.FEAT_LSE2", 25, false),    // HWCAP_USCAT
    ("hw.optional.arm.FEAT_LRCPC2", 26, false),  // HWCAP_ILRCPC
    ("hw.optional.arm.FEAT_FlagM", 27, false),   // HWCAP_FLAGM
    ("hw.optional.arm.FEAT_SSBS", 28, false),    // HWCAP_SSBS
    ("hw.optional.arm.FEAT_SB", 29, false),      // HWCAP_SB
    ("hw.optional.arm.FEAT_DPB2", 0, true),      // HWCAP2_DCPODP
    ("hw.optional.arm.FEAT_FlagM2", 7, true),    // HWCAP2_FLAGM2
    ("hw.optional.arm.FEAT_FRINTTS", 8, true),   // HWCAP2_FRINT
    ("hw.optional.arm.FEAT_I8MM", 13, true),     // HWCAP2_I8MM
    ("hw.optional.arm.FEAT_BF16", 14, true),     // HWCAP2_BF16
    ("hw.optional.arm.FEAT_ECV", 19, true),      // HWCAP2_ECV
    ("hw.optional.arm.FEAT_AFP", 20, true),      // HWCAP2_AFP
    ("hw.optional.arm.FEAT_RPRES", 21, true),    // HWCAP2_RPRES
];

/// Queries this host's real ARM64 feature set via Darwin's `hw.optional.*` sysctls and
/// translates it into the `(AT_HWCAP, AT_HWCAP2)` bitmasks a real Linux kernel would report
/// for the same CPU. Missing/unreadable sysctls are treated as unsupported (bit left clear),
/// matching a real kernel's own behavior for a feature it does not detect.
fn arm_hwcap() -> (u64, u64) {
    let mut hwcap: u64 = 0;
    let mut hwcap2: u64 = 0;
    for &(name, bit, is_hwcap2) in HWCAP_SYSCTLS {
        if sysctl_bool(name) {
            if is_hwcap2 {
                hwcap2 |= 1 << bit;
            } else {
                hwcap |= 1 << bit;
            }
        }
    }
    (hwcap, hwcap2)
}

/// Reads a Darwin `hw.optional.*`-style boolean sysctl (a 32-bit int, nonzero meaning present),
/// returning `false` if the sysctl does not exist on this host or the read otherwise fails.
fn sysctl_bool(name: &str) -> bool {
    // SAFETY: `c_name` is a valid, NUL-terminated C string for the duration of the call, and
    // `value`/`len` are valid, uniquely-owned out-parameters matching what `sysctlbyname`
    // expects for reading a fixed-size (4-byte) integer sysctl.
    unsafe {
        let Ok(c_name) = std::ffi::CString::new(name) else {
            return false;
        };
        let mut value: libc::c_int = 0;
        let mut len = core::mem::size_of::<libc::c_int>();
        let rc = libc::sysctlbyname(
            c_name.as_ptr(),
            (&raw mut value).cast(),
            &raw mut len,
            core::ptr::null_mut(),
            0,
        );
        rc == 0 && value != 0
    }
}

/// `sysctl_bool` on a name no Darwin host defines must fail closed (`false`), not panic or
/// report a false positive -- this is exactly what a genuinely-unsupported CPU feature looks
/// like to [`arm_hwcap`], and it must never be mistaken for "supported".
#[cfg(test)]
#[test]
fn sysctl_bool_is_false_for_a_nonexistent_sysctl() {
    assert!(!sysctl_bool(
        "hw.optional.litebox_does_not_define_this_sysctl"
    ));
}

/// `decode_mrs_ctr_el0` accepts `mrs Xt, CTR_EL0` for every destination
/// register and rejects everything else -- notably the neighbouring
/// `mrs Xt, DCZID_EL0` and the OpenSSL feature-probe instruction that must
/// still reach the guest as a real `SIGILL`. This is the exact decode the
/// fault handler runs to tell a cache-line-size read (emulate) from an
/// undefined instruction (deliver).
#[cfg(test)]
#[test]
fn decode_mrs_ctr_el0_matches_only_the_real_instruction() {
    // `mrs x3, CTR_EL0` and `mrs x0, CTR_EL0` (the two forms libgcc/JITs emit).
    assert_eq!(decode_mrs_ctr_el0(0xd53b_0023), Some(3));
    assert_eq!(decode_mrs_ctr_el0(0xd53b_0020), Some(0));
    // Highest register.
    assert_eq!(decode_mrs_ctr_el0(0xd53b_003f), Some(31));
    // `mrs x0, DCZID_EL0` (op2=7) -- a different system register, not ours.
    assert_eq!(decode_mrs_ctr_el0(0xd53b_00e0), None);
    // `sm3partw1 v4.4s, v0.4s, v3.4s` -- OpenSSL's probe; must fall through.
    assert_eq!(decode_mrs_ctr_el0(0xce63_c004), None);
    // A plain `nop`.
    assert_eq!(decode_mrs_ctr_el0(0xd503_201f), None);
}

/// The synthesized `CTR_EL0` is well-formed for `__clear_cache`: bit 31 is
/// RES1, and the I/D minimum-line fields decode to a stride no larger than the
/// host's real cache line (so cache maintenance can only over-flush, never
/// skip a line). Verified against the value the platform actually derives on
/// this host.
#[cfg(test)]
#[test]
fn synthetic_ctr_el0_is_well_formed_and_never_understates_the_line() {
    init_synthetic_ctr_el0();
    let ctr = JIT_FAULT.synthetic_ctr_el0.load(Ordering::Relaxed);
    assert_ne!(ctr, 0, "must be initialized");
    assert_eq!(ctr >> 31 & 1, 1, "bit 31 is RES1");
    let imin_words = 1u64 << (ctr & 0xf);
    let dmin_words = 1u64 << (ctr >> 16 & 0xf);
    let real_line = darwin::sysctl_u64(c"hw.cachelinesize").unwrap_or(64);
    // Encoded stride (in bytes) must not exceed the real coherency granule.
    assert!(imin_words * 4 <= real_line, "icache stride over-wide");
    assert!(dmin_words * 4 <= real_line, "dcache stride over-wide");
}

/// The JIT-region registry round-trips: an address inside a registered region
/// matches, one outside does not, and unregistering (as `deallocate_pages`
/// does) makes the region stop matching -- the property that keeps a stale
/// entry from mistaking a later, unrelated mapping for JIT in the fault
/// handler.
#[cfg(test)]
#[test]
fn jit_region_registry_round_trips() {
    // A high address unlikely to collide with a real live JIT region during
    // the test run.
    let base = 0x5000_0000_0000usize;
    let len = 0x10_0000usize;
    assert!(!addr_in_jit_region(base + 0x1000));
    register_jit_region(base, len);
    assert!(addr_in_jit_region(base));
    assert!(addr_in_jit_region(base + len - 1));
    assert!(!addr_in_jit_region(base + len));
    assert!(!addr_in_jit_region(base - 1));
    unregister_jit_region(base, len);
    assert!(!addr_in_jit_region(base + 0x1000));
}

/// Every real Apple Silicon Mac (the only hardware this platform targets) implements
/// floating point and NEON/ASIMD -- if `arm_hwcap` cannot even detect those two baseline,
/// universally-present features via the real `hw.optional.*` sysctls, its sysctl-to-HWCAP-bit
/// wiring is broken, not just conservatively reporting an optional feature as absent.
#[cfg(test)]
#[test]
fn arm_hwcap_reports_the_real_hosts_baseline_features() {
    const HWCAP_FP: u64 = 1 << 0;
    const HWCAP_ASIMD: u64 = 1 << 1;
    let (hwcap, _hwcap2) = arm_hwcap();
    assert_eq!(
        hwcap & (HWCAP_FP | HWCAP_ASIMD),
        HWCAP_FP | HWCAP_ASIMD,
        "every real Apple Silicon Mac has both FP and ASIMD"
    );
}

/// `allocate_pages` used to refuse `MemoryRegionPermissions::SHARED` outright, on the theory
/// that a Darwin `MAP_SHARED|MAP_ANON` mapping does not survive into a forked child. Measured
/// false on this exact hardware with a standalone probe (a shared counter incremented 100000
/// times by each of a parent and its child read back 200000, not 100000, when the mapping was
/// created before the fork) -- and moot regardless, since this platform's own guest `fork`
/// never gives a child a second host address space to diverge from in the first place (see
/// `syscalls::process`'s address-space handoff in `litebox_shim_linux`). This test locks in
/// only the platform-level half: a `SHARED` allocation must actually succeed and be genuinely
/// writable, not merely fail to panic.
#[cfg(test)]
#[test]
fn allocate_pages_no_longer_refuses_shared_anonymous_mappings() {
    use litebox::platform::{PageManagementProvider, RawConstPointer as _};

    let platform = MacOsUserland::new(None);
    let len = litebox::mm::vmem::PAGE_SIZE;
    // `FixedAddressBehavior::Hint` makes `suggested_range.start` advisory only (no `MAP_FIXED`),
    // so any aligned address here is fine -- the kernel is free to place it elsewhere.
    let hint = 0x2000_0000_0000usize;

    let ptr = <MacOsUserland as PageManagementProvider<
        { litebox::mm::vmem::PAGE_SIZE },
    >>::allocate_pages(
        platform,
        hint..hint + len,
        MemoryRegionPermissions::READ | MemoryRegionPermissions::WRITE | MemoryRegionPermissions::SHARED,
        false,
        true,
        FixedAddressBehavior::Hint,
    )
    .expect("a SHARED anonymous mapping must be allocatable, not refused");

    // SAFETY: `ptr` is a freshly allocated, `WRITE`-permissioned mapping of at least `len`
    // bytes, owned exclusively by this test until it is deallocated below.
    unsafe {
        let raw = ptr.as_usize() as *mut u8;
        raw.write_volatile(0xab);
        assert_eq!(
            raw.read_volatile(),
            0xab,
            "a SHARED mapping must be genuinely writable"
        );
    }

    // SAFETY: `ptr`'s range was returned by the matching `allocate_pages` call above and has
    // not been deallocated yet.
    unsafe {
        <MacOsUserland as PageManagementProvider<{ litebox::mm::vmem::PAGE_SIZE }>>::deallocate_pages(
            platform,
            ptr.as_usize()..ptr.as_usize() + len,
        )
        .expect("deallocating the SHARED mapping must succeed");
    }
}

// ---------------------------------------------------------------------------
// Thread-local storage
// ---------------------------------------------------------------------------

std::thread_local! {
    static PLATFORM_TLS: core::cell::Cell<*mut ()> =
        const { core::cell::Cell::new(core::ptr::null_mut()) };
}

// SAFETY: the pointer returned is exactly the one most recently stored for this
// thread, and a thread that has stored nothing reads back the null the cell was
// initialized with.
unsafe impl litebox::platform::ThreadLocalStorageProvider for MacOsUserland {
    fn get_thread_local_storage() -> *mut () {
        PLATFORM_TLS.get()
    }

    unsafe fn replace_thread_local_storage(value: *mut ()) -> *mut () {
        PLATFORM_TLS.replace(value)
    }
}

// ---------------------------------------------------------------------------
// Randomness and derived keys
// ---------------------------------------------------------------------------

impl litebox::platform::CrngProvider for MacOsUserland {
    fn fill_bytes_crng(&self, buf: &mut [u8]) {
        // `arc4random_buf` is the platform's own CSPRNG: it cannot fail, cannot
        // block, and the kernel reseeds it across `fork` and VM snapshots. That
        // pass-through is precisely what the trait asks for.
        //
        // SAFETY: `buf` is a valid writable slice of the length passed.
        unsafe { libc::arc4random_buf(buf.as_mut_ptr().cast::<libc::c_void>(), buf.len()) };
    }
}

impl litebox::platform::DerivedKeyProvider for MacOsUserland {
    fn derive_key<E>(
        &self,
        shim_kdf: Option<fn(&[u8], litebox::platform::KDFParams) -> Result<(), E>>,
        params: litebox::platform::KDFParams,
    ) -> Result<(), litebox::platform::DerivedKeyError<E>> {
        let Some(boot_id) = self.boot_id.get() else {
            return Err(litebox::platform::DerivedKeyError::UnsupportedRebootPersistentKey);
        };
        let Some(shim_kdf) = shim_kdf else {
            // Darwin exposes no KDF of its own that is rooted in a device
            // secret, so a shim that brings none cannot be served here.
            return Err(litebox::platform::DerivedKeyError::ShimKDFRequired);
        };
        // The shim shares this platform's trust boundary, so the root key can be
        // handed to it directly rather than pre-hashed.
        Ok(shim_kdf(boot_id, params)?)
    }
}

// ---------------------------------------------------------------------------
// Signals
// ---------------------------------------------------------------------------

// Asynchronous host signals observed since the guest thread that owns this
// pointer last drained them. Bit `n - 1` corresponds to signal number `n`,
// matching `SigSet`'s encoding.
//
// The bitmap itself lives in that thread's `ThreadHandleInner`, not here --
// `timer_thread` fires on its own dedicated thread and has to mark the
// *target* thread's bit, and a bare `thread_local!` cannot be reached from
// another thread. This cell just caches, on the owning thread, a pointer to
// its own copy of that shared bitmap so `async_signal_handler` and
// `take_pending_signals` can reach it without going through
// `CURRENT_THREAD`'s `RefCell`, which is not safe to borrow from a signal
// handler that might land mid-borrow. Null while the thread has no
// `ThreadHandle::run_with_handle` registration.
thread_local! {
    static PENDING_SIGNALS: core::cell::Cell<*const AtomicU64> =
        const { core::cell::Cell::new(core::ptr::null()) };
}

unsafe extern "C" fn async_signal_handler(signum: libc::c_int) {
    if let Ok(bit) = u32::try_from(signum - 1) {
        let pending = PENDING_SIGNALS.get();
        if !pending.is_null() {
            // SAFETY: non-null only while `run_with_handle` has this thread
            // registered, and cleared before that registration is torn down,
            // so the `ThreadHandleInner` it points into is always live here.
            unsafe { (*pending).fetch_or(1u64 << bit, Ordering::Relaxed) };
        }
    }
}

/// The interrupt signal has two independent jobs. Every delivery, regardless
/// of what follows, already accomplishes the older one just by arriving: EINTR
/// -ing a blocking host call (`SA_RESTART` is deliberately absent below), the
/// mechanism `TimerProvider::create_timer`'s doc comment describes. The
/// newer one is routing to [`litebox::shim::EnterShim::interrupt`] when the
/// signalled thread is genuinely executing guest code, mirroring
/// `litebox_platform_linux_userland`'s `interrupt_signal_handler` (a TLS
/// `in_guest` byte plus `switch_to_guest_start`/`_end` labels) and
/// `litebox_platform_windows_userland`'s `interrupt_thread`
/// (`SuspendThread`/`GetThreadContext`/`SetThreadContext` over the same label
/// range) -- adapted to this platform's process-global, `GUEST_OWNS_CPU`-based
/// single-guest-thread bookkeeping rather than either of theirs.
///
/// Four cases, matching the Linux reference's own four-way split
/// (`litebox_platform_linux_userland::interrupt_signal_handler`'s doc
/// comment), reached in the same priority order that keeps
/// `guest::GUEST_OWNS_CPU`'s own ordering safe: the flag first, then a
/// PC-range check, so a captured `mcontext` is only ever handed to the guest
/// when both agree.
///
/// 1. **Not in guest** (`guest::GUEST_OWNS_CPU` false): includes ordinary
///    host code between guest entries, *and* the tail of
///    `guest::syscall_callback`/`guest::sigreturn_trampoline` once their
///    own first couple of instructions have already cleared the flag. Record
///    `guest::PENDING_INTERRUPT` for `guest::enter_guest_asm` to re-check
///    the next time it is about to hand control to the guest -- otherwise an
///    interrupt racing exactly this narrow window (the shim already decided
///    to signal a thread it saw as "running in guest," but the platform has
///    not yet set the flag for *this* entry) would be silently lost until the
///    guest's next syscall, defeating the entire point of interrupting a
///    compute-bound guest with no syscalls at all.
/// 2. **In guest, but inside `guest::syscall_callback`'s or
///    [`guest::sigreturn_trampoline`]'s own brief ownership-clearing prologue**
///    (their address ranges, checked because `guest::GUEST_OWNS_CPU` has not
///    been cleared yet at this exact PC -- see those functions' own doc
///    comments): the guest is about to reach the shim on its own via the
///    ordinary syscall/sigreturn path within a couple of instructions.
///    [`litebox::shim::EnterShim::interrupt`]'s own doc comment says this is
///    fine ("the platform may just call the corresponding handler instead");
///    same handling as case 1 -- record and let it proceed.
/// 3. **In guest, inside `guest::enter_guest_asm`'s own restore range**
///    (mid-restoring a [`litebox_common_linux::PtRegs`] that is still fully
///    authoritative -- nothing has consumed it yet): abandon this entry
///    attempt without capturing anything, since the existing `*ctx` already
///    describes exactly the state the guest would have resumed with.
/// 4. **Genuinely executing guest code** (flag true, PC outside every above
///    range): capture the interrupted `mcontext`'s general and vector
///    registers the same way [`guest::prepare_exception_delivery`] does for a
///    hardware fault, and redirect to `guest::interrupt_callback`.
///
/// # Safety
///
/// Must be installed as an `SA_SIGINFO` handler (see [`install_fault_handlers`]
/// for why `fault_handler`'s cases don't apply symmetrically the other way:
/// `SIGSEGV`/`SIGBUS` are synchronous and this signal is masked out for their
/// duration, so they can never nest inside this function; the reverse mask on
/// this handler's own installation is what makes the converse true).
unsafe extern "C" fn interrupt_signal_handler(
    _signum: libc::c_int,
    _info: *mut libc::siginfo_t,
    ucontext: *mut libc::c_void,
) {
    // SAFETY: the kernel hands a `ucontext_t` to an `SA_SIGINFO` handler, and
    // its `uc_mcontext` points at a `_STRUCT_MCONTEXT64` on this architecture,
    // exactly as in `fault_handler`.
    let machine_context = unsafe {
        let ucontext = ucontext.cast::<libc::ucontext_t>();
        if ucontext.is_null() {
            return;
        }
        (*ucontext).uc_mcontext.cast::<darwin::McontextPrefix64>()
    };
    if machine_context.is_null() {
        return;
    }

    // Per-thread, so an interrupt aimed at one guest thread can no longer be
    // consumed by a different one (and a `SIGUSR2` landing on a thread that
    // runs no guest at all has nowhere to be recorded, which is correct: its
    // other job, `EINTR`-ing a blocking host call, is already done).
    let guest_state = guest::current_guest_state();
    if !guest::guest_owns_cpu(guest_state) {
        // Case 1.
        guest::record_pending_interrupt(guest_state);
        return;
    }

    // SAFETY: checked non-null just above.
    let pc = unsafe { (*machine_context).thread_state.pc }.trunc();

    if guest::interrupted_pc_is_in_guest_exit_prologue(pc) {
        // Case 2.
        guest::record_pending_interrupt(guest_state);
        return;
    }

    let recovery = if guest::interrupted_pc_is_in_guest_entry_restore(pc) {
        // Case 3: nothing to capture, the live `PtRegs` is already correct.
        //
        // SAFETY: `guest_owns_cpu` was true (so `guest_state` is this thread's
        // own non-null live state) and `pc` falls inside `enter_guest_asm`'s
        // own restore range, matching this function's documented precondition.
        unsafe { guest::abandon_guest_entry_for_interrupt(guest_state) }
    } else {
        // Case 4.
        //
        // SAFETY: checked non-null above.
        let (thread_state, neon_state) = unsafe {
            (
                &(*machine_context).thread_state,
                &(*machine_context).neon_state,
            )
        };
        // SAFETY: `guest_owns_cpu` true (so `guest_state` is this thread's own
        // non-null live state) and `pc` outside every switch-code range
        // checked above means the interrupted context is genuinely the guest's
        // own, matching this function's documented precondition.
        unsafe { guest::prepare_interrupt_delivery(guest_state, thread_state, neon_state) }
    };
    // SAFETY: checked non-null above.
    unsafe { (*machine_context).thread_state.pc = recovery as u64 };
}

/// `pub(crate)` (rather than private) so `guest::tests` can install the real
/// `SIGUSR2` handler directly, the same way `install_fault_handlers` already
/// lets `guest::tests` install the real `SIGSEGV`/`SIGBUS` ones without
/// constructing a whole [`MacOsUserland`].
pub(crate) fn install_async_signal_handlers() {
    for signum in [libc::SIGINT, libc::SIGALRM] {
        darwin::install_handler(
            signum,
            async_signal_handler as *const () as usize,
            false,
            &[],
        );
    }
    // `SA_RESTART` is deliberately absent: interrupting a blocking call is the
    // entire purpose of this signal. Every signal `install_fault_handlers`
    // routes -- `SIGSEGV`/`SIGBUS`, and `SIGILL` for a guest's deliberate
    // CPU-feature probe -- is masked for the duration of this handler (see
    // `darwin::install_handler`'s doc comment), so a guest fault can never nest
    // atop an in-flight interrupt delivery and race the same guest-entry state.
    darwin::install_handler(
        INTERRUPT_SIGNAL,
        interrupt_signal_handler as *const () as usize,
        true,
        &[libc::SIGSEGV, libc::SIGBUS, libc::SIGILL],
    );
}

/// Blocks the two signals [`async_signal_handler`] tracks, for a thread that
/// will never hold a [`ThreadHandle::run_with_handle`] registration -- such a
/// thread has nowhere to record one, so a real `SIGINT`/`SIGALRM` the kernel
/// happened to deliver here instead of to a guest thread would otherwise never
/// reach any guest thread at all, with nothing to show for it. Mirrors
/// `litebox_platform_linux_userland::block_guest_signals`, narrowed to the two
/// real host signals this platform installs handlers for.
fn block_guest_signals() {
    // SAFETY: `set` is fully initialized by the `sigemptyset`/`sigaddset` calls
    // before `pthread_sigmask` reads it; blocking a signal has no further
    // precondition.
    unsafe {
        let mut set: libc::sigset_t = core::mem::zeroed();
        libc::sigemptyset(&raw mut set);
        libc::sigaddset(&raw mut set, libc::SIGINT);
        libc::sigaddset(&raw mut set, libc::SIGALRM);
        libc::pthread_sigmask(libc::SIG_BLOCK, &raw const set, core::ptr::null_mut());
    }
}

impl litebox::platform::SignalProvider for MacOsUserland {
    type Signal = litebox_common_linux::signal::Signal;

    fn take_pending_signals(&self, mut f: impl FnMut(Self::Signal)) {
        let pending_ptr = PENDING_SIGNALS.get();
        if pending_ptr.is_null() {
            return;
        }
        // SAFETY: see `async_signal_handler`.
        let mut pending = unsafe { (*pending_ptr).swap(0, Ordering::Relaxed) };
        while pending != 0 {
            let bit = pending.trailing_zeros();
            pending &= !(1u64 << bit);
            // Host and guest signal numbers agree for the small set of
            // asynchronous signals handled here.
            if let Ok(signal) =
                litebox_common_linux::signal::Signal::try_from(bit.cast_signed() + 1)
            {
                f(signal);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Timers
// ---------------------------------------------------------------------------

/// A one-shot timer.
///
/// Darwin has neither POSIX `timer_create` nor more than one `setitimer` per
/// process, so each timer owns a thread that sleeps until its deadline and then
/// fires. The thread is parked on a condition variable when no deadline is
/// armed, so an idle timer costs nothing but its stack.
///
/// Firing has two jobs, and getting only one of them right is a bug that is
/// easy not to notice: it must both (1) record the *guest*'s chosen signal as
/// pending, and (2) actually wake the guest thread that may be blocked
/// waiting on it (in [`litebox::event::wait::WaitContext::sleep`], backed by
/// this platform's `RawMutex::block_or_timeout`). Recording the pending bit
/// alone is not observable by a thread parked in `ulock_wait2` -- nothing
/// re-evaluates its wait condition until something wakes it. So the timer
/// thread also signals the thread that created it (captured at
/// [`TimerProvider::create_timer`]-time) with `INTERRUPT_SIGNAL`, the same
/// signal [`ThreadProvider::interrupt_thread`] uses purely to interrupt a
/// blocking syscall with `EINTR` -- never `SIGALRM`, which would spuriously
/// mark the *host's* SIGALRM as pending too, even for a timer configured for
/// an unrelated guest signal.
///
/// This needs no OS-level timer or real signal payload to report which guest
/// signal fired (contrast `litebox_platform_linux_userland`, which encodes it
/// in `sigev_value` because its timer genuinely is external kernel state): the
/// timer never leaves this process, so the firing thread can just write the
/// pending-signals bitmap directly before waking the target.
///
/// [`TimerProvider::create_timer`]: litebox::platform::TimerProvider::create_timer
/// [`ThreadProvider::interrupt_thread`]: litebox::platform::ThreadProvider::interrupt_thread
pub struct TimerHandle {
    state: Arc<TimerState>,
}

struct TimerState {
    /// The deadline, or `None` when disarmed. `Condvar` wakes the timer thread
    /// whenever this changes.
    deadline: Mutex<TimerCommand>,
    changed: Condvar,
    /// The guest signal to record as pending when this timer fires.
    signal: litebox_common_linux::signal::Signal,
    /// The thread to wake on fire -- the one that called
    /// [`TimerProvider::create_timer`](litebox::platform::TimerProvider::create_timer),
    /// captured once so a guest that arms the timer and then blocks elsewhere
    /// (the common case: `timer_create` then `nanosleep`) is still reached.
    target: ThreadHandle,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum TimerCommand {
    Disarmed,
    ArmedFor(std::time::Instant),
    Deleted,
}

impl litebox::platform::TimerProvider for MacOsUserland {
    type TimerHandle = TimerHandle;
    type Signal = litebox_common_linux::signal::Signal;

    fn create_timer(
        &self,
        signal: Self::Signal,
    ) -> Result<Self::TimerHandle, litebox::platform::TimerCreationError> {
        let state = Arc::new(TimerState {
            deadline: Mutex::new(TimerCommand::Disarmed),
            changed: Condvar::new(),
            signal,
            target: ThreadHandle::current(),
        });
        let thread_state = Arc::clone(&state);
        std::thread::Builder::new()
            .name("litebox-timer".into())
            .spawn(move || timer_thread(&thread_state))
            .map_err(|_| litebox::platform::TimerCreationError::Unsupported)?;
        Ok(TimerHandle { state })
    }
}

fn timer_thread(state: &TimerState) {
    block_guest_signals();
    let mut command = state.deadline.lock().unwrap();
    loop {
        match *command {
            TimerCommand::Deleted => return,
            TimerCommand::Disarmed => {
                command = state.changed.wait(command).unwrap();
            }
            TimerCommand::ArmedFor(deadline) => {
                let Some(remaining) = deadline.checked_duration_since(std::time::Instant::now())
                else {
                    // Fire, then disarm -- these timers are one-shot. Record the
                    // configured guest signal, then wake the target thread; see
                    // the `TimerHandle` docs for why both steps are required and
                    // why the wakeup must not be `SIGALRM`.
                    *command = TimerCommand::Disarmed;
                    let bit = (state.signal.as_i32() - 1).cast_unsigned();
                    state.target.record_pending_signal(bit);
                    state.target.interrupt();
                    continue;
                };
                let (next, _) = state.changed.wait_timeout(command, remaining).unwrap();
                command = next;
            }
        }
    }
}

impl litebox::platform::TimerHandle for TimerHandle {
    fn set_timer(&self, duration: Duration) {
        let mut command = self.state.deadline.lock().unwrap();
        *command = if duration.is_zero() {
            TimerCommand::Disarmed
        } else {
            TimerCommand::ArmedFor(std::time::Instant::now() + duration)
        };
        drop(command);
        self.state.changed.notify_all();
    }

    fn delete_timer(self) {
        let mut command = self.state.deadline.lock().unwrap();
        *command = TimerCommand::Deleted;
        drop(command);
        self.state.changed.notify_all();
    }
}

// ---------------------------------------------------------------------------
// Threads
// ---------------------------------------------------------------------------

/// A `pthread_t` is an opaque pointer on Darwin, so it needs an explicit
/// `Send`/`Sync` witness to travel between threads.
#[derive(Clone, Copy)]
struct ThreadId(libc::pthread_t);

// SAFETY: the identifier is only ever handed back to `pthread_kill`, which is
// itself thread-safe, and [`ThreadHandle`] clears it before the thread it names
// can exit, so it is never used to signal a dead thread.
unsafe impl Send for ThreadId {}
// SAFETY: see the `Send` witness above.
unsafe impl Sync for ThreadId {}

/// The state shared behind a [`ThreadHandle`].
struct ThreadHandleInner {
    id: Mutex<Option<ThreadId>>,
    /// Interrupt state for the HVF backend: a pending flag plus the vCPU lane
    /// this thread is currently running on, so `interrupt` can kick it.
    hvf: hvf_backend::HvfThreadSlot,
    /// This thread's own pending-signals bitmap -- see [`PENDING_SIGNALS`] for
    /// why it lives here, `Arc`-shared, rather than in a bare `thread_local!`.
    /// Not gated by `id`: recording a bit into a since-exited thread's copy is
    /// harmless (nothing will ever read it), unlike signalling a stale
    /// `pthread_t`.
    pending_signals: AtomicU64,
}

/// A handle to a LiteBox-managed thread, used to interrupt it and to record a
/// pending signal on it from another thread (see `ThreadHandle::record_pending_signal`).
pub struct ThreadHandle(Arc<ThreadHandleInner>);

impl Clone for ThreadHandle {
    fn clone(&self) -> Self {
        Self(Arc::clone(&self.0))
    }
}

std::thread_local! {
    static CURRENT_THREAD: core::cell::RefCell<Option<ThreadHandle>> =
        const { core::cell::RefCell::new(None) };
}

impl ThreadHandle {
    /// Runs `f` with a handle registered for the current thread, so that
    /// [`litebox::platform::ThreadProvider::current_thread`] works inside it.
    fn run_with_handle<R>(f: impl FnOnce() -> R) -> R {
        // SAFETY: `pthread_self` has no preconditions.
        let handle = ThreadHandle(Arc::new(ThreadHandleInner {
            id: Mutex::new(Some(ThreadId(unsafe { libc::pthread_self() }))),
            hvf: hvf_backend::HvfThreadSlot::new(),
            pending_signals: AtomicU64::new(0),
        }));
        // Points into `handle`'s own heap allocation, not `handle` itself, so
        // moving `handle` into `CURRENT_THREAD` below does not invalidate it.
        PENDING_SIGNALS.set(&raw const handle.0.pending_signals);
        CURRENT_THREAD.with_borrow_mut(|current| {
            assert!(
                current.is_none(),
                "nested run_with_handle calls are not supported"
            );
            *current = Some(handle);
        });
        let _guard = litebox::utils::defer(|| {
            // Cleared before `CURRENT_THREAD`, and before the thread can exit,
            // so `async_signal_handler` never dereferences it once the
            // `ThreadHandleInner` it names may be on its way out.
            PENDING_SIGNALS.set(core::ptr::null());
            let current = CURRENT_THREAD.take().expect("handle registered above");
            // Clearing before the thread exits is what makes signalling a stale
            // `pthread_t` impossible.
            *current.0.id.lock().unwrap() = None;
        });
        f()
    }

    pub(crate) fn current() -> Self {
        CURRENT_THREAD.with_borrow(|thread| {
            thread
                .clone()
                .expect("current_thread called outside of a LiteBox thread")
        })
    }

    fn interrupt(&self) {
        if let Some(thread) = *self.0.id.lock().unwrap() {
            // SAFETY: the identifier is live for as long as this lock is held.
            unsafe { libc::pthread_kill(thread.0, INTERRUPT_SIGNAL) };
        }
        // Under HVF the thread may be inside `hv_vcpu_run`, which no host
        // signal reaches: record the interrupt and kick its vCPU.
        if hvf_backend::active().is_some() {
            self.0.hvf.kick();
        }
    }

    /// This thread's HVF interrupt slot (see [`hvf_backend::HvfThreadSlot`]).
    pub(crate) fn hvf_slot(&self) -> &hvf_backend::HvfThreadSlot {
        &self.0.hvf
    }

    /// Records a pending host signal on this thread from anywhere --
    /// in particular from [`timer_thread`], which fires on its own dedicated
    /// thread and has to mark the thread it targets, not itself.
    fn record_pending_signal(&self, bit: u32) {
        self.0
            .pending_signals
            .fetch_or(1u64 << bit, Ordering::Relaxed);
    }
}

/// Two threads' pending-signal bitmaps must stay disjoint -- the property that
/// broke when this bitmap was a single process-wide `static`, which is what
/// made the shared test-harness singleton race across concurrently-run tests.
/// Each thread records a distinct signal via [`async_signal_handler`] (the
/// same call a real signal delivery makes), a `Barrier` forces both writes to
/// land before either reads back, and each must observe only its own bit.
#[cfg(test)]
#[test]
fn pending_signals_are_disjoint_across_threads() {
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));

    let b1 = std::sync::Arc::clone(&barrier);
    let t1 = std::thread::Builder::new()
        .spawn(move || {
            ThreadHandle::run_with_handle(|| {
                // SAFETY: called from within `run_with_handle`, exactly as a
                // real `SIGINT` delivered to this thread would invoke it.
                unsafe { async_signal_handler(libc::SIGINT) };
                b1.wait();
                let ptr = PENDING_SIGNALS.get();
                // SAFETY: still inside `run_with_handle` on the thread that
                // owns this pointer.
                let pending = unsafe { (*ptr).load(Ordering::Relaxed) };
                let sigint_bit = 1u64 << u32::try_from(libc::SIGINT - 1).unwrap();
                assert_eq!(
                    pending, sigint_bit,
                    "thread 1 must observe exactly its own SIGINT, not thread 2's SIGALRM"
                );
            });
        })
        .expect("failed to spawn thread 1");

    let b2 = std::sync::Arc::clone(&barrier);
    let t2 = std::thread::Builder::new()
        .spawn(move || {
            ThreadHandle::run_with_handle(|| {
                // SAFETY: see thread 1.
                unsafe { async_signal_handler(libc::SIGALRM) };
                b2.wait();
                let ptr = PENDING_SIGNALS.get();
                // SAFETY: see thread 1.
                let pending = unsafe { (*ptr).load(Ordering::Relaxed) };
                let sigalrm_bit = 1u64 << u32::try_from(libc::SIGALRM - 1).unwrap();
                assert_eq!(
                    pending, sigalrm_bit,
                    "thread 2 must observe exactly its own SIGALRM, not thread 1's SIGINT"
                );
            });
        })
        .expect("failed to spawn thread 2");

    t1.join().expect("thread 1 panicked");
    t2.join().expect("thread 2 panicked");
}

impl litebox::platform::ThreadProvider for MacOsUserland {
    type ExecutionContext = litebox_common_linux::PtRegs;
    type ThreadSpawnError = std::io::Error;
    type ThreadHandle = ThreadHandle;

    unsafe fn spawn_thread(
        &self,
        ctx: &litebox_common_linux::PtRegs,
        init_thread: alloc::boxed::Box<
            dyn litebox::shim::InitThread<ExecutionContext = litebox_common_linux::PtRegs>,
        >,
    ) -> Result<(), Self::ThreadSpawnError> {
        let mut ctx = ctx.clone();
        std::thread::Builder::new()
            .name("litebox-guest".into())
            .spawn(move || {
                // Let the shim set up its per-thread state before the new thread
                // reaches guest code.
                let shim = init_thread.init();
                ThreadHandle::run_with_handle(|| {
                    with_signal_alt_stack(|| run_guest_thread(shim.as_ref(), &mut ctx));
                });
            })?;
        Ok(())
    }

    fn current_thread(&self) -> Self::ThreadHandle {
        ThreadHandle::current()
    }

    fn interrupt_thread(&self, thread: &Self::ThreadHandle) {
        thread.interrupt();
    }

    #[cfg(debug_assertions)]
    fn run_test_thread<R>(f: impl FnOnce() -> R) -> R {
        ThreadHandle::run_with_handle(f)
    }

    fn get_fp_state(&self) -> litebox::platform::FpSimdState64 {
        if hvf_backend::active().is_some() {
            return hvf_backend::thread_fp_state();
        }
        guest::guest_fp_state()
    }

    fn set_fp_state(&self, state: &litebox::platform::FpSimdState64) {
        if hvf_backend::active().is_some() {
            hvf_backend::set_thread_fp_state(state);
            return;
        }
        guest::set_guest_fp_state(state);
    }
}

/// Runs one guest thread on whichever backend is installed: the HVF vCPU
/// backend when the runner selected it, the native rewritten-code switch
/// otherwise.
fn run_guest_thread(
    shim: &dyn litebox::shim::EnterShim<ExecutionContext = litebox_common_linux::PtRegs>,
    ctx: &mut litebox_common_linux::PtRegs,
) {
    match hvf_backend::active() {
        Some(backend) => backend.run_thread(shim, ctx),
        None => guest::run_thread(shim, ctx),
    }
}

// ---------------------------------------------------------------------------
// Networking
// ---------------------------------------------------------------------------

impl MacOsUserland {
    /// Install the rootless guest NAT engine: a second, private smoltcp stack
    /// that terminates guest TCP flows and relays guest UDP datagrams over
    /// ordinary host sockets, so outbound guest connectivity works with
    /// neither a `utun` device (which needs root) nor proxy environment
    /// variables in the guest. See the `nat` module docs.
    ///
    /// Idempotent: the first call builds and installs the engine; later calls
    /// are no-ops. The engine is driven entirely inside
    /// `send_ip_packet`/`receive_ip_packet`, which the shim's net_worker
    /// already calls in its busy-poll/sleep-backoff loop, so no dedicated
    /// thread or cross-thread lifetime is needed; when a `utun` device is
    /// attached those bodies never consult the engine.
    ///
    /// The engine is configured with the guest network's default gateway
    /// address; a runner overriding `--gateway-ip` must not enable it until
    /// the address can be plumbed through.
    pub fn enable_nat_engine(&'static self) {
        self.nat
            .get_or_init(|| Mutex::new(nat::NatEngine::new(litebox::net::GATEWAY_IP_ADDR)));
        litebox_util_log::debug!(gateway:% = litebox::net::GATEWAY_IP_ADDR; "nat: engine enabled");
    }
}

impl litebox::platform::IPInterfaceProvider for MacOsUserland {
    fn send_ip_packet(&self, packet: &[u8]) -> Result<(), litebox::platform::SendError> {
        // With neither a `utun` device nor the NAT engine installed there is
        // nowhere for the packet to go. `SendError` is `#[non_exhaustive]`
        // with no variants, so silently dropping is the only representable
        // outcome -- and it matches what a guest with no configured interface
        // should observe.
        if let Some(tun) = self.tun.as_ref() {
            net::write_packet(tun, packet);
        } else if let Some(nat) = self.nat.get() {
            nat.lock().unwrap().ingest_guest_packet(packet);
        }
        Ok(())
    }

    fn receive_ip_packet(
        &self,
        packet: &mut [u8],
    ) -> Result<usize, litebox::platform::ReceiveError> {
        if let Some(tun) = self.tun.as_ref() {
            return net::read_packet(tun, packet)
                .ok_or(litebox::platform::ReceiveError::WouldBlock);
        }
        if let Some(nat) = self.nat.get() {
            let mut engine = nat.lock().unwrap();
            // Packets already queued toward the guest are the previous tick's
            // output: hand them over first. The net_worker's receive poll is
            // the engine's only clock, so once the queue is empty pump the
            // host side and look again -- one tick per drained queue rather
            // than one per delivered packet, since a tick walks every flow.
            if let Some(n) = engine.take_packet_to_guest(packet) {
                return Ok(n);
            }
            engine.poll_host_side();
            if let Some(n) = engine.take_packet_to_guest(packet) {
                return Ok(n);
            }
        }
        Err(litebox::platform::ReceiveError::WouldBlock)
    }

    fn has_external_interface(&self) -> bool {
        self.tun.is_some() || self.nat.get().is_some()
    }
}

// ---------------------------------------------------------------------------
// Guest thread pointer
// ---------------------------------------------------------------------------

/// The one process-wide pthread TSD key reserved for the guest thread pointer.
/// Once initialized it is never deleted or replaced, so an already-loaded
/// trampoline's byte offset remains valid for the process lifetime.
static GUEST_TP_TSD_KEY: OnceLock<libc::pthread_key_t> = OnceLock::new();

/// Raise the `RLIMIT_NOFILE` soft limit toward 65536, best-effort.
///
/// The rootless NAT engine holds one host socket per guest flow, so a few
/// thousand concurrent flows would run the default ~256 soft limit out with
/// `EMFILE`. Raised at construction, alongside the other host resources
/// acquired before `enable_seatbelt_sandbox*` installs (which does not mediate
/// `setrlimit`, but this keeps one lifecycle slot for all of them). Darwin
/// rejects a soft limit above `kern.maxfilesperproc` with `EINVAL` even when
/// the hard limit is unlimited, so the request backs off by halving; whatever
/// limit stands on entry is kept if even that fails.
fn raise_nofile_limit() {
    const TARGET: libc::rlim_t = 65536;
    let mut limits = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `limits` is a valid, uniquely-owned out-parameter.
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &raw mut limits) } != 0 {
        return;
    }
    if limits.rlim_cur >= TARGET {
        litebox_util_log::debug!(nofile:% = limits.rlim_cur; "nat: RLIMIT_NOFILE soft limit already sufficient");
        return;
    }
    let mut raised = if limits.rlim_max == libc::RLIM_INFINITY {
        TARGET
    } else {
        limits.rlim_max.min(TARGET)
    };
    loop {
        limits.rlim_cur = raised;
        // SAFETY: `limits` is a valid `rlimit` that outlives the call.
        if unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &raw const limits) } == 0 {
            litebox_util_log::debug!(nofile:% = raised; "nat: raised RLIMIT_NOFILE soft limit");
            return;
        }
        if raised <= 10240 {
            return;
        }
        raised /= 2;
    }
}

/// Return the process-wide pthread TSD key used for the guest thread pointer,
/// reserving it on the first call.
///
/// The key is assigned at runtime after libSystem has reserved its own dynamic
/// keys, so it is not predictable when an image is packaged. Host::MacOs gates
/// therefore read the key's byte offset from their trampoline header. Every
/// supported macOS ELF load path writes [guest_tp_slot_byte_offset] to that
/// header before making the trampoline executable; the rewriter's fixed slot
/// constant is only the on-disk seed.
///
/// # Panics
///
/// Panics only if pthread_key_create itself fails due to resource exhaustion.
fn reserve_guest_tpidr_tsd_slot() -> libc::pthread_key_t {
    *GUEST_TP_TSD_KEY.get_or_init(|| {
        let mut key: libc::pthread_key_t = 0;
        // SAFETY: key is a valid, uniquely-owned out-parameter; no destructor
        // is needed since the platform manages the guest thread pointer's
        // lifetime and keeps the key for the process lifetime.
        let rc = unsafe { libc::pthread_key_create(&raw mut key, None) };
        assert_eq!(
            rc, 0,
            "failed to reserve the guest thread-pointer TSD slot: pthread_key_create returned {rc}"
        );
        key
    })
}

/// The pthread TSD key [ArchSpecificRegister::TpidrEl0] accessors and
/// [guest_tp_slot_byte_offset] both address, or None before
/// [reserve_guest_tpidr_tsd_slot] has run.
///
/// [ArchSpecificRegister::TpidrEl0]: litebox::platform::ArchSpecificRegister::TpidrEl0
fn guest_tp_tsd_key() -> Option<libc::pthread_key_t> {
    GUEST_TP_TSD_KEY.get().copied()
}

/// The byte offset a `Host::MacOs` gate must add to `TPIDRRO_EL0` to reach this
/// process's guest thread-pointer slot, or `None` before
/// `reserve_guest_tpidr_tsd_slot` has run.
///
/// This is the number a loader writes into the trampoline's guest-TP header slot
/// so the ahead-of-time gates address the key this process actually reserved,
/// rather than the one the rewriter guessed at packaging time. Darwin's TSD array
/// is indexed by key with 8-byte elements and no low-bit masking on arm64
/// (verified against xnu's `libsyscall/os/tsd.h` `_os_tsd_get_base`), so the
/// offset is simply the key scaled by the element size -- the same key
/// [`ArchSpecificProvider::get_arch_specific_register`]/[`set_arch_specific_register`]
/// reach via `pthread_getspecific`/`pthread_setspecific` instead, since a gate is
/// raw bytes patched into an arbitrary guest binary and cannot call either.
///
/// [`ArchSpecificProvider::get_arch_specific_register`]: litebox::platform::ArchSpecificProvider::get_arch_specific_register
/// [`set_arch_specific_register`]: litebox::platform::ArchSpecificProvider::set_arch_specific_register
// This crate is aarch64-only (see the module docs), so `usize` is always 64
// bits wide and a `pthread_key_t` always fits; a fallible conversion here
// would only relocate an unreachable failure, never remove it.
#[allow(clippy::cast_possible_truncation)]
pub fn guest_tp_slot_byte_offset() -> Option<usize> {
    Some(guest_tp_tsd_key()? as usize * size_of::<usize>())
}

/// Runs a guest thread with the given shim and initial context, returning when
/// the thread terminates.
///
/// This is how a runner starts the *initial* guest thread; every thread the
/// guest creates afterwards arrives through
/// [`litebox::platform::ThreadProvider::spawn_thread`] instead. It mirrors
/// `litebox_platform_linux_userland::run_thread`, so a runner reads the same on
/// either host.
///
/// # Safety
///
/// `ctx` must be a valid, writable register context. Its guest `pc` or `sp` may
/// fault when execution begins; the platform routes that as a guest exception
/// rather than dereferencing either value in host switch code. Only one guest
/// thread may run at a time on this platform; a second is a loud panic rather
/// than corruption.
pub unsafe fn run_thread<T>(shim: T, ctx: &mut litebox_common_linux::PtRegs)
where
    T: litebox::shim::EnterShim<ExecutionContext = litebox_common_linux::PtRegs>,
{
    // The handle has to exist before the shim runs, not merely before the guest
    // does: `EnterShim::init` attaches an interrupt handle to the thread, which
    // reads `current_thread()`, and that panics on a thread this was never
    // called on. `spawn_thread` wraps its own entry the same way.
    ThreadHandle::run_with_handle(|| {
        with_signal_alt_stack(|| run_guest_thread(&shim, ctx));
    });
}

/// Constructing another platform must not invalidate a guest trampoline that
/// already captured the first platform's guest-TP byte offset.
#[cfg(test)]
#[test]
fn constructing_a_second_platform_preserves_guest_tp_slot_offset() {
    use litebox::platform::SystemInfoProvider as _;

    let first = MacOsUserland::new(None);
    let before = first
        .get_guest_tp_slot_offset()
        .expect("the first platform reserved the process key");
    let _second = MacOsUserland::new(None);
    let after = first
        .get_guest_tp_slot_offset()
        .expect("the process key remains reserved");
    assert_eq!(before, after);
}

/// The reserved key must convert into a byte offset the gates can actually use:
/// non-zero (offset zero is pthread TSD slot 0, live libpthread state) and scaled
/// by the 8-byte TSD element size.
#[cfg(test)]
#[test]
fn the_guest_tp_slot_offset_is_a_scaled_nonzero_byte_offset() {
    let key = reserve_guest_tpidr_tsd_slot();
    let offset = guest_tp_slot_byte_offset().expect("the key is recorded by now");
    assert_eq!(
        offset,
        usize::try_from(key).unwrap() * 8,
        "offset is the key scaled by 8"
    );
    assert_ne!(offset, 0, "offset zero would address live libpthread state");
}

/// Reserving the guest thread-pointer TSD key records the runtime-assigned key
/// that both the architecture-specific accessors and trampoline offset use.
#[cfg(test)]
#[test]
fn reserving_the_tsd_slot_records_the_runtime_key() {
    let key = reserve_guest_tpidr_tsd_slot();
    assert_eq!(
        GUEST_TP_TSD_KEY.get().copied(),
        Some(key),
        "the reserved key should be recorded for runtime trampoline patching"
    );
}

/// `ArchSpecificProvider::{get,set}_arch_specific_register` for `TpidrEl0`
/// route through `pthread_setspecific`/`pthread_getspecific` on
/// [`guest_tp_tsd_key`] -- the same key the rewriter's gates address via
/// `[TPIDRRO_EL0 + guest_tp_slot_byte_offset()]`. A value stored that way must
/// round-trip on this hardware, and a second read must not change it
/// (`macos-tpidr-archspecific-reconciliation`: this used to write a
/// disconnected thread-local instead).
#[cfg(test)]
#[test]
fn guest_tp_tsd_key_round_trips_a_pthread_specific_value() {
    reserve_guest_tpidr_tsd_slot();
    let key = guest_tp_tsd_key().expect("the key is recorded by now");

    // The process-wide key may have been used by an earlier test on this
    // harness thread. Clear it before checking the null baseline.
    // SAFETY: `key` is process-wide and live for this thread.
    assert_eq!(
        unsafe { libc::pthread_setspecific(key, core::ptr::null()) },
        0
    );
    // SAFETY: same live key and thread as the clear above.
    let initial = unsafe { libc::pthread_getspecific(key) };
    assert!(
        initial.is_null(),
        "a freshly reserved key starts null, matching clone(2)'s no-CLONE_SETTLS default"
    );

    let sentinel = 0xDEAD_BEEFusize as *mut libc::c_void;
    // SAFETY: `key` is a live, reserved key; storing an opaque pointer-sized
    // value has no precondition beyond that.
    assert_eq!(unsafe { libc::pthread_setspecific(key, sentinel) }, 0);
    // SAFETY: same key, same thread as the store above.
    assert_eq!(
        unsafe { libc::pthread_getspecific(key) },
        sentinel,
        "the value set_arch_specific_register would store must read back unchanged"
    );
    // Replay: a second read must not itself mutate the stored value.
    // SAFETY: same key, same thread.
    assert_eq!(unsafe { libc::pthread_getspecific(key) }, sentinel);

    // A guest fully controls this value (it is the argument to a guest-issued
    // `MSR TPIDR_EL0` or `clone(CLONE_SETTLS)`), so the full `usize` range
    // must survive the round trip losslessly -- no truncation at either the
    // `val as *const c_void` store or the `as usize` load.
    for adversarial in [0usize, usize::MAX, usize::MAX / 2] {
        let ptr = adversarial as *mut libc::c_void;
        // SAFETY: same key; an opaque store has no precondition on the value.
        assert_eq!(unsafe { libc::pthread_setspecific(key, ptr) }, 0);
        // SAFETY: same key, same thread as the store above.
        assert_eq!(
            unsafe { libc::pthread_getspecific(key) } as usize,
            adversarial,
            "boundary value {adversarial:#x} must round-trip without truncation"
        );
    }
}

/// Two threads sharing the SAME reserved key must observe independent
/// values -- the disjointness property a real deployment depends on, since
/// [`reserve_guest_tpidr_tsd_slot`] reserves one key for the whole process and
/// every guest thread's [`ArchSpecificProvider::set_arch_specific_register`]
/// writes through it. A shared global instead of per-thread TSD storage would
/// let one guest thread's `TPIDR_EL0` leak into another's. A `Barrier` forces
/// both threads' writes to land before either reads back, so the assertion
/// cannot pass merely because of a lucky non-overlapping schedule.
///
/// [`ArchSpecificProvider::set_arch_specific_register`]: litebox::platform::ArchSpecificProvider::set_arch_specific_register
#[cfg(test)]
#[test]
fn guest_tp_tsd_key_is_disjoint_across_threads() {
    reserve_guest_tpidr_tsd_slot();
    let key = guest_tp_tsd_key().expect("the key is recorded by now");
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));

    let b1 = std::sync::Arc::clone(&barrier);
    let t1 = std::thread::Builder::new()
        .spawn(move || {
            let sentinel = 0x1111_1111usize as *mut libc::c_void;
            // SAFETY: `key` is a live, process-wide-reserved key; each thread
            // owns its own TSD slot for it.
            assert_eq!(unsafe { libc::pthread_setspecific(key, sentinel) }, 0);
            b1.wait();
            // SAFETY: same key, same thread as the store above.
            assert_eq!(unsafe { libc::pthread_getspecific(key) }, sentinel);
        })
        .expect("failed to spawn thread 1");

    let b2 = std::sync::Arc::clone(&barrier);
    let t2 = std::thread::Builder::new()
        .spawn(move || {
            let sentinel = 0x2222_2222usize as *mut libc::c_void;
            // SAFETY: `key` is a live, process-wide-reserved key; each thread
            // owns its own TSD slot for it.
            assert_eq!(unsafe { libc::pthread_setspecific(key, sentinel) }, 0);
            b2.wait();
            // SAFETY: same key, same thread as the store above.
            assert_eq!(unsafe { libc::pthread_getspecific(key) }, sentinel);
        })
        .expect("failed to spawn thread 2");

    t1.join().expect("thread 1 panicked");
    t2.join().expect("thread 2 panicked");
}

// ---------------------------------------------------------------------------
// Faults
// ---------------------------------------------------------------------------

/// Install the handlers that make LiteBox's accesses to guest memory fallible,
/// and that route a genuine guest hardware fault to
/// [`litebox::shim::EnterShim::exception`] instead of taking the whole process
/// down.
///
/// Without these, a `UserConstPtr` read of an unmapped guest address takes the
/// process down instead of returning `None`; see
/// [`litebox::platform::common_providers::userspace_pointers`].
///
/// `INTERRUPT_SIGNAL` is masked for the duration of both handlers -- see
/// `darwin::install_handler`'s doc comment -- so a cross-thread
/// `ThreadHandle::interrupt` call can never nest an interrupt-delivery signal
/// atop an in-flight fault delivery and race the same process-global
/// guest-entry state (`guest::GUEST_OWNS_CPU`/`LIVE_PTREGS`/`GUEST_FP`/
/// `PENDING_EXCEPTION_INFO`).
/// `SIGILL` is installed alongside the memory faults because a guest can raise
/// it deliberately and expect to survive: probing for an optional CPU feature by
/// executing an instruction from it and catching the resulting `SIGILL` is a
/// real, widespread idiom. Node's bundled OpenSSL does exactly this with
/// `sm3partw1` (`_armv8_sm3_probe`), and Apple Silicon implements no
/// FEAT_SM3/FEAT_SM4, so the instruction genuinely traps. Without a handler here
/// that trap killed the whole runner instead of reaching the guest's own
/// handler. Nothing downstream needed changing: an undefined instruction raises
/// ESR exception class 0 (`UNKNOWN`), which
/// `litebox_shim_linux::syscalls::signal::aarch64::exception_signal` already
/// maps to `Signal::SIGILL`, mirroring the kernel's own `do_el0_undef`.
pub(crate) fn install_fault_handlers() {
    init_synthetic_ctr_el0();
    for signum in [libc::SIGSEGV, libc::SIGBUS, libc::SIGILL] {
        darwin::install_handler(
            signum,
            fault_handler as *const () as usize,
            true,
            &[INTERRUPT_SIGNAL],
        );
    }
}

/// A synthetic `CTR_EL0` (cache type register) value, computed once at
/// start-up and served to a guest that reads `CTR_EL0` from EL0.
///
/// Apple Silicon leaves `SCTLR_EL1.UCT` clear, so a guest `mrs Xt, CTR_EL0`
/// -- the standard way code computes the cache-line stride for its own
/// instruction-cache maintenance (`__clear_cache`, which every AArch64 JIT and
/// libgcc's own cache-sync routine call after writing code) -- traps to
/// `SIGILL` instead of returning a value. The host itself cannot read the real
/// register either (same EL, same restriction), so the value is synthesized
/// from the cache-line size the kernel *does* expose via `sysctl`, and
/// [`fault_handler`] emulates the read. See `fault_handler`'s own comment.
fn init_synthetic_ctr_el0() {
    // `hw.cachelinesize` is the coherency granule in bytes. `CTR_EL0` encodes
    // I/D minimum line sizes as log2 of the number of 4-byte *words*.
    let line_bytes = darwin::sysctl_u64(c"hw.cachelinesize")
        .unwrap_or(64)
        .max(16);
    let words = (line_bytes / 4).max(1);
    let log2_words = u64::from(u64::BITS - 1 - words.leading_zeros());
    // Only `IminLine` [3:0] and `DminLine` [19:16] matter to `__clear_cache`'s
    // stride; deriving both from the coherency granule can only *over*-flush
    // (a stride no larger than the true line), which is always safe. Bit 31 is
    // RES1. `L1Ip` [15:14] = 0b11 (PIPT), the Apple Silicon value, so a reader
    // that inspects it draws no wrong conclusion about aliasing.
    let ctr = (1u64 << 31) | (log2_words << 16) | (0b11u64 << 14) | log2_words;
    JIT_FAULT.synthetic_ctr_el0.store(ctr, Ordering::Relaxed);
}

/// Decodes `insn` as `mrs Xt, CTR_EL0` and returns the destination register
/// index `t`, or `None`. The fixed bits are `mrs Xt, S3_3_C0_C0_1`; only the
/// low five (`Rt`) vary.
fn decode_mrs_ctr_el0(insn: u32) -> Option<u32> {
    if insn & 0xffff_ffe0 == 0xd53b_0020 {
        Some(insn & 0x1f)
    } else {
        None
    }
}

fn decode_faulted_svc_gate(pc: usize) -> Option<usize> {
    const SUB_SP_16: u32 = 0xd100_43ff;
    const STR_X16_SP: u32 = 0xf900_03f0;
    const STR_X16_SP_8: u32 = 0xf900_07f0;
    const ADRP_X16_MASK: u32 = 0x9f00_001f;
    const ADRP_X16: u32 = 0x9000_0010;
    const ADD_X16_X16_MASK: u32 = 0xffc0_03ff;
    const ADD_X16_X16: u32 = 0x9100_0210;
    const B_MASK: u32 = 0xfc00_0000;
    const B: u32 = 0x1400_0000;

    if !pc.is_multiple_of(4) {
        return None;
    }
    let gate = pc.checked_sub(4)?;
    let words = darwin::read_task_u32s::<6>(gate)?;
    if words[0] != SUB_SP_16
        || words[1] != STR_X16_SP
        || words[2] & ADRP_X16_MASK != ADRP_X16
        || words[3] & ADD_X16_X16_MASK != ADD_X16_X16
        || words[4] != STR_X16_SP_8
        || words[5] & B_MASK != B
    {
        return None;
    }

    let immlo = (words[2] >> 29) & 0x3;
    let immhi = (words[2] >> 5) & 0x7ffff;
    let imm21 = (immhi << 2) | immlo;
    let page_delta = ((u64::from(imm21) << 43).cast_signed() >> 43) << 12;
    let adrp_pc = gate.checked_add(8)?;
    let target_page = (adrp_pc & !0xfff).checked_add_signed(isize::try_from(page_delta).ok()?)?;
    let continuation = target_page.checked_add(((words[3] >> 10) & 0xfff) as usize)?;
    continuation.is_multiple_of(4).then_some(continuation)
}

unsafe extern "C" fn fault_handler(
    signum: libc::c_int,
    _info: *mut libc::siginfo_t,
    ucontext: *mut libc::c_void,
) {
    // SAFETY: the kernel hands a `ucontext_t` to an `SA_SIGINFO` handler, and
    // its `uc_mcontext` points at a `_STRUCT_MCONTEXT64` on this architecture.
    let machine_context = unsafe {
        let ucontext = ucontext.cast::<libc::ucontext_t>();
        if ucontext.is_null() {
            darwin::reraise_fatally(signum);
            return;
        }
        (*ucontext).uc_mcontext.cast::<darwin::McontextPrefix64>()
    };
    if machine_context.is_null() {
        darwin::reraise_fatally(signum);
        return;
    }

    // SAFETY: checked non-null just above.
    let pc = unsafe { (*machine_context).thread_state.pc };

    // Fault-driven W^X toggle for a guest that writes its own machine code
    // into a `MAP_JIT` region (a JIT engine: V8). Darwin makes such a region
    // writable *or* executable per thread, never both, and stock V8 (which
    // dropped `--write-protect-code-memory` in v11.1, and whose Linux/aarch64
    // build compiles out every write-protect API) just stores code and jumps
    // to it as if the pages were plain RWX. Under this host the store faults
    // with a *write permission fault* (the page is execute-only for this
    // thread) and the jump-to-fresh-code faults with an *instruction
    // permission fault* (the page is writable-only). Resolve both by toggling
    // this thread's write-protect the matching way and letting the faulting
    // instruction re-run; no guest signal is delivered.
    //
    // Gated on the exact permission-fault status codes so an unrelated fault
    // that merely lands in a JIT address range (a wild pointer, an illegal
    // instruction, a BTI failure) is not swallowed -- it falls through to the
    // normal guest-fault path below. The toggle direction is fully determined
    // by the fault type, which is self-consistent (a write fault can only
    // occur when not writable; an instruction permission fault only when not
    // executable), so this cannot loop for legitimate JIT access; the
    // registry is cleared on `deallocate_pages`, so a stale entry cannot
    // either.
    //
    // SAFETY: checked non-null just above.
    let guest_state = guest::current_guest_state();
    if guest::guest_owns_cpu(guest_state) {
        // SAFETY: non-null machine context, checked above.
        let esr = u64::from(unsafe { (*machine_context).exception_state.esr });
        // SAFETY: non-null machine context, checked above.
        let far = unsafe { (*machine_context).exception_state.far };
        let ec = (esr >> 26) & 0x3f;
        let fsc = esr & 0x3f;
        let is_permission_fault = (0x0c..=0x0f).contains(&fsc);
        // Data abort (EC 0x24/0x25) with the write bit set: guest is writing
        // code into a JIT page that is currently executable.
        let is_write = matches!(ec, 0x24 | 0x25) && (esr >> 6) & 1 == 1;
        // Instruction abort (EC 0x20/0x21): guest is executing a JIT page that
        // is currently writable.
        let is_exec = matches!(ec, 0x20 | 0x21);
        if is_permission_fault && is_write && addr_in_jit_region(far.trunc()) {
            // SAFETY: makes JIT mappings writable for this thread; the
            // faulting store re-runs and succeeds. No JIT code executes before
            // the paired exec fault toggles it back.
            unsafe { jit_write_protect(false) };
            return;
        }
        if is_permission_fault && is_exec && addr_in_jit_region(pc.trunc()) {
            // SAFETY: makes JIT mappings executable for this thread; the
            // faulting branch/fetch re-runs and succeeds.
            unsafe { jit_write_protect(true) };
            return;
        }

        if ec == 0x24
            && is_write
            && let Some(continuation) = decode_faulted_svc_gate(pc.trunc())
        {
            let recovery = unsafe {
                guest::prepare_faulted_syscall_delivery(
                    guest_state,
                    &(*machine_context).thread_state,
                    &(*machine_context).neon_state,
                    continuation,
                )
            };
            unsafe { (*machine_context).thread_state.pc = recovery as u64 };
            return;
        }

        // Emulate a trapped `mrs Xt, CTR_EL0`. Apple Silicon leaves
        // `SCTLR_EL1.UCT` clear, so reading the cache type register from EL0
        // traps -- but it is exactly what `__clear_cache` reads to size its
        // instruction-cache maintenance loop, so every AArch64 JIT (V8) and
        // libgcc's own cache-sync path hits it right after writing code, and a
        // real guest cannot proceed without an answer. Supply the synthesized
        // value (see `JitFaultGlobals::synthetic_ctr_el0`) and step over the instruction.
        //
        // Only for the exception classes where a validly-fetched instruction
        // trapped: `0x00` (unknown -- how Darwin surfaces an EL0 system-register
        // trap as `SIGILL`, and also a plain undefined instruction) and `0x18`
        // (a trapped `MSR`/`MRS`). Crucially *not* an instruction or data
        // abort (`0x20`-`0x25`): those can carry a `pc` that is itself
        // unmapped -- a guest that branches to a null or wild pointer -- and
        // reading the instruction word there would fault the handler
        // recursively. Decoding the instruction (rather than trusting the
        // signal) still keeps this precise: OpenSSL's `sm3partw1` feature
        // probe is also `ec == 0x00` but decodes to `None` and falls through
        // to real guest `SIGILL` delivery.
        let pc_addr: usize = pc.trunc();
        let insn = if matches!(ec, 0x00 | 0x18) && pc_addr != 0 {
            // SAFETY: `ec` says a validly-fetched instruction trapped, so `pc`
            // addresses live, executable guest memory; reading its 4 bytes is
            // valid.
            unsafe { core::ptr::read(pc_addr as *const u32) }
        } else {
            0 // decodes to `None`
        };
        if let Some(rt) = decode_mrs_ctr_el0(insn) {
            let ctr = JIT_FAULT.synthetic_ctr_el0.load(Ordering::Relaxed);
            // `x0`-`x28` live in the `x` array; `x29`/`x30` are the separate
            // `fp`/`lr` fields; `x31` in this position is the zero register
            // (the write is discarded).
            // SAFETY: non-null machine context, checked above; index bounds
            // enforced by the match.
            unsafe {
                let ts = &mut (*machine_context).thread_state;
                match rt {
                    0..=28 => ts.x[rt as usize] = ctr,
                    29 => ts.fp = ctr,
                    30 => ts.lr = ctr,
                    _ => {} // x31 == xzr: discard.
                }
                // Step past the emulated instruction.
                ts.pc = pc + 4;
            }
            return;
        }
    }

    if let Some(recovery) = litebox::mm::exception_table::search_exception_tables(pc.trunc()) {
        // A LiteBox access to guest memory faulted -- either one of this
        // crate's own recoverable accesses to guest memory, or one of
        // `guest::GUEST_OWNS_CPU`'s boundary windows -- and the exception
        // table says where to continue; redirecting the program counter is
        // what turns the fault into either a `None` return or a loud abort.
        // This check always takes priority over the GUEST_OWNS_CPU check
        // below: every guest-memory touch this platform's own switch code
        // makes while that flag could read true is covered by an entry here,
        // which is exactly what makes the flag-based check below safe.
        //
        // SAFETY: checked non-null just above.
        unsafe { (*machine_context).thread_state.pc = recovery as u64 };
        return;
    }

    // Per-thread: null on any thread that is not inside `guest::run_thread`,
    // and each guest thread's own state is disjoint from every other's.
    let guest_state = guest::current_guest_state();
    if guest::guest_owns_cpu(guest_state) {
        // The exception table missed and the guest genuinely owns the CPU at
        // this pc (not merely mid-switch -- see the ordering note above), so
        // this is a real guest fault: hand it to the guest via
        // `EnterShim::exception` instead of taking the process down.
        //
        // SAFETY: checked non-null just above.
        let (thread_state, exception_state, neon_state) = unsafe {
            (
                &(*machine_context).thread_state,
                &(*machine_context).exception_state,
                &(*machine_context).neon_state,
            )
        };
        let esr = u64::from(exception_state.esr);
        let info = litebox::shim::ExceptionInfo {
            // ESR_EL1's exception class occupies bits [31:26]; see
            // `litebox::shim::ExceptionInfo::exception`'s own doc comment.
            exception: litebox::shim::Exception(((esr >> 26) & 0x3f) as u8),
            fault_address: exception_state.far.trunc(),
            esr,
            // This platform's guest always runs at EL0; there is no
            // "kernel-mode access faulted" case for a userland host to model.
            kernel_mode: false,
        };
        // SAFETY: `guest_owns_cpu` just returned true, which also means
        // `guest_state` is this thread's own non-null live state -- this
        // function's own documented precondition.
        let recovery = unsafe {
            guest::prepare_exception_delivery(guest_state, thread_state, neon_state, info)
        };
        // SAFETY: checked non-null just above.
        unsafe { (*machine_context).thread_state.pc = recovery as u64 };
        return;
    }

    // Not a recoverable LiteBox access, and not a genuine guest fault either.
    // Restore the default disposition and return so the faulting instruction
    // re-executes and takes the process down exactly as it would have without
    // this handler installed.
    darwin::reraise_fatally(signum);
}

/// Detects heap activity performed *inside* [`fault_handler`] or
/// [`interrupt_signal_handler`], so a test can assert that this platform's
/// fault- and interrupt-delivery paths stay async-signal-safe.
///
/// Everything reachable from a POSIX signal handler must be async-signal-safe,
/// and `malloc`/`free` are the canonical counter-example: Darwin's allocator
/// takes a non-reentrant `os_unfair_lock`, so allocating in a handler that
/// interrupted the same thread mid-`malloc` deadlocks the process. The
/// interesting allocations are not this crate's own explicit ones (there are
/// none on that path) but the *hidden* ones a future edit could reintroduce --
/// a `format!`, a `Vec`, or a logging macro whose backend allocates. A
/// pass-through [`core::alloc::GlobalAlloc`] catches all of them uniformly,
/// which is why this is an allocator rather than a call-site assertion.
///
/// "Inside a handler" is detected from the signal mask rather than from a flag
/// the handler sets, because the handler must not be modified to be
/// measurable: [`install_fault_handlers`] installs `SIGSEGV`/`SIGBUS` with
/// `sa_mask = { INTERRUPT_SIGNAL }` and without `SA_NODEFER`, so the kernel
/// runs [`fault_handler`] with both the delivered fault signal *and*
/// [`INTERRUPT_SIGNAL`] blocked; [`install_async_signal_handlers`] installs
/// `INTERRUPT_SIGNAL` with `sa_mask = { SIGSEGV, SIGBUS }`, so
/// [`interrupt_signal_handler`] runs with the same combination in force.
/// Nothing else in this crate ever blocks any of the three
/// ([`block_guest_signals`] blocks only `SIGINT`/`SIGALRM`), so that
/// combination is a precise, self-updating test for "the calling thread is
/// executing one of this platform's guest-delivery signal handlers right now"
/// -- and it keeps working unchanged if the masks are ever widened further.
///
/// The mask query is a real syscall, so it only runs while
/// [`ProbeAllocator::arm`] has turned it on; outside that window every
/// allocation in the test binary pays one relaxed atomic load.
///
/// The probe's own state lives in [`ProbeAllocator`]'s fields rather than in
/// free `static`s purely to keep `dev_tests`' `ratchet_globals` count honest:
/// `#[global_allocator]` requires exactly one `static`, and there is no reason
/// for this test scaffolding to cost three.
#[cfg(test)]
mod signal_handler_alloc_probe {
    use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    /// Whether the calling thread is currently running
    /// [`super::fault_handler`] or [`super::interrupt_signal_handler`], per
    /// this module's doc comment.
    fn inside_signal_handler() -> bool {
        // SAFETY: `current` is fully initialized by `sigemptyset` before
        // `pthread_sigmask` writes it, a null `set` argument makes the call a
        // pure query, and `sigismember` only reads it.
        unsafe {
            let mut current: libc::sigset_t = core::mem::zeroed();
            libc::sigemptyset(&raw mut current);
            if libc::pthread_sigmask(libc::SIG_BLOCK, core::ptr::null(), &raw mut current) != 0 {
                return false;
            }
            libc::sigismember(&raw const current, super::INTERRUPT_SIGNAL) == 1
                && (libc::sigismember(&raw const current, libc::SIGSEGV) == 1
                    || libc::sigismember(&raw const current, libc::SIGBUS) == 1)
        }
    }

    /// The pass-through allocator this module installs for the test binary.
    pub(crate) struct ProbeAllocator {
        /// Whether each allocation should be checked. Off outside a test that
        /// explicitly asked for the check.
        armed: AtomicBool,
        /// How many allocations were made from inside a signal handler while
        /// armed.
        inside_handler: AtomicUsize,
    }

    impl ProbeAllocator {
        pub(crate) const fn new() -> Self {
            Self {
                armed: AtomicBool::new(false),
                inside_handler: AtomicUsize::new(0),
            }
        }

        /// Records one allocation if it is happening inside a signal handler.
        fn note_allocation(&self) {
            if self.armed.load(Ordering::Relaxed) && inside_signal_handler() {
                self.inside_handler.fetch_add(1, Ordering::Relaxed);
            }
        }

        /// Starts checking, resetting the count first so each armed window
        /// reports only its own allocations.
        pub(crate) fn arm(&self) {
            self.inside_handler.store(0, Ordering::Relaxed);
            self.armed.store(true, Ordering::Relaxed);
        }

        /// Stops checking and reports how many allocations happened inside a
        /// signal handler since [`Self::arm`].
        pub(crate) fn disarm(&self) -> usize {
            self.armed.store(false, Ordering::Relaxed);
            self.inside_handler.load(Ordering::Relaxed)
        }
    }

    // SAFETY: every method forwards to `std::alloc::System` with the caller's
    // own arguments unchanged, so the allocator contract is exactly
    // `System`'s; `note_allocation` neither allocates nor touches the
    // returned block.
    unsafe impl core::alloc::GlobalAlloc for ProbeAllocator {
        unsafe fn alloc(&self, layout: core::alloc::Layout) -> *mut u8 {
            self.note_allocation();
            // SAFETY: forwarded caller guarantee.
            unsafe { core::alloc::GlobalAlloc::alloc(&std::alloc::System, layout) }
        }

        unsafe fn alloc_zeroed(&self, layout: core::alloc::Layout) -> *mut u8 {
            self.note_allocation();
            // SAFETY: forwarded caller guarantee.
            unsafe { core::alloc::GlobalAlloc::alloc_zeroed(&std::alloc::System, layout) }
        }

        unsafe fn dealloc(&self, ptr: *mut u8, layout: core::alloc::Layout) {
            self.note_allocation();
            // SAFETY: forwarded caller guarantee.
            unsafe { core::alloc::GlobalAlloc::dealloc(&std::alloc::System, ptr, layout) }
        }

        unsafe fn realloc(
            &self,
            ptr: *mut u8,
            layout: core::alloc::Layout,
            new_size: usize,
        ) -> *mut u8 {
            self.note_allocation();
            // SAFETY: forwarded caller guarantee.
            unsafe { core::alloc::GlobalAlloc::realloc(&std::alloc::System, ptr, layout, new_size) }
        }
    }
}

/// See [`signal_handler_alloc_probe`]; only the crate's own test binary gets
/// this allocator, production builds keep the default one.
#[cfg(test)]
#[global_allocator]
static PROBE_ALLOCATOR: signal_handler_alloc_probe::ProbeAllocator =
    signal_handler_alloc_probe::ProbeAllocator::new();

/// Page faults are serviced by the host kernel, so LiteBox never handles one
/// itself here. Provided to satisfy the trait bound on `PageManager`.
impl litebox::mm::vmem::VmemPageFaultHandler for MacOsUserland {
    unsafe fn handle_page_fault(
        &self,
        _fault_addr: usize,
        _flags: litebox::mm::vmem::VmFlags,
        _error_code: u64,
    ) -> Result<(), litebox::mm::vmem::PageFaultError> {
        unreachable!("host kernel handles page faults for macOS userland")
    }

    fn access_error(_error_code: u64, _flags: litebox::mm::vmem::VmFlags) -> bool {
        unreachable!("host kernel handles page faults for macOS userland")
    }
}

// ---------------------------------------------------------------------------
// Guest-directed signal delivery
// ---------------------------------------------------------------------------

/// Guard page below the alternate signal stack, sized to this platform's 16
/// KiB pages so a stack-overflowing handler faults instead of corrupting
/// whatever mapping [`with_signal_alt_stack`] happened to place below it.
const ALT_STACK_GUARD_SIZE: usize = litebox::mm::vmem::PAGE_SIZE;

/// Runs `f` with an alternate signal stack installed on the calling thread.
///
/// Guest execution owns the hardware `SP`, and a hardware fault may mean that
/// guest-controlled value is itself unmapped. A host signal handler therefore
/// cannot safely run on the interrupted stack. `darwin::install_handler` sets
/// `SA_ONSTACK` on every handler this platform installs, but that flag only
/// takes effect once a thread has registered a stack for it to use. Every entry
/// point that can run guest code
/// ([`ThreadProvider::spawn_thread`](litebox::platform::ThreadProvider::spawn_thread)
/// and the free [`run_thread`]) wraps its call in this so registration always
/// happens first.
fn with_signal_alt_stack<R>(f: impl FnOnce() -> R) -> R {
    let alt_stack_size = libc::SIGSTKSZ * 2;
    // SAFETY: an anonymous mapping with no fixed-address request has no
    // precondition beyond what `mmap` itself checks.
    let stack_base = unsafe {
        libc::mmap(
            core::ptr::null_mut(),
            ALT_STACK_GUARD_SIZE + alt_stack_size,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANON,
            -1,
            0,
        )
    };
    assert!(
        stack_base != libc::MAP_FAILED,
        "failed to allocate the alternate signal stack: {}",
        std::io::Error::last_os_error()
    );
    let _unmap_guard = litebox::utils::defer(|| {
        // SAFETY: `stack_base` is the mapping created above, unmapped exactly
        // once here.
        let rc = unsafe { libc::munmap(stack_base, ALT_STACK_GUARD_SIZE + alt_stack_size) };
        assert!(
            rc == 0,
            "failed to unmap the alternate signal stack: {}",
            std::io::Error::last_os_error()
        );
    });

    // SAFETY: `stack_base` is a live mapping of at least `ALT_STACK_GUARD_SIZE`
    // bytes, still solely owned by this function.
    let rc = unsafe { libc::mprotect(stack_base, ALT_STACK_GUARD_SIZE, libc::PROT_NONE) };
    assert!(
        rc == 0,
        "failed to guard the alternate signal stack: {}",
        std::io::Error::last_os_error()
    );

    let alt_stack = libc::stack_t {
        // SAFETY: `stack_base` addresses a mapping at least
        // `ALT_STACK_GUARD_SIZE + alt_stack_size` bytes long, so this stays
        // within it.
        ss_sp: unsafe { stack_base.add(ALT_STACK_GUARD_SIZE) },
        ss_size: alt_stack_size,
        ss_flags: 0,
    };
    // SAFETY: a zeroed `stack_t` is a valid, if meaningless, initial value;
    // `sigaltstack` below overwrites every field that matters.
    let mut previous: libc::stack_t = unsafe { core::mem::zeroed() };
    // SAFETY: `alt_stack` addresses the mapping above, which outlives this
    // call; `previous` is a live, correctly typed out-parameter.
    let rc = unsafe { libc::sigaltstack(&raw const alt_stack, &raw mut previous) };
    assert!(
        rc == 0,
        "failed to install the alternate signal stack: {}",
        std::io::Error::last_os_error()
    );
    let _restore_guard = litebox::utils::defer(|| {
        // SAFETY: `previous` was filled in by the `sigaltstack` call above and
        // describes whatever stack (if any) this thread had before it.
        let rc = unsafe { libc::sigaltstack(&raw const previous, core::ptr::null_mut()) };
        assert!(
            rc == 0,
            "failed to restore the previous signal stack: {}",
            std::io::Error::last_os_error()
        );
    });

    f()
}

#[cfg(test)]
fn current_signal_stack() -> libc::stack_t {
    // SAFETY: a null `ss` argument only queries the current stack, it does not
    // install one.
    unsafe {
        let mut oss: libc::stack_t = core::mem::zeroed();
        libc::sigaltstack(core::ptr::null(), &raw mut oss);
        oss
    }
}

/// Rust's own runtime already installs a guard-page alternate stack on every
/// thread it starts (for its stack-overflow handler), so a fresh test thread
/// does *not* reliably start with [`libc::SS_DISABLE`] -- this compares
/// against whatever `before` actually was rather than assuming it is
/// disabled.
#[cfg(test)]
#[test]
fn with_signal_alt_stack_actually_registers_one() {
    // `with_signal_alt_stack` does a real host `mmap`/`munmap` of its own,
    // which can race `allocate_jit_pages_hint_honors_the_suggested_address`'s
    // address-space probing under the parallel test harness; serialize
    // against it the same way guest-entry tests already do.
    let _serial = guest::tests::TEST_SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);

    let before = current_signal_stack();
    let during = with_signal_alt_stack(current_signal_stack);
    let after = current_signal_stack();

    assert_ne!(
        during.ss_sp, before.ss_sp,
        "with_signal_alt_stack must install a stack distinct from whatever \
         (if any) the thread already had"
    );
    assert_eq!(
        during.ss_flags & libc::SS_DISABLE,
        0,
        "the installed stack must actually be enabled"
    );
    assert!(
        during.ss_size >= libc::SIGSTKSZ,
        "the installed stack must be large enough to actually run a handler"
    );
    assert_eq!(
        (after.ss_sp, after.ss_size, after.ss_flags),
        (before.ss_sp, before.ss_size, before.ss_flags),
        "the previous stack (if any) must be restored exactly once f returns"
    );
}
