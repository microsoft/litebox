//! A [LiteBox platform](../litebox/platform/index.html) for running LiteBox on userland Linux.

// Restrict this crate to only work on Linux. For now, we are restricting this to only x86-64 Linux,
// but we _may_ allow for more in the future, if we find it useful to do so.
#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use std::os::fd::{AsRawFd as _, FromRawFd as _};
use std::sync::atomic::AtomicU32;
use std::sync::atomic::Ordering::SeqCst;
use std::time::Duration;

use litebox::platform::ImmediatelyWokenUp;
use litebox::platform::UnblockedOrTimedOut;
use litebox::platform::page_mgmt::MemoryRegionPermissions;

mod syscall_intercept;

/// The userland Linux platform.
///
/// This implements the main [`litebox::platform::Provider`] trait, i.e., implements all platform
/// traits. Notably, however, it supports parametric punchtrough (defaulted to impossible
/// punchtrough).
pub struct LinuxUserland<PunchthroughProvider: litebox::platform::PunchthroughProvider = litebox::platform::trivial_providers::ImpossiblePunchthroughProvider> {
    tun_socket_fd: Option<std::os::fd::OwnedFd>,
    punchthrough_provider: PunchthroughProvider,
}

impl<PunchthroughProvider: litebox::platform::PunchthroughProvider>
    LinuxUserland<PunchthroughProvider>
{
    /// Create a new userland-Linux platform for use in `LiteBox`.
    ///
    /// Takes an optional tun device name (such as `"tun0"` or `"tun99"`) to connect networking (if
    /// not specified, networking is disabled).
    ///
    /// Registers `syscall_handler` to handle all intercepted syscalls.
    ///
    /// # Panics
    ///
    /// Panics if the tun device could not be successfully opened.
    pub fn new(
        tun_device_name: Option<&str>,
        punchthrough_provider: PunchthroughProvider,
        syscall_handler: impl Fn(litebox_common_linux::SyscallRequest<LinuxUserland>) -> i64
        + Send
        + Sync
        + 'static,
    ) -> Self {
        // TODO: have better signature and registration of the syscall handler.
        syscall_intercept::init_sys_intercept(syscall_handler);

        let tun_socket_fd = tun_device_name.map(|tun_device_name| {
            let tun_fd = nix::fcntl::open(
                "/dev/net/tun",
                nix::fcntl::OFlag::O_RDWR
                    | nix::fcntl::OFlag::O_CLOEXEC
                    | nix::fcntl::OFlag::O_NONBLOCK,
                nix::sys::stat::Mode::empty(),
            )
            .unwrap();

            nix::ioctl_write_ptr!(tunsetiff, b'T', 202, ::core::ffi::c_int);
            let ifreq = libc::ifreq {
                ifr_name: {
                    let mut name = [0i8; 16];
                    assert!(tun_device_name.len() < 16); // Note: strictly-less-than 16, to ensure it fits
                    for (i, b) in tun_device_name.char_indices() {
                        let b = b as u32;
                        assert!(b < 128);
                        name[i] = i8::try_from(b).unwrap();
                    }
                    name
                },
                ifr_ifru: nix::libc::__c_anonymous_ifr_ifru {
                    ifru_flags: i16::try_from(nix::libc::IFF_TUN).unwrap(),
                },
            };
            let ifreq: *const libc::ifreq = &ifreq as _;
            let ifreq: *const i32 = ifreq.cast();
            unsafe { tunsetiff(tun_fd, ifreq) }.unwrap();

            // By taking ownership, we are letting the drop handler automatically run `libc::close`
            // when necessary.
            unsafe { std::os::fd::OwnedFd::from_raw_fd(tun_fd) }
        });

        Self {
            tun_socket_fd,
            punchthrough_provider,
        }
    }
}

impl<PunchthroughProvider: litebox::platform::PunchthroughProvider> litebox::platform::Provider
    for LinuxUserland<PunchthroughProvider>
{
}

impl<PunchthroughProvider: litebox::platform::PunchthroughProvider>
    litebox::platform::RawMutexProvider for LinuxUserland<PunchthroughProvider>
{
    type RawMutex = RawMutex;

    fn new_raw_mutex(&self) -> Self::RawMutex {
        RawMutex {
            inner: AtomicU32::new(0),
            num_to_wake_up: AtomicU32::new(0),
        }
    }
}

// This raw-mutex design takes up more space than absolutely ideal and may possibly be optimized if
// we can allow for spurious wake-ups. However, the current design makes sure that spurious wake-ups
// do not actually occur, and that something that is `block`ed can only be woken up by a `wake`.
pub struct RawMutex {
    // The `inner` is the value shown to the outside world as an underlying atomic.
    inner: AtomicU32,
    // The `num_to_wake_up` is the actually what the futexes rely upon, and is a bit-field.
    //
    // The uppermost two bits (1<<31, and 1<<30) act as a "lock bit" for the waker (we use two of
    // them to make it easier to catch accidental integer wrapping bugs more easily, at the cost of
    // supporting "only" 1-billion waiters being woken up at once), preventing multiple wakers from
    // running at the same time.
    //
    // The lower 30 bits indicate how many waiters the waker wants to wake up. The waiters
    // themselves will decrement this number as they wake up, but should make sure not to overflow
    // (this is why we use two bits for the lock bit---to catch implementation bugs of this kind).
    num_to_wake_up: AtomicU32,
}

fn latest_errno() -> i32 {
    unsafe { *libc::__errno_location() }
}

impl RawMutex {
    fn block_or_maybe_timeout(
        &self,
        val: u32,
        timeout: Option<Duration>,
    ) -> Result<UnblockedOrTimedOut, ImmediatelyWokenUp> {
        // We immediately wake up (without even hitting syscalls) if we can clearly see that the
        // value is different.
        if self.inner.load(SeqCst) != val {
            return Err(ImmediatelyWokenUp);
        }

        // Track some initial information.
        let mut first_time = true;
        let start = std::time::Instant::now();

        // We'll be looping unless we find a good reason to exit out of the loop, either due to a
        // wake-up or a time-out. We do a singular (only as a one-off) check for the
        // immediate-wake-up purely as an optimization, but otherwise, the only way to exit this
        // loop is to actually hit an `Ok` state out for this function.
        loop {
            let remaining_time = match timeout {
                None => None,
                Some(timeout) => match timeout.checked_sub(start.elapsed()) {
                    None => {
                        break Ok(UnblockedOrTimedOut::TimedOut);
                    }
                    Some(remaining_time) => Some(remaining_time),
                },
            };

            // We wait on the futex, with a timeout if needed; the timeout is based on how much time
            // remains to be elapsed.
            match futex_timeout(
                &self.num_to_wake_up,
                FutexOperation::Wait,
                /* expected value */ 0,
                remaining_time,
                /* ignored */ None,
                /* ignored */ 0,
            ) {
                0 => {
                    // Fallthrough: check if spurious.
                }
                -1 => {
                    let errno = latest_errno();
                    if errno == libc::EAGAIN {
                        // A wake-up was already in progress when we attempted to wait. Has someone
                        // already touched inner value? We only check this on the first time around,
                        // anything else could be a true wake.
                        if first_time && self.inner.load(SeqCst) != val {
                            // Ah, we seem to have actually been immediately woken up! Let us not
                            // miss this.
                            return Err(ImmediatelyWokenUp);
                        } else {
                            // Fallthrough: check if spurious. A wake-up was already in progress
                            // when we attempted to wait, so we can do a proper check.
                        }
                    } else {
                        panic!("Unexpected errno={errno} for FUTEX_WAIT")
                    }
                }
                _ => unreachable!(),
            }

            // We have either been woken up, or this is spurious. Let us check if we were
            // actually woken up.
            match self.num_to_wake_up.fetch_update(SeqCst, SeqCst, |n| {
                if n & (1 << 31) == 0 {
                    // No waker in play, do nothing to the value
                    None
                } else if n & ((1 << 30) - 1) > 0 {
                    // There is a waker, and there is still capacity to wake up
                    Some(n - 1)
                } else {
                    // There is a waker, but capacity is gone
                    None
                }
            }) {
                Ok(_) => {
                    // We marked ourselves as having woken up, we can exit, marking
                    // ourselves as no longer waiting.
                    break Ok(UnblockedOrTimedOut::Unblocked);
                }
                Err(_) => {
                    // We have not yet been asked to wake up, this is spurious. Spin that
                    // loop again.
                    first_time = false;
                    continue;
                }
            }
        }
    }
}

impl litebox::platform::RawMutex for RawMutex {
    fn underlying_atomic(&self) -> &AtomicU32 {
        &self.inner
    }

    fn wake_many(&self, n: usize) -> usize {
        assert!(n > 0);
        let n: u32 = n.try_into().unwrap();

        // We restrict ourselves to a max of ~1 billion waiters being woken up at once, which should
        // be good enough, but makes sure we are not clobbering the "lock bits".
        let n = n.min((1 << 30) - 1);

        // We first requeue all the waiters into a temporary queue, so that anyone else showing up
        // to block is not going to be impacted.
        let temp_q = AtomicU32::new(0);
        match futex_val2(
            &self.num_to_wake_up,
            FutexOperation::Requeue,
            /* number to wake up */ 0,
            /* number to requeue */ u32::MAX,
            Some(&temp_q),
            /* val3: ignored */ 0,
        ) {
            0 => {
                // Since we didn't ask for anyone to wake up, this should just move everyone over,
                // and tell us no one was woken up.
            }
            _ => unreachable!(),
        }

        // Then, we set the number of waiters we want allowed to know that they can wake up, while
        // also grabbing the "lock bit"s.
        while self
            .num_to_wake_up
            .compare_exchange(0, n | (0b11 << 30), SeqCst, SeqCst)
            .is_err()
        {
            // If someone else is _also_ attempting to wake waiters up, then we should just spin
            // until the other waker is done with their job and brings the value down.
            core::hint::spin_loop();
        }

        // Now we can actually wake them up; if anyone is left unwoken though, we should move them
        // back into the main queue.
        let num_woken_up = futex_val2(
            &temp_q,
            FutexOperation::Requeue,
            /* number to wake up */ n,
            /* number to requeue */ u32::MAX,
            Some(&self.num_to_wake_up),
            /* val3: ignored */ 0,
        );

        // Unlock the lock bits, allowing other wakers to run.
        let final_num_to_wake_up = self.num_to_wake_up.swap(0, SeqCst);

        // Confirm that no one has clobbered the lock bits (which would indicate an implementation
        // failure somewhere).
        assert_eq!(
            final_num_to_wake_up >> 30,
            0b11,
            "lock bits should remain unclobbered"
        );

        // Return the number that were actually woken up
        num_woken_up.try_into().unwrap()
    }

    fn block(&self, val: u32) -> Result<(), ImmediatelyWokenUp> {
        match self.block_or_maybe_timeout(val, None) {
            Ok(UnblockedOrTimedOut::Unblocked) => Ok(()),
            Ok(UnblockedOrTimedOut::TimedOut) => unreachable!(),
            Err(ImmediatelyWokenUp) => Err(ImmediatelyWokenUp),
        }
    }

    fn block_or_timeout(
        &self,
        val: u32,
        timeout: Duration,
    ) -> Result<UnblockedOrTimedOut, ImmediatelyWokenUp> {
        self.block_or_maybe_timeout(val, Some(timeout))
    }
}

impl<PunchthroughProvider: litebox::platform::PunchthroughProvider>
    litebox::platform::IPInterfaceProvider for LinuxUserland<PunchthroughProvider>
{
    fn send_ip_packet(&self, packet: &[u8]) -> Result<(), litebox::platform::SendError> {
        let Some(tun_socket_fd) = self.tun_socket_fd.as_ref() else {
            unimplemented!("networking without tun is unimplemented")
        };
        match nix::unistd::write(tun_socket_fd, packet) {
            Ok(size) => {
                if size != packet.len() {
                    unimplemented!()
                }
                Ok(())
            }
            Err(errno) => {
                unimplemented!("unexpected error {}", errno)
            }
        }
    }

    fn receive_ip_packet(
        &self,
        packet: &mut [u8],
    ) -> Result<usize, litebox::platform::ReceiveError> {
        let Some(tun_socket_fd) = self.tun_socket_fd.as_ref() else {
            unimplemented!("networking without tun is unimplemented")
        };
        nix::unistd::read(tun_socket_fd.as_raw_fd(), packet).map_err(|errno| {
            if errno == nix::Error::EWOULDBLOCK || errno == nix::Error::EAGAIN {
                litebox::platform::ReceiveError::WouldBlock
            } else {
                unimplemented!("unexpected error {}", errno)
            }
        })
    }
}

impl<PunchthroughProvider: litebox::platform::PunchthroughProvider> litebox::platform::TimeProvider
    for LinuxUserland<PunchthroughProvider>
{
    type Instant = Instant;

    fn now(&self) -> Self::Instant {
        Instant {
            inner: std::time::Instant::now(),
        }
    }
}

pub struct Instant {
    inner: std::time::Instant,
}

impl litebox::platform::Instant for Instant {
    fn checked_duration_since(&self, earlier: &Self) -> Option<core::time::Duration> {
        self.inner.checked_duration_since(earlier.inner)
    }
}

impl<PunchthroughProvider: litebox::platform::PunchthroughProvider>
    litebox::platform::PunchthroughProvider for LinuxUserland<PunchthroughProvider>
{
    type PunchthroughToken = PunchthroughProvider::PunchthroughToken;

    fn get_punchthrough_token_for(
        &self,
        punchthrough: <Self::PunchthroughToken as litebox::platform::PunchthroughToken>::Punchthrough,
    ) -> Option<Self::PunchthroughToken> {
        // TODO(jayb): We may wish to make the linux userland platform less generic, and support a
        // _specific_ syscall-based punchthrough interface?
        self.punchthrough_provider
            .get_punchthrough_token_for(punchthrough)
    }
}

impl<PunchthroughProvider: litebox::platform::PunchthroughProvider>
    litebox::platform::DebugLogProvider for LinuxUserland<PunchthroughProvider>
{
    fn debug_log_print(&self, msg: &str) {
        eprint!("{msg}");
    }
}

impl<PunchthroughProvider: litebox::platform::PunchthroughProvider>
    litebox::platform::RawPointerProvider for LinuxUserland<PunchthroughProvider>
{
    type RawConstPointer<T: Clone> = litebox::platform::trivial_providers::TransparentConstPtr<T>;
    type RawMutPointer<T: Clone> = litebox::platform::trivial_providers::TransparentMutPtr<T>;
}

/// Operations currently supported by the safer variants of the Linux futex syscall
/// ([`futex_timeout`] and [`futex_val2`]).
#[repr(i32)]
enum FutexOperation {
    Wait = libc::FUTEX_WAIT,
    Requeue = libc::FUTEX_REQUEUE,
}

/// Safer invocation of the Linux futex syscall, with the "timeout" variant of the arguments.
#[expect(clippy::similar_names, reason = "sec/nsec are as needed by libc")]
fn futex_timeout(
    uaddr: &AtomicU32,
    futex_op: FutexOperation,
    val: u32,
    timeout: Option<Duration>,
    uaddr2: Option<&AtomicU32>,
    val3: u32,
) -> i64 {
    let uaddr: *const AtomicU32 = uaddr as _;
    let futex_op: i32 = futex_op as _;
    let timeout = timeout.map(|t| {
        const TEN_POWER_NINE: u128 = 1_000_000_000;
        let nanos: u128 = t.as_nanos();
        let tv_sec = nanos
            .checked_div(TEN_POWER_NINE)
            .unwrap()
            .try_into()
            .unwrap();
        let tv_nsec = nanos
            .checked_rem(TEN_POWER_NINE)
            .unwrap()
            .try_into()
            .unwrap();
        libc::timespec { tv_sec, tv_nsec }
    });
    let timeout: *const libc::timespec = timeout.map_or(std::ptr::null(), |t| &t);
    let uaddr2: *const AtomicU32 = uaddr2.map_or(std::ptr::null(), |u| u);
    unsafe { libc::syscall(libc::SYS_futex, uaddr, futex_op, val, timeout, uaddr2, val3) }
}

/// Safer invocation of the Linux futex syscall, with the "val2" variant of the arguments.
fn futex_val2(
    uaddr: &AtomicU32,
    futex_op: FutexOperation,
    val: u32,
    val2: u32,
    uaddr2: Option<&AtomicU32>,
    val3: u32,
) -> i64 {
    let uaddr: *const AtomicU32 = uaddr as _;
    let futex_op: i32 = futex_op as _;
    let uaddr2: *const AtomicU32 = uaddr2.map_or(std::ptr::null(), |u| u);
    unsafe { libc::syscall(libc::SYS_futex, uaddr, futex_op, val, val2, uaddr2, val3) }
}

fn prot_flags(flags: MemoryRegionPermissions) -> nix::sys::mman::ProtFlags {
    use nix::sys::mman::ProtFlags;
    let mut res = nix::sys::mman::ProtFlags::PROT_NONE;
    res.set(
        ProtFlags::PROT_READ,
        flags.contains(MemoryRegionPermissions::READ),
    );
    res.set(
        ProtFlags::PROT_WRITE,
        flags.contains(MemoryRegionPermissions::WRITE),
    );
    res.set(
        ProtFlags::PROT_EXEC,
        flags.contains(MemoryRegionPermissions::EXEC),
    );
    if flags.contains(MemoryRegionPermissions::SHARED) {
        unimplemented!()
    }
    res
}

impl<const ALIGN: usize> litebox::platform::PageManagementProvider<ALIGN> for LinuxUserland {
    fn allocate_pages(
        &self,
        range: std::ops::Range<usize>,
        initial_permissions: MemoryRegionPermissions,
        can_grow_down: bool,
    ) -> Result<Self::RawMutPointer<u8>, litebox::platform::page_mgmt::AllocationError> {
        let ptr = unsafe {
            nix::sys::mman::mmap_anonymous(
                Some(core::num::NonZeroUsize::new(range.start).expect("non null addr")),
                core::num::NonZeroUsize::new(range.len()).expect("non zero len"),
                prot_flags(initial_permissions),
                nix::sys::mman::MapFlags::MAP_PRIVATE
                    | nix::sys::mman::MapFlags::MAP_ANONYMOUS
                    | nix::sys::mman::MapFlags::MAP_FIXED
                    | (if can_grow_down {
                        nix::sys::mman::MapFlags::MAP_GROWSDOWN
                    } else {
                        nix::sys::mman::MapFlags::empty()
                    }),
            )
        }
        .expect("mmap failed");
        Ok(litebox::platform::trivial_providers::TransparentMutPtr {
            inner: ptr.as_ptr().cast(),
        })
    }

    unsafe fn deallocate_pages(
        &self,
        range: std::ops::Range<usize>,
    ) -> Result<(), litebox::platform::page_mgmt::DeallocationError> {
        let addr = core::ptr::NonNull::new(range.start as _).expect("non null addr");
        unsafe { nix::sys::mman::munmap(addr, range.len()) }.expect("munmap failed");
        Ok(())
    }

    unsafe fn remap_pages(
        &self,
        old_range: std::ops::Range<usize>,
        new_range: std::ops::Range<usize>,
    ) -> Result<(), litebox::platform::page_mgmt::RemapError> {
        let addr = core::ptr::NonNull::new(old_range.start as _).expect("non null addr");
        let new_address =
            Some(core::ptr::NonNull::new(new_range.start as _).expect("non null new addr"));
        let res = unsafe {
            nix::sys::mman::mremap(
                addr,
                old_range.len(),
                new_range.len(),
                nix::sys::mman::MRemapFlags::MREMAP_FIXED,
                new_address,
            )
            .expect("mremap failed")
        };
        assert_eq!(res.as_ptr() as usize, new_range.start);
        Ok(())
    }

    unsafe fn update_permissions(
        &self,
        range: std::ops::Range<usize>,
        new_permissions: MemoryRegionPermissions,
    ) -> Result<(), litebox::platform::page_mgmt::PermissionUpdateError> {
        let addr = core::ptr::NonNull::new(range.start as _).expect("non null addr");
        unsafe { nix::sys::mman::mprotect(addr, range.len(), prot_flags(new_permissions)) }
            .expect("mprotect failed");
        Ok(())
    }
}
