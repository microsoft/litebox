// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Seatbelt (`sandbox_init`) defense-in-depth for the userland macOS platform.
//!
//! This is the macOS counterpart of
//! `litebox_platform_linux_userland::LinuxUserland::enable_seccomp_filter`, and
//! it is deliberately built to the same shape so the two read as one idea:
//!
//! | | Linux | macOS |
//! |---|---|---|
//! | mechanism | seccomp-BPF (`seccompiler`) | Seatbelt / TrustedBSD MAC (`sandbox_init`) |
//! | granularity | syscall number + argument values | *operation* (open a file, connect a socket, exec) |
//! | default verdict | deny (`SeccompAction::Errno(EINVAL)`) | deny (`(deny default)`) |
//! | installed | in the runner, immediately before `load_program` | identical |
//! | on failure | panic (`apply_filter(..).unwrap()`) | panic ([`enable_seatbelt_sandbox`]) |
//! | inherited by threads | yes (whole process) | yes (whole process) |
//!
//! Both are a *second* line of defense sitting behind LiteBox's own guest/host
//! boundary: the guest never issues a host syscall directly, so reaching either
//! layer already means the shim or the platform has been subverted. The point of
//! both is to bound the blast radius of that subversion.
//!
//! # The two layers are not equivalent, and the difference matters
//!
//! seccomp filters *syscall numbers*, so the Linux filter can and does deny
//! whole syscalls (`mkdir` is unreachable; `open` is reachable only with
//! `O_RDONLY`). Seatbelt filters *operations* one level above the syscall, so it
//! cannot say "no `mkdir`" but it can say "no writable access to any path", which
//! subsumes it. Conversely Seatbelt says nothing at all about `mmap`,
//! `mprotect`, `madvise` or the `__ulock_*` family -- those are not
//! policy-mediated operations -- which is exactly why `MAP_JIT` keeps working
//! under a `(deny default)` profile (verified, see the module's test).
//!
//! # `sandbox_init` is deprecated
//!
//! `<sandbox.h>` on this SDK carries
//! `API_DEPRECATED("No longer supported", macos(10.5, 10.8), ...)` and the file
//! banner says "This header is deprecated and may be removed in a future
//! release. Developers who wish to sandbox an app should instead adopt the App
//! Sandbox feature". That is acknowledged and accepted here, because:
//!
//! * The documented replacement, App Sandbox, is a *launch-time* entitlement on
//!   a provisioned, distributed application bundle. It cannot express "run
//!   unsandboxed long enough to read the guest image the user named on the
//!   command line, then drop into a jail", which is precisely the lifecycle this
//!   needs and precisely the lifecycle the Linux seccomp filter already has.
//! * The supported-but-private alternatives (`sandbox_compile_string` /
//!   `sandbox_apply`) are SPI: not in any SDK, not documented, and no more
//!   future-proof.
//! * `sandbox_init` is not merely present but fully functional on this host
//!   (macOS 26.3.1, xnu-12377.91.3, arm64), which the module test re-proves on
//!   every run rather than assuming.
//!
//! There is no deprecation *warning* to suppress on the Rust side: this module
//! declares the symbol itself in an `unsafe extern "C"` block rather than
//! including `<sandbox.h>`, so no `API_DEPRECATED` annotation ever reaches the
//! compiler. Saying "`#[allow(deprecated)]` was added" would be theater; the
//! honest form of the acknowledgement is this comment plus the test.
//!
//! # Fail-safe posture
//!
//! [`enable_seatbelt_sandbox`] panics if the profile does not install. See its
//! doc comment for the Saltzer-and-Schroeder argument; the short version is that
//! a security control which degrades to a `warn!` and keeps running is strictly
//! worse than no control, because it manufactures confidence it is not backing.

use core::ffi::{CStr, c_char, c_int};

unsafe extern "C" {
    /// libSystem's Seatbelt entry point. See the module docs for the
    /// deprecation story.
    ///
    /// With `flags == 0` the `profile` argument is a Sandbox Profile Language
    /// (SBPL) *source string* that the call compiles and installs. The public
    /// header only documents `flags == SANDBOX_NAMED` (a built-in profile
    /// name), but the SBPL-source form is what macOS itself is built on -- the
    /// system ships hundreds of SBPL profiles in
    /// `/System/Library/Sandbox/Profiles` -- and this module's test verifies on
    /// every run that it really compiles and installs on this host, rather than
    /// taking that on trust.
    ///
    /// Returns 0 on success, -1 otherwise, and on failure stores an owned,
    /// NUL-terminated diagnostic string in `*errorbuf`.
    fn sandbox_init(profile: *const c_char, flags: u64, errorbuf: *mut *mut c_char) -> c_int;

    /// Frees a diagnostic string handed back by [`sandbox_init`].
    fn sandbox_free_error(errorbuf: *mut c_char);
}

/// The Seatbelt profile the runner installs just before it hands control to the
/// guest.
///
/// Read this together with `LinuxUserland::enable_seccomp_filter`'s rule list.
/// The posture is the same one: deny by default, then re-admit only the host
/// facilities that the *platform itself* still needs once the guest is running.
///
/// There is exactly **one** exception to `(deny default)`, and it is there
/// because the platform provably stops working without it:
///
/// * `sysctl-read` restricted to the `hw.optional.` prefix.
///   `MacOsUserland::get_hwcap` reads ~30 `hw.optional.*` sysctls to
///   synthesize the guest's `AT_HWCAP`/`AT_HWCAP2`, and it does so from inside
///   `load_program`, i.e. *after* this profile is installed. The prefix filter
///   is what keeps this from being a blanket `(allow sysctl-read)`: `kern.*`,
///   `machdep.*`, and even the rest of `hw.*`, stay denied (measured in the real
///   runner under a debugger: `kern.hostname` returns this host's real hostname
///   a moment before the profile installs and `EPERM` a moment after, while
///   `hw.optional.arm.FEAT_LSE` reads `1` on both sides). `sysctl-write` is
///   denied outright. `sysctl-name-prefix "hw.optional."` is not an exotic
///   construct -- macOS ships that exact filter, with that exact prefix, in its
///   own `/System/Library/Sandbox/Profiles`.
///
/// Everything else the runner needed, it needed only during start-up -- reading
/// the tar archive, opening the `utun` device, sampling whether stdio is a
/// terminal -- and by this point it has already happened, so none of it is
/// re-admitted.
///
/// Notably **not** re-admitted. Each of the following was measured directly, in
/// the real runner process, as succeeding immediately before `sandbox_init` and
/// failing with `EPERM` immediately after (the module test re-measures the same
/// transitions on every run):
///
/// * `open` of a host file for reading (`/etc/passwd`), and `open` with
///   `O_CREAT|O_WRONLY` of a new one. Nothing on the host filesystem is
///   readable or writable any more -- not the user's home directory, not the
///   runner's own binary, not the tar archive the guest was loaded from.
/// * `stat` of a host file: even metadata is refused, because
///   `file-read-metadata` is denied too. So is `unlink`, and so is `chdir`.
/// * `connect` to a remote address and `bind` of a local one, so all inbound and
///   outbound network access is gone.
/// * `socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL)`, which is the only way to
///   open a *new* `utun` device.
/// * `posix_spawn`/`fork`+`exec` of any host program.
/// * `kill` of any *other* process, including a child this very process spawned
///   moments earlier and that ordinary Unix permissions would let it signal.
///
/// Other operation classes -- `mach-lookup` of a system service, `iokit-open`,
/// POSIX and SysV shared memory, `sysctl-write` -- are denied by `(deny default)`
/// as well, but that follows from the default rather than from a measurement
/// taken here, and is stated as such.
///
/// No `(allow signal (target self))` rule is present because none is needed:
/// Darwin exempts same-process signalling from the `signal` operation entirely,
/// so `raise`, `kill(getpid(), ...)` and `pthread_kill` -- which is how this
/// platform interrupts a guest thread out of native execution -- all keep
/// working under a bare `(deny default)`, while `kill` aimed at another process
/// this same user owns is refused. Both halves of that were measured rather than
/// assumed; adding the rule would have been cargo cult.
///
/// Not covered at all, because Seatbelt does not mediate them: `mmap`
/// (including `MAP_JIT`), `mprotect`, `munmap`, `madvise`, `__ulock_wait`
/// /`__ulock_wake`, `clock_gettime`, `arc4random_buf`, thread creation, plain
/// `socket()` creation (it succeeds -- it is `bind`/`connect` that do not), and
/// read/write on descriptors that were *already open* when the profile was
/// installed (stdin/stdout/stderr and the `utun` socket). That last one is load
/// bearing: it is why guest console I/O and guest networking keep working, and
/// it is also the sharpest limitation of this layer -- see the crate docs'
/// residual-risk note.
const RUNNER_PROFILE: &CStr = c"(version 1)
(deny default)
(allow sysctl-read (sysctl-name-prefix \"hw.optional.\"))
";

/// [`RUNNER_PROFILE`] plus `(allow network-outbound)` and the `system-socket` right that
/// `socket(2)` for an outbound dial needs on some macOS versions. Installed instead of the
/// base profile when the runner's `--net-proxy` bridge is active: the bridge terminates guest
/// TCP inside the smoltcp stack and re-originates it as ordinary host connections, which are
/// exactly the operations `(deny default)` refuses. Everything else -- file reads, inbound
/// binds/accepts, mach lookups (so `getaddrinfo`'s mDNSResponder path stays closed; the bridge
/// does its own UDP DNS) -- remains denied.
const RUNNER_PROFILE_WITH_OUTBOUND_NETWORK: &CStr = c"(version 1)
(deny default)
(allow sysctl-read (sysctl-name-prefix \"hw.optional.\"))
(allow network-outbound)
(allow network-bind (local udp))
(allow network-inbound (local udp))
(allow system-socket)
";

/// Why [`enable_seatbelt_sandbox`] could not put this process in a sandbox.
///
/// Deliberately not part of the crate's public API: the only caller,
/// [`enable_seatbelt_sandbox`], turns every variant into a panic, so there is
/// nothing for an outside caller to match on.
#[derive(Debug)]
enum SeatbeltError {
    /// `sandbox_init` rejected the profile or refused to install it, and handed
    /// back this diagnostic (for example `unbound variable: ... at <input
    /// string>, line 3, column 2` for an SBPL syntax error).
    ///
    /// `sandbox.h` also documents "If the process is already in a sandbox, the
    /// new profile is ignored and sandbox_init() returns an error", but that is
    /// *not* what this host does: a second `apply_profile` call on an
    /// already-sandboxed process returns success here (measured on macOS 26.3.1).
    /// Nothing in LiteBox relies on either behavior -- the runner calls
    /// [`enable_seatbelt_sandbox`] exactly once -- and it is written down only so
    /// nobody later builds on the header's claim.
    Init(alloc::string::String),
}

impl core::fmt::Display for SeatbeltError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Init(msg) => write!(f, "sandbox_init failed: {msg}"),
        }
    }
}

impl core::error::Error for SeatbeltError {}

/// Compiles and installs `profile` (SBPL source) on the calling process.
///
/// The sandbox applies to the whole process, every thread, immediately, and for
/// the rest of the process's life: there is no documented way to lift it, and no
/// call can ever widen it.
///
/// On failure the process is left exactly as it was -- an SBPL compile error
/// installs nothing, which is what makes the malformed-profile test below safe
/// to run in the shared test process.
fn apply_profile(profile: &CStr) -> Result<(), SeatbeltError> {
    let mut errorbuf: *mut c_char = core::ptr::null_mut();
    // SAFETY: `profile` is a live NUL-terminated string for the duration of the
    // call, and `errorbuf` is a valid out-parameter. `flags == 0` selects the
    // SBPL-source form documented on the `sandbox_init` declaration above.
    let rc = unsafe { sandbox_init(profile.as_ptr(), 0, &raw mut errorbuf) };
    if rc == 0 {
        // A successful call sets `*errorbuf` to NULL, but free defensively: the
        // contract is "deallocate with `sandbox_free_error`", and that function
        // accepts NULL.
        if !errorbuf.is_null() {
            // SAFETY: `errorbuf` is exactly what `sandbox_init` handed back.
            unsafe { sandbox_free_error(errorbuf) };
        }
        return Ok(());
    }
    let message = if errorbuf.is_null() {
        alloc::string::String::from("(no diagnostic)")
    } else {
        // SAFETY: on failure `sandbox_init` stores an owned, NUL-terminated
        // string here.
        let msg = unsafe { CStr::from_ptr(errorbuf) }
            .to_string_lossy()
            .into_owned();
        // SAFETY: `errorbuf` is exactly what `sandbox_init` handed back, and
        // `msg` above copied out of it before this frees it.
        unsafe { sandbox_free_error(errorbuf) };
        msg
    };
    Err(SeatbeltError::Init(message))
}

/// Installs the runner's Seatbelt profile on this process.
///
/// Call this once, from the runner, at the same point in the lifecycle at which
/// the Linux runner calls `enable_seccomp_filter`: after every host resource the
/// platform will ever need has been acquired (the guest image has been read, the
/// `utun` device opened, stdio sampled), and immediately before `load_program`
/// hands control to guest code. Applying it earlier would deny the runner its
/// own start-up; applying it later would leave a window in which a
/// guest-triggered bug in `load_program` -- an ELF parser, run on attacker-chosen
/// bytes -- runs with the full authority of the invoking user.
///
/// See this module's `RUNNER_PROFILE` for exactly what is denied and what
/// survives.
///
/// # Panics
///
/// Panics if the profile cannot be installed.
///
/// This is a deliberate choice, and it is the same one the Linux filter makes
/// (`seccompiler::apply_filter(&bpf_prog).unwrap()`). Fail-Safe Defaults says
/// the default must be *lack* of access, and that a protection mechanism's
/// failure mode must therefore deny rather than permit. A `sandbox_init` failure
/// here has exactly two plausible causes -- a future macOS finally removing the
/// deprecated entry point, or the profile failing to compile -- and in both the
/// process would otherwise continue at full user authority while the operator,
/// who asked for a sandbox, believes one is in place. A warning that scrolls
/// past in a log is not a substitute; it converts a hard, visible failure into a
/// silent downgrade, which is the precise failure mode this layer exists to
/// prevent elsewhere. Refusing to start is loud, unambiguous, and leaves the
/// operator in control of the trade-off.
pub fn enable_seatbelt_sandbox() {
    if let Err(err) = apply_profile(RUNNER_PROFILE) {
        panic!(
            "refusing to run the guest without the Seatbelt sandbox: {err}\n\
             (this is fail-safe by design; see litebox_platform_macos_userland::seatbelt)"
        );
    }
}

/// [`enable_seatbelt_sandbox`], but with outbound network access left open for the runner's
/// guest-to-host network bridge. See `RUNNER_PROFILE_WITH_OUTBOUND_NETWORK` for exactly what
/// widens and why; same fail-safe panic contract.
///
/// # Panics
///
/// Panics if the profile cannot be installed, for the same reasons as
/// [`enable_seatbelt_sandbox`].
pub fn enable_seatbelt_sandbox_with_outbound_network() {
    if let Err(err) = apply_profile(RUNNER_PROFILE_WITH_OUTBOUND_NETWORK) {
        panic!(
            "refusing to run the guest without the Seatbelt sandbox: {err}\n\
             (this is fail-safe by design; see litebox_platform_macos_userland::seatbelt)"
        );
    }
}

/// The fail-safe path in [`enable_seatbelt_sandbox`] is only correct if
/// [`apply_profile`] actually *reports* a bad profile rather than quietly
/// returning success -- otherwise the panic would be unreachable and the runner
/// would sail on unsandboxed, which is the exact failure this design exists to
/// avoid.
///
/// This is safe to run in the shared test process precisely because a profile
/// that fails to compile installs nothing; the assertion at the end is what
/// proves that, rather than assuming it. (`sandbox_init` also prints its own
/// `sandbox initialization failed: ...` line to stderr; that noise in the test
/// log is real output from the real API, not a leaked `eprintln!`.)
#[cfg(test)]
#[test]
fn a_profile_that_does_not_compile_is_reported_and_installs_nothing() {
    let err = apply_profile(c"(version 1)\n(deny default)\n(litebox-not-an-sbpl-operation)\n")
        .expect_err("a malformed SBPL profile must not install");
    let SeatbeltError::Init(message) = &err;
    assert!(
        message.contains("litebox-not-an-sbpl-operation"),
        "the diagnostic must name the offending form, got: {message}"
    );
    assert!(
        std::fs::File::open("/etc/passwd").is_ok(),
        "a failed sandbox_init must leave the process exactly as it was"
    );
}

/// Set on the re-executed child of
/// [`the_runner_profile_denies_host_access_without_breaking_jit_or_hwcap`]; its
/// presence means "you are the jailed one, run the probes".
#[cfg(test)]
const SEATBELT_CHILD_VAR: &str = "LITEBOX_SEATBELT_SELFTEST_CHILD";

/// The `--exact` name libtest knows
/// [`the_runner_profile_denies_host_access_without_breaking_jit_or_hwcap`] by.
#[cfg(test)]
const SEATBELT_TEST_NAME: &str =
    "seatbelt::the_runner_profile_denies_host_access_without_breaking_jit_or_hwcap";

/// A host file every macOS has, that any user can read, and that a guest has no
/// business reading.
#[cfg(test)]
const HOST_FILE: &str = "/etc/passwd";

/// An integer sysctl that sits *outside* the one prefix [`RUNNER_PROFILE`]
/// admits while still living in the same `hw.` top-level namespace, so the test
/// pins that the filter really is a prefix match and not "anything under `hw.`".
#[cfg(test)]
const DENIED_SYSCTL: &CStr = c"hw.ncpu";

/// Proves three things about [`RUNNER_PROFILE`] on the real host, in a real
/// process, with real syscalls:
///
/// 1. it installs at all (`sandbox_init` still works despite being deprecated),
/// 2. it is **not a no-op** -- operations that demonstrably succeed moments
///    earlier in the very same process are refused with `EPERM` afterwards, and
/// 3. it does not break the platform: `MAP_JIT` allocation, plain anonymous
///    mappings, `sysctl` reads for `AT_HWCAP`, and writes to already-open
///    descriptors all still work.
///
/// The sandbox is irreversible and process-wide, so this cannot run in the
/// shared test process: it would silently break every later test in the binary
/// that touches a file. The test therefore re-executes *this same test binary*
/// as a child, selecting only this test by name, with `SEATBELT_CHILD_VAR` set;
/// the child is the one that actually gets jailed. No mocks and no fakes are
/// involved -- the child runs the real profile and the real syscalls, and the
/// parent asserts on its real exit status and output.
#[cfg(test)]
#[test]
fn the_runner_profile_denies_host_access_without_breaking_jit_or_hwcap() {
    if std::env::var_os(SEATBELT_CHILD_VAR).is_none() {
        let exe = std::env::current_exe().expect("the test binary has a path");
        let output = std::process::Command::new(&exe)
            .args([
                "--exact",
                "--nocapture",
                "--test-threads=1",
                SEATBELT_TEST_NAME,
            ])
            .env(SEATBELT_CHILD_VAR, "1")
            .output()
            .expect("re-executing the test binary");
        assert!(
            output.status.success(),
            "sandboxed child failed.\n--- stdout ---\n{}\n--- stderr ---\n{}",
            alloc::string::String::from_utf8_lossy(&output.stdout),
            alloc::string::String::from_utf8_lossy(&output.stderr),
        );
        let stdout = alloc::string::String::from_utf8_lossy(&output.stdout);
        assert!(
            stdout.contains("seatbelt-selftest: all probes behaved as specified"),
            "sandboxed child did not reach its verdict line.\n--- stdout ---\n{stdout}",
        );
        return;
    }

    // ---- Everything below runs in the re-executed, about-to-be-jailed child.

    // Baseline: these all succeed *right now*, in this process. Without this
    // half the test proves nothing -- a denial is only interesting if the same
    // operation was permitted a moment earlier.
    assert!(
        std::fs::File::open(HOST_FILE).is_ok(),
        "baseline: {HOST_FILE} must be readable before the profile is installed"
    );
    let scratch = std::env::temp_dir().join("litebox-seatbelt-selftest-scratch");
    assert!(
        std::fs::write(&scratch, b"baseline").is_ok(),
        "baseline: the temp dir must be writable before the profile is installed"
    );
    assert!(
        std::net::TcpListener::bind("127.0.0.1:0").is_ok(),
        "baseline: binding a loopback socket must work before the profile is installed"
    );
    assert!(
        std::process::Command::new("/bin/echo")
            .arg("baseline")
            .output()
            .is_ok(),
        "baseline: spawning a host process must work before the profile is installed"
    );
    assert!(
        read_sysctl_int(DENIED_SYSCTL).is_some(),
        "baseline: {DENIED_SYSCTL:?} must be readable before the profile is installed"
    );
    // A live process this user owns, kept around across the transition so the
    // "signalling other processes is denied" claim can be measured against a
    // target that ordinary Unix permissions would happily let us signal.
    let mut victim = std::process::Command::new("/bin/sleep")
        // Long enough that it is certainly still alive a few hundred
        // microseconds later when the post-install probe runs, short enough
        // that reaping it -- the only way left once signalling it is denied --
        // does not dominate the test's runtime.
        .arg("3")
        .spawn()
        .expect("baseline: spawning a host process must work before the profile is installed");
    let victim_pid = libc::pid_t::try_from(victim.id()).expect("a pid fits in pid_t");
    // SAFETY: signal 0 performs the permission check only and delivers nothing.
    assert_eq!(
        unsafe { libc::kill(victim_pid, 0) },
        0,
        "baseline: our own child must be signalable before the profile is installed"
    );

    apply_profile(RUNNER_PROFILE).expect("the runner profile must install on this host");

    // (2) Not a no-op: the same four operations are now refused.
    for (what, err) in [
        (
            "read a host file",
            std::fs::File::open(HOST_FILE).expect_err("reading a host file must now be denied"),
        ),
        (
            "write a host file",
            std::fs::write(&scratch, b"after").expect_err("writing a host file must now be denied"),
        ),
        (
            "bind a socket",
            std::net::TcpListener::bind("127.0.0.1:0")
                .expect_err("binding a socket must now be denied"),
        ),
        (
            "exec a host program",
            std::process::Command::new("/bin/echo")
                .arg("after")
                .output()
                .expect_err("spawning a host process must now be denied"),
        ),
    ] {
        assert_eq!(
            err.raw_os_error(),
            Some(libc::EPERM),
            "{what}: expected EPERM from the sandbox, got {err}"
        );
    }

    // Signalling another process is denied, even one this very process spawned
    // and that ordinary Unix permissions would let it signal. This is half of
    // why `RUNNER_PROFILE` carries no `(allow signal ...)` rule.
    // SAFETY: signal 0 performs the permission check only and delivers nothing.
    assert_eq!(unsafe { libc::kill(victim_pid, 0) }, -1);
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(libc::EPERM),
        "signalling another process must be denied by the profile"
    );

    // ...and the other half: same-process signalling is exempt from the
    // `signal` operation, so the platform's `pthread_kill(SIGUSR2)`-based guest
    // interrupt keeps working without any rule admitting it. Measuring this is
    // what justifies leaving the rule out instead of adding it defensively.
    //
    // The signal is blocked first and then consumed with `sigwait`, so delivery
    // is observed through `sigpending` rather than a handler. That keeps this
    // probe free of both a global flag and any lasting change to this process's
    // signal disposition.
    // SAFETY: every `sigset_t` below is a live, uniquely owned out-parameter,
    // and each call gets the pointer kind it expects.
    unsafe {
        let mut blocked: libc::sigset_t = core::mem::zeroed();
        libc::sigemptyset(&raw mut blocked);
        libc::sigaddset(&raw mut blocked, libc::SIGUSR1);
        let mut previous: libc::sigset_t = core::mem::zeroed();
        assert_eq!(
            libc::pthread_sigmask(libc::SIG_BLOCK, &raw const blocked, &raw mut previous),
            0
        );
        assert_eq!(
            libc::pthread_kill(libc::pthread_self(), libc::SIGUSR1),
            0,
            "same-process signalling must survive the profile"
        );
        let mut pending: libc::sigset_t = core::mem::zeroed();
        assert_eq!(libc::sigpending(&raw mut pending), 0);
        assert_eq!(
            libc::sigismember(&raw const pending, libc::SIGUSR1),
            1,
            "the self-signal must actually have been delivered, not just accepted"
        );
        let mut consumed: c_int = 0;
        assert_eq!(libc::sigwait(&raw const blocked, &raw mut consumed), 0);
        assert_eq!(consumed, libc::SIGUSR1);
        assert_eq!(
            libc::pthread_sigmask(
                libc::SIG_SETMASK,
                &raw const previous,
                core::ptr::null_mut()
            ),
            0
        );
    }

    // The sysctl namespace is admitted by prefix, not wholesale.
    assert!(
        read_sysctl_int(DENIED_SYSCTL).is_none(),
        "{DENIED_SYSCTL:?} must not be readable inside the sandbox"
    );

    // (3) The platform still works. `MAP_JIT` first: this is the one that would
    // make the whole platform unusable if Seatbelt mediated it. This is byte for
    // byte the `mmap` call `allocate_jit_pages` makes for every executable guest
    // mapping.
    let page = litebox::mm::vmem::PAGE_SIZE;
    // SAFETY: a fresh anonymous `MAP_JIT` mapping request with no fixed address.
    let jit = unsafe {
        libc::mmap(
            core::ptr::null_mut(),
            page,
            libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
            libc::MAP_PRIVATE | libc::MAP_ANON | crate::MAP_JIT,
            -1,
            0,
        )
    };
    assert_ne!(
        jit,
        libc::MAP_FAILED,
        "MAP_JIT allocation must still work inside the sandbox: {}",
        std::io::Error::last_os_error()
    );
    // SAFETY: `jit` is exactly the mapping just returned, of exactly this size.
    assert_eq!(unsafe { libc::munmap(jit, page) }, 0);

    // A plain anonymous read/write mapping, which is what every guest data page
    // is, plus an actual store into it.
    // SAFETY: a fresh anonymous mapping request with no fixed address.
    let anon = unsafe {
        libc::mmap(
            core::ptr::null_mut(),
            page,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANON,
            -1,
            0,
        )
    };
    assert_ne!(anon, libc::MAP_FAILED, "anonymous mmap must still work");
    // SAFETY: `anon` is a live, writable, page-long mapping.
    unsafe { anon.cast::<u8>().write_volatile(0x5a) };
    // SAFETY: `anon` is exactly the mapping just returned, of exactly this size.
    assert_eq!(unsafe { libc::munmap(anon, page) }, 0);

    // `AT_HWCAP` synthesis happens after the profile is installed, so the
    // sysctl reads it depends on have to survive.
    let (hwcap, _hwcap2) = crate::arm_hwcap();
    assert_ne!(
        hwcap, 0,
        "hw.optional.* sysctls must still be readable inside the sandbox"
    );

    // Guest console output is a write to an already-open descriptor. If this
    // line does not reach the parent, that is itself the failure.
    println!("seatbelt-selftest: all probes behaved as specified");

    // The child could not be signalled, so reap it the only way left. If even
    // `wait` is refused the process is reparented and reaped on exit, so this
    // is best effort by construction.
    let _ = victim.wait();
}

/// Reads an integer-valued `sysctl` by name, returning `None` if the read fails
/// for any reason (including a sandbox denial).
///
/// This exists so the test can probe a sysctl *outside* the prefix the profile
/// admits; [`crate::arm_hwcap`] covers the inside-the-prefix case.
#[cfg(test)]
fn read_sysctl_int(name: &CStr) -> Option<libc::c_int> {
    let mut value: libc::c_int = 0;
    let mut len = core::mem::size_of::<libc::c_int>();
    // SAFETY: `name` is NUL-terminated, and `value`/`len` are valid, uniquely
    // owned out-parameters matching a fixed-size 4-byte integer read.
    let rc = unsafe {
        libc::sysctlbyname(
            name.as_ptr(),
            (&raw mut value).cast(),
            &raw mut len,
            core::ptr::null_mut(),
            0,
        )
    };
    (rc == 0).then_some(value)
}
