// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Runs an AArch64 Linux guest on an unmodified Apple Silicon macOS host.
//!
//! There is deliberately no x86-64 variant. LiteBox runs guest instructions
//! natively and virtualizes only the system interface, so an x86-64 guest here
//! would need instruction emulation -- the thing the design exists to avoid. An
//! AArch64 guest on an AArch64 host needs none.
#![cfg(all(target_os = "macos", target_arch = "aarch64"))]

extern crate alloc;

use anyhow::{Result, anyhow};
use clap::Parser;
use litebox_platform_macos_userland::MacOsUserland as Platform;

mod net_proxy;
use std::path::PathBuf;

/// Adapts [`litebox::fs::devices::Framebuffer`] to [`litebox_rfb::FramebufferSource`] --
/// `litebox_rfb` deliberately doesn't depend on `litebox` (see its own crate doc comment), so
/// this thin wrapper lives on the runner side of that boundary instead.
struct FramebufferAdapter(litebox::fs::devices::Framebuffer<Platform>);

impl litebox_rfb::FramebufferSource for FramebufferAdapter {
    fn dimensions(&self) -> (u16, u16) {
        let geo = self.0.geometry();
        // A real fbdev geometry is always well within u16 range (RFB's own wire format caps
        // width/height at u16 too); truncation here would only ever fire on a geometry no real
        // client could display anyway.
        (
            u16::try_from(geo.xres).unwrap_or(u16::MAX),
            u16::try_from(geo.yres).unwrap_or(u16::MAX),
        )
    }

    fn snapshot_into(&self, dst: &mut Vec<u8>) {
        self.0.read_visible_into(dst);
    }
}

/// Run Linux programs with LiteBox on unmodified macOS.
///
/// The program binary and all its dependencies must be provided inside a tar
/// archive via `--initial-files`. The program path refers to a path inside the
/// tar archive.
/// Published operation class exercised by `--hvf-published-panic`.
#[derive(Clone, Copy, Debug, clap::ValueEnum)]
pub enum HvfPublishedPanicOperationArg {
    Exclusive,
    Shared,
    ExistingVcpu,
}

#[derive(Parser, Debug)]
#[allow(clippy::struct_excessive_bools)]
pub struct CliArgs {
    /// The program and arguments passed to it (e.g., `/bin/ls --color`).
    ///
    /// The program path refers to a path inside the tar archive provided via
    /// `--initial-files`. All binaries must be pre-rewritten with the syscall
    /// rewriter.
    #[arg(
        required_unless_present_any = ["hvf_smoke", "hvf_boundary", "hvf_memory", "hvf_memory_failure", "hvf_alias_panic_failure", "hvf_published_panic", "hvf_poison", "hvf_register_failure", "hvf_unmap_failure", "hvf_vcpu", "hvf_vcpu_failure", "hvf_vcpu_custody", "hvf_vcpu_totality", "hvf_mirrored_view", "hvf_alias_race", "hvf_sandbox", "hvf_lane_starvation", "hvf_scheduler_latency", "hvf_scheduler_scaling"],
        trailing_var_arg = true,
        value_hint = clap::ValueHint::CommandWithArguments
    )]
    pub program_and_arguments: Vec<String>,
    /// Environment variables passed to the program (`K=V` pairs; can be invoked multiple times)
    #[arg(long = "env")]
    pub environment_variables: Vec<String>,
    /// Forward the existing environment variables
    #[arg(long = "forward-env")]
    pub forward_environment_variables: bool,
    /// Tar archive containing the program and its shared libraries.
    ///
    /// All ELF binaries should be pre-rewritten with the syscall rewriter
    /// (e.g., via `litebox-packager`), for `Host::MacOs`.
    #[arg(
        long = "initial-files",
        value_name = "PATH_TO_TAR",
        required_unless_present_any = ["hvf_smoke", "hvf_boundary", "hvf_memory", "hvf_memory_failure", "hvf_alias_panic_failure", "hvf_published_panic", "hvf_poison", "hvf_register_failure", "hvf_unmap_failure", "hvf_vcpu", "hvf_vcpu_failure", "hvf_vcpu_custody", "hvf_vcpu_totality", "hvf_mirrored_view", "hvf_alias_race", "hvf_sandbox", "hvf_lane_starvation", "hvf_scheduler_latency", "hvf_scheduler_scaling"],
        value_hint = clap::ValueHint::FilePath
    )]
    pub initial_files: Option<PathBuf>,
    /// Allow using unstable options
    #[arg(short = 'Z', long = "unstable")]
    pub unstable: bool,
    /// Run the bounded Hypervisor.framework architecture probe and exit.
    ///
    /// This does not run the requested Linux program and does not select the
    /// native guest backend. It verifies the compact-IPA, 16 KiB stage-one,
    /// stock-SVC/HVC and x18-preservation path that the opt-in HVF backend will
    /// use. The runner executable must carry the
    /// `com.apple.security.hypervisor` entitlement.
    #[arg(
        long = "hvf-smoke",
        requires = "unstable",
        conflicts_with = "hvf_boundary",
        help_heading = "Unstable Options"
    )]
    pub hvf_smoke: bool,
    /// Exercise the production Hypervisor.framework SDK boundary and exit.
    ///
    /// This creates the process-global VM through the active macOS SDK,
    /// validates the linked EL1 monitor, maps and unmaps it with compact IPA,
    /// then creates, verifies, and destroys a vCPU. The runner executable must
    /// carry the `com.apple.security.hypervisor` entitlement.
    #[arg(
        long = "hvf-boundary",
        requires = "unstable",
        help_heading = "Unstable Options"
    )]
    pub hvf_boundary: bool,
    /// Exercise compact IPA allocation, the GVA=HVA ledger, fresh stage-one
    /// roots, stage-two protection, and transactional rejection without running
    /// guest instructions.
    #[arg(
        long = "hvf-memory",
        requires = "unstable",
        conflicts_with_all = ["hvf_smoke", "hvf_boundary"],
        help_heading = "Unstable Options"
    )]
    pub hvf_memory: bool,
    /// Inject compact-memory rollback and host-slot restoration failures, then
    /// prove exact manager quarantine and cleanup-only recovery. This intentionally
    /// poisons its short-lived diagnostic process.
    #[arg(
        long = "hvf-memory-failure",
        requires = "unstable",
        conflicts_with_all = ["hvf_smoke", "hvf_boundary", "hvf_memory", "hvf_poison", "hvf_register_failure", "hvf_unmap_failure"],
        help_heading = "Unstable Options"
    )]
    pub hvf_memory_failure: bool,
    /// Prove that a callback panic remains the primary unwind payload when alias
    /// restoration also fails, then recover the quarantined alias through
    /// cleanup-only admission. This intentionally poisons its short-lived
    /// diagnostic process.
    #[arg(
        long = "hvf-alias-panic-failure",
        requires = "unstable",
        conflicts_with_all = ["hvf_smoke", "hvf_boundary", "hvf_memory", "hvf_memory_failure", "hvf_poison", "hvf_register_failure", "hvf_unmap_failure", "hvf_vcpu", "hvf_vcpu_failure", "hvf_vcpu_custody", "hvf_vcpu_totality", "hvf_mirrored_view", "hvf_alias_race", "hvf_sandbox", "hvf_lane_starvation", "hvf_scheduler_latency", "hvf_scheduler_scaling"],
        help_heading = "HVF diagnostics"
    )]
    pub hvf_alias_panic_failure: bool,
    /// Prove that a panic after a published HVF mutation atomically poison-latches
    /// the VM before releasing its admission. Select `exclusive`, `shared`, or
    /// `existing-vcpu`; each invocation intentionally poisons its short-lived
    /// diagnostic process.
    #[arg(
        long = "hvf-published-panic",
        value_enum,
        requires = "unstable",
        conflicts_with_all = ["hvf_smoke", "hvf_boundary", "hvf_memory", "hvf_memory_failure", "hvf_alias_panic_failure", "hvf_poison", "hvf_register_failure", "hvf_unmap_failure", "hvf_vcpu", "hvf_vcpu_failure", "hvf_vcpu_custody", "hvf_vcpu_totality", "hvf_mirrored_view", "hvf_alias_race", "hvf_sandbox", "hvf_lane_starvation", "hvf_scheduler_latency", "hvf_scheduler_scaling"],
        help_heading = "HVF diagnostics"
    )]
    pub hvf_published_panic: Option<HvfPublishedPanicOperationArg>,
    /// Prove that a pending poison request rejects normal admission, waits for
    /// the in-flight owner to release, and leaves cleanup-only admission available.
    /// This intentionally poisons its short-lived diagnostic process.
    #[arg(
        long = "hvf-poison",
        requires = "unstable",
        conflicts_with_all = ["hvf_smoke", "hvf_boundary", "hvf_memory"],
        help_heading = "Unstable Options"
    )]
    pub hvf_poison: bool,
    /// Inject a stage-one register readback mismatch and prove that the partially
    /// programmed vCPU is destroyed and the diagnostic process is poisoned.
    #[arg(
        long = "hvf-register-failure",
        requires = "unstable",
        conflicts_with_all = ["hvf_smoke", "hvf_boundary", "hvf_memory", "hvf_poison", "hvf_unmap_failure"],
        help_heading = "Unstable Options"
    )]
    pub hvf_register_failure: bool,
    /// Perform one explicit stage-two unmap, inject stage-two protect and unmap
    /// failures, and prove exact logical quarantine, bounded cleanup retry, and
    /// cleanup-only admission after poison without claiming physical residuals.
    #[arg(
        long = "hvf-unmap-failure",
        requires = "unstable",
        conflicts_with_all = ["hvf_smoke", "hvf_boundary", "hvf_memory", "hvf_poison", "hvf_register_failure"],
        help_heading = "Unstable Options"
    )]
    pub hvf_unmap_failure: bool,
    /// Run the production HVF vCPU owner-lane diagnostic and exit.
    ///
    /// Creates a real vCPU on an owner lane, attaches it to a compact address
    /// space, executes stock `SVC #0` code through the EL1 monitor, and
    /// witnesses exact register/FPSIMD/TLS round-trips, resume semantics,
    /// collective TLBI retirement, cross-thread cancellation, the virtual
    /// timer, and zero residual vCPUs after close. The runner executable must
    /// carry the `com.apple.security.hypervisor` entitlement.
    #[arg(
        long = "hvf-vcpu",
        requires = "unstable",
        conflicts_with_all = ["hvf_smoke", "hvf_boundary", "hvf_memory", "hvf_memory_failure", "hvf_poison", "hvf_register_failure", "hvf_unmap_failure", "hvf_vcpu_failure"],
        help_heading = "HVF diagnostics"
    )]
    pub hvf_vcpu: bool,
    /// Run the process-terminal HVF vCPU failure witness and exit.
    ///
    /// Latches a raw `hv_vcpus_exit` kick on an idle vCPU so the next run
    /// returns an unauthenticated `Canceled` exit, then proves the lane retires
    /// the vCPU, abandons itself, poisons the process VM, is reaped with zero
    /// residual vCPUs, and that cleanup-admitted teardown still reaches zero
    /// address spaces. The VM stays poisoned for the rest of the process. The
    /// runner executable must carry the `com.apple.security.hypervisor`
    /// entitlement.
    #[arg(
        long = "hvf-vcpu-failure",
        requires = "unstable",
        conflicts_with_all = ["hvf_smoke", "hvf_boundary", "hvf_memory", "hvf_memory_failure", "hvf_poison", "hvf_register_failure", "hvf_unmap_failure", "hvf_vcpu"],
        help_heading = "HVF diagnostics"
    )]
    pub hvf_vcpu_failure: bool,
    /// Run the process-terminal HVF vCPU cleanup-custody witness and exit.
    ///
    /// Injects `hv_vcpu_destroy` failures for the initial destroy plus one
    /// full retry wave, then proves the owner lane reports residual vCPUs to
    /// close, keeps its owner thread and registry capacity alive as cleanup
    /// custodian, and releases both only after a later wave genuinely
    /// destroys the vCPU. Takes roughly a dozen seconds; the VM stays poisoned
    /// for the rest of the process. The runner executable must carry the
    /// `com.apple.security.hypervisor` entitlement.
    #[arg(
        long = "hvf-vcpu-custody",
        requires = "unstable",
        conflicts_with_all = ["hvf_smoke", "hvf_boundary", "hvf_memory", "hvf_memory_failure", "hvf_poison", "hvf_register_failure", "hvf_unmap_failure", "hvf_vcpu", "hvf_vcpu_failure"],
        help_heading = "HVF diagnostics"
    )]
    pub hvf_vcpu_custody: bool,
    /// Run the process-terminal HVF vCPU totality/capacity-recovery witness
    /// and exit.
    ///
    /// Fills a small dedicated lane's bounded command queue to exactly its
    /// capacity, proves the `capacity + 1`th command is rejected cleanly
    /// (`QueueOverloaded`, not a panic, hang, or silent drop) while the lane
    /// stays live and every genuinely queued command still drains, then
    /// injects a real Rust panic into the owner thread's command dispatch and
    /// proves `catch_unwind` contains it: the process does not abort, the
    /// lane is abandoned and reaped normally, and cleanup reaches exactly
    /// zero residual lanes, vCPUs, and address spaces. The VM stays poisoned
    /// for the rest of the process. The runner executable must carry the
    /// `com.apple.security.hypervisor` entitlement.
    #[arg(
        long = "hvf-vcpu-totality",
        requires = "unstable",
        conflicts_with_all = ["hvf_smoke", "hvf_boundary", "hvf_memory", "hvf_memory_failure", "hvf_poison", "hvf_register_failure", "hvf_unmap_failure", "hvf_vcpu", "hvf_vcpu_failure", "hvf_vcpu_custody"],
        help_heading = "HVF diagnostics"
    )]
    pub hvf_vcpu_totality: bool,
    /// Run the mirrored host-view witness for the HVF backend and exit.
    ///
    /// Proves that a mirrored compact address space presents every guest page
    /// to the host at its own address with guest permissions minus EXECUTE,
    /// that W^X is refused, that unmapped ranges fault recoverably, that
    /// shared backings alias, and that deferred retirements pump to zero. The
    /// runner executable must carry the `com.apple.security.hypervisor`
    /// entitlement.
    #[arg(
        long = "hvf-mirrored-view",
        requires = "unstable",
        conflicts_with_all = ["hvf_smoke", "hvf_boundary", "hvf_memory", "hvf_memory_failure", "hvf_poison", "hvf_register_failure", "hvf_unmap_failure", "hvf_vcpu", "hvf_vcpu_failure", "hvf_vcpu_custody", "hvf_vcpu_totality"],
        help_heading = "HVF diagnostics"
    )]
    pub hvf_mirrored_view: bool,
    /// Run the alias-race witness for the HVF backend and exit.
    ///
    /// Races a raw `memcpy_fallible` reader thread -- standing in for a
    /// Linux shim syscall's `UserPtr`/`UserPtrMut` dereference of the
    /// mirrored guest alias, which holds no lease and runs with the owning
    /// vCPU's `in_flight` slot already retired to zero -- against the owner
    /// thread's repeated `unmap_range`/`map_range` on the exact same GVA,
    /// with no synchronization between the two beyond what the mirrored
    /// address space itself provides. Proves the racer never observes a
    /// torn or foreign value and every fault correlates with a real unmap
    /// window, i.e. no use-after-free, no torn read that escapes the
    /// fallible API, and no wrong-permission access. The runner executable
    /// must carry the `com.apple.security.hypervisor` entitlement.
    #[arg(
        long = "hvf-alias-race",
        requires = "unstable",
        conflicts_with_all = ["hvf_smoke", "hvf_boundary", "hvf_memory", "hvf_memory_failure", "hvf_poison", "hvf_register_failure", "hvf_unmap_failure", "hvf_vcpu", "hvf_vcpu_failure", "hvf_vcpu_custody", "hvf_vcpu_totality", "hvf_mirrored_view"],
        help_heading = "HVF diagnostics"
    )]
    pub hvf_alias_race: bool,
    /// Execute the guest on the Hypervisor.framework backend.
    ///
    /// Unchanged stock AArch64 Linux binaries run at EL0 on real vCPUs: real
    /// `SVC #0` dispatches through the EL1 monitor into the Linux shim, no
    /// syscall rewriting is applied or expected, and `x18` is preserved. The
    /// tar must therefore contain stock (non-rewritten) binaries. The runner
    /// executable must carry the `com.apple.security.hypervisor` entitlement.
    #[arg(long = "hvf", requires = "unstable", help_heading = "HVF diagnostics")]
    pub hvf: bool,
    /// Install the HVF backend, drop into the Seatbelt sandbox exactly as the
    /// production runner does, then run one real `hv_vcpu_run` round-trip and
    /// exit. Proves Hypervisor.framework calls keep working with the sandbox
    /// installed, rather than only ever having been exercised without it.
    /// The runner executable must carry the `com.apple.security.hypervisor`
    /// entitlement.
    #[arg(
        long = "hvf-sandbox",
        requires = "unstable",
        conflicts_with_all = ["hvf_smoke", "hvf_boundary", "hvf_memory", "hvf_memory_failure", "hvf_poison", "hvf_register_failure", "hvf_unmap_failure", "hvf_vcpu", "hvf_vcpu_failure", "hvf_vcpu_custody", "hvf_vcpu_totality", "hvf_mirrored_view", "hvf_alias_race", "hvf_lane_starvation"],
        help_heading = "HVF diagnostics"
    )]
    pub hvf_sandbox: bool,
    /// Install the HVF backend, then prove `LANE_ACQUIRE_TIMEOUT` (60 seconds)
    /// is a genuine bound under real starvation: every pooled vCPU lane is
    /// occupied with a real spinning guest run, one more acquire is issued
    /// against the exhausted pool, and the call must block for approximately
    /// the full deadline before returning a typed timeout error rather than
    /// hanging forever or returning early. Takes just over a minute. The
    /// runner executable must carry the `com.apple.security.hypervisor`
    /// entitlement.
    #[arg(
        long = "hvf-lane-starvation",
        requires = "unstable",
        conflicts_with_all = ["hvf_smoke", "hvf_boundary", "hvf_memory", "hvf_memory_failure", "hvf_poison", "hvf_register_failure", "hvf_unmap_failure", "hvf_vcpu", "hvf_vcpu_failure", "hvf_vcpu_custody", "hvf_vcpu_totality", "hvf_mirrored_view", "hvf_alias_race", "hvf_sandbox"],
        help_heading = "HVF diagnostics"
    )]
    pub hvf_lane_starvation: bool,
    /// Install the HVF backend, then measure real wall-clock latency from a
    /// lane being released back to the pool to a concurrently blocked
    /// waiter waking and acquiring it, across many trials. Reports
    /// p50/p99/max/min/mean in nanoseconds and a trend check across the
    /// trial sequence, live evidence that the lane pool's idle wait is
    /// genuinely bounded rather than unbounded or growing. The runner
    /// executable must carry the `com.apple.security.hypervisor`
    /// entitlement.
    #[arg(
        long = "hvf-scheduler-latency",
        requires = "unstable",
        conflicts_with_all = ["hvf_smoke", "hvf_boundary", "hvf_memory", "hvf_memory_failure", "hvf_poison", "hvf_register_failure", "hvf_unmap_failure", "hvf_vcpu", "hvf_vcpu_failure", "hvf_vcpu_custody", "hvf_vcpu_totality", "hvf_mirrored_view", "hvf_alias_race", "hvf_sandbox", "hvf_lane_starvation", "hvf_scheduler_scaling"],
        help_heading = "HVF diagnostics"
    )]
    pub hvf_scheduler_latency: bool,
    /// Install the HVF backend, then measure real wall-clock scaling of
    /// independent, non-yielding compute-bound guest threads at
    /// concurrency 1, 2, 4, 8 (bounded by the lane pool's own size): each
    /// worker spins an unbounded ALU loop on its own disjoint mapped page,
    /// time-sliced by the production VTimer exactly as `run_thread` does.
    /// Reports summed time-slice throughput and measured speedup per level
    /// -- near-linear scaling up to the lane/core count is live evidence
    /// that independent vCPUs make concurrent progress rather than
    /// serializing behind a shared lock. The runner executable must carry
    /// the `com.apple.security.hypervisor` entitlement.
    #[arg(
        long = "hvf-scheduler-scaling",
        requires = "unstable",
        conflicts_with_all = ["hvf_smoke", "hvf_boundary", "hvf_memory", "hvf_memory_failure", "hvf_poison", "hvf_register_failure", "hvf_unmap_failure", "hvf_vcpu", "hvf_vcpu_failure", "hvf_vcpu_custody", "hvf_vcpu_totality", "hvf_mirrored_view", "hvf_alias_race", "hvf_sandbox", "hvf_lane_starvation", "hvf_scheduler_latency"],
        help_heading = "HVF diagnostics"
    )]
    pub hvf_scheduler_scaling: bool,
    /// Connect to a `utun` device with this name (e.g. `utun4`).
    ///
    /// Creating the interface needs root on this host, so the guest has no
    /// network unless one is named.
    #[arg(
        long = "tun-device-name",
        requires = "unstable",
        help_heading = "Unstable Options"
    )]
    pub tun_device_name: Option<String>,
    /// Override this guest's own address (default: `10.0.0.2`). Needed to run
    /// more than one instance on the same host at once, each independently
    /// reachable — a CLI flag rather than an env var so it survives a
    /// `sudo`-invoked launch even under `env_reset` (the default policy),
    /// which strips arbitrary environment variables but never argv.
    #[arg(
        long = "guest-ip",
        requires = "unstable",
        help_heading = "Unstable Options"
    )]
    pub guest_ip: Option<std::net::Ipv4Addr>,
    /// Override this guest's default-route gateway (default: `10.0.0.1`).
    /// See `--guest-ip`.
    #[arg(
        long = "gateway-ip",
        requires = "unstable",
        help_heading = "Unstable Options"
    )]
    pub gateway_ip: Option<std::net::Ipv4Addr>,
    /// Serve the guest's `/dev/fb0` framebuffer over VNC (RFB), for a real desktop viewer to
    /// connect to. Binds `127.0.0.1` only by default -- see `--vnc-bind-all` to widen that.
    #[arg(long = "vnc", requires = "unstable", help_heading = "Unstable Options")]
    pub vnc: bool,
    /// Port the VNC server listens on when `--vnc` is set (default: `5900`, the conventional RFB
    /// display-0 port).
    #[arg(
        long = "vnc-port",
        requires = "vnc",
        default_value_t = 5900,
        help_heading = "Unstable Options"
    )]
    pub vnc_port: u16,
    /// Bind the VNC server to all interfaces (`0.0.0.0`) instead of the localhost-only default.
    /// Off by default: the guest framebuffer is unauthenticated RFB with no encryption, so
    /// widening past localhost exposes it to the local network without so much as a password.
    #[arg(
        long = "vnc-bind-all",
        requires = "vnc",
        help_heading = "Unstable Options"
    )]
    pub vnc_bind_all: bool,
    /// Serve a browser-based viewer for the guest's `/dev/fb0` on this HTTP port: open
    /// `http://127.0.0.1:<port>/` for a canvas with full keyboard and mouse. Same
    /// framebuffer/input plumbing as `--vnc` without needing a VNC client (macOS's built-in
    /// Screen Sharing refuses to dial localhost). Binds `127.0.0.1` only.
    #[arg(
        long = "vnc-web",
        value_name = "PORT",
        requires = "unstable",
        help_heading = "Unstable Options"
    )]
    pub vnc_web: Option<u16>,
    /// Give the guest rootless network access: an HTTP proxy (CONNECT + absolute-URI) on the
    /// guest's loopback at `127.0.0.1:3128`, a DNS responder, and a bounded ICMP Echo bridge for
    /// `ping`, all backed by ordinary host sockets. Standard lowercase and uppercase HTTP(S)
    /// proxy environment variables default to the HTTP endpoint and can be overridden with
    /// `--env`. Widens the Seatbelt profile with `(allow network-outbound)` -- outbound only;
    /// inbound stays denied.
    #[arg(
        long = "net-proxy",
        requires = "unstable",
        help_heading = "Unstable Options"
    )]
    pub net_proxy: bool,
    /// Present the guest with root identity (uid/gid 0) instead of the default synthetic
    /// uid 1000. The identity is synthetic either way -- isolation comes from the litebox
    /// layer, not the guest uid -- but a desktop stack (Xorg's `-nolock`, dbus, session
    /// managers) hard-checks for root in places a single-user appliance image never needs
    /// to distinguish.
    #[arg(
        long = "guest-root",
        requires = "unstable",
        help_heading = "Unstable Options"
    )]
    pub guest_root: bool,
}

/// Translate an RFB `KeyEvent` keysym into the byte sequence a Linux console keyboard would
/// deliver on that key, for feeding the guest's stdin. Latin-1 keysyms are their own byte
/// (X11 keysyms already encode the shifted character); control keys map to the `linux`
/// terminfo sequences. `ctrl` folds letters onto C0 controls the way a terminal does.
/// Returns `None` for keysyms with no console byte representation (bare modifiers,
/// multimedia keys).
fn keysym_to_tty_bytes(keysym: u32, ctrl: bool) -> Option<Vec<u8>> {
    if ctrl {
        // ^A..^Z (either letter case), plus the punctuation controls a terminal produces.
        let c = if (0x61..=0x7a).contains(&keysym) {
            keysym - 0x20
        } else {
            keysym
        };
        if (0x40..=0x5f).contains(&c) {
            return Some(vec![u8::try_from(c & 0x1f).unwrap_or(0)]);
        }
    }
    match keysym {
        // Latin-1 printables (X keysyms 0x20..=0xff are the characters themselves).
        0x20..=0x7e | 0xa0..=0xff => Some(vec![u8::try_from(keysym).unwrap_or(b'?')]),
        0xff0d | 0xff8d => Some(vec![b'\r']), // Return / KP_Enter
        0xff08 => Some(vec![0x7f]),           // BackSpace (linux console sends DEL)
        0xff09 => Some(vec![b'\t']),          // Tab
        0xff1b => Some(vec![0x1b]),           // Escape
        0xff51 => Some(b"\x1b[D".to_vec()),   // Left
        0xff52 => Some(b"\x1b[A".to_vec()),   // Up
        0xff53 => Some(b"\x1b[C".to_vec()),   // Right
        0xff54 => Some(b"\x1b[B".to_vec()),   // Down
        0xff50 => Some(b"\x1b[1~".to_vec()),  // Home
        0xff57 => Some(b"\x1b[4~".to_vec()),  // End
        0xff55 => Some(b"\x1b[5~".to_vec()),  // Page Up
        0xff56 => Some(b"\x1b[6~".to_vec()),  // Page Down
        0xff63 => Some(b"\x1b[2~".to_vec()),  // Insert
        0xffff => Some(b"\x1b[3~".to_vec()),  // Delete
        0xffbe => Some(b"\x1b[[A".to_vec()),  // F1 (linux console)
        0xffbf => Some(b"\x1b[[B".to_vec()),  // F2
        0xffc0 => Some(b"\x1b[[C".to_vec()),  // F3
        0xffc1 => Some(b"\x1b[[D".to_vec()),  // F4
        0xffc2 => Some(b"\x1b[[E".to_vec()),  // F5
        0xffc3 => Some(b"\x1b[17~".to_vec()), // F6
        0xffc4 => Some(b"\x1b[18~".to_vec()), // F7
        0xffc5 => Some(b"\x1b[19~".to_vec()), // F8
        0xffc6 => Some(b"\x1b[20~".to_vec()), // F9
        0xffc7 => Some(b"\x1b[21~".to_vec()), // F10
        _ => None,
    }
}

#[derive(Default)]
struct InputClientState {
    held_keys: std::collections::BTreeSet<u16>,
    button_mask: u8,
}

#[derive(Default)]
struct InputRouterState {
    clients: std::collections::BTreeMap<litebox_rfb::InputClientId, InputClientState>,
    key_owners: std::collections::BTreeMap<u16, usize>,
    button_owners: [usize; 3],
    latest_pointer: (u16, u16),
}

struct InputRouter {
    input_registry: Option<litebox::fs::devices::InputRegistry<Platform>>,
    input_framebuffer: Option<litebox::fs::devices::Framebuffer<Platform>>,
    platform: &'static Platform,
    epoch: std::time::Instant,
    state: std::sync::Mutex<InputRouterState>,
}

impl InputRouter {
    fn pointer_coordinates(&self, p: litebox_rfb::PointerEvent) -> (i32, i32) {
        let (width, height) = self.input_framebuffer.as_ref().map_or((1024, 768), |fb| {
            let geo = fb.geometry();
            (geo.xres.max(1), geo.yres.max(1))
        });
        let range = i64::from(litebox::fs::devices::ABS_RANGE_MAX);
        let scale = |v: u16, extent: u32| -> i32 {
            let clamped = i64::from(v).min(i64::from(extent) - 1);
            i32::try_from(clamped * range / i64::from(extent.max(1)))
                .unwrap_or(litebox::fs::devices::ABS_RANGE_MAX)
        };
        (scale(p.x, width), scale(p.y, height))
    }

    fn inject_pointer(
        &self,
        registry: &litebox::fs::devices::InputRegistry<Platform>,
        p: litebox_rfb::PointerEvent,
        aggregate_buttons: u8,
        transitions: &[(u16, bool)],
        wheel: i8,
        now: std::time::Duration,
    ) {
        let (x, y) = self.pointer_coordinates(p);
        registry.inject_pointer_abs(x, y, transitions, now);
        if wheel != 0 {
            registry.inject_wheel(-i32::from(wheel), now);
        }
        let ps2_buttons = (aggregate_buttons & 0x01)
            | ((aggregate_buttons >> 2) & 0x01) << 1
            | ((aggregate_buttons >> 1) & 0x01) << 2;
        registry.inject_mice_pointer(i32::from(p.x), i32::from(p.y), ps2_buttons, wheel);
    }

    fn handle(&self, message: litebox_rfb::InputMessage) {
        let Some(registry) = self.input_registry.as_ref() else {
            return;
        };
        let now = self.epoch.elapsed();
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut tty_bytes = None;
        match message {
            litebox_rfb::InputMessage::Connected(client) => {
                state.clients.entry(client).or_default();
            }
            litebox_rfb::InputMessage::Event { client, event } => match event {
                litebox_rfb::InputEvent::Key(key) => {
                    if let Some(code) = litebox_rfb::keymap::keysym_to_evdev(key.key) {
                        let Some(client_state) = state.clients.get_mut(&client) else {
                            return;
                        };
                        let changed = if key.down {
                            client_state.held_keys.insert(code)
                        } else {
                            client_state.held_keys.remove(&code)
                        };
                        if changed {
                            if key.down {
                                let owners = state.key_owners.entry(code).or_default();
                                *owners += 1;
                                if *owners == 1 {
                                    registry.inject_key(code, true, now);
                                }
                            } else if let Some(owners) = state.key_owners.get_mut(&code) {
                                *owners -= 1;
                                if *owners == 0 {
                                    state.key_owners.remove(&code);
                                    registry.inject_key(code, false, now);
                                }
                            }
                        }
                        if key.down {
                            let ctrl = state.key_owners.contains_key(&29)
                                || state.key_owners.contains_key(&97);
                            tty_bytes = keysym_to_tty_bytes(key.key, ctrl);
                        }
                    } else if key.down {
                        tty_bytes = keysym_to_tty_bytes(key.key, false);
                    }
                }
                litebox_rfb::InputEvent::Pointer(p) => {
                    let Some(client_state) = state.clients.get_mut(&client) else {
                        return;
                    };
                    let old_mask = client_state.button_mask;
                    client_state.button_mask = p.button_mask;
                    state.latest_pointer = (p.x, p.y);
                    let changed = old_mask ^ p.button_mask;
                    let mut transitions = Vec::new();
                    for (index, btn) in [
                        litebox::fs::devices::BTN_LEFT,
                        litebox::fs::devices::BTN_MIDDLE,
                        litebox::fs::devices::BTN_RIGHT,
                    ]
                    .into_iter()
                    .enumerate()
                    {
                        let bit = 1u8 << index;
                        if changed & bit == 0 {
                            continue;
                        }
                        let down = p.button_mask & bit != 0;
                        if down {
                            state.button_owners[index] += 1;
                            if state.button_owners[index] == 1 {
                                transitions.push((btn, true));
                            }
                        } else {
                            state.button_owners[index] -= 1;
                            if state.button_owners[index] == 0 {
                                transitions.push((btn, false));
                            }
                        }
                    }
                    let aggregate_buttons = state
                        .button_owners
                        .iter()
                        .enumerate()
                        .fold(0u8, |mask, (index, owners)| {
                            mask | u8::from(*owners != 0) << index
                        });
                    let wheel = if changed & (1 << 3) != 0 && p.button_mask & (1 << 3) != 0 {
                        -1
                    } else {
                        i8::from(changed & (1 << 4) != 0 && p.button_mask & (1 << 4) != 0)
                    };
                    self.inject_pointer(registry, p, aggregate_buttons, &transitions, wheel, now);
                }
            },
            litebox_rfb::InputMessage::Disconnected(client) => {
                let Some(client_state) = state.clients.remove(&client) else {
                    return;
                };
                for code in client_state.held_keys {
                    if let Some(owners) = state.key_owners.get_mut(&code) {
                        *owners -= 1;
                        if *owners == 0 {
                            state.key_owners.remove(&code);
                            registry.inject_key(code, false, now);
                        }
                    }
                }
                let mut transitions = Vec::new();
                for (index, btn) in [
                    litebox::fs::devices::BTN_LEFT,
                    litebox::fs::devices::BTN_MIDDLE,
                    litebox::fs::devices::BTN_RIGHT,
                ]
                .into_iter()
                .enumerate()
                {
                    if client_state.button_mask & (1 << index) != 0 {
                        state.button_owners[index] -= 1;
                        if state.button_owners[index] == 0 {
                            transitions.push((btn, false));
                        }
                    }
                }
                if !transitions.is_empty() {
                    let aggregate_buttons = state
                        .button_owners
                        .iter()
                        .enumerate()
                        .fold(0u8, |mask, (index, owners)| {
                            mask | u8::from(*owners != 0) << index
                        });
                    let p = litebox_rfb::PointerEvent {
                        button_mask: aggregate_buttons,
                        x: state.latest_pointer.0,
                        y: state.latest_pointer.1,
                    };
                    self.inject_pointer(registry, p, aggregate_buttons, &transitions, 0, now);
                }
            }
        }
        drop(state);
        if let Some(bytes) = tty_bytes {
            let _ = self.platform.inject_stdin(&bytes);
        }
    }
}

/// Build a cloneable callback that routes every RFB and browser connection through one shared
/// ownership model before injecting aggregate evdev, PS/2-mouse, and tty input.
fn build_input_handler(
    input_registry: Option<litebox::fs::devices::InputRegistry<Platform>>,
    input_framebuffer: Option<litebox::fs::devices::Framebuffer<Platform>>,
    platform: &'static Platform,
) -> impl Fn(litebox_rfb::InputMessage) + Clone + Send + Sync + 'static {
    let router = std::sync::Arc::new(InputRouter {
        input_registry,
        input_framebuffer,
        platform,
        epoch: std::time::Instant::now(),
        state: std::sync::Mutex::new(InputRouterState::default()),
    });
    move |message| router.handle(message)
}

/// Run a Linux program with LiteBox on unmodified macOS.
///
/// # Errors
///
/// Returns an error when the tar archive cannot be read, or when the shim
/// cannot load the requested program out of it.
///
/// # Panics
///
/// Panics if the host is not set up as expected -- notably if a second guest
/// thread starts, which this platform's process-global guest-entry save area
/// does not yet support (see `docs/roadmap.md`).
pub fn run(cli_args: CliArgs) -> Result<()> {
    tracing_subscriber::fmt()
        .with_timer(tracing_subscriber::fmt::time::uptime())
        .with_level(true)
        .with_env_filter(
            tracing_subscriber::EnvFilter::builder()
                .with_env_var("LITEBOX_LOG")
                .from_env_lossy(),
        )
        .init();

    if cli_args.hvf_smoke {
        let report = litebox_platform_macos_userland::hvf_smoke_probe()
            .map_err(|error| anyhow!("HVF smoke failed: {error}"))?;
        println!("HVF smoke passed:\n{report:#?}");
        return Ok(());
    }

    if cli_args.hvf_boundary {
        let report = litebox_platform_macos_userland::hvf_boundary_probe()
            .map_err(|error| anyhow!("HVF production boundary failed: {error}"))?;
        println!("HVF production boundary passed:\n{report:#?}");
        return Ok(());
    }

    if cli_args.hvf_memory {
        litebox_platform_macos_userland::with_hvf_memory_probe(|report| {
            println!("HVF compact memory passed:\n{report:#?}");
        })
        .map_err(|error| anyhow!("HVF compact memory failed: {error}"))?;
        return Ok(());
    }

    if cli_args.hvf_memory_failure {
        litebox_platform_macos_userland::with_hvf_memory_failure_probe(|report| {
            println!("HVF compact-memory failure recovery passed:\n{report:#?}");
        })
        .map_err(|error| anyhow!("HVF compact-memory failure recovery failed: {error}"))?;
        return Ok(());
    }

    if cli_args.hvf_alias_panic_failure {
        let report = litebox_platform_macos_userland::hvf_alias_panic_failure_probe()
            .map_err(|error| anyhow!("HVF alias-panic recovery failed: {error}"))?;
        println!("HVF alias-panic recovery passed:\n{report:#?}");
        return Ok(());
    }

    if let Some(operation) = cli_args.hvf_published_panic {
        let operation = match operation {
            HvfPublishedPanicOperationArg::Exclusive => {
                litebox_platform_macos_userland::HvfPublishedPanicOperation::Exclusive
            }
            HvfPublishedPanicOperationArg::Shared => {
                litebox_platform_macos_userland::HvfPublishedPanicOperation::Shared
            }
            HvfPublishedPanicOperationArg::ExistingVcpu => {
                litebox_platform_macos_userland::HvfPublishedPanicOperation::ExistingVcpu
            }
        };
        let report = litebox_platform_macos_userland::hvf_published_panic_probe(operation)
            .map_err(|error| anyhow!("HVF published-panic serialization failed: {error}"))?;
        println!("HVF published-panic serialization passed:\n{report:#?}");
        return Ok(());
    }

    if cli_args.hvf_poison {
        let report = litebox_platform_macos_userland::hvf_poison_concurrency_probe()
            .map_err(|error| anyhow!("HVF poison serialization failed: {error}"))?;
        println!("HVF poison serialization passed:\n{report:#?}");
        return Ok(());
    }

    if cli_args.hvf_register_failure {
        let report = litebox_platform_macos_userland::hvf_register_failure_probe()
            .map_err(|error| anyhow!("HVF register-failure quarantine failed: {error}"))?;
        println!("HVF register-failure quarantine passed:\n{report:#?}");
        return Ok(());
    }

    if cli_args.hvf_unmap_failure {
        let report = litebox_platform_macos_userland::hvf_unmap_failure_probe()
            .map_err(|error| anyhow!("HVF unmap-failure quarantine failed: {error}"))?;
        println!("HVF unmap-failure quarantine passed:\n{report:#?}");
        return Ok(());
    }

    if cli_args.hvf_vcpu {
        let report = litebox_platform_macos_userland::hvf_vcpu_diagnostic_probe()
            .map_err(|error| anyhow!("HVF vCPU owner-lane diagnostic failed: {error}"))?;
        println!("HVF vCPU owner-lane diagnostic passed:\n{report:#?}");
        return Ok(());
    }

    if cli_args.hvf_vcpu_failure {
        let report = litebox_platform_macos_userland::hvf_vcpu_failure_probe()
            .map_err(|error| anyhow!("HVF vCPU terminal-exit witness failed: {error}"))?;
        println!("HVF vCPU terminal-exit witness passed:\n{report:#?}");
        return Ok(());
    }

    if cli_args.hvf_vcpu_custody {
        let report = litebox_platform_macos_userland::hvf_vcpu_custody_probe()
            .map_err(|error| anyhow!("HVF vCPU cleanup-custody witness failed: {error}"))?;
        println!("HVF vCPU cleanup-custody witness passed:\n{report:#?}");
        return Ok(());
    }

    if cli_args.hvf_vcpu_totality {
        let report =
            litebox_platform_macos_userland::hvf_vcpu_totality_probe().map_err(|error| {
                anyhow!("HVF vCPU totality/capacity-recovery witness failed: {error}")
            })?;
        println!("HVF vCPU totality/capacity-recovery witness passed:\n{report:#?}");
        return Ok(());
    }

    if cli_args.hvf_mirrored_view {
        let report = litebox_platform_macos_userland::hvf_mirrored_view_probe()
            .map_err(|error| anyhow!("HVF mirrored host view failed: {error}"))?;
        println!("HVF mirrored host view passed:\n{report:#?}");
        return Ok(());
    }

    if cli_args.hvf_alias_race {
        let report = litebox_platform_macos_userland::hvf_alias_race_probe()
            .map_err(|error| anyhow!("HVF alias-race witness failed: {error}"))?;
        println!("HVF alias-race witness passed:\n{report:#?}");
        return Ok(());
    }

    if cli_args.hvf_sandbox {
        Platform::new_with_hvf(cli_args.tun_device_name.as_deref(), false)
            .map_err(|error| anyhow!("failed to install the HVF guest backend: {error}"))?;
        litebox_platform_macos_userland::enable_seatbelt_sandbox();
        litebox_platform_macos_userland::hvf_sandbox_probe()
            .map_err(|error| anyhow!("HVF-under-Seatbelt witness failed: {error}"))?;
        println!("HVF vCPU round-trip under the Seatbelt sandbox passed");
        return Ok(());
    }

    if cli_args.hvf_lane_starvation {
        Platform::new_with_hvf(cli_args.tun_device_name.as_deref(), false)
            .map_err(|error| anyhow!("failed to install the HVF guest backend: {error}"))?;
        let report = litebox_platform_macos_userland::hvf_lane_starvation_probe()
            .map_err(|error| anyhow!("HVF lane starvation witness failed: {error}"))?;
        println!("HVF lane starvation witness passed:\n{report:#?}");
        let replacement_report = litebox_platform_macos_userland::hvf_lane_replacement_probe()
            .map_err(|error| anyhow!("HVF lane replacement witness failed: {error}"))?;
        println!("HVF lane replacement witness passed:\n{replacement_report:#?}");
        return Ok(());
    }

    if cli_args.hvf_scheduler_latency {
        Platform::new_with_hvf(cli_args.tun_device_name.as_deref(), false)
            .map_err(|error| anyhow!("failed to install the HVF guest backend: {error}"))?;
        let report = litebox_platform_macos_userland::hvf_scheduler_latency_probe()
            .map_err(|error| anyhow!("HVF scheduler latency probe failed: {error}"))?;
        println!("HVF scheduler latency probe passed:\n{report:#?}");
        return Ok(());
    }

    if cli_args.hvf_scheduler_scaling {
        Platform::new_with_hvf(cli_args.tun_device_name.as_deref(), false)
            .map_err(|error| anyhow!("failed to install the HVF guest backend: {error}"))?;
        let report = litebox_platform_macos_userland::hvf_scheduler_scaling_probe()
            .map_err(|error| anyhow!("HVF scheduler scaling probe failed: {error}"))?;
        println!("HVF scheduler scaling probe passed:\n{report:#?}");
        return Ok(());
    }

    let tar_file = cli_args
        .initial_files
        .as_ref()
        .expect("clap requires --initial-files unless an HVF diagnostic is selected");
    if tar_file.extension().and_then(|x| x.to_str()) != Some("tar") {
        anyhow::bail!("Expected a .tar file, found {}", tar_file.display());
    }
    let tar_data = std::fs::read(tar_file)
        .map_err(|e| anyhow!("Could not read tar file at {}: {}", tar_file.display(), e))?;

    // `--vnc`/`--vnc-web` make the viewer keyboard a second stdin producer, so a
    // closed/redirected host stdin must not read as EOF to the guest (a console program
    // would exit on it).
    let hold_stdin_open = cli_args.vnc || cli_args.vnc_web.is_some();
    let platform = if cli_args.hvf {
        Platform::new_with_hvf(cli_args.tun_device_name.as_deref(), hold_stdin_open)
            .map_err(|error| anyhow!("failed to install the HVF guest backend: {error}"))?
    } else {
        Platform::new_with_options(cli_args.tun_device_name.as_deref(), hold_stdin_open)
    };
    let shim_builder = litebox_shim_linux::LinuxShimBuilder::new(platform);
    let litebox = shim_builder.litebox();

    // The program path is a Unix-style path inside the tar archive.
    let prog_path = &cli_args.program_and_arguments[0];

    let initial_file_system = {
        let mut in_mem = litebox::fs::in_mem::FileSystem::new(litebox);
        in_mem.with_root_privileges(|fs| {
            use litebox::fs::FileSystem as _;
            fs.mkdir(
                "/tmp",
                litebox::fs::Mode::RWXU | litebox::fs::Mode::RWXG | litebox::fs::Mode::RWXO,
            )
            .unwrap_or_else(|e| {
                panic!("/tmp creation cannot fail on a fresh in-memory file system: {e}")
            });
            fs.chown("/tmp", Some(1000), Some(1000))
                .unwrap_or_else(|e| {
                    panic!("/tmp chown cannot fail on a fresh in-memory file system: {e}")
                });

            // Standard FHS directories that guest tools expect to already exist (e.g. `apk`
            // opens a log file under `/var/log`) but that don't survive as empty-directory
            // entries when an OCI image's rootfs is scanned into a file-based tar: an empty
            // directory has no file contents, so it produces no tar entry, and `TarRo`'s
            // directory tree is inferred purely from file paths.
            for dir in ["/run", "/var", "/var/log", "/var/cache", "/var/tmp"] {
                fs.mkdir(
                    dir,
                    litebox::fs::Mode::RWXU | litebox::fs::Mode::RWXG | litebox::fs::Mode::RWXO,
                )
                .unwrap_or_else(|_| {
                    panic!("{dir} creation cannot fail on a fresh in-memory file system")
                });
            }
        });

        if cli_args.guest_root {
            // Files the guest creates must be owned by the identity the guest runs as; see
            // `set_current_user`'s doc comment for the X/dbus failures a mismatch causes.
            in_mem.set_current_user(0, 0);
        }

        shim_builder.default_fs(in_mem, tar_data.into())
    };
    let initial_file_system = std::sync::Arc::new(initial_file_system);

    // Per-invocation network identity override (mirrors the Linux host
    // runner's fleet-hive patch): lets many concurrent litebox processes on
    // one host each own a distinct, independently-reachable address instead
    // of all defaulting to the same hardcoded 10.0.0.2/10.0.0.1. Unset =
    // identical to upstream behavior. CLI flags rather than env vars
    // (`--guest-ip`/`--gateway-ip`, `CliArgs`) — a `sudo`-invoked launch
    // under the default `env_reset` policy strips arbitrary env vars
    // (confirmed live: "sudo: sorry, you are not allowed to set the
    // following environment variables") but always passes argv through.
    let shim = shim_builder.build_with_net_config(cli_args.guest_ip, cli_args.gateway_ip);

    // Bind AND run the VNC server's whole accept loop before the Seatbelt sandbox below, which
    // denies every syscall not explicitly allowed -- and unlike a plain read/write on an
    // already-open fd (stdio, the `utun` device -- see the sandbox call's own comment below),
    // `accept()` on a listening socket is itself a mediated network operation with no `allow`
    // rule in this profile, so it cannot run post-sandbox. This mirrors the tar-file read and
    // `utun` device open above: every host resource the process will ever need must be acquired
    // -- and here, USED -- before `enable_seatbelt_sandbox()` runs. Concretely: spawn the whole
    // `RfbServer::run` (bind already happened in `RfbServer::bind`, accept-loop-and-serve
    // happens in the spawned thread) before the sandbox call; Seatbelt restrictions apply
    // process-wide and are inherited by every thread (per this crate's own seatbelt module doc
    // comment), so a thread spawned pre-sandbox keeps running exactly as before after the main
    // thread sandboxes itself.
    let input_handler = build_input_handler(shim.input_registry(), shim.framebuffer(), platform);
    let vnc_worker = if cli_args.vnc {
        let framebuffer = shim
            .framebuffer()
            .ok_or_else(|| anyhow!("--vnc requires a filesystem that mounts /dev/fb0"))?;
        let bind_addr = cli_args
            .vnc_bind_all
            .then_some(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));
        let server = litebox_rfb::RfbServer::bind(
            bind_addr,
            cli_args.vnc_port,
            std::sync::Arc::new(FramebufferAdapter(framebuffer)),
        )
        .map_err(|e| {
            anyhow!(
                "failed to bind VNC listener on port {}: {e}\n\
                 (most often another runner instance is still running -- stop it or pick a \
                 different --vnc-port)",
                cli_args.vnc_port
            )
        })?;
        litebox_util_log::info!(
            addr:% = server.local_addr().map_err(|e| anyhow!("{e}"))?;
            "vnc server listening"
        );
        let shutdown_handle = server.shutdown_handle();
        let on_input = input_handler.clone();
        let worker = std::thread::spawn(move || {
            if let Err(e) = server.run(on_input) {
                litebox_util_log::warn!(error:% = e; "vnc server stopped");
            }
        });
        Some((worker, shutdown_handle))
    } else {
        None
    };

    // The browser-based viewer: identical lifecycle to the VNC server (bind + spawn before
    // the sandbox; Seatbelt denies post-sandbox `accept()`), identical input plumbing.
    if let Some(port) = cli_args.vnc_web {
        let framebuffer = shim
            .framebuffer()
            .ok_or_else(|| anyhow!("--vnc-web requires a filesystem that mounts /dev/fb0"))?;
        let server = litebox_rfb::web::WebServer::bind(
            None,
            port,
            std::sync::Arc::new(FramebufferAdapter(framebuffer)),
        )
        .map_err(|e| {
            anyhow!(
                "failed to bind the web viewer listener on port {port}: {e}\n\
                 (most often another runner instance is still running -- stop it or pick a \
                 different --vnc-web port)"
            )
        })?;
        litebox_util_log::info!(
            addr:% = server.local_addr().map_err(|e| anyhow!("{e}"))?;
            "web viewer listening -- open http://127.0.0.1 at this port"
        );
        let on_input = input_handler.clone();
        std::thread::spawn(move || {
            if let Err(e) = server.run(on_input) {
                litebox_util_log::warn!(error:% = e; "web viewer server stopped");
            }
        });
    }

    // The guest-web-access bridge. Same lifecycle position and reasoning as the VNC server
    // above: the in-guest listener and the resolver snapshot (`/etc/resolv.conf` becomes
    // unreadable under the sandbox) must both exist before `enable_seatbelt_sandbox*` runs;
    // the widened profile then keeps the bridge's outbound `connect`s working after.
    if cli_args.net_proxy {
        // With no utun attached, non-proxied outbound packets otherwise have nowhere
        // to go; the engine makes plain guest TCP/UDP work alongside the proxied
        // services below. utun precedence is also enforced in the platform's
        // send/receive bodies.
        if cli_args.tun_device_name.is_none() {
            platform.enable_nat_engine();
        }
        let listener = shim
            .listen_in_guest(std::net::SocketAddr::from(net_proxy::PROXY_ADDR), 16)
            .map_err(|e| anyhow!("failed to start the in-guest proxy listener: {e:?}"))?;
        let resolvers = net_proxy::snapshot_resolvers();
        let tls = net_proxy::build_tls_client_config()
            .map_err(|e| anyhow!("failed to load host TLS trust roots: {e}"))?;
        litebox_util_log::info!(
            addr:? = net_proxy::PROXY_ADDR, resolvers:? = resolvers;
            "guest http proxy listening"
        );
        let dns_socket = shim
            .bind_udp_in_guest(std::net::SocketAddr::from(net_proxy::DNS_ADDR))
            .map_err(|e| anyhow!("failed to start the in-guest DNS responder: {e:?}"))?;
        litebox_util_log::info!(
            addr:? = net_proxy::DNS_ADDR;
            "guest dns responder listening"
        );
        let icmp_host = net_proxy::open_icmp_socket()
            .map_err(|e| anyhow!("failed to open the host ICMP echo socket: {e}"))?;
        let icmp_socket = shim
            .bind_udp_in_guest(std::net::SocketAddr::V4(litebox::net::ICMP_ECHO_PROXY_ADDR))
            .map_err(|e| anyhow!("failed to start the in-guest ICMP echo bridge: {e:?}"))?;
        litebox_util_log::info!(
            addr:% = litebox::net::ICMP_ECHO_PROXY_ADDR;
            "guest ICMP echo bridge listening"
        );
        // The addresses the shim's network was built with (`build_with_net_config` above):
        // the DNS responder answers the guest's own host name with the interface address, and
        // the ICMP bridge answers echoes to either address itself.
        let interface_ip = cli_args.guest_ip.unwrap_or(litebox::net::INTERFACE_IP_ADDR);
        let gateway_ip = cli_args.gateway_ip.unwrap_or(litebox::net::GATEWAY_IP_ADDR);
        let dns_resolvers = resolvers.clone();
        std::thread::spawn(move || {
            net_proxy::serve_dns(&dns_socket, dns_resolvers, interface_ip);
        });
        std::thread::spawn(move || {
            net_proxy::serve_icmp(&icmp_socket, icmp_host, [interface_ip, gateway_ip]);
        });
        std::thread::spawn(move || net_proxy::serve(&listener, resolvers, tls));
    }

    let argv = cli_args
        .program_and_arguments
        .iter()
        .map(|x| {
            std::ffi::CString::new(x.bytes().collect::<Vec<u8>>())
                .map_err(|e| anyhow!("program argument {x:?} contains an embedded NUL byte: {e}"))
        })
        .collect::<Result<Vec<_>>>()?;
    let mut guest_environment = cli_args.environment_variables.clone();
    // The loopback proxy environment was the guest's only way out when `--net-proxy` had no
    // external path. With the rootless NAT engine (no `--tun-device-name`) the guest routes
    // directly, exactly as on Linux; pointing every HTTP client at the proxy would only add a
    // hop and hide the direct path from programs (Chromium, apk, wget) that honour
    // `https_proxy`. The proxy itself keeps listening for clients that ask for it explicitly.
    if cli_args.net_proxy && cli_args.tun_device_name.is_some() {
        const PROXY_URL: &str = "http://127.0.0.1:3128";
        for (name, value) in [
            ("http_proxy", PROXY_URL),
            ("https_proxy", PROXY_URL),
            ("HTTP_PROXY", PROXY_URL),
            ("HTTPS_PROXY", PROXY_URL),
            ("no_proxy", "localhost,127.0.0.1,::1"),
            ("NO_PROXY", "localhost,127.0.0.1,::1"),
        ] {
            if !guest_environment
                .iter()
                .any(|entry| entry.split_once('=').is_some_and(|(key, _)| key == name))
            {
                guest_environment.push(format!("{name}={value}"));
            }
        }
    }
    if cli_args.forward_environment_variables {
        for (name, value) in std::env::vars() {
            if !guest_environment
                .iter()
                .any(|entry| entry.split_once('=').is_some_and(|(key, _)| key == name))
            {
                guest_environment.push(format!("{name}={value}"));
            }
        }
    }
    // No init or login shell ever runs in this guest to set PATH, and ash's built-in default
    // is used for its own lookups but never exported, so a setuid helper like `doas` (which
    // runs its target with the `PATH` it finds in the environment) sees none at all.
    if !guest_environment
        .iter()
        .any(|entry| entry.split_once('=').is_some_and(|(key, _)| key == "PATH"))
    {
        guest_environment
            .push("PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".to_owned());
    }
    let envp = guest_environment
        .iter()
        .map(|entry| {
            std::ffi::CString::new(entry.bytes().collect::<Vec<u8>>()).map_err(|e| {
                anyhow!("environment variable {entry:?} contains an embedded NUL byte: {e}")
            })
        })
        .collect::<Result<Vec<_>>>()?;

    // Drop into the Seatbelt sandbox before any guest-controlled byte is parsed.
    // This is the exact counterpart, and the exact lifecycle position, of the
    // Linux runner's `enable_seccomp_filter` call: every host resource this
    // process will ever need has been acquired by now (the tar archive is read
    // into memory above, the `utun` device was opened in `Platform::new`, stdio
    // was sampled there too), and the very next thing that happens is
    // `load_program` running an ELF parser over attacker-chosen bytes.
    //
    // This panics rather than warning if the sandbox cannot be installed; see
    // `enable_seatbelt_sandbox`'s doc comment for the fail-safe argument.
    if cli_args.net_proxy {
        litebox_platform_macos_userland::enable_seatbelt_sandbox_with_outbound_network();
    } else {
        litebox_platform_macos_userland::enable_seatbelt_sandbox();
    }

    let mut task_params = platform.init_task();
    if cli_args.guest_root {
        task_params.uid = 0;
        task_params.euid = 0;
        task_params.gid = 0;
        task_params.egid = 0;
    }
    let program = shim.load_program(initial_file_system, task_params, prog_path, argv, envp)?;

    // Drive the network stack. The shim keeps its smoltcp interface in
    // `Manual` mode -- nothing polls it unless a runner does -- and the Linux
    // runner spawns this exact loop, but only when a `--tun` device is
    // present. macOS has no tun by default, yet still needs the poll to run:
    // in-process loopback (a guest binding a server on `127.0.0.1` and
    // reaching it from the same process -- a Node `http` server, and the many
    // test frameworks and IPC paths that assume a working loopback) is entirely
    // driven by this poll. Without it every TCP handshake stalls, because the
    // SYN a `connect` queues is never egressed. A short bounded sleep between
    // polls keeps loopback latency low without a hot spin; there is no tun to
    // block on here.
    let shutdown = std::sync::Arc::new(core::sync::atomic::AtomicBool::new(false));
    let net_worker = {
        let shim = shim.clone();
        let shutdown = shutdown.clone();
        std::thread::spawn(move || {
            const IDLE_SLEEP: core::time::Duration = core::time::Duration::from_micros(200);
            const MAX_SLEEP: core::time::Duration = core::time::Duration::from_millis(1);
            while !shutdown.load(core::sync::atomic::Ordering::Relaxed) {
                let timeout = loop {
                    match shim.perform_network_interaction() {
                        litebox::net::PlatformInteractionReinvocationAdvice::CallAgainImmediately => {}
                        litebox::net::PlatformInteractionReinvocationAdvice::WaitOnDeviceOrSocketInteraction { timeout } => {
                            break timeout;
                        }
                    }
                };
                std::thread::sleep(timeout.unwrap_or(IDLE_SLEEP).min(MAX_SLEEP));
            }
            // Final flush so a socket with data still queued at guest exit gets
            // one last chance to drain.
            while shim.perform_network_interaction().call_again_immediately() {}
        })
    };

    // SAFETY: `load_program` produced the entry context, so its `pc` and `sp`
    // describe a loaded, runnable guest image.
    unsafe {
        litebox_platform_macos_userland::run_thread(
            program.entrypoints,
            &mut litebox_common_linux::PtRegs::default(),
        );
    }
    let exit_code = program.process.wait();
    shutdown.store(true, core::sync::atomic::Ordering::Relaxed);
    let _ = net_worker.join();
    if let Some((worker, shutdown_handle)) = vnc_worker {
        shutdown_handle.signal();
        let _ = worker.join();
    }
    std::process::exit(exit_code)
}
