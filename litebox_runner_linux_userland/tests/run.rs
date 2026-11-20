// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

mod cache;
mod common;

use std::path::{Path, PathBuf};

use common::runner::Runner;

#[cfg(target_os = "linux")]
use common::native::Native;
#[cfg(target_os = "linux")]
const BROKER_HELPER_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

#[cfg(target_os = "linux")]
const TEST_RANDOM_BYTE: u8 = 0x5a;

#[cfg(target_os = "linux")]
struct TestRandomProvider;

#[cfg(target_os = "linux")]
impl litebox_broker_core::random::RandomProvider for TestRandomProvider {
    fn fill(
        &self,
        output: &mut [u8],
    ) -> Result<(), litebox_broker_core::random::RandomProviderError> {
        output.fill(TEST_RANDOM_BYTE);
        Ok(())
    }
}

#[cfg(target_os = "linux")]
struct CapturingStdioProvider {
    stdout_tx: std::sync::mpsc::Sender<Vec<u8>>,
}

#[cfg(target_os = "linux")]
impl litebox_broker_core::stdio::StdioProvider for CapturingStdioProvider {
    fn read(
        &self,
        _output: &mut dyn litebox_platform::buffer::ReadBuffer,
    ) -> Result<usize, litebox_broker_core::stdio::StdioProviderError> {
        Err(litebox_broker_core::stdio::StdioProviderError::Unsupported)
    }

    fn write(
        &self,
        stream: litebox_broker_core::stdio::StdioOutputStream,
        input: &dyn litebox_platform::buffer::WriteBuffer,
    ) -> Result<usize, litebox_broker_core::stdio::StdioProviderError> {
        let mut output = vec![0; input.len()];
        input.copy_to_slice_at(0, &mut output)?;
        match stream {
            litebox_broker_core::stdio::StdioOutputStream::Stdout => self
                .stdout_tx
                .send(output)
                .map_err(|_| litebox_broker_core::stdio::StdioProviderError::Failed)?,
            litebox_broker_core::stdio::StdioOutputStream::Stderr => {
                std::io::Write::write_all(&mut std::io::stderr(), &output)
                    .map_err(|_| litebox_broker_core::stdio::StdioProviderError::Failed)?;
            }
        }
        Ok(input.len())
    }
}

#[cfg(target_os = "linux")]
fn gateway_destination_rule() -> litebox_broker_core::DestinationRule {
    use litebox_broker_protocol::socket::{Ipv4Address, Port};

    litebox_broker_core::DestinationRule::new(
        litebox_broker_core::CallerCredential::HostGuaranteed,
        litebox_broker_core::Ipv4Cidr::new(Ipv4Address([10, 0, 2, 1]), 32).unwrap(),
        litebox_broker_core::DestinationPortRange::new(Port(1), Port(u16::MAX)).unwrap(),
    )
}

#[cfg(target_os = "linux")]
fn gateway_tcp_policy() -> litebox_broker_core::SocketPolicy {
    litebox_broker_core::SocketPolicy::guest_network()
        .with_tcp_destination_rules(&[gateway_destination_rule()])
        .unwrap()
}

#[cfg(target_os = "linux")]
fn gateway_udp_policy() -> litebox_broker_core::SocketPolicy {
    litebox_broker_core::SocketPolicy::guest_network()
        .with_udp_destination_rules(&[gateway_destination_rule()])
        .unwrap()
}

/// The variable that has `sendfile.c` check pipes, which in LiteBox need the userland broker.
#[cfg(target_os = "linux")]
const PIPE_BROKER_VARIABLE: &str = "LITEBOX_PIPE_BROKER";

#[cfg(target_os = "linux")]
fn checks_broker_pipes(path: &Path) -> bool {
    path.file_name().and_then(|name| name.to_str()) == Some("sendfile.c")
}

#[cfg(target_os = "linux")]
fn configure_pipe_broker(path: &Path, runner: &mut Runner) {
    if checks_broker_pipes(path) {
        runner
            .use_userland_broker()
            .env(format!("{PIPE_BROKER_VARIABLE}=1"));
    }
}

#[test]
#[cfg(target_os = "linux")]
fn test_utimensat_through_broker_mount() {
    use std::os::unix::fs::MetadataExt as _;

    let target = common::compile("./tests/utimensat.c", "utimensat_broker_mount", true, false);
    let host = Path::new(env!("CARGO_TARGET_TMPDIR")).join("utimensat_broker_mount_dir");
    if host.exists() {
        std::fs::remove_dir_all(&host).unwrap();
    }
    std::fs::create_dir(&host).unwrap();
    // LocalFs does not support guest-created symlinks.
    std::os::unix::fs::symlink("file", host.join("link")).unwrap();
    let output = Runner::new(&target, "utimensat_broker_mount")
        .mount(&host, "/timestamps")
        .arg("/timestamps")
        .output();
    assert!(String::from_utf8_lossy(&output).contains("utimensat ok"));
    let metadata = std::fs::metadata(host.join("file")).unwrap();
    assert_eq!(
        (metadata.atime(), metadata.atime_nsec()),
        (4_000_000_000, 123_456_789)
    );
    assert_eq!(
        (metadata.mtime(), metadata.mtime_nsec()),
        (987_654_321, 987_654_321)
    );
    std::fs::remove_dir_all(host).unwrap();
}

/// Runs a directory rename test with its working directory on a host mount, so held directories
/// and the cwd follow renames and removals of host directories.
#[cfg(target_os = "linux")]
fn run_rename_test_through_broker_mount(source: &str, name: &str, expected: &str) {
    let target = common::compile(source, name, true, false);
    // A fresh directory per run, so entries a failed run leaves behind (possibly without search
    // permission) cannot fail later runs.
    let host = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR")).unwrap();
    // LocalFs reports host owners, so the guest runs as the mount's owner to own what it creates.
    let Ok(host_uid) = u16::try_from(std::os::unix::fs::MetadataExt::uid(
        &std::fs::metadata(host.path()).unwrap(),
    )) else {
        eprintln!("skipping {name}: the host uid does not fit a guest uid");
        return;
    };
    // LocalFs does not support guest-created symlinks.
    let output = Runner::new(&target, name)
        .guest_uid(host_uid)
        .mount(host.path(), "/work")
        .args(["/work", "no-symlinks"])
        .output();
    assert!(String::from_utf8_lossy(&output).contains(expected));
    assert!(
        std::fs::read_dir(host.path()).unwrap().next().is_none(),
        "the test left entries behind on the host"
    );
}

#[test]
#[cfg(target_os = "linux")]
fn test_dirfd_rename_through_broker_mount() {
    run_rename_test_through_broker_mount(
        "./tests/dirfd_rename.c",
        "dirfd_rename_broker_mount",
        "All directory fd rename tests passed.",
    );
}

#[test]
#[cfg(target_os = "linux")]
fn test_cwd_rename_through_broker_mount() {
    run_rename_test_through_broker_mount(
        "./tests/cwd_rename.c",
        "cwd_rename_broker_mount",
        "All cwd rename tests passed.",
    );
}

#[test]
fn test_mount_tmpfs() {
    let target = common::compile("./tests/mount.c", "mount_tmpfs", true, false);
    let output = Runner::new(&target, "mount_tmpfs").output();
    assert!(String::from_utf8_lossy(&output).contains("mount tmpfs ok"));
}

include!(concat!(env!("OUT_DIR"), "/c_tests.rs"));

/// The program that C tests of the `with_exec_child` kind execute.
const EXEC_CHILD: &str = "./tests/vfork_exec_child.c";

fn c_test_stem(path: &str) -> &str {
    Path::new(path)
        .file_stem()
        .and_then(|s| s.to_str())
        .expect("failed to get file stem")
}

/// Builds the C program at `path`, as a static executable if `exec_or_lib`, under a name that every
/// test building it the same way shares.
fn build_c_program(path: &str, exec_or_lib: bool) -> PathBuf {
    let linkage = if exec_or_lib { "static" } else { "dynamic" };
    let name = format!("{}.{linkage}", c_test_stem(path));
    common::compile(path, &name, exec_or_lib, false)
}

/// Runs a C test in LiteBox, letting it create processes if `allow_duplication`, and passing it
/// the path of `vfork_exec_child.c`, built like it, if `with_exec_child`.
fn run_c_test(
    path: &str,
    suffix: &str,
    exec_or_lib: bool,
    allow_duplication: bool,
    with_exec_child: bool,
) {
    let target = build_c_program(path, exec_or_lib);
    let mut runner = Runner::new(&target, &format!("{}{suffix}", c_test_stem(path)));
    #[cfg(target_os = "linux")]
    {
        configure_pipe_broker(Path::new(path), &mut runner);
        if allow_duplication {
            runner.allow_process_duplication();
        }
    }
    #[cfg(not(target_os = "linux"))]
    assert!(!allow_duplication, "only Linux runners create processes");
    if with_exec_child {
        let child = build_c_program(EXEC_CHILD, exec_or_lib);
        // The guest finds the child where the host keeps it.
        let child_guest_path = std::path::absolute(&child).unwrap();
        runner.arg(&child_guest_path).with_fs_path(|root| {
            let destination = root.join(child_guest_path.strip_prefix("/").unwrap());
            assert!(common::rewrite_with_cache(&child, &destination, &[]));
        });
    }
    runner.run();
}

/// Generates a LiteBox sweep test for a C test of the kind `build.rs` gives it.
macro_rules! c_test {
    ($kind:ident $stem:ident, $path:literal, ignore_natively = $reason:literal) => {
        c_test!($kind $stem, $path);
    };
    (dedicated $stem:ident, $path:literal) => {
        c_test!(@test #[ignore = "has a dedicated test"] $stem, $path, false, false);
    };
    // With `--run-ignored`, these would fail without a broker.
    (broker $stem:ident, $path:literal) => {
        c_test!(@test #[ignore = "needs the broker"] $stem, $path, false, false);
    };
    (plain $stem:ident, $path:literal) => {
        c_test!(@test $stem, $path, false, false);
    };
    (duplicating $stem:ident, $path:literal) => {
        c_test!(@test
            #[cfg_attr(not(target_os = "linux"), ignore = "only Linux runners create processes")]
            $stem, $path, true, false);
    };
    (with_exec_child $stem:ident, $path:literal) => {
        c_test!(@test
            #[cfg_attr(not(target_os = "linux"), ignore = "only Linux runners create processes")]
            $stem, $path, true, true);
    };
    (@test $(#[$attribute:meta])* $stem:ident, $path:literal, $allow_duplication:literal,
        $with_exec_child:literal) => {
        $(#[$attribute])*
        #[test]
        fn $stem() {
            super::run_c_test($path, SUFFIX, EXEC_OR_LIB, $allow_duplication, $with_exec_child);
        }
    };
}

mod test_dynamic_lib_with_rewriter {
    const SUFFIX: &str = "_rewriter";
    const EXEC_OR_LIB: bool = false;
    for_each_c_test!(c_test);
}

mod test_static_exec_with_rewriter {
    const SUFFIX: &str = "_exec_rewriter";
    const EXEC_OR_LIB: bool = true;
    for_each_c_test!(c_test);
}

/// Runs a C test natively, as the LiteBox sweeps run it, to check that the test's expectations
/// hold on Linux and not only under LiteBox.
#[cfg(target_os = "linux")]
fn run_native_c_test(path: &str, with_exec_child: bool) {
    let target = build_c_program(path, true);
    let Some(mut native) = Native::new(&target) else {
        return;
    };
    if checks_broker_pipes(Path::new(path)) {
        native.env(PIPE_BROKER_VARIABLE, "1");
    }
    if with_exec_child {
        let child = build_c_program(EXEC_CHILD, true);
        native.arg(std::path::absolute(child).unwrap());
    }
    native.output();
}

/// Generates a native sweep test for a C test of the kind `build.rs` gives it, which, if it has a
/// dedicated test or `build.rs` says to skip it natively, runs only when asked to, e.g. with
/// `--run-ignored`.
#[cfg(target_os = "linux")]
macro_rules! native_c_test {
    (dedicated $stem:ident, $path:literal) => {
        native_c_test!(@test #[ignore = "has a dedicated test"] $stem, $path, false);
    };
    (with_exec_child $stem:ident, $path:literal $(, ignore_natively = $reason:literal)?) => {
        native_c_test!(@test $(#[ignore = $reason])? $stem, $path, true);
    };
    ($kind:ident $stem:ident, $path:literal $(, ignore_natively = $reason:literal)?) => {
        native_c_test!(@test $(#[ignore = $reason])? $stem, $path, false);
    };
    (@test $(#[$attribute:meta])* $stem:ident, $path:literal, $with_exec_child:literal) => {
        $(#[$attribute])*
        #[test]
        fn $stem() {
            super::run_native_c_test($path, $with_exec_child);
        }
    };
}

#[cfg(target_os = "linux")]
mod test_native {
    for_each_c_test!(native_c_test);
}

#[cfg(target_os = "linux")]
fn numeric_field(line: &str, name: &str) -> i32 {
    line.split_whitespace()
        .find_map(|field| {
            field
                .strip_prefix(name)
                .and_then(|value| value.parse().ok())
        })
        .unwrap_or_else(|| panic!("missing {name} in {line:?}"))
}

/// Stages the host's `dash`, with its libraries, as the guest's `/bin/sh`, and a `/tmp` directory.
#[cfg(target_os = "linux")]
fn stage_shell(root: &Path) {
    const SHELL: &str = "/usr/bin/dash";
    assert!(common::rewrite_with_cache(
        Path::new(SHELL),
        &root.join("bin/sh"),
        &[]
    ));
    for library in common::find_dependencies(SHELL) {
        assert!(common::rewrite_with_cache(
            Path::new(&library),
            &root.join(&library[1..]),
            &[]
        ));
    }
    std::fs::create_dir_all(root.join("tmp")).unwrap();
}

#[cfg(target_os = "linux")]
#[test]
fn vfork_children_run_shell_commands() {
    let parent = common::compile(
        "./tests/vfork_shell_parent.c",
        "vfork_shell_parent",
        true,
        false,
    );
    let mut runner = Runner::new(&parent, "vfork_shell_parent");
    runner.allow_process_duplication().with_fs_path(stage_shell);

    let output = String::from_utf8(runner.output()).unwrap();
    let lines: Vec<&str> = output.lines().collect();
    // The second thread, working directory, and umask do not stop `system` and `popen`, whose
    // shells inherit the working directory and umask.
    // A `vfork` child changes its own working directory, umask, and descriptors before exec.
    for expected in [
        "system exited=1 code=7",
        "popen-read cwd=/tmp",
        "popen-read umask=0027",
        "popen-read exited=1 code=0",
        "popen-write exited=1 code=0",
        "vfork-child cwd=/",
        "vfork-child umask=0077",
        "vfork-child kept=closed",
        "vfork exited=1 code=0",
        "parent cwd=/tmp umask=027 kept=1",
    ] {
        assert!(
            lines.contains(&expected),
            "missing {expected:?} in {output:?}"
        );
    }
}

#[cfg(target_os = "linux")]
#[test]
fn interactive_shell_runs_commands_in_foreground_groups() {
    let parent = common::compile(
        "./tests/vfork_job_control_parent.c",
        "vfork_job_control_parent",
        true,
        false,
    );
    let mut runner = Runner::new(&parent, "vfork_job_control_parent");
    runner.allow_process_duplication().with_fs_path(stage_shell);

    let output = String::from_utf8(runner.output()).unwrap();
    // Without job control, `dash` runs commands in its own group and never hands them the
    // terminal.
    assert!(!output.contains("job control turned off"), "{output:?}");
    let lines: Vec<&str> = output
        .lines()
        .map(|line| line.trim_end_matches('\r'))
        .collect();
    // `dash` vforks each command, which brings its own group to the foreground before exec.
    for expected in ["before-cmd", "in-cmd", "after-cmd", "leader exited code=5"] {
        assert!(
            lines.contains(&expected),
            "missing {expected:?} in {output:?}"
        );
    }
}

#[cfg(target_os = "linux")]
#[test]
fn fork_and_exec_keep_detached_cwd() {
    let program = common::compile("./tests/process_cwd.c", "process_cwd", true, false);
    // Natively, the directory to detach defaults to one in the run's own TMPDIR.
    if let Some(mut native) = Native::new(&program) {
        native.arg(std::path::absolute(&program).unwrap()).output();
    }
    Runner::new(&program, "process_cwd")
        .allow_process_duplication()
        .arg(std::path::absolute(&program).unwrap())
        .arg("/registry/detached")
        .run();
}

/// Checks vector state and pointer authentication across `fork` and `vfork`.
#[cfg(all(target_arch = "aarch64", target_os = "linux"))]
#[test]
fn fork_and_vfork_preserve_aarch64_state() {
    let program = common::compile(
        "./tests/fork_aarch64_state.c",
        "fork_aarch64_state",
        true,
        false,
    );
    let mut runner = Runner::new(&program, "fork_aarch64_state");
    runner.allow_process_duplication();

    let output = String::from_utf8(runner.output()).unwrap();
    let line = |prefix: &str| {
        output
            .lines()
            .find(|line| line.starts_with(prefix))
            .unwrap_or_else(|| panic!("missing {prefix:?} output in {output:?}"))
    };
    // Runners disable pointer authentication only for copy-based fork.
    let pac_enabled = !litebox_shim_linux::syscalls::process::COPY_BASED_FORK
        && std::arch::is_aarch64_feature_detected!("paca");
    let pac_line = line("pac ");
    assert_eq!(
        numeric_field(pac_line, "enabled="),
        i32::from(pac_enabled),
        "{pac_line}"
    );
    let fork_line = line("fork ");
    assert_eq!(numeric_field(fork_line, "parent="), 1, "{fork_line}");
    assert_eq!(numeric_field(fork_line, "child="), 1, "{fork_line}");
    let vfork_line = line("vfork ");
    assert_eq!(numeric_field(vfork_line, "parent="), 1, "{vfork_line}");
    assert_eq!(numeric_field(vfork_line, "child="), 1, "{vfork_line}");
    let signed_line = line("signed-fork ");
    assert_eq!(numeric_field(signed_line, "exited="), 1, "{signed_line}");
    assert_eq!(numeric_field(signed_line, "code="), 0, "{signed_line}");
}

#[cfg(all(target_arch = "aarch64", target_os = "linux"))]
#[test]
fn aarch64_hwcaps_expose_only_supported_host_features() {
    use litebox::arch::aarch64::CpuFeatures;
    use litebox_common_linux::hwcap::LinuxHwcaps;

    // Bits from Linux uapi `arch/arm64/include/uapi/asm/hwcap.h` that libc does not define.
    const HWCAP2_BTI: u64 = 1 << 17;
    const HWCAP2_MTE: u64 = 1 << 18;
    const HWCAP2_SME: u64 = 1 << 23;

    let program = common::compile("./tests/aarch64_hwcaps.c", "aarch64_hwcaps", true, false);
    let output = String::from_utf8(Runner::new(&program, "aarch64_hwcaps").output()).unwrap();
    let line = |prefix: &str| {
        output
            .lines()
            .find(|line| line.starts_with(prefix))
            .unwrap_or_else(|| panic!("missing {prefix:?} output in {output:?}"))
    };
    let hwcaps_line = line("hwcaps ");
    let field = |name: &str| -> u64 {
        hwcaps_line
            .split_whitespace()
            .find_map(|field| field.strip_prefix(name)?.parse().ok())
            .unwrap_or_else(|| panic!("missing {name} in {hwcaps_line:?}"))
    };
    let (hwcap, hwcap2) = (field("hwcap="), field("hwcap2="));
    // SAFETY: getauxval only reads this process's auxiliary vector.
    let (host_hwcap, host_hwcap2) = unsafe {
        (
            libc::getauxval(libc::AT_HWCAP),
            libc::getauxval(libc::AT_HWCAP2),
        )
    };

    // Mirrors the platform filter intersected with the shim filter: copy-based fork drops pointer
    // authentication, and PACGA mode drops the generic key it owns.
    let mut exposed =
        CpuFeatures::BASE_STATE_ONLY | CpuFeatures::PAUTH | CpuFeatures::PAUTH_GENERIC;
    if common::guest_sve_vl().is_some() {
        exposed |= CpuFeatures::SVE_STATE_ONLY;
    }
    if litebox_shim_linux::syscalls::process::COPY_BASED_FORK {
        exposed.remove(CpuFeatures::PAUTH | CpuFeatures::PAUTH_GENERIC);
    }
    if cfg!(feature = "aarch64_pacga") {
        exposed.remove(CpuFeatures::PAUTH_GENERIC);
    }
    let host = LinuxHwcaps {
        hwcap: host_hwcap,
        hwcap2: host_hwcap2,
    };
    let expected = LinuxHwcaps::from_cpu_features(host.to_cpu_features() & exposed);
    assert_eq!(
        (hwcap, hwcap2),
        (expected.hwcap, expected.hwcap2),
        "{hwcaps_line}: host hwcap={host_hwcap:#x} hwcap2={host_hwcap2:#x}"
    );
    // These checks are independent of the allow-list and the hwcap mapping.
    let required = libc::HWCAP_FP | libc::HWCAP_ASIMD;
    assert_eq!(hwcap & required, required, "{hwcaps_line}");
    // HWCAP_CPUID would tell glibc/compiler-rt to trust the host's unfiltered ID-register reads.
    let never = libc::HWCAP_CPUID | libc::HWCAP_DIT | libc::HWCAP_SSBS;
    assert_eq!(hwcap & never, 0, "{hwcaps_line}");
    assert_eq!(
        hwcap & libc::HWCAP_SVE != 0,
        common::guest_sve_vl().is_some(),
        "{hwcaps_line}"
    );
    let never2 = HWCAP2_BTI | HWCAP2_MTE | HWCAP2_SME;
    assert_eq!(hwcap2 & never2, 0, "{hwcaps_line}");

    // FPCR controls, including those of the offered FP16, AFP, and EBF16 features, survive
    // syscalls and signals.
    let fpcr_line = line("fpcr ");
    assert_eq!(numeric_field(fpcr_line, "syscall="), 1, "{fpcr_line}");
    assert_eq!(numeric_field(fpcr_line, "signal="), 1, "{fpcr_line}");
}

#[cfg(target_os = "linux")]
#[test]
fn forked_children_share_futexes_in_shared_memory() {
    const EXPECTED: &str = "shared-futex memory=1 wake=1 timeout=1 interrupted=1 private=1 \
                            mutex=1 semaphore=1 bitset=1 misaligned=1 count=1 inaccessible=1 \
                            private-memory=1 clear-tid=1";
    // Copy-based fork cannot share pages, so it refuses to fork with shared anonymous mappings.
    assert!(
        std::env::var_os("LITEBOX_DISABLE_NATIVE_FORK").is_none(),
        "shared futexes across fork require native fork support"
    );
    let parent = common::compile(
        "./tests/fork_shared_futex_parent.c",
        "fork_shared_futex_parent",
        true,
        false,
    );
    // The checks encode Linux's behavior, so they pass natively too.
    if let Some(mut native) = Native::new(&parent) {
        let native = native.output();
        assert!(native.lines().any(|line| line == EXPECTED), "{native:?}");
    }

    let mut runner = Runner::new(&parent, "fork_shared_futex_parent");
    runner.allow_process_duplication();
    let output = String::from_utf8(runner.output()).unwrap();
    assert!(output.lines().any(|line| line == EXPECTED), "{output:?}");
}

#[cfg(target_os = "linux")]
#[test]
fn fork_requires_process_duplication() {
    let parent = common::compile(
        "./tests/fork_parent.c",
        "fork_without_duplication",
        true,
        false,
    );
    let output = Runner::new(&parent, "fork_without_duplication").output_expect_failure();
    let output = String::from_utf8(output).unwrap();
    let line = output
        .lines()
        .find(|line| line.starts_with("fork-failed "))
        .unwrap_or_else(|| panic!("missing fork failure in {output:?}"));
    assert_eq!(numeric_field(line, "errno="), libc::EPERM);
}

#[cfg(target_os = "linux")]
#[test]
fn initial_program_inherits_ignored_signals() {
    let program = common::compile(
        "./tests/inherited_ignored_signals.c",
        "inherited_ignored_signals",
        true,
        false,
    );
    let mut runner = Runner::new(&program, "inherited_ignored_signals");
    for signal in [libc::SIGHUP, libc::SIGINT, libc::SIGALRM, libc::SIGPIPE] {
        runner.ignore_host_signal(signal);
    }

    let output = String::from_utf8(runner.output()).unwrap();
    // The Rust runtime ignores `SIGPIPE` in every runner, hiding the launcher's choice.
    assert_eq!(
        output,
        "SIGHUP=ignored\nSIGINT=ignored\nSIGALRM=ignored\nSIGPIPE=default\nSIGTERM=default\n\
         survived SIGINT\n"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn the_root_is_the_guest_s_init_only_when_the_broker_says_so() {
    let program = common::compile("./tests/root_init.c", "root_init", true, false);

    let mut runner = Runner::new(&program, "root_init");
    runner
        .allow_process_duplication()
        .broker_arg("--root-process-as-init");
    let output = String::from_utf8(runner.output()).unwrap();
    assert_eq!(output, "root-init started\nroot-init survived\n");

    let mut runner = Runner::new(&program, "root_init_ordinary");
    runner.allow_process_duplication();
    let output = String::from_utf8(runner.output_expect_failure()).unwrap();
    assert_eq!(output, "root-init started\n");
}

#[cfg(target_os = "linux")]
#[test]
fn pid_namespaces_number_and_end_with_their_first_process() {
    let program = common::compile("./tests/pid_namespace.c", "pid_namespace", true, false);
    let mut runner = Runner::new(&program, "pid_namespace");
    // Only root creates namespaces.
    runner.allow_process_duplication().guest_uid(0);

    let output = String::from_utf8(runner.output()).unwrap();
    assert!(
        output
            .lines()
            .any(|line| line == "pid-namespace failures=0"),
        "{output}"
    );

    // Any other user can't create namespaces. Process creation is allowed, so a refusal is the
    // namespace rule's.
    let mut runner = Runner::new(&program, "pid_namespace_unprivileged");
    runner.allow_process_duplication().arg("unprivileged");
    let output = String::from_utf8(runner.output()).unwrap();
    assert!(
        output
            .lines()
            .any(|line| line == "pid-namespace unprivileged code=0"),
        "{output}"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn only_root_creates_uts_and_ipc_namespaces() {
    let program = common::compile(
        "./tests/uts_ipc_namespace.c",
        "uts_ipc_namespace",
        true,
        false,
    );
    let mut runner = Runner::new(&program, "uts_ipc_namespace");
    // Only root creates namespaces.
    runner.allow_process_duplication().guest_uid(0);
    let output = String::from_utf8(runner.output()).unwrap();
    assert!(
        output
            .lines()
            .any(|line| line == "uts-ipc-namespace failures=0"),
        "{output}"
    );

    // Any other user can't. Process creation is allowed, so a refusal is the permission rule's.
    let mut runner = Runner::new(&program, "uts_ipc_namespace_unprivileged");
    runner.allow_process_duplication().arg("unprivileged");
    let output = String::from_utf8(runner.output()).unwrap();
    assert!(
        output
            .lines()
            .any(|line| line == "uts-ipc-namespace unprivileged failures=0"),
        "{output}"
    );
}

/// A 512 KiB host stack makes 32 generations exceed the old native fork stack-growth limit,
/// without retaining the hundreds of live runtimes needed to exhaust the default 8 MiB stack.
#[cfg(target_os = "linux")]
const DEEP_FORK_CHAIN_DEPTH: u32 = 32;

/// Runs a deep `fork_chain_parent.c` chain in `mode` and checks that every generation ran.
#[cfg(target_os = "linux")]
fn run_deep_fork_chain(mode: &str) {
    // Copy-based fork never deepens the runner stack, so the chain would pass vacuously.
    assert!(
        std::env::var_os("LITEBOX_DISABLE_NATIVE_FORK").is_none(),
        "deep fork-chain tests require native fork support"
    );
    let name = format!("fork_chain_{mode}");
    let parent = common::compile("./tests/fork_chain_parent.c", &name, true, false);
    let mut runner = Runner::new(&parent, &name);
    runner
        .allow_process_duplication()
        .host_stack_limit(512 * 1024)
        .args([mode, DEEP_FORK_CHAIN_DEPTH.to_string().as_str()]);
    let output = String::from_utf8(runner.output()).unwrap();
    let expected = format!("{mode}-chain depth={DEEP_FORK_CHAIN_DEPTH} code=42");
    assert!(output.lines().any(|line| line == expected), "{output}");
}

#[cfg(target_os = "linux")]
#[test]
fn deep_fork_chains_do_not_exhaust_the_runner_stack() {
    run_deep_fork_chain("fork");
}

#[cfg(target_os = "linux")]
#[test]
fn deep_fork_exec_chains_do_not_exhaust_the_runner_stack() {
    run_deep_fork_chain("exec");
}

#[cfg(target_os = "linux")]
#[test]
fn forked_shell_subshells_and_pipelines() {
    const SCRIPT: &str = r#"
value=$(echo substituted)
echo "substitution=$value"
echo piped | { read line; echo "pipeline=$line"; }
(exit 3)
echo "subshell=$?"
cd /tmp && umask 027 && (read marker < cwd-marker; echo "nested cwd=$marker umask=$(umask)")
"#;
    let mut runner = Runner::new(Path::new("/usr/bin/dash"), "fork_dash");
    runner
        .allow_process_duplication()
        .args(["-c", SCRIPT])
        .with_fs_path(|root| {
            // dash's `pwd` prints its own copy of the cwd, so the forked subshell opens a
            // relative path to check the cwd the child actually restored.
            std::fs::create_dir_all(root.join("tmp")).unwrap();
            std::fs::write(root.join("tmp/cwd-marker"), "tmp\n").unwrap();
        });

    let output = String::from_utf8(runner.output()).unwrap();
    let lines: Vec<&str> = output.lines().collect();
    for expected in [
        "substitution=substituted",
        "pipeline=piped",
        "subshell=3",
        "nested cwd=tmp umask=0027",
    ] {
        assert!(
            lines.contains(&expected),
            "missing {expected:?} in {output:?}"
        );
    }
}

/// Get the path of a program using `which`
fn run_which(prog: &str) -> std::path::PathBuf {
    let prog_path_str = std::process::Command::new("which")
        .arg(prog)
        .output()
        .expect("Failed to find program binary")
        .stdout;
    let prog_path_str = String::from_utf8(prog_path_str).unwrap().trim().to_string();
    let prog_path = std::path::PathBuf::from(prog_path_str);
    assert!(prog_path.exists(), "Program binary not found");
    prog_path
}

#[cfg(target_os = "linux")]
fn unique_test_socket_path(name: &str) -> PathBuf {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!(
        "litebox-{name}-{}-{nonce}.sock",
        std::process::id()
    ))
}

#[cfg(target_os = "linux")]
struct TestBroker {
    thread: Option<std::thread::JoinHandle<()>>,
    done_rx: std::sync::mpsc::Receiver<()>,
    close_object_count_rx: std::sync::mpsc::Receiver<usize>,
    stdout_rx: std::sync::mpsc::Receiver<Vec<u8>>,
    pending_stdout: std::cell::RefCell<Vec<u8>>,
    control_socket_path: PathBuf,
}

#[cfg(target_os = "linux")]
impl TestBroker {
    fn next_close_object_count(&self) -> usize {
        self.close_object_count_rx
            .recv_timeout(BROKER_HELPER_TIMEOUT)
            .expect("broker test host did not report close-object count")
    }

    fn next_stdout_line(&self) -> String {
        self.stdout_line_before(std::time::Instant::now() + BROKER_HELPER_TIMEOUT)
            .expect("timed out waiting for brokered guest stdout")
    }

    /// The next line of the guest's standard output, if one comes before `deadline`.
    fn stdout_line_before(&self, deadline: std::time::Instant) -> Option<String> {
        loop {
            let newline = self
                .pending_stdout
                .borrow()
                .iter()
                .position(|byte| *byte == b'\n');
            if let Some(newline) = newline {
                let mut line = self
                    .pending_stdout
                    .borrow_mut()
                    .drain(..=newline)
                    .collect::<Vec<_>>();
                line.pop();
                if line.last() == Some(&b'\r') {
                    line.pop();
                }
                return Some(String::from_utf8(line).expect("guest stdout was not UTF-8"));
            }

            let remaining = deadline
                .checked_duration_since(std::time::Instant::now())
                .unwrap_or_default();
            let chunk = self.stdout_rx.recv_timeout(remaining).ok()?;
            self.pending_stdout.borrow_mut().extend_from_slice(&chunk);
        }
    }

    fn finish(&mut self) {
        self.done_rx
            .recv_timeout(BROKER_HELPER_TIMEOUT)
            .expect("broker test host did not finish");
        self.thread
            .take()
            .expect("broker test host thread missing")
            .join()
            .expect("broker test host panicked");
    }

    fn join(mut self) {
        self.finish();
    }

    fn join_with_stdout(mut self) -> Vec<u8> {
        self.finish();
        let mut output = core::mem::take(self.pending_stdout.get_mut());
        for chunk in self.stdout_rx.try_iter() {
            output.extend_from_slice(&chunk);
        }
        output
    }
}

#[cfg(target_os = "linux")]
impl Drop for TestBroker {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.control_socket_path);
    }
}

#[cfg(target_os = "linux")]
fn spawn_test_broker(
    control_socket_path: &Path,
    policy: litebox_broker_core::PolicyEngine,
    file_roots: &[&Path],
    connection_count: usize,
) -> TestBroker {
    spawn_test_broker_with_mode(
        control_socket_path,
        policy,
        file_roots,
        connection_count,
        TestBrokerOptions::default(),
    )
}

#[cfg(target_os = "linux")]
fn spawn_concurrent_test_broker(
    control_socket_path: &Path,
    policy: litebox_broker_core::PolicyEngine,
    file_roots: &[&Path],
    connection_count: usize,
) -> TestBroker {
    spawn_test_broker_with_mode(
        control_socket_path,
        policy,
        file_roots,
        connection_count,
        TestBrokerOptions {
            concurrent: true,
            ..TestBrokerOptions::default()
        },
    )
}

/// A test broker with a hybrid vsock bridge at `vsock_uds`; the policy must allow vsock sockets.
#[cfg(target_os = "linux")]
fn spawn_vsock_test_broker(
    control_socket_path: &Path,
    policy: litebox_broker_core::PolicyEngine,
    file_roots: &[&Path],
    connection_count: usize,
    vsock_uds: &Path,
) -> TestBroker {
    spawn_test_broker_with_mode(
        control_socket_path,
        policy,
        file_roots,
        connection_count,
        TestBrokerOptions {
            vsock_uds: Some(vsock_uds.to_path_buf()),
            ..TestBrokerOptions::default()
        },
    )
}

#[cfg(target_os = "linux")]
#[derive(Default)]
struct TestBrokerOptions {
    /// Serves its connections at once, rather than in turn.
    concurrent: bool,
    /// The hybrid vsock bridge's path, if any.
    vsock_uds: Option<PathBuf>,
}

/// The hybrid vsock bridge's ephemeral port seed.
#[cfg(target_os = "linux")]
const TEST_SEED: u64 = 0;

#[cfg(target_os = "linux")]
fn test_file_service(
    file_roots: &[PathBuf],
    stdio: std::sync::Arc<dyn litebox_broker_core::stdio::StdioProvider>,
    max_shared_files: usize,
) -> std::sync::Arc<dyn litebox_broker_core::fs::FileService> {
    use std::os::unix::fs::PermissionsExt;

    use litebox_broker_core::fs::{
        composer::Composer,
        in_mem::{InMem, InitialNode},
        resolver::Resolver,
    };
    use litebox_broker_platform_linux_userland::LinuxSyncPrimitivesProvider;
    use litebox_broker_protocol::fs::{FileMode as Mode, FileUser as UserInfo};

    const GUEST_USER: UserInfo = UserInfo {
        user: 1000,
        group: 1000,
    };

    let directory_mode = Mode::RWXU | Mode::RWXG | Mode::RWXO;
    let mut entries = vec![
        (
            "/tmp".to_owned(),
            InitialNode::Directory {
                mode: directory_mode,
                owner: UserInfo::ROOT,
            },
        ),
        (
            "/registry".to_owned(),
            InitialNode::Directory {
                mode: directory_mode,
                owner: UserInfo::ROOT,
            },
        ),
    ];

    for root in file_roots {
        for entry in walkdir::WalkDir::new(root).sort_by_file_name() {
            let entry = entry.expect("failed to walk runner test root");
            let relative = entry
                .path()
                .strip_prefix(root)
                .expect("runner test path must be below its root");
            if relative.as_os_str().is_empty() {
                continue;
            }

            let guest_path = format!(
                "/{}",
                relative
                    .to_str()
                    .expect("runner test paths must contain valid UTF-8")
            );
            let metadata =
                std::fs::metadata(entry.path()).expect("failed to inspect runner test file");
            let mode = Mode::from_u32_bits_truncate(metadata.permissions().mode());
            let node = if metadata.is_dir() {
                InitialNode::Directory {
                    mode,
                    owner: GUEST_USER,
                }
            } else {
                InitialNode::File {
                    mode,
                    owner: GUEST_USER,
                    data: std::fs::read(entry.path())
                        .expect("failed to read runner test file")
                        .into(),
                }
            };
            entries.push((guest_path, node));
        }
    }

    let backend = Composer::<LinuxSyncPrimitivesProvider>::builder()
        .mount("/", |allocator| {
            InMem::<LinuxSyncPrimitivesProvider>::new_initialized(entries, allocator)
                .with_shared_memory(
                    std::sync::Arc::new(
                        litebox_broker_userland::shared_objects::linux::MemfdFileMemoryProvider,
                    ),
                    std::sync::Arc::new(
                        litebox_broker_core::fs::shared_storage::SharedFileLimit::new(
                            max_shared_files,
                        ),
                    ),
                )
        })
        .mount("/dev", |allocator| {
            litebox_broker_core::fs::devices::Devices::new(
                allocator,
                stdio,
                std::sync::Arc::new(TestRandomProvider),
            )
        })
        .build()
        .unwrap();
    std::sync::Arc::new(Resolver::<LinuxSyncPrimitivesProvider, _>::new(backend))
}

#[cfg(target_os = "linux")]
fn spawn_test_broker_with_mode(
    control_socket_path: &Path,
    policy: litebox_broker_core::PolicyEngine,
    file_roots: &[&Path],
    connection_count: usize,
    TestBrokerOptions {
        concurrent,
        vsock_uds,
    }: TestBrokerOptions,
) -> TestBroker {
    let _ = std::fs::remove_file(control_socket_path);

    let (ready_tx, ready_rx) = std::sync::mpsc::channel();
    let (done_tx, done_rx) = std::sync::mpsc::channel();
    let (close_object_count_tx, close_object_count_rx) = std::sync::mpsc::channel();
    let (stdout_tx, stdout_rx) = std::sync::mpsc::channel();
    let server_control_socket_path = control_socket_path.to_path_buf();
    let cleanup_control_socket_path = control_socket_path.to_path_buf();
    let file_roots = file_roots
        .iter()
        .map(|root| root.to_path_buf())
        .collect::<Vec<_>>();
    let broker_thread = std::thread::spawn(move || {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let control_listener =
                std::os::unix::net::UnixListener::bind(&server_control_socket_path)
                    .expect("failed to bind broker test control socket");
            // Before the core, as the userland broker does.
            let vsock = vsock_uds.as_deref().map(|vsock_uds| {
                litebox_broker_userland::hybrid_vsock::HybridVsock::start(
                    vsock_uds,
                    litebox_broker_userland::hybrid_vsock::DEFAULT_GUEST_CID,
                    TEST_SEED,
                )
                .expect("failed to start the hybrid vsock bridge")
            });
            let limits = litebox_broker_core::BrokerCoreLimits::DEFAULT;
            let mut broker = litebox_broker_core::test_support::TestBrokerBuilder::new(policy)
                .with_limits(limits)
                .with_socket_provider(std::sync::Arc::new(
                    litebox_broker_userland::socket::UserlandSocketProvider::new(
                        limits.max_sockets,
                        limits.max_sockets_per_process,
                    )
                    .expect("failed to create broker test socket provider"),
                ))
                .with_random_provider(std::sync::Arc::new(TestRandomProvider))
                .with_file_service(test_file_service(
                    &file_roots,
                    std::sync::Arc::new(CapturingStdioProvider { stdout_tx }),
                    limits.max_shared_files,
                ))
                .with_host_names(litebox_broker_host::default_host_names());
            if let Some(vsock) = &vsock {
                broker = broker.with_vsock_provider(vsock.provider());
            }
            let broker = broker.build().expect("failed to create broker core");
            ready_tx.send(()).expect("failed to report broker ready");

            let serve_connection = |control_stream, close_object_count_tx| {
                run_test_broker_connection(&broker, control_stream, close_object_count_tx);
            };
            if concurrent {
                std::thread::scope(|scope| {
                    for _ in 0..connection_count {
                        let (control_stream, _) = control_listener
                            .accept()
                            .expect("failed to accept broker local control connection");
                        let close_object_count_tx = close_object_count_tx.clone();
                        scope.spawn(move || {
                            serve_connection(control_stream, close_object_count_tx);
                        });
                    }
                });
            } else {
                for _ in 0..connection_count {
                    let (control_stream, _) = control_listener
                        .accept()
                        .expect("failed to accept broker local control connection");
                    serve_connection(control_stream, close_object_count_tx.clone());
                }
            }
        }));
        let _ = std::fs::remove_file(&server_control_socket_path);
        let _ = done_tx.send(());
        if let Err(panic) = result {
            std::panic::resume_unwind(panic);
        }
    });

    ready_rx
        .recv_timeout(std::time::Duration::from_secs(5))
        .expect("broker test host did not start");
    TestBroker {
        thread: Some(broker_thread),
        done_rx,
        close_object_count_rx,
        stdout_rx,
        pending_stdout: std::cell::RefCell::new(Vec::new()),
        control_socket_path: cleanup_control_socket_path,
    }
}

/// Shuts a test broker association down if one of its lane threads, or the thread starting them,
/// panics, ending every wait on it so the test fails instead of hanging.
#[cfg(target_os = "linux")]
struct ShutdownOnPanic<'a>(
    &'a litebox_broker_transport_linux_userland::unix_socket::UnixControlRingHostShutdown,
);

#[cfg(target_os = "linux")]
impl Drop for ShutdownOnPanic<'_> {
    fn drop(&mut self) {
        if std::thread::panicking() {
            let _ = self.0.shutdown();
        }
    }
}

#[cfg(target_os = "linux")]
fn run_test_broker_connection(
    broker: &litebox_broker_core::test_support::TestBroker,
    control_stream: std::os::unix::net::UnixStream,
    close_object_count_tx: std::sync::mpsc::Sender<usize>,
) {
    let shared_memory = litebox_broker_transport_linux_userland::memfd::MemfdSharedMemory::create(
        litebox_broker_protocol::shared_buffer::SHARED_BUFFER_POOL_SIZE,
    )
    .expect("failed to create broker test shared memory");
    let shared_buffers = std::sync::Arc::new(
        litebox_broker_transport::shared_memory::SharedBufferPool::new(
            shared_memory,
            litebox_broker_protocol::shared_buffer::SHARED_BUFFER_LAYOUT,
        )
        .expect("failed to attach broker test shared-buffer layout"),
    );
    let layout = litebox_broker_transport::control_ring::ControlRingLayout::MULTI_LANE;
    let control_memory =
        litebox_broker_transport_linux_userland::memfd::MemfdSharedMemory::create_control_ring(
            layout,
        )
        .expect("failed to create broker test control ring");
    let control_ring =
        litebox_broker_transport::control_ring::ControlRing::new(control_memory, layout)
            .expect("failed to attach broker test control ring");
    let setup_deadline = std::time::Instant::now() + BROKER_HELPER_TIMEOUT;
    let mut channel =
        litebox_broker_transport_linux_userland::unix_socket::UnixStreamHostSetupChannel::from_host_guaranteed(
            control_stream,
            setup_deadline,
        );
    let readiness =
        std::sync::Arc::new(litebox_broker_userland::readiness::ReadinessPublisherRuntime::new());
    let process = broker
        .create_process(litebox_broker_core::CallerCredential::HostGuaranteed)
        .expect("failed to create broker test process");
    let (shared_objects, runner_shared_objects) =
        litebox_broker_transport_linux_userland::shared_objects::SharedObjectSender::pair()
            .expect("failed to create broker test shared-object channel");
    let shared_objects = litebox_broker_userland::shared_objects::linux::MemfdDelivery(
        std::sync::Arc::new(shared_objects),
    );
    let association = litebox_broker_host::setup_connection(
        &process,
        None,
        &mut channel,
        std::sync::Arc::clone(&shared_buffers),
        readiness.clone(),
        |channel| {
            channel.send_memfd(shared_buffers.memory(), Some(setup_deadline))?;
            channel.send_memfd(control_ring.memory(), Some(setup_deadline))?;
            channel.send_shared_object_channel(
                std::os::fd::AsFd::as_fd(&runner_shared_objects),
                Some(setup_deadline),
            )?;
            channel.send_process_image(None, Some(setup_deadline))
        },
    )
    .expect("broker host setup failed")
    .expect("broker setup terminated before activation");
    drop(runner_shared_objects);
    let (mut lanes, mut notifications, shutdown) = channel
        .into_active(control_ring)
        .expect("failed to activate broker test control ring");
    let publisher_readiness = readiness.clone();
    let publisher = std::thread::spawn(move || publisher_readiness.run(&mut notifications));
    // The number of objects closed, and the open file and signal handles excluded from it since
    // every runner opens them.
    let counts = std::sync::Mutex::new((0, Vec::new()));
    // Serves each call lane the runner starts using on its own thread, until the runner closes the
    // association.
    std::thread::scope(|scope| {
        let _shutdown_on_panic = ShutdownOnPanic(&shutdown);
        while let Some(mut lane) = lanes
            .next_lane()
            .expect("failed to receive a broker test call lane")
        {
            let (association, counts, shutdown, shared_objects) =
                (&association, &counts, &shutdown, &shared_objects);
            scope.spawn(move || {
                let _shutdown_on_panic = ShutdownOnPanic(shutdown);
                loop {
                    match lane
                        .recv_request()
                        .expect("failed to receive broker test request")
                    {
                        litebox_broker_transport::channel::HostReceive::Message(request) => {
                            if let litebox_broker_protocol::message::BrokerOperation::CloseObject(
                                handle,
                            ) = &request.operation
                            {
                                let (close_object_count, uncounted_handles) =
                                    &mut *counts.lock().unwrap();
                                if let Some(index) =
                                    uncounted_handles.iter().position(|value| value == handle)
                                {
                                    uncounted_handles.swap_remove(index);
                                } else {
                                    *close_object_count += 1;
                                }
                            }
                            association
                                .execute_request_with(
                                    request,
                                    |process, operation, _| {
                                        litebox_broker_userland::shared_objects::handle_map_file(
                                            shared_objects,
                                            process,
                                            operation,
                                        )
                                    },
                                    |response| {
                                        match &response.result {
                                        litebox_broker_protocol::message::BrokerResult::File(
                                            litebox_broker_protocol::message::FileResponse::Open(
                                                open,
                                            ),
                                        ) => counts.lock().unwrap().1.push(open.handle),
                                        litebox_broker_protocol::message::BrokerResult::Signal(
                                            litebox_broker_protocol::message::SignalResponse::Open(
                                                open,
                                            ),
                                        ) => counts.lock().unwrap().1.push(open.handle),
                                        _ => {}
                                    }
                                        lane.send_response(response)
                                    },
                                )
                                .expect("failed to execute broker test request");
                        }
                        litebox_broker_transport::channel::HostReceive::PeerClosed => return,
                        litebox_broker_transport::channel::HostReceive::ProtocolViolation => {
                            panic!("broker test request violated the protocol");
                        }
                    }
                }
            });
        }
    });
    readiness.close();
    // The runner's clean close can fail a notification send already in flight, which the broker
    // runtime likewise ignores; any other publication failure is a real error.
    if let Err(error) = publisher
        .join()
        .expect("broker readiness publisher panicked")
    {
        assert!(
            matches!(
                error.kind(),
                std::io::ErrorKind::BrokenPipe
                    | std::io::ErrorKind::UnexpectedEof
                    | std::io::ErrorKind::ConnectionReset
                    | std::io::ErrorKind::ConnectionAborted
            ),
            "broker readiness publication failed: {error:?}"
        );
    }
    association.finish();
    let (close_object_count, _) = counts.into_inner().unwrap();
    close_object_count_tx
        .send(close_object_count)
        .expect("failed to report broker close-object count");
}

#[cfg(target_os = "linux")]
#[test]
#[cfg_attr(
    all(target_arch = "aarch64", feature = "aarch64_virtualize_x18"),
    ignore = "node has AArch64 patch sites the x18-virtualizing rewriter cannot patch"
)]
fn test_runner_broker_integration_with_rewriter() {
    const HELLO_WORLD_JS: &str = r"
const fs = require('node:fs');

const content = 'Hello World!';
console.log(content);
";

    let true_path = run_which("true");
    let node_path = run_which("node");
    let target = common::compile("./tests/eventfd.c", "broker_eventfd_rewriter", false, false);
    let pipe_target = common::compile(
        "./tests/pipe_broker.c",
        "broker_pipe_rewriter",
        false,
        false,
    );
    let urandom_target = common::compile(
        "./tests/urandom_broker.c",
        "broker_urandom_rewriter",
        false,
        false,
    );
    let mut true_runner = Runner::new(&true_path, "broker_true_rewriter");
    let mut eventfd_runner = Runner::new(&target, "broker_eventfd_rewriter");
    let mut pipe_runner = Runner::new(&pipe_target, "broker_pipe_rewriter");
    let mut urandom_runner = Runner::new(&urandom_target, "broker_urandom_rewriter");
    let mut node_runner = Runner::new(&node_path, "hello_node_broker_rewriter");
    node_runner
        .arg("/out/hello_world.js")
        .with_fs_path(|out_dir| {
            std::fs::write(out_dir.join("out/hello_world.js"), HELLO_WORLD_JS).unwrap();
        });
    let control_socket_path = unique_test_socket_path("runner-broker-control");
    let broker_thread = spawn_test_broker(
        &control_socket_path,
        litebox_broker_core::PolicyEngine::with_host_guaranteed_rights(
            litebox_broker_core::ObjectRights::all(),
        ),
        &[
            true_runner.tar_dir(),
            eventfd_runner.tar_dir(),
            pipe_runner.tar_dir(),
            urandom_runner.tar_dir(),
            node_runner.tar_dir(),
        ],
        5,
    );

    true_runner.broker_socket(&control_socket_path).run();
    assert_eq!(broker_thread.next_close_object_count(), 0);

    eventfd_runner.broker_socket(&control_socket_path).run();
    // eventfd.c creates thirteen eventfd objects and one epoll instance; each should release one
    // broker object.
    assert_eq!(broker_thread.next_close_object_count(), 14);

    pipe_runner.broker_socket(&control_socket_path).run();
    // pipe_broker.c creates five pipes; each endpoint owns one broker object.
    assert_eq!(broker_thread.next_close_object_count(), 10);

    urandom_runner
        .broker_socket(&control_socket_path)
        .arg(TEST_RANDOM_BYTE.to_string())
        .run();
    assert_eq!(broker_thread.next_close_object_count(), 0);

    node_runner.broker_socket(&control_socket_path).run();
    assert!(broker_thread.next_close_object_count() > 0);

    broker_thread.join();
}

#[cfg(target_os = "linux")]
#[test]
fn brokered_getrandom() {
    let target = common::compile(
        "./tests/getrandom_broker.c",
        "brokered_getrandom",
        false,
        false,
    );
    let mut runner = Runner::new(&target, "brokered_getrandom");
    runner.use_in_process_runner();
    runner.run();
}

#[cfg(target_os = "linux")]
#[test]
fn test_runner_broker_tcp_client_with_rewriter() {
    use std::io::{Read as _, Write as _};
    use std::net::{Ipv4Addr, TcpListener};

    const REQUEST_SIZE: usize = 65_536;
    const RESPONSE_SIZE: usize = 600_000;
    const BACKPRESSURE_SIZE: usize = 8 * 1024 * 1024;

    let target = common::compile(
        "./tests/tcp_broker.c",
        "broker_tcp_client_rewriter",
        false,
        false,
    );
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut request = vec![0; REQUEST_SIZE];
        stream.read_exact(&mut request).unwrap();
        assert!(request.iter().all(|byte| *byte == 0x5a));
        std::thread::sleep(std::time::Duration::from_millis(100));
        stream.write_all(&[0x11; 16]).unwrap();
        stream.write_all(&vec![0xa5; 20_000]).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(50));
        stream
            .write_all(&vec![0xa5; RESPONSE_SIZE - 20_000])
            .unwrap();
        stream.shutdown(std::net::Shutdown::Write).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(200));
        let mut backpressure = vec![0; BACKPRESSURE_SIZE];
        stream.read_exact(&mut backpressure).unwrap();
        assert!(backpressure.iter().all(|byte| *byte == 0x3c));
        let mut eof = [0; 1];
        assert_eq!(stream.read(&mut eof).unwrap(), 0);

        let linger = libc::linger {
            l_onoff: 1,
            l_linger: 0,
        };
        for _ in 0..3 {
            let (reset_stream, _) = listener.accept().unwrap();
            std::thread::sleep(std::time::Duration::from_millis(20));
            // SAFETY: `reset_stream` owns a live socket and `linger` is valid for the supplied length.
            assert_eq!(
                unsafe {
                    libc::setsockopt(
                        std::os::fd::AsRawFd::as_raw_fd(&reset_stream),
                        libc::SOL_SOCKET,
                        libc::SO_LINGER,
                        std::ptr::from_ref(&linger).cast(),
                        libc::socklen_t::try_from(std::mem::size_of_val(&linger)).unwrap(),
                    )
                },
                0
            );
            drop(reset_stream);
        }
        let (mut partial_reset_stream, _) = listener.accept().unwrap();
        let mut connected = [0; 1];
        partial_reset_stream.read_exact(&mut connected).unwrap();
        assert_eq!(connected, [0x4c]);
        partial_reset_stream.write_all(&[0x7e]).unwrap();
        // SAFETY: `partial_reset_stream` owns a live socket and `linger` is valid for the supplied length.
        assert_eq!(
            unsafe {
                libc::setsockopt(
                    std::os::fd::AsRawFd::as_raw_fd(&partial_reset_stream),
                    libc::SOL_SOCKET,
                    libc::SO_LINGER,
                    std::ptr::from_ref(&linger).cast(),
                    libc::socklen_t::try_from(std::mem::size_of_val(&linger)).unwrap(),
                )
            },
            0
        );
        drop(partial_reset_stream);

        let (mut fault_stream, _) = listener.accept().unwrap();
        match fault_stream.write_all(&vec![0x6d; 512 * 1024 + 4096]) {
            Ok(()) => {}
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::ConnectionReset
                        | std::io::ErrorKind::BrokenPipe
                        | std::io::ErrorKind::NotConnected
                ) => {}
            Err(error) => panic!("failed to write fault response: {error}"),
        }
    });

    let mut runner = Runner::new(&target, "broker_tcp_client_rewriter");
    let control_socket_path = unique_test_socket_path("runner-broker-tcp-control");
    let broker = spawn_test_broker(
        &control_socket_path,
        litebox_broker_core::PolicyEngine::with_host_guaranteed_rights(
            litebox_broker_core::ObjectRights::all(),
        )
        .with_socket_policy(gateway_tcp_policy()),
        &[runner.tar_dir()],
        1,
    );
    runner
        .arg(port.to_string())
        .broker_socket(&control_socket_path)
        .run();
    // Eight sockets and two epoll instances.
    assert_eq!(broker.next_close_object_count(), 10);
    broker.join();
    server.join().unwrap();
}

#[cfg(target_os = "linux")]
#[test]
fn test_runner_broker_tcp_connection_states_with_rewriter() {
    use std::io::{Read as _, Write as _};
    use std::net::{Ipv4Addr, Shutdown, TcpListener, TcpStream};
    use std::os::fd::AsRawFd as _;
    use std::time::Duration;

    let target = common::compile(
        "./tests/tcp_broker_states.c",
        "broker_tcp_states_rewriter",
        false,
        false,
    );

    let reset_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let reset_port = reset_listener.local_addr().unwrap().port();
    let reset_server = std::thread::spawn(move || {
        let linger = libc::linger {
            l_onoff: 1,
            l_linger: 0,
        };
        for _ in 0..3 {
            let (mut stream, _) = reset_listener.accept().unwrap();
            stream.read_exact(&mut [0; 1]).unwrap();
            // SAFETY: `stream` owns a live socket and `linger` is valid for the supplied length.
            assert_eq!(
                unsafe {
                    libc::setsockopt(
                        stream.as_raw_fd(),
                        libc::SOL_SOCKET,
                        libc::SO_LINGER,
                        std::ptr::from_ref(&linger).cast(),
                        libc::socklen_t::try_from(std::mem::size_of_val(&linger)).unwrap(),
                    )
                },
                0
            );
        }
    });

    // Once its accept queue is full, this listener drops connection requests,
    // so connects to it stay pending.
    let unresponsive_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    // SAFETY: `unresponsive_listener` owns a live listening socket.
    assert_eq!(
        unsafe { libc::listen(unresponsive_listener.as_raw_fd(), 0) },
        0
    );
    let unresponsive_address = unresponsive_listener.local_addr().unwrap();
    let mut queued = Vec::new();
    while let Ok(stream) =
        TcpStream::connect_timeout(&unresponsive_address, Duration::from_millis(200))
    {
        queued.push(stream);
        assert!(queued.len() < 8, "listener accept queue did not fill");
    }

    let half_closed_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let half_closed_port = half_closed_listener.local_addr().unwrap().port();
    let half_closed_server = std::thread::spawn(move || {
        (0..2)
            .map(|_| {
                let (stream, _) = half_closed_listener.accept().unwrap();
                stream.shutdown(Shutdown::Write).unwrap();
                stream
            })
            .collect::<Vec<_>>()
    });

    let greeting_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let greeting_port = greeting_listener.local_addr().unwrap().port();
    let greeting_server = std::thread::spawn(move || {
        let (mut stream, _) = greeting_listener.accept().unwrap();
        stream.write_all(b"hi").unwrap();
        stream
    });

    let open_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let open_port = open_listener.local_addr().unwrap().port();
    let open_server = std::thread::spawn(move || {
        (0..8)
            .map(|_| open_listener.accept().unwrap().0)
            .collect::<Vec<_>>()
    });

    let (_refusing, refused_address) = dev_test_support::net::refusing_tcp_address();

    let mut runner = Runner::new(&target, "broker_tcp_states_rewriter");
    let control_socket_path = unique_test_socket_path("runner-broker-tcp-states-control");
    let broker = spawn_test_broker(
        &control_socket_path,
        litebox_broker_core::PolicyEngine::with_host_guaranteed_rights(
            litebox_broker_core::ObjectRights::all(),
        )
        .with_socket_policy(gateway_tcp_policy()),
        &[runner.tar_dir()],
        1,
    );
    runner
        .arg(reset_port.to_string())
        .arg(unresponsive_address.port().to_string())
        .arg(refused_address.port().to_string())
        .arg(half_closed_port.to_string())
        .arg(open_port.to_string())
        .arg(greeting_port.to_string())
        .broker_socket(&control_socket_path)
        .run();
    assert_eq!(broker.next_close_object_count(), 25);
    broker.join();
    reset_server.join().unwrap();
    half_closed_server.join().unwrap();
    open_server.join().unwrap();
    greeting_server.join().unwrap();
}

#[cfg(target_os = "linux")]
#[test]
fn test_runner_broker_udp_with_rewriter() {
    use std::net::{Ipv4Addr, UdpSocket};

    let target = common::compile("./tests/udp_broker.c", "broker_udp_rewriter", false, false);
    let server = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let port = server.local_addr().unwrap().port();
    let (_refusing, refused_address) = dev_test_support::net::refusing_udp_address();
    let mut runner = Runner::new(&target, "broker_udp_rewriter");
    let server = std::thread::spawn(move || {
        let mut packet = [0_u8; 64];

        let (received, client) = server.recv_from(&mut packet).unwrap();
        assert_eq!(&packet[..received], b"unconnected");
        server.send_to(b"0123456789", client).unwrap();
        server
            .set_read_timeout(Some(BROKER_HELPER_TIMEOUT))
            .unwrap();

        let (received, source) = server.recv_from(&mut packet).unwrap();
        assert_eq!(&packet[..received], b"read");
        assert_eq!(source, client);
        server.send_to(b"abcdefghij", client).unwrap();

        let (received, source) = server.recv_from(&mut packet).unwrap();
        assert_eq!(&packet[..received], b"readv");
        assert_eq!(source, client);
        server.send_to(b"abcdefghij", client).unwrap();

        let (received, source) = server.recv_from(&mut packet).unwrap();
        assert_eq!(&packet[..received], b"readv-fault");
        assert_eq!(source, client);
        server.send_to(b"abcdefghij", client).unwrap();

        let (received, source) = server.recv_from(&mut packet).unwrap();
        assert_eq!(received, 0);
        assert_eq!(source, client);
        server.send_to(&[], client).unwrap();

        let (received, source) = server.recv_from(&mut packet).unwrap();
        assert_eq!(&packet[..received], b"connected");
        assert_eq!(source, client);
        server.send_to(b"connected-reply", client).unwrap();

        let (received, source) = server.recv_from(&mut packet).unwrap();
        assert_eq!(&packet[..received], b"writev");
        assert_eq!(source, client);
        server.send_to(b"writev-reply", client).unwrap();

        let (received, source) = server.recv_from(&mut packet).unwrap();
        assert_eq!(&packet[..received], b"explicit");
        assert_eq!(source, client);
        server.send_to(b"explicit-reply", client).unwrap();

        let mut maximum = vec![0_u8; 65_507];
        let (received, source) = server.recv_from(&mut maximum).unwrap();
        assert_eq!(received, maximum.len());
        assert!(maximum.iter().all(|byte| *byte == 0x5a));
        assert_eq!(source, client);
        server.send_to(b"maximum-reply", client).unwrap();

        let (received, source) = server.recv_from(&mut packet).unwrap();
        assert_eq!(&packet[..received], b"preserved");
        assert_eq!(source, client);
        server.send_to(b"preserved-reply", client).unwrap();
    });

    let control_socket_path = unique_test_socket_path("runner-broker-udp-control");
    let broker = spawn_test_broker(
        &control_socket_path,
        litebox_broker_core::PolicyEngine::with_host_guaranteed_rights(
            litebox_broker_core::ObjectRights::all(),
        )
        .with_socket_policy(gateway_udp_policy()),
        &[runner.tar_dir()],
        1,
    );
    runner
        .arg(port.to_string())
        .arg(refused_address.port().to_string())
        .broker_socket(&control_socket_path)
        .run();
    assert_eq!(broker.next_close_object_count(), 3);
    broker.join();
    server.join().unwrap();
}

#[cfg(target_os = "linux")]
#[test]
fn test_runner_broker_udp_namespace_delivers_after_sender_close() {
    use std::process::Stdio;

    let target = common::compile(
        "./tests/udp_broker_namespace.c",
        "broker_udp_namespace_rewriter",
        false,
        false,
    );
    let mut server_runner = Runner::new(&target, "broker_udp_namespace_server_rewriter");
    let mut client_runner = Runner::new(&target, "broker_udp_namespace_client_rewriter");
    let control_socket_path = unique_test_socket_path("runner-broker-udp-namespace-control");
    let broker = spawn_concurrent_test_broker(
        &control_socket_path,
        litebox_broker_core::PolicyEngine::with_host_guaranteed_rights(
            litebox_broker_core::ObjectRights::all(),
        )
        .with_socket_policy(litebox_broker_core::SocketPolicy::guest_network()),
        &[server_runner.tar_dir()],
        2,
    );
    let mut server = server_runner
        .arg("server")
        .broker_socket(&control_socket_path)
        .spawn_with_stdio(Stdio::null(), Stdio::null(), Stdio::inherit());
    let listen = broker.next_stdout_line();
    let port = listen
        .strip_prefix("LISTEN ")
        .expect("unexpected broker UDP server output")
        .parse::<u16>()
        .unwrap();
    assert_ne!(port, 0);

    client_runner
        .arg("client")
        .arg(port.to_string())
        .broker_socket(&control_socket_path)
        .run();

    let deadline = std::time::Instant::now() + BROKER_HELPER_TIMEOUT;
    let status = loop {
        if let Some(status) = server.try_wait().unwrap() {
            break status;
        }
        if std::time::Instant::now() >= deadline {
            server.kill().unwrap();
            let _ = server.wait();
            panic!("broker UDP server guest did not exit");
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    };
    assert!(status.success(), "broker UDP server guest failed: {status}");
    assert_eq!(broker.next_close_object_count(), 1);
    assert_eq!(broker.next_close_object_count(), 1);
    broker.join();
}

#[cfg(target_os = "linux")]
#[test]
fn test_runner_broker_tcp_server_with_rewriter() {
    use std::process::Stdio;

    let target = common::compile(
        "./tests/tcp_broker_server.c",
        "broker_tcp_server_rewriter",
        false,
        false,
    );
    let mut runner = Runner::new(&target, "broker_tcp_server_rewriter");
    let control_socket_path = unique_test_socket_path("runner-broker-tcp-server-control");
    let broker = spawn_test_broker(
        &control_socket_path,
        litebox_broker_core::PolicyEngine::with_host_guaranteed_rights(
            litebox_broker_core::ObjectRights::all(),
        )
        .with_socket_policy(litebox_broker_core::SocketPolicy::guest_network()),
        &[runner.tar_dir()],
        1,
    );
    let mut child = runner.broker_socket(&control_socket_path).spawn_with_stdio(
        Stdio::null(),
        Stdio::null(),
        Stdio::inherit(),
    );
    let mut output = String::new();
    let mut next_marker = |prefix: &str| loop {
        let line = broker.next_stdout_line();
        output.push_str(&line);
        output.push('\n');
        if line.starts_with(prefix) {
            return line;
        }
    };

    let listen = next_marker("LISTEN ");
    assert_ne!(
        listen
            .split_whitespace()
            .nth(1)
            .unwrap()
            .parse::<u16>()
            .unwrap(),
        0
    );
    let first_marker = next_marker("FIRST ");
    assert_ne!(
        first_marker
            .split_whitespace()
            .nth(1)
            .unwrap()
            .parse::<u16>()
            .unwrap(),
        0
    );

    assert_eq!(next_marker("BLOCKING"), "BLOCKING");
    assert!(
        child.try_wait().unwrap().is_none(),
        "blocking accept returned before a client connected"
    );
    let second_marker = next_marker("SECOND ");
    assert_ne!(
        second_marker
            .split_whitespace()
            .nth(1)
            .unwrap()
            .parse::<u16>()
            .unwrap(),
        0
    );

    let deadline = std::time::Instant::now() + BROKER_HELPER_TIMEOUT;
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if std::time::Instant::now() >= deadline {
            child.kill().unwrap();
            let _ = child.wait();
            panic!("broker TCP server guest did not exit; output:\n{output}");
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    };
    assert!(
        status.success(),
        "broker TCP server guest failed with {status}; output:\n{output}"
    );
    assert_eq!(broker.next_close_object_count(), 5);
    broker.join();
}

/// Where the vsock guest tests live, with the VM runner's.
#[cfg(target_os = "linux")]
const VM_VSOCK_TESTS: &str = "../litebox_runner_vm_kernel/tests/linux";

/// Waits for `child` to exit, killing it at `deadline`.
#[cfg(target_os = "linux")]
fn wait_until(
    child: &mut std::process::Child,
    deadline: std::time::Instant,
    name: &str,
) -> std::process::ExitStatus {
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            return status;
        }
        if std::time::Instant::now() >= deadline {
            child.kill().unwrap();
            let _ = child.wait();
            panic!("{name} did not exit in time");
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}

/// `vsock_hybrid.rs` and `vsock_hybrid.host.py` on the userland runner, through the broker's
/// hybrid vsock bridge.
#[cfg(target_os = "linux")]
#[test]
fn vsock_reaches_host_unix_sockets_through_the_hybrid_bridge() {
    use std::io::Write as _;
    use std::process::Stdio;

    const TIMEOUT: std::time::Duration = std::time::Duration::from_secs(120);

    let target = common::compile_rust(
        &format!("{VM_VSOCK_TESTS}/vsock_hybrid.rs"),
        "vsock_hybrid_rewriter",
    );
    let mut runner = Runner::new(&target, "vsock_hybrid_rewriter");
    let dir = tempfile::tempdir().unwrap();
    let vsock_uds = dir.path().join("vsock");
    // vsock_hybrid.host.py waits for the guest's `ready` in this file.
    let console = dir.path().join("console");
    let mut console_file = std::fs::File::create(&console).unwrap();
    let control_socket_path = unique_test_socket_path("runner-broker-vsock-control");
    let broker = spawn_vsock_test_broker(
        &control_socket_path,
        litebox_broker_core::PolicyEngine::with_host_guaranteed_rights(
            litebox_broker_core::ObjectRights::all(),
        )
        .with_vsock_policy(litebox_broker_core::VsockPolicy::any()),
        &[runner.tar_dir()],
        1,
        &vsock_uds,
    );
    let mut host = std::process::Command::new("python3")
        .arg(format!("{VM_VSOCK_TESTS}/vsock_hybrid.host.py"))
        .arg(&vsock_uds)
        .arg(&console)
        .env("TIMEOUT", TIMEOUT.as_secs().to_string())
        .stdin(Stdio::null())
        .spawn()
        .expect("failed to run python3");
    let mut guest = runner.broker_socket(&control_socket_path).spawn_with_stdio(
        Stdio::null(),
        Stdio::null(),
        Stdio::inherit(),
    );

    let deadline = std::time::Instant::now() + TIMEOUT;
    let mut output = String::new();
    while !output.ends_with("vsock-hybrid ok\n") && std::time::Instant::now() < deadline {
        let poll = (std::time::Instant::now() + std::time::Duration::from_secs(1)).min(deadline);
        if let Some(line) = broker.stdout_line_before(poll) {
            writeln!(console_file, "{line}").unwrap();
            output.push_str(&line);
            output.push('\n');
        } else if guest.try_wait().unwrap().is_some() || host.try_wait().unwrap().is_some() {
            break;
        }
    }
    // A guest that failed (e.g., before `ready`) is the failure, not the host's wait for it.
    if let Some(status) = guest.try_wait().unwrap().filter(|status| !status.success()) {
        let _ = host.kill();
        let _ = host.wait();
        panic!("the vsock guest failed with {status}; output:\n{output}");
    }
    let host_status = wait_until(&mut host, deadline, "vsock_hybrid.host.py");
    if !host_status.success() {
        let _ = guest.kill();
        let _ = guest.wait();
        panic!("vsock_hybrid.host.py failed with {host_status}; guest output:\n{output}");
    }
    let guest_status = wait_until(&mut guest, deadline, "the vsock guest");
    // The host may end before the guest prints its last line.
    while let Some(line) = broker.stdout_line_before(std::time::Instant::now()) {
        writeln!(console_file, "{line}").unwrap();
        output.push_str(&line);
        output.push('\n');
    }
    assert!(
        guest_status.success(),
        "the vsock guest failed with {guest_status}; output:\n{output}"
    );
    assert_eq!(output, "ready\nvsock-hybrid ok\n");
    broker.join();
    // The broker stopped the bridge as it ended.
    assert!(!vsock_uds.exists());
}

/// `vsock_listen.c` on the userland broker with `--vsock-uds`; its inherited listener
/// needs the broker's process duplication.
#[cfg(target_os = "linux")]
#[test]
fn vsock_sockets_work_on_the_userland_broker_with_a_hybrid_bridge() {
    let name = "vsock_listen_hybrid";
    let target = common::compile(
        &format!("{VM_VSOCK_TESTS}/vsock_listen.c"),
        name,
        true,
        false,
    );
    let dir = tempfile::tempdir().unwrap();
    let vsock_uds = dir.path().join("vsock");
    // The guest exits 0 only after `vsock-listen ok`; a failure shows its output.
    Runner::new(&target, name)
        .allow_process_duplication()
        .arg("hybrid")
        .broker_arg("--vsock-uds")
        .broker_arg(&vsock_uds)
        .run();
    // The broker removed it as it ended.
    assert!(!vsock_uds.exists());
}

fn dir_entries(dir: &Path) -> Vec<String> {
    // Empty staging directories do not survive into the guest tar.
    fn holds_a_file(path: &Path) -> bool {
        if path.is_file() {
            return true;
        }
        std::fs::read_dir(path)
            .is_ok_and(|entries| entries.flatten().any(|e| holds_a_file(&e.path())))
    }

    let mut names = std::fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("cannot read staged rootfs {}: {e}", dir.display()))
        .flatten()
        .filter(|entry| holds_a_file(&entry.path()))
        // The tar excludes cache bookkeeping files.
        .filter(|entry| {
            entry
                .path()
                .extension()
                .is_none_or(|ext| ext != "cache-checksum")
        })
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .collect::<Vec<_>>();
    names.sort();
    names
}

fn assert_ls_listed(output: &[u8], dir: &Path, expected: &[String]) {
    let output_str = String::from_utf8_lossy(output);
    let listed = output_str.split_whitespace().collect::<Vec<_>>();
    assert!(!expected.is_empty(), "nothing staged in {}", dir.display());
    for each in [".", ".."]
        .iter()
        .copied()
        .chain(expected.iter().map(String::as_str))
    {
        assert!(
            listed.contains(&each),
            "ls of {} did not list {each}:\n{output_str}",
            dir.display(),
        );
    }
}

/// Rewrites dynamic `ls` and its shared objects, checking that their appended
/// trampolines coexist and that every staged non-cache entry remains visible.
#[test]
fn test_runner_with_ls() {
    let ls_path = run_which("ls");

    let mut runner = Runner::new(&ls_path, "ls_rewriter");
    let expected_root = dir_entries(runner.tar_dir());
    let output = runner.arg("-a").output();
    assert_ls_listed(&output, Path::new("/"), &expected_root);

    // Derive the library directory from ldd because host layouts vary.
    let libs = common::find_dependencies(ls_path.to_str().unwrap());
    let lib_guest_dir = libs
        .iter()
        .map(PathBuf::from)
        .find(|lib| {
            !lib.file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .starts_with("ld-")
        })
        .and_then(|lib| lib.parent().map(Path::to_path_buf))
        .expect("ls has no resolvable shared-library dependency to list");

    let mut runner = Runner::new(&ls_path, "ls_lib_rewriter");
    let staged_lib_dir = runner
        .tar_dir()
        .join(lib_guest_dir.strip_prefix("/").unwrap());
    let expected_libs = dir_entries(&staged_lib_dir);
    let output = runner
        .args(["-a", lib_guest_dir.to_str().unwrap()])
        .output();
    assert_ls_listed(&output, &staged_lib_dir, &expected_libs);
}

#[cfg(target_os = "linux")]
fn run_python(args: &[&str]) -> String {
    let output = std::process::Command::new("python3")
        .args(["-I", "-S"])
        .args(args)
        .output()
        .expect("Failed to run Python");
    assert!(output.status.success(), "Python script failed");
    String::from_utf8(output.stdout).unwrap()
}

#[cfg(target_os = "linux")]
fn python_runner() -> Runner {
    const ROOTFS_NAME: &str = "python_rewriter";
    let python_path = run_which("python3");
    let python_guest_dir = python_path.parent().unwrap().to_str().unwrap().to_string();

    let is_optional_package_path = |path: &Path| {
        path.components().any(|component| {
            matches!(
                component.as_os_str().to_str(),
                Some("site-packages" | "dist-packages")
            )
        })
    };

    let python_config = run_python(&[
        "-c",
        "import sys; print(sys.prefix); print(':'.join(sys.path))",
    ]);
    let (python_home, python_sys_path) = python_config.trim().split_once('\n').unwrap();
    println!("Detected PYTHONHOME: {python_home}");
    println!("Detected PYTHONPATH: {python_sys_path}");
    let python_home_dir = PathBuf::from(python_home);
    let python_lib_paths = python_sys_path
        .split(':')
        .map(str::trim)
        .filter(|path| !path.is_empty())
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .filter(|path| path.starts_with(&python_home_dir))
        .filter(|path| !is_optional_package_path(path))
        .collect::<Vec<_>>();

    let python_lib_paths_str = python_lib_paths
        .iter()
        .map(|path| path.to_str().unwrap())
        .collect::<Vec<_>>()
        .join(":");

    // Host packages can contain hundreds of large native modules unrelated to
    // these tests. Exclude them before both staging and rewriting on every host.
    let mut paths_to_stage = std::collections::BTreeSet::new();
    paths_to_stage.extend(python_lib_paths.iter().cloned());

    let mut input_files = vec![python_path.clone(), PathBuf::from("/usr/bin/dash")];
    for program in [&python_path, Path::new("/usr/bin/dash")] {
        input_files.extend(
            common::find_dependencies(program.to_str().unwrap())
                .into_iter()
                .map(PathBuf::from),
        );
    }
    for source in &paths_to_stage {
        input_files.extend(
            walkdir::WalkDir::new(source)
                .follow_links(true)
                .into_iter()
                .filter_entry(|entry| !is_optional_package_path(entry.path()))
                .filter_map(Result::ok)
                .filter(|entry| entry.path().is_file())
                .map(walkdir::DirEntry::into_path),
        );
    }
    input_files.extend(common::find_rewriter_source_files());
    for source in ["run.rs", "cache.rs", "common/mod.rs", "common/runner.rs"] {
        input_files.push(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests")
                .join(source),
        );
    }
    input_files.sort();
    input_files.dedup();
    let input_paths = input_files.iter().map(PathBuf::as_path).collect::<Vec<_>>();
    let cache_command = format!(
        "python rootfs {} {python_config:?} {:?}",
        python_path.canonicalize().unwrap().display(),
        common::rewriter_flags(),
    );
    let tmp_dir = Path::new(env!("CARGO_TARGET_TMPDIR"));
    let tar_file = tmp_dir.join(format!("rootfs_{ROOTFS_NAME}.tar"));
    // Never unlink the lock: waiting builders must continue to lock the same inode.
    let lock = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(tmp_dir.join(format!("rootfs_{ROOTFS_NAME}.lock")))
        .unwrap();
    lock.lock().unwrap();
    let rootfs_cached =
        crate::cache::is_cached_and_valid(&input_paths, &tar_file, &cache_command).unwrap_or(false);
    let mut runner = if rootfs_cached {
        println!("Using cached Python rootfs");
        Runner::new_with_rootfs(&python_path, ROOTFS_NAME)
    } else {
        Runner::new(&python_path, ROOTFS_NAME)
    };
    runner.envs([
        &format!("PYTHONHOME={python_home}"),
        &format!("PYTHONPATH={python_lib_paths_str}"),
        // LiteBox does not provide /proc/self/exe yet; give glibc a fallback
        // origin for DT_NEEDED entries like $ORIGIN/../lib/libpython*.so.
        &format!("LD_ORIGIN_PATH={python_guest_dir}"),
        // LiteBox does not support timestamp yet, so pre-compiled .pyc files are not usable.
        // Avoid creating .pyc files as tar filesystem is read-only.
        "PYTHONDONTWRITEBYTECODE=1",
        // These tests run without a broker and do not exercise Python hash randomization.
        "PYTHONHASHSEED=0",
    ]);
    if !rootfs_cached {
        runner.with_fs_path(|out_dir| {
            for source_path in &paths_to_stage {
                if !source_path.exists() {
                    continue;
                }

                if source_path.is_file() {
                    let dest_path = out_dir.join(source_path.strip_prefix("/").unwrap());
                    if let Some(parent) = dest_path.parent() {
                        std::fs::create_dir_all(parent).unwrap();
                    }
                    std::fs::copy(source_path, dest_path).unwrap();
                    continue;
                }

                if source_path.is_dir() {
                    let python_lib_dst = out_dir.join(source_path.strip_prefix("/").unwrap());
                    std::fs::create_dir_all(&python_lib_dst).unwrap();
                    println!(
                        "Copying python3 lib from {} to {}",
                        source_path.display(),
                        python_lib_dst.display()
                    );
                    let mut sources = std::fs::read_dir(source_path)
                        .unwrap()
                        .map(|entry| entry.unwrap().path())
                        .filter(|path| !is_optional_package_path(path))
                        .collect::<Vec<_>>();
                    sources.sort();
                    if !sources.is_empty() {
                        let output = std::process::Command::new("cp")
                            // Preserve attributes for the tar cache and dereference symlinks.
                            .arg("-rpL")
                            .args(&sources)
                            .arg(&python_lib_dst)
                            .output()
                            .expect("Failed to copy python3 lib");
                        // Broken symlinks can fail without preventing the remaining copies.
                        if !output.status.success() {
                            let stderr =
                                std::str::from_utf8(output.stderr.as_slice()).unwrap_or("");
                            eprintln!("Warning: cp finished with errors (non-critical):\n{stderr}");
                        }
                    }

                    // Rewrite shared objects (.so, .so.1, .so.1.2.3, etc.) under the python lib directory.
                    for entry in walkdir::WalkDir::new(source_path)
                        .into_iter()
                        .filter_entry(|entry| !is_optional_package_path(entry.path()))
                        .filter_map(std::result::Result::ok)
                        .filter(|e| e.file_type().is_file())
                        .filter(|e| {
                            e.path()
                                .file_name()
                                .and_then(|n| n.to_str())
                                .is_some_and(|name| name.contains(".so"))
                        })
                        // Skip non-ELF files (e.g., linker scripts like libcurses.so)
                        .filter(|e| {
                            let mut magic = [0u8; 4];
                            std::fs::File::open(e.path())
                                .and_then(|mut f| {
                                    use std::io::Read;
                                    f.read_exact(&mut magic)
                                })
                                .is_ok()
                                && magic == *b"\x7fELF"
                        })
                    {
                        let so_file = entry.path();
                        let so_file_dest = out_dir.join(so_file.strip_prefix("/").unwrap());
                        println!(
                            "Rewrite {} to {}",
                            so_file.display(),
                            so_file_dest.display()
                        );
                        let success = common::rewrite_with_cache(so_file, &so_file_dest, &[]);
                        assert!(success, "failed to rewrite {} file", so_file.display());
                    }
                }
            }
        });
        runner.with_fs_path(stage_shell);
        assert_eq!(runner.prepare_rootfs(), tar_file);
        crate::cache::create_cache_entry(&input_paths, &tar_file, &cache_command).unwrap();
    }
    runner
}

#[cfg(target_os = "linux")]
#[test]
fn python_runs_child_programs() {
    const SCRIPT: &str = r#"
import os, subprocess, threading
release = threading.Event()
thread = threading.Thread(target=release.wait)
thread.start()
try:
    os.chdir("/tmp")
    os.umask(0o027)
    sh = lambda command, **kwargs: subprocess.run(["/bin/sh", "-c", command], **kwargs)
    print("run", sh("exit 7").returncode)
    print("capture", sh("pwd; umask", capture_output=True, text=True).stdout.split())
    print("cwd", sh("pwd", cwd="/", capture_output=True, text=True).stdout.strip())
    print("system", os.waitstatus_to_exitcode(os.system("exit 5")))
    with os.popen("echo popen") as output:
        print("popen", output.read().strip())
    print("parent", os.getcwd(), oct(os.umask(0o027)))
finally:
    release.set()
    thread.join()
"#;
    let mut runner = python_runner();
    runner.allow_process_duplication().args(["-c", SCRIPT]);

    let output = String::from_utf8(runner.output()).unwrap();
    let lines: Vec<&str> = output.lines().collect();
    for expected in [
        "run 7",
        "capture ['/tmp', '0027']",
        "cwd /",
        "system 5",
        "popen popen",
        "parent /tmp 0o27",
    ] {
        assert!(
            lines.contains(&expected),
            "missing {expected:?} in {output:?}"
        );
    }
}

#[cfg(target_os = "linux")]
#[test]
fn python_os_fork() {
    const SCRIPT: &str = r#"
import os
data = {"value": 1}
read_fd, write_fd = os.pipe()
pid = os.fork()
if pid == 0:
    os.close(read_fd)
    data["value"] = 2
    os.write(write_fd, f"child {os.getpid()} {os.getppid()} {data['value']}".encode())
    os._exit(11)
os.close(write_fd)
with os.fdopen(read_fd) as pipe:
    message = pipe.read()
waited, status = os.waitpid(pid, 0)
print("pipe", message == f"child {pid} {os.getpid()} 2")
print("wait", waited == pid, os.waitstatus_to_exitcode(status))
print("parent", data["value"])
"#;
    let mut runner = python_runner();
    runner.allow_process_duplication().args(["-c", SCRIPT]);

    let output = String::from_utf8(runner.output()).unwrap();
    let lines: Vec<&str> = output.lines().collect();
    for expected in ["pipe True", "wait True 11", "parent 1"] {
        assert!(
            lines.contains(&expected),
            "missing {expected:?} in {output:?}"
        );
    }
}

#[cfg(target_os = "linux")]
#[test]
fn test_runner_with_python_repl_pty() {
    let mut runner = python_runner();
    let mut pty = common::pty::Pty::open();
    let (stdin, stdout, stderr) = pty.slave_stdio();
    let mut child =
        runner.spawn_with_controlling_terminal(pty.slave(), stdin, stdout, stderr, false);
    pty.close_slave();

    let mut output = Vec::new();
    pty.wait_for_output(&mut output, b">>> ");
    pty.write_all(b"print(\"hi\")\nexit()\n");
    let status = pty.wait_for_child_exit(&mut child, &mut output);
    assert!(
        status.success(),
        "Python exited with {status}; output:\n{}",
        String::from_utf8_lossy(&output)
    );

    let output = String::from_utf8_lossy(&output).replace("\r\n", "\n");
    assert!(
        output.lines().any(|line| line.trim() == "hi"),
        "Python REPL did not print a standalone hi line; output:\n{output}"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn test_runner_broker_tty_line_discipline() {
    check_broker_tty_line_discipline(false);
}

#[cfg(target_os = "linux")]
#[test]
fn test_runner_broker_tty_alias() {
    check_broker_tty_line_discipline(true);
}

#[cfg(target_os = "linux")]
fn check_broker_tty_line_discipline(alias: bool) {
    use std::os::fd::AsRawFd as _;
    let name = if alias {
        "tty_alias"
    } else {
        "tty_line_discipline"
    };
    let target = common::compile("./tests/tty.c", name, true, false);
    let mut runner = Runner::new(&target, name);
    runner.allow_process_duplication();
    let mut pty = common::pty::Pty::open();
    let original = pty.attributes();
    // SAFETY: slave is a live descriptor and F_GETFL takes no argument.
    let flags = unsafe { libc::fcntl(pty.slave().as_raw_fd(), libc::F_GETFL) };
    let (stdin, stdout, stderr) = pty.slave_stdio();
    let mut child =
        runner.spawn_with_controlling_terminal(pty.slave(), stdin, stdout, stderr, alias);
    let mut output = Vec::new();
    for (prompt, input) in [
        (
            b"CANONICAL READY".as_slice(),
            b"hellx\x7fo\nsecond\n".as_slice(),
        ),
        (b"EOF READY", b"\x04"),
        (b"POLL READY", b"half"),
        (b"POLL BLOCKED", b"\n"),
        (b"RAW READY", b"\r\x03\x04"),
        (b"INTERRUPT READY", b"\x03"),
        (b"QUIT READY", b"\x1c"),
    ] {
        pty.wait_for_output(&mut output, prompt);
        pty.write_all(input);
    }
    pty.wait_for_output(&mut output, b"RESIZE READY");
    pty.set_window_size(37, 101);
    let status = pty.wait_for_child_exit(&mut child, &mut output);
    assert!(
        status.success(),
        "TTY fixture failed with {status}:\n{}",
        String::from_utf8_lossy(&output)
    );
    assert!(output.windows(8).any(|bytes| bytes == b"TTY DONE"));
    assert!(output.windows(11).any(|bytes| bytes == b"a       b\r\n"));
    assert_eq!(pty.attributes(), original);
    // SAFETY: slave is still live; F_GETFL takes no argument.
    assert_eq!(
        unsafe { libc::fcntl(pty.slave().as_raw_fd(), libc::F_GETFL) },
        flags
    );
}

/// The session moves the terminal's events to its foreground process group.
#[cfg(target_os = "linux")]
#[test]
fn test_runner_broker_tty_job_control() {
    let target = common::compile("./tests/tty.c", "tty_jobs", true, false);
    let mut runner = Runner::new(&target, "tty_jobs");
    runner.allow_process_duplication().arg("jobs");
    let mut pty = common::pty::Pty::open();
    let (stdin, stdout, stderr) = pty.slave_stdio();
    let mut child =
        runner.spawn_with_controlling_terminal(pty.slave(), stdin, stdout, stderr, false);
    let mut output = Vec::new();
    pty.wait_for_output(&mut output, b"JOB READY");
    pty.write_all(b"\x03");
    let status = pty.wait_for_child_exit(&mut child, &mut output);
    assert!(
        status.success(),
        "job-control TTY fixture failed with {status}:\n{}",
        String::from_utf8_lossy(&output)
    );
    assert!(output.windows(9).any(|bytes| bytes == b"JOBS DONE"));
}

/// A piped standard stream leaves the terminal to the host: the guest has none.
#[cfg(target_os = "linux")]
#[test]
fn test_runner_broker_tty_with_piped_stdout() {
    use std::io::Read as _;
    let target = common::compile("./tests/tty.c", "tty_pipe", true, false);
    let mut runner = Runner::new(&target, "tty_pipe");
    runner.arg("pipe");
    let mut pty = common::pty::Pty::open();
    let original = pty.attributes();
    let (stdin, _stdout, stderr) = pty.slave_stdio();
    let mut child = runner.spawn_with_controlling_terminal(
        pty.slave(),
        stdin,
        std::process::Stdio::piped(),
        stderr,
        false,
    );
    let mut output = Vec::new();
    pty.wait_for_output(&mut output, b"PIPE READY");
    assert_eq!(
        pty.attributes(),
        original,
        "the broker took over a terminal shared with a pipe"
    );
    pty.write_all(b"input\n");
    let status = pty.wait_for_child_exit(&mut child, &mut output);
    assert!(
        status.success(),
        "piped TTY fixture failed with {status}:\n{}",
        String::from_utf8_lossy(&output)
    );
    let mut stdout = Vec::new();
    child
        .stdout
        .take()
        .unwrap()
        .read_to_end(&mut stdout)
        .unwrap();
    assert_eq!(stdout, b"pipe\n");
}

/// With standard input from a file, the guest keeps the terminal, behind
/// `/dev/tty` and the other standard streams.
#[cfg(target_os = "linux")]
#[test]
fn test_runner_broker_tty_with_file_stdin() {
    let target = common::compile("./tests/tty.c", "tty_file", true, false);
    let mut runner = Runner::new(&target, "tty_file");
    runner.arg("file");
    let input = unlinked_test_file("tty-file-stdin", b"file\n");
    let mut pty = common::pty::Pty::open();
    let original = pty.attributes();
    let (_stdin, stdout, stderr) = pty.slave_stdio();
    let mut child =
        runner.spawn_with_controlling_terminal(pty.slave(), input.into(), stdout, stderr, false);
    let mut output = Vec::new();
    pty.wait_for_output(&mut output, b"FILE READY");
    pty.write_all(b"keys\n");
    let status = pty.wait_for_child_exit(&mut child, &mut output);
    assert!(
        status.success(),
        "file-input TTY fixture failed with {status}:\n{}",
        String::from_utf8_lossy(&output)
    );
    assert!(output.windows(9).any(|bytes| bytes == b"FILE DONE"));
    assert_eq!(pty.attributes(), original);
}

/// The terminal signals the guest even when no standard stream refers to it
/// and the guest has not opened it.
#[cfg(target_os = "linux")]
#[test]
fn test_runner_broker_tty_signals_without_terminal_streams() {
    use std::os::unix::fs::FileExt as _;
    let target = common::compile("./tests/tty.c", "tty_detached", true, false);
    let mut runner = Runner::new(&target, "tty_detached");
    runner.arg("detached");
    let log = unlinked_test_file("tty-detached-stdout", b"");
    let read_log = || {
        let mut contents = [0; 64];
        let len = log.read_at(&mut contents, 0).unwrap();
        contents[..len].to_vec()
    };
    let mut pty = common::pty::Pty::open();
    let original = pty.attributes();
    let mut child = runner.spawn_with_controlling_terminal(
        pty.slave(),
        std::process::Stdio::null(),
        log.try_clone().unwrap().into(),
        std::process::Stdio::null(),
        false,
    );
    let mut output = Vec::new();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while read_log() != b"DETACHED READY\n" {
        if std::time::Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("timed out waiting for the fixture");
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    pty.write_all(b"\x03");
    let status = pty.wait_for_child_exit(&mut child, &mut output);
    assert!(
        status.success(),
        "detached TTY fixture failed with {status}:\n{}",
        String::from_utf8_lossy(&output)
    );
    assert_eq!(read_log(), b"DETACHED READY\nDETACHED DONE\n");
    assert_eq!(pty.attributes(), original);
}

/// Opens a temporary file holding `contents` for reading and writing, already
/// unlinked so that it never outlives the test.
#[cfg(target_os = "linux")]
fn unlinked_test_file(name: &str, contents: &[u8]) -> std::fs::File {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!("litebox-{name}-{}-{nonce}", std::process::id()));
    std::fs::write(&path, contents).unwrap();
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&path)
        .unwrap();
    std::fs::remove_file(&path).unwrap();
    file
}

#[cfg(target_os = "linux")]
#[test]
#[cfg_attr(
    all(target_arch = "aarch64", feature = "aarch64_virtualize_x18"),
    ignore = "x18-virtualized libcrypto.so.3 fails to load (failed to map segment)"
)]
fn test_broker_with_curl() {
    use std::io::{Read, Write};
    use std::net::{Ipv4Addr, TcpListener};

    const RESPONSE_BODY: &str = "#!/bin/bash\necho 'Hello from litebox!'\n";

    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("Failed to bind HTTP server");
    let port = listener.local_addr().unwrap().port();

    let server_thread = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("Failed to accept connection");
        let mut buf = [0u8; 4096];
        let n = stream.read(&mut buf).expect("Failed to read request");
        let request = String::from_utf8_lossy(&buf[..n]);
        println!("Received HTTP request:\n{request}");

        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            RESPONSE_BODY.len(),
            RESPONSE_BODY
        );
        stream
            .write_all(response.as_bytes())
            .expect("Failed to send response");
    });

    let curl_path = run_which("curl");
    let mut runner = Runner::new(&curl_path, "curl_rewriter");
    let control_socket_path = unique_test_socket_path("runner-broker-curl-control");
    let broker = spawn_test_broker(
        &control_socket_path,
        litebox_broker_core::PolicyEngine::with_host_guaranteed_rights(
            litebox_broker_core::ObjectRights::all(),
        )
        .with_socket_policy(gateway_tcp_policy()),
        &[runner.tar_dir()],
        1,
    );
    let url = format!("http://10.0.2.1:{port}/something");
    runner
        .args(["-sS", &url])
        .broker_socket(&control_socket_path)
        .run();

    server_thread.join().expect("Server thread panicked");
    assert!(broker.next_close_object_count() > 0);
    let output = broker.join_with_stdout();

    let output_str = String::from_utf8_lossy(&output);
    assert!(output_str.contains(RESPONSE_BODY), "Unexpected curl output");
}

#[cfg(target_os = "linux")]
#[test]
#[cfg_attr(
    all(target_arch = "aarch64", feature = "aarch64_virtualize_x18"),
    ignore = "x18-virtualized libcrypto.so.3 fails to load (failed to map segment)"
)]
fn test_managed_egress_proxy_with_curl() {
    const CA_BUNDLE: &str = "/etc/ssl/certs/ca-certificates.crt";

    let probe = std::net::UdpSocket::bind((std::net::Ipv4Addr::UNSPECIFIED, 0))
        .expect("failed to create IPv4 route probe");
    if let Err(error) = probe.connect((std::net::Ipv4Addr::new(192, 0, 2, 1), 9)) {
        if error.kind() == std::io::ErrorKind::NetworkUnreachable {
            eprintln!("skipping managed egress proxy test: IPv4 route unavailable: {error}");
            return;
        }
        panic!("IPv4 route probe failed: {error}");
    }

    assert!(
        Path::new(CA_BUNDLE).is_file(),
        "system CA bundle is unavailable at {CA_BUNDLE}"
    );

    let curl_path = run_which("curl");
    let mut runner = Runner::new(&curl_path, "managed_egress_proxy_curl");
    runner
        .allow_proxy_host("bing.com:443")
        .env("HTTPS_PROXY=http://wrong.example:8080")
        .env("NO_PROXY=*")
        .with_fs_path(|root| {
            let destination = root.join(CA_BUNDLE.trim_start_matches('/'));
            std::fs::create_dir_all(destination.parent().unwrap()).unwrap();
            let source_metadata = std::fs::metadata(CA_BUNDLE).unwrap();
            let modified = source_metadata.modified().unwrap();
            if !std::fs::metadata(&destination).is_ok_and(|metadata| {
                metadata.len() == source_metadata.len() && metadata.modified().unwrap() == modified
            }) {
                // `copy` keeps a read-only mode, so remove any earlier copy.
                let _ = std::fs::remove_file(&destination);
                std::fs::copy(CA_BUNDLE, &destination).unwrap();
                std::fs::File::open(&destination)
                    .unwrap()
                    .set_modified(modified)
                    .unwrap();
            }
        })
        .args([
            "--silent",
            "--show-error",
            "--output",
            "/dev/null",
            "--write-out",
            "%{http_code}",
            "--connect-timeout",
            "10",
            "--max-time",
            "30",
            "--cacert",
            CA_BUNDLE,
            "https://bing.com/",
        ]);

    let output = runner.output();
    let status = String::from_utf8(output).expect("curl emitted non-UTF-8 status");
    assert!(
        status.len() == 3 && status.bytes().all(|byte| byte.is_ascii_digit()) && status != "000",
        "curl did not receive an HTTPS response from bing.com: {status:?}"
    );
}

/// Exercises sustained brokered TCP traffic and backpressure with iperf3.
///
/// To run it with a release build and see output:
/// ```
/// cargo test --package litebox_runner_linux_userland --test run --release -- test_broker_with_iperf3 --exact --nocapture
/// ```
#[cfg(target_os = "linux")]
#[test]
#[cfg_attr(
    all(target_arch = "aarch64", feature = "aarch64_virtualize_x18"),
    ignore = "x18-virtualized libcrypto.so.3 fails to load (failed to map segment)"
)]
fn test_broker_with_iperf3() {
    use std::io::{BufRead, BufReader};
    use std::net::{Ipv4Addr, TcpListener};
    use std::process::Stdio;

    const IPERF_TEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

    let iperf3_path = run_which("iperf3");
    let mut runner = Runner::new(&iperf3_path, "broker_iperf3_client_rewriter");
    let control_socket_path = unique_test_socket_path("runner-broker-iperf3-control");
    let broker = spawn_test_broker(
        &control_socket_path,
        litebox_broker_core::PolicyEngine::with_host_guaranteed_rights(
            litebox_broker_core::ObjectRights::all(),
        )
        .with_socket_policy(gateway_tcp_policy()),
        &[runner.tar_dir()],
        1,
    );

    let mut last_server_output = String::new();
    let mut started_server = None;
    for _ in 0..5 {
        let port = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .expect("failed to reserve iperf3 port")
            .local_addr()
            .unwrap()
            .port();
        let mut server = std::process::Command::new(&iperf3_path)
            .args([
                "-s",
                "-1",
                "--forceflush",
                "-B",
                "127.0.0.1",
                "-p",
                &port.to_string(),
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("failed to start iperf3 server");
        let server_stdout = server.stdout.take().unwrap();
        let (listening_tx, listening_rx) = std::sync::mpsc::channel();
        let server_output = std::thread::spawn(move || {
            let mut stdout = BufReader::new(server_stdout);
            let mut output = String::new();
            let mut listening_reported = false;
            loop {
                let mut line = String::new();
                if stdout
                    .read_line(&mut line)
                    .expect("failed to read iperf3 server output")
                    == 0
                {
                    break;
                }
                output.push_str(&line);
                if !listening_reported && line.contains("Server listening") {
                    listening_reported = true;
                    let _ = listening_tx.send(());
                }
            }
            output
        });
        if listening_rx.recv_timeout(BROKER_HELPER_TIMEOUT).is_ok() {
            started_server = Some((port, server, server_output));
            break;
        }
        let _ = server.kill();
        let _ = server.wait();
        last_server_output = server_output.join().unwrap();
    }
    let (port, mut server, server_output) = started_server
        .unwrap_or_else(|| panic!("iperf3 server did not start; output:\n{last_server_output}"));

    runner
        .args([
            "-c",
            "10.0.2.1",
            "-p",
            &port.to_string(),
            "--connect-timeout",
            "1000",
            "--bytes",
            "1M",
        ])
        .broker_socket(&control_socket_path);

    let mut guest = runner.spawn_with_stdio(Stdio::null(), Stdio::inherit(), Stdio::inherit());
    let deadline = std::time::Instant::now() + IPERF_TEST_TIMEOUT;
    let mut guest_status = None;
    let mut server_status = None;
    while guest_status.is_none() || server_status.is_none() {
        if guest_status.is_none() {
            guest_status = guest.try_wait().expect("failed to wait for iperf3 guest");
        }
        if server_status.is_none() {
            server_status = server.try_wait().expect("failed to wait for iperf3 server");
        }
        if guest_status.is_some() && server_status.is_some() {
            break;
        }
        if std::time::Instant::now() >= deadline {
            if guest_status.is_none() {
                guest.kill().expect("failed to stop iperf3 guest");
                let _ = guest.wait();
            }
            if server_status.is_none() {
                server.kill().expect("failed to stop iperf3 server");
                let _ = server.wait();
            }
            let output = server_output.join().unwrap();
            panic!("iperf3 test did not finish; server output:\n{output}");
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    let guest_status = guest.wait().expect("failed to reap iperf3 guest");
    let server_status = server.wait().expect("failed to reap iperf3 server");
    let server_output = server_output.join().unwrap();
    assert!(
        guest_status.success(),
        "iperf3 guest failed ({guest_status}); server output:\n{server_output}"
    );
    assert!(
        server_status.success(),
        "iperf3 server failed; output:\n{server_output}"
    );
    assert!(broker.next_close_object_count() > 0);
    broker.join();
}

#[test]
fn test_shebang() {
    let bash_path = run_which("bash");

    let output = Runner::new(&bash_path, "shebang_rewriter")
        .with_fs_path(|out_dir| {
            // Create a shebang script pointing to the staged bash.
            std::fs::write(
                out_dir.join("out/script.sh"),
                format!("#!{}\necho shebang_test_passed\n", bash_path.display()),
            )
            .unwrap();
        })
        .guest_program_path("/out/script.sh")
        .output();

    let output_str = String::from_utf8_lossy(&output);
    assert!(
        output_str.contains("shebang_test_passed"),
        "shebang test failed, output: {output_str}"
    );
}
