// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Broker tests require `cargo nextest` process-per-test isolation:
//! only one broker core may be constructed per process.

extern crate std;

use super::*;
use crate::MacosShimBuilder;
use alloc::sync::Arc;
use litebox::{
    LiteBox,
    platform::{PageManagementProvider, page_mgmt::MemoryRegionPermissions as Permissions},
};
use litebox_broker_core::{
    BrokerCore, ObjectRights, PolicyEngine,
    fs::{
        in_mem::{InMem, InitialNode},
        resolver::Resolver,
    },
    random::{RandomProvider, RandomProviderError},
    test_support::{FailingRandomProvider, TestBrokerCoreBuilder},
};
use litebox_broker_host::test_support::InProcessBrokerSetup;
use litebox_broker_local::BrokerLocal;
use litebox_broker_protocol::fs::{FileAccessMode, FileOpenFlags, FileUser};
use litebox_common_macos::{STACK_ALIGNMENT, TaskParams, errno::Errno, user_pointers::UserPtr};
use litebox_platform_macos_userland::{GuestAbi, MacosUserland as Platform, set_guest_abi};
use std::process::Command;

/// Requires Xcode command-line tools; the executable needs neither libc nor dyld.
fn image() -> Vec<u8> {
    link(
        include_str!("fixtures/static.S"),
        &["-static", "-e", "_start"],
    )
}

/// Assemble and link an AArch64 Mach-O with Xcode command-line tools.
fn link(assembly: &str, link_args: &[&str]) -> Vec<u8> {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("image.S");
    let object = dir.path().join("image.o");
    let executable = dir.path().join("image");
    std::fs::write(&source, assembly).unwrap();
    for mut command in [
        {
            let mut command = Command::new("xcrun");
            command
                .args(["as", "-arch", "arm64"])
                .arg(&source)
                .arg("-o")
                .arg(&object);
            command
        },
        {
            let mut command = Command::new("xcrun");
            command
                .args(["ld", "-arch", "arm64"])
                .args(link_args)
                .arg(&object)
                .arg("-o")
                .arg(&executable);
            command
        },
    ] {
        let output = command
            .output()
            .expect("Xcode command-line tools are required");
        assert!(
            output.status.success(),
            "{command:?}: {}",
            std::string::String::from_utf8_lossy(&output.stderr)
        );
    }
    std::fs::read(executable).unwrap()
}

fn builder(executable: Vec<u8>, random: Arc<dyn RandomProvider>) -> MacosShimBuilder<Platform> {
    let mode = FileMode::from_u32_bits_truncate(0o755);
    let directory = || InitialNode::Directory {
        mode,
        owner: FileUser::ROOT,
    };
    let fs = InMem::<Platform>::new_initialized(vec![
        ("/", directory()),
        ("/bin", directory()),
        (
            "/bin/main",
            InitialNode::File {
                mode,
                owner: FileUser::ROOT,
                data: executable.into(),
            },
        ),
    ]);
    let core = TestBrokerCoreBuilder::new(PolicyEngine::with_unauthenticated_rights(
        ObjectRights::all(),
    ))
    .with_file_service(Arc::new(Resolver::<Platform, _>::new(fs)))
    .with_random_provider(random)
    .build()
    .unwrap();
    builder_for(Platform::new(), core)
}

/// A shim builder associated with `core` as its own broker process.
fn builder_for(platform: &'static Platform, core: BrokerCore) -> MacosShimBuilder<Platform> {
    let setup = InProcessBrokerSetup::new(core);
    let readiness = setup.readiness_sink();
    let (local, _startup, ()) = BrokerLocal::negotiate(setup, |setup| {
        let memory = setup.shared_memory();
        Ok((setup.activate(), memory, ()))
    })
    .unwrap();
    let litebox = LiteBox::new_with_broker_local(platform, local);
    readiness.attach(litebox.broker_notification_dispatcher());
    MacosShimBuilder::new_with_litebox(platform, litebox)
}

/// Fixed bytes for the apple[] entropy keys dynamic executables require.
struct FixedRandomProvider;

impl RandomProvider for FixedRandomProvider {
    fn fill(&self, output: &mut [u8]) -> Result<(), RandomProviderError> {
        output.fill(0x5a);
        Ok(())
    }
}

fn read_bytes(address: usize, size: usize) -> Vec<u8> {
    UserPtr::from_usize(address)
        .to_owned_slice::<Platform>(size)
        .unwrap()
        .to_vec()
}
fn word(address: usize) -> usize {
    usize::from_le_bytes(read_bytes(address, size_of::<usize>()).try_into().unwrap())
}

#[test]
fn filesystem_loader_runs_linked_static_macho() {
    set_guest_abi(GuestAbi::Darwin);
    let executable = image();
    let plan = MachoParsedFile::parse(&executable).unwrap();
    let mut builder = builder(executable.clone(), Arc::new(FixedRandomProvider));
    // Executable descriptors must not consume or close inherited guest FDs.
    let fd = builder
        .litebox()
        .open_file(
            &litebox::fs::Context::new(),
            "/bin/main",
            FileAccessMode::ReadOnly,
            FileOpenFlags::NONE,
            FileMode::empty(),
        )
        .unwrap();
    assert_eq!(builder.inherit_file(fd), Ok(0));
    let shim = builder.build();
    let global = Arc::downgrade(&shim.global);
    let argv = vec![CString::new("not-the-executable-path").unwrap()];
    let envp = vec![CString::new("K=V").unwrap()];
    let argument_count = argv.len();
    let argv_end = 1 + argument_count; // argc word followed by argv pointers
    let envp_end = argv_end + 1 + envp.len();
    let apple_start = envp_end + 1;
    let program = shim
        .load_program(TaskParams::default(), "/bin/main", argv, envp)
        .unwrap();
    let task = &program.entrypoints.task;
    assert!(task.files.typed_fd(0).is_ok());
    assert!(matches!(task.files.typed_fd(1), Err(Errno::EBADF)));
    let relocate = |address| {
        program.initial_ctx.pc - (plan.entry - plan.virtual_range.start)
            + (address - plan.virtual_range.start)
    };
    let mut bss_bytes = 0;
    for segment in &plan.segments {
        let start = relocate(segment.virtual_range.start);
        let range = start..start + segment.virtual_range.len();
        for (protection, permission) in [
            (VmProtection::READ, Permissions::READ),
            (VmProtection::WRITE, Permissions::WRITE),
            (VmProtection::EXECUTE, Permissions::EXEC),
        ] {
            assert_eq!(
                task.global
                    .mm
                    .range_has_permissions(range.clone(), permission),
                segment.protection.contains(protection)
            );
        }
        if segment.protection.contains(VmProtection::WRITE) {
            assert_eq!(
                read_bytes(start, segment.file_range.len()),
                &executable[segment.file_range.clone()]
            );
            let bss = segment.virtual_range.len() - segment.file_range.len();
            assert!(
                read_bytes(start + segment.file_range.len(), bss)
                    .iter()
                    .all(|&byte| byte == 0)
            );
            bss_bytes += bss;
        }
    }
    assert!(
        bss_bytes >= 2 * PAGE_SIZE,
        "fixture must exercise multi-page BSS"
    );
    let sp = program.initial_ctx.sp;
    assert_eq!(sp % STACK_ALIGNMENT, 0);
    let midpoint =
        Platform::TASK_ADDR_MIN + (Platform::TASK_ADDR_MAX - Platform::TASK_ADDR_MIN) / 2;
    assert!(sp >= midpoint, "stack was not placed top-down: {sp:#x}");
    assert_eq!(word(sp), argument_count);
    let stack_end = (sp + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
    let guard = stack_end - STACK_SIZE - PAGE_SIZE;
    let apple = [
        std::string::String::from("executable_path=/bin/main"),
        std::string::String::from("stack_guard=0x5a5a5a5a5a5a005a"),
        std::format!("malloc_entropy={0:#x},{0:#x}", 0x5a5a_5a5a_5a5a_5a5a_u64),
        std::format!("ptr_munge={:#x}", 0x5a5a_5a5a_5a5a_5a5a_u64),
        std::format!(
            "main_stack={stack_end:#x},{STACK_SIZE:#x},{guard:#x},{:#x}",
            STACK_SIZE + PAGE_SIZE
        ),
        std::string::String::from("security_config=0x0"),
    ];
    for terminator in [argv_end, envp_end, apple_start + apple.len()] {
        assert_eq!(word(sp + terminator * size_of::<usize>()), 0);
    }
    for (index, expected) in apple.iter().enumerate() {
        let address = word(sp + (apple_start + index) * size_of::<usize>());
        assert_eq!(
            read_bytes(address, expected.len() + 1),
            [expected.as_bytes(), b"\0"].concat()
        );
    }
    assert!(
        !task
            .global
            .mm
            .range_has_permissions(guard..guard + PAGE_SIZE, Permissions::READ)
    );
    let crate::LoadedProgram {
        entrypoints,
        process,
        mut initial_ctx,
    } = program;
    // SAFETY: the loader validated and rewrote this linked static executable;
    // entrypoints own all mappings until run_thread returns.
    unsafe {
        litebox_platform_macos_userland::run_thread(entrypoints, &mut initial_ctx);
    }
    assert_eq!(process.exit_status(), Some(42));
    assert!(global.upgrade().is_none());
}

#[test]
fn byte_snapshot_path_is_independent_of_argv() {
    set_guest_abi(GuestAbi::Darwin);
    let platform = Platform::new();
    let executable = image();
    // argv[0] is arbitrary bytes, not an executable identity or a UTF-8 path.
    let argument = CString::new(vec![0xff, b'x']).unwrap();
    let argv = vec![argument.clone()];
    // argc, argv[], NULL and empty envp's NULL precede apple[].
    let apple_index = 1 + argv.len() + 1 + 1;
    let program = MacosShimBuilder::new(platform)
        .build()
        .load_program_from_bytes(
            TaskParams::default(),
            "/bin/actual-executable",
            &executable,
            argv,
            Vec::new(),
        )
        .unwrap();
    let sp = program.initial_ctx.sp;
    let first_argument = word(sp + size_of::<usize>());
    assert_eq!(
        read_bytes(first_argument, argument.as_bytes_with_nul().len()),
        argument.as_bytes_with_nul()
    );
    let apple = word(sp + apple_index * size_of::<usize>());
    let expected = b"executable_path=/bin/actual-executable\0";
    assert_eq!(read_bytes(apple, expected.len()), expected);
}

/// A broker random request that fails would abort the broker association,
/// so the load fails instead of starting a static executable without entropy.
#[test]
fn failed_random_request_fails_static_load() {
    set_guest_abi(GuestAbi::Darwin);
    let result = builder(image(), Arc::new(FailingRandomProvider))
        .build()
        .load_program(TaskParams::default(), "/bin/main", Vec::new(), Vec::new());
    assert!(matches!(result, Err(MachoLoaderError::Entropy)));
}

#[test]
fn static_load_without_random_source_omits_entropy_keys() {
    set_guest_abi(GuestAbi::Darwin);
    let program = MacosShimBuilder::new(Platform::new())
        .build()
        .load_program_from_bytes(
            TaskParams::default(),
            "/bin/main",
            &image(),
            Vec::new(),
            Vec::new(),
        )
        .unwrap();
    // argc, the empty argv and envp terminators, then apple[].
    let apple_start = 3;
    let sp = program.initial_ctx.sp;
    let apple = |index: usize| word(sp + (apple_start + index) * size_of::<usize>());
    for (index, prefix) in [
        &b"executable_path="[..],
        b"main_stack=",
        b"security_config=",
    ]
    .into_iter()
    .enumerate()
    {
        assert_eq!(read_bytes(apple(index), prefix.len()), prefix);
    }
    assert_eq!(apple(3), 0);
}

/// A minimal executable linked against libSystem, so it requires dyld.
fn dynamic_main() -> Vec<u8> {
    let sdk = Command::new("xcrun")
        .arg("--show-sdk-path")
        .output()
        .expect("Xcode command-line tools are required");
    assert!(sdk.status.success());
    let sdk = std::string::String::from_utf8(sdk.stdout).unwrap();
    link(
        ".global _main\n.p2align 2\n_main:\n mov x0, #42\n ret\n",
        &["-e", "_main", "-lSystem", "-syslibroot", sdk.trim()],
    )
}

/// libSystem's initializers require the entropy keys.
#[test]
fn dynamic_load_without_random_source_fails() {
    set_guest_abi(GuestAbi::Darwin);
    let host_dyld = std::fs::read("/usr/lib/dyld").unwrap();
    let result = MacosShimBuilder::new(Platform::new())
        .build()
        .load_program_with_dyld(
            TaskParams::default(),
            "/bin/main",
            &dynamic_main(),
            arm64_slice(&host_dyld).unwrap(),
            Vec::new(),
            Vec::new(),
        );
    assert!(matches!(result, Err(MachoLoaderError::Entropy)));
}

#[test]
fn aot_rewritten_dyld_loads_like_raw_dyld() {
    set_guest_abi(GuestAbi::Darwin);
    let main = dynamic_main();
    let host_dyld = std::fs::read("/usr/lib/dyld").unwrap();
    let raw = arm64_slice(&host_dyld).unwrap();
    let aot =
        hook_syscalls_in_macho_with_options(raw, None, crate::aarch64_rewrite_options()).unwrap();
    assert!(matches!(
        MachoParsedFile::parse(&aot).unwrap().parse_trampoline(&aot),
        Ok(Some(_))
    ));
    let broker = TestBrokerCoreBuilder::new(PolicyEngine::with_unauthenticated_rights(
        ObjectRights::all(),
    ))
    .with_random_provider(Arc::new(FixedRandomProvider))
    .build()
    .unwrap();
    // The loader rewrites raw dyld itself and uses the AOT image as supplied;
    // both must yield the same dyld entry code.
    let entry_code = |dyld: &[u8]| {
        let program = builder_for(Platform::new(), broker.clone())
            .build()
            .load_program_with_dyld(
                TaskParams::default(),
                "/bin/main",
                &main,
                dyld,
                Vec::new(),
                Vec::new(),
            )
            .unwrap();
        let sp = program.initial_ctx.sp;
        let main_header = word(sp);
        let code = read_bytes(program.initial_ctx.pc, 64);
        assert_eq!(read_bytes(main_header, 4), 0xfeed_facf_u32.to_le_bytes());
        code
    };
    assert_eq!(entry_code(raw), entry_code(&aot));
}
