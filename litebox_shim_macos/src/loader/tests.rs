// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Broker tests require `cargo nextest` process-per-test isolation:
//! only one broker core may be constructed per process.

extern crate std;

use super::*;
use crate::MacosShimBuilder;
use alloc::sync::Arc;
use litebox::{LiteBox, platform::page_mgmt::MemoryRegionPermissions as Permissions};
use litebox_broker_core::{
    ObjectRights, PolicyEngine,
    fs::{
        in_mem::{InMem, InitialNode},
        resolver::Resolver,
    },
    test_support::TestBrokerCoreBuilder,
};
use litebox_broker_host::test_support::InProcessBrokerSetup;
use litebox_broker_local::BrokerLocal;
use litebox_broker_protocol::fs::{FileAccessMode, FileOpenFlags, FileUser};
use litebox_common_macos::{STACK_ALIGNMENT, TaskParams, errno::Errno, user_pointers::UserPtr};
use litebox_platform_macos_userland::{GuestAbi, MacosUserland as Platform, set_guest_abi};
use std::process::Command;

/// Requires Xcode command-line tools; the executable needs neither libc nor dyld.
fn image() -> Vec<u8> {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("static.S");
    let object = dir.path().join("static.o");
    let executable = dir.path().join("static");
    std::fs::write(&source, include_str!("fixtures/static.S")).unwrap();
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
                .args(["ld", "-arch", "arm64", "-static", "-e", "_start"])
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

fn builder(executable: Vec<u8>) -> MacosShimBuilder<Platform> {
    let platform = Platform::new();
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
    .build()
    .unwrap();
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
    let mut builder = builder(executable.clone());
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
                    .pm
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
    assert_eq!(word(sp), argument_count);
    for terminator in [argv_end, envp_end, apple_start + 1] {
        assert_eq!(word(sp + terminator * size_of::<usize>()), 0);
    }
    let apple = b"executable_path=/bin/main\0";
    assert_eq!(
        read_bytes(word(sp + apple_start * size_of::<usize>()), apple.len()),
        apple
    );
    let stack_end = (sp + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
    let guard = stack_end - STACK_SIZE - PAGE_SIZE;
    assert!(
        !task
            .global
            .pm
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
