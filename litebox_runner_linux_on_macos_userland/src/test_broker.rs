// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! In-process broker fixture for the test-broker runner feature.

use anyhow::{Context as _, Result, anyhow};
use litebox::LiteBox;
use litebox_broker_core::{
    ObjectRights, PolicyEngine,
    fs::{
        composer::Composer,
        devices::Devices,
        in_mem::{InMem, InitialNode},
        overlay::Overlay,
        resolver::Resolver,
        tar_ro::{EMPTY_TAR_FILE, TarRo},
    },
    random::{RandomProvider, RandomProviderError},
    test_support::{TestBrokerCoreBuilder, TestStdioProvider},
};
use litebox_broker_host::test_support::InProcessBrokerSetup;
use litebox_broker_local::BrokerLocal;
use litebox_broker_protocol::{
    fs::{FileMode, FileUser},
    stdio::StdioOutputStream,
};
use litebox_platform_macos_userland::MacosUserland;
use litebox_shim_linux::LinuxShimBuilder;
use std::{
    borrow::Cow,
    io::{Read as _, Write as _},
    path::Path,
    sync::Arc,
};

const HOST_PROGRAM_PATH: &str = "/.litebox-host-program";

struct TestRandomProvider;

impl RandomProvider for TestRandomProvider {
    fn fill(&self, output: &mut [u8]) -> Result<(), RandomProviderError> {
        output.fill(0x5a);
        Ok(())
    }
}

pub(crate) struct Setup {
    pub(crate) builder: LinuxShimBuilder<MacosUserland>,
    pub(crate) process_id: i32,
    pub(crate) program_path: String,
    pub(crate) stdio: Arc<TestStdioProvider>,
}

pub(crate) fn setup(
    platform: &'static MacosUserland,
    initial_files: Option<&Path>,
    host_program: Option<&Path>,
) -> Result<Setup> {
    let stdio = Arc::new(TestStdioProvider::default());
    let mut input = Vec::new();
    std::io::stdin()
        .read_to_end(&mut input)
        .context("reading test input")?;
    stdio.push_input(&input);

    let directory = || InitialNode::Directory {
        mode: FileMode::RWXU | FileMode::RWXG | FileMode::RWXO,
        owner: FileUser::ROOT,
    };
    let mut entries = vec![("/tmp".to_owned(), directory())];
    if let Some(path) = host_program {
        entries.push((
            HOST_PROGRAM_PATH.to_owned(),
            InitialNode::File {
                mode: FileMode::RUSR
                    | FileMode::WUSR
                    | FileMode::XUSR
                    | FileMode::RGRP
                    | FileMode::XGRP
                    | FileMode::ROTH
                    | FileMode::XOTH,
                owner: FileUser::ROOT,
                data: std::fs::read(path)
                    .with_context(|| format!("reading guest program {}", path.display()))?
                    .into(),
            },
        ));
    }
    let tar_data = match initial_files {
        Some(path) => Cow::Owned(
            std::fs::read(path)
                .with_context(|| format!("reading initial files {}", path.display()))?,
        ),
        None => Cow::Borrowed(EMPTY_TAR_FILE),
    };
    let upper = InMem::<MacosUserland>::new_initialized(entries);
    let fs = Composer::builder()
        .mount_nestable("/", |allocators| {
            Overlay::<MacosUserland>::new(
                upper,
                TarRo::new(tar_data, allocators.next()),
                allocators.next(),
            )
        })
        .mount("/dev", Devices::new)
        .build()
        .map_err(|error| anyhow!("test filesystem: {error:?}"))?;
    let core = TestBrokerCoreBuilder::new(PolicyEngine::with_unauthenticated_rights(
        ObjectRights::all(),
    ))
    .with_random_provider(Arc::new(TestRandomProvider))
    .with_stdio_provider(stdio.clone())
    .with_file_service(Arc::new(Resolver::<MacosUserland, _>::new(fs)))
    .build()
    .map_err(|error| anyhow!("test broker: {error:?}"))?;
    let setup = InProcessBrokerSetup::new(core);
    let readiness = setup.readiness_sink();
    let (local, ()) = BrokerLocal::negotiate(setup, |setup| {
        let memory = setup.shared_memory();
        Ok((setup.activate(), memory, ()))
    })
    .map_err(|error| anyhow!("test broker negotiation: {error:?}"))?;
    let process_id = 1;
    let litebox = LiteBox::new_with_broker_local(platform, local);
    readiness.attach(litebox.broker_notification_dispatcher());

    Ok(Setup {
        builder: LinuxShimBuilder::new_with_litebox(platform, litebox),
        process_id,
        program_path: host_program.map_or_else(String::new, |_| HOST_PROGRAM_PATH.to_owned()),
        stdio,
    })
}

pub(crate) fn flush_output(stdio: &TestStdioProvider) -> Result<()> {
    for (stream, bytes) in stdio.writes() {
        match stream {
            StdioOutputStream::Stdout => std::io::stdout().write_all(&bytes)?,
            StdioOutputStream::Stderr => std::io::stderr().write_all(&bytes)?,
        }
    }
    Ok(())
}
