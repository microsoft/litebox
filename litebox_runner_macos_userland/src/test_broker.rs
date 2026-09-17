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
        resolver::Resolver,
    },
    test_support::{TestBrokerCoreBuilder, TestStdioProvider},
};
use litebox_broker_host::test_support::InProcessBrokerSetup;
use litebox_broker_local::BrokerLocal;
use litebox_broker_protocol::{
    fs::{FileAccessMode, FileMode, FileOpenFlags, FileUser},
    stdio::StdioOutputStream,
};
use litebox_platform_macos_userland::MacosUserland;
use litebox_shim_macos::MacosShimBuilder;
use std::{
    io::{Read as _, Write as _},
    sync::Arc,
};

pub(crate) fn setup(
    platform: &'static MacosUserland,
    executable: Vec<u8>,
    mmap_image: Option<&[u8]>,
) -> Result<(MacosShimBuilder<MacosUserland>, Arc<TestStdioProvider>)> {
    let stdio = Arc::new(TestStdioProvider::default());
    let mut input = Vec::new();
    std::io::stdin()
        .read_to_end(&mut input)
        .context("reading test input")?;
    stdio.push_input(&input);
    let mut initial_nodes = vec![
        (
            "/",
            InitialNode::Directory {
                mode: FileMode::RWXU | FileMode::RWXG | FileMode::RWXO,
                owner: FileUser::ROOT,
            },
        ),
        (
            "/executable",
            InitialNode::File {
                mode: FileMode::from_u32_bits_truncate(0o555),
                owner: FileUser::ROOT,
                data: executable.into(),
            },
        ),
    ];
    if let Some(image) = mmap_image {
        initial_nodes.push((
            "/mmap-image",
            InitialNode::File {
                mode: FileMode::from_u32_bits_truncate(0o555),
                owner: FileUser::ROOT,
                data: image.to_vec().into(),
            },
        ));
    }
    let fs = InMem::<MacosUserland>::new_initialized(initial_nodes);
    let fs = Composer::builder()
        .mount("/", |_| fs)
        .mount("/dev", Devices::new)
        .build()
        .map_err(|error| anyhow!("test filesystem: {error:?}"))?;
    let core = TestBrokerCoreBuilder::new(PolicyEngine::with_unauthenticated_rights(
        ObjectRights::all(),
    ))
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
    let litebox = LiteBox::new_with_broker_local(platform, local);
    readiness.attach(litebox.broker_notification_dispatcher());
    let mut builder = MacosShimBuilder::new_with_litebox(platform, litebox);
    let mut context = litebox::fs::Context::new();
    context.set_acting_user(FileUser::ROOT);
    for (path, access) in [
        ("/dev/stdin", FileAccessMode::ReadOnly),
        ("/dev/stdout", FileAccessMode::WriteOnly),
        ("/dev/stderr", FileAccessMode::WriteOnly),
    ] {
        let fd = builder
            .litebox()
            .open_file(
                &context,
                path,
                access,
                FileOpenFlags::NONE,
                FileMode::empty(),
            )
            .with_context(|| format!("opening test stream {path}"))?;
        builder
            .inherit_file(fd)
            .map_err(|error| anyhow!("inheriting {path}: {error}"))?;
    }
    Ok((builder, stdio))
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
