// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use std::sync::Arc;

use litebox_broker_core::AssociationCancellation;
use litebox_broker_core::filesystem::FilesystemProvider;
use litebox_broker_core::fs::{
    Mode, NamespacedFilesystemProvider, OFlags, create_windows_registry_provider,
};
use litebox_broker_core::random::{RandomProvider, RandomProviderError};
use litebox_broker_core::stdio::UnsupportedStdioProvider;
use litebox_broker_platform_linux_userland::LinuxSyncPrimitivesProvider;
use litebox_broker_protocol::filesystem::{FilesystemError, FilesystemNamespace, FilesystemUser};

struct TestRandomProvider;

impl RandomProvider for TestRandomProvider {
    fn fill(&self, output: &mut [u8]) -> Result<(), RandomProviderError> {
        output.fill(0);
        Ok(())
    }
}

fn empty_provider() -> Arc<dyn FilesystemProvider> {
    create_windows_registry_provider::<LinuxSyncPrimitivesProvider>(
        Arc::new(TestRandomProvider),
        Arc::new(UnsupportedStdioProvider),
    )
    .unwrap()
}

#[test]
fn filesystem_namespaces_are_isolated() {
    let provider = NamespacedFilesystemProvider::new(empty_provider(), empty_provider());
    let cancellation = AssociationCancellation::default();
    let user = FilesystemUser { user: 0, group: 0 };

    drop(
        provider
            .open(
                &cancellation,
                FilesystemNamespace::Guest,
                "/guest-only",
                user,
                (OFlags::CREAT | OFlags::WRONLY).bits(),
                Mode::RUSR.bits(),
            )
            .unwrap(),
    );
    assert!(
        provider
            .path_status(
                &cancellation,
                FilesystemNamespace::Guest,
                "/guest-only",
                user,
            )
            .is_ok()
    );
    assert_eq!(
        provider.path_status(
            &cancellation,
            FilesystemNamespace::WindowsRegistry,
            "/guest-only",
            user,
        ),
        Err(FilesystemError::NoSuchFileOrDirectory)
    );
}
