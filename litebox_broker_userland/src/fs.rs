// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Broker-owned file service construction shared by userland platforms.

use std::borrow::Cow;
use std::io::{Error as IoError, ErrorKind, Result as IoResult};
use std::path::Path;
use std::sync::Arc;

use litebox_broker_core::fs::FileService;
use litebox_broker_core::fs::composer::Composer;
use litebox_broker_core::fs::in_mem::{InMem, InitialNode};
use litebox_broker_core::fs::overlay::Overlay;
use litebox_broker_core::fs::resolver::Resolver;
use litebox_broker_core::fs::tar_ro::{EMPTY_TAR_FILE, TarRo};
use litebox_broker_protocol::fs::{FileMode as Mode, FileUser as UserInfo};
use litebox_platform::sync::RawSyncPrimitivesProvider;

pub(super) fn create_file_service<Platform>(
    initial_files: Option<&Path>,
) -> IoResult<Arc<dyn FileService>>
where
    Platform: RawSyncPrimitivesProvider,
{
    let writable_directory = |owner| InitialNode::Directory {
        mode: Mode::RWXU | Mode::RWXG | Mode::RWXO,
        owner,
    };
    let entries = vec![
        ("/tmp".to_owned(), writable_directory(UserInfo::ROOT)),
        ("/registry".to_owned(), writable_directory(UserInfo::ROOT)),
    ];

    let tar_data = match initial_files {
        Some(path) => {
            if path.extension().and_then(|extension| extension.to_str()) != Some("tar") {
                return Err(IoError::new(
                    ErrorKind::InvalidInput,
                    format!("expected a .tar file, found {}", path.display()),
                ));
            }
            Cow::Owned(std::fs::read(path)?)
        }
        None => Cow::Borrowed(EMPTY_TAR_FILE),
    };
    let in_mem = InMem::<Platform>::new_initialized(entries);
    let backend = Composer::builder()
        .mount_nestable("/", |allocators| {
            Overlay::<Platform>::new(
                in_mem,
                TarRo::new(tar_data, allocators.next()),
                allocators.next(),
            )
        })
        .mount("/dev", litebox_broker_core::fs::devices::Devices::new)
        .build()
        .map_err(|_| IoError::other("failed to construct broker file service"))?;
    Ok(Arc::new(Resolver::<Platform, _>::new(backend)))
}
