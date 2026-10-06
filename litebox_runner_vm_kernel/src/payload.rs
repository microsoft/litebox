// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! The first boot module: a tar of named files. Services and clients take the
//! files they need.

use alloc::collections::BTreeMap;
use litebox_bootloader::handoff::BootInfo;
use litebox_platform_vm_kernel::KERNEL_OFFSET;

pub struct Payload {
    files: BTreeMap<&'static str, &'static [u8]>,
}

impl Payload {
    /// # Errors
    ///
    /// No boot module, or not a tar.
    pub fn read(info: &BootInfo) -> Result<Self, &'static str> {
        let module = info
            .modules
            .first()
            .ok_or("no payload module (pass -initrd)")?;
        let len = usize::try_from(module.end - module.start).unwrap();
        // Safety: boot modules are excluded from the heap and stay mapped at
        // `PA + KERNEL_OFFSET` for the kernel's lifetime.
        let data: &'static [u8] = unsafe {
            core::slice::from_raw_parts((module.start.as_u64() + KERNEL_OFFSET) as *const u8, len)
        };
        let archive = tar_no_std::TarArchiveRef::new(data).map_err(|_| "payload is not a tar")?;
        let mut files = BTreeMap::new();
        for entry in archive.entries() {
            let filename = entry.filename();
            let Ok(name) = filename.as_str() else {
                continue;
            };
            // `tar_no_std` names do not outlive the entry.
            let name: &'static str = alloc::boxed::Box::leak(name.trim_start_matches("./").into());
            files.insert(name, entry.data());
        }
        Ok(Self { files })
    }

    pub fn file(&self, name: &str) -> Option<&'static [u8]> {
        self.files.get(name).copied()
    }
}
