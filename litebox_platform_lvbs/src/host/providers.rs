// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Optional host capabilities exposed through the shared kernel. These do not
//! grant VTL authority: the LVBS Vmap implementation remains gate-aware and
//! concrete. A host can implement VmapManager directly for other memory models,
//! including explicit rejection by a plain-VM test host.

use super::Host;
use crate::LinuxKernel;
use litebox::platform::{CrngProvider, DerivedKeyError, DerivedKeyProvider, KDFParams};
use litebox_common_linux::vmap::{
    PhysPageAddrArray, PhysPageMapPermissions, PhysPointerError, VmapManager,
};

impl<H: Host + CrngProvider> CrngProvider for LinuxKernel<H> {
    fn fill_bytes_crng(&self, buf: &mut [u8]) {
        self.host.fill_bytes_crng(buf);
    }
}
impl<H: Host + DerivedKeyProvider> DerivedKeyProvider for LinuxKernel<H> {
    fn derive_key<E>(
        &self,
        kdf: Option<fn(&[u8], KDFParams) -> Result<(), E>>,
        params: KDFParams,
    ) -> Result<(), DerivedKeyError<E>> {
        self.host.derive_key(kdf, params)
    }
}

// SAFETY: mapping identity, validation and protection semantics are those of
// the host; no access checks are removed and no unsupported request succeeds.
unsafe impl<H: Host + VmapManager<ALIGN>, const ALIGN: usize> VmapManager<ALIGN>
    for LinuxKernel<H>
{
    type MapInfo = H::MapInfo;
    unsafe fn vmap(
        &self,
        pages: &PhysPageAddrArray<ALIGN>,
        perms: PhysPageMapPermissions,
    ) -> Result<Self::MapInfo, PhysPointerError> {
        unsafe { self.host.vmap(pages, perms) }
    }
    unsafe fn vmap_privileged(
        &self,
        pages: &PhysPageAddrArray<ALIGN>,
        perms: PhysPageMapPermissions,
    ) -> Result<Self::MapInfo, PhysPointerError> {
        unsafe { self.host.vmap_privileged(pages, perms) }
    }
    unsafe fn vunmap(
        &self,
        mapping: Self::MapInfo,
    ) -> Result<(), (PhysPointerError, Self::MapInfo)> {
        unsafe { self.host.vunmap(mapping) }
    }
    fn validate_unowned(&self, pages: &PhysPageAddrArray<ALIGN>) -> Result<(), PhysPointerError> {
        self.host.validate_unowned(pages)
    }
    unsafe fn protect(
        &self,
        pages: &PhysPageAddrArray<ALIGN>,
        perms: PhysPageMapPermissions,
    ) -> Result<(), PhysPointerError> {
        unsafe { self.host.protect(pages, perms) }
    }
}
