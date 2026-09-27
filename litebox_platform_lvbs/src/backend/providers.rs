// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Optional backend capabilities exposed through the shared kernel. These do not
//! grant VTL authority: the LVBS Vmap implementation remains gate-aware and
//! concrete. A backend can implement VmapManager directly for other memory models,
//! including explicit rejection by a plain-VM test backend.

use super::KernelBackend;
use crate::LinuxKernel;
use litebox::platform::{CrngProvider, DerivedKeyError, DerivedKeyProvider, KDFParams};
use litebox_common_linux::vmap::{
    PhysPageAddrArray, PhysPageMapPermissions, PhysPointerError, VmapManager,
};

impl<B: KernelBackend + CrngProvider> CrngProvider for LinuxKernel<B> {
    fn fill_bytes_crng(&self, buf: &mut [u8]) {
        self.backend.fill_bytes_crng(buf);
    }
}
impl<B: KernelBackend + DerivedKeyProvider> DerivedKeyProvider for LinuxKernel<B> {
    fn derive_key<E>(
        &self,
        kdf: Option<fn(&[u8], KDFParams) -> Result<(), E>>,
        params: KDFParams,
    ) -> Result<(), DerivedKeyError<E>> {
        self.backend.derive_key(kdf, params)
    }
}

// SAFETY: mapping identity, validation and protection semantics are those of
// the backend; no access checks are removed and no unsupported request succeeds.
unsafe impl<B: KernelBackend + VmapManager<ALIGN>, const ALIGN: usize> VmapManager<ALIGN>
    for LinuxKernel<B>
{
    type MapInfo = B::MapInfo;
    unsafe fn vmap(
        &self,
        pages: &PhysPageAddrArray<ALIGN>,
        perms: PhysPageMapPermissions,
    ) -> Result<Self::MapInfo, PhysPointerError> {
        unsafe { self.backend.vmap(pages, perms) }
    }
    unsafe fn vmap_privileged(
        &self,
        pages: &PhysPageAddrArray<ALIGN>,
        perms: PhysPageMapPermissions,
    ) -> Result<Self::MapInfo, PhysPointerError> {
        unsafe { self.backend.vmap_privileged(pages, perms) }
    }
    unsafe fn vunmap(
        &self,
        mapping: Self::MapInfo,
    ) -> Result<(), (PhysPointerError, Self::MapInfo)> {
        unsafe { self.backend.vunmap(mapping) }
    }
    fn validate_unowned(&self, pages: &PhysPageAddrArray<ALIGN>) -> Result<(), PhysPointerError> {
        self.backend.validate_unowned(pages)
    }
    unsafe fn protect(
        &self,
        pages: &PhysPageAddrArray<ALIGN>,
        perms: PhysPageMapPermissions,
    ) -> Result<(), PhysPointerError> {
        unsafe { self.backend.protect(pages, perms) }
    }
}
