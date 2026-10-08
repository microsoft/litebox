// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! An implementation of [`HostInterface`] for LVBS

use crate::{
    Errno, HostInterface, arch::ioport::serial_print_string,
    host::per_cpu_variables::with_per_cpu_variables,
};
use zeroize::Zeroizing;

pub type LvbsLinuxKernel = crate::LinuxKernel<HostLvbsInterface>;

#[cfg(not(test))]
mod alloc {
    use crate::HostInterface;

    const HEAP_ORDER: usize = 25;

    #[global_allocator]
    static LVBS_ALLOCATOR: litebox::mm::allocator::SafeZoneAllocator<
        'static,
        HEAP_ORDER,
        super::LvbsLinuxKernel,
    > = litebox::mm::allocator::SafeZoneAllocator::new();

    impl litebox::mm::allocator::MemoryProvider for super::LvbsLinuxKernel {
        fn alloc(layout: &core::alloc::Layout) -> Option<(usize, usize)> {
            super::HostLvbsInterface::alloc(layout)
        }

        unsafe fn free(addr: usize) {
            unsafe { super::HostLvbsInterface::free(addr) }
        }
    }

    impl crate::mm::MemoryProvider for super::LvbsLinuxKernel {
        const GVA_OFFSET: x86_64::VirtAddr = x86_64::VirtAddr::new(crate::GVA_OFFSET);
        const PRIVATE_PTE_MASK: u64 = 0;

        fn mem_allocate_pages(order: u32) -> Option<*mut u8> {
            LVBS_ALLOCATOR.allocate_pages(order)
        }

        unsafe fn mem_free_pages(ptr: *mut u8, order: u32) {
            unsafe {
                LVBS_ALLOCATOR.free_pages(ptr, order);
            }
        }

        unsafe fn mem_fill_pages(start: usize, size: usize) {
            unsafe { LVBS_ALLOCATOR.fill_pages(start, size) };
        }
    }
}

#[cfg(test)]
impl crate::mm::MemoryProvider for LvbsLinuxKernel {
    const GVA_OFFSET: x86_64::VirtAddr = x86_64::VirtAddr::new(crate::GVA_OFFSET);
    const PRIVATE_PTE_MASK: u64 = 0;

    fn mem_allocate_pages(_order: u32) -> Option<*mut u8> {
        unimplemented!("not used in tests")
    }

    unsafe fn mem_free_pages(_ptr: *mut u8, _order: u32) {
        unimplemented!("not used in tests")
    }

    unsafe fn mem_fill_pages(_start: usize, _size: usize) {
        unimplemented!("not used in tests")
    }
}

unsafe impl litebox::platform::ThreadLocalStorageProvider for LvbsLinuxKernel {
    fn get_thread_local_storage() -> *mut () {
        let tls = with_per_cpu_variables(|pcv| pcv.tls.get());
        tls.as_mut_ptr::<()>()
    }

    unsafe fn replace_thread_local_storage(value: *mut ()) -> *mut () {
        with_per_cpu_variables(|pcv| {
            let old = pcv.tls.get();
            pcv.tls.set(x86_64::VirtAddr::new(value as u64));
            old.as_u64() as *mut ()
        })
    }
}

// The PRK lives only in `crate::vault`. Never expose a raw PRK getter; use
// `DerivedKeyProvider`.

impl litebox::platform::DerivedKeyProvider for LvbsLinuxKernel {
    fn derive_key<E>(
        &self,
        kdf: Option<fn(&[u8], litebox::platform::KDFParams) -> Result<(), E>>,
        params: litebox::platform::KDFParams,
    ) -> Result<(), litebox::platform::DerivedKeyError<E>> {
        use litebox::platform::{DerivedKeyError, KDFParams};

        struct Ctx<'a, E> {
            kdf: fn(&[u8], KDFParams) -> Result<(), E>,
            params: Option<KDFParams<'a>>,
            result: Option<Result<(), E>>,
        }

        if !crate::vault::is_installed() {
            return Err(DerivedKeyError::UnsupportedRebootPersistentKey);
        }
        let Some(kdf) = kdf else {
            return Err(DerivedKeyError::ShimKDFRequired);
        };

        // Bounce buffers the vault cannot reach through kernel heap memory.
        let KDFParams { context, output } = params;
        let context_copy;
        let context = if crate::vault::is_accessible(context) {
            context
        } else {
            context_copy = Zeroizing::new(context.to_vec());
            context_copy.as_slice()
        };
        let mut output_copy = (!crate::vault::is_accessible(output))
            .then(|| Zeroizing::new(::alloc::vec![0u8; output.len()]));

        let mut ctx = Ctx {
            kdf,
            params: Some(KDFParams {
                context,
                output: match output_copy.as_mut() {
                    Some(copy) => copy.as_mut_slice(),
                    None => &mut *output,
                },
            }),
            result: None,
        };
        crate::vault::with_prk(&mut ctx, |prk, ctx| {
            if let Some(params) = ctx.params.take() {
                // Safety: this callback runs inside the serialized vault window.
                ctx.result = Some(unsafe { crate::vault::invoke_kdf(ctx.kdf, prk, params) });
            }
        })
        .map_err(|_| DerivedKeyError::UnsupportedRebootPersistentKey)?;
        ctx.result.expect("vault did not run the KDF")?;
        if let Some(copy) = &output_copy {
            output.copy_from_slice(copy);
        }
        Ok(())
    }
}

pub struct HostLvbsInterface;

impl HostLvbsInterface {}

impl HostInterface for HostLvbsInterface {
    fn log(msg: &str) {
        serial_print_string(msg);
    }

    fn alloc(_layout: &core::alloc::Layout) -> Option<(usize, usize)> {
        // Called on OOM. Must not panic so that fallible callers see the failure.
        None
    }

    unsafe fn free(_addr: usize) {
        unimplemented!()
    }

    fn exit() -> ! {
        unimplemented!()
    }

    fn terminate(_reason_set: u64, _reason_code: u64) -> ! {
        unimplemented!()
    }

    fn wake_many(_mutex: &core::sync::atomic::AtomicU32, _n: usize) -> Result<usize, Errno> {
        unimplemented!()
    }

    fn block_or_maybe_timeout(
        _mutex: &core::sync::atomic::AtomicU32,
        _val: u32,
        _timeout: Option<core::time::Duration>,
    ) -> Result<(), Errno> {
        unimplemented!()
    }

    fn switch(_result: u64) -> ! {
        unimplemented!()
    }
}
