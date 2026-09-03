// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use core::mem::{offset_of, size_of};

use litebox::mm::linux::{CreatePagesFlags, MappingError, NonZeroPageSize};
use litebox::platform::{RawConstPointer as _, RawMutPointer as _};
use litebox_common_windows::loader::PAGE_SIZE;
use rangemap::RangeMap;

use crate::nt_types::ProcessEnvironmentBlock;
use crate::syscalls::mm::{MemoryType, PageProtection};
use crate::{MutPtr, ShimPlatform, Task, WindowsVirtualAllocation};

const GDI_SHARED_TABLE_SIZE: usize = 0x182000;
const GDI_STOCK_OBJECT_TABLE_OFFSET: usize = 0x1800b0;
const DC_BRUSH_STOCK_OBJECT_ID: usize = 18;
const DC_PEN_STOCK_OBJECT_ID: usize = 19;
const GDI_STOCK_OBJECT_SENTINEL: u64 = 1;

#[derive(Clone, Copy)]
pub(crate) struct GdiProcessState {
    shared_table: usize,
    cookie: usize,
}

impl<Platform: ShimPlatform> Task<Platform> {
    pub(crate) fn sys_nt_gdi_init2(&self) -> usize {
        let mut state = self.process.gdi_state.lock();
        if let Some(state) = *state {
            return self.publish_gdi_state(state);
        }

        let mut cookie_bytes = [0_u8; size_of::<usize>()];
        if self.global.litebox.fill_random(&mut cookie_bytes).is_err() {
            return 0;
        }
        let cookie = usize::from_ne_bytes(cookie_bytes).max(1);

        let Some(length) = NonZeroPageSize::<PAGE_SIZE>::new(GDI_SHARED_TABLE_SIZE) else {
            return 0;
        };
        // SAFETY: no fixed address is requested, so the page manager selects an unused guest
        // range. The callback initializes only offsets within the newly allocated mapping.
        let mapping = unsafe {
            self.global.page_manager.create_writable_pages(
                None,
                length,
                CreatePagesFlags::empty(),
                initialize_gdi_shared_table::<Platform>,
            )
        };
        let Ok(mapping) = mapping else {
            return 0;
        };
        let shared_table = mapping.as_usize();
        let mut pages = RangeMap::new();
        pages.insert(
            shared_table..shared_table + GDI_SHARED_TABLE_SIZE,
            PageProtection::PAGE_READWRITE,
        );
        self.process.virtual_allocations.write().insert(
            shared_table,
            WindowsVirtualAllocation {
                base: shared_table,
                size: GDI_SHARED_TABLE_SIZE,
                allocation_protect: PageProtection::PAGE_READWRITE,
                type_: MemoryType::MEM_MAPPED,
                pages,
            },
        );

        let new_state = GdiProcessState {
            shared_table,
            cookie,
        };
        if self.publish_gdi_state(new_state) == 0 {
            self.process
                .virtual_allocations
                .write()
                .remove(&shared_table);
            // SAFETY: the mapping was just created and was not published to the process state.
            let _ = unsafe {
                self.global.page_manager.remove_pages(
                    MutPtr::<Platform, u8>::from_usize(shared_table),
                    GDI_SHARED_TABLE_SIZE,
                )
            };
            return 0;
        }
        *state = Some(new_state);
        cookie
    }

    fn publish_gdi_state(&self, state: GdiProcessState) -> usize {
        let offset = offset_of!(ProcessEnvironmentBlock, gdi_shared_handle_table);
        if crate::write_field_at_offset::<Platform, usize>(
            self.process.peb_address,
            offset,
            state.shared_table,
        )
        .is_none()
        {
            return 0;
        }
        state.cookie
    }
}

fn initialize_gdi_shared_table<Platform: ShimPlatform>(
    mapping: MutPtr<Platform, u8>,
) -> Result<usize, MappingError> {
    let base = mapping.as_usize();
    // GdiDllInitialize requires non-null DC_BRUSH and DC_PEN stock objects even for console-only
    // processes. These are compatibility sentinels, not usable GDI handles.
    for stock_object_id in [DC_BRUSH_STOCK_OBJECT_ID, DC_PEN_STOCK_OBJECT_ID] {
        let address = base + GDI_STOCK_OBJECT_TABLE_OFFSET + stock_object_id * size_of::<u64>();
        MutPtr::<Platform, u64>::from_usize(address)
            .write_at_offset(0, GDI_STOCK_OBJECT_SENTINEL)
            .ok_or(MappingError::OutOfMemory)?;
    }
    Ok(0)
}

#[cfg(test)]
mod tests {
    use alloc::sync::Arc;

    use zerocopy::FromZeros as _;

    use super::*;
    use crate::tests::{run_with_test_platform_pointers, test_task, test_task_with_random_broker};

    fn set_test_peb(
        task: &mut Task<crate::tests::TestPlatform>,
        peb: &mut ProcessEnvironmentBlock,
    ) {
        Arc::get_mut(&mut task.process)
            .expect("test task has a unique process")
            .peb_address = core::ptr::from_mut(peb) as usize;
    }

    #[test]
    fn gdi_initialization_requires_broker_randomness() {
        run_with_test_platform_pointers(|| {
            let mut peb = ProcessEnvironmentBlock::new_zeroed();
            let mut task = test_task();
            set_test_peb(&mut task, &mut peb);

            assert_eq!(task.sys_nt_gdi_init2(), 0);
            assert_eq!(peb.gdi_shared_handle_table, 0);
            assert!(task.process.gdi_state.lock().is_none());
        });
    }

    #[test]
    fn gdi_initialization_uses_broker_randomness() {
        run_with_test_platform_pointers(|| {
            let mut peb = ProcessEnvironmentBlock::new_zeroed();
            let mut task = test_task_with_random_broker();
            set_test_peb(&mut task, &mut peb);

            let cookie = task.sys_nt_gdi_init2();
            assert_ne!(cookie, 0);
            assert_ne!(peb.gdi_shared_handle_table, 0);
            assert_eq!(task.sys_nt_gdi_init2(), cookie);
        });
    }
}
