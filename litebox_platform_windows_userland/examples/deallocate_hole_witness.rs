// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#[cfg(windows)]
mod imp {
    use litebox::platform::PageManagementProvider;
    use litebox_platform_windows_userland::WindowsUserland;
    use windows_sys::Win32::System::Memory::{
        MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_NOACCESS, PAGE_READWRITE, VirtualAlloc,
        VirtualFree,
    };

    const GRANULARITY: usize = 0x1_0000;

    fn ensure(condition: bool, error: &'static str) -> Result<(), &'static str> {
        condition.then_some(()).ok_or(error)
    }

    pub fn run() -> Result<(), &'static str> {
        let arena = unsafe {
            VirtualAlloc(
                core::ptr::null_mut(),
                7 * GRANULARITY,
                MEM_RESERVE,
                PAGE_NOACCESS,
            )
        };
        ensure(!arena.is_null(), "initial reserve failed")?;
        ensure(
            unsafe { VirtualFree(arena, 0, MEM_RELEASE) } != 0,
            "initial release failed",
        )?;
        let segment = |index: usize| arena.wrapping_byte_add(index * GRANULARITY);
        for index in [0, 2, 4, 6] {
            ensure(
                unsafe {
                    VirtualAlloc(
                        segment(index),
                        GRANULARITY,
                        MEM_RESERVE | MEM_COMMIT,
                        PAGE_READWRITE,
                    )
                } == segment(index),
                "fixed sentinel or target allocation failed",
            )?;
        }
        unsafe {
            segment(0).cast::<u8>().write_volatile(0x5a);
            segment(6).cast::<u8>().write_volatile(0xa5);
        }
        let platform = WindowsUserland::new();
        let target = segment(1) as usize..segment(6) as usize;
        unsafe {
            <WindowsUserland as PageManagementProvider<4096>>::deallocate_pages(
                platform,
                target.clone(),
            )
            .map_err(|_| "mixed deallocation failed")?;
            <WindowsUserland as PageManagementProvider<4096>>::deallocate_pages(
                platform,
                segment(1) as usize..segment(2) as usize,
            )
            .map_err(|_| "all-free deallocation failed")?;
            <WindowsUserland as PageManagementProvider<4096>>::deallocate_pages(platform, target)
                .map_err(|_| "replayed deallocation failed")?;
        }
        ensure(
            unsafe { segment(0).cast::<u8>().read_volatile() } == 0x5a,
            "leading sentinel changed",
        )?;
        ensure(
            unsafe { segment(6).cast::<u8>().read_volatile() } == 0xa5,
            "trailing sentinel changed",
        )?;
        for index in [1, 3, 5] {
            ensure(
                unsafe {
                    VirtualAlloc(
                        segment(index),
                        GRANULARITY,
                        MEM_RESERVE | MEM_COMMIT,
                        PAGE_READWRITE,
                    )
                } == segment(index),
                "free hole did not remain free",
            )?;
        }
        for index in [2, 4] {
            ensure(
                unsafe { VirtualAlloc(segment(index), GRANULARITY, MEM_COMMIT, PAGE_READWRITE) }
                    == segment(index),
                "committed target did not become decommitted",
            )?;
        }
        for index in 0..7 {
            ensure(
                unsafe { VirtualFree(segment(index), 0, MEM_RELEASE) } != 0,
                "final release failed",
            )?;
        }
        Ok(())
    }
}

fn main() {
    #[cfg(windows)]
    {
        if let Err(error) = imp::run() {
            eprintln!("WINDOWS_DEALLOCATE_HOLE_WITNESS=FAIL error={error}");
            std::process::exit(1);
        }
        println!(
            "WINDOWS_DEALLOCATE_HOLE_WITNESS=PASS cases=leading,interior,trailing,all-free,replay sentinels=preserved"
        );
    }
    #[cfg(not(windows))]
    {
        println!("WINDOWS_DEALLOCATE_HOLE_WITNESS=SKIPPED reason=non-windows-host");
    }
}
