#[cfg(feature = "platform_linux_userland")]
use litebox::platform::ThreadLocalStorageProvider;
use litebox_common_optee::TeeResult;

#[cfg(feature = "platform_linux_userland")]
use litebox::platform::ThreadProvider;

// placeholder
pub fn sys_return(ret: usize) -> ! {
    #[cfg(debug_assertions)]
    litebox::log_println!(
        litebox_platform_multiplex::platform(),
        "sys_return: ret {}",
        ret
    );

    cfg_if::cfg_if! {
        if #[cfg(feature = "platform_linux_userland")] {
            let tid = litebox_platform_multiplex::platform()
                .with_thread_local_storage_mut(|tls| tls.current_task.tid);
            #[allow(clippy::cast_sign_loss)]
            let session_id = tid as u32;
            crate::optee_command_loop_return(session_id);
        } else if #[cfg(feature = "platform_lvbs")] {
            todo!("switch to VTL0");
        } else {
            compile_error!(r##"No platform specified."##);
        }
    }
}

pub fn sys_log(buf: &[u8]) -> Result<(), TeeResult> {
    #[cfg(debug_assertions)]
    litebox::log_println!(
        litebox_platform_multiplex::platform(),
        "sys_log: buf {:#x}",
        buf.as_ptr() as usize
    );
    let msg = core::str::from_utf8(buf).map_err(|_| TeeResult::BadFormat)?;
    litebox::log_println!(litebox_platform_multiplex::platform(), "{}", msg);
    Ok(())
}

// placeholder
pub fn sys_panic(code: usize) -> ! {
    litebox::log_println!(
        litebox_platform_multiplex::platform(),
        "panic with code {}",
        code,
    );

    cfg_if::cfg_if! {
        if #[cfg(feature = "platform_linux_userland")] {
            litebox_platform_multiplex::platform().terminate_thread(i32::try_from(code).unwrap_or(0));
        } else if #[cfg(feature = "platform_lvbs")] {
            todo!("switch to VTL0");
        } else {
            compile_error!(r##"No platform specified."##);
        }
    }
}
