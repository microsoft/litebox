use litebox_common_optee::TeeResult;

// placeholder
pub fn sys_return(_ret: usize) -> ! {
    todo!("switch to VTL0");
}

pub fn sys_log(buf: &[u8]) -> Result<(), TeeResult> {
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
    todo!("switch to VTL0");
}
