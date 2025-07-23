use litebox_common_linux::errno::Errno;

// placeholder
pub fn sys_return(_ret_value: usize) -> ! {
    todo!("switch to VTL0");
}

pub fn sys_log(buf: &[u8]) -> Result<usize, Errno> {
    let msg = core::str::from_utf8(buf).map_err(|_| Errno::EINVAL)?;
    litebox::log_println!(litebox_platform_multiplex::platform(), "{}", msg);
    Ok(0)
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
