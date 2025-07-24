use litebox_common_optee::TeeResult;

// Use RDRAND instruction for now for testing. We should decide whether we want to use this RNG or Rust one.
// This heavily depends on the source of entropy we have (and whether we can trust it).
#[cfg(target_arch = "x86_64")]
pub fn sys_cryp_random_number_generate(buf: &mut [u8]) -> Result<(), TeeResult> {
    use core::arch::x86_64::_rdrand64_step as rdrand64_step;
    if buf.is_empty() {
        return Err(TeeResult::BadParameters);
    }

    let blen8 = buf.len() >> 3;

    for i in 0..blen8 {
        let mut val: u64 = 0;
        unsafe {
            rdrand64_step(&mut val);
        }
        buf[i * 8..(i + 1) * 8].copy_from_slice(&val.to_be_bytes());
    }

    let remainder = buf.len() % 8;
    if remainder != 0 {
        let mut val: u64 = 0;
        unsafe {
            rdrand64_step(&mut val);
        }
        buf[blen8 * 8..blen8 * 8 + remainder].copy_from_slice(&val.to_be_bytes()[..remainder]);
    }

    Ok(())
}

#[cfg(target_arch = "x86")]
pub fn sys_cryp_random_number_generate(_buf: &mut [u8]) -> Result<(), TeeResult> {
    todo!("we don't support 32-bit mode syscalls for now");
}
