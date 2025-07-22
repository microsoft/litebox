use litebox_common_linux::errno::Errno;

// Use RDRAND instruction for now for testing. We should decide whether we want to use this RNG or Rust one.
// This heavily depends on the source of entropy we have (and whether we can trust it).
pub fn sys_cryp_random_number_generate(buf: &mut [u8]) -> Result<(), Errno> {
    use core::arch::x86_64::_rdrand64_step as rdrand64_step;
    if buf.is_empty() {
        return Err(Errno::EINVAL);
    }

    let blen8 = buf.len() >> 3;

    for i in 0..blen8 {
        let mut val: u64 = 0;
        unsafe {
            rdrand64_step(&mut val);
        }
        let bytes = val.to_be_bytes();
        for j in 0..8 {
            buf[i * 8 + j] = bytes[j];
        }
    }

    if buf.len() % 8 != 0 {
        let mut val: u64 = 0;
        unsafe {
            rdrand64_step(&mut val);
        }
        let bytes = val.to_be_bytes();
        for j in 0..(buf.len() % 8) {
            buf[blen8 * 8 + j] = bytes[j];
        }
    }

    Ok(())
}
