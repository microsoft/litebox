use litebox::utils::rng::FastRng;
use litebox_common_optee::TeeResult;

pub fn sys_cryp_random_number_generate(buf: &mut [u8]) -> Result<(), TeeResult> {
    // FIXME: before we have secure randomness source (see #41), use a fast and insecure one.
    let mut rng = FastRng::new_from_seed(core::num::NonZeroU64::new(0x4d595df4d0f33173).unwrap());
    if buf.is_empty() {
        return Err(TeeResult::BadParameters);
    }

    let blen8 = buf.len() >> 3;

    for i in 0..blen8 {
        let val = rng.next_u64();
        buf[i * 8..(i + 1) * 8].copy_from_slice(&val.to_be_bytes());
    }

    let remainder = buf.len() % 8;
    if remainder != 0 {
        let val = rng.next_u64();
        buf[blen8 * 8..blen8 * 8 + remainder].copy_from_slice(&val.to_be_bytes()[..remainder]);
    }

    Ok(())
}
