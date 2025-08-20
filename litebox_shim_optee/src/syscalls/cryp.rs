use aes::{
    Aes128, Aes192, Aes256,
    cipher::{NewCipher, StreamCipher, generic_array::GenericArray},
};
use ctr::Ctr128BE;
use litebox::{platform::RawMutPointer, utils::rng::FastRng};
use litebox_common_optee::{
    TeeAlgorithm, TeeAlgorithmClass, TeeCrypStateHandle, TeeObjHandle, TeeObjectInfo,
    TeeObjectType, TeeOperationMode, TeeResult, UteeAttribute,
};

use crate::{Cipher, MutPtr, TeeCrypState, TeeObj, tee_cryp_state_map, tee_obj_map};

pub(crate) fn sys_cryp_state_alloc(
    algo: TeeAlgorithm,
    mode: TeeOperationMode,
    key1: TeeObjHandle,
    key2: TeeObjHandle,
    state: MutPtr<TeeCrypStateHandle>,
) -> Result<(), TeeResult> {
    if key1 != TeeObjHandle::NULL {
        if !tee_obj_map().exists(key1) {
            return Err(TeeResult::BadState);
        }
        if tee_obj_map().is_busy(key1) {
            return Err(TeeResult::BadParameters);
        }
        // TODO: validate key type
    }
    if key2 != TeeObjHandle::NULL {
        if !tee_obj_map().exists(key2) {
            return Err(TeeResult::BadState);
        }
        if tee_obj_map().is_busy(key2) {
            return Err(TeeResult::BadParameters);
        }
        // TODO: validate key type
    }

    // TODO: validate whether the number of keys is valid

    let cryp_state = TeeCrypState::new(
        algo,
        mode,
        if key1 == TeeObjHandle::NULL {
            None
        } else {
            Some(key1)
        },
        if key2 == TeeObjHandle::NULL {
            None
        } else {
            Some(key2)
        },
    );

    let handle = tee_cryp_state_map().allocate(&cryp_state);
    unsafe {
        state
            .write_at_offset(0, handle)
            .ok_or(TeeResult::BadParameters)?;
    }

    if key1 != TeeObjHandle::NULL {
        tee_obj_map().set_busy(key1, true);
    }
    if key2 != TeeObjHandle::NULL {
        tee_obj_map().set_busy(key2, true);
    }
    Ok(())
}

#[allow(clippy::unnecessary_wraps)]
pub(crate) fn sys_cryp_state_free(state: TeeCrypStateHandle) -> Result<(), TeeResult> {
    if let Some(cryp_state) = tee_cryp_state_map().get_copy(state) {
        if let Some(handle) = cryp_state.get_object_handle(true) {
            tee_obj_map().remove(handle);
        }
        if let Some(handle) = cryp_state.get_object_handle(false) {
            tee_obj_map().remove(handle);
        }
        tee_cryp_state_map().remove(state);
    }

    // this function returns `void`
    Ok(())
}

fn create_cipher(algo: TeeAlgorithm, key: &[u8], iv: &[u8]) -> Option<Cipher> {
    match algo {
        TeeAlgorithm::AesCtr => match key.len() {
            16 => Some(Cipher::Aes128Ctr(Ctr128BE::<Aes128>::new(
                GenericArray::from_slice(key),
                GenericArray::from_slice(iv),
            ))),
            24 => Some(Cipher::Aes192Ctr(Ctr128BE::<Aes192>::new(
                GenericArray::from_slice(key),
                GenericArray::from_slice(iv),
            ))),
            32 => Some(Cipher::Aes256Ctr(Ctr128BE::<Aes256>::new(
                GenericArray::from_slice(key),
                GenericArray::from_slice(iv),
            ))),
            _ => None,
        },
        _ => None,
    }
}

pub(crate) fn sys_cipher_init(state: TeeCrypStateHandle, iv: &[u8]) -> Result<(), TeeResult> {
    if let Some(cryp_state) = tee_cryp_state_map().get_copy(state)
        && let Some(handle) = cryp_state.get_object_handle(true)
        && tee_obj_map().exists(handle)
    {
        if cryp_state.algorithm_class() != TeeAlgorithmClass::Cipher {
            return Err(TeeResult::BadState);
        }

        let tee_obj = tee_obj_map()
            .get_copy(handle)
            .ok_or(TeeResult::BadParameters)?;
        let Some(key) = tee_obj.get_key() else {
            return Err(TeeResult::BadParameters);
        };

        if let Some(handle) = cryp_state.get_object_handle(false)
            && tee_obj_map().exists(handle)
        {
            todo!("support two-key algorithms");
        }

        let Some(cipher) = create_cipher(cryp_state.algorithm(), key, iv) else {
            todo!("implement algorithm {}", cryp_state.algorithm() as u32);
        };
        tee_cryp_state_map().set_cipher(state, &cipher)?;
        Ok(())
    } else {
        Err(TeeResult::BadParameters)
    }
}

pub(crate) fn sys_cipher_update(
    state: TeeCrypStateHandle,
    src_slice: &[u8],
    dst_slice: &mut [u8],
    dst_len: &mut usize,
) -> Result<(), TeeResult> {
    do_cipher_update(state, src_slice, dst_slice, dst_len, false)
}

pub(crate) fn sys_cipher_final(
    state: TeeCrypStateHandle,
    src_slice: &[u8],
    dst_slice: &mut [u8],
    dst_len: &mut usize,
) -> Result<(), TeeResult> {
    do_cipher_update(state, src_slice, dst_slice, dst_len, true)
}

fn do_cipher_update(
    state: TeeCrypStateHandle,
    src_slice: &[u8],
    dst_slice: &mut [u8],
    dst_len: &mut usize,
    last_block: bool,
) -> Result<(), TeeResult> {
    if dst_slice.len() < src_slice.len() {
        return Err(TeeResult::ShortBuffer);
    }
    if let Some(mut map) = tee_cryp_state_map().get_mut(state) {
        if let &mut Some(ref mut cipher) = &mut map.get_mut(&state).unwrap().get_mut_cipher() {
            dst_slice.copy_from_slice(src_slice);
            match cipher {
                Cipher::Aes128Ctr(aes128ctr) => {
                    aes128ctr.apply_keystream(&mut dst_slice[..src_slice.len()]);
                }
                Cipher::Aes192Ctr(aes192ctr) => {
                    aes192ctr.apply_keystream(&mut dst_slice[..src_slice.len()]);
                }
                Cipher::Aes256Ctr(aes256ctr) => {
                    aes256ctr.apply_keystream(&mut dst_slice[..src_slice.len()]);
                }
            }
            *dst_len = src_slice.len();
        }
        if last_block {
            todo!("support algorithms which have a certain finalization logic");
        }
        Ok(())
    } else {
        Err(TeeResult::BadParameters)
    }
}

pub(crate) fn sys_cryp_obj_get_info(
    obj: TeeObjHandle,
    info: MutPtr<TeeObjectInfo>,
) -> Result<(), TeeResult> {
    if tee_obj_map().exists(obj) {
        let tee_obj = tee_obj_map().get_copy(obj).ok_or(TeeResult::ItemNotFound)?;
        unsafe {
            info.write_at_offset(0, tee_obj.info)
                .ok_or(TeeResult::AccessDenied)
        }
    } else {
        Err(TeeResult::BadState)
    }
}

pub(crate) fn sys_cryp_obj_alloc(
    typ: TeeObjectType,
    max_size: u32,
    obj: crate::MutPtr<TeeObjHandle>,
) -> Result<(), TeeResult> {
    let tee_obj = TeeObj::new(typ, max_size);
    let handle = tee_obj_map().allocate(&tee_obj);
    if let Some(()) = unsafe { obj.write_at_offset(0, handle) } {
        Ok(())
    } else {
        tee_obj_map().remove(handle);
        Err(TeeResult::AccessDenied)
    }
}

pub(crate) fn sys_cryp_obj_close(obj: TeeObjHandle) -> Result<(), TeeResult> {
    if tee_obj_map().exists(obj) {
        tee_obj_map().remove(obj);
        Ok(())
    } else {
        Err(TeeResult::BadState)
    }
}

pub(crate) fn sys_cryp_obj_reset(obj: TeeObjHandle) -> Result<(), TeeResult> {
    if tee_obj_map().exists(obj) {
        tee_obj_map().reset(obj)
    } else {
        Err(TeeResult::BadState)
    }
}

pub(crate) fn sys_cryp_obj_populate(
    obj: TeeObjHandle,
    attrs: &[UteeAttribute],
) -> Result<(), TeeResult> {
    if attrs.len() > 1 {
        todo!("handle multiple attributes");
    }
    if !tee_obj_map().exists(obj) {
        return Err(TeeResult::BadState);
    }
    tee_obj_map()
        .populate(obj, attrs)
        .map_err(|_| TeeResult::BadParameters)
}

pub(crate) fn sys_cryp_obj_copy(dst: TeeObjHandle, src: TeeObjHandle) -> Result<(), TeeResult> {
    let src_obj = tee_obj_map().get_copy(src).ok_or(TeeResult::BadState)?;
    if !src_obj
        .info
        .handle_flags
        .contains(litebox_common_optee::TeeHandleFlag::TEE_HANDLE_FLAG_INITIALIZED)
    {
        return Err(TeeResult::BadParameters);
    }

    let dst_obj = tee_obj_map().get_copy(dst).ok_or(TeeResult::BadState)?;
    if dst_obj
        .info
        .handle_flags
        .contains(litebox_common_optee::TeeHandleFlag::TEE_HANDLE_FLAG_INITIALIZED)
    {
        return Err(TeeResult::BadParameters);
    }

    tee_obj_map().replace(dst, &src_obj);
    Ok(())
}

pub(crate) fn sys_cryp_random_number_generate(buf: &mut [u8]) -> Result<(), TeeResult> {
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
