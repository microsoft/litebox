// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use crate::syscalls::pta::PTA_DEFAULT_FLAGS;
use crate::{
    NormalWorldMutPtr, TA_DIGEST_LEN, TaDigest, Task, UserConstPtr, UserMutPtr, syscalls::Cleanup,
};
use alloc::vec::Vec;
use litebox::{
    mm::linux::PAGE_SIZE,
    platform::{CrngProvider, RawConstPointer as _, RawMutPointer as _},
    utils::TruncateExt,
};
use litebox_common_linux::errno::Errno;
use litebox_common_optee::{TaFlags, TeeParamType, TeeResult, TeeUuid, UteeParams};
use num_enum::TryFromPrimitive;
use p384::{
    NonZeroScalar,
    ecdsa::{Signature, SigningKey, signature::Signer},
    elliptic_curve::sec1::ToEncodedPoint,
};
use spin::Once;
use zeroize::Zeroizing;

const IDENTITY_SIGNING_PRIVATE_KEY_LEN: usize = 48;
const IDENTITY_SIGNING_PUBLIC_KEY_LEN: usize = 97;
const KEY_ALGORITHM_MASK: u64 = 0xff00;
const KEY_VARIANT_MASK: u64 = 0xff;
const KEY_ALGORITHM_VALUE_MASK: u64 = KEY_ALGORITHM_MASK | KEY_VARIANT_MASK;
const MAX_KEYGEN_ATTEMPT: usize = 256;
const IDKS_ENDORSEMENT_DATA_MAX_SIZE: usize = 8 * 1024 * 1024;
const IDKS_ENDORSEMENT_MAGIC: &[u8; 4] = b"IDKS";
const IDKS_ENDORSEMENT_VERSION: u32 = 1;
#[cfg(not(feature = "idks-production"))]
const IDKS_DEBUG_FLAG: u8 = 1;
#[cfg(feature = "idks-production")]
const IDKS_DEBUG_FLAG: u8 = 0;
const ISOLATION_SOLUTION: &[u8] = b"LVBS";
pub(crate) const IDKS_ENDORSEMENT_SIGNATURE_LEN: usize = 96;
const IDKS_ENDORSEMENT_METADATA_LEN: usize = IDKS_ENDORSEMENT_MAGIC.len()
    + size_of::<u32>()
    + size_of::<TeeUuid>()
    + size_of::<u32>()
    + TA_DIGEST_LEN
    + size_of::<u8>()
    + ISOLATION_SOLUTION.len();
pub(crate) struct IdksPta;

#[derive(Clone, Copy, TryFromPrimitive)]
#[repr(u32)]
pub(crate) enum IdksCommandId {
    EndorseData = 0,
}

impl IdksPta {
    pub(crate) const FLAGS: TaFlags = PTA_DEFAULT_FLAGS.union(TaFlags::CONCURRENT);
    pub(crate) const UUID: TeeUuid = TeeUuid {
        time_low: 0xfd79_8211,
        time_mid: 0x38a3,
        time_hi_and_version: 0x474a,
        clock_seq_and_node: [0xab, 0x6c, 0x75, 0x61, 0x0d, 0x45, 0x35, 0x93],
    };

    pub(crate) fn open_session(params: &UteeParams) -> Result<u32, TeeResult> {
        crate::syscalls::pta::open_default_pta_session(params)
    }

    pub(crate) fn close_session(_task: &Task, _session_id: u32) {}

    pub(crate) fn invoke_command(
        task: &Task,
        cmd_id: u32,
        params: &mut UteeParams,
    ) -> Result<Cleanup, TeeResult> {
        match IdksCommandId::try_from(cmd_id).map_err(|_| TeeResult::BadParameters)? {
            IdksCommandId::EndorseData => Self::endorse_data(task, params).map(|()| Cleanup::None),
        }
    }

    fn endorse_data(task: &Task, params: &mut UteeParams) -> Result<(), TeeResult> {
        use TeeParamType::{MemrefInput, MemrefOutput, None};

        if !params.has_types([MemrefInput, MemrefOutput, None, None]) {
            return Err(TeeResult::BadParameters);
        }

        let (ta_data_addr, ta_data_size) = params
            .get_values(0)
            .map_err(|_| TeeResult::BadParameters)?
            .ok_or(TeeResult::BadParameters)?;
        let ta_data_size = usize::try_from(ta_data_size).map_err(|_| TeeResult::BadParameters)?;
        if ta_data_size > IDKS_ENDORSEMENT_DATA_MAX_SIZE {
            return Err(TeeResult::BadParameters);
        }
        if ta_data_size > 0 && ta_data_addr == 0 {
            return Err(TeeResult::BadParameters);
        }

        let (endorsement_addr, endorsement_size) = params
            .get_values(1)
            .map_err(|_| TeeResult::BadParameters)?
            .ok_or(TeeResult::BadParameters)?;
        let required_endorsement_size = ta_data_size
            .checked_add(IDKS_ENDORSEMENT_METADATA_LEN)
            .and_then(|size| size.checked_add(IDKS_ENDORSEMENT_SIGNATURE_LEN))
            .ok_or(TeeResult::BadParameters)?;
        let required_endorsement_size_u64 =
            u64::try_from(required_endorsement_size).map_err(|_| TeeResult::BadParameters)?;
        if endorsement_size < required_endorsement_size_u64 {
            params
                .set_values(1, endorsement_addr, required_endorsement_size_u64)
                .map_err(|_| TeeResult::BadParameters)?;
            return Err(TeeResult::ShortBuffer);
        }
        if endorsement_addr == 0 {
            return Err(TeeResult::BadParameters);
        }

        let ta_data = if ta_data_size == 0 {
            Vec::new().into_boxed_slice()
        } else {
            UserConstPtr::<u8>::from_usize(
                usize::try_from(ta_data_addr).map_err(|_| TeeResult::BadParameters)?,
            )
            .to_owned_slice(ta_data_size)
            .ok_or(TeeResult::BadParameters)?
        };
        let mut endorsement =
            build_endorsement_data(&ta_data, &task.ta_app_id, task.ta_svn, &task.ta_digest)
                .ok_or(TeeResult::BadParameters)?;
        let key_pair = get_identity_signing_key_pair().map_err(|_| TeeResult::GenericError)?;
        let signature = endorse_data_with(&endorsement, &key_pair.private_key)
            .map_err(|_| TeeResult::GenericError)?;
        endorsement.extend_from_slice(&signature);
        UserMutPtr::<u8>::from_usize(
            usize::try_from(endorsement_addr).map_err(|_| TeeResult::BadParameters)?,
        )
        .copy_from_slice(0, &endorsement)
        .ok_or(TeeResult::AccessDenied)?;
        params
            .set_values(1, endorsement_addr, required_endorsement_size_u64)
            .map_err(|_| TeeResult::BadParameters)
    }
}

fn build_endorsement_data(
    ta_data: &[u8],
    ta_uuid: &TeeUuid,
    ta_svn: u32,
    ta_digest: &TaDigest,
) -> Option<Vec<u8>> {
    // MAGIC || VERSION || TA_DATA || TA_UUID || TA_SVN || TA_DIGEST || DEBUG || ISOLATION_SOLUTION
    let capacity = ta_data.len().checked_add(IDKS_ENDORSEMENT_METADATA_LEN)?;
    let mut endorsement = Vec::with_capacity(capacity);
    endorsement.extend_from_slice(IDKS_ENDORSEMENT_MAGIC);
    endorsement.extend_from_slice(&IDKS_ENDORSEMENT_VERSION.to_le_bytes());
    endorsement.extend_from_slice(ta_data);
    endorsement.extend_from_slice(&ta_uuid.to_le_bytes());
    endorsement.extend_from_slice(&ta_svn.to_le_bytes());
    endorsement.extend_from_slice(ta_digest);
    endorsement.push(IDKS_DEBUG_FLAG);
    endorsement.extend_from_slice(ISOLATION_SOLUTION);
    Some(endorsement)
}

fn endorse_data_with(
    endorsement_data: &[u8],
    private_key: &[u8; IDENTITY_SIGNING_PRIVATE_KEY_LEN],
) -> Result<[u8; IDKS_ENDORSEMENT_SIGNATURE_LEN], Errno> {
    let signing_key = SigningKey::from_slice(private_key).map_err(|_| Errno::EINVAL)?;
    let signature: Signature = signing_key.sign(endorsement_data);
    let mut signature_bytes = [0u8; IDKS_ENDORSEMENT_SIGNATURE_LEN];
    signature_bytes.copy_from_slice(&signature.to_bytes());
    Ok(signature_bytes)
}

static IDENTITY_SIGNING_KEY_PAIR: Once<IdentitySigningKeyPair> = Once::new();

struct IdentitySigningKeyPair {
    private_key: Zeroizing<[u8; IDENTITY_SIGNING_PRIVATE_KEY_LEN]>,
    public_key: [u8; IDENTITY_SIGNING_PUBLIC_KEY_LEN],
}

#[derive(TryFromPrimitive)]
#[repr(u8)]
enum KeyAlgorithm {
    Rsa = 0x01,
    Ecdsa = 0x02,
    Pqc = 0x04,
}

#[derive(TryFromPrimitive)]
#[repr(u8)]
enum EcdsaCurve {
    P256 = 0x01,
    P384 = 0x02,
    P521 = 0x03,
}

pub fn generate_identity_signing_key(public_key_pa: u64, key_alg: u64) -> i64 {
    match generate_identity_signing_key_inner(public_key_pa, key_alg) {
        Ok(res) => res,
        Err(e) => e.as_neg().into(),
    }
}

/// This function generates an identity signing key pair (IDK_S) and returns the public
/// portion of it.
///
/// - `public_key_pa`: VTL0/Normal-world physical address where an uncompressed SEC1 P-384
///   public key will be written. The corresponding private key is generated by the platform
///   CRNG, retained for the boot cycle, and never leaves VTL1/secure-world.
/// - `key_alg`: Key algorithm namespace and variant. Only ECDSA P-384 is supported.
///
/// We intentially uses the raw format. Any DER/SPKI wrapping or TCG event‑log construction
/// is the VTL0's responsibility, allowing VTL1 ABI to be independent of verifier's format.
///
/// This function assumes that the caller prepares a buffer at the given physical
/// address (in a single or contiguous physical memory page(s)) whose length is equal to
/// or greater than `IDENTITY_SIGNING_PUBLIC_KEY_LEN`.
fn generate_identity_signing_key_inner(public_key_pa: u64, key_alg: u64) -> Result<i64, Errno> {
    validate_key_algorithm(key_alg)?;

    let pubkey_ptr =
        NormalWorldMutPtr::<[u8; IDENTITY_SIGNING_PUBLIC_KEY_LEN], PAGE_SIZE>::with_usize(
            public_key_pa.trunc(),
        )
        .map_err(|_| Errno::EINVAL)?;

    let key_pair = get_identity_signing_key_pair()?;
    pubkey_ptr
        .write_at_offset(0, key_pair.public_key)
        .map_err(|_| Errno::EFAULT)?;
    Ok(0)
}

fn validate_key_algorithm(key_alg: u64) -> Result<(), Errno> {
    if key_alg & !KEY_ALGORITHM_VALUE_MASK != 0 {
        return Err(Errno::EINVAL);
    }

    let algorithm = u8::try_from((key_alg & KEY_ALGORITHM_MASK) >> 8)
        .ok()
        .and_then(|value| KeyAlgorithm::try_from(value).ok())
        .ok_or(Errno::EINVAL)?;
    let variant = u8::try_from(key_alg & KEY_VARIANT_MASK).map_err(|_| Errno::EINVAL)?;
    if variant == 0 {
        return Err(Errno::EINVAL);
    }

    match algorithm {
        KeyAlgorithm::Ecdsa => match EcdsaCurve::try_from(variant).map_err(|_| Errno::EINVAL)? {
            EcdsaCurve::P384 => Ok(()),
            EcdsaCurve::P256 | EcdsaCurve::P521 => Err(Errno::EOPNOTSUPP),
        },
        KeyAlgorithm::Rsa | KeyAlgorithm::Pqc => Err(Errno::EOPNOTSUPP),
    }
}

fn get_identity_signing_key_pair() -> Result<&'static IdentitySigningKeyPair, Errno> {
    IDENTITY_SIGNING_KEY_PAIR.try_call_once(|| {
        let private_key = generate_identity_signing_private_key()?;
        let public_key = identity_signing_public_key_from_private_key(&private_key)?;
        Ok(IdentitySigningKeyPair {
            private_key,
            public_key,
        })
    })
}

fn generate_identity_signing_private_key()
-> Result<Zeroizing<[u8; IDENTITY_SIGNING_PRIVATE_KEY_LEN]>, Errno> {
    let mut private_key_bytes = Zeroizing::new([0u8; IDENTITY_SIGNING_PRIVATE_KEY_LEN]);

    for _ in 0..MAX_KEYGEN_ATTEMPT {
        litebox_platform_multiplex::platform().fill_bytes_crng(&mut *private_key_bytes);
        if is_valid_identity_signing_private_key(&private_key_bytes) {
            return Ok(private_key_bytes);
        }
    }

    Err(Errno::EIO)
}

#[inline]
fn is_valid_identity_signing_private_key(
    private_key: &[u8; IDENTITY_SIGNING_PRIVATE_KEY_LEN],
) -> bool {
    // P-384 private keys must be valid non-zero scalars smaller than the curve order.
    NonZeroScalar::try_from(&private_key[..]).is_ok()
}

fn identity_signing_public_key_from_private_key(
    private_key: &[u8; IDENTITY_SIGNING_PRIVATE_KEY_LEN],
) -> Result<[u8; IDENTITY_SIGNING_PUBLIC_KEY_LEN], Errno> {
    let private_key_scalar =
        Zeroizing::new(NonZeroScalar::try_from(&private_key[..]).map_err(|_| Errno::EINVAL)?);
    let public_key = p384::PublicKey::from_secret_scalar(&private_key_scalar);
    let encoded_point = public_key.to_encoded_point(false);
    let mut public_key_bytes = [0u8; IDENTITY_SIGNING_PUBLIC_KEY_LEN];
    public_key_bytes.copy_from_slice(encoded_point.as_bytes());
    Ok(public_key_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endorsement_signature_covers_plaintext_layout() {
        use p384::ecdsa::{Signature, VerifyingKey, signature::Verifier};

        let mut private_key = [0u8; IDENTITY_SIGNING_PRIVATE_KEY_LEN];
        private_key[IDENTITY_SIGNING_PRIVATE_KEY_LEN - 1] = 1;
        let ta_data = b"TA public key";
        let ta_uuid = TeeUuid {
            time_low: 0x1122_3344,
            time_mid: 0x5566,
            time_hi_and_version: 0x7788,
            clock_seq_and_node: [0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00],
        };

        let ta_svn = 7u32;
        let ta_digest = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff, 0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5, 0x96, 0x87, 0x78, 0x69, 0x5a, 0x4b,
            0x3c, 0x2d, 0x1e, 0x0f,
        ];
        let expected_plaintext =
            build_endorsement_data(ta_data, &ta_uuid, ta_svn, &ta_digest).unwrap();

        let signature = endorse_data_with(&expected_plaintext, &private_key).unwrap();
        let public_key = identity_signing_public_key_from_private_key(&private_key).unwrap();
        let verifying_key = VerifyingKey::from_sec1_bytes(&public_key).unwrap();
        let signature = Signature::from_slice(&signature).unwrap();

        verifying_key
            .verify(&expected_plaintext, &signature)
            .unwrap();
    }
}
