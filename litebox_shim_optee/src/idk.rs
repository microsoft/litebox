// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use crate::syscalls::pta::PTA_DEFAULT_FLAGS;
use crate::{
    NormalWorldMutPtr, TA_DIGEST_LEN, TaDigest, Task, UserConstPtr, UserMutPtr, syscalls::Cleanup,
};
use alloc::vec::Vec;
use litebox::{
    mm::linux::PAGE_SIZE,
    platform::{RawConstPointer as _, RawMutPointer as _},
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
    + ISOLATION_SOLUTION.len()
    + size_of::<u32>(); // DER leaf certificate length
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

    pub(crate) fn close_session<Platform: crate::OpteeShimPlatform>(
        _task: &Task<Platform>,
        _session_id: u32,
    ) {
    }

    pub(crate) fn invoke_command<Platform: crate::OpteeShimPlatform>(
        task: &Task<Platform>,
        cmd_id: u32,
        params: &mut UteeParams,
    ) -> Result<Cleanup, TeeResult> {
        match IdksCommandId::try_from(cmd_id).map_err(|_| TeeResult::BadParameters)? {
            IdksCommandId::EndorseData => Self::endorse_data(task, params).map(|()| Cleanup::None),
        }
    }

    /// Parameter 0 is the TA data; parameter 1 receives the signed endorsement.
    fn endorse_data<Platform: crate::OpteeShimPlatform>(
        task: &Task<Platform>,
        params: &mut UteeParams,
    ) -> Result<(), TeeResult> {
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
        let ta_signing_cert = task.global.ta_signing_cert;
        let required_endorsement_size = endorsement_data_len(ta_data_size, ta_signing_cert.len())
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
            UserConstPtr::<Platform, u8>::from_usize(
                usize::try_from(ta_data_addr).map_err(|_| TeeResult::BadParameters)?,
            )
            .to_owned_slice(ta_data_size)
            .ok_or(TeeResult::BadParameters)?
        };
        let mut endorsement = build_endorsement_data(
            &ta_data,
            &task.ta_app_id,
            task.ta_svn,
            &task.ta_digest,
            ta_signing_cert,
        )
        .ok_or(TeeResult::BadParameters)?;
        let key_pair = get_identity_signing_key_pair(task.global.platform)
            .map_err(|_| TeeResult::GenericError)?;
        let signature = endorse_data_with(&endorsement, &key_pair.private_key)
            .map_err(|_| TeeResult::GenericError)?;
        endorsement.extend_from_slice(&signature);
        UserMutPtr::<Platform, u8>::from_usize(
            usize::try_from(endorsement_addr).map_err(|_| TeeResult::BadParameters)?,
        )
        .copy_from_slice(0, &endorsement)
        .ok_or(TeeResult::AccessDenied)?;
        params
            .set_values(1, endorsement_addr, required_endorsement_size_u64)
            .map_err(|_| TeeResult::BadParameters)
    }
}

fn endorsement_data_len(ta_data_len: usize, ta_signing_cert_len: usize) -> Option<usize> {
    u32::try_from(ta_signing_cert_len).ok()?;
    ta_data_len
        .checked_add(IDKS_ENDORSEMENT_METADATA_LEN)?
        .checked_add(ta_signing_cert_len)
}

/// Serializes the flat prefix covered by the IDK_S signature:
/// MAGIC || VERSION || TA_DATA || TA_UUID || TA_SVN || TA_DIGEST || DEBUG ||
/// ISOLATION_SOLUTION || TA_SIGNING_CERT_LEN || TA_SIGNING_CERT_DER.
///
/// Integers (including the u32 certificate length) and the UUID use little endian.
/// TA_DATA retains its caller-known length. The certificate is the embedded TA
/// signing leaf certificate, not the IDK_S certificate; its bytes are copied
/// verbatim for the verifier to use when verifying the TA signature. An empty
/// certificate placeholder is encoded with length zero.
fn build_endorsement_data(
    ta_data: &[u8],
    ta_uuid: &TeeUuid,
    ta_svn: u32,
    ta_digest: &TaDigest,
    ta_signing_cert: &[u8],
) -> Option<Vec<u8>> {
    let capacity = endorsement_data_len(ta_data.len(), ta_signing_cert.len())?;
    let cert_len = u32::try_from(ta_signing_cert.len()).ok()?;
    let mut endorsement = Vec::with_capacity(capacity);
    endorsement.extend_from_slice(IDKS_ENDORSEMENT_MAGIC);
    endorsement.extend_from_slice(&IDKS_ENDORSEMENT_VERSION.to_le_bytes());
    endorsement.extend_from_slice(ta_data);
    endorsement.extend_from_slice(&ta_uuid.to_le_bytes());
    endorsement.extend_from_slice(&ta_svn.to_le_bytes());
    endorsement.extend_from_slice(ta_digest);
    endorsement.push(IDKS_DEBUG_FLAG);
    endorsement.extend_from_slice(ISOLATION_SOLUTION);
    endorsement.extend_from_slice(&cert_len.to_le_bytes());
    endorsement.extend_from_slice(ta_signing_cert);
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

pub fn generate_identity_signing_key<Platform: crate::OpteeShimPlatform>(
    platform: &Platform,
    public_key_pa: u64,
    key_alg: u64,
) -> i64 {
    match generate_identity_signing_key_inner(platform, public_key_pa, key_alg) {
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
fn generate_identity_signing_key_inner<Platform: crate::OpteeShimPlatform>(
    platform: &Platform,
    public_key_pa: u64,
    key_alg: u64,
) -> Result<i64, Errno> {
    validate_key_algorithm(key_alg)?;

    let pubkey_ptr =
        NormalWorldMutPtr::<Platform, [u8; IDENTITY_SIGNING_PUBLIC_KEY_LEN], PAGE_SIZE>::with_usize(
            platform,
            public_key_pa.trunc(),
        )
        .map_err(|_| Errno::EINVAL)?;

    let key_pair = get_identity_signing_key_pair(platform)?;
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

fn get_identity_signing_key_pair<Platform: crate::OpteeShimPlatform>(
    platform: &Platform,
) -> Result<&'static IdentitySigningKeyPair, Errno> {
    IDENTITY_SIGNING_KEY_PAIR.try_call_once(|| {
        let private_key = generate_identity_signing_private_key(platform)?;
        let public_key = identity_signing_public_key_from_private_key(&private_key)?;
        Ok(IdentitySigningKeyPair {
            private_key,
            public_key,
        })
    })
}

fn generate_identity_signing_private_key<Platform: crate::OpteeShimPlatform>(
    platform: &Platform,
) -> Result<Zeroizing<[u8; IDENTITY_SIGNING_PRIVATE_KEY_LEN]>, Errno> {
    let mut private_key_bytes = Zeroizing::new([0u8; IDENTITY_SIGNING_PRIVATE_KEY_LEN]);

    for _ in 0..MAX_KEYGEN_ATTEMPT {
        platform.fill_bytes_crng(&mut *private_key_bytes);
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

    // Opaque test bytes: the shim transports the certificate without parsing it.
    const TEST_CERT: &[u8] = &[0x30, 0x03, 0x02, 0x01, 0x01];

    #[test]
    fn endorsement_has_expected_flat_layout() {
        let uuid = TeeUuid {
            time_low: 0x1122_3344,
            time_mid: 0x5566,
            time_hi_and_version: 0x7788,
            clock_seq_and_node: [0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00],
        };
        let digest = [0xa5; TA_DIGEST_LEN];
        for cert in [TEST_CERT, &[]] {
            for data in [b"TA data".as_slice(), &[]] {
                let endorsement = build_endorsement_data(data, &uuid, 7, &digest, cert).unwrap();
                let mut expected = Vec::from(b"IDKS\x01\x00\x00\x00".as_slice());
                expected.extend_from_slice(data);
                expected.extend_from_slice(&[
                    0x44, 0x33, 0x22, 0x11, 0x66, 0x55, 0x88, 0x77, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
                    0xee, 0xff, 0x00,
                ]);
                expected.extend_from_slice(&[7, 0, 0, 0]);
                expected.extend_from_slice(&digest);
                expected.push(IDKS_DEBUG_FLAG);
                expected.extend_from_slice(b"LVBS");
                expected.extend_from_slice(&u32::try_from(cert.len()).unwrap().to_le_bytes());
                expected.extend_from_slice(cert);
                assert_eq!(endorsement, expected);
                assert_eq!(
                    endorsement.len(),
                    endorsement_data_len(data.len(), cert.len()).unwrap()
                );
            }
        }
    }

    #[test]
    fn pta_endorsement_uses_global_certificate_and_reports_output_size() {
        use p384::ecdsa::{Signature, VerifyingKey, signature::Verifier};

        for cert in [TEST_CERT, &[]] {
            let shim = crate::syscalls::tests::shim_builder()
                .with_ta_signing_cert(cert)
                .build();
            let task = shim.0.new_test_task();
            assert!(core::ptr::eq(task.global.ta_signing_cert, cert));

            for data in [b"TA data".as_slice(), &[]] {
                let mut params = UteeParams::new();
                params.set_type(0, TeeParamType::MemrefInput).unwrap();
                params.set_type(1, TeeParamType::MemrefOutput).unwrap();
                let data_addr = if data.is_empty() {
                    0
                } else {
                    data.as_ptr() as u64
                };
                params.set_values(0, data_addr, data.len() as u64).unwrap();
                let expected = build_endorsement_data(
                    data,
                    &task.ta_app_id,
                    task.ta_svn,
                    &task.ta_digest,
                    cert,
                )
                .unwrap();
                let required_size = expected.len() + IDKS_ENDORSEMENT_SIGNATURE_LEN;

                assert_eq!(
                    IdksPta::endorse_data(&task, &mut params),
                    Err(TeeResult::ShortBuffer)
                );
                assert_eq!(
                    params.get_values(1).unwrap(),
                    Some((0, required_size as u64))
                );

                let mut output = alloc::vec![0xcc; required_size + 1];
                let output_addr = output.as_mut_ptr() as u64;
                params
                    .set_values(1, output_addr, (required_size - 1) as u64)
                    .unwrap();
                assert_eq!(
                    IdksPta::endorse_data(&task, &mut params),
                    Err(TeeResult::ShortBuffer)
                );
                assert!(output.iter().all(|byte| *byte == 0xcc));
                assert_eq!(
                    params.get_values(1).unwrap(),
                    Some((output_addr, required_size as u64))
                );

                IdksPta::endorse_data(&task, &mut params).unwrap();
                assert_eq!(&output[..expected.len()], expected);
                assert_eq!(output[required_size], 0xcc);
                let key_pair = get_identity_signing_key_pair(task.global.platform).unwrap();
                let verifying_key = VerifyingKey::from_sec1_bytes(&key_pair.public_key).unwrap();
                let signature =
                    Signature::from_slice(&output[expected.len()..required_size]).unwrap();
                verifying_key.verify(&expected, &signature).unwrap();
            }
        }
    }

    #[test]
    fn pta_rejects_keyiso_parameters_and_invalid_buffers() {
        let task = crate::syscalls::tests::init_platform();
        let mut params = UteeParams::new();
        params.set_type(0, TeeParamType::MemrefInput).unwrap();
        params.set_type(1, TeeParamType::MemrefInput).unwrap();
        params.set_type(2, TeeParamType::MemrefOutput).unwrap();
        assert_eq!(
            IdksPta::endorse_data(&task, &mut params),
            Err(TeeResult::BadParameters)
        );

        params.set_type(1, TeeParamType::MemrefOutput).unwrap();
        params.set_type(2, TeeParamType::None).unwrap();
        params.set_values(0, 0, 1).unwrap();
        assert_eq!(
            IdksPta::endorse_data(&task, &mut params),
            Err(TeeResult::BadParameters)
        );
        params
            .set_values(0, 1, (IDKS_ENDORSEMENT_DATA_MAX_SIZE + 1) as u64)
            .unwrap();
        assert_eq!(
            IdksPta::endorse_data(&task, &mut params),
            Err(TeeResult::BadParameters)
        );
        params.set_values(0, 0, 0).unwrap();
        params.set_values(1, 0, u64::MAX).unwrap();
        assert_eq!(
            IdksPta::endorse_data(&task, &mut params),
            Err(TeeResult::BadParameters)
        );
    }

    #[test]
    fn endorsement_length_rejects_overflow() {
        assert!(endorsement_data_len(usize::MAX, 0).is_none());
        assert!(endorsement_data_len(0, usize::MAX).is_none());
        assert!(endorsement_data_len(0, u32::MAX as usize + 1).is_none());
    }

    #[test]
    fn endorsement_signature_covers_plaintext_and_certificate() {
        use p384::ecdsa::{Signature, VerifyingKey, signature::Verifier};

        let mut private_key = [0u8; IDENTITY_SIGNING_PRIVATE_KEY_LEN];
        private_key[IDENTITY_SIGNING_PRIVATE_KEY_LEN - 1] = 1;
        let mut endorsement = build_endorsement_data(
            b"TA data",
            &TeeUuid::NIL,
            7,
            &[0xa5; TA_DIGEST_LEN],
            TEST_CERT,
        )
        .unwrap();
        let signature = endorse_data_with(&endorsement, &private_key).unwrap();
        let public_key = identity_signing_public_key_from_private_key(&private_key).unwrap();
        let verifying_key = VerifyingKey::from_sec1_bytes(&public_key).unwrap();
        let signature = Signature::from_slice(&signature).unwrap();
        verifying_key.verify(&endorsement, &signature).unwrap();

        // Tamper with the TA data, digest, certificate length, and certificate bytes.
        let cert_start = endorsement.len() - TEST_CERT.len();
        for offset in [8, 8 + b"TA data".len() + 16 + 4, cert_start - 4, cert_start] {
            endorsement[offset] ^= 1;
            assert!(verifying_key.verify(&endorsement, &signature).is_err());
            endorsement[offset] ^= 1;
        }
    }
}
