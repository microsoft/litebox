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
use zerocopy::{
    Immutable, IntoBytes,
    byteorder::{LittleEndian, U32},
};
use zeroize::Zeroizing;

const IDENTITY_SIGNING_PRIVATE_KEY_LEN: usize = 48;
const IDENTITY_SIGNING_PUBLIC_KEY_LEN: usize = 97;
const KEY_ALGORITHM_MASK: u64 = 0xff00;
const KEY_VARIANT_MASK: u64 = 0xff;
const KEY_ALGORITHM_VALUE_MASK: u64 = KEY_ALGORITHM_MASK | KEY_VARIANT_MASK;
const MAX_KEYGEN_ATTEMPT: usize = 256;
const IDKS_ENDORSEMENT_DATA_MAX_SIZE: usize = 8 * 1024 * 1024;
const IDKS_NONCE_MAX_SIZE: usize = 64;
const IDKS_ENDORSEMENT_MAGIC: &[u8; 4] = b"IDKS";
const IDKS_ENDORSEMENT_VERSION: u32 = 1;
#[cfg(not(feature = "idks-production"))]
const IDKS_DEBUG_FLAG: u8 = 1;
#[cfg(feature = "idks-production")]
const IDKS_DEBUG_FLAG: u8 = 0;
const ISOLATION_SOLUTION: &[u8] = b"LVBS";
const TRUSTLET_PROPERTY_UUID: &[u8] = b"TRUSTLET_PROPERTY_UUID";
const TRUSTLET_PROPERTY_SVN: &[u8] = b"TRUSTLET_PROPERTY_SVN";
const TRUSTLET_PROPERTY_TA_DIGEST: &[u8] = b"TRUSTLET_PROPERTY_TA_DIGEST";
const TRUSTLET_PROPERTY_DEBUGGED: &[u8] = b"TRUSTLET_PROPERTY_DEBUGGED";
const TRUSTLET_PROPERTY_ISOLATION_SOLUTION: &[u8] = b"TRUSTLET_PROPERTY_ISOLATION_SOLUTION";
const KEYISO_SIGNATURE_ALGORITHM_ID: &[u8] = b"ECDSA_P384";
const KEYISO_SIGNATURE_HASH_ALGORITHM: &[u8] = b"SHA384";
pub(crate) const IDKS_ENDORSEMENT_SIGNATURE_LEN: usize = 96;
const IDKS_ENDORSEMENT_METADATA_LEN: usize = IDKS_ENDORSEMENT_MAGIC.len()
    + size_of::<u32>()
    + size_of::<TeeUuid>()
    + size_of::<u32>()
    + TA_DIGEST_LEN
    + size_of::<u8>()
    + ISOLATION_SOLUTION.len();
pub(crate) struct IdksPta;

type LeU32 = U32<LittleEndian>;

const _: () = assert!(size_of::<TeeUuid>() == 16);

#[derive(Clone, Copy)]
#[repr(u32)]
enum KeyIsoMagic {
    AttestationStatement = 0x4d53_414b,
    KeyAttestationHeader = 0x4841_4b4b,
    TrustletReport = 0x4d52_544b,
    TrustletInformation = 0x4954_414b,
    TrustletProperty = 0x5054_414b,
    SignatureParams = 0x5053_414b,
    EccSignatureParams = 0x5045_414b,
    Signature = 0x5353_414b,
}

#[derive(Clone, Copy)]
#[repr(u32)]
enum KeyIsoVersion {
    V1 = 1,
}

#[derive(Clone, Copy)]
#[repr(u32)]
enum KeyIsoClaimType {
    KeyAttestation = 0x8000_0001,
}

#[derive(Immutable, IntoBytes)]
#[repr(C)]
struct KeyIsoAttestationStatement {
    magic: LeU32,
    version: LeU32,
    claim_type: LeU32,
}

#[derive(Immutable, IntoBytes)]
#[repr(C)]
struct KeyIsoKeyAttestationHeader {
    magic: LeU32,
    version: LeU32,
    cb_ta_data: LeU32,
    cb_nonce: LeU32,
    cb_report: LeU32,
    c_signature_parameters: LeU32,
    c_signatures: LeU32,
}

#[derive(Immutable, IntoBytes)]
#[repr(C)]
struct KeyIsoTrustletReport {
    magic: LeU32,
    report_size: LeU32,
    offset_to_var_data: LeU32,
    version: LeU32,
    cb_trustlet_information: LeU32,
}

#[derive(Immutable, IntoBytes)]
#[repr(C)]
struct KeyIsoAttestationTrustletInformation {
    magic: LeU32,
    version: LeU32,
    c_properties: LeU32,
}

#[derive(Immutable, IntoBytes)]
#[repr(C)]
struct KeyIsoAttestationTrustletProperty {
    magic: LeU32,
    version: LeU32,
    cb_property_name: LeU32,
    cb_property: LeU32,
}

#[derive(Immutable, IntoBytes)]
#[repr(C)]
struct KeyIsoAttestationSignatureParams {
    magic: LeU32,
    version: LeU32,
    cb_alg_id: LeU32,
    cb_alg_params: LeU32,
    cb_hash_alg: LeU32,
}

#[derive(Immutable, IntoBytes)]
#[repr(C)]
struct KeyIsoAttestationEccSignatureParams {
    magic: LeU32,
    version: LeU32,
}

#[derive(Immutable, IntoBytes)]
#[repr(C)]
struct KeyIsoAttestationSignature {
    magic: LeU32,
    version: LeU32,
    cb_signature: LeU32,
}

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

        if !params.has_types([MemrefInput, MemrefInput, MemrefOutput, None]) {
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

        let (nonce_addr, nonce_size) = params
            .get_values(1)
            .map_err(|_| TeeResult::BadParameters)?
            .ok_or(TeeResult::BadParameters)?;
        let nonce_size = usize::try_from(nonce_size).map_err(|_| TeeResult::BadParameters)?;
        if nonce_size > IDKS_NONCE_MAX_SIZE {
            return Err(TeeResult::BadParameters);
        }
        if nonce_size > 0 && nonce_addr == 0 {
            return Err(TeeResult::BadParameters);
        }

        let (endorsement_addr, endorsement_size) = params
            .get_values(2)
            .map_err(|_| TeeResult::BadParameters)?
            .ok_or(TeeResult::BadParameters)?;
        let required_endorsement_size =
            KeyIsoClaimLayout::new(ta_data_size, nonce_size, TA_DIGEST_LEN)
                .map(|layout| layout.claim)
                .and_then(|size| size.checked_add(IDKS_ENDORSEMENT_SIGNATURE_LEN))
                .ok_or(TeeResult::BadParameters)?;
        let required_endorsement_size_u64 =
            u64::try_from(required_endorsement_size).map_err(|_| TeeResult::BadParameters)?;
        if endorsement_size < required_endorsement_size_u64 {
            params
                .set_values(2, endorsement_addr, required_endorsement_size_u64)
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
        let nonce = if nonce_size == 0 {
            Vec::new().into_boxed_slice()
        } else {
            UserConstPtr::<u8>::from_usize(
                usize::try_from(nonce_addr).map_err(|_| TeeResult::BadParameters)?,
            )
            .to_owned_slice(nonce_size)
            .ok_or(TeeResult::BadParameters)?
        };
        let mut endorsement = build_keyiso_claim(
            &ta_data,
            &nonce,
            &task.ta_app_id,
            task.ta_svn,
            Some(&task.ta_digest),
        )
        .ok_or(TeeResult::GenericError)?;
        let key_pair = get_identity_signing_key_pair().map_err(|_| TeeResult::GenericError)?;
        let signature = endorse_data_with(&endorsement, &key_pair.private_key)
            .map_err(|_| TeeResult::GenericError)?;
        endorsement.extend_from_slice(&signature);
        if endorsement.len() != required_endorsement_size {
            return Err(TeeResult::GenericError);
        }
        UserMutPtr::<u8>::from_usize(
            usize::try_from(endorsement_addr).map_err(|_| TeeResult::BadParameters)?,
        )
        .copy_from_slice(0, &endorsement)
        .ok_or(TeeResult::AccessDenied)?;
        params
            .set_values(2, endorsement_addr, required_endorsement_size_u64)
            .map_err(|_| TeeResult::BadParameters)
    }
}

// TODO: drop this if we decide to use the KeyIso claim structure
#[allow(dead_code)]
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

struct KeyIsoClaimLayout {
    trustlet_information: usize,
    report: usize,
    claim: usize,
}

impl KeyIsoClaimLayout {
    fn new(ta_data_len: usize, nonce_len: usize, ta_digest_len: usize) -> Option<Self> {
        let property_names_size = TRUSTLET_PROPERTY_UUID
            .len()
            .checked_add(TRUSTLET_PROPERTY_SVN.len())?
            .checked_add(TRUSTLET_PROPERTY_TA_DIGEST.len())?
            .checked_add(TRUSTLET_PROPERTY_DEBUGGED.len())?
            .checked_add(TRUSTLET_PROPERTY_ISOLATION_SOLUTION.len())?;
        let property_values_size = size_of::<TeeUuid>()
            .checked_add(size_of::<u32>())?
            .checked_add(ta_digest_len)?
            .checked_add(size_of::<u8>())?
            .checked_add(ISOLATION_SOLUTION.len())?;
        let properties_size = 5usize
            .checked_mul(size_of::<KeyIsoAttestationTrustletProperty>())?
            .checked_add(property_names_size)?
            .checked_add(property_values_size)?;
        let trustlet_information_size =
            size_of::<KeyIsoAttestationTrustletInformation>().checked_add(properties_size)?;
        let report_size =
            size_of::<KeyIsoTrustletReport>().checked_add(trustlet_information_size)?;
        let claim_size = size_of::<KeyIsoAttestationStatement>()
            .checked_add(size_of::<KeyIsoKeyAttestationHeader>())?
            .checked_add(ta_data_len)?
            .checked_add(nonce_len)?
            .checked_add(report_size)?
            .checked_add(size_of::<KeyIsoAttestationSignatureParams>())?
            .checked_add(KEYISO_SIGNATURE_ALGORITHM_ID.len())?
            .checked_add(size_of::<KeyIsoAttestationEccSignatureParams>())?
            .checked_add(KEYISO_SIGNATURE_HASH_ALGORITHM.len())?
            .checked_add(size_of::<KeyIsoAttestationSignature>())?;
        Some(Self {
            trustlet_information: trustlet_information_size,
            report: report_size,
            claim: claim_size,
        })
    }
}

/// Serializes the KeyIso claim prefix covered by the identity-key signature.
///
/// Variable data immediately follows its C-compatible zerocopy header. The signature header is
/// included in this returned prefix; only the signature bytes are appended after signing.
fn build_keyiso_claim(
    ta_data: &[u8],
    nonce: &[u8],
    ta_uuid: &TeeUuid,
    ta_svn: u32,
    ta_digest: Option<&TaDigest>,
) -> Option<Vec<u8>> {
    let uuid = ta_uuid.to_le_bytes();
    let svn = ta_svn.to_le_bytes();
    let debugged = [IDKS_DEBUG_FLAG];
    let properties: [(&[u8], &[u8]); 5] = [
        (TRUSTLET_PROPERTY_UUID, &uuid),
        (TRUSTLET_PROPERTY_SVN, &svn),
        (
            TRUSTLET_PROPERTY_TA_DIGEST,
            ta_digest.map_or(&[][..], TaDigest::as_slice),
        ),
        (TRUSTLET_PROPERTY_DEBUGGED, &debugged),
        (TRUSTLET_PROPERTY_ISOLATION_SOLUTION, ISOLATION_SOLUTION),
    ];
    let layout = KeyIsoClaimLayout::new(
        ta_data.len(),
        nonce.len(),
        ta_digest.map_or(0, |_| TA_DIGEST_LEN),
    )?;

    let mut endorsement = Vec::with_capacity(layout.claim);
    endorsement.extend_from_slice(
        KeyIsoAttestationStatement {
            magic: LeU32::new(KeyIsoMagic::AttestationStatement as u32),
            version: LeU32::new(KeyIsoVersion::V1 as u32),
            claim_type: LeU32::new(KeyIsoClaimType::KeyAttestation as u32),
        }
        .as_bytes(),
    );
    endorsement.extend_from_slice(
        KeyIsoKeyAttestationHeader {
            magic: LeU32::new(KeyIsoMagic::KeyAttestationHeader as u32),
            version: LeU32::new(KeyIsoVersion::V1 as u32),
            cb_ta_data: LeU32::new(ta_data.len().try_into().ok()?),
            cb_nonce: LeU32::new(nonce.len().try_into().ok()?),
            cb_report: LeU32::new(layout.report.try_into().ok()?),
            c_signature_parameters: LeU32::new(1),
            c_signatures: LeU32::new(1),
        }
        .as_bytes(),
    );
    endorsement.extend_from_slice(ta_data);
    endorsement.extend_from_slice(nonce);
    endorsement.extend_from_slice(
        KeyIsoTrustletReport {
            magic: LeU32::new(KeyIsoMagic::TrustletReport as u32),
            report_size: LeU32::new(layout.report.try_into().ok()?),
            offset_to_var_data: LeU32::new(size_of::<KeyIsoTrustletReport>().try_into().ok()?),
            version: LeU32::new(KeyIsoVersion::V1 as u32),
            cb_trustlet_information: LeU32::new(layout.trustlet_information.try_into().ok()?),
        }
        .as_bytes(),
    );
    endorsement.extend_from_slice(
        KeyIsoAttestationTrustletInformation {
            magic: LeU32::new(KeyIsoMagic::TrustletInformation as u32),
            version: LeU32::new(KeyIsoVersion::V1 as u32),
            c_properties: LeU32::new(properties.len().try_into().ok()?),
        }
        .as_bytes(),
    );

    for (name, value) in properties {
        endorsement.extend_from_slice(
            KeyIsoAttestationTrustletProperty {
                magic: LeU32::new(KeyIsoMagic::TrustletProperty as u32),
                version: LeU32::new(KeyIsoVersion::V1 as u32),
                cb_property_name: LeU32::new(name.len().try_into().ok()?),
                cb_property: LeU32::new(value.len().try_into().ok()?),
            }
            .as_bytes(),
        );
        endorsement.extend_from_slice(name);
        endorsement.extend_from_slice(value);
    }

    endorsement.extend_from_slice(
        KeyIsoAttestationSignatureParams {
            magic: LeU32::new(KeyIsoMagic::SignatureParams as u32),
            version: LeU32::new(KeyIsoVersion::V1 as u32),
            cb_alg_id: LeU32::new(KEYISO_SIGNATURE_ALGORITHM_ID.len().try_into().ok()?),
            cb_alg_params: LeU32::new(
                size_of::<KeyIsoAttestationEccSignatureParams>()
                    .try_into()
                    .ok()?,
            ),
            cb_hash_alg: LeU32::new(KEYISO_SIGNATURE_HASH_ALGORITHM.len().try_into().ok()?),
        }
        .as_bytes(),
    );
    endorsement.extend_from_slice(KEYISO_SIGNATURE_ALGORITHM_ID);
    endorsement.extend_from_slice(
        KeyIsoAttestationEccSignatureParams {
            magic: LeU32::new(KeyIsoMagic::EccSignatureParams as u32),
            version: LeU32::new(KeyIsoVersion::V1 as u32),
        }
        .as_bytes(),
    );
    endorsement.extend_from_slice(KEYISO_SIGNATURE_HASH_ALGORITHM);
    endorsement.extend_from_slice(
        KeyIsoAttestationSignature {
            magic: LeU32::new(KeyIsoMagic::Signature as u32),
            version: LeU32::new(KeyIsoVersion::V1 as u32),
            cb_signature: LeU32::new(IDKS_ENDORSEMENT_SIGNATURE_LEN.try_into().ok()?),
        }
        .as_bytes(),
    );
    if endorsement.len() != layout.claim {
        return None;
    }
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

    fn read_u32(bytes: &[u8], offset: &mut usize) -> u32 {
        let value = u32::from_le_bytes(bytes[*offset..*offset + 4].try_into().unwrap());
        *offset += 4;
        value
    }

    fn assert_property(bytes: &[u8], offset: &mut usize, name: &[u8], value: &[u8]) {
        assert_eq!(read_u32(bytes, offset), 0x5054_414b);
        assert_eq!(read_u32(bytes, offset), 1);
        assert_eq!(read_u32(bytes, offset), u32::try_from(name.len()).unwrap());
        assert_eq!(read_u32(bytes, offset), u32::try_from(value.len()).unwrap());
        assert_eq!(&bytes[*offset..*offset + name.len()], name);
        *offset += name.len();
        assert_eq!(&bytes[*offset..*offset + value.len()], value);
        *offset += value.len();
    }

    #[test]
    fn keyiso_claim_has_expected_layout() {
        let ta_data = b"TA data";
        let nonce = [0x5a; 32];
        let ta_uuid = TeeUuid {
            time_low: 0x1122_3344,
            time_mid: 0x5566,
            time_hi_and_version: 0x7788,
            clock_seq_and_node: [0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00],
        };
        let ta_svn = 7u32;
        let ta_digest = [0xa5; TA_DIGEST_LEN];

        let endorsement =
            build_keyiso_claim(ta_data, &nonce, &ta_uuid, ta_svn, Some(&ta_digest)).unwrap();
        let mut offset = 0;

        assert_eq!(read_u32(&endorsement, &mut offset), 0x4d53_414b);
        assert_eq!(read_u32(&endorsement, &mut offset), 1);
        assert_eq!(read_u32(&endorsement, &mut offset), 0x8000_0001);

        assert_eq!(read_u32(&endorsement, &mut offset), 0x4841_4b4b);
        assert_eq!(read_u32(&endorsement, &mut offset), 1);
        assert_eq!(
            read_u32(&endorsement, &mut offset),
            u32::try_from(ta_data.len()).unwrap()
        );
        assert_eq!(
            read_u32(&endorsement, &mut offset),
            u32::try_from(nonce.len()).unwrap()
        );
        let report_size = read_u32(&endorsement, &mut offset) as usize;
        assert_eq!(read_u32(&endorsement, &mut offset), 1);
        assert_eq!(read_u32(&endorsement, &mut offset), 1);
        assert_eq!(&endorsement[offset..offset + ta_data.len()], ta_data);
        offset += ta_data.len();
        assert_eq!(&endorsement[offset..offset + nonce.len()], nonce);
        offset += nonce.len();

        let report_start = offset;
        assert_eq!(read_u32(&endorsement, &mut offset), 0x4d52_544b);
        assert_eq!(read_u32(&endorsement, &mut offset) as usize, report_size);
        assert_eq!(read_u32(&endorsement, &mut offset), 20);
        assert_eq!(read_u32(&endorsement, &mut offset), 1);
        let trustlet_information_size = read_u32(&endorsement, &mut offset) as usize;

        let trustlet_information_start = offset;
        assert_eq!(read_u32(&endorsement, &mut offset), 0x4954_414b);
        assert_eq!(read_u32(&endorsement, &mut offset), 1);
        assert_eq!(read_u32(&endorsement, &mut offset), 5);
        assert_property(
            &endorsement,
            &mut offset,
            b"TRUSTLET_PROPERTY_UUID",
            &ta_uuid.to_le_bytes(),
        );
        assert_property(
            &endorsement,
            &mut offset,
            b"TRUSTLET_PROPERTY_SVN",
            &ta_svn.to_le_bytes(),
        );
        assert_property(
            &endorsement,
            &mut offset,
            b"TRUSTLET_PROPERTY_TA_DIGEST",
            &ta_digest,
        );
        assert_property(
            &endorsement,
            &mut offset,
            b"TRUSTLET_PROPERTY_DEBUGGED",
            &[IDKS_DEBUG_FLAG],
        );
        assert_property(
            &endorsement,
            &mut offset,
            b"TRUSTLET_PROPERTY_ISOLATION_SOLUTION",
            b"LVBS",
        );
        assert_eq!(
            offset - trustlet_information_start,
            trustlet_information_size
        );
        assert_eq!(offset - report_start, report_size);

        assert_eq!(read_u32(&endorsement, &mut offset), 0x5053_414b);
        assert_eq!(read_u32(&endorsement, &mut offset), 1);
        assert_eq!(read_u32(&endorsement, &mut offset), 10);
        assert_eq!(read_u32(&endorsement, &mut offset), 8);
        assert_eq!(read_u32(&endorsement, &mut offset), 6);
        assert_eq!(&endorsement[offset..offset + 10], b"ECDSA_P384");
        offset += 10;
        assert_eq!(read_u32(&endorsement, &mut offset), 0x5045_414b);
        assert_eq!(read_u32(&endorsement, &mut offset), 1);
        assert_eq!(&endorsement[offset..offset + 6], b"SHA384");
        offset += 6;

        assert_eq!(read_u32(&endorsement, &mut offset), 0x5353_414b);
        assert_eq!(read_u32(&endorsement, &mut offset), 1);
        assert_eq!(read_u32(&endorsement, &mut offset), 96);

        assert_eq!(offset, endorsement.len());
    }

    #[test]
    fn keyiso_signature_covers_entire_claim_prefix() {
        use p384::ecdsa::{Signature, VerifyingKey, signature::Verifier};

        let mut private_key = [0u8; IDENTITY_SIGNING_PRIVATE_KEY_LEN];
        private_key[IDENTITY_SIGNING_PRIVATE_KEY_LEN - 1] = 1;
        let nonce = [0x5a; 32];
        let ta_uuid = TeeUuid::NIL;
        let ta_digest = [0xa5; TA_DIGEST_LEN];
        let mut endorsement =
            build_keyiso_claim(b"TA data", &nonce, &ta_uuid, 7, Some(&ta_digest)).unwrap();
        let signed_len = endorsement.len();
        let signature = endorse_data_with(&endorsement, &private_key).unwrap();

        endorsement.extend_from_slice(&signature);

        let public_key = identity_signing_public_key_from_private_key(&private_key).unwrap();
        let verifying_key = VerifyingKey::from_sec1_bytes(&public_key).unwrap();
        let parsed_signature = Signature::from_slice(&endorsement[signed_len..]).unwrap();
        verifying_key
            .verify(&endorsement[..signed_len], &parsed_signature)
            .unwrap();
    }

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
