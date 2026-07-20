// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use crate::NormalWorldMutPtr;
use litebox::{
    mm::linux::PAGE_SIZE,
    platform::{DerivedKeyError, DerivedKeyProvider, KDFParams},
    utils::TruncateExt,
};
use litebox_common_linux::errno::Errno;
use num_enum::TryFromPrimitive;
use p384::{NonZeroScalar, elliptic_curve::sec1::ToEncodedPoint};
use sha2::{Digest, Sha384};
use zeroize::{Zeroize, Zeroizing};

const IDENTITY_SIGNING_KEY_DERIVATION_INFO: &[u8] = b"litebox-lvbs-identity-signing-key-p384-v1";
const IDENTITY_SIGNING_PRIVATE_KEY_LEN: usize = 48;
const IDENTITY_SIGNING_PUBLIC_KEY_LEN: usize = 97;
const KEY_ALGORITHM_MASK: u64 = 0xff00;
const KEY_VARIANT_MASK: u64 = 0xff;
const KEY_ALGORITHM_VALUE_MASK: u64 = KEY_ALGORITHM_MASK | KEY_VARIANT_MASK;

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
///   public key will be written. The corresponding private key is derived from the PRK
///   and never leaves VTL1/secure-world.
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

    let public_key = derive_identity_signing_public_key()?;
    pubkey_ptr
        .write_at_offset(0, public_key)
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

fn derive_identity_signing_public_key() -> Result<[u8; IDENTITY_SIGNING_PUBLIC_KEY_LEN], Errno> {
    let private_key = derive_identity_signing_private_key()?;
    identity_signing_public_key_from_private_key(&private_key)
}

fn derive_identity_signing_private_key()
-> Result<Zeroizing<[u8; IDENTITY_SIGNING_PRIVATE_KEY_LEN]>, Errno> {
    derive_identity_signing_private_key_with(|context, output| {
        litebox_platform_multiplex::platform()
            .derive_key(
                Some(identity_signing_key_kdf),
                KDFParams { context, output },
            )
            .map_err(|err| match err {
                DerivedKeyError::ShimKDFRequired
                | DerivedKeyError::UnsupportedRebootPersistentKey => Errno::EINVAL,
                DerivedKeyError::ShimKDFError(err) => err,
            })
    })
}

fn derive_identity_signing_private_key_with(
    derive_private_key: impl Fn(&[u8], &mut [u8]) -> Result<(), Errno>,
) -> Result<Zeroizing<[u8; IDENTITY_SIGNING_PRIVATE_KEY_LEN]>, Errno> {
    let mut derivation_info = [0u8; IDENTITY_SIGNING_KEY_DERIVATION_INFO.len() + 1];
    derivation_info[..IDENTITY_SIGNING_KEY_DERIVATION_INFO.len()]
        .copy_from_slice(IDENTITY_SIGNING_KEY_DERIVATION_INFO);
    let mut private_key_bytes = Zeroizing::new([0u8; IDENTITY_SIGNING_PRIVATE_KEY_LEN]);

    // HKDF output is uniformly random bytes, but P-384 private keys must be
    // valid non-zero scalars smaller than the curve order. Retry with a new
    // derivation label until the candidate is accepted.
    for counter in u8::MIN..=u8::MAX {
        derivation_info[IDENTITY_SIGNING_KEY_DERIVATION_INFO.len()] = counter;
        private_key_bytes.zeroize();
        derive_private_key(&derivation_info, &mut *private_key_bytes)?;

        if is_valid_identity_signing_private_key(&private_key_bytes) {
            return Ok(private_key_bytes);
        }
    }

    Err(Errno::EINVAL)
}

#[inline]
fn is_valid_identity_signing_private_key(
    private_key: &[u8; IDENTITY_SIGNING_PRIVATE_KEY_LEN],
) -> bool {
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

fn identity_signing_key_kdf(root_key: &[u8], params: KDFParams<'_>) -> Result<(), Errno> {
    let digest = Sha384::new()
        .chain_update(root_key)
        .chain_update(params.context)
        .finalize();
    if params.output.len() != digest.len() {
        return Err(Errno::EINVAL);
    }
    params.output.copy_from_slice(&digest);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    pub const PRK_LEN: usize = 32;

    #[test]
    fn identity_signing_private_key_signs_and_verifies_message() {
        use p384::ecdsa::{
            Signature, SigningKey, VerifyingKey,
            signature::{Signer, Verifier},
        };

        let prk = [0x5a; PRK_LEN];
        let message = b"IDK_S signing test message";

        let private_key = derive_identity_signing_private_key_with(|context, output| {
            identity_signing_key_kdf(&prk, KDFParams { context, output })
        })
        .unwrap();
        let signing_key = SigningKey::from_slice(&private_key[..]).unwrap();
        let public_key = identity_signing_public_key_from_private_key(&private_key).unwrap();
        let verifying_key = VerifyingKey::from_sec1_bytes(&public_key).unwrap();

        let signature: Signature = signing_key.sign(message);

        verifying_key.verify(message, &signature).unwrap();
    }

    #[test]
    fn identity_signing_public_key_derivation_is_deterministic() {
        let prk = [0x5a; PRK_LEN];

        let first_private_key = derive_identity_signing_private_key_with(|context, output| {
            identity_signing_key_kdf(&prk, KDFParams { context, output })
        })
        .unwrap();
        let second_private_key = derive_identity_signing_private_key_with(|context, output| {
            identity_signing_key_kdf(&prk, KDFParams { context, output })
        })
        .unwrap();
        let first = identity_signing_public_key_from_private_key(&first_private_key).unwrap();
        let second = identity_signing_public_key_from_private_key(&second_private_key).unwrap();

        assert_eq!(first, second);
    }
}
