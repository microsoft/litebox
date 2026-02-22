// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! OP-TEE Signed Header (SHDR) types, parsing, and signature verification.
//!
//! Based on `optee_os/core/include/signed_hdr.h` at commit 33919ffbd54a7cea68cba484b442f39017cd864c.
//!
//! Binary layout for a signed Bootstrap TA:
//! ```text
//! +-------------------+  offset 0
//! | shdr (20 bytes)   |  magic, img_type, img_size, algo, hash_size, sig_size
//! +-------------------+  offset 20
//! | hash[hash_size]   |  SHA-256 digest (32 bytes)
//! +-------------------+  offset 20 + hash_size
//! | sig[sig_size]     |  RSA signature (e.g. 256 bytes for RSA-2048)
//! +-------------------+  offset 20 + hash_size + sig_size
//! | uuid (16 bytes)   |  TA UUID in RFC 4122 big-endian format
//! +-------------------+  offset 20 + hash_size + sig_size + 16
//! | ta_version (4 B)  |  TA version number (little-endian u32)
//! +-------------------+  offset 20 + hash_size + sig_size + 20
//! | img[img_size]     |  Raw ELF image
//! +-------------------+
//! ```
//!
//! The hash covers: `shdr` (20 bytes) + `uuid` (16 bytes) + `ta_version` (4 bytes LE) + `img` (raw ELF).

use alloc::boxed::Box;
use core::mem::size_of;

use litebox_common_optee::TeeUuid;
use rsa::RsaPublicKey;
use rsa::signature::hazmat::PrehashVerifier;
use sha2::{Digest, Sha256};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// SHDR magic number: "OPTE" in ASCII, but stored as `0x4f545348` ("OTSH" little-endian).
const SHDR_MAGIC: u32 = 0x4f54_5348;

/// Size of the base SHDR structure in bytes.
const SHDR_SIZE: usize = 20;

/// Size of the bootstrap TA sub-header (UUID + ta_version).
const SHDR_BOOTSTRAP_TA_SIZE: usize = size_of::<TeeUuid>() + size_of::<u32>();

/// Image type: Bootstrap TA
///
/// Note: OP-TEE also supports "Encrypted TA" and "Subkey" image types, but
/// we only support signed TAs (bootstrap) for now.
const SHDR_BOOTSTRAP_TA: u32 = 1;

/// Algorithm: `TEE_ALG_RSASSA_PKCS1_V1_5_SHA256`
const SHDR_ALGO_RSASSA_PKCS1_V1_5_SHA256: u32 = 0x7000_4830;
/// Algorithm: `TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA256`
const SHDR_ALGO_RSASSA_PKCS1_PSS_MGF1_SHA256: u32 = 0x7041_4930;

/// Parsed SHDR base header.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct Shdr {
    pub magic: u32,
    pub img_type: u32,
    pub img_size: u32,
    pub algo: u32,
    pub hash_size: u16,
    pub sig_size: u16,
}

/// Parsed bootstrap TA sub-header.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct ShdrBootstrapTa {
    pub uuid: TeeUuid,
    pub ta_version: u32,
}

/// Result of parsing a signed TA binary.
#[derive(Debug)]
pub struct ParsedSignedTa<'a> {
    /// The base SHDR header.
    pub shdr: Shdr,
    /// The bootstrap TA sub-header (UUID and version).
    pub bootstrap: ShdrBootstrapTa,
    /// The SHA-256 hash from the signed header.
    pub hash: &'a [u8],
    /// The RSA signature from the signed header.
    pub signature: &'a [u8],
    /// The raw ELF image bytes (after stripping the signed header).
    pub image: &'a [u8],
}

/// Errors that can occur when parsing or verifying a signed TA header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShdrError {
    /// Binary is too short to contain the SHDR structure.
    TooShort,
    /// Magic number doesn't match `SHDR_MAGIC`.
    BadMagic,
    /// Unsupported image type (only `SHDR_BOOTSTRAP_TA` is supported).
    UnsupportedImageType,
    /// Unsupported algorithm (only PKCS1v1.5-SHA256 and PSS-SHA256 are supported).
    UnsupportedAlgorithm,
    /// Hash size is not 32 (SHA-256).
    InvalidHashSize,
    /// Binary size is inconsistent with the header fields.
    InconsistentSize,
    /// UUID in the signed header doesn't match the expected UUID.
    UuidMismatch,
    /// Computed hash doesn't match the hash in the signed header.
    HashMismatch,
    /// RSA signature verification failed.
    SignatureVerificationFailed,
}

/// Check whether a given binary blob appears to be a signed TA by
/// looking for the SHDR magic number at the start.
pub fn is_signed_ta(data: &[u8]) -> bool {
    if data.len() < 4 {
        return false;
    }
    let magic = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    magic == SHDR_MAGIC
}

/// Parse a signed TA binary, extracting the header, hash, signature, and raw ELF image.
///
/// This function validates the header structure and consistency but does NOT verify
/// the cryptographic signature. Signature verification must be done separately.
pub fn parse_signed_ta(data: &[u8]) -> Result<ParsedSignedTa<'_>, ShdrError> {
    if data.len() < SHDR_SIZE {
        return Err(ShdrError::TooShort);
    }

    // Parse base SHDR (all fields are little-endian)
    let shdr = Shdr {
        magic: u32::from_le_bytes([data[0], data[1], data[2], data[3]]),
        img_type: u32::from_le_bytes([data[4], data[5], data[6], data[7]]),
        img_size: u32::from_le_bytes([data[8], data[9], data[10], data[11]]),
        algo: u32::from_le_bytes([data[12], data[13], data[14], data[15]]),
        hash_size: u16::from_le_bytes([data[16], data[17]]),
        sig_size: u16::from_le_bytes([data[18], data[19]]),
    };

    if shdr.magic != SHDR_MAGIC {
        return Err(ShdrError::BadMagic);
    }

    if shdr.img_type != SHDR_BOOTSTRAP_TA {
        return Err(ShdrError::UnsupportedImageType);
    }

    if shdr.algo != SHDR_ALGO_RSASSA_PKCS1_V1_5_SHA256
        && shdr.algo != SHDR_ALGO_RSASSA_PKCS1_PSS_MGF1_SHA256
    {
        return Err(ShdrError::UnsupportedAlgorithm);
    }

    if shdr.hash_size != 32 {
        return Err(ShdrError::InvalidHashSize);
    }

    let hash_size = shdr.hash_size as usize;
    let sig_size = shdr.sig_size as usize;
    let img_size = shdr.img_size as usize;

    let total_header_size = SHDR_SIZE
        .checked_add(hash_size)
        .and_then(|s| s.checked_add(sig_size))
        .and_then(|s| s.checked_add(SHDR_BOOTSTRAP_TA_SIZE))
        .ok_or(ShdrError::InconsistentSize)?;

    let total_size = total_header_size
        .checked_add(img_size)
        .ok_or(ShdrError::InconsistentSize)?;

    if data.len() < total_size {
        return Err(ShdrError::InconsistentSize);
    }

    // Extract hash and signature
    let hash_offset = SHDR_SIZE;
    let sig_offset = hash_offset + hash_size;
    let bootstrap_offset = sig_offset + sig_size;
    let img_offset = bootstrap_offset + SHDR_BOOTSTRAP_TA_SIZE;

    let hash = &data[hash_offset..sig_offset];
    let signature = &data[sig_offset..bootstrap_offset];

    // Parse bootstrap TA sub-header: uuid (16 bytes) + ta_version (4 bytes LE)
    let bootstrap_data = &data[bootstrap_offset..img_offset];
    let uuid_bytes: [u8; 16] = bootstrap_data[..16]
        .try_into()
        .map_err(|_| ShdrError::InconsistentSize)?;
    let uuid = TeeUuid::from_bytes(uuid_bytes);
    let ta_version = u32::from_le_bytes(
        bootstrap_data[16..20]
            .try_into()
            .map_err(|_| ShdrError::InconsistentSize)?,
    );

    let bootstrap = ShdrBootstrapTa { uuid, ta_version };

    let image = &data[img_offset..img_offset + img_size];

    Ok(ParsedSignedTa {
        shdr,
        bootstrap,
        hash,
        signature,
        image,
    })
}

/// Result of successfully processing a signed TA binary.
pub(crate) struct VerifiedTa {
    /// The raw ELF image bytes (owned, stripped of SHDR).
    pub binary: Box<[u8]>,
    /// The TA UUID from the signed header.
    pub uuid: TeeUuid,
    /// The TA version from the signed header.
    pub ta_version: u32,
}

/// Compute the SHA-256 digest that the SHDR signature covers.
///
/// The hash covers: `shdr` (20 bytes) + `uuid` (16 bytes) + `ta_version` (4 bytes LE) + `image`.
fn compute_shdr_digest(raw_data: &[u8], parsed: &ParsedSignedTa<'_>) -> [u8; 32] {
    let hash_size = parsed.shdr.hash_size as usize;
    let sig_size = parsed.shdr.sig_size as usize;
    let bootstrap_offset = SHDR_SIZE + hash_size + sig_size;

    let shdr_bytes = &raw_data[..SHDR_SIZE];
    let bootstrap_bytes = &raw_data[bootstrap_offset..bootstrap_offset + SHDR_BOOTSTRAP_TA_SIZE];

    let mut hasher = Sha256::new();
    hasher.update(shdr_bytes);
    hasher.update(bootstrap_bytes);
    hasher.update(parsed.image);
    let result = hasher.finalize();
    let mut digest = [0u8; 32];
    digest.copy_from_slice(&result);
    digest
}

/// Verify the RSA signature of a parsed signed TA.
///
/// Supports both PKCS#1 v1.5 and PSS (MGF1-SHA256) signature schemes.
/// Uses prehash verification since we already have the computed SHA-256 digest.
fn verify_signature(
    parsed: &ParsedSignedTa<'_>,
    digest: &[u8; 32],
    public_key: &RsaPublicKey,
) -> Result<(), ShdrError> {
    match parsed.shdr.algo {
        SHDR_ALGO_RSASSA_PKCS1_V1_5_SHA256 => {
            let verifying_key = rsa::pkcs1v15::VerifyingKey::<Sha256>::new(public_key.clone());
            let signature = rsa::pkcs1v15::Signature::try_from(parsed.signature)
                .map_err(|_| ShdrError::SignatureVerificationFailed)?;
            verifying_key
                .verify_prehash(digest, &signature)
                .map_err(|_| ShdrError::SignatureVerificationFailed)
        }
        SHDR_ALGO_RSASSA_PKCS1_PSS_MGF1_SHA256 => {
            let verifying_key = rsa::pss::VerifyingKey::<Sha256>::new(public_key.clone());
            let signature = rsa::pss::Signature::try_from(parsed.signature)
                .map_err(|_| ShdrError::SignatureVerificationFailed)?;
            verifying_key
                .verify_prehash(digest, &signature)
                .map_err(|_| ShdrError::SignatureVerificationFailed)
        }
        _ => Err(ShdrError::UnsupportedAlgorithm),
    }
}

/// Verify a signed TA binary and extract its contents.
///
/// Always verifies the SHA-256 hash. When `verification_keys` is empty, signature verification
/// is skipped (useful when no verification keys have been provisioned yet). Otherwise each key
/// is tried in order and verification succeeds if any key validates the signature.
///
/// Returns a `VerifiedTa` containing the stripped ELF binary, UUID, and version.
pub(crate) fn verify_signed_ta(
    data: &[u8],
    verification_keys: &[RsaPublicKey],
) -> Result<VerifiedTa, ShdrError> {
    let parsed = parse_signed_ta(data)?;

    let computed_digest = compute_shdr_digest(data, &parsed);

    if computed_digest != parsed.hash {
        return Err(ShdrError::HashMismatch);
    }

    if !verification_keys.is_empty() {
        let verified = verification_keys
            .iter()
            .any(|key| verify_signature(&parsed, &computed_digest, key).is_ok());
        if !verified {
            return Err(ShdrError::SignatureVerificationFailed);
        }
    }

    Ok(VerifiedTa {
        binary: parsed.image.into(),
        uuid: parsed.bootstrap.uuid,
        ta_version: parsed.bootstrap.ta_version,
    })
}
