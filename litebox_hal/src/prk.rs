// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Platform root key (PRK) sources.

/// SHA-256 of "litebox-vm development platform root key v1 -- NOT A SECRET".
const DEVELOPMENT: [u8; 32] = [
    0xb3, 0x09, 0x9d, 0xf9, 0x38, 0x4f, 0xc7, 0x67, 0xb7, 0x38, 0x1c, 0x49, 0xc1, 0x67, 0x13, 0x82,
    0xeb, 0x25, 0x85, 0xaf, 0x85, 0xf0, 0x39, 0xc9, 0xe8, 0x30, 0x4e, 0x4e, 0x04, 0xe1, 0xc8, 0x11,
];

/// No confidentiality: this key is public and identical on every boot.
/// TODO: a TPM-backed source.
#[must_use]
pub fn development() -> [u8; 32] {
    litebox_util_log::warn!(
        "using a DEVELOPMENT platform root key with NO SECURITY VALUE; \
         anything sealed with keys derived from it is sealed against nobody"
    );
    DEVELOPMENT
}
