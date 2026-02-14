// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Linux kernel ABI types shared between platform and runner crates.

use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

/// `list_head` from [Linux](https://elixir.bootlin.com/linux/v6.6.85/source/include/linux/types.h#L190)
/// Pointer fields stored as u64 since we don't dereference them.
#[derive(Clone, Copy, Debug, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct ListHead {
    pub next: u64,
    pub prev: u64,
}

#[allow(non_camel_case_types)]
pub type __be32 = u32;

#[repr(u8)]
pub enum PkeyIdType {
    PkeyIdPgp = 0,
    PkeyIdX509 = 1,
    PkeyIdPkcs7 = 2,
}

/// `module_signature` from [Linux](https://elixir.bootlin.com/linux/v6.6.85/source/include/linux/module_signature.h#L33)
#[repr(C)]
#[derive(Debug, Clone, Copy, FromBytes, Immutable, KnownLayout)]
pub struct ModuleSignature {
    pub algo: u8,
    pub hash: u8,
    pub id_type: u8,
    pub signer_len: u8,
    pub key_id_len: u8,
    _pad: [u8; 3],
    sig_len: __be32,
}

impl ModuleSignature {
    pub fn sig_len(&self) -> u32 {
        u32::from_be(self.sig_len)
    }

    /// Currently, Linux kernel only supports PKCS#7 signatures for module signing and thus `id_type` is always `PkeyIdType::PkeyIdPkcs7`.
    /// Other fields except for `sig_len` are set to zero.
    pub fn is_valid(&self) -> bool {
        self.sig_len() > 0
            && self.algo == 0
            && self.hash == 0
            && self.id_type == PkeyIdType::PkeyIdPkcs7 as u8
            && self.signer_len == 0
            && self.key_id_len == 0
    }
}
