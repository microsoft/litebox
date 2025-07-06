//! Functions for checking the memory integrity of VTL0 kernel image and modules

#[cfg(debug_assertions)]
use alloc::vec::Vec;

use crate::{
    debug_serial_println, host::linux::ModuleSignature, mshv::vsm::ModuleMemory, serial_println,
};
use alloc::vec;
use cms::{content_info::ContentInfo, signed_data::SignedData};
use const_oid::db::rfc5912::{ID_SHA_256, ID_SHA_512, RSA_ENCRYPTION};
use elf::{
    ElfBytes,
    abi::{
        R_X86_64_32, R_X86_64_32S, R_X86_64_64, R_X86_64_PC32, R_X86_64_PLT32, SHF_ALLOC, SHT_RELA,
    },
    endian::AnyEndian,
    parse::ParsingTable,
    section::SectionHeader,
    string_table::StringTable,
    symbol::Symbol,
};
use rangemap::set::RangeSet;
use rsa::{RsaPublicKey, pkcs1::DecodeRsaPublicKey, pkcs1v15::Signature, signature::Verifier};
use sha2::{Sha256, Sha512};
use x509_cert::{
    Certificate,
    der::{Decode, Encode, oid::ObjectIdentifier},
};

/// This function validates the memory content of a loaded kernel module against the original ELF file.
/// In particular, it checks whether the non-relocatable/patchable bytes of certain sections
/// (e.g., `.text`, `.init.text`) of the module are tampered with.
///
/// The goal of this function is to restrict certain capabilities of a compromised VTL0 kernel module loader.
/// Note that this is mainly for defense-in-depth. Even without this code and data tampering, the compromised
/// module loader could still leverage other attack mechanisms like return-oriented programming (ROP).
/// In the future, we can add more checks to harden the validation.
pub fn validate_kernel_module_against_elf(
    module_memory: &ModuleMemory,
    original_elf_data: &[u8],
) -> Result<bool, KernelElfError> {
    let mut result = true;

    let elf = ElfBytes::<AnyEndian>::minimal_parse(original_elf_data)
        .map_err(|_| KernelElfError::ElfParseFailed)?;
    let Ok((Some(shdrs), Some(shdr_strtab))) = elf.section_headers_with_strtab() else {
        return Err(KernelElfError::ElfParseFailed);
    };
    let Ok(Some((symtab, sym_strtab))) = elf.symbol_table() else {
        return Err(KernelElfError::ElfParseFailed);
    };

    for target_section_name in sections_to_validate() {
        // section loaded in memory (with VTL0's relocations and patches applied)
        let section_memory_container = module_memory
            .find_section_by_name(target_section_name)
            .expect("Section not found in module memory");
        if section_memory_container.is_empty() {
            continue;
        }

        let Some(target_shdr) = shdrs.iter().find(|s| {
            s.sh_flags & u64::from(SHF_ALLOC) != 0
                && s.sh_size > 0
                && usize::try_from(s.sh_name).is_ok()
                && shdr_strtab
                    .get(usize::try_from(s.sh_name).unwrap())
                    .is_ok_and(|n| n == target_section_name)
        }) else {
            return Err(KernelElfError::SectionNotFound);
        };

        let elf_params = ElfParams {
            elf: &elf,
            shdrs: &shdrs,
            shdr_strtab: &shdr_strtab,
            symtab: &symtab,
            sym_strtab: &sym_strtab,
        };

        // load original ELF section (no relocation and patch applied)
        let start =
            usize::try_from(target_shdr.sh_offset).map_err(|_| KernelElfError::ElfParseFailed)?;
        let end = start
            .checked_add(
                usize::try_from(target_shdr.sh_size).map_err(|_| KernelElfError::ElfParseFailed)?,
            )
            .ok_or(KernelElfError::ElfParseFailed)?;
        let mut section_from_elf = vec![0u8; end - start];
        section_from_elf.copy_from_slice(&original_elf_data[start..end]);

        let mut reloc_ranges = RangeSet::<usize>::new();
        identify_direct_relocations(
            elf_params,
            target_section_name,
            &section_from_elf,
            &mut reloc_ranges,
        )?;
        identify_indirect_relocations(
            elf_params,
            target_section_name,
            &section_from_elf,
            &mut reloc_ranges,
        )?;

        // load relocated/patched section
        let mut section_in_memory = vec![0u8; section_from_elf.len()];
        section_memory_container
            .read_bytes(
                section_memory_container
                    .start()
                    .ok_or(KernelElfError::SectionReadFailed)?,
                &mut section_in_memory,
            )
            .map_err(|_| KernelElfError::SectionReadFailed)?;

        // check whether non-relocatable bytes are modified
        #[cfg(not(debug_assertions))]
        {
            for reloc in reloc_ranges {
                section_from_elf[reloc.clone()].copy_from_slice(&section_in_memory[reloc.clone()]);
            }
            if section_from_elf != section_in_memory {
                serial_println!(
                    "Found {} mismatches in {target_section_name}",
                    target_section_name
                );
                result = false;
            }
        }
        #[cfg(debug_assertions)]
        {
            let mut diffs = Vec::new();
            for non_reloc in reloc_ranges.gaps(&(0..section_from_elf.len())) {
                for i in non_reloc {
                    if section_from_elf[i] != section_in_memory[i] {
                        diffs.push(i);
                    }
                }
            }
            if !diffs.is_empty() {
                serial_println!(
                    "Found {} mismatches in {target_section_name} at {:?}",
                    diffs.len(),
                    diffs
                );
                result = false;
            }
        }
    }
    Ok(result)
}

// a list of sections which we validate
fn sections_to_validate() -> [&'static str; 3] {
    [".text", ".init.text", ".init.rodata"]
}

// for passing ELF-related parameters around local functions
#[derive(Copy, Clone)]
struct ElfParams<'a> {
    elf: &'a ElfBytes<'a, AnyEndian>,
    shdrs: &'a ParsingTable<'a, AnyEndian, SectionHeader>,
    shdr_strtab: &'a StringTable<'a>,
    symtab: &'a ParsingTable<'a, AnyEndian, Symbol>,
    sym_strtab: &'a StringTable<'a>,
}

/// This function identifies direct relocations which are specified in the `.rela.<target_section_name>` section.
fn identify_direct_relocations(
    elf_params: ElfParams<'_>,
    target_section_name: &str,
    section_from_elf: &[u8],
    reloc_ranges: &mut RangeSet<usize>,
) -> Result<(), KernelElfError> {
    if !sections_to_validate().contains(&target_section_name) {
        return Err(KernelElfError::SectionNotFound);
    }
    if let Some(rela_shdr) = elf_params.shdrs.iter().find(|s| {
        s.sh_size > 0
            && s.sh_type == SHT_RELA
            && usize::try_from(s.sh_name).is_ok()
            && elf_params
                .shdr_strtab
                .get(usize::try_from(s.sh_name).unwrap())
                .is_ok_and(|n| n == [".rela", target_section_name].join(""))
    }) {
        let relas = elf_params
            .elf
            .section_data_as_relas(&rela_shdr)
            .map_err(|_| KernelElfError::ElfParseFailed)?;
        for rela in relas {
            let r_sym = usize::try_from(rela.r_sym).map_err(|_| KernelElfError::ElfParseFailed)?;
            let r_offset =
                usize::try_from(rela.r_offset).map_err(|_| KernelElfError::ElfParseFailed)?;
            if elf_params.symtab.get(r_sym).is_ok() {
                let reloc_size: usize = match rela.r_type {
                    R_X86_64_64 => 8,
                    R_X86_64_32 | R_X86_64_32S | R_X86_64_PLT32 | R_X86_64_PC32 => 4,
                    _ => {
                        todo!("Unsupported relocation type {:?}", rela.r_type);
                    }
                };
                let start = r_offset;
                if let Some(end) = start
                    .checked_add(reloc_size)
                    .filter(|&end| end <= section_from_elf.len())
                {
                    reloc_ranges.insert(start..end);
                }
            }
        }
    } else {
        return Err(KernelElfError::SectionNotFound);
    }
    Ok(())
}

/// Allowed list of relocation sections. We do not consider other relocation sections like `.rela.debug_*`
#[inline]
fn is_allowed_rela_section(name: &str) -> bool {
    matches!(
        name,
        ".rela.altinstructions"
            | ".rela.call_sites"
            | ".rela.ibt_endbr_seal"
            | ".rela.parainstructions"
            | ".rela.retpoline_sites"
            | ".rela.return_sites"
            | ".rela__patchable_function_entries"
    )
}

/// This function identifies all possible indirect relocations against the target section. For example,
/// a rela section like `.rela.altinstructions` can relocate `.text` if it has unnamed symbols belonging to `.text`.
fn identify_indirect_relocations(
    elf_params: ElfParams<'_>,
    target_section_name: &str,
    section_from_elf: &[u8],
    reloc_ranges: &mut RangeSet<usize>,
) -> Result<(), KernelElfError> {
    for shdr in elf_params.shdrs.iter().filter(|s| {
        s.sh_size > 0
            && s.sh_type == SHT_RELA
            && usize::try_from(s.sh_name).is_ok()
            && elf_params
                .shdr_strtab
                .get(usize::try_from(s.sh_name).unwrap())
                .is_ok_and(is_allowed_rela_section)
    }) {
        let relas = elf_params
            .elf
            .section_data_as_relas(&shdr)
            .map_err(|_| KernelElfError::ElfParseFailed)?;
        for rela in relas {
            let r_sym = usize::try_from(rela.r_sym).map_err(|_| KernelElfError::ElfParseFailed)?;
            let r_addend =
                usize::try_from(rela.r_addend).map_err(|_| KernelElfError::ElfParseFailed)?;
            let Ok(sym) = elf_params.symtab.get(r_sym) else {
                continue;
            };
            if let Ok(sym_name) = elf_params
                .sym_strtab
                .get(usize::try_from(sym.st_name).map_err(|_| KernelElfError::ElfParseFailed)?)
            {
                if !sym_name.is_empty() {
                    continue;
                }
            }

            // checks whether an unnamed symbol belongs to the target section
            if elf_params
                .shdrs
                .get(usize::from(sym.st_shndx))
                .and_then(|s| {
                    if let Ok(sh_name) = usize::try_from(s.sh_name) {
                        elf_params
                            .shdr_strtab
                            .get(sh_name)
                            .map(|n| n == target_section_name)
                    } else {
                        Err(elf::ParseError::IntegerOverflow)
                    }
                })
                .is_ok()
            {
                let reloc_size: usize = match rela.r_type {
                    R_X86_64_64 => 8,
                    R_X86_64_32 | R_X86_64_32S | R_X86_64_PLT32 | R_X86_64_PC32 => 4,
                    _ => {
                        todo!("Unsupported relocation type {:?}", rela.r_type);
                    }
                };

                // indirect relocations rely on `r_addend` to specify the offsets to patch
                let start = r_addend;
                if let Some(end) = start
                    .checked_add(reloc_size)
                    .filter(|&end| end <= section_from_elf.len())
                {
                    reloc_ranges.insert(start..end);

                    // handle some exceptions which depend on sections
                    let section_name = elf_params
                        .shdr_strtab
                        .get(
                            usize::try_from(shdr.sh_name)
                                .map_err(|_| KernelElfError::ElfParseFailed)?,
                        )
                        .map_err(|_| KernelElfError::ElfParseFailed)?;
                    // `.rela.altinstructions` could patch `nop` which is one byte prior to the specified relocation.
                    if section_name == ".rela.altinstructions"
                        && start > 0
                        && section_from_elf[start - 1] == 0x90
                    {
                        reloc_ranges.insert(start - 1..start);
                    }
                }
            }
        }
    }
    Ok(())
}

/// This function parses the `.modinfo` section of a kernel module ELF
#[cfg(debug_assertions)]
pub fn parse_modinfo(original_elf_data: &[u8]) -> Result<(), KernelElfError> {
    let elf = ElfBytes::<AnyEndian>::minimal_parse(original_elf_data)
        .map_err(|_| KernelElfError::ElfParseFailed)?;

    let (shdrs_opt, shdr_strtab_opt) = elf
        .section_headers_with_strtab()
        .map_err(|_| KernelElfError::ElfParseFailed)?;
    let shdrs = shdrs_opt.ok_or(KernelElfError::ElfParseFailed)?;
    let shdr_strtab = shdr_strtab_opt.ok_or(KernelElfError::ElfParseFailed)?;

    if let Some(shdr) = shdrs.iter().find(|s| {
        s.sh_flags & u64::from(SHF_ALLOC) != 0
            && s.sh_size > 0
            && usize::try_from(s.sh_name).is_ok()
            && shdr_strtab
                .get(usize::try_from(s.sh_name).unwrap())
                .is_ok_and(|n| n == ".modinfo")
    }) {
        let start = usize::try_from(shdr.sh_offset).map_err(|_| KernelElfError::ElfParseFailed)?;
        let end = start
            .checked_add(usize::try_from(shdr.sh_size).map_err(|_| KernelElfError::ElfParseFailed)?)
            .ok_or(KernelElfError::ElfParseFailed)?;
        let modinfo_data = &original_elf_data[start..end];

        for entry in modinfo_data.split(|&b| b == 0) {
            if let Ok(s) = str::from_utf8(entry) {
                if let Some((k, v)) = s.split_once('=') {
                    if k == "name" {
                        debug_serial_println!("Modinfo: {} = {}", k, v);
                    }
                }
            }
        }
    }
    Ok(())
}

/// This function verifies the signature of a Linux kernel module.
/// When module signing is configured, the Linux kernel build pipeline signs each kernel module and appends
/// the signature to it. This function extracts the signature and verifies it using the system certificate which
/// contains the pubic portion of the build pipeline key. VTL0 does not have access to the private portion.
///
/// Currently, this function is slow because it uses the `sha2` crate with the `force-soft` feature.
/// We should consider using HW-accelerated SHA-512 in the future (need to save/restore vector registers).
pub fn verify_kernel_module_signature(
    signed_module: &[u8],
    cert: &Certificate,
) -> Result<(), VerificationError> {
    let (module_data, signature_der) = extract_data_and_signature(signed_module)?;
    let (signature, digest_alg, signature_alg) = decode_signature(signature_der)?;

    // We only support RSA with SHA-256 or SHA-512 for now as most Linux distributions use this combination.
    if (digest_alg != ID_SHA_256 && digest_alg != ID_SHA_512) || (signature_alg != RSA_ENCRYPTION) {
        todo!(
            "Unsupported digest or signature algorithm: {:?}, {:?}",
            digest_alg,
            signature_alg
        );
    }

    let key_info = &cert.tbs_certificate.subject_public_key_info;
    let rsa_pubkey = RsaPublicKey::from_pkcs1_der(key_info.subject_public_key.raw_bytes())
        .map_err(|_| VerificationError::InvalidCertificate)?;
    let rsa_verifier = RsaPkcs1v15Verifier::new(rsa_pubkey, digest_alg)?;
    rsa_verifier
        .verify(module_data, &signature)
        .map_err(|_| VerificationError::AuthenticationFailed)
}

// Wrapper for RSA PKCS#1 v1.5 verifier with a specified digest algorithm
enum RsaPkcs1v15Verifier {
    RsaSha256(rsa::pkcs1v15::VerifyingKey<Sha256>),
    RsaSha512(rsa::pkcs1v15::VerifyingKey<Sha512>),
}

impl RsaPkcs1v15Verifier {
    fn new(
        rsa_pubkey: RsaPublicKey,
        digest_alg: ObjectIdentifier,
    ) -> Result<Self, VerificationError> {
        match digest_alg {
            ID_SHA_256 => Ok(RsaPkcs1v15Verifier::RsaSha256(
                rsa::pkcs1v15::VerifyingKey::<Sha256>::new(rsa_pubkey),
            )),
            ID_SHA_512 => Ok(RsaPkcs1v15Verifier::RsaSha512(
                rsa::pkcs1v15::VerifyingKey::<Sha512>::new(rsa_pubkey),
            )),
            _ => Err(VerificationError::Unsupported),
        }
    }

    fn verify(&self, data: &[u8], signature: &Signature) -> Result<(), VerificationError> {
        match self {
            RsaPkcs1v15Verifier::RsaSha256(verifier) => verifier
                .verify(data, signature)
                .map_err(|_| VerificationError::AuthenticationFailed),
            RsaPkcs1v15Verifier::RsaSha512(verifier) => verifier
                .verify(data, signature)
                .map_err(|_| VerificationError::AuthenticationFailed),
        }
    }
}

/// This function extracts the module data and signature from a signed kernel module.
/// A signed kernel module has the following layout:
/// [module data (ELF)][signature (PKCS#7/DER)][`ModuleSignature`][`MODULE_SIGNATURE_MAGIC`]
fn extract_data_and_signature(signed_module: &[u8]) -> Result<(&[u8], &[u8]), VerificationError> {
    const MODULE_SIGNATURE_MAGIC: &[u8] = b"~Module signature appended~\n";

    let module_signature_offset = signed_module
        .len()
        .checked_sub(core::mem::size_of::<ModuleSignature>() + MODULE_SIGNATURE_MAGIC.len())
        .filter(|offset| {
            &signed_module[offset + core::mem::size_of::<ModuleSignature>()..]
                == MODULE_SIGNATURE_MAGIC
        })
        .ok_or(VerificationError::SignatureNotFound)?;

    #[expect(clippy::cast_ptr_alignment)]
    let module_signature = unsafe {
        &*(signed_module
            .as_ptr()
            .add(module_signature_offset)
            .cast::<ModuleSignature>())
    };
    if !module_signature.is_valid() {
        return Err(VerificationError::InvalidSignature);
    }
    let sig_len = usize::try_from(module_signature.sig_len())
        .map_err(|_| VerificationError::InvalidSignature)?;
    let signature_offset = module_signature_offset
        .checked_sub(sig_len)
        .ok_or(VerificationError::InvalidSignature)?;

    let (module_data, rest) = signed_module.split_at(signature_offset);
    let (signature_der, _) = rest.split_at(sig_len);
    Ok((module_data, signature_der))
}

/// This function decodes the DER-encoded signature from a kernel module and returns the decoded signature
/// along with the digest algorithm and signature algorithm OIDs.
fn decode_signature(
    signature_der: &[u8],
) -> Result<(Signature, ObjectIdentifier, ObjectIdentifier), VerificationError> {
    let content_info =
        ContentInfo::from_der(signature_der).map_err(|_| VerificationError::InvalidSignature)?;
    let signed_data = SignedData::from_der(
        &content_info
            .content
            .to_der()
            .map_err(|_| VerificationError::InvalidSignature)?,
    )
    .map_err(|_| VerificationError::InvalidSignature)?;

    // `SignedData` can have multiple `SignerInfo`s. A Linux kernel module typically has one `SignerInfo`.
    let signer_info = signed_data
        .signer_infos
        .0
        .get(0)
        .ok_or(VerificationError::InvalidSignature)?;

    let signature = Signature::try_from(signer_info.signature.as_bytes())
        .map_err(|_| VerificationError::InvalidSignature)?;
    Ok((
        signature,
        signer_info.digest_alg.oid,
        signer_info.signature_algorithm.oid,
    ))
}

/// Error for Kernel ELF validation and relocation failures.
#[derive(Debug, PartialEq)]
pub enum KernelElfError {
    SectionReadFailed,
    ElfParseFailed,
    SectionNotFound,
}

/// Errors for module signature verification failures.
#[derive(Debug, PartialEq)]
pub enum VerificationError {
    SignatureNotFound,
    InvalidSignature,
    InvalidCertificate,
    AuthenticationFailed,
    Unsupported,
}
