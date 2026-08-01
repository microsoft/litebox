// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::mem::size_of;
use litebox::fd::TypedFd;
use litebox::fs::errors::{FileStatusError, OpenError, PathError, ReadError};
use litebox::fs::{FileType, Mode, OFlags};
use litebox::mm::linux::{CreatePagesFlags, MappingError, NonZeroPageSize};
use litebox::platform::{RawConstPointer as _, RawMutPointer as _, RawPointerProvider};
use litebox::utils::TruncateExt as _;
use litebox_common_windows::loader::PAGE_SIZE;
use litebox_common_windows::nt_status::NtStatus;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

use crate::nt_types::ProcessEnvironmentBlock;
use crate::{MutPtr, ShimFS, ShimPlatform, Task, probe_guest_output_preserving_value, write_value};

pub(crate) const DEFAULT_LOCALE_ID: u32 = 0x0409;

const ANSI_CODE_PAGE: u32 = 1252;
const MUI_MIN_LANGUAGE_CAPACITY: usize = 4;
const MUI_MIN_LANGUAGE_CONFIG_CAPACITY: usize = 1;
const MUI_STRING_CAPACITY: usize = 4;
const OEM_CODE_PAGE: u32 = 437;
const UNICODE_CASE_TABLE: u32 = 10000;
const NLS_SECTION_LOCALE: u32 = 2;
const NLS_SECTION_SORTKEYS: u32 = 9;
const NLS_SECTION_CASEMAP: u32 = 10;
const NLS_SECTION_CODEPAGE: u32 = 11;
const NLS_SECTION_NORMALIZE: u32 = 12;

bitflags::bitflags! {
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct MuiRegistryInfoFlags: u32 {
        const QUERY = 0x1;
        const CLEAR = 0x2;
        const COMMIT = 0x8;
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, FromBytes, Immutable, IntoBytes, KnownLayout, PartialEq)]
struct MuiRegistryInfo {
    owned: u32,
    install_language_fallback: [u16; 4],
    generation: u32,
    process_generation: u32,
    padding_14: [u8; 4],
    installed_offset: u64,
    strings_offset: u64,
    machine_config_offset: u64,
    user_config_offset: u64,
    machine_preferred_offset: u64,
    user_preferred_offset: u64,
    process_preferred_offset: u64,
    merged_user_offset: u64,
    merged_machine_offset: u64,
    merged_fallback_offset: u64,
    previous_registry_info_offset: u64,
    locked: u32,
    secure_environment: u32,
    number_allowed: u32,
    padding_7c: [u8; 4],
    allowed_language_offset: u64,
    installed_sku_offset: u64,
    installed_sku_size: u32,
    allowed_language_size: u32,
    disallowed_language_offset: u64,
    disallowed_language_size: u32,
    padding_a4: [u8; 4],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, FromBytes, Immutable, IntoBytes, KnownLayout, PartialEq)]
struct MuiLanguages {
    total_size: u32,
    max_languages: u16,
    languages: u16,
    installed_languages: u16,
    padding_a: [u8; 6],
    language_info_offset: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, FromBytes, Immutable, IntoBytes, KnownLayout, PartialEq)]
struct MuiLanguageInfo {
    flags: u16,
    reserved: u16,
    language_id: u16,
    language_name_index: i16,
    fallback_types: u16,
    neutral_language_index: i16,
    fallback_indices: [i16; 4],
    alternate_code_pages: [i16; 4],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, FromBytes, Immutable, IntoBytes, KnownLayout, PartialEq)]
struct MuiStringPool {
    total_size: u32,
    max_strings: u16,
    strings: u16,
    max_characters: u16,
    characters: u16,
    padding_c: [u8; 4],
    string_indices_offset: u64,
    pool_offset: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, FromBytes, Immutable, IntoBytes, KnownLayout, PartialEq)]
struct MuiLanguageConfigList {
    total_size: u32,
    languages: u16,
    max_languages: u16,
    language_configs_offset: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, FromBytes, Immutable, IntoBytes, KnownLayout, PartialEq)]
struct MuiLanguageConfigNode {
    language_index: i16,
    fallback_types: u16,
    reserved: u16,
    fallback_indices: [i16; 3],
}

const MUI_INSTALLED_SKU_SIZE: usize = size_of::<[u16; 387]>();
const MUI_INSTALLED_OFFSET: usize = size_of::<MuiRegistryInfo>();
const EMPTY_MUI_LANGUAGE_INFO: MuiLanguageInfo = MuiLanguageInfo {
    flags: 0,
    reserved: 0,
    language_id: 0,
    language_name_index: 0,
    fallback_types: 0,
    neutral_language_index: 0,
    fallback_indices: [0; 4],
    alternate_code_pages: [0; 4],
};
const EN_US_MUI_LANGUAGE_INFO: MuiLanguageInfo = MuiLanguageInfo {
    flags: 0x0931,
    reserved: 0,
    language_id: 0x0409,
    language_name_index: 1,
    fallback_types: 0,
    neutral_language_index: 0,
    fallback_indices: [0; 4],
    alternate_code_pages: [0; 4],
};
const EN_US_MUI_LANGUAGE: MuiLanguage<'static> = MuiLanguage {
    info: EN_US_MUI_LANGUAGE_INFO,
    name: "en-US",
};
const EMPTY_MUI_LANGUAGE_CONFIG: MuiLanguageConfigNode = MuiLanguageConfigNode {
    language_index: 0,
    fallback_types: 0,
    reserved: 0,
    fallback_indices: [0; 3],
};

#[derive(Clone, Copy)]
struct MuiLanguage<'a> {
    info: MuiLanguageInfo,
    name: &'a str,
}

#[derive(Clone, Copy)]
struct MuiRegistryLayout {
    language_capacity: usize,
    installed_size: usize,
    strings_offset: usize,
    string_capacity: usize,
    character_capacity: usize,
    string_pool_size: usize,
    machine_config_offset: usize,
    language_config_capacity: usize,
    machine_config_size: usize,
    installed_sku_offset: usize,
    total_size: usize,
}

const INSTALLED_SKU_BYTES: &[u8] = b"en-US\0en-AU\0en-CA\0en-GB\0en-HK\0en-IE\0en-NZ\0en-SG\0\
ar-SA\0pt-BR\0zh-TW\0zh-CN\0zh-HK\0zh-SG\0cs-CZ\0da-DK\0el-GR\0es-AR\0es-CL\0\
es-CO\0es-ES\0es-MX\0es-US\0fi-FI\0fr-BE\0fr-CA\0fr-CH\0fr-FR\0de-AT\0de-CH\0\
de-DE\0he-IL\0hu-HU\0it-IT\0ja-JP\0ko-KR\0nl-BE\0nl-NL\0nb-NO\0pl-PL\0pt-PT\0\
ru-RU\0sv-SE\0tr-TR\0bg-BG\0hr-HR\0et-EE\0lv-LV\0lt-LT\0ro-RO\0sr-Latn-CS\0\
sr-Latn-RS\0sk-SK\0sl-SI\0th-TH\0uk-UA\0fy-NL\0qps-ploc\0qps-plocm\0\
qps-Latn-x-sh\0\0\0";
const _: () = assert!(core::mem::size_of::<[u16; 387]>() == 774);

const fn utf16_from_ascii<const N: usize>(bytes: &[u8]) -> [u16; N] {
    assert!(bytes.len() == N);
    let mut output = [0; N];
    let mut index = 0;
    while index < bytes.len() {
        output[index] = bytes[index] as u16;
        index += 1;
    }
    output
}

fn align_up(value: usize, alignment: usize) -> Option<usize> {
    value
        .checked_add(alignment.checked_sub(1)?)?
        .checked_div(alignment)?
        .checked_mul(alignment)
}

fn mui_registry_layout(
    languages: &[MuiLanguage<'_>],
    language_config_count: usize,
) -> Option<MuiRegistryLayout> {
    let language_capacity = languages.len().max(MUI_MIN_LANGUAGE_CAPACITY);
    let installed_size = align_up(
        size_of::<MuiLanguages>()
            .checked_add(language_capacity.checked_mul(size_of::<MuiLanguageInfo>())?)?,
        8,
    )?;
    let strings_offset = MUI_INSTALLED_OFFSET.checked_add(installed_size)?;
    let string_capacity = languages.len().checked_add(1)?.max(MUI_STRING_CAPACITY);
    let characters = languages.iter().try_fold(2usize, |characters, language| {
        characters.checked_add(language.name.encode_utf16().count().checked_add(1)?)
    })?;
    let character_capacity = characters.max(40);
    let string_pool_size = size_of::<MuiStringPool>()
        .checked_add(string_capacity.checked_mul(size_of::<i16>())?)?
        .checked_add(character_capacity.checked_mul(size_of::<u16>())?)?;
    let machine_config_offset = align_up(strings_offset.checked_add(string_pool_size)?, 8)?;
    let language_config_capacity = language_config_count.max(MUI_MIN_LANGUAGE_CONFIG_CAPACITY);
    let machine_config_size = size_of::<MuiLanguageConfigList>()
        .checked_add(language_config_capacity.checked_mul(size_of::<MuiLanguageConfigNode>())?)?;
    let installed_sku_offset =
        align_up(machine_config_offset.checked_add(machine_config_size)?, 8)?;
    let total_size = align_up(installed_sku_offset.checked_add(MUI_INSTALLED_SKU_SIZE)?, 8)?;
    debug_assert_eq!(strings_offset % 8, 0);
    debug_assert_eq!(machine_config_offset % 8, 0);
    debug_assert_eq!(installed_sku_offset % 8, 0);
    Some(MuiRegistryLayout {
        language_capacity,
        installed_size,
        strings_offset,
        string_capacity,
        character_capacity,
        string_pool_size,
        machine_config_offset,
        language_config_capacity,
        machine_config_size,
        installed_sku_offset,
        total_size,
    })
}

// TODO(mui-registry-info): Populate the generic serializer from the guest registry when installed
// language configuration becomes mutable. The shim currently supplies only its fixed en-US locale.
fn mui_registry_data(
    generation: u32,
    languages: &[MuiLanguage<'_>],
    language_configs: &[MuiLanguageConfigNode],
) -> Option<Vec<u8>> {
    let layout = mui_registry_layout(languages, language_configs.len())?;
    let language_count = u16::try_from(languages.len()).ok()?;
    let language_capacity = u16::try_from(layout.language_capacity).ok()?;
    let language_config_count = u16::try_from(language_configs.len()).ok()?;
    let language_config_capacity = u16::try_from(layout.language_config_capacity).ok()?;

    let mut install_language_fallback = [0; 4];
    for (slot, language) in install_language_fallback.iter_mut().zip(languages.iter()) {
        *slot = language.info.language_id;
    }
    let registry_info = MuiRegistryInfo {
        owned: 0x400,
        install_language_fallback,
        generation,
        process_generation: 0,
        padding_14: [0; 4],
        installed_offset: u64::try_from(MUI_INSTALLED_OFFSET).expect("MUI offset fits in u64"),
        strings_offset: u64::try_from(layout.strings_offset).expect("MUI offset fits in u64"),
        machine_config_offset: u64::try_from(layout.machine_config_offset)
            .expect("MUI offset fits in u64"),
        user_config_offset: 0,
        machine_preferred_offset: 0,
        user_preferred_offset: 0,
        process_preferred_offset: 0,
        merged_user_offset: 0,
        merged_machine_offset: 0,
        merged_fallback_offset: 0,
        previous_registry_info_offset: 0,
        locked: 0,
        secure_environment: 0,
        number_allowed: 1000,
        padding_7c: [0; 4],
        allowed_language_offset: 0,
        installed_sku_offset: u64::try_from(layout.installed_sku_offset)
            .expect("MUI offset fits in u64"),
        installed_sku_size: MUI_INSTALLED_SKU_SIZE.trunc(),
        allowed_language_size: 0,
        disallowed_language_offset: 0,
        disallowed_language_size: 0,
        padding_a4: [0; 4],
    };
    let installed = MuiLanguages {
        total_size: layout.installed_size.trunc(),
        max_languages: language_capacity,
        languages: language_count,
        installed_languages: 0,
        padding_a: [0; 6],
        // A zero nested offset is the native inline-array representation.
        language_info_offset: 0,
    };
    let string_count = u16::try_from(languages.len().checked_add(1)?).ok()?;
    let string_capacity = u16::try_from(layout.string_capacity).ok()?;
    let character_capacity = u16::try_from(layout.character_capacity).ok()?;
    let mut string_indices = Vec::with_capacity(layout.string_capacity);
    string_indices.push(0i16);
    let mut string_pool = Vec::with_capacity(layout.character_capacity);
    string_pool.push(0u16);
    let mut language_info = Vec::with_capacity(languages.len());
    for language in languages {
        let name_index = i16::try_from(string_pool.len()).ok()?;
        string_indices.push(name_index);
        let mut info = language.info;
        info.language_name_index = name_index;
        language_info.push(info);
        string_pool.extend(language.name.encode_utf16());
        string_pool.push(0);
    }
    string_pool.push(0);
    let characters = u16::try_from(string_pool.len()).ok()?;
    string_indices.resize(layout.string_capacity, 0);
    string_pool.resize(layout.character_capacity, 0);
    let strings = MuiStringPool {
        total_size: layout.string_pool_size.trunc(),
        max_strings: string_capacity,
        strings: string_count,
        max_characters: character_capacity,
        characters,
        padding_c: [0; 4],
        string_indices_offset: 0,
        pool_offset: 0,
    };
    let machine_config = MuiLanguageConfigList {
        total_size: layout.machine_config_size.trunc(),
        languages: language_config_count,
        max_languages: language_config_capacity,
        // A zero nested offset is the native inline-array representation.
        language_configs_offset: 0,
    };

    let mut data = Vec::with_capacity(layout.total_size);
    data.extend_from_slice(registry_info.as_bytes());
    data.extend_from_slice(installed.as_bytes());
    for language in &language_info {
        data.extend_from_slice(language.as_bytes());
    }
    for _ in language_info.len()..layout.language_capacity {
        data.extend_from_slice(EMPTY_MUI_LANGUAGE_INFO.as_bytes());
    }
    data.resize(layout.strings_offset, 0);
    data.extend_from_slice(strings.as_bytes());
    data.extend_from_slice(string_indices.as_bytes());
    data.extend_from_slice(string_pool.as_bytes());
    data.resize(layout.machine_config_offset, 0);
    data.extend_from_slice(machine_config.as_bytes());
    for config in language_configs {
        data.extend_from_slice(config.as_bytes());
    }
    for _ in language_configs.len()..layout.language_config_capacity {
        data.extend_from_slice(EMPTY_MUI_LANGUAGE_CONFIG.as_bytes());
    }
    data.resize(layout.installed_sku_offset, 0);
    data.extend_from_slice(utf16_from_ascii::<387>(INSTALLED_SKU_BYTES).as_bytes());
    data.resize(layout.total_size, 0);
    Some(data)
}

struct NlsSectionRequest<Platform: RawPointerProvider> {
    section_type: u32,
    section_data: u32,
    context_data: usize,
    section_pointer: MutPtr<Platform, usize>,
    section_size: Option<MutPtr<Platform, u32>>,
}

impl<Platform: RawPointerProvider> Clone for NlsSectionRequest<Platform> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<Platform: RawPointerProvider> Copy for NlsSectionRequest<Platform> {}

#[derive(Clone, Copy)]
struct MappedNlsSection {
    address: usize,
    len: usize,
}

struct NlsSectionFile<FS: ShimFS> {
    fd: TypedFd<FS>,
    len: usize,
}

impl<Platform: ShimPlatform, FS: ShimFS> Task<Platform, FS> {
    pub(crate) fn sys_nt_get_mui_registry_info(
        &self,
        flags: u32,
        data_size: Option<MutPtr<Platform, u32>>,
        data: Option<MutPtr<Platform, u8>>,
    ) -> NtStatus {
        let flags = if flags == 0 {
            MuiRegistryInfoFlags::QUERY
        } else {
            let Some(flags) = MuiRegistryInfoFlags::from_bits(flags) else {
                return NtStatus::INVALID_PARAMETER;
            };
            flags
        };

        let supplied_size = match data_size {
            Some(data_size) => match data_size.read_at_offset(0) {
                Some(size) => size,
                None => return NtStatus::ACCESS_VIOLATION,
            },
            None if flags
                .intersects(MuiRegistryInfoFlags::CLEAR | MuiRegistryInfoFlags::COMMIT) =>
            {
                0
            }
            None => return NtStatus::INVALID_PARAMETER,
        };

        if (supplied_size == 0 && data.is_some()) || (supplied_size != 0 && data.is_none()) {
            return NtStatus::INVALID_PARAMETER;
        }

        if !flags.contains(MuiRegistryInfoFlags::QUERY) {
            if flags.contains(MuiRegistryInfoFlags::COMMIT) {
                self.global
                    .mui_generation
                    .fetch_add(1, core::sync::atomic::Ordering::Relaxed);
            }
            return NtStatus::SUCCESS;
        }

        let Some(data_size) = data_size else {
            return NtStatus::INVALID_PARAMETER;
        };
        let generation = self
            .global
            .mui_generation
            .load(core::sync::atomic::Ordering::Relaxed);
        let Some(layout) = mui_registry_layout(&[EN_US_MUI_LANGUAGE], 0) else {
            return NtStatus::UNSUCCESSFUL;
        };
        let required_size = layout.total_size.trunc();
        if supplied_size == 0 {
            return write_required_output::<Platform, u32>(data_size, required_size);
        }
        if supplied_size < required_size {
            return if data_size.write_at_offset(0, required_size).is_some() {
                NtStatus::BUFFER_TOO_SMALL
            } else {
                NtStatus::ACCESS_VIOLATION
            };
        }

        if data_size.write_at_offset(0, required_size).is_none() {
            return NtStatus::ACCESS_VIOLATION;
        }
        let Some(data) = data else {
            return NtStatus::INVALID_PARAMETER;
        };
        let Some(registry_data) = mui_registry_data(generation, &[EN_US_MUI_LANGUAGE], &[]) else {
            return NtStatus::UNSUCCESSFUL;
        };
        if data.copy_from_slice(0, &registry_data).is_none() {
            return NtStatus::ACCESS_VIOLATION;
        }

        litebox_util_log::debug!(
            flags:? = flags,
            data_size = required_size,
            generation;
            "Handled NtGetMUIRegistryInfo syscall"
        );
        NtStatus::SUCCESS
    }

    pub(crate) fn sys_nt_get_nls_section_ptr(
        &self,
        section_type: u32,
        section_data: u32,
        context_data: usize,
        section_pointer: MutPtr<Platform, usize>,
        section_size: Option<MutPtr<Platform, u32>>,
    ) -> NtStatus {
        let request = NlsSectionRequest {
            section_type,
            section_data,
            context_data,
            section_pointer,
            section_size,
        };

        if <MutPtr<Platform, usize> as litebox::platform::RawConstPointer<usize>>::as_usize(
            &request.section_pointer,
        ) == 0
        {
            return NtStatus::INVALID_PARAMETER;
        }

        let cache_key = (request.section_type, request.section_data);
        if let Some(mapped_section) = self.cached_nls_section(cache_key) {
            return self.write_nls_section_result(request, mapped_section, true);
        }

        let mapped_section = match self.map_nls_section_file(request) {
            Ok(mapped_section) => mapped_section,
            Err(status) => {
                litebox_util_log::debug!(
                    section_type = request.section_type,
                    section_data = request.section_data,
                    status:? = status;
                    "NtGetNlsSectionPtr section is not available"
                );
                return status;
            }
        };

        let (mapped_section, cached) = self.publish_nls_section_mapping(cache_key, mapped_section);
        let status = self.write_nls_section_result(request, mapped_section, cached);
        if status != NtStatus::SUCCESS && !cached {
            self.remove_owned_cached_nls_section(cache_key, mapped_section);
        }
        status
    }

    pub(crate) fn sys_nt_initialize_nls_files(
        &self,
        base_address: MutPtr<Platform, usize>,
        default_locale_id: MutPtr<Platform, u32>,
        _default_casing_table_size: MutPtr<Platform, i64>,
    ) -> NtStatus {
        if base_address.as_usize() == 0 {
            return NtStatus::ACCESS_VIOLATION;
        }

        let request = NlsSectionRequest {
            section_type: NLS_SECTION_LOCALE,
            section_data: 0,
            context_data: 0,
            section_pointer: base_address,
            section_size: None,
        };
        let cache_key = (NLS_SECTION_LOCALE, 0);
        let (mapped_section, cached) =
            if let Some(mapped_section) = self.cached_nls_section(cache_key) {
                (mapped_section, true)
            } else {
                let mapped_section = match self.map_nls_section_file(request) {
                    Ok(mapped_section) => mapped_section,
                    Err(status) => return status,
                };
                self.publish_nls_section_mapping(cache_key, mapped_section)
            };

        let locale_id = self
            .process
            .system_lcid
            .load(core::sync::atomic::Ordering::Relaxed);
        if probe_guest_output_preserving_value::<Platform, usize>(base_address).is_err()
            || probe_guest_output_preserving_value::<Platform, u32>(default_locale_id).is_err()
            || default_locale_id.write_at_offset(0, locale_id).is_none()
            || base_address
                .write_at_offset(0, mapped_section.address)
                .is_none()
        {
            if !cached {
                self.remove_owned_cached_nls_section(cache_key, mapped_section);
            }
            return NtStatus::ACCESS_VIOLATION;
        }

        litebox_util_log::debug!(
            base:% = format_args!("{:#x}", mapped_section.address),
            default_locale_id = locale_id;
            "Handled NtInitializeNlsFiles syscall"
        );
        NtStatus::SUCCESS
    }

    pub(crate) fn sys_nt_query_default_locale(
        &self,
        user_profile: u8,
        default_locale_id: MutPtr<Platform, u32>,
    ) -> NtStatus {
        let locale_id = if user_profile == 0 {
            self.process
                .system_lcid
                .load(core::sync::atomic::Ordering::Relaxed)
        } else {
            self.process
                .user_lcid
                .load(core::sync::atomic::Ordering::Relaxed)
        };
        write_required_output::<Platform, u32>(default_locale_id, locale_id)
    }

    pub(crate) fn sys_nt_set_default_locale(
        &self,
        user_profile: u8,
        default_locale_id: u32,
    ) -> NtStatus {
        if user_profile == 0 {
            self.process
                .system_lcid
                .store(default_locale_id, core::sync::atomic::Ordering::Relaxed);
        } else {
            self.process
                .user_lcid
                .store(default_locale_id, core::sync::atomic::Ordering::Relaxed);
        }
        NtStatus::SUCCESS
    }

    pub(crate) fn sys_nt_query_default_ui_language(
        &self,
        default_ui_language: MutPtr<Platform, u16>,
    ) -> NtStatus {
        let lang_id = lang_id_from_locale_id(
            self.process
                .user_ui_language
                .load(core::sync::atomic::Ordering::Relaxed),
        );
        write_required_output::<Platform, u16>(default_ui_language, lang_id)
    }

    pub(crate) fn sys_nt_set_default_ui_language(&self, default_ui_language: u16) -> NtStatus {
        self.process.user_ui_language.store(
            u32::from(default_ui_language),
            core::sync::atomic::Ordering::Relaxed,
        );
        NtStatus::SUCCESS
    }

    pub(crate) fn sys_nt_query_install_ui_language(
        &self,
        install_ui_language: MutPtr<Platform, u16>,
    ) -> NtStatus {
        let lang_id = lang_id_from_locale_id(
            self.process
                .system_lcid
                .load(core::sync::atomic::Ordering::Relaxed),
        );
        write_required_output::<Platform, u16>(install_ui_language, lang_id)
    }

    fn map_nls_section_file(
        &self,
        request: NlsSectionRequest<Platform>,
    ) -> Result<MappedNlsSection, NtStatus> {
        let section_file = self.open_nls_section_file(request)?;
        let section_len = section_file.len;
        let alloc_len = match nls_section_alloc_len(section_len) {
            Ok(alloc_len) => alloc_len,
            Err(status) => {
                let _ = self.fs.close(&section_file.fd);
                return Err(status);
            }
        };
        let Some(page_len) = NonZeroPageSize::<PAGE_SIZE>::new(alloc_len) else {
            let _ = self.fs.close(&section_file.fd);
            return Err(NtStatus::INVALID_PARAMETER);
        };

        let mut copy_status = None;
        // SAFETY: No fixed address is requested, so the page manager chooses an unused guest
        // range. The callback only initializes the newly allocated pages before they are exposed.
        let mapping = unsafe {
            self.global.page_manager.create_readable_pages(
                None,
                page_len,
                CreatePagesFlags::POPULATE_PAGES_IMMEDIATELY,
                |ptr| match self.copy_nls_section_file(&section_file.fd, section_len, ptr) {
                    Ok(copied) => Ok(copied),
                    Err(status) => {
                        copy_status = Some(status);
                        Err(MappingError::OutOfMemory)
                    }
                },
            )
        };
        let _ = self.fs.close(&section_file.fd);
        let mapping = mapping.map_err(|_| copy_status.unwrap_or(NtStatus::NO_MEMORY))?;
        Ok(MappedNlsSection {
            address: mapping.as_usize(),
            len: alloc_len,
        })
    }

    fn open_nls_section_file(
        &self,
        request: NlsSectionRequest<Platform>,
    ) -> Result<NlsSectionFile<FS>, NtStatus> {
        let path = nls_section_file_path(request.section_type, request.section_data)?;
        let fd = self
            .fs
            .open(path.as_str(), OFlags::RDONLY, Mode::empty())
            .map_err(map_nls_open_error)?;

        let status = match self.fs.fd_file_status(&fd) {
            Ok(status) => status,
            Err(error) => {
                let _ = self.fs.close(&fd);
                return Err(map_nls_file_status_error(error));
            }
        };
        if status.file_type != FileType::RegularFile {
            let _ = self.fs.close(&fd);
            return Err(NtStatus::OBJECT_TYPE_MISMATCH);
        }
        if status.size == 0 {
            let _ = self.fs.close(&fd);
            return Err(NtStatus::OBJECT_NAME_NOT_FOUND);
        }

        Ok(NlsSectionFile {
            fd,
            len: status.size,
        })
    }

    fn copy_nls_section_file(
        &self,
        fd: &TypedFd<FS>,
        section_len: usize,
        output: MutPtr<Platform, u8>,
    ) -> Result<usize, NtStatus> {
        let mut offset = 0;
        while offset < section_len {
            let mut chunk = [0; PAGE_SIZE];
            let remaining = section_len - offset;
            let chunk_len = remaining.min(PAGE_SIZE);
            let read = self
                .fs
                .read(fd, &mut chunk[..chunk_len], Some(offset))
                .map_err(map_nls_read_error)?;
            if read == 0 {
                return Err(NtStatus::END_OF_FILE);
            }
            let Ok(output_offset) = isize::try_from(offset) else {
                return Err(NtStatus::INVALID_PARAMETER);
            };
            if output
                .write_slice_at_offset(output_offset, &chunk[..read])
                .is_none()
            {
                return Err(NtStatus::ACCESS_VIOLATION);
            }
            offset += read;
        }
        Ok(offset)
    }

    fn write_nls_section_result(
        &self,
        request: NlsSectionRequest<Platform>,
        mapped_section: MappedNlsSection,
        cached: bool,
    ) -> NtStatus {
        if probe_guest_output_preserving_value::<Platform, usize>(request.section_pointer).is_err()
        {
            return NtStatus::ACCESS_VIOLATION;
        }
        let Ok(len) = u32::try_from(mapped_section.len) else {
            return NtStatus::SECTION_TOO_BIG;
        };
        if let Some(section_size) = request.section_size
            && section_size.write_at_offset(0, len).is_none()
        {
            return NtStatus::ACCESS_VIOLATION;
        }
        if request
            .section_pointer
            .write_at_offset(0, mapped_section.address)
            .is_none()
        {
            return NtStatus::ACCESS_VIOLATION;
        }
        self.set_peb_nls_pointer(request.section_data, mapped_section.address);

        litebox_util_log::debug!(
            section_type = request.section_type,
            section_data = request.section_data,
            context_data:% = format_args!("{:#x}", request.context_data),
            mapped_address:% = format_args!("{:#x}", mapped_section.address),
            section_len = mapped_section.len,
            cached = cached;
            "Handled NtGetNlsSectionPtr syscall"
        );

        NtStatus::SUCCESS
    }

    fn cached_nls_section(&self, cache_key: (u32, u32)) -> Option<MappedNlsSection> {
        self.process
            .nls_section_mappings
            .read()
            .get(&cache_key)
            .copied()
            .map(|(address, len)| MappedNlsSection { address, len })
    }

    fn publish_nls_section_mapping(
        &self,
        cache_key: (u32, u32),
        mapped_section: MappedNlsSection,
    ) -> (MappedNlsSection, bool) {
        let mut mappings = self.process.nls_section_mappings.write();
        if let Some((mapped_address, section_len)) = mappings.get(&cache_key).copied() {
            drop(mappings);
            self.unmap_owned_nls_section(mapped_section);
            return (
                MappedNlsSection {
                    address: mapped_address,
                    len: section_len,
                },
                true,
            );
        }

        mappings.insert(cache_key, (mapped_section.address, mapped_section.len));
        (mapped_section, false)
    }

    fn remove_owned_cached_nls_section(
        &self,
        cache_key: (u32, u32),
        mapped_section: MappedNlsSection,
    ) {
        let mut mappings = self.process.nls_section_mappings.write();
        let remove_cached_mapping =
            mappings.get(&cache_key).copied() == Some((mapped_section.address, mapped_section.len));
        if remove_cached_mapping {
            mappings.remove(&cache_key);
        }
        drop(mappings);

        if remove_cached_mapping {
            self.unmap_owned_nls_section(mapped_section);
        }
    }

    fn set_peb_nls_pointer(&self, section_data: u32, mapped_address: usize) {
        if self.process.peb_address == 0 {
            return;
        }

        let Some(field_offset) = (match section_data {
            ANSI_CODE_PAGE => Some(core::mem::offset_of!(
                ProcessEnvironmentBlock,
                ansi_code_page_data
            )),
            OEM_CODE_PAGE => Some(core::mem::offset_of!(
                ProcessEnvironmentBlock,
                oem_code_page_data
            )),
            UNICODE_CASE_TABLE => Some(core::mem::offset_of!(
                ProcessEnvironmentBlock,
                unicode_case_table_data
            )),
            _ => None,
        }) else {
            return;
        };

        let peb_field =
            MutPtr::<Platform, usize>::from_usize(self.process.peb_address + field_offset);
        let _ = peb_field.write_at_offset(0, mapped_address);
    }

    fn unmap_owned_nls_section(&self, mapped_section: MappedNlsSection) {
        // SAFETY: The mapping was created by this syscall path and has not been published on the
        // failing path, so no guest execution can hold a valid reference to it yet.
        let _ = unsafe {
            self.global.page_manager.remove_pages(
                MutPtr::<Platform, u8>::from_usize(mapped_section.address),
                mapped_section.len,
            )
        };
    }
}

fn nls_section_file_path(section_type: u32, section_data: u32) -> Result<String, NtStatus> {
    match section_type {
        NLS_SECTION_LOCALE if section_data == 0 => Ok(String::from("/Windows/System32/locale.nls")),
        NLS_SECTION_SORTKEYS if section_data == 0 => Ok(String::from(
            "/Windows/Globalization/Sorting/sortdefault.nls",
        )),
        NLS_SECTION_CASEMAP if section_data == 0 => {
            Ok(String::from("/Windows/System32/l_intl.nls"))
        }
        NLS_SECTION_CASEMAP => Err(NtStatus::UNSUCCESSFUL),
        NLS_SECTION_CODEPAGE => Ok(format!("/Windows/System32/c_{section_data:03}.nls")),
        NLS_SECTION_NORMALIZE => normalize_nls_file_name(section_data)
            .map(|name| format!("/Windows/System32/{name}.nls"))
            .ok_or(NtStatus::OBJECT_NAME_NOT_FOUND),
        _ => Err(NtStatus::INVALID_PARAMETER_1),
    }
}

fn nls_section_alloc_len(section_len: usize) -> Result<usize, NtStatus> {
    let alloc_len = section_len
        .checked_next_multiple_of(PAGE_SIZE)
        .ok_or(NtStatus::SECTION_TOO_BIG)?;
    if u32::try_from(alloc_len).is_err() {
        return Err(NtStatus::SECTION_TOO_BIG);
    }
    Ok(alloc_len)
}

fn lang_id_from_locale_id(locale_id: u32) -> u16 {
    u16::try_from(locale_id & u32::from(u16::MAX)).expect("masked locale id fits in a LANGID")
}

fn normalize_nls_file_name(section_data: u32) -> Option<&'static str> {
    match section_data {
        1 => Some("normnfc"),
        2 => Some("normnfd"),
        5 => Some("normnfkc"),
        6 => Some("normnfkd"),
        13 => Some("normidna"),
        _ => None,
    }
}

fn write_required_output<Platform, T>(output: MutPtr<Platform, T>, value: T) -> NtStatus
where
    Platform: RawPointerProvider,
    T: zerocopy::FromBytes + zerocopy::IntoBytes,
{
    if write_value::<Platform, T>(output.as_usize(), value).is_some() {
        NtStatus::SUCCESS
    } else {
        NtStatus::ACCESS_VIOLATION
    }
}

fn map_nls_open_error(error: OpenError) -> NtStatus {
    match error {
        OpenError::PathError(
            PathError::NoSuchFileOrDirectory
            | PathError::MissingComponent
            | PathError::ComponentNotADirectory,
        ) => NtStatus::OBJECT_NAME_NOT_FOUND,
        OpenError::PathError(PathError::NoSearchPerms { .. }) | OpenError::AccessNotAllowed => {
            NtStatus::ACCESS_DENIED
        }
        _ => NtStatus::UNSUCCESSFUL,
    }
}

fn map_nls_file_status_error(error: FileStatusError) -> NtStatus {
    match error {
        FileStatusError::PathError(
            PathError::NoSuchFileOrDirectory
            | PathError::MissingComponent
            | PathError::ComponentNotADirectory,
        ) => NtStatus::OBJECT_NAME_NOT_FOUND,
        FileStatusError::PathError(PathError::NoSearchPerms { .. }) => NtStatus::ACCESS_DENIED,
        _ => NtStatus::UNSUCCESSFUL,
    }
}

fn map_nls_read_error(error: ReadError) -> NtStatus {
    match error {
        ReadError::NotForReading => NtStatus::ACCESS_DENIED,
        _ => NtStatus::UNSUCCESSFUL,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::mut_ptr;
    use alloc::vec;
    use litebox::platform::RawPointerProvider;

    extern crate std;

    type TestPlatform = crate::tests::TestPlatform;

    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    unsafe extern "system" {
        fn NtGetNlsSectionPtr(
            section_type: u32,
            section_data: u32,
            context_data: *mut core::ffi::c_void,
            section_pointer: *mut *const u8,
            section_size: *mut u32,
        ) -> i32;

        fn NtInitializeNlsFiles(
            base_address: *mut *const u8,
            default_locale_id: *mut u32,
            default_casing_table_size: *mut i64,
        ) -> i32;

        fn NtGetMUIRegistryInfo(flags: u32, data_size: *mut u32, data: *mut u8) -> i32;

        fn NtQueryDefaultLocale(user_profile: u8, default_locale_id: *mut u32) -> i32;

        fn NtQueryDefaultUILanguage(default_ui_language: *mut u16) -> i32;

        fn NtQueryInstallUILanguage(install_ui_language: *mut u16) -> i32;
    }

    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    fn host_system32_file_bytes(file_name: &str) -> std::vec::Vec<u8> {
        std::fs::read(
            std::path::PathBuf::from(
                std::env::var_os("SystemRoot")
                    .unwrap_or_else(|| std::ffi::OsString::from(r"C:\Windows")),
            )
            .join("System32")
            .join(file_name),
        )
        .unwrap()
    }

    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    fn host_status(status: i32) -> NtStatus {
        NtStatus::from_raw(u32::from_ne_bytes(status.to_ne_bytes()))
    }

    #[test]
    fn nt_get_mui_registry_info_queries_and_fills_host_shaped_data() {
        let task = crate::tests::test_task();
        let mut data_size = 0u32;
        let expected = mui_registry_data(0, &[EN_US_MUI_LANGUAGE], &[]).unwrap();

        assert_eq!(
            task.sys_nt_get_mui_registry_info(0, Some(mut_ptr(&mut data_size)), None,),
            NtStatus::SUCCESS
        );
        assert_eq!(data_size as usize, expected.len());
        assert_eq!(data_size, 1232);

        let mut data = vec![0; data_size as usize];
        assert_eq!(
            task.sys_nt_get_mui_registry_info(
                MuiRegistryInfoFlags::QUERY.bits(),
                Some(mut_ptr(&mut data_size)),
                Some(mut_ptr(data.first_mut().unwrap())),
            ),
            NtStatus::SUCCESS
        );

        let registry_info = MuiRegistryInfo::read_from_prefix(&data).unwrap().0;
        assert_eq!(
            data,
            mui_registry_data(registry_info.generation, &[EN_US_MUI_LANGUAGE], &[]).unwrap()
        );
        assert_eq!(registry_info.install_language_fallback[0], 0x0409);
        assert_eq!(registry_info.installed_offset, 0xa8);
        assert_eq!(registry_info.strings_offset, 0x130);
        assert_eq!(registry_info.machine_config_offset, 0x1a8);
        assert_eq!(registry_info.installed_sku_offset, 0x1c8);
        let installed_offset = usize::try_from(registry_info.installed_offset).unwrap();
        let strings_offset = usize::try_from(registry_info.strings_offset).unwrap();
        let installed = MuiLanguages::read_from_prefix(&data[installed_offset..])
            .unwrap()
            .0;
        assert_eq!(installed.total_size, 0x88);
        let language_info = MuiLanguageInfo::read_from_prefix(
            &data[installed_offset + size_of::<MuiLanguages>()..],
        )
        .unwrap()
        .0;
        assert_eq!(language_info.language_id, 0x0409);
        assert_eq!(
            &data[strings_offset
                + size_of::<MuiStringPool>()
                + size_of::<[i16; MUI_STRING_CAPACITY]>()
                + size_of::<u16>()
                ..strings_offset
                    + size_of::<MuiStringPool>()
                    + size_of::<[i16; MUI_STRING_CAPACITY]>()
                    + 7 * size_of::<u16>()],
            &[b'e', 0, b'n', 0, b'-', 0, b'U', 0, b'S', 0, 0, 0]
        );
    }

    #[test]
    fn nt_get_mui_registry_info_reports_required_size_without_touching_short_buffer() {
        let task = crate::tests::test_task();
        let required_size = mui_registry_data(0, &[EN_US_MUI_LANGUAGE], &[])
            .unwrap()
            .len();
        let mut data_size: u32 = required_size.trunc();
        data_size -= 1;
        let mut data = vec![0xa5; data_size as usize];
        let before = data.clone();

        assert_eq!(
            task.sys_nt_get_mui_registry_info(
                MuiRegistryInfoFlags::QUERY.bits(),
                Some(mut_ptr(&mut data_size)),
                Some(mut_ptr(data.first_mut().unwrap())),
            ),
            NtStatus::BUFFER_TOO_SMALL
        );
        assert_eq!(data_size as usize, required_size);
        assert_eq!(data, before);
    }

    #[test]
    fn nt_get_mui_registry_info_rejects_invalid_flags_and_buffer_shapes() {
        let task = crate::tests::test_task();
        let mut data_size = 0u32;
        let mut data = mui_registry_data(0, &[EN_US_MUI_LANGUAGE], &[]).unwrap();

        assert_eq!(
            task.sys_nt_get_mui_registry_info(0x4, Some(mut_ptr(&mut data_size)), None,),
            NtStatus::INVALID_PARAMETER
        );
        assert_eq!(
            task.sys_nt_get_mui_registry_info(
                0,
                Some(mut_ptr(&mut data_size)),
                Some(mut_ptr(data.first_mut().unwrap())),
            ),
            NtStatus::INVALID_PARAMETER
        );
        data_size = data.len().trunc();
        assert_eq!(
            task.sys_nt_get_mui_registry_info(0, Some(mut_ptr(&mut data_size)), None,),
            NtStatus::INVALID_PARAMETER
        );
    }

    #[test]
    fn mui_registry_data_serializes_multiple_languages_and_configs() {
        let second_language = MuiLanguage {
            info: MuiLanguageInfo {
                language_id: 0x040c,
                ..EN_US_MUI_LANGUAGE_INFO
            },
            name: "fr-FR",
        };
        let configs = [
            EMPTY_MUI_LANGUAGE_CONFIG,
            MuiLanguageConfigNode {
                language_index: 1,
                fallback_types: 1,
                ..EMPTY_MUI_LANGUAGE_CONFIG
            },
        ];
        let languages = [EN_US_MUI_LANGUAGE, second_language];
        let data = mui_registry_data(7, &languages, &configs).unwrap();
        let layout = mui_registry_layout(&languages, 2).unwrap();
        assert_eq!(data.len(), layout.total_size);

        let registry_info = MuiRegistryInfo::read_from_prefix(&data).unwrap().0;
        assert_eq!(registry_info.generation, 7);
        assert_eq!(
            registry_info.install_language_fallback[..2],
            [0x0409, 0x040c]
        );
        let installed_offset = usize::try_from(registry_info.installed_offset).unwrap();
        let machine_config_offset = usize::try_from(registry_info.machine_config_offset).unwrap();
        let installed = MuiLanguages::read_from_prefix(&data[installed_offset..])
            .unwrap()
            .0;
        assert_eq!(installed.languages, 2);
        assert_eq!(installed.max_languages, 4);
        assert_eq!(installed.language_info_offset, 0);
        let second_info_offset =
            installed_offset + size_of::<MuiLanguages>() + size_of::<MuiLanguageInfo>();
        assert_eq!(
            MuiLanguageInfo::read_from_prefix(&data[second_info_offset..])
                .unwrap()
                .0
                .language_id,
            second_language.info.language_id
        );
        assert_eq!(
            MuiLanguageInfo::read_from_prefix(&data[second_info_offset..])
                .unwrap()
                .0
                .language_name_index,
            7
        );
        for index in 2..layout.language_capacity {
            let offset =
                installed_offset + size_of::<MuiLanguages>() + index * size_of::<MuiLanguageInfo>();
            assert_eq!(
                MuiLanguageInfo::read_from_prefix(&data[offset..])
                    .unwrap()
                    .0,
                EMPTY_MUI_LANGUAGE_INFO
            );
        }

        let strings_offset = usize::try_from(registry_info.strings_offset).unwrap();
        let strings = MuiStringPool::read_from_prefix(&data[strings_offset..])
            .unwrap()
            .0;
        assert_eq!(strings.strings, 3);
        assert_eq!(strings.max_strings, 4);
        assert_eq!(strings.characters, 14);
        assert_eq!(strings.max_characters, 40);
        let indices_offset = strings_offset + size_of::<MuiStringPool>();
        let indices = <[i16; MUI_STRING_CAPACITY]>::read_from_prefix(&data[indices_offset..])
            .unwrap()
            .0;
        assert_eq!(indices, [0, 1, 7, 0]);
        let pool_offset = indices_offset + size_of::<[i16; MUI_STRING_CAPACITY]>();
        let names = <[u16; 14]>::read_from_prefix(&data[pool_offset..])
            .unwrap()
            .0;
        assert_eq!(
            names,
            [0, 101, 110, 45, 85, 83, 0, 102, 114, 45, 70, 82, 0, 0]
        );

        let machine_config =
            MuiLanguageConfigList::read_from_prefix(&data[machine_config_offset..])
                .unwrap()
                .0;
        assert_eq!(machine_config.languages, 2);
        assert_eq!(machine_config.max_languages, 2);
        assert_eq!(machine_config.language_configs_offset, 0);
        assert_eq!(
            machine_config.total_size as usize,
            size_of::<MuiLanguageConfigList>() + 2 * size_of::<MuiLanguageConfigNode>()
        );
        let second_config_offset = machine_config_offset
            + size_of::<MuiLanguageConfigList>()
            + size_of::<MuiLanguageConfigNode>();
        assert_eq!(
            MuiLanguageConfigNode::read_from_prefix(&data[second_config_offset..])
                .unwrap()
                .0,
            configs[1]
        );
        assert_eq!(
            usize::try_from(registry_info.installed_sku_offset).unwrap(),
            align_up(
                machine_config_offset + machine_config.total_size as usize,
                8
            )
            .unwrap()
        );
    }

    #[test]
    fn mui_registry_data_rejects_unrepresentable_language_name_indices() {
        let long_name = "a".repeat(i16::MAX as usize);
        let languages = [
            MuiLanguage {
                info: EN_US_MUI_LANGUAGE_INFO,
                name: &long_name,
            },
            EN_US_MUI_LANGUAGE,
        ];

        assert!(mui_registry_data(0, &languages, &[]).is_none());
    }

    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    #[test]
    fn nt_get_mui_registry_info_matches_host_query_contract_and_layout() {
        let mut host_size = 0u32;
        // SAFETY: This is the host's documented size-query shape: a writable size pointer and a
        // null data buffer.
        let status = unsafe {
            NtGetMUIRegistryInfo(0, core::ptr::addr_of_mut!(host_size), core::ptr::null_mut())
        };
        assert_eq!(host_status(status), NtStatus::SUCCESS);
        assert_eq!(
            host_size as usize,
            mui_registry_data(0, &[EN_US_MUI_LANGUAGE], &[])
                .unwrap()
                .len()
        );

        let mut host_data = vec![0; host_size as usize];
        // SAFETY: `host_data` is a writable buffer of the size returned by the host query.
        let status = unsafe {
            NtGetMUIRegistryInfo(
                0,
                core::ptr::addr_of_mut!(host_size),
                host_data.as_mut_ptr(),
            )
        };
        assert_eq!(host_status(status), NtStatus::SUCCESS);
        let host_registry_info = MuiRegistryInfo::read_from_prefix(&host_data).unwrap().0;
        assert_eq!(
            host_registry_info.installed_offset,
            u64::try_from(MUI_INSTALLED_OFFSET).unwrap(),
        );
        let expected =
            mui_registry_data(host_registry_info.generation, &[EN_US_MUI_LANGUAGE], &[]).unwrap();
        assert_eq!(host_data, expected);
    }

    #[test]
    fn nt_get_nls_section_ptr_maps_file_backed_section() {
        let section_bytes = vec![1, 2, 3, 4, 5];
        let task = crate::tests::test_task_with_nls_files(&[(
            "/Windows/System32/c_1252.nls",
            section_bytes.as_slice(),
        )]);
        let mut section_pointer = 0usize;
        let mut section_size = 0u32;

        assert_eq!(
            task.sys_nt_get_nls_section_ptr(
                NLS_SECTION_CODEPAGE,
                ANSI_CODE_PAGE,
                0,
                mut_ptr(&mut section_pointer),
                Some(mut_ptr(&mut section_size)),
            ),
            NtStatus::SUCCESS
        );

        assert_ne!(section_pointer, 0);
        assert_eq!(section_size, u32::try_from(PAGE_SIZE).unwrap());
        let mapped = <TestPlatform as RawPointerProvider>::RawConstPointer::<u8>::from_usize(
            section_pointer,
        );
        assert_eq!(
            mapped.to_owned_slice(section_bytes.len()).unwrap().as_ref(),
            section_bytes.as_slice()
        );

        let mut second_section_pointer = 0usize;
        assert_eq!(
            task.sys_nt_get_nls_section_ptr(
                NLS_SECTION_CODEPAGE,
                ANSI_CODE_PAGE,
                0,
                mut_ptr(&mut second_section_pointer),
                None,
            ),
            NtStatus::SUCCESS
        );
        assert_eq!(second_section_pointer, section_pointer);
    }

    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    #[test]
    fn nt_get_nls_section_ptr_matches_host_section_content() {
        let host_file_bytes = host_system32_file_bytes("c_1252.nls");
        let task = crate::tests::test_task_with_nls_files(&[(
            "/Windows/System32/c_1252.nls",
            host_file_bytes.as_slice(),
        )]);

        let mut host_section_pointer = core::ptr::null::<u8>();
        let mut host_section_size = 0u32;
        // SAFETY: The pointers reference local output variables, and the section type/data pair is
        // the same supported codepage section requested by normal Windows process startup.
        let status = unsafe {
            NtGetNlsSectionPtr(
                NLS_SECTION_CODEPAGE,
                ANSI_CODE_PAGE,
                core::ptr::null_mut(),
                core::ptr::addr_of_mut!(host_section_pointer),
                core::ptr::addr_of_mut!(host_section_size),
            )
        };
        assert_eq!(host_status(status), NtStatus::SUCCESS);
        assert!(!host_section_pointer.is_null());

        let mut section_pointer = 0usize;
        let mut section_size = 0u32;
        assert_eq!(
            task.sys_nt_get_nls_section_ptr(
                NLS_SECTION_CODEPAGE,
                ANSI_CODE_PAGE,
                0,
                mut_ptr(&mut section_pointer),
                Some(mut_ptr(&mut section_size)),
            ),
            NtStatus::SUCCESS
        );

        let host_section_len = usize::try_from(host_section_size).unwrap();
        assert_eq!(section_size, host_section_size);
        let mapped = <TestPlatform as RawPointerProvider>::RawConstPointer::<u8>::from_usize(
            section_pointer,
        );
        // SAFETY: A successful host NtGetNlsSectionPtr returned a non-null pointer and size for a
        // process-lifetime read-only NLS mapping.
        let host_section =
            unsafe { core::slice::from_raw_parts(host_section_pointer, host_section_len) };
        assert_eq!(
            mapped.to_owned_slice(host_section_len).unwrap().as_ref(),
            host_section
        );
    }

    #[test]
    fn nt_get_nls_section_ptr_rejects_invalid_arguments() {
        let bytes = [0xaa];
        let task = crate::tests::test_task_with_nls_files(&[(
            "/Windows/System32/c_437.nls",
            bytes.as_slice(),
        )]);
        let mut section_pointer = 0usize;

        assert_eq!(
            task.sys_nt_get_nls_section_ptr(
                NLS_SECTION_CODEPAGE,
                OEM_CODE_PAGE,
                0,
                MutPtr::<TestPlatform, usize>::from_usize(0),
                None,
            ),
            NtStatus::INVALID_PARAMETER
        );
        assert_eq!(
            task.sys_nt_get_nls_section_ptr(
                NLS_SECTION_CODEPAGE,
                ANSI_CODE_PAGE,
                0,
                mut_ptr(&mut section_pointer),
                None,
            ),
            NtStatus::OBJECT_NAME_NOT_FOUND
        );
        assert_eq!(section_pointer, 0);
    }

    #[test]
    fn nls_section_file_path_formats_codepage_names() {
        assert_eq!(
            nls_section_file_path(NLS_SECTION_CODEPAGE, 37).unwrap(),
            "/Windows/System32/c_037.nls"
        );
        assert_eq!(
            nls_section_file_path(NLS_SECTION_CODEPAGE, ANSI_CODE_PAGE).unwrap(),
            "/Windows/System32/c_1252.nls"
        );
    }

    #[test]
    fn nls_section_alloc_len_rejects_unrepresentable_sections() {
        assert_eq!(nls_section_alloc_len(1).unwrap(), PAGE_SIZE);
        assert_eq!(
            nls_section_alloc_len(usize::MAX),
            Err(NtStatus::SECTION_TOO_BIG)
        );
        assert_eq!(
            nls_section_alloc_len(usize::try_from(u32::MAX).unwrap()),
            Err(NtStatus::SECTION_TOO_BIG)
        );
    }

    #[test]
    fn nt_initialize_nls_files_maps_locale_file() {
        let locale_bytes = vec![0x44; PAGE_SIZE + 1];
        let task = crate::tests::test_task_with_nls_files(&[(
            "/Windows/System32/locale.nls",
            locale_bytes.as_slice(),
        )]);
        let mut base_address = 0usize;
        let mut locale_id = 0u32;
        let mut casing_table_size = 0x1234_5678i64;

        assert_eq!(
            task.sys_nt_initialize_nls_files(
                mut_ptr(&mut base_address),
                mut_ptr(&mut locale_id),
                mut_ptr(&mut casing_table_size),
            ),
            NtStatus::SUCCESS
        );

        assert_ne!(base_address, 0);
        assert_eq!(locale_id, DEFAULT_LOCALE_ID);
        assert_eq!(casing_table_size, 0x1234_5678);
        let mapped =
            <TestPlatform as RawPointerProvider>::RawConstPointer::<u8>::from_usize(base_address);
        assert_eq!(
            mapped.to_owned_slice(locale_bytes.len()).unwrap().as_ref(),
            locale_bytes.as_slice()
        );
    }

    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    #[test]
    fn nt_initialize_nls_files_matches_host_outputs() {
        let host_file_bytes = host_system32_file_bytes("locale.nls");
        let task = crate::tests::test_task_with_nls_files(&[(
            "/Windows/System32/locale.nls",
            host_file_bytes.as_slice(),
        )]);

        let mut host_base_address = core::ptr::null::<u8>();
        let mut host_locale_id = 0x1234_5678u32;
        let mut host_casing_table_size = 0x1234_5678i64;
        // SAFETY: The pointers reference local output variables and mirror the normal process
        // startup call shape; the returned mapping is process-lifetime read-only NLS data.
        let status = unsafe {
            NtInitializeNlsFiles(
                core::ptr::addr_of_mut!(host_base_address),
                core::ptr::addr_of_mut!(host_locale_id),
                core::ptr::addr_of_mut!(host_casing_table_size),
            )
        };
        assert_eq!(host_status(status), NtStatus::SUCCESS);
        assert!(!host_base_address.is_null());

        task.process
            .system_lcid
            .store(host_locale_id, core::sync::atomic::Ordering::Relaxed);
        let mut base_address = 0usize;
        let mut locale_id = 0x1234_5678u32;
        let mut casing_table_size = 0x1234_5678i64;
        assert_eq!(
            task.sys_nt_initialize_nls_files(
                mut_ptr(&mut base_address),
                mut_ptr(&mut locale_id),
                mut_ptr(&mut casing_table_size),
            ),
            NtStatus::SUCCESS
        );

        assert_eq!(locale_id, host_locale_id);
        assert_eq!(casing_table_size, host_casing_table_size);
        let mapped =
            <TestPlatform as RawPointerProvider>::RawConstPointer::<u8>::from_usize(base_address);
        // SAFETY: A successful host NtInitializeNlsFiles returned a non-null process-lifetime NLS
        // mapping, and the fixture file length bounds the comparison.
        let host_section =
            unsafe { core::slice::from_raw_parts(host_base_address, host_file_bytes.len()) };
        assert_eq!(
            mapped
                .to_owned_slice(host_file_bytes.len())
                .unwrap()
                .as_ref(),
            host_section
        );
    }

    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    #[test]
    fn locale_query_syscalls_match_host_outputs() {
        let task = crate::tests::test_task();
        let mut host_system_locale = 0u32;
        let mut host_user_locale = 0u32;
        let mut host_user_ui_language = 0u16;
        let mut host_install_ui_language = 0u16;

        // SAFETY: The pointers reference local output variables for read-only host locale queries.
        unsafe {
            assert_eq!(
                host_status(NtQueryDefaultLocale(
                    0,
                    core::ptr::addr_of_mut!(host_system_locale),
                )),
                NtStatus::SUCCESS
            );
            assert_eq!(
                host_status(NtQueryDefaultLocale(
                    1,
                    core::ptr::addr_of_mut!(host_user_locale),
                )),
                NtStatus::SUCCESS
            );
            assert_eq!(
                host_status(NtQueryDefaultUILanguage(core::ptr::addr_of_mut!(
                    host_user_ui_language
                ))),
                NtStatus::SUCCESS
            );
            assert_eq!(
                host_status(NtQueryInstallUILanguage(core::ptr::addr_of_mut!(
                    host_install_ui_language
                ))),
                NtStatus::SUCCESS
            );
        }

        task.process
            .system_lcid
            .store(host_system_locale, core::sync::atomic::Ordering::Relaxed);
        task.process
            .user_lcid
            .store(host_user_locale, core::sync::atomic::Ordering::Relaxed);
        task.process.user_ui_language.store(
            u32::from(host_user_ui_language),
            core::sync::atomic::Ordering::Relaxed,
        );

        let mut locale_id = 0u32;
        let mut language = 0u16;
        assert_eq!(
            task.sys_nt_query_default_locale(0, mut_ptr(&mut locale_id)),
            NtStatus::SUCCESS
        );
        assert_eq!(locale_id, host_system_locale);
        assert_eq!(
            task.sys_nt_query_default_locale(1, mut_ptr(&mut locale_id)),
            NtStatus::SUCCESS
        );
        assert_eq!(locale_id, host_user_locale);
        assert_eq!(
            task.sys_nt_query_default_ui_language(mut_ptr(&mut language)),
            NtStatus::SUCCESS
        );
        assert_eq!(language, host_user_ui_language);
        task.process.system_lcid.store(
            u32::from(host_install_ui_language),
            core::sync::atomic::Ordering::Relaxed,
        );
        assert_eq!(
            task.sys_nt_query_install_ui_language(mut_ptr(&mut language)),
            NtStatus::SUCCESS
        );
        assert_eq!(language, host_install_ui_language);
    }

    #[test]
    fn locale_syscalls_query_and_update_process_locale_state() {
        let task = crate::tests::test_task();
        let mut locale_id = 0u32;
        let mut language = 0u16;

        assert_eq!(
            task.sys_nt_query_default_locale(0, mut_ptr(&mut locale_id)),
            NtStatus::SUCCESS
        );
        assert_eq!(locale_id, DEFAULT_LOCALE_ID);

        assert_eq!(task.sys_nt_set_default_locale(0, 0x0411), NtStatus::SUCCESS);
        assert_eq!(
            task.sys_nt_query_default_locale(0, mut_ptr(&mut locale_id)),
            NtStatus::SUCCESS
        );
        assert_eq!(locale_id, 0x0411);

        assert_eq!(
            task.sys_nt_set_default_ui_language(0x040c),
            NtStatus::SUCCESS
        );
        assert_eq!(
            task.sys_nt_query_default_ui_language(mut_ptr(&mut language)),
            NtStatus::SUCCESS
        );
        assert_eq!(language, 0x040c);

        assert_eq!(
            task.sys_nt_query_install_ui_language(mut_ptr(&mut language)),
            NtStatus::SUCCESS
        );
        assert_eq!(language, 0x0411);
    }
}
