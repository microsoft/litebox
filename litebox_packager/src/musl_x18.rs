// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Substitutes a `-ffixed-x18`-rebuilt musl libc when packaging for a macOS
//! host, closing the gap documented in `docs/roadmap.md`'s "XNU destroys a
//! live guest `x18`" section.
//!
//! XNU zeroes the AArch64 platform register `x18` on every return to EL0.
//! musl's dynamic linker holds a live value in `x18` across exactly that kind
//! of boundary during its own relocation bootstrap, so an ordinary Alpine
//! musl can corrupt relocation under native guest execution on macOS.
//!
//! Rebuilding musl needs a real Alpine toolchain. The companion
//! `litebox_packager/scripts/build-musl-x18-fixed.sh` therefore publishes a
//! local cache generation keyed by the exact stock musl bytes. Recipe v2 uses
//! an atomically replaced manifest that names an immutable payload and attests
//! its source identity, size, and content hash. Legacy filename-only entries
//! are intentionally ignored: one such entry was measured with 18 residual
//! x18-using instructions after stock `libgcc.a` contaminated the link.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use sha2::{Digest as _, Sha256};

/// Env var overriding the cache directory this module reads from and the build
/// script writes into. Unset defaults to [`default_cache_dir`].
const CACHE_DIR_ENV: &str = "LITEBOX_MUSL_X18_CACHE";
const REQUIRE_PATCH_ENV: &str = "LITEBOX_REQUIRE_MUSL_X18";
const CACHE_RECIPE_VERSION: &str = "2";

/// Returns `true` if `path`'s file name matches musl's standard Alpine naming
/// convention (`ld-musl-<arch>.so.1` or `libc.musl-<arch>.so.1`).
pub(crate) fn is_musl_libc_filename(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
        return false;
    };
    (name.starts_with("ld-musl-") || name.starts_with("libc.musl-")) && name.contains(".so")
}

fn content_hash(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let digest = hasher.finalize();
    digest.iter().fold(String::new(), |mut acc, b| {
        let _ = write!(acc, "{b:02x}");
        acc
    })
}

fn default_cache_dir() -> PathBuf {
    let home = std::env::var_os("HOME").map_or_else(|| PathBuf::from("."), PathBuf::from);
    home.join(".cache").join("litebox").join("musl-x18-fixed")
}

fn cache_dir() -> PathBuf {
    std::env::var_os(CACHE_DIR_ENV).map_or_else(default_cache_dir, PathBuf::from)
}

pub(crate) fn patch_is_required() -> bool {
    std::env::var_os(REQUIRE_PATCH_ENV).is_some_and(|value| value == "1")
}

fn parse_metadata(data: &str) -> Option<BTreeMap<&str, &str>> {
    let mut fields = BTreeMap::new();
    for line in data.lines() {
        let (key, value) = line.split_once('=')?;
        if key.is_empty() || value.is_empty() || fields.insert(key, value).is_some() {
            return None;
        }
    }
    Some(fields)
}

fn read_u16_le(data: &[u8], offset: usize) -> Option<u16> {
    let bytes: [u8; 2] = data.get(offset..offset.checked_add(2)?)?.try_into().ok()?;
    Some(u16::from_le_bytes(bytes))
}

fn read_u32_le(data: &[u8], offset: usize) -> Option<u32> {
    let bytes: [u8; 4] = data.get(offset..offset.checked_add(4)?)?.try_into().ok()?;
    Some(u32::from_le_bytes(bytes))
}

fn read_u64_le(data: &[u8], offset: usize) -> Option<u64> {
    let bytes: [u8; 8] = data.get(offset..offset.checked_add(8)?)?.try_into().ok()?;
    Some(u64::from_le_bytes(bytes))
}

fn file_range_is_in_bounds(offset: u64, size: u64, file_size: usize) -> bool {
    let Ok(offset) = usize::try_from(offset) else {
        return false;
    };
    let Ok(size) = usize::try_from(size) else {
        return false;
    };
    offset.checked_add(size).is_some_and(|end| end <= file_size)
}

fn is_runnable_aarch64_shared_object(data: &[u8]) -> bool {
    const ELF64_HEADER_SIZE: usize = 64;
    const ELF64_PROGRAM_HEADER_SIZE: usize = 56;

    if data.len() < ELF64_HEADER_SIZE
        || !data.starts_with(&[0x7f, b'E', b'L', b'F', 2, 1, 1])
        || read_u16_le(data, 16) != Some(object::elf::ET_DYN)
        || read_u16_le(data, 18) != Some(object::elf::EM_AARCH64)
        || read_u32_le(data, 20) != Some(1)
        || read_u16_le(data, 52) != Some(u16::try_from(ELF64_HEADER_SIZE).unwrap())
        || read_u16_le(data, 54) != Some(u16::try_from(ELF64_PROGRAM_HEADER_SIZE).unwrap())
    {
        return false;
    }

    let Some(program_header_offset) =
        read_u64_le(data, 32).and_then(|offset| usize::try_from(offset).ok())
    else {
        return false;
    };
    let Some(program_header_count) = read_u16_le(data, 56).map(usize::from) else {
        return false;
    };
    if program_header_offset < ELF64_HEADER_SIZE
        || program_header_count == 0
        || program_header_count == usize::from(u16::MAX)
    {
        return false;
    }
    let Some(table_size) = ELF64_PROGRAM_HEADER_SIZE.checked_mul(program_header_count) else {
        return false;
    };
    if program_header_offset
        .checked_add(table_size)
        .is_none_or(|end| end > data.len())
    {
        return false;
    }

    let mut has_nonempty_load = false;
    let mut has_dynamic = false;
    for index in 0..program_header_count {
        let offset = program_header_offset + index * ELF64_PROGRAM_HEADER_SIZE;
        let Some(segment_type) = read_u32_le(data, offset) else {
            return false;
        };
        if segment_type != object::elf::PT_LOAD && segment_type != object::elf::PT_DYNAMIC {
            continue;
        }
        let (Some(file_offset), Some(file_size), Some(memory_size)) = (
            read_u64_le(data, offset + 8),
            read_u64_le(data, offset + 32),
            read_u64_le(data, offset + 40),
        ) else {
            return false;
        };
        if file_size > memory_size || !file_range_is_in_bounds(file_offset, file_size, data.len()) {
            return false;
        }
        if segment_type == object::elf::PT_LOAD {
            has_nonempty_load |= file_size != 0;
        } else {
            if file_size == 0 {
                return false;
            }
            has_dynamic = true;
        }
    }

    has_nonempty_load && has_dynamic
}

/// Looks up and validates a recipe-v2 replacement for `original_data`.
///
/// Publication writes the immutable payload first and atomically replaces the
/// manifest last. A concurrent reader therefore observes either the previous
/// complete generation or the new one, never a transient cache miss. Any
/// legacy, partial, malformed, or hash-mismatched generation is rejected.
pub(crate) fn lookup_patched_musl(original_data: &[u8]) -> Option<Vec<u8>> {
    const REQUIRED_KEYS: [&str; 9] = [
        "aports_commit",
        "arch",
        "base_image",
        "musl_pkgver",
        "patched_sha256",
        "payload",
        "recipe",
        "size",
        "stock_sha256",
    ];

    let stock_hash = content_hash(original_data);
    let manifest_path = cache_dir().join(format!("{stock_hash}.v2.meta"));
    let manifest = std::fs::read_to_string(manifest_path).ok()?;
    let fields = parse_metadata(&manifest)?;

    if fields.len() != REQUIRED_KEYS.len()
        || REQUIRED_KEYS.iter().any(|key| !fields.contains_key(key))
        || fields.get("recipe") != Some(&CACHE_RECIPE_VERSION)
        || fields.get("stock_sha256") != Some(&stock_hash.as_str())
        || fields.get("arch") != Some(&"aarch64")
    {
        return None;
    }

    let aports_commit = fields["aports_commit"];
    if aports_commit.len() != 40 || !aports_commit.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    if !fields["base_image"].contains("@sha256:") {
        return None;
    }

    let patched_hash = fields["patched_sha256"];
    if patched_hash.len() != 64
        || !patched_hash.bytes().all(|b| b.is_ascii_hexdigit())
        || patched_hash == stock_hash
    {
        return None;
    }
    let expected_payload = format!("{stock_hash}.v2.{patched_hash}.so");
    if fields["payload"] != expected_payload {
        return None;
    }

    let patched = std::fs::read(cache_dir().join(expected_payload)).ok()?;
    let expected_size = fields["size"].parse::<usize>().ok()?;
    if patched.len() != expected_size
        || content_hash(&patched) != patched_hash
        || !is_runnable_aarch64_shared_object(&patched)
    {
        return None;
    }
    Some(patched)
}

/// Prints the one-time warning steering a user toward creating a validated
/// recipe-v2 cache generation for this exact stock musl build.
pub(crate) fn warn_missing_patch(path: &Path, original_data: &[u8]) {
    let hash = content_hash(original_data);
    eprintln!(
        "warning: packaging {} for a macOS host without a validated -ffixed-x18 musl fix \
         (see docs/roadmap.md's \"XNU destroys a live guest x18\" section) -- \
         this guest's musl relocation bootstrap will likely crash under LiteBox on macOS.\n\
         \x20 to fix: run litebox_packager/scripts/build-musl-x18-fixed.sh, which publishes \
         {}/{hash}.v2.meta and its attested payload; re-run packaging afterward.",
        path.display(),
        cache_dir().display(),
    );
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;

    static CACHE_ENV_LOCK: Mutex<()> = Mutex::new(());

    fn with_cache<T>(name: &str, test: impl FnOnce(&Path) -> T) -> T {
        let _guard = CACHE_ENV_LOCK.lock().unwrap();
        let dir =
            std::env::temp_dir().join(format!("litebox-musl-x18-{name}-{}", std::process::id()));
        std::fs::remove_dir_all(&dir).ok();
        std::fs::create_dir_all(&dir).unwrap();
        // SAFETY: all tests that mutate this process-global variable serialize
        // through CACHE_ENV_LOCK.
        unsafe {
            std::env::set_var(CACHE_DIR_ENV, &dir);
        }
        let result = test(&dir);
        unsafe {
            std::env::remove_var(CACHE_DIR_ENV);
        }
        std::fs::remove_dir_all(&dir).ok();
        result
    }

    fn test_runnable_aarch64_shared_object() -> Vec<u8> {
        const PROGRAM_HEADERS_OFFSET: usize = 64;
        const PROGRAM_HEADER_SIZE: usize = 56;
        const DYNAMIC_OFFSET: usize = PROGRAM_HEADERS_OFFSET + 2 * PROGRAM_HEADER_SIZE;
        const FILE_SIZE: usize = DYNAMIC_OFFSET + 16;

        let mut data = vec![0; FILE_SIZE];
        data[..7].copy_from_slice(&[0x7f, b'E', b'L', b'F', 2, 1, 1]);
        data[16..18].copy_from_slice(&object::elf::ET_DYN.to_le_bytes());
        data[18..20].copy_from_slice(&object::elf::EM_AARCH64.to_le_bytes());
        data[20..24].copy_from_slice(&1u32.to_le_bytes());
        data[32..40].copy_from_slice(&(PROGRAM_HEADERS_OFFSET as u64).to_le_bytes());
        data[52..54].copy_from_slice(&64u16.to_le_bytes());
        data[54..56].copy_from_slice(&u16::try_from(PROGRAM_HEADER_SIZE).unwrap().to_le_bytes());
        data[56..58].copy_from_slice(&2u16.to_le_bytes());

        let load = PROGRAM_HEADERS_OFFSET;
        data[load..load + 4].copy_from_slice(&object::elf::PT_LOAD.to_le_bytes());
        data[load + 32..load + 40].copy_from_slice(&(FILE_SIZE as u64).to_le_bytes());
        data[load + 40..load + 48].copy_from_slice(&(FILE_SIZE as u64).to_le_bytes());

        let dynamic = PROGRAM_HEADERS_OFFSET + PROGRAM_HEADER_SIZE;
        data[dynamic..dynamic + 4].copy_from_slice(&object::elf::PT_DYNAMIC.to_le_bytes());
        data[dynamic + 8..dynamic + 16].copy_from_slice(&(DYNAMIC_OFFSET as u64).to_le_bytes());
        data[dynamic + 32..dynamic + 40].copy_from_slice(&16u64.to_le_bytes());
        data[dynamic + 40..dynamic + 48].copy_from_slice(&16u64.to_le_bytes());
        data
    }

    #[test]
    fn runnable_musl_shape_rejects_header_only_and_malformed_segments() {
        let valid = test_runnable_aarch64_shared_object();
        assert!(is_runnable_aarch64_shared_object(&valid));
        assert!(!is_runnable_aarch64_shared_object(&valid[..64]));

        let mut malformed = valid.clone();
        malformed[56..58].copy_from_slice(&0u16.to_le_bytes());
        assert!(!is_runnable_aarch64_shared_object(&malformed));

        let mut malformed = valid.clone();
        malformed[64..68].copy_from_slice(&object::elf::PT_NULL.to_le_bytes());
        assert!(!is_runnable_aarch64_shared_object(&malformed));

        let mut malformed = valid.clone();
        malformed[120..124].copy_from_slice(&object::elf::PT_NULL.to_le_bytes());
        assert!(!is_runnable_aarch64_shared_object(&malformed));

        let mut malformed = valid.clone();
        malformed[128..136].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(!is_runnable_aarch64_shared_object(&malformed));

        let mut truncated = valid;
        truncated.truncate(100);
        assert!(!is_runnable_aarch64_shared_object(&truncated));
    }

    fn publish_test_generation(dir: &Path, original: &[u8], patched: &[u8]) {
        let stock_hash = content_hash(original);
        let patched_hash = content_hash(patched);
        let payload = format!("{stock_hash}.v2.{patched_hash}.so");
        std::fs::write(dir.join(&payload), patched).unwrap();
        std::fs::write(
            dir.join(format!("{stock_hash}.v2.meta")),
            format!(
                "recipe=2\nstock_sha256={stock_hash}\npatched_sha256={patched_hash}\n\
                 size={}\npayload={payload}\nmusl_pkgver=1.2.5-r21\narch=aarch64\n\
                 base_image=example.invalid/alpine@sha256:{}\n\
                 aports_commit={}\n",
                patched.len(),
                "a".repeat(64),
                "b".repeat(40),
            ),
        )
        .unwrap();
    }

    #[test]
    fn recognizes_both_musl_alpine_names() {
        assert!(is_musl_libc_filename(Path::new(
            "/lib/ld-musl-aarch64.so.1"
        )));
        assert!(is_musl_libc_filename(Path::new(
            "/lib/libc.musl-aarch64.so.1"
        )));
        assert!(is_musl_libc_filename(Path::new("/lib/ld-musl-x86_64.so.1")));
    }

    #[test]
    fn rejects_unrelated_filenames() {
        assert!(!is_musl_libc_filename(Path::new("/usr/bin/node")));
        assert!(!is_musl_libc_filename(Path::new(
            "/lib/x86_64-linux-gnu/libc.so.6"
        )));
        assert!(!is_musl_libc_filename(Path::new("/lib/ld-musl-notice.txt")));
    }

    #[test]
    fn cache_miss_on_empty_directory_returns_none() {
        with_cache("miss", |_| {
            assert!(lookup_patched_musl(b"stock musl bytes").is_none());
        });
    }

    #[test]
    fn legacy_filename_only_entry_is_rejected() {
        with_cache("legacy", |dir| {
            let original = b"stock musl bytes";
            std::fs::write(
                dir.join(format!("{}.so", content_hash(original))),
                b"known-bad legacy bytes",
            )
            .unwrap();
            assert!(lookup_patched_musl(original).is_none());
        });
    }

    #[test]
    fn cache_hit_returns_attested_payload() {
        with_cache("hit", |dir| {
            let original = b"stock musl bytes for the hit test";
            let patched = test_runnable_aarch64_shared_object();
            publish_test_generation(dir, original, &patched);
            assert_eq!(lookup_patched_musl(original), Some(patched));
        });
    }

    #[test]
    fn cache_hash_mismatch_is_rejected() {
        with_cache("tamper", |dir| {
            let original = b"stock musl bytes for the tamper test";
            let patched = test_runnable_aarch64_shared_object();
            publish_test_generation(dir, original, &patched);
            let stock_hash = content_hash(original);
            let manifest =
                std::fs::read_to_string(dir.join(format!("{stock_hash}.v2.meta"))).unwrap();
            let fields = parse_metadata(&manifest).unwrap();
            std::fs::write(dir.join(fields["payload"]), b"tampered").unwrap();
            assert!(lookup_patched_musl(original).is_none());
        });
    }
}
