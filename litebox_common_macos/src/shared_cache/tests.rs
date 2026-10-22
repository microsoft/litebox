// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Synthetic-buffer tests for shared-cache parsing and v5 rebasing.
#![allow(clippy::cast_possible_truncation)]

use super::*;
use alloc::vec;
use object::macho;

const REGION_START: u64 = 0x1_8000_0000;
const REGION_SIZE: u64 = 0x4_0000;
const TEXT_ADDRESS: u64 = REGION_START + 0x4000;
const TEXT_SIZE: u64 = 0x8000;
const DATA_ADDRESS: u64 = REGION_START + 0x1_0000;
const DATA_HEADER_SIZE: u64 = 0x4000;
const DATA_SIZE: u64 = 0x4000;
const DYNAMIC_DATA_OFFSET: u64 = 0x3_c000;
const MAIN_UUID: [u8; 16] = [0x11; 16];
const TEXT_UUID: [u8; 16] = [0x22; 16];
const DATA_UUID: [u8; 16] = [0x33; 16];
const MAPPINGS: usize = 0x228;
const SUBCACHES: usize = 0x260;
const IMAGES: usize = 0x300;
const PATHS: usize = 0x800;
const RX: u32 = 5;
const RW: u32 = 3;

fn put32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}
fn put64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

/// (address, size, file offset, slide info file range, flags, protection).
type MappingSpec = (u64, u64, u64, Range<u64>, u64, u32);

/// A cache file header with `mappings` at [`MAPPINGS`].
fn cache_file(size: usize, uuid: [u8; 16], mappings: &[MappingSpec]) -> Vec<u8> {
    let mut file = vec![0; size];
    file[..16].copy_from_slice(&CACHE_MAGIC_ARM64E);
    put32(&mut file, HEADER_MAPPING_OFFSET, MAPPINGS as u32);
    file[HEADER_UUID..HEADER_UUID + 16].copy_from_slice(&uuid);
    put64(&mut file, HEADER_SHARED_REGION_START, REGION_START);
    put64(&mut file, HEADER_SHARED_REGION_SIZE, REGION_SIZE);
    put64(&mut file, HEADER_MAX_SLIDE, 0x1000_0000);
    put32(&mut file, HEADER_MAPPING_WITH_SLIDE_OFFSET, MAPPINGS as u32);
    put32(
        &mut file,
        HEADER_MAPPING_WITH_SLIDE_OFFSET + 4,
        mappings.len() as u32,
    );
    put64(&mut file, HEADER_DYNAMIC_DATA_OFFSET, DYNAMIC_DATA_OFFSET);
    put64(&mut file, HEADER_DYNAMIC_DATA_MAX_SIZE, 0x4000);
    for (index, (address, size, offset, slide, flags, protection)) in mappings.iter().enumerate() {
        let entry = MAPPINGS + index * MAPPING_AND_SLIDE_INFO_BYTES;
        put64(&mut file, entry, *address);
        put64(&mut file, entry + 8, *size);
        put64(&mut file, entry + 16, *offset);
        put64(&mut file, entry + 24, slide.start);
        put64(&mut file, entry + 32, slide.end - slide.start);
        put64(&mut file, entry + 40, *flags);
        put32(&mut file, entry + 48, *protection);
        put32(&mut file, entry + 52, *protection);
    }
    file
}

/// One test image: (path, address, file type, dependencies). A dependency's
/// command is a load command, or [`USE`] plus `dylib_use_command` flags.
type ImageSpec<'a> = (&'a str, u64, u32, &'a [(&'a str, u32)]);

/// Marks a test dependency as a `dylib_use_command` with these flags.
const USE: u32 = 0x100;

/// `__TEXT,__text` relative to each synthetic image's Mach header.
const TEXT_SECTION: core::ops::Range<u64> = 0x100..0x800;

/// Images follow the TEXT subcache's own header.
fn image_address(index: u64) -> u64 {
    TEXT_ADDRESS + 0x1000 * (index + 1)
}

const LIBSYSTEM: &str = "/usr/lib/libSystem.B.dylib";
const IMAGES_SPEC: &[ImageSpec<'static>] = &[
    (
        LIBSYSTEM,
        TEXT_ADDRESS + 0x1000,
        macho::MH_DYLIB,
        &[
            ("/usr/lib/system/libb.dylib", macho::LC_REEXPORT_DYLIB),
            ("/usr/lib/libc_alias.dylib", macho::LC_LOAD_DYLIB),
            ("/usr/lib/missing.dylib", macho::LC_LOAD_WEAK_DYLIB),
            ("/usr/lib/libe.dylib", macho::LC_LOAD_UPWARD_DYLIB),
            // Delayed-init targets are not initialized at launch.
            ("/usr/lib/libunused.dylib", USE | 0x08),
            // Re-exports are never delayed.
            ("/usr/lib/libf.dylib", USE | 0x0a),
        ],
    ),
    // Cycle back to libSystem.
    (
        "/usr/lib/system/libb.dylib",
        TEXT_ADDRESS + 0x2000,
        macho::MH_DYLIB,
        &[(LIBSYSTEM, macho::LC_LOAD_DYLIB)],
    ),
    // Self-cycle; also reached through an alias.
    (
        "/usr/lib/libc.dylib",
        TEXT_ADDRESS + 0x3000,
        macho::MH_DYLIB,
        &[("/usr/lib/libc.dylib", macho::LC_LOAD_DYLIB)],
    ),
    (
        "/usr/lib/libe.dylib",
        TEXT_ADDRESS + 0x4000,
        macho::MH_DYLIB,
        &[],
    ),
    // dyld's own dylib commands are ignored, like dyld's forEachLinkedDylib.
    (
        "/usr/lib/dyld",
        TEXT_ADDRESS + 0x5000,
        macho::MH_DYLINKER,
        &[("/usr/lib/libunused.dylib", macho::LC_LOAD_DYLIB)],
    ),
    // Not reachable from the roots.
    (
        "/usr/lib/libunused.dylib",
        TEXT_ADDRESS + 0x6000,
        macho::MH_DYLIB,
        &[("/usr/lib/not-in-cache.dylib", macho::LC_LOAD_DYLIB)],
    ),
    ("/usr/lib/libc_alias.dylib", TEXT_ADDRESS + 0x3000, 0, &[]),
    (
        "/usr/lib/libf.dylib",
        TEXT_ADDRESS + 0x7000,
        macho::MH_DYLIB,
        &[],
    ),
];

/// Write a Mach-O header with `__TEXT`, `LC_UUID`, `LC_ID_DYLIB` (dylibs only)
/// and dylib load commands at `offset`.
fn write_image(file: &mut [u8], offset: usize, image: &ImageSpec<'_>, uuid: u8) {
    let (path, address, file_type, dependencies) = *image;
    let mut commands = Vec::new();
    let mut segment = vec![0; SEGMENT_COMMAND_64_BYTES + SECTION_64_BYTES];
    put32(&mut segment, 0, macho::LC_SEGMENT_64);
    put32(
        &mut segment,
        4,
        (SEGMENT_COMMAND_64_BYTES + SECTION_64_BYTES) as u32,
    );
    segment[8..14].copy_from_slice(b"__TEXT");
    put64(&mut segment, 24, address);
    put64(&mut segment, 32, 0x1000);
    put32(&mut segment, 56, RX);
    put32(&mut segment, 60, RX);
    put32(&mut segment, 64, 1);
    let section = &mut segment[SEGMENT_COMMAND_64_BYTES..];
    section[..6].copy_from_slice(b"__text");
    section[16..22].copy_from_slice(b"__TEXT");
    put64(section, 32, address + TEXT_SECTION.start);
    put64(section, 40, TEXT_SECTION.end - TEXT_SECTION.start);
    put32(
        section,
        64,
        macho::S_ATTR_PURE_INSTRUCTIONS | macho::S_ATTR_SOME_INSTRUCTIONS,
    );
    commands.push(segment);
    let mut uuid_command = vec![0; UUID_COMMAND_BYTES];
    put32(&mut uuid_command, 0, macho::LC_UUID);
    put32(&mut uuid_command, 4, UUID_COMMAND_BYTES as u32);
    uuid_command[8..24].fill(uuid);
    commands.push(uuid_command);
    let dylib = |raw: u32, name: &str| {
        let (command, name_offset) = if raw & USE == 0 {
            (raw, DYLIB_COMMAND_BYTES)
        } else {
            (macho::LC_LOAD_DYLIB, DYLIB_USE_COMMAND_BYTES)
        };
        let size = (name_offset + name.len() + 1).next_multiple_of(8);
        let mut bytes = vec![0; size];
        put32(&mut bytes, 0, command);
        put32(&mut bytes, 4, size as u32);
        put32(&mut bytes, 8, name_offset as u32);
        if name_offset == DYLIB_USE_COMMAND_BYTES {
            put32(&mut bytes, 12, DYLIB_USE_MARKER);
            put32(&mut bytes, 24, raw & !USE);
        }
        bytes[name_offset..name_offset + name.len()].copy_from_slice(name.as_bytes());
        bytes
    };
    if file_type == macho::MH_DYLIB {
        commands.push(dylib(macho::LC_ID_DYLIB, path));
    }
    for (dependency, command) in dependencies {
        commands.push(dylib(*command, dependency));
    }
    let header = &mut file[offset..offset + MACH_HEADER_64_BYTES];
    put32(header, 0, macho::MH_MAGIC_64);
    put32(header, 4, macho::CPU_TYPE_ARM64);
    put32(header, 12, file_type);
    put32(header, 16, commands.len() as u32);
    put32(
        header,
        20,
        commands.iter().map(Vec::len).sum::<usize>() as u32,
    );
    let mut cursor = offset + MACH_HEADER_64_BYTES;
    for command in commands {
        file[cursor..cursor + command.len()].copy_from_slice(&command);
        cursor += command.len();
    }
}

/// A slide-info v5 blob for `page_starts` with `value_add`.
fn slide_info(page_size: u32, value_add: u64, page_starts: &[u16]) -> Vec<u8> {
    let mut bytes = vec![0; SLIDE_INFO_V5_HEADER_BYTES + 2 * page_starts.len()];
    put32(&mut bytes, 0, 5);
    put32(&mut bytes, 4, page_size);
    put32(&mut bytes, 8, page_starts.len() as u32);
    put64(&mut bytes, 16, value_add);
    for (index, start) in page_starts.iter().enumerate() {
        bytes[SLIDE_INFO_V5_HEADER_BYTES + 2 * index..][..2].copy_from_slice(&start.to_le_bytes());
    }
    bytes
}

struct Files {
    main: Vec<u8>,
    text: Vec<u8>,
    data: Vec<u8>,
}

fn files() -> Files {
    let mut main = cache_file(0x4000, MAIN_UUID, &[(REGION_START, 0x4000, 0, 0..0, 0, RX)]);
    put64(&mut main, HEADER_DYLD_IN_CACHE_MH, image_address(4));
    put32(&mut main, HEADER_SUBCACHE_ARRAY_OFFSET, SUBCACHES as u32);
    put32(&mut main, HEADER_SUBCACHE_ARRAY_OFFSET + 4, 2);
    for (index, (uuid, address, suffix)) in [
        (TEXT_UUID, TEXT_ADDRESS, ".01"),
        (DATA_UUID, DATA_ADDRESS, ".02.dylddata"),
    ]
    .iter()
    .enumerate()
    {
        let entry = SUBCACHES + index * SUBCACHE_ENTRY_BYTES;
        main[entry..entry + 16].copy_from_slice(uuid);
        put64(&mut main, entry + 16, address - REGION_START);
        main[entry + 24..entry + 24 + suffix.len()].copy_from_slice(suffix.as_bytes());
    }
    put32(&mut main, HEADER_IMAGES_OFFSET, IMAGES as u32);
    put32(
        &mut main,
        HEADER_IMAGES_OFFSET + 4,
        IMAGES_SPEC.len() as u32,
    );
    let mut path_offset = PATHS;
    for (index, (path, address, ..)) in IMAGES_SPEC.iter().enumerate() {
        let entry = IMAGES + index * IMAGE_INFO_BYTES;
        put64(&mut main, entry, *address);
        put32(&mut main, entry + 24, path_offset as u32);
        main[path_offset..path_offset + path.len()].copy_from_slice(path.as_bytes());
        path_offset += path.len() + 1;
    }

    let mut text = cache_file(
        TEXT_SIZE as usize,
        TEXT_UUID,
        &[(TEXT_ADDRESS, TEXT_SIZE, 0, 0..0, 0, RX)],
    );
    for (index, image) in IMAGES_SPEC.iter().enumerate() {
        if image.2 != 0 {
            let offset = (image.1 - TEXT_ADDRESS) as usize;
            write_image(&mut text, offset, image, index as u8);
        }
    }
    // Header mapping, then one DATA mapping whose slide info follows it.
    let slide_offset = DATA_HEADER_SIZE + DATA_SIZE;
    let info = slide_info(0x4000, 0, &[SLIDE_V5_PAGE_NO_REBASE]);
    let mut data = cache_file(
        (slide_offset as usize) + info.len(),
        DATA_UUID,
        &[
            (DATA_ADDRESS, DATA_HEADER_SIZE, 0, 0..0, 0, RX),
            (
                DATA_ADDRESS + DATA_HEADER_SIZE,
                DATA_SIZE,
                DATA_HEADER_SIZE,
                slide_offset..slide_offset + info.len() as u64,
                MappingFlags::CONST_DATA.bits(),
                RW,
            ),
        ],
    );
    data[slide_offset as usize..].copy_from_slice(&info);
    Files { main, text, data }
}

fn parse(files: &Files) -> Result<SharedCache<&[u8]>> {
    SharedCache::new(
        CacheFile::parse(files.main.as_slice())?,
        vec![
            CacheFile::parse(files.text.as_slice())?,
            CacheFile::parse(files.data.as_slice())?,
        ],
    )
}

#[test]
fn header_mappings_and_subcache_entries_parse() {
    let files = files();
    let main = CacheFile::parse(files.main.as_slice()).unwrap();
    let header = main.header();
    assert_eq!(header.mapping_offset, MAPPINGS as u32);
    assert_eq!(header.uuid, MAIN_UUID);
    assert_eq!(header.shared_region_start, REGION_START);
    assert_eq!(header.shared_region_size, REGION_SIZE);
    assert_eq!(header.dyld_in_cache_mh, image_address(4));
    assert_eq!(header.dynamic_data, Some((DYNAMIC_DATA_OFFSET, 0x4000)));
    assert_eq!(
        main.subcache_entries().unwrap(),
        [
            SubcacheEntry {
                uuid: TEXT_UUID,
                cache_vm_offset: TEXT_ADDRESS - REGION_START,
                file_suffix: ".01".into(),
            },
            SubcacheEntry {
                uuid: DATA_UUID,
                cache_vm_offset: DATA_ADDRESS - REGION_START,
                file_suffix: ".02.dylddata".into(),
            },
        ]
    );
    let data = CacheFile::parse(files.data.as_slice()).unwrap();
    let mapping = &data.mappings()[1];
    assert_eq!(
        mapping.address_range(),
        DATA_ADDRESS + DATA_HEADER_SIZE..DATA_ADDRESS + DATA_HEADER_SIZE + DATA_SIZE
    );
    assert_eq!(
        mapping.file_range(),
        DATA_HEADER_SIZE..DATA_HEADER_SIZE + DATA_SIZE
    );
    assert_eq!(mapping.flags, MappingFlags::CONST_DATA);
    assert_eq!(
        mapping.initial_protection,
        VmProtection::READ | VmProtection::WRITE
    );
    let info = data.slide_info(mapping).unwrap().unwrap();
    assert_eq!((info.page_size(), info.page_count()), (0x4000, 1));
    assert_eq!(info.page_start(0), Ok(None));
    assert_eq!(data.slide_info(&data.mappings()[0]), Ok(None));

    let cache = parse(&files).unwrap();
    assert_eq!(cache.files().len(), 3);
    assert_eq!(cache.images().len(), IMAGES_SPEC.len());
    assert_eq!(
        cache.image_index_by_path("/usr/lib/libc_alias.dylib"),
        Some(6)
    );
    assert_eq!(cache.dyld_image_index(), Some(4));
    let (file, mapping) = cache.mapping_containing(image_address(2), 8).unwrap();
    assert_eq!((file, mapping.address), (1, TEXT_ADDRESS));
    assert_eq!(
        cache.read_at_address(TEXT_ADDRESS, 16).unwrap(),
        CACHE_MAGIC_ARM64E
    );
    assert!(
        cache
            .mapping_containing(TEXT_ADDRESS + TEXT_SIZE - 4, 8)
            .is_none()
    );
    assert_eq!(
        cache.read_at_address(REGION_START + 0x3_f000, 1),
        Err(SharedCacheError::Unmapped {
            address: REGION_START + 0x3_f000,
            length: 1
        })
    );
    let image = cache.parse_image(image_address(0)).unwrap();
    assert_eq!(image.install_name.as_deref(), Some(LIBSYSTEM));
    assert_eq!(image.uuid, Some([0; 16]));
    let text = image.segment("__TEXT").unwrap();
    assert_eq!(
        text.address_range,
        image_address(0)..image_address(0) + 0x1000
    );
    let [section] = text.sections.as_slice() else {
        panic!("__TEXT has one section")
    };
    assert_eq!(section.name, "__text");
    assert_eq!(
        section.address_range,
        image_address(0) + TEXT_SECTION.start..image_address(0) + TEXT_SECTION.end
    );
    assert!(section.has_instructions());
    assert_eq!(
        image
            .dependencies
            .iter()
            .map(|dependency| dependency.attributes)
            .collect::<Vec<_>>(),
        [
            DylibAttributes::REEXPORT,
            DylibAttributes::empty(),
            DylibAttributes::WEAK,
            DylibAttributes::UPWARD,
            DylibAttributes::DELAYED_INIT,
            DylibAttributes::REEXPORT,
        ]
    );
    let dyld = cache.parse_image(image_address(4)).unwrap();
    assert_eq!(
        (dyld.file_type, dyld.install_name),
        (macho::MH_DYLINKER, None)
    );
    assert_eq!(dyld.dependencies, Vec::new());
}

#[test]
fn malformed_cache_files_are_rejected() {
    let reject = |mutate: &dyn Fn(&mut Files)| {
        let mut files = files();
        mutate(&mut files);
        parse(&files)
            .err()
            .expect("malformed cache must be rejected")
    };
    assert_eq!(
        reject(&|files| files.main.truncate(0x100)),
        SharedCacheError::Read {
            offset: 0,
            length: MAPPINGS
        }
    );
    assert!(matches!(
        reject(&|files| files.main[7] = b'2'),
        SharedCacheError::Unsupported(_)
    ));
    assert!(matches!(
        reject(&|files| put32(
            &mut files.main,
            HEADER_MAPPING_OFFSET,
            HEADER_CACHE_SUB_TYPE as u32
        )),
        SharedCacheError::Unsupported(_)
    ));
    assert!(matches!(
        reject(&|files| put32(&mut files.main, HEADER_MAPPING_OFFSET, u32::MAX)),
        SharedCacheError::Malformed(_)
    ));
    // Mapping file range past the end of the file.
    assert!(matches!(
        reject(&|files| put64(&mut files.text, MAPPINGS + 8, TEXT_SIZE + 1)),
        SharedCacheError::Malformed(_)
    ));
    // Address overflow.
    assert!(matches!(
        reject(&|files| put64(&mut files.text, MAPPINGS, u64::MAX - 1)),
        SharedCacheError::Malformed(_)
    ));
    // Overlapping mappings inside one file and across files.
    assert!(matches!(
        reject(&|files| put64(&mut files.data, MAPPINGS + 56, DATA_ADDRESS)),
        SharedCacheError::Malformed(_)
    ));
    assert!(matches!(
        reject(&|files| {
            put64(&mut files.text, MAPPINGS, REGION_START);
            put64(&mut files.main, SUBCACHES + 16, 0);
        }),
        SharedCacheError::Malformed("mappings outside the region or overlapping")
    ));
    // Outside the shared region.
    assert!(matches!(
        reject(&|files| {
            put64(&mut files.main, HEADER_SHARED_REGION_SIZE, 0x8000);
        }),
        SharedCacheError::Malformed("mappings outside the region or overlapping")
    ));
    // Unknown protection bits and mapping counts.
    assert!(matches!(
        reject(&|files| put32(&mut files.text, MAPPINGS + 52, 0x10)),
        SharedCacheError::Malformed(_)
    ));
    assert!(matches!(
        reject(&|files| put32(&mut files.text, HEADER_MAPPING_WITH_SLIDE_OFFSET + 4, 0)),
        SharedCacheError::Malformed(_)
    ));
    assert_eq!(
        reject(&|files| files.data[HEADER_UUID] ^= 1),
        SharedCacheError::SubcacheUuidMismatch { index: 1 }
    );
    assert!(matches!(
        reject(&|files| put64(&mut files.main, SUBCACHES + 16, 0)),
        SharedCacheError::Malformed(_)
    ));
    assert!(matches!(
        reject(&|files| files.main[SUBCACHES + 24..SUBCACHES + 28].copy_from_slice(b"/../")),
        SharedCacheError::Malformed(_)
    ));
    assert!(matches!(
        reject(&|files| files.main[SUBCACHES + 24..SUBCACHES + 56].fill(b'1')),
        SharedCacheError::Malformed(_)
    ));
    // Unterminated image path at the end of the main file.
    assert!(matches!(
        reject(&|files| {
            let end = files.main.len() - 1;
            files.main[end] = b'x';
            put32(&mut files.main, IMAGES + 24, end as u32);
        }),
        SharedCacheError::Malformed(_)
    ));
    assert!(matches!(
        reject(&|files| put32(&mut files.main, HEADER_IMAGES_OFFSET + 4, u32::MAX)),
        SharedCacheError::Malformed(_)
    ));
    let mut files = files();
    files.data.truncate(files.data.len() - 1);
    assert!(matches!(parse(&files), Err(SharedCacheError::Malformed(_))));
}

#[test]
fn malformed_images_are_rejected() {
    let mut files = files();
    let cache = parse(&files).unwrap();
    // Zero bytes inside an image are not a Mach header.
    assert!(matches!(
        cache.parse_image(image_address(0) + 0x800),
        Err(SharedCacheError::Malformed(_))
    ));
    let header = (image_address(0) - TEXT_ADDRESS) as usize;
    let first_command = header + MACH_HEADER_64_BYTES;
    for (offset, value) in [
        // Load command size not a multiple of 8, and beyond sizeofcmds.
        (first_command + 4, 70),
        (first_command + 4, 0x1000),
        // More commands than sizeofcmds holds.
        (header + 16, 100),
        // sizeofcmds beyond the mapping.
        (header + 20, 0x10_0000),
        // Section count beyond the segment command.
        (first_command + 64, 2),
        // Section extending beyond its segment.
        (first_command + 72 + 40, 0x1000),
        // Dylib name offset inside the fixed command fields.
        (first_command + 152 + 24 + 8, 8),
    ] {
        let original = files.text.clone();
        put32(&mut files.text, offset, value);
        let cache = parse(&files).unwrap();
        assert!(
            cache.parse_image(image_address(0)).is_err(),
            "offset {offset:#x} = {value:#x}"
        );
        files.text = original;
    }
    // Missing NUL in an install name.
    let id = first_command + 152 + 24;
    let size = u32::from_le_bytes(files.text[id + 4..id + 8].try_into().unwrap()) as usize;
    files.text[id + DYLIB_COMMAND_BYTES..id + size].fill(b'a');
    let cache = parse(&files).unwrap();
    assert!(cache.parse_image(image_address(0)).is_err());
}

/// A plain v5 chain entry; `next` counts 8-byte strides.
fn regular(target: u64, high8: u8, next: u64) -> u64 {
    target | (u64::from(high8) << 34) | (next << 52)
}

fn authenticated(target: u64, diversity: u16, address: bool, data: bool, next: u64) -> u64 {
    target
        | (u64::from(diversity) << 34)
        | (u64::from(address) << 50)
        | (u64::from(data) << 51)
        | (next << 52)
        | (1 << 63)
}

struct RecordingSigner(core::cell::RefCell<Vec<(u64, PointerAuthKey, u64)>>);

impl PointerSigner for RecordingSigner {
    fn sign(&self, value: u64, key: PointerAuthKey, discriminator: u64) -> u64 {
        self.0.borrow_mut().push((value, key, discriminator));
        value ^ 0x00a5_0000_0000_0000
    }
}

fn page_with(words: &[(usize, u64)]) -> Vec<u8> {
    let mut page = vec![0; 0x1000];
    for (offset, value) in words {
        put64(&mut page, *offset, *value);
    }
    page
}

#[test]
fn slide_v5_rebases_regular_and_authenticated_chains() {
    const VALUE_ADD: u64 = 0x1_8000_0000;
    const SLIDE: u64 = 0xe_8000_0000;
    const PAGE_ADDRESS: u64 = 0x10_0000_4000;
    let info = SlideInfoV5::parse(&slide_info(
        0x1000,
        VALUE_ADD,
        &[SLIDE_V5_PAGE_NO_REBASE, 0x10],
    ))
    .unwrap();
    assert_eq!(info.value_add(), VALUE_ADD);
    let original = page_with(&[
        (0x10, regular(0x1234, 0, 1)),
        (0x18, regular(0x2_0000_0000, 0x5a, 2)),
        (0x28, authenticated(0x3000, 0xbeef, true, false, 3)),
        (0x40, authenticated(0x4000, 0x1234, false, true, 0)),
        (0x48, 0xdead_beef),
    ]);
    let signer = RecordingSigner(core::cell::RefCell::new(Vec::new()));

    let mut page = original.clone();
    info.rebase_page(&mut page, 0, SLIDE, PAGE_ADDRESS, &signer)
        .unwrap();
    assert_eq!(page, original, "NO_REBASE pages are unchanged");

    info.rebase_page(&mut page, 1, SLIDE, PAGE_ADDRESS, &signer)
        .unwrap();
    let word = |offset: usize| u64::from_le_bytes(page[offset..offset + 8].try_into().unwrap());
    let base = VALUE_ADD + SLIDE;
    assert_eq!(word(0x10), base + 0x1234);
    assert_eq!(word(0x18), (base + 0x2_0000_0000) | (0x5a << 56));
    assert_eq!(word(0x28), (base + 0x3000) ^ 0x00a5_0000_0000_0000);
    assert_eq!(word(0x40), (base + 0x4000) ^ 0x00a5_0000_0000_0000);
    assert_eq!(word(0x48), 0xdead_beef, "chain ended before this slot");
    assert_eq!(
        *signer.0.borrow(),
        [
            (
                base + 0x3000,
                PointerAuthKey::Ia,
                blended_discriminator(PAGE_ADDRESS + 0x28, 0xbeef)
            ),
            (base + 0x4000, PointerAuthKey::Da, 0x1234),
        ]
    );
    assert_eq!(
        blended_discriminator(0xffff_1234_5678_9abc, 0xbeef),
        0xbeef_1234_5678_9abc
    );

    // Unsigned pointers keep authenticated values plain, as XNU without JOP keys.
    let mut page = original;
    info.rebase_page(&mut page, 1, SLIDE, PAGE_ADDRESS, &UnsignedPointers)
        .unwrap();
    assert_eq!(
        u64::from_le_bytes(page[0x28..0x30].try_into().unwrap()),
        base + 0x3000
    );
}

#[test]
fn slide_v5_rejects_chains_leaving_the_page_and_bad_input() {
    let info = SlideInfoV5::parse(&slide_info(0x1000, 0, &[0xff8, 0x10, 0xffc, 0x1000])).unwrap();
    // The second pointer would start at 0x1000, past the page.
    let original = page_with(&[(0xff8, regular(1, 0, 1))]);
    let mut page = original.clone();
    assert_eq!(
        info.rebase_page(&mut page, 0, 0, 0, &UnsignedPointers),
        Err(SharedCacheError::ChainOutOfPage {
            page_index: 0,
            offset: 0x1000
        })
    );
    assert_eq!(page, original, "failed rebases leave the page unchanged");
    // A long chain that runs off the page.
    let mut page = page_with(&[(0x10, regular(1, 0, 0x7ff))]);
    assert!(matches!(
        info.rebase_page(&mut page, 1, 0, 0, &UnsignedPointers),
        Err(SharedCacheError::ChainOutOfPage { .. })
    ));
    // Misaligned and out-of-page starts.
    for index in [2, 3] {
        let mut page = page_with(&[]);
        assert!(matches!(
            info.rebase_page(&mut page, index, 0, 0, &UnsignedPointers),
            Err(SharedCacheError::ChainOutOfPage { .. })
        ));
    }
    // Bad page index, page length and arithmetic overflow.
    let mut page = page_with(&[(0x10, regular(1, 0, 0))]);
    assert!(
        info.rebase_page(&mut page, 4, 0, 0, &UnsignedPointers)
            .is_err()
    );
    assert!(
        info.rebase_page(&mut page[..0x800], 1, 0, 0, &UnsignedPointers)
            .is_err()
    );
    assert!(
        info.rebase_page(&mut page, 1, u64::MAX, 0, &UnsignedPointers)
            .is_err()
    );
    // Header validation.
    let mut wrong_version = slide_info(0x1000, 0, &[0]);
    put32(&mut wrong_version, 0, 3);
    assert!(matches!(
        SlideInfoV5::parse(&wrong_version),
        Err(SharedCacheError::Unsupported(_))
    ));
    assert!(SlideInfoV5::parse(&slide_info(0x2000, 0, &[0])).is_err());
    let truncated = slide_info(0x1000, 0, &[0, 0]);
    assert!(SlideInfoV5::parse(&truncated[..truncated.len() - 1]).is_err());
    assert!(SlideInfoV5::parse(&truncated[..8]).is_err());
}

#[test]
fn slide_info_must_cover_its_mapping() {
    let mut files = files();
    let slide = (DATA_HEADER_SIZE + DATA_SIZE) as usize;
    files.data[slide..].copy_from_slice(&slide_info(0x1000, 0, &[SLIDE_V5_PAGE_NO_REBASE]));
    let data = CacheFile::parse(files.data.as_slice()).unwrap();
    assert!(matches!(
        data.slide_info(&data.mappings()[1]),
        Err(SharedCacheError::Malformed(_))
    ));
}

#[test]
fn dynamic_region_cache_path_is_bounded() {
    let mut region = vec![0u8; 0x100];
    region[..16].copy_from_slice(b"dyld_data    v3\0");
    put32(&mut region, 36, 0x80);
    let path = b"/System/Library/dyld/dyld_shared_cache_arm64e";
    region[0x80..0x80 + path.len()].copy_from_slice(path);
    assert_eq!(
        dynamic_region_cache_path(&region),
        Ok(core::str::from_utf8(path).unwrap())
    );
    for (offset, bytes) in [
        (0, &b"dyld_data    v1"[..]),
        (0, b"dyld_dota    v3"),
        (36, &0u32.to_le_bytes()),
        (36, &0x100u32.to_le_bytes()),
    ] {
        let mut copy = region.clone();
        copy[offset..offset + bytes.len()].copy_from_slice(bytes);
        assert!(dynamic_region_cache_path(&copy).is_err(), "{offset}");
    }
    region[0x80 + path.len()..].fill(b'a');
    assert!(dynamic_region_cache_path(&region).is_err());
}
