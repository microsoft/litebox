// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Darwin startup stack.
//!
//! Static `LC_UNIXTHREAD` entry points receive `argc` at SP. For dyld, the
//! kernel's `mainExecutable` Mach header pointer precedes `argc`.

use super::{MachoLoaderError, STACK_SIZE};
use crate::ShimPlatform;
use alloc::{ffi::CString, vec, vec::Vec};
use litebox_common_macos::{STACK_ALIGNMENT, user_pointers::UserPtrMut};

// argc and the terminators for argv, envp and apple.
const FIXED_STACK_WORDS: usize = 4;

pub(super) fn initialize<P: ShimPlatform>(
    base: usize,
    argv: &[CString],
    envp: &[CString],
    apple: &[CString],
    main_executable: Option<usize>,
) -> Result<usize, MachoLoaderError> {
    let (bytes, offset) = stack_image(base, STACK_SIZE, argv, envp, apple, main_executable)?;
    UserPtrMut::from_usize(base + offset)
        .copy_from_slice::<P>(0, &bytes)
        .ok_or(MachoLoaderError::Memory)?;
    Ok(base + offset)
}

fn stack_image(
    base: usize,
    size: usize,
    argv: &[CString],
    envp: &[CString],
    apple: &[CString],
    main_executable: Option<usize>,
) -> Result<(Vec<u8>, usize), MachoLoaderError> {
    use MachoLoaderError::ArgumentsTooLarge;
    debug_assert!(base.is_multiple_of(STACK_ALIGNMENT));
    base.checked_add(size).ok_or(ArgumentsTooLarge)?;
    let pointer_bytes = argv
        .len()
        .checked_add(envp.len())
        .and_then(|n| n.checked_add(apple.len()))
        .and_then(|n| n.checked_add(FIXED_STACK_WORDS))
        .and_then(|n| n.checked_add(usize::from(main_executable.is_some())))
        .and_then(|n| n.checked_mul(size_of::<usize>()))
        .ok_or(ArgumentsTooLarge)?;
    let string_bytes = argv
        .iter()
        .chain(envp)
        .chain(apple)
        .try_fold(0usize, |size, string| {
            size.checked_add(string.as_bytes_with_nul().len())
        })
        .ok_or(ArgumentsTooLarge)?;
    let sp = size
        .checked_sub(string_bytes)
        .and_then(|position| position.checked_sub(pointer_bytes))
        .ok_or(ArgumentsTooLarge)?
        & !(STACK_ALIGNMENT - 1);
    // Unused stack bytes are already zero-filled by the anonymous mapping.
    let mut bytes = vec![0u8; size - sp];
    let mut position = bytes.len();
    let mut pointers = Vec::with_capacity(pointer_bytes / size_of::<usize>());
    if let Some(main_executable) = main_executable {
        pointers.push(main_executable);
    }
    pointers.push(argv.len());
    for strings in [argv, envp, apple] {
        for string in strings {
            let data = string.as_bytes_with_nul();
            position = position.checked_sub(data.len()).ok_or(ArgumentsTooLarge)?;
            bytes[position..position + data.len()].copy_from_slice(data);
            pointers.push(base + sp + position);
        }
        pointers.push(0);
    }
    for (slot, value) in bytes[..pointer_bytes]
        .as_chunks_mut::<{ size_of::<usize>() }>()
        .0
        .iter_mut()
        .zip(pointers)
    {
        slot.copy_from_slice(&value.to_le_bytes());
    }
    Ok((bytes, sp))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn static_stack_layout() {
        const BASE: usize = litebox_common_macos::PAGE_SIZE;
        const SMALL_STACK_SIZE: usize = 256;
        let argv = [
            CString::new("program").unwrap(),
            CString::new("arg").unwrap(),
        ];
        let env = [CString::new("KEY=VALUE").unwrap()];
        let apple = [CString::new("executable_path=/program").unwrap()];
        let (bytes, sp) = stack_image(BASE, SMALL_STACK_SIZE, &argv, &env, &apple, None).unwrap();
        assert_eq!(sp % STACK_ALIGNMENT, 0);
        let word_count = FIXED_STACK_WORDS + argv.len() + env.len() + apple.len();
        let words: Vec<_> = bytes[..word_count * size_of::<usize>()]
            .as_chunks::<{ size_of::<usize>() }>()
            .0
            .iter()
            .map(|w| usize::from_le_bytes(*w))
            .collect();
        assert_eq!(words[0], argv.len());
        let mut index = 1; // skip argc
        for strings in [&argv[..], &env[..], &apple[..]] {
            for string in strings {
                let pos = words[index] - (BASE + sp);
                assert_eq!(
                    &bytes[pos..pos + string.as_bytes_with_nul().len()],
                    string.as_bytes_with_nul()
                );
                index += 1;
            }
            assert_eq!(words[index], 0);
            index += 1;
        }
        assert_eq!(index, words.len());
        let (large, large_sp) = stack_image(BASE, STACK_SIZE, &argv, &env, &apple, None).unwrap();
        assert_eq!(large.len(), bytes.len());
        assert_eq!(large_sp + large.len(), STACK_SIZE);
        for (base, size) in [
            (0, FIXED_STACK_WORDS * size_of::<usize>() - 1),
            (usize::MAX & !(STACK_ALIGNMENT - 1), SMALL_STACK_SIZE),
        ] {
            assert!(matches!(
                stack_image(base, size, &argv, &env, &apple, None),
                Err(MachoLoaderError::ArgumentsTooLarge)
            ));
        }
        let (empty, sp) = stack_image(BASE, STACK_SIZE, &[], &[], &[], None).unwrap();
        assert_eq!(empty, [0; FIXED_STACK_WORDS * size_of::<usize>()]);
        assert_eq!(sp, STACK_SIZE - empty.len());
    }
}
