// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

pub(crate) mod file;
pub(crate) mod mm;
pub(crate) mod nls;
pub(crate) mod registry;
pub(crate) mod sysinfo;

use litebox::platform::{RawConstPointer as _, RawPointerProvider};
use litebox::utils::TruncateExt as _;
use litebox_common_windows::NtSysno;
use litebox_common_windows::nt_status::NtStatus;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

use crate::nt_types;

const FIRST_STACK_ARGUMENT_OFFSET: usize = 0x28;
const HANDLE_SHIFT: u32 = 2;
const HANDLE_TAG_MASK: usize = (1usize << HANDLE_SHIFT) - 1;

#[repr(transparent)]
#[derive(
    Clone, Copy, Debug, Default, Eq, PartialEq, FromBytes, IntoBytes, Immutable, KnownLayout,
)]
pub(crate) struct Handle(usize);

impl Handle {
    #[must_use]
    pub(crate) const fn from_raw(raw: usize) -> Self {
        Self(raw)
    }

    #[must_use]
    pub(crate) fn from_raw_fd(raw_fd: usize) -> Option<Self> {
        raw_fd
            .checked_add(1)?
            .checked_mul(1usize << HANDLE_SHIFT)
            .map(Self)
    }

    #[must_use]
    pub(crate) fn raw_fd(self) -> Option<usize> {
        if self.0 & HANDLE_TAG_MASK != 0 {
            return None;
        }
        (self.0 >> HANDLE_SHIFT).checked_sub(1)
    }

    #[must_use]
    pub(crate) const fn as_raw(self) -> usize {
        self.0
    }

    #[must_use]
    pub(crate) const fn is_null(self) -> bool {
        self.as_raw() == 0
    }
}

#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct ProcessHandle(Handle);

impl ProcessHandle {
    pub(crate) const CURRENT: Self = Self::from_raw(usize::MAX);

    #[must_use]
    pub(crate) const fn from_raw(raw: usize) -> Self {
        Self(Handle::from_raw(raw))
    }

    #[must_use]
    pub(crate) const fn is_null(self) -> bool {
        self.0.is_null()
    }

    #[must_use]
    pub(crate) fn is_current(self) -> bool {
        self == Self::CURRENT
    }
}

#[allow(clippy::enum_variant_names)]
#[derive(Debug)]
pub(crate) enum SyscallRequest<Platform: RawPointerProvider> {
    NtClose {
        handle: Handle,
    },
    NtOpenFile {
        file_handle: Platform::RawMutPointer<Handle>,
        desired_access: u32,
        object_attributes: Option<Platform::RawConstPointer<nt_types::ObjectAttributes>>,
        io_status_block: Platform::RawMutPointer<nt_types::IoStatusBlock>,
        share_access: u32,
        open_options: u32,
    },
    NtCreateFile {
        file_handle: Platform::RawMutPointer<Handle>,
        desired_access: u32,
        object_attributes: Option<Platform::RawConstPointer<nt_types::ObjectAttributes>>,
        io_status_block: Platform::RawMutPointer<nt_types::IoStatusBlock>,
        allocation_size: Option<Platform::RawConstPointer<i64>>,
        file_attributes: u32,
        share_access: u32,
        create_disposition: u32,
        create_options: u32,
        ea_buffer: Option<Platform::RawConstPointer<u8>>,
        ea_length: u32,
    },
    NtOpenKey {
        key_handle: Platform::RawMutPointer<Handle>,
        desired_access: u32,
        object_attributes: Option<Platform::RawConstPointer<nt_types::ObjectAttributes>>,
    },
    NtQueryValueKey {
        key_handle: Handle,
        value_name: Platform::RawConstPointer<nt_types::UnicodeString>,
        key_value_information_class: u32,
        key_value_information: Platform::RawMutPointer<u8>,
        length: u32,
        result_length: Platform::RawMutPointer<u32>,
    },
    NtGetNlsSectionPtr {
        section_type: u32,
        section_data: u32,
        context_data: usize,
        section_pointer: Platform::RawMutPointer<usize>,
        section_size: Option<Platform::RawMutPointer<u32>>,
    },
    NtInitializeNlsFiles {
        base_address: Platform::RawMutPointer<usize>,
        default_locale_id: Platform::RawMutPointer<u32>,
        default_casing_table_size: Platform::RawMutPointer<i64>,
    },
    NtQueryDefaultLocale {
        user_profile: u8,
        default_locale_id: Platform::RawMutPointer<u32>,
    },
    NtSetDefaultLocale {
        user_profile: u8,
        default_locale_id: u32,
    },
    NtQueryDefaultUILanguage {
        default_ui_language: Platform::RawMutPointer<u16>,
    },
    NtSetDefaultUILanguage {
        default_ui_language: u16,
    },
    NtQueryInstallUILanguage {
        install_ui_language: Platform::RawMutPointer<u16>,
    },
    NtQueryPerformanceCounter {
        performance_counter: Platform::RawMutPointer<i64>,
        performance_frequency: Option<Platform::RawMutPointer<i64>>,
    },
    NtConvertBetweenAuxiliaryCounterAndPerformanceCounter {
        flag: u32,
        source: Platform::RawConstPointer<u64>,
        destination: Platform::RawMutPointer<u64>,
        conversion_error: Option<Platform::RawMutPointer<u64>>,
    },
    NtAllocateVirtualMemory {
        process_handle: ProcessHandle,
        base_address: Platform::RawMutPointer<usize>,
        zero_bits: usize,
        region_size: Platform::RawMutPointer<usize>,
        allocation_type: u32,
        protect: u32,
    },
    NtAllocateVirtualMemoryEx {
        process_handle: ProcessHandle,
        base_address: Platform::RawMutPointer<usize>,
        region_size: Platform::RawMutPointer<usize>,
        allocation_type: u32,
        protect: u32,
        extended_parameters: Option<Platform::RawConstPointer<mm::MemoryExtendedParameter>>,
        extended_parameter_count: u32,
    },
    NtFreeVirtualMemory {
        process_handle: ProcessHandle,
        base_address: Platform::RawMutPointer<usize>,
        region_size: Platform::RawMutPointer<usize>,
        free_type: u32,
    },
    NtProtectVirtualMemory {
        process_handle: ProcessHandle,
        base_address: Platform::RawMutPointer<usize>,
        region_size: Platform::RawMutPointer<usize>,
        new_protect: u32,
        old_protect: Platform::RawMutPointer<u32>,
    },
    NtQueryVirtualMemory {
        process_handle: ProcessHandle,
        base_address: usize,
        memory_information_class: u32,
        memory_information: Platform::RawMutPointer<u8>,
        memory_information_length: usize,
        return_length: Option<Platform::RawMutPointer<usize>>,
    },
    NtTerminateProcess {
        process_handle: ProcessHandle,
        exit_status: i32,
    },
}

impl<Platform: RawPointerProvider> SyscallRequest<Platform> {
    pub(crate) fn try_from_raw(pt_regs: &litebox_common_linux::PtRegs) -> Option<Self> {
        macro_rules! sys_req {
            ($id:ident { $( $field:ident $(:$star:tt)? ),* $(,)? }) => {
                sys_req!(@[$id] [ $( $field $(:$star)? ),* ] [ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 ] [ ])
            };
            (@[$id:ident] [ $f:ident $(,)? $($field:ident $(:$star:tt)?),* ] [ $n:literal $(,)? $($ns:literal),* ] [ $($tail:tt)* ]) => {
                sys_req!(@[$id] [ $( $field $(:$star)? ),* ] [ $($ns),* ] [ $($tail)* $f: win_sys_req_arg::<Platform, _>(pt_regs, $n)?, ])
            };
            (@[$id:ident] [ $f:ident : * $(,)? $($field:ident $(:$star:tt)?),* ] [ $n:literal $(,)? $($ns:literal),* ] [ $($tail:tt)* ]) => {
                sys_req!(@[$id] [ $( $field $(:$star)? ),* ] [ $($ns),* ] [ $($tail)* $f: win_sys_req_ptr::<Platform, _, _>(pt_regs, $n)?, ])
            };
            (@[$id:ident] [ $f:ident : { $expr:expr } $(,)? $($field:ident $(:$star:tt)?),* ] [ $n:literal $(,)? $($ns:literal),* ] [ $($tail:tt)* ]) => {
                sys_req!(@[$id] [ $( $field $(:$star)? ),* ] [ $($ns),* ] [ $($tail)* $f: ($expr)(win_sys_req_arg::<Platform, _>(pt_regs, $n)?), ])
            };
            (@[$id:ident] [ ] [ $($ns:literal),* ] [ $($tail:tt)* ]) => {
                SyscallRequest::$id { $($tail)* }
            };
        }

        match NtSysno::from_raw(pt_regs.orig_rax)? {
            NtSysno::NtClose => Some(sys_req!(NtClose {
                handle: { Handle::from_raw },
            })),
            NtSysno::NtOpenFile => Some(sys_req!(NtOpenFile {
                file_handle:*,
                desired_access,
                object_attributes:*,
                io_status_block:*,
                share_access,
                open_options,
            })),
            NtSysno::NtCreateFile => Some(sys_req!(NtCreateFile {
                file_handle:*,
                desired_access,
                object_attributes:*,
                io_status_block:*,
                allocation_size:*,
                file_attributes,
                share_access,
                create_disposition,
                create_options,
                ea_buffer:*,
                ea_length,
            })),
            NtSysno::NtOpenKey => Some(sys_req!(NtOpenKey {
                key_handle:*,
                desired_access,
                object_attributes:*,
            })),
            NtSysno::NtQueryValueKey => Some(sys_req!(NtQueryValueKey {
                key_handle:{Handle::from_raw},
                value_name:*,
                key_value_information_class,
                key_value_information:*,
                length,
                result_length:*,
            })),
            NtSysno::NtGetNlsSectionPtr => Some(sys_req!(NtGetNlsSectionPtr {
                section_type,
                section_data,
                context_data,
                section_pointer:*,
                section_size:*,
            })),
            NtSysno::NtInitializeNlsFiles => Some(sys_req!(NtInitializeNlsFiles {
                base_address:*,
                default_locale_id:*,
                default_casing_table_size:*,
            })),
            NtSysno::NtQueryDefaultLocale => Some(sys_req!(NtQueryDefaultLocale {
                user_profile,
                default_locale_id:*,
            })),
            NtSysno::NtSetDefaultLocale => Some(sys_req!(NtSetDefaultLocale {
                user_profile,
                default_locale_id,
            })),
            NtSysno::NtQueryDefaultUILanguage => Some(sys_req!(NtQueryDefaultUILanguage {
                default_ui_language:*,
            })),
            NtSysno::NtSetDefaultUILanguage => Some(sys_req!(NtSetDefaultUILanguage {
                default_ui_language,
            })),
            NtSysno::NtQueryInstallUILanguage => Some(sys_req!(NtQueryInstallUILanguage {
                install_ui_language:*,
            })),
            NtSysno::NtQueryPerformanceCounter => Some(sys_req!(NtQueryPerformanceCounter {
                performance_counter:*,
                performance_frequency:*,
            })),
            NtSysno::NtConvertBetweenAuxiliaryCounterAndPerformanceCounter => Some(
                sys_req!(NtConvertBetweenAuxiliaryCounterAndPerformanceCounter {
                    flag,
                    source:*,
                    destination:*,
                    conversion_error:*,
                }),
            ),
            NtSysno::NtAllocateVirtualMemory => Some(sys_req!(NtAllocateVirtualMemory {
                process_handle: { ProcessHandle::from_raw },
                base_address:*,
                zero_bits,
                region_size:*,
                allocation_type,
                protect,
            })),
            NtSysno::NtAllocateVirtualMemoryEx => Some(sys_req!(NtAllocateVirtualMemoryEx {
                process_handle: { ProcessHandle::from_raw },
                base_address:*,
                region_size:*,
                allocation_type,
                protect,
                extended_parameters:*,
                extended_parameter_count,
            })),
            NtSysno::NtFreeVirtualMemory => Some(sys_req!(NtFreeVirtualMemory {
                process_handle: { ProcessHandle::from_raw },
                base_address:*,
                region_size:*,
                free_type,
            })),
            NtSysno::NtProtectVirtualMemory => Some(sys_req!(NtProtectVirtualMemory {
                process_handle: { ProcessHandle::from_raw },
                base_address:*,
                region_size:*,
                new_protect,
                old_protect:*,
            })),
            NtSysno::NtQueryVirtualMemory => Some(sys_req!(NtQueryVirtualMemory {
                process_handle: { ProcessHandle::from_raw },
                base_address,
                memory_information_class,
                memory_information:*,
                memory_information_length,
                return_length:*,
            })),
            NtSysno::NtTerminateProcess => Some(sys_req!(NtTerminateProcess {
                process_handle: { ProcessHandle::from_raw },
                exit_status,
            })),
            _ => None,
        }
    }
}

fn win_syscall_arg<Platform: RawPointerProvider>(
    pt_regs: &litebox_common_linux::PtRegs,
    idx: usize,
) -> Option<usize> {
    match idx {
        0 => Some(pt_regs.r10),
        1 => Some(pt_regs.rdx),
        2 => Some(pt_regs.r8),
        3 => Some(pt_regs.r9),
        idx => {
            // The first stack argument sits after the return address and x64 shadow space.
            let stack_offset = FIRST_STACK_ARGUMENT_OFFSET
                .checked_add((idx - 4).checked_mul(size_of::<usize>())?)?;
            let stack_address = pt_regs.rsp.checked_add(stack_offset)?;
            let stack_arg = Platform::RawConstPointer::<usize>::from_usize(stack_address);
            stack_arg.read_at_offset(0)
        }
    }
}

fn win_sys_req_arg<Platform: RawPointerProvider, T: ReinterpretTruncatedFromUsize>(
    pt_regs: &litebox_common_linux::PtRegs,
    idx: usize,
) -> Option<T> {
    Some(T::reinterpret_truncated_from_usize(win_syscall_arg::<
        Platform,
    >(pt_regs, idx)?))
}

fn win_sys_req_ptr<
    Platform: RawPointerProvider,
    T: zerocopy::FromBytes,
    P: ReinterpretUsizeAsPtr<T>,
>(
    pt_regs: &litebox_common_linux::PtRegs,
    idx: usize,
) -> Option<P> {
    Some(P::reinterpret_usize_as_ptr(win_syscall_arg::<Platform>(
        pt_regs, idx,
    )?))
}

trait ReinterpretTruncatedFromUsize: Sized {
    fn reinterpret_truncated_from_usize(value: usize) -> Self;
}

impl ReinterpretTruncatedFromUsize for usize {
    fn reinterpret_truncated_from_usize(value: usize) -> Self {
        value
    }
}

impl ReinterpretTruncatedFromUsize for u64 {
    fn reinterpret_truncated_from_usize(value: usize) -> Self {
        value as u64
    }
}

impl ReinterpretTruncatedFromUsize for isize {
    fn reinterpret_truncated_from_usize(value: usize) -> Self {
        value.cast_signed()
    }
}

impl ReinterpretTruncatedFromUsize for NtStatus {
    fn reinterpret_truncated_from_usize(value: usize) -> Self {
        Self::from_raw(value.trunc())
    }
}

macro_rules! reinterpret_truncated_unsigned {
    ($($ty:ty),* $(,)?) => {
        $(
            impl ReinterpretTruncatedFromUsize for $ty {
                fn reinterpret_truncated_from_usize(value: usize) -> Self {
                    value.trunc()
                }
            }
        )*
    };
}

macro_rules! reinterpret_truncated_signed {
    ($($sty:ty),* $(,)?) => {
        $(
            impl ReinterpretTruncatedFromUsize for $sty {
                fn reinterpret_truncated_from_usize(value: usize) -> Self {
                    value.cast_signed().trunc()
                }
            }
        )*
    };
}

reinterpret_truncated_unsigned!(u8, u16, u32);
reinterpret_truncated_signed!(i8, i16, i32);

trait ReinterpretUsizeAsPtr<T>: Sized {
    fn reinterpret_usize_as_ptr(value: usize) -> Self;
}

impl<T: zerocopy::FromBytes, P: litebox::platform::RawConstPointer<T>>
    ReinterpretUsizeAsPtr<core::marker::PhantomData<((), T)>> for P
{
    fn reinterpret_usize_as_ptr(value: usize) -> Self {
        P::from_usize(value)
    }
}

impl<T: zerocopy::FromBytes, P: litebox::platform::RawConstPointer<T>>
    ReinterpretUsizeAsPtr<core::marker::PhantomData<(bool, T)>> for Option<P>
{
    fn reinterpret_usize_as_ptr(value: usize) -> Self {
        if value == 0 {
            None
        } else {
            Some(P::from_usize(value))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handle_encodes_raw_fds_and_rejects_invalid_values() {
        let first_handle = Handle::from_raw_fd(0).expect("raw fd 0 should encode");
        assert_eq!(first_handle, Handle::from_raw(1usize << HANDLE_SHIFT));
        assert_eq!(first_handle.raw_fd(), Some(0));

        let max_raw_fd = (usize::MAX >> HANDLE_SHIFT) - 1;
        for raw_fd in [1, 42, max_raw_fd] {
            let handle = Handle::from_raw_fd(raw_fd).expect("raw fd should encode");
            assert_eq!(handle.raw_fd(), Some(raw_fd));
        }

        assert_eq!(Handle::from_raw(0).raw_fd(), None);

        for tag in 1..=HANDLE_TAG_MASK {
            assert_eq!(Handle::from_raw(tag).raw_fd(), None);
            assert_eq!(
                Handle::from_raw((2usize << HANDLE_SHIFT) | tag).raw_fd(),
                None
            );
        }

        assert_eq!(Handle::from_raw_fd(usize::MAX >> HANDLE_SHIFT), None);
        assert_eq!(Handle::from_raw_fd(usize::MAX), None);
    }
}
