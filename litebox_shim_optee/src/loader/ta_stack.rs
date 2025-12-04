//! This module manages the stack layout for TA (stack and `UteeParams`).

use litebox::{
    mm::linux::CreatePagesFlags,
    platform::{RawConstPointer, RawMutPointer},
};
use litebox_common_optee::{LdelfArg, TeeParamType, UteeParamOwned, UteeParams};

use crate::{UserMutPtr, litebox_page_manager};

#[inline]
fn align_down(addr: usize, align: usize) -> usize {
    debug_assert!(align.is_power_of_two());
    addr & !(align - 1)
}

/// the user stack for OP-TEE TAs. Unlike Linux/libc, OP-TEE TAs do not assume
/// any specific stack layout (i.e., no argc, argv, envp, ...). Instead, it does
/// use `UteeParams` to pass input and out parameters. `UteeParams` supports
/// passing both value and memory reference parameters. We repurpose a specific
/// stack area (i.e., above the stack pointer) to allocate corresponding memory
/// buffers to copy in/out data (if exist) and to store `UteeParams`.
///
/// Our TA stack layout is as follows:
/// ```text
///                           STACK LAYOUT
/// position            content                     size (bytes) + comment
/// ------------------------------------------------------------------------
/// stack pointer ->    [ padding ]                 0 - 16
///                     [ canary  ]                 16
///                     [ buffer_3 ]                >= 0
///                     [ buffer_2 ]                >= 0
///                     [ buffer_1 ]                >= 0
///                     [ buffer_0 ]                >= 0
/// rdx           ->    [ `UteeParams::types`]      8   (bitfield)
///                     [ `UteeParams::vals[0]`]    16  (two u64 values or
///                     [ `UteeParams::vals[1]`]    16   address and size)
///                     [ `UteeParams::vals[2]`]    16
///                     [ `UteeParams::vals[3]`]    16
///                     < bottom of stack >         0   (virtual)
/// ------------------------------------------------------------------------
/// ```
/// - rdi: function ID
/// - rsi: session ID
/// - rcx: command ID
///
/// NOTE: The above layout diagram is for 64-bit processes.
pub struct TaStack {
    /// The top of the stack (base address)
    stack_top: UserMutPtr<u8>,
    /// The length of the stack
    len: usize,
    /// The current position of the stack pointer
    pos: usize,
    /// `UteeParams` to be stored on the stack
    params: UteeParams,
    /// The number of parameters stored (<= 4)
    num_params: usize,
}

impl TaStack {
    /// Stack alignment required by libc ABI (not for TAs but for compatibility)
    const STACK_ALIGNMENT: usize = 16;

    /// Create a new stack for the user process.
    ///
    /// `stack_top` and `len` must be aligned to [`Self::STACK_ALIGNMENT`]
    pub(super) fn new(stack_top: UserMutPtr<u8>, len: usize) -> Option<Self> {
        if !stack_top.as_usize().is_multiple_of(Self::STACK_ALIGNMENT)
            || !len.is_multiple_of(Self::STACK_ALIGNMENT)
        {
            return None;
        }
        Some(Self {
            stack_top,
            len,
            pos: len - core::mem::size_of::<UteeParams>(),
            params: UteeParams::new(),
            num_params: 0,
        })
    }

    /// Get the current stack pointer.
    pub fn get_cur_stack_top(&self) -> usize {
        self.stack_top.as_usize() + self.pos
    }

    pub(crate) fn get_stack_base(&self) -> usize {
        self.stack_top.as_usize()
    }

    /// Get the address of `UteeParams` on the stack.
    pub(crate) fn get_params_address(&self) -> usize {
        self.stack_top.as_usize() + self.len - core::mem::size_of::<UteeParams>()
    }

    /// Get the address of `LdelfArg` on the stack.
    pub(crate) fn get_ldelf_arg_address(&self) -> usize {
        self.stack_top.as_usize() + self.len - core::mem::size_of::<LdelfArg>()
    }

    /// Push `bytes` to the stack.
    ///
    /// Returns `None` if stack has no enough space.
    fn push_bytes(&mut self, bytes: &[u8]) -> Option<()> {
        self.pos = self.pos.checked_sub(bytes.len())?;
        self.stack_top.copy_from_slice(self.pos, bytes)?;
        Some(())
    }

    /// Push a parameter whose type is `TeeParamType::None` to the stack.
    fn push_param_none(&mut self) -> Option<()> {
        if self.num_params >= UteeParams::TEE_NUM_PARAMS {
            return None;
        }
        self.params
            .set_type(self.num_params, TeeParamType::None)
            .ok()?;
        self.num_params += 1;
        Some(())
    }

    /// Push a parameter whose type is `TeeParamType::Value*` to the stack.
    fn push_param_values(
        &mut self,
        param_type: TeeParamType,
        values: Option<(u64, u64)>,
    ) -> Option<()> {
        if self.num_params >= UteeParams::TEE_NUM_PARAMS {
            return None;
        }
        match param_type {
            TeeParamType::ValueInput | TeeParamType::ValueInout => {
                if let Some((value_a, value_b)) = values {
                    self.params
                        .set_values(self.num_params, value_a, value_b)
                        .ok()?;
                } else {
                    return None;
                }
            }
            TeeParamType::ValueOutput => {}
            _ => return None,
        }
        self.params.set_type(self.num_params, param_type).ok()?;
        self.num_params += 1;
        Some(())
    }

    /// Push a parameter whose type is `TeeParamType::Memref*` (i.e., buffer) to the stack.
    fn push_param_memref(
        &mut self,
        param_type: TeeParamType,
        bytes: Option<&[u8]>,
        len: usize,
    ) -> Option<()> {
        if self.num_params >= UteeParams::TEE_NUM_PARAMS {
            return None;
        }
        match param_type {
            TeeParamType::MemrefInput | TeeParamType::MemrefInout => {
                if let Some(bytes) = bytes {
                    if len > bytes.len() {
                        self.pos = self.pos.checked_sub(len - bytes.len())?;
                    }
                    self.push_bytes(bytes)?;
                    self.params
                        .set_values(
                            self.num_params,
                            u64::try_from(self.get_cur_stack_top()).unwrap(),
                            u64::try_from(len).unwrap(),
                        )
                        .ok()?;
                } else {
                    return None;
                }
            }
            TeeParamType::MemrefOutput => {
                self.pos = self.pos.checked_sub(len)?;
                self.params
                    .set_values(
                        self.num_params,
                        u64::try_from(self.get_cur_stack_top()).unwrap(),
                        u64::try_from(len).unwrap(),
                    )
                    .ok()?;
            }
            _ => {
                return None;
            }
        }
        self.params.set_type(self.num_params, param_type).ok()?;
        self.num_params += 1;
        Some(())
    }

    /// Set `UteeParams` on the stack.
    fn set_utee_params(&mut self) -> Option<()> {
        let size = core::mem::size_of::<UteeParams>();
        let bytes = unsafe {
            core::slice::from_raw_parts(core::ptr::from_ref(&self.params).cast::<u8>(), size)
        };
        self.stack_top.copy_from_slice(self.len - size, bytes)?;
        Some(())
    }

    pub(crate) fn init(&mut self, params: &[UteeParamOwned]) -> Option<()> {
        if params.len() > UteeParams::TEE_NUM_PARAMS {
            return None;
        }
        for param in params {
            match param {
                UteeParamOwned::ValueInput { value_a, value_b } => {
                    self.push_param_values(TeeParamType::ValueInput, Some((*value_a, *value_b)))?;
                }
                UteeParamOwned::ValueOutput { out_address: _ } => {
                    self.push_param_values(TeeParamType::ValueOutput, None)?;
                }
                UteeParamOwned::ValueInout {
                    value_a,
                    value_b,
                    out_address: _,
                } => {
                    self.push_param_values(TeeParamType::ValueInout, Some((*value_a, *value_b)))?;
                }
                UteeParamOwned::MemrefInput { data } => {
                    self.push_param_memref(TeeParamType::MemrefInput, Some(data), data.len())?;
                }
                UteeParamOwned::MemrefInout {
                    data,
                    buffer_size,
                    out_addresses: _,
                } => {
                    self.push_param_memref(TeeParamType::MemrefInout, Some(data), *buffer_size)?;
                }
                UteeParamOwned::MemrefOutput {
                    buffer_size,
                    out_addresses: _,
                } => {
                    self.push_param_memref(TeeParamType::MemrefOutput, None, *buffer_size)?;
                }
                UteeParamOwned::None => self.push_param_none()?,
            }
        }

        self.set_utee_params()?;

        // TODO: generate a random value
        self.push_bytes(&[
            0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD,
            0xBE, 0xEF,
        ])?;

        // ensure stack is aligned
        self.pos = align_down(self.pos, Self::STACK_ALIGNMENT);
        assert_eq!(self.pos, align_down(self.pos, Self::STACK_ALIGNMENT));
        Some(())
    }

    pub(crate) fn init_with_ldelf_arg(&mut self, ldelf_arg: &LdelfArg) -> Option<()> {
        self.push_bytes(unsafe {
            core::slice::from_raw_parts(
                core::ptr::from_ref(ldelf_arg).cast::<u8>(),
                core::mem::size_of::<LdelfArg>(),
            )
        })?;

        self.pos = align_down(self.pos, Self::STACK_ALIGNMENT);
        assert_eq!(self.pos, align_down(self.pos, Self::STACK_ALIGNMENT));
        Some(())
    }
}

/// Allocate stack pages for a TA session. if `sp` is `Some`, it re-uses the allocated stack pages.
///
/// # Safety
/// The caller must ensure that `sp` is a valid stack pointer and is not currently used.
/// Normally, `sp` should be the return value of this function's previous call (with `None`).
pub(crate) fn allocate_stack(stack_base: Option<usize>) -> Option<TaStack> {
    let sp = if let Some(stack_base) = stack_base {
        UserMutPtr::from_usize(stack_base)
    } else {
        let length = litebox::mm::linux::NonZeroPageSize::new(super::DEFAULT_STACK_SIZE)
            .expect("DEFAULT_STACK_SIZE is not page-aligned");
        unsafe {
            litebox_page_manager()
                .create_stack_pages(None, length, CreatePagesFlags::empty())
                .ok()?
        }
    };
    let stack = TaStack::new(sp, super::DEFAULT_STACK_SIZE)?;

    Some(stack)
}
