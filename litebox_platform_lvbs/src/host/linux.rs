//! Linux Structs

/// Context saved when entering the kernel
///
/// pt_regs from [Linux](https://elixir.bootlin.com/linux/v5.19.17/source/arch/x86/include/asm/ptrace.h#L12)
#[allow(non_camel_case_types)]
#[repr(C, packed)]
pub struct pt_regs {
    /*
     * C ABI says these regs are callee-preserved. They aren't saved on kernel entry
     * unless syscall needs a complete, fully filled "struct pt_regs".
     */
    pub r15: u64,
    pub r14: u64,
    pub r13: u64,
    pub r12: u64,
    pub rbp: u64,
    pub rbx: u64,
    /* These regs are callee-clobbered. Always saved on kernel entry. */
    pub r11: u64,
    pub r10: u64,
    pub r9: u64,
    pub r8: u64,
    pub rax: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,

    /*
     * On syscall entry, this is syscall#. On CPU exception, this is error code.
     * On hw interrupt, it's IRQ number:
     */
    pub orig_rax: u64,
    /* Return frame for iretq */
    pub rip: u64,
    pub cs: u64,
    pub eflags: u64,
    pub rsp: u64,
    pub ss: u64,
    /* top of stack page */
}

/// timespec from [Linux](https://elixir.bootlin.com/linux/v5.19.17/source/include/uapi/linux/time.h#L11)
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct Timespec {
    /// Seconds.
    pub tv_sec: i64,

    /// Nanoseconds. Must be less than 1_000_000_000.
    pub tv_nsec: i64,
}

#[allow(non_camel_case_types)]
pub type sigset_t = ::core::ffi::c_ulong;

const CONFIG_NR_CPUS: usize = 512;
const BITS_PER_LONG: usize = 64;

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct CpuMask {
    bits: [u64; CONFIG_NR_CPUS.div_ceil(BITS_PER_LONG)],
}

impl CpuMask {
    #[expect(dead_code)]
    fn new() -> Self {
        CpuMask {
            bits: [0; CONFIG_NR_CPUS.div_ceil(BITS_PER_LONG)],
        }
    }

    pub fn decode_cpu_mask(&self) -> [bool; CONFIG_NR_CPUS] {
        let mut cpu_mask = [false; CONFIG_NR_CPUS];
        for (i, &word) in self.bits.iter().enumerate() {
            for j in 0..BITS_PER_LONG {
                if (word & (1 << j)) != 0 {
                    cpu_mask[i * BITS_PER_LONG + j] = true;
                }
            }
        }

        cpu_mask
    }
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
#[derive(Debug, Clone, Copy)]
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
