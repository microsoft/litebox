// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use litebox::utils::TruncateExt as _;

use crate::arch::{
    PhysAddr, VirtAddr,
    instructions::{rdmsr, vc_vmgexit, wrmsr},
};

// GHCB MSR
const GHCB_MSR: u32 = 0xc0010130;
// GHCB Protocols
const GHCB_HV_DEBUG: u64 = 0xf03;

const GHCB_VERSION_1: u16 = 1;
const GHCB_SEV_INFO: u64 = 0x001;
const GHCB_SEV_INFO_REQ: u64 = 0x002;
const GHCB_REGISTER_GPA_REQ: u64 = 0x012;
const GHCB_REGISTER_GPA_RESP: u64 = 0x013;
const HV_X64_MSR_GUEST_OS_ID: u32 = 0x40000000;

const SVM_EXIT_MSR: u64 = 0x07c;

// LiteBox OS ID: use some random number for now
const LITEBOX_OS_ID: u64 = 0x123;

fn str2u64(s: &str, start: usize, size: usize) -> u64 {
    let mut buf = [0u8; 8];
    buf[0..size].copy_from_slice(&s.as_bytes()[start..(start + size)]);
    u64::from_le_bytes(buf)
}

pub fn ghcb_prints(s: &str) {
    let mut index = 0;
    let n = s.len();
    let orig_val: u64 = rdmsr(GHCB_MSR);
    while index < n {
        let len = 6.min(n - index);
        let mut val = GHCB_HV_DEBUG;
        val |= str2u64(s, index, len) << 16;
        wrmsr(GHCB_MSR, val);
        vc_vmgexit();
        index += len;
    }
    // restore ghcb msr val
    wrmsr(GHCB_MSR, orig_val);
}

fn ghcb_msr_call(request: u64) -> u64 {
    // Save the current GHCB MSR value
    let value: u64 = rdmsr(GHCB_MSR);

    // Perform the MSR protocol
    wrmsr(GHCB_MSR, request);
    vc_vmgexit();
    let response = rdmsr(GHCB_MSR);

    // Restore the GHCB MSR value
    wrmsr(GHCB_MSR, value);

    response
}

fn num_to_char(n: u8) -> u8 {
    if n < 10 { n + b'0' } else { n - 10 + b'a' }
}

pub fn num_to_buf(buf: &mut [u8; 40], mut n: u64, base: u64) -> usize {
    let mut i = 0;
    if n == 0 {
        buf[i] = num_to_char(0);
        i += 1;
    }
    while n > 0 {
        buf[i] = num_to_char((n % base).truncate());
        n /= base;
        i += 1;
    }
    i
}

#[macro_export]
macro_rules! print_int {
    ($num: expr, $base: expr) => {{
        let mut _buf = [0u8; 40];
        let i = $crate::host::snp::ghcb::num_to_buf(&mut _buf, $num, $base);
        let slice = &mut _buf[..i];
        slice.reverse();
        let s = core::str::from_utf8(&*slice).unwrap();
        $crate::host::snp::ghcb::ghcb_prints(s);
    }};
}

#[macro_export]
macro_rules! print_str_and_int {
    ($str: expr, $num: expr, $base: expr) => {{
        $crate::host::snp::ghcb::ghcb_prints($str);
        $crate::print_int!($num, $base);
        $crate::host::snp::ghcb::ghcb_prints("\n");
    }};
}

// See GHCB layout
pub const SNP_VMPL_GHCB_RAX_OFFSET: u64 = 0x1f8;
pub const SNP_VMPL_GHCB_RCX_OFFSET: u64 = 0x308;
pub const SNP_VMPL_GHCB_RDX_OFFSET: u64 = 0x310;
pub const SNP_VMPL_GHCB_SW_EXIT_CODE_OFFSET: u64 = 0x390;
pub const SNP_VMPL_GHCB_SW_EXIT_INFO_1_OFFSET: u64 = 0x398;
pub const SNP_VMPL_GHCB_SW_EXIT_INFO_2_OFFSET: u64 = 0x3a0;

macro_rules! ghcb_fns {
    ($name: ident, $valty: tt) => {
        paste::paste! {
        pub fn [<set_ $name>](&mut self, value: $valty) {
            self.vmsa.[<$name>] = value;
            self.set_offset_valid([<SNP_VMPL_GHCB_ $name:upper _OFFSET>]);
        }
        }
    };
}

macro_rules! ghcb_fns_u64 {
    ($name: ident) => {
        ghcb_fns! {$name, u64}
    };
}

pub const SHARED_BUFFER_SIZE: usize = 2032;

#[repr(C, packed)]
struct GhcbPage {
    vmsa: super::vmsa::Vmsa,
    valid_bitmap: [u8; 16],
    reserved6: [u8; 1024],
    shared_buffer: [u8; SHARED_BUFFER_SIZE],
    reserved7: [u8; 10],
    version: u16,
    usage: u32,
}

impl GhcbPage {
    ghcb_fns_u64!(rax);

    ghcb_fns_u64!(rcx);

    ghcb_fns_u64!(rdx);

    ghcb_fns_u64!(sw_exit_code);

    ghcb_fns_u64!(sw_exit_info_1);

    ghcb_fns_u64!(sw_exit_info_2);

    fn get_ghcb_page(va: VirtAddr) -> &'static mut GhcbPage {
        unsafe { &mut *(va.as_u64() as *mut GhcbPage) }
    }

    fn reset(&mut self) {
        self.vmsa.sw_exit_code = 0;
        self.valid_bitmap.fill(0);
    }

    /// GHCB page-based communication must set bitmap correctly.
    fn set_offset_valid(&mut self, offset: u64) {
        let idx: u8 = ((offset / 8) / 8).truncate();
        let bit: u8 = ((offset / 8) % 8).truncate();
        let oldv: u8 = self.valid_bitmap[idx as usize];
        let newv = oldv | (1u8 << (bit));
        self.valid_bitmap[idx as usize] = newv;
    }

    fn page_vc_proto(&mut self, exit: u64, exit1: u64, exit2: u64) -> Option<()> {
        self.version = GHCB_VERSION_1;
        self.usage = 0; // GHCB_DEFAULT_USAGE

        self.set_sw_exit_code(exit);
        self.set_sw_exit_info_1(exit1);
        self.set_sw_exit_info_2(exit2);
        vc_vmgexit();

        // Perform a volatile read to prevent the compiler from optimizing out the check
        let sw_exit_info_1 =
            unsafe { core::ptr::read_volatile(core::ptr::addr_of!(self.vmsa.sw_exit_info_1)) };
        if sw_exit_info_1 & 0xffffffff == 1 {
            ghcb_prints("page_vc_proto: failed to handle request");
            return None;
        }
        Some(())
    }
}

/// 0xfff
const GHCB_MSR_INFO_MASK: u64 = 0xfff;

pub struct GhcbProtocol;

impl GhcbProtocol {
    fn ghcb_write_msr(va: VirtAddr, reg: u32, val: u64) -> Option<()> {
        let ghcb_page = GhcbPage::get_ghcb_page(va);
        ghcb_page.reset();

        ghcb_page.set_rcx(u64::from(reg));

        let low_val: u32 = val.truncate();
        let high_val: u32 = (val >> 32).truncate();
        ghcb_page.set_rax(u64::from(low_val));
        ghcb_page.set_rdx(u64::from(high_val));

        ghcb_page.page_vc_proto(SVM_EXIT_MSR, 1, 0)
    }

    fn sev_es_negotiate_protocol() -> Option<()> {
        let val = ghcb_msr_call(GHCB_SEV_INFO_REQ);
        let code = val & GHCB_MSR_INFO_MASK;
        if code != GHCB_SEV_INFO {
            print_str_and_int!("Failed to negotiate GHCB protocol: ", val, 16);
            return None;
        }
        Some(())
    }

    pub fn setup_ghcb_page(pa: PhysAddr, va: VirtAddr) -> Option<()> {
        Self::sev_es_negotiate_protocol()?;

        let val = ghcb_msr_call(GHCB_REGISTER_GPA_REQ | pa.as_u64());
        let code = val & GHCB_MSR_INFO_MASK;
        let ret_pa = val & !GHCB_MSR_INFO_MASK;
        if code != GHCB_REGISTER_GPA_RESP || ret_pa != pa.as_u64() {
            print_str_and_int!("code: ", code, 16);
            print_str_and_int!("ret_pa: ", ret_pa, 16);
            return None;
        }

        // specify the guest physical address of the GHCB page
        // so that the hypervisor can identify it
        crate::arch::instructions::wrmsr(GHCB_MSR, pa.as_u64());

        Self::ghcb_write_msr(va, HV_X64_MSR_GUEST_OS_ID, LITEBOX_OS_ID)
    }
}
