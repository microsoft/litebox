#![expect(dead_code)]

// SM Termination constants
/// 15
pub(crate) const SM_SEV_TERM_SET: u64 = 0x3;
/// 0
pub(crate) const SM_TERM_GENERAL: u64 = 0;
/// 1
pub(crate) const SM_TERM_NOT_VMPL0: u64 = 1;
/// 2
pub(crate) const SM_TERM_UNHANDLED_VC: u64 = 2;
/// 3
pub(crate) const SM_TERM_PSC_ERROR: u64 = 3;
/// 4
pub(crate) const SM_TERM_SET_PAGE_ERROR: u64 = 4;
/// 5
pub(crate) const SM_TERM_NO_GHCB: u64 = 5;
/// 6
pub(crate) const SM_TERM_GHCB_RESP_INVALID: u64 = 6;
/// 7
pub(crate) const SM_TERM_INVALID_PARAM: u64 = 7;
/// 8
pub(crate) const SM_TERM_PVALIDATE: u64 = 8;
/// 9
pub(crate) const SM_TERM_ENOMEM: u64 = 9;
/// 10
pub(crate) const SM_TERM_EXCEPTION: u64 = 10;
/// 11
pub(crate) const SM_TERM_UNHANDLED_SYSCALL: u64 = 11;
