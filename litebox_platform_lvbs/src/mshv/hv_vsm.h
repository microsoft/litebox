/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2023, Microsoft Corporation.
 *
 * Author:
 *
 */

//! This file is originated from `lsg-linux-origin/project/lvbs/6.6`

#ifndef _HV_VSM_H
#define _HV_VSM_H

#define VSM_VTL_CALL_FUNC_ID_ENABLE_APS_VTL	0x1FFE0
#define VSM_VTL_CALL_FUNC_ID_BOOT_APS		0x1FFE1
#define VSM_VTL_CALL_FUNC_ID_LOCK_REGS		0x1FFE2
#define VSM_VTL_CALL_FUNC_ID_SIGNAL_END_OF_BOOT	0x1FFE3
#define VSM_VTL_CALL_FUNC_ID_PROTECT_MEMORY	0x1FFE4
#define VSM_VTL_CALL_FUNC_ID_LOAD_KDATA		0x1FFE5
#define VSM_VTL_CALL_FUNC_ID_VALIDATE_MODULE	0x1FFE6
#define VSM_VTL_CALL_FUNC_ID_FREE_MODULE_INIT	0x1FFE7
#define VSM_VTL_CALL_FUNC_ID_UNLOAD_MODULE	0x1FFE8
#define VSM_VTL_CALL_FUNC_ID_COPY_SECONDARY_KEY 0x1FFE9
#define VSM_VTL_CALL_FUNC_ID_KEXEC_VALIDATE	0x1FFEA

// #define HV_VTL1_IOCTL	0xE1
// #define HV_RETURN_TO_LOWER_VTL    _IO(HV_VTL1_IOCTL, 0)

#define VTL_ENTRY_REASON_LOWER_VTL_CALL     0x1
#define VTL_ENTRY_REASON_INTERRUPT          0x2
#define VTL_ENTRY_REASON_INTERCEPT          0x3

#define HV_PAGE_ACCESS_NONE		0x0
#define HV_PAGE_READABLE		0x1
#define HV_PAGE_WRITABLE		0x2
#define HV_PAGE_KERNEL_EXECUTABLE	0x4
#define HV_PAGE_USER_EXECUTABLE		0x8
#define HV_PAGE_EXECUTABLE		(HV_PAGE_KERNEL_EXECUTABLE | HV_PAGE_USER_EXECUTABLE)
#define HV_PAGE_FULL_ACCESS		(HV_PAGE_READABLE | HV_PAGE_WRITABLE | HV_PAGE_EXECUTABLE)

#define X86_CR4_VME             (1ul << 0)
#define X86_CR4_PVI             (1ul << 1)
#define X86_CR4_TSD             (1ul << 2)
#define X86_CR4_DE              (1ul << 3)
#define X86_CR4_PSE             (1ul << 4)
#define X86_CR4_PAE             (1ul << 5)
#define X86_CR4_MCE             (1ul << 6)
#define X86_CR4_PGE             (1ul << 7)
#define X86_CR4_PCE             (1ul << 8)
#define X86_CR4_OSFXSR          (1ul << 9)
#define X86_CR4_OSXMMEXCPT      (1ul << 10)
#define X86_CR4_UMIP            (1ul << 11)
#define X86_CR4_LA57            (1ul << 12)
#define X86_CR4_VMXE            (1ul << 13)
#define X86_CR4_SMXE            (1ul << 14)
#define X86_CR4_FSGSBASE        (1ul << 16)
#define X86_CR4_PCIDE           (1ul << 17)
#define X86_CR4_OSXSAVE         (1ul << 18)
#define X86_CR4_SMEP            (1ul << 20)
#define X86_CR4_SMAP            (1ul << 21)
#define X86_CR4_PKE             (1ul << 22)

#define X86_CR0_PE          (1UL<<0) /* Protection Enable */
#define X86_CR0_MP          (1UL<<1) /* Monitor Coprocessor */
#define X86_CR0_EM          (1UL<<2) /* Emulation */
#define X86_CR0_TS          (1UL<<3) /* Task Switched */
#define X86_CR0_ET          (1UL<<4) /* Extension Type */
#define X86_CR0_NE          (1UL<<5) /* Numeric Error */
#define X86_CR0_WP          (1UL<<16) /* Write Protect */
#define X86_CR0_AM          (1UL<<18) /* Alignment Mask */
#define X86_CR0_NW          (1UL<<29) /* Not Write-through */
#define X86_CR0_CD          (1UL<<30) /* Cache Disable */
#define X86_CR0_PG          (1UL<<31) /* Paging */

#define CR4_PIN_MASK ~(X86_CR4_MCE | X86_CR4_PGE | X86_CR4_PCE | X86_CR4_VMXE)
#define CR0_PIN_MASK (X86_CR0_PE | X86_CR0_WP | X86_CR0_PG)

/*
extern bool hv_vsm_boot_success;
extern bool hv_vsm_mbec_enabled;
extern union hv_register_vsm_code_page_offsets vsm_code_page_offsets;
extern struct resource sk_res;
*/

struct hv_vtlcall_param {
	u64	a0;
	u64	a1;
	u64	a2;
	u64	a3;
};
// } __packed;

union hv_register_vsm_code_page_offsets {
	u64 as_uint64;

	struct {
		u64 vtl_call_offset : 12;
		u64 vtl_return_offset : 12;
		u64 reserved_z : 40;
	};
};
// } __packed;

/*
int __init hv_vsm_init_heki(void);
int __hv_vsm_get_register(u32 reg_name, u64 *result, u8 input_vtl);
int __hv_vsm_set_register(u32 reg_name, u64 value, u8 input_vtl);
int hv_vsm_get_register(u32 reg_name, u64 *result);
int hv_vsm_set_register(u32 reg_name, u64 value);
int hv_vsm_get_code_page_offsets(void);
void __hv_vsm_vtlcall(struct hv_vtlcall_param *args);
*/

struct hv_intercept_message_header {
	u32 vp_index;
	u8 instruction_length;
	u8 intercept_access_type;
	/* ToDo: Define union for this */
	u16 execution_state;
	struct hv_x64_segment_register cs_segment;
	u64 rip;
	u64 rflags;
} __packed;

union hv_register_access_info {
	u64 reg_value_low;
	u64 reg_value_high;
	u32 reg_name;
	u64 src_addr;
	u64 dest_addr;
} __packed;

union hv_memory_access_info {
	u8 as_u8;
	struct {
		u8 gva_valid : 1;
		u8 gva_gpa_valid : 1;
		u8 hypercall_op_pending : 1;
		u8 tlb_blocked : 1;
		u8 supervisor_shadow_stack : 1;
		u8 verify_page_wr : 1;
		u8 reserved : 2;
	};
} __packed;

struct hv_intercept_message {
	struct hv_intercept_message_header hdr;
	u8 is_memory_op;
	u8 reserved_0;
	u16 reserved_1;
	u32 reg_name;
	union hv_register_access_info info;
} __packed;

struct hv_msr_intercept_message {
	struct hv_intercept_message_header hdr;
	u32 msr;
	u32 reserved_0;
	u64 rdx;
	u64 rax;
} __packed;

struct hv_mem_intercept_message {
	struct hv_intercept_message_header hdr;
	u32 cache_type;
	u8 instruction_byte_count;
	union hv_memory_access_info info;
	u8 tpr_priority;
	u8 reserved;
	u64 gva;
	u64 gpa;
	u8 instr_bytes[16];
} __packed;

union hv_register_vsm_vp_secure_vtl_config {
	u64 as_u64;
	struct {
		u64 mbec_enabled : 1;
		u64 tlb_locked : 1;
		u64 reserved: 62;
	};
};

union hv_register_vsm_partition_config {
	__u64 as_u64;
	struct {
		__u64 enable_vtl_protection : 1;
		__u64 default_vtl_protection_mask : 4;
		__u64 zero_memory_on_reset : 1;
		__u64 deny_lower_vtl_startup : 1;
		__u64 intercept_acceptance : 1;
		__u64 intercept_enable_vtl_protection : 1;
		__u64 intercept_vp_startup : 1;
		__u64 intercept_cpuid_unimplemented : 1;
		__u64 intercept_unrecoverable_exception : 1;
		__u64 intercept_page : 1;
		__u64 mbz : 51;
	};
};

struct hv_input_modify_vtl_protection_mask {
	u64 partition_id;
	u32 map_flags;
	union hv_input_vtl target_vtl;
	u8 reserved8_z;
	u16 reserved16_z;
	// __aligned(8) u64 gpa_page_list[];
};

#endif /* _HV_VSM_H */
