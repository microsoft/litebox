// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#include <Hypervisor/Hypervisor.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <os/object.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#if !defined(__arm64__)
#error "the LiteBox Hypervisor.framework boundary requires arm64"
#endif

#if __MAC_OS_X_VERSION_MAX_ALLOWED < 260000
#error "the LiteBox Hypervisor.framework boundary requires the macOS 26 SDK"
#endif

_Static_assert(sizeof(uintptr_t) <= sizeof(size_t),
               "monitor address deltas must fit in size_t");

enum {
    LITEBOX_HVF_ABI_VERSION = 1,
    LITEBOX_HVF_EXIT_MALFORMED = 0,
    LITEBOX_HVF_EXIT_CANCELED = 1,
    LITEBOX_HVF_EXIT_EXCEPTION = 2,
    LITEBOX_HVF_EXIT_VTIMER = 3,
    LITEBOX_HVF_EXIT_UNKNOWN = 4,
};

typedef struct {
    uint8_t bytes[16];
} litebox_hvf_simd128_t;

typedef struct {
    uint32_t abi_version;
    uint32_t byte_size;
    uint64_t x[31];
    litebox_hvf_simd128_t q[32];
    uint64_t fpcr;
    uint64_t fpsr;
    uint64_t tpidr_el0;
    uint64_t sp_el0;
    uint64_t sp_el1;
    uint64_t pc;
    uint64_t cpsr;
    uint64_t spsr_el1;
    uint64_t elr_el1;
    uint64_t esr_el1;
    uint64_t far_el1;
} litebox_hvf_arch_state_t;

typedef struct {
    uint32_t abi_version;
    uint32_t byte_size;
    uint64_t sctlr_el1;
    uint64_t cpacr_el1;
    uint64_t ttbr0_el1;
    uint64_t ttbr1_el1;
    uint64_t tcr_el1;
    uint64_t mair_el1;
    uint64_t vbar_el1;
    uint64_t cntkctl_el1;
    uint64_t cntv_ctl_el0;
    uint64_t cntv_cval_el0;
    uint64_t tpidr_el1;
    uint64_t contextidr_el1;
    uint64_t mdscr_el1;
} litebox_hvf_el1_state_t;

typedef struct {
    uint32_t abi_version;
    uint32_t byte_size;
    uint32_t kind;
    uint32_t raw_reason;
    uint64_t syndrome;
    uint64_t virtual_address;
    uint64_t physical_address;
} litebox_hvf_exit_t;

_Static_assert(sizeof(litebox_hvf_simd128_t) == 16,
               "stable SIMD slot size changed");
_Static_assert(offsetof(litebox_hvf_arch_state_t, x) == 8,
               "stable architecture-state X offset changed");
_Static_assert(offsetof(litebox_hvf_arch_state_t, q) == 256,
               "stable architecture-state Q offset changed");
_Static_assert(offsetof(litebox_hvf_arch_state_t, fpcr) == 768,
               "stable architecture-state scalar offset changed");
_Static_assert(sizeof(litebox_hvf_arch_state_t) == 856,
               "stable architecture-state size changed");
_Static_assert(sizeof(litebox_hvf_el1_state_t) == 112,
               "stable EL1-state size changed");
_Static_assert(sizeof(litebox_hvf_exit_t) == 40,
               "stable exit size changed");
_Static_assert(HV_EXIT_REASON_CANCELED == 0,
               "active SDK canceled exit reason changed");
_Static_assert(HV_EXIT_REASON_EXCEPTION == 1,
               "active SDK exception exit reason changed");
_Static_assert(HV_EXIT_REASON_VTIMER_ACTIVATED == 2,
               "active SDK vtimer exit reason changed");
_Static_assert(HV_EXIT_REASON_UNKNOWN == 3,
               "active SDK unknown exit reason changed");

extern const uint8_t litebox_hvf_monitor_start[];
extern const uint8_t litebox_hvf_monitor_syscall[];
extern const uint8_t litebox_hvf_monitor_resume[];
extern const uint8_t litebox_hvf_monitor_synchronize[];
extern const uint8_t litebox_hvf_monitor_end[];

static const hv_reg_t litebox_general_regs[31] API_AVAILABLE(macos(26.0)) = {
    HV_REG_X0,  HV_REG_X1,  HV_REG_X2,  HV_REG_X3,  HV_REG_X4,
    HV_REG_X5,  HV_REG_X6,  HV_REG_X7,  HV_REG_X8,  HV_REG_X9,
    HV_REG_X10, HV_REG_X11, HV_REG_X12, HV_REG_X13, HV_REG_X14,
    HV_REG_X15, HV_REG_X16, HV_REG_X17, HV_REG_X18, HV_REG_X19,
    HV_REG_X20, HV_REG_X21, HV_REG_X22, HV_REG_X23, HV_REG_X24,
    HV_REG_X25, HV_REG_X26, HV_REG_X27, HV_REG_X28, HV_REG_X29,
    HV_REG_X30,
};

static const hv_simd_fp_reg_t litebox_simd_regs[32]
    API_AVAILABLE(macos(26.0)) = {
        HV_SIMD_FP_REG_Q0,  HV_SIMD_FP_REG_Q1,  HV_SIMD_FP_REG_Q2,
        HV_SIMD_FP_REG_Q3,  HV_SIMD_FP_REG_Q4,  HV_SIMD_FP_REG_Q5,
        HV_SIMD_FP_REG_Q6,  HV_SIMD_FP_REG_Q7,  HV_SIMD_FP_REG_Q8,
        HV_SIMD_FP_REG_Q9,  HV_SIMD_FP_REG_Q10, HV_SIMD_FP_REG_Q11,
        HV_SIMD_FP_REG_Q12, HV_SIMD_FP_REG_Q13, HV_SIMD_FP_REG_Q14,
        HV_SIMD_FP_REG_Q15, HV_SIMD_FP_REG_Q16, HV_SIMD_FP_REG_Q17,
        HV_SIMD_FP_REG_Q18, HV_SIMD_FP_REG_Q19, HV_SIMD_FP_REG_Q20,
        HV_SIMD_FP_REG_Q21, HV_SIMD_FP_REG_Q22, HV_SIMD_FP_REG_Q23,
        HV_SIMD_FP_REG_Q24, HV_SIMD_FP_REG_Q25, HV_SIMD_FP_REG_Q26,
        HV_SIMD_FP_REG_Q27, HV_SIMD_FP_REG_Q28, HV_SIMD_FP_REG_Q29,
        HV_SIMD_FP_REG_Q30, HV_SIMD_FP_REG_Q31,
    };

static const hv_sys_reg_t litebox_pac_key_regs[10]
    API_AVAILABLE(macos(26.0)) = {
        HV_SYS_REG_APIAKEYLO_EL1, HV_SYS_REG_APIAKEYHI_EL1,
        HV_SYS_REG_APIBKEYLO_EL1, HV_SYS_REG_APIBKEYHI_EL1,
        HV_SYS_REG_APDAKEYLO_EL1, HV_SYS_REG_APDAKEYHI_EL1,
        HV_SYS_REG_APDBKEYLO_EL1, HV_SYS_REG_APDBKEYHI_EL1,
        HV_SYS_REG_APGAKEYLO_EL1, HV_SYS_REG_APGAKEYHI_EL1,
    };

static const hv_feature_reg_t litebox_feature_regs[] API_AVAILABLE(macos(26.0)) = {
    HV_FEATURE_REG_ID_AA64DFR0_EL1,
    HV_FEATURE_REG_ID_AA64DFR1_EL1,
    HV_FEATURE_REG_ID_AA64ISAR0_EL1,
    HV_FEATURE_REG_ID_AA64ISAR1_EL1,
    HV_FEATURE_REG_ID_AA64MMFR0_EL1,
    HV_FEATURE_REG_ID_AA64MMFR1_EL1,
    HV_FEATURE_REG_ID_AA64MMFR2_EL1,
    HV_FEATURE_REG_ID_AA64PFR0_EL1,
    HV_FEATURE_REG_ID_AA64PFR1_EL1,
    HV_FEATURE_REG_CTR_EL0,
    HV_FEATURE_REG_CLIDR_EL1,
    HV_FEATURE_REG_DCZID_EL0,
    HV_FEATURE_REG_ID_AA64SMFR0_EL1,
    HV_FEATURE_REG_ID_AA64ZFR0_EL1,
};

typedef struct {
    size_t feature_index;
    hv_sys_reg_t system_register;
} litebox_hvf_feature_sys_reg_t;

static const litebox_hvf_feature_sys_reg_t litebox_feature_sys_regs[]
    API_AVAILABLE(macos(26.0)) = {
        {0, HV_SYS_REG_ID_AA64DFR0_EL1},
        {1, HV_SYS_REG_ID_AA64DFR1_EL1},
        {2, HV_SYS_REG_ID_AA64ISAR0_EL1},
        {3, HV_SYS_REG_ID_AA64ISAR1_EL1},
        {4, HV_SYS_REG_ID_AA64MMFR0_EL1},
        {5, HV_SYS_REG_ID_AA64MMFR1_EL1},
        {6, HV_SYS_REG_ID_AA64MMFR2_EL1},
        {7, HV_SYS_REG_ID_AA64PFR0_EL1},
        {8, HV_SYS_REG_ID_AA64PFR1_EL1},
        {12, HV_SYS_REG_ID_AA64SMFR0_EL1},
        {13, HV_SYS_REG_ID_AA64ZFR0_EL1},
    };

uint32_t litebox_hvf_sdk_max_allowed(void) {
    return __MAC_OS_X_VERSION_MAX_ALLOWED;
}

uint8_t litebox_hvf_runtime_is_macos_26_or_newer(void) {
    if (__builtin_available(macOS 26.0, *)) {
        return 1;
    }
    return 0;
}

uint8_t litebox_hvf_return_is_success(hv_return_t result) {
    return result == HV_SUCCESS;
}

uint8_t litebox_hvf_return_is_denied(hv_return_t result) {
    return result == HV_DENIED;
}

void litebox_hvf_monitor_layout(const uint8_t **start, size_t *length,
                                size_t *syscall_offset, size_t *resume_offset,
                                size_t *synchronize_offset) {
    const uintptr_t start_address = (uintptr_t)litebox_hvf_monitor_start;
    const uintptr_t syscall_address = (uintptr_t)litebox_hvf_monitor_syscall;
    const uintptr_t resume_address = (uintptr_t)litebox_hvf_monitor_resume;
    const uintptr_t synchronize_address =
        (uintptr_t)litebox_hvf_monitor_synchronize;
    const uintptr_t end_address = (uintptr_t)litebox_hvf_monitor_end;
    *start = litebox_hvf_monitor_start;
    if (end_address < start_address || syscall_address < start_address ||
        syscall_address >= end_address || resume_address < start_address ||
        resume_address >= end_address || synchronize_address < start_address ||
        synchronize_address >= end_address) {
        *length = SIZE_MAX;
        *syscall_offset = SIZE_MAX;
        *resume_offset = SIZE_MAX;
        *synchronize_offset = SIZE_MAX;
        return;
    }
    *length = (size_t)(end_address - start_address);
    *syscall_offset = (size_t)(syscall_address - start_address);
    *resume_offset = (size_t)(resume_address - start_address);
    *synchronize_offset = (size_t)(synchronize_address - start_address);
}

int32_t litebox_hvf_host_remap(uintptr_t source, uintptr_t destination,
                               size_t size, uint8_t copy) {
    mach_vm_address_t target = (mach_vm_address_t)destination;
    vm_prot_t current_protection = VM_PROT_NONE;
    vm_prot_t maximum_protection = VM_PROT_NONE;
    kern_return_t result = mach_vm_remap(
        mach_task_self(), &target, (mach_vm_size_t)size, 0,
        VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE, mach_task_self(),
        (mach_vm_address_t)source, copy != 0, &current_protection,
        &maximum_protection, VM_INHERIT_NONE);
    if (result == KERN_SUCCESS && target != (mach_vm_address_t)destination) {
        (void)mach_vm_deallocate(mach_task_self(), target,
                                 (mach_vm_size_t)size);
        return KERN_FAILURE;
    }
    return result;
}

#pragma clang attribute push(__attribute__((availability(macos, introduced = 26.0))), \
                             apply_to = function)

void *litebox_hvf_vm_config_create(void) {
    return hv_vm_config_create();
}

void *litebox_hvf_vcpu_config_create(void) {
    return hv_vcpu_config_create();
}

void litebox_hvf_vm_config_release(void *object) {
    os_release((hv_vm_config_t)object);
}

void litebox_hvf_vcpu_config_release(void *object) {
    os_release((hv_vcpu_config_t)object);
}

hv_return_t litebox_hvf_vm_config_get_max_ipa_size(uint32_t *bits) {
    return hv_vm_config_get_max_ipa_size(bits);
}

hv_return_t litebox_hvf_vm_config_set_ipa_size(void *config, uint32_t bits) {
    return hv_vm_config_set_ipa_size((hv_vm_config_t)config, bits);
}

hv_return_t litebox_hvf_vm_config_get_ipa_size(void *config, uint32_t *bits) {
    return hv_vm_config_get_ipa_size((hv_vm_config_t)config, bits);
}

hv_return_t litebox_hvf_vm_config_set_ipa_granule_16k(void *config) {
    return hv_vm_config_set_ipa_granule((hv_vm_config_t)config, HV_IPA_GRANULE_16KB);
}

hv_return_t litebox_hvf_vm_config_get_ipa_granule(void *config, uint32_t *raw,
                                                   uint8_t *is_16k) {
    hv_ipa_granule_t granule = HV_IPA_GRANULE_4KB;
    hv_return_t result = hv_vm_config_get_ipa_granule((hv_vm_config_t)config, &granule);
    if (result == HV_SUCCESS) {
        *raw = (uint32_t)granule;
        *is_16k = granule == HV_IPA_GRANULE_16KB;
    }
    return result;
}

hv_return_t litebox_hvf_vm_config_get_el2_supported(uint8_t *supported) {
    bool value = false;
    hv_return_t result = hv_vm_config_get_el2_supported(&value);
    if (result == HV_SUCCESS) {
        *supported = value;
    }
    return result;
}

hv_return_t litebox_hvf_vm_config_set_el2_disabled(void *config) {
    return hv_vm_config_set_el2_enabled((hv_vm_config_t)config, false);
}

hv_return_t litebox_hvf_vm_config_get_el2_enabled(void *config, uint8_t *enabled) {
    bool value = false;
    hv_return_t result = hv_vm_config_get_el2_enabled((hv_vm_config_t)config, &value);
    if (result == HV_SUCCESS) {
        *enabled = value;
    }
    return result;
}

hv_return_t litebox_hvf_vm_get_max_vcpu_count(uint32_t *count) {
    return hv_vm_get_max_vcpu_count(count);
}

hv_return_t litebox_hvf_vm_create(void *config) {
    return hv_vm_create((hv_vm_config_t)config);
}

hv_return_t litebox_hvf_vm_destroy(void) {
    return hv_vm_destroy();
}

static hv_return_t litebox_hvf_memory_flags(uint8_t permissions,
                                             hv_memory_flags_t *flags) {
    if ((permissions & (uint8_t)~0x7u) != 0) {
        return HV_BAD_ARGUMENT;
    }
    *flags = 0;
    if ((permissions & 0x1u) != 0) {
        *flags |= HV_MEMORY_READ;
    }
    if ((permissions & 0x2u) != 0) {
        *flags |= HV_MEMORY_WRITE;
    }
    if ((permissions & 0x4u) != 0) {
        *flags |= HV_MEMORY_EXEC;
    }
    return HV_SUCCESS;
}

hv_return_t litebox_hvf_vm_map(void *address, uint64_t ipa, size_t size,
                               uint8_t permissions) {
    hv_memory_flags_t flags = 0;
    hv_return_t result = litebox_hvf_memory_flags(permissions, &flags);
    if (result != HV_SUCCESS) {
        return result;
    }
    return hv_vm_map(address, ipa, size, flags);
}

hv_return_t litebox_hvf_vm_protect(uint64_t ipa, size_t size,
                                   uint8_t permissions) {
    hv_memory_flags_t flags = 0;
    hv_return_t result = litebox_hvf_memory_flags(permissions, &flags);
    if (result != HV_SUCCESS) {
        return result;
    }
    return hv_vm_protect(ipa, size, flags);
}

hv_return_t litebox_hvf_vm_unmap(uint64_t ipa, size_t size) {
    return hv_vm_unmap(ipa, size);
}

size_t litebox_hvf_feature_reg_count(void) {
    return sizeof(litebox_feature_regs) / sizeof(litebox_feature_regs[0]);
}

hv_return_t litebox_hvf_vcpu_config_get_feature_regs(void *config, uint64_t *values,
                                                      size_t count) {
    if (count != litebox_hvf_feature_reg_count()) {
        return HV_BAD_ARGUMENT;
    }
    for (size_t i = 0; i < count; ++i) {
        hv_return_t result = hv_vcpu_config_get_feature_reg(
            (hv_vcpu_config_t)config, litebox_feature_regs[i], &values[i]);
        if (result != HV_SUCCESS) {
            return result;
        }
    }
    return HV_SUCCESS;
}

hv_return_t litebox_hvf_vcpu_create(uint64_t *identifier, void **exit_area,
                                    void *config) {
    hv_vcpu_t vcpu = 0;
    hv_vcpu_exit_t *exit = NULL;
    hv_return_t result = hv_vcpu_create(&vcpu, &exit, (hv_vcpu_config_t)config);
    if (result == HV_SUCCESS) {
        *identifier = (uint64_t)vcpu;
        *exit_area = exit;
    }
    return result;
}

/*
 * Failure injection for the owner-lane cleanup-custody witness.  While the
 * counter is nonzero, litebox_hvf_vcpu_destroy consumes one unit and reports
 * HV_ERROR without calling the SDK, so the vCPU stays alive and a later retry
 * on the owning thread genuinely destroys it.  Owner threads race on this
 * counter, hence the atomic decrement.
 */
static _Atomic uint32_t litebox_hvf_injected_vcpu_destroy_failures = 0;

uint32_t litebox_hvf_inject_vcpu_destroy_failures(uint32_t count) {
    return atomic_exchange(&litebox_hvf_injected_vcpu_destroy_failures, count);
}

uint32_t litebox_hvf_remaining_vcpu_destroy_failures(void) {
    return atomic_load(&litebox_hvf_injected_vcpu_destroy_failures);
}

hv_return_t litebox_hvf_vcpu_destroy(uint64_t identifier) {
    uint32_t remaining =
        atomic_load(&litebox_hvf_injected_vcpu_destroy_failures);
    while (remaining != 0) {
        if (atomic_compare_exchange_weak(
                &litebox_hvf_injected_vcpu_destroy_failures, &remaining,
                remaining - 1)) {
            return HV_ERROR;
        }
    }
    return hv_vcpu_destroy((hv_vcpu_t)identifier);
}

hv_return_t litebox_hvf_vcpu_program_stage_one(
    uint64_t identifier, uint64_t ttbr0_el1, uint64_t tcr_el1,
    uint64_t mair_el1, uint64_t *ttbr0_readback, uint64_t *tcr_readback,
    uint64_t *mair_readback) {
    hv_vcpu_t vcpu = (hv_vcpu_t)identifier;
    hv_return_t result = hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_MAIR_EL1,
                                             mair_el1);
    if (result != HV_SUCCESS) {
        return result;
    }
    result = hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_TCR_EL1, tcr_el1);
    if (result != HV_SUCCESS) {
        return result;
    }
    result = hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_TTBR0_EL1, ttbr0_el1);
    if (result != HV_SUCCESS) {
        return result;
    }
    result = hv_vcpu_get_sys_reg(vcpu, HV_SYS_REG_MAIR_EL1,
                                 mair_readback);
    if (result != HV_SUCCESS) {
        return result;
    }
    result = hv_vcpu_get_sys_reg(vcpu, HV_SYS_REG_TCR_EL1, tcr_readback);
    if (result != HV_SUCCESS) {
        return result;
    }
    return hv_vcpu_get_sys_reg(vcpu, HV_SYS_REG_TTBR0_EL1,
                               ttbr0_readback);
}

hv_return_t litebox_hvf_vcpu_verify_feature_regs(uint64_t identifier,
                                                 void *config,
                                                 const uint64_t *expected,
                                                 size_t count,
                                                 size_t *mismatch_index,
                                                 uint64_t *actual_value) {
    if (config == NULL || count != litebox_hvf_feature_reg_count()) {
        return HV_BAD_ARGUMENT;
    }
    *mismatch_index = SIZE_MAX;
    *actual_value = 0;
    for (size_t i = 0; i < count; ++i) {
        uint64_t actual = 0;
        hv_return_t result = hv_vcpu_config_get_feature_reg(
            (hv_vcpu_config_t)config, litebox_feature_regs[i], &actual);
        if (result != HV_SUCCESS) {
            *mismatch_index = i;
            return result;
        }
        if (actual != expected[i]) {
            *mismatch_index = i;
            *actual_value = actual;
            return HV_SUCCESS;
        }
    }
    for (size_t i = 0;
         i < sizeof(litebox_feature_sys_regs) /
                 sizeof(litebox_feature_sys_regs[0]);
         ++i) {
        const size_t feature_index = litebox_feature_sys_regs[i].feature_index;
        uint64_t actual = 0;
        hv_return_t result = hv_vcpu_get_sys_reg(
            (hv_vcpu_t)identifier,
            litebox_feature_sys_regs[i].system_register, &actual);
        if (result != HV_SUCCESS) {
            *mismatch_index = feature_index;
            return result;
        }
        if (actual != expected[feature_index]) {
            *mismatch_index = feature_index;
            *actual_value = actual;
            return HV_SUCCESS;
        }
    }
    return HV_SUCCESS;
}

#define LITEBOX_HVF_TRY(expression)                                           \
    do {                                                                      \
        hv_return_t litebox_result = (expression);                            \
        if (litebox_result != HV_SUCCESS) {                                   \
            return litebox_result;                                            \
        }                                                                     \
    } while (0)

static bool litebox_hvf_arch_state_valid(
    const litebox_hvf_arch_state_t *state) {
    return state != NULL && state->abi_version == LITEBOX_HVF_ABI_VERSION &&
           state->byte_size == sizeof(*state);
}

static bool litebox_hvf_el1_state_valid(const litebox_hvf_el1_state_t *state) {
    return state != NULL && state->abi_version == LITEBOX_HVF_ABI_VERSION &&
           state->byte_size == sizeof(*state);
}

hv_return_t litebox_hvf_vcpu_get_arch_state(
    uint64_t identifier, litebox_hvf_arch_state_t *state) {
    if (state == NULL) {
        return HV_BAD_ARGUMENT;
    }
    memset(state, 0, sizeof(*state));
    state->abi_version = LITEBOX_HVF_ABI_VERSION;
    state->byte_size = sizeof(*state);
    hv_vcpu_t vcpu = (hv_vcpu_t)identifier;
    for (size_t index = 0; index < 31; ++index) {
        LITEBOX_HVF_TRY(
            hv_vcpu_get_reg(vcpu, litebox_general_regs[index], &state->x[index]));
    }
    for (size_t index = 0; index < 32; ++index) {
        hv_simd_fp_uchar16_t value;
        LITEBOX_HVF_TRY(
            hv_vcpu_get_simd_fp_reg(vcpu, litebox_simd_regs[index], &value));
        memcpy(state->q[index].bytes, &value, sizeof(value));
    }
    LITEBOX_HVF_TRY(hv_vcpu_get_reg(vcpu, HV_REG_FPCR, &state->fpcr));
    LITEBOX_HVF_TRY(hv_vcpu_get_reg(vcpu, HV_REG_FPSR, &state->fpsr));
    LITEBOX_HVF_TRY(
        hv_vcpu_get_sys_reg(vcpu, HV_SYS_REG_TPIDR_EL0, &state->tpidr_el0));
    LITEBOX_HVF_TRY(
        hv_vcpu_get_sys_reg(vcpu, HV_SYS_REG_SP_EL0, &state->sp_el0));
    LITEBOX_HVF_TRY(
        hv_vcpu_get_sys_reg(vcpu, HV_SYS_REG_SP_EL1, &state->sp_el1));
    LITEBOX_HVF_TRY(hv_vcpu_get_reg(vcpu, HV_REG_PC, &state->pc));
    LITEBOX_HVF_TRY(hv_vcpu_get_reg(vcpu, HV_REG_CPSR, &state->cpsr));
    LITEBOX_HVF_TRY(
        hv_vcpu_get_sys_reg(vcpu, HV_SYS_REG_SPSR_EL1, &state->spsr_el1));
    LITEBOX_HVF_TRY(
        hv_vcpu_get_sys_reg(vcpu, HV_SYS_REG_ELR_EL1, &state->elr_el1));
    LITEBOX_HVF_TRY(
        hv_vcpu_get_sys_reg(vcpu, HV_SYS_REG_ESR_EL1, &state->esr_el1));
    return hv_vcpu_get_sys_reg(vcpu, HV_SYS_REG_FAR_EL1, &state->far_el1);
}

hv_return_t litebox_hvf_vcpu_set_arch_state(
    uint64_t identifier, const litebox_hvf_arch_state_t *state,
    litebox_hvf_arch_state_t *readback) {
    if (!litebox_hvf_arch_state_valid(state) || readback == NULL) {
        return HV_BAD_ARGUMENT;
    }
    hv_vcpu_t vcpu = (hv_vcpu_t)identifier;
    for (size_t index = 0; index < 31; ++index) {
        LITEBOX_HVF_TRY(
            hv_vcpu_set_reg(vcpu, litebox_general_regs[index], state->x[index]));
    }
    for (size_t index = 0; index < 32; ++index) {
        hv_simd_fp_uchar16_t value;
        memcpy(&value, state->q[index].bytes, sizeof(value));
        LITEBOX_HVF_TRY(
            hv_vcpu_set_simd_fp_reg(vcpu, litebox_simd_regs[index], value));
    }
    LITEBOX_HVF_TRY(hv_vcpu_set_reg(vcpu, HV_REG_FPCR, state->fpcr));
    LITEBOX_HVF_TRY(hv_vcpu_set_reg(vcpu, HV_REG_FPSR, state->fpsr));
    LITEBOX_HVF_TRY(
        hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_TPIDR_EL0, state->tpidr_el0));
    LITEBOX_HVF_TRY(
        hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_SP_EL0, state->sp_el0));
    LITEBOX_HVF_TRY(
        hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_SP_EL1, state->sp_el1));
    LITEBOX_HVF_TRY(hv_vcpu_set_reg(vcpu, HV_REG_PC, state->pc));
    LITEBOX_HVF_TRY(hv_vcpu_set_reg(vcpu, HV_REG_CPSR, state->cpsr));
    LITEBOX_HVF_TRY(
        hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_SPSR_EL1, state->spsr_el1));
    LITEBOX_HVF_TRY(
        hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_ELR_EL1, state->elr_el1));
    LITEBOX_HVF_TRY(
        hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_ESR_EL1, state->esr_el1));
    LITEBOX_HVF_TRY(
        hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_FAR_EL1, state->far_el1));
    return litebox_hvf_vcpu_get_arch_state(identifier, readback);
}

static hv_return_t litebox_hvf_vcpu_read_el1(
    hv_vcpu_t vcpu, litebox_hvf_el1_state_t *state) {
    if (state == NULL) {
        return HV_BAD_ARGUMENT;
    }
    memset(state, 0, sizeof(*state));
    state->abi_version = LITEBOX_HVF_ABI_VERSION;
    state->byte_size = sizeof(*state);
    LITEBOX_HVF_TRY(
        hv_vcpu_get_sys_reg(vcpu, HV_SYS_REG_SCTLR_EL1, &state->sctlr_el1));
    LITEBOX_HVF_TRY(
        hv_vcpu_get_sys_reg(vcpu, HV_SYS_REG_CPACR_EL1, &state->cpacr_el1));
    LITEBOX_HVF_TRY(
        hv_vcpu_get_sys_reg(vcpu, HV_SYS_REG_TTBR0_EL1, &state->ttbr0_el1));
    LITEBOX_HVF_TRY(
        hv_vcpu_get_sys_reg(vcpu, HV_SYS_REG_TTBR1_EL1, &state->ttbr1_el1));
    LITEBOX_HVF_TRY(
        hv_vcpu_get_sys_reg(vcpu, HV_SYS_REG_TCR_EL1, &state->tcr_el1));
    LITEBOX_HVF_TRY(
        hv_vcpu_get_sys_reg(vcpu, HV_SYS_REG_MAIR_EL1, &state->mair_el1));
    LITEBOX_HVF_TRY(
        hv_vcpu_get_sys_reg(vcpu, HV_SYS_REG_VBAR_EL1, &state->vbar_el1));
    LITEBOX_HVF_TRY(
        hv_vcpu_get_sys_reg(vcpu, HV_SYS_REG_CNTKCTL_EL1, &state->cntkctl_el1));
    LITEBOX_HVF_TRY(
        hv_vcpu_get_sys_reg(vcpu, HV_SYS_REG_CNTV_CTL_EL0, &state->cntv_ctl_el0));
    LITEBOX_HVF_TRY(
        hv_vcpu_get_sys_reg(vcpu, HV_SYS_REG_CNTV_CVAL_EL0, &state->cntv_cval_el0));
    LITEBOX_HVF_TRY(
        hv_vcpu_get_sys_reg(vcpu, HV_SYS_REG_TPIDR_EL1, &state->tpidr_el1));
    LITEBOX_HVF_TRY(hv_vcpu_get_sys_reg(
        vcpu, HV_SYS_REG_CONTEXTIDR_EL1, &state->contextidr_el1));
    return hv_vcpu_get_sys_reg(vcpu, HV_SYS_REG_MDSCR_EL1,
                               &state->mdscr_el1);
}

hv_return_t litebox_hvf_vcpu_get_el1_state(
    uint64_t identifier, litebox_hvf_el1_state_t *state) {
    return litebox_hvf_vcpu_read_el1((hv_vcpu_t)identifier, state);
}

hv_return_t litebox_hvf_vcpu_initialize_el1(
    uint64_t identifier, const litebox_hvf_el1_state_t *configuration,
    litebox_hvf_el1_state_t *readback) {
    if (!litebox_hvf_el1_state_valid(configuration) || readback == NULL) {
        return HV_BAD_ARGUMENT;
    }
    hv_vcpu_t vcpu = (hv_vcpu_t)identifier;
    LITEBOX_HVF_TRY(hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_SCTLR_EL1,
                                        configuration->sctlr_el1));
    LITEBOX_HVF_TRY(hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_CPACR_EL1,
                                        configuration->cpacr_el1));
    LITEBOX_HVF_TRY(hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_TTBR0_EL1,
                                        configuration->ttbr0_el1));
    LITEBOX_HVF_TRY(hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_TTBR1_EL1,
                                        configuration->ttbr1_el1));
    LITEBOX_HVF_TRY(hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_TCR_EL1,
                                        configuration->tcr_el1));
    LITEBOX_HVF_TRY(hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_MAIR_EL1,
                                        configuration->mair_el1));
    LITEBOX_HVF_TRY(hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_VBAR_EL1,
                                        configuration->vbar_el1));
    LITEBOX_HVF_TRY(hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_CNTKCTL_EL1,
                                        configuration->cntkctl_el1));
    LITEBOX_HVF_TRY(hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_CNTV_CTL_EL0,
                                        configuration->cntv_ctl_el0));
    LITEBOX_HVF_TRY(hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_CNTV_CVAL_EL0,
                                        configuration->cntv_cval_el0));
    LITEBOX_HVF_TRY(hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_TPIDR_EL1,
                                        configuration->tpidr_el1));
    LITEBOX_HVF_TRY(hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_CONTEXTIDR_EL1,
                                        configuration->contextidr_el1));
    LITEBOX_HVF_TRY(hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_MDSCR_EL1,
                                        configuration->mdscr_el1));
    for (size_t index = 0;
         index < sizeof(litebox_pac_key_regs) / sizeof(litebox_pac_key_regs[0]);
         ++index) {
        LITEBOX_HVF_TRY(
            hv_vcpu_set_sys_reg(vcpu, litebox_pac_key_regs[index], 0));
    }
    hv_vcpu_sme_state_t sme_state = {
        .streaming_sve_mode_enabled = false,
        .za_storage_enabled = false,
    };
    hv_return_t sme_result = hv_vcpu_set_sme_state(vcpu, &sme_state);
    if (sme_result != HV_SUCCESS && sme_result != HV_UNSUPPORTED) {
        return sme_result;
    }
    LITEBOX_HVF_TRY(hv_vcpu_set_trap_debug_exceptions(vcpu, true));
    LITEBOX_HVF_TRY(hv_vcpu_set_trap_debug_reg_accesses(vcpu, true));
    return litebox_hvf_vcpu_read_el1(vcpu, readback);
}

hv_return_t litebox_hvf_vcpu_get_debug_traps(
    uint64_t identifier, uint8_t *exceptions, uint8_t *register_accesses) {
    if (exceptions == NULL || register_accesses == NULL) {
        return HV_BAD_ARGUMENT;
    }
    bool exception_value = false;
    bool register_value = false;
    hv_vcpu_t vcpu = (hv_vcpu_t)identifier;
    LITEBOX_HVF_TRY(
        hv_vcpu_get_trap_debug_exceptions(vcpu, &exception_value));
    LITEBOX_HVF_TRY(
        hv_vcpu_get_trap_debug_reg_accesses(vcpu, &register_value));
    *exceptions = exception_value ? 1 : 0;
    *register_accesses = register_value ? 1 : 0;
    return HV_SUCCESS;
}

hv_return_t litebox_hvf_vcpu_run(
    uint64_t identifier, const void *exit_area, litebox_hvf_exit_t *exit) {
    if (exit_area == NULL || exit == NULL) {
        return HV_BAD_ARGUMENT;
    }
    hv_vcpu_t vcpu = (hv_vcpu_t)identifier;
    LITEBOX_HVF_TRY(hv_vcpu_run(vcpu));
    const hv_vcpu_exit_t *sdk_exit = (const hv_vcpu_exit_t *)exit_area;
    memset(exit, 0, sizeof(*exit));
    exit->abi_version = LITEBOX_HVF_ABI_VERSION;
    exit->byte_size = sizeof(*exit);
    exit->raw_reason = (uint32_t)sdk_exit->reason;
    switch (sdk_exit->reason) {
    case HV_EXIT_REASON_CANCELED:
        exit->kind = LITEBOX_HVF_EXIT_CANCELED;
        break;
    case HV_EXIT_REASON_EXCEPTION:
        exit->kind = LITEBOX_HVF_EXIT_EXCEPTION;
        exit->syndrome = sdk_exit->exception.syndrome;
        exit->virtual_address = sdk_exit->exception.virtual_address;
        exit->physical_address = sdk_exit->exception.physical_address;
        break;
    case HV_EXIT_REASON_VTIMER_ACTIVATED:
        exit->kind = LITEBOX_HVF_EXIT_VTIMER;
        break;
    case HV_EXIT_REASON_UNKNOWN:
        exit->kind = LITEBOX_HVF_EXIT_UNKNOWN;
        break;
    default:
        exit->kind = LITEBOX_HVF_EXIT_MALFORMED;
        break;
    }
    return HV_SUCCESS;
}

hv_return_t litebox_hvf_vcpu_exit(uint64_t identifier) {
    hv_vcpu_t vcpu = (hv_vcpu_t)identifier;
    return hv_vcpus_exit(&vcpu, 1);
}

hv_return_t litebox_hvf_vcpu_set_pending_interrupt(
    uint64_t identifier, uint8_t fiq, uint8_t pending) {
    if (fiq > 1 || pending > 1) {
        return HV_BAD_ARGUMENT;
    }
    return hv_vcpu_set_pending_interrupt(
        (hv_vcpu_t)identifier,
        fiq != 0 ? HV_INTERRUPT_TYPE_FIQ : HV_INTERRUPT_TYPE_IRQ,
        pending != 0);
}

hv_return_t litebox_hvf_vcpu_get_pending_interrupt(
    uint64_t identifier, uint8_t fiq, uint8_t *pending) {
    if (fiq > 1 || pending == NULL) {
        return HV_BAD_ARGUMENT;
    }
    bool value = false;
    LITEBOX_HVF_TRY(hv_vcpu_get_pending_interrupt(
        (hv_vcpu_t)identifier,
        fiq != 0 ? HV_INTERRUPT_TYPE_FIQ : HV_INTERRUPT_TYPE_IRQ, &value));
    *pending = value ? 1 : 0;
    return HV_SUCCESS;
}

hv_return_t litebox_hvf_vcpu_set_vtimer_mask(uint64_t identifier,
                                             uint8_t masked) {
    if (masked > 1) {
        return HV_BAD_ARGUMENT;
    }
    return hv_vcpu_set_vtimer_mask((hv_vcpu_t)identifier, masked != 0);
}

/*
 * Arms the virtual timer as a one-shot deadline: CNTV_CVAL_EL0 = cval,
 * CNTV_CTL_EL0 = ENABLE (not IMASK), and the SDK-level mask cleared so the
 * activation surfaces as HV_EXIT_REASON_VTIMER_ACTIVATED.  Used by the owner
 * lane to bound one guest time slice.
 */
hv_return_t litebox_hvf_vcpu_arm_vtimer(uint64_t identifier, uint64_t cval) {
    hv_vcpu_t vcpu = (hv_vcpu_t)identifier;
    hv_return_t result =
        hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_CNTV_CVAL_EL0, cval);
    if (result != HV_SUCCESS) {
        return result;
    }
    result = hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_CNTV_CTL_EL0, 1);
    if (result != HV_SUCCESS) {
        return result;
    }
    return hv_vcpu_set_vtimer_mask(vcpu, false);
}

hv_return_t litebox_hvf_vcpu_get_vtimer_mask(uint64_t identifier,
                                             uint8_t *masked) {
    if (masked == NULL) {
        return HV_BAD_ARGUMENT;
    }
    bool value = false;
    LITEBOX_HVF_TRY(
        hv_vcpu_get_vtimer_mask((hv_vcpu_t)identifier, &value));
    *masked = value ? 1 : 0;
    return HV_SUCCESS;
}

hv_return_t litebox_hvf_vcpu_set_vtimer_offset(uint64_t identifier,
                                               uint64_t offset) {
    return hv_vcpu_set_vtimer_offset((hv_vcpu_t)identifier, offset);
}

hv_return_t litebox_hvf_vcpu_get_vtimer_offset(uint64_t identifier,
                                               uint64_t *offset) {
    if (offset == NULL) {
        return HV_BAD_ARGUMENT;
    }
    return hv_vcpu_get_vtimer_offset((hv_vcpu_t)identifier, offset);
}

hv_return_t litebox_hvf_vcpu_get_exec_time(uint64_t identifier,
                                           uint64_t *time) {
    if (time == NULL) {
        return HV_BAD_ARGUMENT;
    }
    return hv_vcpu_get_exec_time((hv_vcpu_t)identifier, time);
}

#undef LITEBOX_HVF_TRY

#pragma clang attribute pop
