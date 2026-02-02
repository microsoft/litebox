// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! This file is copied from sandbox_driver/include/snp-sandbox.h

#ifndef _SNP_SANDBOX_SNP_SANDBOX_HEADER_H
#define _SNP_SANDBOX_SNP_SANDBOX_HEADER_H

#define VMSA_GUEST_ERROR_RETRY 0xfff

// Protocol code for SNP VMPL
// Must have the prefix SNP_VMPL_, otherwise bindgen won't recognize it
#define SNP_VMPL_EXIT_REQ 0x0
#define SNP_VMPL_RESPONSE 0x1
#define SNP_VMPL_EXCEPTION_REQ 0x2
#define SNP_VMPL_SYSCALL_REQ 0x3
#define SNP_VMPL_ALLOC_REQ 0x4
#define SNP_VMPL_KPTI_REQ 0x5
#define SNP_VMPL_PRINT_REQ 0x6
#define SNP_VMPL_TUN_READ_REQ 0x7
#define SNP_VMPL_TUN_WRITE_REQ 0x8
#define SNP_VMPL_SLEEP_REQ 0x9
#define SNP_VMPL_ALLOC_FUTEX_REQ 0xa
#define SNP_VMPL_FILEMAP_READ_REQ 0xb
#define SNP_VMPL_RT_SIGRETURN_REQ 0xc
#define SNP_VMPL_CLONE_REQ 0xd
#define SNP_VMPL_EXECVE_REQ 0xe
#define SNP_VMPL_HANDLE_SIGNAL_REQ 0xf
#define SNP_VMPL_LOAD_FILE_REQ 0x10
// Do nothing, just return back to VMPL2 for measurement
#define SNP_VMPL_IDLE_REQ 0xff
#define SNP_VMPL_TERMINATE_REQ 0x100

#define SNP_VMPL_REQ_INCOMPLETE 0x0
#define SNP_VMPL_REQ_SUCCESS 0x1
#define SNP_VMPL_REQ_FAILURE 0x2
#define SNP_VMPL_REQ_PAGE_FAULT 0x3
#define SNP_VMPL_REQ_FORK 0x4

#define SNP_VMPL_PRINT_STACK 0x1
#define SNP_VMPL_PRINT_PGFAULT 0x2
#define SNP_VMPL_PRINT_PT_REGS 0x3

#define SNP_VMPL_ALLOC_MAX_ORDER 10 // MAX_ORDER - 1

#define SNP_VMPL_MEM_SIZE PGDIR_SIZE // Cover 512GB memory

#define MAX_VM_AREA_ENTRY 128

#define SNP_VMPL_STATUS_INIT 0
#define SNP_VMPL_STATUS_RUNNING 1
#define SNP_VMPL_STATUS_EXIT 2

/// only the lower 32 bits are used in Linux
#define SNP_VMPL_VM_VMPL2_MEM 0x100000000
#define SNP_VMPL_VM_FILEMAP_MEM 0x200000000

struct vmpl2_page {
	uint64_t refcnt;
};

struct vm_area {
	uint64_t start;
	uint64_t end;
	uint64_t flags;
} __attribute__((__packed__));

struct vmpl2_boot_params {
	uint64_t zero_page;
	/// NOT used if enabling separate page tables
	uint64_t snp_vmpl2_mem_base;

	uint64_t ghcb_page;
	uint64_t ghcb_page_va;

	uint64_t cpu_khz;

	/// Thread ID - the internal kernel "pid"
	int32_t pid;
	/// Parent Process ID
	int32_t ppid;
	/// real UID of the task
	uint32_t uid;
	/// real GID of the task
	uint32_t gid;
	/// effective UID of the task
	uint32_t euid;
	/// effective GID of the task
	uint32_t egid;

	/// length of command line arguments
	int argv_len;
	/// length of environment variables
	int env_len;
	/// command line arguments and environment variables
	///
	/// make the whole struct 4096 bytes so this array fills the remaining space.
	uint8_t argv_and_env[4024];
} __attribute__((__packed__));

/* Sanity check: ensure the boot params struct occupies exactly 4KB. */
#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
_Static_assert(sizeof(struct vmpl2_boot_params) == 4096, "vmpl2_boot_params must be 4096 bytes");
#endif

#define MAX_ROOTPATH_SIZE 256

struct vsbox_task {
	// per-thread data
	// The top two fields are used by the sandbox kernel
	// and has to be the first two fields in this struct.
	uint64_t rsp_scratch;
	uint64_t vmpl2_kernel_sp;

	uint64_t status;
	uint64_t alt_stack;
	uint64_t robust_list;
	unsigned long flags; // task_struct->thread_info->flags in Linux
	uint64_t mem_map; // VData<MemMAP>
	/// Thread ID - the internal kernel "pid"
	uint32_t pid;
	/// Process ID - thread groupd ID
	uint32_t tgid;
	/// real UID of the task
	uint32_t uid;
	/// real GID of the task
	uint32_t gid;
	/// effective UID of the task
	uint32_t euid;
	/// effective GID of the task
	uint32_t egid;

	// per-process data
	uint64_t mm; // VData<SpinLock<MMStruct>>
	uint64_t pgtable; // VData<SpinLock<OffsetPageTable>>
	uint64_t fs; // VData<RwLock<FsResolver>>
	uint64_t file_table; // VData<Mutex<FileTable>>
	uint64_t umask;
	uint64_t rootpath_len;
	uint8_t rootpath[MAX_ROOTPATH_SIZE];
	uint64_t snp_vmpl0_mem_base;

	// Thread-local storage used by VMPL2
	void *tls;

	// accessible but not directly used by the sandbox kernel
	// must be kept at the bottom of this struct because
	// we simply convert them to empty struct with bindgen
	/// Do not access this field directly in sandbox
	struct desc_struct gdt[GDT_ENTRIES];
	/// Do not access this field directly in sandbox
	struct x86_hw_tss tss;
};

// Make sure it is 8-byte aligned
struct SnpVmplRequestArgs {
	/// Request number
	uint32_t code;
	/// Status
	uint32_t status;
	/// number of arguments
	uint32_t size;
	/// padding
	uint32_t padding;
	/// arguments up to 6
	uint64_t args[6];
	/// return value
	uint64_t ret;
} __attribute__((__packed__));

#define SNP_SANDBOX_IOCTL_DEBUG 0x6300 // _IO('c', 0)
#define SNP_SANDBOX_IOCTL_ENTER 0x6301 // _IO('c', 1)
#define SNP_SANDBOX_IOCTL_EXECVE 0x6302 // _IO('c', 2)
#define SNP_SANDBOX_IOCTL_CONFIG 0x6303 // _IO('c', 3)
// _IO('c', 5) -- unused (previously used for separate tun-read thread)
// _IO('c', 6) -- unused (previously used for separate tun-write thread)
#define SNP_SANDBOX_IOCTL_MOUNT 0x6307 // _IO('c', 7)
#define SNP_SANDBOX_IOCTL_TUN_READ_WRITE 0x6308 // _IO('c', 8)

struct snp_sandbox_execve_args {
	const char *rootpath;
	const char *filename;
	const char *const *argv;
	const char *const *envp;
};

struct snp_sandbox_config_args {
	uint64_t shared_page;
	uint64_t nr_pages;
} __attribute__((__packed__));

void snp_vmpl2_ret_from_fork(void);

int vsbox_init_unexported_symbols(void);
void vsbox_detach_kprobe(void);
int vsbox_attach_kprobe(void);
#endif