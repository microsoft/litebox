use num_enum::TryFromPrimitive;

pub const SYSCALL_SYS_RETURN: u32 = 0;
pub const SYSCALL_LOG: u32 = 1;
pub const SYSCALL_PANIC: u32 = 2;
pub const SYSCALL_GET_PROPERTY: u32 = 3;
pub const SYSCALL_GET_PROPERTY_NAME_TO_INDEX: u32 = 4;
pub const SYSCALL_OPEN_TA_SESSION: u32 = 5;
pub const SYSCALL_CLOSE_TA_SESSION: u32 = 6;
pub const SYSCALL_INVOKE_TA_COMMAND: u32 = 7;
pub const SYSCALL_CHECK_ACCESS_RIGHTS: u32 = 8;
pub const SYSCALL_GET_CANCELLATION_FLAG: u32 = 9;
pub const SYSCALL_UNMASK_CANCELLATION: u32 = 10;
pub const SYSCALL_MASK_CANCELLATION: u32 = 11;
pub const SYSCALL_WAIT: u32 = 12;
pub const SYSCALL_GET_TIME: u32 = 13;
pub const SYSCALL_SET_TA_TIME: u32 = 14;
pub const SYSCALL_CRYP_STATE_ALLOC: u32 = 15;
pub const SYSCALL_CRYP_STATE_COPY: u32 = 16;
pub const SYSCALL_CRYP_STATE_FREE: u32 = 17;
pub const SYSCALL_HASH_INIT: u32 = 18;
pub const SYSCALL_HASH_UPDATE: u32 = 19;
pub const SYSCALL_HASH_FINAL: u32 = 20;
pub const SYSCALL_CIPHER_INIT: u32 = 21;
pub const SYSCALL_CIPHER_UPDATE: u32 = 22;
pub const SYSCALL_CIPHER_FINAL: u32 = 23;
pub const SYSCALL_CRYP_OBJ_GET_INFO: u32 = 24;
pub const SYSCALL_CRYP_OBJ_RESTRICT_USAGE: u32 = 25;
pub const SYSCALL_CRYP_OBJ_GET_ATTR: u32 = 26;
pub const SYSCALL_CRYP_OBJ_ALLOC: u32 = 27;
pub const SYSCALL_CRYP_OBJ_CLOSE: u32 = 28;
pub const SYSCALL_CRYP_OBJ_RESET: u32 = 29;
pub const SYSCALL_CRYP_OBJ_POPULATE: u32 = 30;
pub const SYSCALL_CRYP_OBJ_COPY: u32 = 31;
pub const SYSCALL_CRYP_DERIVE_KEY: u32 = 32;
pub const SYSCALL_CRYP_RANDOM_NUMBER_GENERATE: u32 = 33;
pub const SYSCALL_AUTHENC_INIT: u32 = 34;
pub const SYSCALL_AUTHENC_UPDATE_AAD: u32 = 35;
pub const SYSCALL_AUTHENC_UPDATE_PAYLOAD: u32 = 36;
pub const SYSCALL_AUTHENC_ENC_FINAL: u32 = 37;
pub const SYSCALL_AUTHENC_DEC_FINAL: u32 = 38;
pub const SYSCALL_ASYMM_OPERATE: u32 = 39;
pub const SYSCALL_ASYMM_VERIFY: u32 = 40;
pub const SYSCALL_STORAGE_OBJ_OPEN: u32 = 41;
pub const SYSCALL_STORAGE_OBJ_CREATE: u32 = 42;
pub const SYSCALL_STORAGE_OBJ_DEL: u32 = 43;
pub const SYSCALL_STORAGE_OBJ_RENAME: u32 = 44;
pub const SYSCALL_STORAGE_ALLOC_ENUM: u32 = 45;
pub const SYSCALL_STORAGE_FREE_ENUM: u32 = 46;
pub const SYSCALL_STORAGE_RESET_ENUM: u32 = 47;
pub const SYSCALL_STORAGE_START_ENUM: u32 = 48;
pub const SYSCALL_STORAGE_NEXT_ENUM: u32 = 49;
pub const SYSCALL_STORAGE_OBJ_READ: u32 = 50;
pub const SYSCALL_STORAGE_OBJ_WRITE: u32 = 51;
pub const SYSCALL_STORAGE_OBJ_TRUNC: u32 = 52;
pub const SYSCALL_STORAGE_OBJ_SEEK: u32 = 53;
pub const SYSCALL_OBJ_GENERATE_KEY: u32 = 54;
pub const SYSCALL_CACHE_OPERATION: u32 = 70;

/// OP-TEE TEE syscall numbers.
/// OP-TEE provides two types of syscalls: TEE syscalls and LDELF syscalls.
/// This works like when OP-TEE runs LDELF (a TA ELF loader in the user space)
/// with a processor core, it loads the LDELF syscall handler into the core's
/// MSR instead of the TEE syscall handler. TEE syscalls and LDELF syscalls
/// share certain system call numbers so their handlers should be separated.
/// Since LiteBox has its own ELF loader, we do not consider LDELF syscalls here.
#[derive(Debug, PartialEq, TryFromPrimitive)]
#[repr(u32)]
pub enum TeeSyscallNr {
    Return = SYSCALL_SYS_RETURN + SYSCALL_NR_SHIFT,
    Log = SYSCALL_LOG + SYSCALL_NR_SHIFT,
    Panic = SYSCALL_PANIC + SYSCALL_NR_SHIFT,
    GetProperty = SYSCALL_GET_PROPERTY + SYSCALL_NR_SHIFT,
    GetPropertyNameToIndex = SYSCALL_GET_PROPERTY_NAME_TO_INDEX + SYSCALL_NR_SHIFT,
    OpenTaSession = SYSCALL_OPEN_TA_SESSION + SYSCALL_NR_SHIFT,
    CloseTaSession = SYSCALL_CLOSE_TA_SESSION + SYSCALL_NR_SHIFT,
    InvokeTaCommand = SYSCALL_INVOKE_TA_COMMAND + SYSCALL_NR_SHIFT,
    CheckAccessRights = SYSCALL_CHECK_ACCESS_RIGHTS + SYSCALL_NR_SHIFT,
    GetCancellationFlag = SYSCALL_GET_CANCELLATION_FLAG + SYSCALL_NR_SHIFT,
    UnmaskCancellation = SYSCALL_UNMASK_CANCELLATION + SYSCALL_NR_SHIFT,
    MaskCancellation = SYSCALL_MASK_CANCELLATION + SYSCALL_NR_SHIFT,
    Wait = SYSCALL_WAIT + SYSCALL_NR_SHIFT,
    GetTime = SYSCALL_GET_TIME + SYSCALL_NR_SHIFT,
    SetTaTime = SYSCALL_SET_TA_TIME + SYSCALL_NR_SHIFT,
    CrypStateAlloc = SYSCALL_CRYP_STATE_ALLOC + SYSCALL_NR_SHIFT,
    CrypStateCopy = SYSCALL_CRYP_STATE_COPY + SYSCALL_NR_SHIFT,
    CrypStateFree = SYSCALL_CRYP_STATE_FREE + SYSCALL_NR_SHIFT,
    HashInit = SYSCALL_HASH_INIT + SYSCALL_NR_SHIFT,
    HashUpdate = SYSCALL_HASH_UPDATE + SYSCALL_NR_SHIFT,
    HashFinal = SYSCALL_HASH_FINAL + SYSCALL_NR_SHIFT,
    CipherInit = SYSCALL_CIPHER_INIT + SYSCALL_NR_SHIFT,
    CipherUpdate = SYSCALL_CIPHER_UPDATE + SYSCALL_NR_SHIFT,
    CipherFinal = SYSCALL_CIPHER_FINAL + SYSCALL_NR_SHIFT,
    CrypObjGetInfo = SYSCALL_CRYP_OBJ_GET_INFO + SYSCALL_NR_SHIFT,
    CrypObjRestrictUsage = SYSCALL_CRYP_OBJ_RESTRICT_USAGE + SYSCALL_NR_SHIFT,
    CrypObjGetAttr = SYSCALL_CRYP_OBJ_GET_ATTR + SYSCALL_NR_SHIFT,
    CrypObjAlloc = SYSCALL_CRYP_OBJ_ALLOC + SYSCALL_NR_SHIFT,
    CrypObjClose = SYSCALL_CRYP_OBJ_CLOSE + SYSCALL_NR_SHIFT,
    CrypObjReset = SYSCALL_CRYP_OBJ_RESET + SYSCALL_NR_SHIFT,
    CrypObjPopulate = SYSCALL_CRYP_OBJ_POPULATE + SYSCALL_NR_SHIFT,
    CrypObjCopy = SYSCALL_CRYP_OBJ_COPY + SYSCALL_NR_SHIFT,
    CrypDeriveKey = SYSCALL_CRYP_DERIVE_KEY + SYSCALL_NR_SHIFT,
    CrypRandomNumberGenerate = SYSCALL_CRYP_RANDOM_NUMBER_GENERATE + SYSCALL_NR_SHIFT,
    AuthencInit = SYSCALL_AUTHENC_INIT + SYSCALL_NR_SHIFT,
    AuthencUpdateAad = SYSCALL_AUTHENC_UPDATE_AAD + SYSCALL_NR_SHIFT,
    AuthencUpdatePayload = SYSCALL_AUTHENC_UPDATE_PAYLOAD + SYSCALL_NR_SHIFT,
    AuthencEncFinal = SYSCALL_AUTHENC_ENC_FINAL + SYSCALL_NR_SHIFT,
    AuthencDecFinal = SYSCALL_AUTHENC_DEC_FINAL + SYSCALL_NR_SHIFT,
    AsymmOperate = SYSCALL_ASYMM_OPERATE + SYSCALL_NR_SHIFT,
    AsymmVerify = SYSCALL_ASYMM_VERIFY + SYSCALL_NR_SHIFT,
    StorageObjOpen = SYSCALL_STORAGE_OBJ_OPEN + SYSCALL_NR_SHIFT,
    StorageObjCreate = SYSCALL_STORAGE_OBJ_CREATE + SYSCALL_NR_SHIFT,
    StorageObjDel = SYSCALL_STORAGE_OBJ_DEL + SYSCALL_NR_SHIFT,
    StorageObjRename = SYSCALL_STORAGE_OBJ_RENAME + SYSCALL_NR_SHIFT,
    StorageAllocEnum = SYSCALL_STORAGE_ALLOC_ENUM + SYSCALL_NR_SHIFT,
    StorageFreeEnum = SYSCALL_STORAGE_FREE_ENUM + SYSCALL_NR_SHIFT,
    StorageResetEnum = SYSCALL_STORAGE_RESET_ENUM + SYSCALL_NR_SHIFT,
    StorageStartEnum = SYSCALL_STORAGE_START_ENUM + SYSCALL_NR_SHIFT,
    StorageNextEnum = SYSCALL_STORAGE_NEXT_ENUM + SYSCALL_NR_SHIFT,
    StorageObjRead = SYSCALL_STORAGE_OBJ_READ + SYSCALL_NR_SHIFT,
    StorageObjWrite = SYSCALL_STORAGE_OBJ_WRITE + SYSCALL_NR_SHIFT,
    StorageObjTrunc = SYSCALL_STORAGE_OBJ_TRUNC + SYSCALL_NR_SHIFT,
    StorageObjSeek = SYSCALL_STORAGE_OBJ_SEEK + SYSCALL_NR_SHIFT,
    ObjGenerateKey = SYSCALL_OBJ_GENERATE_KEY + SYSCALL_NR_SHIFT,
    CacheOperation = SYSCALL_CACHE_OPERATION + SYSCALL_NR_SHIFT,
    Unknown = 0xffff_ffff,
}

/// The syscall numbers might need to be shifted by this value to avoid conflicts
/// with other critical Linux syscalls like `rt_sigreturn` which enable systrap.
/// This shifting is necessary if we use the systrap backend.
/// If we use the syscall rewriter or if we run this on top of the LVBS platform,
/// this shifting is not necessary.
#[cfg(feature = "shift_syscall_number")]
const SYSCALL_NR_SHIFT: u32 = 400;
#[cfg(not(feature = "shift_syscall_number"))]
const SYSCALL_NR_SHIFT: u32 = 0;
