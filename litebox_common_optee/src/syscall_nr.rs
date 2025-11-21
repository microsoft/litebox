use num_enum::TryFromPrimitive;

const SYSCALL_SYS_RETURN: u32 = 0;
const SYSCALL_LOG: u32 = 1;
const SYSCALL_PANIC: u32 = 2;
const SYSCALL_GET_PROPERTY: u32 = 3;
const SYSCALL_GET_PROPERTY_NAME_TO_INDEX: u32 = 4;
const SYSCALL_OPEN_TA_SESSION: u32 = 5;
const SYSCALL_CLOSE_TA_SESSION: u32 = 6;
const SYSCALL_INVOKE_TA_COMMAND: u32 = 7;
const SYSCALL_CHECK_ACCESS_RIGHTS: u32 = 8;
const SYSCALL_GET_CANCELLATION_FLAG: u32 = 9;
const SYSCALL_UNMASK_CANCELLATION: u32 = 10;
const SYSCALL_MASK_CANCELLATION: u32 = 11;
const SYSCALL_WAIT: u32 = 12;
const SYSCALL_GET_TIME: u32 = 13;
const SYSCALL_SET_TA_TIME: u32 = 14;
const SYSCALL_CRYP_STATE_ALLOC: u32 = 15;
const SYSCALL_CRYP_STATE_COPY: u32 = 16;
const SYSCALL_CRYP_STATE_FREE: u32 = 17;
const SYSCALL_HASH_INIT: u32 = 18;
const SYSCALL_HASH_UPDATE: u32 = 19;
const SYSCALL_HASH_FINAL: u32 = 20;
const SYSCALL_CIPHER_INIT: u32 = 21;
const SYSCALL_CIPHER_UPDATE: u32 = 22;
const SYSCALL_CIPHER_FINAL: u32 = 23;
const SYSCALL_CRYP_OBJ_GET_INFO: u32 = 24;
const SYSCALL_CRYP_OBJ_RESTRICT_USAGE: u32 = 25;
const SYSCALL_CRYP_OBJ_GET_ATTR: u32 = 26;
const SYSCALL_CRYP_OBJ_ALLOC: u32 = 27;
const SYSCALL_CRYP_OBJ_CLOSE: u32 = 28;
const SYSCALL_CRYP_OBJ_RESET: u32 = 29;
const SYSCALL_CRYP_OBJ_POPULATE: u32 = 30;
const SYSCALL_CRYP_OBJ_COPY: u32 = 31;
const SYSCALL_CRYP_DERIVE_KEY: u32 = 32;
const SYSCALL_CRYP_RANDOM_NUMBER_GENERATE: u32 = 33;
const SYSCALL_AUTHENC_INIT: u32 = 34;
const SYSCALL_AUTHENC_UPDATE_AAD: u32 = 35;
const SYSCALL_AUTHENC_UPDATE_PAYLOAD: u32 = 36;
const SYSCALL_AUTHENC_ENC_FINAL: u32 = 37;
const SYSCALL_AUTHENC_DEC_FINAL: u32 = 38;
const SYSCALL_ASYMM_OPERATE: u32 = 39;
const SYSCALL_ASYMM_VERIFY: u32 = 40;
const SYSCALL_STORAGE_OBJ_OPEN: u32 = 41;
const SYSCALL_STORAGE_OBJ_CREATE: u32 = 42;
const SYSCALL_STORAGE_OBJ_DEL: u32 = 43;
const SYSCALL_STORAGE_OBJ_RENAME: u32 = 44;
const SYSCALL_STORAGE_ALLOC_ENUM: u32 = 45;
const SYSCALL_STORAGE_FREE_ENUM: u32 = 46;
const SYSCALL_STORAGE_RESET_ENUM: u32 = 47;
const SYSCALL_STORAGE_START_ENUM: u32 = 48;
const SYSCALL_STORAGE_NEXT_ENUM: u32 = 49;
const SYSCALL_STORAGE_OBJ_READ: u32 = 50;
const SYSCALL_STORAGE_OBJ_WRITE: u32 = 51;
const SYSCALL_STORAGE_OBJ_TRUNC: u32 = 52;
const SYSCALL_STORAGE_OBJ_SEEK: u32 = 53;
const SYSCALL_OBJ_GENERATE_KEY: u32 = 54;
const SYSCALL_CACHE_OPERATION: u32 = 70;

/// OP-TEE TEE syscall numbers.
/// OP-TEE provides two types of syscalls: TEE syscalls and LDELF syscalls.
/// This works like when OP-TEE runs LDELF (a TA ELF loader in the user space)
/// with a processor core, it loads the LDELF syscall handler into the core's
/// MSR instead of the TEE syscall handler. TEE syscalls and LDELF syscalls
/// share certain system call numbers so their handlers should be separated.
#[derive(Debug, PartialEq, TryFromPrimitive)]
#[repr(u32)]
pub enum TeeSyscallNr {
    Return = SYSCALL_SYS_RETURN,
    Log = SYSCALL_LOG,
    Panic = SYSCALL_PANIC,
    GetProperty = SYSCALL_GET_PROPERTY,
    GetPropertyNameToIndex = SYSCALL_GET_PROPERTY_NAME_TO_INDEX,
    OpenTaSession = SYSCALL_OPEN_TA_SESSION,
    CloseTaSession = SYSCALL_CLOSE_TA_SESSION,
    InvokeTaCommand = SYSCALL_INVOKE_TA_COMMAND,
    CheckAccessRights = SYSCALL_CHECK_ACCESS_RIGHTS,
    GetCancellationFlag = SYSCALL_GET_CANCELLATION_FLAG,
    UnmaskCancellation = SYSCALL_UNMASK_CANCELLATION,
    MaskCancellation = SYSCALL_MASK_CANCELLATION,
    Wait = SYSCALL_WAIT,
    GetTime = SYSCALL_GET_TIME,
    SetTaTime = SYSCALL_SET_TA_TIME,
    CrypStateAlloc = SYSCALL_CRYP_STATE_ALLOC,
    CrypStateCopy = SYSCALL_CRYP_STATE_COPY,
    CrypStateFree = SYSCALL_CRYP_STATE_FREE,
    HashInit = SYSCALL_HASH_INIT,
    HashUpdate = SYSCALL_HASH_UPDATE,
    HashFinal = SYSCALL_HASH_FINAL,
    CipherInit = SYSCALL_CIPHER_INIT,
    CipherUpdate = SYSCALL_CIPHER_UPDATE,
    CipherFinal = SYSCALL_CIPHER_FINAL,
    CrypObjGetInfo = SYSCALL_CRYP_OBJ_GET_INFO,
    CrypObjRestrictUsage = SYSCALL_CRYP_OBJ_RESTRICT_USAGE,
    CrypObjGetAttr = SYSCALL_CRYP_OBJ_GET_ATTR,
    CrypObjAlloc = SYSCALL_CRYP_OBJ_ALLOC,
    CrypObjClose = SYSCALL_CRYP_OBJ_CLOSE,
    CrypObjReset = SYSCALL_CRYP_OBJ_RESET,
    CrypObjPopulate = SYSCALL_CRYP_OBJ_POPULATE,
    CrypObjCopy = SYSCALL_CRYP_OBJ_COPY,
    CrypDeriveKey = SYSCALL_CRYP_DERIVE_KEY,
    CrypRandomNumberGenerate = SYSCALL_CRYP_RANDOM_NUMBER_GENERATE,
    AuthencInit = SYSCALL_AUTHENC_INIT,
    AuthencUpdateAad = SYSCALL_AUTHENC_UPDATE_AAD,
    AuthencUpdatePayload = SYSCALL_AUTHENC_UPDATE_PAYLOAD,
    AuthencEncFinal = SYSCALL_AUTHENC_ENC_FINAL,
    AuthencDecFinal = SYSCALL_AUTHENC_DEC_FINAL,
    AsymmOperate = SYSCALL_ASYMM_OPERATE,
    AsymmVerify = SYSCALL_ASYMM_VERIFY,
    StorageObjOpen = SYSCALL_STORAGE_OBJ_OPEN,
    StorageObjCreate = SYSCALL_STORAGE_OBJ_CREATE,
    StorageObjDel = SYSCALL_STORAGE_OBJ_DEL,
    StorageObjRename = SYSCALL_STORAGE_OBJ_RENAME,
    StorageAllocEnum = SYSCALL_STORAGE_ALLOC_ENUM,
    StorageFreeEnum = SYSCALL_STORAGE_FREE_ENUM,
    StorageResetEnum = SYSCALL_STORAGE_RESET_ENUM,
    StorageStartEnum = SYSCALL_STORAGE_START_ENUM,
    StorageNextEnum = SYSCALL_STORAGE_NEXT_ENUM,
    StorageObjRead = SYSCALL_STORAGE_OBJ_READ,
    StorageObjWrite = SYSCALL_STORAGE_OBJ_WRITE,
    StorageObjTrunc = SYSCALL_STORAGE_OBJ_TRUNC,
    StorageObjSeek = SYSCALL_STORAGE_OBJ_SEEK,
    ObjGenerateKey = SYSCALL_OBJ_GENERATE_KEY,
    CacheOperation = SYSCALL_CACHE_OPERATION,
    Unknown = 0xffff_ffff,
}

const LDELF_RETURN: u32 = 0;
const LDELF_LOG: u32 = 1;
const LDELF_PANIC: u32 = 2;
const LDELF_MAP_ZI: u32 = 3;
const LDELF_UNMAP: u32 = 4;
const LDELF_OPEN_BIN: u32 = 5;
const LDELF_CLOSE_BIN: u32 = 6;
const LDELF_MAP_BIN: u32 = 7;
const LDELF_CP_FROM_BIN: u32 = 8;
const LDELF_SET_PROT: u32 = 9;
const LDELF_REMAP: u32 = 10;
const LDELF_GEN_RND_NUM: u32 = 11;

/// LDELF syscall numbers
#[derive(Debug, PartialEq, TryFromPrimitive)]
#[repr(u32)]
pub enum LdelfSyscallNr {
    Return = LDELF_RETURN,
    Log = LDELF_LOG,
    Panic = LDELF_PANIC,
    MapZi = LDELF_MAP_ZI,
    Unmap = LDELF_UNMAP,
    OpenBin = LDELF_OPEN_BIN,
    CloseBin = LDELF_CLOSE_BIN,
    MapBin = LDELF_MAP_BIN,
    CpFromBin = LDELF_CP_FROM_BIN,
    SetProt = LDELF_SET_PROT,
    Remap = LDELF_REMAP,
    GenRndNum = LDELF_GEN_RND_NUM,
    Unknown = 0xffff_ffff,
}
