/// Operation not permitted
pub const EPERM: i32 = 1;
/// No such file or directory
pub const ENOENT: i32 = 2;
/// No such process
pub const ESRCH: i32 = 3;
/// Interrupted system call
pub const EINTR: i32 = 4;
/// Input/output error
pub const EIO: i32 = 5;
/// No such device or address
pub const ENXIO: i32 = 6;
/// Argument list too long
pub const E2BIG: i32 = 7;
/// Exec format error
pub const ENOEXEC: i32 = 8;
/// Bad file descriptor
pub const EBADF: i32 = 9;
/// No child processes
pub const ECHILD: i32 = 10;
/// Resource temporarily unavailable
pub const EAGAIN: i32 = 11;
/// Cannot allocate memory
pub const ENOMEM: i32 = 12;
/// Permission denied
pub const EACCES: i32 = 13;
/// Bad address
pub const EFAULT: i32 = 14;
/// Block device required
pub const ENOTBLK: i32 = 15;
/// Device or resource busy
pub const EBUSY: i32 = 16;
/// File exists
pub const EEXIST: i32 = 17;
/// Invalid cross-device link
pub const EXDEV: i32 = 18;
/// No such device
pub const ENODEV: i32 = 19;
/// Not a directory
pub const ENOTDIR: i32 = 20;
/// Is a directory
pub const EISDIR: i32 = 21;
/// Invalid argument
pub const EINVAL: i32 = 22;
/// Too many open files in system
pub const ENFILE: i32 = 23;
/// Too many open files
pub const EMFILE: i32 = 24;
/// Inappropriate ioctl for device
pub const ENOTTY: i32 = 25;
/// Text file busy
pub const ETXTBSY: i32 = 26;
/// File too large
pub const EFBIG: i32 = 27;
/// No space left on device
pub const ENOSPC: i32 = 28;
/// Illegal seek
pub const ESPIPE: i32 = 29;
/// Read-only file system
pub const EROFS: i32 = 30;
/// Too many links
pub const EMLINK: i32 = 31;
/// Broken pipe
pub const EPIPE: i32 = 32;
/// Numerical argument out of domain
pub const EDOM: i32 = 33;
/// Numerical result out of range
pub const ERANGE: i32 = 34;
/// Resource deadlock avoided
pub const EDEADLOCK: i32 = 35;
/// File name too long
pub const ENAMETOOLONG: i32 = 36;
/// No locks available
pub const ENOLCK: i32 = 37;
/// Function not implemented
pub const ENOSYS: i32 = 38;
/// Directory not empty
pub const ENOTEMPTY: i32 = 39;
/// Too many levels of symbolic links
pub const ELOOP: i32 = 40;
/// No message of desired type
pub const ENOMSG: i32 = 42;
/// Identifier removed
pub const EIDRM: i32 = 43;
/// Channel number out of range
pub const ECHRNG: i32 = 44;
/// Level 2 not synchronized
pub const EL2NSYNC: i32 = 45;
/// Level 3 halted
pub const EL3HLT: i32 = 46;
/// Level 3 reset
pub const EL3RST: i32 = 47;
/// Link number out of range
pub const ELNRNG: i32 = 48;
/// Protocol driver not attached
pub const EUNATCH: i32 = 49;
/// No CSI structure available
pub const ENOCSI: i32 = 50;
/// Level 2 halted
pub const EL2HLT: i32 = 51;
/// Invalid exchange
pub const EBADE: i32 = 52;
/// Invalid request descriptor
pub const EBADR: i32 = 53;
/// Exchange full
pub const EXFULL: i32 = 54;
/// No anode
pub const ENOANO: i32 = 55;
/// Invalid request code
pub const EBADRQC: i32 = 56;
/// Invalid slot
pub const EBADSLT: i32 = 57;
/// Bad font file format
pub const EBFONT: i32 = 59;
/// Device not a stream
pub const ENOSTR: i32 = 60;
/// No data available
pub const ENODATA: i32 = 61;
/// Timer expired
pub const ETIME: i32 = 62;
/// Out of streams resources
pub const ENOSR: i32 = 63;
/// Machine is not on the network
pub const ENONET: i32 = 64;
/// Package not installed
pub const ENOPKG: i32 = 65;
/// Object is remote
pub const EREMOTE: i32 = 66;
/// Link has been severed
pub const ENOLINK: i32 = 67;
/// Advertise error
pub const EADV: i32 = 68;
/// Srmount error
pub const ESRMNT: i32 = 69;
/// Communication error on send
pub const ECOMM: i32 = 70;
/// Protocol error
pub const EPROTO: i32 = 71;
/// Multihop attempted
pub const EMULTIHOP: i32 = 72;
/// RFS specific error
pub const EDOTDOT: i32 = 73;
/// Bad message
pub const EBADMSG: i32 = 74;
/// Value too large for defined data type
pub const EOVERFLOW: i32 = 75;
/// Name not unique on network
pub const ENOTUNIQ: i32 = 76;
/// File descriptor in bad state
pub const EBADFD: i32 = 77;
/// Remote address changed
pub const EREMCHG: i32 = 78;
/// Can not access a needed shared library
pub const ELIBACC: i32 = 79;
/// Accessing a corrupted shared library
pub const ELIBBAD: i32 = 80;
/// .lib section in a.out corrupted
pub const ELIBSCN: i32 = 81;
/// Attempting to link in too many shared libraries
pub const ELIBMAX: i32 = 82;
/// Cannot exec a shared library directly
pub const ELIBEXEC: i32 = 83;
/// Invalid or incomplete multibyte or wide character
pub const EILSEQ: i32 = 84;
/// Interrupted system call should be restarted
pub const ERESTART: i32 = 85;
/// Streams pipe error
pub const ESTRPIPE: i32 = 86;
/// Too many users
pub const EUSERS: i32 = 87;
/// Socket operation on non-socket
pub const ENOTSOCK: i32 = 88;
/// Destination address required
pub const EDESTADDRREQ: i32 = 89;
/// Message too long
pub const EMSGSIZE: i32 = 90;
/// Protocol wrong type for socket
pub const EPROTOTYPE: i32 = 91;
/// Protocol not available
pub const ENOPROTOOPT: i32 = 92;
/// Protocol not supported
pub const EPROTONOSUPPORT: i32 = 93;
/// Socket type not supported
pub const ESOCKTNOSUPPORT: i32 = 94;
/// Operation not supported
pub const ENOTSUP: i32 = 95;
/// Protocol family not supported
pub const EPFNOSUPPORT: i32 = 96;
/// Address family not supported by protocol
pub const EAFNOSUPPORT: i32 = 97;
/// Address already in use
pub const EADDRINUSE: i32 = 98;
/// Cannot assign requested address
pub const EADDRNOTAVAIL: i32 = 99;
/// Network is down
pub const ENETDOWN: i32 = 100;
/// Network is unreachable
pub const ENETUNREACH: i32 = 101;
/// Network dropped connection on reset
pub const ENETRESET: i32 = 102;
/// Software caused connection abort
pub const ECONNABORTED: i32 = 103;
/// Connection reset by peer
pub const ECONNRESET: i32 = 104;
/// No buffer space available
pub const ENOBUFS: i32 = 105;
/// Transport endpoint is already connected
pub const EISCONN: i32 = 106;
/// Transport endpoint is not connected
pub const ENOTCONN: i32 = 107;
/// Cannot send after transport endpoint shutdown
pub const ESHUTDOWN: i32 = 108;
/// Too many references: cannot splice
pub const ETOOMANYREFS: i32 = 109;
/// Connection timed out
pub const ETIMEDOUT: i32 = 110;
/// Connection refused
pub const ECONNREFUSED: i32 = 111;
/// Host is down
pub const EHOSTDOWN: i32 = 112;
/// No route to host
pub const EHOSTUNREACH: i32 = 113;
/// Operation already in progress
pub const EALREADY: i32 = 114;
/// Operation now in progress
pub const EINPROGRESS: i32 = 115;
/// Stale file handle
pub const ESTALE: i32 = 116;
/// Structure needs cleaning
pub const EUCLEAN: i32 = 117;
/// Not a XENIX named type file
pub const ENOTNAM: i32 = 118;
/// No XENIX semaphores available
pub const ENAVAIL: i32 = 119;
/// Is a named type file
pub const EISNAM: i32 = 120;
/// Remote I/O error
pub const EREMOTEIO: i32 = 121;
/// Disk quota exceeded
pub const EDQUOT: i32 = 122;
/// No medium found
pub const ENOMEDIUM: i32 = 123;
/// Wrong medium type
pub const EMEDIUMTYPE: i32 = 124;
/// Operation canceled
pub const ECANCELED: i32 = 125;
/// Required key not available
pub const ENOKEY: i32 = 126;
/// Key has expired
pub const EKEYEXPIRED: i32 = 127;
/// Key has been revoked
pub const EKEYREVOKED: i32 = 128;
/// Key was rejected by service
pub const EKEYREJECTED: i32 = 129;
/// Owner died
pub const EOWNERDEAD: i32 = 130;
/// State not recoverable
pub const ENOTRECOVERABLE: i32 = 131;
/// Operation not possible due to RF-kill
pub const ERFKILL: i32 = 132;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(i32)]
#[non_exhaustive]
pub enum Errno {
    UnknownErrno = 0,
    EPERM = EPERM,
    ENOENT = ENOENT,
    ESRCH = ESRCH,
    EINTR = EINTR,
    EIO = EIO,
    ENXIO = ENXIO,
    E2BIG = E2BIG,
    ENOEXEC = ENOEXEC,
    EBADF = EBADF,
    ECHILD = ECHILD,
    EAGAIN = EAGAIN,
    ENOMEM = ENOMEM,
    EACCES = EACCES,
    EFAULT = EFAULT,
    ENOTBLK = ENOTBLK,
    EBUSY = EBUSY,
    EEXIST = EEXIST,
    EXDEV = EXDEV,
    ENODEV = ENODEV,
    ENOTDIR = ENOTDIR,
    EISDIR = EISDIR,
    EINVAL = EINVAL,
    ENFILE = ENFILE,
    EMFILE = EMFILE,
    ENOTTY = ENOTTY,
    ETXTBSY = ETXTBSY,
    EFBIG = EFBIG,
    ENOSPC = ENOSPC,
    ESPIPE = ESPIPE,
    EROFS = EROFS,
    EMLINK = EMLINK,
    EPIPE = EPIPE,
    EDOM = EDOM,
    ERANGE = ERANGE,
    EDEADLK = EDEADLOCK,
    ENAMETOOLONG = ENAMETOOLONG,
    ENOLCK = ENOLCK,
    ENOSYS = ENOSYS,
    ENOTEMPTY = ENOTEMPTY,
    ELOOP = ELOOP,
    ENOMSG = ENOMSG,
    EIDRM = EIDRM,
    ECHRNG = ECHRNG,
    EL2NSYNC = EL2NSYNC,
    EL3HLT = EL3HLT,
    EL3RST = EL3RST,
    ELNRNG = ELNRNG,
    EUNATCH = EUNATCH,
    ENOCSI = ENOCSI,
    EL2HLT = EL2HLT,
    EBADE = EBADE,
    EBADR = EBADR,
    EXFULL = EXFULL,
    ENOANO = ENOANO,
    EBADRQC = EBADRQC,
    EBADSLT = EBADSLT,
    EBFONT = EBFONT,
    ENOSTR = ENOSTR,
    ENODATA = ENODATA,
    ETIME = ETIME,
    ENOSR = ENOSR,
    ENONET = ENONET,
    ENOPKG = ENOPKG,
    EREMOTE = EREMOTE,
    ENOLINK = ENOLINK,
    EADV = EADV,
    ESRMNT = ESRMNT,
    ECOMM = ECOMM,
    EPROTO = EPROTO,
    EMULTIHOP = EMULTIHOP,
    EDOTDOT = EDOTDOT,
    EBADMSG = EBADMSG,
    EOVERFLOW = EOVERFLOW,
    ENOTUNIQ = ENOTUNIQ,
    EBADFD = EBADFD,
    EREMCHG = EREMCHG,
    ELIBACC = ELIBACC,
    ELIBBAD = ELIBBAD,
    ELIBSCN = ELIBSCN,
    ELIBMAX = ELIBMAX,
    ELIBEXEC = ELIBEXEC,
    EILSEQ = EILSEQ,
    ERESTART = ERESTART,
    ESTRPIPE = ESTRPIPE,
    EUSERS = EUSERS,
    ENOTSOCK = ENOTSOCK,
    EDESTADDRREQ = EDESTADDRREQ,
    EMSGSIZE = EMSGSIZE,
    EPROTOTYPE = EPROTOTYPE,
    ENOPROTOOPT = ENOPROTOOPT,
    EPROTONOSUPPORT = EPROTONOSUPPORT,
    ESOCKTNOSUPPORT = ESOCKTNOSUPPORT,
    EOPNOTSUPP = ENOTSUP,
    EPFNOSUPPORT = EPFNOSUPPORT,
    EAFNOSUPPORT = EAFNOSUPPORT,
    EADDRINUSE = EADDRINUSE,
    EADDRNOTAVAIL = EADDRNOTAVAIL,
    ENETDOWN = ENETDOWN,
    ENETUNREACH = ENETUNREACH,
    ENETRESET = ENETRESET,
    ECONNABORTED = ECONNABORTED,
    ECONNRESET = ECONNRESET,
    ENOBUFS = ENOBUFS,
    EISCONN = EISCONN,
    ENOTCONN = ENOTCONN,
    ESHUTDOWN = ESHUTDOWN,
    ETOOMANYREFS = ETOOMANYREFS,
    ETIMEDOUT = ETIMEDOUT,
    ECONNREFUSED = ECONNREFUSED,
    EHOSTDOWN = EHOSTDOWN,
    EHOSTUNREACH = EHOSTUNREACH,
    EALREADY = EALREADY,
    EINPROGRESS = EINPROGRESS,
    ESTALE = ESTALE,
    EUCLEAN = EUCLEAN,
    ENOTNAM = ENOTNAM,
    ENAVAIL = ENAVAIL,
    EISNAM = EISNAM,
    EREMOTEIO = EREMOTEIO,
    EDQUOT = EDQUOT,
    ENOMEDIUM = ENOMEDIUM,
    EMEDIUMTYPE = EMEDIUMTYPE,
    ECANCELED = ECANCELED,
    ENOKEY = ENOKEY,
    EKEYEXPIRED = EKEYEXPIRED,
    EKEYREVOKED = EKEYREVOKED,
    EKEYREJECTED = EKEYREJECTED,
    EOWNERDEAD = EOWNERDEAD,
    ENOTRECOVERABLE = ENOTRECOVERABLE,
    ERFKILL = ERFKILL,
}

impl Errno {
    pub const EWOULDBLOCK: Errno = Errno::EAGAIN;
    pub const EDEADLOCK: Errno = Errno::EDEADLK;
    pub const ENOTSUP: Errno = Errno::EOPNOTSUPP;

    pub const fn from_raw(e: i32) -> Errno {
        match e {
            EPERM => Errno::EPERM,
            ENOENT => Errno::ENOENT,
            ESRCH => Errno::ESRCH,
            EINTR => Errno::EINTR,
            EIO => Errno::EIO,
            ENXIO => Errno::ENXIO,
            E2BIG => Errno::E2BIG,
            ENOEXEC => Errno::ENOEXEC,
            EBADF => Errno::EBADF,
            ECHILD => Errno::ECHILD,
            EAGAIN => Errno::EAGAIN,
            ENOMEM => Errno::ENOMEM,
            EACCES => Errno::EACCES,
            EFAULT => Errno::EFAULT,
            ENOTBLK => Errno::ENOTBLK,
            EBUSY => Errno::EBUSY,
            EEXIST => Errno::EEXIST,
            EXDEV => Errno::EXDEV,
            ENODEV => Errno::ENODEV,
            ENOTDIR => Errno::ENOTDIR,
            EISDIR => Errno::EISDIR,
            EINVAL => Errno::EINVAL,
            ENFILE => Errno::ENFILE,
            EMFILE => Errno::EMFILE,
            ENOTTY => Errno::ENOTTY,
            ETXTBSY => Errno::ETXTBSY,
            EFBIG => Errno::EFBIG,
            ENOSPC => Errno::ENOSPC,
            ESPIPE => Errno::ESPIPE,
            EROFS => Errno::EROFS,
            EMLINK => Errno::EMLINK,
            EPIPE => Errno::EPIPE,
            EDOM => Errno::EDOM,
            ERANGE => Errno::ERANGE,
            EDEADLOCK => Errno::EDEADLK,
            ENAMETOOLONG => Errno::ENAMETOOLONG,
            ENOLCK => Errno::ENOLCK,
            ENOSYS => Errno::ENOSYS,
            ENOTEMPTY => Errno::ENOTEMPTY,
            ELOOP => Errno::ELOOP,
            ENOMSG => Errno::ENOMSG,
            EIDRM => Errno::EIDRM,
            ECHRNG => Errno::ECHRNG,
            EL2NSYNC => Errno::EL2NSYNC,
            EL3HLT => Errno::EL3HLT,
            EL3RST => Errno::EL3RST,
            ELNRNG => Errno::ELNRNG,
            EUNATCH => Errno::EUNATCH,
            ENOCSI => Errno::ENOCSI,
            EL2HLT => Errno::EL2HLT,
            EBADE => Errno::EBADE,
            EBADR => Errno::EBADR,
            EXFULL => Errno::EXFULL,
            ENOANO => Errno::ENOANO,
            EBADRQC => Errno::EBADRQC,
            EBADSLT => Errno::EBADSLT,
            EBFONT => Errno::EBFONT,
            ENOSTR => Errno::ENOSTR,
            ENODATA => Errno::ENODATA,
            ETIME => Errno::ETIME,
            ENOSR => Errno::ENOSR,
            ENONET => Errno::ENONET,
            ENOPKG => Errno::ENOPKG,
            EREMOTE => Errno::EREMOTE,
            ENOLINK => Errno::ENOLINK,
            EADV => Errno::EADV,
            ESRMNT => Errno::ESRMNT,
            ECOMM => Errno::ECOMM,
            EPROTO => Errno::EPROTO,
            EMULTIHOP => Errno::EMULTIHOP,
            EDOTDOT => Errno::EDOTDOT,
            EBADMSG => Errno::EBADMSG,
            EOVERFLOW => Errno::EOVERFLOW,
            ENOTUNIQ => Errno::ENOTUNIQ,
            EBADFD => Errno::EBADFD,
            EREMCHG => Errno::EREMCHG,
            ELIBACC => Errno::ELIBACC,
            ELIBBAD => Errno::ELIBBAD,
            ELIBSCN => Errno::ELIBSCN,
            ELIBMAX => Errno::ELIBMAX,
            ELIBEXEC => Errno::ELIBEXEC,
            EILSEQ => Errno::EILSEQ,
            ERESTART => Errno::ERESTART,
            ESTRPIPE => Errno::ESTRPIPE,
            EUSERS => Errno::EUSERS,
            ENOTSOCK => Errno::ENOTSOCK,
            EDESTADDRREQ => Errno::EDESTADDRREQ,
            EMSGSIZE => Errno::EMSGSIZE,
            EPROTOTYPE => Errno::EPROTOTYPE,
            ENOPROTOOPT => Errno::ENOPROTOOPT,
            EPROTONOSUPPORT => Errno::EPROTONOSUPPORT,
            ESOCKTNOSUPPORT => Errno::ESOCKTNOSUPPORT,
            ENOTSUP => Errno::EOPNOTSUPP,
            EPFNOSUPPORT => Errno::EPFNOSUPPORT,
            EAFNOSUPPORT => Errno::EAFNOSUPPORT,
            EADDRINUSE => Errno::EADDRINUSE,
            EADDRNOTAVAIL => Errno::EADDRNOTAVAIL,
            ENETDOWN => Errno::ENETDOWN,
            ENETUNREACH => Errno::ENETUNREACH,
            ENETRESET => Errno::ENETRESET,
            ECONNABORTED => Errno::ECONNABORTED,
            ECONNRESET => Errno::ECONNRESET,
            ENOBUFS => Errno::ENOBUFS,
            EISCONN => Errno::EISCONN,
            ENOTCONN => Errno::ENOTCONN,
            ESHUTDOWN => Errno::ESHUTDOWN,
            ETOOMANYREFS => Errno::ETOOMANYREFS,
            ETIMEDOUT => Errno::ETIMEDOUT,
            ECONNREFUSED => Errno::ECONNREFUSED,
            EHOSTDOWN => Errno::EHOSTDOWN,
            EHOSTUNREACH => Errno::EHOSTUNREACH,
            EALREADY => Errno::EALREADY,
            EINPROGRESS => Errno::EINPROGRESS,
            ESTALE => Errno::ESTALE,
            EUCLEAN => Errno::EUCLEAN,
            ENOTNAM => Errno::ENOTNAM,
            ENAVAIL => Errno::ENAVAIL,
            EISNAM => Errno::EISNAM,
            EREMOTEIO => Errno::EREMOTEIO,
            EDQUOT => Errno::EDQUOT,
            ENOMEDIUM => Errno::ENOMEDIUM,
            EMEDIUMTYPE => Errno::EMEDIUMTYPE,
            ECANCELED => Errno::ECANCELED,
            ENOKEY => Errno::ENOKEY,
            EKEYEXPIRED => Errno::EKEYEXPIRED,
            EKEYREVOKED => Errno::EKEYREVOKED,
            EKEYREJECTED => Errno::EKEYREJECTED,
            EOWNERDEAD => Errno::EOWNERDEAD,
            ENOTRECOVERABLE => Errno::ENOTRECOVERABLE,
            ERFKILL => Errno::ERFKILL,
            _ => Errno::UnknownErrno,
        }
    }
}

impl core::error::Error for Errno {}

impl core::fmt::Display for Errno {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(f, "{:?}: some error", self)
    }
}
