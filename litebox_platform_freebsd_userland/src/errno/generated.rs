//! Generated code for the [`super::Errno`] constants.
//!
//! This particular module itself is private, but defines all of the below within the public
//! [`super::Errno`] type, so as to have them all be exposed, but still keep the auto-generated code
//! restricted to this single file.
//!

impl super::Errno {
    /// Human-friendly readable version of `self`.
    ///
    /// Generated from FreeBSD 14.3 errno manual page
    /// https://man.freebsd.org/cgi/man.cgi?errno
    #[expect(
        clippy::too_many_lines,
        reason = "auto-generated code that needs to reference a large number of values"
    )]
    pub(crate) const fn as_str(self) -> &'static str {
        match self.value.get() {
            1 => "EPERM: Operation not permitted",
            2 => "ENOENT: No such file or directory",
            3 => "ESRCH: No such process",
            4 => "EINTR: Interrupted system call",
            5 => "EIO: Input/output error",
            6 => "ENXIO: Device not configured",
            7 => "E2BIG: Argument list too long",
            8 => "ENOEXEC: Exec format error",
            9 => "EBADF: Bad file descriptor",
            10 => "ECHILD: No child processes",
            11 => "EDEADLK: Resource deadlock avoided",
            12 => "ENOMEM: Cannot allocate memory",
            13 => "EACCES: Permission denied",
            14 => "EFAULT: Bad address",
            15 => "ENOTBLK: Block device required",
            16 => "EBUSY: Device busy",
            17 => "EEXIST: File exists",
            18 => "EXDEV: Cross-device link",
            19 => "ENODEV: Operation not supported by device",
            20 => "ENOTDIR: Not a directory",
            21 => "EISDIR: Is a directory",
            22 => "EINVAL: Invalid argument",
            23 => "ENFILE: Too many open files in system",
            24 => "EMFILE: Too many open files",
            25 => "ENOTTY: Inappropriate ioctl for device",
            26 => "ETXTBSY: Text file busy",
            27 => "EFBIG: File too large",
            28 => "ENOSPC: No space left on device",
            29 => "ESPIPE: Illegal seek",
            30 => "EROFS: Read-only file system",
            31 => "EMLINK: Too many links",
            32 => "EPIPE: Broken pipe",
            33 => "EDOM: Numerical argument out of domain",
            34 => "ERANGE: Result too large",
            35 => "EAGAIN: Resource temporarily unavailable",
            36 => "EINPROGRESS: Operation now in progress",
            37 => "EALREADY: Operation already in progress",
            38 => "ENOTSOCK: Socket operation on non-socket",
            39 => "EDESTADDRREQ: Destination address required",
            40 => "EMSGSIZE: Message too long",
            41 => "EPROTOTYPE: Protocol wrong type for socket",
            42 => "ENOPROTOOPT: Protocol not available",
            43 => "EPROTONOSUPPORT: Protocol not supported",
            44 => "ESOCKTNOSUPPORT: Socket type not supported",
            45 => "EOPNOTSUPP: Operation not supported",
            46 => "EPFNOSUPPORT: Protocol family not supported",
            47 => "EAFNOSUPPORT: Address family not supported by protocol family",
            48 => "EADDRINUSE: Address already in use",
            49 => "EADDRNOTAVAIL: Can't assign requested address",
            50 => "ENETDOWN: Network is down",
            51 => "ENETUNREACH: Network is unreachable",
            52 => "ENETRESET: Network dropped connection on reset",
            53 => "ECONNABORTED: Software caused connection abort",
            54 => "ECONNRESET: Connection reset by peer",
            55 => "ENOBUFS: No buffer space available",
            56 => "EISCONN: Socket is already connected",
            57 => "ENOTCONN: Socket is not connected",
            58 => "ESHUTDOWN: Can't send after socket shutdown",
            60 => "ETIMEDOUT: Operation timed out",
            61 => "ECONNREFUSED: Connection refused",
            62 => "ELOOP: Too many levels of symbolic links",
            63 => "ENAMETOOLONG: File name too long",
            64 => "EHOSTDOWN: Host is down",
            65 => "EHOSTUNREACH: No route to host",
            66 => "ENOTEMPTY: Directory not empty",
            67 => "EPROCLIM: Too many processes",
            68 => "EUSERS: Too many users",
            69 => "EDQUOT: Disc quota exceeded",
            70 => "ESTALE: Stale NFS file handle",
            72 => "EBADRPC: RPC struct is bad",
            73 => "ERPCMISMATCH: RPC version wrong",
            74 => "EPROGUNAVAIL: RPC prog. not avail",
            75 => "EPROGMISMATCH: Program version wrong",
            76 => "EPROCUNAVAIL: Bad procedure for program",
            77 => "ENOLCK: No locks available",
            78 => "ENOSYS: Function not implemented",
            79 => "EFTYPE: Inappropriate file type or format",
            80 => "EAUTH: Authentication error",
            81 => "ENEEDAUTH: Need authenticator",
            82 => "EIDRM: Identifier removed",
            83 => "ENOMSG: No message of desired type",
            84 => "EOVERFLOW: Value too large to be stored in data type",
            85 => "ECANCELED: Operation canceled",
            86 => "EILSEQ: Illegal byte sequence",
            87 => "ENOATTR: Attribute not found",
            88 => "EDOOFUS: Programming error",
            89 => "EBADMSG: Bad message",
            90 => "EMULTIHOP: Multihop attempted",
            91 => "ENOLINK: Link has been severed",
            92 => "EPROTO: Protocol error",
            93 => "ENOTCAPABLE: Capabilities insufficient",
            94 => "ECAPMODE: Not permitted in capability mode",
            95 => "ENOTRECOVERABLE: State not recoverable",
            96 => "EOWNERDEAD: Previous owner died",
            97 => "EINTEGRITY: Integrity check failed",
            _ => unreachable!(),
        }
    }
}

/// The associated constants for [`super::Errno`] are generated from FreeBSD errno values
/// https://man.freebsd.org/cgi/man.cgi?errno
#[expect(unused, reason = "Generated code that is not used in the current context, but useful for error handling later on.")]
impl super::Errno {
    /// Operation not permitted
    pub(crate) const EPERM: Self = Self::from_const(1);
    /// No such file or directory
    pub(crate) const ENOENT: Self = Self::from_const(2);
    /// No such process
    pub(crate) const ESRCH: Self = Self::from_const(3);
    /// Interrupted system call
    pub(crate) const EINTR: Self = Self::from_const(4);
    /// Input/output error
    pub(crate) const EIO: Self = Self::from_const(5);
    /// Device not configured
    pub(crate) const ENXIO: Self = Self::from_const(6);
    /// Argument list too long
    pub(crate) const E2BIG: Self = Self::from_const(7);
    /// Exec format error
    pub(crate) const ENOEXEC: Self = Self::from_const(8);
    /// Bad file descriptor
    pub(crate) const EBADF: Self = Self::from_const(9);
    /// No child processes
    pub(crate) const ECHILD: Self = Self::from_const(10);
    /// Resource deadlock avoided
    pub(crate) const EDEADLK: Self = Self::from_const(11);
    /// Cannot allocate memory
    pub(crate) const ENOMEM: Self = Self::from_const(12);
    /// Permission denied
    pub(crate) const EACCES: Self = Self::from_const(13);
    /// Bad address
    pub(crate) const EFAULT: Self = Self::from_const(14);
    /// Block device required
    pub(crate) const ENOTBLK: Self = Self::from_const(15);
    /// Device busy
    pub(crate) const EBUSY: Self = Self::from_const(16);
    /// File exists
    pub(crate) const EEXIST: Self = Self::from_const(17);
    /// Cross-device link
    pub(crate) const EXDEV: Self = Self::from_const(18);
    /// Operation not supported by device
    pub(crate) const ENODEV: Self = Self::from_const(19);
    /// Not a directory
    pub(crate) const ENOTDIR: Self = Self::from_const(20);
    /// Is a directory
    pub(crate) const EISDIR: Self = Self::from_const(21);
    /// Invalid argument
    pub(crate) const EINVAL: Self = Self::from_const(22);
    /// Too many open files in system
    pub(crate) const ENFILE: Self = Self::from_const(23);
    /// Too many open files
    pub(crate) const EMFILE: Self = Self::from_const(24);
    /// Inappropriate ioctl for device
    pub(crate) const ENOTTY: Self = Self::from_const(25);
    /// Text file busy
    pub(crate) const ETXTBSY: Self = Self::from_const(26);
    /// File too large
    pub(crate) const EFBIG: Self = Self::from_const(27);
    /// No space left on device
    pub(crate) const ENOSPC: Self = Self::from_const(28);
    /// Illegal seek
    pub(crate) const ESPIPE: Self = Self::from_const(29);
    /// Read-only file system
    pub(crate) const EROFS: Self = Self::from_const(30);
    /// Too many links
    pub(crate) const EMLINK: Self = Self::from_const(31);
    /// Broken pipe
    pub(crate) const EPIPE: Self = Self::from_const(32);
    /// Numerical argument out of domain
    pub(crate) const EDOM: Self = Self::from_const(33);
    /// Result too large
    pub(crate) const ERANGE: Self = Self::from_const(34);
    /// Resource temporarily unavailable
    pub(crate) const EAGAIN: Self = Self::from_const(35);
    /// Operation now in progress
    pub(crate) const EINPROGRESS: Self = Self::from_const(36);
    /// Operation already in progress
    pub(crate) const EALREADY: Self = Self::from_const(37);
    /// Socket operation on non-socket
    pub(crate) const ENOTSOCK: Self = Self::from_const(38);
    /// Destination address required
    pub(crate) const EDESTADDRREQ: Self = Self::from_const(39);
    /// Message too long
    pub(crate) const EMSGSIZE: Self = Self::from_const(40);
    /// Protocol wrong type for socket
    pub(crate) const EPROTOTYPE: Self = Self::from_const(41);
    /// Protocol not available
    pub(crate) const ENOPROTOOPT: Self = Self::from_const(42);
    /// Protocol not supported
    pub(crate) const EPROTONOSUPPORT: Self = Self::from_const(43);
    /// Socket type not supported
    pub(crate) const ESOCKTNOSUPPORT: Self = Self::from_const(44);
    /// Operation not supported
    pub(crate) const EOPNOTSUPP: Self = Self::from_const(45);
    /// Protocol family not supported
    pub(crate) const EPFNOSUPPORT: Self = Self::from_const(46);
    /// Address family not supported by protocol family
    pub(crate) const EAFNOSUPPORT: Self = Self::from_const(47);
    /// Address already in use
    pub(crate) const EADDRINUSE: Self = Self::from_const(48);
    /// Can't assign requested address
    pub(crate) const EADDRNOTAVAIL: Self = Self::from_const(49);
    /// Network is down
    pub(crate) const ENETDOWN: Self = Self::from_const(50);
    /// Network is unreachable
    pub(crate) const ENETUNREACH: Self = Self::from_const(51);
    /// Network dropped connection on reset
    pub(crate) const ENETRESET: Self = Self::from_const(52);
    /// Software caused connection abort
    pub(crate) const ECONNABORTED: Self = Self::from_const(53);
    /// Connection reset by peer
    pub(crate) const ECONNRESET: Self = Self::from_const(54);
    /// No buffer space available
    pub(crate) const ENOBUFS: Self = Self::from_const(55);
    /// Socket is already connected
    pub(crate) const EISCONN: Self = Self::from_const(56);
    /// Socket is not connected
    pub(crate) const ENOTCONN: Self = Self::from_const(57);
    /// Can't send after socket shutdown
    pub(crate) const ESHUTDOWN: Self = Self::from_const(58);
    /// Operation timed out
    pub(crate) const ETIMEDOUT: Self = Self::from_const(60);
    /// Connection refused
    pub(crate) const ECONNREFUSED: Self = Self::from_const(61);
    /// Too many levels of symbolic links
    pub(crate) const ELOOP: Self = Self::from_const(62);
    /// File name too long
    pub(crate) const ENAMETOOLONG: Self = Self::from_const(63);
    /// Host is down
    pub(crate) const EHOSTDOWN: Self = Self::from_const(64);
    /// No route to host
    pub(crate) const EHOSTUNREACH: Self = Self::from_const(65);
    /// Directory not empty
    pub(crate) const ENOTEMPTY: Self = Self::from_const(66);
    /// Too many processes
    pub(crate) const EPROCLIM: Self = Self::from_const(67);
    /// Too many users
    pub(crate) const EUSERS: Self = Self::from_const(68);
    /// Disc quota exceeded
    pub(crate) const EDQUOT: Self = Self::from_const(69);
    /// Stale NFS file handle
    pub(crate) const ESTALE: Self = Self::from_const(70);
    /// RPC struct is bad
    pub(crate) const EBADRPC: Self = Self::from_const(72);
    /// RPC version wrong
    pub(crate) const ERPCMISMATCH: Self = Self::from_const(73);
    /// RPC prog. not avail
    pub(crate) const EPROGUNAVAIL: Self = Self::from_const(74);
    /// Program version wrong
    pub(crate) const EPROGMISMATCH: Self = Self::from_const(75);
    /// Bad procedure for program
    pub(crate) const EPROCUNAVAIL: Self = Self::from_const(76);
    /// No locks available
    pub(crate) const ENOLCK: Self = Self::from_const(77);
    /// Function not implemented
    pub(crate) const ENOSYS: Self = Self::from_const(78);
    /// Inappropriate file type or format
    pub(crate) const EFTYPE: Self = Self::from_const(79);
    /// Authentication error
    pub(crate) const EAUTH: Self = Self::from_const(80);
    /// Need authenticator
    pub(crate) const ENEEDAUTH: Self = Self::from_const(81);
    /// Identifier removed
    pub(crate) const EIDRM: Self = Self::from_const(82);
    /// No message of desired type
    pub(crate) const ENOMSG: Self = Self::from_const(83);
    /// Value too large to be stored in data type
    pub(crate) const EOVERFLOW: Self = Self::from_const(84);
    /// Operation canceled
    pub(crate) const ECANCELED: Self = Self::from_const(85);
    /// Illegal byte sequence
    pub(crate) const EILSEQ: Self = Self::from_const(86);
    /// Attribute not found
    pub(crate) const ENOATTR: Self = Self::from_const(87);
    /// Programming error
    pub(crate) const EDOOFUS: Self = Self::from_const(88);
    /// Bad message
    pub(crate) const EBADMSG: Self = Self::from_const(89);
    /// Multihop attempted
    pub(crate) const EMULTIHOP: Self = Self::from_const(90);
    /// Link has been severed
    pub(crate) const ENOLINK: Self = Self::from_const(91);
    /// Protocol error
    pub(crate) const EPROTO: Self = Self::from_const(92);
    /// Capabilities insufficient
    pub(crate) const ENOTCAPABLE: Self = Self::from_const(93);
    /// Not permitted in capability mode
    pub(crate) const ECAPMODE: Self = Self::from_const(94);
    /// State not recoverable
    pub(crate) const ENOTRECOVERABLE: Self = Self::from_const(95);
    /// Previous owner died
    pub(crate) const EOWNERDEAD: Self = Self::from_const(96);
    /// Integrity check failed
    pub(crate) const EINTEGRITY: Self = Self::from_const(97);

    /// Resource temporarily unavailable (alias for EAGAIN)
    pub(crate) const EWOULDBLOCK: Self = Self::from_const(35);
    /// Operation not supported (alias for EOPNOTSUPP)
    pub(crate) const ENOTSUP: Self = Self::from_const(45);

    /// The maximum supported Errno
    pub(crate) const MAX: Self = Self::from_const(97);
}
