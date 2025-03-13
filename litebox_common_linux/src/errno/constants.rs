//! Error number constants. See [`Errno`] docs to see the command to generate the following.
//!
//! This particular module itself is private, but defines all the below associated constants within
//! the public [`Errno`] type, so as to have them all be exposed, but still keep the auto-generated
//! code restricted to this single file.

use core::num::NonZeroU8;

impl super::Errno {
    /// Operation not permitted
    pub const EPERM: Self = Self {
        value: NonZeroU8::new(1).unwrap(),
    };
    /// No such file or directory
    pub const ENOENT: Self = Self {
        value: NonZeroU8::new(2).unwrap(),
    };
    /// No such process
    pub const ESRCH: Self = Self {
        value: NonZeroU8::new(3).unwrap(),
    };
    /// Interrupted system call
    pub const EINTR: Self = Self {
        value: NonZeroU8::new(4).unwrap(),
    };
    /// Input/output error
    pub const EIO: Self = Self {
        value: NonZeroU8::new(5).unwrap(),
    };
    /// No such device or address
    pub const ENXIO: Self = Self {
        value: NonZeroU8::new(6).unwrap(),
    };
    /// Argument list too long
    pub const E2BIG: Self = Self {
        value: NonZeroU8::new(7).unwrap(),
    };
    /// Exec format error
    pub const ENOEXEC: Self = Self {
        value: NonZeroU8::new(8).unwrap(),
    };
    /// Bad file descriptor
    pub const EBADF: Self = Self {
        value: NonZeroU8::new(9).unwrap(),
    };
    /// No child processes
    pub const ECHILD: Self = Self {
        value: NonZeroU8::new(10).unwrap(),
    };
    /// Resource temporarily unavailable
    pub const EAGAIN: Self = Self {
        value: NonZeroU8::new(11).unwrap(),
    };
    /// Cannot allocate memory
    pub const ENOMEM: Self = Self {
        value: NonZeroU8::new(12).unwrap(),
    };
    /// Permission denied
    pub const EACCES: Self = Self {
        value: NonZeroU8::new(13).unwrap(),
    };
    /// Bad address
    pub const EFAULT: Self = Self {
        value: NonZeroU8::new(14).unwrap(),
    };
    /// Block device required
    pub const ENOTBLK: Self = Self {
        value: NonZeroU8::new(15).unwrap(),
    };
    /// Device or resource busy
    pub const EBUSY: Self = Self {
        value: NonZeroU8::new(16).unwrap(),
    };
    /// File exists
    pub const EEXIST: Self = Self {
        value: NonZeroU8::new(17).unwrap(),
    };
    /// Invalid cross-device link
    pub const EXDEV: Self = Self {
        value: NonZeroU8::new(18).unwrap(),
    };
    /// No such device
    pub const ENODEV: Self = Self {
        value: NonZeroU8::new(19).unwrap(),
    };
    /// Not a directory
    pub const ENOTDIR: Self = Self {
        value: NonZeroU8::new(20).unwrap(),
    };
    /// Is a directory
    pub const EISDIR: Self = Self {
        value: NonZeroU8::new(21).unwrap(),
    };
    /// Invalid argument
    pub const EINVAL: Self = Self {
        value: NonZeroU8::new(22).unwrap(),
    };
    /// Too many open files in system
    pub const ENFILE: Self = Self {
        value: NonZeroU8::new(23).unwrap(),
    };
    /// Too many open files
    pub const EMFILE: Self = Self {
        value: NonZeroU8::new(24).unwrap(),
    };
    /// Inappropriate ioctl for device
    pub const ENOTTY: Self = Self {
        value: NonZeroU8::new(25).unwrap(),
    };
    /// Text file busy
    pub const ETXTBSY: Self = Self {
        value: NonZeroU8::new(26).unwrap(),
    };
    /// File too large
    pub const EFBIG: Self = Self {
        value: NonZeroU8::new(27).unwrap(),
    };
    /// No space left on device
    pub const ENOSPC: Self = Self {
        value: NonZeroU8::new(28).unwrap(),
    };
    /// Illegal seek
    pub const ESPIPE: Self = Self {
        value: NonZeroU8::new(29).unwrap(),
    };
    /// Read-only file system
    pub const EROFS: Self = Self {
        value: NonZeroU8::new(30).unwrap(),
    };
    /// Too many links
    pub const EMLINK: Self = Self {
        value: NonZeroU8::new(31).unwrap(),
    };
    /// Broken pipe
    pub const EPIPE: Self = Self {
        value: NonZeroU8::new(32).unwrap(),
    };
    /// Numerical argument out of domain
    pub const EDOM: Self = Self {
        value: NonZeroU8::new(33).unwrap(),
    };
    /// Numerical result out of range
    pub const ERANGE: Self = Self {
        value: NonZeroU8::new(34).unwrap(),
    };
    /// Resource deadlock avoided
    pub const EDEADLK: Self = Self {
        value: NonZeroU8::new(35).unwrap(),
    };
    /// File name too long
    pub const ENAMETOOLONG: Self = Self {
        value: NonZeroU8::new(36).unwrap(),
    };
    /// No locks available
    pub const ENOLCK: Self = Self {
        value: NonZeroU8::new(37).unwrap(),
    };
    /// Function not implemented
    pub const ENOSYS: Self = Self {
        value: NonZeroU8::new(38).unwrap(),
    };
    /// Directory not empty
    pub const ENOTEMPTY: Self = Self {
        value: NonZeroU8::new(39).unwrap(),
    };
    /// Too many levels of symbolic links
    pub const ELOOP: Self = Self {
        value: NonZeroU8::new(40).unwrap(),
    };
    /// Resource temporarily unavailable
    pub const EWOULDBLOCK: Self = Self {
        value: NonZeroU8::new(11).unwrap(),
    };
    /// No message of desired type
    pub const ENOMSG: Self = Self {
        value: NonZeroU8::new(42).unwrap(),
    };
    /// Identifier removed
    pub const EIDRM: Self = Self {
        value: NonZeroU8::new(43).unwrap(),
    };
    /// Channel number out of range
    pub const ECHRNG: Self = Self {
        value: NonZeroU8::new(44).unwrap(),
    };
    /// Level 2 not synchronized
    pub const EL2NSYNC: Self = Self {
        value: NonZeroU8::new(45).unwrap(),
    };
    /// Level 3 halted
    pub const EL3HLT: Self = Self {
        value: NonZeroU8::new(46).unwrap(),
    };
    /// Level 3 reset
    pub const EL3RST: Self = Self {
        value: NonZeroU8::new(47).unwrap(),
    };
    /// Link number out of range
    pub const ELNRNG: Self = Self {
        value: NonZeroU8::new(48).unwrap(),
    };
    /// Protocol driver not attached
    pub const EUNATCH: Self = Self {
        value: NonZeroU8::new(49).unwrap(),
    };
    /// No CSI structure available
    pub const ENOCSI: Self = Self {
        value: NonZeroU8::new(50).unwrap(),
    };
    /// Level 2 halted
    pub const EL2HLT: Self = Self {
        value: NonZeroU8::new(51).unwrap(),
    };
    /// Invalid exchange
    pub const EBADE: Self = Self {
        value: NonZeroU8::new(52).unwrap(),
    };
    /// Invalid request descriptor
    pub const EBADR: Self = Self {
        value: NonZeroU8::new(53).unwrap(),
    };
    /// Exchange full
    pub const EXFULL: Self = Self {
        value: NonZeroU8::new(54).unwrap(),
    };
    /// No anode
    pub const ENOANO: Self = Self {
        value: NonZeroU8::new(55).unwrap(),
    };
    /// Invalid request code
    pub const EBADRQC: Self = Self {
        value: NonZeroU8::new(56).unwrap(),
    };
    /// Invalid slot
    pub const EBADSLT: Self = Self {
        value: NonZeroU8::new(57).unwrap(),
    };
    /// Resource deadlock avoided
    pub const EDEADLOCK: Self = Self {
        value: NonZeroU8::new(35).unwrap(),
    };
    /// Bad font file format
    pub const EBFONT: Self = Self {
        value: NonZeroU8::new(59).unwrap(),
    };
    /// Device not a stream
    pub const ENOSTR: Self = Self {
        value: NonZeroU8::new(60).unwrap(),
    };
    /// No data available
    pub const ENODATA: Self = Self {
        value: NonZeroU8::new(61).unwrap(),
    };
    /// Timer expired
    pub const ETIME: Self = Self {
        value: NonZeroU8::new(62).unwrap(),
    };
    /// Out of streams resources
    pub const ENOSR: Self = Self {
        value: NonZeroU8::new(63).unwrap(),
    };
    /// Machine is not on the network
    pub const ENONET: Self = Self {
        value: NonZeroU8::new(64).unwrap(),
    };
    /// Package not installed
    pub const ENOPKG: Self = Self {
        value: NonZeroU8::new(65).unwrap(),
    };
    /// Object is remote
    pub const EREMOTE: Self = Self {
        value: NonZeroU8::new(66).unwrap(),
    };
    /// Link has been severed
    pub const ENOLINK: Self = Self {
        value: NonZeroU8::new(67).unwrap(),
    };
    /// Advertise error
    pub const EADV: Self = Self {
        value: NonZeroU8::new(68).unwrap(),
    };
    /// Srmount error
    pub const ESRMNT: Self = Self {
        value: NonZeroU8::new(69).unwrap(),
    };
    /// Communication error on send
    pub const ECOMM: Self = Self {
        value: NonZeroU8::new(70).unwrap(),
    };
    /// Protocol error
    pub const EPROTO: Self = Self {
        value: NonZeroU8::new(71).unwrap(),
    };
    /// Multihop attempted
    pub const EMULTIHOP: Self = Self {
        value: NonZeroU8::new(72).unwrap(),
    };
    /// RFS specific error
    pub const EDOTDOT: Self = Self {
        value: NonZeroU8::new(73).unwrap(),
    };
    /// Bad message
    pub const EBADMSG: Self = Self {
        value: NonZeroU8::new(74).unwrap(),
    };
    /// Value too large for defined data type
    pub const EOVERFLOW: Self = Self {
        value: NonZeroU8::new(75).unwrap(),
    };
    /// Name not unique on network
    pub const ENOTUNIQ: Self = Self {
        value: NonZeroU8::new(76).unwrap(),
    };
    /// File descriptor in bad state
    pub const EBADFD: Self = Self {
        value: NonZeroU8::new(77).unwrap(),
    };
    /// Remote address changed
    pub const EREMCHG: Self = Self {
        value: NonZeroU8::new(78).unwrap(),
    };
    /// Can not access a needed shared library
    pub const ELIBACC: Self = Self {
        value: NonZeroU8::new(79).unwrap(),
    };
    /// Accessing a corrupted shared library
    pub const ELIBBAD: Self = Self {
        value: NonZeroU8::new(80).unwrap(),
    };
    /// .lib section in a.out corrupted
    pub const ELIBSCN: Self = Self {
        value: NonZeroU8::new(81).unwrap(),
    };
    /// Attempting to link in too many shared libraries
    pub const ELIBMAX: Self = Self {
        value: NonZeroU8::new(82).unwrap(),
    };
    /// Cannot exec a shared library directly
    pub const ELIBEXEC: Self = Self {
        value: NonZeroU8::new(83).unwrap(),
    };
    /// Invalid or incomplete multibyte or wide character
    pub const EILSEQ: Self = Self {
        value: NonZeroU8::new(84).unwrap(),
    };
    /// Interrupted system call should be restarted
    pub const ERESTART: Self = Self {
        value: NonZeroU8::new(85).unwrap(),
    };
    /// Streams pipe error
    pub const ESTRPIPE: Self = Self {
        value: NonZeroU8::new(86).unwrap(),
    };
    /// Too many users
    pub const EUSERS: Self = Self {
        value: NonZeroU8::new(87).unwrap(),
    };
    /// Socket operation on non-socket
    pub const ENOTSOCK: Self = Self {
        value: NonZeroU8::new(88).unwrap(),
    };
    /// Destination address required
    pub const EDESTADDRREQ: Self = Self {
        value: NonZeroU8::new(89).unwrap(),
    };
    /// Message too long
    pub const EMSGSIZE: Self = Self {
        value: NonZeroU8::new(90).unwrap(),
    };
    /// Protocol wrong type for socket
    pub const EPROTOTYPE: Self = Self {
        value: NonZeroU8::new(91).unwrap(),
    };
    /// Protocol not available
    pub const ENOPROTOOPT: Self = Self {
        value: NonZeroU8::new(92).unwrap(),
    };
    /// Protocol not supported
    pub const EPROTONOSUPPORT: Self = Self {
        value: NonZeroU8::new(93).unwrap(),
    };
    /// Socket type not supported
    pub const ESOCKTNOSUPPORT: Self = Self {
        value: NonZeroU8::new(94).unwrap(),
    };
    /// Operation not supported
    pub const EOPNOTSUPP: Self = Self {
        value: NonZeroU8::new(95).unwrap(),
    };
    /// Protocol family not supported
    pub const EPFNOSUPPORT: Self = Self {
        value: NonZeroU8::new(96).unwrap(),
    };
    /// Address family not supported by protocol
    pub const EAFNOSUPPORT: Self = Self {
        value: NonZeroU8::new(97).unwrap(),
    };
    /// Address already in use
    pub const EADDRINUSE: Self = Self {
        value: NonZeroU8::new(98).unwrap(),
    };
    /// Cannot assign requested address
    pub const EADDRNOTAVAIL: Self = Self {
        value: NonZeroU8::new(99).unwrap(),
    };
    /// Network is down
    pub const ENETDOWN: Self = Self {
        value: NonZeroU8::new(100).unwrap(),
    };
    /// Network is unreachable
    pub const ENETUNREACH: Self = Self {
        value: NonZeroU8::new(101).unwrap(),
    };
    /// Network dropped connection on reset
    pub const ENETRESET: Self = Self {
        value: NonZeroU8::new(102).unwrap(),
    };
    /// Software caused connection abort
    pub const ECONNABORTED: Self = Self {
        value: NonZeroU8::new(103).unwrap(),
    };
    /// Connection reset by peer
    pub const ECONNRESET: Self = Self {
        value: NonZeroU8::new(104).unwrap(),
    };
    /// No buffer space available
    pub const ENOBUFS: Self = Self {
        value: NonZeroU8::new(105).unwrap(),
    };
    /// Transport endpoint is already connected
    pub const EISCONN: Self = Self {
        value: NonZeroU8::new(106).unwrap(),
    };
    /// Transport endpoint is not connected
    pub const ENOTCONN: Self = Self {
        value: NonZeroU8::new(107).unwrap(),
    };
    /// Cannot send after transport endpoint shutdown
    pub const ESHUTDOWN: Self = Self {
        value: NonZeroU8::new(108).unwrap(),
    };
    /// Too many references: cannot splice
    pub const ETOOMANYREFS: Self = Self {
        value: NonZeroU8::new(109).unwrap(),
    };
    /// Connection timed out
    pub const ETIMEDOUT: Self = Self {
        value: NonZeroU8::new(110).unwrap(),
    };
    /// Connection refused
    pub const ECONNREFUSED: Self = Self {
        value: NonZeroU8::new(111).unwrap(),
    };
    /// Host is down
    pub const EHOSTDOWN: Self = Self {
        value: NonZeroU8::new(112).unwrap(),
    };
    /// No route to host
    pub const EHOSTUNREACH: Self = Self {
        value: NonZeroU8::new(113).unwrap(),
    };
    /// Operation already in progress
    pub const EALREADY: Self = Self {
        value: NonZeroU8::new(114).unwrap(),
    };
    /// Operation now in progress
    pub const EINPROGRESS: Self = Self {
        value: NonZeroU8::new(115).unwrap(),
    };
    /// Stale file handle
    pub const ESTALE: Self = Self {
        value: NonZeroU8::new(116).unwrap(),
    };
    /// Structure needs cleaning
    pub const EUCLEAN: Self = Self {
        value: NonZeroU8::new(117).unwrap(),
    };
    /// Not a XENIX named type file
    pub const ENOTNAM: Self = Self {
        value: NonZeroU8::new(118).unwrap(),
    };
    /// No XENIX semaphores available
    pub const ENAVAIL: Self = Self {
        value: NonZeroU8::new(119).unwrap(),
    };
    /// Is a named type file
    pub const EISNAM: Self = Self {
        value: NonZeroU8::new(120).unwrap(),
    };
    /// Remote I/O error
    pub const EREMOTEIO: Self = Self {
        value: NonZeroU8::new(121).unwrap(),
    };
    /// Disk quota exceeded
    pub const EDQUOT: Self = Self {
        value: NonZeroU8::new(122).unwrap(),
    };
    /// No medium found
    pub const ENOMEDIUM: Self = Self {
        value: NonZeroU8::new(123).unwrap(),
    };
    /// Wrong medium type
    pub const EMEDIUMTYPE: Self = Self {
        value: NonZeroU8::new(124).unwrap(),
    };
    /// Operation canceled
    pub const ECANCELED: Self = Self {
        value: NonZeroU8::new(125).unwrap(),
    };
    /// Required key not available
    pub const ENOKEY: Self = Self {
        value: NonZeroU8::new(126).unwrap(),
    };
    /// Key has expired
    pub const EKEYEXPIRED: Self = Self {
        value: NonZeroU8::new(127).unwrap(),
    };
    /// Key has been revoked
    pub const EKEYREVOKED: Self = Self {
        value: NonZeroU8::new(128).unwrap(),
    };
    /// Key was rejected by service
    pub const EKEYREJECTED: Self = Self {
        value: NonZeroU8::new(129).unwrap(),
    };
    /// Owner died
    pub const EOWNERDEAD: Self = Self {
        value: NonZeroU8::new(130).unwrap(),
    };
    /// State not recoverable
    pub const ENOTRECOVERABLE: Self = Self {
        value: NonZeroU8::new(131).unwrap(),
    };
    /// Operation not possible due to RF-kill
    pub const ERFKILL: Self = Self {
        value: NonZeroU8::new(132).unwrap(),
    };
    /// Memory page has hardware error
    pub const EHWPOISON: Self = Self {
        value: NonZeroU8::new(133).unwrap(),
    };
    /// Operation not supported
    pub const ENOTSUP: Self = Self {
        value: NonZeroU8::new(95).unwrap(),
    };
}
