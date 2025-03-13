//! Error number constants. See [`Errno`] docs to see the command to generate the following.
//!
//! This particular module itself is private, but defines all the below associated constants within
//! the public [`Errno`] type, so as to have them all be exposed, but still keep the auto-generated
//! code restricted to this single file.

impl super::Errno {
    /// Operation not permitted
    pub const EPERM: Self = Self::from_const(1);
    /// No such file or directory
    pub const ENOENT: Self = Self::from_const(2);
    /// No such process
    pub const ESRCH: Self = Self::from_const(3);
    /// Interrupted system call
    pub const EINTR: Self = Self::from_const(4);
    /// Input/output error
    pub const EIO: Self = Self::from_const(5);
    /// No such device or address
    pub const ENXIO: Self = Self::from_const(6);
    /// Argument list too long
    pub const E2BIG: Self = Self::from_const(7);
    /// Exec format error
    pub const ENOEXEC: Self = Self::from_const(8);
    /// Bad file descriptor
    pub const EBADF: Self = Self::from_const(9);
    /// No child processes
    pub const ECHILD: Self = Self::from_const(10);
    /// Resource temporarily unavailable
    pub const EAGAIN: Self = Self::from_const(11);
    /// Cannot allocate memory
    pub const ENOMEM: Self = Self::from_const(12);
    /// Permission denied
    pub const EACCES: Self = Self::from_const(13);
    /// Bad address
    pub const EFAULT: Self = Self::from_const(14);
    /// Block device required
    pub const ENOTBLK: Self = Self::from_const(15);
    /// Device or resource busy
    pub const EBUSY: Self = Self::from_const(16);
    /// File exists
    pub const EEXIST: Self = Self::from_const(17);
    /// Invalid cross-device link
    pub const EXDEV: Self = Self::from_const(18);
    /// No such device
    pub const ENODEV: Self = Self::from_const(19);
    /// Not a directory
    pub const ENOTDIR: Self = Self::from_const(20);
    /// Is a directory
    pub const EISDIR: Self = Self::from_const(21);
    /// Invalid argument
    pub const EINVAL: Self = Self::from_const(22);
    /// Too many open files in system
    pub const ENFILE: Self = Self::from_const(23);
    /// Too many open files
    pub const EMFILE: Self = Self::from_const(24);
    /// Inappropriate ioctl for device
    pub const ENOTTY: Self = Self::from_const(25);
    /// Text file busy
    pub const ETXTBSY: Self = Self::from_const(26);
    /// File too large
    pub const EFBIG: Self = Self::from_const(27);
    /// No space left on device
    pub const ENOSPC: Self = Self::from_const(28);
    /// Illegal seek
    pub const ESPIPE: Self = Self::from_const(29);
    /// Read-only file system
    pub const EROFS: Self = Self::from_const(30);
    /// Too many links
    pub const EMLINK: Self = Self::from_const(31);
    /// Broken pipe
    pub const EPIPE: Self = Self::from_const(32);
    /// Numerical argument out of domain
    pub const EDOM: Self = Self::from_const(33);
    /// Numerical result out of range
    pub const ERANGE: Self = Self::from_const(34);
    /// Resource deadlock avoided
    pub const EDEADLK: Self = Self::from_const(35);
    /// File name too long
    pub const ENAMETOOLONG: Self = Self::from_const(36);
    /// No locks available
    pub const ENOLCK: Self = Self::from_const(37);
    /// Function not implemented
    pub const ENOSYS: Self = Self::from_const(38);
    /// Directory not empty
    pub const ENOTEMPTY: Self = Self::from_const(39);
    /// Too many levels of symbolic links
    pub const ELOOP: Self = Self::from_const(40);
    /// Resource temporarily unavailable
    pub const EWOULDBLOCK: Self = Self::from_const(11);
    /// No message of desired type
    pub const ENOMSG: Self = Self::from_const(42);
    /// Identifier removed
    pub const EIDRM: Self = Self::from_const(43);
    /// Channel number out of range
    pub const ECHRNG: Self = Self::from_const(44);
    /// Level 2 not synchronized
    pub const EL2NSYNC: Self = Self::from_const(45);
    /// Level 3 halted
    pub const EL3HLT: Self = Self::from_const(46);
    /// Level 3 reset
    pub const EL3RST: Self = Self::from_const(47);
    /// Link number out of range
    pub const ELNRNG: Self = Self::from_const(48);
    /// Protocol driver not attached
    pub const EUNATCH: Self = Self::from_const(49);
    /// No CSI structure available
    pub const ENOCSI: Self = Self::from_const(50);
    /// Level 2 halted
    pub const EL2HLT: Self = Self::from_const(51);
    /// Invalid exchange
    pub const EBADE: Self = Self::from_const(52);
    /// Invalid request descriptor
    pub const EBADR: Self = Self::from_const(53);
    /// Exchange full
    pub const EXFULL: Self = Self::from_const(54);
    /// No anode
    pub const ENOANO: Self = Self::from_const(55);
    /// Invalid request code
    pub const EBADRQC: Self = Self::from_const(56);
    /// Invalid slot
    pub const EBADSLT: Self = Self::from_const(57);
    /// Resource deadlock avoided
    pub const EDEADLOCK: Self = Self::from_const(35);
    /// Bad font file format
    pub const EBFONT: Self = Self::from_const(59);
    /// Device not a stream
    pub const ENOSTR: Self = Self::from_const(60);
    /// No data available
    pub const ENODATA: Self = Self::from_const(61);
    /// Timer expired
    pub const ETIME: Self = Self::from_const(62);
    /// Out of streams resources
    pub const ENOSR: Self = Self::from_const(63);
    /// Machine is not on the network
    pub const ENONET: Self = Self::from_const(64);
    /// Package not installed
    pub const ENOPKG: Self = Self::from_const(65);
    /// Object is remote
    pub const EREMOTE: Self = Self::from_const(66);
    /// Link has been severed
    pub const ENOLINK: Self = Self::from_const(67);
    /// Advertise error
    pub const EADV: Self = Self::from_const(68);
    /// Srmount error
    pub const ESRMNT: Self = Self::from_const(69);
    /// Communication error on send
    pub const ECOMM: Self = Self::from_const(70);
    /// Protocol error
    pub const EPROTO: Self = Self::from_const(71);
    /// Multihop attempted
    pub const EMULTIHOP: Self = Self::from_const(72);
    /// RFS specific error
    pub const EDOTDOT: Self = Self::from_const(73);
    /// Bad message
    pub const EBADMSG: Self = Self::from_const(74);
    /// Value too large for defined data type
    pub const EOVERFLOW: Self = Self::from_const(75);
    /// Name not unique on network
    pub const ENOTUNIQ: Self = Self::from_const(76);
    /// File descriptor in bad state
    pub const EBADFD: Self = Self::from_const(77);
    /// Remote address changed
    pub const EREMCHG: Self = Self::from_const(78);
    /// Can not access a needed shared library
    pub const ELIBACC: Self = Self::from_const(79);
    /// Accessing a corrupted shared library
    pub const ELIBBAD: Self = Self::from_const(80);
    /// .lib section in a.out corrupted
    pub const ELIBSCN: Self = Self::from_const(81);
    /// Attempting to link in too many shared libraries
    pub const ELIBMAX: Self = Self::from_const(82);
    /// Cannot exec a shared library directly
    pub const ELIBEXEC: Self = Self::from_const(83);
    /// Invalid or incomplete multibyte or wide character
    pub const EILSEQ: Self = Self::from_const(84);
    /// Interrupted system call should be restarted
    pub const ERESTART: Self = Self::from_const(85);
    /// Streams pipe error
    pub const ESTRPIPE: Self = Self::from_const(86);
    /// Too many users
    pub const EUSERS: Self = Self::from_const(87);
    /// Socket operation on non-socket
    pub const ENOTSOCK: Self = Self::from_const(88);
    /// Destination address required
    pub const EDESTADDRREQ: Self = Self::from_const(89);
    /// Message too long
    pub const EMSGSIZE: Self = Self::from_const(90);
    /// Protocol wrong type for socket
    pub const EPROTOTYPE: Self = Self::from_const(91);
    /// Protocol not available
    pub const ENOPROTOOPT: Self = Self::from_const(92);
    /// Protocol not supported
    pub const EPROTONOSUPPORT: Self = Self::from_const(93);
    /// Socket type not supported
    pub const ESOCKTNOSUPPORT: Self = Self::from_const(94);
    /// Operation not supported
    pub const EOPNOTSUPP: Self = Self::from_const(95);
    /// Protocol family not supported
    pub const EPFNOSUPPORT: Self = Self::from_const(96);
    /// Address family not supported by protocol
    pub const EAFNOSUPPORT: Self = Self::from_const(97);
    /// Address already in use
    pub const EADDRINUSE: Self = Self::from_const(98);
    /// Cannot assign requested address
    pub const EADDRNOTAVAIL: Self = Self::from_const(99);
    /// Network is down
    pub const ENETDOWN: Self = Self::from_const(100);
    /// Network is unreachable
    pub const ENETUNREACH: Self = Self::from_const(101);
    /// Network dropped connection on reset
    pub const ENETRESET: Self = Self::from_const(102);
    /// Software caused connection abort
    pub const ECONNABORTED: Self = Self::from_const(103);
    /// Connection reset by peer
    pub const ECONNRESET: Self = Self::from_const(104);
    /// No buffer space available
    pub const ENOBUFS: Self = Self::from_const(105);
    /// Transport endpoint is already connected
    pub const EISCONN: Self = Self::from_const(106);
    /// Transport endpoint is not connected
    pub const ENOTCONN: Self = Self::from_const(107);
    /// Cannot send after transport endpoint shutdown
    pub const ESHUTDOWN: Self = Self::from_const(108);
    /// Too many references: cannot splice
    pub const ETOOMANYREFS: Self = Self::from_const(109);
    /// Connection timed out
    pub const ETIMEDOUT: Self = Self::from_const(110);
    /// Connection refused
    pub const ECONNREFUSED: Self = Self::from_const(111);
    /// Host is down
    pub const EHOSTDOWN: Self = Self::from_const(112);
    /// No route to host
    pub const EHOSTUNREACH: Self = Self::from_const(113);
    /// Operation already in progress
    pub const EALREADY: Self = Self::from_const(114);
    /// Operation now in progress
    pub const EINPROGRESS: Self = Self::from_const(115);
    /// Stale file handle
    pub const ESTALE: Self = Self::from_const(116);
    /// Structure needs cleaning
    pub const EUCLEAN: Self = Self::from_const(117);
    /// Not a XENIX named type file
    pub const ENOTNAM: Self = Self::from_const(118);
    /// No XENIX semaphores available
    pub const ENAVAIL: Self = Self::from_const(119);
    /// Is a named type file
    pub const EISNAM: Self = Self::from_const(120);
    /// Remote I/O error
    pub const EREMOTEIO: Self = Self::from_const(121);
    /// Disk quota exceeded
    pub const EDQUOT: Self = Self::from_const(122);
    /// No medium found
    pub const ENOMEDIUM: Self = Self::from_const(123);
    /// Wrong medium type
    pub const EMEDIUMTYPE: Self = Self::from_const(124);
    /// Operation canceled
    pub const ECANCELED: Self = Self::from_const(125);
    /// Required key not available
    pub const ENOKEY: Self = Self::from_const(126);
    /// Key has expired
    pub const EKEYEXPIRED: Self = Self::from_const(127);
    /// Key has been revoked
    pub const EKEYREVOKED: Self = Self::from_const(128);
    /// Key was rejected by service
    pub const EKEYREJECTED: Self = Self::from_const(129);
    /// Owner died
    pub const EOWNERDEAD: Self = Self::from_const(130);
    /// State not recoverable
    pub const ENOTRECOVERABLE: Self = Self::from_const(131);
    /// Operation not possible due to RF-kill
    pub const ERFKILL: Self = Self::from_const(132);
    /// Memory page has hardware error
    pub const EHWPOISON: Self = Self::from_const(133);
    /// Operation not supported
    pub const ENOTSUP: Self = Self::from_const(95);
    /// The maximum supported Errno
    pub const MAX: Self = Self::from_const(133);
}
