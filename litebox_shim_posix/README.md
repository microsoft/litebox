# A shim that provides a POSIX-compatible ABI via LiteBox

This shim is parametric in the choice of platform, which is initialized by first
invoking `set_platform`, after which all functionality within the POSIX shim is
able to use that particular platform.
