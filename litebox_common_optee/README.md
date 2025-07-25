# Common elements to enable OP-TEE-like functionalities

> [!WARNING]
> This crate is work in progress.

This crates contains common elements to enable OP-TEE-like functionalities.
In particular, it defines the OP-TEE `SyscallRequest` and other related
data structures which are referred by other crates including
`litebox_platform_lvbs`, `litebox_runner_lvbs`, and `litebox_shim_optee`.
Another reason to separate this code from the `litebox_shim_optee` is
to avoid cyclic dependency issues. Without this crate,
`litebox_platform_lvbs` and `litebox_shim_optee` would depend on each other.
