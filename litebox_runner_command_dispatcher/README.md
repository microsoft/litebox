# Command dispatcher interface for LiteBox

This creates maintains the entry and exit points of the command dispatcher
(OP-TEE TA, OP-TEE SMC, VSM-VTL call, ...) for LiteBox. We make this
interface stand alone because it will be used by several crates
(e.g., Shim and Runner) which cannot depend on each other. We expect
the Runner implements the actual command dispatcher logic
(e.g., `dispatcher_impl`).
