//! Upcall for platforms
//!
//! This module defines types and trait to provide upcalls for platforms.
//! A platform may receive some messages or requests from the host, devices,
//! or remote parties that it does not know how to handle. Rather than
//! making the platform be aware of all these messages or requests itself,
//! we implement upcalls to let platforms delegate handling of unknown
//! messages or requests to other layers of LiteBox (i.e., runner or shim).
//! Examples of such messages or requests include HVCI/Heki requests from
//! VTL0 and OP-TEE SMC calls from the normal world.
//!
//! # Security considerations
//!
//! Unlike other upcalls like hyperupcalls from the hypervisor to a guest VM,
//! this upcall is handled within LiteBox's TCB (i.e., by either runner or shim).
//! Therefore, the security considerations for this upcall are similar to function
//! calls within LiteBox. However, care must be taken to ensure that the upcall's
//! parameters and return values are properly validated and sanitized to prevent
//! potential security vulnerabilities. This is because the parameters might be
//! provided by untrusted sources and return values might contain sensitive
//! information. We assume that the upcall providers must implement necessary
//! security checks and validations. The platform would simply pass the parameters
//! and return values between untrusted sources and upcall providers (because it
//! does not have semantics to validate them). We can specify a function for early
//! validation at the platform side if needed but its advantages are not clear at
//! this moment (since there is no costly context switch within LiteBox).

use thiserror::Error;

/// An interface for upcalls from the platform to other layers of LiteBox.
pub trait Upcall {
    /// The upcall parameter type to be passed from the platform.
    type Parameter;

    /// The upcall return type to be returned to the platform.
    type Return;

    /// Initialize the upcall handler. Must be called by the platform exactly once.
    /// Per-thread initialization is possible but all threads must share the same
    /// upcall handler.
    fn init(
        &self,
    ) -> alloc::boxed::Box<
        dyn crate::upcall::Upcall<Parameter = Self::Parameter, Return = Self::Return>,
    >;

    /// Execute the upcall with the given parameter. Since we do not expect that the
    /// platform validates the parameters, the implementation of `execute` must validate
    /// parameters to avoid potential security vulnerabilities. Also, it must sanitize
    /// the return values before returning them to the platform.
    fn execute(&self, ctx: &mut Self::Parameter) -> Result<Self::Return, UpcallError>;
}

/// The error type for upcalls
#[non_exhaustive]
#[derive(Error, Debug)]
pub enum UpcallError {
    #[error("Upcall failed")]
    Failure,
    #[error("Upcall needs to be retried")]
    Retry,
    #[error("Upcall parameter is invalid")]
    InvalidParameter,
}
