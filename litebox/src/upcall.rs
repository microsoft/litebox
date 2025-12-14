//! Types and traits to provide upcalls for platforms.
//! A platform may get some messages or requests from the host or
//! remote parties that it does not know how to handle (e.g.,
//! an OP-TEE SMC call from the normal-world kernel). Rather than
//! making the platform handle all these messages or requests itself,
//! we implement upcalls to let the platform delegate handling of
//! unknown messages or requests to other layers of LiteBox (i.e.,
//! runner or shim).
use thiserror::Error;

pub trait Upcall {
    /// The upcall parameter type
    type Parameter;

    /// The upcall return type
    type Return;

    /// Initialize the upcall handler
    fn init(
        &self,
    ) -> alloc::boxed::Box<
        dyn crate::upcall::Upcall<Parameter = Self::Parameter, Return = Self::Return>,
    >;

    /// Execute the upcall with the given parameter
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
}
