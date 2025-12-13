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
    /// The upcall context type
    type Context;

    /// Initialize the upcall handler
    fn init(&self) -> alloc::boxed::Box<dyn crate::upcall::Upcall<Context = Self::Context>>;

    /// Execute the upcall with the given context
    fn execute(&self, ctx: &mut Self::Context) -> Result<Self::Context, UpcallError>;
}

/// The operation to perform after returning from a shim handler
#[derive(Error, Debug)]
pub enum UpcallError {
    #[error("Upcall failed")]
    Failure,
    #[error("Upcall needs to be retried")]
    Retry,
}
