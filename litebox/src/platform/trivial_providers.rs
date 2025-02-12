//! Implementations of trivial providers.
//!
//! Most users of LiteBox may possibly need more featureful providers, provided by other crates;
//! however, some users might find these sufficient for their use case.

use super::{Punchthrough, PunchthroughError, PunchthroughProvider, PunchthroughToken};

/// A trivial provider, useful when no punchthrough is necessary.
pub struct ImpossiblePunchthroughProvider {}
impl PunchthroughProvider for ImpossiblePunchthroughProvider {
    type PunchthroughToken<'a>
        = ImpossiblePunchthroughToken
    where
        Self: 'a;
    fn get_punchthrough_token_for(
        &mut self,
        punchthrough: <Self::PunchthroughToken<'_> as PunchthroughToken>::Punchthrough,
    ) -> Option<Self::PunchthroughToken<'_>> {
        // Since `ImpossiblePunchthrough` is an empty enum, it is impossible to actually invoke
        // `execute` upon it, meaning that the implementation here is irrelevant, since anything
        // within it is provably unreachable.
        unreachable!()
    }
}
/// A [`Punchthrough`] for [`ImpossiblePunchthroughProvider`]
pub enum ImpossiblePunchthrough {}
impl Punchthrough for ImpossiblePunchthrough {
    // Infallible has the same role as the never type (`!`) which will _eventually_ be stabilized in
    // Rust. Since `Infallible` has no variant, a value of this type can never actually exist.
    type ReturnSuccess = core::convert::Infallible;
    type ReturnFailure = core::convert::Infallible;
}
/// A [`PunchthroughToken`] for [`ImpossiblePunchthrough`]
pub enum ImpossiblePunchthroughToken {}
impl PunchthroughToken for ImpossiblePunchthroughToken {
    type Punchthrough = ImpossiblePunchthrough;
    fn execute(
        self,
    ) -> Result<
        <Self::Punchthrough as Punchthrough>::ReturnSuccess,
        PunchthroughError<<Self::Punchthrough as Punchthrough>::ReturnFailure>,
    > {
        // Since `ImpossiblePunchthroughToken` is an empty enum, it is impossible to actually invoke
        // `execute` upon it, meaning that the implementation here is irrelevant, since anything
        // within it is provably unreachable.
        unreachable!()
    }
}

/// A trivial provider, useful when punchthroughs are be necessary, but might prefer to be
/// simply caught as "unimplemented" temporarily, while more infrastructure is set up.
pub struct IgnoredPunchthroughProvider {}
impl PunchthroughProvider for IgnoredPunchthroughProvider {
    type PunchthroughToken<'a>
        = IgnoredPunchthroughToken
    where
        Self: 'a;
    fn get_punchthrough_token_for(
        &mut self,
        punchthrough: <Self::PunchthroughToken<'_> as PunchthroughToken>::Punchthrough,
    ) -> Option<Self::PunchthroughToken<'_>> {
        Some(IgnoredPunchthroughToken { punchthrough })
    }
}
/// A [`Punchthrough`] for [`IgnoredPunchthroughProvider`]
pub struct IgnoredPunchthrough {
    data: &'static str,
}
impl Punchthrough for IgnoredPunchthrough {
    type ReturnSuccess = Underspecified;
    type ReturnFailure = Underspecified;
}
/// A [`PunchthroughToken`] for [`IgnoredPunchthrough`]
pub struct IgnoredPunchthroughToken {
    punchthrough: IgnoredPunchthrough,
}
impl PunchthroughToken for IgnoredPunchthroughToken {
    type Punchthrough = IgnoredPunchthrough;
    fn execute(
        self,
    ) -> Result<
        <Self::Punchthrough as Punchthrough>::ReturnSuccess,
        PunchthroughError<<Self::Punchthrough as Punchthrough>::ReturnFailure>,
    > {
        Err(PunchthroughError::Unimplemented(self.punchthrough.data))
    }
}

/// An under-specified type that cannot be "inspected" or created; used for [`IgnoredPunchthrough`]
#[doc(hidden)]
pub struct Underspecified {
    // Explicitly private field, to prevent destructuring or creation outside this module.
    __private: (),
}
impl core::fmt::Debug for Underspecified {
    fn fmt(&self, _f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        unreachable!("Underspecified is never constructed")
    }
}
impl core::fmt::Display for Underspecified {
    fn fmt(&self, _f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        unreachable!("Underspecified is never constructed")
    }
}
impl core::error::Error for Underspecified {}
