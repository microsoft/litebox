// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Randomness sources. LiteBox requires a hardware-backed CSPRNG; every source
//! here is one.

/// A source could not produce output.
#[derive(Debug)]
pub struct RngError;

/// The machine's hardware-backed CSPRNG.
pub struct Hardware(Rdrand);

impl Hardware {
    /// # Errors
    ///
    /// See [`RngError`].
    pub fn fill(&self, output: &mut [u8]) -> Result<(), RngError> {
        self.0.fill(output)
    }
}

/// # Panics
///
/// If the machine has no hardware-backed CSPRNG.
#[must_use]
pub fn hardware() -> Hardware {
    Hardware(
        Rdrand::new().expect("no hardware-backed CSPRNG (RDRAND; for QEMU, use e.g. `-cpu max`)"),
    )
}

/// The CPU's RDRAND. Construction requires CPUID-confirmed support.
pub struct Rdrand(());

impl Rdrand {
    #[must_use]
    pub fn new() -> Option<Self> {
        // CPUID.1:ECX[30]
        let supported = core::arch::x86_64::__cpuid_count(1, 0).ecx & (1 << 30) != 0;
        supported.then_some(Self(()))
    }

    /// # Errors
    ///
    /// RDRAND kept underflowing.
    pub fn fill(&self, output: &mut [u8]) -> Result<(), RngError> {
        /// Intel's recommended retry budget for a transient RDRAND underflow.
        const RDRAND_RETRY_ATTEMPTS: u32 = 10;

        for chunk in output.chunks_mut(8) {
            let mut word = 0;
            // Safety: RDRAND support was checked when `self` was created.
            let ok = (0..RDRAND_RETRY_ATTEMPTS)
                .any(|_| unsafe { core::arch::x86_64::_rdrand64_step(&mut word) } == 1);
            if !ok {
                return Err(RngError);
            }
            chunk.copy_from_slice(&word.to_le_bytes()[..chunk.len()]);
        }
        Ok(())
    }
}
