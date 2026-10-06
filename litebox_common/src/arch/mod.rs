//! Architecture-specific helpers independent of host operating systems and guest ABIs.

#[cfg(target_arch = "x86_64")]
pub mod x86_64;
