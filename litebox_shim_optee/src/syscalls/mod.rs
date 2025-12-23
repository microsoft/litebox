// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Syscalls Handlers

pub(crate) mod cryp;
pub(crate) mod ldelf;
pub(crate) mod mm;
pub(crate) mod pta;
pub(crate) mod tee;

#[cfg(test)]
pub(crate) mod tests;
