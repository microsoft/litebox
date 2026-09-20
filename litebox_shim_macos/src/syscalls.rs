// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Darwin syscall implementations grouped by subsystem.

pub(crate) mod file;
pub(crate) mod mach;
pub(crate) mod misc;
pub(crate) mod mm;
pub(crate) mod policy;
pub(crate) mod process;
pub(crate) mod signal;
