// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Helpers shared by tests across LiteBox crates, needing nothing from
//! LiteBox itself. Helpers that need a crate's internals stay in that crate's
//! `test_support` module.

#[cfg(any(target_os = "linux", windows))]
pub mod net;
