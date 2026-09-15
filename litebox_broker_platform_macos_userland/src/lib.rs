// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! macOS-userland implementations of trusted broker platform capabilities.

#![cfg(target_os = "macos")]

mod sync;

pub use sync::MacosSyncPrimitivesProvider;
