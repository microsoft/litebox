// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Different host implementations of [`super::HostInterface`]
pub mod snp;

#[cfg(test)]
pub mod mock;
