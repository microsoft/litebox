// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Exact hostname and destination-port policy primitives for the LiteBox
//! egress proxy.
//!
//! Policy rules and request authorities share one canonical hostname type, so
//! authorization is an exact match after normalization.

#![no_std]

extern crate alloc;

pub mod authority;
pub mod policy;
