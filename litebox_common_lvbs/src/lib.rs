// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Common data-only types for LVBS (VTL1) — shared between platform and runner crates.

#![no_std]

pub mod error;
pub mod heki;
pub mod hvcall;
pub mod linux;
pub mod mem_layout;
pub mod mshv;
pub mod vsm;
