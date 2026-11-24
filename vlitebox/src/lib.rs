// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Top-level LiteBox verification, consuming executable-crate contracts.

#![no_std]

use litebox_broker_core as _;
use vstd as _;

pub mod properties;
pub mod trusted;

pub use properties::object_proof;
pub use properties::pipe_proof;
pub use trusted::object_spec;
pub use trusted::pipe_spec;
