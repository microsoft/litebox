// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#![no_std]

//! HEKI/HVCI + VSM service: VSM dispatch and HEKI enforcement policy, generic
//! over the [`litebox_common_lvbs::Vtl0Mediation`] capability.

extern crate alloc;

mod mem_integrity;
mod state;
mod vsm;

pub use state::HekiState;
pub use vsm::Vsm;
