// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Top-level LiteBox verification, consuming executable-crate contracts.

#![no_std]

use litebox_broker_core as _;
use vstd as _;

pub mod properties;
pub mod trusted;

mod shared_memory_id_callers;

pub use properties::error_proof;
pub use properties::event_proof;
pub use properties::ipc_projection_proof;
pub use properties::object_proof;
pub use properties::pipe_proof;
pub use properties::shared_futex_proof;
pub use properties::shared_memory_id_proof;
pub use properties::timer_proof;
pub use trusted::error_spec;
pub use trusted::event_spec;
pub use trusted::ipc_projection_spec;
pub use trusted::object_spec;
pub use trusted::pipe_spec;
pub use trusted::shared_futex_spec;
pub use trusted::shared_memory_id_spec;
pub use trusted::timer_spec;
