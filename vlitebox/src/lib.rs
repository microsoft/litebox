// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Top-level LiteBox verification, consuming executable-crate contracts.

#![no_std]

extern crate alloc;

use litebox_broker_core as _;
use vstd as _;

pub mod properties;
pub mod spec;

mod shared_memory_id_callers;

pub use properties::channel_proof;
pub use properties::channel_waiters_proof;
pub use properties::device_number_proof;
pub use properties::directory_decoder_proof;
pub use properties::error_proof;
pub use properties::event_proof;
pub use properties::file_offset_proof;
pub use properties::file_projection_proof;
pub use properties::filesystem_errors_proof;
pub use properties::ipc_projection_proof;
pub use properties::object_proof;
pub use properties::pending_sender_proof;
pub use properties::pipe_proof;
pub use properties::process_identity_proof;
pub use properties::readonly_metadata_proof;
pub use properties::shared_buffer_layout_proof;
pub use properties::shared_futex_proof;
pub use properties::shared_memory_id_proof;
pub use properties::timer_proof;
pub use properties::transfer_proof;
