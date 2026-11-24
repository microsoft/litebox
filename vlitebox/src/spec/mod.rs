// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Property definitions and interfaces to checked native contracts.
//! These are not assumed executable guarantees. Local unproved contracts live
//! in vlitebox-thirdparty/src/assumptions; see vlitebox/README.md for the boundary.

pub mod channel_spec;
pub mod channel_waiters_spec;
pub mod directory_decoder_spec;
pub mod error_spec;
pub mod event_spec;
pub mod file_offset_spec;
pub mod file_projection_spec;
pub mod filesystem_errors_spec;
pub mod ipc_projection_spec;
pub mod object_spec;
pub mod pipe_spec;
pub mod process_identity_spec;
pub mod readonly_metadata_spec;
pub mod shared_buffer_layout_spec;
pub mod shared_futex_spec;
pub mod shared_memory_id_spec;
pub mod timer_spec;
pub mod transfer_spec;
