// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! The original file-service checked_offset body validates explicit byte ranges.
//! None returns Ok(None) regardless of length. Some(offset) succeeds exactly
//! when its mathematical offset+length fits usize, preserving the offset;
//! narrowing or addition failure returns InvalidOffset.
//! This does not bound implicit file positions, file size, actual I/O, policy
//! decisions, ownership or concurrent resource effects. No new std contracts.

pub use litebox_broker_core::fs::{file_offset_outcome, file_offset_policy};
