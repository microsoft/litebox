// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Hyper-V hypercall error types.

use crate::mshv::{
    HV_STATUS_ACCESS_DENIED, HV_STATUS_INSUFFICIENT_BUFFERS, HV_STATUS_INSUFFICIENT_MEMORY,
    HV_STATUS_INVALID_ALIGNMENT, HV_STATUS_INVALID_CONNECTION_ID, HV_STATUS_INVALID_HYPERCALL_CODE,
    HV_STATUS_INVALID_HYPERCALL_INPUT, HV_STATUS_INVALID_PARAMETER, HV_STATUS_INVALID_PORT_ID,
    HV_STATUS_OPERATION_DENIED, HV_STATUS_TIME_OUT, HV_STATUS_VTL_ALREADY_ENABLED,
};
use num_enum::{IntoPrimitive, TryFromPrimitive};
use thiserror::Error;

/// Errors for Hyper-V hypercalls.
#[derive(Debug, Error, TryFromPrimitive, IntoPrimitive)]
#[non_exhaustive]
#[repr(u32)]
pub enum HypervCallError {
    #[error("invalid hypercall code")]
    InvalidCode = HV_STATUS_INVALID_HYPERCALL_CODE,
    #[error("invalid hypercall input")]
    InvalidInput = HV_STATUS_INVALID_HYPERCALL_INPUT,
    #[error("invalid alignment")]
    InvalidAlignment = HV_STATUS_INVALID_ALIGNMENT,
    #[error("invalid parameter")]
    InvalidParameter = HV_STATUS_INVALID_PARAMETER,
    #[error("access denied")]
    AccessDenied = HV_STATUS_ACCESS_DENIED,
    #[error("operation denied")]
    OperationDenied = HV_STATUS_OPERATION_DENIED,
    #[error("insufficient memory")]
    InsufficientMemory = HV_STATUS_INSUFFICIENT_MEMORY,
    #[error("invalid port ID")]
    InvalidPortID = HV_STATUS_INVALID_PORT_ID,
    #[error("invalid connection ID")]
    InvalidConnectionID = HV_STATUS_INVALID_CONNECTION_ID,
    #[error("insufficient buffers")]
    InsufficientBuffers = HV_STATUS_INSUFFICIENT_BUFFERS,
    #[error("timeout")]
    TimeOut = HV_STATUS_TIME_OUT,
    #[error("VTL already enabled")]
    AlreadyEnabled = HV_STATUS_VTL_ALREADY_ENABLED,
    #[error("unknown hypercall error")]
    Unknown = 0xffff_ffff,
}
