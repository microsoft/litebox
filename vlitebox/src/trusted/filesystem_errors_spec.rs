// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Must-read with the eight original conversion annotations and semantic/From
//! definitions in litebox_broker_core/src/fs/{errors,errors_spec,shared_storage}.rs,
//! plus the native Fault and BrokerError conversion. No custom assumptions are added.
//! Shared mapping translates NoSpace to NoMemory and Fault/Busy/Io to Io.
//! This proves error translation, not I/O, authorization, or correct failure.
//! The original file-service read/write/shared-mapping compatibility helpers
//! are also checked. Shared NoMemory becomes guest NoSpace; compatibility
//! read/write WouldBlock and Broker(_) become Io. Full service methods may
//! handle broker errors separately; no whole-syscall disposition is inferred.

pub use litebox_broker_core::fs::{
    file_map_shared_error_value, file_read_error_value, file_service_error_policy,
    file_write_error_value,
};

use vstd::prelude::*;

verus! {

pub open spec fn filesystem_error_policy() -> bool {
    litebox_broker_core::fs::errors::verification::filesystem_error_policy()
}

}
