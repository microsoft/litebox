// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Guest-facing filesystem facade.
//!
//! Filesystem resolution and backend implementations are owned by
//! [`litebox_broker_core::fs`]. This module retains the guest descriptor facade
//! and re-exports filesystem value types used by shims.

pub use litebox_broker_core::fs::{
    DirEntry, FileStatus, FileType, Mode, NodeInfo, OFlags, SeekWhence, UserInfo,
};

pub mod resolver;

pub mod errors {
    pub use litebox_broker_core::fs::errors::*;
}

#[doc(hidden)]
#[cfg(any(test, feature = "local_filesystem"))]
pub mod backend {
    pub use litebox_broker_core::fs::backend::*;
}

#[doc(hidden)]
#[cfg(any(test, feature = "local_filesystem"))]
pub mod composer {
    pub use litebox_broker_core::fs::composer::*;
}

#[doc(hidden)]
#[cfg(any(test, feature = "local_filesystem"))]
pub mod devices {
    pub use litebox_broker_core::fs::devices::*;
}

#[doc(hidden)]
#[cfg(any(test, feature = "local_filesystem"))]
pub mod in_mem {
    pub use litebox_broker_core::fs::in_mem::*;
}

#[doc(hidden)]
#[cfg(test)]
pub(crate) mod inode_allocator {
    pub(crate) use litebox_broker_core::fs::inode_allocator::*;
}

#[doc(hidden)]
#[cfg(any(test, feature = "local_filesystem"))]
pub mod nine_p {
    pub use litebox_broker_core::fs::nine_p::*;
}

#[doc(hidden)]
#[cfg(any(test, feature = "local_filesystem"))]
pub mod overlay {
    pub use litebox_broker_core::fs::overlay::*;
}

#[doc(hidden)]
#[cfg(any(test, feature = "local_filesystem"))]
pub mod tar_ro {
    pub use litebox_broker_core::fs::tar_ro::*;
}

#[cfg(test)]
mod tests;

#[cfg(all(test, target_os = "linux"))]
mod nine_p_tests;
