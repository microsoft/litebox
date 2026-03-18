// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Litebox File Broker — policy-enforced external file access for sandboxed
//! processes.
//!
//! Provides a 9P2000.L server that serves files from the host filesystem
//! with policy enforcement and optional ELF syscall rewriting.
//! Also provides a network proxy that bridges guest networking over IPC.

pub mod net_proxy;
pub mod nine_p;
pub mod policy;
pub mod sock_compat;
