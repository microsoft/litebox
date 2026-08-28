// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Exact hostname/port policy and controlled DNS primitives for the LiteBox
//! egress proxy.
//!
//! Policy and request authorities share one canonical hostname type. After an
//! exact hostname and destination-port match, [`dns::HostResolver`] resolves
//! the hostname through one explicitly configured DNS server without using
//! system resolver configuration, search domains, or a hosts file.

pub mod authority;
pub mod dns;
pub mod limits;
pub mod policy;
