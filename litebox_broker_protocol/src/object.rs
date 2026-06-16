// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

/// Broker object reference handle returned to the local core.
///
/// The local core may cache this value, but the broker remains authoritative for
/// object identity, object lifetime, reference lifetime, type, and rights.
///
/// The value is an opaque broker reference identifier owned by one authenticated
/// process association.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ObjectHandle(pub u64);
