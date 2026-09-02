// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Broker-provided cryptographic randomness.

/// Maximum number of random bytes transferred by one broker operation.
pub const MAX_RANDOM_TRANSFER_SIZE: u32 = 256;
