// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Library interface for the litebox test harness.
//!
//! Re-exports the test group registry so that the integration test
//! (`tests/integration.rs`) can discover the same test groups used
//! by the coordinator's dispatch loop.

pub mod test_registry;
