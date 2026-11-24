// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Check the original core as well as this composition target.
//! Existing vstd arithmetic/Option contracts; no custom behavioral assumptions.

use crate::channel_spec::channel_accounting_policy;
use vstd::prelude::*;

verus! {

pub proof fn channel_scalar_operations_preserve_their_frames<Q, W>()
    ensures channel_accounting_policy::<Q, W>(),
{
    litebox_broker_core::verification::prove_channel_accounting::<Q, W>();
}

}
