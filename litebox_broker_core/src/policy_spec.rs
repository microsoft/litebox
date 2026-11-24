// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Native duplication-policy configuration only, not caller authentication,
//! effect authority, operation success, or cross-runner stability.

use super::PolicyEngine;
use vstd::prelude::*;

verus! {

impl PolicyEngine {
    /// The original observer returns the configured permission.
    pub proof fn prove_duplication_policy_observer()
        ensures
            forall|engine: &PolicyEngine, result: bool|
                #[trigger] PolicyEngine::process_duplication_enabled.ensures((engine,), result)
                    ==> result == engine.duplication_policy_enabled(),
    {
    }
}

}
