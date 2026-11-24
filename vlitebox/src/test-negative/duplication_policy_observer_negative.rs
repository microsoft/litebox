// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Deliberately false: the original policy observer cannot negate its field.
//! Run with `cargo verus focus -p vlitebox --example duplication_policy_observer_negative`.

use litebox_broker_core::PolicyEngine;
use vstd::prelude::*;

verus! {

fn reject_negated_duplication_policy(engine: &PolicyEngine) -> (result: bool)
    ensures result != engine.duplication_policy_enabled(),
{
    proof {
        PolicyEngine::prove_duplication_policy_observer();
    }

    engine.process_duplication_enabled()
}

}

fn main() {}
