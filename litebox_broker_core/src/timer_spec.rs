// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Kind/value projection contracts for the original timer accessors.
//! Timer scheduling, clocks, readiness, and caller rights remain unverified.

use super::TimerObject;
use crate::object::ObjectEntry;
use crate::{BrokerError, Result};
use vstd::prelude::*;

verus! {

pub(crate) open spec fn timer_projection(entry: &ObjectEntry, result: Result<&TimerObject>) -> bool {
    match entry {
        ObjectEntry::Timer(timer) => result == Ok(timer),
        _ => result == Err(BrokerError::InvalidRights),
    }
}

pub(crate) open spec fn timer_mut_projection(
    prev: ObjectEntry,
    cur: ObjectEntry,
    result: Result<(TimerObject, TimerObject)>,
) -> bool {
    match prev {
        ObjectEntry::Timer(timer) => match result {
            Ok((loan_prev, loan_cur)) => {
                &&& loan_prev == timer
                &&& cur == ObjectEntry::Timer(loan_cur)
            },
            Err(_) => false,
        },
        _ => {
            &&& result == Err(BrokerError::InvalidRights)
            &&& cur == prev
        },
    }
}

fn apply_timer_transition(
    prev: ObjectEntry,
    replacement: TimerObject,
) -> (result: (ObjectEntry, Result<Ghost<TimerObject>>))
    ensures timer_mut_projection(prev, result.0, match result.1 {
        Ok(loan_prev) => Ok((loan_prev@, replacement)),
        Err(error) => Err(error),
    }),
{
    let mut cur = prev;

    let result = match cur.as_timer_mut() {
        Ok(timer) => {
            let loan_prev = Ghost(*timer);

            *timer = replacement;

            Ok(loan_prev)
        },
        Err(error) => Err(error),
    };

    (cur, result)
}

closed spec fn timer_transition(
    prev: ObjectEntry,
    cur: ObjectEntry,
    replacement: TimerObject,
    result: Result<Ghost<TimerObject>>,
) -> bool {
    apply_timer_transition.ensures((prev, replacement), (cur, result))
}

pub closed spec fn timer_projection_policy() -> bool {
    &&& (forall|prev: ObjectEntry, result: Result<&TimerObject>|
        #[trigger] ObjectEntry::as_timer.ensures((&prev,), result) ==> timer_projection(&prev, result))
    &&& (forall|prev: ObjectEntry, cur: ObjectEntry, replacement: TimerObject,
        result: Result<Ghost<TimerObject>>|
        #[trigger] timer_transition(prev, cur, replacement, result)
            ==> timer_mut_projection(prev, cur, match result {
                Ok(loan_prev) => Ok((loan_prev@, replacement)),
                Err(error) => Err(error),
            }))
}

pub proof fn prove_timer_projection()
    ensures timer_projection_policy(),
{
}

// Verification-only caller regression for both accessors and mutable framing.
fn check_timer_replacement(entry: &mut ObjectEntry, replacement: TimerObject) -> (result: Result<()>)
    ensures
        match *old(entry) {
            ObjectEntry::Timer(_) =>
                result == Ok(()) && *final(entry) == ObjectEntry::Timer(replacement),
            _ => result == Err(BrokerError::InvalidRights) && *final(entry) == *old(entry),
        },
{
    let _timer = entry.as_timer()?;
    let timer = entry.as_timer_mut()?;
    *timer = replacement;

    Ok(())
}

}
