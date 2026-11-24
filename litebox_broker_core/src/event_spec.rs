// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Mutable kind projection for the original `ObjectEntry::as_event_mut`.
//! On success, the final outer value follows the returned mutable loan.
//! Counter operations, readiness, and caller authorization remain unverified.

use super::EventObject;
use crate::object::ObjectEntry;
use crate::{BrokerError, Result};
use vstd::prelude::*;

verus! {

pub(crate) open spec fn event_projection(
    prev: ObjectEntry,
    cur: ObjectEntry,
    result: Result<(EventObject, EventObject)>,
) -> bool {
    match prev {
        ObjectEntry::Event(event) => match result {
            Ok((loan_prev, loan_cur)) => {
                &&& loan_prev == event
                &&& cur == ObjectEntry::Event(loan_cur)
            },
            Err(_) => false,
        },
        _ => {
            &&& result == Err(BrokerError::InvalidRights)
            &&& cur == prev
        },
    }
}

// Checked adapter observes the initial loan and applies an arbitrary replacement.
fn apply_event_transition(
    prev: ObjectEntry,
    replacement: EventObject,
) -> (result: (ObjectEntry, Result<Ghost<EventObject>>))
    ensures event_projection(prev, result.0, match result.1 {
        Ok(loan_prev) => Ok((loan_prev@, replacement)),
        Err(error) => Err(error),
    }),
{
    let mut cur = prev;

    let result = match cur.as_event_mut() {
        Ok(event) => {
            let loan_prev = Ghost(*event);

            *event = replacement;

            Ok(loan_prev)
        },
        Err(error) => Err(error),
    };

    (cur, result)
}

closed spec fn event_transition(
    prev: ObjectEntry,
    cur: ObjectEntry,
    replacement: EventObject,
    result: Result<Ghost<EventObject>>,
) -> bool {
    apply_event_transition.ensures((prev, replacement), (cur, result))
}

pub closed spec fn event_projection_policy() -> bool {
    forall|prev: ObjectEntry, cur: ObjectEntry, replacement: EventObject,
        result: Result<Ghost<EventObject>>|
        #[trigger] event_transition(prev, cur, replacement, result)
            ==> event_projection(prev, cur, match result {
                Ok(loan_prev) => Ok((loan_prev@, replacement)),
                Err(error) => Err(error),
            })
}

pub proof fn prove_event_projection()
    ensures event_projection_policy(),
{
}

// Verification-only caller regression: mutations must reach the original enum,
// while projection failure must leave it unchanged.
fn check_event_replacement(entry: &mut ObjectEntry, replacement: EventObject) -> (result: Result<()>)
    ensures
        match *old(entry) {
            ObjectEntry::Event(_) =>
                result == Ok(()) && *final(entry) == ObjectEntry::Event(replacement),
            _ => result == Err(BrokerError::InvalidRights) && *final(entry) == *old(entry),
        },
{
    let event = entry.as_event_mut()?;
    *event = replacement;

    Ok(())
}

}
