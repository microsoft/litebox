// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use super::*;
use alloc::vec::Vec;
use core::cell::RefCell;

#[derive(Debug, PartialEq)]
enum Event {
    Program,
    Acknowledge,
    Disable,
}

#[test]
fn unavailable_timer_does_not_program_or_disarm_hardware() {
    let state = PreemptionState::default();
    state.arm(|| panic!("disabled timer was programmed"));
    state.disarm(|| panic!("disabled timer touched hardware"));
    let acknowledged = Cell::new(false);
    state.on_kernel_interrupt(
        || acknowledged.set(true),
        || panic!("disabled timer was rearmed"),
    );
    assert!(acknowledged.get());
    assert!(!state.armed.get());
    assert!(!state.take_user_timeout_kill());
}

#[test]
fn arm_publishes_state_before_programming_and_reentry_keeps_budget() {
    let state = PreemptionState::default();
    state.enabled.set(true);
    let writes = Cell::new(0);
    state.arm(|| {
        assert!(state.armed.get());
        writes.set(writes.get() + 1);
    });
    state.arm(|| writes.set(writes.get() + 1));
    assert_eq!(writes.get(), 1);
    assert!(state.armed.get());
}

#[test]
fn live_kernel_expiry_acknowledges_then_rearms() {
    let state = PreemptionState::default();
    state.enabled.set(true);
    state.arm(|| {});
    let events = RefCell::new(Vec::new());
    state.on_kernel_interrupt(
        || events.borrow_mut().push(Event::Acknowledge),
        || {
            assert!(state.armed.get());
            events.borrow_mut().push(Event::Program);
        },
    );
    assert_eq!(*events.borrow(), [Event::Acknowledge, Event::Program]);
    assert!(!state.take_user_timeout_kill());
}

#[test]
fn disarm_clears_state_before_hardware_and_stale_irq_cannot_rearm() {
    let state = PreemptionState::default();
    state.enabled.set(true);
    state.arm(|| {});
    let events = RefCell::new(Vec::new());
    state.disarm(|| {
        assert!(!state.armed.get());
        // Simulate an IRQ precisely between clearing the flag and disabling
        // the device: it must ACK only, never resurrect the deadline.
        state.on_kernel_interrupt(
            || events.borrow_mut().push(Event::Acknowledge),
            || events.borrow_mut().push(Event::Program),
        );
        events.borrow_mut().push(Event::Disable);
    });
    state.disarm(|| panic!("duplicate disarm touched hardware"));
    assert_eq!(*events.borrow(), [Event::Acknowledge, Event::Disable]);
    assert!(!state.armed.get());
    // A new residency can arm normally after the VTL0-return disarm.
    state.arm(|| events.borrow_mut().push(Event::Program));
    assert!(state.armed.get());
    assert_eq!(events.borrow().last(), Some(&Event::Program));
}

#[test]
fn user_expiry_is_acknowledged_and_notification_consumed_once() {
    let state = PreemptionState::default();
    state.enabled.set(true);
    state.arm(|| {});
    state.on_user_exception(Exception::PAGE_FAULT, || {
        panic!("unrelated vector was ACKed")
    });
    assert!(!state.killed_user.get());
    state.on_user_exception(Exception(STIMER_VECTOR), || {
        assert!(!state.killed_user.get());
    });
    // Expiry does not end the residency; the VTL return path still disarms.
    assert!(state.armed.get());
    assert!(state.take_user_timeout_kill());
    assert!(!state.take_user_timeout_kill());
}

#[test]
fn stale_user_expiry_preserves_existing_termination_notification() {
    let state = PreemptionState::default();
    let acknowledged = Cell::new(false);
    state.on_user_exception(Exception(STIMER_VECTOR), || acknowledged.set(true));
    assert!(acknowledged.get());
    assert!(state.take_user_timeout_kill());
    assert!(!state.armed.get());
}
