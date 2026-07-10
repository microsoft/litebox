#[path = "common/fill_drain.rs"]
mod fill_drain;

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

#[test]
fn stops_when_selector_empty() {
    let select_calls = AtomicUsize::new(0);
    let run_calls = AtomicUsize::new(0);
    let drain = AtomicBool::new(false);

    let outcome = fill_drain::run_until_done_or_drained(
        || {
            select_calls.fetch_add(1, Ordering::SeqCst);
            Vec::<usize>::new()
        },
        |_| {
            run_calls.fetch_add(1, Ordering::SeqCst);
        },
        || drain.load(Ordering::SeqCst),
    );

    assert_eq!(outcome, fill_drain::FillDrainOutcome::Done);
    assert_eq!(select_calls.load(Ordering::SeqCst), 1);
    assert_eq!(run_calls.load(Ordering::SeqCst), 0);
}

#[test]
fn stops_selecting_new_trials_once_drain_flag_set() {
    let select_calls = AtomicUsize::new(0);
    let run_calls = AtomicUsize::new(0);
    let drain = AtomicBool::new(false);

    let outcome = fill_drain::run_until_done_or_drained(
        || {
            select_calls.fetch_add(1, Ordering::SeqCst);
            vec![1usize]
        },
        |_| {
            run_calls.fetch_add(1, Ordering::SeqCst);
            drain.store(true, Ordering::SeqCst);
        },
        || drain.load(Ordering::SeqCst),
    );

    assert_eq!(outcome, fill_drain::FillDrainOutcome::Drained);
    assert_eq!(select_calls.load(Ordering::SeqCst), 1);
    assert_eq!(run_calls.load(Ordering::SeqCst), 1);
}
