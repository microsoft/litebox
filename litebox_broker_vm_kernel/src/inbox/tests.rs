// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Host tests of an inbox's state word ([`Word`]), apart from atomics.

use super::{Op, Word};

/// Posts `ops` in turn to `word`: the word after them, and which bound it.
fn post_all(mut word: Word, ops: &[Op]) -> (Word, alloc::vec::Vec<bool>) {
    let mut bound = alloc::vec::Vec::new();
    for &op in ops {
        let (posted, binds) = word.post(op).expect("a post taken");
        word = posted;
        bound.push(binds);
    }
    (word, bound)
}

/// The operations the bound thread takes from `word`, and the word then.
fn drain(mut word: Word) -> (alloc::vec::Vec<Op>, Word) {
    let mut taken = alloc::vec::Vec::new();
    while let Some(op) = word.next() {
        taken.push(op);
        word = word.take(op);
    }
    (taken, word)
}

#[test]
fn the_first_post_binds_and_later_ones_coalesce() {
    let (word, bound) = post_all(
        Word::default(),
        &[Op::Submitted, Op::Submitted, Op::Handshake],
    );
    assert_eq!(bound, [true, false, false]);
    assert!(!word.is_idle());
    let (taken, word) = drain(word);
    assert_eq!(
        taken,
        [Op::Handshake, Op::Submitted],
        "posts of one kind coalesce"
    );
    let word = word.unbound().expect("nothing is left");
    assert!(word.is_idle());
    assert_eq!(word.post(Op::Submitted).map(|(_, bound)| bound), Some(true));
}

#[test]
fn operations_are_taken_adoption_handshake_then_requests() {
    let (word, _) = post_all(Word::default(), &[Op::Submitted, Op::Handshake, Op::Adopt]);
    assert_eq!(drain(word).0, [Op::Adopt, Op::Handshake, Op::Submitted]);
}

#[test]
fn the_end_comes_first_drops_the_rest_and_is_final() {
    let (word, bound) = post_all(Word::default(), &[Op::Submitted, Op::Adopt, Op::End]);
    assert_eq!(
        bound,
        [true, false, false],
        "the end binds no second thread"
    );
    let (taken, word) = drain(word);
    assert_eq!(
        taken,
        [Op::End],
        "the operations not yet started are dropped"
    );
    assert!(word.is_ending());
    for op in [Op::Submitted, Op::Handshake, Op::Adopt, Op::End] {
        assert_eq!(word.post(op), None, "nothing is posted after the end");
    }
    assert!(word.unbound().is_some_and(Word::is_idle));
}

#[test]
fn a_second_handshake_is_refused() {
    let (word, _) = post_all(Word::default(), &[Op::Handshake]);
    assert_eq!(word.post(Op::Handshake), None, "while pending");
    let word = word.take(Op::Handshake).unbound().expect("nothing is left");
    assert_eq!(word.post(Op::Handshake), None, "once done");
    assert!(word.post(Op::Submitted).is_some());
}

#[test]
fn a_finished_thread_is_unbound_only_if_nothing_is_left() {
    let (word, _) = post_all(Word::default(), &[Op::Submitted]);
    let taken = word.take(Op::Submitted);
    let (posted, bound) = taken.post(Op::Submitted).expect("a post taken");
    assert!(!bound, "the inbox is still bound");
    assert_eq!(posted.unbound(), None);
    assert_eq!(drain(posted).0, [Op::Submitted]);
}
