// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use std::sync::{Arc, Mutex};

use litebox_e2e_harness::HarnessRunner;

#[test]
fn guest_spawns_child_thread() {
    let recorded: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let runner = HarnessRunner::new();
    {
        let recorded = Arc::clone(&recorded);
        runner.run(move |api| {
            recorded.lock().unwrap().push(String::from("parent"));
            let r2 = Arc::clone(&recorded);
            api.spawn_thread(move |_api| {
                r2.lock().unwrap().push(String::from("child"));
            })
            .expect("spawn_thread failed");
        });
    }
    drop(runner);

    let recorded = recorded.lock().unwrap();
    assert!(
        recorded.contains(&String::from("parent")),
        "parent message missing: {recorded:?}"
    );
    assert!(
        recorded.contains(&String::from("child")),
        "child message missing: {recorded:?}"
    );
    assert_eq!(recorded.len(), 2, "unexpected messages: {recorded:?}");
}

#[test]
fn guest_spawns_nested_child_threads() {
    let recorded: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let runner = HarnessRunner::new();
    {
        let recorded = Arc::clone(&recorded);
        runner.run(move |api| {
            recorded.lock().unwrap().push(String::from("L0"));
            let r1 = Arc::clone(&recorded);
            api.spawn_thread(move |api| {
                r1.lock().unwrap().push(String::from("L1"));
                let r2 = Arc::clone(&r1);
                api.spawn_thread(move |_api| {
                    r2.lock().unwrap().push(String::from("L2"));
                })
                .expect("nested spawn_thread failed");
            })
            .expect("spawn_thread failed");
        });
    }
    drop(runner);

    let recorded = recorded.lock().unwrap();
    for expected in ["L0", "L1", "L2"] {
        assert!(
            recorded.contains(&String::from(expected)),
            "{expected} message missing: {recorded:?}"
        );
    }
    assert_eq!(recorded.len(), 3, "unexpected messages: {recorded:?}");
}
