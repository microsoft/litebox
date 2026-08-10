// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use std::sync::{Arc, Mutex};

use litebox_e2e_harness::HarnessRunner;

#[test]
fn guest_thread_prints_and_records_message() {
    let recorded: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let runner = HarnessRunner::new();
    {
        let recorded = Arc::clone(&recorded);
        runner.run(move |_api| {
            println!("hello from harness guest");
            recorded
                .lock()
                .unwrap()
                .push(String::from("hello from harness guest"));
        });
    }
    let recorded = recorded.lock().unwrap();
    assert_eq!(
        recorded.as_slice(),
        &[String::from("hello from harness guest")]
    );
}
