// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#![cfg(any(target_os = "linux", all(windows, target_arch = "x86_64")))]

use std::sync::{Arc, Barrier};

use litebox_broker_core::{ObjectRights, PolicyEngine};
use litebox_broker_local_userland::connect_in_process;
use litebox_broker_protocol::readiness::ReadinessFlags;
use litebox_broker_userland::builder::BrokerCoreBuilder;

#[test]
fn in_process_connection_serves_concurrent_requests_and_shuts_down() {
    let broker = BrokerCoreBuilder::new(PolicyEngine::with_host_guaranteed_rights(
        ObjectRights::all(),
    ))
    .build()
    .unwrap();
    let connection = connect_in_process(&broker).unwrap();
    let local = Arc::new(connection.local);
    let mut notifications = connection.notifications;

    let start = Arc::new(Barrier::new(9));
    let callers = (0..8)
        .map(|initial_count| {
            let local = Arc::clone(&local);
            let start = Arc::clone(&start);
            std::thread::spawn(move || {
                start.wait();
                local.create_event_with_count(initial_count)
            })
        })
        .collect::<Vec<_>>();
    start.wait();

    for (initial_count, caller) in callers.into_iter().enumerate() {
        let handle = caller.join().unwrap().unwrap();
        let readiness = local.check_readiness(handle).unwrap();
        assert_eq!(readiness.contains(ReadinessFlags::READ), initial_count != 0);
        local.close_object(handle).unwrap();
    }

    let notification_receiver = std::thread::spawn(move || {
        loop {
            match notifications.recv_notification() {
                Ok(Some(_)) => {}
                terminal => return terminal,
            }
        }
    });
    drop(local);
    assert!(
        notification_receiver.join().unwrap().is_err(),
        "association shutdown must fail the blocked notification receiver"
    );
}
