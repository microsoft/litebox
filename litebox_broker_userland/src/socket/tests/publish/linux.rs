// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use super::*;

#[test]
fn clients_wait_in_the_host_backlog_until_the_guest_accepts() {
    let guest = guest(8, 20_802);
    let (listener, _) = guest.listen("10.0.2.15:80");
    // Listening again raises the host backlog from 4, which would hold only 5 clients: unlike
    // Winsock, which keeps a listener's first backlog.
    let relisten = litebox_broker_core::socket::listen(&guest.process, listener, 16);
    assert!(matches!(relisten, Ok(SocketOutcome::Completed(_))));
    let (host, timeout) = (guest.host.into(), Duration::from_secs(1));
    let clients: Vec<_> = (0..6)
        .map(|_| TcpStream::connect_timeout(&host, timeout))
        .collect();
    for client in clients {
        guest.wait(listener);
        let port = client.unwrap().local_addr().unwrap().port();
        assert_eq!(guest.accept(listener).unwrap().remote_address.port(), port);
    }
    assert_eq!(guest.accept(listener).err(), Some(BrokerError::WouldBlock));
    let readiness = guest.process.check_readiness(listener).unwrap();
    assert!(!readiness.contains(ReadinessFlags::READ));
}
