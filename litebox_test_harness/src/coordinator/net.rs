// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use super::*;
use crate::protocol::{Command, Response};

pub(super) async fn net_tests(r: &mut TestRunner) {
    // N1: Parent→child (init → A)
    let resp = r.send("A", Command::NetListen { port: 9001 }).await;
    let pass = matches!(resp, Response::Listening { .. });
    r.record("N1.listen", "A", pass, &format!("{resp:?}"));

    let resp = r
        .send(
            "init",
            Command::NetConnect {
                addr: "127.0.0.1:9001".into(),
                data: "N1".into(),
            },
        )
        .await;
    let pass = matches!(&resp, Response::Connected { echo } if echo == "N1");
    r.record("N1.init→A", "init", pass, &format!("{resp:?}"));

    // N2: A → B (sibling)
    let resp = r.send("B", Command::NetListen { port: 9002 }).await;
    let pass = matches!(resp, Response::Listening { .. });
    r.record("N2.listen", "B", pass, &format!("{resp:?}"));

    let resp = r
        .send(
            "A",
            Command::NetConnect {
                addr: "127.0.0.1:9002".into(),
                data: "N2".into(),
            },
        )
        .await;
    let pass = matches!(&resp, Response::Connected { echo } if echo == "N2");
    r.record("N2.A→B", "A", pass, &format!("{resp:?}"));

    // N3: B → A (reverse sibling)
    let resp = r
        .send(
            "B",
            Command::NetConnect {
                addr: "127.0.0.1:9001".into(),
                data: "N3".into(),
            },
        )
        .await;
    let pass = matches!(&resp, Response::Connected { echo } if echo == "N3");
    r.record("N3.B→A", "B", pass, &format!("{resp:?}"));

    // N4: Grandchild → grandparent (AAA → A)
    let resp = r
        .send(
            "AAA",
            Command::NetConnect {
                addr: "127.0.0.1:9001".into(),
                data: "N4".into(),
            },
        )
        .await;
    let pass = matches!(&resp, Response::Connected { echo } if echo == "N4");
    r.record("N4.AAA→A", "AAA", pass, &format!("{resp:?}"));

    // Done with A:9001
    let resp = r.send("A", Command::NetUnlisten { port: 9001 }).await;
    r.record(
        "N1.unlisten",
        "A",
        matches!(resp, Response::Ok { .. }),
        &format!("{resp:?}"),
    );

    // N5: Cross-subtree (B → AAA)
    let resp = r.send("AAA", Command::NetListen { port: 9005 }).await;
    let pass = matches!(resp, Response::Listening { .. });
    r.record("N5.listen", "AAA", pass, &format!("{resp:?}"));

    let resp = r
        .send(
            "B",
            Command::NetConnect {
                addr: "127.0.0.1:9005".into(),
                data: "N5".into(),
            },
        )
        .await;
    let pass = matches!(&resp, Response::Connected { echo } if echo == "N5");
    r.record("N5.B→AAA", "B", pass, &format!("{resp:?}"));

    let resp = r.send("AAA", Command::NetUnlisten { port: 9005 }).await;
    r.record(
        "N5.unlisten",
        "AAA",
        matches!(resp, Response::Ok { .. }),
        &format!("{resp:?}"),
    );

    // N6: Sibling at depth 2 (AA → AB)
    let resp = r.send("AB", Command::NetListen { port: 9004 }).await;
    let pass = matches!(resp, Response::Listening { .. });
    r.record("N6.listen", "AB", pass, &format!("{resp:?}"));

    let resp = r
        .send(
            "AA",
            Command::NetConnect {
                addr: "127.0.0.1:9004".into(),
                data: "N6".into(),
            },
        )
        .await;
    let pass = matches!(&resp, Response::Connected { echo } if echo == "N6");
    r.record("N6.AA→AB", "AA", pass, &format!("{resp:?}"));

    let resp = r.send("AB", Command::NetUnlisten { port: 9004 }).await;
    r.record(
        "N6.unlisten",
        "AB",
        matches!(resp, Response::Ok { .. }),
        &format!("{resp:?}"),
    );

    // N7: Sibling at depth 3 (AAA → AAB)
    let resp = r.send("AAB", Command::NetListen { port: 9006 }).await;
    let pass = matches!(resp, Response::Listening { .. });
    r.record("N7.listen", "AAB", pass, &format!("{resp:?}"));

    let resp = r
        .send(
            "AAA",
            Command::NetConnect {
                addr: "127.0.0.1:9006".into(),
                data: "N7".into(),
            },
        )
        .await;
    let pass = matches!(&resp, Response::Connected { echo } if echo == "N7");
    r.record("N7.AAA→AAB", "AAA", pass, &format!("{resp:?}"));

    let resp = r.send("AAB", Command::NetUnlisten { port: 9006 }).await;
    r.record(
        "N7.unlisten",
        "AAB",
        matches!(resp, Response::Ok { .. }),
        &format!("{resp:?}"),
    );

    // N8: Uncle (AB → B)
    let resp = r
        .send(
            "AB",
            Command::NetConnect {
                addr: "127.0.0.1:9002".into(),
                data: "N8".into(),
            },
        )
        .await;
    let pass = matches!(&resp, Response::Connected { echo } if echo == "N8");
    r.record("N8.AB→B", "AB", pass, &format!("{resp:?}"));

    // Done with B:9002
    let resp = r.send("B", Command::NetUnlisten { port: 9002 }).await;
    r.record(
        "N8.unlisten",
        "B",
        matches!(resp, Response::Ok { .. }),
        &format!("{resp:?}"),
    );
}
