// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use super::*;
use crate::protocol::{Command, Response};

pub(super) async fn fs_tests(r: &mut TestRunner) {
    // Ensure /shared/ exists and clean up stale files from prior runs.
    let _ = tokio::fs::create_dir_all("/shared").await;
    for name in [
        "f1.txt",
        "f2.txt",
        "f3.txt",
        "f3b.txt",
        "f4.txt",
        "f4c.txt",
        "for_host.txt",
    ] {
        let _ = tokio::fs::remove_file(format!("/shared/{name}")).await;
    }

    // F1: Parent→child CRUD (init writes, A reads)
    let resp = r
        .send(
            "A",
            Command::FsRead {
                path: "/shared/f1.txt".into(),
            },
        )
        .await;
    r.record(
        "F1.absent",
        "A",
        matches!(resp, Response::NotFound),
        &format!("{resp:?}"),
    );
    r.send(
        "init",
        Command::FsWrite {
            path: "/shared/f1.txt".into(),
            data: "hello".into(),
        },
    )
    .await;
    let resp = r
        .send(
            "A",
            Command::FsRead {
                path: "/shared/f1.txt".into(),
            },
        )
        .await;
    let pass = matches!(&resp, Response::Ok { data: Some(d) } if d == "hello");
    r.record("F1.created", "A", pass, &format!("{resp:?}"));
    r.send(
        "init",
        Command::FsWrite {
            path: "/shared/f1.txt".into(),
            data: "updated".into(),
        },
    )
    .await;
    let resp = r
        .send(
            "A",
            Command::FsRead {
                path: "/shared/f1.txt".into(),
            },
        )
        .await;
    let pass = matches!(&resp, Response::Ok { data: Some(d) } if d == "updated");
    r.record("F1.updated", "A", pass, &format!("{resp:?}"));
    r.send(
        "init",
        Command::FsDelete {
            path: "/shared/f1.txt".into(),
        },
    )
    .await;
    let resp = r
        .send(
            "A",
            Command::FsRead {
                path: "/shared/f1.txt".into(),
            },
        )
        .await;
    r.record(
        "F1.deleted",
        "A",
        matches!(resp, Response::NotFound),
        &format!("{resp:?}"),
    );

    // F2: Child→parent (A writes, init reads)
    r.send(
        "A",
        Command::FsWrite {
            path: "/shared/f2.txt".into(),
            data: "from_child".into(),
        },
    )
    .await;
    let resp = r
        .send(
            "init",
            Command::FsRead {
                path: "/shared/f2.txt".into(),
            },
        )
        .await;
    let pass = matches!(&resp, Response::Ok { data: Some(d) } if d == "from_child");
    r.record("F2", "init", pass, &format!("{resp:?}"));
    r.send(
        "A",
        Command::FsWrite {
            path: "/shared/f2.txt".into(),
            data: "child_update".into(),
        },
    )
    .await;
    let resp = r
        .send(
            "init",
            Command::FsRead {
                path: "/shared/f2.txt".into(),
            },
        )
        .await;
    let pass = matches!(&resp, Response::Ok { data: Some(d) } if d == "child_update");
    r.record("F2.update", "init", pass, &format!("{resp:?}"));
    r.send(
        "A",
        Command::FsDelete {
            path: "/shared/f2.txt".into(),
        },
    )
    .await;
    let resp = r
        .send(
            "init",
            Command::FsRead {
                path: "/shared/f2.txt".into(),
            },
        )
        .await;
    r.record(
        "F2.deleted",
        "init",
        matches!(resp, Response::NotFound),
        &format!("{resp:?}"),
    );

    // F3: Sibling visibility (A writes, B reads)
    r.send(
        "A",
        Command::FsWrite {
            path: "/shared/f3.txt".into(),
            data: "from_A".into(),
        },
    )
    .await;
    let resp = r
        .send(
            "B",
            Command::FsRead {
                path: "/shared/f3.txt".into(),
            },
        )
        .await;
    let pass = matches!(&resp, Response::Ok { data: Some(d) } if d == "from_A");
    r.record("F3.A→B", "B", pass, &format!("{resp:?}"));
    r.send(
        "B",
        Command::FsWrite {
            path: "/shared/f3b.txt".into(),
            data: "from_B".into(),
        },
    )
    .await;
    let resp = r
        .send(
            "A",
            Command::FsRead {
                path: "/shared/f3b.txt".into(),
            },
        )
        .await;
    let pass = matches!(&resp, Response::Ok { data: Some(d) } if d == "from_B");
    r.record("F3.B→A", "A", pass, &format!("{resp:?}"));

    // F4: Grandchild (AA writes, init reads)
    r.send(
        "AA",
        Command::FsWrite {
            path: "/shared/f4.txt".into(),
            data: "from_AA".into(),
        },
    )
    .await;
    let resp = r
        .send(
            "init",
            Command::FsRead {
                path: "/shared/f4.txt".into(),
            },
        )
        .await;
    let pass = matches!(&resp, Response::Ok { data: Some(d) } if d == "from_AA");
    r.record("F4.AA→init", "init", pass, &format!("{resp:?}"));
    let resp = r
        .send(
            "B",
            Command::FsRead {
                path: "/shared/f4.txt".into(),
            },
        )
        .await;
    let pass = matches!(&resp, Response::Ok { data: Some(d) } if d == "from_AA");
    r.record("F4.AA→B", "B", pass, &format!("{resp:?}"));
    r.send(
        "AAA",
        Command::FsWrite {
            path: "/shared/f4c.txt".into(),
            data: "from_AAA".into(),
        },
    )
    .await;
    let resp = r
        .send(
            "init",
            Command::FsRead {
                path: "/shared/f4c.txt".into(),
            },
        )
        .await;
    let pass = matches!(&resp, Response::Ok { data: Some(d) } if d == "from_AAA");
    r.record("F4.AAA→init", "init", pass, &format!("{resp:?}"));

    // F5: /tmp isolation (A writes /tmp, AA reads — should be absent if isolated)
    r.send(
        "A",
        Command::FsWrite {
            path: "/tmp/f5.txt".into(),
            data: "temp".into(),
        },
    )
    .await;
    let resp = r
        .send(
            "AA",
            Command::FsRead {
                path: "/tmp/f5.txt".into(),
            },
        )
        .await;
    let is_isolated = matches!(resp, Response::NotFound);
    r.record(
        "F5.parent→child",
        "AA",
        true,
        &format!("tmp_isolated={is_isolated}: {resp:?}"),
    );
    let resp = r
        .send(
            "B",
            Command::FsRead {
                path: "/tmp/f5.txt".into(),
            },
        )
        .await;
    let is_isolated = matches!(resp, Response::NotFound);
    r.record(
        "F5.sibling",
        "B",
        true,
        &format!("tmp_isolated={is_isolated}: {resp:?}"),
    );

    // F6: Host pre-written file (/shared/host_wrote.txt must exist in rootfs)
    // xfail when file doesn't exist — the integration test rootfs creates it,
    // but the VS Code rootfs doesn't have it pre-written.
    let resp = r
        .send(
            "init",
            Command::FsRead {
                path: "/shared/host_wrote.txt".into(),
            },
        )
        .await;
    let pass = matches!(&resp, Response::Ok { data: Some(d) } if d == "from_host");
    if matches!(&resp, Response::NotFound) {
        r.record_xfail(
            "F6.host→init",
            "init",
            pass,
            "host_wrote.txt not in rootfs",
            &format!("{resp:?}"),
        );
    } else {
        r.record("F6.host→init", "init", pass, &format!("{resp:?}"));
    }
    let resp = r
        .send(
            "A",
            Command::FsRead {
                path: "/shared/host_wrote.txt".into(),
            },
        )
        .await;
    let pass = matches!(&resp, Response::Ok { data: Some(d) } if d == "from_host");
    if matches!(&resp, Response::NotFound) {
        r.record_xfail(
            "F6.host→A",
            "A",
            pass,
            "host_wrote.txt not in rootfs",
            &format!("{resp:?}"),
        );
    } else {
        r.record("F6.host→A", "A", pass, &format!("{resp:?}"));
    }
    // Agent writes for host to read after exit
    r.send(
        "init",
        Command::FsWrite {
            path: "/shared/for_host.txt".into(),
            data: "from_agent".into(),
        },
    )
    .await;
}
