// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Symlink tests — create, readlink, read-through, visibility across process tree.

use super::TestRunner;
use crate::protocol::{Command, Response};

pub(super) async fn symlink_tests(r: &mut TestRunner) {
    // Probe: does the platform support symlink creation?
    // Litebox currently returns ENOTSUP for symlink().
    let probe = r
        .send(
            "A",
            Command::FsSymlink {
                target: "/tmp/probe_target".into(),
                link: "/tmp/probe_link".into(),
            },
        )
        .await;
    let symlink_unsupported =
        matches!(&probe, Response::Error { error } if error.contains("not supported"));
    // Clean up probe.
    let _ = r
        .send(
            "A",
            Command::FsDelete {
                path: "/tmp/probe_link".into(),
            },
        )
        .await;

    // Helper: record as xfail if symlinks are unsupported, otherwise expect pass.
    macro_rules! record_sym {
        ($test:expr, $agent:expr, $pass:expr, $detail:expr) => {
            if symlink_unsupported {
                r.record_xfail($test, $agent, $pass, "symlink() returns ENOTSUP", $detail);
            } else {
                r.record($test, $agent, $pass, $detail);
            }
        };
    }

    // Clean up stale symlinks from prior runs.
    for name in [
        "s1_link",
        "s1_file",
        "s2_link",
        "s2_file",
        "s3_link",
        "s3_file",
        "s4_link",
        "s4_file",
        "s5_link",
        "s5_file",
        "s7_dangling",
        "s8_link1",
        "s8_link2",
        "s8_file",
        "s9_file",
        "s9_relative",
    ] {
        let _ = r
            .send(
                "init",
                Command::FsDelete {
                    path: format!("/shared/{name}"),
                },
            )
            .await;
    }
    // Clean up S6 directory symlink.
    let _ = r
        .send(
            "A",
            super::exec(vec![
                "rm".into(),
                "-rf".into(),
                "/shared/s6_dir".into(),
                "/shared/s6_dirlink".into(),
            ]),
        )
        .await;

    // S1: In-process — create file, create symlink, readlink, read through symlink
    r.send(
        "A",
        Command::FsWrite {
            path: "/shared/s1_file".into(),
            data: "S1_DATA".into(),
        },
    )
    .await;
    let resp = r
        .send(
            "A",
            Command::FsSymlink {
                target: "/shared/s1_file".into(),
                link: "/shared/s1_link".into(),
            },
        )
        .await;
    let pass = matches!(&resp, Response::Ok { .. });
    record_sym!("S1.create", "A", pass, &format!("{resp:?}"));

    let resp = r
        .send(
            "A",
            Command::FsReadlink {
                path: "/shared/s1_link".into(),
            },
        )
        .await;
    let pass = matches!(&resp, Response::Ok { data: Some(d) } if d == "/shared/s1_file");
    record_sym!("S1.readlink", "A", pass, &format!("{resp:?}"));

    let resp = r
        .send(
            "A",
            Command::FsRead {
                path: "/shared/s1_link".into(),
            },
        )
        .await;
    let pass = matches!(&resp, Response::Ok { data: Some(d) } if d == "S1_DATA");
    record_sym!("S1.read_through", "A", pass, &format!("{resp:?}"));

    let resp = r
        .send(
            "A",
            Command::FsStat {
                path: "/shared/s1_link".into(),
            },
        )
        .await;
    let pass = matches!(&resp, Response::Ok { data: Some(d) } if d == "symlink");
    record_sym!("S1.stat_type", "A", pass, &format!("{resp:?}"));

    // S2: Parent creates symlink, child reads through it
    r.send(
        "init",
        Command::FsWrite {
            path: "/shared/s2_file".into(),
            data: "S2_PARENT".into(),
        },
    )
    .await;
    r.send(
        "init",
        Command::FsSymlink {
            target: "/shared/s2_file".into(),
            link: "/shared/s2_link".into(),
        },
    )
    .await;
    let resp = r
        .send(
            "A",
            Command::FsRead {
                path: "/shared/s2_link".into(),
            },
        )
        .await;
    let pass = matches!(&resp, Response::Ok { data: Some(d) } if d == "S2_PARENT");
    record_sym!("S2.parent→child", "A", pass, &format!("{resp:?}"));

    // S3: Child creates symlink, parent reads through it
    r.send(
        "A",
        Command::FsWrite {
            path: "/shared/s3_file".into(),
            data: "S3_CHILD".into(),
        },
    )
    .await;
    r.send(
        "A",
        Command::FsSymlink {
            target: "/shared/s3_file".into(),
            link: "/shared/s3_link".into(),
        },
    )
    .await;
    let resp = r
        .send(
            "init",
            Command::FsRead {
                path: "/shared/s3_link".into(),
            },
        )
        .await;
    let pass = matches!(&resp, Response::Ok { data: Some(d) } if d == "S3_CHILD");
    record_sym!("S3.child→parent", "init", pass, &format!("{resp:?}"));

    // S4: Sibling visibility — A creates, B reads through
    r.send(
        "A",
        Command::FsWrite {
            path: "/shared/s4_file".into(),
            data: "S4_FROM_A".into(),
        },
    )
    .await;
    r.send(
        "A",
        Command::FsSymlink {
            target: "/shared/s4_file".into(),
            link: "/shared/s4_link".into(),
        },
    )
    .await;
    let resp = r
        .send(
            "B",
            Command::FsRead {
                path: "/shared/s4_link".into(),
            },
        )
        .await;
    let pass = matches!(&resp, Response::Ok { data: Some(d) } if d == "S4_FROM_A");
    record_sym!("S4.sibling", "B", pass, &format!("{resp:?}"));

    // S5: Grandchild creates, init reads
    r.send(
        "AA",
        Command::FsWrite {
            path: "/shared/s5_file".into(),
            data: "S5_GRANDCHILD".into(),
        },
    )
    .await;
    r.send(
        "AA",
        Command::FsSymlink {
            target: "/shared/s5_file".into(),
            link: "/shared/s5_link".into(),
        },
    )
    .await;
    let resp = r
        .send(
            "init",
            Command::FsRead {
                path: "/shared/s5_link".into(),
            },
        )
        .await;
    let pass = matches!(&resp, Response::Ok { data: Some(d) } if d == "S5_GRANDCHILD");
    record_sym!("S5.grandchild→init", "init", pass, &format!("{resp:?}"));

    // S6: Symlink to directory — create dir, create symlink, read file through dir symlink
    let _ = r
        .send(
            "A",
            super::exec(vec![
                "bash".into(),
                "-c".into(),
                "mkdir -p /shared/s6_dir && echo S6_CONTENT > /shared/s6_dir/inside.txt".into(),
            ]),
        )
        .await;
    r.send(
        "A",
        Command::FsSymlink {
            target: "/shared/s6_dir".into(),
            link: "/shared/s6_dirlink".into(),
        },
    )
    .await;
    let resp = r
        .send(
            "A",
            Command::FsRead {
                path: "/shared/s6_dirlink/inside.txt".into(),
            },
        )
        .await;
    let pass = matches!(&resp, Response::Ok { data: Some(d) } if d.trim() == "S6_CONTENT");
    record_sym!("S6.dir_symlink", "A", pass, &format!("{resp:?}"));

    // S7: Dangling symlink — readlink succeeds, read fails
    r.send(
        "A",
        Command::FsSymlink {
            target: "/shared/nonexistent_target".into(),
            link: "/shared/s7_dangling".into(),
        },
    )
    .await;
    let resp = r
        .send(
            "A",
            Command::FsReadlink {
                path: "/shared/s7_dangling".into(),
            },
        )
        .await;
    let pass = matches!(&resp, Response::Ok { data: Some(d) } if d == "/shared/nonexistent_target");
    record_sym!("S7.readlink_dangling", "A", pass, &format!("{resp:?}"));

    let resp = r
        .send(
            "A",
            Command::FsRead {
                path: "/shared/s7_dangling".into(),
            },
        )
        .await;
    let pass = matches!(&resp, Response::Error { .. } | Response::NotFound);
    // read_dangling always passes: if symlinks work, it returns error/notfound
    // because the target doesn't exist. If symlinks are unsupported, the
    // symlink itself doesn't exist, so it also returns notfound.
    r.record("S7.read_dangling", "A", pass, &format!("{resp:?}"));

    // S8: Nested symlinks — link1 → link2 → file
    r.send(
        "A",
        Command::FsWrite {
            path: "/shared/s8_file".into(),
            data: "S8_NESTED".into(),
        },
    )
    .await;
    r.send(
        "A",
        Command::FsSymlink {
            target: "/shared/s8_file".into(),
            link: "/shared/s8_link2".into(),
        },
    )
    .await;
    r.send(
        "A",
        Command::FsSymlink {
            target: "/shared/s8_link2".into(),
            link: "/shared/s8_link1".into(),
        },
    )
    .await;
    let resp = r
        .send(
            "A",
            Command::FsRead {
                path: "/shared/s8_link1".into(),
            },
        )
        .await;
    let pass = matches!(&resp, Response::Ok { data: Some(d) } if d == "S8_NESTED");
    record_sym!("S8.nested", "A", pass, &format!("{resp:?}"));

    // S9: Relative symlink target
    r.send(
        "A",
        Command::FsWrite {
            path: "/shared/s9_file".into(),
            data: "S9_RELATIVE".into(),
        },
    )
    .await;
    r.send(
        "A",
        Command::FsSymlink {
            target: "s9_file".into(),
            link: "/shared/s9_relative".into(),
        },
    )
    .await;
    let resp = r
        .send(
            "A",
            Command::FsRead {
                path: "/shared/s9_relative".into(),
            },
        )
        .await;
    let pass = matches!(&resp, Response::Ok { data: Some(d) } if d == "S9_RELATIVE");
    record_sym!("S9.relative_target", "A", pass, &format!("{resp:?}"));
}
