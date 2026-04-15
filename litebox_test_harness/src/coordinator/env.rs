// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use super::*;
use crate::protocol::{Command, Response};

pub(super) async fn env_tests(r: &mut TestRunner) {
    // E1: HOME env var
    let resp = r.send("A", Command::EnvGet { var: "HOME".into() }).await;
    let pass = matches!(&resp, Response::Ok { data: Some(d) } if !d.is_empty() && d != "NOT_SET");
    r.record("E1.A", "A", pass, &format!("{resp:?}"));

    // E2: PATH env var
    let resp = r.send("A", Command::EnvGet { var: "PATH".into() }).await;
    let pass = matches!(&resp, Response::Ok { data: Some(d) } if !d.is_empty() && d != "NOT_SET");
    r.record("E2.A", "A", pass, &format!("{resp:?}"));

    // E3: CWD
    let resp = r.send("A", Command::CwdGet).await;
    let pass = matches!(&resp, Response::Ok { data: Some(_) });
    r.record("E3.A", "A", pass, &format!("{resp:?}"));

    // E4: Env var from deep worker
    let resp = r.send("AAA", Command::EnvGet { var: "HOME".into() }).await;
    let pass = matches!(&resp, Response::Ok { data: Some(d) } if !d.is_empty() && d != "NOT_SET");
    r.record("E4.AAA", "AAA", pass, &format!("{resp:?}"));

    // E5: CWD from sibling
    let resp = r.send("B", Command::CwdGet).await;
    let pass = matches!(&resp, Response::Ok { data: Some(_) });
    r.record("E5.B", "B", pass, &format!("{resp:?}"));
}
