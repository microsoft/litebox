// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! What the shim's tests share on every platform: a fake containerd event service, and requests.

use std::sync::{Condvar, Mutex};
use std::time::{Duration, Instant};

use containerd_shim::protos::events::task::{
    TaskCreate, TaskDelete, TaskExecAdded, TaskExecStarted, TaskExit, TaskStart,
};
use containerd_shim::protos::protobuf::Message as _;
use containerd_shim::protos::shim::events::ForwardRequest;
use containerd_shim::protos::shim_sync::Events;
use containerd_shim::protos::ttrpc::{self, Code, TtrpcContext, context};
use containerd_shim::protos::types::empty::Empty;

pub const TIMEOUT: Duration = Duration::from_mins(1);

pub fn deadline() -> context::Context {
    context::with_timeout(i64::try_from(TIMEOUT.as_nanos()).unwrap())
}

/// Polls `done` until it holds, failing with `what` after [`TIMEOUT`].
pub fn wait_until(what: &str, mut done: impl FnMut() -> bool) {
    let start = Instant::now();
    while !done() {
        assert!(start.elapsed() < TIMEOUT, "{what}");
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// The events the shim publishes in `namespace`, as `topic summary`.
pub struct EventLog {
    namespace: String,
    events: Mutex<Vec<String>>,
    published: Condvar,
}

impl EventLog {
    pub fn new(namespace: &str) -> Self {
        Self {
            namespace: namespace.to_owned(),
            events: Mutex::default(),
            published: Condvar::new(),
        }
    }

    /// Waits up to [`TIMEOUT`] for `count` events and returns those published.
    pub fn wait_for(&self, count: usize) -> Vec<String> {
        let events = self.events.lock().unwrap();
        let (events, _) = self
            .published
            .wait_timeout_while(events, TIMEOUT, |events| events.len() < count)
            .unwrap();
        events.clone()
    }
}

impl Events for EventLog {
    fn forward(&self, _ctx: &TtrpcContext, request: ForwardRequest) -> ttrpc::Result<Empty> {
        let envelope = request.envelope.unwrap_or_default();
        assert_eq!(envelope.namespace, self.namespace);
        let value = &envelope.event.value;
        let summary = match envelope.topic.as_str() {
            "/tasks/create" => TaskCreate::parse_from_bytes(value).unwrap().container_id,
            "/tasks/start" => TaskStart::parse_from_bytes(value).unwrap().container_id,
            "/tasks/exec-added" => TaskExecAdded::parse_from_bytes(value).unwrap().exec_id,
            "/tasks/exec-started" => TaskExecStarted::parse_from_bytes(value).unwrap().exec_id,
            "/tasks/exit" => {
                let event = TaskExit::parse_from_bytes(value).unwrap();
                format!("{} {}", event.id, event.exit_status)
            }
            "/tasks/delete" => {
                let event = TaskDelete::parse_from_bytes(value).unwrap();
                format!("{} {}", event.container_id, event.exit_status)
            }
            topic => panic!("unexpected event topic {topic}"),
        };
        let mut events = self.events.lock().unwrap();
        events.push(format!("{} {summary}", envelope.topic));
        self.published.notify_all();
        Ok(Empty::new())
    }
}

pub fn code(error: &ttrpc::Error) -> Code {
    match error {
        ttrpc::Error::RpcStatus(status) => status.code(),
        other => panic!("not a status: {other:?}"),
    }
}

/// An OCI `process` running `args` as root.
pub fn process(args: &[&str]) -> serde_json::Value {
    serde_json::json!({
        "args": args,
        "env": ["PATH=/bin"],
        "cwd": "/",
        "user": {"uid": 0, "gid": 0},
    })
}
