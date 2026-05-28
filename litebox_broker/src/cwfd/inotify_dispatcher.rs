// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Broker-global inotify subscription fan-out for 9P filesystem mutations.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, Weak};

use crate::cwfd::inotify_state::InotifyState;

#[derive(Clone, Debug)]
struct WatchRegistration {
    wd: i32,
    mask: u32,
    state: Weak<InotifyState>,
}

/// Broker-global map from watched guest path to interested inotify states.
#[derive(Debug, Default)]
pub struct InotifyDispatcher {
    watches: Mutex<BTreeMap<String, Vec<WatchRegistration>>>,
}

impl InotifyDispatcher {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&self, path: String, wd: i32, mask: u32, state: &Arc<InotifyState>) {
        self.watches
            .lock()
            .expect("InotifyDispatcher poisoned")
            .entry(normalize_guest_path(&path))
            .or_default()
            .push(WatchRegistration {
                wd,
                mask,
                state: Arc::downgrade(state),
            });
    }

    pub fn unregister(&self, path: &str, wd: i32) {
        let mut watches = self.watches.lock().expect("InotifyDispatcher poisoned");
        let key = normalize_guest_path(path);
        if let Some(entries) = watches.get_mut(&key) {
            entries.retain(|entry| entry.wd != wd || entry.state.strong_count() == 0);
            if entries.is_empty() {
                watches.remove(&key);
            }
        }
    }

    pub fn dispatch(&self, watched_path: &str, mask: u32, cookie: u32, name: &str) {
        let key = normalize_guest_path(watched_path);
        let entries = {
            let mut watches = self.watches.lock().expect("InotifyDispatcher poisoned");
            let Some(entries) = watches.get_mut(&key) else {
                return;
            };
            entries.retain(|entry| entry.state.strong_count() > 0);
            entries.clone()
        };
        for entry in entries {
            if entry.mask & mask == 0 {
                continue;
            }
            if let Some(state) = entry.state.upgrade() {
                state.enqueue_event(entry.wd, mask, cookie, name.to_string());
            }
        }
    }
}

pub fn normalize_guest_path(path: &str) -> String {
    if path.is_empty() || path == "/" {
        return "/".to_string();
    }
    let mut out = if path.starts_with('/') {
        path.to_string()
    } else {
        format!("/{path}")
    };
    while out.len() > 1 && out.ends_with('/') {
        out.pop();
    }
    out
}
