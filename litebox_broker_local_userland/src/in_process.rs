// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use std::io::{Error, Result as IoResult};
use std::sync::Mutex;
use std::thread::JoinHandle;

pub(crate) struct InProcessHostThread {
    thread: Mutex<Option<JoinHandle<IoResult<()>>>>,
}

impl InProcessHostThread {
    pub(crate) const fn new(thread: JoinHandle<IoResult<()>>) -> Self {
        Self {
            thread: Mutex::new(Some(thread)),
        }
    }

    pub(crate) fn join(&self) -> IoResult<()> {
        let mut thread = self
            .thread
            .lock()
            .map_err(|_| Error::other("in-process broker host thread mutex poisoned"))?;
        let Some(thread) = thread.take() else {
            return Ok(());
        };
        thread
            .join()
            .map_err(|_| Error::other("in-process broker host thread panicked"))?
    }

    pub(crate) fn join_and_report(&self) {
        if let Err(error) = self.join() {
            eprintln!("in-process broker host failed: {error}");
        }
    }
}

impl Drop for InProcessHostThread {
    fn drop(&mut self) {
        if let Err(error) = self.join() {
            eprintln!("in-process broker host failed: {error}");
        }
    }
}
