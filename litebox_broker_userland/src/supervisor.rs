// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Concurrent ownership for a finite set of out-of-process runners.

use std::io::{Error as IoError, Result as IoResult};
use std::process::ExitStatus;

use litebox_broker_core::BrokerCore;

use crate::runner::{RunnerConfig, RunnerInstance};

/// Runs out-of-process runners concurrently against one broker core.
pub struct RunnerSupervisor {
    broker: BrokerCore,
}

impl RunnerSupervisor {
    /// Creates a supervisor that owns the shared broker core.
    #[must_use]
    pub const fn new(broker: BrokerCore) -> Self {
        Self { broker }
    }

    /// Runs every configured runner concurrently and waits for all of them.
    ///
    /// Results retain configuration order. A runner's launch, association, or
    /// exit does not stop the other runners.
    pub fn run_to_completion(self, runners: Vec<RunnerConfig>) -> Vec<IoResult<ExitStatus>> {
        let workers = runners
            .into_iter()
            .enumerate()
            .map(|(runner_index, config)| {
                let broker = self.broker.clone();
                std::thread::Builder::new()
                    .name(format!("litebox-runner-{runner_index}"))
                    .spawn(move || RunnerInstance::start(config)?.run_to_completion(&broker))
            })
            .collect::<Vec<_>>();

        workers
            .into_iter()
            .map(|worker| match worker {
                Ok(worker) => worker
                    .join()
                    .unwrap_or_else(|_| Err(IoError::other("runner supervisor worker panicked"))),
                Err(error) => Err(IoError::new(
                    error.kind(),
                    format!("failed to start runner supervisor worker: {error}"),
                )),
            })
            .collect()
    }
}
