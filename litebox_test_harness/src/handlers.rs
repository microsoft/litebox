// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Generic handler dispatch for `Command::Run`.
//!
//! A *handler* is an async function registered under a string name
//! that runs on the agent in response to `Command::Run { handler,
//! args }`. The handler's body holds any per-invocation state in its
//! own stack frame (no global `AgentState` access by default), so
//! handlers from different tests don't accidentally couple.
//!
//! Handlers may rendezvous with other agents mid-flight via
//! `HandlerCtx::checkpoint(tag)` — the sole sync primitive in this
//! protocol. The agent emits `Response::Checkpoint { tag }`, then
//! blocks reading stdin for `Command::Resume { tag }`.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex, OnceLock};

use serde_json::Value;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

use crate::protocol::{Command, Response};

/// Error returned by a handler. String-typed for simplicity.
#[derive(Debug, Clone)]
pub struct HandlerError(pub String);

impl<E: std::fmt::Display> From<E> for HandlerError {
    fn from(e: E) -> Self {
        Self(e.to_string())
    }
}

/// Runtime context handed to a handler body. Carries access to the
/// agent's stdin reader (for `checkpoint`) and `self_exe` (for
/// handlers that need to spawn child agents, e.g. fork tests).
pub struct HandlerCtx<'a> {
    pub self_exe: &'a str,
    reader: &'a mut BufReader<tokio::io::Stdin>,
}

impl<'a> HandlerCtx<'a> {
    pub fn new(self_exe: &'a str, reader: &'a mut BufReader<tokio::io::Stdin>) -> Self {
        Self { self_exe, reader }
    }

    /// Rendezvous point. Emits `Response::Checkpoint { tag }` and
    /// blocks reading stdin until the coord sends back
    /// `Command::Resume { tag }`.
    ///
    /// # Errors
    /// Returns Err on stdin/stdout I/O failure or if the coord sends
    /// a wrong-tag Resume or unrelated command.
    pub async fn checkpoint(&mut self, tag: &str) -> Result<(), HandlerError> {
        let json = serde_json::to_string(&Response::Checkpoint {
            tag: tag.to_string(),
        })
        .map_err(|e| HandlerError(format!("checkpoint serialize: {e}")))?;
        let mut stdout = tokio::io::stdout();
        stdout
            .write_all(format!("{json}\n").as_bytes())
            .await
            .map_err(|e| HandlerError(format!("checkpoint write: {e}")))?;
        stdout
            .flush()
            .await
            .map_err(|e| HandlerError(format!("checkpoint flush: {e}")))?;

        let mut line = String::new();
        loop {
            line.clear();
            let n = self
                .reader
                .read_line(&mut line)
                .await
                .map_err(|e| HandlerError(format!("await_resume read: {e}")))?;
            if n == 0 {
                return Err(HandlerError("eof while awaiting resume".into()));
            }
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            let cmd: Command = serde_json::from_str(trimmed)
                .map_err(|e| HandlerError(format!("await_resume parse: {e}")))?;
            match cmd {
                Command::Resume { tag: got } if got == tag => return Ok(()),
                Command::Resume { tag: got } => {
                    return Err(HandlerError(format!(
                        "wrong resume tag: expected {tag}, got {got}"
                    )));
                }
                other => {
                    return Err(HandlerError(format!("expected Resume, got {other:?}")));
                }
            }
        }
    }
}

/// Type-erased dispatcher: knows how to deserialize args, invoke the
/// user fn, and serialize the result.
pub trait HandlerDispatch: Send + Sync {
    fn invoke<'a>(
        &'a self,
        args: Value,
        ctx: &'a mut HandlerCtx<'a>,
    ) -> Pin<Box<dyn Future<Output = Result<Value, HandlerError>> + Send + 'a>>;
}

/// Adapter from a typed `async fn` (lifted via `handler_fn!`) into
/// the type-erased trait object.
struct FnHandler<F> {
    f: F,
}

impl<F> HandlerDispatch for FnHandler<F>
where
    F: for<'a, 'b> Fn(
            Value,
            &'b mut HandlerCtx<'a>,
        )
            -> Pin<Box<dyn Future<Output = Result<Value, HandlerError>> + Send + 'b>>
        + Send
        + Sync
        + 'static,
{
    fn invoke<'a>(
        &'a self,
        args: Value,
        ctx: &'a mut HandlerCtx<'a>,
    ) -> Pin<Box<dyn Future<Output = Result<Value, HandlerError>> + Send + 'a>> {
        (self.f)(args, ctx)
    }
}

/// Lift an `async fn(A: DeserializeOwned, &mut HandlerCtx<'_>) ->
/// Result<O: Serialize, HandlerError>` into the untyped closure shape
/// the dispatcher expects. The macro generates the deserialize-args
/// / call-fn / serialize-out adapter.
///
/// ```ignore
/// async fn handle_foo(args: FooArgs, ctx: &mut HandlerCtx<'_>)
///     -> Result<FooOut, HandlerError> { ... }
///
/// register_handler!("foo", handle_foo);
/// ```
#[macro_export]
macro_rules! handler_fn {
    ($f:path) => {
        |args, ctx| {
            ::std::boxed::Box::pin(async move {
                let typed_args = ::serde_json::from_value(args).map_err(|e| {
                    $crate::handlers::HandlerError(format!("args deserialize: {e}"))
                })?;
                let typed_out = $f(typed_args, ctx).await?;
                ::serde_json::to_value(&typed_out)
                    .map_err(|e| $crate::handlers::HandlerError(format!("out serialize: {e}")))
            })
        }
    };
}

// ─── Registry ──────────────────────────────────────────────────────

type Registry = Mutex<HashMap<String, Arc<dyn HandlerDispatch>>>;
static HANDLERS: OnceLock<Registry> = OnceLock::new();

fn registry() -> &'static Registry {
    HANDLERS.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Register a handler under `name`. Called at registration time
/// from each family's test-registration function (via
/// `register_handler!` for ergonomics).
///
/// # Panics
/// Panics if the registry mutex is poisoned.
pub fn register<F>(name: &str, f: F)
where
    F: for<'a, 'b> Fn(
            Value,
            &'b mut HandlerCtx<'a>,
        )
            -> Pin<Box<dyn Future<Output = Result<Value, HandlerError>> + Send + 'b>>
        + Send
        + Sync
        + 'static,
{
    let dispatcher: Arc<dyn HandlerDispatch> = Arc::new(FnHandler { f });
    let mut m = registry().lock().expect("handler registry poisoned");
    m.insert(name.to_string(), dispatcher);
}

/// Look up a registered handler.
///
/// # Panics
/// Panics if the registry mutex is poisoned.
#[must_use]
pub fn lookup(name: &str) -> Option<Arc<dyn HandlerDispatch>> {
    let m = registry().lock().expect("handler registry poisoned");
    m.get(name).cloned()
}

/// Convenience macro for registration. Wraps `handler_fn!` and the
/// `register` call.
///
/// ```ignore
/// register_handler!("inotify.create_file.watcher", handle_watch_for_create);
/// ```
#[macro_export]
macro_rules! register_handler {
    ($name:expr, $f:path) => {
        $crate::handlers::register($name, $crate::handler_fn!($f))
    };
}

// ─── Agent-side dispatch entry point ────────────────────────────────

/// Dispatch a `Command::Run` to its registered handler and return
/// the protocol `Response` to write back. Constructs a `HandlerCtx`
/// from the agent's `self_exe` and stdin reader.
pub async fn dispatch_run(
    handler: &str,
    args: Value,
    self_exe: &str,
    reader: &mut BufReader<tokio::io::Stdin>,
) -> Response {
    let Some(dispatcher) = lookup(handler) else {
        return Response::Result {
            ok: false,
            data: Value::Null,
            error: Some(format!("no handler registered: {handler}")),
        };
    };
    let mut ctx = HandlerCtx::new(self_exe, reader);
    match dispatcher.invoke(args, &mut ctx).await {
        Ok(value) => Response::Result {
            ok: true,
            data: value,
            error: None,
        },
        Err(err) => Response::Result {
            ok: false,
            data: Value::Null,
            error: Some(err.0),
        },
    }
}
