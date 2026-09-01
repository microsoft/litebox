// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Idle-timeout stream wrapper.

use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll};
use core::time::Duration;
use std::io;

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::time::{Instant, Sleep, sleep_until};

/// A stream that fails after making no progress for its idle timeout.
pub(crate) struct IdleTimeoutStream<S> {
    inner: S,
    idle: Duration,
    timer: Pin<Box<Sleep>>,
}

impl<S> IdleTimeoutStream<S> {
    pub(crate) fn new(inner: S, idle: Duration) -> Self {
        Self {
            inner,
            idle,
            timer: Box::pin(sleep_until(Instant::now() + idle)),
        }
    }

    fn touch(&mut self) {
        self.timer.as_mut().reset(Instant::now() + self.idle);
    }

    fn expired(&mut self, cx: &mut Context<'_>) -> bool {
        self.timer.as_mut().poll(cx).is_ready()
    }
}

fn timed_out() -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, "stream idle timeout exceeded")
}

impl<S: AsyncRead + Unpin> AsyncRead for IdleTimeoutStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_read(cx, buffer) {
            Poll::Ready(result) => {
                this.touch();
                Poll::Ready(result)
            }
            Poll::Pending if this.expired(cx) => Poll::Ready(Err(timed_out())),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for IdleTimeoutStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_write(cx, buffer) {
            Poll::Ready(result) => {
                this.touch();
                Poll::Ready(result)
            }
            Poll::Pending if this.expired(cx) => Poll::Ready(Err(timed_out())),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_flush(cx) {
            Poll::Ready(result) => {
                this.touch();
                Poll::Ready(result)
            }
            Poll::Pending if this.expired(cx) => Poll::Ready(Err(timed_out())),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_shutdown(cx) {
            Poll::Ready(result) => {
                this.touch();
                Poll::Ready(result)
            }
            Poll::Pending if this.expired(cx) => Poll::Ready(Err(timed_out())),
            Poll::Pending => Poll::Pending,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use tokio::io::{AsyncReadExt, duplex};

    #[tokio::test(start_paused = true)]
    async fn idle_stream_times_out() {
        let (client, _server) = duplex(64);
        let mut limited = IdleTimeoutStream::new(client, Duration::from_secs(60));
        let mut buffer = [0_u8; 8];
        let error = limited.read(&mut buffer).await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    }
}
