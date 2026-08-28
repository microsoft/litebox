// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Idle-timeout stream wrapper.

use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll};
use core::time::Duration;
use std::io;
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::time::{Instant, Sleep, sleep_until};

/// A clonable handle to the read half of a TCP stream.
///
/// The proxy retains one handle so it can perform a bounded drain after Hyper
/// flushes a non-upgraded response and releases its stream.
#[derive(Clone)]
pub(crate) struct SharedTcpRead {
    inner: Arc<Mutex<OwnedReadHalf>>,
}

impl AsyncRead for SharedTcpRead {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let Ok(mut inner) = self.inner.lock() else {
            return Poll::Ready(Err(io::Error::other("TCP read half mutex poisoned")));
        };
        Pin::new(&mut *inner).poll_read(cx, buf)
    }
}

/// A split TCP stream whose read half can be retained for bounded closing.
pub(crate) struct SharedTcpStream {
    read: SharedTcpRead,
    write: OwnedWriteHalf,
}

/// Splits a stream while retaining a clonable handle to its read half.
pub(crate) fn share_tcp_read(stream: TcpStream) -> (SharedTcpStream, SharedTcpRead) {
    let (read, write) = stream.into_split();
    let read = SharedTcpRead {
        inner: Arc::new(Mutex::new(read)),
    };
    (
        SharedTcpStream {
            read: read.clone(),
            write,
        },
        read,
    )
}

impl AsyncRead for SharedTcpStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().read).poll_read(cx, buf)
    }
}

impl AsyncWrite for SharedTcpStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().write).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().write).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().write).poll_shutdown(cx)
    }
}

/// A stream that replays a prefix before reading from its inner stream.
pub struct PrefixedStream<S> {
    prefix: Bytes,
    inner: S,
}

impl<S> PrefixedStream<S> {
    /// Creates a stream that yields `prefix` before bytes from `inner`.
    pub fn new(prefix: Bytes, inner: S) -> Self {
        Self { prefix, inner }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for PrefixedStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if !this.prefix.is_empty() && buf.remaining() != 0 {
            let length = this.prefix.len().min(buf.remaining());
            let bytes = this.prefix.split_to(length);
            buf.put_slice(&bytes);
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for PrefixedStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

/// A stream that fails once it stalls for too long, or outlives its deadline.
pub struct LimitedStream<S> {
    inner: S,
    idle: Duration,
    idle_timer: Pin<Box<Sleep>>,
}

impl<S> LimitedStream<S> {
    /// Wraps `inner` with an idle timeout.
    pub fn new(inner: S, idle: Duration) -> Self {
        Self {
            inner,
            idle,
            idle_timer: Box::pin(sleep_until(Instant::now() + idle)),
        }
    }

    /// Restarts the idle timeout after observable progress.
    fn touch(&mut self) {
        let deadline = Instant::now() + self.idle;
        self.idle_timer.as_mut().reset(deadline);
    }

    /// Returns `true` when the stream has been idle for too long.
    fn idle_expired(&mut self, cx: &mut Context<'_>) -> bool {
        self.idle_timer.as_mut().poll(cx).is_ready()
    }
}

fn timed_out(reason: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, reason)
}

impl<S: AsyncRead + Unpin> AsyncRead for LimitedStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_read(cx, buf) {
            Poll::Ready(result) => {
                this.touch();
                Poll::Ready(result)
            }
            Poll::Pending if this.idle_expired(cx) => {
                Poll::Ready(Err(timed_out("stream idle timeout exceeded")))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for LimitedStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_write(cx, buf) {
            Poll::Ready(result) => {
                this.touch();
                Poll::Ready(result)
            }
            Poll::Pending if this.idle_expired(cx) => {
                Poll::Ready(Err(timed_out("stream idle timeout exceeded")))
            }
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
            Poll::Pending if this.idle_expired(cx) => {
                Poll::Ready(Err(timed_out("stream idle timeout exceeded")))
            }
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
            Poll::Pending if this.idle_expired(cx) => {
                Poll::Ready(Err(timed_out("stream idle timeout exceeded")))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use tokio::io::{AsyncReadExt, duplex};

    fn runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
    }

    #[test]
    fn idle_stream_times_out() {
        runtime().block_on(async {
            tokio::time::pause();
            let (client, _server) = duplex(64);
            let mut limited = LimitedStream::new(client, Duration::from_secs(60));
            let mut buffer = [0_u8; 8];
            let error = limited.read(&mut buffer).await.unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        });
    }

}
