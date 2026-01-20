// Copyright (c) 2025 Geoffrey Huntley <ghuntley@ghuntley.com>. All rights reserved.
// SPDX-License-Identifier: Proprietary

use crate::error::{LocalError, LocalResult};
use bytes::Bytes;
use futures::Future;
use pin_project_lite::pin_project;
use portable_pty::{native_pty_system, CommandBuilder, PtyPair, PtySize};
use std::io::{self, Read, Write};
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc;

const CHANNEL_BUFFER_SIZE: usize = 32;
const READ_BUFFER_SIZE: usize = 4096;

pin_project! {
	pub struct PtyAsyncReader {
		rx: mpsc::Receiver<io::Result<Bytes>>,
		buffer: Bytes,
	}
}

impl PtyAsyncReader {
	pub fn new(mut reader: Box<dyn Read + Send>) -> Self {
		let (tx, rx) = mpsc::channel(CHANNEL_BUFFER_SIZE);

		tokio::task::spawn_blocking(move || {
			let mut buf = vec![0u8; READ_BUFFER_SIZE];
			loop {
				match reader.read(&mut buf) {
					Ok(0) => {
						let _ = tx.blocking_send(Ok(Bytes::new()));
						break;
					}
					Ok(n) => {
						let bytes = Bytes::copy_from_slice(&buf[..n]);
						if tx.blocking_send(Ok(bytes)).is_err() {
							break;
						}
					}
					Err(e) => {
						let _ = tx.blocking_send(Err(e));
						break;
					}
				}
			}
		});

		Self {
			rx,
			buffer: Bytes::new(),
		}
	}
}

impl AsyncRead for PtyAsyncReader {
	fn poll_read(
		self: Pin<&mut Self>,
		cx: &mut Context<'_>,
		buf: &mut ReadBuf<'_>,
	) -> Poll<io::Result<()>> {
		let this = self.project();

		if !this.buffer.is_empty() {
			let to_copy = std::cmp::min(this.buffer.len(), buf.remaining());
			buf.put_slice(&this.buffer[..to_copy]);
			*this.buffer = this.buffer.slice(to_copy..);
			return Poll::Ready(Ok(()));
		}

		match this.rx.poll_recv(cx) {
			Poll::Ready(Some(Ok(bytes))) => {
				if bytes.is_empty() {
					return Poll::Ready(Ok(()));
				}
				let to_copy = std::cmp::min(bytes.len(), buf.remaining());
				buf.put_slice(&bytes[..to_copy]);
				if to_copy < bytes.len() {
					*this.buffer = bytes.slice(to_copy..);
				}
				Poll::Ready(Ok(()))
			}
			Poll::Ready(Some(Err(e))) => Poll::Ready(Err(e)),
			Poll::Ready(None) => Poll::Ready(Ok(())),
			Poll::Pending => Poll::Pending,
		}
	}
}

pin_project! {
	pub struct PtyAsyncWriter {
		tx: mpsc::Sender<Bytes>,
		#[pin]
		pending_permit: Option<tokio::sync::mpsc::Permit<'static, Bytes>>,
	}
}

impl PtyAsyncWriter {
	pub fn new(mut writer: Box<dyn Write + Send>) -> Self {
		let (tx, mut rx) = mpsc::channel::<Bytes>(CHANNEL_BUFFER_SIZE);

		tokio::task::spawn_blocking(move || {
			while let Some(bytes) = rx.blocking_recv() {
				if writer.write_all(&bytes).is_err() {
					break;
				}
				if writer.flush().is_err() {
					break;
				}
			}
		});

		Self {
			tx,
			pending_permit: None,
		}
	}
}

impl AsyncWrite for PtyAsyncWriter {
	fn poll_write(
		self: Pin<&mut Self>,
		cx: &mut Context<'_>,
		buf: &[u8],
	) -> Poll<io::Result<usize>> {
		let this = self.project();

		// Try fast path with try_reserve first
		match this.tx.try_reserve() {
			Ok(permit) => {
				let bytes = Bytes::copy_from_slice(buf);
				let len = bytes.len();
				permit.send(bytes);
				return Poll::Ready(Ok(len));
			}
			Err(mpsc::error::TrySendError::Closed(_)) => {
				return Poll::Ready(Err(io::Error::new(
					io::ErrorKind::BrokenPipe,
					"pty writer closed",
				)));
			}
			Err(mpsc::error::TrySendError::Full(_)) => {
				// Channel full, need to wait via reserve() which properly registers waker
				// Fall through to slow path below
			}
		}

		// Slow path: use send() which internally uses reserve() and registers waker correctly
		let bytes = Bytes::copy_from_slice(buf);
		let len = bytes.len();
		let tx = this.tx.clone();

		// Create a future for send operation
		let mut send_future = Box::pin(async move {
			tx.send(bytes).await
		});

		// Poll the send future - this registers the waker via reserve()
		match send_future.as_mut().poll(cx) {
			Poll::Ready(Ok(())) => Poll::Ready(Ok(len)),
			Poll::Ready(Err(_)) => Poll::Ready(Err(io::Error::new(
				io::ErrorKind::BrokenPipe,
				"pty writer closed",
			))),
			Poll::Pending => Poll::Pending, // Waker properly registered by send()
		}
	}

	fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
		Poll::Ready(Ok(()))
	}

	fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
		Poll::Ready(Ok(()))
	}
}

pub struct PtyProcess {
	pub reader: PtyAsyncReader,
	pub writer: PtyAsyncWriter,
	_pair: PtyPair,
}

impl PtyProcess {
	pub fn spawn_tmux_attach(session_name: &str) -> LocalResult<Self> {
		let pty_system = native_pty_system();

		let pair = pty_system
			.openpty(PtySize {
				rows: 24,
				cols: 80,
				pixel_width: 0,
				pixel_height: 0,
			})
			.map_err(|e| LocalError::PtyError {
				message: format!("failed to open pty: {e}"),
			})?;

		let mut cmd = CommandBuilder::new("tmux");
		cmd.args(["attach-session", "-t", session_name]);

		let _child = pair.slave.spawn_command(cmd).map_err(|e| LocalError::PtyError {
			message: format!("failed to spawn tmux attach: {e}"),
		})?;

		let reader = pair.master.try_clone_reader().map_err(|e| LocalError::PtyError {
			message: format!("failed to clone reader: {e}"),
		})?;

		let writer = pair.master.take_writer().map_err(|e| LocalError::PtyError {
			message: format!("failed to take writer: {e}"),
		})?;

		Ok(Self {
			reader: PtyAsyncReader::new(reader),
			writer: PtyAsyncWriter::new(writer),
			_pair: pair,
		})
	}
}
