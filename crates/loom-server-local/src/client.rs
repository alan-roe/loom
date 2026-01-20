// Copyright (c) 2025 Geoffrey Huntley <ghuntley@ghuntley.com>. All rights reserved.
// SPDX-License-Identifier: Proprietary

use crate::config::LocalConfig;
use crate::error::{LocalError, LocalResult};
use crate::pod_builder::{local_weaver_to_pod, matches_selector, parse_weaver_id};
use crate::pty::PtyProcess;
use crate::tmux::{check_tmux_available, list_sessions, TmuxSession};
use crate::weaver::{LocalWeaver, WeaverMetadata, WeaverStatus};
use async_trait::async_trait;
use bytes::Bytes;
use futures::stream;
use k8s_openapi::api::core::v1::{Namespace, Pod};
use loom_server_k8s::{AttachedProcess, K8sClient, K8sError, LogOptions, LogStream, TokenReviewResult};
use notify::{RecommendedWatcher, RecursiveMode, Watcher};
use std::collections::BTreeMap;
use std::fs;
use std::io::SeekFrom;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncSeekExt};
use tokio::sync::{mpsc, Mutex};

/// Follows a log file continuously, yielding new bytes as they are appended.
/// Implements spec §4: "Follow mode: The stream continues indefinitely"
pub struct LogFollower {
	file: tokio::fs::File,
	#[allow(dead_code)]
	watcher: RecommendedWatcher,
	notify_rx: mpsc::Receiver<()>,
	position: u64,
	session_name: String,
}

impl LogFollower {
	pub async fn new(log_path: &Path, session_name: String, tail_lines: u64) -> std::io::Result<Self> {
		let mut file = tokio::fs::File::open(log_path).await?;
		let file_len = file.metadata().await?.len();

		// Handle tail option: seek to show only last N lines
		let position = if tail_lines > 0 && file_len > 0 {
			// Read entire file to count lines and find offset
			let mut content = Vec::new();
			file.read_to_end(&mut content).await?;

			let mut line_positions: Vec<u64> = vec![0];
			for (i, &byte) in content.iter().enumerate() {
				if byte == b'\n' && i + 1 < content.len() {
					line_positions.push((i + 1) as u64);
				}
			}

			let total_lines = line_positions.len();
			let skip_lines = total_lines.saturating_sub(tail_lines as usize);
			let start_pos = if skip_lines < line_positions.len() {
				line_positions[skip_lines]
			} else {
				0
			};

			// Reopen file and seek to position
			file = tokio::fs::File::open(log_path).await?;
			file.seek(SeekFrom::Start(start_pos)).await?;
			start_pos
		} else {
			0
		};

		// Set up file system watcher
		let (notify_tx, notify_rx) = mpsc::channel(16);
		let watcher = notify::recommended_watcher(move |_res: Result<notify::Event, notify::Error>| {
			let _ = notify_tx.blocking_send(());
		})
		.map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

		// Note: We can't call watch() with async, so we use std::path
		let mut watcher = watcher;
		watcher
			.watch(log_path, RecursiveMode::NonRecursive)
			.map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

		Ok(Self {
			file,
			watcher,
			notify_rx,
			position,
			session_name,
		})
	}

	/// Returns the next chunk of bytes, or None if the stream should terminate.
	/// Spec §4: "Stream terminates when weaver process exits and all buffered output read"
	pub async fn next_chunk(&mut self) -> std::io::Result<Option<Bytes>> {
		loop {
			// Check current file length
			let current_len = self.file.metadata().await?.len();

			if current_len > self.position {
				// New data available - read it
				let bytes_to_read = (current_len - self.position) as usize;
				let mut buf = vec![0u8; bytes_to_read];
				self.file.seek(SeekFrom::Start(self.position)).await?;
				let n = self.file.read(&mut buf).await?;
				if n > 0 {
					self.position += n as u64;
					return Ok(Some(Bytes::from(buf[..n].to_vec())));
				}
			}

			// Check if weaver session still exists (spec §4 termination condition)
			let session = TmuxSession::new(&self.session_name);
			match session.exists() {
				Ok(false) => {
					// Session gone - drain any remaining data and terminate
					let final_len = self.file.metadata().await?.len();
					if final_len > self.position {
						let bytes_to_read = (final_len - self.position) as usize;
						let mut buf = vec![0u8; bytes_to_read];
						self.file.seek(SeekFrom::Start(self.position)).await?;
						let n = self.file.read(&mut buf).await?;
						if n > 0 {
							self.position += n as u64;
							return Ok(Some(Bytes::from(buf[..n].to_vec())));
						}
					}
					return Ok(None);
				}
				Ok(true) => {
					// Session still running, wait for file changes
				}
				Err(_) => {
					// Error checking session - assume still running
				}
			}

			// Wait for file change notification or timeout
			tokio::select! {
				result = self.notify_rx.recv() => {
					if result.is_none() {
						// Channel closed - watcher dropped
						return Ok(None);
					}
					// File changed, loop back to check for new data
				}
				_ = tokio::time::sleep(Duration::from_millis(500)) => {
					// Periodic check in case we miss notifications
				}
			}
		}
	}
}

pub struct LocalClient {
	config: LocalConfig,
	weavers: Arc<Mutex<BTreeMap<String, LocalWeaver>>>,
}

impl LocalClient {
	pub async fn new(server_url: impl Into<String>) -> LocalResult<Self> {
		let config = LocalConfig::new(server_url);

		check_tmux_available()?;

		if !config.base_dir.exists() {
			fs::create_dir_all(&config.base_dir)?;
		}

		let client = Self {
			config,
			weavers: Arc::new(Mutex::new(BTreeMap::new())),
		};

		client.reconcile().await?;

		Ok(client)
	}

	pub async fn with_config(config: LocalConfig) -> LocalResult<Self> {
		check_tmux_available()?;

		if !config.base_dir.exists() {
			fs::create_dir_all(&config.base_dir)?;
		}

		let client = Self {
			config,
			weavers: Arc::new(Mutex::new(BTreeMap::new())),
		};

		client.reconcile().await?;

		Ok(client)
	}

	async fn reconcile(&self) -> LocalResult<()> {
		let weaver_ids = LocalWeaver::list_all(&self.config)?;
		let tmux_sessions = list_sessions()?;

		let mut weavers = self.weavers.lock().await;

		for id in weaver_ids {
			match LocalWeaver::load(&self.config, &id) {
				Ok(mut weaver) => {
					let session_name = weaver.session_name();
					let session_exists = tmux_sessions.contains(&session_name);

					if session_exists {
						let session = TmuxSession::new(&session_name);
						weaver.status = if session.is_pane_dead()? {
							WeaverStatus::Succeeded
						} else {
							WeaverStatus::Running
						};
					} else {
						weaver.status = WeaverStatus::Failed;
					}

					tracing::info!(
						weaver_id = %id,
						status = ?weaver.status,
						"reconciled weaver"
					);

					weavers.insert(id, weaver);
				}
				Err(e) => {
					tracing::warn!(
						weaver_id = %id,
						error = %e,
						"failed to load weaver during reconciliation"
					);
				}
			}
		}

		Ok(())
	}

	async fn get_weaver_status(&self, id: &str) -> LocalResult<WeaverStatus> {
		let session = TmuxSession::new(format!("weaver-{id}"));

		if !session.exists()? {
			return Ok(WeaverStatus::Failed);
		}

		if session.is_pane_dead()? {
			Ok(WeaverStatus::Succeeded)
		} else {
			Ok(WeaverStatus::Running)
		}
	}

	fn extract_weaver_id_from_pod(pod: &Pod) -> Option<String> {
		pod.metadata
			.name
			.as_ref()
			.and_then(|name| parse_weaver_id(name))
	}

	fn extract_labels_from_pod(pod: &Pod) -> BTreeMap<String, String> {
		pod.spec
			.as_ref()
			.and_then(|spec| spec.containers.first())
			.and_then(|_| pod.metadata.labels.clone())
			.unwrap_or_default()
	}

	fn extract_image_from_pod(pod: &Pod) -> String {
		pod.spec
			.as_ref()
			.and_then(|spec| spec.containers.first())
			.and_then(|c| c.image.clone())
			.unwrap_or_else(|| "loom:latest".to_string())
	}

	fn extract_env_vars_from_pod(pod: &Pod) -> Vec<(String, String)> {
		pod.spec
			.as_ref()
			.and_then(|spec| spec.containers.first())
			.map(|c| {
				c.env
					.as_ref()
					.map(|envs| {
						envs.iter()
							.filter_map(|e| e.value.as_ref().map(|v| (e.name.clone(), v.clone())))
							.collect()
					})
					.unwrap_or_default()
			})
			.unwrap_or_default()
	}

	fn extract_annotations_from_pod(pod: &Pod) -> BTreeMap<String, String> {
		pod.metadata.annotations.clone().unwrap_or_default()
	}
}

#[async_trait]
impl K8sClient for LocalClient {
	async fn create_pod(&self, _namespace: &str, pod: Pod) -> Result<Pod, K8sError> {
		let id = Self::extract_weaver_id_from_pod(&pod).ok_or_else(|| LocalError::InvalidWeaverId {
			id: pod.metadata.name.clone().unwrap_or_default(),
		})?;

		let labels = Self::extract_labels_from_pod(&pod);
		let image = Self::extract_image_from_pod(&pod);
		let env_vars = Self::extract_env_vars_from_pod(&pod);
		let annotations = Self::extract_annotations_from_pod(&pod);

		// Resolve working directory from env vars or annotations
		let working_dir = self.config.resolve_working_dir(&id, &env_vars, &annotations);
		let is_fallback_dir = working_dir == self.config.weaver_dir(&id);

		let metadata =
			WeaverMetadata::new(id.clone(), image, labels, working_dir.clone()).with_env_vars(env_vars.clone());

		let weaver = LocalWeaver::create(&self.config, metadata)?;

		// Git clone LOOM_REPO only if using fallback directory (not an existing directory)
		if is_fallback_dir {
			if let Some(repo_url) = env_vars.iter().find(|(k, _)| k == "LOOM_REPO").map(|(_, v)| v) {
				let clone_result = std::process::Command::new("git")
					.args(["clone", repo_url, weaver.dir.to_str().unwrap_or(".")])
					.output();

				match clone_result {
					Ok(output) if output.status.success() => {
						tracing::info!(weaver_id = %id, repo = %repo_url, "cloned LOOM_REPO");
					}
					Ok(output) => {
						let stderr = String::from_utf8_lossy(&output.stderr);
						tracing::warn!(weaver_id = %id, repo = %repo_url, error = %stderr, "failed to clone LOOM_REPO");
					}
					Err(e) => {
						tracing::warn!(weaver_id = %id, repo = %repo_url, error = %e, "failed to run git clone");
					}
				}
			}
		}

		let session = TmuxSession::new(weaver.session_name());
		session.create(&weaver.dir)?;

		let output_log = self.config.output_log_path(&id);
		session.pipe_pane(&output_log)?;

		let mut env_str = String::new();
		for (key, value) in &weaver.metadata.env_vars {
			env_str.push_str(&format!("{}='{}' ", key, value.replace('\'', "'\\''")));
		}

		let server_url = &self.config.server_url;
		let loom_command = &self.config.loom_command;
		let cmd = format!("exec env {env_str}LOOM_SERVER_URL='{server_url}' {loom_command}");
		session.send_keys(&cmd)?;

		if let Some(pid) = session.get_pane_pid()? {
			let pid_path = self.config.pid_path(&id);
			fs::write(&pid_path, pid.to_string()).map_err(LocalError::from)?;
		}

		let mut weavers = self.weavers.lock().await;
		let mut weaver = LocalWeaver::load(&self.config, &id)?;
		weaver.status = WeaverStatus::Running;

		let pod = local_weaver_to_pod(&weaver);
		weavers.insert(id, weaver);

		Ok(pod)
	}

	async fn delete_pod(
		&self,
		name: &str,
		_namespace: &str,
		grace_period_seconds: u32,
	) -> Result<(), K8sError> {
		let id = parse_weaver_id(name).ok_or_else(|| LocalError::InvalidWeaverId {
			id: name.to_string(),
		})?;

		let session = TmuxSession::new(format!("weaver-{id}"));
		session.kill()?;

		// Wait for graceful shutdown if requested
		if grace_period_seconds > 0 {
			tokio::time::sleep(Duration::from_secs(grace_period_seconds as u64)).await;
		}

		// Load metadata to determine cleanup strategy
		if let Ok(weaver) = LocalWeaver::load(&self.config, &id) {
			let is_fallback = weaver.metadata.effective_working_dir(&self.config)
				== self.config.weaver_dir(&id);

			if is_fallback {
				// Delete entire fallback directory (user didn't provide their own)
				LocalWeaver::delete(&self.config, &id)?;
			} else {
				// Only delete metadata directory, preserve user's working directory
				LocalWeaver::delete_metadata_only(&self.config, &id)?;
			}
		} else {
			// Weaver not found in metadata, try to clean up anyway
			LocalWeaver::delete(&self.config, &id)?;
		}

		let mut weavers = self.weavers.lock().await;
		weavers.remove(&id);

		tracing::info!(weaver_id = %id, "deleted weaver");

		Ok(())
	}

	async fn list_pods(&self, _namespace: &str, label_selector: &str) -> Result<Vec<Pod>, K8sError> {
		let weaver_ids = LocalWeaver::list_all(&self.config)?;

		let mut pods = Vec::new();

		for id in weaver_ids {
			match LocalWeaver::load(&self.config, &id) {
				Ok(mut weaver) => {
					if !matches_selector(&weaver.metadata.labels, label_selector) {
						continue;
					}

					weaver.status = self.get_weaver_status(&id).await?;

					pods.push(local_weaver_to_pod(&weaver));
				}
				Err(e) => {
					tracing::warn!(weaver_id = %id, error = %e, "failed to load weaver");
				}
			}
		}

		Ok(pods)
	}

	async fn get_pod(&self, name: &str, _namespace: &str) -> Result<Pod, K8sError> {
		let id = parse_weaver_id(name).ok_or_else(|| LocalError::InvalidWeaverId {
			id: name.to_string(),
		})?;

		let mut weaver = LocalWeaver::load(&self.config, &id)?;
		weaver.status = self.get_weaver_status(&id).await?;

		Ok(local_weaver_to_pod(&weaver))
	}

	async fn get_namespace(&self, _name: &str) -> Result<Namespace, K8sError> {
		if !self.config.base_dir.exists() {
			fs::create_dir_all(&self.config.base_dir).map_err(LocalError::from)?;
		}

		Ok(Namespace {
			metadata: k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta {
				name: Some("local".to_string()),
				..Default::default()
			},
			..Default::default()
		})
	}

	async fn stream_logs(
		&self,
		name: &str,
		_namespace: &str,
		_container: &str,
		opts: LogOptions,
	) -> Result<LogStream, K8sError> {
		let id = parse_weaver_id(name).ok_or_else(|| LocalError::InvalidWeaverId {
			id: name.to_string(),
		})?;

		let log_path = self.config.output_log_path(&id);

		if !log_path.exists() {
			return Err(K8sError::PodNotFound {
				name: name.to_string(),
			});
		}

		let session_name = format!("weaver-{id}");

		// Create LogFollower for continuous file following (spec §4)
		let follower = LogFollower::new(&log_path, session_name, opts.tail.into())
			.await
			.map_err(|e| K8sError::StreamError {
				message: format!("failed to create log follower: {e}"),
			})?;

		// Stream chunks as Bytes (spec §4: "not necessarily line-delimited")
		let stream = stream::unfold(follower, move |mut follower| async move {
			match follower.next_chunk().await {
				Ok(Some(bytes)) => Some((Ok(bytes), follower)),
				Ok(None) => None, // Stream terminated (weaver exited)
				Err(e) => Some((Err(std::io::Error::new(std::io::ErrorKind::Other, e)), follower)),
			}
		});

		Ok(Box::pin(stream))
	}

	async fn exec_attach(
		&self,
		name: &str,
		_namespace: &str,
		_container: &str,
	) -> Result<AttachedProcess, K8sError> {
		let id = parse_weaver_id(name).ok_or_else(|| LocalError::InvalidWeaverId {
			id: name.to_string(),
		})?;

		let session_name = format!("weaver-{id}");
		let session = TmuxSession::new(&session_name);

		if !session.exists()? {
			return Err(K8sError::PodNotFound {
				name: name.to_string(),
			});
		}

		let pty_process = PtyProcess::spawn_tmux_attach(&session_name)?;

		Ok(AttachedProcess {
			stdin: Box::pin(pty_process.writer),
			stdout: Box::pin(pty_process.reader),
		})
	}

	async fn validate_token(
		&self,
		_token: &str,
		audiences: &[&str],
	) -> Result<TokenReviewResult, K8sError> {
		Ok(TokenReviewResult::authenticated(
			"local-dev-user".to_string(),
			vec!["system:authenticated".to_string()],
			std::collections::HashMap::new(),
			audiences.iter().map(|s| s.to_string()).collect(),
		))
	}
}
