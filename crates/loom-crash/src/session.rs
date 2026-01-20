// Copyright (c) 2025 Geoffrey Huntley <ghuntley@ghuntley.com>. All rights reserved.
// SPDX-License-Identifier: Proprietary

//! Session tracking for release health metrics.
//!
//! Sessions track user engagement periods and enable release health metrics
//! like crash-free rate and adoption tracking.

use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

use crate::error::Result;

/// Configuration for session tracking.
#[derive(Debug, Clone)]
pub struct SessionConfig {
	/// Whether session tracking is enabled.
	pub enabled: bool,
	/// Sample rate for sessions (0.0-1.0).
	/// Crashed sessions are always stored regardless of this rate.
	pub sample_rate: f64,
	/// Distinct ID for identifying the user/device.
	pub distinct_id: String,
}

impl Default for SessionConfig {
	fn default() -> Self {
		Self {
			enabled: true,
			sample_rate: 1.0,
			distinct_id: Uuid::now_v7().to_string(),
		}
	}
}

/// Request to start a session.
#[derive(Debug, Serialize)]
struct SessionStartRequest {
	project_id: String,
	distinct_id: String,
	platform: String,
	environment: String,
	#[serde(skip_serializing_if = "Option::is_none")]
	release: Option<String>,
	sample_rate: f64,
}

/// Response from session start.
#[derive(Debug, Deserialize)]
struct SessionStartResponse {
	session_id: String,
	sampled: bool,
}

/// Request to end a session.
#[derive(Debug, Serialize)]
struct SessionEndRequest {
	project_id: String,
	session_id: String,
	status: String,
	error_count: u32,
	crash_count: u32,
	duration_ms: u64,
}

/// Response from session end.
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct SessionEndResponse {
	success: bool,
}

/// Session status for reporting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionStatus {
	/// Session ended normally.
	Exited,
	/// Session had at least one unhandled error.
	Crashed,
	/// Session had handled errors but completed normally.
	Errored,
}

impl SessionStatus {
	fn as_str(&self) -> &'static str {
		match self {
			SessionStatus::Exited => "exited",
			SessionStatus::Crashed => "crashed",
			SessionStatus::Errored => "errored",
		}
	}
}

/// Inner state for session tracker.
#[allow(dead_code)]
struct SessionTrackerInner {
	session_id: String,
	project_id: String,
	started_at: DateTime<Utc>,
	error_count: AtomicU32,
	crash_count: AtomicU32,
	sample_rate: f64,
	sampled: bool,
	ended: AtomicBool,
	base_url: String,
	auth_token: String,
	environment: String,
	release: Option<String>,
	http_client: Client,
}

/// Tracks a single user engagement session.
///
/// Sessions are automatically started when the crash client is initialized
/// (if session tracking is enabled) and ended when the client is shut down.
pub struct SessionTracker {
	inner: Arc<RwLock<Option<SessionTrackerInner>>>,
	config: SessionConfig,
}

impl SessionTracker {
	/// Creates a new session tracker with the given configuration.
	pub(crate) fn new(config: SessionConfig) -> Self {
		Self {
			inner: Arc::new(RwLock::new(None)),
			config,
		}
	}

	/// Starts a new session.
	///
	/// This is called automatically when the crash client is built.
	pub(crate) async fn start(
		&self,
		project_id: &str,
		base_url: &str,
		auth_token: &str,
		environment: &str,
		release: Option<&str>,
		http_client: &Client,
	) -> Result<()> {
		if !self.config.enabled {
			debug!("Session tracking disabled");
			return Ok(());
		}

		let session_id = Uuid::now_v7().to_string();
		let started_at = Utc::now();

		// Deterministic sampling based on session ID hash
		let sampled = {
			use std::hash::{Hash, Hasher};
			let mut hasher = std::collections::hash_map::DefaultHasher::new();
			session_id.hash(&mut hasher);
			let hash = hasher.finish();
			(hash % 10000) < ((self.config.sample_rate * 10000.0) as u64)
		};

		// Send start request if sampled
		if sampled {
			let url = format!("{}/api/sessions/start", base_url);
			let request = SessionStartRequest {
				project_id: project_id.to_string(),
				distinct_id: self.config.distinct_id.clone(),
				platform: "rust".to_string(),
				environment: environment.to_string(),
				release: release.map(|s| s.to_string()),
				sample_rate: self.config.sample_rate,
			};

			match http_client
				.post(&url)
				.header("Authorization", format!("Bearer {}", auth_token))
				.json(&request)
				.timeout(Duration::from_secs(10))
				.send()
				.await
			{
				Ok(response) => {
					if response.status().is_success() {
						let body: SessionStartResponse = response.json().await?;
						info!(
							session_id = %body.session_id,
							sampled = body.sampled,
							"Session started"
						);
					} else {
						let status = response.status().as_u16();
						let message = response.text().await.unwrap_or_default();
						warn!(status, message = %message, "Failed to start session (server error)");
					}
				}
				Err(e) => {
					warn!(error = %e, "Failed to start session (request error)");
				}
			}
		} else {
			debug!(session_id = %session_id, "Session not sampled, skipping start request");
		}

		// Store session state
		let inner = SessionTrackerInner {
			session_id: session_id.clone(),
			project_id: project_id.to_string(),
			started_at,
			error_count: AtomicU32::new(0),
			crash_count: AtomicU32::new(0),
			sample_rate: self.config.sample_rate,
			sampled,
			ended: AtomicBool::new(false),
			base_url: base_url.to_string(),
			auth_token: auth_token.to_string(),
			environment: environment.to_string(),
			release: release.map(|s| s.to_string()),
			http_client: http_client.clone(),
		};

		*self.inner.write().await = Some(inner);

		Ok(())
	}

	/// Records a handled error (increments error_count).
	pub(crate) async fn record_error(&self) {
		if let Some(inner) = self.inner.read().await.as_ref() {
			inner.error_count.fetch_add(1, Ordering::SeqCst);
		}
	}

	/// Records an unhandled error/crash (increments crash_count).
	#[allow(dead_code)]
	pub(crate) async fn record_crash(&self) {
		if let Some(inner) = self.inner.read().await.as_ref() {
			inner.crash_count.fetch_add(1, Ordering::SeqCst);
		}
	}

	/// Records an unhandled error/crash synchronously (for panic hooks).
	pub(crate) fn record_crash_sync(&self) {
		// Use try_read to avoid blocking in panic context
		if let Ok(guard) = self.inner.try_read() {
			if let Some(inner) = guard.as_ref() {
				inner.crash_count.fetch_add(1, Ordering::SeqCst);
			}
		}
	}

	/// Ends the session.
	///
	/// This is called automatically when the crash client is shut down.
	/// Crashed sessions are always sent regardless of sampling.
	pub(crate) async fn end(&self) -> Result<()> {
		let inner_guard = self.inner.read().await;
		let Some(inner) = inner_guard.as_ref() else {
			return Ok(());
		};

		// Prevent double-ending
		if inner.ended.swap(true, Ordering::SeqCst) {
			return Ok(());
		}

		let error_count = inner.error_count.load(Ordering::SeqCst);
		let crash_count = inner.crash_count.load(Ordering::SeqCst);

		// Determine status
		let status = if crash_count > 0 {
			SessionStatus::Crashed
		} else if error_count > 0 {
			SessionStatus::Errored
		} else {
			SessionStatus::Exited
		};

		// Always send crashed sessions, even if not sampled
		if !inner.sampled && status != SessionStatus::Crashed {
			debug!(
				session_id = %inner.session_id,
				status = %status.as_str(),
				"Session not sampled and not crashed, skipping end request"
			);
			return Ok(());
		}

		let ended_at = Utc::now();
		let duration_ms = (ended_at - inner.started_at).num_milliseconds() as u64;

		let url = format!("{}/api/sessions/end", inner.base_url);
		let request = SessionEndRequest {
			project_id: inner.project_id.clone(),
			session_id: inner.session_id.clone(),
			status: status.as_str().to_string(),
			error_count,
			crash_count,
			duration_ms,
		};

		match inner
			.http_client
			.post(&url)
			.header("Authorization", format!("Bearer {}", inner.auth_token))
			.json(&request)
			.timeout(Duration::from_secs(10))
			.send()
			.await
		{
			Ok(response) => {
				if response.status().is_success() {
					info!(
						session_id = %inner.session_id,
						status = %status.as_str(),
						error_count,
						crash_count,
						duration_ms,
						"Session ended"
					);
				} else {
					let status_code = response.status().as_u16();
					let message = response.text().await.unwrap_or_default();
					error!(status = status_code, message = %message, "Failed to end session (server error)");
				}
			}
			Err(e) => {
				error!(error = %e, "Failed to end session (request error)");
			}
		}

		Ok(())
	}

	/// Gets the current session ID, if a session is active.
	pub fn session_id(&self) -> Option<String> {
		// Use try_read to avoid async
		self.inner
			.try_read()
			.ok()
			.and_then(|guard| guard.as_ref().map(|inner| inner.session_id.clone()))
	}

	/// Returns whether session tracking is enabled.
	pub fn is_enabled(&self) -> bool {
		self.config.enabled
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_session_config_default() {
		let config = SessionConfig::default();
		assert!(config.enabled);
		assert!((config.sample_rate - 1.0).abs() < f64::EPSILON);
		assert!(!config.distinct_id.is_empty());
	}

	#[test]
	fn test_session_status_as_str() {
		assert_eq!(SessionStatus::Exited.as_str(), "exited");
		assert_eq!(SessionStatus::Crashed.as_str(), "crashed");
		assert_eq!(SessionStatus::Errored.as_str(), "errored");
	}

	#[tokio::test]
	async fn test_session_tracker_disabled() {
		let config = SessionConfig {
			enabled: false,
			..Default::default()
		};
		let tracker = SessionTracker::new(config);

		assert!(!tracker.is_enabled());
		assert!(tracker.session_id().is_none());
	}

	#[tokio::test]
	async fn test_session_tracker_new() {
		let config = SessionConfig::default();
		let tracker = SessionTracker::new(config);

		assert!(tracker.is_enabled());
		// Session not started yet
		assert!(tracker.session_id().is_none());
	}
}
