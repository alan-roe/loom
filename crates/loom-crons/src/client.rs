// Copyright (c) 2025 Geoffrey Huntley <ghuntley@ghuntley.com>. All rights reserved.
// SPDX-License-Identifier: Proprietary

//! Crons SDK client for check-in based monitoring.

use std::future::Future;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use chrono::Utc;
use loom_common_http::RetryConfig;
use loom_crons_core::{CheckInId, CheckInStatus};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use tracing::{debug, error, info};

use crate::error::{CronsSdkError, Result};

/// SDK version for identification.
const SDK_VERSION: &str = env!("CARGO_PKG_VERSION");
/// SDK name for identification.
const SDK_NAME: &str = "loom-crons-rust";

/// Configuration for the crons client.
#[derive(Debug, Clone)]
pub struct ClientConfig {
	/// Timeout for HTTP requests.
	pub request_timeout: Duration,
	/// Retry configuration for HTTP requests.
	pub retry_config: RetryConfig,
}

impl Default for ClientConfig {
	fn default() -> Self {
		Self {
			request_timeout: Duration::from_secs(30),
			retry_config: RetryConfig::default(),
		}
	}
}

/// Builder for constructing a CronsClient.
pub struct CronsClientBuilder {
	auth_token: Option<String>,
	base_url: Option<String>,
	org_id: Option<String>,
	environment: Option<String>,
	release: Option<String>,
	config: ClientConfig,
	#[cfg(feature = "crash")]
	crash_client: Option<loom_crash::CrashClient>,
}

impl CronsClientBuilder {
	/// Creates a new builder with default settings.
	pub fn new() -> Self {
		Self {
			auth_token: None,
			base_url: None,
			org_id: None,
			environment: None,
			release: None,
			config: ClientConfig::default(),
			#[cfg(feature = "crash")]
			crash_client: None,
		}
	}

	/// Sets the authentication token (user bearer token).
	///
	/// This should be obtained from `loom login` command.
	pub fn auth_token(mut self, token: impl Into<String>) -> Self {
		self.auth_token = Some(token.into());
		self
	}

	/// Sets the base URL for the Loom server.
	///
	/// Example: `https://loom.ghuntley.com`
	pub fn base_url(mut self, url: impl Into<String>) -> Self {
		self.base_url = Some(url.into());
		self
	}

	/// Sets the organization ID for all check-ins.
	pub fn org_id(mut self, id: impl Into<String>) -> Self {
		self.org_id = Some(id.into());
		self
	}

	/// Sets the environment name for check-ins.
	///
	/// Example: `production`, `staging`, `development`
	pub fn environment(mut self, env: impl Into<String>) -> Self {
		self.environment = Some(env.into());
		self
	}

	/// Sets the release version for check-ins.
	///
	/// Example: `1.2.3` or `git commit SHA`
	pub fn release(mut self, release: impl Into<String>) -> Self {
		self.release = Some(release.into());
		self
	}

	/// Sets the HTTP request timeout.
	pub fn request_timeout(mut self, timeout: Duration) -> Self {
		self.config.request_timeout = timeout;
		self
	}

	/// Sets the retry configuration.
	pub fn retry_config(mut self, config: RetryConfig) -> Self {
		self.config.retry_config = config;
		self
	}

	/// Sets the crash client for linking failed check-ins to crash events.
	#[cfg(feature = "crash")]
	pub fn crash_client(mut self, client: loom_crash::CrashClient) -> Self {
		self.crash_client = Some(client);
		self
	}

	/// Builds the CronsClient.
	pub fn build(self) -> Result<CronsClient> {
		let auth_token = self.auth_token.ok_or(CronsSdkError::InvalidAuthToken)?;
		let base_url = self.base_url.ok_or(CronsSdkError::InvalidBaseUrl)?;
		let org_id = self.org_id.ok_or(CronsSdkError::MissingOrgId)?;

		// Normalize base URL
		let base_url = base_url.trim_end_matches('/').to_string();

		let http_client = loom_common_http::builder()
			.timeout(self.config.request_timeout)
			.build()
			.map_err(CronsSdkError::RequestFailed)?;

		let inner = Arc::new(CronsClientInner {
			auth_token,
			base_url: base_url.clone(),
			org_id,
			environment: self.environment,
			release: self.release,
			http_client,
			config: self.config,
			closed: AtomicBool::new(false),
			#[cfg(feature = "crash")]
			crash_client: self.crash_client,
		});

		info!(base_url = %base_url, sdk_name = SDK_NAME, sdk_version = SDK_VERSION, "Crons client initialized");

		Ok(CronsClient { inner })
	}
}

impl Default for CronsClientBuilder {
	fn default() -> Self {
		Self::new()
	}
}

/// Internal client state.
struct CronsClientInner {
	auth_token: String,
	base_url: String,
	org_id: String,
	environment: Option<String>,
	release: Option<String>,
	http_client: Client,
	config: ClientConfig,
	closed: AtomicBool,
	#[cfg(feature = "crash")]
	crash_client: Option<loom_crash::CrashClient>,
}

/// Client for cron monitoring via check-ins.
///
/// # Example
///
/// ```ignore
/// use loom_crons::{CronsClient, CheckInOk};
///
/// let client = CronsClient::builder()
///     .auth_token("your_auth_token")
///     .base_url("https://loom.ghuntley.com")
///     .org_id("org_xxx")
///     .build()?;
///
/// // Start a check-in
/// let checkin_id = client.checkin_start("daily-cleanup").await?;
///
/// // Do work...
///
/// // Complete the check-in
/// client.checkin_ok(checkin_id, CheckInOk {
///     duration_ms: Some(1234),
///     output: Some("Processed 1000 records".to_string()),
/// }).await?;
/// ```
#[derive(Clone)]
pub struct CronsClient {
	inner: Arc<CronsClientInner>,
}

impl CronsClient {
	/// Creates a new builder for constructing a CronsClient.
	pub fn builder() -> CronsClientBuilder {
		CronsClientBuilder::new()
	}

	/// Starts a check-in for the specified monitor (job starting).
	///
	/// Returns the check-in ID which should be used to complete the check-in
	/// with either `checkin_ok` or `checkin_error`.
	pub async fn checkin_start(&self, monitor_slug: &str) -> Result<CheckInId> {
		self.check_closed()?;

		let request = CreateCheckInRequest {
			org_id: self.inner.org_id.clone(),
			status: CheckInStatus::InProgress,
			started_at: Some(Utc::now().to_rfc3339()),
			finished_at: None,
			duration_ms: None,
			environment: self.inner.environment.clone(),
			release: self.inner.release.clone(),
			exit_code: None,
			output: None,
			crash_event_id: None,
		};

		let response = self.create_checkin(monitor_slug, &request).await?;

		info!(
			monitor_slug = %monitor_slug,
			checkin_id = %response.id,
			"Check-in started"
		);

		Ok(response.id)
	}

	/// Completes a check-in successfully.
	pub async fn checkin_ok(&self, checkin_id: CheckInId, details: CheckInOk) -> Result<()> {
		self.check_closed()?;

		let request = UpdateCheckInRequest {
			status: CheckInStatus::Ok,
			finished_at: Some(Utc::now().to_rfc3339()),
			duration_ms: details.duration_ms,
			exit_code: None,
			output: details.output,
			crash_event_id: None,
		};

		self.update_checkin(checkin_id, &request).await?;

		info!(
			checkin_id = %checkin_id,
			duration_ms = ?details.duration_ms,
			"Check-in completed successfully"
		);

		Ok(())
	}

	/// Completes a check-in with an error.
	pub async fn checkin_error(&self, checkin_id: CheckInId, details: CheckInError) -> Result<()> {
		self.check_closed()?;

		let request = UpdateCheckInRequest {
			status: CheckInStatus::Error,
			finished_at: Some(Utc::now().to_rfc3339()),
			duration_ms: details.duration_ms,
			exit_code: details.exit_code,
			output: details.output,
			crash_event_id: details.crash_event_id,
		};

		self.update_checkin(checkin_id, &request).await?;

		info!(
			checkin_id = %checkin_id,
			duration_ms = ?details.duration_ms,
			exit_code = ?details.exit_code,
			"Check-in completed with error"
		);

		Ok(())
	}

	/// Convenience wrapper that handles the full check-in lifecycle.
	///
	/// Starts a check-in, runs the provided async function, and completes
	/// the check-in based on the result.
	///
	/// # Example
	///
	/// ```ignore
	/// crons.with_monitor("daily-cleanup", || async {
	///     run_daily_cleanup().await
	/// }).await?;
	/// ```
	pub async fn with_monitor<F, Fut, T, E>(&self, slug: &str, f: F) -> Result<T>
	where
		F: FnOnce() -> Fut,
		Fut: Future<Output = std::result::Result<T, E>>,
		E: std::error::Error + 'static,
	{
		let start = Instant::now();
		let checkin_id = self.checkin_start(slug).await?;

		match f().await {
			Ok(result) => {
				self.checkin_ok(
					checkin_id,
					CheckInOk {
						duration_ms: Some(start.elapsed().as_millis() as u64),
						output: None,
					},
				)
				.await?;
				Ok(result)
			}
			Err(e) => {
				// Optionally capture in crash system
				#[cfg(feature = "crash")]
				let crash_event_id = if let Some(crash) = &self.inner.crash_client {
					crash.capture_error(&e).await.ok().map(|r| r.event_id)
				} else {
					None
				};

				#[cfg(not(feature = "crash"))]
				let crash_event_id: Option<String> = None;

				self.checkin_error(
					checkin_id,
					CheckInError {
						duration_ms: Some(start.elapsed().as_millis() as u64),
						exit_code: Some(1),
						output: Some(e.to_string()),
						crash_event_id,
					},
				)
				.await?;

				Err(CronsSdkError::JobFailed(e.to_string()))
			}
		}
	}

	/// Shuts down the client.
	pub async fn shutdown(&self) -> Result<()> {
		if self.inner.closed.swap(true, Ordering::SeqCst) {
			return Ok(());
		}

		info!("Crons client shutdown");
		Ok(())
	}

	/// Returns true if the client has been shut down.
	pub fn is_closed(&self) -> bool {
		self.inner.closed.load(Ordering::SeqCst)
	}

	fn check_closed(&self) -> Result<()> {
		if self.inner.closed.load(Ordering::SeqCst) {
			return Err(CronsSdkError::ClientShutdown);
		}
		Ok(())
	}

	async fn create_checkin(
		&self,
		monitor_slug: &str,
		request: &CreateCheckInRequest,
	) -> Result<CreateCheckInResponse> {
		let url = format!(
			"{}/api/crons/monitors/{}/checkins",
			self.inner.base_url, monitor_slug
		);

		debug!(url = %url, monitor_slug = %monitor_slug, "Creating check-in");

		let response = loom_common_http::retry(&self.inner.config.retry_config, || async {
			self.inner
				.http_client
				.post(&url)
				.header("Authorization", format!("Bearer {}", self.inner.auth_token))
				.json(&request)
				.send()
				.await
		})
		.await
		.map_err(CronsSdkError::RequestFailed)?;

		if response.status() == reqwest::StatusCode::NOT_FOUND {
			return Err(CronsSdkError::MonitorNotFound {
				slug: monitor_slug.to_string(),
			});
		}

		if response.status() == reqwest::StatusCode::TOO_MANY_REQUESTS {
			let retry_after = response
				.headers()
				.get("Retry-After")
				.and_then(|v| v.to_str().ok())
				.and_then(|s| s.parse().ok());
			return Err(CronsSdkError::RateLimited {
				retry_after_secs: retry_after,
			});
		}

		if !response.status().is_success() {
			let status = response.status().as_u16();
			let message = response.text().await.unwrap_or_default();
			error!(status, message = %message, "Failed to create check-in");
			return Err(CronsSdkError::ServerError { status, message });
		}

		let body: CreateCheckInResponse = response.json().await?;
		Ok(body)
	}

	async fn update_checkin(
		&self,
		checkin_id: CheckInId,
		request: &UpdateCheckInRequest,
	) -> Result<()> {
		let url = format!("{}/api/crons/checkins/{}", self.inner.base_url, checkin_id);

		debug!(url = %url, checkin_id = %checkin_id, status = %request.status, "Updating check-in");

		let response = loom_common_http::retry(&self.inner.config.retry_config, || async {
			self.inner
				.http_client
				.patch(&url)
				.header("Authorization", format!("Bearer {}", self.inner.auth_token))
				.json(&request)
				.send()
				.await
		})
		.await
		.map_err(CronsSdkError::RequestFailed)?;

		if response.status() == reqwest::StatusCode::NOT_FOUND {
			return Err(CronsSdkError::CheckInNotFound {
				id: checkin_id.to_string(),
			});
		}

		if response.status() == reqwest::StatusCode::TOO_MANY_REQUESTS {
			let retry_after = response
				.headers()
				.get("Retry-After")
				.and_then(|v| v.to_str().ok())
				.and_then(|s| s.parse().ok());
			return Err(CronsSdkError::RateLimited {
				retry_after_secs: retry_after,
			});
		}

		if !response.status().is_success() {
			let status = response.status().as_u16();
			let message = response.text().await.unwrap_or_default();
			error!(status, message = %message, "Failed to update check-in");
			return Err(CronsSdkError::ServerError { status, message });
		}

		Ok(())
	}
}

/// Details for a successful check-in completion.
#[derive(Debug, Clone, Default)]
pub struct CheckInOk {
	/// Duration of the job in milliseconds.
	pub duration_ms: Option<u64>,
	/// Optional output from the job.
	pub output: Option<String>,
}

/// Details for a failed check-in completion.
#[derive(Debug, Clone, Default)]
pub struct CheckInError {
	/// Duration of the job in milliseconds.
	pub duration_ms: Option<u64>,
	/// Exit code (non-zero indicates failure).
	pub exit_code: Option<i32>,
	/// Optional output/error message from the job.
	pub output: Option<String>,
	/// Optional crash event ID for linking to crash analytics.
	pub crash_event_id: Option<String>,
}

/// Request payload for creating a check-in.
#[derive(Debug, Serialize)]
struct CreateCheckInRequest {
	org_id: String,
	status: CheckInStatus,
	#[serde(skip_serializing_if = "Option::is_none")]
	started_at: Option<String>,
	#[serde(skip_serializing_if = "Option::is_none")]
	finished_at: Option<String>,
	#[serde(skip_serializing_if = "Option::is_none")]
	duration_ms: Option<u64>,
	#[serde(skip_serializing_if = "Option::is_none")]
	environment: Option<String>,
	#[serde(skip_serializing_if = "Option::is_none")]
	release: Option<String>,
	#[serde(skip_serializing_if = "Option::is_none")]
	exit_code: Option<i32>,
	#[serde(skip_serializing_if = "Option::is_none")]
	output: Option<String>,
	#[serde(skip_serializing_if = "Option::is_none")]
	crash_event_id: Option<String>,
}

/// Response from creating a check-in.
#[derive(Debug, Deserialize)]
struct CreateCheckInResponse {
	id: CheckInId,
	#[allow(dead_code)]
	status: CheckInStatus,
}

/// Request payload for updating a check-in.
#[derive(Debug, Serialize)]
struct UpdateCheckInRequest {
	status: CheckInStatus,
	#[serde(skip_serializing_if = "Option::is_none")]
	finished_at: Option<String>,
	#[serde(skip_serializing_if = "Option::is_none")]
	duration_ms: Option<u64>,
	#[serde(skip_serializing_if = "Option::is_none")]
	exit_code: Option<i32>,
	#[serde(skip_serializing_if = "Option::is_none")]
	output: Option<String>,
	#[serde(skip_serializing_if = "Option::is_none")]
	crash_event_id: Option<String>,
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_builder_requires_auth_token() {
		let result = CronsClientBuilder::new()
			.base_url("https://example.com")
			.org_id("org_123")
			.build();

		assert!(matches!(result, Err(CronsSdkError::InvalidAuthToken)));
	}

	#[test]
	fn test_builder_requires_base_url() {
		let result = CronsClientBuilder::new()
			.auth_token("token_123")
			.org_id("org_123")
			.build();

		assert!(matches!(result, Err(CronsSdkError::InvalidBaseUrl)));
	}

	#[test]
	fn test_builder_requires_org_id() {
		let result = CronsClientBuilder::new()
			.auth_token("token_123")
			.base_url("https://example.com")
			.build();

		assert!(matches!(result, Err(CronsSdkError::MissingOrgId)));
	}

	#[test]
	fn test_builder_success() {
		let result = CronsClientBuilder::new()
			.auth_token("token_123")
			.base_url("https://example.com")
			.org_id("org_123")
			.build();

		assert!(result.is_ok());
	}

	#[test]
	fn test_builder_normalizes_base_url() {
		let client = CronsClientBuilder::new()
			.auth_token("token_123")
			.base_url("https://example.com/")
			.org_id("org_123")
			.build()
			.unwrap();

		assert!(!client.inner.base_url.ends_with('/'));
	}

	#[test]
	fn test_client_config_defaults() {
		let config = ClientConfig::default();
		assert_eq!(config.request_timeout, Duration::from_secs(30));
	}

	#[tokio::test]
	async fn test_shutdown_prevents_operations() {
		let client = CronsClientBuilder::new()
			.auth_token("token_123")
			.base_url("https://example.com")
			.org_id("org_123")
			.build()
			.unwrap();

		client.shutdown().await.unwrap();

		let result = client.checkin_start("test-monitor").await;
		assert!(matches!(result, Err(CronsSdkError::ClientShutdown)));
	}

	#[tokio::test]
	async fn test_double_shutdown_is_ok() {
		let client = CronsClientBuilder::new()
			.auth_token("token_123")
			.base_url("https://example.com")
			.org_id("org_123")
			.build()
			.unwrap();

		client.shutdown().await.unwrap();
		client.shutdown().await.unwrap();
	}

	#[test]
	fn test_checkin_ok_defaults() {
		let details = CheckInOk::default();
		assert!(details.duration_ms.is_none());
		assert!(details.output.is_none());
	}

	#[test]
	fn test_checkin_error_defaults() {
		let details = CheckInError::default();
		assert!(details.duration_ms.is_none());
		assert!(details.exit_code.is_none());
		assert!(details.output.is_none());
		assert!(details.crash_event_id.is_none());
	}
}
