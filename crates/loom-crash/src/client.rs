// Copyright (c) 2025 Geoffrey Huntley <ghuntley@ghuntley.com>. All rights reserved.
// SPDX-License-Identifier: Proprietary

//! Crash analytics client for capturing and reporting errors.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use loom_common_http::RetryConfig;
use loom_crash_core::{Breadcrumb, BreadcrumbLevel, Frame, Stacktrace, UserContext};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tracing::{debug, error, info};

use crate::backtrace::capture_backtrace;
use crate::error::{CrashSdkError, Result};
use crate::panic_hook::install_panic_hook;
use crate::session::{SessionConfig, SessionTracker};

/// SDK version for identification.
const SDK_VERSION: &str = env!("CARGO_PKG_VERSION");
/// SDK name for identification.
const SDK_NAME: &str = "loom-crash-rust";

/// Maximum number of breadcrumbs to keep.
const MAX_BREADCRUMBS: usize = 100;

/// Configuration for the crash client.
#[derive(Debug, Clone)]
pub struct ClientConfig {
	/// Timeout for HTTP requests.
	pub request_timeout: Duration,
	/// Retry configuration for HTTP requests.
	pub retry_config: RetryConfig,
	/// Maximum breadcrumbs to keep.
	pub max_breadcrumbs: usize,
}

impl Default for ClientConfig {
	fn default() -> Self {
		Self {
			request_timeout: Duration::from_secs(30),
			retry_config: RetryConfig::default(),
			max_breadcrumbs: MAX_BREADCRUMBS,
		}
	}
}

/// Builder for constructing a CrashClient.
pub struct CrashClientBuilder {
	auth_token: Option<String>,
	base_url: Option<String>,
	project_id: Option<String>,
	release: Option<String>,
	environment: Option<String>,
	server_name: Option<String>,
	config: ClientConfig,
	session_config: SessionConfig,
}

impl CrashClientBuilder {
	/// Creates a new builder with default settings.
	pub fn new() -> Self {
		Self {
			auth_token: None,
			base_url: None,
			project_id: None,
			release: None,
			environment: None,
			server_name: None,
			config: ClientConfig::default(),
			session_config: SessionConfig::default(),
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

	/// Sets the project ID for crash events.
	pub fn project_id(mut self, id: impl Into<String>) -> Self {
		self.project_id = Some(id.into());
		self
	}

	/// Sets the release version.
	///
	/// Example: `1.2.3` or `git commit SHA`
	pub fn release(mut self, release: impl Into<String>) -> Self {
		self.release = Some(release.into());
		self
	}

	/// Sets the environment name.
	///
	/// Example: `production`, `staging`, `development`
	pub fn environment(mut self, env: impl Into<String>) -> Self {
		self.environment = Some(env.into());
		self
	}

	/// Sets the server name for identification.
	pub fn server_name(mut self, name: impl Into<String>) -> Self {
		self.server_name = Some(name.into());
		self
	}

	/// Sets the HTTP request timeout.
	pub fn request_timeout(mut self, timeout: Duration) -> Self {
		self.config.request_timeout = timeout;
		self
	}

	/// Sets the maximum number of breadcrumbs to keep.
	pub fn max_breadcrumbs(mut self, max: usize) -> Self {
		self.config.max_breadcrumbs = max;
		self
	}

	/// Sets the retry configuration.
	pub fn retry_config(mut self, config: RetryConfig) -> Self {
		self.config.retry_config = config;
		self
	}

	/// Enables or disables automatic session tracking.
	///
	/// When enabled (default), the SDK will automatically track user engagement
	/// sessions for release health metrics. Sessions are started when the client
	/// is built and ended when the client is shut down.
	///
	/// # Example
	///
	/// ```ignore
	/// let client = CrashClient::builder()
	///     .auth_token("token")
	///     .base_url("https://loom.example.com")
	///     .project_id("proj_xxx")
	///     .with_session_tracking(true)  // Default: true
	///     .build()?;
	/// ```
	pub fn with_session_tracking(mut self, enabled: bool) -> Self {
		self.session_config.enabled = enabled;
		self
	}

	/// Sets the session sample rate (0.0-1.0).
	///
	/// This controls what percentage of sessions are stored. Crashed sessions
	/// are always stored regardless of this setting.
	///
	/// # Example
	///
	/// ```ignore
	/// let client = CrashClient::builder()
	///     .auth_token("token")
	///     .base_url("https://loom.example.com")
	///     .project_id("proj_xxx")
	///     .session_sample_rate(0.5)  // Store 50% of sessions
	///     .build()?;
	/// ```
	pub fn session_sample_rate(mut self, rate: f64) -> Self {
		self.session_config.sample_rate = rate.clamp(0.0, 1.0);
		self
	}

	/// Sets the distinct ID for session tracking.
	///
	/// This is used to identify the user/device across sessions. If not set,
	/// a random UUID will be generated.
	pub fn session_distinct_id(mut self, distinct_id: impl Into<String>) -> Self {
		self.session_config.distinct_id = distinct_id.into();
		self
	}

	/// Builds the CrashClient.
	///
	/// Note: To start automatic session tracking, call `start_session()` after building,
	/// or use `build_async()` which does both.
	pub fn build(self) -> Result<CrashClient> {
		let auth_token = self.auth_token.ok_or(CrashSdkError::InvalidApiKey)?;
		let base_url = self.base_url.ok_or(CrashSdkError::InvalidBaseUrl)?;
		let project_id = self.project_id.ok_or(CrashSdkError::MissingProjectId)?;

		// Normalize base URL
		let base_url = base_url.trim_end_matches('/').to_string();

		let http_client = loom_common_http::builder()
			.timeout(self.config.request_timeout)
			.build()
			.map_err(CrashSdkError::RequestFailed)?;

		// Create session tracker
		let session_tracker = SessionTracker::new(self.session_config);

		let environment = self.environment.unwrap_or_else(|| "production".to_string());

		let inner = Arc::new(CrashClientInner {
			auth_token,
			base_url: base_url.clone(),
			project_id,
			release: self.release,
			environment,
			server_name: self.server_name,
			http_client,
			config: self.config,
			tags: RwLock::new(HashMap::new()),
			extra: RwLock::new(serde_json::Value::Object(serde_json::Map::new())),
			user_context: RwLock::new(None),
			breadcrumbs: RwLock::new(Vec::new()),
			closed: AtomicBool::new(false),
			session_tracker,
		});

		info!(base_url = %base_url, "Crash client initialized");

		Ok(CrashClient { inner })
	}

	/// Builds the CrashClient and starts session tracking.
	///
	/// This is the recommended way to create a crash client when you want
	/// automatic session tracking for release health metrics.
	///
	/// # Example
	///
	/// ```ignore
	/// let client = CrashClient::builder()
	///     .auth_token("token")
	///     .base_url("https://loom.example.com")
	///     .project_id("proj_xxx")
	///     .release(env!("CARGO_PKG_VERSION"))
	///     .build_async()
	///     .await?;
	/// ```
	pub async fn build_async(self) -> Result<CrashClient> {
		let client = self.build()?;
		client.start_session().await?;
		Ok(client)
	}
}

impl Default for CrashClientBuilder {
	fn default() -> Self {
		Self::new()
	}
}

/// Internal client state.
pub struct CrashClientInner {
	auth_token: String,
	base_url: String,
	project_id: String,
	release: Option<String>,
	environment: String,
	server_name: Option<String>,
	http_client: Client,
	config: ClientConfig,
	tags: RwLock<HashMap<String, String>>,
	extra: RwLock<serde_json::Value>,
	user_context: RwLock<Option<UserContext>>,
	breadcrumbs: RwLock<Vec<Breadcrumb>>,
	closed: AtomicBool,
	session_tracker: SessionTracker,
}

impl CrashClientInner {
	/// Send a panic event synchronously (for use in panic hooks).
	pub fn send_panic_sync(
		&self,
		message: &str,
		_location: Option<&str>,
		stacktrace: Stacktrace,
	) -> Result<()> {
		if self.closed.load(Ordering::SeqCst) {
			return Err(CrashSdkError::ClientShutdown);
		}

		// Build tags with SDK info
		let mut tags = self.tags.blocking_read().clone();
		tags.insert("sdk.name".to_string(), SDK_NAME.to_string());
		tags.insert("sdk.version".to_string(), SDK_VERSION.to_string());

		// Build the capture request
		let request = CaptureRequest {
			project_id: self.project_id.clone(),
			exception_type: "panic".to_string(),
			exception_value: message.to_string(),
			stacktrace: CaptureStacktrace::from_stacktrace(&stacktrace),
			environment: Some(self.environment.clone()),
			platform: Some("rust".to_string()),
			release: self.release.clone(),
			dist: None,
			distinct_id: None,
			person_id: None,
			server_name: self.server_name.clone(),
			tags,
			extra: self.extra.blocking_read().clone(),
			active_flags: HashMap::new(),
			breadcrumbs: self
				.breadcrumbs
				.blocking_read()
				.iter()
				.map(CaptureBreadcrumb::from_breadcrumb)
				.collect(),
			timestamp: Some(Utc::now().to_rfc3339()),
		};

		// Send synchronously using blocking HTTP
		let url = format!("{}/api/crash/capture", self.base_url);

		// Use a simple blocking client for panic situations
		let client = reqwest::blocking::Client::builder()
			.timeout(Duration::from_secs(5))
			.build()
			.map_err(|e| CrashSdkError::RequestFailed(e.into()))?;

		let response = client
			.post(&url)
			.header("Authorization", format!("Bearer {}", self.auth_token))
			.json(&request)
			.send()
			.map_err(|e| CrashSdkError::RequestFailed(e.into()))?;

		if response.status().is_success() {
			debug!("Panic reported successfully");
			Ok(())
		} else {
			let status = response.status().as_u16();
			let message = response.text().unwrap_or_default();
			error!(status, message = %message, "Failed to report panic");
			Err(CrashSdkError::ServerError { status, message })
		}
	}

	/// Record a crash in the session tracker (for panic hooks).
	pub fn record_crash_sync(&self) {
		self.session_tracker.record_crash_sync();
	}
}

/// Client for capturing crash events and reporting them to Loom.
///
/// # Example
///
/// ```ignore
/// use loom_crash::CrashClient;
///
/// let client = CrashClient::builder()
///     .auth_token("your_auth_token")
///     .base_url("https://loom.ghuntley.com")
///     .project_id("proj_xxx")
///     .release(env!("CARGO_PKG_VERSION"))
///     .environment("production")
///     .build()?;
///
/// // Install panic hook for automatic crash reporting
/// client.install_panic_hook();
///
/// // Set user context
/// client.set_user(UserContext {
///     id: Some(user.id.to_string()),
///     email: Some(user.email.clone()),
///     ..Default::default()
/// }).await;
///
/// // Add breadcrumb
/// client.add_breadcrumb(Breadcrumb {
///     category: "http".into(),
///     message: Some("GET /api/users".into()),
///     level: BreadcrumbLevel::Info,
///     ..Default::default()
/// }).await;
///
/// // Manual capture
/// if let Err(e) = do_something() {
///     client.capture_error(&e).await?;
/// }
///
/// // Shutdown
/// client.shutdown().await?;
/// ```
#[derive(Clone)]
pub struct CrashClient {
	inner: Arc<CrashClientInner>,
}

impl CrashClient {
	/// Creates a new builder for constructing a CrashClient.
	pub fn builder() -> CrashClientBuilder {
		CrashClientBuilder::new()
	}

	/// Installs a panic hook for automatic crash reporting.
	///
	/// This should be called early in your application's startup.
	/// The hook will capture panic information and send it to the server
	/// before the default panic hook runs.
	pub fn install_panic_hook(&self) {
		install_panic_hook(Arc::clone(&self.inner));
		info!("Panic hook installed");
	}

	/// Starts session tracking for release health metrics.
	///
	/// This should be called after building the client if you want automatic
	/// session tracking. Sessions are automatically ended when `shutdown()` is called.
	///
	/// # Example
	///
	/// ```ignore
	/// let client = CrashClient::builder()
	///     .auth_token("token")
	///     .base_url("https://loom.example.com")
	///     .project_id("proj_xxx")
	///     .build()?;
	///
	/// // Start session tracking
	/// client.start_session().await?;
	///
	/// // ... application code ...
	///
	/// // Session automatically ends here
	/// client.shutdown().await?;
	/// ```
	pub async fn start_session(&self) -> Result<()> {
		self.inner
			.session_tracker
			.start(
				&self.inner.project_id,
				&self.inner.base_url,
				&self.inner.auth_token,
				&self.inner.environment,
				self.inner.release.as_deref(),
				&self.inner.http_client,
			)
			.await
	}

	/// Returns the current session ID, if session tracking is active.
	pub fn session_id(&self) -> Option<String> {
		self.inner.session_tracker.session_id()
	}

	/// Returns whether session tracking is enabled.
	pub fn is_session_tracking_enabled(&self) -> bool {
		self.inner.session_tracker.is_enabled()
	}

	/// Captures an error and sends it to the crash analytics server.
	pub async fn capture_error(&self, error: &dyn std::error::Error) -> Result<CaptureResponse> {
		self.capture_exception(
			std::any::type_name_of_val(error),
			&error.to_string(),
			capture_backtrace(),
		)
		.await
	}

	/// Captures an exception with custom type and message.
	///
	/// This method also increments the session error count for release health tracking.
	pub async fn capture_exception(
		&self,
		exception_type: &str,
		exception_value: &str,
		stacktrace: Stacktrace,
	) -> Result<CaptureResponse> {
		self.check_closed()?;

		// Record error in session tracker
		self.inner.session_tracker.record_error().await;

		// Build tags with SDK info
		let mut tags = self.inner.tags.read().await.clone();
		tags.insert("sdk.name".to_string(), SDK_NAME.to_string());
		tags.insert("sdk.version".to_string(), SDK_VERSION.to_string());

		let request = CaptureRequest {
			project_id: self.inner.project_id.clone(),
			exception_type: exception_type.to_string(),
			exception_value: exception_value.to_string(),
			stacktrace: CaptureStacktrace::from_stacktrace(&stacktrace),
			environment: Some(self.inner.environment.clone()),
			platform: Some("rust".to_string()),
			release: self.inner.release.clone(),
			dist: None,
			distinct_id: None,
			person_id: None,
			server_name: self.inner.server_name.clone(),
			tags,
			extra: self.inner.extra.read().await.clone(),
			active_flags: HashMap::new(),
			breadcrumbs: self
				.inner
				.breadcrumbs
				.read()
				.await
				.iter()
				.map(CaptureBreadcrumb::from_breadcrumb)
				.collect(),
			timestamp: Some(Utc::now().to_rfc3339()),
		};

		self.send_capture(request).await
	}

	/// Captures a message (not an error) as a crash event.
	pub async fn capture_message(
		&self,
		message: &str,
		level: BreadcrumbLevel,
	) -> Result<CaptureResponse> {
		self.check_closed()?;

		let exception_type = match level {
			BreadcrumbLevel::Debug => "debug",
			BreadcrumbLevel::Info => "info",
			BreadcrumbLevel::Warning => "warning",
			BreadcrumbLevel::Error => "error",
		};

		// Build tags with SDK info
		let mut tags = self.inner.tags.read().await.clone();
		tags.insert("sdk.name".to_string(), SDK_NAME.to_string());
		tags.insert("sdk.version".to_string(), SDK_VERSION.to_string());

		let request = CaptureRequest {
			project_id: self.inner.project_id.clone(),
			exception_type: exception_type.to_string(),
			exception_value: message.to_string(),
			stacktrace: CaptureStacktrace::from_stacktrace(&capture_backtrace()),
			environment: Some(self.inner.environment.clone()),
			platform: Some("rust".to_string()),
			release: self.inner.release.clone(),
			dist: None,
			distinct_id: None,
			person_id: None,
			server_name: self.inner.server_name.clone(),
			tags,
			extra: self.inner.extra.read().await.clone(),
			active_flags: HashMap::new(),
			breadcrumbs: self
				.inner
				.breadcrumbs
				.read()
				.await
				.iter()
				.map(CaptureBreadcrumb::from_breadcrumb)
				.collect(),
			timestamp: Some(Utc::now().to_rfc3339()),
		};

		self.send_capture(request).await
	}

	/// Sets a global tag that will be attached to all crash events.
	pub async fn set_tag(&self, key: impl Into<String>, value: impl Into<String>) {
		self.inner.tags.write().await.insert(key.into(), value.into());
	}

	/// Removes a global tag.
	pub async fn remove_tag(&self, key: &str) {
		self.inner.tags.write().await.remove(key);
	}

	/// Sets global extra data that will be attached to all crash events.
	pub async fn set_extra(&self, key: impl Into<String>, value: serde_json::Value) {
		if let serde_json::Value::Object(ref mut map) = *self.inner.extra.write().await {
			map.insert(key.into(), value);
		}
	}

	/// Sets the user context.
	pub async fn set_user(&self, user: UserContext) {
		*self.inner.user_context.write().await = Some(user);
	}

	/// Clears the user context.
	pub async fn clear_user(&self) {
		*self.inner.user_context.write().await = None;
	}

	/// Adds a breadcrumb to the trail.
	pub async fn add_breadcrumb(&self, breadcrumb: Breadcrumb) {
		let mut breadcrumbs = self.inner.breadcrumbs.write().await;
		breadcrumbs.push(breadcrumb);

		// Trim to max size
		while breadcrumbs.len() > self.inner.config.max_breadcrumbs {
			breadcrumbs.remove(0);
		}
	}

	/// Clears all breadcrumbs.
	pub async fn clear_breadcrumbs(&self) {
		self.inner.breadcrumbs.write().await.clear();
	}

	/// Shuts down the client and ends the current session.
	///
	/// This will send the session end request to the server if session tracking
	/// is enabled. The session status will be determined based on error/crash counts.
	pub async fn shutdown(&self) -> Result<()> {
		if self.inner.closed.swap(true, Ordering::SeqCst) {
			return Ok(());
		}

		// End session tracking
		if let Err(e) = self.inner.session_tracker.end().await {
			error!(error = %e, "Failed to end session during shutdown");
		}

		info!("Crash client shutdown");
		Ok(())
	}

	/// Returns true if the client has been shut down.
	pub fn is_closed(&self) -> bool {
		self.inner.closed.load(Ordering::SeqCst)
	}

	fn check_closed(&self) -> Result<()> {
		if self.inner.closed.load(Ordering::SeqCst) {
			return Err(CrashSdkError::ClientShutdown);
		}
		Ok(())
	}

	async fn send_capture(&self, request: CaptureRequest) -> Result<CaptureResponse> {
		let url = format!("{}/api/crash/capture", self.inner.base_url);

		debug!(url = %url, project_id = %request.project_id, "Sending crash event");

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
		.map_err(CrashSdkError::RequestFailed)?;

		if response.status() == reqwest::StatusCode::TOO_MANY_REQUESTS {
			let retry_after = response
				.headers()
				.get("Retry-After")
				.and_then(|v| v.to_str().ok())
				.and_then(|s| s.parse().ok());
			return Err(CrashSdkError::RateLimited {
				retry_after_secs: retry_after,
			});
		}

		if !response.status().is_success() {
			let status = response.status().as_u16();
			let message = response.text().await.unwrap_or_default();
			return Err(CrashSdkError::ServerError { status, message });
		}

		let capture_response: CaptureResponse = response.json().await?;

		info!(
			event_id = %capture_response.event_id,
			issue_id = %capture_response.issue_id,
			short_id = %capture_response.short_id,
			is_new_issue = capture_response.is_new_issue,
			"Crash event captured"
		);

		Ok(capture_response)
	}
}

/// Request payload for capturing a crash event.
#[derive(Debug, Serialize, Deserialize)]
struct CaptureRequest {
	project_id: String,
	exception_type: String,
	exception_value: String,
	stacktrace: CaptureStacktrace,
	#[serde(skip_serializing_if = "Option::is_none")]
	environment: Option<String>,
	#[serde(skip_serializing_if = "Option::is_none")]
	platform: Option<String>,
	#[serde(skip_serializing_if = "Option::is_none")]
	release: Option<String>,
	#[serde(skip_serializing_if = "Option::is_none")]
	dist: Option<String>,
	#[serde(skip_serializing_if = "Option::is_none")]
	distinct_id: Option<String>,
	#[serde(skip_serializing_if = "Option::is_none")]
	person_id: Option<String>,
	#[serde(skip_serializing_if = "Option::is_none")]
	server_name: Option<String>,
	#[serde(default)]
	tags: HashMap<String, String>,
	#[serde(default)]
	extra: serde_json::Value,
	#[serde(default)]
	active_flags: HashMap<String, String>,
	#[serde(default)]
	breadcrumbs: Vec<CaptureBreadcrumb>,
	#[serde(skip_serializing_if = "Option::is_none")]
	timestamp: Option<String>,
}

/// Stacktrace in capture request format.
#[derive(Debug, Serialize, Deserialize)]
struct CaptureStacktrace {
	frames: Vec<CaptureFrame>,
}

impl CaptureStacktrace {
	fn from_stacktrace(st: &Stacktrace) -> Self {
		Self {
			frames: st.frames.iter().map(CaptureFrame::from_frame).collect(),
		}
	}
}

/// Frame in capture request format.
#[derive(Debug, Serialize, Deserialize)]
struct CaptureFrame {
	#[serde(skip_serializing_if = "Option::is_none")]
	function: Option<String>,
	#[serde(skip_serializing_if = "Option::is_none")]
	module: Option<String>,
	#[serde(skip_serializing_if = "Option::is_none")]
	filename: Option<String>,
	#[serde(skip_serializing_if = "Option::is_none")]
	abs_path: Option<String>,
	#[serde(skip_serializing_if = "Option::is_none")]
	lineno: Option<u32>,
	#[serde(skip_serializing_if = "Option::is_none")]
	colno: Option<u32>,
	#[serde(default)]
	in_app: bool,
}

impl CaptureFrame {
	fn from_frame(frame: &Frame) -> Self {
		Self {
			function: frame.function.clone(),
			module: frame.module.clone(),
			filename: frame.filename.clone(),
			abs_path: frame.abs_path.clone(),
			lineno: frame.lineno,
			colno: frame.colno,
			in_app: frame.in_app,
		}
	}
}

/// Breadcrumb in capture request format.
#[derive(Debug, Serialize, Deserialize)]
struct CaptureBreadcrumb {
	#[serde(skip_serializing_if = "Option::is_none")]
	timestamp: Option<String>,
	#[serde(skip_serializing_if = "Option::is_none")]
	category: Option<String>,
	#[serde(skip_serializing_if = "Option::is_none")]
	message: Option<String>,
	#[serde(skip_serializing_if = "Option::is_none")]
	level: Option<String>,
	#[serde(default)]
	data: serde_json::Value,
}

impl CaptureBreadcrumb {
	fn from_breadcrumb(bc: &Breadcrumb) -> Self {
		Self {
			timestamp: Some(bc.timestamp.to_rfc3339()),
			category: Some(bc.category.clone()),
			message: bc.message.clone(),
			level: Some(bc.level.to_string()),
			data: bc.data.clone(),
		}
	}
}

/// Response from capture endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaptureResponse {
	/// Unique ID of the captured event.
	pub event_id: String,
	/// ID of the issue this event was grouped into.
	pub issue_id: String,
	/// Human-readable short ID (e.g., "PROJ-123").
	pub short_id: String,
	/// Whether this created a new issue.
	pub is_new_issue: bool,
	/// Whether this is a regression of a previously resolved issue.
	pub is_regression: bool,
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_builder_requires_auth_token() {
		let result = CrashClientBuilder::new()
			.base_url("https://example.com")
			.project_id("proj_123")
			.build();

		assert!(matches!(result, Err(CrashSdkError::InvalidApiKey)));
	}

	#[test]
	fn test_builder_requires_base_url() {
		let result = CrashClientBuilder::new()
			.auth_token("token_123")
			.project_id("proj_123")
			.build();

		assert!(matches!(result, Err(CrashSdkError::InvalidBaseUrl)));
	}

	#[test]
	fn test_builder_requires_project_id() {
		let result = CrashClientBuilder::new()
			.auth_token("token_123")
			.base_url("https://example.com")
			.build();

		assert!(matches!(result, Err(CrashSdkError::MissingProjectId)));
	}

	#[test]
	fn test_builder_success() {
		let result = CrashClientBuilder::new()
			.auth_token("token_123")
			.base_url("https://example.com")
			.project_id("proj_123")
			.build();

		assert!(result.is_ok());
	}

	#[test]
	fn test_builder_normalizes_base_url() {
		let client = CrashClientBuilder::new()
			.auth_token("token_123")
			.base_url("https://example.com/")
			.project_id("proj_123")
			.build()
			.unwrap();

		assert!(!client.inner.base_url.ends_with('/'));
	}

	#[test]
	fn test_client_config_defaults() {
		let config = ClientConfig::default();
		assert_eq!(config.request_timeout, Duration::from_secs(30));
		assert_eq!(config.max_breadcrumbs, MAX_BREADCRUMBS);
	}

	#[tokio::test]
	async fn test_shutdown_prevents_capture() {
		let client = CrashClientBuilder::new()
			.auth_token("token_123")
			.base_url("https://example.com")
			.project_id("proj_123")
			.build()
			.unwrap();

		client.shutdown().await.unwrap();

		let result = client
			.capture_message("test", BreadcrumbLevel::Error)
			.await;
		assert!(matches!(result, Err(CrashSdkError::ClientShutdown)));
	}

	#[tokio::test]
	async fn test_double_shutdown_is_ok() {
		let client = CrashClientBuilder::new()
			.auth_token("token_123")
			.base_url("https://example.com")
			.project_id("proj_123")
			.build()
			.unwrap();

		client.shutdown().await.unwrap();
		client.shutdown().await.unwrap();
	}

	#[tokio::test]
	async fn test_set_and_remove_tag() {
		let client = CrashClientBuilder::new()
			.auth_token("token_123")
			.base_url("https://example.com")
			.project_id("proj_123")
			.build()
			.unwrap();

		client.set_tag("env", "test").await;
		assert!(client.inner.tags.read().await.contains_key("env"));

		client.remove_tag("env").await;
		assert!(!client.inner.tags.read().await.contains_key("env"));
	}

	#[tokio::test]
	async fn test_breadcrumb_limit() {
		let client = CrashClientBuilder::new()
			.auth_token("token_123")
			.base_url("https://example.com")
			.project_id("proj_123")
			.max_breadcrumbs(5)
			.build()
			.unwrap();

		// Add more than the limit
		for i in 0..10 {
			client
				.add_breadcrumb(Breadcrumb {
					category: format!("test_{}", i),
					..Default::default()
				})
				.await;
		}

		let breadcrumbs = client.inner.breadcrumbs.read().await;
		assert_eq!(breadcrumbs.len(), 5);
		// Should keep the most recent ones
		assert_eq!(breadcrumbs[0].category, "test_5");
	}
}
