// Copyright (c) 2025 Geoffrey Huntley <ghuntley@ghuntley.com>. All rights reserved.
// SPDX-License-Identifier: Proprietary

//! Error types for the crons SDK.

use thiserror::Error;

/// Result type for crons SDK operations.
pub type Result<T> = std::result::Result<T, CronsSdkError>;

/// Errors that can occur when using the crons SDK.
#[derive(Debug, Error)]
pub enum CronsSdkError {
	/// Invalid or missing auth token.
	#[error("invalid or missing auth token")]
	InvalidAuthToken,

	/// Invalid or missing base URL.
	#[error("invalid or missing base URL")]
	InvalidBaseUrl,

	/// Missing organization ID.
	#[error("missing organization ID")]
	MissingOrgId,

	/// Monitor not found.
	#[error("monitor not found: {slug}")]
	MonitorNotFound { slug: String },

	/// Check-in not found.
	#[error("check-in not found: {id}")]
	CheckInNotFound { id: String },

	/// Client has been shut down.
	#[error("client has been shut down")]
	ClientShutdown,

	/// Job failed during `with_monitor` execution.
	#[error("job failed: {0}")]
	JobFailed(String),

	/// HTTP request failed.
	#[error("HTTP request failed: {0}")]
	RequestFailed(#[from] reqwest::Error),

	/// Server returned an error response.
	#[error("server error (HTTP {status}): {message}")]
	ServerError { status: u16, message: String },

	/// Rate limited by the server.
	#[error("rate limited (retry after {retry_after_secs:?}s)")]
	RateLimited { retry_after_secs: Option<u64> },

	/// JSON serialization/deserialization error.
	#[error("JSON error: {0}")]
	Json(#[from] serde_json::Error),
}
