// Copyright (c) 2025 Geoffrey Huntley <ghuntley@ghuntley.com>. All rights reserved.
// SPDX-License-Identifier: Proprietary

//! Error types for the crash SDK.

use thiserror::Error;

/// Result type alias for crash operations.
pub type Result<T> = std::result::Result<T, CrashSdkError>;

/// Errors that can occur in the crash SDK.
#[derive(Debug, Error)]
pub enum CrashSdkError {
	/// The client has been shut down.
	#[error("crash client has been shut down")]
	ClientShutdown,

	/// Invalid API key format.
	#[error("invalid API key format")]
	InvalidApiKey,

	/// Invalid base URL.
	#[error("invalid base URL")]
	InvalidBaseUrl,

	/// Missing required project ID.
	#[error("project ID is required")]
	MissingProjectId,

	/// HTTP request failed.
	#[error("HTTP request failed: {0}")]
	RequestFailed(#[from] reqwest::Error),

	/// Server returned an error.
	#[error("server error (status {status}): {message}")]
	ServerError {
		/// HTTP status code.
		status: u16,
		/// Error message from server.
		message: String,
	},

	/// Rate limited by server.
	#[error("rate limited, retry after {retry_after_secs:?} seconds")]
	RateLimited {
		/// Optional retry-after header value.
		retry_after_secs: Option<u64>,
	},

	/// Failed to serialize event.
	#[error("serialization error: {0}")]
	SerializationError(#[from] serde_json::Error),

	/// Lock acquisition failed.
	#[error("failed to acquire lock")]
	LockError,
}
