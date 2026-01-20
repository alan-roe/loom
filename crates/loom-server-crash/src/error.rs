// Copyright (c) 2025 Geoffrey Huntley <ghuntley@ghuntley.com>. All rights reserved.
// SPDX-License-Identifier: Proprietary

//! Error types for crash server operations.

use thiserror::Error;

/// Errors that can occur in crash server operations.
#[derive(Debug, Error)]
pub enum CrashServerError {
	#[error("project not found: {0}")]
	ProjectNotFound(String),

	#[error("issue not found: {0}")]
	IssueNotFound(String),

	#[error("event not found: {0}")]
	EventNotFound(String),

	#[error("API key not found: {0}")]
	ApiKeyNotFound(String),

	#[error("API key revoked")]
	ApiKeyRevoked,

	#[error("invalid API key")]
	InvalidApiKey,

	#[error("failed to hash API key")]
	ApiKeyHash,

	#[error("database error: {0}")]
	Database(#[from] sqlx::Error),

	#[error("serialization error: {0}")]
	Serialization(#[from] serde_json::Error),

	#[error("invalid UUID: {0}")]
	InvalidUuid(#[from] uuid::Error),

	#[error("invalid datetime: {0}")]
	InvalidDateTime(String),

	#[error("parse error: {0}")]
	Parse(String),

	#[error("symbolication error: {0}")]
	Symbolication(String),
}

/// Result type for crash server operations.
pub type Result<T> = std::result::Result<T, CrashServerError>;
