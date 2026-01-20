// Copyright (c) 2025 Geoffrey Huntley <ghuntley@ghuntley.com>. All rights reserved.
// SPDX-License-Identifier: Proprietary

//! Error types for symbolication operations.

use thiserror::Error;

/// Errors that can occur during symbolication.
#[derive(Debug, Error)]
pub enum SymbolicateError {
	#[error("Invalid source map JSON: {0}")]
	InvalidSourceMapJson(#[from] serde_json::Error),

	#[error("Invalid source map version: expected 3, got {0}")]
	InvalidSourceMapVersion(u32),

	#[error("Invalid VLQ character: {0}")]
	InvalidVlqChar(char),

	#[error("Invalid source index: {0}")]
	InvalidSourceIndex(u32),

	#[error("Invalid name index: {0}")]
	InvalidNameIndex(u32),

	#[error("Source map is missing required field: {0}")]
	MissingField(&'static str),

	#[error("Source map lookup failed: no mapping found for line {line}, column {column}")]
	NoMappingFound { line: u32, column: u32 },

	#[error("IO error: {0}")]
	Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, SymbolicateError>;
