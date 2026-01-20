// Copyright (c) 2025 Geoffrey Huntley <ghuntley@ghuntley.com>. All rights reserved.
// SPDX-License-Identifier: Proprietary

use loom_server_k8s::K8sError;
use std::io;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum LocalError {
	#[error("tmux error: {message}")]
	TmuxError { message: String },

	#[error("weaver not found: {id}")]
	WeaverNotFound { id: String },

	#[error("weaver already exists: {id}")]
	WeaverExists { id: String },

	#[error("IO error: {0}")]
	Io(#[from] io::Error),

	#[error("PTY error: {message}")]
	PtyError { message: String },

	#[error("metadata error: {message}")]
	MetadataError { message: String },

	#[error("process error: {message}")]
	ProcessError { message: String },

	#[error("invalid weaver id: {id}")]
	InvalidWeaverId { id: String },
}

impl From<LocalError> for K8sError {
	fn from(err: LocalError) -> Self {
		match err {
			LocalError::WeaverNotFound { id } => K8sError::PodNotFound { name: id },
			LocalError::TmuxError { message } => K8sError::ApiError { message },
			LocalError::Io(e) => K8sError::ApiError {
				message: e.to_string(),
			},
			LocalError::PtyError { message } => K8sError::AttachError { message },
			LocalError::MetadataError { message } => K8sError::ApiError { message },
			LocalError::ProcessError { message } => K8sError::ApiError { message },
			LocalError::WeaverExists { id } => K8sError::ApiError {
				message: format!("weaver already exists: {id}"),
			},
			LocalError::InvalidWeaverId { id } => K8sError::ApiError {
				message: format!("invalid weaver id: {id}"),
			},
		}
	}
}

pub type LocalResult<T> = Result<T, LocalError>;
