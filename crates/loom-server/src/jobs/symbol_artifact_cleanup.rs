// Copyright (c) 2025 Geoffrey Huntley <ghuntley@ghuntley.com>. All rights reserved.
// SPDX-License-Identifier: Proprietary

//! Background job for cleaning up old symbol artifacts.
//!
//! This job runs daily to delete symbol artifacts that haven't been accessed
//! within the retention period (default: 90 days). Artifacts are deleted based on
//! their `last_accessed_at` timestamp, or `uploaded_at` if never accessed.

use async_trait::async_trait;
use chrono::{Duration, Utc};
use loom_server_crash::{CrashRepository, SqliteCrashRepository};
use loom_server_jobs::{Job, JobContext, JobError, JobOutput};
use std::sync::Arc;
use tracing::{info, instrument};

/// Default retention period for symbol artifacts (90 days after last access).
const DEFAULT_RETENTION_DAYS: i64 = 90;

pub struct SymbolArtifactCleanupJob {
	crash_repo: Arc<SqliteCrashRepository>,
	retention_days: i64,
}

impl SymbolArtifactCleanupJob {
	pub fn new(crash_repo: Arc<SqliteCrashRepository>) -> Self {
		Self {
			crash_repo,
			retention_days: DEFAULT_RETENTION_DAYS,
		}
	}

	/// Create with a custom retention period.
	#[allow(dead_code)]
	pub fn with_retention_days(crash_repo: Arc<SqliteCrashRepository>, days: i64) -> Self {
		Self {
			crash_repo,
			retention_days: days,
		}
	}
}

#[async_trait]
impl Job for SymbolArtifactCleanupJob {
	fn id(&self) -> &str {
		"symbol-artifact-cleanup"
	}

	fn name(&self) -> &str {
		"Symbol Artifact Cleanup"
	}

	fn description(&self) -> &str {
		"Delete symbol artifacts not accessed within retention period"
	}

	#[instrument(skip(self, ctx), fields(job_id = "symbol-artifact-cleanup", retention_days = %self.retention_days))]
	async fn run(&self, ctx: &JobContext) -> Result<JobOutput, JobError> {
		if ctx.cancellation_token.is_cancelled() {
			return Err(JobError::Cancelled);
		}

		let cutoff = Utc::now() - Duration::days(self.retention_days);

		info!(
			cutoff = %cutoff.to_rfc3339(),
			retention_days = self.retention_days,
			"Starting symbol artifact cleanup"
		);

		let deleted_count = self
			.crash_repo
			.delete_old_artifacts(cutoff)
			.await
			.map_err(|e| JobError::Failed {
				message: format!("Failed to delete old symbol artifacts: {}", e),
				retryable: true,
			})?;

		info!(
			deleted_count = deleted_count,
			cutoff = %cutoff.to_rfc3339(),
			"Symbol artifact cleanup completed"
		);

		Ok(JobOutput {
			message: format!(
				"Deleted {} symbol artifacts not accessed in {} days",
				deleted_count, self.retention_days
			),
			metadata: Some(serde_json::json!({
				"deleted_count": deleted_count,
				"cutoff": cutoff.to_rfc3339(),
				"retention_days": self.retention_days,
			})),
		})
	}
}
