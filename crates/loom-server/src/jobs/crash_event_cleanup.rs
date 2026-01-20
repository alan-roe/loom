// Copyright (c) 2025 Geoffrey Huntley <ghuntley@ghuntley.com>. All rights reserved.
// SPDX-License-Identifier: Proprietary

//! Background job for cleaning up old crash events.
//!
//! This job runs daily to delete crash events older than the retention period
//! (default: 90 days). Issues and aggregated data are kept for longer historical
//! analysis.

use async_trait::async_trait;
use chrono::{Duration, Utc};
use loom_server_crash::{CrashRepository, SqliteCrashRepository};
use loom_server_jobs::{Job, JobContext, JobError, JobOutput};
use std::sync::Arc;
use tracing::{info, instrument};

/// Default retention period for crash events (90 days).
const DEFAULT_RETENTION_DAYS: i64 = 90;

pub struct CrashEventCleanupJob {
	crash_repo: Arc<SqliteCrashRepository>,
	retention_days: i64,
}

impl CrashEventCleanupJob {
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
impl Job for CrashEventCleanupJob {
	fn id(&self) -> &str {
		"crash-event-cleanup"
	}

	fn name(&self) -> &str {
		"Crash Event Cleanup"
	}

	fn description(&self) -> &str {
		"Delete crash events older than retention period"
	}

	#[instrument(skip(self, ctx), fields(job_id = "crash-event-cleanup", retention_days = %self.retention_days))]
	async fn run(&self, ctx: &JobContext) -> Result<JobOutput, JobError> {
		if ctx.cancellation_token.is_cancelled() {
			return Err(JobError::Cancelled);
		}

		let cutoff = Utc::now() - Duration::days(self.retention_days);

		info!(
			cutoff = %cutoff.to_rfc3339(),
			retention_days = self.retention_days,
			"Starting crash event cleanup"
		);

		let deleted_count = self
			.crash_repo
			.delete_old_events(cutoff)
			.await
			.map_err(|e| JobError::Failed {
				message: format!("Failed to delete old crash events: {}", e),
				retryable: true,
			})?;

		info!(
			deleted_count = deleted_count,
			cutoff = %cutoff.to_rfc3339(),
			"Crash event cleanup completed"
		);

		Ok(JobOutput {
			message: format!(
				"Deleted {} crash events older than {} days",
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
