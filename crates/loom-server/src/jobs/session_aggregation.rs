// Copyright (c) 2025 Geoffrey Huntley <ghuntley@ghuntley.com>. All rights reserved.
// SPDX-License-Identifier: Proprietary

//! Background job for aggregating app sessions into hourly rollups.
//!
//! This job runs periodically (typically every hour) to aggregate individual
//! sessions into hourly buckets for efficient release health calculations.

use async_trait::async_trait;
use chrono::{Duration, DurationRound, Utc};
use loom_server_jobs::{Job, JobContext, JobError, JobOutput};
use loom_server_sessions::{SessionsRepository, SqliteSessionsRepository};
use loom_sessions_core::{SessionAggregate, SessionAggregateId, SessionStatus};
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{info, instrument, warn};

pub struct SessionAggregationJob {
	sessions_repo: Arc<SqliteSessionsRepository>,
}

impl SessionAggregationJob {
	pub fn new(sessions_repo: Arc<SqliteSessionsRepository>) -> Self {
		Self { sessions_repo }
	}
}

/// Key for grouping sessions into aggregates
#[derive(Debug, Hash, PartialEq, Eq, Clone)]
struct AggregateKey {
	org_id: String,
	project_id: String,
	release: Option<String>,
	environment: String,
}

#[async_trait]
impl Job for SessionAggregationJob {
	fn id(&self) -> &str {
		"session-aggregation"
	}

	fn name(&self) -> &str {
		"Session Aggregation"
	}

	fn description(&self) -> &str {
		"Aggregate app sessions into hourly rollups for release health metrics"
	}

	#[instrument(skip(self, ctx), fields(job_id = "session-aggregation"))]
	async fn run(&self, ctx: &JobContext) -> Result<JobOutput, JobError> {
		if ctx.cancellation_token.is_cancelled() {
			return Err(JobError::Cancelled);
		}

		let now = Utc::now();
		// Aggregate the previous hour (not current hour which may still have incoming sessions)
		let current_hour = now.duration_trunc(Duration::hours(1)).unwrap_or(now);
		let previous_hour = current_hour - Duration::hours(1);

		info!(
			previous_hour = %previous_hour.to_rfc3339(),
			current_hour = %current_hour.to_rfc3339(),
			"Starting session aggregation for previous hour"
		);

		// Fetch all sessions from the previous hour
		let sessions = self
			.sessions_repo
			.get_sessions_for_aggregation(previous_hour, current_hour)
			.await
			.map_err(|e| JobError::Failed {
				message: format!("Failed to fetch sessions for aggregation: {}", e),
				retryable: true,
			})?;

		if sessions.is_empty() {
			info!("No sessions to aggregate for the previous hour");
			return Ok(JobOutput {
				message: "No sessions to aggregate".to_string(),
				metadata: Some(serde_json::json!({
					"hour": previous_hour.to_rfc3339(),
					"sessions_processed": 0,
					"aggregates_created": 0,
				})),
			});
		}

		if ctx.cancellation_token.is_cancelled() {
			return Err(JobError::Cancelled);
		}

		// Group sessions by (org, project, release, environment)
		let mut groups: HashMap<AggregateKey, Vec<_>> = HashMap::new();
		for session in &sessions {
			let key = AggregateKey {
				org_id: session.org_id.clone(),
				project_id: session.project_id.clone(),
				release: session.release.clone(),
				environment: session.environment.clone(),
			};
			groups.entry(key).or_default().push(session);
		}

		let mut aggregates_upserted = 0;
		let now = Utc::now();

		// Create aggregates for each group
		for (key, group_sessions) in groups {
			if ctx.cancellation_token.is_cancelled() {
				return Err(JobError::Cancelled);
			}

			let mut total_sessions = 0u64;
			let mut exited_sessions = 0u64;
			let mut crashed_sessions = 0u64;
			let mut abnormal_sessions = 0u64;
			let mut errored_sessions = 0u64;
			let mut unique_users = std::collections::HashSet::new();
			let mut crashed_users = std::collections::HashSet::new();
			let mut total_duration_ms = 0u64;
			let mut min_duration_ms: Option<u64> = None;
			let mut max_duration_ms: Option<u64> = None;
			let mut total_errors = 0u64;
			let mut total_crashes = 0u64;

			for session in &group_sessions {
				total_sessions += 1;

				match session.status {
					SessionStatus::Exited => exited_sessions += 1,
					SessionStatus::Crashed => crashed_sessions += 1,
					SessionStatus::Abnormal => abnormal_sessions += 1,
					SessionStatus::Errored => errored_sessions += 1,
					SessionStatus::Active => {
						// Active sessions that haven't ended yet - count as abnormal
						abnormal_sessions += 1;
					}
				}

				// Track unique users by distinct_id (or person_id if available)
				let user_id = session.person_id.as_ref().unwrap_or(&session.distinct_id);
				unique_users.insert(user_id.clone());

				if session.crashed {
					crashed_users.insert(user_id.clone());
				}

				// Duration stats
				if let Some(duration) = session.duration_ms {
					total_duration_ms += duration;
					min_duration_ms = Some(min_duration_ms.map_or(duration, |m| m.min(duration)));
					max_duration_ms = Some(max_duration_ms.map_or(duration, |m| m.max(duration)));
				}

				total_errors += session.error_count as u64;
				total_crashes += session.crash_count as u64;
			}

			let aggregate = SessionAggregate {
				id: SessionAggregateId::new(),
				org_id: key.org_id,
				project_id: key.project_id,
				release: key.release,
				environment: key.environment,
				hour: previous_hour,
				total_sessions,
				exited_sessions,
				crashed_sessions,
				abnormal_sessions,
				errored_sessions,
				unique_users: unique_users.len() as u64,
				crashed_users: crashed_users.len() as u64,
				total_duration_ms,
				min_duration_ms,
				max_duration_ms,
				total_errors,
				total_crashes,
				updated_at: now,
			};

			if let Err(e) = self.sessions_repo.upsert_aggregate(&aggregate).await {
				warn!(
					project_id = %aggregate.project_id,
					release = ?aggregate.release,
					environment = %aggregate.environment,
					hour = %aggregate.hour,
					error = %e,
					"Failed to upsert session aggregate"
				);
				continue;
			}

			aggregates_upserted += 1;
		}

		let sessions_count = sessions.len();

		info!(
			hour = %previous_hour.to_rfc3339(),
			sessions_processed = sessions_count,
			aggregates_upserted = aggregates_upserted,
			"Session aggregation completed"
		);

		Ok(JobOutput {
			message: format!(
				"Aggregated {} sessions into {} aggregates for {}",
				sessions_count,
				aggregates_upserted,
				previous_hour.to_rfc3339()
			),
			metadata: Some(serde_json::json!({
				"hour": previous_hour.to_rfc3339(),
				"sessions_processed": sessions_count,
				"aggregates_created": aggregates_upserted,
			})),
		})
	}
}
