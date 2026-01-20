// Copyright (c) 2025 Geoffrey Huntley <ghuntley@ghuntley.com>. All rights reserved.
// SPDX-License-Identifier: Proprietary

use crate::context::{CancellationToken, JobContext};
use crate::error::{JobError, Result};
use crate::health::{HealthState, JobHealthStatus, JobsHealthStatus, LastRunInfo};
use crate::job::Job;
use crate::repository::JobRepository;
use crate::types::{JobDefinition, JobRun, JobStatus, JobType, TriggerSource};
use chrono::Utc;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{broadcast, Mutex};
use tokio::task::JoinHandle;
use tracing::{info, instrument, warn};

const BASE_RETRY_DELAY_SECS: u64 = 1;
const MAX_RETRY_DELAY_SECS: u64 = 60;
const RETRY_FACTOR: f64 = 2.0;
const MAX_RETRIES: u32 = 3;

struct RegisteredJob {
	job: Arc<dyn Job>,
	job_type: JobType,
	cancellation_token: CancellationToken,
}

pub struct JobScheduler {
	jobs: HashMap<String, RegisteredJob>,
	repository: Arc<JobRepository>,
	shutdown_tx: broadcast::Sender<()>,
	handles: Mutex<Vec<JoinHandle<()>>>,
}

impl JobScheduler {
	pub fn new(repository: Arc<JobRepository>) -> Self {
		let (shutdown_tx, _) = broadcast::channel(1);
		Self {
			jobs: HashMap::new(),
			repository,
			shutdown_tx,
			handles: Mutex::new(Vec::new()),
		}
	}

	pub fn register_periodic(&mut self, job: Arc<dyn Job>, interval: Duration) {
		let id = job.id().to_string();
		self.jobs.insert(
			id,
			RegisteredJob {
				job,
				job_type: JobType::Periodic { interval },
				cancellation_token: CancellationToken::new(),
			},
		);
	}

	pub fn register_one_shot(&mut self, job: Arc<dyn Job>) {
		let id = job.id().to_string();
		self.jobs.insert(
			id,
			RegisteredJob {
				job,
				job_type: JobType::OneShot,
				cancellation_token: CancellationToken::new(),
			},
		);
	}

	#[instrument(skip(self))]
	pub async fn start(&self) -> Result<()> {
		let mut handles = self.handles.lock().await;

		for (job_id, registered) in &self.jobs {
			let def = JobDefinition {
				id: job_id.clone(),
				name: registered.job.name().to_string(),
				description: registered.job.description().to_string(),
				job_type: match &registered.job_type {
					JobType::Periodic { .. } => "periodic".to_string(),
					JobType::OneShot => "one_shot".to_string(),
				},
				interval_secs: match &registered.job_type {
					JobType::Periodic { interval } => Some(interval.as_secs() as i64),
					JobType::OneShot => None,
				},
				enabled: true,
			};
			self.repository.upsert_definition(&def).await?;

			if let JobType::Periodic { interval } = registered.job_type {
				let job = Arc::clone(&registered.job);
				let repository = Arc::clone(&self.repository);
				let mut shutdown_rx = self.shutdown_tx.subscribe();
				let cancellation_token = registered.cancellation_token.clone();
				let job_id = job_id.clone();

				let handle = tokio::spawn(async move {
					loop {
						tokio::select! {
								_ = tokio::time::sleep(interval) => {
										if cancellation_token.is_cancelled() {
												continue;
										}
										let _ = run_job_with_retry(
												&job,
												&repository,
												TriggerSource::Schedule,
												&cancellation_token,
										).await;
								}
								_ = shutdown_rx.recv() => {
										info!(job_id = %job_id, "Shutting down periodic job");
										break;
								}
						}
					}
				});

				handles.push(handle);
			}
		}

		info!(job_count = handles.len(), "Job scheduler started");
		Ok(())
	}

	#[instrument(skip(self))]
	pub async fn trigger_job(&self, job_id: &str, triggered_by: TriggerSource) -> Result<String> {
		let registered = self
			.jobs
			.get(job_id)
			.ok_or_else(|| JobError::NotFound(job_id.to_string()))?;

		run_job_with_retry(
			&registered.job,
			&self.repository,
			triggered_by,
			&registered.cancellation_token,
		)
		.await
	}

	#[instrument(skip(self))]
	pub async fn cancel_job(&self, job_id: &str) -> Result<()> {
		let registered = self
			.jobs
			.get(job_id)
			.ok_or_else(|| JobError::NotFound(job_id.to_string()))?;

		registered.cancellation_token.cancel();
		Ok(())
	}

	#[instrument(skip(self))]
	pub async fn shutdown(&self) {
		let _ = self.shutdown_tx.send(());

		let mut handles = self.handles.lock().await;
		for handle in handles.drain(..) {
			match tokio::time::timeout(Duration::from_secs(10), handle).await {
				Ok(Ok(())) => {}
				Ok(Err(e)) => warn!(error = %e, "Job task panicked during shutdown"),
				Err(_) => warn!("Job did not shut down within 10 second timeout"),
			}
		}

		info!("Job scheduler shut down");
	}

	pub fn job_ids(&self) -> Vec<String> {
		self.jobs.keys().cloned().collect()
	}

	#[instrument(skip(self))]
	pub async fn job_status(&self, job_id: &str) -> Option<JobHealthStatus> {
		let registered = self.jobs.get(job_id)?;

		let last_run = self.repository.get_last_run(job_id).await.ok().flatten();
		let consecutive_failures = self
			.repository
			.count_consecutive_failures(job_id)
			.await
			.unwrap_or(0);

		let status = determine_health_state(&last_run, consecutive_failures);

		Some(JobHealthStatus {
			job_id: job_id.to_string(),
			name: registered.job.name().to_string(),
			status,
			last_run: last_run.map(|r| LastRunInfo {
				run_id: r.id,
				status: r.status,
				started_at: r.started_at,
				duration_ms: r.duration_ms,
				error: r.error_message,
			}),
			consecutive_failures,
		})
	}

	#[instrument(skip(self))]
	pub async fn health_status(&self) -> JobsHealthStatus {
		let mut jobs = Vec::new();
		let mut worst_state = HealthState::Healthy;

		for job_id in self.jobs.keys() {
			if let Some(status) = self.job_status(job_id).await {
				if status.status == HealthState::Unhealthy {
					worst_state = HealthState::Unhealthy;
				} else if status.status == HealthState::Degraded && worst_state != HealthState::Unhealthy {
					worst_state = HealthState::Degraded;
				}
				jobs.push(status);
			}
		}

		JobsHealthStatus {
			status: worst_state,
			jobs,
		}
	}
}

fn determine_health_state(last_run: &Option<JobRun>, consecutive_failures: u32) -> HealthState {
	match last_run {
		None => HealthState::Healthy,
		Some(run) => match run.status {
			JobStatus::Succeeded => HealthState::Healthy,
			JobStatus::Running => HealthState::Healthy,
			JobStatus::Cancelled => HealthState::Healthy,
			JobStatus::Failed => {
				if consecutive_failures >= 3 {
					HealthState::Unhealthy
				} else if consecutive_failures >= 1 {
					HealthState::Degraded
				} else {
					HealthState::Healthy
				}
			}
		},
	}
}

async fn run_job_with_retry(
	job: &Arc<dyn Job>,
	repository: &Arc<JobRepository>,
	triggered_by: TriggerSource,
	cancellation_token: &CancellationToken,
) -> Result<String> {
	let mut retry_count = 0u32;
	let run_id = uuid::Uuid::new_v4().to_string();

	loop {
		let ctx = JobContext {
			run_id: run_id.clone(),
			triggered_by: if retry_count > 0 {
				TriggerSource::Retry
			} else {
				triggered_by
			},
			cancellation_token: cancellation_token.clone(),
		};

		let run = JobRun {
			id: run_id.clone(),
			job_id: job.id().to_string(),
			status: JobStatus::Running,
			started_at: Utc::now(),
			completed_at: None,
			duration_ms: None,
			error_message: None,
			retry_count,
			triggered_by: ctx.triggered_by,
			metadata: None,
		};

		if retry_count == 0 {
			repository.record_run_start(&run).await?;
		}

		match job.run(&ctx).await {
			Ok(output) => {
				repository
					.record_run_complete(&run_id, JobStatus::Succeeded, None, output.metadata)
					.await?;
				info!(job_id = %job.id(), run_id = %run_id, "Job completed successfully");
				return Ok(run_id);
			}
			Err(JobError::Cancelled) => {
				repository
					.record_run_complete(&run_id, JobStatus::Cancelled, None, None)
					.await?;
				info!(job_id = %job.id(), run_id = %run_id, "Job cancelled");
				return Err(JobError::Cancelled);
			}
			Err(JobError::Failed { message, retryable }) => {
				if retryable && retry_count < MAX_RETRIES {
					retry_count += 1;
					let delay_secs = calculate_backoff_delay(retry_count);
					warn!(
							job_id = %job.id(),
							run_id = %run_id,
							retry_count,
							delay_secs,
							error = %message,
							"Job failed, retrying"
					);
					tokio::time::sleep(Duration::from_secs(delay_secs)).await;
					continue;
				}

				repository
					.record_run_complete(&run_id, JobStatus::Failed, Some(message.clone()), None)
					.await?;
				warn!(job_id = %job.id(), run_id = %run_id, error = %message, "Job failed");
				return Err(JobError::Failed { message, retryable });
			}
			Err(e) => {
				let message = e.to_string();
				repository
					.record_run_complete(&run_id, JobStatus::Failed, Some(message.clone()), None)
					.await?;
				warn!(job_id = %job.id(), run_id = %run_id, error = %message, "Job failed with error");
				return Err(e);
			}
		}
	}
}

pub(crate) fn calculate_backoff_delay(retry_count: u32) -> u64 {
	let delay = BASE_RETRY_DELAY_SECS as f64 * RETRY_FACTOR.powi(retry_count as i32 - 1);
	(delay as u64).min(MAX_RETRY_DELAY_SECS)
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::context::JobContext;
	use crate::error::JobError;
	use crate::types::JobOutput;
	use async_trait::async_trait;
	use sqlx::SqlitePool;
	use std::time::Duration;

	async fn setup_db() -> SqlitePool {
		let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
		sqlx::query(
			r#"
            CREATE TABLE job_definitions (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                description TEXT NOT NULL,
                job_type TEXT NOT NULL,
                interval_secs INTEGER,
                enabled INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            "#,
		)
		.execute(&pool)
		.await
		.unwrap();

		sqlx::query(
			r#"
            CREATE TABLE job_runs (
                id TEXT PRIMARY KEY,
                job_id TEXT NOT NULL,
                status TEXT NOT NULL,
                started_at TEXT NOT NULL,
                completed_at TEXT,
                duration_ms INTEGER,
                error_message TEXT,
                retry_count INTEGER NOT NULL DEFAULT 0,
                triggered_by TEXT NOT NULL,
                metadata TEXT,
                FOREIGN KEY (job_id) REFERENCES job_definitions(id)
            )
            "#,
		)
		.execute(&pool)
		.await
		.unwrap();

		pool
	}

	struct MockJob {
		id: String,
		name: String,
	}

	impl MockJob {
		fn new(id: &str, name: &str) -> Self {
			Self {
				id: id.to_string(),
				name: name.to_string(),
			}
		}
	}

	#[async_trait]
	impl Job for MockJob {
		fn id(&self) -> &str {
			&self.id
		}

		fn name(&self) -> &str {
			&self.name
		}

		fn description(&self) -> &str {
			"A mock job for testing"
		}

		async fn run(&self, _ctx: &JobContext) -> std::result::Result<JobOutput, JobError> {
			Ok(JobOutput {
				message: "Mock job completed".to_string(),
				metadata: None,
			})
		}
	}

	#[test]
	fn test_calculate_backoff_delay_retry_1() {
		let delay = calculate_backoff_delay(1);
		assert_eq!(delay, BASE_RETRY_DELAY_SECS);
	}

	#[test]
	fn test_calculate_backoff_delay_retry_2() {
		let delay = calculate_backoff_delay(2);
		assert_eq!(delay, 2);
	}

	#[test]
	fn test_calculate_backoff_delay_retry_3() {
		let delay = calculate_backoff_delay(3);
		assert_eq!(delay, 4);
	}

	#[test]
	fn test_calculate_backoff_delay_caps_at_max() {
		let delay = calculate_backoff_delay(10);
		assert_eq!(delay, MAX_RETRY_DELAY_SECS);

		let delay = calculate_backoff_delay(100);
		assert_eq!(delay, MAX_RETRY_DELAY_SECS);
	}

	#[test]
	fn test_determine_health_state_no_last_run() {
		let state = determine_health_state(&None, 0);
		assert_eq!(state, HealthState::Healthy);
	}

	#[test]
	fn test_determine_health_state_succeeded() {
		let run = JobRun {
			id: "run-1".to_string(),
			job_id: "job-1".to_string(),
			status: JobStatus::Succeeded,
			started_at: Utc::now(),
			completed_at: Some(Utc::now()),
			duration_ms: Some(100),
			error_message: None,
			retry_count: 0,
			triggered_by: TriggerSource::Schedule,
			metadata: None,
		};
		let state = determine_health_state(&Some(run), 0);
		assert_eq!(state, HealthState::Healthy);
	}

	#[test]
	fn test_determine_health_state_running() {
		let run = JobRun {
			id: "run-1".to_string(),
			job_id: "job-1".to_string(),
			status: JobStatus::Running,
			started_at: Utc::now(),
			completed_at: None,
			duration_ms: None,
			error_message: None,
			retry_count: 0,
			triggered_by: TriggerSource::Schedule,
			metadata: None,
		};
		let state = determine_health_state(&Some(run), 0);
		assert_eq!(state, HealthState::Healthy);
	}

	#[test]
	fn test_determine_health_state_cancelled() {
		let run = JobRun {
			id: "run-1".to_string(),
			job_id: "job-1".to_string(),
			status: JobStatus::Cancelled,
			started_at: Utc::now(),
			completed_at: Some(Utc::now()),
			duration_ms: Some(50),
			error_message: None,
			retry_count: 0,
			triggered_by: TriggerSource::Manual,
			metadata: None,
		};
		let state = determine_health_state(&Some(run), 0);
		assert_eq!(state, HealthState::Healthy);
	}

	#[test]
	fn test_determine_health_state_failed_zero_consecutive() {
		let run = JobRun {
			id: "run-1".to_string(),
			job_id: "job-1".to_string(),
			status: JobStatus::Failed,
			started_at: Utc::now(),
			completed_at: Some(Utc::now()),
			duration_ms: Some(100),
			error_message: Some("Error".to_string()),
			retry_count: 0,
			triggered_by: TriggerSource::Schedule,
			metadata: None,
		};
		let state = determine_health_state(&Some(run), 0);
		assert_eq!(state, HealthState::Healthy);
	}

	#[test]
	fn test_determine_health_state_failed_one_consecutive() {
		let run = JobRun {
			id: "run-1".to_string(),
			job_id: "job-1".to_string(),
			status: JobStatus::Failed,
			started_at: Utc::now(),
			completed_at: Some(Utc::now()),
			duration_ms: Some(100),
			error_message: Some("Error".to_string()),
			retry_count: 0,
			triggered_by: TriggerSource::Schedule,
			metadata: None,
		};
		let state = determine_health_state(&Some(run), 1);
		assert_eq!(state, HealthState::Degraded);
	}

	#[test]
	fn test_determine_health_state_failed_two_consecutive() {
		let run = JobRun {
			id: "run-1".to_string(),
			job_id: "job-1".to_string(),
			status: JobStatus::Failed,
			started_at: Utc::now(),
			completed_at: Some(Utc::now()),
			duration_ms: Some(100),
			error_message: Some("Error".to_string()),
			retry_count: 0,
			triggered_by: TriggerSource::Schedule,
			metadata: None,
		};
		let state = determine_health_state(&Some(run), 2);
		assert_eq!(state, HealthState::Degraded);
	}

	#[test]
	fn test_determine_health_state_failed_three_plus_consecutive() {
		let run = JobRun {
			id: "run-1".to_string(),
			job_id: "job-1".to_string(),
			status: JobStatus::Failed,
			started_at: Utc::now(),
			completed_at: Some(Utc::now()),
			duration_ms: Some(100),
			error_message: Some("Error".to_string()),
			retry_count: 0,
			triggered_by: TriggerSource::Schedule,
			metadata: None,
		};
		let state = determine_health_state(&Some(run.clone()), 3);
		assert_eq!(state, HealthState::Unhealthy);

		let state = determine_health_state(&Some(run), 5);
		assert_eq!(state, HealthState::Unhealthy);
	}

	#[tokio::test]
	async fn test_register_periodic_job() {
		let pool = setup_db().await;
		let repository = Arc::new(JobRepository::new(pool));
		let mut scheduler = JobScheduler::new(repository);

		let job = Arc::new(MockJob::new("periodic-job-1", "Periodic Test Job"));
		scheduler.register_periodic(job, Duration::from_secs(60));

		let job_ids = scheduler.job_ids();
		assert!(job_ids.contains(&"periodic-job-1".to_string()));
	}

	#[tokio::test]
	async fn test_register_one_shot_job() {
		let pool = setup_db().await;
		let repository = Arc::new(JobRepository::new(pool));
		let mut scheduler = JobScheduler::new(repository);

		let job = Arc::new(MockJob::new("oneshot-job-1", "One Shot Test Job"));
		scheduler.register_one_shot(job);

		let job_ids = scheduler.job_ids();
		assert!(job_ids.contains(&"oneshot-job-1".to_string()));
	}

	#[tokio::test]
	async fn test_trigger_nonexistent_job_returns_not_found() {
		let pool = setup_db().await;
		let repository = Arc::new(JobRepository::new(pool));
		let scheduler = JobScheduler::new(repository);

		let result = scheduler
			.trigger_job("nonexistent-job", TriggerSource::Manual)
			.await;

		assert!(result.is_err());
		match result.unwrap_err() {
			JobError::NotFound(id) => assert_eq!(id, "nonexistent-job"),
			e => panic!("Expected NotFound error, got: {:?}", e),
		}
	}
}
