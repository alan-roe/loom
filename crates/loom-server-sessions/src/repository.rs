// Copyright (c) 2025 Geoffrey Huntley <ghuntley@ghuntley.com>. All rights reserved.
// SPDX-License-Identifier: Proprietary

//! Repository layer for session analytics database operations.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::SqlitePool;
use tracing::instrument;

use loom_sessions_core::{Session, SessionAggregate, SessionAggregateId, SessionId, SessionStatus};

use crate::error::{Result, SessionsServerError};

/// Repository trait for sessions operations.
#[async_trait]
pub trait SessionsRepository: Send + Sync {
	// Session operations
	async fn create_session(&self, session: &Session) -> Result<()>;
	async fn get_session_by_id(&self, id: &SessionId) -> Result<Option<Session>>;
	async fn update_session(&self, session: &Session) -> Result<()>;
	async fn list_sessions(&self, project_id: &str, limit: u32, offset: u32) -> Result<Vec<Session>>;
	async fn list_sessions_by_release(
		&self,
		project_id: &str,
		release: &str,
		limit: u32,
	) -> Result<Vec<Session>>;
	async fn delete_old_sessions(&self, cutoff: DateTime<Utc>) -> Result<u64>;

	// Session state updates
	async fn end_session(
		&self,
		id: &SessionId,
		status: SessionStatus,
		error_count: u32,
		crash_count: u32,
		ended_at: DateTime<Utc>,
		duration_ms: u64,
	) -> Result<()>;

	// Aggregate operations
	async fn upsert_aggregate(&self, aggregate: &SessionAggregate) -> Result<()>;
	async fn get_aggregates(
		&self,
		project_id: &str,
		release: Option<&str>,
		environment: &str,
		start: DateTime<Utc>,
		end: DateTime<Utc>,
	) -> Result<Vec<SessionAggregate>>;
	async fn get_total_sessions_in_range(
		&self,
		project_id: &str,
		environment: &str,
		start: DateTime<Utc>,
		end: DateTime<Utc>,
	) -> Result<u64>;

	// Release queries
	async fn get_releases(&self, project_id: &str, environment: &str) -> Result<Vec<String>>;

	// Aggregation job
	async fn get_sessions_for_aggregation(
		&self,
		hour_start: DateTime<Utc>,
		hour_end: DateTime<Utc>,
	) -> Result<Vec<Session>>;
}

/// SQLite implementation of the sessions repository.
#[derive(Clone)]
pub struct SqliteSessionsRepository {
	pool: SqlitePool,
}

impl SqliteSessionsRepository {
	pub fn new(pool: SqlitePool) -> Self {
		Self { pool }
	}
}

// Database row structs for mapping
#[derive(sqlx::FromRow)]
struct SessionRow {
	id: String,
	org_id: String,
	project_id: String,
	person_id: Option<String>,
	distinct_id: String,
	status: String,
	release: Option<String>,
	environment: String,
	error_count: i32,
	crash_count: i32,
	crashed: i32,
	started_at: String,
	ended_at: Option<String>,
	duration_ms: Option<i64>,
	platform: String,
	user_agent: Option<String>,
	sampled: i32,
	sample_rate: f64,
	created_at: String,
	updated_at: String,
}

impl TryFrom<SessionRow> for Session {
	type Error = SessionsServerError;

	fn try_from(row: SessionRow) -> Result<Self> {
		Ok(Session {
			id: SessionId(
				row
					.id
					.parse()
					.map_err(|_| SessionsServerError::InvalidData("invalid session ID".into()))?,
			),
			org_id: row.org_id,
			project_id: row.project_id,
			person_id: row.person_id,
			distinct_id: row.distinct_id,
			status: row
				.status
				.parse()
				.map_err(|e| SessionsServerError::InvalidData(format!("invalid status: {e}")))?,
			release: row.release,
			environment: row.environment,
			error_count: row.error_count as u32,
			crash_count: row.crash_count as u32,
			crashed: row.crashed != 0,
			started_at: DateTime::parse_from_rfc3339(&row.started_at)
				.map_err(|e| SessionsServerError::InvalidData(format!("invalid started_at: {e}")))?
				.with_timezone(&Utc),
			ended_at: row
				.ended_at
				.map(|s| {
					DateTime::parse_from_rfc3339(&s)
						.map(|dt| dt.with_timezone(&Utc))
						.map_err(|e| SessionsServerError::InvalidData(format!("invalid ended_at: {e}")))
				})
				.transpose()?,
			duration_ms: row.duration_ms.map(|d| d as u64),
			platform: row
				.platform
				.parse()
				.map_err(|e| SessionsServerError::InvalidData(format!("invalid platform: {e}")))?,
			user_agent: row.user_agent,
			sampled: row.sampled != 0,
			sample_rate: row.sample_rate,
			created_at: DateTime::parse_from_rfc3339(&row.created_at)
				.map_err(|e| SessionsServerError::InvalidData(format!("invalid created_at: {e}")))?
				.with_timezone(&Utc),
			updated_at: DateTime::parse_from_rfc3339(&row.updated_at)
				.map_err(|e| SessionsServerError::InvalidData(format!("invalid updated_at: {e}")))?
				.with_timezone(&Utc),
		})
	}
}

#[derive(sqlx::FromRow)]
struct AggregateRow {
	id: String,
	org_id: String,
	project_id: String,
	release: Option<String>,
	environment: String,
	hour: String,
	total_sessions: i64,
	exited_sessions: i64,
	crashed_sessions: i64,
	abnormal_sessions: i64,
	errored_sessions: i64,
	unique_users: i64,
	crashed_users: i64,
	total_duration_ms: i64,
	min_duration_ms: Option<i64>,
	max_duration_ms: Option<i64>,
	total_errors: i64,
	total_crashes: i64,
	updated_at: String,
}

impl TryFrom<AggregateRow> for SessionAggregate {
	type Error = SessionsServerError;

	fn try_from(row: AggregateRow) -> Result<Self> {
		Ok(SessionAggregate {
			id: SessionAggregateId(
				row
					.id
					.parse()
					.map_err(|_| SessionsServerError::InvalidData("invalid aggregate ID".into()))?,
			),
			org_id: row.org_id,
			project_id: row.project_id,
			release: row.release,
			environment: row.environment,
			hour: DateTime::parse_from_rfc3339(&row.hour)
				.map_err(|e| SessionsServerError::InvalidData(format!("invalid hour: {e}")))?
				.with_timezone(&Utc),
			total_sessions: row.total_sessions as u64,
			exited_sessions: row.exited_sessions as u64,
			crashed_sessions: row.crashed_sessions as u64,
			abnormal_sessions: row.abnormal_sessions as u64,
			errored_sessions: row.errored_sessions as u64,
			unique_users: row.unique_users as u64,
			crashed_users: row.crashed_users as u64,
			total_duration_ms: row.total_duration_ms as u64,
			min_duration_ms: row.min_duration_ms.map(|d| d as u64),
			max_duration_ms: row.max_duration_ms.map(|d| d as u64),
			total_errors: row.total_errors as u64,
			total_crashes: row.total_crashes as u64,
			updated_at: DateTime::parse_from_rfc3339(&row.updated_at)
				.map_err(|e| SessionsServerError::InvalidData(format!("invalid updated_at: {e}")))?
				.with_timezone(&Utc),
		})
	}
}

#[async_trait]
impl SessionsRepository for SqliteSessionsRepository {
	#[instrument(skip(self, session), fields(session_id = %session.id))]
	async fn create_session(&self, session: &Session) -> Result<()> {
		sqlx::query(
			r#"
			INSERT INTO app_sessions (
				id, org_id, project_id, person_id, distinct_id,
				status, release, environment,
				error_count, crash_count, crashed,
				started_at, ended_at, duration_ms,
				platform, user_agent,
				sampled, sample_rate,
				created_at, updated_at
			)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
			"#,
		)
		.bind(session.id.to_string())
		.bind(&session.org_id)
		.bind(&session.project_id)
		.bind(&session.person_id)
		.bind(&session.distinct_id)
		.bind(session.status.to_string())
		.bind(&session.release)
		.bind(&session.environment)
		.bind(session.error_count as i32)
		.bind(session.crash_count as i32)
		.bind(if session.crashed { 1 } else { 0 })
		.bind(session.started_at.to_rfc3339())
		.bind(session.ended_at.map(|dt| dt.to_rfc3339()))
		.bind(session.duration_ms.map(|d| d as i64))
		.bind(session.platform.to_string())
		.bind(&session.user_agent)
		.bind(if session.sampled { 1 } else { 0 })
		.bind(session.sample_rate)
		.bind(session.created_at.to_rfc3339())
		.bind(session.updated_at.to_rfc3339())
		.execute(&self.pool)
		.await?;

		Ok(())
	}

	#[instrument(skip(self), fields(session_id = %id))]
	async fn get_session_by_id(&self, id: &SessionId) -> Result<Option<Session>> {
		let row = sqlx::query_as::<_, SessionRow>(
			r#"
			SELECT id, org_id, project_id, person_id, distinct_id,
				   status, release, environment,
				   error_count, crash_count, crashed,
				   started_at, ended_at, duration_ms,
				   platform, user_agent,
				   sampled, sample_rate,
				   created_at, updated_at
			FROM app_sessions
			WHERE id = ?
			"#,
		)
		.bind(id.to_string())
		.fetch_optional(&self.pool)
		.await?;

		row.map(TryInto::try_into).transpose()
	}

	#[instrument(skip(self, session), fields(session_id = %session.id))]
	async fn update_session(&self, session: &Session) -> Result<()> {
		sqlx::query(
			r#"
			UPDATE app_sessions SET
				person_id = ?,
				status = ?,
				error_count = ?,
				crash_count = ?,
				crashed = ?,
				ended_at = ?,
				duration_ms = ?,
				updated_at = ?
			WHERE id = ?
			"#,
		)
		.bind(&session.person_id)
		.bind(session.status.to_string())
		.bind(session.error_count as i32)
		.bind(session.crash_count as i32)
		.bind(if session.crashed { 1 } else { 0 })
		.bind(session.ended_at.map(|dt| dt.to_rfc3339()))
		.bind(session.duration_ms.map(|d| d as i64))
		.bind(session.updated_at.to_rfc3339())
		.bind(session.id.to_string())
		.execute(&self.pool)
		.await?;

		Ok(())
	}

	#[instrument(skip(self), fields(project_id = %project_id))]
	async fn list_sessions(&self, project_id: &str, limit: u32, offset: u32) -> Result<Vec<Session>> {
		let rows = sqlx::query_as::<_, SessionRow>(
			r#"
			SELECT id, org_id, project_id, person_id, distinct_id,
				   status, release, environment,
				   error_count, crash_count, crashed,
				   started_at, ended_at, duration_ms,
				   platform, user_agent,
				   sampled, sample_rate,
				   created_at, updated_at
			FROM app_sessions
			WHERE project_id = ?
			ORDER BY started_at DESC
			LIMIT ? OFFSET ?
			"#,
		)
		.bind(project_id)
		.bind(limit as i32)
		.bind(offset as i32)
		.fetch_all(&self.pool)
		.await?;

		rows.into_iter().map(TryInto::try_into).collect()
	}

	#[instrument(skip(self), fields(project_id = %project_id, release = %release))]
	async fn list_sessions_by_release(
		&self,
		project_id: &str,
		release: &str,
		limit: u32,
	) -> Result<Vec<Session>> {
		let rows = sqlx::query_as::<_, SessionRow>(
			r#"
			SELECT id, org_id, project_id, person_id, distinct_id,
				   status, release, environment,
				   error_count, crash_count, crashed,
				   started_at, ended_at, duration_ms,
				   platform, user_agent,
				   sampled, sample_rate,
				   created_at, updated_at
			FROM app_sessions
			WHERE project_id = ? AND release = ?
			ORDER BY started_at DESC
			LIMIT ?
			"#,
		)
		.bind(project_id)
		.bind(release)
		.bind(limit as i32)
		.fetch_all(&self.pool)
		.await?;

		rows.into_iter().map(TryInto::try_into).collect()
	}

	#[instrument(skip(self), fields(cutoff = %cutoff))]
	async fn delete_old_sessions(&self, cutoff: DateTime<Utc>) -> Result<u64> {
		let result = sqlx::query("DELETE FROM app_sessions WHERE started_at < ?")
			.bind(cutoff.to_rfc3339())
			.execute(&self.pool)
			.await?;

		Ok(result.rows_affected())
	}

	#[instrument(skip(self), fields(session_id = %id, status = %status))]
	async fn end_session(
		&self,
		id: &SessionId,
		status: SessionStatus,
		error_count: u32,
		crash_count: u32,
		ended_at: DateTime<Utc>,
		duration_ms: u64,
	) -> Result<()> {
		let crashed = crash_count > 0;
		let now = Utc::now();

		sqlx::query(
			r#"
			UPDATE app_sessions SET
				status = ?,
				error_count = ?,
				crash_count = ?,
				crashed = ?,
				ended_at = ?,
				duration_ms = ?,
				updated_at = ?
			WHERE id = ?
			"#,
		)
		.bind(status.to_string())
		.bind(error_count as i32)
		.bind(crash_count as i32)
		.bind(if crashed { 1 } else { 0 })
		.bind(ended_at.to_rfc3339())
		.bind(duration_ms as i64)
		.bind(now.to_rfc3339())
		.bind(id.to_string())
		.execute(&self.pool)
		.await?;

		Ok(())
	}

	#[instrument(skip(self, aggregate), fields(aggregate_id = %aggregate.id))]
	async fn upsert_aggregate(&self, aggregate: &SessionAggregate) -> Result<()> {
		sqlx::query(
			r#"
			INSERT INTO app_session_aggregates (
				id, org_id, project_id, release, environment, hour,
				total_sessions, exited_sessions, crashed_sessions, abnormal_sessions, errored_sessions,
				unique_users, crashed_users,
				total_duration_ms, min_duration_ms, max_duration_ms,
				total_errors, total_crashes,
				updated_at
			)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT(project_id, release, environment, hour) DO UPDATE SET
				total_sessions = excluded.total_sessions,
				exited_sessions = excluded.exited_sessions,
				crashed_sessions = excluded.crashed_sessions,
				abnormal_sessions = excluded.abnormal_sessions,
				errored_sessions = excluded.errored_sessions,
				unique_users = excluded.unique_users,
				crashed_users = excluded.crashed_users,
				total_duration_ms = excluded.total_duration_ms,
				min_duration_ms = excluded.min_duration_ms,
				max_duration_ms = excluded.max_duration_ms,
				total_errors = excluded.total_errors,
				total_crashes = excluded.total_crashes,
				updated_at = excluded.updated_at
			"#,
		)
		.bind(aggregate.id.to_string())
		.bind(&aggregate.org_id)
		.bind(&aggregate.project_id)
		.bind(&aggregate.release)
		.bind(&aggregate.environment)
		.bind(aggregate.hour.to_rfc3339())
		.bind(aggregate.total_sessions as i64)
		.bind(aggregate.exited_sessions as i64)
		.bind(aggregate.crashed_sessions as i64)
		.bind(aggregate.abnormal_sessions as i64)
		.bind(aggregate.errored_sessions as i64)
		.bind(aggregate.unique_users as i64)
		.bind(aggregate.crashed_users as i64)
		.bind(aggregate.total_duration_ms as i64)
		.bind(aggregate.min_duration_ms.map(|d| d as i64))
		.bind(aggregate.max_duration_ms.map(|d| d as i64))
		.bind(aggregate.total_errors as i64)
		.bind(aggregate.total_crashes as i64)
		.bind(aggregate.updated_at.to_rfc3339())
		.execute(&self.pool)
		.await?;

		Ok(())
	}

	#[instrument(skip(self), fields(project_id = %project_id))]
	async fn get_aggregates(
		&self,
		project_id: &str,
		release: Option<&str>,
		environment: &str,
		start: DateTime<Utc>,
		end: DateTime<Utc>,
	) -> Result<Vec<SessionAggregate>> {
		let rows = if let Some(rel) = release {
			sqlx::query_as::<_, AggregateRow>(
				r#"
				SELECT id, org_id, project_id, release, environment, hour,
					   total_sessions, exited_sessions, crashed_sessions, abnormal_sessions, errored_sessions,
					   unique_users, crashed_users,
					   total_duration_ms, min_duration_ms, max_duration_ms,
					   total_errors, total_crashes,
					   updated_at
				FROM app_session_aggregates
				WHERE project_id = ? AND release = ? AND environment = ?
				  AND hour >= ? AND hour < ?
				ORDER BY hour ASC
				"#,
			)
			.bind(project_id)
			.bind(rel)
			.bind(environment)
			.bind(start.to_rfc3339())
			.bind(end.to_rfc3339())
			.fetch_all(&self.pool)
			.await?
		} else {
			sqlx::query_as::<_, AggregateRow>(
				r#"
				SELECT id, org_id, project_id, release, environment, hour,
					   total_sessions, exited_sessions, crashed_sessions, abnormal_sessions, errored_sessions,
					   unique_users, crashed_users,
					   total_duration_ms, min_duration_ms, max_duration_ms,
					   total_errors, total_crashes,
					   updated_at
				FROM app_session_aggregates
				WHERE project_id = ? AND environment = ?
				  AND hour >= ? AND hour < ?
				ORDER BY hour ASC
				"#,
			)
			.bind(project_id)
			.bind(environment)
			.bind(start.to_rfc3339())
			.bind(end.to_rfc3339())
			.fetch_all(&self.pool)
			.await?
		};

		rows.into_iter().map(TryInto::try_into).collect()
	}

	#[instrument(skip(self), fields(project_id = %project_id))]
	async fn get_total_sessions_in_range(
		&self,
		project_id: &str,
		environment: &str,
		start: DateTime<Utc>,
		end: DateTime<Utc>,
	) -> Result<u64> {
		let row: (i64,) = sqlx::query_as(
			r#"
			SELECT COALESCE(SUM(total_sessions), 0)
			FROM app_session_aggregates
			WHERE project_id = ? AND environment = ?
			  AND hour >= ? AND hour < ?
			"#,
		)
		.bind(project_id)
		.bind(environment)
		.bind(start.to_rfc3339())
		.bind(end.to_rfc3339())
		.fetch_one(&self.pool)
		.await?;

		Ok(row.0 as u64)
	}

	#[instrument(skip(self), fields(project_id = %project_id))]
	async fn get_releases(&self, project_id: &str, environment: &str) -> Result<Vec<String>> {
		let rows: Vec<(String,)> = sqlx::query_as(
			r#"
			SELECT DISTINCT release
			FROM app_session_aggregates
			WHERE project_id = ? AND environment = ? AND release IS NOT NULL
			ORDER BY release DESC
			"#,
		)
		.bind(project_id)
		.bind(environment)
		.fetch_all(&self.pool)
		.await?;

		Ok(rows.into_iter().map(|(r,)| r).collect())
	}

	#[instrument(skip(self), fields(hour_start = %hour_start, hour_end = %hour_end))]
	async fn get_sessions_for_aggregation(
		&self,
		hour_start: DateTime<Utc>,
		hour_end: DateTime<Utc>,
	) -> Result<Vec<Session>> {
		let rows = sqlx::query_as::<_, SessionRow>(
			r#"
			SELECT id, org_id, project_id, person_id, distinct_id,
				   status, release, environment,
				   error_count, crash_count, crashed,
				   started_at, ended_at, duration_ms,
				   platform, user_agent,
				   sampled, sample_rate,
				   created_at, updated_at
			FROM app_sessions
			WHERE started_at >= ? AND started_at < ?
			"#,
		)
		.bind(hour_start.to_rfc3339())
		.bind(hour_end.to_rfc3339())
		.fetch_all(&self.pool)
		.await?;

		rows.into_iter().map(TryInto::try_into).collect()
	}
}
