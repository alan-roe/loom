// Copyright (c) 2025 Geoffrey Huntley <ghuntley@ghuntley.com>. All rights reserved.
// SPDX-License-Identifier: Proprietary

//! Repository layer for crash database operations.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::SqlitePool;
use tracing::instrument;

use loom_crash_core::{
	CrashApiKey, CrashApiKeyId, CrashEvent, CrashEventId, CrashProject, Issue, IssueId, OrgId,
	PersonId, ProjectId, Release, ReleaseId, SymbolArtifact, SymbolArtifactId, UserId,
};

use crate::error::{CrashServerError, Result};

/// Repository trait for crash operations.
#[async_trait]
pub trait CrashRepository: Send + Sync {
	// Project operations
	async fn create_project(&self, project: &CrashProject) -> Result<()>;
	async fn get_project_by_id(&self, id: ProjectId) -> Result<Option<CrashProject>>;
	async fn get_project_by_slug(&self, org_id: OrgId, slug: &str) -> Result<Option<CrashProject>>;
	async fn list_projects(&self, org_id: OrgId) -> Result<Vec<CrashProject>>;
	async fn update_project(&self, project: &CrashProject) -> Result<()>;
	async fn delete_project(&self, id: ProjectId) -> Result<bool>;

	// Issue operations
	async fn create_issue(&self, issue: &Issue) -> Result<()>;
	async fn get_issue_by_id(&self, id: IssueId) -> Result<Option<Issue>>;
	async fn get_issue_by_fingerprint(
		&self,
		project_id: ProjectId,
		fingerprint: &str,
	) -> Result<Option<Issue>>;
	async fn list_issues(&self, project_id: ProjectId, limit: u32) -> Result<Vec<Issue>>;
	async fn get_issue_count(&self, project_id: ProjectId) -> Result<u64>;
	async fn update_issue(&self, issue: &Issue) -> Result<()>;
	async fn delete_issue(&self, id: IssueId) -> Result<bool>;

	// Event operations
	async fn create_event(&self, event: &CrashEvent) -> Result<()>;
	async fn get_event_by_id(&self, id: CrashEventId) -> Result<Option<CrashEvent>>;
	async fn list_events_for_issue(&self, issue_id: IssueId, limit: u32) -> Result<Vec<CrashEvent>>;
	async fn delete_old_events(&self, cutoff: DateTime<Utc>) -> Result<u64>;

	// Issue state updates
	async fn increment_issue_event_count(&self, id: IssueId) -> Result<()>;
	async fn add_issue_person(&self, issue_id: IssueId, person_id: PersonId) -> Result<()>;
	async fn issue_has_person(&self, issue_id: IssueId, person_id: PersonId) -> Result<bool>;

	// Short ID generation
	async fn get_next_short_id(&self, project_id: ProjectId) -> Result<String>;

	// Release operations
	async fn create_release(&self, release: &Release) -> Result<()>;
	async fn get_release_by_id(&self, id: ReleaseId) -> Result<Option<Release>>;
	async fn get_release_by_version(
		&self,
		project_id: ProjectId,
		version: &str,
	) -> Result<Option<Release>>;
	async fn list_releases(&self, project_id: ProjectId, limit: u32) -> Result<Vec<Release>>;
	async fn update_release(&self, release: &Release) -> Result<()>;
	async fn get_or_create_release(
		&self,
		project_id: ProjectId,
		org_id: OrgId,
		version: &str,
	) -> Result<Release>;
	async fn increment_release_crash_count(
		&self,
		project_id: ProjectId,
		version: &str,
		is_new_issue: bool,
		is_regression: bool,
	) -> Result<()>;

	// Artifact operations
	async fn create_artifact(&self, artifact: &SymbolArtifact) -> Result<()>;
	async fn get_artifact_by_id(&self, id: SymbolArtifactId) -> Result<Option<SymbolArtifact>>;
	async fn get_artifact_by_sha256(
		&self,
		project_id: ProjectId,
		sha256: &str,
	) -> Result<Option<SymbolArtifact>>;
	async fn get_artifact_by_name(
		&self,
		project_id: ProjectId,
		release: &str,
		name: &str,
		dist: Option<&str>,
	) -> Result<Option<SymbolArtifact>>;
	async fn list_artifacts(
		&self,
		project_id: ProjectId,
		release: Option<&str>,
		limit: u32,
	) -> Result<Vec<SymbolArtifact>>;
	async fn delete_artifact(&self, id: SymbolArtifactId) -> Result<bool>;
	async fn delete_old_artifacts(&self, cutoff: DateTime<Utc>) -> Result<u64>;
	async fn update_artifact_last_accessed(&self, id: SymbolArtifactId) -> Result<()>;

	// API key operations
	async fn create_api_key(&self, api_key: &CrashApiKey) -> Result<()>;
	async fn get_api_key_by_id(&self, id: CrashApiKeyId) -> Result<Option<CrashApiKey>>;
	async fn get_api_key_by_hash(&self, key_hash: &str) -> Result<Option<CrashApiKey>>;
	async fn list_api_keys(&self, project_id: ProjectId) -> Result<Vec<CrashApiKey>>;
	async fn revoke_api_key(&self, id: CrashApiKeyId) -> Result<bool>;
	async fn update_api_key_last_used(&self, id: CrashApiKeyId) -> Result<()>;
}

/// SQLite implementation of the crash repository.
#[derive(Clone)]
pub struct SqliteCrashRepository {
	pool: SqlitePool,
}

impl SqliteCrashRepository {
	pub fn new(pool: SqlitePool) -> Self {
		Self { pool }
	}
}

#[async_trait]
impl CrashRepository for SqliteCrashRepository {
	#[instrument(skip(self, project), fields(project_id = %project.id, slug = %project.slug))]
	async fn create_project(&self, project: &CrashProject) -> Result<()> {
		let fingerprint_rules_json = serde_json::to_string(&project.fingerprint_rules)?;

		sqlx::query(
			r#"
			INSERT INTO crash_projects (
				id, org_id, name, slug, platform,
				auto_resolve_age_days, fingerprint_rules,
				created_at, updated_at
			)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
			"#,
		)
		.bind(project.id.0.to_string())
		.bind(project.org_id.0.to_string())
		.bind(&project.name)
		.bind(&project.slug)
		.bind(project.platform.to_string())
		.bind(project.auto_resolve_age_days.map(|d| d as i32))
		.bind(fingerprint_rules_json)
		.bind(project.created_at.to_rfc3339())
		.bind(project.updated_at.to_rfc3339())
		.execute(&self.pool)
		.await?;

		Ok(())
	}

	#[instrument(skip(self), fields(project_id = %id))]
	async fn get_project_by_id(&self, id: ProjectId) -> Result<Option<CrashProject>> {
		let row = sqlx::query_as::<_, ProjectRow>(
			r#"
			SELECT id, org_id, name, slug, platform,
				   auto_resolve_age_days, fingerprint_rules,
				   created_at, updated_at
			FROM crash_projects
			WHERE id = ?
			"#,
		)
		.bind(id.0.to_string())
		.fetch_optional(&self.pool)
		.await?;

		row.map(TryInto::try_into).transpose()
	}

	#[instrument(skip(self), fields(org_id = %org_id, slug = %slug))]
	async fn get_project_by_slug(&self, org_id: OrgId, slug: &str) -> Result<Option<CrashProject>> {
		let row = sqlx::query_as::<_, ProjectRow>(
			r#"
			SELECT id, org_id, name, slug, platform,
				   auto_resolve_age_days, fingerprint_rules,
				   created_at, updated_at
			FROM crash_projects
			WHERE org_id = ? AND slug = ?
			"#,
		)
		.bind(org_id.0.to_string())
		.bind(slug)
		.fetch_optional(&self.pool)
		.await?;

		row.map(TryInto::try_into).transpose()
	}

	#[instrument(skip(self), fields(org_id = %org_id))]
	async fn list_projects(&self, org_id: OrgId) -> Result<Vec<CrashProject>> {
		let rows = sqlx::query_as::<_, ProjectRow>(
			r#"
			SELECT id, org_id, name, slug, platform,
				   auto_resolve_age_days, fingerprint_rules,
				   created_at, updated_at
			FROM crash_projects
			WHERE org_id = ?
			ORDER BY name
			"#,
		)
		.bind(org_id.0.to_string())
		.fetch_all(&self.pool)
		.await?;

		rows.into_iter().map(TryInto::try_into).collect()
	}

	#[instrument(skip(self, project), fields(project_id = %project.id))]
	async fn update_project(&self, project: &CrashProject) -> Result<()> {
		sqlx::query(
			r#"
			UPDATE crash_projects
			SET name = ?, auto_resolve_age_days = ?, updated_at = ?
			WHERE id = ?
			"#,
		)
		.bind(&project.name)
		.bind(project.auto_resolve_age_days.map(|d| d as i32))
		.bind(project.updated_at.to_rfc3339())
		.bind(project.id.0.to_string())
		.execute(&self.pool)
		.await?;

		Ok(())
	}

	#[instrument(skip(self), fields(project_id = %id))]
	async fn delete_project(&self, id: ProjectId) -> Result<bool> {
		let result = sqlx::query("DELETE FROM crash_projects WHERE id = ?")
			.bind(id.0.to_string())
			.execute(&self.pool)
			.await?;

		Ok(result.rows_affected() > 0)
	}

	#[instrument(skip(self, issue), fields(issue_id = %issue.id, fingerprint = %issue.fingerprint))]
	async fn create_issue(&self, issue: &Issue) -> Result<()> {
		let metadata_json = serde_json::to_string(&issue.metadata)?;

		sqlx::query(
			r#"
			INSERT INTO crash_issues (
				id, org_id, project_id, short_id, fingerprint,
				title, culprit, metadata,
				status, level, priority,
				event_count, user_count,
				first_seen, last_seen,
				resolved_at, resolved_by, resolved_in_release,
				times_regressed, last_regressed_at, regressed_in_release,
				assigned_to, created_at, updated_at
			)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
			"#,
		)
		.bind(issue.id.0.to_string())
		.bind(issue.org_id.0.to_string())
		.bind(issue.project_id.0.to_string())
		.bind(&issue.short_id)
		.bind(&issue.fingerprint)
		.bind(&issue.title)
		.bind(&issue.culprit)
		.bind(metadata_json)
		.bind(issue.status.to_string())
		.bind(issue.level.to_string())
		.bind(issue.priority.to_string())
		.bind(issue.event_count as i64)
		.bind(issue.user_count as i64)
		.bind(issue.first_seen.to_rfc3339())
		.bind(issue.last_seen.to_rfc3339())
		.bind(issue.resolved_at.map(|dt| dt.to_rfc3339()))
		.bind(issue.resolved_by.map(|u| u.0.to_string()))
		.bind(&issue.resolved_in_release)
		.bind(issue.times_regressed as i32)
		.bind(issue.last_regressed_at.map(|dt| dt.to_rfc3339()))
		.bind(&issue.regressed_in_release)
		.bind(issue.assigned_to.map(|u| u.0.to_string()))
		.bind(issue.created_at.to_rfc3339())
		.bind(issue.updated_at.to_rfc3339())
		.execute(&self.pool)
		.await?;

		Ok(())
	}

	#[instrument(skip(self), fields(issue_id = %id))]
	async fn get_issue_by_id(&self, id: IssueId) -> Result<Option<Issue>> {
		let row = sqlx::query_as::<_, IssueRow>(
			r#"
			SELECT id, org_id, project_id, short_id, fingerprint,
				   title, culprit, metadata,
				   status, level, priority,
				   event_count, user_count,
				   first_seen, last_seen,
				   resolved_at, resolved_by, resolved_in_release,
				   times_regressed, last_regressed_at, regressed_in_release,
				   assigned_to, created_at, updated_at
			FROM crash_issues
			WHERE id = ?
			"#,
		)
		.bind(id.0.to_string())
		.fetch_optional(&self.pool)
		.await?;

		row.map(TryInto::try_into).transpose()
	}

	#[instrument(skip(self), fields(project_id = %project_id))]
	async fn get_issue_by_fingerprint(
		&self,
		project_id: ProjectId,
		fingerprint: &str,
	) -> Result<Option<Issue>> {
		let row = sqlx::query_as::<_, IssueRow>(
			r#"
			SELECT id, org_id, project_id, short_id, fingerprint,
				   title, culprit, metadata,
				   status, level, priority,
				   event_count, user_count,
				   first_seen, last_seen,
				   resolved_at, resolved_by, resolved_in_release,
				   times_regressed, last_regressed_at, regressed_in_release,
				   assigned_to, created_at, updated_at
			FROM crash_issues
			WHERE project_id = ? AND fingerprint = ?
			"#,
		)
		.bind(project_id.0.to_string())
		.bind(fingerprint)
		.fetch_optional(&self.pool)
		.await?;

		row.map(TryInto::try_into).transpose()
	}

	#[instrument(skip(self), fields(project_id = %project_id))]
	async fn list_issues(&self, project_id: ProjectId, limit: u32) -> Result<Vec<Issue>> {
		let rows = sqlx::query_as::<_, IssueRow>(
			r#"
			SELECT id, org_id, project_id, short_id, fingerprint,
				   title, culprit, metadata,
				   status, level, priority,
				   event_count, user_count,
				   first_seen, last_seen,
				   resolved_at, resolved_by, resolved_in_release,
				   times_regressed, last_regressed_at, regressed_in_release,
				   assigned_to, created_at, updated_at
			FROM crash_issues
			WHERE project_id = ?
			ORDER BY last_seen DESC
			LIMIT ?
			"#,
		)
		.bind(project_id.0.to_string())
		.bind(limit as i32)
		.fetch_all(&self.pool)
		.await?;

		rows.into_iter().map(TryInto::try_into).collect()
	}

	#[instrument(skip(self), fields(project_id = %project_id))]
	async fn get_issue_count(&self, project_id: ProjectId) -> Result<u64> {
		let count = sqlx::query_scalar::<_, i64>(
			r#"
			SELECT COUNT(*) FROM crash_issues WHERE project_id = ?
			"#,
		)
		.bind(project_id.0.to_string())
		.fetch_one(&self.pool)
		.await?;

		Ok(count as u64)
	}

	#[instrument(skip(self, issue), fields(issue_id = %issue.id))]
	async fn update_issue(&self, issue: &Issue) -> Result<()> {
		let metadata_json = serde_json::to_string(&issue.metadata)?;

		sqlx::query(
			r#"
			UPDATE crash_issues SET
				title = ?, culprit = ?, metadata = ?,
				status = ?, level = ?, priority = ?,
				event_count = ?, user_count = ?,
				last_seen = ?,
				resolved_at = ?, resolved_by = ?, resolved_in_release = ?,
				times_regressed = ?, last_regressed_at = ?, regressed_in_release = ?,
				assigned_to = ?, updated_at = ?
			WHERE id = ?
			"#,
		)
		.bind(&issue.title)
		.bind(&issue.culprit)
		.bind(metadata_json)
		.bind(issue.status.to_string())
		.bind(issue.level.to_string())
		.bind(issue.priority.to_string())
		.bind(issue.event_count as i64)
		.bind(issue.user_count as i64)
		.bind(issue.last_seen.to_rfc3339())
		.bind(issue.resolved_at.map(|dt| dt.to_rfc3339()))
		.bind(issue.resolved_by.map(|u| u.0.to_string()))
		.bind(&issue.resolved_in_release)
		.bind(issue.times_regressed as i32)
		.bind(issue.last_regressed_at.map(|dt| dt.to_rfc3339()))
		.bind(&issue.regressed_in_release)
		.bind(issue.assigned_to.map(|u| u.0.to_string()))
		.bind(Utc::now().to_rfc3339())
		.bind(issue.id.0.to_string())
		.execute(&self.pool)
		.await?;

		Ok(())
	}

	#[instrument(skip(self), fields(issue_id = %id))]
	async fn delete_issue(&self, id: IssueId) -> Result<bool> {
		let result = sqlx::query("DELETE FROM crash_issues WHERE id = ?")
			.bind(id.0.to_string())
			.execute(&self.pool)
			.await?;

		Ok(result.rows_affected() > 0)
	}

	#[instrument(skip(self, event), fields(event_id = %event.id, exception_type = %event.exception_type))]
	async fn create_event(&self, event: &CrashEvent) -> Result<()> {
		let stacktrace_json = serde_json::to_string(&event.stacktrace)?;
		let raw_stacktrace_json = event
			.raw_stacktrace
			.as_ref()
			.map(|s| serde_json::to_string(s))
			.transpose()?;
		let runtime_json = event
			.runtime
			.as_ref()
			.map(|r| serde_json::to_string(r))
			.transpose()?;
		let tags_json = serde_json::to_string(&event.tags)?;
		let extra_json = serde_json::to_string(&event.extra)?;
		let user_context_json = event
			.user_context
			.as_ref()
			.map(|c| serde_json::to_string(c))
			.transpose()?;
		let device_context_json = event
			.device_context
			.as_ref()
			.map(|c| serde_json::to_string(c))
			.transpose()?;
		let browser_context_json = event
			.browser_context
			.as_ref()
			.map(|c| serde_json::to_string(c))
			.transpose()?;
		let os_context_json = event
			.os_context
			.as_ref()
			.map(|c| serde_json::to_string(c))
			.transpose()?;
		let active_flags_json = serde_json::to_string(&event.active_flags)?;
		let request_json = event
			.request
			.as_ref()
			.map(|r| serde_json::to_string(r))
			.transpose()?;
		let breadcrumbs_json = serde_json::to_string(&event.breadcrumbs)?;

		sqlx::query(
			r#"
			INSERT INTO crash_events (
				id, org_id, project_id, issue_id,
				person_id, distinct_id,
				exception_type, exception_value, stacktrace, raw_stacktrace,
				release, dist, environment, platform, runtime, server_name,
				tags, extra, user_context, device_context, browser_context, os_context,
				active_flags, request, breadcrumbs,
				timestamp, received_at
			)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
			"#,
		)
		.bind(event.id.0.to_string())
		.bind(event.org_id.0.to_string())
		.bind(event.project_id.0.to_string())
		.bind(event.issue_id.map(|i| i.0.to_string()))
		.bind(event.person_id.map(|p| p.0.to_string()))
		.bind(&event.distinct_id)
		.bind(&event.exception_type)
		.bind(&event.exception_value)
		.bind(stacktrace_json)
		.bind(raw_stacktrace_json)
		.bind(&event.release)
		.bind(&event.dist)
		.bind(&event.environment)
		.bind(event.platform.to_string())
		.bind(runtime_json)
		.bind(&event.server_name)
		.bind(tags_json)
		.bind(extra_json)
		.bind(user_context_json)
		.bind(device_context_json)
		.bind(browser_context_json)
		.bind(os_context_json)
		.bind(active_flags_json)
		.bind(request_json)
		.bind(breadcrumbs_json)
		.bind(event.timestamp.to_rfc3339())
		.bind(event.received_at.to_rfc3339())
		.execute(&self.pool)
		.await?;

		Ok(())
	}

	#[instrument(skip(self), fields(event_id = %id))]
	async fn get_event_by_id(&self, id: CrashEventId) -> Result<Option<CrashEvent>> {
		let row = sqlx::query_as::<_, EventRow>(
			r#"
			SELECT id, org_id, project_id, issue_id,
				   person_id, distinct_id,
				   exception_type, exception_value, stacktrace, raw_stacktrace,
				   release, dist, environment, platform, runtime, server_name,
				   tags, extra, user_context, device_context, browser_context, os_context,
				   active_flags, request, breadcrumbs,
				   timestamp, received_at
			FROM crash_events
			WHERE id = ?
			"#,
		)
		.bind(id.0.to_string())
		.fetch_optional(&self.pool)
		.await?;

		row.map(TryInto::try_into).transpose()
	}

	#[instrument(skip(self), fields(issue_id = %issue_id))]
	async fn list_events_for_issue(&self, issue_id: IssueId, limit: u32) -> Result<Vec<CrashEvent>> {
		let rows = sqlx::query_as::<_, EventRow>(
			r#"
			SELECT id, org_id, project_id, issue_id,
				   person_id, distinct_id,
				   exception_type, exception_value, stacktrace, raw_stacktrace,
				   release, dist, environment, platform, runtime, server_name,
				   tags, extra, user_context, device_context, browser_context, os_context,
				   active_flags, request, breadcrumbs,
				   timestamp, received_at
			FROM crash_events
			WHERE issue_id = ?
			ORDER BY timestamp DESC
			LIMIT ?
			"#,
		)
		.bind(issue_id.0.to_string())
		.bind(limit as i32)
		.fetch_all(&self.pool)
		.await?;

		rows.into_iter().map(TryInto::try_into).collect()
	}

	#[instrument(skip(self), fields(cutoff = %cutoff))]
	async fn delete_old_events(&self, cutoff: DateTime<Utc>) -> Result<u64> {
		let result = sqlx::query(
			r#"
			DELETE FROM crash_events
			WHERE received_at < ?
			"#,
		)
		.bind(cutoff.to_rfc3339())
		.execute(&self.pool)
		.await?;

		Ok(result.rows_affected())
	}

	#[instrument(skip(self), fields(issue_id = %id))]
	async fn increment_issue_event_count(&self, id: IssueId) -> Result<()> {
		sqlx::query(
			r#"
			UPDATE crash_issues SET
				event_count = event_count + 1,
				last_seen = ?,
				updated_at = ?
			WHERE id = ?
			"#,
		)
		.bind(Utc::now().to_rfc3339())
		.bind(Utc::now().to_rfc3339())
		.bind(id.0.to_string())
		.execute(&self.pool)
		.await?;

		Ok(())
	}

	#[instrument(skip(self), fields(issue_id = %issue_id, person_id = %person_id))]
	async fn add_issue_person(&self, issue_id: IssueId, person_id: PersonId) -> Result<()> {
		sqlx::query(
			r#"
			INSERT OR IGNORE INTO crash_issue_persons (issue_id, person_id, first_seen)
			VALUES (?, ?, ?)
			"#,
		)
		.bind(issue_id.0.to_string())
		.bind(person_id.0.to_string())
		.bind(Utc::now().to_rfc3339())
		.execute(&self.pool)
		.await?;

		// Update user_count
		sqlx::query(
			r#"
			UPDATE crash_issues SET
				user_count = (SELECT COUNT(*) FROM crash_issue_persons WHERE issue_id = ?),
				updated_at = ?
			WHERE id = ?
			"#,
		)
		.bind(issue_id.0.to_string())
		.bind(Utc::now().to_rfc3339())
		.bind(issue_id.0.to_string())
		.execute(&self.pool)
		.await?;

		Ok(())
	}

	#[instrument(skip(self), fields(issue_id = %issue_id, person_id = %person_id))]
	async fn issue_has_person(&self, issue_id: IssueId, person_id: PersonId) -> Result<bool> {
		let row = sqlx::query_scalar::<_, i32>(
			r#"
			SELECT COUNT(*) FROM crash_issue_persons
			WHERE issue_id = ? AND person_id = ?
			"#,
		)
		.bind(issue_id.0.to_string())
		.bind(person_id.0.to_string())
		.fetch_one(&self.pool)
		.await?;

		Ok(row > 0)
	}

	#[instrument(skip(self), fields(project_id = %project_id))]
	async fn get_next_short_id(&self, project_id: ProjectId) -> Result<String> {
		// Get project slug for the short ID prefix
		let project = self
			.get_project_by_id(project_id)
			.await?
			.ok_or_else(|| CrashServerError::ProjectNotFound(project_id.to_string()))?;

		// Count existing issues for this project
		let count = sqlx::query_scalar::<_, i32>(
			r#"
			SELECT COUNT(*) FROM crash_issues WHERE project_id = ?
			"#,
		)
		.bind(project_id.0.to_string())
		.fetch_one(&self.pool)
		.await?;

		// Generate short ID like "PROJ-123"
		let prefix = project.slug.to_uppercase();
		let prefix = if prefix.len() > 4 {
			&prefix[..4]
		} else {
			&prefix
		};

		Ok(format!("{}-{}", prefix, count + 1))
	}

	#[instrument(skip(self, release), fields(release_id = %release.id, version = %release.version))]
	async fn create_release(&self, release: &Release) -> Result<()> {
		sqlx::query(
			r#"
			INSERT INTO crash_releases (
				id, org_id, project_id, version, short_version, url,
				crash_count, new_issue_count, regression_count, user_count,
				date_released, first_event, last_event, created_at
			)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
			"#,
		)
		.bind(release.id.0.to_string())
		.bind(release.org_id.0.to_string())
		.bind(release.project_id.0.to_string())
		.bind(&release.version)
		.bind(&release.short_version)
		.bind(&release.url)
		.bind(release.crash_count as i64)
		.bind(release.new_issue_count as i64)
		.bind(release.regression_count as i64)
		.bind(release.user_count as i64)
		.bind(release.date_released.map(|dt| dt.to_rfc3339()))
		.bind(release.first_event.map(|dt| dt.to_rfc3339()))
		.bind(release.last_event.map(|dt| dt.to_rfc3339()))
		.bind(release.created_at.to_rfc3339())
		.execute(&self.pool)
		.await?;

		Ok(())
	}

	#[instrument(skip(self), fields(release_id = %id))]
	async fn get_release_by_id(&self, id: ReleaseId) -> Result<Option<Release>> {
		let row = sqlx::query_as::<_, ReleaseRow>(
			r#"
			SELECT id, org_id, project_id, version, short_version, url,
				   crash_count, new_issue_count, regression_count, user_count,
				   date_released, first_event, last_event, created_at
			FROM crash_releases
			WHERE id = ?
			"#,
		)
		.bind(id.0.to_string())
		.fetch_optional(&self.pool)
		.await?;

		row.map(TryInto::try_into).transpose()
	}

	#[instrument(skip(self), fields(project_id = %project_id, version = %version))]
	async fn get_release_by_version(
		&self,
		project_id: ProjectId,
		version: &str,
	) -> Result<Option<Release>> {
		let row = sqlx::query_as::<_, ReleaseRow>(
			r#"
			SELECT id, org_id, project_id, version, short_version, url,
				   crash_count, new_issue_count, regression_count, user_count,
				   date_released, first_event, last_event, created_at
			FROM crash_releases
			WHERE project_id = ? AND version = ?
			"#,
		)
		.bind(project_id.0.to_string())
		.bind(version)
		.fetch_optional(&self.pool)
		.await?;

		row.map(TryInto::try_into).transpose()
	}

	#[instrument(skip(self), fields(project_id = %project_id))]
	async fn list_releases(&self, project_id: ProjectId, limit: u32) -> Result<Vec<Release>> {
		let rows = sqlx::query_as::<_, ReleaseRow>(
			r#"
			SELECT id, org_id, project_id, version, short_version, url,
				   crash_count, new_issue_count, regression_count, user_count,
				   date_released, first_event, last_event, created_at
			FROM crash_releases
			WHERE project_id = ?
			ORDER BY created_at DESC
			LIMIT ?
			"#,
		)
		.bind(project_id.0.to_string())
		.bind(limit as i32)
		.fetch_all(&self.pool)
		.await?;

		rows.into_iter().map(TryInto::try_into).collect()
	}

	#[instrument(skip(self, release), fields(release_id = %release.id))]
	async fn update_release(&self, release: &Release) -> Result<()> {
		sqlx::query(
			r#"
			UPDATE crash_releases SET
				short_version = ?, url = ?,
				crash_count = ?, new_issue_count = ?, regression_count = ?, user_count = ?,
				date_released = ?, first_event = ?, last_event = ?
			WHERE id = ?
			"#,
		)
		.bind(&release.short_version)
		.bind(&release.url)
		.bind(release.crash_count as i64)
		.bind(release.new_issue_count as i64)
		.bind(release.regression_count as i64)
		.bind(release.user_count as i64)
		.bind(release.date_released.map(|dt| dt.to_rfc3339()))
		.bind(release.first_event.map(|dt| dt.to_rfc3339()))
		.bind(release.last_event.map(|dt| dt.to_rfc3339()))
		.bind(release.id.0.to_string())
		.execute(&self.pool)
		.await?;

		Ok(())
	}

	#[instrument(skip(self), fields(project_id = %project_id, org_id = %org_id, version = %version))]
	async fn get_or_create_release(
		&self,
		project_id: ProjectId,
		org_id: OrgId,
		version: &str,
	) -> Result<Release> {
		// Try to get existing release
		if let Some(release) = self.get_release_by_version(project_id, version).await? {
			return Ok(release);
		}

		// Create new release
		let release = Release {
			id: ReleaseId::new(),
			org_id,
			project_id,
			version: version.to_string(),
			short_version: None,
			url: None,
			crash_count: 0,
			new_issue_count: 0,
			regression_count: 0,
			user_count: 0,
			date_released: None,
			first_event: None,
			last_event: None,
			created_at: Utc::now(),
		};

		self.create_release(&release).await?;
		Ok(release)
	}

	#[instrument(skip(self), fields(project_id = %project_id, version = %version))]
	async fn increment_release_crash_count(
		&self,
		project_id: ProjectId,
		version: &str,
		is_new_issue: bool,
		is_regression: bool,
	) -> Result<()> {
		let now = Utc::now().to_rfc3339();

		// Update crash count and optionally new_issue_count/regression_count
		let mut query = String::from(
			r#"
			UPDATE crash_releases SET
				crash_count = crash_count + 1,
				last_event = ?,
				first_event = COALESCE(first_event, ?)
			"#,
		);

		if is_new_issue {
			query.push_str(", new_issue_count = new_issue_count + 1");
		}

		if is_regression {
			query.push_str(", regression_count = regression_count + 1");
		}

		query.push_str(" WHERE project_id = ? AND version = ?");

		sqlx::query(&query)
			.bind(&now)
			.bind(&now)
			.bind(project_id.0.to_string())
			.bind(version)
			.execute(&self.pool)
			.await?;

		Ok(())
	}

	#[instrument(skip(self, artifact), fields(artifact_id = %artifact.id, name = %artifact.name))]
	async fn create_artifact(&self, artifact: &SymbolArtifact) -> Result<()> {
		sqlx::query(
			r#"
			INSERT INTO symbol_artifacts (
				id, org_id, project_id, release, dist,
				artifact_type, name, data, size_bytes, sha256,
				source_map_url, sources_content,
				uploaded_at, uploaded_by, last_accessed_at
			)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
			"#,
		)
		.bind(artifact.id.0.to_string())
		.bind(artifact.org_id.0.to_string())
		.bind(artifact.project_id.0.to_string())
		.bind(&artifact.release)
		.bind(&artifact.dist)
		.bind(artifact.artifact_type.to_string())
		.bind(&artifact.name)
		.bind(&artifact.data)
		.bind(artifact.size_bytes as i64)
		.bind(&artifact.sha256)
		.bind(&artifact.source_map_url)
		.bind(artifact.sources_content as i32)
		.bind(artifact.uploaded_at.to_rfc3339())
		.bind(artifact.uploaded_by.0.to_string())
		.bind(artifact.last_accessed_at.map(|dt| dt.to_rfc3339()))
		.execute(&self.pool)
		.await?;

		Ok(())
	}

	#[instrument(skip(self), fields(artifact_id = %id))]
	async fn get_artifact_by_id(&self, id: SymbolArtifactId) -> Result<Option<SymbolArtifact>> {
		let row = sqlx::query_as::<_, ArtifactRow>(
			r#"
			SELECT id, org_id, project_id, release, dist,
				   artifact_type, name, data, size_bytes, sha256,
				   source_map_url, sources_content,
				   uploaded_at, uploaded_by, last_accessed_at
			FROM symbol_artifacts
			WHERE id = ?
			"#,
		)
		.bind(id.0.to_string())
		.fetch_optional(&self.pool)
		.await?;

		row.map(TryInto::try_into).transpose()
	}

	#[instrument(skip(self), fields(project_id = %project_id, sha256 = %sha256))]
	async fn get_artifact_by_sha256(
		&self,
		project_id: ProjectId,
		sha256: &str,
	) -> Result<Option<SymbolArtifact>> {
		let row = sqlx::query_as::<_, ArtifactRow>(
			r#"
			SELECT id, org_id, project_id, release, dist,
				   artifact_type, name, data, size_bytes, sha256,
				   source_map_url, sources_content,
				   uploaded_at, uploaded_by, last_accessed_at
			FROM symbol_artifacts
			WHERE project_id = ? AND sha256 = ?
			"#,
		)
		.bind(project_id.0.to_string())
		.bind(sha256)
		.fetch_optional(&self.pool)
		.await?;

		row.map(TryInto::try_into).transpose()
	}

	#[instrument(skip(self), fields(project_id = %project_id, release = %release, name = %name))]
	async fn get_artifact_by_name(
		&self,
		project_id: ProjectId,
		release: &str,
		name: &str,
		dist: Option<&str>,
	) -> Result<Option<SymbolArtifact>> {
		let row = if let Some(d) = dist {
			sqlx::query_as::<_, ArtifactRow>(
				r#"
				SELECT id, org_id, project_id, release, dist,
					   artifact_type, name, data, size_bytes, sha256,
					   source_map_url, sources_content,
					   uploaded_at, uploaded_by, last_accessed_at
				FROM symbol_artifacts
				WHERE project_id = ? AND release = ? AND name = ? AND dist = ?
				"#,
			)
			.bind(project_id.0.to_string())
			.bind(release)
			.bind(name)
			.bind(d)
			.fetch_optional(&self.pool)
			.await?
		} else {
			sqlx::query_as::<_, ArtifactRow>(
				r#"
				SELECT id, org_id, project_id, release, dist,
					   artifact_type, name, data, size_bytes, sha256,
					   source_map_url, sources_content,
					   uploaded_at, uploaded_by, last_accessed_at
				FROM symbol_artifacts
				WHERE project_id = ? AND release = ? AND name = ? AND dist IS NULL
				"#,
			)
			.bind(project_id.0.to_string())
			.bind(release)
			.bind(name)
			.fetch_optional(&self.pool)
			.await?
		};

		row.map(TryInto::try_into).transpose()
	}

	#[instrument(skip(self), fields(project_id = %project_id))]
	async fn list_artifacts(
		&self,
		project_id: ProjectId,
		release: Option<&str>,
		limit: u32,
	) -> Result<Vec<SymbolArtifact>> {
		let rows = if let Some(rel) = release {
			sqlx::query_as::<_, ArtifactRow>(
				r#"
				SELECT id, org_id, project_id, release, dist,
					   artifact_type, name, data, size_bytes, sha256,
					   source_map_url, sources_content,
					   uploaded_at, uploaded_by, last_accessed_at
				FROM symbol_artifacts
				WHERE project_id = ? AND release = ?
				ORDER BY uploaded_at DESC
				LIMIT ?
				"#,
			)
			.bind(project_id.0.to_string())
			.bind(rel)
			.bind(limit as i32)
			.fetch_all(&self.pool)
			.await?
		} else {
			sqlx::query_as::<_, ArtifactRow>(
				r#"
				SELECT id, org_id, project_id, release, dist,
					   artifact_type, name, data, size_bytes, sha256,
					   source_map_url, sources_content,
					   uploaded_at, uploaded_by, last_accessed_at
				FROM symbol_artifacts
				WHERE project_id = ?
				ORDER BY uploaded_at DESC
				LIMIT ?
				"#,
			)
			.bind(project_id.0.to_string())
			.bind(limit as i32)
			.fetch_all(&self.pool)
			.await?
		};

		rows.into_iter().map(TryInto::try_into).collect()
	}

	#[instrument(skip(self), fields(artifact_id = %id))]
	async fn delete_artifact(&self, id: SymbolArtifactId) -> Result<bool> {
		let result = sqlx::query("DELETE FROM symbol_artifacts WHERE id = ?")
			.bind(id.0.to_string())
			.execute(&self.pool)
			.await?;

		Ok(result.rows_affected() > 0)
	}

	#[instrument(skip(self), fields(cutoff = %cutoff))]
	async fn delete_old_artifacts(&self, cutoff: DateTime<Utc>) -> Result<u64> {
		let result = sqlx::query(
			r#"
			DELETE FROM symbol_artifacts
			WHERE (last_accessed_at IS NOT NULL AND last_accessed_at < ?)
			   OR (last_accessed_at IS NULL AND uploaded_at < ?)
			"#,
		)
		.bind(cutoff.to_rfc3339())
		.bind(cutoff.to_rfc3339())
		.execute(&self.pool)
		.await?;

		Ok(result.rows_affected())
	}

	#[instrument(skip(self), fields(artifact_id = %id))]
	async fn update_artifact_last_accessed(&self, id: SymbolArtifactId) -> Result<()> {
		sqlx::query(
			r#"
			UPDATE symbol_artifacts SET last_accessed_at = ? WHERE id = ?
			"#,
		)
		.bind(Utc::now().to_rfc3339())
		.bind(id.0.to_string())
		.execute(&self.pool)
		.await?;

		Ok(())
	}

	// API key operations

	#[instrument(skip(self, api_key), fields(api_key_id = %api_key.id, project_id = %api_key.project_id))]
	async fn create_api_key(&self, api_key: &CrashApiKey) -> Result<()> {
		let allowed_origins_json = serde_json::to_string(&api_key.allowed_origins)?;

		sqlx::query(
			r#"
			INSERT INTO crash_api_keys (
				id, project_id, name, key_type, key_hash,
				rate_limit_per_minute, allowed_origins,
				created_by, created_at, last_used_at, revoked_at
			)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
			"#,
		)
		.bind(api_key.id.0.to_string())
		.bind(api_key.project_id.0.to_string())
		.bind(&api_key.name)
		.bind(api_key.key_type.to_string())
		.bind(&api_key.key_hash)
		.bind(api_key.rate_limit_per_minute.map(|n| n as i32))
		.bind(allowed_origins_json)
		.bind(api_key.created_by.0.to_string())
		.bind(api_key.created_at.to_rfc3339())
		.bind(api_key.last_used_at.map(|dt| dt.to_rfc3339()))
		.bind(api_key.revoked_at.map(|dt| dt.to_rfc3339()))
		.execute(&self.pool)
		.await?;

		Ok(())
	}

	#[instrument(skip(self), fields(api_key_id = %id))]
	async fn get_api_key_by_id(&self, id: CrashApiKeyId) -> Result<Option<CrashApiKey>> {
		let row = sqlx::query_as::<_, ApiKeyRow>(
			r#"
			SELECT id, project_id, name, key_type, key_hash,
				   rate_limit_per_minute, allowed_origins,
				   created_by, created_at, last_used_at, revoked_at
			FROM crash_api_keys
			WHERE id = ?
			"#,
		)
		.bind(id.0.to_string())
		.fetch_optional(&self.pool)
		.await?;

		row.map(TryInto::try_into).transpose()
	}

	#[instrument(skip(self))]
	async fn get_api_key_by_hash(&self, key_hash: &str) -> Result<Option<CrashApiKey>> {
		let row = sqlx::query_as::<_, ApiKeyRow>(
			r#"
			SELECT id, project_id, name, key_type, key_hash,
				   rate_limit_per_minute, allowed_origins,
				   created_by, created_at, last_used_at, revoked_at
			FROM crash_api_keys
			WHERE key_hash = ?
			"#,
		)
		.bind(key_hash)
		.fetch_optional(&self.pool)
		.await?;

		row.map(TryInto::try_into).transpose()
	}

	#[instrument(skip(self), fields(project_id = %project_id))]
	async fn list_api_keys(&self, project_id: ProjectId) -> Result<Vec<CrashApiKey>> {
		let rows = sqlx::query_as::<_, ApiKeyRow>(
			r#"
			SELECT id, project_id, name, key_type, key_hash,
				   rate_limit_per_minute, allowed_origins,
				   created_by, created_at, last_used_at, revoked_at
			FROM crash_api_keys
			WHERE project_id = ?
			ORDER BY created_at DESC
			"#,
		)
		.bind(project_id.0.to_string())
		.fetch_all(&self.pool)
		.await?;

		rows.into_iter().map(TryInto::try_into).collect()
	}

	#[instrument(skip(self), fields(api_key_id = %id))]
	async fn revoke_api_key(&self, id: CrashApiKeyId) -> Result<bool> {
		let result = sqlx::query(
			r#"
			UPDATE crash_api_keys SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL
			"#,
		)
		.bind(Utc::now().to_rfc3339())
		.bind(id.0.to_string())
		.execute(&self.pool)
		.await?;

		Ok(result.rows_affected() > 0)
	}

	#[instrument(skip(self), fields(api_key_id = %id))]
	async fn update_api_key_last_used(&self, id: CrashApiKeyId) -> Result<()> {
		sqlx::query(
			r#"
			UPDATE crash_api_keys SET last_used_at = ? WHERE id = ?
			"#,
		)
		.bind(Utc::now().to_rfc3339())
		.bind(id.0.to_string())
		.execute(&self.pool)
		.await?;

		Ok(())
	}
}

// ============================================================================
// Row types for SQLite
// ============================================================================

#[derive(Debug, sqlx::FromRow)]
struct ProjectRow {
	id: String,
	org_id: String,
	name: String,
	slug: String,
	platform: String,
	auto_resolve_age_days: Option<i32>,
	fingerprint_rules: String,
	created_at: String,
	updated_at: String,
}

impl TryFrom<ProjectRow> for CrashProject {
	type Error = CrashServerError;

	fn try_from(row: ProjectRow) -> Result<Self> {
		Ok(CrashProject {
			id: ProjectId(row.id.parse()?),
			org_id: OrgId(row.org_id.parse()?),
			name: row.name,
			slug: row.slug,
			platform: row
				.platform
				.parse()
				.map_err(|_| CrashServerError::Parse(format!("invalid platform: {}", row.platform)))?,
			auto_resolve_age_days: row.auto_resolve_age_days.map(|d| d as u32),
			fingerprint_rules: serde_json::from_str(&row.fingerprint_rules)?,
			created_at: parse_datetime(&row.created_at)?,
			updated_at: parse_datetime(&row.updated_at)?,
		})
	}
}

#[derive(Debug, sqlx::FromRow)]
struct IssueRow {
	id: String,
	org_id: String,
	project_id: String,
	short_id: String,
	fingerprint: String,
	title: String,
	culprit: Option<String>,
	metadata: String,
	status: String,
	level: String,
	priority: String,
	event_count: i64,
	user_count: i64,
	first_seen: String,
	last_seen: String,
	resolved_at: Option<String>,
	resolved_by: Option<String>,
	resolved_in_release: Option<String>,
	times_regressed: i32,
	last_regressed_at: Option<String>,
	regressed_in_release: Option<String>,
	assigned_to: Option<String>,
	created_at: String,
	updated_at: String,
}

impl TryFrom<IssueRow> for Issue {
	type Error = CrashServerError;

	fn try_from(row: IssueRow) -> Result<Self> {
		Ok(Issue {
			id: IssueId(row.id.parse()?),
			org_id: OrgId(row.org_id.parse()?),
			project_id: ProjectId(row.project_id.parse()?),
			short_id: row.short_id,
			fingerprint: row.fingerprint,
			title: row.title,
			culprit: row.culprit,
			metadata: serde_json::from_str(&row.metadata)?,
			status: row
				.status
				.parse()
				.map_err(|_| CrashServerError::Parse(format!("invalid status: {}", row.status)))?,
			level: row
				.level
				.parse()
				.map_err(|_| CrashServerError::Parse(format!("invalid level: {}", row.level)))?,
			priority: row
				.priority
				.parse()
				.map_err(|_| CrashServerError::Parse(format!("invalid priority: {}", row.priority)))?,
			event_count: row.event_count as u64,
			user_count: row.user_count as u64,
			first_seen: parse_datetime(&row.first_seen)?,
			last_seen: parse_datetime(&row.last_seen)?,
			resolved_at: row.resolved_at.map(|s| parse_datetime(&s)).transpose()?,
			resolved_by: row
				.resolved_by
				.map(|s| Ok::<_, CrashServerError>(UserId(s.parse()?)))
				.transpose()?,
			resolved_in_release: row.resolved_in_release,
			times_regressed: row.times_regressed as u32,
			last_regressed_at: row
				.last_regressed_at
				.map(|s| parse_datetime(&s))
				.transpose()?,
			regressed_in_release: row.regressed_in_release,
			assigned_to: row
				.assigned_to
				.map(|s| Ok::<_, CrashServerError>(UserId(s.parse()?)))
				.transpose()?,
			created_at: parse_datetime(&row.created_at)?,
			updated_at: parse_datetime(&row.updated_at)?,
		})
	}
}

#[derive(Debug, sqlx::FromRow)]
struct EventRow {
	id: String,
	org_id: String,
	project_id: String,
	issue_id: Option<String>,
	person_id: Option<String>,
	distinct_id: String,
	exception_type: String,
	exception_value: String,
	stacktrace: String,
	raw_stacktrace: Option<String>,
	release: Option<String>,
	dist: Option<String>,
	environment: String,
	platform: String,
	runtime: Option<String>,
	server_name: Option<String>,
	tags: String,
	extra: String,
	user_context: Option<String>,
	device_context: Option<String>,
	browser_context: Option<String>,
	os_context: Option<String>,
	active_flags: String,
	request: Option<String>,
	breadcrumbs: String,
	timestamp: String,
	received_at: String,
}

impl TryFrom<EventRow> for CrashEvent {
	type Error = CrashServerError;

	fn try_from(row: EventRow) -> Result<Self> {
		Ok(CrashEvent {
			id: CrashEventId(row.id.parse()?),
			org_id: OrgId(row.org_id.parse()?),
			project_id: ProjectId(row.project_id.parse()?),
			issue_id: row
				.issue_id
				.map(|s| Ok::<_, CrashServerError>(IssueId(s.parse()?)))
				.transpose()?,
			person_id: row
				.person_id
				.map(|s| Ok::<_, CrashServerError>(PersonId(s.parse()?)))
				.transpose()?,
			distinct_id: row.distinct_id,
			exception_type: row.exception_type,
			exception_value: row.exception_value,
			stacktrace: serde_json::from_str(&row.stacktrace)?,
			raw_stacktrace: row
				.raw_stacktrace
				.map(|s| serde_json::from_str(&s))
				.transpose()?,
			release: row.release,
			dist: row.dist,
			environment: row.environment,
			platform: row
				.platform
				.parse()
				.map_err(|_| CrashServerError::Parse(format!("invalid platform: {}", row.platform)))?,
			runtime: row.runtime.map(|s| serde_json::from_str(&s)).transpose()?,
			server_name: row.server_name,
			tags: serde_json::from_str(&row.tags)?,
			extra: serde_json::from_str(&row.extra)?,
			user_context: row
				.user_context
				.map(|s| serde_json::from_str(&s))
				.transpose()?,
			device_context: row
				.device_context
				.map(|s| serde_json::from_str(&s))
				.transpose()?,
			browser_context: row
				.browser_context
				.map(|s| serde_json::from_str(&s))
				.transpose()?,
			os_context: row
				.os_context
				.map(|s| serde_json::from_str(&s))
				.transpose()?,
			active_flags: serde_json::from_str(&row.active_flags)?,
			request: row.request.map(|s| serde_json::from_str(&s)).transpose()?,
			breadcrumbs: serde_json::from_str(&row.breadcrumbs)?,
			timestamp: parse_datetime(&row.timestamp)?,
			received_at: parse_datetime(&row.received_at)?,
		})
	}
}

#[derive(Debug, sqlx::FromRow)]
struct ReleaseRow {
	id: String,
	org_id: String,
	project_id: String,
	version: String,
	short_version: Option<String>,
	url: Option<String>,
	crash_count: i64,
	new_issue_count: i64,
	regression_count: i64,
	user_count: i64,
	date_released: Option<String>,
	first_event: Option<String>,
	last_event: Option<String>,
	created_at: String,
}

impl TryFrom<ReleaseRow> for Release {
	type Error = CrashServerError;

	fn try_from(row: ReleaseRow) -> Result<Self> {
		Ok(Release {
			id: ReleaseId(row.id.parse()?),
			org_id: OrgId(row.org_id.parse()?),
			project_id: ProjectId(row.project_id.parse()?),
			version: row.version,
			short_version: row.short_version,
			url: row.url,
			crash_count: row.crash_count as u64,
			new_issue_count: row.new_issue_count as u64,
			regression_count: row.regression_count as u64,
			user_count: row.user_count as u64,
			date_released: row.date_released.map(|s| parse_datetime(&s)).transpose()?,
			first_event: row.first_event.map(|s| parse_datetime(&s)).transpose()?,
			last_event: row.last_event.map(|s| parse_datetime(&s)).transpose()?,
			created_at: parse_datetime(&row.created_at)?,
		})
	}
}

#[derive(Debug, sqlx::FromRow)]
struct ArtifactRow {
	id: String,
	org_id: String,
	project_id: String,
	release: String,
	dist: Option<String>,
	artifact_type: String,
	name: String,
	data: Vec<u8>,
	size_bytes: i64,
	sha256: String,
	source_map_url: Option<String>,
	sources_content: i32,
	uploaded_at: String,
	uploaded_by: String,
	last_accessed_at: Option<String>,
}

impl TryFrom<ArtifactRow> for SymbolArtifact {
	type Error = CrashServerError;

	fn try_from(row: ArtifactRow) -> Result<Self> {
		Ok(SymbolArtifact {
			id: SymbolArtifactId(row.id.parse()?),
			org_id: OrgId(row.org_id.parse()?),
			project_id: ProjectId(row.project_id.parse()?),
			release: row.release,
			dist: row.dist,
			artifact_type: row.artifact_type.parse().map_err(|_| {
				CrashServerError::Parse(format!("invalid artifact type: {}", row.artifact_type))
			})?,
			name: row.name,
			data: row.data,
			size_bytes: row.size_bytes as u64,
			sha256: row.sha256,
			source_map_url: row.source_map_url,
			sources_content: row.sources_content != 0,
			uploaded_at: parse_datetime(&row.uploaded_at)?,
			uploaded_by: UserId(row.uploaded_by.parse()?),
			last_accessed_at: row
				.last_accessed_at
				.map(|s| parse_datetime(&s))
				.transpose()?,
		})
	}
}

#[derive(Debug, sqlx::FromRow)]
struct ApiKeyRow {
	id: String,
	project_id: String,
	name: String,
	key_type: String,
	key_hash: String,
	rate_limit_per_minute: Option<i32>,
	allowed_origins: String,
	created_by: String,
	created_at: String,
	last_used_at: Option<String>,
	revoked_at: Option<String>,
}

impl TryFrom<ApiKeyRow> for CrashApiKey {
	type Error = CrashServerError;

	fn try_from(row: ApiKeyRow) -> Result<Self> {
		Ok(CrashApiKey {
			id: CrashApiKeyId(row.id.parse()?),
			project_id: ProjectId(row.project_id.parse()?),
			name: row.name,
			key_type: row.key_type.parse().map_err(|_| {
				CrashServerError::Parse(format!("invalid key type: {}", row.key_type))
			})?,
			key_hash: row.key_hash,
			rate_limit_per_minute: row.rate_limit_per_minute.map(|n| n as u32),
			allowed_origins: serde_json::from_str(&row.allowed_origins)?,
			created_by: UserId(row.created_by.parse()?),
			created_at: parse_datetime(&row.created_at)?,
			last_used_at: row.last_used_at.map(|s| parse_datetime(&s)).transpose()?,
			revoked_at: row.revoked_at.map(|s| parse_datetime(&s)).transpose()?,
		})
	}
}

fn parse_datetime(s: &str) -> Result<DateTime<Utc>> {
	DateTime::parse_from_rfc3339(s)
		.map(|dt| dt.with_timezone(&Utc))
		.map_err(|_| CrashServerError::InvalidDateTime(s.to_string()))
}
