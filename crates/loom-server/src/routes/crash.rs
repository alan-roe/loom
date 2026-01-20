// Copyright (c) 2025 Geoffrey Huntley <ghuntley@ghuntley.com>. All rights
// reserved. SPDX-License-Identifier: Proprietary

//! Crash analytics HTTP handlers.
//!
//! Implements endpoints for crash event capture, issue management,
//! and project configuration.

use std::convert::Infallible;
use std::sync::Arc;

use axum::{
	extract::{Multipart, Path, Query, State},
	http::{header::HeaderMap, StatusCode},
	response::sse::{Event, Sse},
	Json,
};
use chrono::Utc;
use futures::stream::Stream;
use serde::{Deserialize, Serialize};
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::StreamExt;
use tracing::{info, instrument};

use loom_crash_core::{
	compute_fingerprint, fingerprint, ArtifactType, Breadcrumb, CrashApiKey, CrashApiKeyId,
	CrashEvent, CrashEventId, CrashKeyType, CrashProject, Frame, Issue, IssueId, IssueLevel,
	IssueMetadata, IssuePriority, IssueStatus, OrgId, PersonId, Platform, ProjectId, Release,
	ReleaseId, Stacktrace, SymbolArtifact, SymbolArtifactId, UserId,
};
use loom_server_audit::{AuditEventType, AuditLogBuilder, UserId as AuditUserId};
use loom_server_auth::middleware::CurrentUser;
use loom_server_auth::types::OrgId as AuthOrgId;
use loom_server_crash::{
	generate_api_key, hash_api_key, verify_api_key, CrashRepository, CrashStreamEvent,
	SymbolicationService, KEY_PREFIX_ADMIN, KEY_PREFIX_CAPTURE,
};

use crate::api::AppState;
use crate::auth_middleware::RequireAuth;
use crate::i18n::{resolve_user_locale, t};

/// Error response for crash endpoints.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct CrashErrorResponse {
	pub error: String,
	pub message: String,
}

/// Verify that the current user is a member of the specified organization.
async fn verify_org_membership(
	state: &AppState,
	org_id: &OrgId,
	user_id: &loom_server_auth::types::UserId,
	locale: &str,
) -> Result<(), (StatusCode, Json<CrashErrorResponse>)> {
	let auth_org_id = AuthOrgId::from(org_id.0);

	match state.org_repo.get_membership(&auth_org_id, user_id).await {
		Ok(Some(_)) => Ok(()),
		Ok(None) => Err((
			StatusCode::FORBIDDEN,
			Json(CrashErrorResponse {
				error: "forbidden".to_string(),
				message: t(locale, "server.api.org.not_a_member").to_string(),
			}),
		)),
		Err(e) => {
			tracing::error!(error = %e, %org_id, "Failed to check org membership");
			Err((
				StatusCode::INTERNAL_SERVER_ERROR,
				Json(CrashErrorResponse {
					error: "internal_error".to_string(),
					message: t(locale, "server.api.error.internal").to_string(),
				}),
			))
		}
	}
}

/// Symbolicate a crash event's stacktrace if source maps are available.
///
/// This function:
/// 1. Saves the original (minified) stacktrace as raw_stacktrace
/// 2. Attempts to symbolicate the stacktrace using uploaded source maps
/// 3. Updates the event's stacktrace with the symbolicated version
///
/// Symbolication is only attempted if a release is specified.
async fn symbolicate_event(
	state: &AppState,
	event: &mut CrashEvent,
	project_id: ProjectId,
) {
	// Skip if no release specified
	let (release, dist) = match (&event.release, &event.dist) {
		(Some(r), d) => (r.as_str(), d.as_deref()),
		(None, _) => return,
	};

	// Save the original (minified) stacktrace
	let raw_stacktrace = event.stacktrace.clone();

	// Create symbolication service and symbolicate
	let symbolication_service = SymbolicationService::new(Arc::clone(&state.crash_repo));
	match symbolication_service
		.symbolicate(
			&event.stacktrace,
			event.platform,
			project_id,
			Some(release),
			dist,
		)
		.await
	{
		Ok(symbolicated) => {
			// Only save raw_stacktrace if symbolication actually changed something
			if symbolicated.frames != raw_stacktrace.frames {
				event.raw_stacktrace = Some(raw_stacktrace);
				event.stacktrace = symbolicated;
				info!(
					project_id = %project_id,
					release = ?event.release,
					"Symbolicated crash stacktrace"
				);
			}
		}
		Err(e) => {
			tracing::warn!(error = %e, "Symbolication failed, using original stacktrace");
		}
	}
}

// ============================================================================
// Capture Endpoint (SDK ingestion)
// ============================================================================

/// Request body for crash capture endpoint.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct CaptureRequest {
	pub project_id: String,
	pub exception_type: String,
	pub exception_value: String,
	pub stacktrace: CaptureStacktrace,
	#[serde(default)]
	pub environment: Option<String>,
	pub platform: Option<String>,
	pub release: Option<String>,
	pub dist: Option<String>,
	pub distinct_id: Option<String>,
	pub person_id: Option<String>,
	pub server_name: Option<String>,
	#[serde(default)]
	pub tags: std::collections::HashMap<String, String>,
	#[serde(default)]
	pub extra: serde_json::Value,
	#[serde(default)]
	pub active_flags: std::collections::HashMap<String, String>,
	#[serde(default)]
	pub breadcrumbs: Vec<CaptureBreadcrumb>,
	pub timestamp: Option<String>,
}

/// Stacktrace in capture request.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct CaptureStacktrace {
	pub frames: Vec<CaptureFrame>,
}

/// Frame in capture request.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct CaptureFrame {
	pub function: Option<String>,
	pub module: Option<String>,
	pub filename: Option<String>,
	pub abs_path: Option<String>,
	pub lineno: Option<u32>,
	pub colno: Option<u32>,
	#[serde(default)]
	pub in_app: bool,
}

/// Breadcrumb in capture request.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct CaptureBreadcrumb {
	pub timestamp: Option<String>,
	pub category: Option<String>,
	pub message: Option<String>,
	pub level: Option<String>,
	#[serde(default)]
	pub data: serde_json::Value,
}

/// Response for crash capture endpoint.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct CaptureResponse {
	pub event_id: String,
	pub issue_id: String,
	pub short_id: String,
	pub is_new_issue: bool,
	pub is_regression: bool,
}

/// POST /api/crash/capture - Capture a crash event
#[utoipa::path(
	post,
	path = "/api/crash/capture",
	request_body = CaptureRequest,
	responses(
		(status = 200, description = "Crash captured", body = CaptureResponse),
		(status = 400, description = "Invalid request", body = CrashErrorResponse),
		(status = 404, description = "Project not found", body = CrashErrorResponse),
		(status = 500, description = "Internal error", body = CrashErrorResponse),
	),
	tag = "crash"
)]
#[instrument(skip(state, current_user, body), fields(project_id = %body.project_id))]
pub async fn capture_crash(
	State(state): State<AppState>,
	RequireAuth(current_user): RequireAuth,
	Json(body): Json<CaptureRequest>,
) -> Result<Json<CaptureResponse>, (StatusCode, Json<CrashErrorResponse>)> {
	let locale = resolve_user_locale(&current_user, &state.default_locale);

	// Parse project ID
	let project_id: ProjectId = body.project_id.parse().map_err(|_| {
		(
			StatusCode::BAD_REQUEST,
			Json(CrashErrorResponse {
				error: "invalid_project_id".to_string(),
				message: "Invalid project ID".to_string(),
			}),
		)
	})?;

	// Get project
	let project = state
		.crash_repo
		.get_project_by_id(project_id)
		.await
		.map_err(|e| {
			tracing::error!(error = %e, "Failed to get project");
			(
				StatusCode::INTERNAL_SERVER_ERROR,
				Json(CrashErrorResponse {
					error: "internal_error".to_string(),
					message: t(&locale, "server.api.error.internal").to_string(),
				}),
			)
		})?
		.ok_or_else(|| {
			(
				StatusCode::NOT_FOUND,
				Json(CrashErrorResponse {
					error: "project_not_found".to_string(),
					message: "Project not found".to_string(),
				}),
			)
		})?;

	// Verify org membership
	verify_org_membership(&state, &project.org_id, &current_user.user.id, &locale).await?;

	// Convert capture request to CrashEvent
	let platform = body
		.platform
		.as_deref()
		.unwrap_or("javascript")
		.parse()
		.unwrap_or(Platform::JavaScript);

	let stacktrace = Stacktrace {
		frames: body
			.stacktrace
			.frames
			.into_iter()
			.map(|f| Frame {
				function: f.function,
				module: f.module,
				filename: f.filename,
				abs_path: f.abs_path,
				lineno: f.lineno,
				colno: f.colno,
				in_app: f.in_app,
				..Default::default()
			})
			.collect(),
	};

	let breadcrumbs: Vec<Breadcrumb> = body
		.breadcrumbs
		.into_iter()
		.map(|b| Breadcrumb {
			timestamp: b
				.timestamp
				.and_then(|s| chrono::DateTime::parse_from_rfc3339(&s).ok())
				.map(|dt| dt.with_timezone(&Utc))
				.unwrap_or_else(Utc::now),
			category: b.category.unwrap_or_default(),
			message: b.message,
			level: b
				.level
				.and_then(|l| l.parse().ok())
				.unwrap_or(loom_crash_core::BreadcrumbLevel::Info),
			data: b.data,
		})
		.collect();

	let timestamp = body
		.timestamp
		.and_then(|s| chrono::DateTime::parse_from_rfc3339(&s).ok())
		.map(|dt| dt.with_timezone(&Utc))
		.unwrap_or_else(Utc::now);

	let person_id = body.person_id.and_then(|s| s.parse().ok()).map(PersonId);

	let mut event = CrashEvent {
		id: CrashEventId::new(),
		org_id: project.org_id,
		project_id,
		issue_id: None,
		person_id,
		distinct_id: body
			.distinct_id
			.unwrap_or_else(|| uuid::Uuid::new_v4().to_string()),
		exception_type: body.exception_type,
		exception_value: body.exception_value,
		stacktrace,
		raw_stacktrace: None,
		release: body.release,
		dist: body.dist,
		environment: body.environment.unwrap_or_else(|| "production".to_string()),
		platform,
		runtime: None,
		server_name: body.server_name,
		tags: body.tags,
		extra: body.extra,
		user_context: None,
		device_context: None,
		browser_context: None,
		os_context: None,
		active_flags: body.active_flags,
		request: None,
		breadcrumbs,
		timestamp,
		received_at: Utc::now(),
	};

	// Symbolicate the stacktrace if source maps are available
	symbolicate_event(&state, &mut event, project_id).await;

	// Compute fingerprint (based on symbolicated stacktrace for better grouping)
	let fingerprint = compute_fingerprint(&event);

	// Find or create issue
	let (issue, is_new_issue, is_regression) = match state
		.crash_repo
		.get_issue_by_fingerprint(project_id, &fingerprint)
		.await
		.map_err(|e| {
			tracing::error!(error = %e, "Failed to find issue by fingerprint");
			(
				StatusCode::INTERNAL_SERVER_ERROR,
				Json(CrashErrorResponse {
					error: "internal_error".to_string(),
					message: t(&locale, "server.api.error.internal").to_string(),
				}),
			)
		})? {
		Some(mut existing_issue) => {
			let is_regression = existing_issue.status == IssueStatus::Resolved;

			// Update issue
			existing_issue.event_count += 1;
			existing_issue.last_seen = event.timestamp;

			if is_regression {
				existing_issue.status = IssueStatus::Regressed;
				existing_issue.times_regressed += 1;
				existing_issue.last_regressed_at = Some(Utc::now());
				existing_issue.regressed_in_release = event.release.clone();
			}

			state
				.crash_repo
				.update_issue(&existing_issue)
				.await
				.map_err(|e| {
					tracing::error!(error = %e, "Failed to update issue");
					(
						StatusCode::INTERNAL_SERVER_ERROR,
						Json(CrashErrorResponse {
							error: "internal_error".to_string(),
							message: t(&locale, "server.api.error.internal").to_string(),
						}),
					)
				})?;

			// Track person if present
			if let Some(pid) = event.person_id {
				let _ = state
					.crash_repo
					.add_issue_person(existing_issue.id, pid)
					.await;
			}

			// Broadcast regression if needed
			if is_regression {
				state
					.crash_broadcaster
					.broadcast_regression(project_id, &existing_issue)
					.await;
			}

			(existing_issue, false, is_regression)
		}
		None => {
			// Create new issue
			let short_id = state
				.crash_repo
				.get_next_short_id(project_id)
				.await
				.map_err(|e| {
					tracing::error!(error = %e, "Failed to get next short ID");
					(
						StatusCode::INTERNAL_SERVER_ERROR,
						Json(CrashErrorResponse {
							error: "internal_error".to_string(),
							message: t(&locale, "server.api.error.internal").to_string(),
						}),
					)
				})?;

			let culprit = fingerprint::find_culprit(&event);
			let title = format!(
				"{}: {}",
				event.exception_type,
				fingerprint::truncate(&event.exception_value, 100)
			);

			let issue = Issue {
				id: IssueId::new(),
				org_id: project.org_id,
				project_id,
				short_id,
				fingerprint,
				title,
				culprit,
				metadata: IssueMetadata {
					exception_type: event.exception_type.clone(),
					exception_value: event.exception_value.clone(),
					filename: event
						.stacktrace
						.frames
						.iter()
						.find(|f| f.in_app)
						.and_then(|f| f.filename.clone()),
					function: event
						.stacktrace
						.frames
						.iter()
						.find(|f| f.in_app)
						.and_then(|f| f.function.clone()),
				},
				status: IssueStatus::Unresolved,
				level: IssueLevel::Error,
				priority: IssuePriority::Medium,
				event_count: 1,
				user_count: if event.person_id.is_some() { 1 } else { 0 },
				first_seen: event.timestamp,
				last_seen: event.timestamp,
				resolved_at: None,
				resolved_by: None,
				resolved_in_release: None,
				times_regressed: 0,
				last_regressed_at: None,
				regressed_in_release: None,
				assigned_to: None,
				created_at: Utc::now(),
				updated_at: Utc::now(),
			};

			state.crash_repo.create_issue(&issue).await.map_err(|e| {
				tracing::error!(error = %e, "Failed to create issue");
				(
					StatusCode::INTERNAL_SERVER_ERROR,
					Json(CrashErrorResponse {
						error: "internal_error".to_string(),
						message: t(&locale, "server.api.error.internal").to_string(),
					}),
				)
			})?;

			// Track person if present
			if let Some(pid) = event.person_id {
				let _ = state.crash_repo.add_issue_person(issue.id, pid).await;
			}

			(issue, true, false)
		}
	};

	// Set issue_id on event and save
	event.issue_id = Some(issue.id);
	state.crash_repo.create_event(&event).await.map_err(|e| {
		tracing::error!(error = %e, "Failed to create event");
		(
			StatusCode::INTERNAL_SERVER_ERROR,
			Json(CrashErrorResponse {
				error: "internal_error".to_string(),
				message: t(&locale, "server.api.error.internal").to_string(),
			}),
		)
	})?;

	// Track release if present
	if let Some(ref release_version) = event.release {
		// Get or create the release
		if let Err(e) = state
			.crash_repo
			.get_or_create_release(project_id, project.org_id, release_version)
			.await
		{
			tracing::warn!(error = %e, release = %release_version, "Failed to get/create release");
		}

		// Update release crash count
		if let Err(e) = state
			.crash_repo
			.increment_release_crash_count(project_id, release_version, is_new_issue, is_regression)
			.await
		{
			tracing::warn!(error = %e, release = %release_version, "Failed to increment release crash count");
		}
	}

	// Broadcast new crash event
	state
		.crash_broadcaster
		.broadcast_new_crash(project_id, event.id, &issue, is_new_issue)
		.await;

	info!(
		event_id = %event.id,
		issue_id = %issue.id,
		short_id = %issue.short_id,
		is_new_issue,
		is_regression,
		"Crash event captured"
	);

	Ok(Json(CaptureResponse {
		event_id: event.id.to_string(),
		issue_id: issue.id.to_string(),
		short_id: issue.short_id,
		is_new_issue,
		is_regression,
	}))
}

/// API key header name for SDK capture requests.
const CRASH_API_KEY_HEADER: &str = "x-crash-api-key";

/// Verify an API key for a project.
/// Returns the verified API key if valid and not revoked.
async fn verify_project_api_key(
	state: &AppState,
	project_id: ProjectId,
	raw_key: &str,
) -> Result<CrashApiKey, (StatusCode, Json<CrashErrorResponse>)> {
	// Get all non-revoked API keys for the project
	let keys = state.crash_repo.list_api_keys(project_id).await.map_err(|e| {
		tracing::error!(error = %e, "Failed to list API keys");
		(
			StatusCode::INTERNAL_SERVER_ERROR,
			Json(CrashErrorResponse {
				error: "internal_error".to_string(),
				message: "Internal server error".to_string(),
			}),
		)
	})?;

	// Try to verify against each non-revoked key
	for key in keys {
		if key.is_revoked() {
			continue;
		}

		match verify_api_key(raw_key, &key.key_hash) {
			Ok(true) => {
				// Update last_used timestamp (fire and forget)
				let crash_repo = state.crash_repo.clone();
				let key_id = key.id;
				tokio::spawn(async move {
					let _ = crash_repo.update_api_key_last_used(key_id).await;
				});

				return Ok(key);
			}
			Ok(false) => continue,
			Err(e) => {
				tracing::warn!(error = %e, "API key verification failed");
				continue;
			}
		}
	}

	Err((
		StatusCode::UNAUTHORIZED,
		Json(CrashErrorResponse {
			error: "invalid_api_key".to_string(),
			message: "Invalid or revoked API key".to_string(),
		}),
	))
}

/// POST /api/crash/capture (API key auth) - Capture a crash event with API key authentication
///
/// This endpoint accepts API key authentication via the `X-Crash-Api-Key` header.
/// Use this for SDK integrations where user authentication is not available.
#[utoipa::path(
	post,
	path = "/api/crash/capture/sdk",
	request_body = CaptureRequest,
	responses(
		(status = 200, description = "Crash captured", body = CaptureResponse),
		(status = 400, description = "Invalid request", body = CrashErrorResponse),
		(status = 401, description = "Invalid API key", body = CrashErrorResponse),
		(status = 404, description = "Project not found", body = CrashErrorResponse),
		(status = 500, description = "Internal error", body = CrashErrorResponse),
	),
	tag = "crash"
)]
#[instrument(skip(state, headers, body), fields(project_id = %body.project_id))]
pub async fn capture_crash_with_api_key(
	State(state): State<AppState>,
	headers: HeaderMap,
	Json(body): Json<CaptureRequest>,
) -> Result<Json<CaptureResponse>, (StatusCode, Json<CrashErrorResponse>)> {
	// Extract API key from header
	let raw_key = headers
		.get(CRASH_API_KEY_HEADER)
		.and_then(|v| v.to_str().ok())
		.ok_or_else(|| {
			(
				StatusCode::UNAUTHORIZED,
				Json(CrashErrorResponse {
					error: "missing_api_key".to_string(),
					message: format!("Missing {} header", CRASH_API_KEY_HEADER),
				}),
			)
		})?;

	// Parse project ID
	let project_id: ProjectId = body.project_id.parse().map_err(|_| {
		(
			StatusCode::BAD_REQUEST,
			Json(CrashErrorResponse {
				error: "invalid_project_id".to_string(),
				message: "Invalid project ID".to_string(),
			}),
		)
	})?;

	// Get project
	let project = state
		.crash_repo
		.get_project_by_id(project_id)
		.await
		.map_err(|e| {
			tracing::error!(error = %e, "Failed to get project");
			(
				StatusCode::INTERNAL_SERVER_ERROR,
				Json(CrashErrorResponse {
					error: "internal_error".to_string(),
					message: "Internal server error".to_string(),
				}),
			)
		})?
		.ok_or_else(|| {
			(
				StatusCode::NOT_FOUND,
				Json(CrashErrorResponse {
					error: "project_not_found".to_string(),
					message: "Project not found".to_string(),
				}),
			)
		})?;

	// Verify API key
	let api_key = verify_project_api_key(&state, project_id, raw_key).await?;

	// Check key type - only capture or admin keys can capture
	if api_key.key_type != CrashKeyType::Capture && api_key.key_type != CrashKeyType::Admin {
		return Err((
			StatusCode::FORBIDDEN,
			Json(CrashErrorResponse {
				error: "forbidden".to_string(),
				message: "API key does not have capture permission".to_string(),
			}),
		));
	}

	// Convert capture request to CrashEvent
	let platform = body
		.platform
		.as_deref()
		.unwrap_or("javascript")
		.parse()
		.unwrap_or(Platform::JavaScript);

	let stacktrace = Stacktrace {
		frames: body
			.stacktrace
			.frames
			.into_iter()
			.map(|f| Frame {
				function: f.function,
				module: f.module,
				filename: f.filename,
				abs_path: f.abs_path,
				lineno: f.lineno,
				colno: f.colno,
				in_app: f.in_app,
				..Default::default()
			})
			.collect(),
	};

	let breadcrumbs: Vec<Breadcrumb> = body
		.breadcrumbs
		.into_iter()
		.map(|b| Breadcrumb {
			timestamp: b
				.timestamp
				.and_then(|s| chrono::DateTime::parse_from_rfc3339(&s).ok())
				.map(|dt| dt.with_timezone(&Utc))
				.unwrap_or_else(Utc::now),
			category: b.category.unwrap_or_default(),
			message: b.message,
			level: b
				.level
				.and_then(|l| l.parse().ok())
				.unwrap_or(loom_crash_core::BreadcrumbLevel::Info),
			data: b.data,
		})
		.collect();

	let timestamp = body
		.timestamp
		.and_then(|s| chrono::DateTime::parse_from_rfc3339(&s).ok())
		.map(|dt| dt.with_timezone(&Utc))
		.unwrap_or_else(Utc::now);

	let person_id = body.person_id.and_then(|s| s.parse().ok()).map(PersonId);

	let mut event = CrashEvent {
		id: CrashEventId::new(),
		org_id: project.org_id,
		project_id,
		issue_id: None,
		person_id,
		distinct_id: body
			.distinct_id
			.unwrap_or_else(|| uuid::Uuid::new_v4().to_string()),
		exception_type: body.exception_type,
		exception_value: body.exception_value,
		stacktrace,
		raw_stacktrace: None,
		release: body.release,
		dist: body.dist,
		environment: body.environment.unwrap_or_else(|| "production".to_string()),
		platform,
		runtime: None,
		server_name: body.server_name,
		tags: body.tags,
		extra: body.extra,
		user_context: None,
		device_context: None,
		browser_context: None,
		os_context: None,
		active_flags: body.active_flags,
		request: None,
		breadcrumbs,
		timestamp,
		received_at: Utc::now(),
	};

	// Symbolicate the stacktrace if source maps are available
	symbolicate_event(&state, &mut event, project_id).await;

	// Compute fingerprint
	let fingerprint = compute_fingerprint(&event);

	// Check if issue already exists or create new one
	let (issue, is_new_issue, is_regression) = match state
		.crash_repo
		.get_issue_by_fingerprint(project_id, &fingerprint)
		.await
	{
		Ok(Some(mut existing_issue)) => {
			// Check for regression
			let is_regression = if existing_issue.status == IssueStatus::Resolved {
				existing_issue.status = IssueStatus::Unresolved;
				existing_issue.times_regressed += 1;
				existing_issue.last_regressed_at = Some(event.timestamp);
				existing_issue.regressed_in_release = event.release.clone();
				true
			} else {
				false
			};

			// Update existing issue
			existing_issue.event_count += 1;
			existing_issue.last_seen = event.timestamp;
			existing_issue.updated_at = Utc::now();

			// Track new user if applicable
			if let Some(pid) = event.person_id {
				if !state
					.crash_repo
					.issue_has_person(existing_issue.id, pid)
					.await
					.unwrap_or(false)
				{
					existing_issue.user_count += 1;
					let _ = state.crash_repo.add_issue_person(existing_issue.id, pid).await;
				}
			}

			state.crash_repo.update_issue(&existing_issue).await.map_err(|e| {
				tracing::error!(error = %e, "Failed to update issue");
				(
					StatusCode::INTERNAL_SERVER_ERROR,
					Json(CrashErrorResponse {
						error: "internal_error".to_string(),
						message: "Internal server error".to_string(),
					}),
				)
			})?;

			(existing_issue, false, is_regression)
		}
		Ok(None) | Err(_) => {
			// Create new issue
			let short_id = state
				.crash_repo
				.get_next_short_id(project_id)
				.await
				.map_err(|e| {
					tracing::error!(error = %e, "Failed to get next short ID");
					(
						StatusCode::INTERNAL_SERVER_ERROR,
						Json(CrashErrorResponse {
							error: "internal_error".to_string(),
							message: "Internal server error".to_string(),
						}),
					)
				})?;

			let title = format!("{}: {}", event.exception_type, event.exception_value);
			let culprit = event
				.stacktrace
				.frames
				.iter()
				.find(|f| f.in_app)
				.and_then(|f| {
					let func = f.function.as_deref().unwrap_or("<anonymous>");
					Some(format!(
						"{} in {}",
						func,
						f.filename.as_deref().unwrap_or("<unknown>")
					))
				});

			let issue = Issue {
				id: IssueId::new(),
				org_id: project.org_id,
				project_id,
				short_id,
				fingerprint,
				title,
				culprit,
				metadata: IssueMetadata {
					exception_type: event.exception_type.clone(),
					exception_value: event.exception_value.clone(),
					filename: event
						.stacktrace
						.frames
						.iter()
						.find(|f| f.in_app)
						.and_then(|f| f.filename.clone()),
					function: event
						.stacktrace
						.frames
						.iter()
						.find(|f| f.in_app)
						.and_then(|f| f.function.clone()),
				},
				status: IssueStatus::Unresolved,
				level: IssueLevel::Error,
				priority: IssuePriority::Medium,
				event_count: 1,
				user_count: if event.person_id.is_some() { 1 } else { 0 },
				first_seen: event.timestamp,
				last_seen: event.timestamp,
				resolved_at: None,
				resolved_by: None,
				resolved_in_release: None,
				times_regressed: 0,
				last_regressed_at: None,
				regressed_in_release: None,
				assigned_to: None,
				created_at: Utc::now(),
				updated_at: Utc::now(),
			};

			state.crash_repo.create_issue(&issue).await.map_err(|e| {
				tracing::error!(error = %e, "Failed to create issue");
				(
					StatusCode::INTERNAL_SERVER_ERROR,
					Json(CrashErrorResponse {
						error: "internal_error".to_string(),
						message: "Internal server error".to_string(),
					}),
				)
			})?;

			// Track person if present
			if let Some(pid) = event.person_id {
				let _ = state.crash_repo.add_issue_person(issue.id, pid).await;
			}

			(issue, true, false)
		}
	};

	// Set issue_id on event and save
	event.issue_id = Some(issue.id);
	state.crash_repo.create_event(&event).await.map_err(|e| {
		tracing::error!(error = %e, "Failed to create event");
		(
			StatusCode::INTERNAL_SERVER_ERROR,
			Json(CrashErrorResponse {
				error: "internal_error".to_string(),
				message: "Internal server error".to_string(),
			}),
		)
	})?;

	// Track release if present
	if let Some(ref release_version) = event.release {
		// Get or create the release
		if let Err(e) = state
			.crash_repo
			.get_or_create_release(project_id, project.org_id, release_version)
			.await
		{
			tracing::warn!(error = %e, release = %release_version, "Failed to get/create release");
		}

		// Update release crash count
		if let Err(e) = state
			.crash_repo
			.increment_release_crash_count(project_id, release_version, is_new_issue, is_regression)
			.await
		{
			tracing::warn!(error = %e, release = %release_version, "Failed to increment release crash count");
		}
	}

	// Broadcast new crash event
	state
		.crash_broadcaster
		.broadcast_new_crash(project_id, event.id, &issue, is_new_issue)
		.await;

	info!(
		event_id = %event.id,
		issue_id = %issue.id,
		short_id = %issue.short_id,
		is_new_issue,
		is_regression,
		api_key_id = %api_key.id,
		"Crash event captured via API key"
	);

	Ok(Json(CaptureResponse {
		event_id: event.id.to_string(),
		issue_id: issue.id.to_string(),
		short_id: issue.short_id,
		is_new_issue,
		is_regression,
	}))
}

// ============================================================================
// Batch Capture Endpoint
// ============================================================================

/// Request body for batch crash capture endpoint.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct BatchCaptureRequest {
	/// List of crash events to capture (max 100 per request)
	pub events: Vec<CaptureRequest>,
}

/// Result for a single event in a batch capture.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct BatchCaptureEventResult {
	/// Index of the event in the request array
	pub index: usize,
	/// Whether the event was successfully captured
	pub success: bool,
	/// Event ID if successful
	pub event_id: Option<String>,
	/// Issue ID if successful
	pub issue_id: Option<String>,
	/// Short ID if successful
	pub short_id: Option<String>,
	/// Whether this created a new issue
	pub is_new_issue: Option<bool>,
	/// Whether this is a regression
	pub is_regression: Option<bool>,
	/// Error message if failed
	pub error: Option<String>,
}

/// Response for batch crash capture endpoint.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct BatchCaptureResponse {
	/// Total number of events in the request
	pub total: usize,
	/// Number of successfully captured events
	pub success_count: usize,
	/// Number of failed events
	pub error_count: usize,
	/// Results for each event in the batch
	pub results: Vec<BatchCaptureEventResult>,
}

/// POST /api/crash/batch - Capture multiple crash events in a single request
#[utoipa::path(
	post,
	path = "/api/crash/batch",
	request_body = BatchCaptureRequest,
	responses(
		(status = 200, description = "Batch capture results", body = BatchCaptureResponse),
		(status = 400, description = "Invalid request", body = CrashErrorResponse),
		(status = 500, description = "Internal error", body = CrashErrorResponse),
	),
	tag = "crash"
)]
#[instrument(skip(state, current_user, body), fields(event_count = body.events.len()))]
pub async fn batch_capture_crash(
	State(state): State<AppState>,
	RequireAuth(current_user): RequireAuth,
	Json(body): Json<BatchCaptureRequest>,
) -> Result<Json<BatchCaptureResponse>, (StatusCode, Json<CrashErrorResponse>)> {
	let locale = resolve_user_locale(&current_user, &state.default_locale);

	// Validate batch size
	const MAX_BATCH_SIZE: usize = 100;
	if body.events.len() > MAX_BATCH_SIZE {
		return Err((
			StatusCode::BAD_REQUEST,
			Json(CrashErrorResponse {
				error: "batch_too_large".to_string(),
				message: format!("Batch size exceeds maximum of {} events", MAX_BATCH_SIZE),
			}),
		));
	}

	if body.events.is_empty() {
		return Ok(Json(BatchCaptureResponse {
			total: 0,
			success_count: 0,
			error_count: 0,
			results: vec![],
		}));
	}

	let mut results = Vec::with_capacity(body.events.len());
	let mut success_count = 0;
	let mut error_count = 0;

	// Process each event
	for (index, event_request) in body.events.into_iter().enumerate() {
		let result = process_single_capture(&state, &current_user, &locale, event_request, index).await;

		match result {
			Ok(capture_result) => {
				success_count += 1;
				results.push(BatchCaptureEventResult {
					index,
					success: true,
					event_id: Some(capture_result.event_id),
					issue_id: Some(capture_result.issue_id),
					short_id: Some(capture_result.short_id),
					is_new_issue: Some(capture_result.is_new_issue),
					is_regression: Some(capture_result.is_regression),
					error: None,
				});
			}
			Err(error_msg) => {
				error_count += 1;
				results.push(BatchCaptureEventResult {
					index,
					success: false,
					event_id: None,
					issue_id: None,
					short_id: None,
					is_new_issue: None,
					is_regression: None,
					error: Some(error_msg),
				});
			}
		}
	}

	info!(
		total = results.len(),
		success_count, error_count, "Batch crash capture completed"
	);

	Ok(Json(BatchCaptureResponse {
		total: results.len(),
		success_count,
		error_count,
		results,
	}))
}

/// Internal helper to process a single capture request within a batch.
/// Returns Ok(CaptureResponse) on success, Err(String) with error message on failure.
async fn process_single_capture(
	state: &AppState,
	current_user: &CurrentUser,
	locale: &str,
	body: CaptureRequest,
	_index: usize,
) -> Result<CaptureResponse, String> {
	// Parse project ID
	let project_id: ProjectId = body
		.project_id
		.parse()
		.map_err(|_| "Invalid project ID".to_string())?;

	// Get project
	let project = state
		.crash_repo
		.get_project_by_id(project_id)
		.await
		.map_err(|e| format!("Failed to get project: {}", e))?
		.ok_or_else(|| "Project not found".to_string())?;

	// Verify org membership
	let auth_org_id = AuthOrgId::from(project.org_id.0);
	match state
		.org_repo
		.get_membership(&auth_org_id, &current_user.user.id)
		.await
	{
		Ok(Some(_)) => {}
		Ok(None) => return Err(t(locale, "server.api.org.not_a_member").to_string()),
		Err(e) => return Err(format!("Failed to check org membership: {}", e)),
	}

	// Convert capture request to CrashEvent
	let platform = body
		.platform
		.as_deref()
		.unwrap_or("javascript")
		.parse()
		.unwrap_or(Platform::JavaScript);

	let stacktrace = Stacktrace {
		frames: body
			.stacktrace
			.frames
			.into_iter()
			.map(|f| Frame {
				function: f.function,
				module: f.module,
				filename: f.filename,
				abs_path: f.abs_path,
				lineno: f.lineno,
				colno: f.colno,
				in_app: f.in_app,
				..Default::default()
			})
			.collect(),
	};

	let breadcrumbs: Vec<Breadcrumb> = body
		.breadcrumbs
		.into_iter()
		.map(|b| Breadcrumb {
			timestamp: b
				.timestamp
				.and_then(|s| chrono::DateTime::parse_from_rfc3339(&s).ok())
				.map(|dt| dt.with_timezone(&Utc))
				.unwrap_or_else(Utc::now),
			category: b.category.unwrap_or_default(),
			message: b.message,
			level: b
				.level
				.and_then(|l| l.parse().ok())
				.unwrap_or(loom_crash_core::BreadcrumbLevel::Info),
			data: b.data,
		})
		.collect();

	let timestamp = body
		.timestamp
		.and_then(|s| chrono::DateTime::parse_from_rfc3339(&s).ok())
		.map(|dt| dt.with_timezone(&Utc))
		.unwrap_or_else(Utc::now);

	let person_id = body.person_id.and_then(|s| s.parse().ok()).map(PersonId);

	let mut event = CrashEvent {
		id: CrashEventId::new(),
		org_id: project.org_id,
		project_id,
		issue_id: None,
		person_id,
		distinct_id: body
			.distinct_id
			.unwrap_or_else(|| uuid::Uuid::new_v4().to_string()),
		exception_type: body.exception_type,
		exception_value: body.exception_value,
		stacktrace,
		raw_stacktrace: None,
		release: body.release,
		dist: body.dist,
		environment: body.environment.unwrap_or_else(|| "production".to_string()),
		platform,
		runtime: None,
		server_name: body.server_name,
		tags: body.tags,
		extra: body.extra,
		user_context: None,
		device_context: None,
		browser_context: None,
		os_context: None,
		active_flags: body.active_flags,
		request: None,
		breadcrumbs,
		timestamp,
		received_at: Utc::now(),
	};

	// Symbolicate the stacktrace if source maps are available
	symbolicate_event(state, &mut event, project_id).await;

	// Compute fingerprint (based on symbolicated stacktrace for better grouping)
	let fingerprint = compute_fingerprint(&event);

	// Find or create issue
	let (issue, is_new_issue, is_regression) = match state
		.crash_repo
		.get_issue_by_fingerprint(project_id, &fingerprint)
		.await
		.map_err(|e| format!("Failed to find issue: {}", e))?
	{
		Some(mut existing_issue) => {
			let is_regression = existing_issue.status == IssueStatus::Resolved;

			// Update issue
			existing_issue.event_count += 1;
			existing_issue.last_seen = event.timestamp;

			if is_regression {
				existing_issue.status = IssueStatus::Regressed;
				existing_issue.times_regressed += 1;
				existing_issue.last_regressed_at = Some(Utc::now());
				existing_issue.regressed_in_release = event.release.clone();
			}

			state
				.crash_repo
				.update_issue(&existing_issue)
				.await
				.map_err(|e| format!("Failed to update issue: {}", e))?;

			// Track person if present
			if let Some(pid) = event.person_id {
				let _ = state
					.crash_repo
					.add_issue_person(existing_issue.id, pid)
					.await;
			}

			// Broadcast regression if needed
			if is_regression {
				state
					.crash_broadcaster
					.broadcast_regression(project_id, &existing_issue)
					.await;
			}

			(existing_issue, false, is_regression)
		}
		None => {
			// Create new issue
			let short_id = state
				.crash_repo
				.get_next_short_id(project_id)
				.await
				.map_err(|e| format!("Failed to get short ID: {}", e))?;

			let culprit = fingerprint::find_culprit(&event);
			let title = format!(
				"{}: {}",
				event.exception_type,
				fingerprint::truncate(&event.exception_value, 100)
			);

			let issue = Issue {
				id: IssueId::new(),
				org_id: project.org_id,
				project_id,
				short_id,
				fingerprint,
				title,
				culprit,
				metadata: IssueMetadata {
					exception_type: event.exception_type.clone(),
					exception_value: event.exception_value.clone(),
					filename: event
						.stacktrace
						.frames
						.iter()
						.find(|f| f.in_app)
						.and_then(|f| f.filename.clone()),
					function: event
						.stacktrace
						.frames
						.iter()
						.find(|f| f.in_app)
						.and_then(|f| f.function.clone()),
				},
				status: IssueStatus::Unresolved,
				level: IssueLevel::Error,
				priority: IssuePriority::Medium,
				event_count: 1,
				user_count: if event.person_id.is_some() { 1 } else { 0 },
				first_seen: event.timestamp,
				last_seen: event.timestamp,
				resolved_at: None,
				resolved_by: None,
				resolved_in_release: None,
				times_regressed: 0,
				last_regressed_at: None,
				regressed_in_release: None,
				assigned_to: None,
				created_at: Utc::now(),
				updated_at: Utc::now(),
			};

			state
				.crash_repo
				.create_issue(&issue)
				.await
				.map_err(|e| format!("Failed to create issue: {}", e))?;

			// Track person if present
			if let Some(pid) = event.person_id {
				let _ = state.crash_repo.add_issue_person(issue.id, pid).await;
			}

			(issue, true, false)
		}
	};

	// Set issue_id on event and save
	event.issue_id = Some(issue.id);
	state
		.crash_repo
		.create_event(&event)
		.await
		.map_err(|e| format!("Failed to create event: {}", e))?;

	// Track release if present
	if let Some(ref release_version) = event.release {
		// Get or create the release
		if let Err(e) = state
			.crash_repo
			.get_or_create_release(project_id, project.org_id, release_version)
			.await
		{
			tracing::warn!(error = %e, release = %release_version, "Failed to get/create release");
		}

		// Update release crash count
		if let Err(e) = state
			.crash_repo
			.increment_release_crash_count(project_id, release_version, is_new_issue, is_regression)
			.await
		{
			tracing::warn!(error = %e, release = %release_version, "Failed to increment release crash count");
		}
	}

	// Broadcast new crash event
	state
		.crash_broadcaster
		.broadcast_new_crash(project_id, event.id, &issue, is_new_issue)
		.await;

	Ok(CaptureResponse {
		event_id: event.id.to_string(),
		issue_id: issue.id.to_string(),
		short_id: issue.short_id,
		is_new_issue,
		is_regression,
	})
}

// ============================================================================
// Project Endpoints
// ============================================================================

/// Request to create a crash project.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct CreateProjectRequest {
	pub org_id: String,
	pub name: String,
	pub slug: String,
	#[serde(default = "default_platform")]
	pub platform: String,
}

fn default_platform() -> String {
	"javascript".to_string()
}

/// Response for project operations.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct ProjectResponse {
	pub id: String,
	pub org_id: String,
	pub name: String,
	pub slug: String,
	pub platform: String,
	pub created_at: String,
	pub updated_at: String,
}

impl From<CrashProject> for ProjectResponse {
	fn from(p: CrashProject) -> Self {
		Self {
			id: p.id.to_string(),
			org_id: p.org_id.to_string(),
			name: p.name,
			slug: p.slug,
			platform: p.platform.to_string(),
			created_at: p.created_at.to_rfc3339(),
			updated_at: p.updated_at.to_rfc3339(),
		}
	}
}

/// GET /api/crash/projects - List crash projects
#[utoipa::path(
	get,
	path = "/api/crash/projects",
	params(
		("org_id" = String, Query, description = "Organization ID"),
	),
	responses(
		(status = 200, description = "List of projects", body = Vec<ProjectResponse>),
		(status = 403, description = "Forbidden", body = CrashErrorResponse),
	),
	security(("bearer" = [])),
	tag = "crash"
)]
#[instrument(skip(state, current_user))]
pub async fn list_projects(
	State(state): State<AppState>,
	RequireAuth(current_user): RequireAuth,
	Query(params): Query<ListProjectsParams>,
) -> Result<Json<Vec<ProjectResponse>>, (StatusCode, Json<CrashErrorResponse>)> {
	let locale = resolve_user_locale(&current_user, &state.default_locale);

	let org_id: OrgId = params.org_id.parse().map_err(|_| {
		(
			StatusCode::BAD_REQUEST,
			Json(CrashErrorResponse {
				error: "invalid_org_id".to_string(),
				message: "Invalid organization ID".to_string(),
			}),
		)
	})?;

	verify_org_membership(&state, &org_id, &current_user.user.id, &locale).await?;

	let projects = state.crash_repo.list_projects(org_id).await.map_err(|e| {
		tracing::error!(error = %e, "Failed to list projects");
		(
			StatusCode::INTERNAL_SERVER_ERROR,
			Json(CrashErrorResponse {
				error: "internal_error".to_string(),
				message: t(&locale, "server.api.error.internal").to_string(),
			}),
		)
	})?;

	Ok(Json(
		projects.into_iter().map(ProjectResponse::from).collect(),
	))
}

#[derive(Debug, Deserialize)]
pub struct ListProjectsParams {
	pub org_id: String,
}

/// POST /api/crash/projects - Create a crash project
#[utoipa::path(
	post,
	path = "/api/crash/projects",
	request_body = CreateProjectRequest,
	responses(
		(status = 201, description = "Project created", body = ProjectResponse),
		(status = 400, description = "Invalid request", body = CrashErrorResponse),
		(status = 403, description = "Forbidden", body = CrashErrorResponse),
	),
	security(("bearer" = [])),
	tag = "crash"
)]
#[instrument(skip(state, current_user, body))]
pub async fn create_project(
	State(state): State<AppState>,
	RequireAuth(current_user): RequireAuth,
	Json(body): Json<CreateProjectRequest>,
) -> Result<(StatusCode, Json<ProjectResponse>), (StatusCode, Json<CrashErrorResponse>)> {
	let locale = resolve_user_locale(&current_user, &state.default_locale);

	let org_id: OrgId = body.org_id.parse().map_err(|_| {
		(
			StatusCode::BAD_REQUEST,
			Json(CrashErrorResponse {
				error: "invalid_org_id".to_string(),
				message: "Invalid organization ID".to_string(),
			}),
		)
	})?;

	verify_org_membership(&state, &org_id, &current_user.user.id, &locale).await?;

	// Validate slug
	if !CrashProject::validate_slug(&body.slug) {
		return Err((
			StatusCode::BAD_REQUEST,
			Json(CrashErrorResponse {
				error: "invalid_slug".to_string(),
				message: "Slug must be 3-50 lowercase alphanumeric characters with hyphens/underscores"
					.to_string(),
			}),
		));
	}

	let platform: Platform = body.platform.parse().unwrap_or(Platform::JavaScript);

	let now = Utc::now();
	let project = CrashProject {
		id: ProjectId::new(),
		org_id,
		name: body.name,
		slug: body.slug,
		platform,
		auto_resolve_age_days: None,
		fingerprint_rules: vec![],
		created_at: now,
		updated_at: now,
	};

	state
		.crash_repo
		.create_project(&project)
		.await
		.map_err(|e| {
			tracing::error!(error = %e, "Failed to create project");
			(
				StatusCode::INTERNAL_SERVER_ERROR,
				Json(CrashErrorResponse {
					error: "internal_error".to_string(),
					message: t(&locale, "server.api.error.internal").to_string(),
				}),
			)
		})?;

	info!(project_id = %project.id, slug = %project.slug, "Crash project created");

	state.audit_service.log(
		AuditLogBuilder::new(AuditEventType::CrashProjectCreated)
			.actor(AuditUserId::new(current_user.user.id.into_inner()))
			.resource("crash_project", project.id.to_string())
			.details(serde_json::json!({
				"org_id": project.org_id.to_string(),
				"name": project.name.clone(),
				"slug": project.slug.clone(),
				"platform": project.platform.to_string(),
			}))
			.build(),
	);

	Ok((StatusCode::CREATED, Json(ProjectResponse::from(project))))
}

// ============================================================================
// Issue Endpoints
// ============================================================================

/// Response for issue operations.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct IssueResponse {
	pub id: String,
	pub project_id: String,
	pub short_id: String,
	pub title: String,
	pub culprit: Option<String>,
	pub status: String,
	pub level: String,
	pub priority: String,
	pub event_count: u64,
	pub user_count: u64,
	pub first_seen: String,
	pub last_seen: String,
	pub times_regressed: u32,
}

impl From<Issue> for IssueResponse {
	fn from(i: Issue) -> Self {
		Self {
			id: i.id.to_string(),
			project_id: i.project_id.to_string(),
			short_id: i.short_id,
			title: i.title,
			culprit: i.culprit,
			status: i.status.to_string(),
			level: i.level.to_string(),
			priority: i.priority.to_string(),
			event_count: i.event_count,
			user_count: i.user_count,
			first_seen: i.first_seen.to_rfc3339(),
			last_seen: i.last_seen.to_rfc3339(),
			times_regressed: i.times_regressed,
		}
	}
}

/// GET /api/crash/projects/{project_id}/issues - List issues
#[utoipa::path(
	get,
	path = "/api/crash/projects/{project_id}/issues",
	params(
		("project_id" = String, Path, description = "Project ID"),
	),
	responses(
		(status = 200, description = "List of issues", body = Vec<IssueResponse>),
		(status = 403, description = "Forbidden", body = CrashErrorResponse),
		(status = 404, description = "Project not found", body = CrashErrorResponse),
	),
	security(("bearer" = [])),
	tag = "crash"
)]
#[instrument(skip(state, current_user))]
pub async fn list_issues(
	State(state): State<AppState>,
	RequireAuth(current_user): RequireAuth,
	Path(project_id_str): Path<String>,
) -> Result<Json<Vec<IssueResponse>>, (StatusCode, Json<CrashErrorResponse>)> {
	let locale = resolve_user_locale(&current_user, &state.default_locale);

	let project_id: ProjectId = project_id_str.parse().map_err(|_| {
		(
			StatusCode::BAD_REQUEST,
			Json(CrashErrorResponse {
				error: "invalid_project_id".to_string(),
				message: "Invalid project ID".to_string(),
			}),
		)
	})?;

	let project = state
		.crash_repo
		.get_project_by_id(project_id)
		.await
		.map_err(|e| {
			tracing::error!(error = %e, "Failed to get project");
			(
				StatusCode::INTERNAL_SERVER_ERROR,
				Json(CrashErrorResponse {
					error: "internal_error".to_string(),
					message: t(&locale, "server.api.error.internal").to_string(),
				}),
			)
		})?
		.ok_or_else(|| {
			(
				StatusCode::NOT_FOUND,
				Json(CrashErrorResponse {
					error: "project_not_found".to_string(),
					message: "Project not found".to_string(),
				}),
			)
		})?;

	verify_org_membership(&state, &project.org_id, &current_user.user.id, &locale).await?;

	let issues = state
		.crash_repo
		.list_issues(project_id, 100)
		.await
		.map_err(|e| {
			tracing::error!(error = %e, "Failed to list issues");
			(
				StatusCode::INTERNAL_SERVER_ERROR,
				Json(CrashErrorResponse {
					error: "internal_error".to_string(),
					message: t(&locale, "server.api.error.internal").to_string(),
				}),
			)
		})?;

	Ok(Json(issues.into_iter().map(IssueResponse::from).collect()))
}

/// POST /api/crash/projects/{project_id}/issues/{issue_id}/resolve - Resolve an issue
#[utoipa::path(
	post,
	path = "/api/crash/projects/{project_id}/issues/{issue_id}/resolve",
	params(
		("project_id" = String, Path, description = "Project ID"),
		("issue_id" = String, Path, description = "Issue ID"),
	),
	responses(
		(status = 200, description = "Issue resolved", body = IssueResponse),
		(status = 403, description = "Forbidden", body = CrashErrorResponse),
		(status = 404, description = "Issue not found", body = CrashErrorResponse),
	),
	security(("bearer" = [])),
	tag = "crash"
)]
#[instrument(skip(state, current_user))]
pub async fn resolve_issue(
	State(state): State<AppState>,
	RequireAuth(current_user): RequireAuth,
	Path((project_id_str, issue_id_str)): Path<(String, String)>,
) -> Result<Json<IssueResponse>, (StatusCode, Json<CrashErrorResponse>)> {
	let locale = resolve_user_locale(&current_user, &state.default_locale);

	let project_id: ProjectId = project_id_str.parse().map_err(|_| {
		(
			StatusCode::BAD_REQUEST,
			Json(CrashErrorResponse {
				error: "invalid_project_id".to_string(),
				message: "Invalid project ID".to_string(),
			}),
		)
	})?;

	let issue_id: IssueId = issue_id_str.parse().map_err(|_| {
		(
			StatusCode::BAD_REQUEST,
			Json(CrashErrorResponse {
				error: "invalid_issue_id".to_string(),
				message: "Invalid issue ID".to_string(),
			}),
		)
	})?;

	let project = state
		.crash_repo
		.get_project_by_id(project_id)
		.await
		.map_err(|e| {
			tracing::error!(error = %e, "Failed to get project");
			(
				StatusCode::INTERNAL_SERVER_ERROR,
				Json(CrashErrorResponse {
					error: "internal_error".to_string(),
					message: t(&locale, "server.api.error.internal").to_string(),
				}),
			)
		})?
		.ok_or_else(|| {
			(
				StatusCode::NOT_FOUND,
				Json(CrashErrorResponse {
					error: "project_not_found".to_string(),
					message: "Project not found".to_string(),
				}),
			)
		})?;

	verify_org_membership(&state, &project.org_id, &current_user.user.id, &locale).await?;

	let mut issue = state
		.crash_repo
		.get_issue_by_id(issue_id)
		.await
		.map_err(|e| {
			tracing::error!(error = %e, "Failed to get issue");
			(
				StatusCode::INTERNAL_SERVER_ERROR,
				Json(CrashErrorResponse {
					error: "internal_error".to_string(),
					message: t(&locale, "server.api.error.internal").to_string(),
				}),
			)
		})?
		.ok_or_else(|| {
			(
				StatusCode::NOT_FOUND,
				Json(CrashErrorResponse {
					error: "issue_not_found".to_string(),
					message: "Issue not found".to_string(),
				}),
			)
		})?;

	// Verify issue belongs to project
	if issue.project_id != project_id {
		return Err((
			StatusCode::NOT_FOUND,
			Json(CrashErrorResponse {
				error: "issue_not_found".to_string(),
				message: "Issue not found".to_string(),
			}),
		));
	}

	issue.status = IssueStatus::Resolved;
	issue.resolved_at = Some(Utc::now());
	issue.resolved_by = Some(loom_crash_core::UserId(current_user.user.id.into_inner()));

	state.crash_repo.update_issue(&issue).await.map_err(|e| {
		tracing::error!(error = %e, "Failed to update issue");
		(
			StatusCode::INTERNAL_SERVER_ERROR,
			Json(CrashErrorResponse {
				error: "internal_error".to_string(),
				message: t(&locale, "server.api.error.internal").to_string(),
			}),
		)
	})?;

	state
		.crash_broadcaster
		.broadcast_resolved(project_id, &issue)
		.await;

	info!(issue_id = %issue.id, short_id = %issue.short_id, "Issue resolved");

	state.audit_service.log(
		AuditLogBuilder::new(AuditEventType::CrashIssueResolved)
			.actor(AuditUserId::new(current_user.user.id.into_inner()))
			.resource("crash_issue", issue.id.to_string())
			.details(serde_json::json!({
				"project_id": project_id.to_string(),
				"short_id": issue.short_id.clone(),
				"title": issue.title.clone(),
			}))
			.build(),
	);

	Ok(Json(IssueResponse::from(issue)))
}

/// POST /api/crash/projects/{project_id}/issues/{issue_id}/unresolve - Unresolve an issue
///
/// Transitions a resolved or ignored issue back to unresolved status.
#[utoipa::path(
	post,
	path = "/api/crash/projects/{project_id}/issues/{issue_id}/unresolve",
	params(
		("project_id" = String, Path, description = "Project ID"),
		("issue_id" = String, Path, description = "Issue ID"),
	),
	responses(
		(status = 200, description = "Issue unresolve", body = IssueResponse),
		(status = 403, description = "Forbidden", body = CrashErrorResponse),
		(status = 404, description = "Issue not found", body = CrashErrorResponse),
	),
	security(("bearer" = [])),
	tag = "crash"
)]
#[instrument(skip(state, current_user))]
pub async fn unresolve_issue(
	State(state): State<AppState>,
	RequireAuth(current_user): RequireAuth,
	Path((project_id_str, issue_id_str)): Path<(String, String)>,
) -> Result<Json<IssueResponse>, (StatusCode, Json<CrashErrorResponse>)> {
	let locale = resolve_user_locale(&current_user, &state.default_locale);

	let project_id: ProjectId = project_id_str.parse().map_err(|_| {
		(
			StatusCode::BAD_REQUEST,
			Json(CrashErrorResponse {
				error: "invalid_project_id".to_string(),
				message: "Invalid project ID".to_string(),
			}),
		)
	})?;

	let issue_id: IssueId = issue_id_str.parse().map_err(|_| {
		(
			StatusCode::BAD_REQUEST,
			Json(CrashErrorResponse {
				error: "invalid_issue_id".to_string(),
				message: "Invalid issue ID".to_string(),
			}),
		)
	})?;

	let project = state
		.crash_repo
		.get_project_by_id(project_id)
		.await
		.map_err(|e| {
			tracing::error!(error = %e, "Failed to get project");
			(
				StatusCode::INTERNAL_SERVER_ERROR,
				Json(CrashErrorResponse {
					error: "internal_error".to_string(),
					message: t(&locale, "server.api.error.internal").to_string(),
				}),
			)
		})?
		.ok_or_else(|| {
			(
				StatusCode::NOT_FOUND,
				Json(CrashErrorResponse {
					error: "project_not_found".to_string(),
					message: "Project not found".to_string(),
				}),
			)
		})?;

	verify_org_membership(&state, &project.org_id, &current_user.user.id, &locale).await?;

	let mut issue = state
		.crash_repo
		.get_issue_by_id(issue_id)
		.await
		.map_err(|e| {
			tracing::error!(error = %e, "Failed to get issue");
			(
				StatusCode::INTERNAL_SERVER_ERROR,
				Json(CrashErrorResponse {
					error: "internal_error".to_string(),
					message: t(&locale, "server.api.error.internal").to_string(),
				}),
			)
		})?
		.ok_or_else(|| {
			(
				StatusCode::NOT_FOUND,
				Json(CrashErrorResponse {
					error: "issue_not_found".to_string(),
					message: "Issue not found".to_string(),
				}),
			)
		})?;

	if issue.project_id != project_id {
		return Err((
			StatusCode::NOT_FOUND,
			Json(CrashErrorResponse {
				error: "issue_not_found".to_string(),
				message: "Issue not found".to_string(),
			}),
		));
	}

	issue.status = IssueStatus::Unresolved;
	issue.resolved_at = None;
	issue.resolved_by = None;
	issue.resolved_in_release = None;

	state.crash_repo.update_issue(&issue).await.map_err(|e| {
		tracing::error!(error = %e, "Failed to update issue");
		(
			StatusCode::INTERNAL_SERVER_ERROR,
			Json(CrashErrorResponse {
				error: "internal_error".to_string(),
				message: t(&locale, "server.api.error.internal").to_string(),
			}),
		)
	})?;

	info!(issue_id = %issue.id, short_id = %issue.short_id, "Issue unresolved");

	Ok(Json(IssueResponse::from(issue)))
}

/// POST /api/crash/projects/{project_id}/issues/{issue_id}/ignore - Ignore an issue
///
/// Marks an issue as ignored, which suppresses it from default views.
#[utoipa::path(
	post,
	path = "/api/crash/projects/{project_id}/issues/{issue_id}/ignore",
	params(
		("project_id" = String, Path, description = "Project ID"),
		("issue_id" = String, Path, description = "Issue ID"),
	),
	responses(
		(status = 200, description = "Issue ignored", body = IssueResponse),
		(status = 403, description = "Forbidden", body = CrashErrorResponse),
		(status = 404, description = "Issue not found", body = CrashErrorResponse),
	),
	security(("bearer" = [])),
	tag = "crash"
)]
#[instrument(skip(state, current_user))]
pub async fn ignore_issue(
	State(state): State<AppState>,
	RequireAuth(current_user): RequireAuth,
	Path((project_id_str, issue_id_str)): Path<(String, String)>,
) -> Result<Json<IssueResponse>, (StatusCode, Json<CrashErrorResponse>)> {
	let locale = resolve_user_locale(&current_user, &state.default_locale);

	let project_id: ProjectId = project_id_str.parse().map_err(|_| {
		(
			StatusCode::BAD_REQUEST,
			Json(CrashErrorResponse {
				error: "invalid_project_id".to_string(),
				message: "Invalid project ID".to_string(),
			}),
		)
	})?;

	let issue_id: IssueId = issue_id_str.parse().map_err(|_| {
		(
			StatusCode::BAD_REQUEST,
			Json(CrashErrorResponse {
				error: "invalid_issue_id".to_string(),
				message: "Invalid issue ID".to_string(),
			}),
		)
	})?;

	let project = state
		.crash_repo
		.get_project_by_id(project_id)
		.await
		.map_err(|e| {
			tracing::error!(error = %e, "Failed to get project");
			(
				StatusCode::INTERNAL_SERVER_ERROR,
				Json(CrashErrorResponse {
					error: "internal_error".to_string(),
					message: t(&locale, "server.api.error.internal").to_string(),
				}),
			)
		})?
		.ok_or_else(|| {
			(
				StatusCode::NOT_FOUND,
				Json(CrashErrorResponse {
					error: "project_not_found".to_string(),
					message: "Project not found".to_string(),
				}),
			)
		})?;

	verify_org_membership(&state, &project.org_id, &current_user.user.id, &locale).await?;

	let mut issue = state
		.crash_repo
		.get_issue_by_id(issue_id)
		.await
		.map_err(|e| {
			tracing::error!(error = %e, "Failed to get issue");
			(
				StatusCode::INTERNAL_SERVER_ERROR,
				Json(CrashErrorResponse {
					error: "internal_error".to_string(),
					message: t(&locale, "server.api.error.internal").to_string(),
				}),
			)
		})?
		.ok_or_else(|| {
			(
				StatusCode::NOT_FOUND,
				Json(CrashErrorResponse {
					error: "issue_not_found".to_string(),
					message: "Issue not found".to_string(),
				}),
			)
		})?;

	if issue.project_id != project_id {
		return Err((
			StatusCode::NOT_FOUND,
			Json(CrashErrorResponse {
				error: "issue_not_found".to_string(),
				message: "Issue not found".to_string(),
			}),
		));
	}

	issue.status = IssueStatus::Ignored;

	state.crash_repo.update_issue(&issue).await.map_err(|e| {
		tracing::error!(error = %e, "Failed to update issue");
		(
			StatusCode::INTERNAL_SERVER_ERROR,
			Json(CrashErrorResponse {
				error: "internal_error".to_string(),
				message: t(&locale, "server.api.error.internal").to_string(),
			}),
		)
	})?;

	state.audit_service.log(
		AuditLogBuilder::new(AuditEventType::CrashIssueIgnored)
			.actor(AuditUserId::new(current_user.user.id.into_inner()))
			.resource("crash_issue", issue.id.to_string())
			.details(serde_json::json!({
				"project_id": project_id.to_string(),
				"short_id": issue.short_id.clone(),
				"title": issue.title.clone(),
			}))
			.build(),
	);

	info!(issue_id = %issue.id, short_id = %issue.short_id, "Issue ignored");

	Ok(Json(IssueResponse::from(issue)))
}

// ============================================================================
// Issue Detail Endpoint
// ============================================================================

/// Detailed response for a single issue including metadata.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct IssueDetailResponse {
	pub id: String,
	pub org_id: String,
	pub project_id: String,
	pub short_id: String,
	pub fingerprint: String,
	pub title: String,
	pub culprit: Option<String>,
	pub metadata: IssueMetadataResponse,
	pub status: String,
	pub level: String,
	pub priority: String,
	pub event_count: u64,
	pub user_count: u64,
	pub first_seen: String,
	pub last_seen: String,
	pub resolved_at: Option<String>,
	pub resolved_by: Option<String>,
	pub resolved_in_release: Option<String>,
	pub times_regressed: u32,
	pub last_regressed_at: Option<String>,
	pub regressed_in_release: Option<String>,
	pub assigned_to: Option<String>,
	pub created_at: String,
	pub updated_at: String,
}

/// Issue metadata response.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct IssueMetadataResponse {
	pub exception_type: String,
	pub exception_value: String,
	pub filename: Option<String>,
	pub function: Option<String>,
}

impl From<Issue> for IssueDetailResponse {
	fn from(i: Issue) -> Self {
		Self {
			id: i.id.to_string(),
			org_id: i.org_id.to_string(),
			project_id: i.project_id.to_string(),
			short_id: i.short_id,
			fingerprint: i.fingerprint,
			title: i.title,
			culprit: i.culprit,
			metadata: IssueMetadataResponse {
				exception_type: i.metadata.exception_type,
				exception_value: i.metadata.exception_value,
				filename: i.metadata.filename,
				function: i.metadata.function,
			},
			status: i.status.to_string(),
			level: i.level.to_string(),
			priority: i.priority.to_string(),
			event_count: i.event_count,
			user_count: i.user_count,
			first_seen: i.first_seen.to_rfc3339(),
			last_seen: i.last_seen.to_rfc3339(),
			resolved_at: i.resolved_at.map(|dt| dt.to_rfc3339()),
			resolved_by: i.resolved_by.map(|u| u.0.to_string()),
			resolved_in_release: i.resolved_in_release,
			times_regressed: i.times_regressed,
			last_regressed_at: i.last_regressed_at.map(|dt| dt.to_rfc3339()),
			regressed_in_release: i.regressed_in_release,
			assigned_to: i.assigned_to.map(|u| u.0.to_string()),
			created_at: i.created_at.to_rfc3339(),
			updated_at: i.updated_at.to_rfc3339(),
		}
	}
}

/// GET /api/crash/projects/{project_id}/issues/{issue_id} - Get issue detail
#[utoipa::path(
	get,
	path = "/api/crash/projects/{project_id}/issues/{issue_id}",
	params(
		("project_id" = String, Path, description = "Project ID"),
		("issue_id" = String, Path, description = "Issue ID"),
	),
	responses(
		(status = 200, description = "Issue detail", body = IssueDetailResponse),
		(status = 403, description = "Forbidden", body = CrashErrorResponse),
		(status = 404, description = "Issue not found", body = CrashErrorResponse),
	),
	security(("bearer" = [])),
	tag = "crash"
)]
#[instrument(skip(state, current_user))]
pub async fn get_issue(
	State(state): State<AppState>,
	RequireAuth(current_user): RequireAuth,
	Path((project_id_str, issue_id_str)): Path<(String, String)>,
) -> Result<Json<IssueDetailResponse>, (StatusCode, Json<CrashErrorResponse>)> {
	let locale = resolve_user_locale(&current_user, &state.default_locale);

	let project_id: ProjectId = project_id_str.parse().map_err(|_| {
		(
			StatusCode::BAD_REQUEST,
			Json(CrashErrorResponse {
				error: "invalid_project_id".to_string(),
				message: "Invalid project ID".to_string(),
			}),
		)
	})?;

	let issue_id: IssueId = issue_id_str.parse().map_err(|_| {
		(
			StatusCode::BAD_REQUEST,
			Json(CrashErrorResponse {
				error: "invalid_issue_id".to_string(),
				message: "Invalid issue ID".to_string(),
			}),
		)
	})?;

	let project = state
		.crash_repo
		.get_project_by_id(project_id)
		.await
		.map_err(|e| {
			tracing::error!(error = %e, "Failed to get project");
			(
				StatusCode::INTERNAL_SERVER_ERROR,
				Json(CrashErrorResponse {
					error: "internal_error".to_string(),
					message: t(&locale, "server.api.error.internal").to_string(),
				}),
			)
		})?
		.ok_or_else(|| {
			(
				StatusCode::NOT_FOUND,
				Json(CrashErrorResponse {
					error: "project_not_found".to_string(),
					message: "Project not found".to_string(),
				}),
			)
		})?;

	verify_org_membership(&state, &project.org_id, &current_user.user.id, &locale).await?;

	let issue = state
		.crash_repo
		.get_issue_by_id(issue_id)
		.await
		.map_err(|e| {
			tracing::error!(error = %e, "Failed to get issue");
			(
				StatusCode::INTERNAL_SERVER_ERROR,
				Json(CrashErrorResponse {
					error: "internal_error".to_string(),
					message: t(&locale, "server.api.error.internal").to_string(),
				}),
			)
		})?
		.ok_or_else(|| {
			(
				StatusCode::NOT_FOUND,
				Json(CrashErrorResponse {
					error: "issue_not_found".to_string(),
					message: "Issue not found".to_string(),
				}),
			)
		})?;

	// Verify issue belongs to project
	if issue.project_id != project_id {
		return Err((
			StatusCode::NOT_FOUND,
			Json(CrashErrorResponse {
				error: "issue_not_found".to_string(),
				message: "Issue not found".to_string(),
			}),
		));
	}

	info!(issue_id = %issue.id, short_id = %issue.short_id, "Issue detail retrieved");

	Ok(Json(IssueDetailResponse::from(issue)))
}

// ============================================================================
// Issue Events Endpoint
// ============================================================================

/// Response for a crash event.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct CrashEventResponse {
	pub id: String,
	pub issue_id: Option<String>,
	pub person_id: Option<String>,
	pub distinct_id: String,
	pub exception_type: String,
	pub exception_value: String,
	pub stacktrace: StacktraceResponse,
	pub release: Option<String>,
	pub dist: Option<String>,
	pub environment: String,
	pub platform: String,
	pub server_name: Option<String>,
	pub tags: std::collections::HashMap<String, String>,
	pub active_flags: std::collections::HashMap<String, String>,
	pub timestamp: String,
	pub received_at: String,
}

/// Response for a stacktrace.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct StacktraceResponse {
	pub frames: Vec<FrameResponse>,
}

/// Response for a stack frame.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct FrameResponse {
	pub function: Option<String>,
	pub module: Option<String>,
	pub filename: Option<String>,
	pub abs_path: Option<String>,
	pub lineno: Option<u32>,
	pub colno: Option<u32>,
	pub in_app: bool,
	pub context_line: Option<String>,
	pub pre_context: Vec<String>,
	pub post_context: Vec<String>,
}

impl From<loom_crash_core::CrashEvent> for CrashEventResponse {
	fn from(e: loom_crash_core::CrashEvent) -> Self {
		Self {
			id: e.id.to_string(),
			issue_id: e.issue_id.map(|i| i.to_string()),
			person_id: e.person_id.map(|p| p.0.to_string()),
			distinct_id: e.distinct_id,
			exception_type: e.exception_type,
			exception_value: e.exception_value,
			stacktrace: StacktraceResponse {
				frames: e
					.stacktrace
					.frames
					.into_iter()
					.map(|f| FrameResponse {
						function: f.function,
						module: f.module,
						filename: f.filename,
						abs_path: f.abs_path,
						lineno: f.lineno,
						colno: f.colno,
						in_app: f.in_app,
						context_line: f.context_line,
						pre_context: f.pre_context,
						post_context: f.post_context,
					})
					.collect(),
			},
			release: e.release,
			dist: e.dist,
			environment: e.environment,
			platform: e.platform.to_string(),
			server_name: e.server_name,
			tags: e.tags,
			active_flags: e.active_flags,
			timestamp: e.timestamp.to_rfc3339(),
			received_at: e.received_at.to_rfc3339(),
		}
	}
}

/// GET /api/crash/projects/{project_id}/issues/{issue_id}/events - List events for an issue
#[utoipa::path(
	get,
	path = "/api/crash/projects/{project_id}/issues/{issue_id}/events",
	params(
		("project_id" = String, Path, description = "Project ID"),
		("issue_id" = String, Path, description = "Issue ID"),
	),
	responses(
		(status = 200, description = "List of crash events", body = Vec<CrashEventResponse>),
		(status = 403, description = "Forbidden", body = CrashErrorResponse),
		(status = 404, description = "Issue not found", body = CrashErrorResponse),
	),
	security(("bearer" = [])),
	tag = "crash"
)]
#[instrument(skip(state, current_user))]
pub async fn list_issue_events(
	State(state): State<AppState>,
	RequireAuth(current_user): RequireAuth,
	Path((project_id_str, issue_id_str)): Path<(String, String)>,
) -> Result<Json<Vec<CrashEventResponse>>, (StatusCode, Json<CrashErrorResponse>)> {
	let locale = resolve_user_locale(&current_user, &state.default_locale);

	let project_id: ProjectId = project_id_str.parse().map_err(|_| {
		(
			StatusCode::BAD_REQUEST,
			Json(CrashErrorResponse {
				error: "invalid_project_id".to_string(),
				message: "Invalid project ID".to_string(),
			}),
		)
	})?;

	let issue_id: IssueId = issue_id_str.parse().map_err(|_| {
		(
			StatusCode::BAD_REQUEST,
			Json(CrashErrorResponse {
				error: "invalid_issue_id".to_string(),
				message: "Invalid issue ID".to_string(),
			}),
		)
	})?;

	let project = state
		.crash_repo
		.get_project_by_id(project_id)
		.await
		.map_err(|e| {
			tracing::error!(error = %e, "Failed to get project");
			(
				StatusCode::INTERNAL_SERVER_ERROR,
				Json(CrashErrorResponse {
					error: "internal_error".to_string(),
					message: t(&locale, "server.api.error.internal").to_string(),
				}),
			)
		})?
		.ok_or_else(|| {
			(
				StatusCode::NOT_FOUND,
				Json(CrashErrorResponse {
					error: "project_not_found".to_string(),
					message: "Project not found".to_string(),
				}),
			)
		})?;

	verify_org_membership(&state, &project.org_id, &current_user.user.id, &locale).await?;

	// Verify issue exists and belongs to project
	let issue = state
		.crash_repo
		.get_issue_by_id(issue_id)
		.await
		.map_err(|e| {
			tracing::error!(error = %e, "Failed to get issue");
			(
				StatusCode::INTERNAL_SERVER_ERROR,
				Json(CrashErrorResponse {
					error: "internal_error".to_string(),
					message: t(&locale, "server.api.error.internal").to_string(),
				}),
			)
		})?
		.ok_or_else(|| {
			(
				StatusCode::NOT_FOUND,
				Json(CrashErrorResponse {
					error: "issue_not_found".to_string(),
					message: "Issue not found".to_string(),
				}),
			)
		})?;

	if issue.project_id != project_id {
		return Err((
			StatusCode::NOT_FOUND,
			Json(CrashErrorResponse {
				error: "issue_not_found".to_string(),
				message: "Issue not found".to_string(),
			}),
		));
	}

	let events = state
		.crash_repo
		.list_events_for_issue(issue_id, 100)
		.await
		.map_err(|e| {
			tracing::error!(error = %e, "Failed to list events");
			(
				StatusCode::INTERNAL_SERVER_ERROR,
				Json(CrashErrorResponse {
					error: "internal_error".to_string(),
					message: t(&locale, "server.api.error.internal").to_string(),
				}),
			)
		})?;

	info!(issue_id = %issue.id, event_count = %events.len(), "Issue events retrieved");

	Ok(Json(
		events.into_iter().map(CrashEventResponse::from).collect(),
	))
}

// ============================================================================
// SSE Stream Endpoint
// ============================================================================

/// Query parameters for the crash stream endpoint.
#[derive(Debug, Deserialize)]
pub struct StreamCrashParams {
	pub project_id: String,
}

/// GET /api/crash/projects/{project_id}/stream - SSE stream for crash events
///
/// Streams real-time updates for crash events including:
/// - `init`: Initial state with issue count on connect
/// - `crash.new`: New crash event received
/// - `issue.regressed`: Resolved issue regressed
/// - `issue.resolved`: Issue was resolved
/// - `issue.assigned`: Issue was assigned
/// - `heartbeat`: Keep-alive (every 30s)
#[utoipa::path(
	get,
	path = "/api/crash/projects/{project_id}/stream",
	params(
		("project_id" = String, Path, description = "Project ID"),
	),
	responses(
		(status = 200, description = "SSE stream connection established"),
		(status = 401, description = "Not authenticated"),
		(status = 403, description = "Not a member of the organization"),
		(status = 404, description = "Project not found"),
	),
	security(("bearer" = [])),
	tag = "crash"
)]
#[instrument(skip(state, current_user))]
pub async fn stream_crash(
	State(state): State<AppState>,
	RequireAuth(current_user): RequireAuth,
	Path(project_id_str): Path<String>,
) -> Result<
	Sse<impl Stream<Item = Result<Event, Infallible>>>,
	(StatusCode, Json<CrashErrorResponse>),
> {
	let locale = resolve_user_locale(&current_user, &state.default_locale);

	let project_id: ProjectId = project_id_str.parse().map_err(|_| {
		(
			StatusCode::BAD_REQUEST,
			Json(CrashErrorResponse {
				error: "invalid_project_id".to_string(),
				message: "Invalid project ID".to_string(),
			}),
		)
	})?;

	// Get project to verify it exists and get org_id
	let project = state
		.crash_repo
		.get_project_by_id(project_id)
		.await
		.map_err(|e| {
			tracing::error!(error = %e, "Failed to get project");
			(
				StatusCode::INTERNAL_SERVER_ERROR,
				Json(CrashErrorResponse {
					error: "internal_error".to_string(),
					message: t(&locale, "server.api.error.internal").to_string(),
				}),
			)
		})?
		.ok_or_else(|| {
			(
				StatusCode::NOT_FOUND,
				Json(CrashErrorResponse {
					error: "project_not_found".to_string(),
					message: "Project not found".to_string(),
				}),
			)
		})?;

	// Verify org membership
	verify_org_membership(&state, &project.org_id, &current_user.user.id, &locale).await?;

	info!(
		project_id = %project_id,
		user_id = %current_user.user.id,
		"Client connected to crash stream"
	);

	// Get issue count for init event
	let issues = state
		.crash_repo
		.list_issues(project_id, 1)
		.await
		.map_err(|e| {
			tracing::error!(error = %e, "Failed to get issue count for init");
			(
				StatusCode::INTERNAL_SERVER_ERROR,
				Json(CrashErrorResponse {
					error: "internal_error".to_string(),
					message: t(&locale, "server.api.error.internal").to_string(),
				}),
			)
		})?;

	// Get the actual count - we need a count method, but for now we'll use a rough estimate
	let issue_count = state
		.crash_repo
		.get_issue_count(project_id)
		.await
		.unwrap_or(issues.len() as u64);

	// Create init event
	let init_event = CrashStreamEvent::init(project_id, issue_count);

	// Subscribe to broadcast channel
	let receiver = state.crash_broadcaster.subscribe(project_id).await;
	let broadcast_stream = BroadcastStream::new(receiver);

	// Create a stream that first yields the init event, then yields broadcast events
	let init_stream = futures::stream::once(async move {
		let json = serde_json::to_string(&init_event).unwrap_or_else(|_| "{}".to_string());
		Ok::<_, Infallible>(Event::default().event("init").data(json))
	});

	let updates_stream = broadcast_stream.filter_map(|result| match result {
		Ok(event) => {
			let event_type = event.event_type();
			match serde_json::to_string(&event) {
				Ok(json) => Some(Ok::<_, Infallible>(
					Event::default().event(event_type).data(json),
				)),
				Err(e) => {
					tracing::warn!(error = %e, "Failed to serialize crash SSE event");
					None
				}
			}
		}
		Err(e) => {
			tracing::debug!(error = %e, "Broadcast stream error (client may have disconnected)");
			None
		}
	});

	let combined_stream = init_stream.chain(updates_stream);

	Ok(
		Sse::new(combined_stream).keep_alive(
			axum::response::sse::KeepAlive::new()
				.interval(std::time::Duration::from_secs(30))
				.text("heartbeat"),
		),
	)
}

// ============================================================================
// Release Endpoints
// ============================================================================

/// Response for release operations.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct ReleaseResponse {
	pub id: String,
	pub project_id: String,
	pub version: String,
	pub short_version: Option<String>,
	pub url: Option<String>,
	pub crash_count: u64,
	pub new_issue_count: u64,
	pub regression_count: u64,
	pub user_count: u64,
	pub date_released: Option<String>,
	pub first_event: Option<String>,
	pub last_event: Option<String>,
	pub created_at: String,
}

impl From<Release> for ReleaseResponse {
	fn from(r: Release) -> Self {
		Self {
			id: r.id.to_string(),
			project_id: r.project_id.to_string(),
			version: r.version,
			short_version: r.short_version,
			url: r.url,
			crash_count: r.crash_count,
			new_issue_count: r.new_issue_count,
			regression_count: r.regression_count,
			user_count: r.user_count,
			date_released: r.date_released.map(|dt| dt.to_rfc3339()),
			first_event: r.first_event.map(|dt| dt.to_rfc3339()),
			last_event: r.last_event.map(|dt| dt.to_rfc3339()),
			created_at: r.created_at.to_rfc3339(),
		}
	}
}

/// Request to create a release.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct CreateReleaseRequest {
	pub version: String,
	pub short_version: Option<String>,
	pub url: Option<String>,
	pub date_released: Option<String>,
}

/// GET /api/crash/projects/{project_id}/releases - List releases for a project
#[utoipa::path(
	get,
	path = "/api/crash/projects/{project_id}/releases",
	params(
		("project_id" = String, Path, description = "Project ID"),
	),
	responses(
		(status = 200, description = "List of releases", body = Vec<ReleaseResponse>),
		(status = 403, description = "Forbidden", body = CrashErrorResponse),
		(status = 404, description = "Project not found", body = CrashErrorResponse),
	),
	security(("bearer" = [])),
	tag = "crash"
)]
#[instrument(skip(state, current_user))]
pub async fn list_releases(
	State(state): State<AppState>,
	RequireAuth(current_user): RequireAuth,
	Path(project_id_str): Path<String>,
) -> Result<Json<Vec<ReleaseResponse>>, (StatusCode, Json<CrashErrorResponse>)> {
	let locale = resolve_user_locale(&current_user, &state.default_locale);

	let project_id: ProjectId = project_id_str.parse().map_err(|_| {
		(
			StatusCode::BAD_REQUEST,
			Json(CrashErrorResponse {
				error: "invalid_project_id".to_string(),
				message: "Invalid project ID".to_string(),
			}),
		)
	})?;

	let project = state
		.crash_repo
		.get_project_by_id(project_id)
		.await
		.map_err(|e| {
			tracing::error!(error = %e, "Failed to get project");
			(
				StatusCode::INTERNAL_SERVER_ERROR,
				Json(CrashErrorResponse {
					error: "internal_error".to_string(),
					message: t(&locale, "server.api.error.internal").to_string(),
				}),
			)
		})?
		.ok_or_else(|| {
			(
				StatusCode::NOT_FOUND,
				Json(CrashErrorResponse {
					error: "project_not_found".to_string(),
					message: "Project not found".to_string(),
				}),
			)
		})?;

	verify_org_membership(&state, &project.org_id, &current_user.user.id, &locale).await?;

	let releases = state
		.crash_repo
		.list_releases(project_id, 100)
		.await
		.map_err(|e| {
			tracing::error!(error = %e, "Failed to list releases");
			(
				StatusCode::INTERNAL_SERVER_ERROR,
				Json(CrashErrorResponse {
					error: "internal_error".to_string(),
					message: t(&locale, "server.api.error.internal").to_string(),
				}),
			)
		})?;

	info!(project_id = %project_id, release_count = %releases.len(), "Releases listed");

	Ok(Json(
		releases.into_iter().map(ReleaseResponse::from).collect(),
	))
}

/// POST /api/crash/projects/{project_id}/releases - Create a release
#[utoipa::path(
	post,
	path = "/api/crash/projects/{project_id}/releases",
	params(
		("project_id" = String, Path, description = "Project ID"),
	),
	request_body = CreateReleaseRequest,
	responses(
		(status = 201, description = "Release created", body = ReleaseResponse),
		(status = 400, description = "Invalid request", body = CrashErrorResponse),
		(status = 403, description = "Forbidden", body = CrashErrorResponse),
		(status = 404, description = "Project not found", body = CrashErrorResponse),
		(status = 409, description = "Release already exists", body = CrashErrorResponse),
	),
	security(("bearer" = [])),
	tag = "crash"
)]
#[instrument(skip(state, current_user, body))]
pub async fn create_release(
	State(state): State<AppState>,
	RequireAuth(current_user): RequireAuth,
	Path(project_id_str): Path<String>,
	Json(body): Json<CreateReleaseRequest>,
) -> Result<(StatusCode, Json<ReleaseResponse>), (StatusCode, Json<CrashErrorResponse>)> {
	let locale = resolve_user_locale(&current_user, &state.default_locale);

	let project_id: ProjectId = project_id_str.parse().map_err(|_| {
		(
			StatusCode::BAD_REQUEST,
			Json(CrashErrorResponse {
				error: "invalid_project_id".to_string(),
				message: "Invalid project ID".to_string(),
			}),
		)
	})?;

	// Validate version
	if body.version.is_empty() || body.version.len() > 200 {
		return Err((
			StatusCode::BAD_REQUEST,
			Json(CrashErrorResponse {
				error: "invalid_version".to_string(),
				message: "Version must be 1-200 characters".to_string(),
			}),
		));
	}

	let project = state
		.crash_repo
		.get_project_by_id(project_id)
		.await
		.map_err(|e| {
			tracing::error!(error = %e, "Failed to get project");
			(
				StatusCode::INTERNAL_SERVER_ERROR,
				Json(CrashErrorResponse {
					error: "internal_error".to_string(),
					message: t(&locale, "server.api.error.internal").to_string(),
				}),
			)
		})?
		.ok_or_else(|| {
			(
				StatusCode::NOT_FOUND,
				Json(CrashErrorResponse {
					error: "project_not_found".to_string(),
					message: "Project not found".to_string(),
				}),
			)
		})?;

	verify_org_membership(&state, &project.org_id, &current_user.user.id, &locale).await?;

	// Check if release already exists
	if let Some(_existing) = state
		.crash_repo
		.get_release_by_version(project_id, &body.version)
		.await
		.map_err(|e| {
			tracing::error!(error = %e, "Failed to check for existing release");
			(
				StatusCode::INTERNAL_SERVER_ERROR,
				Json(CrashErrorResponse {
					error: "internal_error".to_string(),
					message: t(&locale, "server.api.error.internal").to_string(),
				}),
			)
		})? {
		return Err((
			StatusCode::CONFLICT,
			Json(CrashErrorResponse {
				error: "release_exists".to_string(),
				message: format!("Release {} already exists", body.version),
			}),
		));
	}

	let date_released = body
		.date_released
		.and_then(|s| chrono::DateTime::parse_from_rfc3339(&s).ok())
		.map(|dt| dt.with_timezone(&Utc));

	let release = Release {
		id: ReleaseId::new(),
		org_id: project.org_id,
		project_id,
		version: body.version.clone(),
		short_version: body.short_version,
		url: body.url,
		crash_count: 0,
		new_issue_count: 0,
		regression_count: 0,
		user_count: 0,
		date_released,
		first_event: None,
		last_event: None,
		created_at: Utc::now(),
	};

	state
		.crash_repo
		.create_release(&release)
		.await
		.map_err(|e| {
			tracing::error!(error = %e, "Failed to create release");
			(
				StatusCode::INTERNAL_SERVER_ERROR,
				Json(CrashErrorResponse {
					error: "internal_error".to_string(),
					message: t(&locale, "server.api.error.internal").to_string(),
				}),
			)
		})?;

	info!(release_id = %release.id, version = %release.version, "Release created");

	state.audit_service.log(
		AuditLogBuilder::new(AuditEventType::CrashReleaseCreated)
			.actor(AuditUserId::new(current_user.user.id.into_inner()))
			.resource("crash_release", release.id.to_string())
			.details(serde_json::json!({
				"project_id": project_id.to_string(),
				"version": release.version.clone(),
			}))
			.build(),
	);

	Ok((StatusCode::CREATED, Json(ReleaseResponse::from(release))))
}

/// GET /api/crash/projects/{project_id}/releases/{version} - Get release detail
#[utoipa::path(
	get,
	path = "/api/crash/projects/{project_id}/releases/{version}",
	params(
		("project_id" = String, Path, description = "Project ID"),
		("version" = String, Path, description = "Release version"),
	),
	responses(
		(status = 200, description = "Release detail", body = ReleaseResponse),
		(status = 403, description = "Forbidden", body = CrashErrorResponse),
		(status = 404, description = "Release not found", body = CrashErrorResponse),
	),
	security(("bearer" = [])),
	tag = "crash"
)]
#[instrument(skip(state, current_user))]
pub async fn get_release(
	State(state): State<AppState>,
	RequireAuth(current_user): RequireAuth,
	Path((project_id_str, version)): Path<(String, String)>,
) -> Result<Json<ReleaseResponse>, (StatusCode, Json<CrashErrorResponse>)> {
	let locale = resolve_user_locale(&current_user, &state.default_locale);

	let project_id: ProjectId = project_id_str.parse().map_err(|_| {
		(
			StatusCode::BAD_REQUEST,
			Json(CrashErrorResponse {
				error: "invalid_project_id".to_string(),
				message: "Invalid project ID".to_string(),
			}),
		)
	})?;

	let project = state
		.crash_repo
		.get_project_by_id(project_id)
		.await
		.map_err(|e| {
			tracing::error!(error = %e, "Failed to get project");
			(
				StatusCode::INTERNAL_SERVER_ERROR,
				Json(CrashErrorResponse {
					error: "internal_error".to_string(),
					message: t(&locale, "server.api.error.internal").to_string(),
				}),
			)
		})?
		.ok_or_else(|| {
			(
				StatusCode::NOT_FOUND,
				Json(CrashErrorResponse {
					error: "project_not_found".to_string(),
					message: "Project not found".to_string(),
				}),
			)
		})?;

	verify_org_membership(&state, &project.org_id, &current_user.user.id, &locale).await?;

	let release = state
		.crash_repo
		.get_release_by_version(project_id, &version)
		.await
		.map_err(|e| {
			tracing::error!(error = %e, "Failed to get release");
			(
				StatusCode::INTERNAL_SERVER_ERROR,
				Json(CrashErrorResponse {
					error: "internal_error".to_string(),
					message: t(&locale, "server.api.error.internal").to_string(),
				}),
			)
		})?
		.ok_or_else(|| {
			(
				StatusCode::NOT_FOUND,
				Json(CrashErrorResponse {
					error: "release_not_found".to_string(),
					message: format!("Release {} not found", version),
				}),
			)
		})?;

	info!(release_id = %release.id, version = %release.version, "Release retrieved");

	Ok(Json(ReleaseResponse::from(release)))
}

// ============================================================================
// Artifact Endpoints (Symbol Upload)
// ============================================================================

/// Response for artifact operations.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct ArtifactResponse {
	pub id: String,
	pub project_id: String,
	pub release: String,
	pub dist: Option<String>,
	pub artifact_type: String,
	pub name: String,
	pub size_bytes: u64,
	pub sha256: String,
	pub source_map_url: Option<String>,
	pub sources_content: bool,
	pub uploaded_at: String,
	pub uploaded_by: String,
	pub last_accessed_at: Option<String>,
}

impl From<SymbolArtifact> for ArtifactResponse {
	fn from(a: SymbolArtifact) -> Self {
		Self {
			id: a.id.to_string(),
			project_id: a.project_id.to_string(),
			release: a.release,
			dist: a.dist,
			artifact_type: a.artifact_type.to_string(),
			name: a.name,
			size_bytes: a.size_bytes,
			sha256: a.sha256,
			source_map_url: a.source_map_url,
			sources_content: a.sources_content,
			uploaded_at: a.uploaded_at.to_rfc3339(),
			uploaded_by: a.uploaded_by.to_string(),
			last_accessed_at: a.last_accessed_at.map(|dt| dt.to_rfc3339()),
		}
	}
}

/// Response for artifact upload operations.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct UploadArtifactResponse {
	/// Total number of files in the request
	pub total: usize,
	/// Number of newly uploaded files
	pub uploaded_count: usize,
	/// Number of files that already existed (deduplicated)
	pub existing_count: usize,
	/// Number of files that failed to upload
	pub error_count: usize,
	/// List of artifacts (both new and existing)
	pub artifacts: Vec<ArtifactResponse>,
	/// Errors for files that failed
	pub errors: Vec<ArtifactUploadError>,
}

/// Error for a single artifact upload.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct ArtifactUploadError {
	pub filename: String,
	pub error: String,
}

/// Query parameters for listing artifacts.
#[derive(Debug, Deserialize)]
pub struct ListArtifactsParams {
	pub release: Option<String>,
	#[serde(default = "default_artifact_limit")]
	pub limit: u32,
}

fn default_artifact_limit() -> u32 {
	100
}

/// POST /api/crash/projects/{project_id}/artifacts - Upload artifacts (multipart)
///
/// Upload source maps and minified source files for a release. Files are deduplicated
/// by SHA256 hash. The multipart form should include:
/// - `release` (text field): The release version these artifacts belong to
/// - `dist` (optional text field): Distribution variant
/// - Files: One or more source map (.map) or JavaScript (.js) files
#[utoipa::path(
	post,
	path = "/api/crash/projects/{project_id}/artifacts",
	params(
		("project_id" = String, Path, description = "Project ID"),
	),
	responses(
		(status = 200, description = "Upload results", body = UploadArtifactResponse),
		(status = 400, description = "Invalid request", body = CrashErrorResponse),
		(status = 403, description = "Forbidden", body = CrashErrorResponse),
		(status = 404, description = "Project not found", body = CrashErrorResponse),
	),
	security(("bearer" = [])),
	tag = "crash"
)]
#[instrument(skip(state, current_user, multipart))]
pub async fn upload_artifacts(
	State(state): State<AppState>,
	RequireAuth(current_user): RequireAuth,
	Path(project_id_str): Path<String>,
	mut multipart: Multipart,
) -> Result<Json<UploadArtifactResponse>, (StatusCode, Json<CrashErrorResponse>)> {
	let locale = resolve_user_locale(&current_user, &state.default_locale);

	let project_id: ProjectId = project_id_str.parse().map_err(|_| {
		(
			StatusCode::BAD_REQUEST,
			Json(CrashErrorResponse {
				error: "invalid_project_id".to_string(),
				message: "Invalid project ID".to_string(),
			}),
		)
	})?;

	let project = state
		.crash_repo
		.get_project_by_id(project_id)
		.await
		.map_err(|e| {
			tracing::error!(error = %e, "Failed to get project");
			(
				StatusCode::INTERNAL_SERVER_ERROR,
				Json(CrashErrorResponse {
					error: "internal_error".to_string(),
					message: t(&locale, "server.api.error.internal").to_string(),
				}),
			)
		})?
		.ok_or_else(|| {
			(
				StatusCode::NOT_FOUND,
				Json(CrashErrorResponse {
					error: "project_not_found".to_string(),
					message: "Project not found".to_string(),
				}),
			)
		})?;

	verify_org_membership(&state, &project.org_id, &current_user.user.id, &locale).await?;

	// Parse multipart form
	let mut release: Option<String> = None;
	let mut dist: Option<String> = None;
	let mut files: Vec<(String, Vec<u8>)> = Vec::new();

	while let Some(field) = multipart.next_field().await.map_err(|e| {
		tracing::error!(error = %e, "Failed to read multipart field");
		(
			StatusCode::BAD_REQUEST,
			Json(CrashErrorResponse {
				error: "invalid_multipart".to_string(),
				message: format!("Failed to read multipart data: {}", e),
			}),
		)
	})? {
		let name = field.name().map(|s| s.to_string());
		let file_name = field.file_name().map(|s| s.to_string());

		match name.as_deref() {
			Some("release") => {
				let bytes = field.bytes().await.map_err(|e| {
					(
						StatusCode::BAD_REQUEST,
						Json(CrashErrorResponse {
							error: "invalid_multipart".to_string(),
							message: format!("Failed to read release field: {}", e),
						}),
					)
				})?;
				release = Some(String::from_utf8_lossy(&bytes).to_string());
			}
			Some("dist") => {
				let bytes = field.bytes().await.map_err(|e| {
					(
						StatusCode::BAD_REQUEST,
						Json(CrashErrorResponse {
							error: "invalid_multipart".to_string(),
							message: format!("Failed to read dist field: {}", e),
						}),
					)
				})?;
				let dist_str = String::from_utf8_lossy(&bytes).to_string();
				if !dist_str.is_empty() {
					dist = Some(dist_str);
				}
			}
			_ => {
				// Assume it's a file
				if let Some(filename) = file_name {
					let data = field.bytes().await.map_err(|e| {
						(
							StatusCode::BAD_REQUEST,
							Json(CrashErrorResponse {
								error: "invalid_multipart".to_string(),
								message: format!("Failed to read file {}: {}", filename, e),
							}),
						)
					})?;
					files.push((filename, data.to_vec()));
				}
			}
		}
	}

	// Validate release is provided
	let release = release.ok_or_else(|| {
		(
			StatusCode::BAD_REQUEST,
			Json(CrashErrorResponse {
				error: "missing_release".to_string(),
				message: "The 'release' field is required".to_string(),
			}),
		)
	})?;

	if release.is_empty() || release.len() > 200 {
		return Err((
			StatusCode::BAD_REQUEST,
			Json(CrashErrorResponse {
				error: "invalid_release".to_string(),
				message: "Release must be 1-200 characters".to_string(),
			}),
		));
	}

	// Process files
	let mut artifacts = Vec::new();
	let mut errors = Vec::new();
	let mut uploaded_count = 0;
	let mut existing_count = 0;
	let total = files.len();

	for (filename, data) in files {
		// Compute SHA256
		use sha2::{Digest, Sha256};
		let mut hasher = Sha256::new();
		hasher.update(&data);
		let sha256 = format!("{:x}", hasher.finalize());

		// Check for existing artifact by hash
		match state
			.crash_repo
			.get_artifact_by_sha256(project_id, &sha256)
			.await
		{
			Ok(Some(existing)) => {
				info!(
					artifact_id = %existing.id,
					filename = %filename,
					sha256 = %sha256,
					"Artifact already exists (deduplicated)"
				);
				artifacts.push(ArtifactResponse::from(existing));
				existing_count += 1;
				continue;
			}
			Ok(None) => {}
			Err(e) => {
				tracing::warn!(error = %e, filename = %filename, "Failed to check for existing artifact");
				errors.push(ArtifactUploadError {
					filename,
					error: format!("Failed to check for duplicates: {}", e),
				});
				continue;
			}
		}

		// Determine artifact type
		let artifact_type = if filename.ends_with(".map") {
			ArtifactType::SourceMap
		} else {
			ArtifactType::MinifiedSource
		};

		// For source maps, check if sourcesContent is embedded
		let sources_content = if artifact_type == ArtifactType::SourceMap {
			// Simple check for sourcesContent in the JSON
			String::from_utf8_lossy(&data).contains("\"sourcesContent\"")
		} else {
			false
		};

		let artifact = SymbolArtifact {
			id: SymbolArtifactId::new(),
			org_id: project.org_id,
			project_id,
			release: release.clone(),
			dist: dist.clone(),
			artifact_type,
			name: filename.clone(),
			data: data.clone(),
			size_bytes: data.len() as u64,
			sha256,
			source_map_url: None,
			sources_content,
			uploaded_at: Utc::now(),
			uploaded_by: UserId(current_user.user.id.into_inner()),
			last_accessed_at: None,
		};

		match state.crash_repo.create_artifact(&artifact).await {
			Ok(()) => {
				info!(
					artifact_id = %artifact.id,
					filename = %filename,
					size_bytes = %artifact.size_bytes,
					"Artifact uploaded"
				);
				artifacts.push(ArtifactResponse::from(artifact));
				uploaded_count += 1;
			}
			Err(e) => {
				tracing::error!(error = %e, filename = %filename, "Failed to save artifact");
				errors.push(ArtifactUploadError {
					filename,
					error: format!("Failed to save: {}", e),
				});
			}
		}
	}

	info!(
		project_id = %project_id,
		release = %release,
		total,
		uploaded_count,
		existing_count,
		error_count = errors.len(),
		"Artifact upload completed"
	);

	if uploaded_count > 0 {
		state.audit_service.log(
			AuditLogBuilder::new(AuditEventType::CrashSymbolsUploaded)
				.actor(AuditUserId::new(current_user.user.id.into_inner()))
				.resource("crash_project", project_id.to_string())
				.details(serde_json::json!({
					"release": release,
					"total": total,
					"uploaded_count": uploaded_count,
					"existing_count": existing_count,
					"error_count": errors.len(),
				}))
				.build(),
		);
	}

	Ok(Json(UploadArtifactResponse {
		total,
		uploaded_count,
		existing_count,
		error_count: errors.len(),
		artifacts,
		errors,
	}))
}

/// GET /api/crash/projects/{project_id}/artifacts - List artifacts
#[utoipa::path(
	get,
	path = "/api/crash/projects/{project_id}/artifacts",
	params(
		("project_id" = String, Path, description = "Project ID"),
		("release" = Option<String>, Query, description = "Filter by release version"),
		("limit" = Option<u32>, Query, description = "Maximum number of artifacts to return (default 100)"),
	),
	responses(
		(status = 200, description = "List of artifacts", body = Vec<ArtifactResponse>),
		(status = 403, description = "Forbidden", body = CrashErrorResponse),
		(status = 404, description = "Project not found", body = CrashErrorResponse),
	),
	security(("bearer" = [])),
	tag = "crash"
)]
#[instrument(skip(state, current_user))]
pub async fn list_artifacts(
	State(state): State<AppState>,
	RequireAuth(current_user): RequireAuth,
	Path(project_id_str): Path<String>,
	Query(params): Query<ListArtifactsParams>,
) -> Result<Json<Vec<ArtifactResponse>>, (StatusCode, Json<CrashErrorResponse>)> {
	let locale = resolve_user_locale(&current_user, &state.default_locale);

	let project_id: ProjectId = project_id_str.parse().map_err(|_| {
		(
			StatusCode::BAD_REQUEST,
			Json(CrashErrorResponse {
				error: "invalid_project_id".to_string(),
				message: "Invalid project ID".to_string(),
			}),
		)
	})?;

	let project = state
		.crash_repo
		.get_project_by_id(project_id)
		.await
		.map_err(|e| {
			tracing::error!(error = %e, "Failed to get project");
			(
				StatusCode::INTERNAL_SERVER_ERROR,
				Json(CrashErrorResponse {
					error: "internal_error".to_string(),
					message: t(&locale, "server.api.error.internal").to_string(),
				}),
			)
		})?
		.ok_or_else(|| {
			(
				StatusCode::NOT_FOUND,
				Json(CrashErrorResponse {
					error: "project_not_found".to_string(),
					message: "Project not found".to_string(),
				}),
			)
		})?;

	verify_org_membership(&state, &project.org_id, &current_user.user.id, &locale).await?;

	let limit = params.limit.min(1000);
	let artifacts = state
		.crash_repo
		.list_artifacts(project_id, params.release.as_deref(), limit)
		.await
		.map_err(|e| {
			tracing::error!(error = %e, "Failed to list artifacts");
			(
				StatusCode::INTERNAL_SERVER_ERROR,
				Json(CrashErrorResponse {
					error: "internal_error".to_string(),
					message: t(&locale, "server.api.error.internal").to_string(),
				}),
			)
		})?;

	info!(
		project_id = %project_id,
		artifact_count = %artifacts.len(),
		"Artifacts listed"
	);

	Ok(Json(
		artifacts.into_iter().map(ArtifactResponse::from).collect(),
	))
}

/// GET /api/crash/projects/{project_id}/artifacts/{artifact_id} - Get artifact metadata
#[utoipa::path(
	get,
	path = "/api/crash/projects/{project_id}/artifacts/{artifact_id}",
	params(
		("project_id" = String, Path, description = "Project ID"),
		("artifact_id" = String, Path, description = "Artifact ID"),
	),
	responses(
		(status = 200, description = "Artifact metadata", body = ArtifactResponse),
		(status = 403, description = "Forbidden", body = CrashErrorResponse),
		(status = 404, description = "Artifact not found", body = CrashErrorResponse),
	),
	security(("bearer" = [])),
	tag = "crash"
)]
#[instrument(skip(state, current_user))]
pub async fn get_artifact(
	State(state): State<AppState>,
	RequireAuth(current_user): RequireAuth,
	Path((project_id_str, artifact_id_str)): Path<(String, String)>,
) -> Result<Json<ArtifactResponse>, (StatusCode, Json<CrashErrorResponse>)> {
	let locale = resolve_user_locale(&current_user, &state.default_locale);

	let project_id: ProjectId = project_id_str.parse().map_err(|_| {
		(
			StatusCode::BAD_REQUEST,
			Json(CrashErrorResponse {
				error: "invalid_project_id".to_string(),
				message: "Invalid project ID".to_string(),
			}),
		)
	})?;

	let artifact_id: SymbolArtifactId = artifact_id_str.parse().map_err(|_| {
		(
			StatusCode::BAD_REQUEST,
			Json(CrashErrorResponse {
				error: "invalid_artifact_id".to_string(),
				message: "Invalid artifact ID".to_string(),
			}),
		)
	})?;

	let project = state
		.crash_repo
		.get_project_by_id(project_id)
		.await
		.map_err(|e| {
			tracing::error!(error = %e, "Failed to get project");
			(
				StatusCode::INTERNAL_SERVER_ERROR,
				Json(CrashErrorResponse {
					error: "internal_error".to_string(),
					message: t(&locale, "server.api.error.internal").to_string(),
				}),
			)
		})?
		.ok_or_else(|| {
			(
				StatusCode::NOT_FOUND,
				Json(CrashErrorResponse {
					error: "project_not_found".to_string(),
					message: "Project not found".to_string(),
				}),
			)
		})?;

	verify_org_membership(&state, &project.org_id, &current_user.user.id, &locale).await?;

	let artifact = state
		.crash_repo
		.get_artifact_by_id(artifact_id)
		.await
		.map_err(|e| {
			tracing::error!(error = %e, "Failed to get artifact");
			(
				StatusCode::INTERNAL_SERVER_ERROR,
				Json(CrashErrorResponse {
					error: "internal_error".to_string(),
					message: t(&locale, "server.api.error.internal").to_string(),
				}),
			)
		})?
		.ok_or_else(|| {
			(
				StatusCode::NOT_FOUND,
				Json(CrashErrorResponse {
					error: "artifact_not_found".to_string(),
					message: "Artifact not found".to_string(),
				}),
			)
		})?;

	// Verify artifact belongs to project
	if artifact.project_id != project_id {
		return Err((
			StatusCode::NOT_FOUND,
			Json(CrashErrorResponse {
				error: "artifact_not_found".to_string(),
				message: "Artifact not found".to_string(),
			}),
		));
	}

	// Update last_accessed_at
	let _ = state
		.crash_repo
		.update_artifact_last_accessed(artifact_id)
		.await;

	info!(
		artifact_id = %artifact.id,
		name = %artifact.name,
		"Artifact retrieved"
	);

	Ok(Json(ArtifactResponse::from(artifact)))
}

/// DELETE /api/crash/projects/{project_id}/artifacts/{artifact_id} - Delete artifact
#[utoipa::path(
	delete,
	path = "/api/crash/projects/{project_id}/artifacts/{artifact_id}",
	params(
		("project_id" = String, Path, description = "Project ID"),
		("artifact_id" = String, Path, description = "Artifact ID"),
	),
	responses(
		(status = 204, description = "Artifact deleted"),
		(status = 403, description = "Forbidden", body = CrashErrorResponse),
		(status = 404, description = "Artifact not found", body = CrashErrorResponse),
	),
	security(("bearer" = [])),
	tag = "crash"
)]
#[instrument(skip(state, current_user))]
pub async fn delete_artifact(
	State(state): State<AppState>,
	RequireAuth(current_user): RequireAuth,
	Path((project_id_str, artifact_id_str)): Path<(String, String)>,
) -> Result<StatusCode, (StatusCode, Json<CrashErrorResponse>)> {
	let locale = resolve_user_locale(&current_user, &state.default_locale);

	let project_id: ProjectId = project_id_str.parse().map_err(|_| {
		(
			StatusCode::BAD_REQUEST,
			Json(CrashErrorResponse {
				error: "invalid_project_id".to_string(),
				message: "Invalid project ID".to_string(),
			}),
		)
	})?;

	let artifact_id: SymbolArtifactId = artifact_id_str.parse().map_err(|_| {
		(
			StatusCode::BAD_REQUEST,
			Json(CrashErrorResponse {
				error: "invalid_artifact_id".to_string(),
				message: "Invalid artifact ID".to_string(),
			}),
		)
	})?;

	let project = state
		.crash_repo
		.get_project_by_id(project_id)
		.await
		.map_err(|e| {
			tracing::error!(error = %e, "Failed to get project");
			(
				StatusCode::INTERNAL_SERVER_ERROR,
				Json(CrashErrorResponse {
					error: "internal_error".to_string(),
					message: t(&locale, "server.api.error.internal").to_string(),
				}),
			)
		})?
		.ok_or_else(|| {
			(
				StatusCode::NOT_FOUND,
				Json(CrashErrorResponse {
					error: "project_not_found".to_string(),
					message: "Project not found".to_string(),
				}),
			)
		})?;

	verify_org_membership(&state, &project.org_id, &current_user.user.id, &locale).await?;

	// Verify artifact exists and belongs to project
	let artifact = state
		.crash_repo
		.get_artifact_by_id(artifact_id)
		.await
		.map_err(|e| {
			tracing::error!(error = %e, "Failed to get artifact");
			(
				StatusCode::INTERNAL_SERVER_ERROR,
				Json(CrashErrorResponse {
					error: "internal_error".to_string(),
					message: t(&locale, "server.api.error.internal").to_string(),
				}),
			)
		})?
		.ok_or_else(|| {
			(
				StatusCode::NOT_FOUND,
				Json(CrashErrorResponse {
					error: "artifact_not_found".to_string(),
					message: "Artifact not found".to_string(),
				}),
			)
		})?;

	if artifact.project_id != project_id {
		return Err((
			StatusCode::NOT_FOUND,
			Json(CrashErrorResponse {
				error: "artifact_not_found".to_string(),
				message: "Artifact not found".to_string(),
			}),
		));
	}

	let deleted = state
		.crash_repo
		.delete_artifact(artifact_id)
		.await
		.map_err(|e| {
			tracing::error!(error = %e, "Failed to delete artifact");
			(
				StatusCode::INTERNAL_SERVER_ERROR,
				Json(CrashErrorResponse {
					error: "internal_error".to_string(),
					message: t(&locale, "server.api.error.internal").to_string(),
				}),
			)
		})?;

	if deleted {
		info!(
			artifact_id = %artifact.id,
			name = %artifact.name,
			"Artifact deleted"
		);

		state.audit_service.log(
			AuditLogBuilder::new(AuditEventType::CrashSymbolsDeleted)
				.actor(AuditUserId::new(current_user.user.id.into_inner()))
				.resource("crash_artifact", artifact.id.to_string())
				.details(serde_json::json!({
					"project_id": project_id.to_string(),
					"name": artifact.name.clone(),
					"release": artifact.release.clone(),
				}))
				.build(),
		);

		Ok(StatusCode::NO_CONTENT)
	} else {
		Err((
			StatusCode::NOT_FOUND,
			Json(CrashErrorResponse {
				error: "artifact_not_found".to_string(),
				message: "Artifact not found".to_string(),
			}),
		))
	}
}

// ============================================================================
// API Key Management Endpoints
// ============================================================================

/// Request body for creating an API key.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct CreateApiKeyRequest {
	pub name: String,
	/// "capture" for client-safe keys, "admin" for management keys
	pub key_type: String,
	pub rate_limit_per_minute: Option<u32>,
	#[serde(default)]
	pub allowed_origins: Vec<String>,
}

/// Response for creating an API key.
/// Note: The raw key is only returned once at creation time.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct CreateApiKeyResponse {
	pub id: String,
	pub key: String,
	pub name: String,
	pub key_type: String,
	pub created_at: String,
}

/// Response for listing API keys.
/// Note: key_hash is not exposed, only metadata.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct ApiKeyResponse {
	pub id: String,
	pub name: String,
	pub key_type: String,
	pub rate_limit_per_minute: Option<u32>,
	pub allowed_origins: Vec<String>,
	pub created_at: String,
	pub last_used_at: Option<String>,
	pub revoked_at: Option<String>,
}

impl From<CrashApiKey> for ApiKeyResponse {
	fn from(key: CrashApiKey) -> Self {
		Self {
			id: key.id.to_string(),
			name: key.name,
			key_type: key.key_type.to_string(),
			rate_limit_per_minute: key.rate_limit_per_minute,
			allowed_origins: key.allowed_origins,
			created_at: key.created_at.to_rfc3339(),
			last_used_at: key.last_used_at.map(|dt| dt.to_rfc3339()),
			revoked_at: key.revoked_at.map(|dt| dt.to_rfc3339()),
		}
	}
}

/// POST /api/crash/projects/{project_id}/api-keys - Create a new API key
#[utoipa::path(
	post,
	path = "/api/crash/projects/{project_id}/api-keys",
	params(
		("project_id" = String, Path, description = "Project ID"),
	),
	request_body = CreateApiKeyRequest,
	responses(
		(status = 201, description = "API key created", body = CreateApiKeyResponse),
		(status = 400, description = "Invalid request", body = CrashErrorResponse),
		(status = 403, description = "Forbidden", body = CrashErrorResponse),
		(status = 404, description = "Project not found", body = CrashErrorResponse),
	),
	tag = "crash"
)]
#[instrument(skip(state, current_user, body), fields(project_id = %project_id))]
pub async fn create_api_key(
	State(state): State<AppState>,
	RequireAuth(current_user): RequireAuth,
	Path(project_id): Path<String>,
	Json(body): Json<CreateApiKeyRequest>,
) -> Result<(StatusCode, Json<CreateApiKeyResponse>), (StatusCode, Json<CrashErrorResponse>)> {
	let locale = resolve_user_locale(&current_user, &state.default_locale);

	// Parse project ID
	let project_id: ProjectId = project_id.parse().map_err(|_| {
		(
			StatusCode::BAD_REQUEST,
			Json(CrashErrorResponse {
				error: "invalid_project_id".to_string(),
				message: "Invalid project ID".to_string(),
			}),
		)
	})?;

	// Get project
	let project = state
		.crash_repo
		.get_project_by_id(project_id)
		.await
		.map_err(|e| {
			tracing::error!(error = %e, "Failed to get project");
			(
				StatusCode::INTERNAL_SERVER_ERROR,
				Json(CrashErrorResponse {
					error: "internal_error".to_string(),
					message: t(&locale, "server.api.error.internal").to_string(),
				}),
			)
		})?
		.ok_or_else(|| {
			(
				StatusCode::NOT_FOUND,
				Json(CrashErrorResponse {
					error: "project_not_found".to_string(),
					message: "Project not found".to_string(),
				}),
			)
		})?;

	// Verify org membership
	verify_org_membership(&state, &project.org_id, &current_user.user.id, &locale).await?;

	// Validate key type
	let key_type: CrashKeyType = body.key_type.parse().map_err(|_| {
		(
			StatusCode::BAD_REQUEST,
			Json(CrashErrorResponse {
				error: "invalid_key_type".to_string(),
				message: "Key type must be 'capture' or 'admin'".to_string(),
			}),
		)
	})?;

	// Generate the raw key
	let prefix = match key_type {
		CrashKeyType::Capture => KEY_PREFIX_CAPTURE,
		CrashKeyType::Admin => KEY_PREFIX_ADMIN,
	};
	let raw_key = generate_api_key(prefix);

	// Hash the key for storage
	let key_hash = hash_api_key(&raw_key).map_err(|e| {
		tracing::error!(error = %e, "Failed to hash API key");
		(
			StatusCode::INTERNAL_SERVER_ERROR,
			Json(CrashErrorResponse {
				error: "internal_error".to_string(),
				message: t(&locale, "server.api.error.internal").to_string(),
			}),
		)
	})?;

	let now = Utc::now();
	let api_key = CrashApiKey {
		id: CrashApiKeyId::new(),
		project_id,
		name: body.name.clone(),
		key_type,
		key_hash,
		rate_limit_per_minute: body.rate_limit_per_minute,
		allowed_origins: body.allowed_origins,
		created_by: UserId(current_user.user.id.into_inner()),
		created_at: now,
		last_used_at: None,
		revoked_at: None,
	};

	state.crash_repo.create_api_key(&api_key).await.map_err(|e| {
		tracing::error!(error = %e, "Failed to create API key");
		(
			StatusCode::INTERNAL_SERVER_ERROR,
			Json(CrashErrorResponse {
				error: "internal_error".to_string(),
				message: t(&locale, "server.api.error.internal").to_string(),
			}),
		)
	})?;

	info!(
		api_key_id = %api_key.id,
		project_id = %project_id,
		key_type = %key_type,
		"API key created"
	);

	Ok((
		StatusCode::CREATED,
		Json(CreateApiKeyResponse {
			id: api_key.id.to_string(),
			key: raw_key,
			name: api_key.name,
			key_type: api_key.key_type.to_string(),
			created_at: api_key.created_at.to_rfc3339(),
		}),
	))
}

/// GET /api/crash/projects/{project_id}/api-keys - List API keys for a project
#[utoipa::path(
	get,
	path = "/api/crash/projects/{project_id}/api-keys",
	params(
		("project_id" = String, Path, description = "Project ID"),
	),
	responses(
		(status = 200, description = "API keys retrieved", body = Vec<ApiKeyResponse>),
		(status = 403, description = "Forbidden", body = CrashErrorResponse),
		(status = 404, description = "Project not found", body = CrashErrorResponse),
	),
	tag = "crash"
)]
#[instrument(skip(state, current_user), fields(project_id = %project_id))]
pub async fn list_api_keys(
	State(state): State<AppState>,
	RequireAuth(current_user): RequireAuth,
	Path(project_id): Path<String>,
) -> Result<Json<Vec<ApiKeyResponse>>, (StatusCode, Json<CrashErrorResponse>)> {
	let locale = resolve_user_locale(&current_user, &state.default_locale);

	// Parse project ID
	let project_id: ProjectId = project_id.parse().map_err(|_| {
		(
			StatusCode::BAD_REQUEST,
			Json(CrashErrorResponse {
				error: "invalid_project_id".to_string(),
				message: "Invalid project ID".to_string(),
			}),
		)
	})?;

	// Get project
	let project = state
		.crash_repo
		.get_project_by_id(project_id)
		.await
		.map_err(|e| {
			tracing::error!(error = %e, "Failed to get project");
			(
				StatusCode::INTERNAL_SERVER_ERROR,
				Json(CrashErrorResponse {
					error: "internal_error".to_string(),
					message: t(&locale, "server.api.error.internal").to_string(),
				}),
			)
		})?
		.ok_or_else(|| {
			(
				StatusCode::NOT_FOUND,
				Json(CrashErrorResponse {
					error: "project_not_found".to_string(),
					message: "Project not found".to_string(),
				}),
			)
		})?;

	// Verify org membership
	verify_org_membership(&state, &project.org_id, &current_user.user.id, &locale).await?;

	// List API keys
	let keys = state
		.crash_repo
		.list_api_keys(project_id)
		.await
		.map_err(|e| {
			tracing::error!(error = %e, "Failed to list API keys");
			(
				StatusCode::INTERNAL_SERVER_ERROR,
				Json(CrashErrorResponse {
					error: "internal_error".to_string(),
					message: t(&locale, "server.api.error.internal").to_string(),
				}),
			)
		})?;

	Ok(Json(keys.into_iter().map(ApiKeyResponse::from).collect()))
}

/// DELETE /api/crash/projects/{project_id}/api-keys/{key_id} - Revoke an API key
#[utoipa::path(
	delete,
	path = "/api/crash/projects/{project_id}/api-keys/{key_id}",
	params(
		("project_id" = String, Path, description = "Project ID"),
		("key_id" = String, Path, description = "API key ID"),
	),
	responses(
		(status = 204, description = "API key revoked"),
		(status = 403, description = "Forbidden", body = CrashErrorResponse),
		(status = 404, description = "API key not found", body = CrashErrorResponse),
	),
	tag = "crash"
)]
#[instrument(skip(state, current_user), fields(project_id = %project_id, key_id = %key_id))]
pub async fn revoke_api_key(
	State(state): State<AppState>,
	RequireAuth(current_user): RequireAuth,
	Path((project_id, key_id)): Path<(String, String)>,
) -> Result<StatusCode, (StatusCode, Json<CrashErrorResponse>)> {
	let locale = resolve_user_locale(&current_user, &state.default_locale);

	// Parse IDs
	let project_id: ProjectId = project_id.parse().map_err(|_| {
		(
			StatusCode::BAD_REQUEST,
			Json(CrashErrorResponse {
				error: "invalid_project_id".to_string(),
				message: "Invalid project ID".to_string(),
			}),
		)
	})?;

	let key_id: CrashApiKeyId = key_id.parse().map_err(|_| {
		(
			StatusCode::BAD_REQUEST,
			Json(CrashErrorResponse {
				error: "invalid_key_id".to_string(),
				message: "Invalid API key ID".to_string(),
			}),
		)
	})?;

	// Get project
	let project = state
		.crash_repo
		.get_project_by_id(project_id)
		.await
		.map_err(|e| {
			tracing::error!(error = %e, "Failed to get project");
			(
				StatusCode::INTERNAL_SERVER_ERROR,
				Json(CrashErrorResponse {
					error: "internal_error".to_string(),
					message: t(&locale, "server.api.error.internal").to_string(),
				}),
			)
		})?
		.ok_or_else(|| {
			(
				StatusCode::NOT_FOUND,
				Json(CrashErrorResponse {
					error: "project_not_found".to_string(),
					message: "Project not found".to_string(),
				}),
			)
		})?;

	// Verify org membership
	verify_org_membership(&state, &project.org_id, &current_user.user.id, &locale).await?;

	// Verify API key exists and belongs to project
	let api_key = state
		.crash_repo
		.get_api_key_by_id(key_id)
		.await
		.map_err(|e| {
			tracing::error!(error = %e, "Failed to get API key");
			(
				StatusCode::INTERNAL_SERVER_ERROR,
				Json(CrashErrorResponse {
					error: "internal_error".to_string(),
					message: t(&locale, "server.api.error.internal").to_string(),
				}),
			)
		})?
		.ok_or_else(|| {
			(
				StatusCode::NOT_FOUND,
				Json(CrashErrorResponse {
					error: "api_key_not_found".to_string(),
					message: "API key not found".to_string(),
				}),
			)
		})?;

	if api_key.project_id != project_id {
		return Err((
			StatusCode::NOT_FOUND,
			Json(CrashErrorResponse {
				error: "api_key_not_found".to_string(),
				message: "API key not found".to_string(),
			}),
		));
	}

	// Revoke the key
	let revoked = state.crash_repo.revoke_api_key(key_id).await.map_err(|e| {
		tracing::error!(error = %e, "Failed to revoke API key");
		(
			StatusCode::INTERNAL_SERVER_ERROR,
			Json(CrashErrorResponse {
				error: "internal_error".to_string(),
				message: t(&locale, "server.api.error.internal").to_string(),
			}),
		)
	})?;

	if revoked {
		info!(api_key_id = %key_id, "API key revoked");
		Ok(StatusCode::NO_CONTENT)
	} else {
		// Key was already revoked
		Err((
			StatusCode::NOT_FOUND,
			Json(CrashErrorResponse {
				error: "api_key_not_found".to_string(),
				message: "API key not found or already revoked".to_string(),
			}),
		))
	}
}

// ============================================================================
// Assign Issue Endpoint
// ============================================================================

/// Request body for assigning an issue.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct AssignIssueRequest {
	/// User ID to assign the issue to. If None or null, unassigns the issue.
	pub user_id: Option<String>,
}

/// POST /api/crash/projects/{project_id}/issues/{issue_id}/assign - Assign an issue to a user
///
/// Assigns an issue to a specific user, or unassigns if user_id is null/omitted.
#[utoipa::path(
	post,
	path = "/api/crash/projects/{project_id}/issues/{issue_id}/assign",
	params(
		("project_id" = String, Path, description = "Project ID"),
		("issue_id" = String, Path, description = "Issue ID"),
	),
	request_body = AssignIssueRequest,
	responses(
		(status = 200, description = "Issue assigned", body = IssueDetailResponse),
		(status = 403, description = "Forbidden", body = CrashErrorResponse),
		(status = 404, description = "Issue not found", body = CrashErrorResponse),
	),
	security(("bearer" = [])),
	tag = "crash"
)]
#[instrument(skip(state, current_user, body))]
pub async fn assign_issue(
	State(state): State<AppState>,
	RequireAuth(current_user): RequireAuth,
	Path((project_id_str, issue_id_str)): Path<(String, String)>,
	Json(body): Json<AssignIssueRequest>,
) -> Result<Json<IssueDetailResponse>, (StatusCode, Json<CrashErrorResponse>)> {
	let locale = resolve_user_locale(&current_user, &state.default_locale);

	let project_id: ProjectId = project_id_str.parse().map_err(|_| {
		(
			StatusCode::BAD_REQUEST,
			Json(CrashErrorResponse {
				error: "invalid_project_id".to_string(),
				message: "Invalid project ID".to_string(),
			}),
		)
	})?;

	let issue_id: IssueId = issue_id_str.parse().map_err(|_| {
		(
			StatusCode::BAD_REQUEST,
			Json(CrashErrorResponse {
				error: "invalid_issue_id".to_string(),
				message: "Invalid issue ID".to_string(),
			}),
		)
	})?;

	let project = state
		.crash_repo
		.get_project_by_id(project_id)
		.await
		.map_err(|e| {
			tracing::error!(error = %e, "Failed to get project");
			(
				StatusCode::INTERNAL_SERVER_ERROR,
				Json(CrashErrorResponse {
					error: "internal_error".to_string(),
					message: t(&locale, "server.api.error.internal").to_string(),
				}),
			)
		})?
		.ok_or_else(|| {
			(
				StatusCode::NOT_FOUND,
				Json(CrashErrorResponse {
					error: "project_not_found".to_string(),
					message: "Project not found".to_string(),
				}),
			)
		})?;

	verify_org_membership(&state, &project.org_id, &current_user.user.id, &locale).await?;

	let mut issue = state
		.crash_repo
		.get_issue_by_id(issue_id)
		.await
		.map_err(|e| {
			tracing::error!(error = %e, "Failed to get issue");
			(
				StatusCode::INTERNAL_SERVER_ERROR,
				Json(CrashErrorResponse {
					error: "internal_error".to_string(),
					message: t(&locale, "server.api.error.internal").to_string(),
				}),
			)
		})?
		.ok_or_else(|| {
			(
				StatusCode::NOT_FOUND,
				Json(CrashErrorResponse {
					error: "issue_not_found".to_string(),
					message: "Issue not found".to_string(),
				}),
			)
		})?;

	if issue.project_id != project_id {
		return Err((
			StatusCode::NOT_FOUND,
			Json(CrashErrorResponse {
				error: "issue_not_found".to_string(),
				message: "Issue not found".to_string(),
			}),
		));
	}

	// Parse and assign user ID
	let assigned_user_id: Option<loom_crash_core::UserId> = match &body.user_id {
		Some(uid) => {
			let parsed: uuid::Uuid = uid.parse().map_err(|_| {
				(
					StatusCode::BAD_REQUEST,
					Json(CrashErrorResponse {
						error: "invalid_user_id".to_string(),
						message: "Invalid user ID".to_string(),
					}),
				)
			})?;
			Some(loom_crash_core::UserId(parsed))
		}
		None => None,
	};

	issue.assigned_to = assigned_user_id;
	issue.updated_at = Utc::now();

	state.crash_repo.update_issue(&issue).await.map_err(|e| {
		tracing::error!(error = %e, "Failed to update issue");
		(
			StatusCode::INTERNAL_SERVER_ERROR,
			Json(CrashErrorResponse {
				error: "internal_error".to_string(),
				message: t(&locale, "server.api.error.internal").to_string(),
			}),
		)
	})?;

	state.audit_service.log(
		AuditLogBuilder::new(AuditEventType::CrashIssueAssigned)
			.actor(AuditUserId::new(current_user.user.id.into_inner()))
			.resource("crash_issue", issue.id.to_string())
			.details(serde_json::json!({
				"project_id": project_id.to_string(),
				"short_id": issue.short_id.clone(),
				"assigned_to": body.user_id.clone(),
			}))
			.build(),
	);

	info!(
		issue_id = %issue.id,
		short_id = %issue.short_id,
		assigned_to = ?body.user_id,
		"Issue assigned"
	);

	Ok(Json(IssueDetailResponse::from(issue)))
}

// ============================================================================
// Delete Issue Endpoint
// ============================================================================

/// DELETE /api/crash/projects/{project_id}/issues/{issue_id} - Delete an issue
///
/// Permanently deletes an issue and all associated events.
#[utoipa::path(
	delete,
	path = "/api/crash/projects/{project_id}/issues/{issue_id}",
	params(
		("project_id" = String, Path, description = "Project ID"),
		("issue_id" = String, Path, description = "Issue ID"),
	),
	responses(
		(status = 204, description = "Issue deleted"),
		(status = 403, description = "Forbidden", body = CrashErrorResponse),
		(status = 404, description = "Issue not found", body = CrashErrorResponse),
	),
	security(("bearer" = [])),
	tag = "crash"
)]
#[instrument(skip(state, current_user))]
pub async fn delete_issue(
	State(state): State<AppState>,
	RequireAuth(current_user): RequireAuth,
	Path((project_id_str, issue_id_str)): Path<(String, String)>,
) -> Result<StatusCode, (StatusCode, Json<CrashErrorResponse>)> {
	let locale = resolve_user_locale(&current_user, &state.default_locale);

	let project_id: ProjectId = project_id_str.parse().map_err(|_| {
		(
			StatusCode::BAD_REQUEST,
			Json(CrashErrorResponse {
				error: "invalid_project_id".to_string(),
				message: "Invalid project ID".to_string(),
			}),
		)
	})?;

	let issue_id: IssueId = issue_id_str.parse().map_err(|_| {
		(
			StatusCode::BAD_REQUEST,
			Json(CrashErrorResponse {
				error: "invalid_issue_id".to_string(),
				message: "Invalid issue ID".to_string(),
			}),
		)
	})?;

	let project = state
		.crash_repo
		.get_project_by_id(project_id)
		.await
		.map_err(|e| {
			tracing::error!(error = %e, "Failed to get project");
			(
				StatusCode::INTERNAL_SERVER_ERROR,
				Json(CrashErrorResponse {
					error: "internal_error".to_string(),
					message: t(&locale, "server.api.error.internal").to_string(),
				}),
			)
		})?
		.ok_or_else(|| {
			(
				StatusCode::NOT_FOUND,
				Json(CrashErrorResponse {
					error: "project_not_found".to_string(),
					message: "Project not found".to_string(),
				}),
			)
		})?;

	verify_org_membership(&state, &project.org_id, &current_user.user.id, &locale).await?;

	// Get issue first to verify it exists and belongs to project
	let issue = state
		.crash_repo
		.get_issue_by_id(issue_id)
		.await
		.map_err(|e| {
			tracing::error!(error = %e, "Failed to get issue");
			(
				StatusCode::INTERNAL_SERVER_ERROR,
				Json(CrashErrorResponse {
					error: "internal_error".to_string(),
					message: t(&locale, "server.api.error.internal").to_string(),
				}),
			)
		})?
		.ok_or_else(|| {
			(
				StatusCode::NOT_FOUND,
				Json(CrashErrorResponse {
					error: "issue_not_found".to_string(),
					message: "Issue not found".to_string(),
				}),
			)
		})?;

	if issue.project_id != project_id {
		return Err((
			StatusCode::NOT_FOUND,
			Json(CrashErrorResponse {
				error: "issue_not_found".to_string(),
				message: "Issue not found".to_string(),
			}),
		));
	}

	let deleted = state.crash_repo.delete_issue(issue_id).await.map_err(|e| {
		tracing::error!(error = %e, "Failed to delete issue");
		(
			StatusCode::INTERNAL_SERVER_ERROR,
			Json(CrashErrorResponse {
				error: "internal_error".to_string(),
				message: t(&locale, "server.api.error.internal").to_string(),
			}),
		)
	})?;

	if deleted {
		state.audit_service.log(
			AuditLogBuilder::new(AuditEventType::CrashIssueDeleted)
				.actor(AuditUserId::new(current_user.user.id.into_inner()))
				.resource("crash_issue", issue.id.to_string())
				.details(serde_json::json!({
					"project_id": project_id.to_string(),
					"short_id": issue.short_id.clone(),
					"title": issue.title.clone(),
				}))
				.build(),
		);

		info!(issue_id = %issue_id, short_id = %issue.short_id, "Issue deleted");
		Ok(StatusCode::NO_CONTENT)
	} else {
		Err((
			StatusCode::NOT_FOUND,
			Json(CrashErrorResponse {
				error: "issue_not_found".to_string(),
				message: "Issue not found".to_string(),
			}),
		))
	}
}

// ============================================================================
// Project Detail Endpoints
// ============================================================================

/// GET /api/crash/projects/{project_id} - Get project detail
#[utoipa::path(
	get,
	path = "/api/crash/projects/{project_id}",
	params(
		("project_id" = String, Path, description = "Project ID"),
	),
	responses(
		(status = 200, description = "Project detail", body = ProjectResponse),
		(status = 403, description = "Forbidden", body = CrashErrorResponse),
		(status = 404, description = "Project not found", body = CrashErrorResponse),
	),
	security(("bearer" = [])),
	tag = "crash"
)]
#[instrument(skip(state, current_user))]
pub async fn get_project(
	State(state): State<AppState>,
	RequireAuth(current_user): RequireAuth,
	Path(project_id_str): Path<String>,
) -> Result<Json<ProjectResponse>, (StatusCode, Json<CrashErrorResponse>)> {
	let locale = resolve_user_locale(&current_user, &state.default_locale);

	let project_id: ProjectId = project_id_str.parse().map_err(|_| {
		(
			StatusCode::BAD_REQUEST,
			Json(CrashErrorResponse {
				error: "invalid_project_id".to_string(),
				message: "Invalid project ID".to_string(),
			}),
		)
	})?;

	let project = state
		.crash_repo
		.get_project_by_id(project_id)
		.await
		.map_err(|e| {
			tracing::error!(error = %e, "Failed to get project");
			(
				StatusCode::INTERNAL_SERVER_ERROR,
				Json(CrashErrorResponse {
					error: "internal_error".to_string(),
					message: t(&locale, "server.api.error.internal").to_string(),
				}),
			)
		})?
		.ok_or_else(|| {
			(
				StatusCode::NOT_FOUND,
				Json(CrashErrorResponse {
					error: "project_not_found".to_string(),
					message: "Project not found".to_string(),
				}),
			)
		})?;

	verify_org_membership(&state, &project.org_id, &current_user.user.id, &locale).await?;

	Ok(Json(ProjectResponse::from(project)))
}

/// Request body for updating a project.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct UpdateProjectRequest {
	/// New project name (optional)
	pub name: Option<String>,
	/// Auto-resolve age in days (optional, set to null to disable)
	pub auto_resolve_age_days: Option<u32>,
}

/// PATCH /api/crash/projects/{project_id} - Update a project
#[utoipa::path(
	patch,
	path = "/api/crash/projects/{project_id}",
	params(
		("project_id" = String, Path, description = "Project ID"),
	),
	request_body = UpdateProjectRequest,
	responses(
		(status = 200, description = "Project updated", body = ProjectResponse),
		(status = 403, description = "Forbidden", body = CrashErrorResponse),
		(status = 404, description = "Project not found", body = CrashErrorResponse),
	),
	security(("bearer" = [])),
	tag = "crash"
)]
#[instrument(skip(state, current_user, body))]
pub async fn update_project(
	State(state): State<AppState>,
	RequireAuth(current_user): RequireAuth,
	Path(project_id_str): Path<String>,
	Json(body): Json<UpdateProjectRequest>,
) -> Result<Json<ProjectResponse>, (StatusCode, Json<CrashErrorResponse>)> {
	let locale = resolve_user_locale(&current_user, &state.default_locale);

	let project_id: ProjectId = project_id_str.parse().map_err(|_| {
		(
			StatusCode::BAD_REQUEST,
			Json(CrashErrorResponse {
				error: "invalid_project_id".to_string(),
				message: "Invalid project ID".to_string(),
			}),
		)
	})?;

	let mut project = state
		.crash_repo
		.get_project_by_id(project_id)
		.await
		.map_err(|e| {
			tracing::error!(error = %e, "Failed to get project");
			(
				StatusCode::INTERNAL_SERVER_ERROR,
				Json(CrashErrorResponse {
					error: "internal_error".to_string(),
					message: t(&locale, "server.api.error.internal").to_string(),
				}),
			)
		})?
		.ok_or_else(|| {
			(
				StatusCode::NOT_FOUND,
				Json(CrashErrorResponse {
					error: "project_not_found".to_string(),
					message: "Project not found".to_string(),
				}),
			)
		})?;

	verify_org_membership(&state, &project.org_id, &current_user.user.id, &locale).await?;

	// Apply updates
	if let Some(name) = &body.name {
		if name.is_empty() {
			return Err((
				StatusCode::BAD_REQUEST,
				Json(CrashErrorResponse {
					error: "invalid_name".to_string(),
					message: "Project name cannot be empty".to_string(),
				}),
			));
		}
		project.name = name.clone();
	}

	if body.auto_resolve_age_days.is_some() {
		project.auto_resolve_age_days = body.auto_resolve_age_days;
	}

	project.updated_at = Utc::now();

	state
		.crash_repo
		.update_project(&project)
		.await
		.map_err(|e| {
			tracing::error!(error = %e, "Failed to update project");
			(
				StatusCode::INTERNAL_SERVER_ERROR,
				Json(CrashErrorResponse {
					error: "internal_error".to_string(),
					message: t(&locale, "server.api.error.internal").to_string(),
				}),
			)
		})?;

	info!(project_id = %project.id, "Project updated");

	Ok(Json(ProjectResponse::from(project)))
}

/// DELETE /api/crash/projects/{project_id} - Delete a project
///
/// Permanently deletes a project and all associated issues, events, and artifacts.
#[utoipa::path(
	delete,
	path = "/api/crash/projects/{project_id}",
	params(
		("project_id" = String, Path, description = "Project ID"),
	),
	responses(
		(status = 204, description = "Project deleted"),
		(status = 403, description = "Forbidden", body = CrashErrorResponse),
		(status = 404, description = "Project not found", body = CrashErrorResponse),
	),
	security(("bearer" = [])),
	tag = "crash"
)]
#[instrument(skip(state, current_user))]
pub async fn delete_project(
	State(state): State<AppState>,
	RequireAuth(current_user): RequireAuth,
	Path(project_id_str): Path<String>,
) -> Result<StatusCode, (StatusCode, Json<CrashErrorResponse>)> {
	let locale = resolve_user_locale(&current_user, &state.default_locale);

	let project_id: ProjectId = project_id_str.parse().map_err(|_| {
		(
			StatusCode::BAD_REQUEST,
			Json(CrashErrorResponse {
				error: "invalid_project_id".to_string(),
				message: "Invalid project ID".to_string(),
			}),
		)
	})?;

	let project = state
		.crash_repo
		.get_project_by_id(project_id)
		.await
		.map_err(|e| {
			tracing::error!(error = %e, "Failed to get project");
			(
				StatusCode::INTERNAL_SERVER_ERROR,
				Json(CrashErrorResponse {
					error: "internal_error".to_string(),
					message: t(&locale, "server.api.error.internal").to_string(),
				}),
			)
		})?
		.ok_or_else(|| {
			(
				StatusCode::NOT_FOUND,
				Json(CrashErrorResponse {
					error: "project_not_found".to_string(),
					message: "Project not found".to_string(),
				}),
			)
		})?;

	verify_org_membership(&state, &project.org_id, &current_user.user.id, &locale).await?;

	let deleted = state
		.crash_repo
		.delete_project(project_id)
		.await
		.map_err(|e| {
			tracing::error!(error = %e, "Failed to delete project");
			(
				StatusCode::INTERNAL_SERVER_ERROR,
				Json(CrashErrorResponse {
					error: "internal_error".to_string(),
					message: t(&locale, "server.api.error.internal").to_string(),
				}),
			)
		})?;

	if deleted {
		state.audit_service.log(
			AuditLogBuilder::new(AuditEventType::CrashProjectDeleted)
				.actor(AuditUserId::new(current_user.user.id.into_inner()))
				.resource("crash_project", project.id.to_string())
				.details(serde_json::json!({
					"org_id": project.org_id.to_string(),
					"name": project.name.clone(),
					"slug": project.slug.clone(),
				}))
				.build(),
		);

		info!(project_id = %project_id, slug = %project.slug, "Project deleted");
		Ok(StatusCode::NO_CONTENT)
	} else {
		Err((
			StatusCode::NOT_FOUND,
			Json(CrashErrorResponse {
				error: "project_not_found".to_string(),
				message: "Project not found".to_string(),
			}),
		))
	}
}
