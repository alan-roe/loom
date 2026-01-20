// Copyright (c) 2025 Geoffrey Huntley <ghuntley@ghuntley.com>. All rights
// reserved. SPDX-License-Identifier: Proprietary

//! Cron monitoring HTTP handlers.
//!
//! Implements ping endpoints for simple shell script monitoring and
//! API endpoints for monitor management, including SSE streaming for real-time updates.

use std::convert::Infallible;

use axum::{
	extract::{Path, Query, State},
	http::StatusCode,
	response::{
		sse::{Event, Sse},
		IntoResponse,
	},
	Json,
};
use chrono::Utc;
use futures::stream::Stream;
use serde::{Deserialize, Serialize};
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::StreamExt;
use tracing::{info, instrument, warn};

use loom_crons_core::{
	truncate_output, CheckIn, CheckInId, CheckInSource, CheckInStatus, CronStreamEvent, Monitor,
	MonitorHealth, MonitorId, MonitorSchedule, MonitorState, MonitorStatus, OrgId,
};
use loom_server_audit::{AuditEventType, AuditLogBuilder, UserId as AuditUserId};
use loom_server_auth::types::OrgId as AuthOrgId;
use loom_server_crons::{calculate_next_expected, CronsRepository};

use crate::api::AppState;
use crate::auth_middleware::RequireAuth;
use crate::i18n::{resolve_user_locale, t};

/// Error response for crons endpoints.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct CronsErrorResponse {
	pub error: String,
	pub message: String,
}

/// Verify that the current user is a member of the specified organization.
async fn verify_org_membership(
	state: &AppState,
	org_id: &OrgId,
	user_id: &loom_server_auth::types::UserId,
	locale: &str,
) -> Result<(), (StatusCode, Json<CronsErrorResponse>)> {
	// Convert OrgId to AuthOrgId
	let auth_org_id = AuthOrgId::from(org_id.0);

	match state.org_repo.get_membership(&auth_org_id, user_id).await {
		Ok(Some(_)) => Ok(()),
		Ok(None) => Err((
			StatusCode::FORBIDDEN,
			Json(CronsErrorResponse {
				error: "forbidden".to_string(),
				message: t(locale, "server.api.org.not_a_member").to_string(),
			}),
		)),
		Err(e) => {
			tracing::error!(error = %e, %org_id, "Failed to check org membership");
			Err((
				StatusCode::INTERNAL_SERVER_ERROR,
				Json(CronsErrorResponse {
					error: "internal_error".to_string(),
					message: t(locale, "server.api.error.internal").to_string(),
				}),
			))
		}
	}
}

// ============================================================================
// Ping Endpoints (Public - no auth required)
// ============================================================================

/// Query parameters for ping endpoints.
#[derive(Debug, Deserialize)]
pub struct PingParams {
	pub exit_code: Option<i32>,
}

/// Response for ping/start endpoint.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct PingStartResponse {
	pub checkin_id: CheckInId,
}

/// GET /ping/{key} - Simple success ping
#[utoipa::path(
	get,
	path = "/ping/{key}",
	params(
		("key" = String, Path, description = "Ping key (UUID)"),
		("exit_code" = Option<i32>, Query, description = "Exit code (optional)"),
	),
	responses(
		(status = 200, description = "Ping recorded successfully"),
		(status = 404, description = "Invalid ping key"),
	),
	tag = "crons"
)]
#[instrument(skip(state), fields(ping_key = %key))]
pub async fn ping_success(
	State(state): State<AppState>,
	Path(key): Path<String>,
	Query(params): Query<PingParams>,
) -> impl IntoResponse {
	let monitor = match state.crons_repo.get_monitor_by_ping_key(&key).await {
		Ok(Some(m)) => m,
		Ok(None) => return StatusCode::NOT_FOUND.into_response(),
		Err(e) => {
			tracing::error!(error = %e, "Failed to get monitor by ping key");
			return StatusCode::INTERNAL_SERVER_ERROR.into_response();
		}
	};

	let now = Utc::now();

	let status = if params.exit_code.unwrap_or(0) == 0 {
		CheckInStatus::Ok
	} else {
		CheckInStatus::Error
	};

	let is_failure = status == CheckInStatus::Error;

	let checkin = CheckIn {
		id: CheckInId::new(),
		monitor_id: monitor.id,
		status,
		started_at: None,
		finished_at: now,
		duration_ms: None,
		environment: None,
		release: None,
		exit_code: params.exit_code,
		output: None,
		crash_event_id: None,
		source: CheckInSource::Ping,
		created_at: now,
	};

	if let Err(e) = state.crons_repo.create_checkin(&checkin).await {
		tracing::error!(error = %e, "Failed to create checkin");
		return StatusCode::INTERNAL_SERVER_ERROR.into_response();
	}

	let health = if is_failure {
		MonitorHealth::Failing
	} else {
		MonitorHealth::Healthy
	};

	// Calculate next expected check-in time
	let next_expected_at = calculate_next_expected(&monitor.schedule, &monitor.timezone, now).ok();

	let _ = state
		.crons_repo
		.update_monitor_health(monitor.id, health)
		.await;
	let _ = state
		.crons_repo
		.update_monitor_last_checkin(monitor.id, status, next_expected_at)
		.await;
	let _ = state
		.crons_repo
		.increment_monitor_stats(monitor.id, is_failure)
		.await;

	// Broadcast SSE event
	let sse_event = if is_failure {
		CronStreamEvent::checkin_error(
			monitor.id,
			monitor.slug.clone(),
			checkin.id,
			params.exit_code,
			monitor.consecutive_failures + 1,
		)
	} else {
		CronStreamEvent::checkin_ok(monitor.id, monitor.slug.clone(), checkin.id, None)
	};
	state
		.crons_broadcaster
		.broadcast(monitor.org_id, sse_event)
		.await;

	info!(
		monitor_id = %monitor.id,
		monitor_slug = %monitor.slug,
		status = %status,
		"Ping recorded"
	);

	StatusCode::OK.into_response()
}

/// GET /ping/{key}/start - Job starting
#[utoipa::path(
	get,
	path = "/ping/{key}/start",
	params(
		("key" = String, Path, description = "Ping key (UUID)"),
	),
	responses(
		(status = 200, description = "Start ping recorded", body = PingStartResponse),
		(status = 404, description = "Invalid ping key"),
	),
	tag = "crons"
)]
#[instrument(skip(state), fields(ping_key = %key))]
pub async fn ping_start(
	State(state): State<AppState>,
	Path(key): Path<String>,
) -> impl IntoResponse {
	let monitor = match state.crons_repo.get_monitor_by_ping_key(&key).await {
		Ok(Some(m)) => m,
		Ok(None) => return StatusCode::NOT_FOUND.into_response(),
		Err(e) => {
			tracing::error!(error = %e, "Failed to get monitor by ping key");
			return StatusCode::INTERNAL_SERVER_ERROR.into_response();
		}
	};

	let now = Utc::now();

	let checkin = CheckIn {
		id: CheckInId::new(),
		monitor_id: monitor.id,
		status: CheckInStatus::InProgress,
		started_at: Some(now),
		finished_at: now,
		duration_ms: None,
		environment: None,
		release: None,
		exit_code: None,
		output: None,
		crash_event_id: None,
		source: CheckInSource::Ping,
		created_at: now,
	};

	if let Err(e) = state.crons_repo.create_checkin(&checkin).await {
		tracing::error!(error = %e, "Failed to create checkin");
		return StatusCode::INTERNAL_SERVER_ERROR.into_response();
	}

	// Broadcast SSE event
	let sse_event = CronStreamEvent::checkin_started(monitor.id, monitor.slug.clone(), checkin.id);
	state
		.crons_broadcaster
		.broadcast(monitor.org_id, sse_event)
		.await;

	info!(
		monitor_id = %monitor.id,
		monitor_slug = %monitor.slug,
		checkin_id = %checkin.id,
		"Start ping recorded"
	);

	Json(PingStartResponse {
		checkin_id: checkin.id,
	})
	.into_response()
}

/// GET /ping/{key}/fail - Job failed
#[utoipa::path(
	get,
	path = "/ping/{key}/fail",
	params(
		("key" = String, Path, description = "Ping key (UUID)"),
		("exit_code" = Option<i32>, Query, description = "Exit code (optional)"),
	),
	responses(
		(status = 200, description = "Fail ping recorded"),
		(status = 404, description = "Invalid ping key"),
	),
	tag = "crons"
)]
#[instrument(skip(state), fields(ping_key = %key))]
pub async fn ping_fail(
	State(state): State<AppState>,
	Path(key): Path<String>,
	Query(params): Query<PingParams>,
) -> impl IntoResponse {
	let monitor = match state.crons_repo.get_monitor_by_ping_key(&key).await {
		Ok(Some(m)) => m,
		Ok(None) => return StatusCode::NOT_FOUND.into_response(),
		Err(e) => {
			tracing::error!(error = %e, "Failed to get monitor by ping key");
			return StatusCode::INTERNAL_SERVER_ERROR.into_response();
		}
	};

	let now = Utc::now();

	let checkin = CheckIn {
		id: CheckInId::new(),
		monitor_id: monitor.id,
		status: CheckInStatus::Error,
		started_at: None,
		finished_at: now,
		duration_ms: None,
		environment: None,
		release: None,
		exit_code: params.exit_code,
		output: None,
		crash_event_id: None,
		source: CheckInSource::Ping,
		created_at: now,
	};

	if let Err(e) = state.crons_repo.create_checkin(&checkin).await {
		tracing::error!(error = %e, "Failed to create checkin");
		return StatusCode::INTERNAL_SERVER_ERROR.into_response();
	}

	// Calculate next expected check-in time
	let next_expected_at = calculate_next_expected(&monitor.schedule, &monitor.timezone, now).ok();

	let _ = state
		.crons_repo
		.update_monitor_health(monitor.id, MonitorHealth::Failing)
		.await;
	let _ = state
		.crons_repo
		.update_monitor_last_checkin(monitor.id, CheckInStatus::Error, next_expected_at)
		.await;
	let _ = state
		.crons_repo
		.increment_monitor_stats(monitor.id, true)
		.await;

	// Broadcast SSE event
	let sse_event = CronStreamEvent::checkin_error(
		monitor.id,
		monitor.slug.clone(),
		checkin.id,
		params.exit_code,
		monitor.consecutive_failures + 1,
	);
	state
		.crons_broadcaster
		.broadcast(monitor.org_id, sse_event)
		.await;

	warn!(
		monitor_id = %monitor.id,
		monitor_slug = %monitor.slug,
		exit_code = ?params.exit_code,
		"Fail ping recorded"
	);

	StatusCode::OK.into_response()
}

/// POST /ping/{key} - Ping with body
#[utoipa::path(
	post,
	path = "/ping/{key}",
	params(
		("key" = String, Path, description = "Ping key (UUID)"),
		("exit_code" = Option<i32>, Query, description = "Exit code (0 = success)"),
	),
	request_body = String,
	responses(
		(status = 200, description = "Ping recorded successfully"),
		(status = 404, description = "Invalid ping key"),
	),
	tag = "crons"
)]
#[instrument(skip(state, body), fields(ping_key = %key))]
pub async fn ping_with_body(
	State(state): State<AppState>,
	Path(key): Path<String>,
	Query(params): Query<PingParams>,
	body: String,
) -> impl IntoResponse {
	let monitor = match state.crons_repo.get_monitor_by_ping_key(&key).await {
		Ok(Some(m)) => m,
		Ok(None) => return StatusCode::NOT_FOUND.into_response(),
		Err(e) => {
			tracing::error!(error = %e, "Failed to get monitor by ping key");
			return StatusCode::INTERNAL_SERVER_ERROR.into_response();
		}
	};

	let now = Utc::now();

	let status = if params.exit_code.unwrap_or(0) == 0 {
		CheckInStatus::Ok
	} else {
		CheckInStatus::Error
	};

	let is_failure = status == CheckInStatus::Error;

	let output = if body.is_empty() {
		None
	} else {
		Some(truncate_output(&body))
	};

	let checkin = CheckIn {
		id: CheckInId::new(),
		monitor_id: monitor.id,
		status,
		started_at: None,
		finished_at: now,
		duration_ms: None,
		environment: None,
		release: None,
		exit_code: params.exit_code,
		output,
		crash_event_id: None,
		source: CheckInSource::Ping,
		created_at: now,
	};

	if let Err(e) = state.crons_repo.create_checkin(&checkin).await {
		tracing::error!(error = %e, "Failed to create checkin");
		return StatusCode::INTERNAL_SERVER_ERROR.into_response();
	}

	let health = if is_failure {
		MonitorHealth::Failing
	} else {
		MonitorHealth::Healthy
	};

	// Calculate next expected check-in time
	let next_expected_at = calculate_next_expected(&monitor.schedule, &monitor.timezone, now).ok();

	let _ = state
		.crons_repo
		.update_monitor_health(monitor.id, health)
		.await;
	let _ = state
		.crons_repo
		.update_monitor_last_checkin(monitor.id, status, next_expected_at)
		.await;
	let _ = state
		.crons_repo
		.increment_monitor_stats(monitor.id, is_failure)
		.await;

	// Broadcast SSE event
	let sse_event = if is_failure {
		CronStreamEvent::checkin_error(
			monitor.id,
			monitor.slug.clone(),
			checkin.id,
			params.exit_code,
			monitor.consecutive_failures + 1,
		)
	} else {
		CronStreamEvent::checkin_ok(monitor.id, monitor.slug.clone(), checkin.id, None)
	};
	state
		.crons_broadcaster
		.broadcast(monitor.org_id, sse_event)
		.await;

	info!(
		monitor_id = %monitor.id,
		monitor_slug = %monitor.slug,
		status = %status,
		has_output = !body.is_empty(),
		"Ping with body recorded"
	);

	StatusCode::OK.into_response()
}

// ============================================================================
// Monitor API Endpoints (Authenticated)
// ============================================================================

/// Request to create a new monitor.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct CreateMonitorRequest {
	pub org_id: OrgId,
	pub slug: String,
	pub name: String,
	#[serde(default)]
	pub description: Option<String>,
	pub schedule: MonitorScheduleRequest,
	#[serde(default = "default_timezone")]
	pub timezone: String,
	#[serde(default = "default_margin")]
	pub checkin_margin_minutes: u32,
	#[serde(default)]
	pub max_runtime_minutes: Option<u32>,
	#[serde(default)]
	pub environments: Vec<String>,
}

fn default_timezone() -> String {
	"UTC".to_string()
}

fn default_margin() -> u32 {
	5
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum MonitorScheduleRequest {
	Cron { expression: String },
	Interval { minutes: u32 },
}

impl From<MonitorScheduleRequest> for MonitorSchedule {
	fn from(req: MonitorScheduleRequest) -> Self {
		match req {
			MonitorScheduleRequest::Cron { expression } => MonitorSchedule::Cron { expression },
			MonitorScheduleRequest::Interval { minutes } => MonitorSchedule::Interval { minutes },
		}
	}
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct CreateMonitorResponse {
	pub monitor: Monitor,
	pub ping_url: String,
}

#[derive(Debug, Deserialize)]
pub struct ListMonitorsParams {
	pub org_id: OrgId,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct ListMonitorsResponse {
	pub monitors: Vec<MonitorSummary>,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct MonitorSummary {
	pub id: MonitorId,
	pub slug: String,
	pub name: String,
	pub status: MonitorStatus,
	pub health: MonitorHealth,
	pub last_checkin_at: Option<chrono::DateTime<Utc>>,
	pub next_expected_at: Option<chrono::DateTime<Utc>>,
	pub consecutive_failures: u32,
}

impl From<Monitor> for MonitorSummary {
	fn from(m: Monitor) -> Self {
		Self {
			id: m.id,
			slug: m.slug,
			name: m.name,
			status: m.status,
			health: m.health,
			last_checkin_at: m.last_checkin_at,
			next_expected_at: m.next_expected_at,
			consecutive_failures: m.consecutive_failures,
		}
	}
}

/// GET /api/crons/monitors - List monitors
#[utoipa::path(
	get,
	path = "/api/crons/monitors",
	params(
		("org_id" = OrgId, Query, description = "Organization ID"),
	),
	responses(
		(status = 200, description = "List of monitors", body = ListMonitorsResponse),
		(status = 401, description = "Not authenticated"),
		(status = 403, description = "Not a member of the organization"),
	),
	tag = "crons"
)]
#[instrument(skip(state, current_user))]
pub async fn list_monitors(
	RequireAuth(current_user): RequireAuth,
	State(state): State<AppState>,
	Query(params): Query<ListMonitorsParams>,
) -> impl IntoResponse {
	let locale = resolve_user_locale(&current_user, &state.default_locale);

	// Verify org membership
	if let Err(resp) =
		verify_org_membership(&state, &params.org_id, &current_user.user.id, &locale).await
	{
		return resp.into_response();
	}

	match state.crons_repo.list_monitors(params.org_id).await {
		Ok(monitors) => {
			let summaries: Vec<MonitorSummary> = monitors.into_iter().map(Into::into).collect();
			Json(ListMonitorsResponse {
				monitors: summaries,
			})
			.into_response()
		}
		Err(e) => {
			tracing::error!(error = %e, "Failed to list monitors");
			StatusCode::INTERNAL_SERVER_ERROR.into_response()
		}
	}
}

/// POST /api/crons/monitors - Create monitor
#[utoipa::path(
	post,
	path = "/api/crons/monitors",
	request_body = CreateMonitorRequest,
	responses(
		(status = 201, description = "Monitor created", body = CreateMonitorResponse),
		(status = 400, description = "Invalid request"),
		(status = 401, description = "Not authenticated"),
		(status = 403, description = "Not a member of the organization"),
		(status = 409, description = "Duplicate slug"),
	),
	tag = "crons"
)]
#[instrument(skip(state, current_user, req), fields(org_id = %req.org_id, slug = %req.slug))]
pub async fn create_monitor(
	RequireAuth(current_user): RequireAuth,
	State(state): State<AppState>,
	Json(req): Json<CreateMonitorRequest>,
) -> impl IntoResponse {
	let locale = resolve_user_locale(&current_user, &state.default_locale);

	// Verify org membership
	if let Err(resp) =
		verify_org_membership(&state, &req.org_id, &current_user.user.id, &locale).await
	{
		return resp.into_response();
	}

	if !Monitor::validate_slug(&req.slug) {
		return (
			StatusCode::BAD_REQUEST,
			Json(serde_json::json!({"error": "Invalid slug"})),
		)
			.into_response();
	}

	if let Ok(Some(_)) = state
		.crons_repo
		.get_monitor_by_slug(req.org_id, &req.slug)
		.await
	{
		return (
			StatusCode::CONFLICT,
			Json(serde_json::json!({"error": "Duplicate slug"})),
		)
			.into_response();
	}

	let now = Utc::now();
	let ping_key = Monitor::generate_ping_key();
	let schedule: MonitorSchedule = req.schedule.into();

	// Calculate initial next_expected_at based on schedule
	let next_expected_at = calculate_next_expected(&schedule, &req.timezone, now).ok();

	let monitor = Monitor {
		id: MonitorId::new(),
		org_id: req.org_id,
		slug: req.slug,
		name: req.name,
		description: req.description,
		status: MonitorStatus::Active,
		health: MonitorHealth::Unknown,
		schedule,
		timezone: req.timezone,
		checkin_margin_minutes: req.checkin_margin_minutes,
		max_runtime_minutes: req.max_runtime_minutes,
		ping_key: ping_key.clone(),
		environments: req.environments,
		last_checkin_at: None,
		last_checkin_status: None,
		next_expected_at,
		consecutive_failures: 0,
		total_checkins: 0,
		total_failures: 0,
		created_at: now,
		updated_at: now,
	};

	if let Err(e) = state.crons_repo.create_monitor(&monitor).await {
		tracing::error!(error = %e, "Failed to create monitor");
		return StatusCode::INTERNAL_SERVER_ERROR.into_response();
	}

	info!(monitor_id = %monitor.id, slug = %monitor.slug, "Monitor created");

	state.audit_service.log(
		AuditLogBuilder::new(AuditEventType::CronMonitorCreated)
			.actor(AuditUserId::new(current_user.user.id.into_inner()))
			.resource("cron_monitor", monitor.id.to_string())
			.details(serde_json::json!({
				"org_id": monitor.org_id.to_string(),
				"slug": monitor.slug.clone(),
				"name": monitor.name.clone(),
				"schedule": format!("{:?}", monitor.schedule),
			}))
			.build(),
	);

	let ping_url = format!("{}/ping/{}", state.base_url, ping_key);

	(
		StatusCode::CREATED,
		Json(CreateMonitorResponse { monitor, ping_url }),
	)
		.into_response()
}

#[derive(Debug, Deserialize)]
pub struct GetMonitorParams {
	pub org_id: OrgId,
}

/// GET /api/crons/monitors/{slug} - Get monitor
#[utoipa::path(
	get,
	path = "/api/crons/monitors/{slug}",
	params(
		("slug" = String, Path, description = "Monitor slug"),
		("org_id" = OrgId, Query, description = "Organization ID"),
	),
	responses(
		(status = 200, description = "Monitor details", body = Monitor),
		(status = 401, description = "Not authenticated"),
		(status = 403, description = "Not a member of the organization"),
		(status = 404, description = "Monitor not found"),
	),
	tag = "crons"
)]
#[instrument(skip(state, current_user), fields(slug = %slug))]
pub async fn get_monitor(
	RequireAuth(current_user): RequireAuth,
	State(state): State<AppState>,
	Path(slug): Path<String>,
	Query(params): Query<GetMonitorParams>,
) -> impl IntoResponse {
	let locale = resolve_user_locale(&current_user, &state.default_locale);

	// Verify org membership
	if let Err(resp) =
		verify_org_membership(&state, &params.org_id, &current_user.user.id, &locale).await
	{
		return resp.into_response();
	}

	match state
		.crons_repo
		.get_monitor_by_slug(params.org_id, &slug)
		.await
	{
		Ok(Some(monitor)) => Json(monitor).into_response(),
		Ok(None) => StatusCode::NOT_FOUND.into_response(),
		Err(e) => {
			tracing::error!(error = %e, "Failed to get monitor");
			StatusCode::INTERNAL_SERVER_ERROR.into_response()
		}
	}
}

/// DELETE /api/crons/monitors/{slug} - Delete monitor
#[utoipa::path(
	delete,
	path = "/api/crons/monitors/{slug}",
	params(
		("slug" = String, Path, description = "Monitor slug"),
		("org_id" = OrgId, Query, description = "Organization ID"),
	),
	responses(
		(status = 204, description = "Monitor deleted"),
		(status = 401, description = "Not authenticated"),
		(status = 403, description = "Not a member of the organization"),
		(status = 404, description = "Monitor not found"),
	),
	tag = "crons"
)]
#[instrument(skip(state, current_user), fields(slug = %slug))]
pub async fn delete_monitor(
	RequireAuth(current_user): RequireAuth,
	State(state): State<AppState>,
	Path(slug): Path<String>,
	Query(params): Query<GetMonitorParams>,
) -> impl IntoResponse {
	let locale = resolve_user_locale(&current_user, &state.default_locale);

	// Verify org membership
	if let Err(resp) =
		verify_org_membership(&state, &params.org_id, &current_user.user.id, &locale).await
	{
		return resp.into_response();
	}

	let monitor = match state
		.crons_repo
		.get_monitor_by_slug(params.org_id, &slug)
		.await
	{
		Ok(Some(m)) => m,
		Ok(None) => return StatusCode::NOT_FOUND.into_response(),
		Err(e) => {
			tracing::error!(error = %e, "Failed to get monitor");
			return StatusCode::INTERNAL_SERVER_ERROR.into_response();
		}
	};

	if let Err(e) = state.crons_repo.delete_monitor(monitor.id).await {
		tracing::error!(error = %e, "Failed to delete monitor");
		return StatusCode::INTERNAL_SERVER_ERROR.into_response();
	}

	info!(monitor_id = %monitor.id, "Monitor deleted");

	state.audit_service.log(
		AuditLogBuilder::new(AuditEventType::CronMonitorDeleted)
			.actor(AuditUserId::new(current_user.user.id.into_inner()))
			.resource("cron_monitor", monitor.id.to_string())
			.details(serde_json::json!({
				"org_id": monitor.org_id.to_string(),
				"slug": monitor.slug.clone(),
				"name": monitor.name.clone(),
			}))
			.build(),
	);

	StatusCode::NO_CONTENT.into_response()
}

#[derive(Debug, Deserialize)]
pub struct ListCheckInsParams {
	pub org_id: OrgId,
	pub limit: Option<u32>,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct ListCheckInsResponse {
	pub checkins: Vec<CheckIn>,
}

/// GET /api/crons/monitors/{slug}/checkins - List check-ins
#[utoipa::path(
	get,
	path = "/api/crons/monitors/{slug}/checkins",
	params(
		("slug" = String, Path, description = "Monitor slug"),
		("org_id" = OrgId, Query, description = "Organization ID"),
		("limit" = Option<u32>, Query, description = "Max results (default 50)"),
	),
	responses(
		(status = 200, description = "List of check-ins", body = ListCheckInsResponse),
		(status = 401, description = "Not authenticated"),
		(status = 403, description = "Not a member of the organization"),
		(status = 404, description = "Monitor not found"),
	),
	tag = "crons"
)]
#[instrument(skip(state, current_user), fields(slug = %slug))]
pub async fn list_checkins(
	RequireAuth(current_user): RequireAuth,
	State(state): State<AppState>,
	Path(slug): Path<String>,
	Query(params): Query<ListCheckInsParams>,
) -> impl IntoResponse {
	let locale = resolve_user_locale(&current_user, &state.default_locale);

	// Verify org membership
	if let Err(resp) =
		verify_org_membership(&state, &params.org_id, &current_user.user.id, &locale).await
	{
		return resp.into_response();
	}

	let monitor = match state
		.crons_repo
		.get_monitor_by_slug(params.org_id, &slug)
		.await
	{
		Ok(Some(m)) => m,
		Ok(None) => return StatusCode::NOT_FOUND.into_response(),
		Err(e) => {
			tracing::error!(error = %e, "Failed to get monitor");
			return StatusCode::INTERNAL_SERVER_ERROR.into_response();
		}
	};

	let limit = params.limit.unwrap_or(50);
	match state.crons_repo.list_checkins(monitor.id, limit).await {
		Ok(checkins) => Json(ListCheckInsResponse { checkins }).into_response(),
		Err(e) => {
			tracing::error!(error = %e, "Failed to list checkins");
			StatusCode::INTERNAL_SERVER_ERROR.into_response()
		}
	}
}

// ============================================================================
// SDK Check-in Endpoints
// ============================================================================

/// Request to create a check-in via SDK.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct CreateCheckInRequest {
	pub org_id: OrgId,
	pub status: CheckInStatus,
	#[serde(default)]
	pub started_at: Option<chrono::DateTime<Utc>>,
	#[serde(default)]
	pub finished_at: Option<chrono::DateTime<Utc>>,
	#[serde(default)]
	pub duration_ms: Option<u64>,
	#[serde(default)]
	pub environment: Option<String>,
	#[serde(default)]
	pub release: Option<String>,
	#[serde(default)]
	pub exit_code: Option<i32>,
	#[serde(default)]
	pub output: Option<String>,
	#[serde(default)]
	pub crash_event_id: Option<String>,
}

/// Response for check-in creation.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct CreateCheckInResponse {
	pub id: CheckInId,
	pub status: CheckInStatus,
}

/// POST /api/crons/monitors/{slug}/checkins - Create check-in (SDK)
#[utoipa::path(
	post,
	path = "/api/crons/monitors/{slug}/checkins",
	params(
		("slug" = String, Path, description = "Monitor slug"),
	),
	request_body = CreateCheckInRequest,
	responses(
		(status = 201, description = "Check-in created", body = CreateCheckInResponse),
		(status = 400, description = "Invalid request"),
		(status = 401, description = "Not authenticated"),
		(status = 403, description = "Not a member of the organization"),
		(status = 404, description = "Monitor not found"),
	),
	tag = "crons"
)]
#[instrument(skip(state, current_user, req), fields(slug = %slug, status = %req.status))]
pub async fn create_checkin(
	RequireAuth(current_user): RequireAuth,
	State(state): State<AppState>,
	Path(slug): Path<String>,
	Json(req): Json<CreateCheckInRequest>,
) -> impl IntoResponse {
	let locale = resolve_user_locale(&current_user, &state.default_locale);

	// Verify org membership
	if let Err(resp) =
		verify_org_membership(&state, &req.org_id, &current_user.user.id, &locale).await
	{
		return resp.into_response();
	}

	let monitor = match state
		.crons_repo
		.get_monitor_by_slug(req.org_id, &slug)
		.await
	{
		Ok(Some(m)) => m,
		Ok(None) => return StatusCode::NOT_FOUND.into_response(),
		Err(e) => {
			tracing::error!(error = %e, "Failed to get monitor");
			return StatusCode::INTERNAL_SERVER_ERROR.into_response();
		}
	};

	let now = Utc::now();

	// Truncate output if provided
	let output = req.output.map(|o| truncate_output(&o));

	let checkin = CheckIn {
		id: CheckInId::new(),
		monitor_id: monitor.id,
		status: req.status,
		started_at: req
			.started_at
			.or(if req.status == CheckInStatus::InProgress {
				Some(now)
			} else {
				None
			}),
		finished_at: req.finished_at.unwrap_or(now),
		duration_ms: req.duration_ms,
		environment: req.environment,
		release: req.release,
		exit_code: req.exit_code,
		output,
		crash_event_id: req.crash_event_id,
		source: CheckInSource::Sdk,
		created_at: now,
	};

	if let Err(e) = state.crons_repo.create_checkin(&checkin).await {
		tracing::error!(error = %e, "Failed to create checkin");
		return StatusCode::INTERNAL_SERVER_ERROR.into_response();
	}

	// Update monitor state based on check-in status
	let is_failure = matches!(
		req.status,
		CheckInStatus::Error | CheckInStatus::Missed | CheckInStatus::Timeout
	);

	if req.status != CheckInStatus::InProgress {
		let health = if is_failure {
			MonitorHealth::Failing
		} else {
			MonitorHealth::Healthy
		};

		// Calculate next expected check-in time
		let next_expected_at = calculate_next_expected(&monitor.schedule, &monitor.timezone, now).ok();

		let _ = state
			.crons_repo
			.update_monitor_health(monitor.id, health)
			.await;
		let _ = state
			.crons_repo
			.update_monitor_last_checkin(monitor.id, req.status, next_expected_at)
			.await;
		let _ = state
			.crons_repo
			.increment_monitor_stats(monitor.id, is_failure)
			.await;
	}

	// Broadcast SSE event
	let sse_event = match req.status {
		CheckInStatus::InProgress => {
			CronStreamEvent::checkin_started(monitor.id, monitor.slug.clone(), checkin.id)
		}
		CheckInStatus::Ok => CronStreamEvent::checkin_ok(
			monitor.id,
			monitor.slug.clone(),
			checkin.id,
			req.duration_ms,
		),
		CheckInStatus::Error | CheckInStatus::Missed | CheckInStatus::Timeout => {
			CronStreamEvent::checkin_error(
				monitor.id,
				monitor.slug.clone(),
				checkin.id,
				req.exit_code,
				monitor.consecutive_failures + 1,
			)
		}
	};
	state
		.crons_broadcaster
		.broadcast(monitor.org_id, sse_event)
		.await;

	info!(
		monitor_id = %monitor.id,
		monitor_slug = %monitor.slug,
		checkin_id = %checkin.id,
		status = %req.status,
		"SDK check-in created"
	);

	(
		StatusCode::CREATED,
		Json(CreateCheckInResponse {
			id: checkin.id,
			status: checkin.status,
		}),
	)
		.into_response()
}

/// Request to update a check-in.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct UpdateCheckInRequest {
	pub status: CheckInStatus,
	#[serde(default)]
	pub finished_at: Option<chrono::DateTime<Utc>>,
	#[serde(default)]
	pub duration_ms: Option<u64>,
	#[serde(default)]
	pub exit_code: Option<i32>,
	#[serde(default)]
	pub output: Option<String>,
	#[serde(default)]
	pub crash_event_id: Option<String>,
}

/// PATCH /api/crons/checkins/{id} - Update check-in
#[utoipa::path(
	patch,
	path = "/api/crons/checkins/{id}",
	params(
		("id" = CheckInId, Path, description = "Check-in ID"),
	),
	request_body = UpdateCheckInRequest,
	responses(
		(status = 200, description = "Check-in updated", body = CheckIn),
		(status = 401, description = "Not authenticated"),
		(status = 403, description = "Not a member of the organization"),
		(status = 404, description = "Check-in not found"),
	),
	tag = "crons"
)]
#[instrument(skip(state, current_user, req), fields(checkin_id = %id, status = %req.status))]
pub async fn update_checkin(
	RequireAuth(current_user): RequireAuth,
	State(state): State<AppState>,
	Path(id): Path<CheckInId>,
	Json(req): Json<UpdateCheckInRequest>,
) -> impl IntoResponse {
	let locale = resolve_user_locale(&current_user, &state.default_locale);

	let mut checkin = match state.crons_repo.get_checkin_by_id(id).await {
		Ok(Some(c)) => c,
		Ok(None) => return StatusCode::NOT_FOUND.into_response(),
		Err(e) => {
			tracing::error!(error = %e, "Failed to get checkin");
			return StatusCode::INTERNAL_SERVER_ERROR.into_response();
		}
	};

	// Get the monitor to verify org membership
	let monitor = match state.crons_repo.get_monitor_by_id(checkin.monitor_id).await {
		Ok(Some(m)) => m,
		Ok(None) => return StatusCode::NOT_FOUND.into_response(),
		Err(e) => {
			tracing::error!(error = %e, "Failed to get monitor for checkin");
			return StatusCode::INTERNAL_SERVER_ERROR.into_response();
		}
	};

	// Verify org membership
	if let Err(resp) =
		verify_org_membership(&state, &monitor.org_id, &current_user.user.id, &locale).await
	{
		return resp.into_response();
	}

	let now = Utc::now();

	// Update fields
	checkin.status = req.status;
	checkin.finished_at = req.finished_at.unwrap_or(now);
	if let Some(duration_ms) = req.duration_ms {
		checkin.duration_ms = Some(duration_ms);
	} else if let Some(started_at) = checkin.started_at {
		// Calculate duration from started_at if not provided
		checkin.duration_ms = Some((checkin.finished_at - started_at).num_milliseconds() as u64);
	}
	if let Some(exit_code) = req.exit_code {
		checkin.exit_code = Some(exit_code);
	}
	if let Some(output) = req.output {
		checkin.output = Some(truncate_output(&output));
	}
	if let Some(crash_event_id) = req.crash_event_id {
		checkin.crash_event_id = Some(crash_event_id);
	}

	if let Err(e) = state.crons_repo.update_checkin(&checkin).await {
		tracing::error!(error = %e, "Failed to update checkin");
		return StatusCode::INTERNAL_SERVER_ERROR.into_response();
	}

	// Update monitor state
	let is_failure = matches!(
		req.status,
		CheckInStatus::Error | CheckInStatus::Missed | CheckInStatus::Timeout
	);
	let health = if is_failure {
		MonitorHealth::Failing
	} else {
		MonitorHealth::Healthy
	};

	// Get monitor to calculate next expected time
	let next_expected_at = match state.crons_repo.get_monitor_by_id(checkin.monitor_id).await {
		Ok(Some(monitor)) => calculate_next_expected(&monitor.schedule, &monitor.timezone, now).ok(),
		_ => None,
	};

	let _ = state
		.crons_repo
		.update_monitor_health(checkin.monitor_id, health)
		.await;
	let _ = state
		.crons_repo
		.update_monitor_last_checkin(checkin.monitor_id, req.status, next_expected_at)
		.await;
	let _ = state
		.crons_repo
		.increment_monitor_stats(checkin.monitor_id, is_failure)
		.await;

	// Broadcast SSE event
	let sse_event = match req.status {
		CheckInStatus::InProgress => {
			CronStreamEvent::checkin_started(monitor.id, monitor.slug.clone(), checkin.id)
		}
		CheckInStatus::Ok => CronStreamEvent::checkin_ok(
			monitor.id,
			monitor.slug.clone(),
			checkin.id,
			checkin.duration_ms,
		),
		CheckInStatus::Error | CheckInStatus::Missed | CheckInStatus::Timeout => {
			CronStreamEvent::checkin_error(
				monitor.id,
				monitor.slug.clone(),
				checkin.id,
				checkin.exit_code,
				monitor.consecutive_failures + 1,
			)
		}
	};
	state
		.crons_broadcaster
		.broadcast(monitor.org_id, sse_event)
		.await;

	info!(
		checkin_id = %checkin.id,
		monitor_id = %checkin.monitor_id,
		status = %req.status,
		"Check-in updated"
	);

	Json(checkin).into_response()
}

/// GET /api/crons/checkins/{id} - Get check-in by ID
#[utoipa::path(
	get,
	path = "/api/crons/checkins/{id}",
	params(
		("id" = CheckInId, Path, description = "Check-in ID"),
	),
	responses(
		(status = 200, description = "Check-in details", body = CheckIn),
		(status = 401, description = "Not authenticated"),
		(status = 403, description = "Not a member of the organization"),
		(status = 404, description = "Check-in not found"),
	),
	tag = "crons"
)]
#[instrument(skip(state, current_user), fields(checkin_id = %id))]
pub async fn get_checkin(
	RequireAuth(current_user): RequireAuth,
	State(state): State<AppState>,
	Path(id): Path<CheckInId>,
) -> impl IntoResponse {
	let locale = resolve_user_locale(&current_user, &state.default_locale);

	let checkin = match state.crons_repo.get_checkin_by_id(id).await {
		Ok(Some(c)) => c,
		Ok(None) => return StatusCode::NOT_FOUND.into_response(),
		Err(e) => {
			tracing::error!(error = %e, "Failed to get checkin");
			return StatusCode::INTERNAL_SERVER_ERROR.into_response();
		}
	};

	// Get the monitor to verify org membership
	let monitor = match state.crons_repo.get_monitor_by_id(checkin.monitor_id).await {
		Ok(Some(m)) => m,
		Ok(None) => return StatusCode::NOT_FOUND.into_response(),
		Err(e) => {
			tracing::error!(error = %e, "Failed to get monitor for checkin");
			return StatusCode::INTERNAL_SERVER_ERROR.into_response();
		}
	};

	// Verify org membership
	if let Err(resp) =
		verify_org_membership(&state, &monitor.org_id, &current_user.user.id, &locale).await
	{
		return resp.into_response();
	}

	Json(checkin).into_response()
}

// ============================================================================
// SSE Streaming Endpoints
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct StreamCronsParams {
	pub org_id: OrgId,
}

/// GET /api/crons/stream - SSE stream for all monitors in an organization
///
/// Streams real-time updates for cron monitor events including:
/// - `init`: Full state of all monitors on connect
/// - `checkin.started`: Job started (in_progress)
/// - `checkin.ok`: Job completed successfully
/// - `checkin.error`: Job failed
/// - `monitor.missed`: Expected check-in didn't arrive
/// - `monitor.timeout`: Job exceeded max runtime
/// - `monitor.healthy`: Monitor recovered from failure
/// - `heartbeat`: Keep-alive (every 30s)
#[utoipa::path(
	get,
	path = "/api/crons/stream",
	params(
		("org_id" = OrgId, Query, description = "Organization ID"),
	),
	responses(
		(status = 200, description = "SSE stream connection established"),
		(status = 401, description = "Not authenticated"),
		(status = 403, description = "Not a member of the organization"),
	),
	tag = "crons"
)]
#[instrument(skip(state, current_user))]
pub async fn stream_crons(
	RequireAuth(current_user): RequireAuth,
	State(state): State<AppState>,
	Query(params): Query<StreamCronsParams>,
) -> Result<
	Sse<impl Stream<Item = Result<Event, Infallible>>>,
	(StatusCode, Json<CronsErrorResponse>),
> {
	let locale = resolve_user_locale(&current_user, &state.default_locale);

	// Verify org membership
	verify_org_membership(&state, &params.org_id, &current_user.user.id, &locale).await?;

	info!(
		org_id = %params.org_id,
		user_id = %current_user.user.id,
		"Client connected to crons stream"
	);

	// Build initial state - list all monitors for this org
	let monitors = state
		.crons_repo
		.list_monitors(params.org_id)
		.await
		.map_err(|e| {
			tracing::error!(error = %e, "Failed to list monitors for init");
			(
				StatusCode::INTERNAL_SERVER_ERROR,
				Json(CronsErrorResponse {
					error: "internal_error".to_string(),
					message: t(&locale, "server.api.error.internal").to_string(),
				}),
			)
		})?;

	// Convert to MonitorState for SSE init
	let monitor_states: Vec<MonitorState> = monitors
		.into_iter()
		.map(|m| MonitorState {
			id: m.id,
			slug: m.slug,
			name: m.name,
			status: m.status,
			health: m.health,
			last_checkin_status: m.last_checkin_status,
			last_checkin_at: m.last_checkin_at,
			next_expected_at: m.next_expected_at,
			consecutive_failures: m.consecutive_failures,
		})
		.collect();

	// Create init event
	let init_event = CronStreamEvent::init(monitor_states);

	// Subscribe to broadcast channel
	let receiver = state.crons_broadcaster.subscribe(params.org_id).await;
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
					tracing::warn!(error = %e, "Failed to serialize crons SSE event");
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
