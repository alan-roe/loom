// Copyright (c) 2025 Geoffrey Huntley <ghuntley@ghuntley.com>. All rights reserved.
// SPDX-License-Identifier: Proprietary

//! Authorization tests for session analytics routes.
//!
//! Key invariants:
//! - All session endpoints require user authentication
//! - Users can only access sessions within projects in orgs they are members of
//! - Cross-org isolation: users cannot see sessions from other orgs

use axum::http::StatusCode;
use serde_json::json;

use super::support::TestApp;

// ============================================================================
// Helper: Create a crash project and return its ID
// ============================================================================

async fn create_test_project(app: &TestApp, org_id: &str, slug: &str) -> String {
	let response = app
		.post(
			"/api/crash/projects",
			Some(&app.fixtures.org_a.member),
			json!({
				"org_id": org_id,
				"name": format!("Test Project {}", slug),
				"slug": slug,
				"platform": "javascript"
			}),
		)
		.await;

	assert_eq!(
		response.status(),
		StatusCode::CREATED,
		"Failed to create test project"
	);

	let (_, body) = response.into_parts();
	let body_bytes = axum::body::to_bytes(body, usize::MAX).await.unwrap();
	let result: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();

	result["id"].as_str().unwrap().to_string()
}

// ============================================================================
// Session Start Tests
// ============================================================================

#[tokio::test]
async fn start_session_requires_auth() {
	let app = TestApp::new().await;
	let org_id = app.fixtures.org_a.org.id.to_string();
	let project_id = create_test_project(&app, &org_id, "session-start-auth-test").await;

	// No auth should return 401
	let response = app
		.post(
			"/api/sessions/start",
			None,
			json!({
				"project_id": project_id,
				"distinct_id": "user-123",
				"release": "1.0.0",
				"environment": "production",
				"platform": "rust",
				"sample_rate": 1.0
			}),
		)
		.await;
	assert_eq!(
		response.status(),
		StatusCode::UNAUTHORIZED,
		"Start session without auth should return 401"
	);
}

#[tokio::test]
async fn start_session_requires_org_membership() {
	let app = TestApp::new().await;
	let org_id = app.fixtures.org_a.org.id.to_string();
	let project_id = create_test_project(&app, &org_id, "session-start-membership-test").await;

	// User from org_b trying to start session in org_a's project should be forbidden
	let response = app
		.post(
			"/api/sessions/start",
			Some(&app.fixtures.org_b.member),
			json!({
				"project_id": project_id,
				"distinct_id": "user-123",
				"release": "1.0.0",
				"environment": "production",
				"platform": "rust",
				"sample_rate": 1.0
			}),
		)
		.await;
	assert_eq!(
		response.status(),
		StatusCode::FORBIDDEN,
		"Non-member should not be able to start session in another org's project"
	);
}

#[tokio::test]
async fn start_session_succeeds_for_org_member() {
	let app = TestApp::new().await;
	let org_id = app.fixtures.org_a.org.id.to_string();
	let project_id = create_test_project(&app, &org_id, "session-start-success-test").await;

	let response = app
		.post(
			"/api/sessions/start",
			Some(&app.fixtures.org_a.member),
			json!({
				"project_id": project_id,
				"distinct_id": "user-123",
				"release": "1.0.0",
				"environment": "production",
				"platform": "rust",
				"sample_rate": 1.0
			}),
		)
		.await;
	assert_eq!(
		response.status(),
		StatusCode::CREATED,
		"Org member should be able to start session"
	);

	// Verify the response contains session_id
	let (_, body) = response.into_parts();
	let body_bytes = axum::body::to_bytes(body, usize::MAX).await.unwrap();
	let result: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
	assert!(
		result["session_id"].is_string(),
		"Response should contain session_id"
	);
}

// ============================================================================
// Session End Tests
// ============================================================================

async fn create_test_session(app: &TestApp, project_id: &str) -> String {
	let response = app
		.post(
			"/api/sessions/start",
			Some(&app.fixtures.org_a.member),
			json!({
				"project_id": project_id,
				"distinct_id": "user-test",
				"release": "1.0.0",
				"environment": "production",
				"platform": "rust",
				"sample_rate": 1.0
			}),
		)
		.await;

	assert_eq!(
		response.status(),
		StatusCode::CREATED,
		"Failed to create test session"
	);

	let (_, body) = response.into_parts();
	let body_bytes = axum::body::to_bytes(body, usize::MAX).await.unwrap();
	let result: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();

	result["session_id"].as_str().unwrap().to_string()
}

#[tokio::test]
async fn end_session_requires_auth() {
	let app = TestApp::new().await;
	let org_id = app.fixtures.org_a.org.id.to_string();
	let project_id = create_test_project(&app, &org_id, "session-end-auth-test").await;
	let session_id = create_test_session(&app, &project_id).await;

	// No auth should return 401
	let response = app
		.post(
			"/api/sessions/end",
			None,
			json!({
				"project_id": project_id,
				"session_id": session_id,
				"status": "exited",
				"duration_ms": 60000
			}),
		)
		.await;
	assert_eq!(
		response.status(),
		StatusCode::UNAUTHORIZED,
		"End session without auth should return 401"
	);
}

#[tokio::test]
async fn end_session_requires_org_membership() {
	let app = TestApp::new().await;
	let org_id = app.fixtures.org_a.org.id.to_string();
	let project_id = create_test_project(&app, &org_id, "session-end-membership-test").await;
	let session_id = create_test_session(&app, &project_id).await;

	// User from org_b trying to end session in org_a's project should be forbidden
	let response = app
		.post(
			"/api/sessions/end",
			Some(&app.fixtures.org_b.member),
			json!({
				"project_id": project_id,
				"session_id": session_id,
				"status": "exited",
				"duration_ms": 60000
			}),
		)
		.await;
	assert_eq!(
		response.status(),
		StatusCode::FORBIDDEN,
		"Non-member should not be able to end session in another org's project"
	);
}

#[tokio::test]
async fn end_session_succeeds_for_org_member() {
	let app = TestApp::new().await;
	let org_id = app.fixtures.org_a.org.id.to_string();
	let project_id = create_test_project(&app, &org_id, "session-end-success-test").await;
	let session_id = create_test_session(&app, &project_id).await;

	let response = app
		.post(
			"/api/sessions/end",
			Some(&app.fixtures.org_a.member),
			json!({
				"project_id": project_id,
				"session_id": session_id,
				"status": "exited",
				"duration_ms": 60000
			}),
		)
		.await;
	assert_eq!(
		response.status(),
		StatusCode::OK,
		"Org member should be able to end session"
	);
}

// ============================================================================
// List Sessions Tests
// ============================================================================

#[tokio::test]
async fn list_sessions_requires_auth() {
	let app = TestApp::new().await;
	let org_id = app.fixtures.org_a.org.id.to_string();
	let project_id = create_test_project(&app, &org_id, "list-sessions-auth-test").await;

	// No auth should return 401
	let response = app
		.get(
			&format!("/api/app-sessions?project_id={}", project_id),
			None,
		)
		.await;
	assert_eq!(
		response.status(),
		StatusCode::UNAUTHORIZED,
		"List sessions without auth should return 401"
	);
}

#[tokio::test]
async fn list_sessions_requires_org_membership() {
	let app = TestApp::new().await;
	let org_id = app.fixtures.org_a.org.id.to_string();
	let project_id = create_test_project(&app, &org_id, "list-sessions-membership-test").await;

	// User from org_b trying to list sessions in org_a's project should be forbidden
	let response = app
		.get(
			&format!("/api/app-sessions?project_id={}", project_id),
			Some(&app.fixtures.org_b.member),
		)
		.await;
	assert_eq!(
		response.status(),
		StatusCode::FORBIDDEN,
		"Non-member should not be able to list sessions in another org's project"
	);
}

#[tokio::test]
async fn list_sessions_succeeds_for_org_member() {
	let app = TestApp::new().await;
	let org_id = app.fixtures.org_a.org.id.to_string();
	let project_id = create_test_project(&app, &org_id, "list-sessions-success-test").await;

	// Create a test session first
	let _ = create_test_session(&app, &project_id).await;

	let response = app
		.get(
			&format!("/api/app-sessions?project_id={}", project_id),
			Some(&app.fixtures.org_a.member),
		)
		.await;
	assert_eq!(
		response.status(),
		StatusCode::OK,
		"Org member should be able to list sessions"
	);

	// Verify the response contains sessions array
	let (_, body) = response.into_parts();
	let body_bytes = axum::body::to_bytes(body, usize::MAX).await.unwrap();
	let result: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
	assert!(
		result["sessions"].is_array(),
		"Response should contain sessions array"
	);
}

// ============================================================================
// Release Health List Tests
// ============================================================================

#[tokio::test]
async fn list_release_health_requires_auth() {
	let app = TestApp::new().await;
	let org_id = app.fixtures.org_a.org.id.to_string();
	let project_id = create_test_project(&app, &org_id, "release-health-auth-test").await;

	// No auth should return 401
	let response = app
		.get(
			&format!("/api/app-sessions/releases?project_id={}", project_id),
			None,
		)
		.await;
	assert_eq!(
		response.status(),
		StatusCode::UNAUTHORIZED,
		"List release health without auth should return 401"
	);
}

#[tokio::test]
async fn list_release_health_requires_org_membership() {
	let app = TestApp::new().await;
	let org_id = app.fixtures.org_a.org.id.to_string();
	let project_id = create_test_project(&app, &org_id, "release-health-membership-test").await;

	// User from org_b trying to list release health in org_a's project should be forbidden
	let response = app
		.get(
			&format!("/api/app-sessions/releases?project_id={}", project_id),
			Some(&app.fixtures.org_b.member),
		)
		.await;
	assert_eq!(
		response.status(),
		StatusCode::FORBIDDEN,
		"Non-member should not be able to list release health in another org's project"
	);
}

#[tokio::test]
async fn list_release_health_succeeds_for_org_member() {
	let app = TestApp::new().await;
	let org_id = app.fixtures.org_a.org.id.to_string();
	let project_id = create_test_project(&app, &org_id, "release-health-success-test").await;

	let response = app
		.get(
			&format!("/api/app-sessions/releases?project_id={}", project_id),
			Some(&app.fixtures.org_a.member),
		)
		.await;
	assert_eq!(
		response.status(),
		StatusCode::OK,
		"Org member should be able to list release health"
	);
}

// ============================================================================
// Release Health Detail Tests
// ============================================================================

#[tokio::test]
async fn get_release_health_requires_auth() {
	let app = TestApp::new().await;
	let org_id = app.fixtures.org_a.org.id.to_string();
	let project_id = create_test_project(&app, &org_id, "release-health-detail-auth-test").await;

	// No auth should return 401
	let response = app
		.get(
			&format!("/api/app-sessions/releases/1.0.0?project_id={}", project_id),
			None,
		)
		.await;
	assert_eq!(
		response.status(),
		StatusCode::UNAUTHORIZED,
		"Get release health without auth should return 401"
	);
}

#[tokio::test]
async fn get_release_health_requires_org_membership() {
	let app = TestApp::new().await;
	let org_id = app.fixtures.org_a.org.id.to_string();
	let project_id =
		create_test_project(&app, &org_id, "release-health-detail-membership-test").await;

	// User from org_b trying to get release health in org_a's project should be forbidden
	let response = app
		.get(
			&format!("/api/app-sessions/releases/1.0.0?project_id={}", project_id),
			Some(&app.fixtures.org_b.member),
		)
		.await;
	assert_eq!(
		response.status(),
		StatusCode::FORBIDDEN,
		"Non-member should not be able to get release health in another org's project"
	);
}

#[tokio::test]
async fn get_release_health_returns_404_for_no_data() {
	let app = TestApp::new().await;
	let org_id = app.fixtures.org_a.org.id.to_string();
	let project_id = create_test_project(&app, &org_id, "release-health-detail-404-test").await;

	// Should return 404 for release with no data
	let response = app
		.get(
			&format!(
				"/api/app-sessions/releases/nonexistent?project_id={}",
				project_id
			),
			Some(&app.fixtures.org_a.member),
		)
		.await;
	assert_eq!(
		response.status(),
		StatusCode::NOT_FOUND,
		"Get release health for nonexistent release should return 404"
	);
}

// ============================================================================
// Session Status Transitions
// ============================================================================

#[tokio::test]
async fn session_can_be_marked_as_crashed() {
	let app = TestApp::new().await;
	let org_id = app.fixtures.org_a.org.id.to_string();
	let project_id = create_test_project(&app, &org_id, "session-crash-test").await;
	let session_id = create_test_session(&app, &project_id).await;

	// End session with crashed status
	let response = app
		.post(
			"/api/sessions/end",
			Some(&app.fixtures.org_a.member),
			json!({
				"project_id": project_id,
				"session_id": session_id,
				"status": "crashed",
				"duration_ms": 30000
			}),
		)
		.await;
	assert_eq!(
		response.status(),
		StatusCode::OK,
		"Should be able to end session with crashed status"
	);
}

#[tokio::test]
async fn session_can_be_marked_as_abnormal() {
	let app = TestApp::new().await;
	let org_id = app.fixtures.org_a.org.id.to_string();
	let project_id = create_test_project(&app, &org_id, "session-abnormal-test").await;
	let session_id = create_test_session(&app, &project_id).await;

	// End session with abnormal status
	let response = app
		.post(
			"/api/sessions/end",
			Some(&app.fixtures.org_a.member),
			json!({
				"project_id": project_id,
				"session_id": session_id,
				"status": "abnormal",
				"duration_ms": 45000
			}),
		)
		.await;
	assert_eq!(
		response.status(),
		StatusCode::OK,
		"Should be able to end session with abnormal status"
	);
}
