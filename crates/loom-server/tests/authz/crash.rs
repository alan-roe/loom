// Copyright (c) 2025 Geoffrey Huntley <ghuntley@ghuntley.com>. All rights reserved.
// SPDX-License-Identifier: Proprietary

//! Authorization tests for crash analytics routes.
//!
//! Key invariants:
//! - All crash endpoints require user authentication
//! - Users can only access projects/issues within orgs they are members of
//! - Cross-org isolation: users cannot see projects/issues from other orgs

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
// Project List Tests
// ============================================================================

#[tokio::test]
async fn list_projects_requires_auth() {
	let app = TestApp::new().await;
	let org_id = app.fixtures.org_a.org.id.to_string();

	// No auth should return 401
	let response = app
		.get(&format!("/api/crash/projects?org_id={}", org_id), None)
		.await;
	assert_eq!(
		response.status(),
		StatusCode::UNAUTHORIZED,
		"List projects without auth should return 401"
	);
}

#[tokio::test]
async fn list_projects_requires_org_membership() {
	let app = TestApp::new().await;
	let org_id = app.fixtures.org_b.org.id.to_string();

	// User from org_a trying to list projects in org_b should be forbidden
	let response = app
		.get(
			&format!("/api/crash/projects?org_id={}", org_id),
			Some(&app.fixtures.org_a.member),
		)
		.await;
	assert_eq!(
		response.status(),
		StatusCode::FORBIDDEN,
		"Non-member should not be able to list projects in another org"
	);
}

#[tokio::test]
async fn list_projects_succeeds_for_org_member() {
	let app = TestApp::new().await;
	let org_id = app.fixtures.org_a.org.id.to_string();

	let response = app
		.get(
			&format!("/api/crash/projects?org_id={}", org_id),
			Some(&app.fixtures.org_a.member),
		)
		.await;
	assert_eq!(
		response.status(),
		StatusCode::OK,
		"Org member should be able to list projects"
	);
}

// ============================================================================
// Project Create Tests
// ============================================================================

#[tokio::test]
async fn create_project_requires_auth() {
	let app = TestApp::new().await;
	let org_id = app.fixtures.org_a.org.id.to_string();

	// No auth should return 401
	let response = app
		.post(
			"/api/crash/projects",
			None,
			json!({
				"org_id": org_id,
				"name": "Test Project",
				"slug": "test-project",
				"platform": "javascript"
			}),
		)
		.await;
	assert_eq!(
		response.status(),
		StatusCode::UNAUTHORIZED,
		"Create project without auth should return 401"
	);
}

#[tokio::test]
async fn create_project_requires_org_membership() {
	let app = TestApp::new().await;
	let org_id = app.fixtures.org_b.org.id.to_string();

	// User from org_a trying to create project in org_b should be forbidden
	let response = app
		.post(
			"/api/crash/projects",
			Some(&app.fixtures.org_a.member),
			json!({
				"org_id": org_id,
				"name": "Test Project",
				"slug": "test-project",
				"platform": "javascript"
			}),
		)
		.await;
	assert_eq!(
		response.status(),
		StatusCode::FORBIDDEN,
		"Non-member should not be able to create project in another org"
	);
}

#[tokio::test]
async fn create_project_succeeds_for_org_member() {
	let app = TestApp::new().await;
	let org_id = app.fixtures.org_a.org.id.to_string();

	let response = app
		.post(
			"/api/crash/projects",
			Some(&app.fixtures.org_a.member),
			json!({
				"org_id": org_id,
				"name": "Test Project",
				"slug": "test-project-create",
				"platform": "javascript"
			}),
		)
		.await;
	assert_eq!(
		response.status(),
		StatusCode::CREATED,
		"Org member should be able to create project"
	);
}

// ============================================================================
// Capture Tests
// ============================================================================

#[tokio::test]
async fn capture_crash_requires_auth() {
	let app = TestApp::new().await;
	let org_id = app.fixtures.org_a.org.id.to_string();

	// First create a project
	let project_id = create_test_project(&app, &org_id, "capture-auth-test").await;

	// No auth should return 401
	let response = app
		.post(
			"/api/crash/capture",
			None,
			json!({
				"project_id": project_id,
				"exception_type": "TypeError",
				"exception_value": "Cannot read property 'x' of undefined",
				"stacktrace": {
					"frames": [{
						"function": "handleClick",
						"filename": "app.js",
						"lineno": 42,
						"in_app": true
					}]
				}
			}),
		)
		.await;
	assert_eq!(
		response.status(),
		StatusCode::UNAUTHORIZED,
		"Capture crash without auth should return 401"
	);
}

#[tokio::test]
async fn capture_crash_requires_org_membership() {
	let app = TestApp::new().await;
	let org_id = app.fixtures.org_a.org.id.to_string();

	// Create project in org_a
	let project_id = create_test_project(&app, &org_id, "capture-membership-test").await;

	// User from org_b trying to capture crash in org_a's project should be forbidden
	let response = app
		.post(
			"/api/crash/capture",
			Some(&app.fixtures.org_b.member),
			json!({
				"project_id": project_id,
				"exception_type": "TypeError",
				"exception_value": "Cannot read property 'x' of undefined",
				"stacktrace": {
					"frames": [{
						"function": "handleClick",
						"filename": "app.js",
						"lineno": 42,
						"in_app": true
					}]
				}
			}),
		)
		.await;
	assert_eq!(
		response.status(),
		StatusCode::FORBIDDEN,
		"Non-member should not be able to capture crash in another org's project"
	);
}

#[tokio::test]
async fn capture_crash_succeeds_for_org_member() {
	let app = TestApp::new().await;
	let org_id = app.fixtures.org_a.org.id.to_string();

	// Create project
	let project_id = create_test_project(&app, &org_id, "capture-success-test").await;

	// Org member can capture crash
	let response = app
		.post(
			"/api/crash/capture",
			Some(&app.fixtures.org_a.member),
			json!({
				"project_id": project_id,
				"exception_type": "TypeError",
				"exception_value": "Cannot read property 'x' of undefined",
				"stacktrace": {
					"frames": [{
						"function": "handleClick",
						"filename": "app.js",
						"lineno": 42,
						"in_app": true
					}]
				}
			}),
		)
		.await;
	assert_eq!(
		response.status(),
		StatusCode::OK,
		"Org member should be able to capture crash"
	);
}

// ============================================================================
// Issues List Tests
// ============================================================================

#[tokio::test]
async fn list_issues_requires_auth() {
	let app = TestApp::new().await;
	let org_id = app.fixtures.org_a.org.id.to_string();
	let project_id = create_test_project(&app, &org_id, "issues-auth-test").await;

	// No auth should return 401
	let response = app
		.get(&format!("/api/crash/projects/{}/issues", project_id), None)
		.await;
	assert_eq!(
		response.status(),
		StatusCode::UNAUTHORIZED,
		"List issues without auth should return 401"
	);
}

#[tokio::test]
async fn list_issues_requires_org_membership() {
	let app = TestApp::new().await;
	let org_id = app.fixtures.org_a.org.id.to_string();
	let project_id = create_test_project(&app, &org_id, "issues-membership-test").await;

	// User from org_b trying to list issues in org_a's project should be forbidden
	let response = app
		.get(
			&format!("/api/crash/projects/{}/issues", project_id),
			Some(&app.fixtures.org_b.member),
		)
		.await;
	assert_eq!(
		response.status(),
		StatusCode::FORBIDDEN,
		"Non-member should not be able to list issues in another org's project"
	);
}

#[tokio::test]
async fn list_issues_succeeds_for_org_member() {
	let app = TestApp::new().await;
	let org_id = app.fixtures.org_a.org.id.to_string();
	let project_id = create_test_project(&app, &org_id, "issues-success-test").await;

	let response = app
		.get(
			&format!("/api/crash/projects/{}/issues", project_id),
			Some(&app.fixtures.org_a.member),
		)
		.await;
	assert_eq!(
		response.status(),
		StatusCode::OK,
		"Org member should be able to list issues"
	);
}

// ============================================================================
// Helper: Create a crash event and return the issue ID
// ============================================================================

async fn create_test_issue(app: &TestApp, project_id: &str) -> String {
	let response = app
		.post(
			"/api/crash/capture",
			Some(&app.fixtures.org_a.member),
			json!({
				"project_id": project_id,
				"exception_type": "TypeError",
				"exception_value": "Cannot read property 'x' of undefined",
				"stacktrace": {
					"frames": [{
						"function": "handleClick",
						"filename": "app.js",
						"lineno": 42,
						"in_app": true
					}]
				}
			}),
		)
		.await;

	assert_eq!(
		response.status(),
		StatusCode::OK,
		"Failed to capture crash for test issue"
	);

	let (_, body) = response.into_parts();
	let body_bytes = axum::body::to_bytes(body, usize::MAX).await.unwrap();
	let result: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();

	result["issue_id"].as_str().unwrap().to_string()
}

// ============================================================================
// Get Issue Detail Tests
// ============================================================================

#[tokio::test]
async fn get_issue_requires_auth() {
	let app = TestApp::new().await;
	let org_id = app.fixtures.org_a.org.id.to_string();
	let project_id = create_test_project(&app, &org_id, "get-issue-auth-test").await;
	let issue_id = create_test_issue(&app, &project_id).await;

	// No auth should return 401
	let response = app
		.get(
			&format!("/api/crash/projects/{}/issues/{}", project_id, issue_id),
			None,
		)
		.await;
	assert_eq!(
		response.status(),
		StatusCode::UNAUTHORIZED,
		"Get issue without auth should return 401"
	);
}

#[tokio::test]
async fn get_issue_requires_org_membership() {
	let app = TestApp::new().await;
	let org_id = app.fixtures.org_a.org.id.to_string();
	let project_id = create_test_project(&app, &org_id, "get-issue-membership-test").await;
	let issue_id = create_test_issue(&app, &project_id).await;

	// User from org_b trying to get issue in org_a's project should be forbidden
	let response = app
		.get(
			&format!("/api/crash/projects/{}/issues/{}", project_id, issue_id),
			Some(&app.fixtures.org_b.member),
		)
		.await;
	assert_eq!(
		response.status(),
		StatusCode::FORBIDDEN,
		"Non-member should not be able to get issue in another org's project"
	);
}

#[tokio::test]
async fn get_issue_succeeds_for_org_member() {
	let app = TestApp::new().await;
	let org_id = app.fixtures.org_a.org.id.to_string();
	let project_id = create_test_project(&app, &org_id, "get-issue-success-test").await;
	let issue_id = create_test_issue(&app, &project_id).await;

	let response = app
		.get(
			&format!("/api/crash/projects/{}/issues/{}", project_id, issue_id),
			Some(&app.fixtures.org_a.member),
		)
		.await;
	assert_eq!(
		response.status(),
		StatusCode::OK,
		"Org member should be able to get issue detail"
	);
}

#[tokio::test]
async fn get_issue_returns_404_for_nonexistent_issue() {
	let app = TestApp::new().await;
	let org_id = app.fixtures.org_a.org.id.to_string();
	let project_id = create_test_project(&app, &org_id, "get-issue-404-test").await;

	let response = app
		.get(
			&format!(
				"/api/crash/projects/{}/issues/{}",
				project_id,
				uuid::Uuid::new_v4()
			),
			Some(&app.fixtures.org_a.member),
		)
		.await;
	assert_eq!(
		response.status(),
		StatusCode::NOT_FOUND,
		"Getting nonexistent issue should return 404"
	);
}

// ============================================================================
// List Issue Events Tests
// ============================================================================

#[tokio::test]
async fn list_issue_events_requires_auth() {
	let app = TestApp::new().await;
	let org_id = app.fixtures.org_a.org.id.to_string();
	let project_id = create_test_project(&app, &org_id, "list-events-auth-test").await;
	let issue_id = create_test_issue(&app, &project_id).await;

	// No auth should return 401
	let response = app
		.get(
			&format!(
				"/api/crash/projects/{}/issues/{}/events",
				project_id, issue_id
			),
			None,
		)
		.await;
	assert_eq!(
		response.status(),
		StatusCode::UNAUTHORIZED,
		"List issue events without auth should return 401"
	);
}

#[tokio::test]
async fn list_issue_events_requires_org_membership() {
	let app = TestApp::new().await;
	let org_id = app.fixtures.org_a.org.id.to_string();
	let project_id = create_test_project(&app, &org_id, "list-events-membership-test").await;
	let issue_id = create_test_issue(&app, &project_id).await;

	// User from org_b trying to list events in org_a's project should be forbidden
	let response = app
		.get(
			&format!(
				"/api/crash/projects/{}/issues/{}/events",
				project_id, issue_id
			),
			Some(&app.fixtures.org_b.member),
		)
		.await;
	assert_eq!(
		response.status(),
		StatusCode::FORBIDDEN,
		"Non-member should not be able to list events in another org's project"
	);
}

#[tokio::test]
async fn list_issue_events_succeeds_for_org_member() {
	let app = TestApp::new().await;
	let org_id = app.fixtures.org_a.org.id.to_string();
	let project_id = create_test_project(&app, &org_id, "list-events-success-test").await;
	let issue_id = create_test_issue(&app, &project_id).await;

	let response = app
		.get(
			&format!(
				"/api/crash/projects/{}/issues/{}/events",
				project_id, issue_id
			),
			Some(&app.fixtures.org_a.member),
		)
		.await;
	assert_eq!(
		response.status(),
		StatusCode::OK,
		"Org member should be able to list issue events"
	);

	// Verify we got at least one event (from the test crash we created)
	let (_, body) = response.into_parts();
	let body_bytes = axum::body::to_bytes(body, usize::MAX).await.unwrap();
	let events: Vec<serde_json::Value> = serde_json::from_slice(&body_bytes).unwrap();
	assert!(
		!events.is_empty(),
		"Should have at least one event for the issue"
	);
}

#[tokio::test]
async fn list_issue_events_returns_404_for_nonexistent_issue() {
	let app = TestApp::new().await;
	let org_id = app.fixtures.org_a.org.id.to_string();
	let project_id = create_test_project(&app, &org_id, "list-events-404-test").await;

	let response = app
		.get(
			&format!(
				"/api/crash/projects/{}/issues/{}/events",
				project_id,
				uuid::Uuid::new_v4()
			),
			Some(&app.fixtures.org_a.member),
		)
		.await;
	assert_eq!(
		response.status(),
		StatusCode::NOT_FOUND,
		"Listing events for nonexistent issue should return 404"
	);
}

// ============================================================================
// SSE Stream Tests
// ============================================================================

#[tokio::test]
async fn stream_crash_requires_auth() {
	let app = TestApp::new().await;
	let org_id = app.fixtures.org_a.org.id.to_string();
	let project_id = create_test_project(&app, &org_id, "stream-auth-test").await;

	// No auth should return 401
	let response = app
		.get(&format!("/api/crash/projects/{}/stream", project_id), None)
		.await;
	assert_eq!(
		response.status(),
		StatusCode::UNAUTHORIZED,
		"Stream crash without auth should return 401"
	);
}

#[tokio::test]
async fn stream_crash_requires_org_membership() {
	let app = TestApp::new().await;
	let org_id = app.fixtures.org_a.org.id.to_string();
	let project_id = create_test_project(&app, &org_id, "stream-membership-test").await;

	// User from org_b trying to stream crash in org_a's project should be forbidden
	let response = app
		.get(
			&format!("/api/crash/projects/{}/stream", project_id),
			Some(&app.fixtures.org_b.member),
		)
		.await;
	assert_eq!(
		response.status(),
		StatusCode::FORBIDDEN,
		"Non-member should not be able to stream crash in another org's project"
	);
}

#[tokio::test]
async fn stream_crash_succeeds_for_org_member() {
	let app = TestApp::new().await;
	let org_id = app.fixtures.org_a.org.id.to_string();
	let project_id = create_test_project(&app, &org_id, "stream-success-test").await;

	let response = app
		.get(
			&format!("/api/crash/projects/{}/stream", project_id),
			Some(&app.fixtures.org_a.member),
		)
		.await;
	assert_eq!(
		response.status(),
		StatusCode::OK,
		"Org member should be able to stream crash events"
	);
}

#[tokio::test]
async fn stream_crash_returns_404_for_nonexistent_project() {
	let app = TestApp::new().await;

	let response = app
		.get(
			&format!("/api/crash/projects/{}/stream", uuid::Uuid::new_v4()),
			Some(&app.fixtures.org_a.member),
		)
		.await;
	assert_eq!(
		response.status(),
		StatusCode::NOT_FOUND,
		"Streaming nonexistent project should return 404"
	);
}

// ============================================================================
// Release List Tests
// ============================================================================

#[tokio::test]
async fn list_releases_requires_auth() {
	let app = TestApp::new().await;
	let org_id = app.fixtures.org_a.org.id.to_string();
	let project_id = create_test_project(&app, &org_id, "releases-auth-test").await;

	// No auth should return 401
	let response = app
		.get(
			&format!("/api/crash/projects/{}/releases", project_id),
			None,
		)
		.await;
	assert_eq!(
		response.status(),
		StatusCode::UNAUTHORIZED,
		"List releases without auth should return 401"
	);
}

#[tokio::test]
async fn list_releases_requires_org_membership() {
	let app = TestApp::new().await;
	let org_id = app.fixtures.org_a.org.id.to_string();
	let project_id = create_test_project(&app, &org_id, "releases-membership-test").await;

	// User from org_b trying to list releases in org_a's project should be forbidden
	let response = app
		.get(
			&format!("/api/crash/projects/{}/releases", project_id),
			Some(&app.fixtures.org_b.member),
		)
		.await;
	assert_eq!(
		response.status(),
		StatusCode::FORBIDDEN,
		"Non-member should not be able to list releases in another org's project"
	);
}

#[tokio::test]
async fn list_releases_succeeds_for_org_member() {
	let app = TestApp::new().await;
	let org_id = app.fixtures.org_a.org.id.to_string();
	let project_id = create_test_project(&app, &org_id, "releases-success-test").await;

	let response = app
		.get(
			&format!("/api/crash/projects/{}/releases", project_id),
			Some(&app.fixtures.org_a.member),
		)
		.await;
	assert_eq!(
		response.status(),
		StatusCode::OK,
		"Org member should be able to list releases"
	);
}

// ============================================================================
// Create Release Tests
// ============================================================================

#[tokio::test]
async fn create_release_requires_auth() {
	let app = TestApp::new().await;
	let org_id = app.fixtures.org_a.org.id.to_string();
	let project_id = create_test_project(&app, &org_id, "create-release-auth-test").await;

	// No auth should return 401
	let response = app
		.post(
			&format!("/api/crash/projects/{}/releases", project_id),
			None,
			json!({
				"version": "1.0.0"
			}),
		)
		.await;
	assert_eq!(
		response.status(),
		StatusCode::UNAUTHORIZED,
		"Create release without auth should return 401"
	);
}

#[tokio::test]
async fn create_release_requires_org_membership() {
	let app = TestApp::new().await;
	let org_id = app.fixtures.org_a.org.id.to_string();
	let project_id = create_test_project(&app, &org_id, "create-release-membership-test").await;

	// User from org_b trying to create release in org_a's project should be forbidden
	let response = app
		.post(
			&format!("/api/crash/projects/{}/releases", project_id),
			Some(&app.fixtures.org_b.member),
			json!({
				"version": "1.0.0"
			}),
		)
		.await;
	assert_eq!(
		response.status(),
		StatusCode::FORBIDDEN,
		"Non-member should not be able to create release in another org's project"
	);
}

#[tokio::test]
async fn create_release_succeeds_for_org_member() {
	let app = TestApp::new().await;
	let org_id = app.fixtures.org_a.org.id.to_string();
	let project_id = create_test_project(&app, &org_id, "create-release-success-test").await;

	let response = app
		.post(
			&format!("/api/crash/projects/{}/releases", project_id),
			Some(&app.fixtures.org_a.member),
			json!({
				"version": "1.0.0",
				"short_version": "v1.0",
				"url": "https://example.com/releases/1.0.0"
			}),
		)
		.await;
	assert_eq!(
		response.status(),
		StatusCode::CREATED,
		"Org member should be able to create release"
	);
}

#[tokio::test]
async fn create_release_returns_conflict_for_duplicate_version() {
	let app = TestApp::new().await;
	let org_id = app.fixtures.org_a.org.id.to_string();
	let project_id = create_test_project(&app, &org_id, "create-release-conflict-test").await;

	// Create first release
	let response = app
		.post(
			&format!("/api/crash/projects/{}/releases", project_id),
			Some(&app.fixtures.org_a.member),
			json!({
				"version": "2.0.0"
			}),
		)
		.await;
	assert_eq!(response.status(), StatusCode::CREATED);

	// Try to create release with same version
	let response = app
		.post(
			&format!("/api/crash/projects/{}/releases", project_id),
			Some(&app.fixtures.org_a.member),
			json!({
				"version": "2.0.0"
			}),
		)
		.await;
	assert_eq!(
		response.status(),
		StatusCode::CONFLICT,
		"Creating duplicate release should return 409 Conflict"
	);
}

// ============================================================================
// Get Release Detail Tests
// ============================================================================

#[tokio::test]
async fn get_release_requires_auth() {
	let app = TestApp::new().await;
	let org_id = app.fixtures.org_a.org.id.to_string();
	let project_id = create_test_project(&app, &org_id, "get-release-auth-test").await;

	// Create a release first
	let _ = app
		.post(
			&format!("/api/crash/projects/{}/releases", project_id),
			Some(&app.fixtures.org_a.member),
			json!({
				"version": "1.0.0"
			}),
		)
		.await;

	// No auth should return 401
	let response = app
		.get(
			&format!("/api/crash/projects/{}/releases/1.0.0", project_id),
			None,
		)
		.await;
	assert_eq!(
		response.status(),
		StatusCode::UNAUTHORIZED,
		"Get release without auth should return 401"
	);
}

#[tokio::test]
async fn get_release_requires_org_membership() {
	let app = TestApp::new().await;
	let org_id = app.fixtures.org_a.org.id.to_string();
	let project_id = create_test_project(&app, &org_id, "get-release-membership-test").await;

	// Create a release first
	let _ = app
		.post(
			&format!("/api/crash/projects/{}/releases", project_id),
			Some(&app.fixtures.org_a.member),
			json!({
				"version": "1.0.0"
			}),
		)
		.await;

	// User from org_b trying to get release in org_a's project should be forbidden
	let response = app
		.get(
			&format!("/api/crash/projects/{}/releases/1.0.0", project_id),
			Some(&app.fixtures.org_b.member),
		)
		.await;
	assert_eq!(
		response.status(),
		StatusCode::FORBIDDEN,
		"Non-member should not be able to get release in another org's project"
	);
}

#[tokio::test]
async fn get_release_succeeds_for_org_member() {
	let app = TestApp::new().await;
	let org_id = app.fixtures.org_a.org.id.to_string();
	let project_id = create_test_project(&app, &org_id, "get-release-success-test").await;

	// Create a release first
	let _ = app
		.post(
			&format!("/api/crash/projects/{}/releases", project_id),
			Some(&app.fixtures.org_a.member),
			json!({
				"version": "1.0.0"
			}),
		)
		.await;

	let response = app
		.get(
			&format!("/api/crash/projects/{}/releases/1.0.0", project_id),
			Some(&app.fixtures.org_a.member),
		)
		.await;
	assert_eq!(
		response.status(),
		StatusCode::OK,
		"Org member should be able to get release detail"
	);
}

#[tokio::test]
async fn get_release_returns_404_for_nonexistent_version() {
	let app = TestApp::new().await;
	let org_id = app.fixtures.org_a.org.id.to_string();
	let project_id = create_test_project(&app, &org_id, "get-release-404-test").await;

	let response = app
		.get(
			&format!("/api/crash/projects/{}/releases/nonexistent", project_id),
			Some(&app.fixtures.org_a.member),
		)
		.await;
	assert_eq!(
		response.status(),
		StatusCode::NOT_FOUND,
		"Getting nonexistent release should return 404"
	);
}

// ============================================================================
// Batch Capture Tests
// ============================================================================

#[tokio::test]
async fn batch_capture_requires_auth() {
	let app = TestApp::new().await;
	let org_id = app.fixtures.org_a.org.id.to_string();
	let project_id = create_test_project(&app, &org_id, "batch-auth-test").await;

	// No auth should return 401
	let response = app
		.post(
			"/api/crash/batch",
			None,
			json!({
				"events": [{
					"project_id": project_id,
					"exception_type": "TypeError",
					"exception_value": "Test error",
					"stacktrace": {
						"frames": [{
							"function": "test",
							"filename": "test.js",
							"lineno": 1,
							"in_app": true
						}]
					}
				}]
			}),
		)
		.await;
	assert_eq!(
		response.status(),
		StatusCode::UNAUTHORIZED,
		"Batch capture without auth should return 401"
	);
}

#[tokio::test]
async fn batch_capture_requires_org_membership() {
	let app = TestApp::new().await;
	let org_id = app.fixtures.org_a.org.id.to_string();
	let project_id = create_test_project(&app, &org_id, "batch-membership-test").await;

	// User from org_b trying to batch capture in org_a's project should fail
	let response = app
		.post(
			"/api/crash/batch",
			Some(&app.fixtures.org_b.member),
			json!({
				"events": [{
					"project_id": project_id,
					"exception_type": "TypeError",
					"exception_value": "Test error",
					"stacktrace": {
						"frames": [{
							"function": "test",
							"filename": "test.js",
							"lineno": 1,
							"in_app": true
						}]
					}
				}]
			}),
		)
		.await;

	// Batch returns 200 but individual events will have errors
	assert_eq!(
		response.status(),
		StatusCode::OK,
		"Batch capture returns 200 with individual errors"
	);

	let (_, body) = response.into_parts();
	let body_bytes = axum::body::to_bytes(body, usize::MAX).await.unwrap();
	let result: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();

	// Verify the event failed due to membership
	assert_eq!(result["error_count"], 1, "Should have one failed event");
	assert_eq!(
		result["success_count"], 0,
		"Should have no successful events"
	);
}

#[tokio::test]
async fn batch_capture_succeeds_for_org_member() {
	let app = TestApp::new().await;
	let org_id = app.fixtures.org_a.org.id.to_string();
	let project_id = create_test_project(&app, &org_id, "batch-success-test").await;

	let response = app
		.post(
			"/api/crash/batch",
			Some(&app.fixtures.org_a.member),
			json!({
				"events": [
					{
						"project_id": project_id,
						"exception_type": "TypeError",
						"exception_value": "Error 1",
						"stacktrace": {
							"frames": [{
								"function": "func1",
								"filename": "test.js",
								"lineno": 1,
								"in_app": true
							}]
						}
					},
					{
						"project_id": project_id,
						"exception_type": "ReferenceError",
						"exception_value": "Error 2",
						"stacktrace": {
							"frames": [{
								"function": "func2",
								"filename": "other.js",
								"lineno": 42,
								"in_app": true
							}]
						}
					}
				]
			}),
		)
		.await;
	assert_eq!(
		response.status(),
		StatusCode::OK,
		"Batch capture should succeed for org member"
	);

	let (_, body) = response.into_parts();
	let body_bytes = axum::body::to_bytes(body, usize::MAX).await.unwrap();
	let result: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();

	assert_eq!(result["total"], 2, "Should have processed 2 events");
	assert_eq!(result["success_count"], 2, "Both events should succeed");
	assert_eq!(result["error_count"], 0, "Should have no errors");

	// Verify results contain event details
	let results = result["results"].as_array().unwrap();
	assert!(results[0]["event_id"].is_string());
	assert!(results[0]["issue_id"].is_string());
	assert!(results[1]["event_id"].is_string());
	assert!(results[1]["issue_id"].is_string());
}

#[tokio::test]
async fn batch_capture_empty_events_returns_empty_result() {
	let app = TestApp::new().await;

	let response = app
		.post(
			"/api/crash/batch",
			Some(&app.fixtures.org_a.member),
			json!({
				"events": []
			}),
		)
		.await;
	assert_eq!(response.status(), StatusCode::OK);

	let (_, body) = response.into_parts();
	let body_bytes = axum::body::to_bytes(body, usize::MAX).await.unwrap();
	let result: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();

	assert_eq!(result["total"], 0);
	assert_eq!(result["success_count"], 0);
	assert_eq!(result["error_count"], 0);
}

#[tokio::test]
async fn batch_capture_rejects_too_many_events() {
	let app = TestApp::new().await;
	let org_id = app.fixtures.org_a.org.id.to_string();
	let project_id = create_test_project(&app, &org_id, "batch-limit-test").await;

	// Create 101 events (over the 100 limit)
	let events: Vec<serde_json::Value> = (0..101)
		.map(|i| {
			json!({
				"project_id": project_id,
				"exception_type": "Error",
				"exception_value": format!("Error {}", i),
				"stacktrace": {
					"frames": [{
						"function": "test",
						"filename": "test.js",
						"lineno": i,
						"in_app": true
					}]
				}
			})
		})
		.collect();

	let response = app
		.post(
			"/api/crash/batch",
			Some(&app.fixtures.org_a.member),
			json!({ "events": events }),
		)
		.await;
	assert_eq!(
		response.status(),
		StatusCode::BAD_REQUEST,
		"Batch with >100 events should be rejected"
	);

	let (_, body) = response.into_parts();
	let body_bytes = axum::body::to_bytes(body, usize::MAX).await.unwrap();
	let result: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
	assert!(
		result["error"]
			.as_str()
			.unwrap()
			.contains("batch_too_large"),
		"Error should indicate batch too large"
	);
}

#[tokio::test]
async fn batch_capture_handles_mixed_success_and_failure() {
	let app = TestApp::new().await;
	let org_id = app.fixtures.org_a.org.id.to_string();
	let project_id = create_test_project(&app, &org_id, "batch-mixed-test").await;

	let response = app
		.post(
			"/api/crash/batch",
			Some(&app.fixtures.org_a.member),
			json!({
				"events": [
					{
						"project_id": project_id,
						"exception_type": "TypeError",
						"exception_value": "Valid error",
						"stacktrace": {
							"frames": [{
								"function": "test",
								"filename": "test.js",
								"lineno": 1,
								"in_app": true
							}]
						}
					},
					{
						"project_id": "invalid-project-id",
						"exception_type": "Error",
						"exception_value": "Should fail",
						"stacktrace": {
							"frames": [{
								"function": "test",
								"filename": "test.js",
								"lineno": 1,
								"in_app": true
							}]
						}
					}
				]
			}),
		)
		.await;
	assert_eq!(response.status(), StatusCode::OK);

	let (_, body) = response.into_parts();
	let body_bytes = axum::body::to_bytes(body, usize::MAX).await.unwrap();
	let result: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();

	assert_eq!(result["total"], 2);
	assert_eq!(result["success_count"], 1, "First event should succeed");
	assert_eq!(result["error_count"], 1, "Second event should fail");

	let results = result["results"].as_array().unwrap();
	assert!(results[0]["success"].as_bool().unwrap());
	assert!(!results[1]["success"].as_bool().unwrap());
	assert!(results[1]["error"].is_string());
}

// ============================================================================
// Release Auto-Creation via Crash Capture
// ============================================================================

#[tokio::test]
async fn capture_crash_auto_creates_release() {
	let app = TestApp::new().await;
	let org_id = app.fixtures.org_a.org.id.to_string();
	let project_id = create_test_project(&app, &org_id, "auto-release-test").await;

	// Capture a crash with a release version
	let response = app
		.post(
			"/api/crash/capture",
			Some(&app.fixtures.org_a.member),
			json!({
				"project_id": project_id,
				"exception_type": "Error",
				"exception_value": "Test error",
				"stacktrace": {
					"frames": [{
						"function": "test",
						"filename": "test.js",
						"lineno": 1,
						"in_app": true
					}]
				},
				"release": "3.0.0"
			}),
		)
		.await;
	assert_eq!(response.status(), StatusCode::OK);

	// Verify the release was auto-created
	let response = app
		.get(
			&format!("/api/crash/projects/{}/releases/3.0.0", project_id),
			Some(&app.fixtures.org_a.member),
		)
		.await;
	assert_eq!(
		response.status(),
		StatusCode::OK,
		"Release should be auto-created when capturing crash with release version"
	);

	// Verify crash count was incremented
	let (_, body) = response.into_parts();
	let body_bytes = axum::body::to_bytes(body, usize::MAX).await.unwrap();
	let release: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
	assert_eq!(release["crash_count"], 1, "Release crash count should be 1");
	assert_eq!(
		release["new_issue_count"], 1,
		"Release new_issue_count should be 1"
	);
}

// ============================================================================
// Artifact List Tests
// ============================================================================

#[tokio::test]
async fn list_artifacts_requires_auth() {
	let app = TestApp::new().await;
	let org_id = app.fixtures.org_a.org.id.to_string();
	let project_id = create_test_project(&app, &org_id, "artifacts-auth-test").await;

	// No auth should return 401
	let response = app
		.get(
			&format!("/api/crash/projects/{}/artifacts", project_id),
			None,
		)
		.await;
	assert_eq!(
		response.status(),
		StatusCode::UNAUTHORIZED,
		"List artifacts without auth should return 401"
	);
}

#[tokio::test]
async fn list_artifacts_requires_org_membership() {
	let app = TestApp::new().await;
	let org_id = app.fixtures.org_a.org.id.to_string();
	let project_id = create_test_project(&app, &org_id, "artifacts-membership-test").await;

	// User from org_b trying to list artifacts in org_a's project should be forbidden
	let response = app
		.get(
			&format!("/api/crash/projects/{}/artifacts", project_id),
			Some(&app.fixtures.org_b.member),
		)
		.await;
	assert_eq!(
		response.status(),
		StatusCode::FORBIDDEN,
		"Non-member should not be able to list artifacts in another org's project"
	);
}

#[tokio::test]
async fn list_artifacts_succeeds_for_org_member() {
	let app = TestApp::new().await;
	let org_id = app.fixtures.org_a.org.id.to_string();
	let project_id = create_test_project(&app, &org_id, "artifacts-success-test").await;

	let response = app
		.get(
			&format!("/api/crash/projects/{}/artifacts", project_id),
			Some(&app.fixtures.org_a.member),
		)
		.await;
	assert_eq!(
		response.status(),
		StatusCode::OK,
		"Org member should be able to list artifacts"
	);
}

#[tokio::test]
async fn list_artifacts_returns_404_for_nonexistent_project() {
	let app = TestApp::new().await;

	let response = app
		.get(
			&format!("/api/crash/projects/{}/artifacts", uuid::Uuid::new_v4()),
			Some(&app.fixtures.org_a.member),
		)
		.await;
	assert_eq!(
		response.status(),
		StatusCode::NOT_FOUND,
		"Listing artifacts for nonexistent project should return 404"
	);
}

// ============================================================================
// Get Artifact Tests
// ============================================================================

#[tokio::test]
async fn get_artifact_requires_auth() {
	let app = TestApp::new().await;
	let org_id = app.fixtures.org_a.org.id.to_string();
	let project_id = create_test_project(&app, &org_id, "get-artifact-auth-test").await;

	// No auth should return 401
	let response = app
		.get(
			&format!(
				"/api/crash/projects/{}/artifacts/{}",
				project_id,
				uuid::Uuid::new_v4()
			),
			None,
		)
		.await;
	assert_eq!(
		response.status(),
		StatusCode::UNAUTHORIZED,
		"Get artifact without auth should return 401"
	);
}

#[tokio::test]
async fn get_artifact_requires_org_membership() {
	let app = TestApp::new().await;
	let org_id = app.fixtures.org_a.org.id.to_string();
	let project_id = create_test_project(&app, &org_id, "get-artifact-membership-test").await;

	// User from org_b trying to get artifact in org_a's project should be forbidden
	let response = app
		.get(
			&format!(
				"/api/crash/projects/{}/artifacts/{}",
				project_id,
				uuid::Uuid::new_v4()
			),
			Some(&app.fixtures.org_b.member),
		)
		.await;
	assert_eq!(
		response.status(),
		StatusCode::FORBIDDEN,
		"Non-member should not be able to get artifact in another org's project"
	);
}

#[tokio::test]
async fn get_artifact_returns_404_for_nonexistent_artifact() {
	let app = TestApp::new().await;
	let org_id = app.fixtures.org_a.org.id.to_string();
	let project_id = create_test_project(&app, &org_id, "get-artifact-404-test").await;

	let response = app
		.get(
			&format!(
				"/api/crash/projects/{}/artifacts/{}",
				project_id,
				uuid::Uuid::new_v4()
			),
			Some(&app.fixtures.org_a.member),
		)
		.await;
	assert_eq!(
		response.status(),
		StatusCode::NOT_FOUND,
		"Getting nonexistent artifact should return 404"
	);
}

// ============================================================================
// Delete Artifact Tests
// ============================================================================

#[tokio::test]
async fn delete_artifact_requires_auth() {
	let app = TestApp::new().await;
	let org_id = app.fixtures.org_a.org.id.to_string();
	let project_id = create_test_project(&app, &org_id, "delete-artifact-auth-test").await;

	// No auth should return 401
	let response = app
		.delete(
			&format!(
				"/api/crash/projects/{}/artifacts/{}",
				project_id,
				uuid::Uuid::new_v4()
			),
			None,
		)
		.await;
	assert_eq!(
		response.status(),
		StatusCode::UNAUTHORIZED,
		"Delete artifact without auth should return 401"
	);
}

#[tokio::test]
async fn delete_artifact_requires_org_membership() {
	let app = TestApp::new().await;
	let org_id = app.fixtures.org_a.org.id.to_string();
	let project_id = create_test_project(&app, &org_id, "delete-artifact-membership-test").await;

	// User from org_b trying to delete artifact in org_a's project should be forbidden
	let response = app
		.delete(
			&format!(
				"/api/crash/projects/{}/artifacts/{}",
				project_id,
				uuid::Uuid::new_v4()
			),
			Some(&app.fixtures.org_b.member),
		)
		.await;
	assert_eq!(
		response.status(),
		StatusCode::FORBIDDEN,
		"Non-member should not be able to delete artifact in another org's project"
	);
}

#[tokio::test]
async fn delete_artifact_returns_404_for_nonexistent_artifact() {
	let app = TestApp::new().await;
	let org_id = app.fixtures.org_a.org.id.to_string();
	let project_id = create_test_project(&app, &org_id, "delete-artifact-404-test").await;

	let response = app
		.delete(
			&format!(
				"/api/crash/projects/{}/artifacts/{}",
				project_id,
				uuid::Uuid::new_v4()
			),
			Some(&app.fixtures.org_a.member),
		)
		.await;
	assert_eq!(
		response.status(),
		StatusCode::NOT_FOUND,
		"Deleting nonexistent artifact should return 404"
	);
}

// ============================================================================
// API Key Management Tests
// ============================================================================

/// Helper: Create an API key and return the raw key
async fn create_test_api_key(app: &TestApp, project_id: &str, key_type: &str) -> (String, String) {
	let response = app
		.post(
			&format!("/api/crash/projects/{}/api-keys", project_id),
			Some(&app.fixtures.org_a.member),
			json!({
				"name": "Test API Key",
				"key_type": key_type
			}),
		)
		.await;

	assert_eq!(
		response.status(),
		StatusCode::CREATED,
		"Failed to create test API key"
	);

	let (_, body) = response.into_parts();
	let body_bytes = axum::body::to_bytes(body, usize::MAX).await.unwrap();
	let result: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();

	(
		result["id"].as_str().unwrap().to_string(),
		result["key"].as_str().unwrap().to_string(),
	)
}

#[tokio::test]
async fn create_api_key_requires_auth() {
	let app = TestApp::new().await;
	let org_id = app.fixtures.org_a.org.id.to_string();
	let project_id = create_test_project(&app, &org_id, "api-key-auth-test").await;

	// No auth should return 401
	let response = app
		.post(
			&format!("/api/crash/projects/{}/api-keys", project_id),
			None,
			json!({
				"name": "Test Key",
				"key_type": "capture"
			}),
		)
		.await;
	assert_eq!(
		response.status(),
		StatusCode::UNAUTHORIZED,
		"Create API key without auth should return 401"
	);
}

#[tokio::test]
async fn create_api_key_requires_org_membership() {
	let app = TestApp::new().await;
	let org_id = app.fixtures.org_a.org.id.to_string();
	let project_id = create_test_project(&app, &org_id, "api-key-membership-test").await;

	// User from org_b trying to create API key in org_a's project should be forbidden
	let response = app
		.post(
			&format!("/api/crash/projects/{}/api-keys", project_id),
			Some(&app.fixtures.org_b.member),
			json!({
				"name": "Test Key",
				"key_type": "capture"
			}),
		)
		.await;
	assert_eq!(
		response.status(),
		StatusCode::FORBIDDEN,
		"Non-member should not be able to create API key in another org's project"
	);
}

#[tokio::test]
async fn create_api_key_succeeds_for_org_member() {
	let app = TestApp::new().await;
	let org_id = app.fixtures.org_a.org.id.to_string();
	let project_id = create_test_project(&app, &org_id, "api-key-success-test").await;

	let response = app
		.post(
			&format!("/api/crash/projects/{}/api-keys", project_id),
			Some(&app.fixtures.org_a.member),
			json!({
				"name": "Test Capture Key",
				"key_type": "capture"
			}),
		)
		.await;
	assert_eq!(
		response.status(),
		StatusCode::CREATED,
		"Org member should be able to create API key"
	);

	let (_, body) = response.into_parts();
	let body_bytes = axum::body::to_bytes(body, usize::MAX).await.unwrap();
	let result: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();

	assert!(result["id"].is_string());
	assert!(result["key"].as_str().unwrap().starts_with("loom_crash_capture_"));
	assert_eq!(result["key_type"], "capture");
}

#[tokio::test]
async fn create_api_key_admin_type() {
	let app = TestApp::new().await;
	let org_id = app.fixtures.org_a.org.id.to_string();
	let project_id = create_test_project(&app, &org_id, "api-key-admin-test").await;

	let response = app
		.post(
			&format!("/api/crash/projects/{}/api-keys", project_id),
			Some(&app.fixtures.org_a.member),
			json!({
				"name": "Test Admin Key",
				"key_type": "admin"
			}),
		)
		.await;
	assert_eq!(response.status(), StatusCode::CREATED);

	let (_, body) = response.into_parts();
	let body_bytes = axum::body::to_bytes(body, usize::MAX).await.unwrap();
	let result: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();

	assert!(result["key"].as_str().unwrap().starts_with("loom_crash_admin_"));
	assert_eq!(result["key_type"], "admin");
}

#[tokio::test]
async fn create_api_key_invalid_type_rejected() {
	let app = TestApp::new().await;
	let org_id = app.fixtures.org_a.org.id.to_string();
	let project_id = create_test_project(&app, &org_id, "api-key-invalid-test").await;

	let response = app
		.post(
			&format!("/api/crash/projects/{}/api-keys", project_id),
			Some(&app.fixtures.org_a.member),
			json!({
				"name": "Test Key",
				"key_type": "invalid"
			}),
		)
		.await;
	assert_eq!(
		response.status(),
		StatusCode::BAD_REQUEST,
		"Invalid key type should be rejected"
	);
}

#[tokio::test]
async fn list_api_keys_requires_auth() {
	let app = TestApp::new().await;
	let org_id = app.fixtures.org_a.org.id.to_string();
	let project_id = create_test_project(&app, &org_id, "list-api-keys-auth-test").await;

	let response = app
		.get(
			&format!("/api/crash/projects/{}/api-keys", project_id),
			None,
		)
		.await;
	assert_eq!(
		response.status(),
		StatusCode::UNAUTHORIZED,
		"List API keys without auth should return 401"
	);
}

#[tokio::test]
async fn list_api_keys_requires_org_membership() {
	let app = TestApp::new().await;
	let org_id = app.fixtures.org_a.org.id.to_string();
	let project_id = create_test_project(&app, &org_id, "list-api-keys-membership-test").await;

	let response = app
		.get(
			&format!("/api/crash/projects/{}/api-keys", project_id),
			Some(&app.fixtures.org_b.member),
		)
		.await;
	assert_eq!(
		response.status(),
		StatusCode::FORBIDDEN,
		"Non-member should not be able to list API keys in another org's project"
	);
}

#[tokio::test]
async fn list_api_keys_succeeds_for_org_member() {
	let app = TestApp::new().await;
	let org_id = app.fixtures.org_a.org.id.to_string();
	let project_id = create_test_project(&app, &org_id, "list-api-keys-success-test").await;

	// Create an API key first
	let _ = create_test_api_key(&app, &project_id, "capture").await;

	let response = app
		.get(
			&format!("/api/crash/projects/{}/api-keys", project_id),
			Some(&app.fixtures.org_a.member),
		)
		.await;
	assert_eq!(
		response.status(),
		StatusCode::OK,
		"Org member should be able to list API keys"
	);

	let (_, body) = response.into_parts();
	let body_bytes = axum::body::to_bytes(body, usize::MAX).await.unwrap();
	let keys: Vec<serde_json::Value> = serde_json::from_slice(&body_bytes).unwrap();

	assert!(!keys.is_empty(), "Should have at least one API key");
	// Verify the key hash is NOT exposed
	assert!(
		keys[0].get("key_hash").is_none(),
		"key_hash should not be exposed in list response"
	);
}

#[tokio::test]
async fn revoke_api_key_requires_auth() {
	let app = TestApp::new().await;
	let org_id = app.fixtures.org_a.org.id.to_string();
	let project_id = create_test_project(&app, &org_id, "revoke-api-key-auth-test").await;
	let (key_id, _) = create_test_api_key(&app, &project_id, "capture").await;

	let response = app
		.delete(
			&format!("/api/crash/projects/{}/api-keys/{}", project_id, key_id),
			None,
		)
		.await;
	assert_eq!(
		response.status(),
		StatusCode::UNAUTHORIZED,
		"Revoke API key without auth should return 401"
	);
}

#[tokio::test]
async fn revoke_api_key_requires_org_membership() {
	let app = TestApp::new().await;
	let org_id = app.fixtures.org_a.org.id.to_string();
	let project_id = create_test_project(&app, &org_id, "revoke-api-key-membership-test").await;
	let (key_id, _) = create_test_api_key(&app, &project_id, "capture").await;

	let response = app
		.delete(
			&format!("/api/crash/projects/{}/api-keys/{}", project_id, key_id),
			Some(&app.fixtures.org_b.member),
		)
		.await;
	assert_eq!(
		response.status(),
		StatusCode::FORBIDDEN,
		"Non-member should not be able to revoke API key in another org's project"
	);
}

#[tokio::test]
async fn revoke_api_key_succeeds_for_org_member() {
	let app = TestApp::new().await;
	let org_id = app.fixtures.org_a.org.id.to_string();
	let project_id = create_test_project(&app, &org_id, "revoke-api-key-success-test").await;
	let (key_id, _) = create_test_api_key(&app, &project_id, "capture").await;

	let response = app
		.delete(
			&format!("/api/crash/projects/{}/api-keys/{}", project_id, key_id),
			Some(&app.fixtures.org_a.member),
		)
		.await;
	assert_eq!(
		response.status(),
		StatusCode::NO_CONTENT,
		"Org member should be able to revoke API key"
	);

	// Verify the key is now revoked (shows in list with revoked_at)
	let response = app
		.get(
			&format!("/api/crash/projects/{}/api-keys", project_id),
			Some(&app.fixtures.org_a.member),
		)
		.await;
	let (_, body) = response.into_parts();
	let body_bytes = axum::body::to_bytes(body, usize::MAX).await.unwrap();
	let keys: Vec<serde_json::Value> = serde_json::from_slice(&body_bytes).unwrap();

	let revoked_key = keys.iter().find(|k| k["id"] == key_id);
	assert!(
		revoked_key.is_some() && revoked_key.unwrap()["revoked_at"].is_string(),
		"Revoked key should have revoked_at timestamp"
	);
}

#[tokio::test]
async fn revoke_api_key_returns_404_for_nonexistent_key() {
	let app = TestApp::new().await;
	let org_id = app.fixtures.org_a.org.id.to_string();
	let project_id = create_test_project(&app, &org_id, "revoke-api-key-404-test").await;

	let response = app
		.delete(
			&format!(
				"/api/crash/projects/{}/api-keys/{}",
				project_id,
				uuid::Uuid::new_v4()
			),
			Some(&app.fixtures.org_a.member),
		)
		.await;
	assert_eq!(
		response.status(),
		StatusCode::NOT_FOUND,
		"Revoking nonexistent API key should return 404"
	);
}

// ============================================================================
// SDK Capture with API Key Tests
// ============================================================================

#[tokio::test]
async fn sdk_capture_requires_api_key() {
	let app = TestApp::new().await;
	let org_id = app.fixtures.org_a.org.id.to_string();
	let project_id = create_test_project(&app, &org_id, "sdk-capture-no-key-test").await;

	// No API key header should return 401
	let response = app
		.post(
			"/api/crash/capture/sdk",
			None,
			json!({
				"project_id": project_id,
				"exception_type": "TypeError",
				"exception_value": "Test error",
				"stacktrace": {
					"frames": [{
						"function": "test",
						"filename": "test.js",
						"lineno": 1,
						"in_app": true
					}]
				}
			}),
		)
		.await;
	assert_eq!(
		response.status(),
		StatusCode::UNAUTHORIZED,
		"SDK capture without API key should return 401"
	);
}

#[tokio::test]
async fn sdk_capture_with_invalid_api_key() {
	let app = TestApp::new().await;
	let org_id = app.fixtures.org_a.org.id.to_string();
	let project_id = create_test_project(&app, &org_id, "sdk-capture-invalid-key-test").await;

	let response = app
		.post_with_header(
			"/api/crash/capture/sdk",
			"x-crash-api-key",
			"invalid_key_here",
			json!({
				"project_id": project_id,
				"exception_type": "TypeError",
				"exception_value": "Test error",
				"stacktrace": {
					"frames": [{
						"function": "test",
						"filename": "test.js",
						"lineno": 1,
						"in_app": true
					}]
				}
			}),
		)
		.await;
	assert_eq!(
		response.status(),
		StatusCode::UNAUTHORIZED,
		"SDK capture with invalid API key should return 401"
	);
}

#[tokio::test]
async fn sdk_capture_with_valid_api_key() {
	let app = TestApp::new().await;
	let org_id = app.fixtures.org_a.org.id.to_string();
	let project_id = create_test_project(&app, &org_id, "sdk-capture-valid-key-test").await;
	let (_, raw_key) = create_test_api_key(&app, &project_id, "capture").await;

	let response = app
		.post_with_header(
			"/api/crash/capture/sdk",
			"x-crash-api-key",
			&raw_key,
			json!({
				"project_id": project_id,
				"exception_type": "TypeError",
				"exception_value": "SDK captured error",
				"stacktrace": {
					"frames": [{
						"function": "sdkHandler",
						"filename": "sdk.js",
						"lineno": 100,
						"in_app": true
					}]
				}
			}),
		)
		.await;
	assert_eq!(
		response.status(),
		StatusCode::OK,
		"SDK capture with valid API key should succeed"
	);

	let (_, body) = response.into_parts();
	let body_bytes = axum::body::to_bytes(body, usize::MAX).await.unwrap();
	let result: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();

	assert!(result["event_id"].is_string());
	assert!(result["issue_id"].is_string());
}

#[tokio::test]
async fn sdk_capture_with_revoked_api_key() {
	let app = TestApp::new().await;
	let org_id = app.fixtures.org_a.org.id.to_string();
	let project_id = create_test_project(&app, &org_id, "sdk-capture-revoked-key-test").await;
	let (key_id, raw_key) = create_test_api_key(&app, &project_id, "capture").await;

	// Revoke the key
	let _ = app
		.delete(
			&format!("/api/crash/projects/{}/api-keys/{}", project_id, key_id),
			Some(&app.fixtures.org_a.member),
		)
		.await;

	// Try to use the revoked key
	let response = app
		.post_with_header(
			"/api/crash/capture/sdk",
			"x-crash-api-key",
			&raw_key,
			json!({
				"project_id": project_id,
				"exception_type": "TypeError",
				"exception_value": "Should not capture",
				"stacktrace": {
					"frames": [{
						"function": "test",
						"filename": "test.js",
						"lineno": 1,
						"in_app": true
					}]
				}
			}),
		)
		.await;
	assert_eq!(
		response.status(),
		StatusCode::UNAUTHORIZED,
		"SDK capture with revoked API key should return 401"
	);
}

// ============================================================================
// Resolve Issue Tests
// ============================================================================

#[tokio::test]
async fn resolve_issue_requires_auth() {
	let app = TestApp::new().await;
	let org_id = app.fixtures.org_a.org.id.to_string();
	let project_id = create_test_project(&app, &org_id, "resolve-auth-test").await;
	let issue_id = create_test_issue(&app, &project_id).await;

	let response = app
		.post(
			&format!(
				"/api/crash/projects/{}/issues/{}/resolve",
				project_id, issue_id
			),
			None,
			json!({}),
		)
		.await;
	assert_eq!(
		response.status(),
		StatusCode::UNAUTHORIZED,
		"Resolve issue without auth should return 401"
	);
}

#[tokio::test]
async fn resolve_issue_requires_org_membership() {
	let app = TestApp::new().await;
	let org_id = app.fixtures.org_a.org.id.to_string();
	let project_id = create_test_project(&app, &org_id, "resolve-membership-test").await;
	let issue_id = create_test_issue(&app, &project_id).await;

	// User from org_b trying to resolve issue in org_a's project
	let response = app
		.post(
			&format!(
				"/api/crash/projects/{}/issues/{}/resolve",
				project_id, issue_id
			),
			Some(&app.fixtures.org_b.member),
			json!({}),
		)
		.await;
	assert_eq!(
		response.status(),
		StatusCode::FORBIDDEN,
		"Non-member should not be able to resolve issue in another org's project"
	);
}

#[tokio::test]
async fn resolve_issue_succeeds_for_org_member() {
	let app = TestApp::new().await;
	let org_id = app.fixtures.org_a.org.id.to_string();
	let project_id = create_test_project(&app, &org_id, "resolve-success-test").await;
	let issue_id = create_test_issue(&app, &project_id).await;

	let response = app
		.post(
			&format!(
				"/api/crash/projects/{}/issues/{}/resolve",
				project_id, issue_id
			),
			Some(&app.fixtures.org_a.member),
			json!({}),
		)
		.await;
	assert_eq!(
		response.status(),
		StatusCode::OK,
		"Org member should be able to resolve issue"
	);

	let (_, body) = response.into_parts();
	let body_bytes = axum::body::to_bytes(body, usize::MAX).await.unwrap();
	let result: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
	assert_eq!(result["status"], "resolved");
}

#[tokio::test]
async fn resolve_issue_returns_404_for_nonexistent_issue() {
	let app = TestApp::new().await;
	let org_id = app.fixtures.org_a.org.id.to_string();
	let project_id = create_test_project(&app, &org_id, "resolve-404-test").await;

	let response = app
		.post(
			&format!(
				"/api/crash/projects/{}/issues/01938a6b-cdef-7000-8000-000000000000/resolve",
				project_id
			),
			Some(&app.fixtures.org_a.member),
			json!({}),
		)
		.await;
	assert_eq!(
		response.status(),
		StatusCode::NOT_FOUND,
		"Resolving nonexistent issue should return 404"
	);
}

// ============================================================================
// Unresolve Issue Tests
// ============================================================================

#[tokio::test]
async fn unresolve_issue_requires_auth() {
	let app = TestApp::new().await;
	let org_id = app.fixtures.org_a.org.id.to_string();
	let project_id = create_test_project(&app, &org_id, "unresolve-auth-test").await;
	let issue_id = create_test_issue(&app, &project_id).await;

	let response = app
		.post(
			&format!(
				"/api/crash/projects/{}/issues/{}/unresolve",
				project_id, issue_id
			),
			None,
			json!({}),
		)
		.await;
	assert_eq!(
		response.status(),
		StatusCode::UNAUTHORIZED,
		"Unresolve issue without auth should return 401"
	);
}

#[tokio::test]
async fn unresolve_issue_requires_org_membership() {
	let app = TestApp::new().await;
	let org_id = app.fixtures.org_a.org.id.to_string();
	let project_id = create_test_project(&app, &org_id, "unresolve-membership-test").await;
	let issue_id = create_test_issue(&app, &project_id).await;

	// User from org_b trying to unresolve issue in org_a's project
	let response = app
		.post(
			&format!(
				"/api/crash/projects/{}/issues/{}/unresolve",
				project_id, issue_id
			),
			Some(&app.fixtures.org_b.member),
			json!({}),
		)
		.await;
	assert_eq!(
		response.status(),
		StatusCode::FORBIDDEN,
		"Non-member should not be able to unresolve issue in another org's project"
	);
}

#[tokio::test]
async fn unresolve_issue_succeeds_for_org_member() {
	let app = TestApp::new().await;
	let org_id = app.fixtures.org_a.org.id.to_string();
	let project_id = create_test_project(&app, &org_id, "unresolve-success-test").await;
	let issue_id = create_test_issue(&app, &project_id).await;

	// First resolve the issue
	let _ = app
		.post(
			&format!(
				"/api/crash/projects/{}/issues/{}/resolve",
				project_id, issue_id
			),
			Some(&app.fixtures.org_a.member),
			json!({}),
		)
		.await;

	// Then unresolve it
	let response = app
		.post(
			&format!(
				"/api/crash/projects/{}/issues/{}/unresolve",
				project_id, issue_id
			),
			Some(&app.fixtures.org_a.member),
			json!({}),
		)
		.await;
	assert_eq!(
		response.status(),
		StatusCode::OK,
		"Org member should be able to unresolve issue"
	);

	let (_, body) = response.into_parts();
	let body_bytes = axum::body::to_bytes(body, usize::MAX).await.unwrap();
	let result: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
	assert_eq!(result["status"], "unresolved");
}

#[tokio::test]
async fn unresolve_issue_returns_404_for_nonexistent_issue() {
	let app = TestApp::new().await;
	let org_id = app.fixtures.org_a.org.id.to_string();
	let project_id = create_test_project(&app, &org_id, "unresolve-404-test").await;

	let response = app
		.post(
			&format!(
				"/api/crash/projects/{}/issues/01938a6b-cdef-7000-8000-000000000000/unresolve",
				project_id
			),
			Some(&app.fixtures.org_a.member),
			json!({}),
		)
		.await;
	assert_eq!(
		response.status(),
		StatusCode::NOT_FOUND,
		"Unresolving nonexistent issue should return 404"
	);
}

// ============================================================================
// Ignore Issue Tests
// ============================================================================

#[tokio::test]
async fn ignore_issue_requires_auth() {
	let app = TestApp::new().await;
	let org_id = app.fixtures.org_a.org.id.to_string();
	let project_id = create_test_project(&app, &org_id, "ignore-auth-test").await;
	let issue_id = create_test_issue(&app, &project_id).await;

	let response = app
		.post(
			&format!(
				"/api/crash/projects/{}/issues/{}/ignore",
				project_id, issue_id
			),
			None,
			json!({}),
		)
		.await;
	assert_eq!(
		response.status(),
		StatusCode::UNAUTHORIZED,
		"Ignore issue without auth should return 401"
	);
}

#[tokio::test]
async fn ignore_issue_requires_org_membership() {
	let app = TestApp::new().await;
	let org_id = app.fixtures.org_a.org.id.to_string();
	let project_id = create_test_project(&app, &org_id, "ignore-membership-test").await;
	let issue_id = create_test_issue(&app, &project_id).await;

	// User from org_b trying to ignore issue in org_a's project
	let response = app
		.post(
			&format!(
				"/api/crash/projects/{}/issues/{}/ignore",
				project_id, issue_id
			),
			Some(&app.fixtures.org_b.member),
			json!({}),
		)
		.await;
	assert_eq!(
		response.status(),
		StatusCode::FORBIDDEN,
		"Non-member should not be able to ignore issue in another org's project"
	);
}

#[tokio::test]
async fn ignore_issue_succeeds_for_org_member() {
	let app = TestApp::new().await;
	let org_id = app.fixtures.org_a.org.id.to_string();
	let project_id = create_test_project(&app, &org_id, "ignore-success-test").await;
	let issue_id = create_test_issue(&app, &project_id).await;

	let response = app
		.post(
			&format!(
				"/api/crash/projects/{}/issues/{}/ignore",
				project_id, issue_id
			),
			Some(&app.fixtures.org_a.member),
			json!({}),
		)
		.await;
	assert_eq!(
		response.status(),
		StatusCode::OK,
		"Org member should be able to ignore issue"
	);

	let (_, body) = response.into_parts();
	let body_bytes = axum::body::to_bytes(body, usize::MAX).await.unwrap();
	let result: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
	assert_eq!(result["status"], "ignored");
}

#[tokio::test]
async fn ignore_issue_returns_404_for_nonexistent_issue() {
	let app = TestApp::new().await;
	let org_id = app.fixtures.org_a.org.id.to_string();
	let project_id = create_test_project(&app, &org_id, "ignore-404-test").await;

	let response = app
		.post(
			&format!(
				"/api/crash/projects/{}/issues/01938a6b-cdef-7000-8000-000000000000/ignore",
				project_id
			),
			Some(&app.fixtures.org_a.member),
			json!({}),
		)
		.await;
	assert_eq!(
		response.status(),
		StatusCode::NOT_FOUND,
		"Ignoring nonexistent issue should return 404"
	);
}

#[tokio::test]
async fn issue_lifecycle_full_workflow() {
	let app = TestApp::new().await;
	let org_id = app.fixtures.org_a.org.id.to_string();
	let project_id = create_test_project(&app, &org_id, "lifecycle-test").await;
	let issue_id = create_test_issue(&app, &project_id).await;

	// 1. Initially unresolved
	let response = app
		.get(
			&format!("/api/crash/projects/{}/issues/{}", project_id, issue_id),
			Some(&app.fixtures.org_a.member),
		)
		.await;
	let (_, body) = response.into_parts();
	let body_bytes = axum::body::to_bytes(body, usize::MAX).await.unwrap();
	let result: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
	assert_eq!(result["status"], "unresolved");

	// 2. Resolve the issue
	let response = app
		.post(
			&format!(
				"/api/crash/projects/{}/issues/{}/resolve",
				project_id, issue_id
			),
			Some(&app.fixtures.org_a.member),
			json!({}),
		)
		.await;
	assert_eq!(response.status(), StatusCode::OK);
	let (_, body) = response.into_parts();
	let body_bytes = axum::body::to_bytes(body, usize::MAX).await.unwrap();
	let result: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
	assert_eq!(result["status"], "resolved");

	// 3. Unresolve the issue
	let response = app
		.post(
			&format!(
				"/api/crash/projects/{}/issues/{}/unresolve",
				project_id, issue_id
			),
			Some(&app.fixtures.org_a.member),
			json!({}),
		)
		.await;
	assert_eq!(response.status(), StatusCode::OK);
	let (_, body) = response.into_parts();
	let body_bytes = axum::body::to_bytes(body, usize::MAX).await.unwrap();
	let result: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
	assert_eq!(result["status"], "unresolved");

	// 4. Ignore the issue
	let response = app
		.post(
			&format!(
				"/api/crash/projects/{}/issues/{}/ignore",
				project_id, issue_id
			),
			Some(&app.fixtures.org_a.member),
			json!({}),
		)
		.await;
	assert_eq!(response.status(), StatusCode::OK);
	let (_, body) = response.into_parts();
	let body_bytes = axum::body::to_bytes(body, usize::MAX).await.unwrap();
	let result: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
	assert_eq!(result["status"], "ignored");

	// 5. Unresolve (unignore) the issue
	let response = app
		.post(
			&format!(
				"/api/crash/projects/{}/issues/{}/unresolve",
				project_id, issue_id
			),
			Some(&app.fixtures.org_a.member),
			json!({}),
		)
		.await;
	assert_eq!(response.status(), StatusCode::OK);
	let (_, body) = response.into_parts();
	let body_bytes = axum::body::to_bytes(body, usize::MAX).await.unwrap();
	let result: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
	assert_eq!(result["status"], "unresolved");
}

// ============================================================================
// Assign Issue Tests
// ============================================================================

#[tokio::test]
async fn assign_issue_requires_auth() {
	let app = TestApp::new().await;
	let org_id = app.fixtures.org_a.org.id.to_string();
	let project_id = create_test_project(&app, &org_id, "assign-auth-test").await;
	let issue_id = create_test_issue(&app, &project_id).await;

	let response = app
		.post(
			&format!(
				"/api/crash/projects/{}/issues/{}/assign",
				project_id, issue_id
			),
			None,
			json!({"user_id": null}),
		)
		.await;
	assert_eq!(
		response.status(),
		StatusCode::UNAUTHORIZED,
		"Assign issue without auth should return 401"
	);
}

#[tokio::test]
async fn assign_issue_requires_org_membership() {
	let app = TestApp::new().await;
	let org_id = app.fixtures.org_a.org.id.to_string();
	let project_id = create_test_project(&app, &org_id, "assign-membership-test").await;
	let issue_id = create_test_issue(&app, &project_id).await;

	// User from org_b trying to assign issue in org_a's project
	let response = app
		.post(
			&format!(
				"/api/crash/projects/{}/issues/{}/assign",
				project_id, issue_id
			),
			Some(&app.fixtures.org_b.member),
			json!({"user_id": null}),
		)
		.await;
	assert_eq!(
		response.status(),
		StatusCode::FORBIDDEN,
		"Non-member should not be able to assign issue in another org's project"
	);
}

#[tokio::test]
async fn assign_issue_succeeds_for_org_member() {
	let app = TestApp::new().await;
	let org_id = app.fixtures.org_a.org.id.to_string();
	let project_id = create_test_project(&app, &org_id, "assign-success-test").await;
	let issue_id = create_test_issue(&app, &project_id).await;

	let user_id = app.fixtures.org_a.member.user.id.to_string();

	let response = app
		.post(
			&format!(
				"/api/crash/projects/{}/issues/{}/assign",
				project_id, issue_id
			),
			Some(&app.fixtures.org_a.member),
			json!({"user_id": user_id}),
		)
		.await;
	assert_eq!(
		response.status(),
		StatusCode::OK,
		"Org member should be able to assign issue"
	);

	let (_, body) = response.into_parts();
	let body_bytes = axum::body::to_bytes(body, usize::MAX).await.unwrap();
	let result: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
	assert_eq!(result["assigned_to"], user_id);
}

#[tokio::test]
async fn assign_issue_can_unassign() {
	let app = TestApp::new().await;
	let org_id = app.fixtures.org_a.org.id.to_string();
	let project_id = create_test_project(&app, &org_id, "unassign-test").await;
	let issue_id = create_test_issue(&app, &project_id).await;

	let user_id = app.fixtures.org_a.member.user.id.to_string();

	// First assign
	let _ = app
		.post(
			&format!(
				"/api/crash/projects/{}/issues/{}/assign",
				project_id, issue_id
			),
			Some(&app.fixtures.org_a.member),
			json!({"user_id": user_id}),
		)
		.await;

	// Then unassign by passing null
	let response = app
		.post(
			&format!(
				"/api/crash/projects/{}/issues/{}/assign",
				project_id, issue_id
			),
			Some(&app.fixtures.org_a.member),
			json!({"user_id": null}),
		)
		.await;
	assert_eq!(
		response.status(),
		StatusCode::OK,
		"Org member should be able to unassign issue"
	);

	let (_, body) = response.into_parts();
	let body_bytes = axum::body::to_bytes(body, usize::MAX).await.unwrap();
	let result: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
	assert!(result["assigned_to"].is_null());
}

#[tokio::test]
async fn assign_issue_returns_404_for_nonexistent_issue() {
	let app = TestApp::new().await;
	let org_id = app.fixtures.org_a.org.id.to_string();
	let project_id = create_test_project(&app, &org_id, "assign-404-test").await;

	let response = app
		.post(
			&format!(
				"/api/crash/projects/{}/issues/01938a6b-cdef-7000-8000-000000000000/assign",
				project_id
			),
			Some(&app.fixtures.org_a.member),
			json!({"user_id": null}),
		)
		.await;
	assert_eq!(
		response.status(),
		StatusCode::NOT_FOUND,
		"Assigning nonexistent issue should return 404"
	);
}

// ============================================================================
// Delete Issue Tests
// ============================================================================

#[tokio::test]
async fn delete_issue_requires_auth() {
	let app = TestApp::new().await;
	let org_id = app.fixtures.org_a.org.id.to_string();
	let project_id = create_test_project(&app, &org_id, "delete-issue-auth-test").await;
	let issue_id = create_test_issue(&app, &project_id).await;

	let response = app
		.delete(
			&format!(
				"/api/crash/projects/{}/issues/{}",
				project_id, issue_id
			),
			None,
		)
		.await;
	assert_eq!(
		response.status(),
		StatusCode::UNAUTHORIZED,
		"Delete issue without auth should return 401"
	);
}

#[tokio::test]
async fn delete_issue_requires_org_membership() {
	let app = TestApp::new().await;
	let org_id = app.fixtures.org_a.org.id.to_string();
	let project_id = create_test_project(&app, &org_id, "delete-issue-membership-test").await;
	let issue_id = create_test_issue(&app, &project_id).await;

	// User from org_b trying to delete issue in org_a's project
	let response = app
		.delete(
			&format!(
				"/api/crash/projects/{}/issues/{}",
				project_id, issue_id
			),
			Some(&app.fixtures.org_b.member),
		)
		.await;
	assert_eq!(
		response.status(),
		StatusCode::FORBIDDEN,
		"Non-member should not be able to delete issue in another org's project"
	);
}

#[tokio::test]
async fn delete_issue_succeeds_for_org_member() {
	let app = TestApp::new().await;
	let org_id = app.fixtures.org_a.org.id.to_string();
	let project_id = create_test_project(&app, &org_id, "delete-issue-success-test").await;
	let issue_id = create_test_issue(&app, &project_id).await;

	let response = app
		.delete(
			&format!(
				"/api/crash/projects/{}/issues/{}",
				project_id, issue_id
			),
			Some(&app.fixtures.org_a.member),
		)
		.await;
	assert_eq!(
		response.status(),
		StatusCode::NO_CONTENT,
		"Org member should be able to delete issue"
	);

	// Verify issue is gone
	let response = app
		.get(
			&format!(
				"/api/crash/projects/{}/issues/{}",
				project_id, issue_id
			),
			Some(&app.fixtures.org_a.member),
		)
		.await;
	assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn delete_issue_returns_404_for_nonexistent_issue() {
	let app = TestApp::new().await;
	let org_id = app.fixtures.org_a.org.id.to_string();
	let project_id = create_test_project(&app, &org_id, "delete-issue-404-test").await;

	let response = app
		.delete(
			&format!(
				"/api/crash/projects/{}/issues/01938a6b-cdef-7000-8000-000000000000",
				project_id
			),
			Some(&app.fixtures.org_a.member),
		)
		.await;
	assert_eq!(
		response.status(),
		StatusCode::NOT_FOUND,
		"Deleting nonexistent issue should return 404"
	);
}

// ============================================================================
// Get Project Tests
// ============================================================================

#[tokio::test]
async fn get_project_requires_auth() {
	let app = TestApp::new().await;
	let org_id = app.fixtures.org_a.org.id.to_string();
	let project_id = create_test_project(&app, &org_id, "get-project-auth-test").await;

	let response = app
		.get(&format!("/api/crash/projects/{}", project_id), None)
		.await;
	assert_eq!(
		response.status(),
		StatusCode::UNAUTHORIZED,
		"Get project without auth should return 401"
	);
}

#[tokio::test]
async fn get_project_requires_org_membership() {
	let app = TestApp::new().await;
	let org_id = app.fixtures.org_a.org.id.to_string();
	let project_id = create_test_project(&app, &org_id, "get-project-membership-test").await;

	// User from org_b trying to get project in org_a
	let response = app
		.get(
			&format!("/api/crash/projects/{}", project_id),
			Some(&app.fixtures.org_b.member),
		)
		.await;
	assert_eq!(
		response.status(),
		StatusCode::FORBIDDEN,
		"Non-member should not be able to get project in another org"
	);
}

#[tokio::test]
async fn get_project_succeeds_for_org_member() {
	let app = TestApp::new().await;
	let org_id = app.fixtures.org_a.org.id.to_string();
	let project_id = create_test_project(&app, &org_id, "get-project-success-test").await;

	let response = app
		.get(
			&format!("/api/crash/projects/{}", project_id),
			Some(&app.fixtures.org_a.member),
		)
		.await;
	assert_eq!(
		response.status(),
		StatusCode::OK,
		"Org member should be able to get project"
	);

	let (_, body) = response.into_parts();
	let body_bytes = axum::body::to_bytes(body, usize::MAX).await.unwrap();
	let result: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
	assert_eq!(result["id"], project_id);
	assert_eq!(result["slug"], "get-project-success-test");
}

#[tokio::test]
async fn get_project_returns_404_for_nonexistent_project() {
	let app = TestApp::new().await;

	let response = app
		.get(
			"/api/crash/projects/01938a6b-cdef-7000-8000-000000000000",
			Some(&app.fixtures.org_a.member),
		)
		.await;
	assert_eq!(
		response.status(),
		StatusCode::NOT_FOUND,
		"Getting nonexistent project should return 404"
	);
}

// ============================================================================
// Update Project Tests
// ============================================================================

#[tokio::test]
async fn update_project_requires_auth() {
	let app = TestApp::new().await;
	let org_id = app.fixtures.org_a.org.id.to_string();
	let project_id = create_test_project(&app, &org_id, "update-project-auth-test").await;

	let response = app
		.patch(
			&format!("/api/crash/projects/{}", project_id),
			None,
			json!({"name": "Updated Name"}),
		)
		.await;
	assert_eq!(
		response.status(),
		StatusCode::UNAUTHORIZED,
		"Update project without auth should return 401"
	);
}

#[tokio::test]
async fn update_project_requires_org_membership() {
	let app = TestApp::new().await;
	let org_id = app.fixtures.org_a.org.id.to_string();
	let project_id = create_test_project(&app, &org_id, "update-project-membership-test").await;

	// User from org_b trying to update project in org_a
	let response = app
		.patch(
			&format!("/api/crash/projects/{}", project_id),
			Some(&app.fixtures.org_b.member),
			json!({"name": "Updated Name"}),
		)
		.await;
	assert_eq!(
		response.status(),
		StatusCode::FORBIDDEN,
		"Non-member should not be able to update project in another org"
	);
}

#[tokio::test]
async fn update_project_succeeds_for_org_member() {
	let app = TestApp::new().await;
	let org_id = app.fixtures.org_a.org.id.to_string();
	let project_id = create_test_project(&app, &org_id, "update-project-success-test").await;

	let response = app
		.patch(
			&format!("/api/crash/projects/{}", project_id),
			Some(&app.fixtures.org_a.member),
			json!({"name": "Updated Project Name"}),
		)
		.await;
	assert_eq!(
		response.status(),
		StatusCode::OK,
		"Org member should be able to update project"
	);

	let (_, body) = response.into_parts();
	let body_bytes = axum::body::to_bytes(body, usize::MAX).await.unwrap();
	let result: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
	assert_eq!(result["name"], "Updated Project Name");
}

#[tokio::test]
async fn update_project_returns_404_for_nonexistent_project() {
	let app = TestApp::new().await;

	let response = app
		.patch(
			"/api/crash/projects/01938a6b-cdef-7000-8000-000000000000",
			Some(&app.fixtures.org_a.member),
			json!({"name": "Updated Name"}),
		)
		.await;
	assert_eq!(
		response.status(),
		StatusCode::NOT_FOUND,
		"Updating nonexistent project should return 404"
	);
}

#[tokio::test]
async fn update_project_rejects_empty_name() {
	let app = TestApp::new().await;
	let org_id = app.fixtures.org_a.org.id.to_string();
	let project_id = create_test_project(&app, &org_id, "update-project-empty-name-test").await;

	let response = app
		.patch(
			&format!("/api/crash/projects/{}", project_id),
			Some(&app.fixtures.org_a.member),
			json!({"name": ""}),
		)
		.await;
	assert_eq!(
		response.status(),
		StatusCode::BAD_REQUEST,
		"Update project with empty name should return 400"
	);
}

// ============================================================================
// Delete Project Tests
// ============================================================================

#[tokio::test]
async fn delete_project_requires_auth() {
	let app = TestApp::new().await;
	let org_id = app.fixtures.org_a.org.id.to_string();
	let project_id = create_test_project(&app, &org_id, "delete-project-auth-test").await;

	let response = app
		.delete(&format!("/api/crash/projects/{}", project_id), None)
		.await;
	assert_eq!(
		response.status(),
		StatusCode::UNAUTHORIZED,
		"Delete project without auth should return 401"
	);
}

#[tokio::test]
async fn delete_project_requires_org_membership() {
	let app = TestApp::new().await;
	let org_id = app.fixtures.org_a.org.id.to_string();
	let project_id = create_test_project(&app, &org_id, "delete-project-membership-test").await;

	// User from org_b trying to delete project in org_a
	let response = app
		.delete(
			&format!("/api/crash/projects/{}", project_id),
			Some(&app.fixtures.org_b.member),
		)
		.await;
	assert_eq!(
		response.status(),
		StatusCode::FORBIDDEN,
		"Non-member should not be able to delete project in another org"
	);
}

#[tokio::test]
async fn delete_project_succeeds_for_org_member() {
	let app = TestApp::new().await;
	let org_id = app.fixtures.org_a.org.id.to_string();
	let project_id = create_test_project(&app, &org_id, "delete-project-success-test").await;

	let response = app
		.delete(
			&format!("/api/crash/projects/{}", project_id),
			Some(&app.fixtures.org_a.member),
		)
		.await;
	assert_eq!(
		response.status(),
		StatusCode::NO_CONTENT,
		"Org member should be able to delete project"
	);

	// Verify project is gone
	let response = app
		.get(
			&format!("/api/crash/projects/{}", project_id),
			Some(&app.fixtures.org_a.member),
		)
		.await;
	assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn delete_project_returns_404_for_nonexistent_project() {
	let app = TestApp::new().await;

	let response = app
		.delete(
			"/api/crash/projects/01938a6b-cdef-7000-8000-000000000000",
			Some(&app.fixtures.org_a.member),
		)
		.await;
	assert_eq!(
		response.status(),
		StatusCode::NOT_FOUND,
		"Deleting nonexistent project should return 404"
	);
}
