// Copyright (c) 2025 Geoffrey Huntley <ghuntley@ghuntley.com>. All rights reserved.
// SPDX-License-Identifier: Proprietary

use async_trait::async_trait;
use axum::{
	body::Body,
	http::{header::HeaderName, header::HeaderValue, Method, Request, StatusCode},
	response::Response,
	Router,
};
use chrono::Utc;
use loom_common_thread::{
	AgentStateKind, AgentStateSnapshot, ConversationSnapshot, Thread, ThreadId, ThreadMetadata,
	ThreadVisibility,
};
use loom_server_auth::{
	org::{OrgVisibility, Organization},
	session::{generate_session_token, Session},
	team::Team,
	types::{OrgId, OrgRole, SessionType, TeamRole, UserId},
	User,
};
use loom_server_k8s::{
	AttachedProcess, K8sClient, K8sError, LogOptions, LogStream, Namespace, Pod,
};
use loom_server_weaver::{Provisioner, WeaverConfig};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tempfile::TempDir;
use tokio::io::duplex;
use tower::ServiceExt;

use loom_server::{
	api::{create_app_state, create_router, AppState},
	db::ThreadRepository,
	ServerConfig,
};

pub struct MockK8sClient {
	pods: Mutex<HashMap<String, Pod>>,
}

impl MockK8sClient {
	pub fn new() -> Self {
		Self {
			pods: Mutex::new(HashMap::new()),
		}
	}
}

#[async_trait]
impl K8sClient for MockK8sClient {
	async fn create_pod(&self, _namespace: &str, mut pod: Pod) -> Result<Pod, K8sError> {
		let name = pod.metadata.name.clone().unwrap_or_default();
		pod.status = Some(loom_server_k8s::PodStatus {
			phase: Some("Running".to_string()),
			..Default::default()
		});
		let mut pods = self.pods.lock().unwrap();
		pods.insert(name.clone(), pod.clone());
		Ok(pod)
	}

	async fn delete_pod(
		&self,
		name: &str,
		_namespace: &str,
		_grace_period_seconds: u32,
	) -> Result<(), K8sError> {
		let mut pods = self.pods.lock().unwrap();
		pods.remove(name);
		Ok(())
	}

	async fn list_pods(&self, _namespace: &str, _label_selector: &str) -> Result<Vec<Pod>, K8sError> {
		let pods = self.pods.lock().unwrap();
		Ok(pods.values().cloned().collect())
	}

	async fn get_pod(&self, name: &str, _namespace: &str) -> Result<Pod, K8sError> {
		let pods = self.pods.lock().unwrap();
		pods
			.get(name)
			.cloned()
			.ok_or_else(|| K8sError::PodNotFound {
				name: name.to_string(),
			})
	}

	async fn get_namespace(&self, _name: &str) -> Result<Namespace, K8sError> {
		Ok(Namespace::default())
	}

	async fn stream_logs(
		&self,
		_name: &str,
		_namespace: &str,
		_container: &str,
		_opts: LogOptions,
	) -> Result<LogStream, K8sError> {
		Ok(Box::pin(futures::stream::empty()))
	}

	async fn exec_attach(
		&self,
		_name: &str,
		_namespace: &str,
		_container: &str,
	) -> Result<AttachedProcess, K8sError> {
		let (stdin, _) = duplex(1024);
		let (_, stdout) = duplex(1024);
		Ok(AttachedProcess {
			stdin: Box::pin(stdin),
			stdout: Box::pin(stdout),
		})
	}

	async fn validate_token(
		&self,
		_token: &str,
		_audiences: &[&str],
	) -> Result<loom_server_k8s::TokenReviewResult, K8sError> {
		Ok(loom_server_k8s::TokenReviewResult::authenticated(
			"test-user".to_string(),
			vec!["system:authenticated".to_string()],
			std::collections::HashMap::new(),
			vec![],
		))
	}
}

pub fn create_mock_provisioner() -> Arc<Provisioner> {
	let client = Arc::new(MockK8sClient::new());
	let config = WeaverConfig {
		namespace: "test-namespace".to_string(),
		max_concurrent: 100,
		ready_timeout_secs: 1,
		default_ttl_hours: 24,
		max_ttl_hours: 48,
		cleanup_interval_secs: 3600,
		webhooks: vec![],
		image_pull_secrets: vec![],
		audit_enabled: false,
		audit_image: String::new(),
		audit_batch_interval_ms: 100,
		audit_buffer_max_bytes: 256 * 1024 * 1024,
		server_url: String::new(),
		secrets_server_url: None,
		secrets_allow_insecure: false,
		wg_enabled: false,
	};
	Arc::new(Provisioner::new(client, config))
}

fn hash_token(token: &str) -> String {
	let mut hasher = Sha256::new();
	hasher.update(token.as_bytes());
	hex::encode(hasher.finalize())
}

#[derive(Clone)]
pub struct TestUser {
	pub user: User,
	pub session_token: String,
}

impl TestUser {
	pub fn auth_header(&self) -> (HeaderName, HeaderValue) {
		(
			HeaderName::from_static("cookie"),
			HeaderValue::from_str(&format!("loom_session={}", self.session_token)).unwrap(),
		)
	}
}

#[derive(Clone)]
pub struct OrgFixture {
	pub org: Organization,
	pub owner: TestUser,
	pub member: TestUser,
	pub team: Team,
	pub thread: Thread,
}

#[derive(Clone)]
pub struct Fixtures {
	pub org_a: OrgFixture,
	pub org_b: OrgFixture,
	pub admin: TestUser,
}

pub struct TestApp {
	pub router: Router,
	pub fixtures: Fixtures,
	pub state: AppState,
	_temp_dir: TempDir,
}

impl TestApp {
	pub async fn new() -> Self {
		Self::new_internal(false).await
	}

	pub async fn with_provisioner() -> Self {
		Self::new_internal(true).await
	}

	async fn new_internal(with_provisioner: bool) -> Self {
		let temp_dir = tempfile::tempdir().unwrap();
		// Set LOOM_SERVER_DATA_DIR for repo disk storage
		std::env::set_var("LOOM_SERVER_DATA_DIR", temp_dir.path());
		let db_path = temp_dir.path().join("test_authz.db");
		let db_url = format!("sqlite:{}?mode=rwc", db_path.display());
		let pool = loom_server::db::create_pool(&db_url).await.unwrap();
		loom_server::db::run_migrations(&pool).await.unwrap();
		let repo = Arc::new(ThreadRepository::new(pool.clone()));
		let config = ServerConfig::default();
		let mut state = create_app_state(pool, repo.clone(), &config, None).await;

		state.auth_config.dev_mode = false;

		if with_provisioner {
			state.provisioner = Some(create_mock_provisioner());
		}

		let fixtures = create_fixtures(&state, &repo).await;

		let router = create_router(state.clone());

		Self {
			router,
			fixtures,
			state,
			_temp_dir: temp_dir,
		}
	}

	pub async fn get(&self, path: &str, user: Option<&TestUser>) -> Response<Body> {
		self
			.request(Method::GET, path, user, Option::<()>::None)
			.await
	}

	pub async fn post(
		&self,
		path: &str,
		user: Option<&TestUser>,
		body: impl Serialize,
	) -> Response<Body> {
		self.request(Method::POST, path, user, Some(body)).await
	}

	pub async fn put(
		&self,
		path: &str,
		user: Option<&TestUser>,
		body: impl Serialize,
	) -> Response<Body> {
		self.request(Method::PUT, path, user, Some(body)).await
	}

	pub async fn patch(
		&self,
		path: &str,
		user: Option<&TestUser>,
		body: impl Serialize,
	) -> Response<Body> {
		self.request(Method::PATCH, path, user, Some(body)).await
	}

	pub async fn delete(&self, path: &str, user: Option<&TestUser>) -> Response<Body> {
		self
			.request(Method::DELETE, path, user, Option::<()>::None)
			.await
	}

	/// POST with a custom header (e.g., for API key auth)
	pub async fn post_with_header(
		&self,
		path: &str,
		header_name: &str,
		header_value: &str,
		body: impl Serialize,
	) -> Response<Body> {
		let builder = Request::builder()
			.method(Method::POST)
			.uri(path)
			.header("content-type", "application/json")
			.header(header_name, header_value);

		let request_body = Body::from(serde_json::to_string(&body).unwrap());
		let request = builder.body(request_body).unwrap();

		self.router.clone().oneshot(request).await.unwrap()
	}

	async fn request<T: Serialize>(
		&self,
		method: Method,
		path: &str,
		user: Option<&TestUser>,
		body: Option<T>,
	) -> Response<Body> {
		let mut builder = Request::builder().method(method).uri(path);

		if let Some(test_user) = user {
			let (name, value) = test_user.auth_header();
			builder = builder.header(name, value);
		}

		let request_body = match body {
			Some(b) => {
				builder = builder.header("content-type", "application/json");
				Body::from(serde_json::to_string(&b).unwrap())
			}
			None => Body::empty(),
		};

		let request = builder.body(request_body).unwrap();

		self.router.clone().oneshot(request).await.unwrap()
	}
}

pub struct AuthzCase {
	pub name: &'static str,
	pub method: Method,
	pub path: String,
	pub user: Option<TestUser>,
	pub body: Option<serde_json::Value>,
	pub expected_status: StatusCode,
}

pub async fn run_authz_cases(app: &TestApp, cases: &[AuthzCase]) {
	for case in cases {
		let response = match (&case.method, &case.body) {
			(m, Some(body)) if *m == Method::POST => {
				app.post(&case.path, case.user.as_ref(), body.clone()).await
			}
			(m, Some(body)) if *m == Method::PUT => {
				app.put(&case.path, case.user.as_ref(), body.clone()).await
			}
			(m, Some(body)) if *m == Method::PATCH => {
				app
					.patch(&case.path, case.user.as_ref(), body.clone())
					.await
			}
			(m, _) if *m == Method::DELETE => app.delete(&case.path, case.user.as_ref()).await,
			_ => app.get(&case.path, case.user.as_ref()).await,
		};

		if response.status() != case.expected_status {
			// Read the response body for debugging
			let (parts, body) = response.into_parts();
			let body_bytes = axum::body::to_bytes(body, usize::MAX).await.unwrap();
			let body_str = String::from_utf8_lossy(&body_bytes);
			panic!(
				"Case '{}': {} {} - expected {}, got {}\nResponse body: {}",
				case.name, case.method, case.path, case.expected_status, parts.status, body_str
			);
		}
	}
}

async fn create_fixtures(state: &AppState, repo: &Arc<ThreadRepository>) -> Fixtures {
	let admin = create_test_user_internal(state, "admin@test.com", "Admin User", true).await;
	let org_a = create_org_fixture(state, repo, "org-a", "Organization A").await;
	let org_b = create_org_fixture(state, repo, "org-b", "Organization B").await;

	Fixtures {
		org_a,
		org_b,
		admin,
	}
}

async fn create_org_fixture(
	state: &AppState,
	repo: &Arc<ThreadRepository>,
	slug: &str,
	name: &str,
) -> OrgFixture {
	let now = Utc::now();
	let org = Organization {
		id: OrgId::generate(),
		name: name.to_string(),
		slug: slug.to_string(),
		visibility: OrgVisibility::Public,
		is_personal: false,
		created_at: now,
		updated_at: now,
		deleted_at: None,
	};

	state.org_repo.create_org(&org).await.unwrap();

	let owner =
		create_test_user_internal(state, &format!("owner@{slug}.test"), "Owner User", false).await;
	let member =
		create_test_user_internal(state, &format!("member@{slug}.test"), "Member User", false).await;

	state
		.org_repo
		.add_member(&org.id, &owner.user.id, OrgRole::Owner)
		.await
		.unwrap();

	state
		.org_repo
		.add_member(&org.id, &member.user.id, OrgRole::Member)
		.await
		.unwrap();

	let team = Team::new(org.id, format!("{name} Team"), format!("{slug}-team"));
	state.team_repo.create_team(&team).await.unwrap();

	state
		.team_repo
		.add_member(&team.id, &owner.user.id, TeamRole::Maintainer)
		.await
		.unwrap();

	state
		.team_repo
		.add_member(&team.id, &member.user.id, TeamRole::Member)
		.await
		.unwrap();

	let thread = create_test_thread();
	repo.upsert(&thread, None).await.unwrap();
	repo
		.set_owner_user_id(thread.id.as_str(), &owner.user.id.to_string())
		.await
		.unwrap();

	OrgFixture {
		org,
		owner,
		member,
		team,
		thread,
	}
}

async fn create_test_user_internal(
	state: &AppState,
	email: &str,
	display_name: &str,
	is_admin: bool,
) -> TestUser {
	let now = Utc::now();
	let user = User {
		id: UserId::generate(),
		display_name: display_name.to_string(),
		username: None,
		primary_email: Some(email.to_string()),
		avatar_url: None,
		email_visible: true,
		is_system_admin: is_admin,
		is_support: is_admin,
		is_auditor: false,
		created_at: now,
		updated_at: now,
		deleted_at: None,
		locale: None,
	};

	state.user_repo.create_user(&user).await.unwrap();

	let session_token = generate_session_token();
	let token_hash = hash_token(&session_token);

	let session = Session::new(user.id, SessionType::Cli);
	state
		.session_repo
		.create_session(&session, &token_hash)
		.await
		.unwrap();

	TestUser {
		user,
		session_token,
	}
}

fn create_test_thread() -> Thread {
	Thread {
		id: ThreadId::new(),
		version: 1,
		created_at: Utc::now().to_rfc3339(),
		updated_at: Utc::now().to_rfc3339(),
		last_activity_at: Utc::now().to_rfc3339(),
		workspace_root: Some("/test/workspace".to_string()),
		cwd: Some("/test/workspace".to_string()),
		loom_version: Some("0.1.0".to_string()),
		provider: Some("anthropic".to_string()),
		model: Some("claude-sonnet-4-20250514".to_string()),
		git_branch: Some("main".to_string()),
		git_remote_url: Some("github.com/test/repo".to_string()),
		git_initial_branch: Some("main".to_string()),
		git_initial_commit_sha: Some("abc123def456".to_string()),
		git_current_commit_sha: Some("xyz789012345".to_string()),
		git_start_dirty: Some(false),
		git_end_dirty: Some(false),
		git_commits: vec!["abc123def456".to_string(), "xyz789012345".to_string()],
		conversation: ConversationSnapshot { messages: vec![] },
		agent_state: AgentStateSnapshot {
			kind: AgentStateKind::WaitingForUserInput,
			retries: 0,
			last_error: None,
			pending_tool_calls: vec![],
		},
		metadata: ThreadMetadata::default(),
		visibility: ThreadVisibility::Private,
		is_private: false,
		is_shared_with_support: false,
	}
}
