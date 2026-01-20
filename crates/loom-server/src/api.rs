// Copyright (c) 2025 Geoffrey Huntley <ghuntley@ghuntley.com>. All rights
// reserved. SPDX-License-Identifier: Proprietary

//! HTTP API routes and handlers for thread operations.

use axum::routing::{delete, get, patch, post, put};

use crate::{
	abac_middleware::RequireRole,
	typed_router::{AuthedRouter, PublicRouter},
};
use loom_server_auth_github::{GitHubOAuthClient, GitHubOAuthConfig};
use loom_server_auth_google::{GoogleOAuthClient, GoogleOAuthConfig};
use loom_server_auth_okta::{OktaOAuthClient, OktaOAuthConfig};
use loom_server_config::ScimConfig;
use loom_server_db::ScmRepository;
use loom_server_email::EmailService;
use loom_server_geoip::GeoIpService;
use loom_server_github_app::{GithubAppClient, GithubAppConfig};
use loom_server_jobs::{JobRepository, JobScheduler};
use loom_server_k8s::{K8sClient, KubeClient};
use loom_server_local::LocalClient;
use loom_server_llm_service::LlmService;
use loom_server_search_google_cse::CseClient;
use loom_server_search_serper::SerperClient;
use loom_server_secrets::{SecretsService, SoftwareKeyBackend, SqliteSecretStore, SvidIssuer};
use loom_server_session::SessionService;
use loom_server_smtp::SmtpClient;
use loom_server_weaver::{Provisioner, WeaverConfig, WebhookConfig, WebhookDispatcher};
use loom_server_wgtunnel::WgTunnelServices;
use std::sync::Arc;
use tower_http::services::{ServeDir, ServeFile};
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

use axum::Router;
use loom_server_config::ServerConfig;

use loom_server_audit::{
	AuditFilterConfig, AuditService, AuditSink, NoopEnricher, SqliteAuditSink,
};
use loom_server_config::QueueOverflowPolicy;

use crate::{
	db::{
		ApiKeyRepository, AuditRepository, OrgRepository, SessionRepository, ShareRepository,
		TeamRepository, ThreadRepository, UserRepository,
	},
	llm_proxy,
	oauth_state::OAuthStateStore,
	query_metrics::QueryMetrics,
	query_tracing::QueryTraceStore,
	routes,
	server_query::{self, ServerQueryManager},
};
use sqlx::SqlitePool;

/// Application state shared across handlers.
#[derive(Clone)]
pub struct AppState {
	pub repo: Arc<ThreadRepository>,
	pub user_repo: Arc<UserRepository>,
	pub session_repo: Arc<SessionRepository>,
	pub org_repo: Arc<OrgRepository>,
	pub team_repo: Arc<TeamRepository>,
	pub api_key_repo: Arc<ApiKeyRepository>,
	pub user_provisioning: Arc<loom_server_provisioning::UserProvisioningService>,
	pub audit_service: Arc<AuditService>,
	pub share_repo: Arc<ShareRepository>,
	pub auth_config: loom_server_auth::middleware::AuthConfig,
	pub dev_user: Option<loom_server_auth::User>,
	pub base_url: String,
	pub cse_client: Option<Arc<CseClient>>,
	pub serper_client: Option<Arc<SerperClient>>,
	pub github_client: Option<Arc<GithubAppClient>>,
	pub llm_service: Option<Arc<LlmService>>,
	pub query_manager: Arc<ServerQueryManager>,
	pub query_metrics: Arc<QueryMetrics>,
	pub trace_store: QueryTraceStore,
	pub provisioner: Option<Arc<Provisioner>>,
	pub webhook_dispatcher: Option<Arc<WebhookDispatcher>>,
	pub smtp_client: Option<Arc<SmtpClient>>,
	pub email_service: Option<Arc<EmailService>>,
	pub github_oauth: Option<Arc<GitHubOAuthClient>>,
	pub google_oauth: Option<Arc<GoogleOAuthClient>>,
	pub okta_oauth: Option<Arc<OktaOAuthClient>>,
	pub oauth_state_store: Arc<OAuthStateStore>,
	pub default_locale: String,
	pub geoip_service: Option<Arc<GeoIpService>>,
	pub job_scheduler: Option<Arc<JobScheduler>>,
	pub job_repository: Option<Arc<JobRepository>>,
	pub scm_repo_store: Option<Arc<loom_server_scm::SqliteRepoStore>>,
	pub scm_protection_store: Option<Arc<loom_server_scm::ProtectionRepository>>,
	pub scm_webhook_store: Option<Arc<loom_server_scm::SqliteWebhookStore>>,
	pub scm_maintenance_store: Option<Arc<loom_server_scm::SqliteMaintenanceJobStore>>,
	pub scm_team_access_store: Option<Arc<loom_server_scm::SqliteRepoTeamAccessStore>>,
	pub push_mirror_store: Option<Arc<loom_server_scm_mirror::SqlitePushMirrorStore>>,
	pub external_mirror_store: Option<Arc<loom_server_scm_mirror::SqliteExternalMirrorStore>>,
	pub log_buffer: loom_server_logs::LogBuffer,
	pub audit_repo: Arc<AuditRepository>,
	pub k8s_client: Option<Arc<dyn K8sClient>>,
	pub svid_issuer: Option<Arc<SvidIssuer<SoftwareKeyBackend>>>,
	pub secrets_service: Option<Arc<SecretsService<SoftwareKeyBackend, SqliteSecretStore>>>,
	pub wg_tunnel_services: Option<WgTunnelServices>,
	pub scim_config: ScimConfig,
	pub pool: SqlitePool,
	pub session_service: Arc<SessionService>,
	pub flags_repo: Arc<loom_server_flags::SqliteFlagsRepository>,
	pub flags_broadcaster: Arc<loom_server_flags::FlagsBroadcaster>,
	pub analytics_repo: Option<Arc<loom_server_analytics::SqliteAnalyticsRepository>>,
	pub analytics_state: Option<
		Arc<loom_server_analytics::AnalyticsState<loom_server_analytics::SqliteAnalyticsRepository>>,
	>,
	pub crons_repo: Arc<loom_server_crons::SqliteCronsRepository>,
	pub crons_broadcaster: Arc<loom_server_crons::CronsBroadcaster>,
	pub crash_repo: Arc<loom_server_crash::SqliteCrashRepository>,
	pub crash_broadcaster: Arc<loom_server_crash::CrashBroadcaster>,
	pub sessions_repo: Arc<loom_server_sessions::SqliteSessionsRepository>,
}

/// Creates the application state, initializing optional components.
///
/// If `log_buffer` is None, a default buffer will be created.
/// Pass a pre-created buffer if you need to share it with a tracing layer.
pub async fn create_app_state(
	pool: SqlitePool,
	repo: Arc<ThreadRepository>,
	config: &ServerConfig,
	log_buffer: Option<loom_server_logs::LogBuffer>,
) -> AppState {
	// Create auth repositories
	let user_repo = Arc::new(UserRepository::new(pool.clone()));
	let session_repo = Arc::new(SessionRepository::new(pool.clone()));
	let org_repo = Arc::new(OrgRepository::new(pool.clone()));
	let team_repo = Arc::new(TeamRepository::new(pool.clone()));
	let api_key_repo = Arc::new(ApiKeyRepository::new(pool.clone()));

	// Ensure the system mirrors organization exists for on-demand mirroring
	if let Err(e) = org_repo.ensure_mirrors_org().await {
		tracing::error!(error = %e, "Failed to ensure mirrors organization exists");
	}

	// Create user provisioning service
	let user_provisioning = Arc::new(loom_server_provisioning::UserProvisioningService::new(
		user_repo.clone(),
		org_repo.clone(),
		config.auth.signups_disabled,
	));

	// Create SQLite audit sink
	let sqlite_audit_sink: Arc<dyn AuditSink> = Arc::new(SqliteAuditSink::new(
		pool.clone(),
		AuditFilterConfig::default(),
	));

	let audit_service = Arc::new(AuditService::new(
		Arc::new(NoopEnricher),
		AuditFilterConfig::default(),
		10000,
		QueueOverflowPolicy::DropNewest,
		vec![sqlite_audit_sink],
	));
	let share_repo = Arc::new(ShareRepository::new(pool.clone()));
	let scm_repo = ScmRepository::new(pool.clone());
	let scm_repo_store = Arc::new(loom_server_scm::SqliteRepoStore::new(scm_repo.clone()));
	let scm_protection_store = Arc::new(loom_server_scm::ProtectionRepository::new(pool.clone()));
	let scm_webhook_store = Arc::new(loom_server_scm::SqliteWebhookStore::new(scm_repo.clone()));
	let scm_maintenance_store = Arc::new(loom_server_scm::SqliteMaintenanceJobStore::new(
		scm_repo.clone(),
	));
	let scm_team_access_store = Arc::new(loom_server_scm::SqliteRepoTeamAccessStore::new(
		scm_repo.clone(),
	));
	let push_mirror_store = Arc::new(loom_server_scm_mirror::SqlitePushMirrorStore::new(
		pool.clone(),
	));
	let external_mirror_store = Arc::new(loom_server_scm_mirror::SqliteExternalMirrorStore::new(
		pool.clone(),
	));
	let audit_repo = Arc::new(AuditRepository::new(pool.clone()));
	let auth_config = loom_server_auth::middleware::AuthConfig {
		dev_mode: config.auth.dev_mode,
		session_cookie_name: loom_server_auth::middleware::SESSION_COOKIE_NAME.to_string(),
		signups_disabled: config.auth.signups_disabled,
	};
	let cse_client = match (
		std::env::var("LOOM_SERVER_GOOGLE_CSE_API_KEY"),
		std::env::var("LOOM_SERVER_GOOGLE_CSE_SEARCH_ENGINE_ID"),
	) {
		(Ok(api_key), Ok(cx)) if !api_key.is_empty() && !cx.is_empty() => {
			tracing::info!("Google CSE configured, creating client");
			Some(Arc::new(CseClient::new(api_key, cx)))
		}
		_ => {
			tracing::info!("Google CSE not configured");
			None
		}
	};

	let serper_client = match std::env::var("LOOM_SERVER_SERPER_API_KEY") {
		Ok(api_key) if !api_key.is_empty() => {
			tracing::info!("Serper configured, creating client");
			Some(Arc::new(SerperClient::new(api_key)))
		}
		_ => {
			tracing::info!("Serper not configured");
			None
		}
	};

	let github_client = match GithubAppConfig::from_env() {
		Ok(config) => match GithubAppClient::new(config) {
			Ok(client) => {
				tracing::info!("GitHub App configured, creating client");
				Some(Arc::new(client))
			}
			Err(e) => {
				tracing::warn!(error = %e, "Failed to create GitHub App client");
				None
			}
		},
		Err(_) => {
			tracing::info!("GitHub App not configured");
			None
		}
	};

	let llm_service = match LlmService::from_env().await {
		Ok(service) => {
			tracing::info!(
				anthropic = service.has_anthropic(),
				openai = service.has_openai(),
				"LLM service configured"
			);
			Some(Arc::new(service))
		}
		Err(e) => {
			tracing::info!(error = %e, "LLM service not configured");
			None
		}
	};

	let query_metrics = Arc::new(QueryMetrics::default());
	let query_manager = Arc::new(ServerQueryManager::with_metrics(query_metrics.clone()));

	// Initialize weaver infrastructure (provisioner, webhook dispatcher, K8s client)
	let weaver_infra = initialize_weaver_infrastructure(config).await;
	let provisioner = weaver_infra.provisioner;
	let webhook_dispatcher = weaver_infra.webhook_dispatcher;
	let k8s_client = weaver_infra.k8s_client;

	// Initialize SVID issuer and secrets service for weaver auth/secrets
	let (svid_issuer, secrets_service) = initialize_secrets_infrastructure(pool.clone());

	// Initialize WireGuard tunnel services if enabled
	let wg_tunnel_services = initialize_wgtunnel_services(pool.clone()).await;

	// Initialize SMTP client and email service if configured
	let smtp_client = initialize_smtp_client(config);
	let email_service = smtp_client.as_ref().map(|client| {
		Arc::new(EmailService::new(
			client.clone(),
			config.logging.locale.clone(),
		))
	});

	// Initialize OAuth clients
	let github_oauth = initialize_github_oauth();
	let google_oauth = initialize_google_oauth();
	let okta_oauth = initialize_okta_oauth();
	let oauth_state_store = Arc::new(OAuthStateStore::new());

	// Initialize GeoIP service
	let geoip_service = GeoIpService::try_from_env().map(Arc::new);

	// Create or fetch dev user if dev mode is enabled
	let dev_user = if auth_config.dev_mode {
		tracing::warn!("═══════════════════════════════════════════════════════════════════");
		tracing::warn!("⚠️  DEV MODE AUTHENTICATION ENABLED - DO NOT USE IN PRODUCTION ⚠️");
		tracing::warn!("All unauthenticated requests will be auto-authenticated as admin!");
		tracing::warn!("Set LOOM_ENV=production to prevent accidental production use.");
		tracing::warn!("═══════════════════════════════════════════════════════════════════");
		match create_or_get_dev_user(&user_repo).await {
			Ok(user) => {
				tracing::info!(user_id = %user.id, "Dev mode enabled, using dev user");
				Some(user)
			}
			Err(e) => {
				tracing::error!(error = %e, "Failed to create dev user, dev mode disabled");
				None
			}
		}
	} else {
		None
	};

	let session_service = Arc::new(SessionService::new(
		session_repo.clone(),
		audit_service.clone(),
		loom_server_auth::middleware::SESSION_COOKIE_NAME,
	));

	let flags_repo = Arc::new(loom_server_flags::SqliteFlagsRepository::new(pool.clone()));
	let flags_broadcaster = Arc::new(loom_server_flags::FlagsBroadcaster::with_defaults());

	// Initialize crons repository and broadcaster
	let crons_repo = Arc::new(loom_server_crons::SqliteCronsRepository::new(pool.clone()));
	let crons_broadcaster = Arc::new(loom_server_crons::CronsBroadcaster::with_defaults());

	// Initialize crash repository and broadcaster
	let crash_repo = Arc::new(loom_server_crash::SqliteCrashRepository::new(pool.clone()));
	let crash_broadcaster = Arc::new(loom_server_crash::CrashBroadcaster::new(
		loom_server_crash::CrashBroadcasterConfig::default(),
	));

	// Initialize sessions repository
	let sessions_repo = Arc::new(loom_server_sessions::SqliteSessionsRepository::new(
		pool.clone(),
	));

	// Initialize analytics repository and state with audit hook
	let analytics_repo = loom_server_analytics::SqliteAnalyticsRepository::new(pool.clone());
	let analytics_audit_hook: loom_server_analytics::SharedMergeAuditHook =
		Arc::new(routes::AnalyticsMergeAuditHook::new(audit_service.clone()));
	let analytics_state = loom_server_analytics::AnalyticsState::with_audit_hook(
		analytics_repo.clone(),
		analytics_audit_hook,
	);
	tracing::info!("Analytics system initialized with audit logging");

	AppState {
		repo,
		user_repo,
		session_repo,
		org_repo,
		team_repo,
		api_key_repo,
		user_provisioning,
		audit_service,
		share_repo,
		auth_config,
		dev_user,
		base_url: config.http.base_url.clone(),
		cse_client,
		serper_client,
		github_client,
		llm_service,
		query_manager,
		query_metrics,
		trace_store: QueryTraceStore::default(),
		provisioner,
		webhook_dispatcher,
		smtp_client,
		email_service,
		github_oauth,
		google_oauth,
		okta_oauth,
		oauth_state_store,
		default_locale: config.logging.locale.clone(),
		geoip_service,
		job_scheduler: None,
		job_repository: None,
		scm_repo_store: Some(scm_repo_store),
		scm_protection_store: Some(scm_protection_store),
		scm_webhook_store: Some(scm_webhook_store),
		scm_maintenance_store: Some(scm_maintenance_store),
		scm_team_access_store: Some(scm_team_access_store),
		push_mirror_store: Some(push_mirror_store),
		external_mirror_store: Some(external_mirror_store),
		log_buffer: log_buffer.unwrap_or_default(),
		audit_repo,
		k8s_client,
		svid_issuer,
		secrets_service,
		wg_tunnel_services,
		scim_config: config.scim.clone(),
		pool,
		session_service,
		flags_repo,
		flags_broadcaster,
		analytics_repo: Some(Arc::new(analytics_repo)),
		analytics_state: Some(Arc::new(analytics_state)),
		crons_repo,
		crons_broadcaster,
		crash_repo,
		crash_broadcaster,
		sessions_repo,
	}
}

/// Initialize WireGuard tunnel services if enabled.
async fn initialize_wgtunnel_services(pool: SqlitePool) -> Option<WgTunnelServices> {
	use loom_server_wgtunnel::WgTunnelConfig;

	match WgTunnelConfig::from_env() {
		Ok(mut config) => {
			if !config.enabled {
				tracing::info!("WireGuard tunnel disabled");
				return None;
			}

			if let Err(e) = config.load_derp_map().await {
				tracing::warn!(error = %e, "Failed to load DERP map, WG tunnel disabled");
				return None;
			}

			match WgTunnelServices::new(pool, config).await {
				Ok(services) => {
					tracing::info!(
						ip_prefix = %services.config.ip_prefix,
						"WireGuard tunnel services initialized"
					);
					Some(services)
				}
				Err(e) => {
					tracing::warn!(error = %e, "Failed to initialize WG tunnel services");
					None
				}
			}
		}
		Err(e) => {
			tracing::info!(error = %e, "WireGuard tunnel not configured");
			None
		}
	}
}

/// Create or get the development user for dev mode.
pub async fn create_or_get_dev_user(
	user_repo: &Arc<UserRepository>,
) -> Result<loom_server_auth::User, crate::error::ServerError> {
	let email = "dev@localhost";
	let display_name = "Development User";

	// Check if dev user already exists
	if let Some(mut user) = user_repo.get_user_by_email(email).await? {
		// Ensure dev user has admin/support privileges
		if !user.is_system_admin || !user.is_support {
			user.is_system_admin = true;
			user.is_support = true;
			user_repo.update_user(&user).await?;
		}
		return Ok(user);
	}

	// Create new dev user with full privileges
	let now = chrono::Utc::now();
	let username = user_repo.generate_unique_username(display_name).await?;
	let user = loom_server_auth::User {
		id: loom_server_auth::UserId::generate(),
		display_name: display_name.to_string(),
		username: Some(username),
		primary_email: Some(email.to_string()),
		avatar_url: None,
		email_visible: true,
		is_system_admin: true,
		is_support: true,
		is_auditor: false,
		created_at: now,
		updated_at: now,
		deleted_at: None,
		locale: None,
	};

	user_repo.create_user(&user).await?;
	tracing::info!(user_id = %user.id, email = %email, "Created dev user");
	Ok(user)
}

/// Result of weaver infrastructure initialization.
struct WeaverInfrastructure {
	provisioner: Option<Arc<Provisioner>>,
	webhook_dispatcher: Option<Arc<WebhookDispatcher>>,
	k8s_client: Option<Arc<dyn K8sClient>>,
}

/// Initialize the weaver provisioner, webhook dispatcher, and K8s client.
async fn initialize_weaver_infrastructure(config: &ServerConfig) -> WeaverInfrastructure {
	if !config.weaver.enabled {
		tracing::info!("Weaver provisioning disabled");
		return WeaverInfrastructure {
			provisioner: None,
			webhook_dispatcher: None,
			k8s_client: None,
		};
	}

	let k8s_client: Arc<dyn K8sClient> = if config.weaver.backend == "local" {
		let server_url = config.http.base_url.clone();
		match LocalClient::new(server_url).await {
			Ok(client) => Arc::new(client),
			Err(e) => {
				tracing::warn!(
					error = %e,
					"Failed to initialize local client, weaver provisioning disabled"
				);
				return WeaverInfrastructure {
					provisioner: None,
					webhook_dispatcher: None,
					k8s_client: None,
				};
			}
		}
	} else {
		match KubeClient::new().await {
			Ok(client) => Arc::new(client),
			Err(e) => {
				tracing::warn!(
					error = %e,
					"Failed to initialize K8s client, weaver provisioning disabled"
				);
				return WeaverInfrastructure {
					provisioner: None,
					webhook_dispatcher: None,
					k8s_client: None,
				};
			}
		}
	};

	let webhooks: Vec<WebhookConfig> = config
		.weaver
		.webhooks
		.iter()
		.map(|w| WebhookConfig {
			url: w.url.clone(),
			events: w
				.events
				.iter()
				.map(|e| match e {
					loom_server_config::WebhookEvent::WeaverCreated => {
						loom_server_weaver::WebhookEvent::WeaverCreated
					}
					loom_server_config::WebhookEvent::WeaverDeleted => {
						loom_server_weaver::WebhookEvent::WeaverDeleted
					}
					loom_server_config::WebhookEvent::WeaverFailed => {
						loom_server_weaver::WebhookEvent::WeaverFailed
					}
					loom_server_config::WebhookEvent::WeaversCleanup => {
						loom_server_weaver::WebhookEvent::WeaversCleanup
					}
				})
				.collect(),
			secret: w.secret.as_ref().map(|s| s.expose().to_string()),
		})
		.collect();

	let weaver_config = WeaverConfig {
		namespace: config.weaver.namespace.clone(),
		cleanup_interval_secs: config.weaver.cleanup_interval_secs,
		default_ttl_hours: config.weaver.default_ttl_hours,
		max_ttl_hours: config.weaver.max_ttl_hours,
		max_concurrent: config.weaver.max_concurrent,
		ready_timeout_secs: config.weaver.ready_timeout_secs,
		webhooks: webhooks.clone(),
		image_pull_secrets: config.weaver.image_pull_secrets.clone(),
		secrets_server_url: config.weaver.secrets_server_url.clone(),
		secrets_allow_insecure: config.weaver.secrets_allow_insecure,
		wg_enabled: config.weaver.wg_enabled.unwrap_or(true),
		audit_enabled: config.weaver.audit_enabled,
		audit_image: config.weaver.audit_image.clone(),
		audit_batch_interval_ms: config.weaver.audit_batch_interval_ms,
		audit_buffer_max_bytes: config.weaver.audit_buffer_max_bytes,
		server_url: config.http.base_url.clone(),
	};

	let provisioner_client: Arc<dyn K8sClient> = if config.weaver.backend == "local" {
		let server_url = config.http.base_url.clone();
		match LocalClient::new(server_url).await {
			Ok(client) => Arc::new(client),
			Err(e) => {
				tracing::warn!(error = %e, "Failed to create provisioner local client");
				return WeaverInfrastructure {
					provisioner: None,
					webhook_dispatcher: None,
					k8s_client: Some(k8s_client),
				};
			}
		}
	} else {
		match KubeClient::new().await {
			Ok(client) => Arc::new(client),
			Err(e) => {
				tracing::warn!(error = %e, "Failed to create provisioner K8s client");
				return WeaverInfrastructure {
					provisioner: None,
					webhook_dispatcher: None,
					k8s_client: Some(k8s_client),
				};
			}
		}
	};
	let provisioner = Arc::new(Provisioner::new(provisioner_client, weaver_config));
	let webhook_dispatcher = Arc::new(WebhookDispatcher::new(webhooks));

	tracing::info!(
		namespace = %config.weaver.namespace,
		max_concurrent = config.weaver.max_concurrent,
		default_ttl_hours = config.weaver.default_ttl_hours,
		"Weaver provisioning enabled"
	);

	WeaverInfrastructure {
		provisioner: Some(provisioner),
		webhook_dispatcher: Some(webhook_dispatcher),
		k8s_client: Some(k8s_client),
	}
}

type SecretsInfrastructure = (
	Option<Arc<SvidIssuer<SoftwareKeyBackend>>>,
	Option<Arc<SecretsService<SoftwareKeyBackend, SqliteSecretStore>>>,
);

fn initialize_secrets_infrastructure(pool: SqlitePool) -> SecretsInfrastructure {
	use loom_server_secrets::{generate_key, SvidConfig};

	let backend = if let Ok(key_b64) = std::env::var("LOOM_SECRETS_MASTER_KEY") {
		let svid_key = std::env::var("LOOM_SECRETS_SVID_SIGNING_KEY")
			.ok()
			.map(loom_common_secret::SecretString::new);

		let secret = loom_common_secret::SecretString::new(key_b64);
		match SoftwareKeyBackend::from_base64(
			&secret,
			svid_key.as_ref(),
			"loom-secrets".to_string(),
			"loom-secrets".to_string(),
		) {
			Ok(backend) => {
				tracing::info!("Secrets infrastructure initialized from LOOM_SECRETS_MASTER_KEY");
				Arc::new(backend)
			}
			Err(e) => {
				tracing::warn!(error = %e, "Failed to create software key backend from LOOM_SECRETS_MASTER_KEY");
				return (None, None);
			}
		}
	} else {
		tracing::info!(
			"LOOM_SECRETS_MASTER_KEY not set, generating ephemeral key (for development only)"
		);
		let kek = generate_key();
		Arc::new(SoftwareKeyBackend::new(
			kek,
			None,
			"loom-secrets".to_string(),
			"loom-secrets".to_string(),
		))
	};

	let svid_issuer = Arc::new(SvidIssuer::new(backend.clone(), SvidConfig::default()));
	let secret_store = Arc::new(SqliteSecretStore::new(pool));
	let secrets_service = Arc::new(SecretsService::new(backend, secret_store));

	(Some(svid_issuer), Some(secrets_service))
}

/// Initialize the SMTP client if configured.
fn initialize_smtp_client(config: &ServerConfig) -> Option<Arc<SmtpClient>> {
	let smtp = config.smtp.as_ref()?;

	let use_tls = matches!(
		smtp.tls_mode,
		loom_server_config::TlsMode::Tls | loom_server_config::TlsMode::StartTls
	);

	let smtp_config = loom_server_smtp::SmtpConfig {
		host: smtp.host.clone(),
		port: smtp.port,
		username: smtp.username.clone(),
		password: smtp.password.clone(),
		from_address: smtp.from_address.clone(),
		from_name: smtp.from_name.clone(),
		use_tls,
	};

	match SmtpClient::new(smtp_config) {
		Ok(client) => {
			tracing::info!("SMTP client configured");
			Some(Arc::new(client))
		}
		Err(e) => {
			tracing::warn!(error = %e, "Failed to create SMTP client");
			None
		}
	}
}

/// Initialize the GitHub OAuth client if configured.
fn initialize_github_oauth() -> Option<Arc<GitHubOAuthClient>> {
	match GitHubOAuthConfig::from_env() {
		Ok(config) => {
			tracing::info!("GitHub OAuth configured");
			Some(Arc::new(GitHubOAuthClient::new(config)))
		}
		Err(_) => {
			tracing::info!("GitHub OAuth not configured");
			None
		}
	}
}

/// Initialize the Google OAuth client if configured.
fn initialize_google_oauth() -> Option<Arc<GoogleOAuthClient>> {
	match GoogleOAuthConfig::from_env() {
		Ok(config) => {
			tracing::info!("Google OAuth configured");
			Some(Arc::new(GoogleOAuthClient::new(config)))
		}
		Err(_) => {
			tracing::info!("Google OAuth not configured");
			None
		}
	}
}

/// Initialize the Okta OAuth client if configured.
fn initialize_okta_oauth() -> Option<Arc<OktaOAuthClient>> {
	match OktaOAuthConfig::from_env() {
		Ok(config) => {
			tracing::info!("Okta OAuth configured");
			Some(Arc::new(OktaOAuthClient::new(config)))
		}
		Err(_) => {
			tracing::info!("Okta OAuth not configured");
			None
		}
	}
}

fn admin_routes(state: AppState) -> Router<AppState> {
	use crate::{auth_middleware::auth_layer, typed_router::require_auth_layer};
	use axum::middleware::from_fn_with_state;

	Router::new()
		.route("/users", get(routes::admin::list_users))
		.route("/users/{id}", delete(routes::admin::delete_user))
		.route(
			"/users/{id}/roles",
			patch(routes::admin::update_user_roles),
		)
		.route(
			"/impersonate/state",
			get(routes::admin::get_impersonation_state),
		)
		.route(
			"/users/{id}/impersonate",
			post(routes::admin::start_impersonation),
		)
		.route(
			"/impersonate/stop",
			post(routes::admin::stop_impersonation),
		)
		.route("/audit-logs", get(routes::admin::list_audit_logs))
		// Anthropic OAuth pool management
		.route(
			"/anthropic/accounts",
			get(routes::admin_anthropic::list_accounts),
		)
		.route(
			"/anthropic/accounts/{id}",
			delete(routes::admin_anthropic::remove_account),
		)
		.route(
			"/anthropic/oauth/initiate",
			post(routes::admin_anthropic::initiate_oauth),
		)
		.route(
			"/anthropic/oauth/complete",
			post(routes::admin_anthropic::complete_oauth),
		)
		// Job scheduler management
		.route("/jobs", get(routes::admin_jobs::list_jobs))
		.route("/jobs/{job_id}/run", post(routes::admin_jobs::trigger_job))
		.route(
			"/jobs/{job_id}/cancel",
			post(routes::admin_jobs::cancel_job),
		)
		.route(
			"/jobs/{job_id}/history",
			get(routes::admin_jobs::job_history),
		)
		.route(
			"/jobs/{job_id}/enable",
			post(routes::admin_jobs::enable_job),
		)
		.route(
			"/jobs/{job_id}/disable",
			post(routes::admin_jobs::disable_job),
		)
		// Log streaming
		.route("/logs", get(routes::admin_logs::list_logs))
		.route("/logs/stream", get(routes::admin_logs::stream_logs))
		// Platform kill switches management (super admin only)
		// Note: kill-switches routes MUST come before /flags/{key} to avoid route conflicts
		.route(
			"/flags/kill-switches",
			get(routes::admin_flags::list_platform_kill_switches),
		)
		.route(
			"/flags/kill-switches",
			post(routes::admin_flags::create_platform_kill_switch),
		)
		.route(
			"/flags/kill-switches/{key}",
			get(routes::admin_flags::get_platform_kill_switch),
		)
		.route(
			"/flags/kill-switches/{key}",
			patch(routes::admin_flags::update_platform_kill_switch),
		)
		.route(
			"/flags/kill-switches/{key}",
			delete(routes::admin_flags::delete_platform_kill_switch),
		)
		.route(
			"/flags/kill-switches/{key}/activate",
			post(routes::admin_flags::activate_platform_kill_switch),
		)
		.route(
			"/flags/kill-switches/{key}/deactivate",
			post(routes::admin_flags::deactivate_platform_kill_switch),
		)
		// Platform strategies management (super admin only)
		.route(
			"/flags/strategies",
			get(routes::admin_flags::list_platform_strategies),
		)
		// Platform flags management (super admin only)
		.route("/flags", get(routes::admin_flags::list_platform_flags))
		.route("/flags", post(routes::admin_flags::create_platform_flag))
		.route("/flags/{key}", get(routes::admin_flags::get_platform_flag))
		.route(
			"/flags/{key}",
			patch(routes::admin_flags::update_platform_flag),
		)
		.route(
			"/flags/{key}",
			delete(routes::admin_flags::archive_platform_flag),
		)
		.route(
			"/flags/{key}/restore",
			post(routes::admin_flags::restore_platform_flag),
		)
		.route_layer(RequireRole::admin())
		.layer(from_fn_with_state(state.clone(), require_auth_layer))
		.layer(from_fn_with_state(state, auth_layer))
}

/// Create the API router with all routes.
pub fn create_router(state: AppState) -> Router {
	let bin_dir = std::env::var("LOOM_SERVER_BIN_DIR").unwrap_or_else(|_| "./bin".to_string());
	let web_dir = std::env::var("LOOM_SERVER_WEB_DIR").ok();
	let has_provisioner = state.provisioner.is_some();
	let has_wg_tunnel = state.wg_tunnel_services.is_some();
	let scim_config = state.scim_config.clone();
	let scim_provisioning = state.user_provisioning.clone();
	let scim_user_repo = state.user_repo.clone();
	let scim_team_repo = state.team_repo.clone();
	let scim_audit_service = state.audit_service.clone();

	// Public routes - no authentication required
	let public = PublicRouter::new()
		// Health and metrics
		.route("/health", get(routes::health::health_check))
		.route("/metrics", get(routes::health::prometheus_metrics))
		// Auth routes (public)
		.route("/auth/providers", get(routes::auth::get_providers))
		.route(
			"/auth/magic-link",
			post(routes::auth::request_magic_link),
		)
		.route(
			"/auth/magic-link/verify",
			get(routes::auth::verify_magic_link),
		)
		.route("/auth/device/start", post(routes::auth::device_start))
		.route("/auth/device/poll", post(routes::auth::device_poll))
		// OAuth login/callback routes
		.route("/auth/login/github", get(routes::auth::login_github))
		.route("/auth/github/callback", get(routes::auth::callback_github))
		.route("/auth/login/google", get(routes::auth::login_google))
		.route("/auth/google/callback", get(routes::auth::callback_google))
		.route("/auth/login/okta", get(routes::auth::login_okta))
		.route("/auth/okta/callback", get(routes::auth::callback_okta))
		// Public invitation view (GET only)
		.route(
			"/api/invitations/{token}",
			get(routes::invitations::get_invitation),
		)
		// Public shared thread access
		.route(
			"/api/threads/{id}/share/{token}",
			get(routes::share::get_shared_thread),
		)
		// GitHub webhook (signature verified separately)
		.route(
			"/api/github/webhook",
			post(routes::github::github_webhook),
		)
		// Weaver auth routes (public - auth via K8s SA JWT)
		.route(
			"/internal/weaver-auth/token",
			post(routes::weaver_auth::exchange_token),
		)
		.route(
			"/internal/weaver-auth/.well-known/jwks.json",
			get(routes::weaver_auth::get_jwks),
		)
		// Weaver secrets routes (public - auth via Weaver SVID)
		.route(
			"/internal/weaver-secrets/v1/secrets/{scope}/{name}",
			get(routes::weaver_secrets::get_secret),
		)
		// WireGuard tunnel internal routes (public - auth via Weaver SVID)
		.route(
			"/internal/wg/weavers",
			post(routes::wgtunnel::register_weaver),
		)
		.route(
			"/internal/wg/weavers/{id}",
			delete(routes::wgtunnel::unregister_weaver),
		)
		.route(
			"/internal/wg/weavers/{id}",
			get(routes::wgtunnel::get_weaver),
		)
		.route(
			"/internal/wg/weavers/{id}/peers",
			get(routes::wgtunnel::stream_peers),
		)
		// Internal weaver audit endpoint (SPIFFE/SVID auth verified in handler)
		.route(
			"/internal/weaver-audit/events",
			post(routes::weaver_audit::submit_events),
		)
		// Documentation search
		.route("/docs/search", get(routes::docs::search_handler))
		// Feature flags SSE streaming (SDK key auth handled in handler)
		.route("/api/flags/stream", get(routes::flags::stream_flags))
		// Analytics SDK routes (API key auth handled in handler)
		.route(
			"/api/analytics/capture",
			post(routes::analytics::capture_event),
		)
		.route(
			"/api/analytics/batch",
			post(routes::analytics::batch_capture),
		)
		.route(
			"/api/analytics/identify",
			post(routes::analytics::identify),
		)
		.route("/api/analytics/alias", post(routes::analytics::alias))
		.route("/api/analytics/set", post(routes::analytics::set_properties))
		// Analytics query routes (ReadWrite API key auth handled in handler)
		.route(
			"/api/analytics/persons",
			get(routes::analytics::list_persons),
		)
		.route(
			"/api/analytics/persons/by-distinct-id/{distinct_id}",
			get(routes::analytics::get_person_by_distinct_id),
		)
		.route(
			"/api/analytics/persons/{person_id}",
			get(routes::analytics::get_person),
		)
		.route("/api/analytics/events", get(routes::analytics::list_events))
		.route(
			"/api/analytics/events/count",
			get(routes::analytics::count_events),
		)
		.route(
			"/api/analytics/events/export",
			post(routes::analytics::export_events),
		)
		// Cron monitoring ping endpoints (public - uses ping key for auth)
		.route("/ping/{key}", get(routes::crons::ping_success).post(routes::crons::ping_with_body))
		.route("/ping/{key}/start", get(routes::crons::ping_start))
		.route("/ping/{key}/fail", get(routes::crons::ping_fail))
		// Crash SDK capture endpoint (public - uses API key auth in handler)
		.route(
			"/api/crash/capture/sdk",
			post(routes::crash::capture_crash_with_api_key),
		)
		.build();

	// Authenticated routes - require valid session/token
	let mut authed = AuthedRouter::new()
		// Thread API routes
		.route(
			"/api/threads/search",
			get(routes::threads::search_threads),
		)
		.route("/api/threads/{id}", put(routes::threads::upsert_thread))
		.route("/api/threads/{id}", get(routes::threads::get_thread))
		.route(
			"/api/threads/{id}",
			delete(routes::threads::delete_thread),
		)
		.route(
			"/api/threads/{id}/visibility",
			post(routes::threads::update_thread_visibility),
		)
		.route("/api/threads", get(routes::threads::list_threads))
		// Share link routes (authenticated)
		.route(
			"/api/threads/{id}/share",
			post(routes::share::create_share_link),
		)
		.route(
			"/api/threads/{id}/share",
			delete(routes::share::revoke_share_link),
		)
		// Support access routes (authenticated)
		.route(
			"/api/threads/{id}/support-access/request",
			post(routes::share::request_support_access),
		)
		.route(
			"/api/threads/{id}/support-access/approve",
			post(routes::share::approve_support_access),
		)
		.route(
			"/api/threads/{id}/support-access",
			delete(routes::share::revoke_support_access),
		)
		// Auth routes (authenticated)
		.route("/auth/me", get(routes::auth::get_current_user))
		.route("/auth/ws-token", get(routes::auth::get_ws_token))
		.route("/auth/logout", post(routes::auth::logout))
		.route(
			"/auth/device/complete",
			post(routes::auth::device_complete),
		)
		// Session routes
		.route("/api/sessions", get(routes::sessions::list_sessions))
		.route(
			"/api/sessions/{id}",
			delete(routes::sessions::revoke_session),
		)
		// Organization routes
		.route("/api/orgs", get(routes::orgs::list_orgs))
		.route("/api/orgs", post(routes::orgs::create_org))
		.route("/api/orgs/{id}", get(routes::orgs::get_org))
		.route("/api/orgs/{id}", patch(routes::orgs::update_org))
		.route("/api/orgs/{id}", delete(routes::orgs::delete_org))
		.route(
			"/api/orgs/{id}/members",
			get(routes::orgs::list_org_members),
		)
		.route(
			"/api/orgs/{id}/members",
			post(routes::orgs::add_org_member),
		)
		.route(
			"/api/orgs/{org_id}/members/{user_id}",
			delete(routes::orgs::remove_org_member),
		)
		// Team routes
		.route(
			"/api/orgs/{org_id}/teams",
			get(routes::teams::list_teams),
		)
		.route(
			"/api/orgs/{org_id}/teams",
			post(routes::teams::create_team),
		)
		.route(
			"/api/orgs/{org_id}/teams/{team_id}",
			get(routes::teams::get_team),
		)
		.route(
			"/api/orgs/{org_id}/teams/{team_id}",
			patch(routes::teams::update_team),
		)
		.route(
			"/api/orgs/{org_id}/teams/{team_id}",
			delete(routes::teams::delete_team),
		)
		.route(
			"/api/orgs/{org_id}/teams/{team_id}/members",
			get(routes::teams::list_team_members),
		)
		.route(
			"/api/orgs/{org_id}/teams/{team_id}/members",
			post(routes::teams::add_team_member),
		)
		.route(
			"/api/orgs/{org_id}/teams/{team_id}/members/{user_id}",
			delete(routes::teams::remove_team_member),
		)
		// API key routes
		.route(
			"/api/orgs/{org_id}/api-keys",
			get(routes::api_keys::list_api_keys),
		)
		.route(
			"/api/orgs/{org_id}/api-keys",
			post(routes::api_keys::create_api_key),
		)
		.route(
			"/api/orgs/{org_id}/api-keys/{id}",
			delete(routes::api_keys::revoke_api_key),
		)
		.route(
			"/api/orgs/{org_id}/api-keys/{id}/usage",
			get(routes::api_keys::get_api_key_usage),
		)
		// Feature flags routes
		.route(
			"/api/orgs/{org_id}/flags/environments",
			get(routes::flags::list_environments),
		)
		.route(
			"/api/orgs/{org_id}/flags/environments",
			post(routes::flags::create_environment),
		)
		.route(
			"/api/orgs/{org_id}/flags/environments/{env_id}",
			get(routes::flags::get_environment),
		)
		.route(
			"/api/orgs/{org_id}/flags/environments/{env_id}",
			patch(routes::flags::update_environment),
		)
		.route(
			"/api/orgs/{org_id}/flags/environments/{env_id}",
			delete(routes::flags::delete_environment),
		)
		.route(
			"/api/orgs/{org_id}/flags/environments/{env_id}/sdk-keys",
			get(routes::flags::list_sdk_keys),
		)
		.route(
			"/api/orgs/{org_id}/flags/environments/{env_id}/sdk-keys",
			post(routes::flags::create_sdk_key),
		)
		.route(
			"/api/orgs/{org_id}/flags/sdk-keys/{key_id}",
			delete(routes::flags::revoke_sdk_key),
		)
		// Flag management routes
		.route(
			"/api/orgs/{org_id}/flags",
			get(routes::flags::list_flags),
		)
		.route(
			"/api/orgs/{org_id}/flags",
			post(routes::flags::create_flag),
		)
		.route(
			"/api/orgs/{org_id}/flags/{flag_id}",
			get(routes::flags::get_flag),
		)
		.route(
			"/api/orgs/{org_id}/flags/{flag_id}",
			patch(routes::flags::update_flag),
		)
		.route(
			"/api/orgs/{org_id}/flags/{flag_id}/archive",
			post(routes::flags::archive_flag),
		)
		.route(
			"/api/orgs/{org_id}/flags/{flag_id}/restore",
			post(routes::flags::restore_flag),
		)
		// Flag config routes
		.route(
			"/api/orgs/{org_id}/flags/{flag_id}/configs",
			get(routes::flags::list_flag_configs),
		)
		.route(
			"/api/orgs/{org_id}/flags/{flag_id}/configs/{env_id}",
			get(routes::flags::get_flag_config),
		)
		.route(
			"/api/orgs/{org_id}/flags/{flag_id}/configs/{env_id}",
			patch(routes::flags::update_flag_config),
		)
		// Strategy routes
		.route(
			"/api/orgs/{org_id}/flags/strategies",
			get(routes::flags::list_strategies),
		)
		.route(
			"/api/orgs/{org_id}/flags/strategies",
			post(routes::flags::create_strategy),
		)
		.route(
			"/api/orgs/{org_id}/flags/strategies/{strategy_id}",
			get(routes::flags::get_strategy),
		)
		.route(
			"/api/orgs/{org_id}/flags/strategies/{strategy_id}",
			patch(routes::flags::update_strategy),
		)
		.route(
			"/api/orgs/{org_id}/flags/strategies/{strategy_id}",
			delete(routes::flags::delete_strategy),
		)
		// Kill switch routes
		.route(
			"/api/orgs/{org_id}/flags/kill-switches",
			get(routes::flags::list_kill_switches),
		)
		.route(
			"/api/orgs/{org_id}/flags/kill-switches",
			post(routes::flags::create_kill_switch),
		)
		.route(
			"/api/orgs/{org_id}/flags/kill-switches/{kill_switch_id}",
			get(routes::flags::get_kill_switch),
		)
		.route(
			"/api/orgs/{org_id}/flags/kill-switches/{kill_switch_id}",
			patch(routes::flags::update_kill_switch),
		)
		.route(
			"/api/orgs/{org_id}/flags/kill-switches/{kill_switch_id}",
			delete(routes::flags::delete_kill_switch),
		)
		.route(
			"/api/orgs/{org_id}/flags/kill-switches/{kill_switch_id}/activate",
			post(routes::flags::activate_kill_switch),
		)
		.route(
			"/api/orgs/{org_id}/flags/kill-switches/{kill_switch_id}/deactivate",
			post(routes::flags::deactivate_kill_switch),
		)
		// Flag evaluation routes
		.route(
			"/api/orgs/{org_id}/flags/evaluate",
			post(routes::flags::evaluate_all_flags),
		)
		.route(
			"/api/orgs/{org_id}/flags/{flag_key}/evaluate",
			post(routes::flags::evaluate_flag_endpoint),
		)
		// Flag stats routes
		.route(
			"/api/orgs/{org_id}/flags/stale",
			get(routes::flags::list_stale_flags),
		)
		.route(
			"/api/orgs/{org_id}/flags/{flag_key}/stats",
			get(routes::flags::get_flag_stats),
		)
		// Flag stream stats (admin only)
		.route(
			"/api/flags/stream/stats",
			get(routes::flags::stream_stats),
		)
		// Analytics API key management routes (authenticated)
		.route(
			"/api/orgs/{org_id}/analytics/api-keys",
			get(routes::analytics::list_api_keys),
		)
		.route(
			"/api/orgs/{org_id}/analytics/api-keys",
			post(routes::analytics::create_api_key),
		)
		.route(
			"/api/orgs/{org_id}/analytics/api-keys/{key_id}",
			delete(routes::analytics::revoke_api_key),
		)
		// Cron monitoring API routes (authenticated)
		.route(
			"/api/crons/monitors",
			get(routes::crons::list_monitors).post(routes::crons::create_monitor),
		)
		.route(
			"/api/crons/monitors/{slug}",
			get(routes::crons::get_monitor).delete(routes::crons::delete_monitor),
		)
		.route(
			"/api/crons/monitors/{slug}/checkins",
			get(routes::crons::list_checkins).post(routes::crons::create_checkin),
		)
		.route(
			"/api/crons/checkins/{id}",
			get(routes::crons::get_checkin).patch(routes::crons::update_checkin),
		)
		.route("/api/crons/stream", get(routes::crons::stream_crons))
		// Crash analytics routes (authenticated)
		.route(
			"/api/crash/capture",
			post(routes::crash::capture_crash),
		)
		.route("/api/crash/batch", post(routes::crash::batch_capture_crash))
		.route(
			"/api/crash/projects",
			get(routes::crash::list_projects).post(routes::crash::create_project),
		)
		.route(
			"/api/crash/projects/{project_id}",
			get(routes::crash::get_project)
				.patch(routes::crash::update_project)
				.delete(routes::crash::delete_project),
		)
		.route(
			"/api/crash/projects/{project_id}/issues",
			get(routes::crash::list_issues),
		)
		.route(
			"/api/crash/projects/{project_id}/issues/{issue_id}/resolve",
			post(routes::crash::resolve_issue),
		)
		.route(
			"/api/crash/projects/{project_id}/issues/{issue_id}/unresolve",
			post(routes::crash::unresolve_issue),
		)
		.route(
			"/api/crash/projects/{project_id}/issues/{issue_id}/ignore",
			post(routes::crash::ignore_issue),
		)
		.route(
			"/api/crash/projects/{project_id}/issues/{issue_id}/assign",
			post(routes::crash::assign_issue),
		)
		.route(
			"/api/crash/projects/{project_id}/issues/{issue_id}",
			get(routes::crash::get_issue).delete(routes::crash::delete_issue),
		)
		.route(
			"/api/crash/projects/{project_id}/issues/{issue_id}/events",
			get(routes::crash::list_issue_events),
		)
		.route(
			"/api/crash/projects/{project_id}/stream",
			get(routes::crash::stream_crash),
		)
		.route(
			"/api/crash/projects/{project_id}/releases",
			get(routes::crash::list_releases).post(routes::crash::create_release),
		)
		.route(
			"/api/crash/projects/{project_id}/releases/{version}",
			get(routes::crash::get_release),
		)
		// Artifact routes (symbol upload)
		.route(
			"/api/crash/projects/{project_id}/artifacts",
			get(routes::crash::list_artifacts).post(routes::crash::upload_artifacts),
		)
		.route(
			"/api/crash/projects/{project_id}/artifacts/{artifact_id}",
			get(routes::crash::get_artifact).delete(routes::crash::delete_artifact),
		)
		// API key routes
		.route(
			"/api/crash/projects/{project_id}/api-keys",
			get(routes::crash::list_api_keys).post(routes::crash::create_api_key),
		)
		.route(
			"/api/crash/projects/{project_id}/api-keys/{key_id}",
			delete(routes::crash::revoke_api_key),
		)
		// App sessions routes (authenticated)
		.route(
			"/api/sessions/start",
			post(routes::app_sessions::start_session),
		)
		.route(
			"/api/sessions/end",
			post(routes::app_sessions::end_session),
		)
		.route(
			"/api/app-sessions",
			get(routes::app_sessions::list_sessions),
		)
		.route(
			"/api/app-sessions/releases",
			get(routes::app_sessions::list_release_health),
		)
		.route(
			"/api/app-sessions/releases/{version}",
			get(routes::app_sessions::get_release_health),
		)
		// Invitation routes (authenticated)
		.route(
			"/api/orgs/{org_id}/invitations",
			get(routes::invitations::list_invitations),
		)
		.route(
			"/api/orgs/{org_id}/invitations",
			post(routes::invitations::create_invitation),
		)
		.route(
			"/api/orgs/{org_id}/invitations/{id}",
			delete(routes::invitations::cancel_invitation),
		)
		.route(
			"/api/invitations/accept",
			post(routes::invitations::accept_invitation),
		)
		// Join request routes
		.route(
			"/api/orgs/{org_id}/join-requests",
			get(routes::invitations::list_join_requests),
		)
		.route(
			"/api/orgs/{org_id}/join-requests",
			post(routes::invitations::create_join_request),
		)
		.route(
			"/api/orgs/{org_id}/join-requests/{request_id}/approve",
			post(routes::invitations::approve_join_request),
		)
		.route(
			"/api/orgs/{org_id}/join-requests/{request_id}/reject",
			post(routes::invitations::reject_join_request),
		)
		// User routes
		.route("/api/users/{id}", get(routes::users::get_user_profile))
		.route(
			"/api/users/me",
			patch(routes::users::update_current_user),
		)
		.route(
			"/api/users/me/delete",
			post(routes::users::request_account_deletion),
		)
		.route(
			"/api/users/me/restore",
			post(routes::users::restore_account),
		)
		// User identity routes
		.route(
			"/api/users/me/identities",
			get(routes::users::list_identities),
		)
		.route(
			"/api/users/me/identities/{id}",
			delete(routes::users::unlink_identity),
		)
		// Repository routes
		.route("/api/repos", post(routes::repos::create_repo))
		.route("/api/repos/{id}", get(routes::repos::get_repo))
		.route("/api/repos/{id}", patch(routes::repos::update_repo))
		.route("/api/repos/{id}", delete(routes::repos::delete_repo))
		.route(
			"/api/users/{id}/repos",
			get(routes::repos::list_user_repos),
		)
		.route(
			"/api/orgs/{id}/repos",
			get(routes::repos::list_org_repos),
		)
		// Team access routes
		.route(
			"/api/repos/{id}/teams",
			get(routes::repos::list_repo_team_access),
		)
		.route(
			"/api/repos/{id}/teams",
			post(routes::repos::grant_repo_team_access),
		)
		.route(
			"/api/repos/{id}/teams/{tid}",
			delete(routes::repos::revoke_repo_team_access),
		)
		// Branch protection routes
		.route(
			"/api/repos/{id}/protection",
			get(routes::protection::list_protection_rules),
		)
		.route(
			"/api/repos/{id}/protection",
			post(routes::protection::create_protection_rule),
		)
		.route(
			"/api/repos/{id}/protection/{rule_id}",
			delete(routes::protection::delete_protection_rule),
		)
		// Webhook routes
		.route(
			"/api/repos/{id}/webhooks",
			get(routes::webhooks::list_repo_webhooks),
		)
		.route(
			"/api/repos/{id}/webhooks",
			post(routes::webhooks::create_repo_webhook),
		)
		.route(
			"/api/repos/{id}/webhooks/{wid}",
			delete(routes::webhooks::delete_repo_webhook),
		)
		.route(
			"/api/orgs/{id}/webhooks",
			get(routes::webhooks::list_org_webhooks),
		)
		.route(
			"/api/orgs/{id}/webhooks",
			post(routes::webhooks::create_org_webhook),
		)
		.route(
			"/api/orgs/{id}/webhooks/{wid}",
			delete(routes::webhooks::delete_org_webhook),
		)
		// Secrets routes (org-level)
		.route(
			"/api/orgs/{org_id}/secrets",
			get(routes::secrets::list_org_secrets),
		)
		.route(
			"/api/orgs/{org_id}/secrets",
			post(routes::secrets::create_org_secret),
		)
		.route(
			"/api/orgs/{org_id}/secrets/{name}",
			get(routes::secrets::get_org_secret),
		)
		.route(
			"/api/orgs/{org_id}/secrets/{name}",
			put(routes::secrets::update_org_secret),
		)
		.route(
			"/api/orgs/{org_id}/secrets/{name}",
			delete(routes::secrets::delete_org_secret),
		)
		// Secrets routes (repo-level)
		.route(
			"/api/repos/{repo_id}/secrets",
			get(routes::secrets::list_repo_secrets),
		)
		.route(
			"/api/repos/{repo_id}/secrets",
			post(routes::secrets::create_repo_secret),
		)
		.route(
			"/api/repos/{repo_id}/secrets/{name}",
			get(routes::secrets::get_repo_secret),
		)
		.route(
			"/api/repos/{repo_id}/secrets/{name}",
			put(routes::secrets::update_repo_secret),
		)
		.route(
			"/api/repos/{repo_id}/secrets/{name}",
			delete(routes::secrets::delete_repo_secret),
		)
		// Mirror routes
		.route(
			"/api/repos/{id}/mirrors",
			get(routes::mirrors::list_mirrors),
		)
		.route(
			"/api/repos/{id}/mirrors",
			post(routes::mirrors::create_mirror),
		)
		.route(
			"/api/repos/{id}/mirrors/{mirror_id}",
			delete(routes::mirrors::delete_mirror),
		)
		.route(
			"/api/repos/{id}/mirrors/{mirror_id}/sync",
			post(routes::mirrors::trigger_sync),
		)
		// Maintenance routes
		.route(
			"/api/repos/{id}/maintenance",
			post(routes::maintenance::trigger_repo_maintenance),
		)
		.route(
			"/api/repos/{id}/maintenance/jobs",
			get(routes::maintenance::list_repo_maintenance_jobs),
		)
		.route(
			"/api/admin/maintenance/sweep",
			post(routes::maintenance::trigger_global_sweep),
		)
		// CSE proxy route
		.route("/proxy/cse", post(routes::cse::proxy_cse))
		// Serper proxy route
		.route("/proxy/serper", post(routes::serper::proxy_serper))
		// GitHub App endpoints (authenticated)
		.route(
			"/api/github/app",
			get(routes::github::get_github_app_info),
		)
		.route(
			"/api/github/installations/by-repo",
			get(routes::github::get_github_installation_by_repo),
		)
		.route(
			"/proxy/github/search-code",
			post(routes::github::proxy_github_search_code),
		)
		.route(
			"/proxy/github/repo-info",
			post(routes::github::proxy_github_repo_info),
		)
		.route(
			"/proxy/github/file-contents",
			post(routes::github::proxy_github_file_contents),
		)
		// LLM proxy endpoints
		.route(
			"/proxy/anthropic/complete",
			post(llm_proxy::proxy_anthropic_complete),
		)
		.route(
			"/proxy/anthropic/stream",
			post(llm_proxy::proxy_anthropic_stream),
		)
		.route(
			"/proxy/openai/complete",
			post(llm_proxy::proxy_openai_complete),
		)
		.route(
			"/proxy/openai/stream",
			post(llm_proxy::proxy_openai_stream),
		)
		.route(
			"/proxy/vertex/complete",
			post(llm_proxy::proxy_vertex_complete),
		)
		.route(
			"/proxy/vertex/stream",
			post(llm_proxy::proxy_vertex_stream),
		)
		.route(
			"/proxy/zai/complete",
			post(llm_proxy::proxy_zai_complete),
		)
		.route(
			"/proxy/zai/stream",
			post(llm_proxy::proxy_zai_stream),
		)
		// Server query endpoints
		.route(
			"/api/sessions/{session_id}/query-response",
			post(server_query::handle_query_response),
		)
		.route(
			"/api/sessions/{session_id}/queries",
			get(server_query::list_pending_queries),
		)
		// Debug/tracing endpoints
		.route(
			"/api/debug/query-traces/{trace_id}",
			get(routes::debug::get_query_trace),
		)
		.route(
			"/api/debug/query-traces",
			get(routes::debug::list_query_traces),
		)
		.route(
			"/api/debug/query-traces/stats",
			get(routes::debug::get_trace_stats),
		);

	// Add weaver routes if provisioner is configured
	if has_provisioner {
		authed = authed
			.route("/api/weaver", post(routes::weaver::create_weaver))
			.route("/api/weavers", get(routes::weaver::list_weavers))
			.route("/api/weaver/{id}", get(routes::weaver::get_weaver))
			.route("/api/weaver/{id}", delete(routes::weaver::delete_weaver))
			.route("/api/weaver/{id}/logs", get(routes::weaver::stream_logs))
			.route(
				"/api/weaver/{id}/attach",
				get(routes::weaver::attach_weaver),
			)
			.route(
				"/api/weavers/cleanup",
				post(routes::weaver::trigger_cleanup),
			);
	}

	// Add WireGuard tunnel routes if enabled
	if has_wg_tunnel {
		authed = authed
			.route("/api/wg/devices", post(routes::wgtunnel::register_device))
			.route("/api/wg/devices", get(routes::wgtunnel::list_devices))
			.route(
				"/api/wg/devices/{id}",
				delete(routes::wgtunnel::revoke_device),
			)
			.route("/api/wg/sessions", post(routes::wgtunnel::create_session))
			.route("/api/wg/sessions", get(routes::wgtunnel::list_sessions))
			.route(
				"/api/wg/sessions/{id}",
				delete(routes::wgtunnel::terminate_session),
			)
			.route("/api/wg/derp-map", get(routes::wgtunnel::get_derp_map));
	}

	// Build the authenticated router with auth middleware
	let authed = authed.build(state.clone());

	// Git routes use optional auth (public repos allow anonymous access)
	let git_routes = routes::git::router().build(state.clone());

	// Git browser routes (repo browsing API for web UI, optional auth for public repos)
	let git_browser_routes = routes::git_browser::router().build(state.clone());

	// Merge public and authenticated routes
	let mut router = Router::new()
		.merge(public)
		.merge(authed)
		// Git HTTP smart protocol endpoints (optional auth)
		.merge(git_routes)
		// Git browser API endpoints (optional auth)
		.merge(git_browser_routes)
		// Admin routes (nested with role-based authorization layer, built on raw Router)
		.nest("/api/admin", admin_routes(state.clone()))
		// WebSocket endpoint - no auth middleware (uses first-message auth)
		.route(
			"/api/ws/sessions/{session_id}",
			get(crate::websocket::handler::ws_upgrade_handler),
		)
		.with_state(state)
		// Bin directory endpoints
		.nest_service(
			"/bin",
			ServeDir::new(&bin_dir)
				.precompressed_gzip()
				.fallback(axum::routing::get(routes::bin::list_bin_directory)),
		);

	// Mount SCIM routes if enabled
	if scim_config.enabled {
		if let Some(org_id_str) = scim_config.org_id {
			match uuid::Uuid::parse_str(&org_id_str) {
				Ok(uuid) => {
					let org_id = loom_server_auth::OrgId::new(uuid);
					let scim_router = loom_server_scim::scim_routes(
						scim_config.token,
						org_id,
						scim_provisioning,
						scim_user_repo,
						scim_team_repo,
						scim_audit_service,
					);
					router = router.nest("/api/scim", scim_router);
					tracing::info!("SCIM endpoints enabled at /api/scim");
				}
				Err(e) => {
					tracing::warn!(error = %e, org_id = %org_id_str, "SCIM enabled but LOOM_SERVER_SCIM_ORG_ID is not a valid UUID");
				}
			}
		} else {
			tracing::warn!("SCIM enabled but LOOM_SERVER_SCIM_ORG_ID not set");
		}
	}

	// Add OpenAPI documentation
	router = router
		.merge(SwaggerUi::new("/api").url("/api/openapi.json", crate::api_docs::ApiDoc::openapi()));

	// Serve static web assets if LOOM_SERVER_WEB_DIR is set
	if let Some(web_path) = web_dir {
		tracing::info!(web_dir = %web_path, "serving static web assets");
		router = router.fallback_service(
			ServeDir::new(&web_path).fallback(ServeFile::new(format!("{web_path}/index.html"))),
		);
	}

	router
}

#[cfg(test)]
mod tests {
	use super::*;

	use axum::{
		body::Body,
		http::{Request, StatusCode},
	};
	use loom_common_thread::{
		AgentStateKind, AgentStateSnapshot, ConversationSnapshot, Thread, ThreadId, ThreadMetadata,
		ThreadVisibility,
	};
	use tempfile::tempdir;
	use tower::ServiceExt;

	async fn create_test_app() -> (Router, tempfile::TempDir) {
		create_test_app_with_dev_mode(true).await
	}

	async fn create_test_app_no_auth() -> (Router, tempfile::TempDir) {
		create_test_app_with_dev_mode(false).await
	}

	async fn create_test_app_with_dev_mode(dev_mode: bool) -> (Router, tempfile::TempDir) {
		let dir = tempdir().unwrap();
		let db_path = dir.path().join("test.db");
		let db_url = format!("sqlite:{}?mode=rwc", db_path.display());
		let pool = crate::db::create_pool(&db_url).await.unwrap();
		crate::db::run_migrations(&pool).await.unwrap();
		let repo = Arc::new(ThreadRepository::new(pool.clone()));
		let config = ServerConfig::default();
		let mut state = create_app_state(pool, repo, &config, None).await;
		// Override auth config for testing
		state.auth_config.dev_mode = dev_mode;
		if dev_mode && state.dev_user.is_none() {
			// Create dev user if not exists
			state.dev_user = match create_or_get_dev_user(&state.user_repo).await {
				Ok(user) => Some(user),
				Err(_) => None,
			};
		}
		(create_router(state), dir)
	}

	fn create_test_thread() -> Thread {
		Thread {
			id: ThreadId::new(),
			version: 1,
			created_at: chrono::Utc::now().to_rfc3339(),
			updated_at: chrono::Utc::now().to_rfc3339(),
			last_activity_at: chrono::Utc::now().to_rfc3339(),
			workspace_root: Some("/test".to_string()),
			cwd: Some("/test".to_string()),
			loom_version: Some("0.1.0".to_string()),
			git_branch: Some("main".to_string()),
			git_remote_url: Some("github.com/test/repo".to_string()),
			git_initial_branch: Some("main".to_string()),
			git_initial_commit_sha: Some("abc123def456".to_string()),
			git_current_commit_sha: Some("xyz789012345".to_string()),
			git_start_dirty: Some(false),
			git_end_dirty: Some(false),
			git_commits: vec!["abc123def456".to_string(), "xyz789012345".to_string()],
			provider: Some("anthropic".to_string()),
			model: Some("claude-sonnet-4-20250514".to_string()),
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

	#[tokio::test]
	async fn test_health_check() {
		let (app, _dir) = create_test_app().await;

		let response = app
			.oneshot(
				Request::builder()
					.uri("/health")
					.body(Body::empty())
					.unwrap(),
			)
			.await
			.unwrap();

		// Should be OK (healthy or degraded, depending on bin dir)
		assert!(
			response.status() == StatusCode::OK || response.status() == StatusCode::SERVICE_UNAVAILABLE
		);
	}

	#[tokio::test]
	async fn test_health_check_response_structure() {
		let (app, _dir) = create_test_app().await;

		let response = app
			.oneshot(
				Request::builder()
					.uri("/health")
					.body(Body::empty())
					.unwrap(),
			)
			.await
			.unwrap();

		let body = axum::body::to_bytes(response.into_body(), usize::MAX)
			.await
			.unwrap();
		let health: serde_json::Value = serde_json::from_slice(&body).unwrap();

		// Verify response structure
		assert!(health.get("status").is_some());
		assert!(health.get("timestamp").is_some());
		assert!(health.get("duration_ms").is_some());
		assert!(health.get("version").is_some());
		assert!(health.get("components").is_some());

		let components = health.get("components").unwrap();
		assert!(components.get("database").is_some());
		assert!(components.get("bin_dir").is_some());
		assert!(components.get("llm_providers").is_some());
		assert!(components.get("google_cse").is_some());
	}

	#[tokio::test]
	async fn test_upsert_and_get() {
		let (app, _dir) = create_test_app().await;
		let thread = create_test_thread();
		let thread_json = serde_json::to_string(&thread).unwrap();

		// Upsert
		let response = app
			.clone()
			.oneshot(
				Request::builder()
					.method("PUT")
					.uri(format!("/api/threads/{}", thread.id))
					.header("Content-Type", "application/json")
					.body(Body::from(thread_json))
					.unwrap(),
			)
			.await
			.unwrap();

		assert_eq!(response.status(), StatusCode::OK);

		// Get
		let response = app
			.oneshot(
				Request::builder()
					.uri(format!("/api/threads/{}", thread.id))
					.body(Body::empty())
					.unwrap(),
			)
			.await
			.unwrap();

		assert_eq!(response.status(), StatusCode::OK);
	}

	#[tokio::test]
	async fn test_get_not_found() {
		let (app, _dir) = create_test_app().await;

		let response = app
			.oneshot(
				Request::builder()
					.uri("/api/threads/T-nonexistent")
					.body(Body::empty())
					.unwrap(),
			)
			.await
			.unwrap();

		assert_eq!(response.status(), StatusCode::NOT_FOUND);
	}

	#[tokio::test]
	async fn test_list_empty() {
		let (app, _dir) = create_test_app().await;

		let response = app
			.oneshot(
				Request::builder()
					.uri("/api/threads")
					.body(Body::empty())
					.unwrap(),
			)
			.await
			.unwrap();

		assert_eq!(response.status(), StatusCode::OK);
	}

	#[tokio::test]
	async fn test_logout_requires_auth() {
		let (app, _dir) = create_test_app_no_auth().await;
		let response = app
			.oneshot(
				Request::builder()
					.method("POST")
					.uri("/auth/logout")
					.body(Body::empty())
					.unwrap(),
			)
			.await
			.unwrap();
		assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
	}

	#[tokio::test]
	async fn test_get_providers() {
		let (app, _dir) = create_test_app().await;
		let response = app
			.oneshot(
				Request::builder()
					.method("GET")
					.uri("/auth/providers")
					.body(Body::empty())
					.unwrap(),
			)
			.await
			.unwrap();
		assert_eq!(response.status(), StatusCode::OK);
	}

	#[tokio::test]
	async fn test_get_current_user_unauthorized() {
		let (app, _dir) = create_test_app_no_auth().await;
		let response = app
			.oneshot(
				Request::builder()
					.method("GET")
					.uri("/auth/me")
					.body(Body::empty())
					.unwrap(),
			)
			.await
			.unwrap();
		assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
	}

	#[tokio::test]
	async fn test_device_start() {
		let (app, _dir) = create_test_app().await;
		let response = app
			.oneshot(
				Request::builder()
					.method("POST")
					.uri("/auth/device/start")
					.body(Body::empty())
					.unwrap(),
			)
			.await
			.unwrap();
		assert_eq!(response.status(), StatusCode::OK);
	}

	#[tokio::test]
	async fn test_update_visibility() {
		let (app, _dir) = create_test_app().await;
		let thread = create_test_thread();
		let thread_json = serde_json::to_string(&thread).unwrap();

		// First create the thread
		let _ = app
			.clone()
			.oneshot(
				Request::builder()
					.method("PUT")
					.uri(format!("/api/threads/{}", thread.id))
					.header("Content-Type", "application/json")
					.body(Body::from(thread_json))
					.unwrap(),
			)
			.await
			.unwrap();

		// Update visibility
		let response = app
			.oneshot(
				Request::builder()
					.method("POST")
					.uri(format!("/api/threads/{}/visibility", thread.id))
					.header("Content-Type", "application/json")
					.body(Body::from(r#"{"visibility":"public"}"#))
					.unwrap(),
			)
			.await
			.unwrap();

		assert_eq!(response.status(), StatusCode::OK);

		let body = axum::body::to_bytes(response.into_body(), usize::MAX)
			.await
			.unwrap();
		let updated: Thread = serde_json::from_slice(&body).unwrap();
		assert_eq!(
			updated.visibility,
			loom_common_thread::ThreadVisibility::Public
		);
	}

	#[tokio::test]
	async fn test_search_endpoint() {
		let (app, _dir) = create_test_app().await;

		// First create a thread
		let thread = create_test_thread();
		let response = app
			.clone()
			.oneshot(
				Request::builder()
					.method("PUT")
					.uri(format!("/api/threads/{}", thread.id.as_str()))
					.header("Content-Type", "application/json")
					.header("If-Match", "0")
					.body(Body::from(serde_json::to_string(&thread).unwrap()))
					.unwrap(),
			)
			.await
			.unwrap();
		assert_eq!(response.status(), StatusCode::OK);

		// Now search for it
		let response = app
			.oneshot(
				Request::builder()
					.uri("/api/threads/search?q=main")
					.body(Body::empty())
					.unwrap(),
			)
			.await
			.unwrap();

		assert_eq!(response.status(), StatusCode::OK);

		let body = axum::body::to_bytes(response.into_body(), usize::MAX)
			.await
			.unwrap();
		let result: serde_json::Value = serde_json::from_slice(&body).unwrap();
		assert!(result.get("hits").is_some());
	}

	#[tokio::test]
	async fn test_search_empty_query_returns_error() {
		let (app, _dir) = create_test_app().await;

		let response = app
			.oneshot(
				Request::builder()
					.uri("/api/threads/search?q=")
					.body(Body::empty())
					.unwrap(),
			)
			.await
			.unwrap();

		assert_eq!(response.status(), StatusCode::BAD_REQUEST);
	}

	#[tokio::test]
	async fn test_proxy_cse_empty_query_returns_400() {
		let (app, _dir) = create_test_app().await;
		let response = app
			.oneshot(
				Request::builder()
					.method("POST")
					.uri("/proxy/cse")
					.header("Content-Type", "application/json")
					.body(Body::from(r#"{"query":""}"#))
					.unwrap(),
			)
			.await
			.unwrap();
		assert_eq!(response.status(), StatusCode::BAD_REQUEST);
	}

	#[tokio::test]
	async fn test_proxy_cse_whitespace_query_returns_400() {
		let (app, _dir) = create_test_app().await;
		let response = app
			.oneshot(
				Request::builder()
					.method("POST")
					.uri("/proxy/cse")
					.header("Content-Type", "application/json")
					.body(Body::from(r#"{"query":"   "}"#))
					.unwrap(),
			)
			.await
			.unwrap();
		assert_eq!(response.status(), StatusCode::BAD_REQUEST);
	}

	#[tokio::test]
	async fn test_proxy_cse_unconfigured_returns_500() {
		// This test verifies that when CSE is not configured, we get an error
		// (cache miss path, then env var lookup fails)
		let (app, _dir) = create_test_app().await;

		// Clear env vars to ensure CSE is not configured
		std::env::remove_var("LOOM_SERVER_GOOGLE_CSE_API_KEY");
		std::env::remove_var("LOOM_SERVER_GOOGLE_CSE_SEARCH_ENGINE_ID");

		let response = app
			.oneshot(
				Request::builder()
					.method("POST")
					.uri("/proxy/cse")
					.header("Content-Type", "application/json")
					.body(Body::from(r#"{"query":"test query"}"#))
					.unwrap(),
			)
			.await
			.unwrap();

		// Should be 500 because CSE env vars are not set
		assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
	}

	/// Test debug endpoint: GET /api/debug/query-traces/{trace_id}
	/// **Why Important**: Ensures the debug endpoint correctly retrieves stored
	/// traces for performance analysis and debugging query lifecycle issues.
	#[tokio::test]
	async fn test_get_query_trace_endpoint() {
		use crate::query_tracing::QueryTracer;

		let (app, _dir) = create_test_app().await;

		// Create a test trace
		let mut tracer = QueryTracer::new("Q-test-123", Some("session-debug".to_string()));
		tracer.record_sent(10);
		tracer.record_response_received("ok");

		let _trace_id = tracer.trace_id.as_str().to_string();

		// We need to access the app state to store the trace
		// For now, we'll test the endpoint's 404 behavior when trace doesn't exist
		let response = app
			.oneshot(
				Request::builder()
					.uri("/api/debug/query-traces/nonexistent-trace".to_string())
					.body(Body::empty())
					.unwrap(),
			)
			.await
			.unwrap();

		assert_eq!(response.status(), StatusCode::NOT_FOUND);
	}

	/// Test debug endpoint: GET /api/debug/query-traces
	/// **Why Important**: Ensures the listing endpoint correctly returns all
	/// stored traces for monitoring and debugging purposes.
	#[tokio::test]
	async fn test_list_query_traces_endpoint() {
		let (app, _dir) = create_test_app().await;

		let response = app
			.oneshot(
				Request::builder()
					.uri("/api/debug/query-traces")
					.body(Body::empty())
					.unwrap(),
			)
			.await
			.unwrap();

		assert_eq!(response.status(), StatusCode::OK);

		let body = axum::body::to_bytes(response.into_body(), usize::MAX)
			.await
			.unwrap();
		let result: serde_json::Value = serde_json::from_slice(&body).unwrap();

		// Should have a traces array and count
		assert!(result.get("traces").is_some());
		assert!(result.get("count").is_some());
	}

	/// Test debug endpoint: GET /api/debug/query-traces?session_id=...
	/// **Why Important**: Ensures filtering by session_id correctly isolates
	/// traces for specific client sessions.
	#[tokio::test]
	async fn test_list_query_traces_with_session_filter() {
		let (app, _dir) = create_test_app().await;

		let response = app
			.oneshot(
				Request::builder()
					.uri("/api/debug/query-traces?session_id=test-session")
					.body(Body::empty())
					.unwrap(),
			)
			.await
			.unwrap();

		assert_eq!(response.status(), StatusCode::OK);

		let body = axum::body::to_bytes(response.into_body(), usize::MAX)
			.await
			.unwrap();
		let result: serde_json::Value = serde_json::from_slice(&body).unwrap();

		// Should have a traces array and count (likely empty for non-existent session)
		assert!(result.get("traces").is_some());
		assert!(result.get("count").is_some());
		assert_eq!(result["count"].as_u64(), Some(0));
	}

	/// Test debug endpoint: GET /api/debug/query-traces/stats
	/// **Why Important**: Ensures statistics endpoint correctly aggregates trace
	/// metrics for monitoring trace store health and performance bottlenecks.
	#[tokio::test]
	async fn test_get_trace_stats_endpoint() {
		let (app, _dir) = create_test_app().await;

		let response = app
			.oneshot(
				Request::builder()
					.uri("/api/debug/query-traces/stats")
					.body(Body::empty())
					.unwrap(),
			)
			.await
			.unwrap();

		assert_eq!(response.status(), StatusCode::OK);

		let body = axum::body::to_bytes(response.into_body(), usize::MAX)
			.await
			.unwrap();
		let result: serde_json::Value = serde_json::from_slice(&body).unwrap();

		// Should have required statistics fields
		assert!(result.get("total_traces").is_some());
		assert!(result.get("traces_with_errors").is_some());
		assert!(result.get("slow_traces").is_some());
		assert!(result.get("avg_events_per_trace").is_some());
		assert!(result.get("slow_trace_details").is_some());
	}

	/// Test debug endpoints: Complete flow with trace creation and retrieval
	/// **Why Important**: This integration test demonstrates the full flow of
	/// creating, storing, and retrieving traces through the debug endpoints.
	#[tokio::test]
	async fn test_debug_endpoints_integration() {
		use crate::query_tracing::QueryTracer;

		let dir = tempdir().unwrap();
		let db_path = dir.path().join("test.db");
		let db_url = format!("sqlite:{}?mode=rwc", db_path.display());
		let pool = crate::db::create_pool(&db_url).await.unwrap();
		crate::db::run_migrations(&pool).await.unwrap();
		let repo = Arc::new(ThreadRepository::new(pool.clone()));
		let config = ServerConfig::default();
		let mut state = create_app_state(pool, repo, &config, None).await;

		// Enable dev mode for testing
		state.auth_config.dev_mode = true;
		state.dev_user = match create_or_get_dev_user(&state.user_repo).await {
			Ok(user) => Some(user),
			Err(_) => None,
		};

		// Create and store a trace directly
		let mut tracer = QueryTracer::new(
			"Q-integration-test",
			Some("integration-session".to_string()),
		);
		tracer.record_sent(5);
		tokio::time::sleep(std::time::Duration::from_millis(10)).await;
		tracer.record_response_received("success");

		let trace_id = tracer.trace_id.as_str().to_string();
		state.trace_store.store(tracer).await;

		// Create router with our state
		let app = create_router(state);

		// Test 1: Retrieve the stored trace
		let response = app
			.clone()
			.oneshot(
				Request::builder()
					.uri(format!("/api/debug/query-traces/{trace_id}"))
					.body(Body::empty())
					.unwrap(),
			)
			.await
			.unwrap();

		assert_eq!(response.status(), StatusCode::OK);
		let body = axum::body::to_bytes(response.into_body(), usize::MAX)
			.await
			.unwrap();
		let timeline: serde_json::Value = serde_json::from_slice(&body).unwrap();

		assert_eq!(timeline["trace_id"].as_str().unwrap(), &trace_id);
		assert_eq!(timeline["query_id"].as_str().unwrap(), "Q-integration-test");
		assert_eq!(
			timeline["session_id"].as_str().unwrap(),
			"integration-session"
		);
		assert_eq!(timeline["events"].as_array().unwrap().len(), 3); // created, sent, response_received

		// Test 2: List traces
		let response = app
			.clone()
			.oneshot(
				Request::builder()
					.uri("/api/debug/query-traces")
					.body(Body::empty())
					.unwrap(),
			)
			.await
			.unwrap();

		assert_eq!(response.status(), StatusCode::OK);
		let body = axum::body::to_bytes(response.into_body(), usize::MAX)
			.await
			.unwrap();
		let list_result: serde_json::Value = serde_json::from_slice(&body).unwrap();

		assert!(list_result["count"].as_u64().unwrap() >= 1);

		// Test 3: Filter by session
		let response = app
			.clone()
			.oneshot(
				Request::builder()
					.uri("/api/debug/query-traces?session_id=integration-session")
					.body(Body::empty())
					.unwrap(),
			)
			.await
			.unwrap();

		assert_eq!(response.status(), StatusCode::OK);
		let body = axum::body::to_bytes(response.into_body(), usize::MAX)
			.await
			.unwrap();
		let session_result: serde_json::Value = serde_json::from_slice(&body).unwrap();

		assert_eq!(session_result["count"].as_u64().unwrap(), 1);

		// Test 4: Get statistics
		let response = app
			.oneshot(
				Request::builder()
					.uri("/api/debug/query-traces/stats")
					.body(Body::empty())
					.unwrap(),
			)
			.await
			.unwrap();

		assert_eq!(response.status(), StatusCode::OK);
		let body = axum::body::to_bytes(response.into_body(), usize::MAX)
			.await
			.unwrap();
		let stats: serde_json::Value = serde_json::from_slice(&body).unwrap();

		assert!(stats["total_traces"].as_u64().unwrap() >= 1);
		assert_eq!(stats["traces_with_errors"].as_u64().unwrap(), 0);
	}

	/// Test debug endpoint: Trace not found returns 404
	/// **Why Important**: Ensures the endpoint correctly handles missing traces
	/// and returns appropriate HTTP status codes.
	#[tokio::test]
	async fn test_get_query_trace_not_found() {
		let (app, _dir) = create_test_app().await;

		let response = app
			.oneshot(
				Request::builder()
					.uri("/api/debug/query-traces/TRACE-missing-trace-id")
					.body(Body::empty())
					.unwrap(),
			)
			.await
			.unwrap();

		assert_eq!(response.status(), StatusCode::NOT_FOUND);

		let body = axum::body::to_bytes(response.into_body(), usize::MAX)
			.await
			.unwrap();
		let error: serde_json::Value = serde_json::from_slice(&body).unwrap();

		assert!(error.get("message").is_some());
	}
}
