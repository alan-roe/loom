// Copyright (c) 2025 Geoffrey Huntley <ghuntley@ghuntley.com>. All rights
// reserved. SPDX-License-Identifier: Proprietary

//! LLM service implementation.

use std::env;
use std::sync::Arc;

use loom_common_core::{LlmClient, LlmError, LlmRequest, LlmResponse, LlmStream};
use std::time::Duration;
use tokio::sync::Mutex;

use loom_server_llm_anthropic::{
	AnthropicClient, AnthropicConfig, AnthropicPool, AnthropicPoolConfig, MemoryCredentialStore,
};

pub use loom_server_llm_anthropic::{
	AccountDetails, AccountHealthInfo, AccountHealthStatus, OAuthCredentials, PoolStatus,
};
use loom_server_llm_openai::OpenAIClient;
use loom_server_llm_vertex::VertexClient;
use loom_server_llm_zai::ZaiClient;
use tracing::{debug, info, instrument, warn};

use crate::config::{AnthropicAuthConfig, LlmServiceConfig};
use crate::error::LlmServiceError;

/// Health information for Anthropic client.
#[derive(Debug, Clone)]
pub enum AnthropicHealthInfo {
	/// API key mode - just indicates if configured.
	ApiKey { configured: bool },
	/// OAuth pool mode - detailed pool status.
	Pool(PoolStatus),
}

/// Wrapper for Anthropic client that can use either API key or OAuth pool.
enum AnthropicClientWrapper {
	ApiKey(Arc<AnthropicClient<MemoryCredentialStore>>),
	Pool(Arc<AnthropicPool>),
}

impl Clone for AnthropicClientWrapper {
	fn clone(&self) -> Self {
		match self {
			AnthropicClientWrapper::ApiKey(c) => AnthropicClientWrapper::ApiKey(Arc::clone(c)),
			AnthropicClientWrapper::Pool(p) => AnthropicClientWrapper::Pool(Arc::clone(p)),
		}
	}
}

impl AnthropicClientWrapper {
	async fn complete(&self, request: LlmRequest) -> Result<LlmResponse, LlmError> {
		match self {
			AnthropicClientWrapper::ApiKey(c) => c.complete(request).await,
			AnthropicClientWrapper::Pool(p) => p.complete(request).await,
		}
	}

	async fn complete_streaming(&self, request: LlmRequest) -> Result<LlmStream, LlmError> {
		match self {
			AnthropicClientWrapper::ApiKey(c) => c.complete_streaming(request).await,
			AnthropicClientWrapper::Pool(p) => p.complete_streaming(request).await,
		}
	}

	fn shutdown(&self) {
		if let AnthropicClientWrapper::Pool(p) = self {
			p.shutdown();
		}
	}
}

/// Default model for Anthropic when client sends "default".
/// Uses Opus 4 to match Claude Code's default for MAX subscribers.
const DEFAULT_ANTHROPIC_MODEL: &str = "claude-opus-4-20250514";

/// Default model for OpenAI when client sends "default".
const DEFAULT_OPENAI_MODEL: &str = "gpt-4o";

/// Default model for Vertex when client sends "default".
const DEFAULT_VERTEX_MODEL: &str = "gemini-1.5-pro";

/// Default model for Z.ai when client sends "default".
const DEFAULT_ZAI_MODEL: &str = "glm-4.7";

/// Service for managing LLM provider interactions.
///
/// This service holds clients for multiple LLM providers (Anthropic, OpenAI,
/// Vertex) and provides provider-specific methods for making completion
/// requests.
pub struct LlmService {
	anthropic_client: Option<AnthropicClientWrapper>,
	anthropic_model: String,
	openai_client: Option<Arc<OpenAIClient>>,
	openai_model: String,
	vertex_client: Option<Arc<VertexClient>>,
	vertex_model: String,
	zai_client: Option<Arc<ZaiClient>>,
	zai_model: String,
	refresh_task_handle: Mutex<Option<tokio::task::JoinHandle<()>>>,
}

impl LlmService {
	/// Creates a new LLM service with the given configuration.
	///
	/// Initializes clients for all providers that have API keys configured.
	/// This is async because OAuth credential loading requires file I/O.
	pub async fn new(config: LlmServiceConfig) -> Result<Self, LlmServiceError> {
		info!("Initializing LLM service");

		let anthropic_client = match &config.anthropic_auth {
			Some(AnthropicAuthConfig::ApiKey(api_key)) => {
				let mut anthropic_config = AnthropicConfig::new(api_key.expose().clone());
				if let Some(ref model) = config.anthropic_model {
					debug!(model = %model, "Using custom Anthropic model");
					anthropic_config = anthropic_config.with_model(model.clone());
				}

				let client = AnthropicClient::new(anthropic_config)
					.map_err(|e| LlmServiceError::Config(e.to_string()))?;
				info!("Anthropic client initialized with API key");
				Some(AnthropicClientWrapper::ApiKey(Arc::new(client)))
			}
			Some(AnthropicAuthConfig::OAuthPool {
				credential_file,
				cooldown_secs,
			}) => {
				let pool_config = AnthropicPoolConfig {
					cooldown: Duration::from_secs(*cooldown_secs),
					..Default::default()
				};

				debug!(
					credential_file = ?credential_file,
					cooldown_secs = cooldown_secs,
					"Creating Anthropic OAuth pool (accounts managed via admin UI)"
				);

				let pool = Arc::new(AnthropicPool::empty(
					credential_file.clone(),
					config.anthropic_model.clone(),
					pool_config,
				));

				// Load existing accounts from the credential file
				match pool.load_from_file().await {
					Ok(count) => {
						info!(
							accounts_loaded = count,
							"Anthropic OAuth pool initialized with persisted accounts"
						);
					}
					Err(e) => {
						warn!(error = %e, "Failed to load accounts from credential file, starting with empty pool");
					}
				}

				Some(AnthropicClientWrapper::Pool(pool))
			}
			None => {
				debug!("Anthropic auth not configured");
				None
			}
		};

		let openai_client = if let Some(ref api_key) = config.openai_api_key {
			let mut openai_config = loom_server_llm_openai::OpenAIConfig::new(api_key.expose().clone());
			if let Some(ref model) = config.openai_model {
				debug!(model = %model, "Using custom OpenAI model");
				openai_config = openai_config.with_model(model.clone());
			}
			if let Some(org) = config.openai_organization {
				debug!(organization = %org, "Using OpenAI organization");
				openai_config = openai_config.with_organization(org);
			}

			let client =
				OpenAIClient::new(openai_config).map_err(|e| LlmServiceError::Config(e.to_string()))?;
			info!("OpenAI client initialized");
			Some(Arc::new(client))
		} else {
			debug!("OpenAI API key not configured");
			None
		};

		let vertex_client =
			if let (Some(project), Some(location)) = (config.vertex_project, config.vertex_location) {
				let mut vertex_config = loom_server_llm_vertex::VertexConfig::new(project, location);
				if let Some(ref model) = config.vertex_model {
					debug!(model = %model, "Using custom Vertex model");
					vertex_config = vertex_config.with_model(model.clone());
				}

				let client =
					VertexClient::new(vertex_config).map_err(|e| LlmServiceError::Config(e.to_string()))?;
				info!("Vertex client initialized");
				Some(Arc::new(client))
			} else {
				debug!("Vertex project/location not configured");
				None
			};

		let zai_client = if let Some(ref api_key) = config.zai_api_key {
			let mut zai_config = loom_server_llm_zai::ZaiConfig::new(api_key.expose().clone());
			if let Some(ref model) = config.zai_model {
				debug!(model = %model, "Using custom Z.ai model");
				zai_config = zai_config.with_model(model.clone());
			}

			let client =
				ZaiClient::new(zai_config).map_err(|e| LlmServiceError::Config(e.to_string()))?;
			info!("Z.ai client initialized");
			Some(Arc::new(client))
		} else {
			debug!("Z.ai API key not configured");
			None
		};

		if anthropic_client.is_none()
			&& openai_client.is_none()
			&& vertex_client.is_none()
			&& zai_client.is_none()
		{
			return Err(LlmServiceError::ProviderNotConfigured(
				"No LLM providers configured. Set LOOM_SERVER_ANTHROPIC_API_KEY, \
				 LOOM_SERVER_OPENAI_API_KEY, LOOM_SERVER_VERTEX_PROJECT + LOOM_SERVER_VERTEX_LOCATION, or LOOM_SERVER_ZAI_API_KEY"
					.to_string(),
			));
		}

		let refresh_task_handle = if let Some(AnthropicClientWrapper::Pool(ref pool)) = anthropic_client
		{
			let refresh_interval_secs: u64 = env::var("LOOM_SERVER_ANTHROPIC_REFRESH_INTERVAL_SECS")
				.ok()
				.and_then(|s| s.parse().ok())
				.unwrap_or(300);
			let refresh_threshold_secs: u64 = env::var("LOOM_SERVER_ANTHROPIC_REFRESH_THRESHOLD_SECS")
				.ok()
				.and_then(|s| s.parse().ok())
				.unwrap_or(900);

			let handle = Arc::clone(pool).spawn_refresh_task(
				Duration::from_secs(refresh_interval_secs),
				Duration::from_secs(refresh_threshold_secs),
			);
			info!(
				refresh_interval_secs,
				refresh_threshold_secs, "Started Anthropic OAuth token refresh task"
			);
			Some(handle)
		} else {
			None
		};

		let anthropic_model = config
			.anthropic_model
			.clone()
			.unwrap_or_else(|| DEFAULT_ANTHROPIC_MODEL.to_string());
		let openai_model = config
			.openai_model
			.clone()
			.unwrap_or_else(|| DEFAULT_OPENAI_MODEL.to_string());
		let vertex_model = config
			.vertex_model
			.clone()
			.unwrap_or_else(|| DEFAULT_VERTEX_MODEL.to_string());
		let zai_model = config
			.zai_model
			.clone()
			.unwrap_or_else(|| DEFAULT_ZAI_MODEL.to_string());

		info!(
			anthropic = anthropic_client.is_some(),
			openai = openai_client.is_some(),
			vertex = vertex_client.is_some(),
			zai = zai_client.is_some(),
			anthropic_model = %anthropic_model,
			openai_model = %openai_model,
			vertex_model = %vertex_model,
			zai_model = %zai_model,
			"LLM service initialized"
		);

		Ok(Self {
			anthropic_client,
			anthropic_model,
			openai_client,
			openai_model,
			vertex_client,
			vertex_model,
			zai_client,
			zai_model,
			refresh_task_handle: Mutex::new(refresh_task_handle),
		})
	}

	/// Creates a new LLM service from environment variables.
	pub async fn from_env() -> Result<Self, LlmServiceError> {
		let config =
			LlmServiceConfig::from_env().map_err(|e| LlmServiceError::Config(e.to_string()))?;
		Self::new(config).await
	}

	/// Returns whether the Anthropic provider is configured.
	pub fn has_anthropic(&self) -> bool {
		self.anthropic_client.is_some()
	}

	/// Returns whether the OpenAI provider is configured.
	pub fn has_openai(&self) -> bool {
		self.openai_client.is_some()
	}

	/// Returns whether the Vertex AI provider is configured.
	pub fn has_vertex(&self) -> bool {
		self.vertex_client.is_some()
	}

	/// Returns whether the Z.ai provider is configured.
	pub fn has_zai(&self) -> bool {
		self.zai_client.is_some()
	}

	/// Get Anthropic health status.
	pub async fn anthropic_health(&self) -> Option<AnthropicHealthInfo> {
		match &self.anthropic_client {
			Some(AnthropicClientWrapper::ApiKey(_)) => {
				Some(AnthropicHealthInfo::ApiKey { configured: true })
			}
			Some(AnthropicClientWrapper::Pool(pool)) => {
				Some(AnthropicHealthInfo::Pool(pool.pool_status().await))
			}
			None => None,
		}
	}

	/// Returns whether Anthropic is configured in OAuth pool mode.
	pub fn is_anthropic_oauth_pool(&self) -> bool {
		matches!(
			&self.anthropic_client,
			Some(AnthropicClientWrapper::Pool(_))
		)
	}

	/// Add an Anthropic OAuth account to the pool.
	pub async fn add_anthropic_account(
		&self,
		account_id: String,
		credentials: OAuthCredentials,
	) -> Result<(), LlmServiceError> {
		match &self.anthropic_client {
			Some(AnthropicClientWrapper::Pool(pool)) => pool
				.add_account(account_id, credentials)
				.await
				.map_err(|e| LlmServiceError::Config(format!("Failed to add account: {e}"))),
			Some(AnthropicClientWrapper::ApiKey(_)) => Err(LlmServiceError::Config(
				"Cannot add accounts: Anthropic is configured with API key, not OAuth pool".to_string(),
			)),
			None => Err(LlmServiceError::ProviderNotConfigured(
				"Anthropic provider not configured".to_string(),
			)),
		}
	}

	/// Remove an Anthropic OAuth account from the pool.
	pub async fn remove_anthropic_account(&self, account_id: &str) -> Result<(), LlmServiceError> {
		match &self.anthropic_client {
			Some(AnthropicClientWrapper::Pool(pool)) => pool
				.remove_account(account_id)
				.await
				.map_err(|e| LlmServiceError::Config(format!("Failed to remove account: {e}"))),
			Some(AnthropicClientWrapper::ApiKey(_)) => Err(LlmServiceError::Config(
				"Cannot remove accounts: Anthropic is configured with API key, not OAuth pool".to_string(),
			)),
			None => Err(LlmServiceError::ProviderNotConfigured(
				"Anthropic provider not configured".to_string(),
			)),
		}
	}

	/// Get detailed account info for admin API.
	pub async fn anthropic_account_details(&self) -> Option<Vec<AccountDetails>> {
		match &self.anthropic_client {
			Some(AnthropicClientWrapper::Pool(pool)) => Some(pool.account_details().await),
			_ => None,
		}
	}

	/// Gracefully shutdown the LLM service.
	///
	/// This signals the token refresh task to stop and waits for it to complete
	/// with a timeout.
	pub async fn shutdown(&self) {
		// Signal Anthropic pool to stop refresh task
		if let Some(client) = &self.anthropic_client {
			client.shutdown();
		}

		// Wait for refresh task to complete (with timeout)
		let handle = {
			let mut guard = self.refresh_task_handle.lock().await;
			guard.take()
		};

		if let Some(handle) = handle {
			match tokio::time::timeout(Duration::from_secs(5), handle).await {
				Ok(Ok(())) => info!("Token refresh task shut down cleanly"),
				Ok(Err(e)) => warn!(error = %e, "Token refresh task panicked during shutdown"),
				Err(_) => warn!("Token refresh task shutdown timed out after 5 seconds"),
			}
		}
	}

	/// Substitute "default" model with the configured default for Anthropic.
	fn resolve_anthropic_model(&self, request: LlmRequest) -> LlmRequest {
		if request.model == "default" {
			debug!(
				original_model = "default",
				resolved_model = %self.anthropic_model,
				"Substituting default model"
			);
			request.with_model(&self.anthropic_model)
		} else {
			request
		}
	}

	/// Substitute "default" model with the configured default for OpenAI.
	fn resolve_openai_model(&self, request: LlmRequest) -> LlmRequest {
		if request.model == "default" {
			debug!(
				original_model = "default",
				resolved_model = %self.openai_model,
				"Substituting default model"
			);
			request.with_model(&self.openai_model)
		} else {
			request
		}
	}

	/// Substitute "default" model with the configured default for Vertex.
	fn resolve_vertex_model(&self, request: LlmRequest) -> LlmRequest {
		if request.model == "default" {
			debug!(
				original_model = "default",
				resolved_model = %self.vertex_model,
				"Substituting default model"
			);
			request.with_model(&self.vertex_model)
		} else {
			request
		}
	}

	/// Substitute "default" model with the configured default for Z.ai.
	fn resolve_zai_model(&self, request: LlmRequest) -> LlmRequest {
		if request.model == "default" {
			debug!(
				original_model = "default",
				resolved_model = %self.zai_model,
				"Substituting default model"
			);
			request.with_model(&self.zai_model)
		} else {
			request
		}
	}

	/// Sends a completion request to Anthropic.
	#[instrument(skip(self, request), fields(provider = "anthropic"))]
	pub async fn complete_anthropic(&self, request: LlmRequest) -> Result<LlmResponse, LlmError> {
		let client = self
			.anthropic_client
			.as_ref()
			.ok_or_else(|| LlmError::Api("Anthropic provider not configured".to_string()))?;

		let request = self.resolve_anthropic_model(request);

		debug!(
				model = %request.model,
				message_count = request.messages.len(),
				tool_count = request.tools.len(),
				"Sending Anthropic completion request"
		);

		client.complete(request).await
	}

	/// Sends a streaming completion request to Anthropic.
	#[instrument(skip(self, request), fields(provider = "anthropic"))]
	pub async fn complete_streaming_anthropic(
		&self,
		request: LlmRequest,
	) -> Result<LlmStream, LlmError> {
		let client = self
			.anthropic_client
			.as_ref()
			.ok_or_else(|| LlmError::Api("Anthropic provider not configured".to_string()))?;

		let request = self.resolve_anthropic_model(request);

		debug!(
				model = %request.model,
				message_count = request.messages.len(),
				tool_count = request.tools.len(),
				"Sending Anthropic streaming completion request"
		);

		client.complete_streaming(request).await
	}

	/// Sends a completion request to OpenAI.
	#[instrument(skip(self, request), fields(provider = "openai"))]
	pub async fn complete_openai(&self, request: LlmRequest) -> Result<LlmResponse, LlmError> {
		let client = self
			.openai_client
			.as_ref()
			.ok_or_else(|| LlmError::Api("OpenAI provider not configured".to_string()))?;

		let request = self.resolve_openai_model(request);

		debug!(
				model = %request.model,
				message_count = request.messages.len(),
				tool_count = request.tools.len(),
				"Sending OpenAI completion request"
		);

		client.complete(request).await
	}

	/// Sends a streaming completion request to OpenAI.
	#[instrument(skip(self, request), fields(provider = "openai"))]
	pub async fn complete_streaming_openai(
		&self,
		request: LlmRequest,
	) -> Result<LlmStream, LlmError> {
		let client = self
			.openai_client
			.as_ref()
			.ok_or_else(|| LlmError::Api("OpenAI provider not configured".to_string()))?;

		let request = self.resolve_openai_model(request);

		debug!(
				model = %request.model,
				message_count = request.messages.len(),
				tool_count = request.tools.len(),
				"Sending OpenAI streaming completion request"
		);

		client.complete_streaming(request).await
	}

	/// Sends a completion request to Vertex AI.
	#[instrument(skip(self, request), fields(provider = "vertex"))]
	pub async fn complete_vertex(&self, request: LlmRequest) -> Result<LlmResponse, LlmError> {
		let client = self
			.vertex_client
			.as_ref()
			.ok_or_else(|| LlmError::Api("Vertex provider not configured".to_string()))?;

		let request = self.resolve_vertex_model(request);

		debug!(
				model = %request.model,
				message_count = request.messages.len(),
				tool_count = request.tools.len(),
				"Sending Vertex completion request"
		);

		client.complete(request).await
	}

	/// Sends a streaming completion request to Vertex AI.
	#[instrument(skip(self, request), fields(provider = "vertex"))]
	pub async fn complete_streaming_vertex(
		&self,
		request: LlmRequest,
	) -> Result<LlmStream, LlmError> {
		let client = self
			.vertex_client
			.as_ref()
			.ok_or_else(|| LlmError::Api("Vertex provider not configured".to_string()))?;

		let request = self.resolve_vertex_model(request);

		debug!(
				model = %request.model,
				message_count = request.messages.len(),
				tool_count = request.tools.len(),
				"Sending Vertex streaming completion request"
		);

		client.complete_streaming(request).await
	}

	/// Sends a completion request to Z.ai.
	#[instrument(skip(self, request), fields(provider = "zai"))]
	pub async fn complete_zai(&self, request: LlmRequest) -> Result<LlmResponse, LlmError> {
		let client = self
			.zai_client
			.as_ref()
			.ok_or_else(|| LlmError::Api("Z.ai provider not configured".to_string()))?;

		let request = self.resolve_zai_model(request);

		debug!(
				model = %request.model,
				message_count = request.messages.len(),
				tool_count = request.tools.len(),
				"Sending Z.ai completion request"
		);

		client.complete(request).await
	}

	/// Sends a streaming completion request to Z.ai.
	#[instrument(skip(self, request), fields(provider = "zai"))]
	pub async fn complete_streaming_zai(&self, request: LlmRequest) -> Result<LlmStream, LlmError> {
		let client = self
			.zai_client
			.as_ref()
			.ok_or_else(|| LlmError::Api("Z.ai provider not configured".to_string()))?;

		let request = self.resolve_zai_model(request);

		debug!(
				model = %request.model,
				message_count = request.messages.len(),
				tool_count = request.tools.len(),
				"Sending Z.ai streaming completion request"
		);

		client.complete_streaming(request).await
	}
}

impl std::fmt::Debug for LlmService {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("LlmService")
			.field("anthropic_configured", &self.anthropic_client.is_some())
			.field("openai_configured", &self.openai_client.is_some())
			.field("vertex_configured", &self.vertex_client.is_some())
			.field("zai_configured", &self.zai_client.is_some())
			.finish()
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::config::LlmProvider;

	/// Verifies that service creation fails without any API keys.
	/// This is important to fail fast with clear error messages.
	#[tokio::test]
	async fn new_fails_without_any_api_key() {
		let config = LlmServiceConfig::new(LlmProvider::Anthropic);
		let result = LlmService::new(config).await;
		assert!(matches!(
			result,
			Err(LlmServiceError::ProviderNotConfigured(_))
		));
	}

	/// Verifies that has_anthropic() returns true when configured.
	#[tokio::test]
	async fn has_anthropic_returns_true_when_configured() {
		let config = LlmServiceConfig::new(LlmProvider::Anthropic).with_anthropic_api_key("test-key");
		let service = LlmService::new(config).await.unwrap();
		assert!(service.has_anthropic());
		assert!(!service.has_openai());
	}

	/// Verifies that has_openai() returns true when configured.
	#[tokio::test]
	async fn has_openai_returns_true_when_configured() {
		let config = LlmServiceConfig::new(LlmProvider::OpenAi).with_openai_api_key("test-key");
		let service = LlmService::new(config).await.unwrap();
		assert!(!service.has_anthropic());
		assert!(service.has_openai());
	}

	/// Verifies that both providers can be configured simultaneously.
	#[tokio::test]
	async fn both_providers_can_be_configured() {
		let config = LlmServiceConfig::new(LlmProvider::Anthropic)
			.with_anthropic_api_key("anthropic-key")
			.with_openai_api_key("openai-key");
		let service = LlmService::new(config).await.unwrap();
		assert!(service.has_anthropic());
		assert!(service.has_openai());
	}

	/// Verifies that has_zai() returns true when configured.
	#[tokio::test]
	async fn has_zai_returns_true_when_configured() {
		let config = LlmServiceConfig::new(LlmProvider::Zai).with_zai_api_key("test-key");
		let service = LlmService::new(config).await.unwrap();
		assert!(!service.has_anthropic());
		assert!(!service.has_openai());
		assert!(!service.has_vertex());
		assert!(service.has_zai());
	}

	/// Verifies that Debug implementation doesn't expose sensitive data.
	/// This is important for security - API keys should never appear in logs.
	#[tokio::test]
	async fn debug_does_not_expose_secrets() {
		let config =
			LlmServiceConfig::new(LlmProvider::Anthropic).with_anthropic_api_key("super-secret-key");
		let service = LlmService::new(config).await.unwrap();
		let debug_output = format!("{service:?}");
		assert!(!debug_output.contains("super-secret-key"));
	}
}
