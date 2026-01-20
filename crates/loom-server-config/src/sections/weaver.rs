// Copyright (c) 2025 Geoffrey Huntley <ghuntley@ghuntley.com>. All rights reserved.
// SPDX-License-Identifier: Proprietary

//! Weaver configuration section.

use loom_common_config::SecretString;
use serde::{Deserialize, Serialize};

use crate::error::ConfigError;

/// Events that can trigger webhooks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WebhookEvent {
	#[serde(rename = "weaver.created")]
	WeaverCreated,
	#[serde(rename = "weaver.deleted")]
	WeaverDeleted,
	#[serde(rename = "weaver.failed")]
	WeaverFailed,
	#[serde(rename = "weavers.cleanup")]
	WeaversCleanup,
}

/// Webhook configuration (layer).
#[derive(Clone, Serialize, Deserialize)]
pub struct WebhookConfigLayer {
	pub url: Option<String>,
	pub events: Option<Vec<WebhookEvent>>,
	pub secret: Option<SecretString>,
}

impl std::fmt::Debug for WebhookConfigLayer {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("WebhookConfigLayer")
			.field("url", &self.url)
			.field("events", &self.events)
			.field("secret", &self.secret)
			.finish()
	}
}

/// Webhook configuration (runtime).
#[derive(Clone, Serialize, Deserialize)]
pub struct WebhookConfig {
	pub url: String,
	pub events: Vec<WebhookEvent>,
	pub secret: Option<SecretString>,
}

impl std::fmt::Debug for WebhookConfig {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("WebhookConfig")
			.field("url", &self.url)
			.field("events", &self.events)
			.field("secret", &self.secret)
			.finish()
	}
}

/// Weaver configuration layer (for merging).
///
/// All fields are optional to support layered configuration from
/// multiple sources (defaults, files, environment).
#[derive(Clone, Default, Serialize, Deserialize)]
pub struct WeaverConfigLayer {
	pub enabled: Option<bool>,
	pub namespace: Option<String>,
	pub cleanup_interval_secs: Option<u64>,
	pub default_ttl_hours: Option<u32>,
	pub max_ttl_hours: Option<u32>,
	pub max_concurrent: Option<u32>,
	pub ready_timeout_secs: Option<u64>,
	pub webhooks: Option<Vec<WebhookConfigLayer>>,
	pub image_pull_secrets: Option<Vec<String>>,
	/// URL to loom-server for secrets API (in-cluster: http://loom-server.loom.svc.cluster.local:8080)
	pub secrets_server_url: Option<String>,
	/// Allow insecure (HTTP) connections to secrets server (for in-cluster use)
	pub secrets_allow_insecure: Option<bool>,
	/// Enable WireGuard tunnel for weaver pods
	pub wg_enabled: Option<bool>,
	/// Enable audit sidecar for weaver pods
	pub audit_enabled: Option<bool>,
	/// Audit sidecar container image
	pub audit_image: Option<String>,
	/// Audit batch interval in milliseconds
	pub audit_batch_interval_ms: Option<u32>,
	/// Audit buffer max size in bytes
	pub audit_buffer_max_bytes: Option<u64>,
	/// Execution backend: "k8s" (default) or "local"
	pub backend: Option<String>,
}

impl std::fmt::Debug for WeaverConfigLayer {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("WeaverConfigLayer")
			.field("enabled", &self.enabled)
			.field("namespace", &self.namespace)
			.field("cleanup_interval_secs", &self.cleanup_interval_secs)
			.field("default_ttl_hours", &self.default_ttl_hours)
			.field("max_ttl_hours", &self.max_ttl_hours)
			.field("max_concurrent", &self.max_concurrent)
			.field("ready_timeout_secs", &self.ready_timeout_secs)
			.field("webhooks", &self.webhooks)
			.field("image_pull_secrets", &self.image_pull_secrets)
			.field("secrets_server_url", &self.secrets_server_url)
			.field("secrets_allow_insecure", &self.secrets_allow_insecure)
			.field("wg_enabled", &self.wg_enabled)
			.field("audit_enabled", &self.audit_enabled)
			.field("audit_image", &self.audit_image)
			.field("audit_batch_interval_ms", &self.audit_batch_interval_ms)
			.field("audit_buffer_max_bytes", &self.audit_buffer_max_bytes)
			.field("backend", &self.backend)
			.finish()
	}
}

impl WeaverConfigLayer {
	/// Merges another layer on top of this one.
	/// Values from `other` take precedence when present.
	pub fn merge(&mut self, other: WeaverConfigLayer) {
		if other.enabled.is_some() {
			self.enabled = other.enabled;
		}
		if other.namespace.is_some() {
			self.namespace = other.namespace;
		}
		if other.cleanup_interval_secs.is_some() {
			self.cleanup_interval_secs = other.cleanup_interval_secs;
		}
		if other.default_ttl_hours.is_some() {
			self.default_ttl_hours = other.default_ttl_hours;
		}
		if other.max_ttl_hours.is_some() {
			self.max_ttl_hours = other.max_ttl_hours;
		}
		if other.max_concurrent.is_some() {
			self.max_concurrent = other.max_concurrent;
		}
		if other.ready_timeout_secs.is_some() {
			self.ready_timeout_secs = other.ready_timeout_secs;
		}
		if other.webhooks.is_some() {
			self.webhooks = other.webhooks;
		}
		if other.image_pull_secrets.is_some() {
			self.image_pull_secrets = other.image_pull_secrets;
		}
		if other.secrets_server_url.is_some() {
			self.secrets_server_url = other.secrets_server_url;
		}
		if other.secrets_allow_insecure.is_some() {
			self.secrets_allow_insecure = other.secrets_allow_insecure;
		}
		if other.wg_enabled.is_some() {
			self.wg_enabled = other.wg_enabled;
		}
		if other.audit_enabled.is_some() {
			self.audit_enabled = other.audit_enabled;
		}
		if other.audit_image.is_some() {
			self.audit_image = other.audit_image;
		}
		if other.audit_batch_interval_ms.is_some() {
			self.audit_batch_interval_ms = other.audit_batch_interval_ms;
		}
		if other.audit_buffer_max_bytes.is_some() {
			self.audit_buffer_max_bytes = other.audit_buffer_max_bytes;
		}
		if other.backend.is_some() {
			self.backend = other.backend;
		}
	}

	/// Resolves this layer into a runtime configuration.
	pub fn finalize(self) -> WeaverConfig {
		self.resolve().unwrap_or_default()
	}

	/// Resolves this layer into a runtime configuration.
	pub fn resolve(self) -> Result<WeaverConfig, ConfigError> {
		let webhooks = self
			.webhooks
			.unwrap_or_default()
			.into_iter()
			.map(|w| {
				let url = w
					.url
					.ok_or_else(|| ConfigError::Validation("webhook url is required".to_string()))?;
				Ok(WebhookConfig {
					url,
					events: w.events.unwrap_or_default(),
					secret: w.secret,
				})
			})
			.collect::<Result<Vec<_>, ConfigError>>()?;

		Ok(WeaverConfig {
			enabled: self.enabled.unwrap_or(false),
			namespace: self.namespace.unwrap_or_else(|| "loom-weavers".to_string()),
			cleanup_interval_secs: self.cleanup_interval_secs.unwrap_or(1800),
			default_ttl_hours: self.default_ttl_hours.unwrap_or(4),
			max_ttl_hours: self.max_ttl_hours.unwrap_or(48),
			max_concurrent: self.max_concurrent.unwrap_or(64),
			ready_timeout_secs: self.ready_timeout_secs.unwrap_or(60),
			webhooks,
			image_pull_secrets: self.image_pull_secrets.unwrap_or_default(),
			secrets_server_url: self.secrets_server_url,
			secrets_allow_insecure: self.secrets_allow_insecure.unwrap_or(false),
			wg_enabled: self.wg_enabled,
			audit_enabled: self.audit_enabled.unwrap_or(false),
			audit_image: self
				.audit_image
				.unwrap_or_else(|| "ghcr.io/ghuntley/loom-audit-sidecar:latest".to_string()),
			audit_batch_interval_ms: self.audit_batch_interval_ms.unwrap_or(100),
			audit_buffer_max_bytes: self.audit_buffer_max_bytes.unwrap_or(256 * 1024 * 1024),
			backend: self.backend.unwrap_or_else(|| "k8s".to_string()),
		})
	}
}

/// Weaver configuration (runtime, resolved).
#[derive(Clone)]
pub struct WeaverConfig {
	pub enabled: bool,
	pub namespace: String,
	pub cleanup_interval_secs: u64,
	pub default_ttl_hours: u32,
	pub max_ttl_hours: u32,
	pub max_concurrent: u32,
	pub ready_timeout_secs: u64,
	pub webhooks: Vec<WebhookConfig>,
	pub image_pull_secrets: Vec<String>,
	/// URL to loom-server for secrets API (in-cluster: http://loom-server.loom.svc.cluster.local:8080)
	pub secrets_server_url: Option<String>,
	/// Allow insecure (HTTP) connections to secrets server (for in-cluster use)
	pub secrets_allow_insecure: bool,
	/// Enable WireGuard tunnel for weaver pods
	pub wg_enabled: Option<bool>,
	/// Enable audit sidecar for weaver pods
	pub audit_enabled: bool,
	/// Audit sidecar container image
	pub audit_image: String,
	/// Audit batch interval in milliseconds
	pub audit_batch_interval_ms: u32,
	/// Audit buffer max size in bytes
	pub audit_buffer_max_bytes: u64,
	/// Execution backend: "k8s" (default) or "local"
	pub backend: String,
}

impl std::fmt::Debug for WeaverConfig {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("WeaverConfig")
			.field("enabled", &self.enabled)
			.field("namespace", &self.namespace)
			.field("cleanup_interval_secs", &self.cleanup_interval_secs)
			.field("default_ttl_hours", &self.default_ttl_hours)
			.field("max_ttl_hours", &self.max_ttl_hours)
			.field("max_concurrent", &self.max_concurrent)
			.field("ready_timeout_secs", &self.ready_timeout_secs)
			.field("webhooks", &self.webhooks)
			.field("image_pull_secrets", &self.image_pull_secrets)
			.field("secrets_server_url", &self.secrets_server_url)
			.field("secrets_allow_insecure", &self.secrets_allow_insecure)
			.field("wg_enabled", &self.wg_enabled)
			.field("audit_enabled", &self.audit_enabled)
			.field("audit_image", &self.audit_image)
			.field("audit_batch_interval_ms", &self.audit_batch_interval_ms)
			.field("audit_buffer_max_bytes", &self.audit_buffer_max_bytes)
			.field("backend", &self.backend)
			.finish()
	}
}

impl Default for WeaverConfig {
	fn default() -> Self {
		Self {
			enabled: false,
			namespace: "loom-weavers".to_string(),
			cleanup_interval_secs: 1800,
			default_ttl_hours: 4,
			max_ttl_hours: 48,
			max_concurrent: 64,
			ready_timeout_secs: 60,
			webhooks: Vec::new(),
			image_pull_secrets: Vec::new(),
			secrets_server_url: None,
			secrets_allow_insecure: false,
			wg_enabled: None,
			audit_enabled: false,
			audit_image: "ghcr.io/ghuntley/loom-audit-sidecar:latest".to_string(),
			audit_batch_interval_ms: 100,
			audit_buffer_max_bytes: 256 * 1024 * 1024,
			backend: "k8s".to_string(),
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use loom_common_config::Secret;

	mod weaver_config_layer {
		use super::*;

		#[test]
		fn merge_enabled_override() {
			let mut base = WeaverConfigLayer {
				enabled: Some(false),
				..Default::default()
			};
			let overlay = WeaverConfigLayer {
				enabled: Some(true),
				..Default::default()
			};

			base.merge(overlay);
			assert_eq!(base.enabled, Some(true));
		}

		#[test]
		fn merge_preserves_base_when_overlay_is_none() {
			let mut base = WeaverConfigLayer {
				enabled: Some(true),
				namespace: Some("custom-ns".to_string()),
				cleanup_interval_secs: Some(3600),
				..Default::default()
			};
			let overlay = WeaverConfigLayer::default();

			base.merge(overlay);
			assert_eq!(base.enabled, Some(true));
			assert_eq!(base.namespace, Some("custom-ns".to_string()));
			assert_eq!(base.cleanup_interval_secs, Some(3600));
		}

		#[test]
		fn merge_individual_fields() {
			let mut base = WeaverConfigLayer {
				enabled: Some(true),
				namespace: Some("base-ns".to_string()),
				default_ttl_hours: Some(8),
				max_concurrent: Some(32),
				..Default::default()
			};
			let overlay = WeaverConfigLayer {
				namespace: Some("overlay-ns".to_string()),
				max_ttl_hours: Some(72),
				..Default::default()
			};

			base.merge(overlay);
			assert_eq!(base.enabled, Some(true));
			assert_eq!(base.namespace, Some("overlay-ns".to_string()));
			assert_eq!(base.default_ttl_hours, Some(8));
			assert_eq!(base.max_ttl_hours, Some(72));
			assert_eq!(base.max_concurrent, Some(32));
		}

		#[test]
		fn merge_webhooks_replaces_entirely() {
			let mut base = WeaverConfigLayer {
				webhooks: Some(vec![WebhookConfigLayer {
					url: Some("https://base.example.com".to_string()),
					events: Some(vec![WebhookEvent::WeaverCreated]),
					secret: None,
				}]),
				..Default::default()
			};
			let overlay = WeaverConfigLayer {
				webhooks: Some(vec![WebhookConfigLayer {
					url: Some("https://overlay.example.com".to_string()),
					events: Some(vec![WebhookEvent::WeaverDeleted]),
					secret: None,
				}]),
				..Default::default()
			};

			base.merge(overlay);
			assert_eq!(base.webhooks.as_ref().unwrap().len(), 1);
			assert_eq!(
				base.webhooks.as_ref().unwrap()[0].url,
				Some("https://overlay.example.com".to_string())
			);
		}
	}

	mod resolve {
		use super::*;

		#[test]
		fn resolve_uses_defaults() {
			let layer = WeaverConfigLayer::default();
			let config = layer.resolve().unwrap();

			assert!(!config.enabled);
			assert_eq!(config.namespace, "loom-weavers");
			assert_eq!(config.cleanup_interval_secs, 1800);
			assert_eq!(config.default_ttl_hours, 4);
			assert_eq!(config.max_ttl_hours, 48);
			assert_eq!(config.max_concurrent, 64);
			assert_eq!(config.ready_timeout_secs, 60);
			assert!(config.webhooks.is_empty());
			assert!(config.image_pull_secrets.is_empty());
		}

		#[test]
		fn resolve_with_custom_values() {
			let layer = WeaverConfigLayer {
				enabled: Some(true),
				namespace: Some("custom-weavers".to_string()),
				cleanup_interval_secs: Some(900),
				default_ttl_hours: Some(2),
				max_ttl_hours: Some(24),
				max_concurrent: Some(128),
				ready_timeout_secs: Some(120),
				webhooks: None,
				image_pull_secrets: Some(vec!["ghcr-secret".to_string()]),
				secrets_server_url: None,
				secrets_allow_insecure: None,
				wg_enabled: None,
				..Default::default()
			};
			let config = layer.resolve().unwrap();

			assert!(config.enabled);
			assert_eq!(config.namespace, "custom-weavers");
			assert_eq!(config.cleanup_interval_secs, 900);
			assert_eq!(config.default_ttl_hours, 2);
			assert_eq!(config.max_ttl_hours, 24);
			assert_eq!(config.max_concurrent, 128);
			assert_eq!(config.ready_timeout_secs, 120);
			assert_eq!(config.image_pull_secrets, vec!["ghcr-secret"]);
		}

		#[test]
		fn resolve_webhooks() {
			let layer = WeaverConfigLayer {
				webhooks: Some(vec![
					WebhookConfigLayer {
						url: Some("https://hooks.example.com/weaver".to_string()),
						events: Some(vec![
							WebhookEvent::WeaverCreated,
							WebhookEvent::WeaverDeleted,
						]),
						secret: Some(Secret::new("webhook-secret".to_string())),
					},
					WebhookConfigLayer {
						url: Some("https://hooks.example.com/cleanup".to_string()),
						events: Some(vec![WebhookEvent::WeaversCleanup]),
						secret: None,
					},
				]),
				..Default::default()
			};
			let config = layer.resolve().unwrap();

			assert_eq!(config.webhooks.len(), 2);
			assert_eq!(config.webhooks[0].url, "https://hooks.example.com/weaver");
			assert_eq!(
				config.webhooks[0].events,
				vec![WebhookEvent::WeaverCreated, WebhookEvent::WeaverDeleted]
			);
			assert!(config.webhooks[0].secret.is_some());
			assert_eq!(config.webhooks[1].url, "https://hooks.example.com/cleanup");
			assert!(config.webhooks[1].secret.is_none());
		}

		#[test]
		fn resolve_fails_without_webhook_url() {
			let layer = WeaverConfigLayer {
				webhooks: Some(vec![WebhookConfigLayer {
					url: None,
					events: Some(vec![WebhookEvent::WeaverCreated]),
					secret: None,
				}]),
				..Default::default()
			};
			let result = layer.resolve();
			assert!(result.is_err());
		}
	}

	mod debug_redaction {
		use super::*;

		#[test]
		fn debug_redacts_webhook_secrets() {
			let layer = WeaverConfigLayer {
				webhooks: Some(vec![WebhookConfigLayer {
					url: Some("https://example.com".to_string()),
					events: None,
					secret: Some(Secret::new("super-secret-key".to_string())),
				}]),
				..Default::default()
			};

			let debug_output = format!("{layer:?}");
			assert!(!debug_output.contains("super-secret-key"));
			assert!(debug_output.contains("[REDACTED]"));
		}

		#[test]
		fn resolved_config_debug_redacts_secrets() {
			let layer = WeaverConfigLayer {
				webhooks: Some(vec![WebhookConfigLayer {
					url: Some("https://example.com".to_string()),
					events: Some(vec![WebhookEvent::WeaverCreated]),
					secret: Some(Secret::new("super-secret-key".to_string())),
				}]),
				..Default::default()
			};

			let config = layer.resolve().unwrap();
			let debug_output = format!("{config:?}");
			assert!(!debug_output.contains("super-secret-key"));
			assert!(debug_output.contains("[REDACTED]"));
		}
	}

	mod default_values {
		use super::*;

		#[test]
		fn weaver_config_default() {
			let config = WeaverConfig::default();

			assert!(!config.enabled);
			assert_eq!(config.namespace, "loom-weavers");
			assert_eq!(config.cleanup_interval_secs, 1800);
			assert_eq!(config.default_ttl_hours, 4);
			assert_eq!(config.max_ttl_hours, 48);
			assert_eq!(config.max_concurrent, 64);
			assert_eq!(config.ready_timeout_secs, 60);
			assert!(config.webhooks.is_empty());
			assert!(config.image_pull_secrets.is_empty());
		}
	}
}
