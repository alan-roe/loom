// Copyright (c) 2025 Geoffrey Huntley <ghuntley@ghuntley.com>. All rights reserved.
// SPDX-License-Identifier: Proprietary

//! Project and API key types for crash analytics.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;
use uuid::Uuid;

use crate::error::CrashError;
use crate::event::Platform;
use crate::{OrgId, UserId};

/// Unique identifier for a crash project.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ProjectId(pub Uuid);

impl ProjectId {
	pub fn new() -> Self {
		Self(Uuid::now_v7())
	}
}

impl Default for ProjectId {
	fn default() -> Self {
		Self::new()
	}
}

impl fmt::Display for ProjectId {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "{}", self.0)
	}
}

impl FromStr for ProjectId {
	type Err = uuid::Error;

	fn from_str(s: &str) -> Result<Self, Self::Err> {
		Ok(Self(Uuid::parse_str(s)?))
	}
}

/// A crash analytics project within an organization.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct CrashProject {
	pub id: ProjectId,
	pub org_id: OrgId,
	pub name: String,
	/// URL-safe identifier
	pub slug: String,
	pub platform: Platform,

	/// Auto-resolve after N days inactive
	pub auto_resolve_age_days: Option<u32>,
	/// Custom fingerprinting rules (JSON)
	pub fingerprint_rules: Vec<FingerprintRule>,

	pub created_at: DateTime<Utc>,
	pub updated_at: DateTime<Utc>,
}

impl Default for CrashProject {
	fn default() -> Self {
		let now = Utc::now();
		Self {
			id: ProjectId::new(),
			org_id: OrgId::new(),
			name: String::new(),
			slug: String::new(),
			platform: Platform::JavaScript,
			auto_resolve_age_days: None,
			fingerprint_rules: Vec::new(),
			created_at: now,
			updated_at: now,
		}
	}
}

impl CrashProject {
	/// Validate a slug (URL-safe identifier).
	pub fn validate_slug(slug: &str) -> bool {
		if slug.len() < 3 || slug.len() > 50 {
			return false;
		}
		slug
			.chars()
			.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_')
			&& slug.starts_with(|c: char| c.is_ascii_lowercase())
	}
}

/// Custom fingerprinting rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct FingerprintRule {
	pub match_type: FingerprintMatchType,
	pub pattern: String,
	/// Custom fingerprint components
	pub fingerprint: Vec<String>,
}

/// What to match against for custom fingerprinting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum FingerprintMatchType {
	ExceptionType,
	ExceptionMessage,
	Module,
	Function,
}

/// Unique identifier for a crash API key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct CrashApiKeyId(pub Uuid);

impl CrashApiKeyId {
	pub fn new() -> Self {
		Self(Uuid::now_v7())
	}
}

impl Default for CrashApiKeyId {
	fn default() -> Self {
		Self::new()
	}
}

impl fmt::Display for CrashApiKeyId {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "{}", self.0)
	}
}

impl FromStr for CrashApiKeyId {
	type Err = uuid::Error;

	fn from_str(s: &str) -> Result<Self, Self::Err> {
		Ok(Self(Uuid::parse_str(s)?))
	}
}

/// Authentication key for SDK clients.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct CrashApiKey {
	pub id: CrashApiKeyId,
	pub project_id: ProjectId,
	pub name: String,
	pub key_type: CrashKeyType,
	/// Argon2 hash of the key
	pub key_hash: String,
	pub rate_limit_per_minute: Option<u32>,
	/// CORS for browser SDKs
	pub allowed_origins: Vec<String>,
	pub created_by: UserId,
	pub created_at: DateTime<Utc>,
	pub last_used_at: Option<DateTime<Utc>>,
	pub revoked_at: Option<DateTime<Utc>>,
}

impl CrashApiKey {
	/// Check if the key is revoked.
	pub fn is_revoked(&self) -> bool {
		self.revoked_at.is_some()
	}
}

/// Type of API key determining its capabilities.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum CrashKeyType {
	/// Can only send crashes (safe for client-side)
	Capture,
	/// Can manage symbols, issues, settings
	Admin,
}

impl fmt::Display for CrashKeyType {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::Capture => write!(f, "capture"),
			Self::Admin => write!(f, "admin"),
		}
	}
}

impl FromStr for CrashKeyType {
	type Err = CrashError;

	fn from_str(s: &str) -> Result<Self, Self::Err> {
		match s {
			"capture" => Ok(Self::Capture),
			"admin" => Ok(Self::Admin),
			_ => Err(CrashError::InvalidKeyType(s.to_string())),
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use proptest::prelude::*;

	proptest! {
		#[test]
		fn project_id_roundtrip(uuid_bytes in any::<[u8; 16]>()) {
			let uuid = Uuid::from_bytes(uuid_bytes);
			let id = ProjectId(uuid);
			let s = id.to_string();
			let parsed: ProjectId = s.parse().unwrap();
			prop_assert_eq!(id, parsed);
		}

		#[test]
		fn crash_api_key_id_roundtrip(uuid_bytes in any::<[u8; 16]>()) {
			let uuid = Uuid::from_bytes(uuid_bytes);
			let id = CrashApiKeyId(uuid);
			let s = id.to_string();
			let parsed: CrashApiKeyId = s.parse().unwrap();
			prop_assert_eq!(id, parsed);
		}

		#[test]
		fn valid_slug_starts_with_lowercase(s in "[a-z][a-z0-9_-]{2,49}") {
			prop_assert!(CrashProject::validate_slug(&s));
		}

		#[test]
		fn slug_rejects_uppercase(s in "[A-Z][a-z0-9_-]{2,49}") {
			prop_assert!(!CrashProject::validate_slug(&s));
		}

		#[test]
		fn key_type_roundtrip(key_type in prop_oneof![
			Just(CrashKeyType::Capture),
			Just(CrashKeyType::Admin),
		]) {
			let s = key_type.to_string();
			let parsed: CrashKeyType = s.parse().unwrap();
			prop_assert_eq!(key_type, parsed);
		}
	}
}
