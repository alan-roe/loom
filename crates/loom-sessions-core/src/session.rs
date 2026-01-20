// Copyright (c) 2025 Geoffrey Huntley <ghuntley@ghuntley.com>. All rights reserved.
// SPDX-License-Identifier: Proprietary

//! Session types for app session tracking.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Unique identifier for a session.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct SessionId(pub Uuid);

impl SessionId {
	#[must_use]
	pub fn new() -> Self {
		Self(Uuid::now_v7())
	}

	#[must_use]
	pub fn as_uuid(&self) -> &Uuid {
		&self.0
	}
}

impl Default for SessionId {
	fn default() -> Self {
		Self::new()
	}
}

impl std::fmt::Display for SessionId {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		write!(f, "{}", self.0)
	}
}

impl std::str::FromStr for SessionId {
	type Err = uuid::Error;

	fn from_str(s: &str) -> Result<Self, Self::Err> {
		Ok(Self(Uuid::parse_str(s)?))
	}
}

/// A single user engagement period.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct Session {
	pub id: SessionId,
	pub org_id: String,
	pub project_id: String,

	/// Person ID from analytics (if identified)
	pub person_id: Option<String>,
	/// Anonymous/device identifier
	pub distinct_id: String,

	pub status: SessionStatus,

	/// Release version
	pub release: Option<String>,
	/// Environment (production, staging, etc.)
	pub environment: String,

	/// Handled errors during session
	pub error_count: u32,
	/// Unhandled errors (crashes)
	pub crash_count: u32,
	/// Shorthand: crash_count > 0
	pub crashed: bool,

	pub started_at: DateTime<Utc>,
	pub ended_at: Option<DateTime<Utc>>,
	pub duration_ms: Option<u64>,

	pub platform: Platform,
	pub user_agent: Option<String>,

	/// Whether this session was sampled
	pub sampled: bool,
	/// Rate at which it was sampled
	pub sample_rate: f64,

	pub created_at: DateTime<Utc>,
	pub updated_at: DateTime<Utc>,
}

impl Session {
	/// Determine the final status of this session.
	#[must_use]
	pub fn determine_status(&self) -> SessionStatus {
		if self.crash_count > 0 {
			SessionStatus::Crashed
		} else if self.error_count > 0 {
			SessionStatus::Errored
		} else if self.ended_at.is_some() {
			SessionStatus::Exited
		} else {
			SessionStatus::Active
		}
	}
}

/// Session status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum SessionStatus {
	/// Session is active (ongoing)
	Active,
	/// Session ended normally
	Exited,
	/// Session had at least one unhandled error
	Crashed,
	/// Session ended unexpectedly (no end signal received)
	Abnormal,
	/// Session had handled errors but completed normally
	Errored,
}

impl std::fmt::Display for SessionStatus {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			SessionStatus::Active => write!(f, "active"),
			SessionStatus::Exited => write!(f, "exited"),
			SessionStatus::Crashed => write!(f, "crashed"),
			SessionStatus::Abnormal => write!(f, "abnormal"),
			SessionStatus::Errored => write!(f, "errored"),
		}
	}
}

impl std::str::FromStr for SessionStatus {
	type Err = crate::error::SessionsError;

	fn from_str(s: &str) -> Result<Self, Self::Err> {
		match s {
			"active" => Ok(SessionStatus::Active),
			"exited" => Ok(SessionStatus::Exited),
			"crashed" => Ok(SessionStatus::Crashed),
			"abnormal" => Ok(SessionStatus::Abnormal),
			"errored" => Ok(SessionStatus::Errored),
			_ => Err(crate::error::SessionsError::InvalidStatus(s.to_string())),
		}
	}
}

/// Platform type for sessions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum Platform {
	/// Browser JavaScript
	JavaScript,
	/// Node.js
	Node,
	/// Rust application
	Rust,
	/// Python application
	Python,
	/// Other/unknown
	Other,
}

impl std::fmt::Display for Platform {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			Platform::JavaScript => write!(f, "javascript"),
			Platform::Node => write!(f, "node"),
			Platform::Rust => write!(f, "rust"),
			Platform::Python => write!(f, "python"),
			Platform::Other => write!(f, "other"),
		}
	}
}

impl std::str::FromStr for Platform {
	type Err = crate::error::SessionsError;

	fn from_str(s: &str) -> Result<Self, Self::Err> {
		match s {
			"javascript" => Ok(Platform::JavaScript),
			"node" => Ok(Platform::Node),
			"rust" => Ok(Platform::Rust),
			"python" => Ok(Platform::Python),
			"other" => Ok(Platform::Other),
			_ => Err(crate::error::SessionsError::InvalidPlatform(s.to_string())),
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use proptest::prelude::*;

	proptest! {
		#[test]
		fn session_id_roundtrip(uuid_bytes in any::<[u8; 16]>()) {
			let uuid = Uuid::from_bytes(uuid_bytes);
			let id = SessionId(uuid);
			let s = id.to_string();
			let parsed: SessionId = s.parse().unwrap();
			prop_assert_eq!(id, parsed);
		}

		#[test]
		fn session_status_roundtrip(status in prop_oneof![
			Just(SessionStatus::Active),
			Just(SessionStatus::Exited),
			Just(SessionStatus::Crashed),
			Just(SessionStatus::Abnormal),
			Just(SessionStatus::Errored),
		]) {
			let s = status.to_string();
			let parsed: SessionStatus = s.parse().unwrap();
			prop_assert_eq!(status, parsed);
		}

		#[test]
		fn platform_roundtrip(platform in prop_oneof![
			Just(Platform::JavaScript),
			Just(Platform::Node),
			Just(Platform::Rust),
			Just(Platform::Python),
			Just(Platform::Other),
		]) {
			let s = platform.to_string();
			let parsed: Platform = s.parse().unwrap();
			prop_assert_eq!(platform, parsed);
		}
	}

	#[test]
	fn test_session_id_new() {
		let id = SessionId::new();
		assert!(!id.to_string().is_empty());
	}

	#[test]
	fn test_session_id_parse() {
		let id = SessionId::new();
		let parsed: SessionId = id.to_string().parse().unwrap();
		assert_eq!(id, parsed);
	}

	#[test]
	fn test_session_status_display() {
		assert_eq!(SessionStatus::Active.to_string(), "active");
		assert_eq!(SessionStatus::Crashed.to_string(), "crashed");
	}

	#[test]
	fn test_session_status_parse() {
		assert_eq!(
			"active".parse::<SessionStatus>().unwrap(),
			SessionStatus::Active
		);
		assert_eq!(
			"crashed".parse::<SessionStatus>().unwrap(),
			SessionStatus::Crashed
		);
	}

	#[test]
	fn test_platform_display() {
		assert_eq!(Platform::JavaScript.to_string(), "javascript");
		assert_eq!(Platform::Rust.to_string(), "rust");
	}

	#[test]
	fn test_platform_parse() {
		assert_eq!(
			"javascript".parse::<Platform>().unwrap(),
			Platform::JavaScript
		);
		assert_eq!("rust".parse::<Platform>().unwrap(), Platform::Rust);
	}
}
