// Copyright (c) 2025 Geoffrey Huntley <ghuntley@ghuntley.com>. All rights reserved.
// SPDX-License-Identifier: Proprietary

//! Crash event types.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use std::str::FromStr;
use uuid::Uuid;

use crate::breadcrumb::Breadcrumb;
use crate::context::{
	BrowserContext, DeviceContext, OsContext, RequestContext, Runtime, UserContext,
};
use crate::error::CrashError;
use crate::issue::IssueId;
use crate::project::ProjectId;
use crate::{OrgId, PersonId};

/// Unique identifier for a crash event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct CrashEventId(pub Uuid);

impl CrashEventId {
	pub fn new() -> Self {
		Self(Uuid::now_v7())
	}
}

impl Default for CrashEventId {
	fn default() -> Self {
		Self::new()
	}
}

impl fmt::Display for CrashEventId {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "{}", self.0)
	}
}

impl FromStr for CrashEventId {
	type Err = uuid::Error;

	fn from_str(s: &str) -> Result<Self, Self::Err> {
		Ok(Self(Uuid::parse_str(s)?))
	}
}

/// A single crash occurrence captured by the SDK.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct CrashEvent {
	pub id: CrashEventId,
	pub org_id: OrgId,
	pub project_id: ProjectId,
	/// Assigned after fingerprinting
	pub issue_id: Option<IssueId>,

	/// Identity (from loom-analytics integration)
	pub person_id: Option<PersonId>,
	pub distinct_id: String,

	/// Error information
	pub exception_type: String,
	pub exception_value: String,
	pub stacktrace: Stacktrace,
	/// Pre-symbolication (minified)
	pub raw_stacktrace: Option<Stacktrace>,

	/// Environment context
	pub release: Option<String>,
	pub dist: Option<String>,
	pub environment: String,
	pub platform: Platform,
	pub runtime: Option<Runtime>,
	pub server_name: Option<String>,

	/// Custom context
	pub tags: HashMap<String, String>,
	pub extra: serde_json::Value,
	pub user_context: Option<UserContext>,
	pub device_context: Option<DeviceContext>,
	pub browser_context: Option<BrowserContext>,
	pub os_context: Option<OsContext>,

	/// Feature flags active at crash time (from loom-flags integration)
	pub active_flags: HashMap<String, String>,

	/// Request context (for server-side crashes)
	pub request: Option<RequestContext>,

	/// Breadcrumbs (events leading up to crash)
	pub breadcrumbs: Vec<Breadcrumb>,

	/// When crash occurred
	pub timestamp: DateTime<Utc>,
	/// When server received it
	pub received_at: DateTime<Utc>,
}

impl Default for CrashEvent {
	fn default() -> Self {
		Self {
			id: CrashEventId::new(),
			org_id: OrgId::new(),
			project_id: ProjectId::new(),
			issue_id: None,
			person_id: None,
			distinct_id: String::new(),
			exception_type: String::new(),
			exception_value: String::new(),
			stacktrace: Stacktrace::default(),
			raw_stacktrace: None,
			release: None,
			dist: None,
			environment: "production".to_string(),
			platform: Platform::JavaScript,
			runtime: None,
			server_name: None,
			tags: HashMap::new(),
			extra: serde_json::Value::Object(serde_json::Map::new()),
			user_context: None,
			device_context: None,
			browser_context: None,
			os_context: None,
			active_flags: HashMap::new(),
			request: None,
			breadcrumbs: Vec::new(),
			timestamp: Utc::now(),
			received_at: Utc::now(),
		}
	}
}

/// Stack trace containing multiple frames.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct Stacktrace {
	pub frames: Vec<Frame>,
}

/// A single stack frame.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct Frame {
	/// Function/method name
	pub function: Option<String>,
	/// Module/crate/package
	pub module: Option<String>,
	/// Relative filename
	pub filename: Option<String>,
	/// Absolute path (if available)
	pub abs_path: Option<String>,
	pub lineno: Option<u32>,
	pub colno: Option<u32>,

	/// Source context (populated after symbolication)
	pub context_line: Option<String>,
	/// 5 lines before
	pub pre_context: Vec<String>,
	/// 5 lines after
	pub post_context: Vec<String>,

	/// User code vs dependency
	pub in_app: bool,
	/// For native code
	pub instruction_addr: Option<String>,
	pub symbol_addr: Option<String>,
}

impl Default for Frame {
	fn default() -> Self {
		Self {
			function: None,
			module: None,
			filename: None,
			abs_path: None,
			lineno: None,
			colno: None,
			context_line: None,
			pre_context: Vec::new(),
			post_context: Vec::new(),
			in_app: false,
			instruction_addr: None,
			symbol_addr: None,
		}
	}
}

/// Platform/language the crash originated from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum Platform {
	/// Browser JavaScript
	JavaScript,
	/// Node.js
	Node,
	/// Rust
	Rust,
}

impl fmt::Display for Platform {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::JavaScript => write!(f, "javascript"),
			Self::Node => write!(f, "node"),
			Self::Rust => write!(f, "rust"),
		}
	}
}

impl FromStr for Platform {
	type Err = CrashError;

	fn from_str(s: &str) -> Result<Self, Self::Err> {
		match s {
			"javascript" => Ok(Self::JavaScript),
			"node" => Ok(Self::Node),
			"rust" => Ok(Self::Rust),
			_ => Err(CrashError::InvalidPlatform(s.to_string())),
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use proptest::prelude::*;

	proptest! {
		#[test]
		fn crash_event_id_roundtrip(uuid_bytes in any::<[u8; 16]>()) {
			let uuid = Uuid::from_bytes(uuid_bytes);
			let id = CrashEventId(uuid);
			let s = id.to_string();
			let parsed: CrashEventId = s.parse().unwrap();
			prop_assert_eq!(id, parsed);
		}

		#[test]
		fn platform_roundtrip(platform in prop_oneof![
			Just(Platform::JavaScript),
			Just(Platform::Node),
			Just(Platform::Rust),
		]) {
			let s = platform.to_string();
			let parsed: Platform = s.parse().unwrap();
			prop_assert_eq!(platform, parsed);
		}
	}

	#[test]
	fn default_crash_event() {
		let event = CrashEvent::default();
		assert!(event.issue_id.is_none());
		assert_eq!(event.environment, "production");
	}
}
