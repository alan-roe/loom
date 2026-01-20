// Copyright (c) 2025 Geoffrey Huntley <ghuntley@ghuntley.com>. All rights reserved.
// SPDX-License-Identifier: Proprietary

//! Core types for the Loom crash analytics system.
//!
//! This crate provides shared types for crash analytics including crash events,
//! issues, stacktraces, and symbolication artifacts. It is used by both the
//! server-side implementation (`loom-server-crash`) and client SDKs.
//!
//! # Overview
//!
//! The crash analytics system supports:
//! - Crash capture for TypeScript (browser + Node) and Rust applications
//! - Issue grouping via fingerprinting to deduplicate similar crashes
//! - Issue lifecycle with unresolved/resolved/ignored/regressed states
//! - Regression detection when resolved issues reappear in new releases
//! - Source map uploads for TypeScript with source context extraction
//! - Rust panic capture with backtrace symbolication
//! - Integration with `loom-analytics` for person identity
//! - Integration with `loom-flags` for active flags at crash time

pub mod breadcrumb;
pub mod context;
pub mod error;
pub mod event;
pub mod fingerprint;
pub mod issue;
pub mod project;
pub mod release;
pub mod symbol;

pub use breadcrumb::{Breadcrumb, BreadcrumbLevel};
pub use context::{BrowserContext, DeviceContext, OsContext, RequestContext, Runtime, UserContext};
pub use error::{CrashError, Result};
pub use event::{CrashEvent, CrashEventId, Frame, Platform, Stacktrace};
pub use fingerprint::compute_fingerprint;
pub use issue::{Issue, IssueId, IssueLevel, IssueMetadata, IssuePriority, IssueStatus};
pub use project::{CrashApiKey, CrashApiKeyId, CrashKeyType, CrashProject, ProjectId};
pub use release::{Release, ReleaseId};
pub use symbol::{ArtifactType, SymbolArtifact, SymbolArtifactId};

// Re-export common ID types
use std::fmt;
use std::str::FromStr;
use uuid::Uuid;

/// Organization ID (for multi-tenant isolation).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct OrgId(pub Uuid);

impl OrgId {
	pub fn new() -> Self {
		Self(Uuid::now_v7())
	}
}

impl Default for OrgId {
	fn default() -> Self {
		Self::new()
	}
}

impl fmt::Display for OrgId {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "{}", self.0)
	}
}

impl FromStr for OrgId {
	type Err = uuid::Error;

	fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
		Ok(Self(Uuid::parse_str(s)?))
	}
}

/// User ID (for audit and assignment).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct UserId(pub Uuid);

impl UserId {
	pub fn new() -> Self {
		Self(Uuid::now_v7())
	}
}

impl Default for UserId {
	fn default() -> Self {
		Self::new()
	}
}

impl fmt::Display for UserId {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "{}", self.0)
	}
}

impl FromStr for UserId {
	type Err = uuid::Error;

	fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
		Ok(Self(Uuid::parse_str(s)?))
	}
}

/// Person ID (from analytics integration).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct PersonId(pub Uuid);

impl PersonId {
	pub fn new() -> Self {
		Self(Uuid::now_v7())
	}
}

impl Default for PersonId {
	fn default() -> Self {
		Self::new()
	}
}

impl fmt::Display for PersonId {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "{}", self.0)
	}
}

impl FromStr for PersonId {
	type Err = uuid::Error;

	fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
		Ok(Self(Uuid::parse_str(s)?))
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use proptest::prelude::*;

	proptest! {
		#[test]
		fn org_id_roundtrip(uuid_bytes in any::<[u8; 16]>()) {
			let uuid = Uuid::from_bytes(uuid_bytes);
			let id = OrgId(uuid);
			let s = id.to_string();
			let parsed: OrgId = s.parse().unwrap();
			prop_assert_eq!(id, parsed);
		}

		#[test]
		fn user_id_roundtrip(uuid_bytes in any::<[u8; 16]>()) {
			let uuid = Uuid::from_bytes(uuid_bytes);
			let id = UserId(uuid);
			let s = id.to_string();
			let parsed: UserId = s.parse().unwrap();
			prop_assert_eq!(id, parsed);
		}

		#[test]
		fn person_id_roundtrip(uuid_bytes in any::<[u8; 16]>()) {
			let uuid = Uuid::from_bytes(uuid_bytes);
			let id = PersonId(uuid);
			let s = id.to_string();
			let parsed: PersonId = s.parse().unwrap();
			prop_assert_eq!(id, parsed);
		}
	}
}
