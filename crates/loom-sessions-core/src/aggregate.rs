// Copyright (c) 2025 Geoffrey Huntley <ghuntley@ghuntley.com>. All rights reserved.
// SPDX-License-Identifier: Proprietary

//! Session aggregate types for hourly rollups.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Unique identifier for a session aggregate.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct SessionAggregateId(pub Uuid);

impl SessionAggregateId {
	#[must_use]
	pub fn new() -> Self {
		Self(Uuid::now_v7())
	}

	#[must_use]
	pub fn as_uuid(&self) -> &Uuid {
		&self.0
	}
}

impl Default for SessionAggregateId {
	fn default() -> Self {
		Self::new()
	}
}

impl std::fmt::Display for SessionAggregateId {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		write!(f, "{}", self.0)
	}
}

impl std::str::FromStr for SessionAggregateId {
	type Err = uuid::Error;

	fn from_str(s: &str) -> Result<Self, Self::Err> {
		Ok(Self(Uuid::parse_str(s)?))
	}
}

/// Hourly rollup of session data for efficient querying.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct SessionAggregate {
	pub id: SessionAggregateId,
	pub org_id: String,
	pub project_id: String,

	/// Release version (None for sessions without release)
	pub release: Option<String>,
	/// Environment (production, staging, etc.)
	pub environment: String,
	/// Hour timestamp (truncated to hour, e.g., "2026-01-18T12:00:00Z")
	pub hour: DateTime<Utc>,

	/// Total sessions in this hour
	pub total_sessions: u64,
	/// Sessions that ended normally
	pub exited_sessions: u64,
	/// Sessions with unhandled errors
	pub crashed_sessions: u64,
	/// Sessions that ended unexpectedly
	pub abnormal_sessions: u64,
	/// Sessions with handled errors
	pub errored_sessions: u64,

	/// Unique users in this hour
	pub unique_users: u64,
	/// Users who experienced crashes
	pub crashed_users: u64,

	/// Total duration of all sessions (ms)
	pub total_duration_ms: u64,
	/// Minimum session duration (ms)
	pub min_duration_ms: Option<u64>,
	/// Maximum session duration (ms)
	pub max_duration_ms: Option<u64>,

	/// Total handled errors
	pub total_errors: u64,
	/// Total unhandled errors (crashes)
	pub total_crashes: u64,

	pub updated_at: DateTime<Utc>,
}

impl SessionAggregate {
	/// Calculate the crash-free session rate.
	#[must_use]
	pub fn crash_free_session_rate(&self) -> f64 {
		if self.total_sessions > 0 {
			((self.total_sessions - self.crashed_sessions) as f64 / self.total_sessions as f64) * 100.0
		} else {
			100.0
		}
	}

	/// Calculate the crash-free user rate.
	#[must_use]
	pub fn crash_free_user_rate(&self) -> f64 {
		if self.unique_users > 0 {
			((self.unique_users - self.crashed_users) as f64 / self.unique_users as f64) * 100.0
		} else {
			100.0
		}
	}

	/// Calculate average session duration.
	#[must_use]
	pub fn average_duration_ms(&self) -> Option<u64> {
		if self.total_sessions > 0 {
			Some(self.total_duration_ms / self.total_sessions)
		} else {
			None
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use chrono::TimeZone;
	use proptest::prelude::*;

	proptest! {
		#[test]
		fn session_aggregate_id_roundtrip(uuid_bytes in any::<[u8; 16]>()) {
			let uuid = Uuid::from_bytes(uuid_bytes);
			let id = SessionAggregateId(uuid);
			let s = id.to_string();
			let parsed: SessionAggregateId = s.parse().unwrap();
			prop_assert_eq!(id, parsed);
		}
	}

	fn create_test_aggregate() -> SessionAggregate {
		SessionAggregate {
			id: SessionAggregateId::new(),
			org_id: "org-1".to_string(),
			project_id: "proj-1".to_string(),
			release: Some("1.0.0".to_string()),
			environment: "production".to_string(),
			hour: Utc.with_ymd_and_hms(2026, 1, 19, 12, 0, 0).unwrap(),
			total_sessions: 100,
			exited_sessions: 90,
			crashed_sessions: 5,
			abnormal_sessions: 2,
			errored_sessions: 3,
			unique_users: 80,
			crashed_users: 4,
			total_duration_ms: 500_000,
			min_duration_ms: Some(1000),
			max_duration_ms: Some(30000),
			total_errors: 10,
			total_crashes: 5,
			updated_at: Utc::now(),
		}
	}

	#[test]
	fn test_crash_free_session_rate() {
		let agg = create_test_aggregate();
		let rate = agg.crash_free_session_rate();
		assert!((rate - 95.0).abs() < 0.01);
	}

	#[test]
	fn test_crash_free_user_rate() {
		let agg = create_test_aggregate();
		let rate = agg.crash_free_user_rate();
		assert!((rate - 95.0).abs() < 0.01);
	}

	#[test]
	fn test_average_duration() {
		let agg = create_test_aggregate();
		assert_eq!(agg.average_duration_ms(), Some(5000));
	}

	#[test]
	fn test_empty_aggregate_rates() {
		let mut agg = create_test_aggregate();
		agg.total_sessions = 0;
		agg.unique_users = 0;

		assert_eq!(agg.crash_free_session_rate(), 100.0);
		assert_eq!(agg.crash_free_user_rate(), 100.0);
		assert_eq!(agg.average_duration_ms(), None);
	}
}
