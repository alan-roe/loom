// Copyright (c) 2025 Geoffrey Huntley <ghuntley@ghuntley.com>. All rights reserved.
// SPDX-License-Identifier: Proprietary

use crate::config::LocalConfig;
use crate::error::{LocalError, LocalResult};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WeaverMetadata {
	pub id: String,
	pub name: String,
	pub image: String,
	pub labels: BTreeMap<String, String>,
	pub env_vars: Vec<(String, String)>,
	pub created_at: DateTime<Utc>,
	#[serde(default)]
	pub ttl_hours: Option<u32>,
	#[serde(default)]
	pub working_dir: PathBuf,
}

impl WeaverMetadata {
	pub fn new(
		id: String,
		image: String,
		labels: BTreeMap<String, String>,
		working_dir: PathBuf,
	) -> Self {
		let name = format!("weaver-{id}");
		Self {
			id,
			name,
			image,
			labels,
			env_vars: Vec::new(),
			created_at: Utc::now(),
			ttl_hours: None,
			working_dir,
		}
	}

	pub fn with_env_vars(mut self, env_vars: Vec<(String, String)>) -> Self {
		self.env_vars = env_vars;
		self
	}

	pub fn with_ttl(mut self, ttl_hours: u32) -> Self {
		self.ttl_hours = Some(ttl_hours);
		self
	}

	pub fn is_expired(&self) -> bool {
		if let Some(ttl) = self.ttl_hours {
			let expires_at = self.created_at + chrono::Duration::hours(ttl as i64);
			Utc::now() > expires_at
		} else {
			false
		}
	}

	/// Returns the effective working directory, handling backward compatibility
	/// for legacy metadata files that lack a working_dir field.
	pub fn effective_working_dir(&self, config: &LocalConfig) -> PathBuf {
		if self.working_dir.as_os_str().is_empty() {
			config.weaver_dir(&self.id)
		} else {
			self.working_dir.clone()
		}
	}
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WeaverStatus {
	Running,
	Succeeded,
	Failed,
	Unknown,
}

impl WeaverStatus {
	pub fn to_phase(&self) -> &'static str {
		match self {
			WeaverStatus::Running => "Running",
			WeaverStatus::Succeeded => "Succeeded",
			WeaverStatus::Failed => "Failed",
			WeaverStatus::Unknown => "Unknown",
		}
	}
}

#[derive(Debug)]
pub struct LocalWeaver {
	pub metadata: WeaverMetadata,
	pub status: WeaverStatus,
	pub dir: PathBuf,
}

impl LocalWeaver {
	pub fn session_name(&self) -> String {
		format!("weaver-{}", self.metadata.id)
	}

	pub fn load(config: &LocalConfig, id: &str) -> LocalResult<Self> {
		let loom_dir = config.loom_dir(id);
		if !loom_dir.exists() {
			return Err(LocalError::WeaverNotFound { id: id.to_string() });
		}

		let metadata_path = config.metadata_path(id);
		let metadata_json = fs::read_to_string(&metadata_path).map_err(|e| {
			LocalError::MetadataError {
				message: format!("failed to read metadata at {}: {}", metadata_path.display(), e),
			}
		})?;

		let metadata: WeaverMetadata =
			serde_json::from_str(&metadata_json).map_err(|e| LocalError::MetadataError {
				message: format!("failed to parse metadata: {e}"),
			})?;

		// Resolve the actual working directory from metadata
		let dir = metadata.effective_working_dir(config);

		Ok(Self {
			metadata,
			status: WeaverStatus::Unknown,
			dir,
		})
	}

	pub fn create(config: &LocalConfig, metadata: WeaverMetadata) -> LocalResult<Self> {
		let working_dir = metadata.effective_working_dir(config);
		let is_fallback_dir = working_dir == config.weaver_dir(&metadata.id);

		// Metadata always goes in the centralized location for discoverability
		let loom_dir = config.loom_dir(&metadata.id);

		// For fallback directories, the weaver_dir shouldn't already exist
		if is_fallback_dir && working_dir.exists() {
			return Err(LocalError::WeaverExists {
				id: metadata.id.clone(),
			});
		}

		// Create the .loom directory for metadata
		fs::create_dir_all(&loom_dir).map_err(LocalError::Io)?;

		let metadata_path = config.metadata_path(&metadata.id);
		let metadata_json =
			serde_json::to_string_pretty(&metadata).map_err(|e| LocalError::MetadataError {
				message: format!("failed to serialize metadata: {e}"),
			})?;

		// Atomic write: write to temp file then rename (spec §3, §9)
		let temp_path = metadata_path.with_extension("json.tmp");
		{
			let mut file = fs::File::create(&temp_path)?;
			file.write_all(metadata_json.as_bytes())?;
			file.sync_all()?; // Ensure data reaches disk
		}
		fs::rename(&temp_path, &metadata_path)?;

		let output_log = config.output_log_path(&metadata.id);
		fs::write(&output_log, "")?;

		Ok(Self {
			metadata,
			status: WeaverStatus::Unknown,
			dir: working_dir,
		})
	}

	pub fn delete(config: &LocalConfig, id: &str) -> LocalResult<()> {
		let dir = config.weaver_dir(id);
		if dir.exists() {
			fs::remove_dir_all(&dir)?;
		}
		Ok(())
	}

	/// Deletes only the .loom metadata directory, preserving the user's working directory.
	/// Use this when the weaver was created with an existing directory.
	pub fn delete_metadata_only(config: &LocalConfig, id: &str) -> LocalResult<()> {
		let loom_dir = config.loom_dir(id);
		if loom_dir.exists() {
			fs::remove_dir_all(&loom_dir)?;
		}
		Ok(())
	}

	pub fn list_all(config: &LocalConfig) -> LocalResult<Vec<String>> {
		let base_dir = &config.base_dir;
		if !base_dir.exists() {
			return Ok(Vec::new());
		}

		let mut ids = Vec::new();
		for entry in fs::read_dir(base_dir)? {
			let entry = entry?;
			let name = entry.file_name();
			let name_str = name.to_string_lossy();
			if let Some(id) = name_str.strip_prefix("weaver-") {
				if config.metadata_path(id).exists() {
					ids.push(id.to_string());
				}
			}
		}
		Ok(ids)
	}
}
