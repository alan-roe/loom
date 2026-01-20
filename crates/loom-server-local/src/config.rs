// Copyright (c) 2025 Geoffrey Huntley <ghuntley@ghuntley.com>. All rights reserved.
// SPDX-License-Identifier: Proprietary

use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct LocalConfig {
	pub base_dir: PathBuf,
	pub default_image: String,
	pub server_url: String,
}

impl LocalConfig {
	pub fn new(server_url: impl Into<String>) -> Self {
		let base_dir = std::env::var("LOOM_LOCAL_WEAVERS_DIR")
			.map(PathBuf::from)
			.unwrap_or_else(|_| {
				let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("/tmp"));
				home.join("loom-weavers")
			});
		Self {
			base_dir,
			default_image: "loom:latest".to_string(),
			server_url: server_url.into(),
		}
	}

	pub fn with_base_dir(mut self, base_dir: PathBuf) -> Self {
		self.base_dir = base_dir;
		self
	}

	pub fn with_default_image(mut self, image: impl Into<String>) -> Self {
		self.default_image = image.into();
		self
	}

	pub fn weaver_dir(&self, weaver_id: &str) -> PathBuf {
		self.base_dir.join(format!("weaver-{weaver_id}"))
	}

	pub fn loom_dir(&self, weaver_id: &str) -> PathBuf {
		self.weaver_dir(weaver_id).join(".loom")
	}

	pub fn metadata_path(&self, weaver_id: &str) -> PathBuf {
		self.loom_dir(weaver_id).join("metadata.json")
	}

	pub fn pid_path(&self, weaver_id: &str) -> PathBuf {
		self.loom_dir(weaver_id).join("pid")
	}

	pub fn output_log_path(&self, weaver_id: &str) -> PathBuf {
		self.loom_dir(weaver_id).join("output.log")
	}

	/// Resolves the working directory for a weaver, checking multiple sources:
	/// 1. LOOM_WORKING_DIR env var (if the path exists)
	/// 2. loom.dev/working-dir annotation (if the path exists)
	/// 3. Fallback to the default weaver directory
	pub fn resolve_working_dir(
		&self,
		weaver_id: &str,
		env_vars: &[(String, String)],
		annotations: &std::collections::BTreeMap<String, String>,
	) -> PathBuf {
		// Check LOOM_WORKING_DIR env var
		if let Some((_, dir)) = env_vars.iter().find(|(k, _)| k == "LOOM_WORKING_DIR") {
			let path = PathBuf::from(dir);
			if path.exists() {
				return path;
			}
		}

		// Check loom.dev/working-dir annotation
		if let Some(dir) = annotations.get("loom.dev/working-dir") {
			let path = PathBuf::from(dir);
			if path.exists() {
				return path;
			}
		}

		// Fallback to default weaver directory
		self.weaver_dir(weaver_id)
	}
}

mod dirs {
	use std::path::PathBuf;

	pub fn home_dir() -> Option<PathBuf> {
		std::env::var_os("HOME").map(PathBuf::from)
	}
}
