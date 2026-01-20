// Copyright (c) 2025 Geoffrey Huntley <ghuntley@ghuntley.com>. All rights reserved.
// SPDX-License-Identifier: Proprietary

use crate::error::{LocalError, LocalResult};
use std::path::Path;
use std::process::Command;

pub struct TmuxSession {
	pub name: String,
}

impl TmuxSession {
	pub fn new(name: impl Into<String>) -> Self {
		Self { name: name.into() }
	}

	pub fn exists(&self) -> LocalResult<bool> {
		let output = Command::new("tmux")
			.args(["has-session", "-t", &self.name])
			.output()
			.map_err(|e| LocalError::TmuxError {
				message: format!("failed to check session: {e}"),
			})?;

		Ok(output.status.success())
	}

	pub fn create(&self, working_dir: &Path) -> LocalResult<()> {
		let output = Command::new("tmux")
			.args([
				"new-session",
				"-d",
				"-s",
				&self.name,
				"-c",
				working_dir.to_str().unwrap_or("."),
			])
			.output()
			.map_err(|e| LocalError::TmuxError {
				message: format!("failed to create session: {e}"),
			})?;

		if !output.status.success() {
			let stderr = String::from_utf8_lossy(&output.stderr);
			return Err(LocalError::TmuxError {
				message: format!("tmux new-session failed: {stderr}"),
			});
		}

		Ok(())
	}

	pub fn kill(&self) -> LocalResult<()> {
		let output = Command::new("tmux")
			.args(["kill-session", "-t", &self.name])
			.output()
			.map_err(|e| LocalError::TmuxError {
				message: format!("failed to kill session: {e}"),
			})?;

		if !output.status.success() {
			let stderr = String::from_utf8_lossy(&output.stderr);
			if !stderr.contains("session not found") && !stderr.contains("can't find session") {
				return Err(LocalError::TmuxError {
					message: format!("tmux kill-session failed: {stderr}"),
				});
			}
		}

		Ok(())
	}

	pub fn send_keys(&self, keys: &str) -> LocalResult<()> {
		let output = Command::new("tmux")
			.args(["send-keys", "-t", &self.name, keys, "Enter"])
			.output()
			.map_err(|e| LocalError::TmuxError {
				message: format!("failed to send keys: {e}"),
			})?;

		if !output.status.success() {
			let stderr = String::from_utf8_lossy(&output.stderr);
			return Err(LocalError::TmuxError {
				message: format!("tmux send-keys failed: {stderr}"),
			});
		}

		Ok(())
	}

	pub fn get_pane_pid(&self) -> LocalResult<Option<u32>> {
		let output = Command::new("tmux")
			.args(["display-message", "-t", &self.name, "-p", "#{pane_pid}"])
			.output()
			.map_err(|e| LocalError::TmuxError {
				message: format!("failed to get pane pid: {e}"),
			})?;

		if !output.status.success() {
			return Ok(None);
		}

		let stdout = String::from_utf8_lossy(&output.stdout);
		let pid = stdout.trim().parse::<u32>().ok();
		Ok(pid)
	}

	pub fn is_pane_dead(&self) -> LocalResult<bool> {
		let output = Command::new("tmux")
			.args(["display-message", "-t", &self.name, "-p", "#{pane_dead}"])
			.output()
			.map_err(|e| LocalError::TmuxError {
				message: format!("failed to check pane status: {e}"),
			})?;

		if !output.status.success() {
			return Ok(true);
		}

		let stdout = String::from_utf8_lossy(&output.stdout);
		Ok(stdout.trim() == "1")
	}

	pub fn pipe_pane(&self, output_file: &Path) -> LocalResult<()> {
		let output = Command::new("tmux")
			.args([
				"pipe-pane",
				"-t",
				&self.name,
				"-o",
				&format!("cat >> {}", output_file.display()),
			])
			.output()
			.map_err(|e| LocalError::TmuxError {
				message: format!("failed to pipe pane: {e}"),
			})?;

		if !output.status.success() {
			let stderr = String::from_utf8_lossy(&output.stderr);
			return Err(LocalError::TmuxError {
				message: format!("tmux pipe-pane failed: {stderr}"),
			});
		}

		Ok(())
	}
}

pub fn check_tmux_available() -> LocalResult<()> {
	let output = Command::new("tmux").arg("-V").output().map_err(|e| {
		LocalError::TmuxError {
			message: format!("tmux not found: {e}"),
		}
	})?;

	if !output.status.success() {
		return Err(LocalError::TmuxError {
			message: "tmux not available".to_string(),
		});
	}

	tracing::debug!(
		tmux_version = %String::from_utf8_lossy(&output.stdout).trim(),
		"tmux available"
	);

	Ok(())
}

pub fn list_sessions() -> LocalResult<Vec<String>> {
	let output = Command::new("tmux")
		.args(["list-sessions", "-F", "#{session_name}"])
		.output()
		.map_err(|e| LocalError::TmuxError {
			message: format!("failed to list sessions: {e}"),
		})?;

	if !output.status.success() {
		let stderr = String::from_utf8_lossy(&output.stderr);
		if stderr.contains("no server running") || stderr.contains("no sessions") {
			return Ok(Vec::new());
		}
		return Err(LocalError::TmuxError {
			message: format!("tmux list-sessions failed: {stderr}"),
		});
	}

	let stdout = String::from_utf8_lossy(&output.stdout);
	let sessions: Vec<String> = stdout.lines().map(|s| s.to_string()).collect();
	Ok(sessions)
}
