// Copyright (c) 2025 Geoffrey Huntley <ghuntley@ghuntley.com>. All rights reserved.
// SPDX-License-Identifier: Proprietary

//! Server-side symbolication service for crash stack traces.
//!
//! This module provides the `SymbolicationService` which integrates
//! the symbolication processor with the artifact repository.

use std::sync::Arc;
use tracing::{debug, info, instrument, warn};

use loom_crash_core::{ArtifactType, Platform, ProjectId, Stacktrace};
use loom_crash_symbolicate::{ArtifactLookup, ParsedSourceMap, SourceMapProcessor};

use crate::error::Result;
use crate::CrashRepository;

/// Symbolication service that uses the artifact repository.
///
/// This service provides stack trace symbolication by looking up
/// source maps from the database.
pub struct SymbolicationService<R: CrashRepository + 'static> {
	repo: Arc<R>,
}

impl<R: CrashRepository + 'static> SymbolicationService<R> {
	pub fn new(repo: Arc<R>) -> Self {
		Self { repo }
	}

	/// Symbolicate a stack trace for the given project and release.
	///
	/// This method:
	/// 1. Looks up source maps for each frame's filename
	/// 2. Decodes minified positions to original positions
	/// 3. Extracts source context if available
	/// 4. Updates artifact last_accessed timestamps
	#[instrument(skip(self, stacktrace), fields(frame_count = stacktrace.frames.len()))]
	pub async fn symbolicate(
		&self,
		stacktrace: &Stacktrace,
		platform: Platform,
		project_id: ProjectId,
		release: Option<&str>,
		dist: Option<&str>,
	) -> Result<Stacktrace> {
		let release = match release {
			Some(r) => r,
			None => {
				debug!("No release specified, skipping symbolication");
				return Ok(stacktrace.clone());
			}
		};

		match platform {
			Platform::JavaScript | Platform::Node => {
				self.symbolicate_js(stacktrace, project_id, release, dist)
					.await
			}
			Platform::Rust => {
				// Rust demangling doesn't require database lookup
				let artifacts = EmptyArtifacts;
				let processor = SourceMapProcessor::new(artifacts);
				processor
					.symbolicate_rust(stacktrace)
					.map_err(|e| crate::error::CrashServerError::Symbolication(e.to_string()))
			}
		}
	}

	/// Symbolicate a JavaScript/TypeScript stack trace.
	#[instrument(skip(self, stacktrace), fields(frame_count = stacktrace.frames.len()))]
	async fn symbolicate_js(
		&self,
		stacktrace: &Stacktrace,
		project_id: ProjectId,
		release: &str,
		dist: Option<&str>,
	) -> Result<Stacktrace> {
		let mut symbolicated = stacktrace.clone();

		for frame in &mut symbolicated.frames {
			let (filename, lineno, colno) =
				match (&frame.filename, frame.lineno, frame.colno) {
					(Some(f), Some(l), Some(c)) => (f.clone(), l, c),
					_ => continue, // Can't symbolicate without position info
				};

			// Look up source map for this file
			let source_map_name = if filename.ends_with(".map") {
				filename.clone()
			} else {
				format!("{}.map", filename)
			};

			let artifact = match self
				.repo
				.get_artifact_by_name(project_id, release, &source_map_name, dist)
				.await
			{
				Ok(Some(a)) if a.artifact_type == ArtifactType::SourceMap => a,
				Ok(Some(_)) => {
					debug!(filename = %filename, "Artifact is not a source map");
					continue;
				}
				Ok(None) => {
					// Try without .map extension (in case the artifact was uploaded with exact filename)
					match self
						.repo
						.get_artifact_by_name(project_id, release, &filename, dist)
						.await
					{
						Ok(Some(a)) if a.artifact_type == ArtifactType::SourceMap => a,
						_ => {
							debug!(filename = %filename, release = %release, "No source map found");
							continue;
						}
					}
				}
				Err(e) => {
					warn!(error = %e, filename = %filename, "Failed to look up source map");
					continue;
				}
			};

			// Update last accessed timestamp (fire and forget)
			let repo = self.repo.clone();
			let artifact_id = artifact.id;
			tokio::spawn(async move {
				if let Err(e) = repo.update_artifact_last_accessed(artifact_id).await {
					warn!(error = %e, "Failed to update artifact last_accessed");
				}
			});

			// Parse source map
			let source_map = match ParsedSourceMap::from_bytes(&artifact.data) {
				Ok(sm) => sm,
				Err(e) => {
					warn!(error = %e, artifact_id = %artifact.id, "Failed to parse source map");
					continue;
				}
			};

			// Lookup original position
			match source_map.lookup(lineno, colno) {
				Ok(Some(original)) => {
					info!(
						filename = %filename,
						lineno = lineno,
						colno = colno,
						original_source = %original.source,
						original_line = original.line,
						"Symbolicated frame"
					);

					frame.filename = Some(original.source.clone());
					frame.lineno = Some(original.line);
					frame.colno = Some(original.column);

					if let Some(name) = original.name {
						frame.function = Some(name);
					}

					// Extract source context if available
					if let Some(content) = original.source_content {
						let (pre, line, post) =
							loom_crash_symbolicate::extract_context(&content, original.line as usize, 5);
						frame.pre_context = pre;
						frame.context_line = Some(line);
						frame.post_context = post;
					}
				}
				Ok(None) => {
					debug!(
						filename = %filename,
						lineno = lineno,
						colno = colno,
						"No mapping found in source map"
					);
				}
				Err(e) => {
					warn!(error = %e, "Source map lookup failed");
				}
			}
		}

		Ok(symbolicated)
	}
}

/// Empty artifact lookup for platforms that don't need source maps.
struct EmptyArtifacts;

impl ArtifactLookup for EmptyArtifacts {
	fn find_source_map(
		&self,
		_release: &str,
		_dist: Option<&str>,
		_filename: &str,
	) -> Option<&[u8]> {
		None
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::SqliteCrashRepository;
	use loom_crash_core::Frame;
	use sqlx::SqlitePool;
	use tempfile::tempdir;

	async fn create_test_repo() -> (SqlitePool, SqliteCrashRepository) {
		let dir = tempdir().unwrap();
		let db_path = dir.path().join("test.db");
		let url = format!("sqlite:{}?mode=rwc", db_path.display());

		let pool = SqlitePool::connect(&url).await.unwrap();

		// Create tables
		sqlx::query(include_str!(
			"../../loom-server/migrations/033_crash_analytics.sql"
		))
		.execute(&pool)
		.await
		.unwrap_or_default(); // Ignore errors if tables exist

		(pool.clone(), SqliteCrashRepository::new(pool))
	}

	#[allow(dead_code)]
	fn create_test_source_map() -> Vec<u8> {
		r#"{
			"version": 3,
			"file": "bundle.js",
			"sources": ["src/app.ts"],
			"sourcesContent": ["function greet(name: string) {\n  console.log('Hello, ' + name);\n}\n\ngreet('World');\n"],
			"names": ["greet", "name", "console", "log"],
			"mappings": "AAAA,SAASA,MAAMC,IAAY;AACzBC,QAAQ,CAACC,GAAG,CAAC,UAAU,GAAGF,IAAI,CAAC,CAAC;AAClC,CAAC;AAEDD,MAAM,CAAC,OAAO,CAAC,CAAC"
		}"#.as_bytes().to_vec()
	}

	#[tokio::test]
	async fn test_symbolicate_rust_no_db_needed() {
		let (_pool, repo) = create_test_repo().await;
		let service = SymbolicationService::new(Arc::new(repo));

		let stacktrace = Stacktrace {
			frames: vec![Frame {
				function: Some("regular_function".to_string()),
				..Frame::default()
			}],
		};

		let result = service
			.symbolicate(
				&stacktrace,
				Platform::Rust,
				ProjectId::new(),
				Some("1.0.0"),
				None,
			)
			.await
			.unwrap();

		// Non-mangled function should remain unchanged
		assert_eq!(
			result.frames[0].function,
			Some("regular_function".to_string())
		);
	}

	#[tokio::test]
	async fn test_symbolicate_without_release() {
		let (_pool, repo) = create_test_repo().await;
		let service = SymbolicationService::new(Arc::new(repo));

		let stacktrace = Stacktrace {
			frames: vec![Frame {
				filename: Some("bundle.js".to_string()),
				lineno: Some(1),
				colno: Some(0),
				..Frame::default()
			}],
		};

		// Without release, symbolication should be skipped
		let result = service
			.symbolicate(
				&stacktrace,
				Platform::JavaScript,
				ProjectId::new(),
				None,
				None,
			)
			.await
			.unwrap();

		// Frame should be unchanged
		assert_eq!(result.frames[0].filename, Some("bundle.js".to_string()));
	}
}
