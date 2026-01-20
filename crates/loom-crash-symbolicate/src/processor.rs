// Copyright (c) 2025 Geoffrey Huntley <ghuntley@ghuntley.com>. All rights reserved.
// SPDX-License-Identifier: Proprietary

//! Symbolication processor for crash stack traces.
//!
//! This module provides the high-level API for symbolicating crash events
//! using uploaded source maps.

use std::collections::HashMap;
use tracing::{debug, instrument, warn};

use loom_crash_core::{Frame, Platform, Stacktrace};

use crate::error::Result;
use crate::rust::symbolicate_rust_frame;
use crate::sourcemap::{extract_context, ParsedSourceMap};

/// Number of context lines to include before and after the error line.
const CONTEXT_LINES: usize = 5;

/// Artifact lookup trait for retrieving source maps.
///
/// Implementations provide access to uploaded symbol artifacts.
pub trait ArtifactLookup: Send + Sync {
	/// Find a source map for the given release and filename.
	fn find_source_map(
		&self,
		release: &str,
		dist: Option<&str>,
		filename: &str,
	) -> Option<&[u8]>;
}

/// In-memory artifact store for testing and simple use cases.
#[derive(Debug, Default)]
pub struct InMemoryArtifacts {
	/// Maps (release, filename) to source map data.
	artifacts: HashMap<(String, String), Vec<u8>>,
}

impl InMemoryArtifacts {
	pub fn new() -> Self {
		Self::default()
	}

	pub fn add(&mut self, release: &str, filename: &str, data: Vec<u8>) {
		self.artifacts
			.insert((release.to_string(), filename.to_string()), data);
	}
}

impl ArtifactLookup for InMemoryArtifacts {
	fn find_source_map(
		&self,
		release: &str,
		_dist: Option<&str>,
		filename: &str,
	) -> Option<&[u8]> {
		// Try exact match first
		if let Some(data) = self.artifacts.get(&(release.to_string(), filename.to_string())) {
			return Some(data);
		}

		// Try with .map extension
		let map_filename = format!("{}.map", filename);
		if let Some(data) = self.artifacts.get(&(release.to_string(), map_filename)) {
			return Some(data);
		}

		None
	}
}

/// Symbolication processor for crash stack traces.
#[derive(Debug)]
pub struct SourceMapProcessor<A: ArtifactLookup> {
	artifacts: A,
	/// Cache of parsed source maps for efficiency.
	cache: std::sync::Mutex<HashMap<String, ParsedSourceMap>>,
}

impl<A: ArtifactLookup> SourceMapProcessor<A> {
	pub fn new(artifacts: A) -> Self {
		Self {
			artifacts,
			cache: std::sync::Mutex::new(HashMap::new()),
		}
	}

	/// Symbolicate a JavaScript/TypeScript stacktrace.
	///
	/// This method attempts to:
	/// 1. Find source maps for each frame's filename
	/// 2. Decode the minified positions to original positions
	/// 3. Extract source context if available
	#[instrument(skip(self, stacktrace), fields(frame_count = stacktrace.frames.len()))]
	pub fn symbolicate_js(
		&self,
		stacktrace: &Stacktrace,
		release: &str,
		dist: Option<&str>,
	) -> Result<Stacktrace> {
		let mut symbolicated = stacktrace.clone();

		for frame in &mut symbolicated.frames {
			self.symbolicate_js_frame(frame, release, dist)?;
		}

		Ok(symbolicated)
	}

	/// Symbolicate a single JavaScript frame.
	fn symbolicate_js_frame(
		&self,
		frame: &mut Frame,
		release: &str,
		dist: Option<&str>,
	) -> Result<()> {
		let (filename, lineno, colno) = match (
			&frame.filename,
			frame.lineno,
			frame.colno,
		) {
			(Some(f), Some(l), Some(c)) => (f.clone(), l, c),
			_ => return Ok(()), // Can't symbolicate without position info
		};

		// Find source map for this file
		let source_map_data = match self.artifacts.find_source_map(release, dist, &filename) {
			Some(data) => data,
			None => {
				debug!(filename = %filename, release = %release, "No source map found");
				return Ok(());
			}
		};

		// Parse source map (with caching)
		let cache_key = format!("{}:{}", release, filename);
		let source_map = {
			let mut cache = self.cache.lock().unwrap();
			if let Some(sm) = cache.get(&cache_key) {
				sm.clone()
			} else {
				match ParsedSourceMap::from_bytes(source_map_data) {
					Ok(sm) => {
						cache.insert(cache_key.clone(), sm.clone());
						sm
					}
					Err(e) => {
						warn!(error = %e, filename = %filename, "Failed to parse source map");
						return Ok(());
					}
				}
			}
		};

		// Lookup original position
		if let Some(original) = source_map.lookup(lineno, colno)? {
			debug!(
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

			// Extract source context if embedded
			if let Some(content) = original.source_content {
				let (pre, line, post) =
					extract_context(&content, original.line as usize, CONTEXT_LINES);
				frame.pre_context = pre;
				frame.context_line = Some(line);
				frame.post_context = post;
			}
		}

		Ok(())
	}

	/// Symbolicate a Rust stacktrace.
	///
	/// This primarily handles symbol demangling.
	#[instrument(skip(self, stacktrace), fields(frame_count = stacktrace.frames.len()))]
	pub fn symbolicate_rust(&self, stacktrace: &Stacktrace) -> Result<Stacktrace> {
		let mut symbolicated = stacktrace.clone();

		for frame in &mut symbolicated.frames {
			symbolicate_rust_frame(frame);
		}

		Ok(symbolicated)
	}

	/// Symbolicate a stacktrace based on platform.
	#[instrument(skip(self, stacktrace), fields(platform = ?platform))]
	pub fn symbolicate(
		&self,
		stacktrace: &Stacktrace,
		platform: Platform,
		release: Option<&str>,
		dist: Option<&str>,
	) -> Result<Stacktrace> {
		match platform {
			Platform::JavaScript | Platform::Node => {
				if let Some(rel) = release {
					self.symbolicate_js(stacktrace, rel, dist)
				} else {
					debug!("No release specified, skipping JavaScript symbolication");
					Ok(stacktrace.clone())
				}
			}
			Platform::Rust => self.symbolicate_rust(stacktrace),
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

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

	#[test]
	fn test_symbolicate_js_frame() {
		let mut artifacts = InMemoryArtifacts::new();
		artifacts.add("1.0.0", "bundle.js", create_test_source_map());

		let processor = SourceMapProcessor::new(artifacts);

		let stacktrace = Stacktrace {
			frames: vec![Frame {
				filename: Some("bundle.js".to_string()),
				lineno: Some(1),
				colno: Some(0),
				..Frame::default()
			}],
		};

		let result = processor.symbolicate_js(&stacktrace, "1.0.0", None).unwrap();

		assert_eq!(result.frames.len(), 1);
		let frame = &result.frames[0];

		// Should be symbolicated to original source
		assert_eq!(frame.filename, Some("src/app.ts".to_string()));
		assert_eq!(frame.lineno, Some(1));

		// Should have source context
		assert!(frame.context_line.is_some());
	}

	#[test]
	fn test_symbolicate_with_no_source_map() {
		let artifacts = InMemoryArtifacts::new(); // Empty
		let processor = SourceMapProcessor::new(artifacts);

		let stacktrace = Stacktrace {
			frames: vec![Frame {
				filename: Some("unknown.js".to_string()),
				lineno: Some(1),
				colno: Some(0),
				..Frame::default()
			}],
		};

		let result = processor.symbolicate_js(&stacktrace, "1.0.0", None).unwrap();

		// Frame should be unchanged
		assert_eq!(result.frames[0].filename, Some("unknown.js".to_string()));
	}

	#[test]
	fn test_symbolicate_rust_stacktrace() {
		let artifacts = InMemoryArtifacts::new();
		let processor = SourceMapProcessor::new(artifacts);

		let stacktrace = Stacktrace {
			frames: vec![Frame {
				function: Some("regular_function".to_string()),
				..Frame::default()
			}],
		};

		let result = processor.symbolicate_rust(&stacktrace).unwrap();

		// Non-mangled function should remain unchanged
		assert_eq!(
			result.frames[0].function,
			Some("regular_function".to_string())
		);
	}

	#[test]
	fn test_symbolicate_by_platform() {
		let mut artifacts = InMemoryArtifacts::new();
		artifacts.add("1.0.0", "bundle.js", create_test_source_map());

		let processor = SourceMapProcessor::new(artifacts);

		let stacktrace = Stacktrace {
			frames: vec![Frame {
				filename: Some("bundle.js".to_string()),
				lineno: Some(1),
				colno: Some(0),
				..Frame::default()
			}],
		};

		// JavaScript platform should use source maps
		let result = processor
			.symbolicate(&stacktrace, Platform::JavaScript, Some("1.0.0"), None)
			.unwrap();
		assert_eq!(result.frames[0].filename, Some("src/app.ts".to_string()));

		// Rust platform should not try source maps
		let result = processor
			.symbolicate(&stacktrace, Platform::Rust, Some("1.0.0"), None)
			.unwrap();
		assert_eq!(result.frames[0].filename, Some("bundle.js".to_string()));
	}

	#[test]
	fn test_source_map_with_map_extension() {
		let mut artifacts = InMemoryArtifacts::new();
		// Add with .map extension
		artifacts.add("1.0.0", "bundle.js.map", create_test_source_map());

		let processor = SourceMapProcessor::new(artifacts);

		let stacktrace = Stacktrace {
			frames: vec![Frame {
				filename: Some("bundle.js".to_string()),
				lineno: Some(1),
				colno: Some(0),
				..Frame::default()
			}],
		};

		let result = processor.symbolicate_js(&stacktrace, "1.0.0", None).unwrap();

		// Should still find the source map via .map extension fallback
		assert_eq!(result.frames[0].filename, Some("src/app.ts".to_string()));
	}
}
