// Copyright (c) 2025 Geoffrey Huntley <ghuntley@ghuntley.com>. All rights reserved.
// SPDX-License-Identifier: Proprietary

//! Source map parsing and position lookup.
//!
//! Implements the Source Map v3 specification for JavaScript/TypeScript
//! crash symbolication.

use serde::Deserialize;

use crate::error::{Result, SymbolicateError};
use crate::vlq::{decode_vlq_mappings, DecodedMappings};

/// Raw source map JSON structure.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawSourceMap {
	version: u32,
	#[serde(default)]
	file: Option<String>,
	#[serde(default)]
	source_root: Option<String>,
	sources: Vec<String>,
	#[serde(default)]
	sources_content: Option<Vec<Option<String>>>,
	names: Vec<String>,
	mappings: String,
}

/// Parsed source map ready for lookups.
#[derive(Debug, Clone)]
pub struct ParsedSourceMap {
	/// Source map version (should be 3).
	pub version: u32,
	/// Original file name.
	pub file: Option<String>,
	/// Root path prepended to source filenames.
	pub source_root: Option<String>,
	/// List of original source file paths.
	pub sources: Vec<String>,
	/// Optional embedded source content for each source file.
	pub sources_content: Vec<Option<String>>,
	/// List of original identifiers (function/variable names).
	pub names: Vec<String>,
	/// Decoded mappings for position lookup.
	mappings: DecodedMappings,
}

/// Original position information from a source map lookup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OriginalPosition {
	/// Original source file path.
	pub source: String,
	/// Line in the original source (1-indexed for display).
	pub line: u32,
	/// Column in the original source (0-indexed).
	pub column: u32,
	/// Original identifier name if available.
	pub name: Option<String>,
	/// Original source content if embedded.
	pub source_content: Option<String>,
}

impl ParsedSourceMap {
	/// Parse a source map from JSON bytes.
	pub fn from_bytes(data: &[u8]) -> Result<Self> {
		let raw: RawSourceMap = serde_json::from_slice(data)?;

		if raw.version != 3 {
			return Err(SymbolicateError::InvalidSourceMapVersion(raw.version));
		}

		let mappings = decode_vlq_mappings(&raw.mappings)?;
		let sources_content = raw.sources_content.unwrap_or_default();

		Ok(Self {
			version: raw.version,
			file: raw.file,
			source_root: raw.source_root,
			sources: raw.sources,
			sources_content,
			names: raw.names,
			mappings,
		})
	}

	/// Parse a source map from a JSON string.
	pub fn from_str(data: &str) -> Result<Self> {
		Self::from_bytes(data.as_bytes())
	}

	/// Lookup the original position for a generated line and column.
	///
	/// Lines are 1-indexed (as displayed in stack traces), columns are 0-indexed.
	/// Returns None if no mapping exists for this position.
	pub fn lookup(&self, line: u32, column: u32) -> Result<Option<OriginalPosition>> {
		// Convert to 0-indexed line for internal lookup
		let line_0indexed = line.saturating_sub(1);

		let mapping = match self.mappings.find(line_0indexed, column) {
			Some(m) => m,
			None => return Ok(None),
		};

		let source = self
			.sources
			.get(mapping.source_index as usize)
			.ok_or(SymbolicateError::InvalidSourceIndex(mapping.source_index))?
			.clone();

		let source_content = self
			.sources_content
			.get(mapping.source_index as usize)
			.and_then(|c| c.clone());

		let name = mapping
			.name_index
			.and_then(|idx| self.names.get(idx as usize).cloned());

		// Return 1-indexed line for display
		Ok(Some(OriginalPosition {
			source: self.resolve_source_path(&source),
			line: mapping.original_line + 1,
			column: mapping.original_column,
			name,
			source_content,
		}))
	}

	/// Resolve a source path with the source root if present.
	fn resolve_source_path(&self, source: &str) -> String {
		match &self.source_root {
			Some(root) if !root.is_empty() => {
				let root = root.trim_end_matches('/');
				format!("{}/{}", root, source)
			}
			_ => source.to_string(),
		}
	}

	/// Check if this source map has embedded source content.
	pub fn has_sources_content(&self) -> bool {
		self.sources_content.iter().any(|c| c.is_some())
	}

	/// Get the number of source files in this source map.
	pub fn source_count(&self) -> usize {
		self.sources.len()
	}

	/// Get the number of identifier names in this source map.
	pub fn name_count(&self) -> usize {
		self.names.len()
	}

	/// Get the number of mappings in this source map.
	pub fn mapping_count(&self) -> usize {
		self.mappings.len()
	}
}

/// Extract source context lines around a given line number.
///
/// Returns (pre_context, context_line, post_context).
pub fn extract_context(
	source_content: &str,
	line: usize,
	context_lines: usize,
) -> (Vec<String>, String, Vec<String>) {
	let lines: Vec<&str> = source_content.lines().collect();

	// Line is 1-indexed, convert to 0-indexed
	let line_idx = line.saturating_sub(1);

	if line_idx >= lines.len() {
		return (Vec::new(), String::new(), Vec::new());
	}

	let context_line = lines[line_idx].to_string();

	let pre_start = line_idx.saturating_sub(context_lines);
	let pre_context: Vec<String> = lines[pre_start..line_idx]
		.iter()
		.map(|s| s.to_string())
		.collect();

	let post_end = (line_idx + 1 + context_lines).min(lines.len());
	let post_context: Vec<String> = lines[(line_idx + 1)..post_end]
		.iter()
		.map(|s| s.to_string())
		.collect();

	(pre_context, context_line, post_context)
}

#[cfg(test)]
mod tests {
	use super::*;

	fn sample_source_map() -> &'static str {
		r#"{
			"version": 3,
			"file": "out.js",
			"sourceRoot": "",
			"sources": ["src/index.ts"],
			"sourcesContent": ["function hello() {\n  console.log('Hello, World!');\n}\n\nhello();\n"],
			"names": ["hello", "console", "log"],
			"mappings": "AAAA,SAASA,KAAKT,CAAC;AACXC,OAAQ,CAACC,GAAG,CAAC,eAAe,CAAC,CAAC;AAClC,CAAC;AAEDF,KAAK,EAAE,CAAC"
		}"#
	}

	#[test]
	fn test_parse_source_map() {
		let sm = ParsedSourceMap::from_str(sample_source_map()).unwrap();

		assert_eq!(sm.version, 3);
		assert_eq!(sm.file, Some("out.js".to_string()));
		assert_eq!(sm.sources, vec!["src/index.ts"]);
		assert_eq!(sm.names, vec!["hello", "console", "log"]);
		assert!(sm.has_sources_content());
	}

	#[test]
	fn test_lookup_position() {
		let sm = ParsedSourceMap::from_str(sample_source_map()).unwrap();

		// Lookup position in generated code
		let pos = sm.lookup(1, 0).unwrap().unwrap();
		assert_eq!(pos.source, "src/index.ts");
		assert_eq!(pos.line, 1); // 1-indexed
	}

	#[test]
	fn test_extract_context() {
		let source = "line 1\nline 2\nline 3\nline 4\nline 5\nline 6\nline 7";

		let (pre, context, post) = extract_context(source, 4, 2);

		assert_eq!(pre, vec!["line 2", "line 3"]);
		assert_eq!(context, "line 4");
		assert_eq!(post, vec!["line 5", "line 6"]);
	}

	#[test]
	fn test_extract_context_at_start() {
		let source = "line 1\nline 2\nline 3";

		let (pre, context, post) = extract_context(source, 1, 2);

		assert!(pre.is_empty());
		assert_eq!(context, "line 1");
		assert_eq!(post, vec!["line 2", "line 3"]);
	}

	#[test]
	fn test_extract_context_at_end() {
		let source = "line 1\nline 2\nline 3";

		let (pre, context, post) = extract_context(source, 3, 2);

		assert_eq!(pre, vec!["line 1", "line 2"]);
		assert_eq!(context, "line 3");
		assert!(post.is_empty());
	}

	#[test]
	fn test_invalid_version() {
		let json = r#"{"version": 2, "sources": [], "names": [], "mappings": ""}"#;
		let result = ParsedSourceMap::from_str(json);
		assert!(matches!(
			result,
			Err(SymbolicateError::InvalidSourceMapVersion(2))
		));
	}

	#[test]
	fn test_source_root_resolution() {
		let json = r#"{
			"version": 3,
			"sourceRoot": "src/",
			"sources": ["index.ts"],
			"names": [],
			"mappings": "AAAA"
		}"#;
		let sm = ParsedSourceMap::from_str(json).unwrap();

		let pos = sm.lookup(1, 0).unwrap().unwrap();
		assert_eq!(pos.source, "src/index.ts");
	}
}
