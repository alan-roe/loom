// Copyright (c) 2025 Geoffrey Huntley <ghuntley@ghuntley.com>. All rights reserved.
// SPDX-License-Identifier: Proprietary

//! Source map symbolication engine for Loom crash analytics.
//!
//! This crate provides functionality for:
//! - Parsing JavaScript/TypeScript source maps (v3)
//! - Decoding minified stack traces to original source positions
//! - Extracting source context for display
//! - Demangling Rust symbols
//!
//! # Example
//!
//! ```
//! use loom_crash_symbolicate::{SourceMapProcessor, InMemoryArtifacts, ParsedSourceMap};
//! use loom_crash_core::{Frame, Stacktrace, Platform};
//!
//! // Create an artifact store and add source maps
//! let mut artifacts = InMemoryArtifacts::new();
//!
//! // Add a source map (normally loaded from database)
//! let source_map_json = r#"{
//!     "version": 3,
//!     "sources": ["src/app.ts"],
//!     "names": [],
//!     "mappings": "AAAA"
//! }"#;
//! artifacts.add("1.0.0", "bundle.js", source_map_json.as_bytes().to_vec());
//!
//! // Create the processor
//! let processor = SourceMapProcessor::new(artifacts);
//!
//! // Symbolicate a stacktrace
//! let stacktrace = Stacktrace {
//!     frames: vec![Frame {
//!         filename: Some("bundle.js".to_string()),
//!         lineno: Some(1),
//!         colno: Some(0),
//!         ..Frame::default()
//!     }],
//! };
//!
//! let symbolicated = processor.symbolicate(&stacktrace, Platform::JavaScript, Some("1.0.0"), None).unwrap();
//! ```

pub mod error;
pub mod processor;
pub mod rust;
pub mod sourcemap;
pub mod vlq;

// Re-export main types
pub use error::{Result, SymbolicateError};
pub use processor::{ArtifactLookup, InMemoryArtifacts, SourceMapProcessor};
pub use sourcemap::{extract_context, OriginalPosition, ParsedSourceMap};
pub use vlq::{decode_vlq_mappings, decode_vlq_segment, DecodedMappings, Mapping};
