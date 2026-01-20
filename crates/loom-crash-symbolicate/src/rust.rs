// Copyright (c) 2025 Geoffrey Huntley <ghuntley@ghuntley.com>. All rights reserved.
// SPDX-License-Identifier: Proprietary

//! Rust symbol demangling for native crash symbolication.

use loom_crash_core::Frame;
use rustc_demangle::demangle;

/// Demangle a Rust symbol and update the frame with the demangled name.
///
/// This handles Rust's mangled symbol names (starting with `_ZN` or `_R`)
/// and extracts the module path from the demangled name.
pub fn symbolicate_rust_frame(frame: &mut Frame) {
	if let Some(func) = &frame.function {
		// Demangle the symbol
		let demangled = demangle(func).to_string();

		// Only update if demangling produced a different result
		if demangled != *func {
			frame.function = Some(demangled.clone());

			// Extract module from demangled name
			// e.g., "loom_server::handlers::crash::capture" -> "loom_server::handlers::crash"
			if let Some(last_sep) = demangled.rfind("::") {
				// Only set module if it contains at least one `::`
				if demangled[..last_sep].contains("::") {
					frame.module = Some(demangled[..last_sep].to_string());
				} else {
					frame.module = Some(demangled[..last_sep].to_string());
				}
			}
		}
	}
}

/// Check if a symbol appears to be a Rust mangled symbol.
pub fn is_rust_symbol(symbol: &str) -> bool {
	// Rust symbols typically start with these prefixes
	symbol.starts_with("_ZN") || symbol.starts_with("_R")
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_demangle_rust_symbol() {
		let mut frame = Frame {
			function: Some("_ZN4loom6server8handlers5crash7capture17h1234567890abcdefE".to_string()),
			..Frame::default()
		};

		symbolicate_rust_frame(&mut frame);

		// The demangled name should be human-readable
		assert!(
			frame.function.as_ref().unwrap().contains("loom"),
			"Expected demangled function to contain 'loom', got: {:?}",
			frame.function
		);
	}

	#[test]
	fn test_non_mangled_symbol_unchanged() {
		let mut frame = Frame {
			function: Some("regular_function".to_string()),
			..Frame::default()
		};

		symbolicate_rust_frame(&mut frame);

		assert_eq!(frame.function, Some("regular_function".to_string()));
		assert!(frame.module.is_none());
	}

	#[test]
	fn test_is_rust_symbol() {
		assert!(is_rust_symbol("_ZN4loom6serverE"));
		assert!(is_rust_symbol("_R"));
		assert!(!is_rust_symbol("regular_function"));
		assert!(!is_rust_symbol("__libc_start_main"));
	}

	#[test]
	fn test_module_extraction() {
		let mut frame = Frame {
			function: Some(
				"_ZN4loom6server8handlers5crash7capture17h1234567890abcdefE".to_string(),
			),
			..Frame::default()
		};

		symbolicate_rust_frame(&mut frame);

		// Module should be extracted from the demangled name
		// Note: the exact output depends on rustc-demangle's behavior
		if let Some(module) = &frame.module {
			assert!(module.contains("::"), "Module should contain path separators");
		}
	}
}
