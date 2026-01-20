// Copyright (c) 2025 Geoffrey Huntley <ghuntley@ghuntley.com>. All rights reserved.
// SPDX-License-Identifier: Proprietary

//! Backtrace capture and parsing for Rust panics.

use loom_crash_core::{Frame, Stacktrace};
use rustc_demangle::demangle;
use std::backtrace::Backtrace;

/// Parse a Rust backtrace into a Stacktrace.
pub fn parse_backtrace(backtrace: &Backtrace) -> Stacktrace {
	let bt_string = format!("{:#}", backtrace);
	let frames = parse_backtrace_string(&bt_string);
	Stacktrace { frames }
}

/// Parse backtrace string output into frames.
fn parse_backtrace_string(bt_string: &str) -> Vec<Frame> {
	let mut frames = Vec::new();

	for line in bt_string.lines() {
		let line = line.trim();

		// Skip frame numbers and empty lines
		if line.is_empty() || line.chars().next().map(|c| c.is_ascii_digit()).unwrap_or(false) {
			continue;
		}

		// Try to parse as a frame
		if let Some(frame) = parse_frame_line(line) {
			frames.push(frame);
		}
	}

	frames
}

/// Parse a single backtrace line into a Frame.
fn parse_frame_line(line: &str) -> Option<Frame> {
	let line = line.trim();

	// Skip lines that start with "at" (these are location info for the previous frame)
	if line.starts_with("at ") {
		return None;
	}

	// Try to extract function name
	// Backtrace format is typically: "   N: function_name"
	// or "function_name"
	let function_part = if let Some(idx) = line.find(':') {
		// Check if this looks like a frame number prefix
		let prefix = &line[..idx];
		if prefix.trim().parse::<u32>().is_ok() {
			line[idx + 1..].trim()
		} else {
			line
		}
	} else {
		line
	};

	if function_part.is_empty() {
		return None;
	}

	// Demangle the function name
	let demangled = demangle(function_part).to_string();

	// Extract module from demangled name
	// e.g., "loom_server::handlers::crash::capture" -> "loom_server::handlers::crash"
	let module = demangled.rfind("::").map(|idx| demangled[..idx].to_string());

	// Determine if this is in-app code
	// Heuristic: consider it in-app if it doesn't start with std::, core::, alloc::
	// or other common system crates
	let in_app = is_in_app_frame(&demangled);

	Some(Frame {
		function: Some(demangled),
		module,
		filename: None,
		abs_path: None,
		lineno: None,
		colno: None,
		context_line: None,
		pre_context: Vec::new(),
		post_context: Vec::new(),
		in_app,
		instruction_addr: None,
		symbol_addr: None,
	})
}

/// Determine if a frame is from user application code vs standard library.
fn is_in_app_frame(function: &str) -> bool {
	// System/std library prefixes to exclude
	const SYSTEM_PREFIXES: &[&str] = &[
		"std::",
		"core::",
		"alloc::",
		"<std::",
		"<core::",
		"<alloc::",
		"tokio::",
		"<tokio::",
		"futures::",
		"<futures::",
		"async_trait::",
		"tracing::",
		"<tracing::",
		"backtrace::",
		"<backtrace::",
		"panic_unwind::",
		"<panic_unwind::",
		"rust_begin_unwind",
		"rust_panic",
		"__rust_",
		"_rust_",
	];

	// Also exclude common runtime functions
	const SYSTEM_CONTAINS: &[&str] = &[
		"::panic::",
		"::panicking::",
		"::thread::",
		"::rt::",
		"::runtime::",
		"::sys_common::",
	];

	for prefix in SYSTEM_PREFIXES {
		if function.starts_with(prefix) {
			return false;
		}
	}

	for contains in SYSTEM_CONTAINS {
		if function.contains(contains) {
			return false;
		}
	}

	true
}

/// Capture a fresh backtrace and parse it.
pub fn capture_backtrace() -> Stacktrace {
	let backtrace = Backtrace::force_capture();
	parse_backtrace(&backtrace)
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_is_in_app_frame_excludes_std() {
		assert!(!is_in_app_frame("std::panic::panic_any"));
		assert!(!is_in_app_frame("core::panicking::panic"));
		assert!(!is_in_app_frame("alloc::vec::Vec::push"));
		assert!(!is_in_app_frame("tokio::runtime::Runtime::block_on"));
	}

	#[test]
	fn test_is_in_app_frame_includes_user_code() {
		assert!(is_in_app_frame("my_app::main"));
		assert!(is_in_app_frame("loom_crash::client::CrashClient::capture"));
		assert!(is_in_app_frame("foo::bar::baz"));
	}

	#[test]
	fn test_parse_frame_line_demangled() {
		let frame = parse_frame_line("my_app::handlers::process").unwrap();
		assert_eq!(frame.function, Some("my_app::handlers::process".to_string()));
		assert_eq!(frame.module, Some("my_app::handlers".to_string()));
		assert!(frame.in_app);
	}

	#[test]
	fn test_parse_frame_line_with_number() {
		let frame = parse_frame_line("  5: my_app::main").unwrap();
		assert_eq!(frame.function, Some("my_app::main".to_string()));
	}

	#[test]
	fn test_capture_backtrace() {
		// Just verify it doesn't panic - the actual frames captured
		// depend on compilation mode and debug info availability
		let _stacktrace = capture_backtrace();
	}
}
