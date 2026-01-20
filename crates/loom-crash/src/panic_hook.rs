// Copyright (c) 2025 Geoffrey Huntley <ghuntley@ghuntley.com>. All rights reserved.
// SPDX-License-Identifier: Proprietary

//! Panic hook integration for automatic crash reporting.

use std::backtrace::Backtrace;
use std::panic::PanicHookInfo;
use std::sync::Arc;

use crate::backtrace::parse_backtrace;
use crate::client::CrashClientInner;

/// Install a panic hook that reports crashes to the Loom server.
///
/// This function wraps the existing panic hook and reports panic information
/// before calling the original hook.
pub fn install_panic_hook(client: Arc<CrashClientInner>) {
	let default_hook = std::panic::take_hook();

	std::panic::set_hook(Box::new(move |info| {
		// Capture backtrace immediately
		let backtrace = Backtrace::force_capture();

		// Report the panic
		report_panic(&client, info, &backtrace);

		// Call the default hook
		default_hook(info);
	}));
}

/// Report a panic to the crash analytics server.
fn report_panic(client: &CrashClientInner, info: &PanicHookInfo<'_>, backtrace: &Backtrace) {
	// Record crash in session tracker (for release health metrics)
	client.record_crash_sync();

	// Extract panic message
	let message = extract_panic_message(info);

	// Extract location if available
	let location = info.location().map(|l| format!("{}:{}:{}", l.file(), l.line(), l.column()));

	// Parse backtrace into frames
	let stacktrace = parse_backtrace(backtrace);

	// Try to send synchronously (we're panicking, async won't complete)
	// Use a best-effort approach - don't panic if sending fails
	if let Err(e) = client.send_panic_sync(&message, location.as_deref(), stacktrace) {
		eprintln!("Failed to report panic to crash analytics: {}", e);
	}
}

/// Extract the panic message from panic info.
fn extract_panic_message(info: &PanicHookInfo<'_>) -> String {
	if let Some(s) = info.payload().downcast_ref::<&str>() {
		s.to_string()
	} else if let Some(s) = info.payload().downcast_ref::<String>() {
		s.clone()
	} else {
		"Box<dyn Any>".to_string()
	}
}

#[cfg(test)]
mod tests {
	#[test]
	fn test_panic_hook_compiles() {
		// We can't easily test the panic hook without triggering a panic,
		// but we can verify the module compiles correctly
	}
}
