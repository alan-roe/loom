// Copyright (c) 2025 Geoffrey Huntley <ghuntley@ghuntley.com>. All rights reserved.
// SPDX-License-Identifier: Proprietary

//! Crash analytics SDK for Rust applications.
//!
//! This crate provides crash reporting capabilities for Rust applications,
//! including automatic panic capture and manual error reporting.
//!
//! # Quick Start
//!
//! ```ignore
//! use loom_crash::{CrashClient, Breadcrumb, BreadcrumbLevel, UserContext};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Initialize the crash client
//!     let crash = CrashClient::builder()
//!         .auth_token("your_auth_token")  // from `loom login`
//!         .base_url("https://loom.ghuntley.com")
//!         .project_id("proj_xxx")
//!         .release(env!("CARGO_PKG_VERSION"))
//!         .environment("production")
//!         .build()?;
//!
//!     // Install panic hook for automatic crash reporting
//!     crash.install_panic_hook();
//!
//!     // Set user context (optional)
//!     crash.set_user(UserContext {
//!         id: Some("user_123".to_string()),
//!         email: Some("user@example.com".to_string()),
//!         ..Default::default()
//!     }).await;
//!
//!     // Add global tags
//!     crash.set_tag("server", "web-01").await;
//!
//!     // Add breadcrumb
//!     crash.add_breadcrumb(Breadcrumb {
//!         category: "startup".into(),
//!         message: Some("Application started".into()),
//!         level: BreadcrumbLevel::Info,
//!         ..Default::default()
//!     }).await;
//!
//!     // Your application code here...
//!
//!     // Manual capture (for recoverable errors)
//!     if let Err(e) = risky_operation() {
//!         crash.capture_error(&e).await?;
//!     }
//!
//!     // Shutdown gracefully
//!     crash.shutdown().await?;
//!     Ok(())
//! }
//!
//! fn risky_operation() -> Result<(), std::io::Error> {
//!     // ...
//!     Ok(())
//! }
//! ```
//!
//! # Features
//!
//! - **Panic Hook**: Automatically captures panic information with full backtraces
//! - **Manual Capture**: Report errors and messages manually with `capture_error` and `capture_message`
//! - **Breadcrumbs**: Track events leading up to a crash
//! - **Context**: Attach user, device, and custom context to all events
//! - **Tags**: Add global tags for filtering and grouping
//! - **Rust Symbol Demangling**: Automatic demangling of Rust symbols in backtraces
//!
//! # Authentication
//!
//! The crash client uses bearer token authentication. You can obtain a token by running:
//!
//! ```bash
//! loom login --server-url https://loom.ghuntley.com
//! ```
//!
//! The token is stored in your XDG config directory.

mod backtrace;
mod client;
mod error;
mod panic_hook;
mod session;

pub use client::{CaptureResponse, ClientConfig, CrashClient, CrashClientBuilder};
pub use error::{CrashSdkError, Result};
pub use session::SessionConfig;

// Re-export core types for convenience
pub use loom_crash_core::{
	Breadcrumb, BreadcrumbLevel, DeviceContext, Frame, OsContext, Platform, Stacktrace,
	UserContext,
};
