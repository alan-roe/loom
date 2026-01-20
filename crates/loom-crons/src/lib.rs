// Copyright (c) 2025 Geoffrey Huntley <ghuntley@ghuntley.com>. All rights reserved.
// SPDX-License-Identifier: Proprietary

//! Cron monitoring SDK for Rust applications.
//!
//! This crate provides cron/job monitoring capabilities for Rust applications,
//! including check-in based monitoring and a convenient wrapper for async functions.
//!
//! # Quick Start
//!
//! ```ignore
//! use loom_crons::{CronsClient, CheckInOk, CheckInError};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Initialize the crons client
//!     let crons = CronsClient::builder()
//!         .auth_token("your_auth_token")  // from `loom login`
//!         .base_url("https://loom.ghuntley.com")
//!         .org_id("org_xxx")
//!         .build()?;
//!
//!     // Manual check-in pattern
//!     let checkin_id = crons.checkin_start("daily-cleanup").await?;
//!
//!     let start = std::time::Instant::now();
//!     match run_daily_cleanup().await {
//!         Ok(result) => {
//!             crons.checkin_ok(checkin_id, CheckInOk {
//!                 duration_ms: Some(start.elapsed().as_millis() as u64),
//!                 output: Some(format!("Processed {} records", result)),
//!             }).await?;
//!         }
//!         Err(e) => {
//!             crons.checkin_error(checkin_id, CheckInError {
//!                 duration_ms: Some(start.elapsed().as_millis() as u64),
//!                 exit_code: Some(1),
//!                 output: Some(e.to_string()),
//!                 crash_event_id: None,
//!             }).await?;
//!         }
//!     }
//!
//!     // Convenience wrapper
//!     crons.with_monitor("email-digest", || async {
//!         send_email_digest().await
//!     }).await?;
//!
//!     Ok(())
//! }
//!
//! async fn run_daily_cleanup() -> Result<u32, std::io::Error> {
//!     // ...
//!     Ok(1000)
//! }
//!
//! async fn send_email_digest() -> Result<(), std::io::Error> {
//!     // ...
//!     Ok(())
//! }
//! ```
//!
//! # Features
//!
//! - **Manual Check-ins**: Start and complete check-ins manually for fine-grained control
//! - **Convenience Wrapper**: Use `with_monitor` to automatically handle check-in lifecycle
//! - **Duration Tracking**: Automatic duration calculation when using the wrapper
//! - **Error Integration**: Optional crash client integration for linking failures to crash events
//! - **Output Capture**: Attach job output to check-ins for debugging
//!
//! # Authentication
//!
//! The crons client uses bearer token authentication. You can obtain a token by running:
//!
//! ```bash
//! loom login --server-url https://loom.ghuntley.com
//! ```
//!
//! The token is stored in your XDG config directory.

mod client;
mod error;

pub use client::{CheckInError, CheckInOk, ClientConfig, CronsClient, CronsClientBuilder};
pub use error::{CronsSdkError, Result};

// Re-export core types for convenience
pub use loom_crons_core::{
	CheckIn, CheckInId, CheckInSource, CheckInStatus, Monitor, MonitorHealth, MonitorId,
	MonitorSchedule, MonitorStatus, OrgId,
};
