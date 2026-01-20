// Copyright (c) 2025 Geoffrey Huntley <ghuntley@ghuntley.com>. All rights reserved.
// SPDX-License-Identifier: Proprietary

//! Crash analytics server implementation for Loom.
//!
//! This crate provides the server-side implementation for the crash analytics
//! system, including:
//!
//! - Repository layer for database operations
//! - Issue fingerprinting and grouping
//! - SSE broadcasting for real-time updates
//! - API key hashing and verification

pub mod api_key;
pub mod error;
pub mod repository;
pub mod sse;
pub mod symbolicate;

pub use api_key::{
	generate_api_key, hash_api_key, verify_api_key, KEY_PREFIX_ADMIN, KEY_PREFIX_CAPTURE,
};
pub use error::{CrashServerError, Result};
pub use repository::{CrashRepository, SqliteCrashRepository};
pub use sse::{CrashBroadcaster, CrashBroadcasterConfig, CrashStreamEvent};
pub use symbolicate::SymbolicationService;
