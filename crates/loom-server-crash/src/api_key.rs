// Copyright (c) 2025 Geoffrey Huntley <ghuntley@ghuntley.com>. All rights reserved.
// SPDX-License-Identifier: Proprietary

//! API key hashing and verification using Argon2.
//!
//! This module provides functions to hash and verify crash API keys using
//! the Argon2 password hashing algorithm.

use argon2::{
	password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
	Argon2,
};

use crate::error::{CrashServerError, Result};

/// API key prefix for capture-only keys.
pub const KEY_PREFIX_CAPTURE: &str = "loom_crash_capture_";
/// API key prefix for admin keys.
pub const KEY_PREFIX_ADMIN: &str = "loom_crash_admin_";

/// Generates a new API key with the given prefix.
///
/// The key format is: `{prefix}{random_hex}` where random_hex is 32 hex chars.
pub fn generate_api_key(prefix: &str) -> String {
	use std::fmt::Write;

	let mut rng = OsRng;
	let mut random_bytes = [0u8; 16];
	use rand_core::RngCore;
	rng.fill_bytes(&mut random_bytes);

	let mut key = String::with_capacity(prefix.len() + 32);
	key.push_str(prefix);
	for byte in random_bytes {
		write!(key, "{byte:02x}").unwrap();
	}
	key
}

/// Hashes an API key using Argon2 with a random salt.
///
/// Each call produces a different hash due to random salts, but the hash
/// can be verified against the original key using [`verify_api_key`].
pub fn hash_api_key(key: &str) -> Result<String> {
	let salt = SaltString::generate(&mut OsRng);
	let argon2 = Argon2::default();

	argon2
		.hash_password(key.as_bytes(), &salt)
		.map(|hash| hash.to_string())
		.map_err(|_| CrashServerError::ApiKeyHash)
}

/// Verifies a raw API key against a stored Argon2 hash.
///
/// Returns `true` if the key matches, `false` otherwise.
pub fn verify_api_key(key: &str, hash: &str) -> Result<bool> {
	let parsed_hash = PasswordHash::new(hash).map_err(|_| CrashServerError::InvalidApiKey)?;

	Ok(Argon2::default()
		.verify_password(key.as_bytes(), &parsed_hash)
		.is_ok())
}

#[cfg(test)]
mod tests {
	use super::*;
	use proptest::prelude::*;

	#[test]
	fn test_generate_api_key_capture() {
		let key = generate_api_key(KEY_PREFIX_CAPTURE);
		assert!(key.starts_with(KEY_PREFIX_CAPTURE));
		assert_eq!(key.len(), KEY_PREFIX_CAPTURE.len() + 32);
	}

	#[test]
	fn test_generate_api_key_admin() {
		let key = generate_api_key(KEY_PREFIX_ADMIN);
		assert!(key.starts_with(KEY_PREFIX_ADMIN));
		assert_eq!(key.len(), KEY_PREFIX_ADMIN.len() + 32);
	}

	#[test]
	fn test_hash_and_verify() {
		let key = "loom_crash_capture_abc123def456abc123def456abc123de";

		let hash = hash_api_key(key).unwrap();
		assert!(hash.starts_with("$argon2"));

		assert!(verify_api_key(key, &hash).unwrap());
		assert!(!verify_api_key("wrong_key", &hash).unwrap());
	}

	#[test]
	fn test_different_hashes_for_same_key() {
		let key = "loom_crash_admin_abc123def456abc123def456abc123de";

		let hash1 = hash_api_key(key).unwrap();
		let hash2 = hash_api_key(key).unwrap();

		assert_ne!(hash1, hash2);

		assert!(verify_api_key(key, &hash1).unwrap());
		assert!(verify_api_key(key, &hash2).unwrap());
	}

	proptest! {
		#[test]
		fn hash_is_deterministically_verifiable(key in "[a-zA-Z0-9_]{10,50}") {
			let hash = hash_api_key(&key).unwrap();
			prop_assert!(verify_api_key(&key, &hash).unwrap());
		}

		#[test]
		fn wrong_key_does_not_verify(
			key in "[a-zA-Z0-9_]{10,50}",
			wrong_key in "[a-zA-Z0-9_]{10,50}",
		) {
			prop_assume!(key != wrong_key);
			let hash = hash_api_key(&key).unwrap();
			prop_assert!(!verify_api_key(&wrong_key, &hash).unwrap());
		}

		#[test]
		fn hashes_always_start_with_argon2(key in "[a-zA-Z0-9_]{10,50}") {
			let hash = hash_api_key(&key).unwrap();
			prop_assert!(hash.starts_with("$argon2"));
		}
	}
}
