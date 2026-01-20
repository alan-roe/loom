// Copyright (c) 2025 Geoffrey Huntley <ghuntley@ghuntley.com>. All rights reserved.
// SPDX-License-Identifier: Proprietary

//! Build script that compiles .po files to .mo files using msgfmt.
//!
//! If msgfmt is not available, it uses pre-compiled .mo files from the locales directory.

use std::path::Path;
use std::process::Command;

fn main() {
	println!("cargo:rerun-if-changed=locales/");

	let locales = [
		"en", "es", "ar", "fr", "ru", "ja", "ko", "pt", "sv", "nl", "zh-CN", "he", "it", "el", "et",
		"hi", "bn", "id",
	];
	let out_dir = std::env::var("OUT_DIR").expect("OUT_DIR not set");

	for locale in locales {
		let po_path = format!("locales/{locale}/messages.po");
		let precompiled_mo_path = format!("locales/{locale}/messages.mo");
		let out_mo_path = format!("{out_dir}/{locale}.mo");

		println!("cargo:rerun-if-changed={po_path}");
		// Only track the precompiled .mo if it exists, otherwise cargo will
		// always consider the fingerprint stale and rebuild
		if Path::new(&precompiled_mo_path).exists() {
			println!("cargo:rerun-if-changed={precompiled_mo_path}");
		}

		if let Ok(status) = Command::new("msgfmt")
			.args(["-o", &out_mo_path, &po_path])
			.status()
		{
			if status.success() {
				continue;
			}
		}

		if Path::new(&precompiled_mo_path).exists() {
			std::fs::copy(&precompiled_mo_path, &out_mo_path)
				.expect("Failed to copy pre-compiled .mo file");
		} else {
			panic!(
				"msgfmt not available and no pre-compiled .mo file for locale: {locale}. \
				 Install gettext or run: msgfmt -o {precompiled_mo_path} {po_path}"
			);
		}
	}
}
