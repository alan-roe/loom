// Copyright (c) 2025 Geoffrey Huntley <ghuntley@ghuntley.com>. All rights reserved.
// SPDX-License-Identifier: Proprietary

//! Example: Capture a crash event using the loom-crash SDK.
//!
//! Run with:
//!   cargo run --example capture -p loom-crash

use loom_crash::{Breadcrumb, BreadcrumbLevel, CrashClient, UserContext};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
	// Configure from environment or use defaults for testing
	let auth_token =
		std::env::var("LOOM_AUTH_TOKEN").expect("LOOM_AUTH_TOKEN environment variable required");
	let base_url =
		std::env::var("LOOM_BASE_URL").unwrap_or_else(|_| "https://loom.ghuntley.com".to_string());
	let project_id =
		std::env::var("LOOM_PROJECT_ID").expect("LOOM_PROJECT_ID environment variable required");

	println!("Initializing crash client...");
	println!("  Base URL: {}", base_url);
	println!("  Project ID: {}", project_id);

	// Build the client
	let client = CrashClient::builder()
		.auth_token(&auth_token)
		.base_url(&base_url)
		.project_id(&project_id)
		.release("0.1.0-example")
		.environment("development")
		.server_name("example-server")
		.build()?;

	// Set user context
	client
		.set_user(UserContext {
			id: Some("user_example_123".to_string()),
			email: Some("example@example.com".to_string()),
			username: Some("example_user".to_string()),
			ip_address: None,
		})
		.await;

	// Set some tags
	client.set_tag("example", "true").await;
	client.set_tag("rust_version", "1.75.0").await;

	// Add some breadcrumbs
	client
		.add_breadcrumb(Breadcrumb {
			category: "startup".into(),
			message: Some("Application started".into()),
			level: BreadcrumbLevel::Info,
			..Default::default()
		})
		.await;

	client
		.add_breadcrumb(Breadcrumb {
			category: "user".into(),
			message: Some("User logged in".into()),
			level: BreadcrumbLevel::Info,
			..Default::default()
		})
		.await;

	client
		.add_breadcrumb(Breadcrumb {
			category: "http".into(),
			message: Some("GET /api/data failed".into()),
			level: BreadcrumbLevel::Warning,
			..Default::default()
		})
		.await;

	// Capture a test error
	println!("\nCapturing test error...");
	let response = client
		.capture_message("Example test error from loom-crash SDK", BreadcrumbLevel::Error)
		.await?;

	println!("\nCapture successful!");
	println!("  Event ID: {}", response.event_id);
	println!("  Issue ID: {}", response.issue_id);
	println!("  Short ID: {}", response.short_id);
	println!("  Is New Issue: {}", response.is_new_issue);
	println!("  Is Regression: {}", response.is_regression);

	// Shutdown
	client.shutdown().await?;
	println!("\nClient shutdown complete.");

	Ok(())
}
