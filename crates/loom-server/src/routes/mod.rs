// Copyright (c) 2025 Geoffrey Huntley <ghuntley@ghuntley.com>. All rights
// reserved. SPDX-License-Identifier: Proprietary

//! HTTP route handlers organized by concern.

pub mod admin;
pub mod admin_anthropic;
pub mod admin_flags;
pub mod admin_jobs;
pub mod admin_logs;
pub mod analytics;
pub mod api_keys;
pub mod app_sessions;
pub mod auth;
pub mod bin;
pub mod crash;
pub mod crons;
pub mod cse;
pub mod debug;
pub mod docs;
pub mod flags;
pub mod git;
pub mod git_browser;
pub mod github;
pub mod health;
pub mod invitations;
pub mod maintenance;
pub mod mirrors;
pub mod orgs;
pub mod protection;
pub mod repos;
pub mod secrets;
pub mod serper;
pub mod sessions;
pub mod share;
pub mod teams;
pub mod threads;
pub mod users;
pub mod weaver;
pub mod weaver_audit;
pub mod weaver_auth;
pub mod weaver_secrets;
pub mod webhooks;
pub mod wgtunnel;

// Re-export all API types from loom-server-api for backward compatibility
pub use loom_server_api::admin::*;
pub use loom_server_api::analytics::*;
pub use loom_server_api::api_keys::*;
pub use loom_server_api::auth::*;
pub use loom_server_api::cse::*;
pub use loom_server_api::flags::*;
pub use loom_server_api::github::*;
pub use loom_server_api::invitations::*;
pub use loom_server_api::jobs::*;
pub use loom_server_api::maintenance::*;
pub use loom_server_api::mirrors::*;
pub use loom_server_api::orgs::*;
pub use loom_server_api::protection::*;
pub use loom_server_api::repos::*;
pub use loom_server_api::secrets::*;
pub use loom_server_api::sessions::*;
pub use loom_server_api::share::*;
pub use loom_server_api::teams::*;
pub use loom_server_api::threads::*;
pub use loom_server_api::users::*;
pub use loom_server_api::weaver::*;
pub use loom_server_api::webhooks::*;

// Re-export route-specific items not in loom-server-api
pub use analytics::AnalyticsMergeAuditHook;
pub use weaver::weaver_routes;
