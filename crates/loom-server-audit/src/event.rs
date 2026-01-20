// Copyright (c) 2025 Geoffrey Huntley <ghuntley@ghuntley.com>. All rights reserved.
// SPDX-License-Identifier: Proprietary

//! Core event types for audit logging.
//!
//! This module provides the foundational types for the audit system:
//!
//! - [`AuditEventType`]: Enumeration of all auditable events
//! - [`AuditSeverity`]: RFC 5424-compatible severity levels
//! - [`AuditLogEntry`]: Complete audit record with correlation IDs
//! - [`AuditLogBuilder`]: Fluent API for constructing entries

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::fmt;
use uuid::Uuid;

/// Default retention period for audit logs in days.
pub const DEFAULT_AUDIT_RETENTION_DAYS: i64 = 90;

/// Types of events that can be recorded in the audit log.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditEventType {
	// Authentication events
	Login,
	Logout,
	LoginFailed,
	MagicLinkRequested,
	MagicLinkUsed,
	DeviceCodeStarted,
	DeviceCodeCompleted,

	// Session events
	SessionCreated,
	SessionRevoked,
	SessionExpired,

	// API key events
	ApiKeyCreated,
	ApiKeyUsed,
	ApiKeyRevoked,

	// Access control events
	AccessGranted,
	AccessDenied,

	// Organization events
	OrgCreated,
	OrgUpdated,
	OrgDeleted,
	OrgRestored,
	MemberAdded,
	MemberRemoved,
	RoleChanged,

	// Team events
	TeamCreated,
	TeamUpdated,
	TeamDeleted,
	TeamMemberAdded,
	TeamMemberRemoved,

	// Thread events
	ThreadCreated,
	ThreadDeleted,
	ThreadShared,
	ThreadUnshared,
	ThreadVisibilityChanged,

	// Support access events
	SupportAccessRequested,
	SupportAccessApproved,
	SupportAccessRevoked,

	// Admin events
	ImpersonationStarted,
	ImpersonationEnded,
	GlobalRoleChanged,
	UserDeleted,
	UserRestored,

	// Weaver events
	WeaverCreated,
	WeaverDeleted,
	WeaverAttached,

	// Weaver syscall audit events
	WeaverProcessExec,
	WeaverProcessFork,
	WeaverProcessExit,
	WeaverFileWrite,
	WeaverFileRead,
	WeaverFileMetadata,
	WeaverNetworkSocket,
	WeaverNetworkConnect,
	WeaverNetworkListen,
	WeaverNetworkAccept,
	WeaverDnsQuery,
	WeaverDnsResponse,
	WeaverPrivilegeChange,
	WeaverMemoryExec,
	WeaverSandboxEscape,

	// LLM events
	LlmRequestStarted,
	LlmRequestCompleted,
	LlmRequestFailed,

	// SCM events
	RepoCreated,
	RepoDeleted,
	MirrorCreated,
	MirrorSynced,
	WebhookReceived,

	// SCIM events
	ScimUserCreated,
	ScimUserUpdated,
	ScimUserDeleted,
	ScimUserDeprovisioned,
	ScimGroupCreated,
	ScimGroupUpdated,
	ScimGroupDeleted,
	ScimGroupMemberAdded,
	ScimGroupMemberRemoved,
	ScimBulkOperation,
	ScimAuthFailure,

	// Feature flag events
	FlagCreated,
	FlagUpdated,
	FlagArchived,
	FlagRestored,
	FlagConfigUpdated,
	StrategyCreated,
	StrategyUpdated,
	StrategyDeleted,
	KillSwitchCreated,
	KillSwitchUpdated,
	KillSwitchActivated,
	KillSwitchDeactivated,
	KillSwitchDeleted,
	SdkKeyCreated,
	SdkKeyRevoked,
	EnvironmentCreated,
	EnvironmentUpdated,
	EnvironmentDeleted,

	// Analytics events
	AnalyticsApiKeyCreated,
	AnalyticsApiKeyRevoked,
	AnalyticsPersonMerged,
	AnalyticsEventsExported,

	// Crash analytics events
	CrashProjectCreated,
	CrashProjectDeleted,
	CrashIssueResolved,
	CrashIssueIgnored,
	CrashIssueAssigned,
	CrashIssueDeleted,
	CrashSymbolsUploaded,
	CrashSymbolsDeleted,
	CrashReleaseCreated,

	// Cron monitoring events
	CronMonitorCreated,
	CronMonitorUpdated,
	CronMonitorDeleted,
	CronMonitorPaused,
	CronMonitorResumed,
}

impl fmt::Display for AuditEventType {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		let s = match self {
			// Authentication events
			AuditEventType::Login => "login",
			AuditEventType::Logout => "logout",
			AuditEventType::LoginFailed => "login_failed",
			AuditEventType::MagicLinkRequested => "magic_link_requested",
			AuditEventType::MagicLinkUsed => "magic_link_used",
			AuditEventType::DeviceCodeStarted => "device_code_started",
			AuditEventType::DeviceCodeCompleted => "device_code_completed",

			// Session events
			AuditEventType::SessionCreated => "session_created",
			AuditEventType::SessionRevoked => "session_revoked",
			AuditEventType::SessionExpired => "session_expired",

			// API key events
			AuditEventType::ApiKeyCreated => "api_key_created",
			AuditEventType::ApiKeyUsed => "api_key_used",
			AuditEventType::ApiKeyRevoked => "api_key_revoked",

			// Access control events
			AuditEventType::AccessGranted => "access_granted",
			AuditEventType::AccessDenied => "access_denied",

			// Organization events
			AuditEventType::OrgCreated => "org_created",
			AuditEventType::OrgUpdated => "org_updated",
			AuditEventType::OrgDeleted => "org_deleted",
			AuditEventType::OrgRestored => "org_restored",
			AuditEventType::MemberAdded => "member_added",
			AuditEventType::MemberRemoved => "member_removed",
			AuditEventType::RoleChanged => "role_changed",

			// Team events
			AuditEventType::TeamCreated => "team_created",
			AuditEventType::TeamUpdated => "team_updated",
			AuditEventType::TeamDeleted => "team_deleted",
			AuditEventType::TeamMemberAdded => "team_member_added",
			AuditEventType::TeamMemberRemoved => "team_member_removed",

			// Thread events
			AuditEventType::ThreadCreated => "thread_created",
			AuditEventType::ThreadDeleted => "thread_deleted",
			AuditEventType::ThreadShared => "thread_shared",
			AuditEventType::ThreadUnshared => "thread_unshared",
			AuditEventType::ThreadVisibilityChanged => "thread_visibility_changed",

			// Support access events
			AuditEventType::SupportAccessRequested => "support_access_requested",
			AuditEventType::SupportAccessApproved => "support_access_approved",
			AuditEventType::SupportAccessRevoked => "support_access_revoked",

			// Admin events
			AuditEventType::ImpersonationStarted => "impersonation_started",
			AuditEventType::ImpersonationEnded => "impersonation_ended",
			AuditEventType::GlobalRoleChanged => "global_role_changed",

			// Weaver events
			AuditEventType::WeaverCreated => "weaver_created",
			AuditEventType::WeaverDeleted => "weaver_deleted",
			AuditEventType::WeaverAttached => "weaver_attached",

			// Weaver syscall audit events
			AuditEventType::WeaverProcessExec => "weaver_process_exec",
			AuditEventType::WeaverProcessFork => "weaver_process_fork",
			AuditEventType::WeaverProcessExit => "weaver_process_exit",
			AuditEventType::WeaverFileWrite => "weaver_file_write",
			AuditEventType::WeaverFileRead => "weaver_file_read",
			AuditEventType::WeaverFileMetadata => "weaver_file_metadata",
			AuditEventType::WeaverNetworkSocket => "weaver_network_socket",
			AuditEventType::WeaverNetworkConnect => "weaver_network_connect",
			AuditEventType::WeaverNetworkListen => "weaver_network_listen",
			AuditEventType::WeaverNetworkAccept => "weaver_network_accept",
			AuditEventType::WeaverDnsQuery => "weaver_dns_query",
			AuditEventType::WeaverDnsResponse => "weaver_dns_response",
			AuditEventType::WeaverPrivilegeChange => "weaver_privilege_change",
			AuditEventType::WeaverMemoryExec => "weaver_memory_exec",
			AuditEventType::WeaverSandboxEscape => "weaver_sandbox_escape",

			// LLM events
			AuditEventType::LlmRequestStarted => "llm_request_started",
			AuditEventType::LlmRequestCompleted => "llm_request_completed",
			AuditEventType::LlmRequestFailed => "llm_request_failed",

			// SCM events
			AuditEventType::RepoCreated => "repo_created",
			AuditEventType::RepoDeleted => "repo_deleted",
			AuditEventType::MirrorCreated => "mirror_created",
			AuditEventType::MirrorSynced => "mirror_synced",
			AuditEventType::WebhookReceived => "webhook_received",

			// User management events
			AuditEventType::UserDeleted => "user_deleted",
			AuditEventType::UserRestored => "user_restored",

			// SCIM events
			AuditEventType::ScimUserCreated => "scim_user_created",
			AuditEventType::ScimUserUpdated => "scim_user_updated",
			AuditEventType::ScimUserDeleted => "scim_user_deleted",
			AuditEventType::ScimUserDeprovisioned => "scim_user_deprovisioned",
			AuditEventType::ScimGroupCreated => "scim_group_created",
			AuditEventType::ScimGroupUpdated => "scim_group_updated",
			AuditEventType::ScimGroupDeleted => "scim_group_deleted",
			AuditEventType::ScimGroupMemberAdded => "scim_group_member_added",
			AuditEventType::ScimGroupMemberRemoved => "scim_group_member_removed",
			AuditEventType::ScimBulkOperation => "scim_bulk_operation",
			AuditEventType::ScimAuthFailure => "scim_auth_failure",

			// Feature flag events
			AuditEventType::FlagCreated => "flag_created",
			AuditEventType::FlagUpdated => "flag_updated",
			AuditEventType::FlagArchived => "flag_archived",
			AuditEventType::FlagRestored => "flag_restored",
			AuditEventType::FlagConfigUpdated => "flag_config_updated",
			AuditEventType::StrategyCreated => "strategy_created",
			AuditEventType::StrategyUpdated => "strategy_updated",
			AuditEventType::StrategyDeleted => "strategy_deleted",
			AuditEventType::KillSwitchCreated => "kill_switch_created",
			AuditEventType::KillSwitchUpdated => "kill_switch_updated",
			AuditEventType::KillSwitchActivated => "kill_switch_activated",
			AuditEventType::KillSwitchDeactivated => "kill_switch_deactivated",
			AuditEventType::KillSwitchDeleted => "kill_switch_deleted",
			AuditEventType::SdkKeyCreated => "sdk_key_created",
			AuditEventType::SdkKeyRevoked => "sdk_key_revoked",
			AuditEventType::EnvironmentCreated => "environment_created",
			AuditEventType::EnvironmentUpdated => "environment_updated",
			AuditEventType::EnvironmentDeleted => "environment_deleted",

			// Analytics events
			AuditEventType::AnalyticsApiKeyCreated => "analytics_api_key_created",
			AuditEventType::AnalyticsApiKeyRevoked => "analytics_api_key_revoked",
			AuditEventType::AnalyticsPersonMerged => "analytics_person_merged",
			AuditEventType::AnalyticsEventsExported => "analytics_events_exported",

			// Crash analytics events
			AuditEventType::CrashProjectCreated => "crash_project_created",
			AuditEventType::CrashProjectDeleted => "crash_project_deleted",
			AuditEventType::CrashIssueResolved => "crash_issue_resolved",
			AuditEventType::CrashIssueIgnored => "crash_issue_ignored",
			AuditEventType::CrashIssueAssigned => "crash_issue_assigned",
			AuditEventType::CrashIssueDeleted => "crash_issue_deleted",
			AuditEventType::CrashSymbolsUploaded => "crash_symbols_uploaded",
			AuditEventType::CrashSymbolsDeleted => "crash_symbols_deleted",
			AuditEventType::CrashReleaseCreated => "crash_release_created",

			// Cron monitoring events
			AuditEventType::CronMonitorCreated => "cron_monitor_created",
			AuditEventType::CronMonitorUpdated => "cron_monitor_updated",
			AuditEventType::CronMonitorDeleted => "cron_monitor_deleted",
			AuditEventType::CronMonitorPaused => "cron_monitor_paused",
			AuditEventType::CronMonitorResumed => "cron_monitor_resumed",
		};
		write!(f, "{s}")
	}
}

impl AuditEventType {
	/// Returns the default severity for this event type.
	///
	/// Mapping follows RFC 5424 conventions:
	/// - `Info`: Normal operations (login, session created, resource created)
	/// - `Warning`: Security-relevant failures (login failed, access denied)
	/// - `Notice`: Administrative actions (deletions, revocations, impersonation)
	/// - `Error`: Operation failures (LLM request failed)
	pub fn default_severity(&self) -> AuditSeverity {
		match self {
			// Info: Normal successful operations
			AuditEventType::Login
			| AuditEventType::Logout
			| AuditEventType::MagicLinkRequested
			| AuditEventType::MagicLinkUsed
			| AuditEventType::DeviceCodeStarted
			| AuditEventType::DeviceCodeCompleted
			| AuditEventType::SessionCreated
			| AuditEventType::ApiKeyCreated
			| AuditEventType::ApiKeyUsed
			| AuditEventType::AccessGranted
			| AuditEventType::OrgCreated
			| AuditEventType::OrgUpdated
			| AuditEventType::MemberAdded
			| AuditEventType::TeamCreated
			| AuditEventType::TeamUpdated
			| AuditEventType::TeamMemberAdded
			| AuditEventType::ThreadCreated
			| AuditEventType::ThreadShared
			| AuditEventType::WeaverCreated
			| AuditEventType::WeaverAttached
			| AuditEventType::WeaverProcessExec
			| AuditEventType::WeaverProcessFork
			| AuditEventType::WeaverProcessExit
			| AuditEventType::WeaverFileWrite
			| AuditEventType::WeaverFileRead
			| AuditEventType::WeaverFileMetadata
			| AuditEventType::WeaverNetworkSocket
			| AuditEventType::WeaverNetworkConnect
			| AuditEventType::WeaverNetworkListen
			| AuditEventType::WeaverNetworkAccept
			| AuditEventType::WeaverDnsQuery
			| AuditEventType::WeaverDnsResponse
			| AuditEventType::LlmRequestStarted
			| AuditEventType::LlmRequestCompleted
			| AuditEventType::RepoCreated
			| AuditEventType::MirrorCreated
			| AuditEventType::MirrorSynced
			| AuditEventType::WebhookReceived
			| AuditEventType::ScimUserCreated
			| AuditEventType::ScimUserUpdated
			| AuditEventType::ScimGroupCreated
			| AuditEventType::ScimGroupUpdated
			| AuditEventType::ScimGroupMemberAdded
			| AuditEventType::ScimBulkOperation
			// Feature flag events - normal operations
			| AuditEventType::FlagCreated
			| AuditEventType::FlagUpdated
			| AuditEventType::FlagConfigUpdated
			| AuditEventType::StrategyCreated
			| AuditEventType::StrategyUpdated
			| AuditEventType::KillSwitchCreated
			| AuditEventType::KillSwitchUpdated
			| AuditEventType::SdkKeyCreated
			| AuditEventType::EnvironmentCreated
			| AuditEventType::EnvironmentUpdated
			// Analytics events - normal operations
			| AuditEventType::AnalyticsApiKeyCreated
			| AuditEventType::AnalyticsEventsExported
			// Crash analytics events - normal operations
			| AuditEventType::CrashProjectCreated
			| AuditEventType::CrashReleaseCreated
			| AuditEventType::CrashSymbolsUploaded
			// Cron monitoring events - normal operations
			| AuditEventType::CronMonitorCreated => AuditSeverity::Info,

			// Warning: Security-relevant failures
			AuditEventType::LoginFailed
			| AuditEventType::AccessDenied
			| AuditEventType::WeaverPrivilegeChange
			| AuditEventType::WeaverMemoryExec
			| AuditEventType::ScimAuthFailure => AuditSeverity::Warning,

			// Critical: Security breaches
			AuditEventType::WeaverSandboxEscape => AuditSeverity::Critical,

			// Notice: Administrative/destructive actions
			AuditEventType::SessionRevoked
			| AuditEventType::SessionExpired
			| AuditEventType::ApiKeyRevoked
			| AuditEventType::OrgDeleted
			| AuditEventType::OrgRestored
			| AuditEventType::MemberRemoved
			| AuditEventType::RoleChanged
			| AuditEventType::TeamDeleted
			| AuditEventType::TeamMemberRemoved
			| AuditEventType::ThreadDeleted
			| AuditEventType::ThreadUnshared
			| AuditEventType::ThreadVisibilityChanged
			| AuditEventType::SupportAccessRequested
			| AuditEventType::SupportAccessApproved
			| AuditEventType::SupportAccessRevoked
			| AuditEventType::ImpersonationStarted
			| AuditEventType::ImpersonationEnded
			| AuditEventType::GlobalRoleChanged
			| AuditEventType::UserDeleted
			| AuditEventType::UserRestored
			| AuditEventType::WeaverDeleted
			| AuditEventType::RepoDeleted
			| AuditEventType::ScimUserDeleted
			| AuditEventType::ScimUserDeprovisioned
			| AuditEventType::ScimGroupDeleted
			| AuditEventType::ScimGroupMemberRemoved
			// Feature flag events - administrative/destructive actions
			| AuditEventType::FlagArchived
			| AuditEventType::FlagRestored
			| AuditEventType::StrategyDeleted
			| AuditEventType::KillSwitchActivated
			| AuditEventType::KillSwitchDeactivated
			| AuditEventType::KillSwitchDeleted
			| AuditEventType::SdkKeyRevoked
			| AuditEventType::EnvironmentDeleted
			// Analytics events - administrative/destructive actions
			| AuditEventType::AnalyticsApiKeyRevoked
			| AuditEventType::AnalyticsPersonMerged
			// Crash analytics events - administrative/destructive actions
			| AuditEventType::CrashProjectDeleted
			| AuditEventType::CrashIssueResolved
			| AuditEventType::CrashIssueIgnored
			| AuditEventType::CrashIssueAssigned
			| AuditEventType::CrashIssueDeleted
			| AuditEventType::CrashSymbolsDeleted
			// Cron monitoring events - administrative actions
			| AuditEventType::CronMonitorUpdated
			| AuditEventType::CronMonitorDeleted
			| AuditEventType::CronMonitorPaused
			| AuditEventType::CronMonitorResumed => AuditSeverity::Notice,

			// Error: Operation failures
			AuditEventType::LlmRequestFailed => AuditSeverity::Error,
		}
	}
}

/// Severity levels for audit events, compatible with RFC 5424 syslog.
///
/// The numeric values correspond to syslog severity codes, allowing
/// direct mapping when forwarding to syslog-based SIEM systems.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum AuditSeverity {
	Debug = 7,
	#[default]
	Info = 6,
	Notice = 5,
	Warning = 4,
	Error = 3,
	Critical = 2,
}

impl AuditSeverity {
	/// Returns the RFC 5424 numeric severity code.
	pub fn as_syslog_code(&self) -> u8 {
		*self as u8
	}

	/// Returns all severity levels from most to least severe.
	pub fn all() -> &'static [AuditSeverity] {
		&[
			AuditSeverity::Critical,
			AuditSeverity::Error,
			AuditSeverity::Warning,
			AuditSeverity::Notice,
			AuditSeverity::Info,
			AuditSeverity::Debug,
		]
	}
}

impl PartialOrd for AuditSeverity {
	fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
		Some(self.cmp(other))
	}
}

impl Ord for AuditSeverity {
	fn cmp(&self, other: &Self) -> Ordering {
		// Lower numeric value = higher severity (Critical=2 > Debug=7)
		(*other as u8).cmp(&(*self as u8))
	}
}

impl fmt::Display for AuditSeverity {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		let s = match self {
			AuditSeverity::Debug => "debug",
			AuditSeverity::Info => "info",
			AuditSeverity::Notice => "notice",
			AuditSeverity::Warning => "warning",
			AuditSeverity::Error => "error",
			AuditSeverity::Critical => "critical",
		};
		write!(f, "{s}")
	}
}

/// A unique identifier for a user.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct UserId(Uuid);

impl UserId {
	pub fn new(id: Uuid) -> Self {
		Self(id)
	}

	pub fn generate() -> Self {
		Self(Uuid::new_v4())
	}

	pub fn into_inner(self) -> Uuid {
		self.0
	}

	pub fn as_uuid(&self) -> &Uuid {
		&self.0
	}
}

impl fmt::Display for UserId {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "{}", self.0)
	}
}

impl From<Uuid> for UserId {
	fn from(id: Uuid) -> Self {
		Self(id)
	}
}

impl From<UserId> for Uuid {
	fn from(id: UserId) -> Self {
		id.0
	}
}

/// An entry in the audit log recording a security-relevant event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLogEntry {
	/// Unique identifier for this audit entry.
	pub id: Uuid,
	/// When the event occurred.
	pub timestamp: DateTime<Utc>,
	/// The type of event.
	pub event_type: AuditEventType,
	/// The severity level of this event.
	pub severity: AuditSeverity,

	/// The user who performed the action (if known).
	pub actor_user_id: Option<UserId>,
	/// If the actor is impersonating another user, this is the real admin's ID.
	pub impersonating_user_id: Option<UserId>,

	/// The type of resource affected (e.g., "thread", "organization", "session").
	pub resource_type: Option<String>,
	/// The ID of the resource affected.
	pub resource_id: Option<String>,

	/// Human-readable description of the action.
	pub action: String,
	/// IP address of the request origin.
	pub ip_address: Option<String>,
	/// User agent string from the request.
	pub user_agent: Option<String>,
	/// Additional event-specific details.
	pub details: serde_json::Value,

	/// OpenTelemetry trace ID for correlation.
	pub trace_id: Option<String>,
	/// OpenTelemetry span ID for correlation.
	pub span_id: Option<String>,
	/// Application-level request ID for correlation.
	pub request_id: Option<String>,
}

impl AuditLogEntry {
	/// Create a new audit log builder for the given event type.
	pub fn builder(event_type: AuditEventType) -> AuditLogBuilder {
		AuditLogBuilder::new(event_type)
	}
}

/// Builder for constructing audit log entries with a fluent API.
#[derive(Debug, Clone)]
pub struct AuditLogBuilder {
	event_type: AuditEventType,
	severity: Option<AuditSeverity>,
	actor_user_id: Option<UserId>,
	impersonating_user_id: Option<UserId>,
	resource_type: Option<String>,
	resource_id: Option<String>,
	action: Option<String>,
	ip_address: Option<String>,
	user_agent: Option<String>,
	details: serde_json::Value,
	trace_id: Option<String>,
	span_id: Option<String>,
	request_id: Option<String>,
}

impl AuditLogBuilder {
	/// Create a new builder for the given event type.
	pub fn new(event_type: AuditEventType) -> Self {
		Self {
			event_type,
			severity: None,
			actor_user_id: None,
			impersonating_user_id: None,
			resource_type: None,
			resource_id: None,
			action: None,
			ip_address: None,
			user_agent: None,
			details: serde_json::Value::Null,
			trace_id: None,
			span_id: None,
			request_id: None,
		}
	}

	/// Set the severity level. Defaults to the event type's default severity.
	pub fn severity(mut self, severity: AuditSeverity) -> Self {
		self.severity = Some(severity);
		self
	}

	/// Set the user who performed the action.
	pub fn actor(mut self, user_id: UserId) -> Self {
		self.actor_user_id = Some(user_id);
		self
	}

	/// Set the real admin's ID if the actor is impersonating another user.
	pub fn impersonating(mut self, admin_user_id: UserId) -> Self {
		self.impersonating_user_id = Some(admin_user_id);
		self
	}

	/// Set the resource type and ID affected by this event.
	pub fn resource(
		mut self,
		resource_type: impl Into<String>,
		resource_id: impl Into<String>,
	) -> Self {
		self.resource_type = Some(resource_type.into());
		self.resource_id = Some(resource_id.into());
		self
	}

	/// Set the human-readable action description.
	pub fn action(mut self, action: impl Into<String>) -> Self {
		self.action = Some(action.into());
		self
	}

	/// Set the IP address of the request origin.
	pub fn ip_address(mut self, ip: impl Into<String>) -> Self {
		self.ip_address = Some(ip.into());
		self
	}

	/// Set the user agent string from the request.
	pub fn user_agent(mut self, ua: impl Into<String>) -> Self {
		self.user_agent = Some(ua.into());
		self
	}

	/// Set additional event-specific details.
	pub fn details(mut self, details: serde_json::Value) -> Self {
		self.details = details;
		self
	}

	/// Set the OpenTelemetry trace ID.
	pub fn trace_id(mut self, trace_id: impl Into<String>) -> Self {
		self.trace_id = Some(trace_id.into());
		self
	}

	/// Set the OpenTelemetry span ID.
	pub fn span_id(mut self, span_id: impl Into<String>) -> Self {
		self.span_id = Some(span_id.into());
		self
	}

	/// Set the application-level request ID.
	pub fn request_id(mut self, request_id: impl Into<String>) -> Self {
		self.request_id = Some(request_id.into());
		self
	}

	/// Build the audit log entry.
	pub fn build(self) -> AuditLogEntry {
		AuditLogEntry {
			id: Uuid::new_v4(),
			timestamp: Utc::now(),
			event_type: self.event_type,
			severity: self
				.severity
				.unwrap_or_else(|| self.event_type.default_severity()),
			actor_user_id: self.actor_user_id,
			impersonating_user_id: self.impersonating_user_id,
			resource_type: self.resource_type,
			resource_id: self.resource_id,
			action: self.action.unwrap_or_else(|| self.event_type.to_string()),
			ip_address: self.ip_address,
			user_agent: self.user_agent,
			details: self.details,
			trace_id: self.trace_id,
			span_id: self.span_id,
			request_id: self.request_id,
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use proptest::prelude::*;
	use serde_json::json;

	mod audit_event_type {
		use super::*;

		#[test]
		fn display_returns_snake_case() {
			assert_eq!(AuditEventType::Login.to_string(), "login");
			assert_eq!(AuditEventType::LoginFailed.to_string(), "login_failed");
			assert_eq!(
				AuditEventType::SessionCreated.to_string(),
				"session_created"
			);
			assert_eq!(
				AuditEventType::ImpersonationStarted.to_string(),
				"impersonation_started"
			);
			assert_eq!(
				AuditEventType::SupportAccessApproved.to_string(),
				"support_access_approved"
			);
			assert_eq!(
				AuditEventType::MagicLinkRequested.to_string(),
				"magic_link_requested"
			);
			assert_eq!(
				AuditEventType::DeviceCodeCompleted.to_string(),
				"device_code_completed"
			);
			assert_eq!(
				AuditEventType::GlobalRoleChanged.to_string(),
				"global_role_changed"
			);
			assert_eq!(AuditEventType::WeaverCreated.to_string(), "weaver_created");
			assert_eq!(
				AuditEventType::LlmRequestFailed.to_string(),
				"llm_request_failed"
			);
			assert_eq!(AuditEventType::MirrorSynced.to_string(), "mirror_synced");
		}

		#[test]
		fn serializes_snake_case() {
			let event = AuditEventType::ApiKeyCreated;
			let json = serde_json::to_string(&event).unwrap();
			assert_eq!(json, "\"api_key_created\"");
		}

		#[test]
		fn deserializes_snake_case() {
			let event: AuditEventType = serde_json::from_str("\"access_denied\"").unwrap();
			assert_eq!(event, AuditEventType::AccessDenied);
		}

		const ALL_EVENT_TYPES: [AuditEventType; 85] = [
			AuditEventType::Login,
			AuditEventType::Logout,
			AuditEventType::LoginFailed,
			AuditEventType::MagicLinkRequested,
			AuditEventType::MagicLinkUsed,
			AuditEventType::DeviceCodeStarted,
			AuditEventType::DeviceCodeCompleted,
			AuditEventType::SessionCreated,
			AuditEventType::SessionRevoked,
			AuditEventType::SessionExpired,
			AuditEventType::ApiKeyCreated,
			AuditEventType::ApiKeyUsed,
			AuditEventType::ApiKeyRevoked,
			AuditEventType::AccessGranted,
			AuditEventType::AccessDenied,
			AuditEventType::OrgCreated,
			AuditEventType::OrgUpdated,
			AuditEventType::OrgDeleted,
			AuditEventType::OrgRestored,
			AuditEventType::MemberAdded,
			AuditEventType::MemberRemoved,
			AuditEventType::RoleChanged,
			AuditEventType::TeamCreated,
			AuditEventType::TeamUpdated,
			AuditEventType::TeamDeleted,
			AuditEventType::TeamMemberAdded,
			AuditEventType::TeamMemberRemoved,
			AuditEventType::ThreadCreated,
			AuditEventType::ThreadDeleted,
			AuditEventType::ThreadShared,
			AuditEventType::ThreadUnshared,
			AuditEventType::ThreadVisibilityChanged,
			AuditEventType::SupportAccessRequested,
			AuditEventType::SupportAccessApproved,
			AuditEventType::SupportAccessRevoked,
			AuditEventType::ImpersonationStarted,
			AuditEventType::ImpersonationEnded,
			AuditEventType::GlobalRoleChanged,
			AuditEventType::WeaverCreated,
			AuditEventType::WeaverDeleted,
			AuditEventType::WeaverAttached,
			AuditEventType::LlmRequestStarted,
			AuditEventType::LlmRequestCompleted,
			AuditEventType::LlmRequestFailed,
			AuditEventType::RepoCreated,
			AuditEventType::RepoDeleted,
			AuditEventType::MirrorCreated,
			AuditEventType::MirrorSynced,
			AuditEventType::WebhookReceived,
			// Feature flag events
			AuditEventType::FlagCreated,
			AuditEventType::FlagUpdated,
			AuditEventType::FlagArchived,
			AuditEventType::FlagRestored,
			AuditEventType::FlagConfigUpdated,
			AuditEventType::StrategyCreated,
			AuditEventType::StrategyUpdated,
			AuditEventType::StrategyDeleted,
			AuditEventType::KillSwitchCreated,
			AuditEventType::KillSwitchUpdated,
			AuditEventType::KillSwitchActivated,
			AuditEventType::KillSwitchDeactivated,
			AuditEventType::KillSwitchDeleted,
			AuditEventType::SdkKeyCreated,
			AuditEventType::SdkKeyRevoked,
			AuditEventType::EnvironmentCreated,
			AuditEventType::EnvironmentUpdated,
			AuditEventType::EnvironmentDeleted,
			// Analytics events
			AuditEventType::AnalyticsApiKeyCreated,
			AuditEventType::AnalyticsApiKeyRevoked,
			AuditEventType::AnalyticsPersonMerged,
			AuditEventType::AnalyticsEventsExported,
			// Crash analytics events
			AuditEventType::CrashProjectCreated,
			AuditEventType::CrashProjectDeleted,
			AuditEventType::CrashIssueResolved,
			AuditEventType::CrashIssueIgnored,
			AuditEventType::CrashIssueAssigned,
			AuditEventType::CrashIssueDeleted,
			AuditEventType::CrashSymbolsUploaded,
			AuditEventType::CrashSymbolsDeleted,
			AuditEventType::CrashReleaseCreated,
			// Cron monitoring events
			AuditEventType::CronMonitorCreated,
			AuditEventType::CronMonitorUpdated,
			AuditEventType::CronMonitorDeleted,
			AuditEventType::CronMonitorPaused,
			AuditEventType::CronMonitorResumed,
		];

		#[test]
		fn all_event_types_serialize_deserialize() {
			for event in ALL_EVENT_TYPES {
				let json = serde_json::to_string(&event).unwrap();
				let roundtrip: AuditEventType = serde_json::from_str(&json).unwrap();
				assert_eq!(event, roundtrip);
			}
		}

		#[test]
		fn all_event_types_have_default_severity() {
			for event in ALL_EVENT_TYPES {
				let severity = event.default_severity();
				assert!(
					matches!(
						severity,
						AuditSeverity::Debug
							| AuditSeverity::Info
							| AuditSeverity::Notice
							| AuditSeverity::Warning
							| AuditSeverity::Error
							| AuditSeverity::Critical
					),
					"Event {:?} should have a valid severity",
					event
				);
			}
		}

		#[test]
		fn default_severity_mapping() {
			assert_eq!(
				AuditEventType::Login.default_severity(),
				AuditSeverity::Info
			);
			assert_eq!(
				AuditEventType::SessionCreated.default_severity(),
				AuditSeverity::Info
			);
			assert_eq!(
				AuditEventType::OrgCreated.default_severity(),
				AuditSeverity::Info
			);
			assert_eq!(
				AuditEventType::LoginFailed.default_severity(),
				AuditSeverity::Warning
			);
			assert_eq!(
				AuditEventType::AccessDenied.default_severity(),
				AuditSeverity::Warning
			);
			assert_eq!(
				AuditEventType::SessionRevoked.default_severity(),
				AuditSeverity::Notice
			);
			assert_eq!(
				AuditEventType::OrgDeleted.default_severity(),
				AuditSeverity::Notice
			);
			assert_eq!(
				AuditEventType::ImpersonationStarted.default_severity(),
				AuditSeverity::Notice
			);
			assert_eq!(
				AuditEventType::GlobalRoleChanged.default_severity(),
				AuditSeverity::Notice
			);
			assert_eq!(
				AuditEventType::LlmRequestFailed.default_severity(),
				AuditSeverity::Error
			);
		}

		#[test]
		fn feature_flag_event_severities() {
			// Info: normal flag operations
			assert_eq!(
				AuditEventType::FlagCreated.default_severity(),
				AuditSeverity::Info
			);
			assert_eq!(
				AuditEventType::FlagUpdated.default_severity(),
				AuditSeverity::Info
			);
			assert_eq!(
				AuditEventType::FlagConfigUpdated.default_severity(),
				AuditSeverity::Info
			);
			assert_eq!(
				AuditEventType::StrategyCreated.default_severity(),
				AuditSeverity::Info
			);
			assert_eq!(
				AuditEventType::StrategyUpdated.default_severity(),
				AuditSeverity::Info
			);
			assert_eq!(
				AuditEventType::KillSwitchCreated.default_severity(),
				AuditSeverity::Info
			);
			assert_eq!(
				AuditEventType::KillSwitchUpdated.default_severity(),
				AuditSeverity::Info
			);
			assert_eq!(
				AuditEventType::SdkKeyCreated.default_severity(),
				AuditSeverity::Info
			);
			assert_eq!(
				AuditEventType::EnvironmentCreated.default_severity(),
				AuditSeverity::Info
			);
			assert_eq!(
				AuditEventType::EnvironmentUpdated.default_severity(),
				AuditSeverity::Info
			);

			// Notice: administrative/destructive operations
			assert_eq!(
				AuditEventType::FlagArchived.default_severity(),
				AuditSeverity::Notice
			);
			assert_eq!(
				AuditEventType::FlagRestored.default_severity(),
				AuditSeverity::Notice
			);
			assert_eq!(
				AuditEventType::StrategyDeleted.default_severity(),
				AuditSeverity::Notice
			);
			assert_eq!(
				AuditEventType::KillSwitchActivated.default_severity(),
				AuditSeverity::Notice
			);
			assert_eq!(
				AuditEventType::KillSwitchDeactivated.default_severity(),
				AuditSeverity::Notice
			);
			assert_eq!(
				AuditEventType::KillSwitchDeleted.default_severity(),
				AuditSeverity::Notice
			);
			assert_eq!(
				AuditEventType::SdkKeyRevoked.default_severity(),
				AuditSeverity::Notice
			);
			assert_eq!(
				AuditEventType::EnvironmentDeleted.default_severity(),
				AuditSeverity::Notice
			);
		}

		#[test]
		fn feature_flag_event_display() {
			assert_eq!(AuditEventType::FlagCreated.to_string(), "flag_created");
			assert_eq!(AuditEventType::FlagUpdated.to_string(), "flag_updated");
			assert_eq!(AuditEventType::FlagArchived.to_string(), "flag_archived");
			assert_eq!(AuditEventType::FlagRestored.to_string(), "flag_restored");
			assert_eq!(
				AuditEventType::FlagConfigUpdated.to_string(),
				"flag_config_updated"
			);
			assert_eq!(
				AuditEventType::StrategyCreated.to_string(),
				"strategy_created"
			);
			assert_eq!(
				AuditEventType::StrategyUpdated.to_string(),
				"strategy_updated"
			);
			assert_eq!(
				AuditEventType::StrategyDeleted.to_string(),
				"strategy_deleted"
			);
			assert_eq!(
				AuditEventType::KillSwitchCreated.to_string(),
				"kill_switch_created"
			);
			assert_eq!(
				AuditEventType::KillSwitchUpdated.to_string(),
				"kill_switch_updated"
			);
			assert_eq!(
				AuditEventType::KillSwitchActivated.to_string(),
				"kill_switch_activated"
			);
			assert_eq!(
				AuditEventType::KillSwitchDeactivated.to_string(),
				"kill_switch_deactivated"
			);
			assert_eq!(
				AuditEventType::KillSwitchDeleted.to_string(),
				"kill_switch_deleted"
			);
			assert_eq!(AuditEventType::SdkKeyCreated.to_string(), "sdk_key_created");
			assert_eq!(AuditEventType::SdkKeyRevoked.to_string(), "sdk_key_revoked");
			assert_eq!(
				AuditEventType::EnvironmentCreated.to_string(),
				"environment_created"
			);
			assert_eq!(
				AuditEventType::EnvironmentUpdated.to_string(),
				"environment_updated"
			);
			assert_eq!(
				AuditEventType::EnvironmentDeleted.to_string(),
				"environment_deleted"
			);
		}

		#[test]
		fn feature_flag_events_serialize_deserialize() {
			let events = [
				AuditEventType::FlagCreated,
				AuditEventType::FlagUpdated,
				AuditEventType::FlagArchived,
				AuditEventType::FlagRestored,
				AuditEventType::FlagConfigUpdated,
				AuditEventType::StrategyCreated,
				AuditEventType::StrategyUpdated,
				AuditEventType::StrategyDeleted,
				AuditEventType::KillSwitchCreated,
				AuditEventType::KillSwitchUpdated,
				AuditEventType::KillSwitchActivated,
				AuditEventType::KillSwitchDeactivated,
				AuditEventType::KillSwitchDeleted,
				AuditEventType::SdkKeyCreated,
				AuditEventType::SdkKeyRevoked,
				AuditEventType::EnvironmentCreated,
				AuditEventType::EnvironmentUpdated,
				AuditEventType::EnvironmentDeleted,
			];

			for event in events {
				let serialized = serde_json::to_string(&event).unwrap();
				let deserialized: AuditEventType = serde_json::from_str(&serialized).unwrap();
				assert_eq!(event, deserialized);
			}
		}

		#[test]
		fn analytics_event_severities() {
			// Info: normal analytics operations
			assert_eq!(
				AuditEventType::AnalyticsApiKeyCreated.default_severity(),
				AuditSeverity::Info
			);
			assert_eq!(
				AuditEventType::AnalyticsEventsExported.default_severity(),
				AuditSeverity::Info
			);

			// Notice: administrative/destructive operations
			assert_eq!(
				AuditEventType::AnalyticsApiKeyRevoked.default_severity(),
				AuditSeverity::Notice
			);
			assert_eq!(
				AuditEventType::AnalyticsPersonMerged.default_severity(),
				AuditSeverity::Notice
			);
		}

		#[test]
		fn analytics_event_display() {
			assert_eq!(
				AuditEventType::AnalyticsApiKeyCreated.to_string(),
				"analytics_api_key_created"
			);
			assert_eq!(
				AuditEventType::AnalyticsApiKeyRevoked.to_string(),
				"analytics_api_key_revoked"
			);
			assert_eq!(
				AuditEventType::AnalyticsPersonMerged.to_string(),
				"analytics_person_merged"
			);
			assert_eq!(
				AuditEventType::AnalyticsEventsExported.to_string(),
				"analytics_events_exported"
			);
		}

		#[test]
		fn analytics_events_serialize_deserialize() {
			let events = [
				AuditEventType::AnalyticsApiKeyCreated,
				AuditEventType::AnalyticsApiKeyRevoked,
				AuditEventType::AnalyticsPersonMerged,
				AuditEventType::AnalyticsEventsExported,
			];

			for event in events {
				let serialized = serde_json::to_string(&event).unwrap();
				let deserialized: AuditEventType = serde_json::from_str(&serialized).unwrap();
				assert_eq!(event, deserialized);
			}
		}
	}

	mod audit_severity {
		use super::*;

		#[test]
		fn ordering_higher_severity_is_greater() {
			assert!(AuditSeverity::Critical > AuditSeverity::Error);
			assert!(AuditSeverity::Error > AuditSeverity::Warning);
			assert!(AuditSeverity::Warning > AuditSeverity::Notice);
			assert!(AuditSeverity::Notice > AuditSeverity::Info);
			assert!(AuditSeverity::Info > AuditSeverity::Debug);
		}

		#[test]
		fn ordering_same_severity_is_equal() {
			assert_eq!(
				AuditSeverity::Warning.cmp(&AuditSeverity::Warning),
				Ordering::Equal
			);
		}

		#[test]
		fn syslog_codes() {
			assert_eq!(AuditSeverity::Debug.as_syslog_code(), 7);
			assert_eq!(AuditSeverity::Info.as_syslog_code(), 6);
			assert_eq!(AuditSeverity::Notice.as_syslog_code(), 5);
			assert_eq!(AuditSeverity::Warning.as_syslog_code(), 4);
			assert_eq!(AuditSeverity::Error.as_syslog_code(), 3);
			assert_eq!(AuditSeverity::Critical.as_syslog_code(), 2);
		}

		#[test]
		fn display() {
			assert_eq!(AuditSeverity::Debug.to_string(), "debug");
			assert_eq!(AuditSeverity::Info.to_string(), "info");
			assert_eq!(AuditSeverity::Notice.to_string(), "notice");
			assert_eq!(AuditSeverity::Warning.to_string(), "warning");
			assert_eq!(AuditSeverity::Error.to_string(), "error");
			assert_eq!(AuditSeverity::Critical.to_string(), "critical");
		}

		#[test]
		fn serializes_snake_case() {
			assert_eq!(
				serde_json::to_string(&AuditSeverity::Warning).unwrap(),
				"\"warning\""
			);
			assert_eq!(
				serde_json::to_string(&AuditSeverity::Critical).unwrap(),
				"\"critical\""
			);
		}

		#[test]
		fn deserializes_snake_case() {
			let severity: AuditSeverity = serde_json::from_str("\"error\"").unwrap();
			assert_eq!(severity, AuditSeverity::Error);
		}

		#[test]
		fn default_is_info() {
			assert_eq!(AuditSeverity::default(), AuditSeverity::Info);
		}

		#[test]
		fn all_returns_sorted_by_severity() {
			let all = AuditSeverity::all();
			assert_eq!(all.len(), 6);
			for i in 0..all.len() - 1 {
				assert!(
					all[i] > all[i + 1],
					"Expected {:?} > {:?}",
					all[i],
					all[i + 1]
				);
			}
		}
	}

	mod audit_log_entry {
		use super::*;

		#[test]
		fn new_returns_builder() {
			let builder = AuditLogEntry::builder(AuditEventType::Login);
			let entry = builder.build();
			assert_eq!(entry.event_type, AuditEventType::Login);
		}

		#[test]
		fn serializes_to_json() {
			let user_id = UserId::generate();
			let entry = AuditLogEntry::builder(AuditEventType::Login)
				.actor(user_id)
				.ip_address("192.168.1.1")
				.trace_id("abc123")
				.build();

			let json = serde_json::to_string(&entry).unwrap();
			assert!(json.contains("\"event_type\":\"login\""));
			assert!(json.contains("\"ip_address\":\"192.168.1.1\""));
			assert!(json.contains("\"trace_id\":\"abc123\""));
			assert!(json.contains("\"severity\":\"info\""));
		}

		#[test]
		fn deserializes_from_json() {
			let user_id = UserId::generate();
			let original = AuditLogEntry::builder(AuditEventType::AccessDenied)
				.actor(user_id)
				.resource("thread", "thread-123")
				.action("User attempted to access private thread")
				.request_id("req-456")
				.build();

			let json = serde_json::to_string(&original).unwrap();
			let restored: AuditLogEntry = serde_json::from_str(&json).unwrap();

			assert_eq!(restored.id, original.id);
			assert_eq!(restored.event_type, AuditEventType::AccessDenied);
			assert_eq!(restored.severity, AuditSeverity::Warning);
			assert_eq!(restored.resource_type, Some("thread".to_string()));
			assert_eq!(restored.resource_id, Some("thread-123".to_string()));
			assert_eq!(restored.request_id, Some("req-456".to_string()));
		}
	}

	mod audit_log_builder {
		use super::*;

		#[test]
		fn builds_minimal_entry() {
			let entry = AuditLogBuilder::new(AuditEventType::Logout).build();

			assert_eq!(entry.event_type, AuditEventType::Logout);
			assert_eq!(entry.severity, AuditSeverity::Info);
			assert!(entry.actor_user_id.is_none());
			assert!(entry.impersonating_user_id.is_none());
			assert!(entry.resource_type.is_none());
			assert!(entry.resource_id.is_none());
			assert_eq!(entry.action, "logout");
			assert!(entry.ip_address.is_none());
			assert!(entry.user_agent.is_none());
			assert!(entry.trace_id.is_none());
			assert!(entry.span_id.is_none());
			assert!(entry.request_id.is_none());
			assert_eq!(entry.details, serde_json::Value::Null);
		}

		#[test]
		fn builds_full_entry() {
			let actor = UserId::generate();
			let admin = UserId::generate();

			let entry = AuditLogBuilder::new(AuditEventType::RoleChanged)
				.actor(actor)
				.impersonating(admin)
				.resource("org_membership", "mem-456")
				.action("Changed role from member to admin")
				.ip_address("10.0.0.1")
				.user_agent("Mozilla/5.0")
				.details(json!({"old_role": "member", "new_role": "admin"}))
				.severity(AuditSeverity::Warning)
				.trace_id("trace-123")
				.span_id("span-456")
				.request_id("req-789")
				.build();

			assert_eq!(entry.event_type, AuditEventType::RoleChanged);
			assert_eq!(entry.severity, AuditSeverity::Warning);
			assert_eq!(entry.actor_user_id, Some(actor));
			assert_eq!(entry.impersonating_user_id, Some(admin));
			assert_eq!(entry.resource_type, Some("org_membership".to_string()));
			assert_eq!(entry.resource_id, Some("mem-456".to_string()));
			assert_eq!(entry.action, "Changed role from member to admin");
			assert_eq!(entry.ip_address, Some("10.0.0.1".to_string()));
			assert_eq!(entry.user_agent, Some("Mozilla/5.0".to_string()));
			assert_eq!(entry.trace_id, Some("trace-123".to_string()));
			assert_eq!(entry.span_id, Some("span-456".to_string()));
			assert_eq!(entry.request_id, Some("req-789".to_string()));
			assert_eq!(entry.details["old_role"], "member");
			assert_eq!(entry.details["new_role"], "admin");
		}

		#[test]
		fn generates_unique_ids() {
			let entry1 = AuditLogBuilder::new(AuditEventType::Login).build();
			let entry2 = AuditLogBuilder::new(AuditEventType::Login).build();
			assert_ne!(entry1.id, entry2.id);
		}

		#[test]
		fn sets_timestamp_to_now() {
			let before = Utc::now();
			let entry = AuditLogBuilder::new(AuditEventType::Login).build();
			let after = Utc::now();

			assert!(entry.timestamp >= before);
			assert!(entry.timestamp <= after);
		}

		#[test]
		fn default_action_uses_event_type_display() {
			let entry = AuditLogBuilder::new(AuditEventType::ApiKeyRevoked).build();
			assert_eq!(entry.action, "api_key_revoked");
		}

		#[test]
		fn custom_action_overrides_default() {
			let entry = AuditLogBuilder::new(AuditEventType::ApiKeyRevoked)
				.action("Admin revoked API key due to suspected compromise")
				.build();
			assert_eq!(
				entry.action,
				"Admin revoked API key due to suspected compromise"
			);
		}

		#[test]
		fn default_severity_from_event_type() {
			let entry = AuditLogBuilder::new(AuditEventType::LoginFailed).build();
			assert_eq!(entry.severity, AuditSeverity::Warning);

			let entry = AuditLogBuilder::new(AuditEventType::LlmRequestFailed).build();
			assert_eq!(entry.severity, AuditSeverity::Error);
		}

		#[test]
		fn custom_severity_overrides_default() {
			let entry = AuditLogBuilder::new(AuditEventType::Login)
				.severity(AuditSeverity::Critical)
				.build();
			assert_eq!(entry.severity, AuditSeverity::Critical);
		}

		#[test]
		fn impersonation_tracking() {
			let target_user = UserId::generate();
			let admin_user = UserId::generate();

			let entry = AuditLogBuilder::new(AuditEventType::ImpersonationStarted)
				.actor(target_user)
				.impersonating(admin_user)
				.details(json!({"reason": "Investigating reported issue"}))
				.build();

			assert_eq!(entry.actor_user_id, Some(target_user));
			assert_eq!(entry.impersonating_user_id, Some(admin_user));
		}
	}

	mod constants {
		use super::*;

		#[test]
		fn retention_days_is_90() {
			assert_eq!(DEFAULT_AUDIT_RETENTION_DAYS, 90);
		}
	}

	mod proptest_tests {
		use super::*;

		fn arb_severity() -> impl Strategy<Value = AuditSeverity> {
			prop_oneof![
				Just(AuditSeverity::Debug),
				Just(AuditSeverity::Info),
				Just(AuditSeverity::Notice),
				Just(AuditSeverity::Warning),
				Just(AuditSeverity::Error),
				Just(AuditSeverity::Critical),
			]
		}

		proptest! {
			#[test]
			fn severity_ordering_is_transitive(a in arb_severity(), b in arb_severity(), c in arb_severity()) {
				if a <= b && b <= c {
					prop_assert!(a <= c);
				}
			}

			#[test]
			fn severity_ordering_is_antisymmetric(a in arb_severity(), b in arb_severity()) {
				if a <= b && b <= a {
					prop_assert_eq!(a, b);
				}
			}

			#[test]
			fn severity_ordering_is_total(a in arb_severity(), b in arb_severity()) {
				prop_assert!(a <= b || b <= a);
			}

			#[test]
			fn severity_serde_roundtrip(severity in arb_severity()) {
				let json = serde_json::to_string(&severity).unwrap();
				let roundtrip: AuditSeverity = serde_json::from_str(&json).unwrap();
				prop_assert_eq!(severity, roundtrip);
			}

			#[test]
			fn builder_with_arbitrary_strings(
				action in ".*",
				ip in "[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}",
				trace in "[a-f0-9]{32}",
			) {
				let entry = AuditLogBuilder::new(AuditEventType::Login)
					.action(&action)
					.ip_address(&ip)
					.trace_id(&trace)
					.build();

				prop_assert_eq!(entry.action, action);
				prop_assert_eq!(entry.ip_address, Some(ip));
				prop_assert_eq!(entry.trace_id, Some(trace));
			}
		}
	}
}
