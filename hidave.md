<!--
 Copyright (c) 2025 Geoffrey Huntley <ghuntley@ghuntley.com>. All rights reserved.
 SPDX-License-Identifier: Proprietary
-->

# Observability Suite Implementation Plan

**Status:** In Progress\
**Version:** 1.3\
**Last Updated:** 2026-01-21

### Recent Progress

**2026-01-21:** Added project and issue management endpoints ✅ DEPLOYED
- Implemented remaining endpoints from crash-system spec Section 9.4 and 9.7:
  - `POST /api/crash/projects/{id}/issues/{id}/assign` — Assign issue to user
  - `DELETE /api/crash/projects/{id}/issues/{id}` — Delete issue
  - `GET /api/crash/projects/{id}` — Get project detail
  - `PATCH /api/crash/projects/{id}` — Update project
  - `DELETE /api/crash/projects/{id}` — Delete project
- Added `update_project` method to CrashRepository trait and implementation
- Added 22 new authorization tests covering all new endpoints
- All endpoints verified working in production via curl
- Commit: `d810c629`

**2026-01-21:** Added unresolve and ignore issue lifecycle endpoints ✅ DEPLOYED
- Implemented two new issue management endpoints from spec Section 9.4:
  - `POST /api/crash/projects/{id}/issues/{id}/unresolve` — Unresolve issue
  - `POST /api/crash/projects/{id}/issues/{id}/ignore` — Ignore issue
- These complete the issue lifecycle as documented in `specs/crash-system.md`
- Added 13 new authorization tests:
  - 4 for resolve_issue (auth, membership, success, 404)
  - 4 for unresolve_issue (auth, membership, success, 404)
  - 4 for ignore_issue (auth, membership, success, 404)
  - 1 for full issue lifecycle workflow
- All endpoints verified working in production via curl
- Issue lifecycle now fully supports: unresolved → resolved → unresolve, and ignore/unignore
- Commit: `660cdb97`

**2026-01-20:** Added proptest tests to loom-crash-core ✅
- Added proptest tests for ID validation in `loom-crash-core`:
  - `org_id_roundtrip` - property-based test for OrgId serialization
  - `user_id_roundtrip` - property-based test for UserId serialization
  - `person_id_roundtrip` - property-based test for PersonId serialization
  - `crash_api_key_id_roundtrip` - property-based test for CrashApiKeyId serialization
- All 26 tests pass in loom-crash-core (including 4 new proptest tests)
- This completes Phase 2.1 proptest tests for crash-core
- openapi ToSchema attributes were already present on all public types

**2026-01-20:** Implemented API key authentication for Crash SDK ✅ DEPLOYED
- Created `crates/loom-server-crash/src/api_key.rs` with Argon2 hashing:
  - `generate_api_key()` with configurable prefix
  - `hash_api_key()` using Argon2id
  - `verify_api_key()` for constant-time verification
  - Key prefixes: `loom_crash_capture_` (SDK capture), `loom_crash_admin_` (management)
- Added API key management endpoints:
  - `POST /api/crash/projects/{id}/api-keys` — Create API key (returns raw key once)
  - `GET /api/crash/projects/{id}/api-keys` — List API keys (hashes not exposed)
  - `DELETE /api/crash/projects/{id}/api-keys/{key_id}` — Revoke API key
- Added SDK capture endpoint with API key authentication:
  - `POST /api/crash/capture/sdk` — Capture with `X-Crash-Api-Key` header
  - Supports capture-type keys only (not admin keys)
  - Updates `last_used_at` on successful capture
- Added 20 authorization tests in `tests/authz/crash.rs`:
  - API key CRUD: auth required, membership required, success
  - SDK capture: valid key, invalid key, revoked key, wrong project key
- Added `post_with_header()` helper to `tests/authz/support.rs`
- Verified all endpoints working in production via curl
- This completes Phase 4.1 "Implement API key hashing with Argon2"

**2026-01-20:** Added proptest tests to loom-sessions-core ✅
- Added proptest tests for ID validation in `loom-sessions-core`:
  - `session_id_roundtrip` - property-based test for SessionId serialization
  - `session_status_roundtrip` - property-based test for SessionStatus enum
  - `platform_roundtrip` - property-based test for Platform enum
  - `session_aggregate_id_roundtrip` - property-based test for SessionAggregateId
- All 17 tests pass in loom-sessions-core (including new proptest tests)
- Verified all observability APIs via curl: crash capture, crons check-in, session tracking
- loom-cli verified working: weaver commands, version, list threads
- This completes Phase 2.3 proptest tests for sessions

**2026-01-20:** Added session tracking to loom-crash Rust SDK ✅
- Added `SessionTracker` module to `loom-crash` crate for release health metrics
- Session tracking features:
  - Auto-starts session when client is built (via `build_async()` or `start_session()`)
  - Auto-ends session when client is shut down
  - Tracks error counts from `capture_exception()` calls
  - Tracks crash counts from panic hooks
  - Deterministic sampling based on session ID hash
  - Crashed sessions always sent regardless of sample rate
- New builder options:
  - `with_session_tracking(bool)` - enable/disable session tracking
  - `session_sample_rate(f64)` - control sampling rate (0.0-1.0)
  - `session_distinct_id(String)` - set user/device identifier
- Session status determined automatically:
  - `exited` - normal shutdown
  - `errored` - had handled errors
  - `crashed` - had unhandled errors/panics
- Verified via curl: session start/end/listing all working in production
- 20 unit tests pass (including 3 new session tests)
- This completes Phase 7.1 session tracking integration

**2026-01-20:** Implemented Phase 6 - Audit Integration ✅ DEPLOYED
- Commit: `00ba80f1`
- Added 14 new AuditEventType variants for observability suite:
  - Crash events: CrashProjectCreated, CrashProjectDeleted, CrashIssueResolved,
    CrashIssueIgnored, CrashIssueAssigned, CrashIssueDeleted,
    CrashSymbolsUploaded, CrashSymbolsDeleted, CrashReleaseCreated
  - Cron events: CronMonitorCreated, CronMonitorUpdated, CronMonitorDeleted,
    CronMonitorPaused, CronMonitorResumed
- Integrated audit logging into crash route handlers:
  - `create_project` → CrashProjectCreated
  - `resolve_issue` → CrashIssueResolved
  - `create_release` → CrashReleaseCreated
  - `upload_artifacts` → CrashSymbolsUploaded
  - `delete_artifact` → CrashSymbolsDeleted
- Integrated audit logging into cron route handlers:
  - `create_monitor` → CronMonitorCreated
  - `delete_monitor` → CronMonitorDeleted
- Verified audit events are being stored in `audit_logs` table
- All 66 audit module tests pass

**2026-01-20:** Comprehensive API validation via curl and git cli ✅ VERIFIED IN PRODUCTION
- **All observability APIs validated end-to-end:**
- **Crash Analytics API:**
  - `GET /api/crash/projects?org_id={org_id}` — List projects ✅
  - `POST /api/crash/projects` — Create project ✅ (created test project `019bdb12-8e5e-7c50-ad06-22811a2be633`)
  - `POST /api/crash/capture` — Capture crash event ✅
  - `GET /api/crash/projects/{id}/issues` — List issues ✅
  - `GET /api/crash/projects/{id}/issues/{id}` — Get issue detail ✅
  - `GET /api/crash/projects/{id}/issues/{id}/events` — List issue events ✅
  - `POST /api/crash/projects/{id}/issues/{id}/resolve` — Resolve issue ✅
- **Crons Monitoring API:**
  - `POST /api/crons/monitors` — Create monitor ✅ (created `daily-backup-test` with ping key `75cfa3bf-6f43-4f76-ba0e-52d86b0e4fb3`)
  - `GET /ping/{key}` — Success ping ✅
  - `GET /ping/{key}/start` — Job starting ping ✅
  - `GET /ping/{key}/fail` — Job failed ping ✅
  - `GET /api/crons/monitors/{slug}?org_id={org_id}` — Monitor detail ✅
  - `GET /api/crons/monitors/{slug}/checkins?org_id={org_id}` — List check-ins ✅
- **Session Analytics API:**
  - `POST /api/sessions/start` — Start session ✅ (returns session_id, sampled status)
  - `POST /api/sessions/end` — End session ✅ (requires project_id, session_id, status, duration_ms)
  - `GET /api/app-sessions?project_id={project_id}` — List sessions ✅
  - `GET /api/app-sessions/releases?project_id={project_id}` — Release health ✅
- **SCM Git Hosting:**
  - `POST /api/repos` — Create repository ✅ (created `test-git-repo`)
  - Git clone via cli: `git clone https://loom.ghuntley.com/git/ghuntley-personal/test-git-repo.git` ✅
  - Git push via cli: `git push origin cannon` ✅
  - Credential helper integration: `loom credential-helper` ✅
- **Authentication:** Token retrieved from `~/.config/loom/credentials.json` (format: `lt_` prefix)
- **All endpoints require `Authorization: Bearer {token}` header (except ping endpoints which are public)**

**2026-01-20:** Created loom-crons Rust SDK ✅ DEPLOYED
- Commit: `532866e7`
- Created `loom-crons` crate for cron job monitoring:
  - `CronsClient` with builder pattern for configuration
  - `CronsClientBuilder` with auth_token, base_url, org_id, environment, release
  - `checkin_start(monitor_slug)` to start a check-in (returns CheckInId)
  - `checkin_ok(checkin_id, details)` to complete successfully
  - `checkin_error(checkin_id, details)` to complete with error
  - `with_monitor(slug, closure)` convenience wrapper for async functions
  - HTTP transport with retry support via `loom-common-http`
  - Optional crash client integration (feature `crash`) for linking failures
- Features:
  - `CheckInOk` struct with duration_ms, output fields
  - `CheckInError` struct with duration_ms, exit_code, output, crash_event_id
  - Automatic duration calculation in `with_monitor` wrapper
  - Graceful shutdown handling
  - Thread-safe client with Arc
- Verified working in production:
  - Tested SDK check-in endpoint via curl (in_progress → ok/error)
  - Tested monitor health state updates (failing → healthy)
  - Tested ping endpoints for shell script monitoring
- Added 10 unit tests for client builder, config, shutdown, defaults
- This completes Phase 7.2 of the implementation plan

**2026-01-20:** Created loom-crash Rust SDK ✅ DEPLOYED
- Created `loom-crash` crate for Rust crash analytics:
  - `CrashClient` with builder pattern for configuration
  - `CrashClientBuilder` with auth_token, base_url, project_id, release, environment
  - Panic hook integration via `install_panic_hook()`
  - Backtrace capture and parsing with Rust symbol demangling
  - Breadcrumb API for tracking events leading to crash
  - User context management (set_user, clear_user)
  - Tag management (set_tag, remove_tag)
  - Extra data attachment (set_extra)
  - HTTP transport with retry support via `loom-common-http`
  - SDK version tagging in events
- Features:
  - `capture_error()` for std::error::Error types
  - `capture_exception()` for custom exception type/value
  - `capture_message()` for manual message capture
  - Automatic SDK info in tags (sdk.name, sdk.version)
  - Graceful shutdown handling
  - Thread-safe context management with RwLock
- Verified working in production:
  - Tested capture endpoint via curl (HTTP 200, event_id, issue_id returned)
  - Tested SDK example against production server (TEST-3 created as new issue)
- Added 16 unit tests for client builder, config, tags, breadcrumbs, shutdown
- This completes Phase 7.1 of the implementation plan
- Commit: `c6334348`

**2026-01-20:** Added source map symbolication for JavaScript/TypeScript crashes ✅ DEPLOYED
- Created `loom-crash-symbolicate` crate with:
  - VLQ decoder for source map mappings
  - Source map v3 parser (`ParsedSourceMap`)
  - Symbolication processor (`SourceMapProcessor`)
  - Rust symbol demangling support
  - Source context extraction from embedded sources
- Integrated symbolication into crash capture flow:
  - Both single and batch capture endpoints now symbolicate
  - Raw (minified) stacktrace preserved in `raw_stacktrace` field
  - Symbolication runs before fingerprinting for better grouping
  - Graceful fallback if source maps unavailable
- Added `SymbolicationService` in `loom-server-crash`:
  - Async artifact lookup from database
  - Caches parsed source maps per request
  - Updates artifact `last_accessed_at` timestamps
- Added `PartialEq` derives to `Frame` and `Stacktrace` for comparison
- Verified working in production via curl:
  - Uploaded source map for release 1.0.0
  - Captured crash with minified stack trace (bundle.js:1,2,3)
  - Stack trace symbolicated to original source (src/app.ts:1,2,3)
  - Source context extracted (pre_context, context_line, post_context)
- Commit: `e423b932`
- This completes Phase 3 of the implementation plan

**2026-01-20:** Added symbol artifact cleanup background job ✅ DEPLOYED
- Created `SymbolArtifactCleanupJob` in `loom-server/src/jobs/symbol_artifact_cleanup.rs`
- Runs daily to delete symbol artifacts not accessed within 90 days
- Uses existing `delete_old_artifacts()` method from `CrashRepository`
- Deletes artifacts where:
  - `last_accessed_at` is older than cutoff, OR
  - `last_accessed_at` is null AND `uploaded_at` is older than cutoff
- Follows same pattern as `CrashEventCleanupJob`
- This completes all Phase 12.1 background jobs for the observability suite

**2026-01-20:** Added symbol artifact upload and management endpoints ✅ DEPLOYED
- Implemented complete artifact management for source map uploads:
  - `POST /api/crash/projects/{id}/artifacts` — Upload artifacts (multipart)
  - `GET /api/crash/projects/{id}/artifacts` — List artifacts
  - `GET /api/crash/projects/{id}/artifacts/{id}` — Get artifact metadata
  - `DELETE /api/crash/projects/{id}/artifacts/{id}` — Delete artifact
- Added artifact repository methods to `CrashRepository` trait:
  - `create_artifact()`, `get_artifact_by_id()`, `get_artifact_by_sha256()`
  - `get_artifact_by_name()`, `list_artifacts()`, `delete_artifact()`
  - `delete_old_artifacts()`, `update_artifact_last_accessed()`
- Features:
  - SHA256 deduplication for efficient artifact storage
  - Automatic detection of source map type and `sourcesContent` presence
  - `last_accessed_at` tracking for artifact cleanup
- Added 10 authorization tests for artifact endpoints:
  - List: auth required, membership required, success, 404 for nonexistent project
  - Get: auth required, membership required, 404 for nonexistent artifact
  - Delete: auth required, membership required, 404 for nonexistent artifact
- Verified working in production via curl (upload, list, get, deduplication, delete)
- Commit: `9d4b3480`

**2026-01-20:** Added batch crash capture endpoint ✅ DEPLOYED
- Implemented `POST /api/crash/batch` for bulk crash event ingestion
- Accepts up to 100 events per request (configurable limit)
- Returns per-event success/failure status with event_id, issue_id, short_id
- Handles mixed results gracefully (some events succeed, others fail)
- Added 7 authorization tests in `tests/authz/crash.rs`:
  - Auth required, org membership required, success with multiple events
  - Empty events returns empty result
  - Batch size limit enforced (>100 rejected)
  - Mixed success/failure handling
- Verified working locally with dev mode server
- Commit: `6b22a720`

**2026-01-20:** Verified observability suite endpoints via curl ✅ VERIFIED IN PRODUCTION
- Crash analytics:
  - Capture crash events: `POST /api/crash/capture` ✅
  - Issue listing: `GET /api/crash/projects/{id}/issues` ✅
  - Issue detail: `GET /api/crash/projects/{id}/issues/{id}` ✅
  - Issue resolution: `POST /api/crash/projects/{id}/issues/{id}/resolve` ✅
  - **Regression detection**: Resolved issue correctly transitions to "regressed" status when new crash captured ✅
    - `times_regressed` incremented
    - `regressed_in_release` populated with new release version
    - `last_regressed_at` timestamp set
  - Release tracking: `GET /api/crash/projects/{id}/releases` ✅
- Session analytics:
  - Start session: `POST /api/sessions/start` ✅ (returns session_id, sampled status)
  - End session: `POST /api/sessions/end` ✅ (requires project_id, session_id, status)
  - List sessions: `GET /api/app-sessions` ✅
  - Release health: `GET /api/app-sessions/releases` ✅ (returns crash-free rate, adoption stage)
- Crons monitoring:
  - List monitors: `GET /api/crons/monitors` ✅
  - Monitor detail: `GET /api/crons/monitors/{slug}` ✅
  - Ping endpoint: `GET /ping/{ping_key}` ✅ (updates health from "missed" to "healthy")
- Note: loom-cli is for AI assistant features; observability accessed via HTTP API
- Commit: `9ba65f95` (formatting cleanup)

**2026-01-20:** Added crash event cleanup background job ✅ DEPLOYED
- Created `CrashEventCleanupJob` in `loom-server/src/jobs/crash_event_cleanup.rs`
- Runs daily to delete crash events older than 90 days (configurable)
- Added `delete_old_events()` method to `CrashRepository` trait
- Registered in main.rs with 24-hour interval
- All 275 authz tests pass
- This completes the crash event cleanup job from Phase 12.1 of the implementation plan

**2026-01-20:** Added app session cleanup background job ✅ DEPLOYED
- Created `AppSessionCleanupJob` in `loom-server/src/jobs/app_session_cleanup.rs`
- Runs daily to delete individual app sessions older than 30 days
- Keeps session aggregates forever for historical release health metrics
- Logs deleted count and cutoff timestamp
- Registered in main.rs with 24-hour interval
- All 17 sessions authorization tests pass
- This completes the session cleanup job from Phase 12.1 of the implementation plan

**2026-01-20:** Added session aggregation background job ✅ DEPLOYED
- Created `SessionAggregationJob` in `loom-server/src/jobs/session_aggregation.rs`
- Runs hourly to aggregate app sessions into release health metrics
- Groups sessions by project_id, release, environment, hour
- Tracks: session counts by status, unique/crashed users, duration stats
- Uses upsert to handle job reruns safely
- Registered in main.rs with 1-hour interval
- Verified working in production (job registered, sessions being stored)
- Enables release health endpoints to return actual metrics
- Commit: `bf068c4`

**2026-01-19:** Added session analytics endpoints ✅ DEPLOYED
- Created `loom-sessions-core` crate with core types:
  - `Session`, `SessionId`, `SessionStatus`, `Platform` (13 unit tests)
  - `SessionAggregate`, `SessionAggregateId` with crash-free rate calculation
  - `ReleaseHealth`, `AdoptionStage` with health metrics calculation
  - `SessionsError` with thiserror
- Created `loom-server-sessions` crate with:
  - `SessionsRepository` trait with full CRUD operations
  - `SqliteSessionsRepository` implementation for sessions and aggregates
  - Session start/end, status transitions, aggregate upserts
- Added session routes to `loom-server/src/routes/app_sessions.rs`:
  - `POST /api/sessions/start` - Start session (returns session_id, sampled status)
  - `POST /api/sessions/end` - End session (with status, error_count, duration_ms)
  - `GET /api/app-sessions` - List sessions for project
  - `GET /api/app-sessions/releases` - List release health metrics
  - `GET /api/app-sessions/releases/{version}` - Get release health detail
- Added `sessions_repo` to AppState in api.rs
- Deterministic sampling based on session ID hash
- All endpoints verify org membership via project lookup
- Added 19 authorization tests in `tests/authz/sessions.rs`:
  - Session start: auth required, membership required, success
  - Session end: auth required, membership required, success
  - List sessions: auth required, membership required, success
  - Release health list: auth required, membership required, success
  - Release health detail: auth required, membership required, 404
  - Session status transitions: crashed, abnormal
- All endpoints verified working in production via curl
- Commit: `69ec3c71`

**2026-01-19:** Added crash release tracking endpoints ✅ DEPLOYED
- Added `GET /api/crash/projects/{id}/releases` - List releases for a project
- Added `POST /api/crash/projects/{id}/releases` - Create a release
- Added `GET /api/crash/projects/{id}/releases/{version}` - Get release detail
- Added release repository methods to `CrashRepository` trait:
  - `create_release()`, `get_release_by_id()`, `get_release_by_version()`
  - `list_releases()`, `update_release()`
  - `get_or_create_release()`, `increment_release_crash_count()`
- Auto-creates releases when crash events are captured with release version
- Tracks per-release stats: crash_count, new_issue_count, regression_count
- Added 12 authorization tests for release endpoints:
  - List releases: auth required, membership required, success
  - Create release: auth required, membership required, success, conflict on duplicate
  - Get release: auth required, membership required, success, 404 for nonexistent
  - Auto-creation: captures crash → auto-creates release → verifies counts
- Commit: `1c22d4c`

**2026-01-19:** Added crash SSE stream endpoint for real-time events ✅ VERIFIED IN PRODUCTION
- Added `GET /api/crash/projects/{project_id}/stream` SSE endpoint for real-time crash events
- Added `event_type()` and `init()` methods to `CrashStreamEvent` for SSE serialization
- Added `get_issue_count()` method to `CrashRepository` for init event
- Events broadcast: `init`, `crash.new`, `issue.regressed`, `issue.resolved`, `issue.assigned`, `heartbeat`
- Added 4 authorization tests for stream endpoint (auth required, membership required, success, 404)
- Verified working in production: init event returns project_id and issue_count, crash capture triggers crash.new broadcast
- Commit: `8c1c886`

**2026-01-19:** Added crash issue detail and events endpoints ✅ VERIFIED IN PRODUCTION
- Added `GET /api/crash/projects/{project_id}/issues/{issue_id}` - Issue detail endpoint
- Added `GET /api/crash/projects/{project_id}/issues/{issue_id}/events` - List events for issue
- Created comprehensive response types:
  - `IssueDetailResponse` with full issue metadata, fingerprint, timestamps
  - `IssueMetadataResponse` with exception type/value, filename, function
  - `CrashEventResponse` with full event data including stacktrace
  - `StacktraceResponse` and `FrameResponse` for detailed stack info
- Added 8 authorization tests for new endpoints:
  - Issue detail: auth required, membership required, success, 404 for nonexistent
  - Issue events: auth required, membership required, success, 404 for nonexistent
- Verified working in production via curl with full response data
- Commit: `41fe989`

**2026-01-19:** Added crash analytics core infrastructure ✅ VERIFIED IN PRODUCTION
- Created `loom-crash-core` crate with complete type definitions:
  - Core types: `CrashEvent`, `Stacktrace`, `Frame`, `Platform` (22 unit tests)
  - Issue types: `Issue`, `IssueStatus`, `IssueLevel`, `IssuePriority`
  - Project types: `CrashProject`, `CrashApiKey`, `CrashKeyType`
  - Context types: `UserContext`, `DeviceContext`, `BrowserContext`, `OsContext`, `RequestContext`
  - Breadcrumb types: `Breadcrumb`, `BreadcrumbLevel`
  - Symbol types: `SymbolArtifact`, `ArtifactType`
  - Release types: `Release`, `ReleaseId`
  - Fingerprinting: `compute_fingerprint()`, `find_culprit()`, `truncate()` functions
- Created `loom-server-crash` crate with:
  - `CrashRepository` trait and `SqliteCrashRepository` implementation
  - `CrashBroadcaster` for SSE real-time updates
- Added crash routes to `loom-server/src/routes/crash.rs`:
  - `POST /api/crash/capture` - Ingest crash event
  - `GET /api/crash/projects` - List projects
  - `POST /api/crash/projects` - Create project
  - `GET /api/crash/projects/{project_id}/issues` - List issues
  - `POST /api/crash/projects/{project_id}/issues/{issue_id}/resolve` - Resolve issue
- Added `crash_repo` and `crash_broadcaster` to AppState
- Created 12 authorization tests in `tests/authz/crash.rs`:
  - Project operations: list, create (auth, membership, success)
  - Capture operations: auth, membership, success
  - Issue operations: list auth, membership, success
- All endpoints verified working in production (return 401 without auth)
- Commit: `7e1c07e` (current trunk)

**2026-01-19:** Added SSE stream endpoint for crons monitoring ✅ VERIFIED IN PRODUCTION
- Added `GET /api/crons/stream?org_id={org_id}` SSE endpoint for real-time cron events
- Created `CronStreamEvent` types in `loom-crons-core/src/sse.rs` for event serialization
- Created `CronsBroadcaster` in `loom-server-crons/src/sse.rs` for per-org event broadcasting
- Added `crons_broadcaster` to AppState in `api.rs`
- Events broadcast: `init`, `checkin.started`, `checkin.ok`, `checkin.error`, `monitor.missed`, `monitor.timeout`, `monitor.healthy`, `heartbeat`
- All ping handlers and SDK endpoints now broadcast events after check-ins
- Added 3 authorization tests for stream endpoint (authenticated, unauthenticated, cross-org isolation)
- Verified working in production: init event returns monitors, ping triggers checkin.ok broadcast
- Commit: `0e8e538`
- Crons monitoring system is now FEATURE COMPLETE (all routes implemented)

**2026-01-19:** Added crons authorization tests and fixed cross-org security issue
- Created `crates/loom-server/tests/authz/crons.rs` with 26 comprehensive authorization tests
- Fixed security vulnerability: crons API endpoints weren't checking org membership
- Added `verify_org_membership()` to all authenticated crons handlers
- Tests cover: ping endpoints (public), monitor CRUD, check-in operations, cross-org isolation
- All authenticated endpoints now properly return 403 Forbidden for non-members
- Verified working in production via curl
- Commit: `3c50bda`

**2026-01-19:** Added missed run and timeout detector background jobs
- Added `list_overdue_monitors()` and `list_timed_out_checkins()` to CronsRepository
- Created `CronMissedRunDetectorJob` for detecting monitors that miss expected check-ins
- Created `CronTimeoutDetectorJob` for detecting in-progress check-ins exceeding max_runtime
- Both jobs registered in main.rs, running every 60 seconds
- Verified working via curl: monitor correctly transitions to "missed" health, creates system check-in
- Commit: `4347d1e`

**2026-01-19:** Added cron schedule parsing and next_expected_at calculation
- Added `schedule.rs` module with `calculate_next_expected()` function
- Support 5-field Unix cron expressions (auto-converted to 7-field format for cron crate)
- Support interval-based schedules
- Validate cron expressions and IANA timezones
- Wire up `next_expected_at` calculation in all check-in handlers
- Monitor creation now calculates initial `next_expected_at`
- Commits: `5b30c4d` (schedule implementation), `91334b4` (Cargo.nix fix)

**2026-01-19:** Added SDK check-in endpoints for programmatic cron monitoring
- Added `POST /api/crons/monitors/{slug}/checkins` for SDK check-in creation
- Added `PATCH /api/crons/checkins/{id}` for updating in-progress check-ins
- Added `GET /api/crons/checkins/{id}` for retrieving check-in details
- Full SDK monitoring flow verified via curl (in_progress → ok, error check-ins)
- Monitor health state correctly updates on check-in completion
- Commit: `87ecbb0` (SDK check-in endpoints)

**2026-01-19:** Completed crons monitoring system MVP
- Created `loom-crons-core` crate with core types (Monitor, CheckIn, Stats)
- Created `loom-server-crons` crate with SQLite repository
- Wired up HTTP routes in `loom-server/src/routes/crons.rs`
- Added nginx proxy for `/ping/` endpoints
- All ping endpoints verified working: `/ping/{key}`, `/ping/{key}/start`, `/ping/{key}/fail`
- API endpoints verified: create/list/get/delete monitors, list check-ins
- Commits: `2987673` (initial implementation), `034b4cb` (nginx proxy fix)

This document provides a detailed, phased implementation plan for Loom's observability suite: crash analytics, cron monitoring, session tracking, and unified UI. All work follows existing codebase patterns.

---

## Quick Reference

| System | Spec | Crates | Web Packages | Migration |
|--------|------|--------|--------------|-----------|
| Crash | [specs/crash-system.md](specs/crash-system.md) | `loom-crash-core`, `loom-crash` ✅, `loom-crash-symbolicate` ✅, `loom-server-crash` ✅ | `@loom/crash` | `033_crash_analytics.sql` |
| Crons | [specs/crons-system.md](specs/crons-system.md) | `loom-crons-core` ✅, `loom-crons` ✅, `loom-server-crons` ✅ | `@loom/crons` | `034_cron_monitoring.sql` |
| Sessions | [specs/sessions-system.md](specs/sessions-system.md) | `loom-sessions-core`, `loom-server-sessions` | (in `@loom/crash`) | `035_sessions.sql` (tables: `app_sessions`, `app_session_aggregates`) |
| UI | [specs/observability-ui.md](specs/observability-ui.md) | — | `web/loom-web/src/lib/components/` | — |

---

## Phase 1: Database Foundation ✅ COMPLETED

**Goal:** Create all database tables and indexes for the observability suite.

**Status:** Completed 2026-01-18

### 1.1 Create Migration Files

Based on [migration patterns](crates/loom-server/migrations/) (latest: `032_analytics.sql`):

- [x] **`crates/loom-server/migrations/033_crash_analytics.sql`**
  - Tables: `crash_projects`, `crash_api_keys`, `crash_issues`, `crash_events`, `crash_issue_persons`, `symbol_artifacts`, `crash_releases`
  - Indexes for: project lookups, fingerprint matching, timestamp ordering, person correlation
  - Reference: [specs/crash-system.md#12-database-schema](specs/crash-system.md)

- [x] **`crates/loom-server/migrations/034_cron_monitoring.sql`**
  - Tables: `cron_monitors`, `cron_checkins`, `cron_monitor_stats`
  - Indexes for: ping_key lookups, status filtering, next_expected_at ordering
  - Reference: [specs/crons-system.md#10-database-schema](specs/crons-system.md)

- [x] **`crates/loom-server/migrations/035_sessions.sql`**
  - Tables: `app_sessions`, `app_session_aggregates` (renamed from `sessions` to avoid conflict with auth sessions)
  - Indexes for: release health queries, person lookups, time-based aggregation
  - Reference: [specs/sessions-system.md#11-database-schema](specs/sessions-system.md)

### 1.2 Verification

- [x] Run `cargo build -p loom-server` to verify migrations compile
- [x] Run `cargo2nix-update` to regenerate `Cargo.nix` (migrations are `include_str!`)
- [x] Deployed to production and verified migrations ran successfully

**Notes:**
- Session tables renamed to `app_sessions` and `app_session_aggregates` to avoid conflict with existing auth `sessions` table
- Commits: `50bb10f` (initial migrations), `f4b25de` (fix session table naming)

---

## Phase 2: Core Type Crates (Partial)

**Goal:** Create shared type definitions following the `-core` crate pattern.

Reference pattern: [crates/loom-flags-core/](crates/loom-flags-core/), [crates/loom-analytics-core/](crates/loom-analytics-core/)

### 2.1 Create `loom-crash-core` ✅ COMPLETED

**Path:** `crates/loom-crash-core/`

**Status:** Completed 2026-01-19

**Structure:**
```
loom-crash-core/
├── Cargo.toml
└── src/
    ├── lib.rs           # Public exports
    ├── event.rs         # CrashEvent, Stacktrace, Frame, Platform
    ├── issue.rs         # Issue, IssueStatus, IssueLevel, fingerprinting
    ├── symbol.rs        # SymbolArtifact, ArtifactType
    ├── release.rs       # Release tracking
    ├── project.rs       # CrashProject, CrashApiKey
    ├── context.rs       # UserContext, DeviceContext, BrowserContext, etc.
    ├── breadcrumb.rs    # Breadcrumb, BreadcrumbLevel
    ├── fingerprint.rs   # Fingerprinting algorithm
    └── error.rs         # Error types with thiserror
```

**Implementation checklist:**
- [x] Create `Cargo.toml` with dependencies
- [x] Define newtype IDs: `CrashEventId`, `IssueId`, `ProjectId`, `SymbolArtifactId`
- [x] Implement `CrashEvent` struct ([specs/crash-system.md#31-crashevent](specs/crash-system.md))
- [x] Implement `Issue` struct with `IssueStatus` enum ([specs/crash-system.md#32-issue](specs/crash-system.md))
- [x] Implement fingerprinting function ([specs/crash-system.md#4-fingerprinting](specs/crash-system.md))
- [x] Add 26 unit tests for event types ✅ (2026-01-20: 4 new proptest tests)
- [x] Add `#[cfg_attr(feature = "openapi", derive(ToSchema))]` to all public types ✅
- [x] Add proptest tests for ID validation ✅ (2026-01-20: OrgId, UserId, PersonId, CrashApiKeyId)

### 2.2 Create `loom-crons-core` ✅ COMPLETED

**Path:** `crates/loom-crons-core/`

**Status:** Completed 2026-01-19

**Structure:**
```
loom-crons-core/
├── Cargo.toml
└── src/
    ├── lib.rs           # Public exports
    ├── monitor.rs       # Monitor, MonitorSchedule, MonitorStatus, MonitorHealth
    ├── checkin.rs       # CheckIn, CheckInStatus, CheckInSource
    ├── stats.rs         # MonitorStats, StatsPeriod
    └── error.rs         # Error types
```

**Implementation checklist:**
- [x] Create `Cargo.toml` (similar to crash-core)
- [x] Define newtype IDs: `MonitorId`, `CheckInId`, `OrgId`
- [x] Implement `Monitor` struct with schedule types ([specs/crons-system.md#31-monitor](specs/crons-system.md))
- [x] Implement `CheckIn` struct ([specs/crons-system.md#32-checkin](specs/crons-system.md))
- [x] Implement `MonitorStats` struct ([specs/crons-system.md#33-monitorstats](specs/crons-system.md))
- [x] Add proptest tests for type roundtrips

### 2.3 Create `loom-sessions-core` ✅ COMPLETED

**Path:** `crates/loom-sessions-core/`

**Status:** Completed 2026-01-19

**Structure:**
```
loom-sessions-core/
├── Cargo.toml
└── src/
    ├── lib.rs           # Public exports
    ├── session.rs       # Session, SessionStatus
    ├── aggregate.rs     # SessionAggregate
    ├── release_health.rs # ReleaseHealth, AdoptionStage
    └── error.rs         # Error types
```

**Implementation checklist:**
- [x] Create `Cargo.toml` ✅
- [x] Define newtype ID: `SessionId`, `SessionAggregateId` ✅
- [x] Implement `Session` struct ([specs/sessions-system.md#31-session](specs/sessions-system.md)) ✅
- [x] Implement `SessionAggregate` struct ([specs/sessions-system.md#32-sessionaggregate](specs/sessions-system.md)) ✅
- [x] Implement `ReleaseHealth` struct ([specs/sessions-system.md#33-releasehealth](specs/sessions-system.md)) ✅
- [x] Add 13 unit tests for session types ✅
- [x] Add proptest tests for ID validation ✅ (2026-01-20: 4 new proptest tests, 17 total tests)

### 2.4 Workspace Integration

- [x] Add crons crates to `Cargo.toml` workspace members ✅
- [x] Add crash crates to `Cargo.toml` workspace members ✅
- [x] Add sessions crates to `Cargo.toml` workspace members ✅
- [x] Run `cargo build --workspace` to verify crons compilation ✅
- [x] Run `cargo build --workspace` to verify crash compilation ✅
- [x] Run `cargo build --workspace` to verify sessions compilation ✅
- [x] Run `cargo2nix-update` ✅

---

## Phase 3: Source Map Symbolication ✅ COMPLETED

**Goal:** Build the symbolication engine for JavaScript/TypeScript stack traces.

**Status:** Completed 2026-01-20

Reference: [specs/crash-system.md#6-symbolication](specs/crash-system.md)

### 3.1 Create `loom-crash-symbolicate` ✅

**Path:** `crates/loom-crash-symbolicate/`

**Structure:**
```
loom-crash-symbolicate/
├── Cargo.toml
└── src/
    ├── lib.rs           # Public exports
    ├── sourcemap.rs     # SourceMap parsing and lookup
    ├── vlq.rs           # VLQ decoder for mappings
    ├── rust.rs          # Rust symbol demangling
    ├── processor.rs     # SourceMapProcessor pipeline
    └── error.rs         # Error types
```

**Implementation checklist:**
- [x] Create `Cargo.toml` with dependencies ✅
- [x] Implement VLQ decoder ([specs/crash-system.md#63-vlq-decoding](specs/crash-system.md)) ✅
  - `decode_vlq_segment()` function
  - `decode_vlq_mappings()` function
  - `DecodedMappings` with binary search lookup
- [x] Implement `ParsedSourceMap` struct ✅
  - `from_bytes()` and `from_str()` constructors
  - `lookup(line, col)` method with source root resolution
  - Embedded source content support
- [x] Implement `SourceMapProcessor` ✅
  - `symbolicate_js()` method
  - `symbolicate_rust()` method
  - `symbolicate()` method with platform dispatch
  - Source context extraction (5 lines before/after)
- [x] Implement Rust demangling wrapper using `rustc-demangle` ✅
- [x] Add 24 unit tests covering VLQ, source maps, and processor ✅

### 3.2 Integrate with Server ✅

- [x] Added `SymbolicationService` to `loom-server-crash` ✅
- [x] Integrated symbolication into `capture_crash` handler ✅
- [x] Integrated symbolication into `process_single_capture` (batch) ✅
- [x] Symbolication runs before fingerprinting for better grouping ✅
- [x] Raw stacktrace preserved in `raw_stacktrace` field ✅
- [x] Graceful fallback when source maps unavailable ✅

---

## Phase 4: Server Repositories

**Goal:** Implement database access layer following repository trait pattern.

Reference pattern: [crates/loom-server-flags/src/repository.rs](crates/loom-server-flags/src/repository.rs), [crates/loom-server-analytics/src/repository.rs](crates/loom-server-analytics/src/repository.rs)

### 4.1 Create `loom-server-crash` ✅ PARTIALLY COMPLETED (Repository Layer)

**Path:** `crates/loom-server-crash/`

**Status:** Repository layer completed 2026-01-19. Handlers implemented in loom-server/src/routes/crash.rs.

**Structure:**
```
loom-server-crash/
├── Cargo.toml
└── src/
    ├── lib.rs
    ├── repository.rs    # CrashRepository trait + SqliteCrashRepository ✅
    ├── sse.rs           # CrashBroadcaster for real-time events ✅
    ├── error.rs         # Error types ✅
    ├── fingerprint.rs   # Server-side fingerprinting (TODO)
    ├── symbolicate.rs   # Symbolication pipeline integration (TODO)
    └── api_key.rs       # API key validation (Argon2) (TODO)
```

**Implementation checklist:**
- [x] Create `Cargo.toml`:
  ```toml
  [dependencies]
  loom-crash-core = { path = "../loom-crash-core" }
  loom-crash-symbolicate = { path = "../loom-crash-symbolicate" }
  loom-db = { path = "../loom-db" }
  loom-server-audit = { path = "../loom-server-audit" }
  async-trait = "0.1"
  axum = "0.8"
  sqlx = { version = "0.8", features = ["sqlite"] }
  argon2 = "0.5"
  tokio = { version = "1", features = ["sync"] }
  tokio-stream = "0.1"
  tracing = "0.1"
  ```
- [x] Define `CrashRepository` trait with methods:
  - `create_project()`, `get_project()`, `list_projects()` ✅
  - `create_issue()`, `get_issue()`, `update_issue()`, `list_issues()` ✅
  - `create_event()`, `get_event()`, `list_events_for_issue()` ✅
  - `create_artifact()`, `get_artifact()`, `list_artifacts()` ✅
  - `create_release()`, `get_release()`, `list_releases()` ✅
- [x] Implement `SqliteCrashRepository` (basic operations) ✅
- [x] Implement fingerprinting on ingest ([specs/crash-system.md#41-default-fingerprinting-algorithm](specs/crash-system.md)) ✅
- [x] Implement regression detection ([specs/crash-system.md#52-regression-detection](specs/crash-system.md)) ✅ (verified working 2026-01-20)
- [x] Implement API key hashing with Argon2 (pattern: [crates/loom-server-analytics/src/api_key.rs](crates/loom-server-analytics/src/api_key.rs)) ✅
- [x] Implement SSE broadcaster for events ✅

### 4.2 Create `loom-server-crons` ✅ COMPLETED (Repository Layer)

**Path:** `crates/loom-server-crons/`

**Status:** Repository layer completed 2026-01-19. Handlers moved to loom-server/src/routes/crons.rs.

**Structure:**
```
loom-server-crons/
├── Cargo.toml
└── src/
    ├── lib.rs
    ├── repository.rs    # CronsRepository trait + SqliteCronsRepository
    └── error.rs         # Error types
```

**Implementation checklist:**
- [x] Create `Cargo.toml`
- [x] Define `CronsRepository` trait
- [x] Implement `SqliteCronsRepository`
- [x] Implement cron expression parser ([specs/crons-system.md#6-schedule-parsing](specs/crons-system.md)) ✅
- [x] Implement `calculate_next_expected()` function ✅
- [x] Implement ping handlers (in loom-server/src/routes/crons.rs) ([specs/crons-system.md#42-ping-endpoints](specs/crons-system.md))
- [x] Implement missed run detector job ([specs/crons-system.md#71-background-scheduler](specs/crons-system.md)) ✅
- [x] Implement timeout detector job ([specs/crons-system.md#72-timeout-detection](specs/crons-system.md)) ✅

### 4.3 Create `loom-server-sessions` ✅ PARTIALLY COMPLETED (Repository Layer)

**Path:** `crates/loom-server-sessions/`

**Status:** Repository layer completed 2026-01-19. Handlers implemented in loom-server/src/routes/app_sessions.rs.

**Structure:**
```
loom-server-sessions/
├── Cargo.toml
└── src/
    ├── lib.rs
    ├── repository.rs    # SessionsRepository trait + SqliteSessionsRepository ✅
    └── error.rs         # Error types ✅
```

**Implementation checklist:**
- [x] Create `Cargo.toml` ✅
- [x] Define `SessionsRepository` trait ✅
- [x] Implement `SqliteSessionsRepository` (basic operations) ✅
- [x] Implement sampling logic ([specs/sessions-system.md#6-sampling](specs/sessions-system.md)) ✅ (deterministic hash-based)
- [x] Implement hourly aggregation job ([specs/sessions-system.md#71-hourly-aggregation-job](specs/sessions-system.md)) ✅ (2026-01-20)
- [x] Implement cleanup job ([specs/sessions-system.md#72-cleanup-job](specs/sessions-system.md)) ✅ (2026-01-20)
- [x] Implement release health calculation ([specs/sessions-system.md#81-query-for-release-health](specs/sessions-system.md)) ✅

---

## Phase 5: HTTP Route Integration

**Goal:** Wire up HTTP handlers in loom-server.

Reference pattern: [crates/loom-server/src/routes/analytics.rs](crates/loom-server/src/routes/analytics.rs), [crates/loom-server/src/routes/flags.rs](crates/loom-server/src/routes/flags.rs)

### 5.1 Add Dependencies to loom-server

- [x] Add `loom-server-crons` dependency ✅
- [x] Add `loom-server-crash` dependency ✅
- [x] Add `loom-server-sessions` dependency ✅

### 5.2 Create Route Files

**Path:** `crates/loom-server/src/routes/`

- [x] **`crash.rs`** — Crash analytics routes ✅ COMPLETED 2026-01-21
  - `POST /api/crash/capture` — Ingest crash event ✅
  - `GET /api/crash/projects` — List projects ✅
  - `POST /api/crash/projects` — Create project ✅
  - `GET /api/crash/projects/{id}` — Get project detail ✅
  - `PATCH /api/crash/projects/{id}` — Update project ✅
  - `DELETE /api/crash/projects/{id}` — Delete project ✅
  - `GET /api/crash/projects/{id}/issues` — List issues ✅
  - `POST /api/crash/projects/{id}/issues/{id}/resolve` — Resolve issue ✅
  - `POST /api/crash/projects/{id}/issues/{id}/unresolve` — Unresolve issue ✅
  - `POST /api/crash/projects/{id}/issues/{id}/ignore` — Ignore issue ✅
  - `POST /api/crash/projects/{id}/issues/{id}/assign` — Assign issue to user ✅
  - `GET /api/crash/projects/{id}/issues/{id}` — Issue detail ✅
  - `DELETE /api/crash/projects/{id}/issues/{id}` — Delete issue ✅
  - `GET /api/crash/projects/{id}/issues/{id}/events` — List events for issue ✅
  - `GET /api/crash/projects/{id}/releases` — List releases ✅
  - `POST /api/crash/projects/{id}/releases` — Create release ✅
  - `GET /api/crash/projects/{id}/releases/{version}` — Get release detail ✅
  - `POST /api/crash/batch` — Batch ingest ✅
  - `POST /api/crash/projects/{id}/artifacts` — Upload symbols (multipart) ✅
  - `GET /api/crash/projects/{id}/artifacts` — List artifacts ✅
  - `GET /api/crash/projects/{id}/artifacts/{id}` — Get artifact ✅
  - `DELETE /api/crash/projects/{id}/artifacts/{id}` — Delete artifact ✅
  - `GET /api/crash/projects/{id}/stream` — SSE stream ✅
  - Reference: [specs/crash-system.md#9-api-endpoints](specs/crash-system.md)

- [x] **`crons.rs`** — Cron monitoring routes ✅ COMPLETED 2026-01-19
  - `GET /ping/{key}` — Success ping ✅
  - `GET /ping/{key}/start` — Job starting ✅
  - `GET /ping/{key}/fail` — Job failed ✅
  - `POST /ping/{key}` — Ping with body ✅
  - `GET /api/crons/monitors` — List monitors ✅
  - `POST /api/crons/monitors` — Create monitor ✅
  - `GET /api/crons/monitors/{slug}` — Monitor detail ✅
  - `DELETE /api/crons/monitors/{slug}` — Delete monitor ✅
  - `GET /api/crons/monitors/{slug}/checkins` — List check-ins ✅
  - `POST /api/crons/monitors/{slug}/checkins` — SDK check-in ✅
  - `PATCH /api/crons/checkins/{id}` — Update check-in ✅
  - `GET /api/crons/checkins/{id}` — Get check-in ✅
  - `GET /api/crons/stream` — SSE stream ✅
  - Reference: [specs/crons-system.md#8-api-endpoints](specs/crons-system.md)
  - Nginx proxy added in `infra/nixos-modules/loom-web.nix` for `/ping/` routes

- [x] **`app_sessions.rs`** — Session analytics routes ✅ COMPLETED 2026-01-19
  - `POST /api/sessions/start` — Start session ✅
  - `POST /api/sessions/end` — End session ✅
  - `GET /api/app-sessions` — Session list ✅
  - `GET /api/app-sessions/releases` — Release health list ✅
  - `GET /api/app-sessions/releases/{version}` — Release detail ✅
  - Reference: [specs/sessions-system.md#9-api-endpoints](specs/sessions-system.md)

### 5.3 Register Routes

- [x] Update `crates/loom-server/src/routes/mod.rs` to include crons module ✅
- [x] Update `crates/loom-server/src/api.rs` to add crons_repo to `AppState` ✅
- [x] Wire up cron route handlers in router configuration ✅
  - `/ping/*` routes on PublicRouter (unauthenticated)
  - `/api/crons/*` routes on AuthedRouter (authenticated)
- [x] Update `crates/loom-server/src/routes/mod.rs` to include crash module ✅
- [x] Update `crates/loom-server/src/api.rs` to add crash_repo and crash_broadcaster to `AppState` ✅
- [x] Wire up crash route handlers in router configuration ✅
  - `/api/crash/*` routes on AuthedRouter (authenticated)
- [x] Update `crates/loom-server/src/routes/mod.rs` to include app_sessions module ✅
- [x] Update `crates/loom-server/src/api.rs` to add sessions_repo to `AppState` ✅
- [x] Wire up sessions route handlers in router configuration ✅
  - `/api/sessions/*` routes on AuthedRouter (session start/end)
  - `/api/app-sessions/*` routes on AuthedRouter (session list, release health)

### 5.4 Add OpenAPI Documentation

- [ ] Add `#[utoipa::path(...)]` attributes to all handlers
- [ ] Add request/response types to API schemas
- [ ] Update OpenAPI tags for new sections

---

## Phase 6: Audit Integration ✅ COMPLETED

**Goal:** Add audit logging for all observability operations.

**Status:** Completed 2026-01-20 (commit `00ba80f1`)

Reference: [crates/loom-server-audit/src/event.rs](crates/loom-server-audit/src/event.rs), [specs/crash-system.md#16-audit-events](specs/crash-system.md)

### 6.1 Define Audit Event Types ✅

- [x] Add to `AuditEventType` enum:
  ```rust
  // Crash events
  CrashProjectCreated,
  CrashProjectDeleted,
  CrashIssueResolved,
  CrashIssueIgnored,
  CrashIssueAssigned,
  CrashIssueDeleted,
  CrashSymbolsUploaded,
  CrashSymbolsDeleted,
  CrashReleaseCreated,

  // Cron events
  CronMonitorCreated,
  CronMonitorUpdated,
  CronMonitorDeleted,
  CronMonitorPaused,
  CronMonitorResumed,
  ```

### 6.2 Integrate with Handlers ✅

- [x] Add audit logging to crash handlers (create_project, resolve_issue, create_release, upload_artifacts, delete_artifact)
- [x] Add audit logging to cron handlers (create_monitor, delete_monitor)
- [x] Session handlers: N/A - sessions are automated SDK telemetry, no admin actions to audit

---

## Phase 7: Rust SDK Crates

**Goal:** Create client SDKs for Rust applications.

Reference pattern: [crates/loom-analytics/](crates/loom-analytics/) (if exists), HTTP client: [crates/loom-common-http/](crates/loom-common-http/)

### 7.1 Create `loom-crash` ✅ COMPLETED

**Path:** `crates/loom-crash/`

**Status:** Completed 2026-01-20

**Structure:**
```
loom-crash/
├── Cargo.toml
├── examples/
│   └── capture.rs       # Example usage
└── src/
    ├── lib.rs           # Public exports
    ├── client.rs        # CrashClient builder and main API
    ├── panic_hook.rs    # std::panic::set_hook integration
    ├── backtrace.rs     # Backtrace capture and parsing
    └── error.rs         # Error types
```

**Implementation checklist:**
- [x] Create `Cargo.toml` with dependencies ✅
- [x] Implement `CrashClient` builder pattern ([specs/crash-system.md#81-rust-sdk-loom-crash](specs/crash-system.md)) ✅
- [x] Implement panic hook ([specs/crash-system.md#82-panic-hook-implementation](specs/crash-system.md)) ✅
- [x] Implement backtrace parsing with Rust symbol demangling ✅
- [x] Implement breadcrumb API ✅
- [x] Implement tag and extra data management ✅
- [x] Implement user context management ✅
- [x] Added 16 unit tests ✅
- [x] Verified working in production ✅
- [x] Implement session tracking integration ([specs/sessions-system.md#52-rust-sdk-session-tracking](specs/sessions-system.md)) ✅ (2026-01-20)
- [ ] Implement analytics/flags integration if features enabled

### 7.2 Create `loom-crons` ✅ COMPLETED

**Path:** `crates/loom-crons/`

**Status:** Completed 2026-01-20

**Structure:**
```
loom-crons/
├── Cargo.toml
└── src/
    ├── lib.rs           # Public exports
    ├── client.rs        # CronsClient builder and main API
    └── error.rs         # Error types
```

**Implementation checklist:**
- [x] Create `Cargo.toml` with dependencies ✅
- [x] Implement `CronsClient` ([specs/crons-system.md#51-rust-sdk-loom-crons](specs/crons-system.md)) ✅
- [x] Implement `checkin_start()`, `checkin_ok()`, `checkin_error()` ✅
- [x] Implement `with_monitor()` convenience wrapper ✅
- [x] Added 10 unit tests ✅
- [x] Verified working in production ✅
- [ ] Implement loom-jobs auto-instrumentation hook ([specs/crons-system.md#54-integration-with-loom-jobs](specs/crons-system.md))

---

## Phase 8: TypeScript SDK Packages

**Goal:** Create client SDKs for browser and Node.js applications.

Reference pattern: [web/packages/flags/](web/packages/flags/), [web/packages/analytics/](web/packages/analytics/)

### 8.1 Create `@loom/crash`

**Path:** `web/packages/crash/`

**Structure:**
```
crash/
├── package.json
├── tsconfig.json
├── vitest.config.ts
└── src/
    ├── index.ts         # Public exports
    ├── client.ts        # CrashClient
    ├── types.ts         # Type definitions
    ├── stacktrace.ts    # Stack trace parsing
    ├── global-handler.ts # window.onerror, unhandledrejection
    ├── session.ts       # Session tracking
    ├── breadcrumb.ts    # Breadcrumb management
    ├── transport.ts     # HTTP transport
    ├── errors.ts        # Error types
    └── react/
        └── error-boundary.tsx  # React error boundary
```

**Implementation checklist:**
- [ ] Create `package.json`:
  ```json
  {
    "name": "@loom/crash",
    "version": "0.1.0",
    "type": "module",
    "dependencies": {
      "@loom/http": "workspace:*"
    },
    "peerDependencies": {
      "@loom/analytics": "workspace:*",
      "@loom/flags": "workspace:*"
    },
    "peerDependenciesMeta": {
      "@loom/analytics": { "optional": true },
      "@loom/flags": { "optional": true }
    }
  }
  ```
- [ ] Implement `CrashClient` class ([specs/crash-system.md#83-typescript-sdk-loomcrash](specs/crash-system.md))
- [ ] Implement global error handlers ([specs/crash-system.md#84-global-handler-browser](specs/crash-system.md))
- [ ] Implement stack trace parsing ([specs/crash-system.md#85-stack-trace-parsing-javascript](specs/crash-system.md))
- [ ] Implement React error boundary
- [ ] Implement session tracking ([specs/sessions-system.md#55-browser-session-tracking](specs/sessions-system.md))
- [ ] Implement breadcrumb API
- [ ] Add vitest tests

### 8.2 Create `@loom/crons`

**Path:** `web/packages/crons/`

**Structure:**
```
crons/
├── package.json
├── tsconfig.json
├── vitest.config.ts
└── src/
    ├── index.ts         # Public exports
    ├── client.ts        # CronsClient
    ├── types.ts         # Type definitions
    ├── checkin.ts       # Check-in helpers
    └── errors.ts        # Error types
```

**Implementation checklist:**
- [ ] Create `package.json` (following flags/analytics pattern)
- [ ] Implement `CronsClient` class ([specs/crons-system.md#53-typescript-sdk-loomcrons](specs/crons-system.md))
- [ ] Implement `checkinStart()`, `checkinOk()`, `checkinError()`
- [ ] Implement `withMonitor()` async wrapper
- [ ] Add vitest tests

### 8.3 Update Workspace

- [ ] Add new packages to `web/pnpm-workspace.yaml`
- [ ] Run `pnpm install` to link workspaces

---

## Phase 9: Web UI Components

**Goal:** Build Svelte 5 components for the observability UI.

Reference pattern: [web/loom-web/src/lib/ui/](web/loom-web/src/lib/ui/), [web/loom-web/src/lib/components/](web/loom-web/src/lib/components/)

### 9.1 Common Components

**Path:** `web/loom-web/src/lib/components/common/`

- [ ] `StatCard.svelte` — Metric display with trend
- [ ] `Sparkline.svelte` — Mini inline chart
- [ ] `TimeRangePicker.svelte` — Time range selector
- [ ] `RelativeTime.svelte` — "5 minutes ago" display
- [ ] `CopyButton.svelte` — Copy to clipboard

### 9.2 Crash Components

**Path:** `web/loom-web/src/lib/components/crash/`

Reference: [specs/observability-ui.md#42-core-component-examples](specs/observability-ui.md)

- [ ] `IssueList.svelte` — Paginated issue list with filters
- [ ] `IssueListItem.svelte` — Single issue row
- [ ] `IssueDetail.svelte` — Full issue view
- [ ] `IssueStatusBadge.svelte` — Status indicator (Unresolved, Resolved, Regressed)
- [ ] `CrashEventCard.svelte` — Event summary
- [ ] `CrashEventDetail.svelte` — Full event with context
- [ ] `Stacktrace.svelte` — Collapsible frame viewer
- [ ] `StacktraceFrame.svelte` — Single frame with expand
- [ ] `SourceContext.svelte` — Syntax-highlighted source lines
- [ ] `Breadcrumbs.svelte` — Breadcrumb timeline
- [ ] `ActiveFlags.svelte` — Feature flags at crash time
- [ ] `UserContext.svelte` — User info display
- [ ] `SymbolUpload.svelte` — Source map upload form

### 9.3 Crons Components

**Path:** `web/loom-web/src/lib/components/crons/`

- [ ] `MonitorList.svelte` — Monitor list with health
- [ ] `MonitorListItem.svelte` — Single monitor row
- [ ] `MonitorDetail.svelte` — Monitor with history
- [ ] `MonitorForm.svelte` — Create/edit monitor
- [ ] `MonitorStatusBadge.svelte` — Status indicator
- [ ] `MonitorHealthBadge.svelte` — Health indicator
- [ ] `CheckInTimeline.svelte` — Check-in history
- [ ] `CheckInItem.svelte` — Single check-in
- [ ] `CronScheduleInput.svelte` — Cron expression input
- [ ] `PingUrlDisplay.svelte` — Ping URL with copy
- [ ] `UptimeChart.svelte` — Uptime visualization

### 9.4 Sessions Components

**Path:** `web/loom-web/src/lib/components/sessions/`

- [ ] `ReleaseHealthOverview.svelte` — Dashboard card
- [ ] `ReleaseHealthCard.svelte` — Single release health
- [ ] `ReleaseList.svelte` — All releases with metrics
- [ ] `ReleaseListItem.svelte` — Single release row
- [ ] `ReleaseDetail.svelte` — Release detail page
- [ ] `CrashFreeChart.svelte` — Crash-free rate over time
- [ ] `AdoptionChart.svelte` — Release adoption stacked area
- [ ] `SessionList.svelte` — Recent sessions
- [ ] `AdoptionStageBadge.svelte` — Adoption stage indicator

### 9.5 Create Storybook Stories

Following pattern: [web/loom-web/src/lib/ui/Button.stories.ts](web/loom-web/src/lib/ui/Button.stories.ts)

- [ ] Add `.stories.ts` file for each component
- [ ] Define argTypes for interactive controls
- [ ] Create multiple story variations
- [ ] Use `createRawSnippet()` for snippet props

---

## Phase 10: Page Routes

**Goal:** Create SvelteKit page routes for observability UI.

### 10.1 Create Route Files

**Path:** `web/loom-web/src/routes/`

```
routes/
├── (app)/
│   └── [org]/
│       └── [project]/
│           ├── overview/
│           │   └── +page.svelte
│           ├── crashes/
│           │   ├── +page.svelte          # Issue list
│           │   ├── [issueId]/
│           │   │   ├── +page.svelte      # Issue detail
│           │   │   └── events/
│           │   │       ├── +page.svelte  # Events list
│           │   │       └── [eventId]/
│           │   │           └── +page.svelte
│           │   └── releases/
│           │       ├── +page.svelte
│           │       └── [version]/
│           │           └── +page.svelte
│           ├── crons/
│           │   ├── +page.svelte          # Monitor list
│           │   ├── new/
│           │   │   └── +page.svelte
│           │   └── [slug]/
│           │       ├── +page.svelte
│           │       └── checkins/
│           │           └── +page.svelte
│           ├── sessions/
│           │   ├── +page.svelte          # Release health
│           │   ├── releases/
│           │   │   ├── +page.svelte
│           │   │   └── [version]/
│           │   │       └── +page.svelte
│           │   └── users/
│           │       ├── +page.svelte
│           │       └── [sessionId]/
│           │           └── +page.svelte
│           └── settings/
│               ├── +page.svelte
│               ├── api-keys/
│               │   └── +page.svelte
│               └── team/
│                   └── +page.svelte
```

### 10.2 Create Page Load Functions

- [ ] Create `+page.server.ts` files for data loading
- [ ] Implement API calls to observability endpoints
- [ ] Handle authentication and authorization

### 10.3 Create Layout Components

- [ ] Update sidebar navigation to include observability sections
- [ ] Create sub-navigation for each section

---

## Phase 11: SSE Real-time Integration

**Goal:** Wire up SSE for real-time updates across the UI.

### 11.1 Create SSE Client

**Path:** `web/loom-web/src/lib/realtime/`

- [ ] `observability-sse.ts` — SSE connection manager for observability
- [ ] Event handlers for: `issue.new`, `issue.regressed`, `monitor.missed`, `release.health_changed`

### 11.2 Integrate with Components

- [ ] Add SSE subscription to overview dashboard
- [ ] Add SSE subscription to issue list
- [ ] Add SSE subscription to monitor list
- [ ] Add SSE subscription to release health

### 11.3 Notification System

Reference: [specs/observability-ui.md#62-notification-system](specs/observability-ui.md)

- [ ] Create `NotificationProvider.svelte`
- [ ] Create `showNotification()` utility
- [ ] Wire up regression alerts

---

## Phase 12: Background Jobs

**Goal:** Register background jobs for observability maintenance.

Reference: [crates/loom-jobs/](crates/loom-jobs/)

### 12.1 Register Jobs

- [x] **Cron missed run detector** — Runs every minute ✅
  - Reference: [specs/crons-system.md#71-background-scheduler](specs/crons-system.md)
  - Implemented in `loom-server/src/jobs/cron_missed_run.rs`

- [x] **Cron timeout detector** — Runs every minute ✅
  - Reference: [specs/crons-system.md#72-timeout-detection](specs/crons-system.md)
  - Implemented in `loom-server/src/jobs/cron_timeout.rs`

- [x] **Session aggregator** — Runs every hour ✅
  - Reference: [specs/sessions-system.md#71-hourly-aggregation-job](specs/sessions-system.md)
  - Implemented in `loom-server/src/jobs/session_aggregation.rs`

- [x] **Session cleanup** — Runs daily ✅
  - Reference: [specs/sessions-system.md#72-cleanup-job](specs/sessions-system.md)
  - Implemented in `loom-server/src/jobs/app_session_cleanup.rs`

- [x] **Symbol artifact cleanup** — Runs daily (90 day retention) ✅
  - Reference: [specs/crash-system.md#13-retention-policy](specs/crash-system.md)
  - Implemented in `loom-server/src/jobs/symbol_artifact_cleanup.rs`

- [x] **Crash event cleanup** — Runs daily (90 day retention) ✅
  - Implemented in `loom-server/src/jobs/crash_event_cleanup.rs`

### 12.2 Job Implementation

- [ ] Add job definitions to loom-jobs
- [ ] Register jobs in server startup
- [ ] Add health checks for job execution

---

## Phase 13: Testing

**Goal:** Comprehensive test coverage for all components.

### 13.1 Unit Tests

- [ ] Core type validation (proptest)
- [ ] Fingerprinting algorithm tests
- [ ] VLQ decoder tests
- [ ] Cron expression parsing tests
- [ ] Sampling logic tests

### 13.2 Integration Tests

- [ ] Crash ingestion and fingerprinting
- [ ] Issue state transitions
- [ ] Regression detection
- [ ] Ping endpoint handling
- [ ] Missed run detection
- [ ] Session aggregation
- [ ] Release health calculation

### 13.3 Authorization Tests

Reference pattern: [crates/loom-server/tests/authz_*_tests.rs](crates/loom-server/tests/)

- [x] `tests/authz/crash.rs` — Crash endpoint authorization ✅ (74 tests: project CRUD, capture, batch capture, issues list, issue detail, issue events, issue lifecycle, issue assign/delete, releases CRUD, artifact CRUD)
- [x] `tests/authz/crons.rs` — Cron endpoint authorization ✅ (29 tests including stream endpoint)
- [x] `tests/authz/sessions.rs` — Session endpoint authorization ✅ (19 tests: session start/end, list, release health)

### 13.4 UI Tests

- [ ] Component unit tests with Testing Library
- [ ] Storybook interaction tests
- [ ] Visual regression tests (optional)

---

## Phase 14: Documentation

**Goal:** Document APIs and SDK usage.

### 14.1 OpenAPI Documentation

- [ ] Verify all endpoints have `#[utoipa::path]` attributes
- [ ] Add request/response examples
- [ ] Organize under appropriate tags

### 14.2 SDK Documentation

- [ ] README for `@loom/crash`
- [ ] README for `@loom/crons`
- [ ] README for `loom-crash` crate
- [ ] README for `loom-crons` crate

### 14.3 Integration Guides

- [ ] Getting started with crash analytics
- [ ] Setting up cron monitoring
- [ ] Understanding release health

---

## Phase 15: Deployment & Verification

**Goal:** Deploy and verify in production.

### 15.1 Pre-deployment

- [ ] Run `make check` (format + lint + build + test)
- [ ] Run `cargo2nix-update` to regenerate Cargo.nix
- [ ] Verify migrations run on clean database
- [ ] Test SDK packages locally

### 15.2 Deployment

- [ ] Commit all changes
- [ ] Push to trunk: `git push origin trunk`
- [ ] Monitor auto-update: `sudo journalctl -u nixos-auto-update.service -f`

### 15.3 Verification

- [ ] Check deployed revision: `cat /var/lib/nixos-auto-update/deployed-revision`
- [ ] Check loom-server started: `sudo systemctl status loom-server`
- [ ] Check health endpoint: `curl -s https://loom.ghuntley.com/health | jq .`
- [ ] Test crash ingestion with SDK
- [ ] Test ping endpoint with curl
- [ ] Verify UI loads correctly

---

## Summary

| Phase | Description | Estimated Effort |
|-------|-------------|------------------|
| 1 | Database migrations | 2-3 hours |
| 2 | Core type crates | 4-5 hours |
| 3 | Symbolication engine | 4-5 hours |
| 4 | Server repositories | 8-10 hours |
| 5 | HTTP route integration | 4-5 hours |
| 6 | Audit integration | 2-3 hours |
| 7 | Rust SDK crates | 6-8 hours |
| 8 | TypeScript SDK packages | 6-8 hours |
| 9 | Web UI components | 10-12 hours |
| 10 | Page routes | 4-5 hours |
| 11 | SSE integration | 3-4 hours |
| 12 | Background jobs | 3-4 hours |
| 13 | Testing | 6-8 hours |
| 14 | Documentation | 3-4 hours |
| 15 | Deployment & verification | 2-3 hours |

**Total estimated effort:** 68-87 hours

---

## Dependencies

### Build Order

```
Phase 1: Migrations (no deps)
    ↓
Phase 2: Core types (no deps except workspace)
    ↓
Phase 3: Symbolication (depends on crash-core)
    ↓
Phase 4: Server repos (depends on core + symbolicate)
    ↓
Phase 5: Routes (depends on server repos)
    ↓
Phase 6: Audit (parallel with Phase 5)
    ↓
Phase 7: Rust SDKs (depends on core)
Phase 8: TS SDKs (parallel with Phase 7)
    ↓
Phase 9-11: UI (depends on routes being ready)
    ↓
Phase 12: Background jobs (depends on server repos)
    ↓
Phase 13-15: Testing, docs, deployment
```

### Parallel Work Opportunities

- Phase 7 (Rust SDKs) and Phase 8 (TS SDKs) can run in parallel
- Phase 9 (UI components) can start once API structure is defined
- Phase 6 (Audit) can run in parallel with Phase 5 (Routes)
- Phase 13 (Testing) components can be written alongside development
