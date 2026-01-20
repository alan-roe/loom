# Local Execution Backend Specification

**Status:** Draft
**Domain:** Weaver Execution
**Last Updated:** 2026-01-20

---

## 1. Overview

### Architecture Context

Weavers are isolated execution environments that run the `loom` CLI. The loom CLI inside a weaver connects BACK to loom-server's LLM proxy for Anthropic API calls. We are only replacing the execution backend, not the LLM layer.

```
┌─────────────────────────────────────────────────────────────────┐
│                        loom-server                              │
│  ┌─────────────────┐    ┌─────────────────────────────────┐    │
│  │  Provisioner    │    │  LLM Proxy (Anthropic API)      │    │
│  │  uses K8sClient │    │  ← unchanged, calls anthropic   │    │
│  │  trait ←────────┼────┼── weaver connects back here     │    │
│  └────────┬────────┘    └─────────────────────────────────┘    │
└───────────┼─────────────────────────────────────────────────────┘
            │ K8sClient trait
            ▼
    ┌───────────────────────────────────────┐
    │ KubeClient (K8s)  OR  LocalClient     │  ← WE REPLACE THIS
    └───────────────────────────────────────┘
            │
            ▼
    ┌───────────────┐
    │ Weaver        │
    │ runs: loom    │ ──→ connects to loom-server for LLM proxy
    └───────────────┘
```

### Purpose

The Local Execution Backend (`loom-server-local`) provides a `K8sClient` trait implementation that spawns weaver processes directly on the host machine instead of Kubernetes pods. It enables Loom development and usage on macOS/Linux without container orchestration.

### Goals
- Enable full Loom functionality on localhost without Kubernetes
- Maintain API compatibility with existing `Provisioner` code (zero changes needed to Provisioner)
- Support macOS as the primary target platform
- Run the same `loom` CLI that K8s weavers run

### Non-Goals
- Container isolation (processes run as current user)
- Network isolation (localhost networking)
- eBPF audit (deferred - `audit_enabled: false`)
- Multi-tenant security (single-user development use case)
- Replacing the LLM proxy layer (unchanged)

---

## 2. Domain Model

```rust
use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use chrono::{DateTime, Utc};
use futures::Stream;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::Mutex;

// Import types via re-exports from loom-server-k8s (NOT directly from k8s-openapi)
use loom_server_k8s::{
    K8sClient, K8sError, LogOptions, LogStream, AttachedProcess, TokenReviewResult,
    Pod, PodSpec, PodStatus, Container, Namespace,
};
// These must come from k8s-openapi directly (not re-exported)
use k8s_openapi::apimachinery::pkg::apis::meta::v1::{ObjectMeta, Time};

use loom_server_weaver::types::{WeaverId, WeaverStatus};

/// K8s Pod → Local Process (internal implementation detail)
pub struct LocalWeaver {
    pub id: WeaverId,
    pub pid: u32,
    pub working_dir: PathBuf,
    pub status: WeaverStatus,
    pub metadata: WeaverMetadata,
    pub tmux_session: String,  // tmux session name for attach
}

/// K8s Labels/Annotations → Metadata file
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WeaverMetadata {
    pub id: WeaverId,
    pub owner_user_id: String,
    pub org_id: String,
    pub image: String,
    pub tags: HashMap<String, String>,
    pub lifetime_hours: u32,
    pub created_at: DateTime<Utc>,
}

impl WeaverMetadata {
    /// Convert to K8s-style labels BTreeMap
    pub fn to_labels(&self) -> BTreeMap<String, String> {
        let mut labels = BTreeMap::new();
        labels.insert("loom.dev/managed".into(), "true".into());
        labels.insert("loom.dev/weaver-id".into(), self.id.to_string());
        labels.insert("loom.dev/owner-user-id".into(), self.owner_user_id.clone());
        labels
    }

    /// Convert to K8s-style annotations BTreeMap
    pub fn to_annotations(&self) -> BTreeMap<String, String> {
        let mut annotations = BTreeMap::new();
        annotations.insert("loom.dev/tags".into(), serde_json::to_string(&self.tags).unwrap_or_default());
        annotations.insert("loom.dev/lifetime-hours".into(), self.lifetime_hours.to_string());
        annotations
    }
}

/// Our implementation - parallel to KubeClient in loom-server-k8s
pub struct LocalClient {
    base_dir: PathBuf,
    weavers: Arc<Mutex<HashMap<WeaverId, LocalWeaver>>>,
    config: LocalConfig,
}

#[derive(Debug, Clone)]
pub struct LocalConfig {
    pub base_dir: PathBuf,
    pub command: String,
    pub server_url: String,
}
```

---

## 3. Aggregate Invariants

- Only one process per WeaverId (enforced by PID file locking)
- Working directory must exist before process spawn
- Metadata file must be written atomically (write to temp, rename)
- Process cleanup must remove both process, tmux session, and directory
- Each weaver runs inside a tmux session (matches K8s behavior, survives server restart)
- **Startup reconciliation**: On LocalClient init, scan existing weaver directories, verify tmux sessions exist and processes are alive, reconcile in-memory state with filesystem

---

## 4. Behaviors

### Create Weaver (implements `create_pod`)
**Given** a Pod spec with labels, annotations, and container config
**When** `create_pod` is called
**Then**
  - Extract weaver ID from `metadata.labels["loom.dev/weaver-id"]`
  - Create directory `~/loom-weavers/weaver-{id}/workspace/`
  - Write metadata to `.loom/metadata.json`
  - If `LOOM_REPO` env var in pod spec, `git clone` into workspace
  - Create tmux session: `tmux new-session -d -s weaver-{id} -c {workspace_dir}`
  - Configure tmux logging: `tmux pipe-pane -t weaver-{id} "cat >> .loom/output.log"`
  - Run loom CLI in tmux: `tmux send-keys -t weaver-{id} "LOOM_SERVER_URL={url} loom" Enter`
  - Write tmux session PID to `.loom/pid`
  - Store tmux session name in `LocalWeaver` for later `exec_attach`
  - Return Pod with status.phase = "Running"
  - **Note**: Provisioner ignores the return value and polls via `get_pod` separately

### Get Weaver Status (implements `get_pod`)
**Given** a pod name (format: `weaver-{uuid}`)
**When** `get_pod` is called
**Then**
  - Parse WeaverId from pod name
  - Read PID from `.loom/pid`
  - Check if process is alive (`kill -0 $pid`)
  - Map to phase: "Running" if alive, "Succeeded" if exited 0, "Failed" if exited non-zero
  - Return Pod with all required fields populated (see Minimum Pod Fields)

### List Weavers (implements `list_pods`)
**Given** a label selector (e.g., `loom.dev/managed=true`)
**When** `list_pods` is called
**Then**
  - Scan `~/loom-weavers/weaver-*/` directories
  - Filter by metadata fields matching selector (simple `key=value` parsing)
  - Return list of Pod objects

### Delete Weaver (implements `delete_pod`)
**Given** a pod name and grace period
**When** `delete_pod` is called
**Then**
  - Parse WeaverId from pod name
  - Kill tmux session: `tmux kill-session -t weaver-{id}` (sends SIGHUP to all processes)
  - Wait grace period seconds for clean shutdown
  - If directory still exists, remove `~/loom-weavers/weaver-{id}/`
  - Remove from in-memory `weavers` map

### Stream Logs (implements `stream_logs`)
**Given** a pod name
**When** `stream_logs` is called
**Then**
  - Tail `.loom/output.log` (fed by tmux pipe-pane, container param is ignored)
  - Return `Pin<Box<dyn Stream<Item = Result<Bytes, std::io::Error>> + Send>>`

### Attach Terminal (implements `exec_attach`)
**Given** a pod name
**When** `exec_attach` is called
**Then**
  - Parse WeaverId from pod name
  - Spawn `tmux attach-session -t weaver-{id}` with PTY via `portable-pty`
  - Return `AttachedProcess { stdin, stdout }` connected to PTY
  - **Note**: tmux session survives server restart; attach always works for live weavers

### Validate Token (implements `validate_token`)
**Given** any token and audiences slice
**When** `validate_token(token: &str, audiences: &[&str])` is called
**Then**
  - Ignore both `token` and `audiences` parameters (local dev has no auth)
  - Return `TokenReviewResult::authenticated("local-user", vec![], HashMap::new(), vec![])`

### Get Namespace (implements `get_namespace`)
**Given** namespace name (ignored)
**When** `get_namespace` is called
**Then**
  - Ensure `~/loom-weavers/` exists (create if not)
  - Return `Namespace::default()`

---

## 5. Minimum Pod Fields Required

The Provisioner reads these fields from Pod objects. LocalClient must populate them:

```rust
Pod {
    metadata: ObjectMeta {
        name: Some(format!("weaver-{}", id)),           // REQUIRED
        labels: Some(BTreeMap from {
            "loom.dev/managed" => "true",               // REQUIRED for list filtering
            "loom.dev/weaver-id" => id.to_string(),     // REQUIRED for ID parsing
            "loom.dev/owner-user-id" => owner,          // optional, defaults ""
        }),
        annotations: Some(BTreeMap from {
            "loom.dev/tags" => json_string,             // optional, defaults "{}"
            "loom.dev/lifetime-hours" => "4",           // optional, defaults "4"
        }),
        creation_timestamp: Some(Time(created_at)),     // optional, defaults now
        deletion_timestamp: None,                        // set for Terminating status
        ..Default::default()
    },
    spec: Some(PodSpec {
        containers: vec![Container {
            image: Some(image_string),                  // REQUIRED for weaver.image
            ..Default::default()
        }],
        ..Default::default()
    }),
    status: Some(PodStatus {
        phase: Some("Running".to_string()),             // REQUIRED
        message: Some("...".to_string()),               // optional, used on Failed
        ..Default::default()
    }),
}
```

---

## 6. Success Criteria

- [ ] All 8 K8sClient trait methods implemented
- [ ] Existing Provisioner works without modification
- [ ] Weaver lifecycle works: create → get → attach → delete
- [ ] Loom CLI in weaver can reach loom-server LLM proxy
- [ ] Log streaming returns valid `LogStream` type
- [ ] TTL cleanup finds and removes expired weavers
- [ ] Process isolation: each weaver in separate tmux session + directory
- [ ] Graceful shutdown: tmux kill-session → wait → cleanup
- [ ] Startup reconciliation recovers existing weavers (tmux sessions survive server restart)
- [ ] Attach works after server restart (tmux session persistence)

---

## 7. Boundaries (for AI agents)

✅ **Always do**:
- Run `cargo test -p loom-server-local` before committing
- Run `cargo clippy -p loom-server-local` and fix warnings
- Verify trait implementation matches K8sClient exactly

⚠️ **Ask first**:
- Adding new crate dependencies beyond those listed
- Any changes to `loom-server-k8s` trait definitions
- Any changes to Provisioner code

🚫 **Never**:
- Modify files outside `crates/loom-server-local/` (except wiring in api.rs and config)
- Add container/Docker dependencies
- Modify LLM proxy layer
- Use `unsafe` without explicit approval

---

## 8. Configuration & Dependencies

### Wiring into loom-server

**Two locations** in `crates/loom-server/src/api.rs` need modification (lines ~487 and ~549):

```rust
use loom_server_local::LocalClient;

// Replace KubeClient::new() with conditional:
let k8s_client: Arc<dyn K8sClient> = if config.weaver.backend == "local" {
    Arc::new(LocalClient::new(&config.weaver)?)
} else {
    Arc::new(KubeClient::new().await?)
};
```

**Config addition** in `crates/loom-server-config/src/sections/weaver.rs`:

```rust
// Add to WeaverConfigLayer:
pub backend: Option<String>,  // "k8s" (default) or "local"

// Add to WeaverConfig:
pub backend: String,

// Default:
backend: self.backend.unwrap_or_else(|| "k8s".to_string()),
```

### Workspace Setup

**Root Cargo.toml** additions:
```toml
# In [workspace.members]:
"crates/loom-server-local",

# In [workspace.dependencies]:
loom-server-local = { path = "crates/loom-server-local" }
```

**loom-server/Cargo.toml** addition:
```toml
loom-server-local = { workspace = true }
```

### Crate Dependencies

```toml
[package]
name = "loom-server-local"
version = "0.1.0"
edition = "2021"

[dependencies]
# Async runtime
tokio = { version = "1", features = ["full", "process", "sync"] }
async-trait = "0.1"
futures = "0.3"

# PTY handling
portable-pty = "0.8"

# Process signals (Unix) - for checking if processes are alive
nix = { version = "0.27", features = ["signal", "process"] }

# Note: tmux is a runtime dependency (not a Rust crate)
# macOS: brew install tmux
# Linux: apt install tmux

# Serialization
serde = { version = "1", features = ["derive"] }
serde_json = "1"

# Time handling
chrono = { version = "0.4", features = ["serde"] }

# Logging
tracing = "0.1"

# Streaming types
bytes = "1"
tokio-util = { version = "0.7", features = ["io"] }

# Sibling crates (for trait and types)
loom-server-k8s = { workspace = true }
loom-server-weaver = { workspace = true }

# Note: k8s-openapi NOT needed as direct dep - use re-exports from loom-server-k8s
# Exception: ObjectMeta and Time need direct import
k8s-openapi = { workspace = true }
```

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `LOOM_LOCAL_WEAVERS_DIR` | Base directory for weaver workspaces | `~/loom-weavers` |

### Runtime Dependencies

| Dependency | Required | Installation |
|------------|----------|--------------|
| `tmux` | Yes | macOS: `brew install tmux`, Linux: `apt install tmux` |
| `git` | Optional | For `LOOM_REPO` cloning |

---

## 9. Implementation Notes

### Directory Structure
```
~/loom-weavers/
├── weaver-{uuid7}/
│   ├── .loom/
│   │   ├── metadata.json    # Labels, annotations, timestamps
│   │   ├── pid              # tmux server PID
│   │   └── output.log       # Captured output (via tmux pipe-pane)
│   └── workspace/           # Git clone or working files
```

### What Runs in a Weaver

Both K8s and local weavers use tmux for session persistence:

**K8s**: `tmux new-session -A -s loom "loom"`
**Local**: Same pattern, managed via `std::process::Command`

```rust
use std::process::Command;

// Create detached tmux session
Command::new("tmux")
    .args(["new-session", "-d", "-s", &session_name, "-c", &workspace_dir])
    .status()?;

// Enable logging via pipe-pane
Command::new("tmux")
    .args(["pipe-pane", "-t", &session_name, &format!("cat >> {}", log_path)])
    .status()?;

// Start loom CLI inside the session
Command::new("tmux")
    .args(["send-keys", "-t", &session_name, &format!("LOOM_SERVER_URL={} loom", server_url), "Enter"])
    .status()?;

// For exec_attach: spawn `tmux attach-session -t {session}` with PTY
let pair = pty_system.openpty(PtySize::default())?;
let cmd = CommandBuilder::new("tmux");
cmd.args(["attach-session", "-t", &session_name]);
let child = pair.slave.spawn_command(cmd)?;
// pair.master returned as AttachedProcess
```

### Error Mapping

| Local Error | K8sError Variant |
|-------------|------------------|
| Directory not found | `K8sError::PodNotFound { name }` |
| tmux session create failed | `K8sError::ApiError { message }` |
| PID file missing | `K8sError::PodNotFound { name }` |
| tmux kill-session failed | `K8sError::ApiError { message }` |
| Log file read error | `K8sError::StreamError { message }` |
| tmux attach failed | `K8sError::AttachError { message }` |
| Namespace dir missing | `K8sError::NamespaceNotFound { name }` |

### Label Selector Parsing

Support simple `key=value` selectors (what Provisioner uses):

```rust
fn matches_selector(metadata: &WeaverMetadata, selector: &str) -> bool {
    if selector.is_empty() {
        return true;
    }
    let labels = metadata.to_labels();
    selector.split(',').all(|part| {
        if let Some((key, value)) = part.split_once('=') {
            labels.get(key).map(|v| v == value).unwrap_or(false)
        } else {
            true
        }
    })
}
```

### Crate Structure

```
crates/loom-server-local/
├── Cargo.toml
└── src/
    ├── lib.rs              # Re-exports LocalClient
    ├── client.rs           # LocalClient impl K8sClient
    ├── config.rs           # LocalConfig
    ├── weaver.rs           # LocalWeaver, WeaverMetadata
    ├── pod_builder.rs      # local_weaver_to_pod conversion
    └── error.rs            # Error mapping to K8sError
```
