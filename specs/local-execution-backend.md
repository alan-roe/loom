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
- Maintain API compatibility with existing `Provisioner` code (zero changes needed)
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
// Reuse existing Loom types from loom-server-weaver and loom-server-k8s
use loom_server_weaver::types::{WeaverId, WeaverStatus};
use loom_server_k8s::{K8sClient, K8sError, LogOptions, LogStream, AttachedProcess, TokenReviewResult};
use k8s_openapi::api::core::v1::{Pod, Namespace};

/// K8s Pod → Local Process (internal implementation detail)
pub struct LocalWeaver {
    pub id: WeaverId,              // Same UUID7 identifier
    pub pid: u32,                  // OS process ID
    pub working_dir: PathBuf,      // ~/loom-weavers/weaver-{id}/
    pub status: WeaverStatus,      // Reused from loom-server-weaver
    pub metadata: WeaverMetadata,  // Stored in .loom/metadata.json
    pub pty_master: PtyMaster,     // For exec_attach
}

/// K8s Labels/Annotations → Metadata file
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WeaverMetadata {
    pub id: WeaverId,
    pub owner_user_id: String,     // Matches existing Weaver struct
    pub org_id: String,            // Matches existing Weaver struct
    pub image: String,             // For reference only (not used locally)
    pub tags: HashMap<String, String>,  // Matches existing Weaver struct
    pub lifetime_hours: u32,
    pub created_at: DateTime<Utc>,
}

/// The trait we're implementing - imported from loom-server-k8s
/// (shown here for reference, do not redefine)
#[async_trait]
pub trait K8sClient: Send + Sync {
    async fn create_pod(&self, namespace: &str, pod: Pod) -> Result<Pod, K8sError>;
    async fn delete_pod(&self, name: &str, namespace: &str, grace_period_seconds: u32) -> Result<(), K8sError>;
    async fn list_pods(&self, namespace: &str, label_selector: &str) -> Result<Vec<Pod>, K8sError>;
    async fn get_pod(&self, name: &str, namespace: &str) -> Result<Pod, K8sError>;
    async fn get_namespace(&self, name: &str) -> Result<Namespace, K8sError>;
    async fn stream_logs(&self, name: &str, namespace: &str, container: &str, opts: LogOptions) -> Result<LogStream, K8sError>;
    async fn exec_attach(&self, name: &str, namespace: &str, container: &str) -> Result<AttachedProcess, K8sError>;
    async fn validate_token(&self, token: &str, audiences: &[&str]) -> Result<TokenReviewResult, K8sError>;
}

/// Our implementation - parallel to KubeClient in loom-server-k8s
#[derive(Debug)]
pub struct LocalClient {
    base_dir: PathBuf,
    weavers: Arc<Mutex<HashMap<WeaverId, LocalWeaver>>>,
    config: LocalConfig,
}

pub struct LocalConfig {
    pub base_dir: PathBuf,
    pub command: String,           // Default: "loom"
    pub server_url: String,        // Injected as LOOM_SERVER_URL env var
}
```

---

## 3. Aggregate Invariants

- Only one process per WeaverId (enforced by PID file locking)
- Working directory must exist before process spawn
- Metadata file must be written atomically (write to temp, rename)
- Process cleanup must remove both process and directory
- PTY master must be retained for later `exec_attach` calls
- **Startup reconciliation**: On LocalClient init, scan existing weaver directories, read PIDs, verify processes are alive, reconcile in-memory state with filesystem

---

## 4. Behaviors

### Create Weaver (implements `create_pod`)
**Given** a CreateWeaverRequest with id, env vars, and optional repo URL
**When** `create_pod` is called
**Then**
  - Create directory `~/loom-weavers/weaver-{id}/workspace/`
  - Write metadata to `.loom/metadata.json`
  - If repo specified, `git clone` into workspace
  - Spawn `loom` CLI WITH PTY via `portable-pty`
  - Inject `LOOM_SERVER_URL` env var (so loom can reach LLM proxy)
  - Redirect stdout/stderr to `.loom/stdout.log` and `.loom/stderr.log`
  - Write PID to `.loom/pid`
  - Store PTY master handle in `LocalWeaver` for later `exec_attach`
  - Return Pod-shaped response with status Pending→Running

### Get Weaver Status (implements `get_pod`)
**Given** a weaver ID
**When** `get_pod` is called
**Then**
  - Read PID from `.loom/pid`
  - Check if process is alive (`kill -0 $pid`)
  - Map to WeaverStatus: Running if alive, Succeeded/Failed if exited
  - Return Pod-shaped response with metadata from `.loom/metadata.json`

### List Weavers (implements `list_pods`)
**Given** a label selector (e.g., `loom.dev/managed=true`)
**When** `list_pods` is called
**Then**
  - Scan `~/loom-weavers/weaver-*/` directories
  - Filter by metadata fields matching selector (simple `key=value` parsing)
  - Return list of Pod-shaped responses

### Delete Weaver (implements `delete_pod`)
**Given** a weaver ID and grace period
**When** `delete_pod` is called
**Then**
  - Read PID from `.loom/pid`
  - Send SIGTERM, wait grace period
  - Send SIGKILL if still alive
  - Remove directory `~/loom-weavers/weaver-{id}/`
  - Remove from in-memory `weavers` map

### Stream Logs (implements `stream_logs`)
**Given** a weaver ID
**When** `stream_logs` is called
**Then**
  - Tail `.loom/stdout.log` and `.loom/stderr.log`
  - Return async stream of log lines (matching K8s LogStream type)

### Attach Terminal (implements `exec_attach`)
**Given** a weaver ID
**When** `exec_attach` is called
**Then**
  - Retrieve PTY master from in-memory `LocalWeaver`
  - Return AttachedProcess with bidirectional streams to PTY
  - Note: PTY was created at spawn time; this connects to existing session

### Validate Token (implements `validate_token`)
**Given** any token
**When** `validate_token` is called
**Then**
  - Return success (no-op for local development)

### Get Namespace (implements `get_namespace`)
**Given** namespace name
**When** `get_namespace` is called
**Then**
  - Check if `~/loom-weavers/` exists (create if not)
  - Return Namespace-shaped response

---

## 5. Success Criteria

- [ ] All 8 K8sClient trait methods implemented
- [ ] Existing Provisioner works without modification
- [ ] Weaver lifecycle works: create → attach → delete
- [ ] Loom CLI in weaver can reach loom-server LLM proxy
- [ ] Log streaming works with `tail -f` equivalent
- [ ] TTL cleanup finds and removes expired weavers
- [ ] Process isolation: each weaver in separate directory
- [ ] Graceful shutdown: SIGTERM → wait → SIGKILL
- [ ] Startup reconciliation recovers existing weavers

---

## 6. Boundaries (for AI agents)

✅ **Always do**:
- Run tests before committing changes
- Verify trait implementation matches K8sClient exactly
- Test on macOS

⚠️ **Ask first**:
- Adding new crate dependencies
- Any changes to `loom-server-k8s` trait definitions
- Any changes to Provisioner code

🚫 **Never**:
- Modify files outside `crates/loom-server-local/`
- Add container/Docker dependencies
- Modify LLM proxy layer

---

## 7. Configuration & Dependencies

### Wiring into loom-server

The swap happens in `crates/loom-server/src/api.rs` in `initialize_weaver_infrastructure()`:

```rust
// Current (K8s):
let k8s_client: Arc<dyn K8sClient> = Arc::new(KubeClient::new().await?);

// With LocalClient (controlled by env var):
let k8s_client: Arc<dyn K8sClient> = if std::env::var("LOOM_LOCAL_WEAVERS").is_ok() {
    Arc::new(LocalClient::new(local_config)?)
} else {
    Arc::new(KubeClient::new().await?)
};
```

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `LOOM_LOCAL_WEAVERS` | Enable local backend (presence enables) | unset |
| `LOOM_LOCAL_WEAVERS_DIR` | Base directory for weaver workspaces | `~/loom-weavers` |
| `LOOM_LOCAL_COMMAND` | Command to run in weaver | `loom` |

### Crate Dependencies

```toml
[dependencies]
tokio = { version = "1", features = ["full", "process"] }
portable-pty = "0.8"
nix = { version = "0.27", features = ["signal", "process"] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
chrono = { version = "0.4", features = ["serde"] }
tracing = "0.1"

# Import trait from sibling crate
loom-server-k8s = { path = "../loom-server-k8s" }
loom-server-weaver = { path = "../loom-server-weaver" }
k8s-openapi = { version = "0.20", features = ["v1_28"] }
```

---

## 8. Implementation Notes

### Directory Structure
```
~/loom-weavers/
├── weaver-{uuid7}/
│   ├── .loom/
│   │   ├── metadata.json    # Labels, annotations, timestamps
│   │   ├── pid              # Process ID
│   │   ├── stdout.log       # Captured stdout
│   │   └── stderr.log       # Captured stderr
│   └── workspace/           # Git clone or working files
```

### What Runs in a Weaver

In K8s, weavers run: `tmux new-session -A -s loom "loom"`

For local, we simplify (no tmux needed since we have direct PTY):
```rust
Command::new("loom")
    .current_dir(&workspace_dir)
    .env("LOOM_SERVER_URL", &config.server_url)
    .spawn_pty()
```

The `loom` CLI will connect back to loom-server at `LOOM_SERVER_URL` for LLM proxy access.

### K8s Type Compatibility

The `k8s_openapi` types (Pod, Namespace, etc.) are just structs - they can be constructed without K8s:

```rust
fn local_weaver_to_pod(weaver: &LocalWeaver) -> Pod {
    Pod {
        metadata: ObjectMeta {
            name: Some(weaver.id.as_k8s_name()),
            labels: Some(weaver.metadata.to_labels()),
            creation_timestamp: Some(Time(weaver.metadata.created_at)),
            ..Default::default()
        },
        status: Some(PodStatus {
            phase: Some(weaver.status.to_k8s_phase()),
            ..Default::default()
        }),
        ..Default::default()
    }
}
```

### Error Mapping

Map local errors to `K8sError` variants:

| Local Error | K8sError Mapping |
|-------------|------------------|
| Directory not found | `K8sError::NotFound` |
| Process spawn failed | `K8sError::ApiError` |
| PID file missing | `K8sError::NotFound` |
| Signal send failed | `K8sError::ApiError` |

### Label Selector Parsing

Support simple `key=value` selectors only (covers 90% of use cases):

```rust
fn matches_selector(metadata: &WeaverMetadata, selector: &str) -> bool {
    selector.split(',').all(|part| {
        if let Some((key, value)) = part.split_once('=') {
            metadata.labels().get(key) == Some(&value.to_string())
        } else {
            true // ignore malformed parts
        }
    })
}
```
