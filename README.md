# Blocklog Model Context Protocol (MCP) Server

[![CI](https://github.com/blockloglabs/blocklog-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/blockloglabs/blocklog-mcp/actions/workflows/ci.yml)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/Rust-1.88%2B-orange.svg)](https://www.rust-lang.org/)
[![MCP](https://img.shields.io/badge/MCP-Protocol-purple.svg)](https://modelcontextprotocol.io/)

The **Blocklog MCP Server** (`blocklog-mcp`) is an authoritative execution control plane and cryptographic audit gateway for AI agents performing consequential, financial, or data-modifying actions. 

Instead of granting LLMs direct, unmediated access to third-party tools (APIs, databases, webhooks), agents interact with Blocklog via the Model Context Protocol. Blocklog intercepts requests, checks permissions against cryptographically signed policies, coordinates Human-in-the-Loop (HITL) approvals, executes actions atomically, and issues tamper-evident RFC 6962 cryptographic receipts with Ed25519 signatures.

---

## Documentation

- [System Architecture](docs/ARCHITECTURE.md)
- [MCP Tools & Resources Reference](docs/TOOLS_REFERENCE.md)
- [Configuration & Environment Variables](docs/CONFIGURATION.md)
- [Client Integration Guide (Claude, Cursor, Cline)](docs/CLIENT_SETUP.md)
- [Security & Cryptographic Model](docs/SECURITY.md)
- [Contributing Guidelines](CONTRIBUTING.md)
- [Security Policy](SECURITY.md)

---

## Key Capabilities

- **Authoritative Pre-flight Checks**: Verify whether an action is permitted under tenant policies before execution without executing side effects (`blocklog_check_permission`, `blocklog_prepare_execution`).
- **Atomic Two-Phase Execution**: Sign, verify, and atomically consume single-use execution tokens before triggering integrations (`blocklog_execute_action`). Never repeats side effects after dispatch.
- **Human-in-the-Loop (HITL) Integration**: Route high-risk or policy-flagged actions to authorized human reviewers outside the LLM context (`blocklog_request_approval`, `blocklog_get_approval_status`, `blocklog_list_approvals`).
- **Tamper-Evident Ledger Logging**: Record agent decisions, rationale, confidence scores, and causality chains with SHA-256 integrity (`blocklog_log_event`, `blocklog_log_decision`, `blocklog_query_logs`).
- **Independent Offline Verification**: Validate cryptographic receipts in pure Rust—verifying canonical serialization (NFC), Ed25519 signatures, RFC 6962 Merkle inclusion proofs, transparency checkpoints, and counterparty attestations (`blocklog_verify_receipt`).
- **Dual Transport Support**: Run over standard I/O (`stdio`) for local desktop agents (Claude Desktop, Cursor) or Streamable HTTP (with SSE streaming) for remote agent clusters.

---

## MCP Tools Catalog

### 1. Execution Gateway
| Tool Name | Description | Read-Only |
| :--- | :--- | :---: |
| `blocklog_check_permission` | Evaluates tenant policy and returns whether an action is allowed. Audited, but issues no execution token. | No |
| `blocklog_prepare_execution` | Authorizes an action and persists an MCP-bound execution state that can later be executed. | No |
| `blocklog_authorize_action` | Requests a signed, short-lived execution token directly for custom runners. | No |
| `blocklog_execute_action` | Re-authorizes, verifies token, atomically consumes token, runs the integration adapter, records outcome, and returns a verified receipt. | No |
| `blocklog_abort_execution` | Fails closed to prevent side effects on pending executions. | No |

### 2. Human-in-the-Loop (HITL) Approvals
| Tool Name | Description | Read-Only |
| :--- | :--- | :---: |
| `blocklog_request_approval` | Submits an execution for human review with contextual rationale and reviewer targeting. | No |
| `blocklog_get_approval_status` | Checks current decision (PENDING, APPROVED, REJECTED) and reviewer metadata. | Yes |
| `blocklog_list_approvals` | Lists all tenant-scoped HITL approvals and override states. | Yes |
| `blocklog_cancel_approval` | Attempts to cancel pending review (fails closed if already decided or unsupported by backend). | No |

### 3. Audit, Tracing & Ledger
| Tool Name | Description | Read-Only |
| :--- | :--- | :---: |
| `blocklog_log_event` | Appends a structured, tamper-evident event to the Blocklog hash chain ledger. | No |
| `blocklog_log_decision` | Appends a structured agent decision event with rationale and confidence score. | No |
| `blocklog_query_logs` | Queries the audit ledger with filters (event_type, trace_id, session_id, time range). | Yes |
| `blocklog_get_policy_violations` | Summarizes recent policy denials and reason breakdown. | Yes |
| `blocklog_get_agent_activity` | Summarizes executions and activity grouped by agent/principal ID. | Yes |
| `blocklog_get_trace` | Fetches a full trace hierarchy and its constituent events. | Yes |
| `blocklog_list_traces` | Lists execution and audit traces with pagination and metadata filters. | Yes |
| `blocklog_get_session_timeline` | Retrieves chronological events for an interactive session. | Yes |

### 4. Receipts & Cryptographic Verification
| Tool Name | Description | Read-Only |
| :--- | :--- | :---: |
| `blocklog_issue_receipt` | Issues the canonical, authoritative receipt for a completed execution. | No |
| `blocklog_get_receipt` | Exports a receipt by ID and automatically executes independent local verification. | Yes |
| `blocklog_verify_receipt` | Runs pure Rust offline verification of canonical hash, Ed25519 signature, RFC 6962 Merkle tree proofs, and attestations. | Yes |

### 5. Policies & Health
| Tool Name | Description | Read-Only |
| :--- | :--- | :---: |
| `blocklog_list_policies` | Lists tenant policies and guardrails configured on the authoritative gateway. | Yes |
| `blocklog_simulate_policy` | Replays execution tokens against counterfactual policy scenarios without executing. | Yes |
| `blocklog_health` | Returns server health, active transport, mode (enforce/audit), and loaded trust roots. | Yes |

---

## MCP Resources

The server exposes standard MCP resources for direct document inspection:

- `blocklog://policies`: Active tenant policy configurations.
- `blocklog://health`: Current operational state, transport, and trust roots.
- `blocklog://executions/{execution_id}`: Dynamic template for inspecting execution state and step history.
- `blocklog://receipts/{receipt_id}`: Dynamic template for viewing raw receipt artifacts with proofs.
- `blocklog://traces/{trace_id}`: Dynamic template for inspecting complete trace event trees.
- `blocklog://approvals/{approval_id}`: Dynamic template for viewing approval requests and reviewer decisions.

---

## Quickstart

### 1. Build from Source
```bash
cd mcp
cargo build --release
```
The compiled binary will be located at `target/release/blocklog-mcp`.

### 2. Run Tests & Lints
```bash
cargo test --all-targets
cargo clippy --all-targets -- -D warnings
cargo fmt -- --check
```

### 3. Run with Docker
```bash
docker build -t blocklog-mcp .
docker run -p 8080:8080 \
  -e BLOCKLOG_BACKEND_URL=https://api.blocklogsecurity.com \
  -e BLOCKLOG_API_KEY=blk_live_your_api_key_here \
  blocklog-mcp
```

### 4. Connect to Claude Desktop
Add to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "blocklog": {
      "command": "/absolute/path/to/blocklog-mcp",
      "args": ["--transport", "stdio", "--mode", "enforce"],
      "env": {
        "BLOCKLOG_BACKEND_URL": "https://api.blocklogsecurity.com",
        "BLOCKLOG_API_KEY": "blk_live_your_api_key_here"
      }
    }
  }
}
```

See [docs/CLIENT_SETUP.md](docs/CLIENT_SETUP.md) for Cursor, Cline, and HTTP swarm setup.

---

## Security Model

1. **Fail-Closed by Design**: If policy evaluation fails, backend is unreachable, or token consumption fails, execution halts immediately. No destructive actions are performed.
2. **Zero-Trust Token Consumption**: Authorization tokens are single-use and tied to a canonical hash of arguments (`expected_args_hash`). They cannot be replayed or altered.
3. **No LLM Self-Approval**: Approvals cannot be completed by agent tool calls; human reviewers must approve via authorized external channels.
4. **Independent Cryptographic Receipts**: Receipts commit to canonical NFC representations of data, Merkle inclusion roots, and Ed25519 signatures that can be verified completely offline.

---

## License

This project is licensed under the [Apache License 2.0](LICENSE). See [NOTICE](NOTICE) for copyright and attribution details.
