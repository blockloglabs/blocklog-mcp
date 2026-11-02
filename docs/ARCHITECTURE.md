# Blocklog MCP Server Architecture

The **Blocklog MCP Server** (`blocklog-mcp`) serves as a secure, authoritative gateway and execution proxy for LLM agents. It bridges agent reasoning environments (such as Claude Desktop, Cursor, or autonomous agent clusters) with the **Blocklog Control Plane** and external third-party tools.

---

## 1. High-Level System Architecture

```
+-------------------------------------------------------------+
|                     AI Agent Client                         |
|   (Claude Desktop, Cursor, Cline, Autonomous Swarms)        |
+-------------------------------------------------------------+
                              │
               Model Context Protocol (JSON-RPC)
                 - stdio (local desktop)
                 - Streamable HTTP + SSE (remote)
                              │
                              ▼
+─────────────────────────────────────────────────────────────+
│                  Blocklog MCP Gateway                       │
│                                                             │
│  ┌───────────────────────┐       ┌───────────────────────┐  │
│  │     Tool Registry     │       │   Resource Provider   │  │
│  │ (22 Authoritative     │       │ (Dynamic & Static     │  │
│  │  Gateway Tools)       │       │  Audit Resources)     │  │
│  └──────────┬────────────┘       └──────────┬────────────┘  │
│             │                               │               │
│             ▼                               ▼               │
│  ┌───────────────────────────────────────────────────────┐  │
│  │           Security & Normalization Core               │  │
│  │   - Unicode NFC Normalization                         │  │
│  │   - RFC 8785 JSON Canonicalization (sorted keys)      │  │
│  │   - SHA-256 Expected Args Hash derivation             │  │
│  │   - Argument Payload Limit Enforcement                │  │
│  └──────────────────────────┬────────────────────────────┘  │
│                             │                               │
│  ┌──────────────────────────┴────────────────────────────┐  │
│  │           Independent Cryptographic Engine            │  │
│  │   - RFC 6962 Merkle Tree Inclusion Proofs             │  │
│  │   - RFC 6962 Consistency Verification                 │  │
│  │   - Ed25519 Digital Signature Verification            │  │
│  │   - Multi-Anchor Trust Root Validation                │  │
│  └──────────────────────────┬────────────────────────────┘  │
+─────────────────────────────┼───────────────────────────────+
                              │ Authenticated HTTPS / HMAC
                              ▼
+─────────────────────────────────────────────────────────────+
│             Blocklog Authoritative Backend                  │
│                                                             │
│  ┌─────────────────┐  ┌──────────────────┐  ┌─────────────┐ │
│  │ Policy Engine   │  │ Single-Use Token │  │  HITL Appr. │ │
│  │ & Guardrails    │  │ Consumption Unit │  │  Workflow   │ │
│  └─────────────────┘  └──────────────────┘  └─────────────┘ │
│  ┌────────────────────────────────────────────────────────┐ │
│  │ Cryptographic Audit Ledger & Receipt Issuance (Ed25519)│ │
│  └────────────────────────────────────────────────────────┘ │
+─────────────────────────────────────────────────────────────+
                              │ Executed Action
                              ▼
+─────────────────────────────────────────────────────────────+
│       External Target (Stripe, GitHub, AWS, DB, APIs)       │
+─────────────────────────────────────────────────────────────+
```

---

## 2. Core Architectural Principles

### 2.1 Fail-Closed Security
Every operation defaults to denying access:
- If a tenant policy evaluation cannot be completed, execution is halted immediately.
- If network communication with the backend fails during token authorization or consumption, the tool invocation returns a sanitized error and executes no side effects.
- If cryptographic verification of a receipt fails (signature mismatch, untrusted key, or invalid Merkle proof), the receipt is rejected.

### 2.2 Atomic Two-Phase Execution
To prevent hallucinated duplicate executions or altered parameters:
1. **Prepare Phase** (`blocklog_prepare_execution` / `blocklog_authorize_action`):
   - Arguments are normalized using Unicode NFC.
   - Keys are sorted and encoded canonically.
   - A deterministic SHA-256 hash (`expected_args_hash`) is generated.
   - A short-lived, single-use cryptographic token is issued, bound to this exact hash.
2. **Execute Phase** (`blocklog_execute_action`):
   - The token is re-validated against current policy.
   - The token is atomically consumed on the authoritative backend.
   - The target integration adapter executes.
   - The outcome is recorded and a tamper-evident receipt is signed.

### 2.3 Independent Offline Verification
The MCP server contains a standalone, pure-Rust cryptographic verifier (`mcp/src/verifier/` and `mcp/src/merkle.rs`). Even if the remote backend were compromised or unavailable, the MCP server independently proves:
- Payload hash integrity against canonical NFC JSON.
- Ed25519 signature validity against configured trust roots.
- RFC 6962 Merkle tree inclusion paths up to the signed transparency root.
- Optional counterparty and witness signatures.

---

## 3. Supported Transports

### Standard I/O (`stdio`)
- Default mode for desktop clients like Claude Desktop, Cursor, or Cline.
- Communicates via newline-delimited JSON-RPC over stdin/stdout.
- Requires `BLOCKLOG_API_KEY` to be passed via environment variables.

### Streamable HTTP (`streamable-http`)
- Exposes a high-performance HTTP server built on `axum` and `tower-http`.
- Implements Server-Sent Events (SSE) streaming for real-time progress and notifications.
- Supports per-request tenant authentication via the `X-Blocklog-API-Key` or `Authorization: Bearer <key>` header.
- Enforces strict Host header validation (`BLOCKLOG_HTTP_ALLOWED_HOSTS`) and CORS origin rules.

### Concurrent Mode (`both`)
- Spawns both the stdio loop and the HTTP server concurrently within the Tokio runtime.
- Allows local desktop developers to inspect server status over HTTP while interacting via Claude Desktop.

---

## 4. Operating Modes

| Mode | Behavior | Use Case |
| :--- | :--- | :--- |
| `enforce` | Full enforcement. Policies are verified, single-use tokens are consumed, live side effects are dispatched, and receipts are recorded. | Production agent deployments. |
| `audit` | Dry-run simulation mode. Permissions are evaluated and logged, but external side effects are not dispatched. | Development, policy benchmarking, shadow testing. |
