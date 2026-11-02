# Changelog

All notable changes to the Blocklog Model Context Protocol (`blocklog-mcp`) server will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.1.0] - 2026-11-02

### Added
- **MCP Server Core**: Implemented with `rmcp` 3.8.0 supporting Model Context Protocol specification.
- **Dual Transport Protocol**:
  - `stdio` transport for desktop agent integration (Claude Desktop, Cursor, Cline).
  - Streamable HTTP server with Server-Sent Events (SSE) streaming support for remote agent swarms.
  - Concurrent `both` mode for mixed environments.
- **Authoritative Execution Gateway**:
  - Pre-flight policy permission checks (`blocklog_check_permission`, `blocklog_prepare_execution`).
  - Atomic two-phase execution with cryptographic single-use token consumption (`blocklog_execute_action`).
  - Fail-closed execution abort handler (`blocklog_abort_execution`).
- **Human-in-the-Loop (HITL) Workflows**:
  - Structured approval submission with rationale and policy targeting (`blocklog_request_approval`).
  - Status queries and tenant listing (`blocklog_get_approval_status`, `blocklog_list_approvals`).
  - Strict prevention of LLM self-approvals.
- **Audit & Ledger Tracing**:
  - Tamper-evident logging for events and agent decisions (`blocklog_log_event`, `blocklog_log_decision`).
  - Structured audit trail queries and policy violation analytics (`blocklog_query_logs`, `blocklog_get_policy_violations`).
  - Hierarchical trace navigation and interactive session timelines (`blocklog_get_trace`, `blocklog_list_traces`, `blocklog_get_session_timeline`).
- **Cryptographic Verification**:
  - Pure Rust verification engine validating RFC 8785 canonical NFC JSON encoding, SHA-256 digests, Ed25519 digital signatures, and RFC 6962 Merkle tree inclusion/consistency proofs.
  - Multi-root trust anchor verification for primary signers, witness notaries, and counterparty attestations.
- **MCP Dynamic Resources**:
  - Static resources (`blocklog://policies`, `blocklog://health`).
  - Dynamic template resources (`blocklog://executions/{id}`, `blocklog://receipts/{id}`, `blocklog://traces/{id}`, `blocklog://approvals/{id}`).
- **Configuration & CLI**:
  - Comprehensive environment variable parser and CLI flags (`--transport`, `--mode`, `--version`, `--help`).
  - Configurable allowed hosts, allowed CORS origins, payload size limits, and timeout controls.
