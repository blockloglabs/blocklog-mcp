# Blocklog MCP Tools & Resources Reference

This document provides a comprehensive technical specification for all tools and resources exposed by the **Blocklog Model Context Protocol Server**.

---

## Tool Categories

1. [Execution Gateway](#1-execution-gateway)
2. [Human-in-the-Loop (HITL) Approvals](#2-human-in-the-loop-hitl-approvals)
3. [Audit, Traces & Ledger](#3-audit-traces--ledger)
4. [Receipts & Cryptographic Verification](#4-receipts--cryptographic-verification)
5. [Policy & System Health](#5-policy--system-health)
6. [MCP Resources](#6-mcp-resources)

---

## 1. Execution Gateway

### `blocklog_check_permission`
Evaluates tenant policy to determine whether an agent action is permitted prior to execution. Does not issue an execution token or execute side effects.

- **Parameters**:
  - `action_type` (*string*, required): Action identifier (e.g., `"transfer"`, `"execute_order"`).
  - `target` (*string*, required): Target entity, API endpoint, or resource ID.
  - `action_args` (*object*, required): Action arguments payload.
  - `agent_id` (*string*, optional): Agent or principal identifier.
  - `dry_run` (*boolean*, optional, default `true`): Explicit dry-run assertion.
- **Returns**: `PermissionCheckResult` containing `allowed`, `decision_reason`, `policy_id`, `risk_score`, and `requires_hitl`.

---

### `blocklog_prepare_execution`
Authorizes an intended action against tenant policies and persists an execution state on the authoritative gateway.

- **Parameters**:
  - `action_type` (*string*, required): Action category identifier.
  - `target` (*string*, required): Target system or resource.
  - `action_args` (*object*, required): Input parameters.
  - `agent_id` (*string*, optional): Identifier for the acting agent.
  - `session_id` (*string*, optional): Interactive agent session ID.
  - `trace_id` (*string*, optional): Distributed trace ID.
  - `idempotency_key` (*string*, optional): Client-generated deduplication key.
- **Returns**: `PrepareExecutionResult` with `execution_id`, `status` (`"PREPARED"` or `"PENDING_APPROVAL"`), `expected_args_hash`, and expiration timestamp.

---

### `blocklog_authorize_action`
Directly requests a cryptographically signed single-use execution token for custom or external execution runners.

- **Parameters**:
  - `action_type` (*string*, required)
  - `target` (*string*, required)
  - `action_args` (*object*, required)
  - `agent_id` (*string*, optional)
  - `ttl_seconds` (*integer*, optional, default `60`): Lifetime of the token.
- **Returns**: `AuthorizeActionResult` containing `action_token`, `expires_at`, and `expected_args_hash`.

---

### `blocklog_execute_action`
Executes an authorized action. Atomically consumes the single-use token on the control plane, triggers the integration adapter, records the result to the audit ledger, and returns a verified receipt.

- **Parameters**:
  - `execution_id` (*string*, optional): Existing prepared execution ID.
  - `action_token` (*string*, optional): Direct action authorization token.
  - `action_type` (*string*, optional): Required if using `action_token`.
  - `target` (*string*, optional): Required if using `action_token`.
  - `action_args` (*object*, optional): Required if using `action_token`.
  - `verify_receipt` (*boolean*, optional, default `true`): Perform immediate local cryptographic verification of the resulting receipt.
- **Returns**: `ExecuteActionResult` containing `execution_id`, `status` (`"COMPLETED"`, `"FAILED"`), `output`, `receipt_id`, and `receipt_verified`.

---

### `blocklog_abort_execution`
Fails closed to cancel or abort a pending execution, ensuring no subsequent tool invocation can trigger side effects.

- **Parameters**:
  - `execution_id` (*string*, required): Prepared execution ID.
  - `reason` (*string*, required): Human or agent rationale for aborting.
- **Returns**: Status confirmation indicating the execution state is transitioned to `"ABORTED"`.

---

## 2. Human-in-the-Loop (HITL) Approvals

### `blocklog_request_approval`
Submits a policy-flagged or high-risk action for human review outside the LLM context.

- **Parameters**:
  - `execution_id` (*string*, required): ID of the execution requiring approval.
  - `context_summary` (*string*, required): Summary of the agent's intent and reasoning.
  - `requested_reviewers` (*array of strings*, optional): Specific reviewer usernames or roles.
  - `timeout_seconds` (*integer*, optional, default `300`): Auto-expiry timeout.
- **Returns**: `ApprovalRequestResult` with `approval_id`, `status` (`"PENDING"`), and review link.

---

### `blocklog_get_approval_status`
Checks the current human review decision for an approval request.

- **Parameters**:
  - `approval_id` (*string*, required): Approval identifier.
- **Returns**: Current decision state (`"PENDING"`, `"APPROVED"`, `"REJECTED"`, `"TIMED_OUT"`), reviewer identity, and timestamp.

---

### `blocklog_list_approvals`
Lists all tenant-scoped approval requests with optional status filtering.

- **Parameters**:
  - `status` (*string*, optional): Filter by `"PENDING"`, `"APPROVED"`, `"REJECTED"`.
  - `limit` (*integer*, optional, default `20`): Maximum entries to return.
- **Returns**: Array of approval objects and summary counts.

---

### `blocklog_cancel_approval`
Cancels a pending approval request. Fails closed if the review has already been decided.

- **Parameters**:
  - `approval_id` (*string*, required): Approval request identifier.
  - `reason` (*string*, optional): Rationale for cancellation.

---

## 3. Audit, Traces & Ledger

### `blocklog_log_event`
Appends a structured event to the Blocklog cryptographic audit ledger.

- **Parameters**:
  - `event_type` (*string*, required): Event category (e.g., `"agent.thought"`, `"tool.call"`).
  - `data` (*object*, required): Arbitrary event metadata.
  - `session_id` (*string*, optional): Associated session identifier.
  - `trace_id` (*string*, optional): Associated trace identifier.
- **Returns**: `event_id`, canonical `event_hash`, and ledger timestamp.

---

### `blocklog_log_decision`
Specialized event recording an agent's reasoning, deliberation steps, confidence score, and alternative actions considered.

- **Parameters**:
  - `decision_type` (*string*, required): Category of decision.
  - `rationale` (*string*, required): Explanation of the reasoning.
  - `confidence_score` (*number*, required): Value between `0.0` and `1.0`.
  - `chosen_action` (*string*, required): Selected action.
  - `alternatives_considered` (*array of strings*, optional): Alternatives discarded.
- **Returns**: Tamper-evident ledger confirmation.

---

### `blocklog_query_logs`
Searches the audit ledger with indexed filters.

- **Parameters**:
  - `event_type` (*string*, optional)
  - `session_id` (*string*, optional)
  - `trace_id` (*string*, optional)
  - `start_time` (*string*, optional, RFC 3339)
  - `end_time` (*string*, optional, RFC 3339)
  - `limit` (*integer*, optional, default `50`)

---

### `blocklog_get_policy_violations`
Summarizes recent policy denials, rule violations, and risk trends for auditing.

- **Parameters**:
  - `time_window_hours` (*integer*, optional, default `24`)
  - `limit` (*integer*, optional, default `50`)

---

### `blocklog_get_agent_activity`
Aggregates activity and execution statistics grouped by agent or principal ID.

- **Parameters**:
  - `agent_id` (*string*, required)
  - `start_time` (*string*, optional)
  - `limit` (*integer*, optional, default `25`)

---

### `blocklog_get_trace`
Fetches a complete trace hierarchy, including all causally linked events, spans, and child executions.

- **Parameters**:
  - `trace_id` (*string*, required)

---

### `blocklog_list_traces`
Lists execution and audit traces with pagination and status filters.

- **Parameters**:
  - `limit` (*integer*, optional, default `20`)
  - `offset` (*integer*, optional, default `0`)

---

### `blocklog_get_session_timeline`
Retrieves a chronological event timeline for an interactive agent session.

- **Parameters**:
  - `session_id` (*string*, required)
  - `order` (*string*, optional, `"asc"` or `"desc"`, default `"asc"`)

---

## 4. Receipts & Cryptographic Verification

### `blocklog_issue_receipt`
Issues an authoritative, digitally signed cryptographic receipt for a completed execution.

- **Parameters**:
  - `execution_id` (*string*, required): Completed execution identifier.
  - `verify` (*boolean*, optional, default `true`): Run independent local verification immediately.
- **Returns**: Full receipt payload containing Ed25519 signature, Merkle inclusion proof, and verification report.

---

### `blocklog_get_receipt`
Fetches an existing receipt by ID and automatically executes independent local verification against configured trust roots.

- **Parameters**:
  - `receipt_id` (*string*, required)
  - `verify` (*boolean*, optional, default `true`)

---

### `blocklog_verify_receipt`
Performs independent, offline cryptographic verification in pure Rust on a supplied receipt JSON object.

- **Parameters**:
  - `receipt` (*object*, required): Full receipt object.
  - `trust_root_key` (*string*, optional): Hex-encoded Ed25519 public key to verify against (falls back to configured trust roots).
  - `verify_merkle` (*boolean*, optional, default `true`): Validate RFC 6962 Merkle tree inclusion proof.
- **Returns**: Detailed verification report with boolean flags for signature validity, canonical data hash match, Merkle inclusion, and any validation errors.

---

## 5. Policy & System Health

### `blocklog_list_policies`
Lists all active tenant policies, action rules, and guardrail thresholds currently enforced by the authoritative gateway.

- **Parameters**: None.

---

### `blocklog_simulate_policy`
Simulates counterfactual policy evaluations without triggering live executions or logging to production ledgers.

- **Parameters**:
  - `action_type` (*string*, required)
  - `target` (*string*, required)
  - `action_args` (*object*, required)
  - `simulated_policy_override` (*object*, optional): Custom rule definitions to test.

---

### `blocklog_health`
Returns the operational health of the MCP server, active transport, mode, backend connection state, and loaded trust root count.

- **Parameters**: None.

---

## 6. MCP Resources

The server exposes standard MCP resources:

| Resource URI | Description | Dynamic Template |
| :--- | :--- | :---: |
| `blocklog://policies` | Current active tenant policies and rules. | No |
| `blocklog://health` | Operational health and trust anchor metrics. | No |
| `blocklog://executions/{execution_id}` | Full execution state, step history, and hashes. | Yes |
| `blocklog://receipts/{receipt_id}` | Canonical receipt artifact and inclusion proofs. | Yes |
| `blocklog://traces/{trace_id}` | Complete trace event tree and causal links. | Yes |
| `blocklog://approvals/{approval_id}` | Review request details and human reviewer decision. | Yes |
