use std::sync::Arc;

use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::handler::server::wrapper::{Json, Parameters};
use rmcp::model::{
    ErrorData, Implementation, ListResourceTemplatesResult, ListResourcesResult,
    ReadResourceRequestParams, ReadResourceResponse, ReadResourceResult, Resource,
    ResourceContents, ResourceTemplate, ServerCapabilities, ServerConfig,
};
use rmcp::service::RequestContext;
use rmcp::{tool, tool_handler, tool_router, RoleServer, ServerHandler};
use serde_json::{json, Value};

use crate::args::{
    AbortExecutionArgs, ActionArgs, ApprovalStatusArgs, AuthorizeActionArgs, CancelApprovalArgs,
    EmptyArgs, ExecuteActionArgs, GetAgentActivityArgs, GetExecutionArgs, GetPolicyViolationsArgs,
    GetReceiptArgs, GetTraceArgs, IntegrationKind, IntegrationSpec, IssueReceiptArgs,
    ListApprovalsArgs, ListExecutionsArgs, ListPoliciesArgs, ListTracesArgs, LogDecisionArgs,
    LogEventArgs, QueryLogsArgs, RequestApprovalArgs, SessionTimelineArgs, SimulatePolicyArgs,
    VerifyReceiptArgs,
};
use crate::backend::{BackendClient, LogQuery, TraceQuery};
use crate::canonical::{canonical_encode, sha256_hex};
use crate::config::{Config, Mode};
use crate::error::{AppError, AppResult};
use crate::verifier::{verify_receipt as verify_receipt_local, VerificationReport, VerifyOptions};

const INSTRUCTIONS: &str = "Blocklog is the authoritative control plane for consequential agent actions. \
Use blocklog_check_permission or blocklog_prepare_execution before acting, and use blocklog_execute_action \
for actions that this server can perform. An authorization token alone is not evidence of execution. \
Never claim that money moved or an external effect occurred unless blocklog_execute_action reports it and \
you retain the resulting receipt. A valid cryptographic receipt proves authorization and recorded outcome; \
it does not by itself prove an external real-world outcome. Agent identity supplied in tool arguments is \
claimed metadata; API keys are tenant-scoped. Human approval is performed outside MCP by an authorized \
reviewer and cannot be self-approved.";

#[derive(Clone)]
pub struct BlocklogMcpServer {
    config: Arc<Config>,
    backend: BackendClient,
    tool_router: ToolRouter<Self>,
}

impl BlocklogMcpServer {
    pub fn new(config: Config) -> AppResult<Self> {
        let backend = BackendClient::new(&config)?;
        Ok(Self {
            config: Arc::new(config),
            backend,
            tool_router: Self::tool_router(),
        })
    }

    pub fn config(&self) -> &Config {
        &self.config
    }

    fn api_key(&self, context: &RequestContext<RoleServer>) -> AppResult<String> {
        if let Some(parts) = context.extensions.get::<http::request::Parts>() {
            if let Some(value) = parts.headers.get("x-api-key") {
                return header_secret(value);
            }
            if let Some(value) = parts.headers.get("authorization") {
                let value = value.to_str().map_err(|_| {
                    AppError::Unauthorized("Authorization header is not valid UTF-8".to_owned())
                })?;
                let token = value
                    .strip_prefix("Bearer ")
                    .or_else(|| value.strip_prefix("bearer "))
                    .map(str::trim)
                    .filter(|token| !token.is_empty())
                    .ok_or_else(|| {
                        AppError::Unauthorized(
                            "Authorization header must use a Bearer API key".to_owned(),
                        )
                    })?;
                return Ok(token.to_owned());
            }
            return Err(AppError::Unauthorized(
                "Missing X-API-Key header for the MCP HTTP transport".to_owned(),
            ));
        }
        self.config
            .stdio_api_key()
            .map(|secret| secret.expose().to_owned())
            .map_err(|error| AppError::Unauthorized(error.to_string()))
    }

    fn ensure_argument_size<T: serde::Serialize>(&self, args: &T) -> AppResult<()> {
        let size = serde_json::to_vec(args)
            .map_err(|error| AppError::Internal(format!("failed to size arguments: {error}")))?
            .len();
        if size > self.config.max_argument_bytes {
            return Err(AppError::Validation(format!(
                "arguments exceed the {} byte limit",
                self.config.max_argument_bytes
            )));
        }
        Ok(())
    }

    fn verify_options<'a>(&'a self, args: &'a VerifyReceiptArgs) -> VerifyOptions<'a> {
        VerifyOptions {
            public_key: args.public_key.as_deref(),
            default_public_key: self.config.receipt_public_key.as_deref(),
            trust_roots: &self.config.trust_roots,
            witness_trust_roots: &self.config.witness_trust_roots,
            counterparty_trust_roots: &self.config.counterparty_trust_roots,
            require_signature: args.verify_signature.unwrap_or(true),
            require_merkle: args.verify_merkle.unwrap_or(true),
            allowed_witness_ids: None,
        }
    }

    fn verify_value(
        &self,
        receipt: &Value,
        verify_signature: bool,
        verify_merkle: bool,
    ) -> AppResult<VerificationReport> {
        let artifact = extract_receipt_artifact(receipt)?;
        let placeholder = VerifyReceiptArgs {
            receipt: artifact.clone(),
            public_key: None,
            verify_signature: Some(verify_signature),
            verify_merkle: Some(verify_merkle),
        };
        let options = self.verify_options(&placeholder);
        Ok(verify_receipt_local(&artifact, &options))
    }

    fn audit(&self, tool: &str, execution_id: Option<&str>, decision: &str) {
        tracing::info!(
            tool,
            execution_id = execution_id.unwrap_or(""),
            decision,
            mode = %self.config.mode,
            "Blocklog MCP tool completed"
        );
    }
}

#[tool_router]
impl BlocklogMcpServer {
    #[tool(
        name = "blocklog_check_permission",
        description = "Ask Blocklog's authoritative execution gateway whether an action is permitted. This creates a tenant-scoped authorization/audit record but does not perform the action and does not return a token.",
        annotations(
            title = "Check Blocklog Permission",
            read_only_hint = false,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    async fn check_permission(
        &self,
        Parameters(action): Parameters<ActionArgs>,
        context: RequestContext<RoleServer>,
    ) -> Result<Json<Value>, ErrorData> {
        let api_key = self.api_key(&context)?;
        self.ensure_argument_size(&action)?;
        let action = action.normalized()?;
        let args_hash = action.args_hash()?;
        let payload = action.gateway_payload("check_permission", &args_hash, None);
        let response = self.backend.authorize(&api_key, &payload).await?;
        let execution_id = response.get("execution_id").and_then(Value::as_str);
        let decision = response
            .pointer("/outcome/decision")
            .and_then(Value::as_str)
            .unwrap_or("UNKNOWN");
        self.audit("blocklog_check_permission", execution_id, decision);
        Ok(Json(json!({
            "allowed": decision == "APPROVED",
            "decision": decision,
            "authorization": public_authorization(&response),
            "execution_id": execution_id,
            "args_hash": args_hash,
            "creates_execution_record": true,
            "note": "No token is returned. This is an authoritative audited check, not a dry-run.",
            "mode": self.config.mode.to_string(),
        })))
    }

    #[tool(
        name = "blocklog_authorize_action",
        description = "Request a signed, short-lived Blocklog execution token for an action. Returns the token and any human-approval requirement. The token is sensitive; do not log it.",
        annotations(
            title = "Authorize Blocklog Action",
            read_only_hint = false,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    async fn authorize_action(
        &self,
        Parameters(args): Parameters<AuthorizeActionArgs>,
        context: RequestContext<RoleServer>,
    ) -> Result<Json<Value>, ErrorData> {
        let api_key = self.api_key(&context)?;
        self.ensure_argument_size(&args)?;
        if let Some(approval_id) = &args.approval_id {
            validate_uuid(approval_id, "approval_id")?;
        }
        let action = args.action.normalized()?;
        let args_hash = action.args_hash()?;
        let payload =
            action.gateway_payload("authorize_action", &args_hash, args.approval_id.as_deref());
        let response = self.backend.authorize(&api_key, &payload).await?;
        let execution_id = response.get("execution_id").and_then(Value::as_str);
        let decision = response
            .pointer("/outcome/decision")
            .and_then(Value::as_str)
            .unwrap_or("UNKNOWN");
        self.audit("blocklog_authorize_action", execution_id, decision);
        Ok(Json(json!({
            "authorization": response,
            "args_hash": args_hash,
            "execution_id": execution_id,
            "mode": self.config.mode.to_string(),
            "warning": "The token authorizes but does not execute. Use blocklog_execute_action to consume it safely.",
        })))
    }

    #[tool(
        name = "blocklog_prepare_execution",
        description = "Authorize an action and persist an MCP-bound execution that can later be run with blocklog_execute_action. Does not return the execution token or perform the action.",
        annotations(
            title = "Prepare Blocklog Execution",
            read_only_hint = false,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    async fn prepare_execution(
        &self,
        Parameters(action): Parameters<ActionArgs>,
        context: RequestContext<RoleServer>,
    ) -> Result<Json<Value>, ErrorData> {
        let api_key = self.api_key(&context)?;
        self.ensure_argument_size(&action)?;
        let action = action.normalized()?;
        let args_hash = action.args_hash()?;
        let payload = action.gateway_payload("prepare_execution", &args_hash, None);
        let response = self.backend.authorize(&api_key, &payload).await?;
        let execution_id = response.get("execution_id").and_then(Value::as_str);
        let decision = response
            .pointer("/outcome/decision")
            .and_then(Value::as_str)
            .unwrap_or("UNKNOWN");
        self.audit("blocklog_prepare_execution", execution_id, decision);
        Ok(Json(json!({
            "allowed": decision == "APPROVED",
            "decision": decision,
            "execution_id": execution_id,
            "args_hash": args_hash,
            "authorization": public_authorization(&response),
            "approval_required": response
                .pointer("/outcome/approval_required")
                .and_then(Value::as_bool)
                .unwrap_or(false),
            "approval_id": response.get("approval_id"),
            "next": if decision == "APPROVED" {
                json!("Call blocklog_execute_action with this execution_id and expect the recorded outcome/receipt.")
            } else {
                json!("If approval is required, a human reviewer must approve outside MCP before execute_action.")
            },
        })))
    }

    #[tool(
        name = "blocklog_execute_action",
        description = "Execute a previously prepared action exactly once: re-authorize, verify the token, atomically consume it, run the configured built-in integration, record the outcome, and issue a receipt. Never retries after a side effect.",
        annotations(
            title = "Execute Blocklog Action",
            read_only_hint = false,
            destructive_hint = true,
            idempotent_hint = false,
            open_world_hint = true
        )
    )]
    async fn execute_action(
        &self,
        Parameters(args): Parameters<ExecuteActionArgs>,
        context: RequestContext<RoleServer>,
    ) -> Result<Json<Value>, ErrorData> {
        let api_key = self.api_key(&context)?;
        validate_id(&args.execution_id, "execution_id", 256)?;
        let execution = self
            .backend
            .get_execution(&api_key, &args.execution_id, false, true)
            .await?;
        let status = execution
            .get("status")
            .and_then(Value::as_str)
            .unwrap_or("UNKNOWN")
            .to_owned();

        if is_terminal(&status) {
            return Ok(Json(json!({
                "executed": false,
                "terminal": true,
                "execution_id": args.execution_id,
                "status": status,
                "message": "Execution is already terminal. No side effect was performed; use blocklog_get_receipt to retrieve evidence.",
            })));
        }
        if matches!(status.as_str(), "RUNNING" | "DISPATCHED") {
            return Err(AppError::Conflict(format!(
                "Execution {0} has already consumed its authorization (status {0}); refusing to repeat a side effect. Reconcile the recorded outcome before retrying.",
                status
            ))
            .into());
        }
        if status == "WAITING_FOR_APPROVAL" {
            let (pending, _) = approval_ids(&execution);
            return Ok(Json(json!({
                "executed": false,
                "approval_required": true,
                "approval_id": pending,
                "execution_id": args.execution_id,
                "status": status,
                "message": "A human reviewer must approve this action outside MCP before execution.",
            })));
        }
        if status != "AUTHORIZED" {
            return Ok(Json(json!({
                "executed": false,
                "allowed": false,
                "execution_id": args.execution_id,
                "status": status,
                "message": "Execution is not in an executable state.",
            })));
        }

        let stored_context = execution
            .get("context")
            .ok_or_else(|| AppError::Conflict("Execution has no stored context".to_owned()))?;
        let mcp = stored_context
            .get("context")
            .and_then(|context| context.get("mcp"))
            .and_then(Value::as_object)
            .ok_or_else(|| {
                AppError::Conflict(
                    "Execution was not prepared by this MCP server; refusing to execute".to_owned(),
                )
            })?;
        let stored_hash = mcp
            .get("args_hash")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                AppError::Conflict("Execution is missing its MCP args hash".to_owned())
            })?;
        if let Some(expected) = &args.expected_args_hash {
            if !constant_time_eq(expected, stored_hash) {
                return Err(AppError::Validation(
                    "expected_args_hash does not match the stored execution; refusing to execute"
                        .to_owned(),
                )
                .into());
            }
        }
        let integration = mcp
            .get("integration")
            .cloned()
            .map(serde_json::from_value::<IntegrationSpec>)
            .transpose()
            .map_err(|error| AppError::Conflict(format!("Stored integration is invalid: {error}")))?
            .unwrap_or_default();

        let (_, approved) = approval_ids(&execution);
        let mut payload = stored_context.clone();
        if let Some(approved) = &approved {
            if let Some(object) = payload.as_object_mut() {
                object.insert("approval_id".to_owned(), Value::String(approved.clone()));
            }
        }
        let response = self.backend.authorize(&api_key, &payload).await?;
        let decision = response
            .pointer("/outcome/decision")
            .and_then(Value::as_str)
            .unwrap_or("UNKNOWN");
        if decision != "APPROVED" {
            return Ok(Json(json!({
                "executed": false,
                "allowed": false,
                "decision": decision,
                "execution_id": args.execution_id,
                "authorization": public_authorization(&response),
                "message": "Blocklog did not authorize execution.",
            })));
        }
        if self.config.mode == Mode::Audit {
            self.audit(
                "blocklog_execute_action.audit",
                Some(&args.execution_id),
                "WOULD_EXECUTE",
            );
            return Ok(Json(json!({
                "executed": false,
                "audit_mode": true,
                "would_execute": true,
                "execution_id": args.execution_id,
                "integration": integration,
                "authorization": public_authorization(&response),
                "message": "Audit mode is enabled. No side effect, token consumption, outcome, or receipt was produced.",
            })));
        }
        let token = response
            .get("token")
            .and_then(Value::as_str)
            .filter(|token| !token.is_empty())
            .ok_or_else(|| {
                AppError::Conflict(
                    "Blocklog did not return a usable execution token; it may be expired or already consumed"
                        .to_owned(),
                )
            })?;

        let verify_payload = verify_payload_from_stored(stored_context, token)?;
        let verification = self.backend.verify(&api_key, &verify_payload).await?;
        if !verification
            .get("authorized")
            .and_then(Value::as_bool)
            .unwrap_or(false)
        {
            let reasons = verification
                .get("reasons")
                .cloned()
                .unwrap_or_else(|| json!([]));
            return Ok(Json(json!({
                "executed": false,
                "authorized": false,
                "execution_id": args.execution_id,
                "verification": verification,
                "reasons": reasons,
                "message": "Token verification failed; no side effect was performed.",
            })));
        }
        let consume_payload =
            consume_payload_from_stored(stored_context, token, &args.execution_id)?;
        let consumption = self.backend.consume(&api_key, &consume_payload).await?;

        let integration_result = match run_integration(&integration) {
            Ok(result) => result,
            Err(error) => {
                let outcome = if matches!(error, AppError::Unsupported(_)) {
                    "OUTCOME_UNKNOWN"
                } else {
                    "FAILED"
                };
                let mut outcome_body = json!({
                    "status": outcome,
                    "error": {"message": error.to_string(), "code": error.blocklog_code()},
                    "outcome_source": "adapter_verified",
                    "issue_receipt": true,
                });
                if outcome == "OUTCOME_UNKNOWN" {
                    if let Some(object) = outcome_body.as_object_mut() {
                        object.insert("output".to_owned(), json!({"dispatched": false}));
                    }
                }
                let recorded = self
                    .backend
                    .record_outcome(&api_key, &args.execution_id, &outcome_body)
                    .await;
                return match recorded {
                    Ok(recorded) => Ok(Json(json!({
                        "executed": false,
                        "execution_id": args.execution_id,
                        "consumption": consumption,
                        "integration_error": error.to_string(),
                        "outcome": recorded,
                    }))),
                    Err(record_error) => Err(AppError::Internal(format!(
                        "Integration failed ({error}) and the outcome could not be recorded ({record_error}); reconcile execution {} manually",
                        args.execution_id
                    ))
                    .into()),
                };
            }
        };

        let outcome_body = json!({
            "status": "SUCCEEDED",
            "output": {"integration": integration_result},
            "outcome_source": "adapter_verified",
            "issue_receipt": true,
        });
        let recorded = match self
            .backend
            .record_outcome(&api_key, &args.execution_id, &outcome_body)
            .await
        {
            Ok(recorded) => recorded,
            Err(error) => {
                self.audit(
                    "blocklog_execute_action",
                    Some(&args.execution_id),
                    "SIDE_EFFECT_OK_OUTCOME_FAILED",
                );
                return Ok(Json(json!({
                    "executed": true,
                    "side_effect_completed": true,
                    "outcome_recorded": false,
                    "status": "OUTCOME_UNKNOWN",
                    "execution_id": args.execution_id,
                    "consumption": consumption,
                    "integration_result": integration_result,
                    "warning": format!("The local integration completed, but the outcome could not be recorded: {error}. Do NOT retry the action; reconcile it manually."),
                })));
            }
        };
        let receipt = recorded.get("receipt").cloned().unwrap_or(Value::Null);
        let receipt_id = receipt
            .get("receipt_id")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned);
        let receipt_verification = if receipt.is_object() {
            self.verify_value(&receipt, true, true).ok()
        } else {
            None
        };
        self.audit(
            "blocklog_execute_action",
            Some(&args.execution_id),
            "EXECUTED_AND_RECORDED",
        );
        Ok(Json(json!({
            "executed": true,
            "execution_id": args.execution_id,
            "consumption": consumption,
            "outcome": recorded,
            "receipt_id": receipt_id,
            "receipt_verification": receipt_verification,
            "message": "The built-in integration completed and the outcome was recorded. Use receipt evidence according to your trust policy.",
        })))
    }

    #[tool(
        name = "blocklog_request_approval",
        description = "Create or retrieve the pending HITL approval request for an execution. Reviewers approve or reject outside MCP; this tool cannot approve.",
        annotations(
            title = "Request Human Approval",
            read_only_hint = false,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    async fn request_approval(
        &self,
        Parameters(args): Parameters<RequestApprovalArgs>,
        context: RequestContext<RoleServer>,
    ) -> Result<Json<Value>, ErrorData> {
        let api_key = self.api_key(&context)?;
        validate_id(&args.execution_id, "execution_id", 256)?;
        if args.reason.trim().is_empty() || args.reason.len() > 2000 {
            return Err(AppError::Validation(
                "reason must be between 1 and 2000 characters".to_owned(),
            )
            .into());
        }
        let execution = self
            .backend
            .get_execution(&api_key, &args.execution_id, false, true)
            .await?;
        let internal_id = execution
            .get("internal_id")
            .and_then(Value::as_str)
            .ok_or_else(|| AppError::Internal("Execution is missing internal_id".to_owned()))?;
        validate_uuid(internal_id, "execution.internal_id")?;
        let mut body = json!({
            "execution_id": internal_id,
            "reason": args.reason.trim(),
        });
        if let Some(reviewer) = args
            .reviewer
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            body["reviewer"] = json!(reviewer);
        }
        if let Some(metadata) = args.metadata {
            body["metadata"] = Value::Object(metadata);
        }
        let response = self.backend.request_hitl(&api_key, &body).await?;
        self.audit(
            "blocklog_request_approval",
            Some(&args.execution_id),
            "REQUESTED",
        );
        Ok(Json(json!({
            "approval": response,
            "execution_id": args.execution_id,
            "notice": "Approval must be completed by an authorized human reviewer outside MCP.",
        })))
    }

    #[tool(
        name = "blocklog_get_approval_status",
        description = "Read the decision, reason, evidence, and execution binding for a HITL approval.",
        annotations(
            title = "Get Approval Status",
            read_only_hint = true,
            open_world_hint = false
        )
    )]
    async fn get_approval_status(
        &self,
        Parameters(args): Parameters<ApprovalStatusArgs>,
        context: RequestContext<RoleServer>,
    ) -> Result<Json<Value>, ErrorData> {
        let api_key = self.api_key(&context)?;
        validate_uuid(&args.approval_id, "approval_id")?;
        let approval = self
            .backend
            .get_hitl_override(&api_key, &args.approval_id)
            .await?;
        Ok(Json(json!({
            "approval": approval,
            "pending": approval.get("decision").is_none_or(Value::is_null),
            "execution_id_is_internal": true,
            "notice": "The backend override response exposes the internal execution UUID, not the external execution_id.",
        })))
    }

    #[tool(
        name = "blocklog_list_approvals",
        description = "List all tenant-scoped human-in-the-loop (HITL) approval overrides and requests.",
        annotations(
            title = "List Approvals",
            read_only_hint = true,
            open_world_hint = false
        )
    )]
    async fn list_approvals(
        &self,
        Parameters(_): Parameters<ListApprovalsArgs>,
        context: RequestContext<RoleServer>,
    ) -> Result<Json<Value>, ErrorData> {
        let api_key = self.api_key(&context)?;
        let response = self.backend.list_hitl_overrides(&api_key).await?;
        Ok(Json(response))
    }

    #[tool(
        name = "blocklog_cancel_approval",
        description = "Attempt to cancel a pending HITL approval. This backend currently has no API-key cancellation endpoint, so the tool fails closed instead of fabricating a cancellation.",
        annotations(
            title = "Cancel Approval",
            read_only_hint = false,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    async fn cancel_approval(
        &self,
        Parameters(args): Parameters<CancelApprovalArgs>,
        context: RequestContext<RoleServer>,
    ) -> Result<Json<Value>, ErrorData> {
        let api_key = self.api_key(&context)?;
        validate_uuid(&args.approval_id, "approval_id")?;
        let current = self
            .backend
            .get_hitl_override(&api_key, &args.approval_id)
            .await?;
        if current
            .get("decision")
            .is_some_and(|value| !value.is_null())
        {
            return Ok(Json(json!({
                "cancelled": false,
                "already_decided": true,
                "approval": current,
                "message": "The approval already has a decision and cannot be cancelled.",
            })));
        }
        Err(AppError::Unsupported(
            "The Blocklog backend does not expose an API-key approval cancellation endpoint. Ask an authorized human reviewer to reject/expire the approval, or upgrade the backend with the documented narrow extension.".to_owned(),
        )
        .into())
    }

    #[tool(
        name = "blocklog_abort_execution",
        description = "Attempt to abort an execution before or after dispatch. Fails closed because the backend currently lacks a supported API-key abort transition.",
        annotations(
            title = "Abort Execution",
            read_only_hint = false,
            destructive_hint = true,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    async fn abort_execution(
        &self,
        Parameters(args): Parameters<AbortExecutionArgs>,
        context: RequestContext<RoleServer>,
    ) -> Result<Json<Value>, ErrorData> {
        let api_key = self.api_key(&context)?;
        validate_id(&args.execution_id, "execution_id", 256)?;
        let execution = self
            .backend
            .get_execution(&api_key, &args.execution_id, false, false)
            .await?;
        let status = execution
            .get("status")
            .and_then(Value::as_str)
            .unwrap_or("UNKNOWN");
        if is_terminal(status) {
            return Ok(Json(json!({
                "aborted": false,
                "terminal": true,
                "execution_id": args.execution_id,
                "status": status,
                "message": "Execution is already terminal.",
            })));
        }
        Err(AppError::Unsupported(format!(
            "The backend has no supported API-key abort transition from {status} to CANCELLED/OUTCOME_UNKNOWN. Refusing to fabricate an abort. Add the documented narrow backend abort endpoint before relying on this tool."
        ))
        .into())
    }

    #[tool(
        name = "blocklog_log_event",
        description = "Append a tamper-evident event to the Blocklog event ledger. The backend derives actor identity from the API key; agent_id is claimed metadata only.",
        annotations(
            title = "Log Blocklog Event",
            read_only_hint = false,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    async fn log_event(
        &self,
        Parameters(args): Parameters<LogEventArgs>,
        context: RequestContext<RoleServer>,
    ) -> Result<Json<Value>, ErrorData> {
        let api_key = self.api_key(&context)?;
        self.ensure_argument_size(&args)?;
        let response = self
            .backend
            .ingest_log(&api_key, &log_payload(args)?)
            .await?;
        Ok(Json(response))
    }

    #[tool(
        name = "blocklog_log_decision",
        description = "Append a structured agent decision event (event_type=agent.decision) to the Blocklog ledger.",
        annotations(
            title = "Log Agent Decision",
            read_only_hint = false,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    async fn log_decision(
        &self,
        Parameters(args): Parameters<LogDecisionArgs>,
        context: RequestContext<RoleServer>,
    ) -> Result<Json<Value>, ErrorData> {
        let api_key = self.api_key(&context)?;
        if args.decision.trim().is_empty() || args.decision.len() > 256 {
            return Err(AppError::Validation(
                "decision must be between 1 and 256 characters".to_owned(),
            )
            .into());
        }
        if let Some(confidence) = args.confidence {
            if !(0.0..=1.0).contains(&confidence) {
                return Err(AppError::Validation(
                    "confidence must be between 0.0 and 1.0".to_owned(),
                )
                .into());
            }
        }
        let mut data = args.context.unwrap_or_default();
        data.insert("decision".to_owned(), json!(args.decision.trim()));
        if let Some(rationale) = args.rationale.filter(|value| !value.trim().is_empty()) {
            data.insert("rationale".to_owned(), json!(rationale.trim()));
        }
        if let Some(confidence) = args.confidence {
            data.insert("confidence".to_owned(), json!(confidence));
        }
        let event = LogEventArgs {
            event_type: "agent.decision".to_owned(),
            data,
            source: Some("mcp".to_owned()),
            timestamp: None,
            idempotency_key: args.idempotency_key,
            trace_id: args.trace_id,
            session_id: args.session_id,
            workflow_id: args.workflow_id,
            parent_event_id: None,
            root_event_id: None,
            span_id: None,
            causality_type: Some("decision".to_owned()),
            agent_type: Some("ai_agent".to_owned()),
            agent_id: None,
            agent_metadata: None,
        };
        let response = self
            .backend
            .ingest_log(&api_key, &log_payload(event)?)
            .await?;
        Ok(Json(response))
    }

    #[tool(
        name = "blocklog_query_logs",
        description = "Query the tenant-scoped Blocklog event ledger with filters and cursor pagination.",
        annotations(
            title = "Query Blocklog Logs",
            read_only_hint = true,
            open_world_hint = false
        )
    )]
    async fn query_logs(
        &self,
        Parameters(args): Parameters<QueryLogsArgs>,
        context: RequestContext<RoleServer>,
    ) -> Result<Json<Value>, ErrorData> {
        let api_key = self.api_key(&context)?;
        for (name, value) in [
            ("trace_id", args.trace_id.as_deref()),
            ("session_id", args.session_id.as_deref()),
            ("workflow_id", args.workflow_id.as_deref()),
        ] {
            if let Some(value) = value {
                validate_uuid(value, name)?;
            }
        }
        let filters = LogQuery {
            event_type: args.event_type.as_deref(),
            source: args.source.as_deref(),
            trace_id: args.trace_id.as_deref(),
            session_id: args.session_id.as_deref(),
            workflow_id: args.workflow_id.as_deref(),
            integrity: args.integrity.as_deref(),
            query_text: args.query.as_deref(),
            from_ts: args.from.as_deref(),
            to_ts: args.to.as_deref(),
            limit: args.limit.map(|limit| limit as usize),
            cursor: args.cursor.as_deref(),
        };
        let response = self.backend.list_logs(&api_key, &filters).await?;
        Ok(Json(response))
    }

    #[tool(
        name = "blocklog_get_policy_violations",
        description = "Summarize recent authorization denials from Blocklog's ledger. This is derived from execution.authorization.denied events, not a separate policy-violation API.",
        annotations(
            title = "Get Policy Violations",
            read_only_hint = true,
            open_world_hint = false
        )
    )]
    async fn get_policy_violations(
        &self,
        Parameters(args): Parameters<GetPolicyViolationsArgs>,
        context: RequestContext<RoleServer>,
    ) -> Result<Json<Value>, ErrorData> {
        let api_key = self.api_key(&context)?;
        let filters = LogQuery {
            event_type: Some("execution.authorization.denied"),
            from_ts: args.from.as_deref(),
            to_ts: args.to.as_deref(),
            limit: args.limit.map(|limit| limit as usize),
            ..LogQuery::default()
        };
        let response = self.backend.list_logs(&api_key, &filters).await?;
        let mut counts = std::collections::BTreeMap::<String, u64>::new();
        let mut violations = Vec::new();
        let mut total = 0u64;
        if let Some(items) = response.get("items").and_then(Value::as_array) {
            for item in items {
                if let Some(agent_id) = args.agent_id.as_deref() {
                    let observed = item
                        .pointer("/payload/agent_id")
                        .or_else(|| item.pointer("/data/agent_id"))
                        .and_then(Value::as_str)
                        .unwrap_or("");
                    if observed != agent_id && observed != "unattributed" {
                        continue;
                    }
                }
                total += 1;
                let payload = item.get("payload").unwrap_or(item);
                if let Some(reasons) = payload.get("reasons").and_then(Value::as_array) {
                    for reason in reasons.iter().filter_map(Value::as_str) {
                        *counts.entry(reason.to_owned()).or_default() += 1;
                    }
                }
                violations.push(json!({
                    "log_id": item.get("log_id"),
                    "timestamp": item.get("timestamp"),
                    "execution_id": payload.get("execution_id"),
                    "processor": payload.get("processor"),
                    "action_type": payload.get("action_type"),
                    "decision": payload.get("decision"),
                    "reasons": payload.get("reasons"),
                    "chain_hash": item.get("chain_hash"),
                }));
            }
        }
        Ok(Json(json!({
            "total_denials": total,
            "reason_counts": counts,
            "violations": violations,
            "next_cursor": response.get("next_cursor"),
            "source_event_type": "execution.authorization.denied",
            "identity_note": "Denial events do not reliably carry a per-agent identity; API keys are tenant-scoped.",
        })))
    }

    #[tool(
        name = "blocklog_get_agent_activity",
        description = "Summarize recent execution activity for an agent or principal. Gateway executions may not store agent_id, so principal_id is often the reliable correlation key.",
        annotations(
            title = "Get Agent Activity",
            read_only_hint = true,
            open_world_hint = false
        )
    )]
    async fn get_agent_activity(
        &self,
        Parameters(args): Parameters<GetAgentActivityArgs>,
        context: RequestContext<RoleServer>,
    ) -> Result<Json<Value>, ErrorData> {
        let api_key = self.api_key(&context)?;
        let limit = args.limit.unwrap_or(100).clamp(1, 500) as usize;
        let response = self
            .backend
            .list_executions(
                &api_key,
                args.agent_id.as_deref(),
                args.status.as_deref(),
                limit,
                0,
            )
            .await?;
        let mut items = Vec::new();
        let mut status_counts = std::collections::BTreeMap::<String, u64>::new();
        if let Some(executions) = response.get("executions").and_then(Value::as_array) {
            for execution in executions {
                if let Some(principal) = args.principal_id.as_deref() {
                    if execution.get("principal_id").and_then(Value::as_str) != Some(principal) {
                        continue;
                    }
                }
                if let Some(from) = args.from.as_deref() {
                    let created = execution
                        .get("created_at")
                        .and_then(Value::as_str)
                        .unwrap_or("");
                    if created < from {
                        continue;
                    }
                }
                if let Some(to) = args.to.as_deref() {
                    let created = execution
                        .get("created_at")
                        .and_then(Value::as_str)
                        .unwrap_or("");
                    if created > to {
                        continue;
                    }
                }
                let status = execution
                    .get("status")
                    .and_then(Value::as_str)
                    .unwrap_or("UNKNOWN")
                    .to_owned();
                *status_counts.entry(status).or_default() += 1;
                items.push(execution.clone());
            }
        }
        Ok(Json(json!({
            "executions": items,
            "status_counts": status_counts,
            "backend_total": response.get("total"),
            "identity_note": "API keys are tenant-scoped. agent_id and principal_id returned here are recorded metadata, not independently authenticated per-agent identities.",
        })))
    }

    #[tool(
        name = "blocklog_get_execution",
        description = "Read a Blocklog execution with optional steps and HITL approvals.",
        annotations(
            title = "Get Execution",
            read_only_hint = true,
            open_world_hint = false
        )
    )]
    async fn get_execution(
        &self,
        Parameters(args): Parameters<GetExecutionArgs>,
        context: RequestContext<RoleServer>,
    ) -> Result<Json<Value>, ErrorData> {
        let api_key = self.api_key(&context)?;
        validate_id(&args.execution_id, "execution_id", 256)?;
        let response = self
            .backend
            .get_execution(
                &api_key,
                &args.execution_id,
                args.include_steps.unwrap_or(false),
                args.include_approvals.unwrap_or(false),
            )
            .await?;
        Ok(Json(response))
    }

    #[tool(
        name = "blocklog_list_executions",
        description = "List tenant-scoped Blocklog executions with optional agent and status filters.",
        annotations(
            title = "List Executions",
            read_only_hint = true,
            open_world_hint = false
        )
    )]
    async fn list_executions(
        &self,
        Parameters(args): Parameters<ListExecutionsArgs>,
        context: RequestContext<RoleServer>,
    ) -> Result<Json<Value>, ErrorData> {
        let api_key = self.api_key(&context)?;
        let response = self
            .backend
            .list_executions(
                &api_key,
                args.agent_id.as_deref(),
                args.status.as_deref(),
                args.limit.unwrap_or(100).clamp(1, 500) as usize,
                args.offset.unwrap_or(0) as usize,
            )
            .await?;
        Ok(Json(response))
    }

    #[tool(
        name = "blocklog_verify_receipt",
        description = "Verify a Blocklog receipt independently in Rust: canonical hash, Ed25519 signature, RFC 6962 Merkle inclusion, checkpoint consistency, witnesses, and counterparty attestations.",
        annotations(
            title = "Verify Receipt",
            read_only_hint = true,
            open_world_hint = false
        )
    )]
    async fn verify_receipt(
        &self,
        Parameters(args): Parameters<VerifyReceiptArgs>,
        _context: RequestContext<RoleServer>,
    ) -> Result<Json<Value>, ErrorData> {
        self.ensure_argument_size(&args)?;
        let artifact = extract_receipt_artifact(&args.receipt)?;
        let options = self.verify_options(&args);
        let report = verify_receipt_local(&artifact, &options);
        Ok(Json(json!({
            "verified": report.verified,
            "cryptographically_verified": report.cryptographically_verified,
            "signature_verified": report.signature_verified,
            "structural_valid": report.structural_valid,
            "receipt_id": report.receipt_id,
            "checks": report.checks,
            "warnings": report.warnings,
            "errors": report.errors,
            "outcome_assessment": report.outcome_assessment,
            "transparency_assessment": report.transparency_assessment,
            "trust_roots_configured": {
                "signing": self.config.trust_roots.len(),
                "witness": self.config.witness_trust_roots.len(),
                "counterparty": self.config.counterparty_trust_roots.len(),
            },
            "note": "A cryptographic receipt proves authorization and recorded outcome; it does not by itself prove a real-world outcome.",
        })))
    }

    #[tool(
        name = "blocklog_get_receipt",
        description = "Export a Blocklog receipt and, by default, run independent local cryptographic verification.",
        annotations(title = "Get Receipt", read_only_hint = true, open_world_hint = false)
    )]
    async fn get_receipt(
        &self,
        Parameters(args): Parameters<GetReceiptArgs>,
        context: RequestContext<RoleServer>,
    ) -> Result<Json<Value>, ErrorData> {
        let api_key = self.api_key(&context)?;
        validate_id(&args.receipt_id, "receipt_id", 256)?;
        let artifact = self
            .backend
            .export_receipt(&api_key, &args.receipt_id)
            .await?;
        let verification = if args.verify.unwrap_or(true) {
            Some(self.verify_value(&artifact, true, true)?)
        } else {
            None
        };
        Ok(Json(json!({
            "receipt": artifact,
            "verification": verification,
        })))
    }

    #[tool(
        name = "blocklog_issue_receipt",
        description = "Issue the authoritative, cryptographically signed receipt for a completed tenant execution.",
        annotations(
            title = "Issue Receipt",
            read_only_hint = false,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    async fn issue_receipt(
        &self,
        Parameters(args): Parameters<IssueReceiptArgs>,
        context: RequestContext<RoleServer>,
    ) -> Result<Json<Value>, ErrorData> {
        let api_key = self.api_key(&context)?;
        validate_id(&args.execution_id, "execution_id", 256)?;
        let artifact = self
            .backend
            .issue_receipt(&api_key, &args.execution_id)
            .await?;
        let verification = if args.verify.unwrap_or(true) {
            Some(self.verify_value(&artifact, true, true)?)
        } else {
            None
        };
        self.audit("blocklog_issue_receipt", Some(&args.execution_id), "ISSUED");
        Ok(Json(json!({
            "receipt": artifact,
            "verification": verification,
        })))
    }

    #[tool(
        name = "blocklog_simulate_policy",
        description = "Run counterfactual policy simulations for an existing execution token without executing the action.",
        annotations(
            title = "Simulate Policy",
            read_only_hint = true,
            open_world_hint = false
        )
    )]
    async fn simulate_policy(
        &self,
        Parameters(args): Parameters<SimulatePolicyArgs>,
        context: RequestContext<RoleServer>,
    ) -> Result<Json<Value>, ErrorData> {
        let api_key = self.api_key(&context)?;
        validate_uuid(&args.token_id, "token_id")?;
        if args.scenarios.is_empty() || args.scenarios.len() > 20 {
            return Err(AppError::Validation(
                "scenarios must contain between 1 and 20 items".to_owned(),
            )
            .into());
        }
        let scenarios: Vec<Value> = args
            .scenarios
            .into_iter()
            .map(|scenario| {
                json!({
                    "label": scenario.label,
                    "request_overrides": scenario.request_overrides,
                    "policy_overrides": scenario.policy_overrides,
                })
            })
            .collect();
        let response = self
            .backend
            .simulate(
                &api_key,
                &json!({"token_id": args.token_id, "scenarios": scenarios}),
            )
            .await?;
        Ok(Json(response))
    }

    #[tool(
        name = "blocklog_list_policies",
        description = "List all active execution policies configured for the tenant on the authoritative gateway.",
        annotations(
            title = "List Policies",
            read_only_hint = true,
            open_world_hint = false
        )
    )]
    async fn list_policies(
        &self,
        Parameters(_): Parameters<ListPoliciesArgs>,
        context: RequestContext<RoleServer>,
    ) -> Result<Json<Value>, ErrorData> {
        let api_key = self.api_key(&context)?;
        let response = self.backend.list_policies(&api_key).await?;
        Ok(Json(response))
    }

    #[tool(
        name = "blocklog_get_trace",
        description = "Read a complete tenant-scoped trace and its events.",
        annotations(title = "Get Trace", read_only_hint = true, open_world_hint = false)
    )]
    async fn get_trace(
        &self,
        Parameters(args): Parameters<GetTraceArgs>,
        context: RequestContext<RoleServer>,
    ) -> Result<Json<Value>, ErrorData> {
        let api_key = self.api_key(&context)?;
        validate_uuid(&args.trace_id, "trace_id")?;
        let response = self.backend.get_trace(&api_key, &args.trace_id).await?;
        Ok(Json(response))
    }

    #[tool(
        name = "blocklog_list_traces",
        description = "List tenant-scoped execution and audit traces with optional filters and time range.",
        annotations(title = "List Traces", read_only_hint = true, open_world_hint = false)
    )]
    async fn list_traces(
        &self,
        Parameters(args): Parameters<ListTracesArgs>,
        context: RequestContext<RoleServer>,
    ) -> Result<Json<Value>, ErrorData> {
        let api_key = self.api_key(&context)?;
        for (name, value) in [
            ("trace_id", args.trace_id.as_deref()),
            ("session_id", args.session_id.as_deref()),
            ("workflow_id", args.workflow_id.as_deref()),
        ] {
            if let Some(value) = value {
                validate_uuid(value, name)?;
            }
        }
        let filters = TraceQuery {
            trace_id: args.trace_id.as_deref(),
            session_id: args.session_id.as_deref(),
            workflow_id: args.workflow_id.as_deref(),
            source: args.source.as_deref(),
            event_type: args.event_type.as_deref(),
            from_ts: args.from.as_deref(),
            to_ts: args.to.as_deref(),
            limit: args.limit.map(|limit| limit as usize),
        };
        let response = self.backend.list_traces(&api_key, &filters).await?;
        Ok(Json(response))
    }

    #[tool(
        name = "blocklog_get_session_timeline",
        description = "Read the event timeline for a Blocklog session with cursor pagination.",
        annotations(
            title = "Get Session Timeline",
            read_only_hint = true,
            open_world_hint = false
        )
    )]
    async fn get_session_timeline(
        &self,
        Parameters(args): Parameters<SessionTimelineArgs>,
        context: RequestContext<RoleServer>,
    ) -> Result<Json<Value>, ErrorData> {
        let api_key = self.api_key(&context)?;
        validate_uuid(&args.session_id, "session_id")?;
        let limit = args.limit.unwrap_or(100).clamp(1, 500) as usize;
        let path = format!(
            "/sessions/{}/timeline",
            encode_path_segment(&args.session_id)
        );
        let response = self
            .backend
            .get_session_timeline(&api_key, &path, args.cursor.as_deref(), limit)
            .await?;
        Ok(Json(response))
    }

    #[tool(
        name = "blocklog_health",
        description = "Return MCP server configuration health without revealing secrets.",
        annotations(
            title = "Blocklog MCP Health",
            read_only_hint = true,
            open_world_hint = false
        )
    )]
    async fn health(
        &self,
        Parameters(_): Parameters<EmptyArgs>,
        _context: RequestContext<RoleServer>,
    ) -> Result<Json<Value>, ErrorData> {
        Ok(Json(json!({
            "status": "ok",
            "version": env!("CARGO_PKG_VERSION"),
            "mode": self.config.mode.to_string(),
            "transport": format!("{:?}", self.config.transport).to_lowercase(),
            "backend_configured": !self.config.backend_url.is_empty(),
            "trust_roots_configured": {
                "signing": self.config.trust_roots.len(),
                "witness": self.config.witness_trust_roots.len(),
                "counterparty": self.config.counterparty_trust_roots.len(),
            },
        })))
    }
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for BlocklogMcpServer {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(
            ServerCapabilities::builder()
                .enable_tools()
                .enable_resources()
                .build(),
        )
        .with_server_info(Implementation::new(
            "blocklog-mcp",
            env!("CARGO_PKG_VERSION"),
        ))
        .with_instructions(INSTRUCTIONS)
    }

    async fn list_resources(
        &self,
        _request: Option<rmcp::model::PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListResourcesResult, ErrorData> {
        Ok(ListResourcesResult::with_all_items(vec![
            Resource::new("blocklog://policies", "policies")
                .with_title("Blocklog execution policies")
                .with_description(
                    "Tenant-scoped execution policies from the authoritative gateway.",
                )
                .with_mime_type("application/json"),
            Resource::new("blocklog://health", "health")
                .with_title("Blocklog MCP server health")
                .with_description("Current configuration status, mode, and trust roots.")
                .with_mime_type("application/json"),
        ]))
    }

    async fn list_resource_templates(
        &self,
        _request: Option<rmcp::model::PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListResourceTemplatesResult, ErrorData> {
        Ok(ListResourceTemplatesResult::with_all_items(vec![
            ResourceTemplate::new("blocklog://executions/{execution_id}", "execution")
                .with_title("Blocklog execution")
                .with_description("Execution state, steps, and approvals.")
                .with_mime_type("application/json"),
            ResourceTemplate::new("blocklog://receipts/{receipt_id}", "receipt")
                .with_title("Blocklog receipt")
                .with_description("Exported receipt artifact with proofs and attestations.")
                .with_mime_type("application/json"),
            ResourceTemplate::new("blocklog://traces/{trace_id}", "trace")
                .with_title("Blocklog trace")
                .with_description("Complete trace detail and correlated events.")
                .with_mime_type("application/json"),
            ResourceTemplate::new("blocklog://approvals/{approval_id}", "approval")
                .with_title("Blocklog HITL approval")
                .with_description("HITL override/approval decision and audit record.")
                .with_mime_type("application/json"),
        ]))
    }

    async fn read_resource(
        &self,
        request: ReadResourceRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<ReadResourceResponse, ErrorData> {
        let uri = request.uri;
        let value = if uri == "blocklog://health" {
            json!({
                "status": "ok",
                "version": env!("CARGO_PKG_VERSION"),
                "mode": self.config.mode.to_string(),
                "transport": format!("{:?}", self.config.transport).to_lowercase(),
                "backend_configured": !self.config.backend_url.is_empty(),
                "trust_roots_configured": {
                    "signing": self.config.trust_roots.len(),
                    "witness": self.config.witness_trust_roots.len(),
                    "counterparty": self.config.counterparty_trust_roots.len(),
                },
            })
        } else {
            let api_key = self.api_key(&context)?;
            if uri == "blocklog://policies" {
                self.backend.list_policies(&api_key).await?
            } else if let Some(execution_id) = uri.strip_prefix("blocklog://executions/") {
                validate_id(execution_id, "execution_id", 256)?;
                self.backend
                    .get_execution(&api_key, execution_id, true, true)
                    .await?
            } else if let Some(receipt_id) = uri.strip_prefix("blocklog://receipts/") {
                validate_id(receipt_id, "receipt_id", 256)?;
                self.backend.export_receipt(&api_key, receipt_id).await?
            } else if let Some(trace_id) = uri.strip_prefix("blocklog://traces/") {
                validate_uuid(trace_id, "trace_id")?;
                self.backend.get_trace(&api_key, trace_id).await?
            } else if let Some(approval_id) = uri.strip_prefix("blocklog://approvals/") {
                validate_uuid(approval_id, "approval_id")?;
                self.backend
                    .get_hitl_override(&api_key, approval_id)
                    .await?
            } else {
                return Err(
                    AppError::NotFound(format!("Unknown Blocklog resource URI: {uri}")).into(),
                );
            }
        };
        let text = serde_json::to_string_pretty(&value)
            .map_err(|error| AppError::Internal(error.to_string()))?;
        Ok(ReadResourceResult::new(vec![
            ResourceContents::text(text, uri).with_mime_type("application/json")
        ])
        .into())
    }
}

fn header_secret(value: &http::HeaderValue) -> AppResult<String> {
    let value = value
        .to_str()
        .map_err(|_| AppError::Unauthorized("X-API-Key header is not valid UTF-8".to_owned()))?;
    let value = value.trim();
    if value.is_empty() {
        return Err(AppError::Unauthorized(
            "X-API-Key header is empty".to_owned(),
        ));
    }
    Ok(value.to_owned())
}

fn validate_id(value: &str, name: &str, max: usize) -> AppResult<()> {
    let value = value.trim();
    if value.is_empty() || value.len() > max {
        return Err(AppError::Validation(format!(
            "{name} must be between 1 and {max} characters"
        )));
    }
    Ok(())
}

fn validate_uuid(value: &str, name: &str) -> AppResult<()> {
    uuid::Uuid::parse_str(value.trim())
        .map(|_| ())
        .map_err(|_| AppError::Validation(format!("{name} must be a valid UUID")))
}

fn is_terminal(status: &str) -> bool {
    matches!(
        status,
        "REJECTED"
            | "BLOCKED"
            | "COMPLETED"
            | "SUCCEEDED"
            | "FAILED"
            | "INTERRUPTED"
            | "OUTCOME_UNKNOWN"
            | "CANCELLED"
            | "EXPIRED"
    )
}

fn approval_ids(execution: &Value) -> (Option<String>, Option<String>) {
    let mut pending = None;
    let mut approved: Option<(String, String)> = None;
    if let Some(approvals) = execution.get("approvals").and_then(Value::as_array) {
        for approval in approvals {
            let id = approval.get("id").and_then(Value::as_str);
            let decision = approval.get("decision").and_then(Value::as_str);
            match (id, decision) {
                (Some(id), None) => pending = Some(id.to_owned()),
                (Some(id), Some("APPROVED")) => {
                    let decided = approval
                        .get("decided_at")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_owned();
                    if approved
                        .as_ref()
                        .is_none_or(|(_, previous)| decided >= *previous)
                    {
                        approved = Some((id.to_owned(), decided));
                    }
                }
                _ => {}
            }
        }
    }
    (pending, approved.map(|(id, _)| id))
}

fn public_authorization(response: &Value) -> Value {
    json!({
        "status": response.get("status"),
        "decision": response.pointer("/outcome/decision"),
        "reasons": response.pointer("/outcome/reasons"),
        "shadow_mode": response.pointer("/outcome/shadow_mode"),
        "policy_id": response.pointer("/outcome/policy_id"),
        "policy_hash": response.pointer("/outcome/policy_hash"),
        "risk_score": response.pointer("/outcome/risk_score"),
        "risk_level": response.pointer("/outcome/risk_level"),
        "risk_factors": response.pointer("/outcome/risk_factors"),
        "approval_required": response.pointer("/outcome/approval_required"),
        "approval_id": response.get("approval_id"),
        "approval_challenge": response.get("approval_challenge"),
        "approval_expires_at": response.get("approval_expires_at"),
        "execution_id": response.get("execution_id"),
        "execution_status": response.get("execution_status"),
        "token_id": response.get("token_id"),
        "token_expires_at": response.get("token_expires_at"),
    })
}

fn verify_payload_from_stored(context: &Value, token: &str) -> AppResult<Value> {
    let object = context.as_object().ok_or_else(|| {
        AppError::Conflict("Stored execution context is not an object".to_owned())
    })?;
    let required = |name: &str| -> AppResult<Value> {
        object.get(name).cloned().ok_or_else(|| {
            AppError::Conflict(format!("Stored execution context is missing {name}"))
        })
    };
    let mut payload = json!({
        "token": token,
        "processor": required("processor")?,
        "action_type": required("action_type")?,
        "amount_minor": required("amount_minor")?,
        "currency": required("currency")?,
        "idempotency_key": required("idempotency_key")?,
        "subject_reference": required("subject_reference")?,
        "enforce": true,
    });
    if let Some(value) = object.get("destination") {
        payload["destination"] = value.clone();
    }
    if let Some(value) = object.get("transaction_reference") {
        payload["transaction_reference"] = value.clone();
    }
    Ok(payload)
}

fn consume_payload_from_stored(
    context: &Value,
    token: &str,
    execution_id: &str,
) -> AppResult<Value> {
    let object = context.as_object().ok_or_else(|| {
        AppError::Conflict("Stored execution context is not an object".to_owned())
    })?;
    let processor = object.get("processor").cloned().ok_or_else(|| {
        AppError::Conflict("Stored execution context is missing processor".to_owned())
    })?;
    let action_type = object.get("action_type").cloned().ok_or_else(|| {
        AppError::Conflict("Stored execution context is missing action_type".to_owned())
    })?;
    Ok(json!({
        "token": token,
        "processor": processor,
        "action_type": action_type,
        "execution_reference": execution_id,
        "transaction_reference": object.get("transaction_reference").cloned(),
    }))
}

fn run_integration(spec: &IntegrationSpec) -> AppResult<Value> {
    match spec.kind {
        IntegrationKind::Echo => Ok(json!({
            "kind": "echo",
            "payload": spec.payload.clone().unwrap_or_else(|| json!({"acknowledged": true})),
            "deterministic": true,
        })),
        IntegrationKind::Noop => Ok(json!({"kind": "noop", "deterministic": true})),
    }
}

fn extract_receipt_artifact(value: &Value) -> AppResult<Value> {
    let value = if let Some(raw) = value.as_str() {
        serde_json::from_str::<Value>(raw).map_err(|error| {
            AppError::Validation(format!("receipt string is not valid JSON: {error}"))
        })?
    } else {
        value.clone()
    };
    let artifact = value.get("receipt").cloned().unwrap_or(value);
    if !artifact.is_object() {
        return Err(AppError::Validation(
            "receipt must be a JSON object or an envelope containing a receipt object".to_owned(),
        ));
    }
    Ok(artifact)
}

fn log_payload(args: LogEventArgs) -> AppResult<Value> {
    let event_type = args.event_type.trim();
    if event_type.is_empty() || event_type.len() > 256 {
        return Err(AppError::Validation(
            "event_type must be between 1 and 256 characters".to_owned(),
        ));
    }
    if args.data.len() > 1000 {
        return Err(AppError::Validation(
            "data must contain at most 1000 top-level fields".to_owned(),
        ));
    }
    for (name, value) in [
        ("trace_id", args.trace_id.as_deref()),
        ("session_id", args.session_id.as_deref()),
        ("workflow_id", args.workflow_id.as_deref()),
        ("parent_event_id", args.parent_event_id.as_deref()),
        ("root_event_id", args.root_event_id.as_deref()),
    ] {
        if let Some(value) = value {
            validate_uuid(value, name)?;
        }
    }
    let source = args.source.as_deref().map(str::trim).unwrap_or("mcp");
    if source.is_empty() || source.len() > 64 {
        return Err(AppError::Validation(
            "source must be between 1 and 64 characters".to_owned(),
        ));
    }
    let idempotency_key = match args.idempotency_key {
        Some(key) => {
            let key = key.trim();
            if !(8..=128).contains(&key.len()) {
                return Err(AppError::Validation(
                    "idempotency_key must be 8-128 characters".to_owned(),
                ));
            }
            key.to_owned()
        }
        None => {
            let hash_input = json!({
                "event_type": event_type,
                "source": source,
                "data": args.data,
                "timestamp": args.timestamp,
                "trace_id": args.trace_id,
                "session_id": args.session_id,
                "workflow_id": args.workflow_id,
                "parent_event_id": args.parent_event_id,
                "root_event_id": args.root_event_id,
            });
            let encoded = canonical_encode(&hash_input)
                .map_err(|error| AppError::Internal(error.to_string()))?;
            let hash = sha256_hex(encoded);
            format!("mcp-log-{}", &hash[..40])
        }
    };
    let mut payload = json!({
        "event_type": event_type,
        "data": args.data,
        "source": source,
        "idempotency_key": idempotency_key,
    });
    if let Some(timestamp) = args.timestamp {
        chrono::DateTime::parse_from_rfc3339(&timestamp).map_err(|_| {
            AppError::Validation("timestamp must be a valid RFC 3339 timestamp".to_owned())
        })?;
        payload["timestamp"] = json!(timestamp);
    }
    for (name, value) in [
        ("trace_id", args.trace_id),
        ("session_id", args.session_id),
        ("workflow_id", args.workflow_id),
        ("parent_event_id", args.parent_event_id),
        ("root_event_id", args.root_event_id),
        ("span_id", args.span_id),
        ("causality_type", args.causality_type),
        ("agent_type", args.agent_type),
        ("agent_id", args.agent_id),
    ] {
        if let Some(value) = value.filter(|value| !value.trim().is_empty()) {
            payload[name] = json!(value);
        }
    }
    if let Some(metadata) = args.agent_metadata {
        payload["agent_metadata"] = Value::Object(metadata);
    }
    Ok(payload)
}

fn constant_time_eq(left: &str, right: &str) -> bool {
    let left = left.as_bytes();
    let right = right.as_bytes();
    if left.len() != right.len() {
        return false;
    }
    let mut difference = 0u8;
    for (a, b) in left.iter().zip(right) {
        difference |= a ^ b;
    }
    difference == 0
}

fn encode_path_segment(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            encoded.push(byte as char);
        } else {
            encoded.push('%');
            encoded.push_str(&format!("{byte:02X}"));
        }
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn terminal_states() {
        assert!(is_terminal("SUCCEEDED"));
        assert!(is_terminal("OUTCOME_UNKNOWN"));
        assert!(!is_terminal("AUTHORIZED"));
        assert!(!is_terminal("WAITING_FOR_APPROVAL"));
    }

    #[test]
    fn extracts_receipt_envelope() {
        let value = json!({"bundle_version": 1, "receipt": {"receipt_id": "r1"}});
        assert_eq!(
            extract_receipt_artifact(&value).expect("artifact")["receipt_id"],
            "r1"
        );
    }

    #[test]
    fn rejects_non_object_receipt() {
        assert!(extract_receipt_artifact(&json!("[]")).is_err());
    }
}
