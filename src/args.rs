use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::canonical::{canonical_encode, sha256_hex};
use crate::error::{AppError, AppResult};

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum IntegrationKind {
    Echo,
    Noop,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct IntegrationSpec {
    #[serde(default = "default_integration_kind")]
    pub kind: IntegrationKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload: Option<Value>,
}

fn default_integration_kind() -> IntegrationKind {
    IntegrationKind::Echo
}

impl Default for IntegrationSpec {
    fn default() -> Self {
        Self {
            kind: IntegrationKind::Echo,
            payload: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ActionArgs {
    #[schemars(
        description = "Integration or processor identifier, for example 'stripe' or 'internal.transfer'."
    )]
    pub processor: String,
    #[schemars(
        description = "Action type evaluated by the Blocklog execution policy, for example 'payment.create'."
    )]
    pub action_type: String,
    #[schemars(description = "Non-negative amount in the currency's minor unit (for USD, cents).")]
    pub amount_minor: u64,
    #[schemars(description = "ISO 4217 or supported asset currency code, 3-8 characters.")]
    pub currency: String,
    #[schemars(
        description = "Stable reference for the subject of the action, such as an order or account identifier."
    )]
    pub subject_reference: String,
    #[schemars(description = "Optional destination such as a payee or wallet address.")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub destination: Option<String>,
    #[schemars(description = "Optional transaction reference from the calling system.")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transaction_reference: Option<String>,
    #[schemars(
        description = "Optional application context evaluated by policy. Do not include the reserved 'mcp' key."
    )]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<Map<String, Value>>,
    #[schemars(
        description = "Optional caller-supplied idempotency key (8-128 characters). If omitted, a deterministic key is derived from the action."
    )]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idempotency_key: Option<String>,
    #[schemars(description = "Optional trace UUID used to group related events.")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trace_id: Option<String>,
    #[schemars(description = "Optional session UUID.")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[schemars(description = "Optional workflow UUID.")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workflow_id: Option<String>,
    #[schemars(
        description = "Optional built-in execution adapter. Only deterministic local adapters are supported; no arbitrary URLs, shell commands, or code."
    )]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub integration: Option<IntegrationSpec>,
}

impl ActionArgs {
    pub fn normalized(mut self) -> AppResult<Self> {
        self.processor = trimmed(&self.processor, "processor", 1, 256)?;
        self.action_type = trimmed(&self.action_type, "action_type", 1, 256)?;
        self.currency = self.currency.trim().to_ascii_uppercase();
        if !(3..=8).contains(&self.currency.len())
            || !self
                .currency
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric())
        {
            return Err(AppError::Validation(
                "currency must be 3-8 ASCII letters or digits".to_owned(),
            ));
        }
        self.subject_reference = trimmed(&self.subject_reference, "subject_reference", 1, 256)?;
        self.destination = optional_trimmed(self.destination, "destination", 512)?;
        self.transaction_reference =
            optional_trimmed(self.transaction_reference, "transaction_reference", 512)?;
        for (name, value) in [
            ("trace_id", self.trace_id.as_deref()),
            ("session_id", self.session_id.as_deref()),
            ("workflow_id", self.workflow_id.as_deref()),
        ] {
            if let Some(value) = value {
                uuid::Uuid::parse_str(value.trim())
                    .map_err(|_| AppError::Validation(format!("{name} must be a valid UUID")))?;
            }
        }
        if let Some(key) = &self.idempotency_key {
            let key = key.trim();
            if !(8..=128).contains(&key.len()) {
                return Err(AppError::Validation(
                    "idempotency_key must be 8-128 characters".to_owned(),
                ));
            }
            self.idempotency_key = Some(key.to_owned());
        }
        if let Some(context) = &self.context {
            if context.contains_key("mcp") {
                return Err(AppError::Validation(
                    "context.mcp is reserved for MCP execution binding".to_owned(),
                ));
            }
        }
        if let Some(integration) = &self.integration {
            if let Some(payload) = &integration.payload {
                if payload.is_array() || payload.is_object() {
                    let size = serde_json::to_vec(payload)
                        .map_err(|error| AppError::Internal(error.to_string()))?
                        .len();
                    if size > 64 * 1024 {
                        return Err(AppError::Validation(
                            "integration payload must be at most 65536 bytes".to_owned(),
                        ));
                    }
                }
            }
        }
        Ok(self)
    }

    pub fn args_hash(&self) -> AppResult<String> {
        let value = serde_json::to_value(self)?;
        canonical_encode(&value)
            .map(sha256_hex)
            .map_err(|error| AppError::Internal(error.to_string()))
    }

    pub fn idempotency_key(&self, purpose: &str, args_hash: &str) -> String {
        self.idempotency_key.clone().unwrap_or_else(|| {
            let suffix = args_hash.get(..40).unwrap_or(args_hash);
            format!("mcp-{purpose}-{suffix}")
        })
    }

    pub fn gateway_payload(
        &self,
        purpose: &str,
        args_hash: &str,
        approval_id: Option<&str>,
    ) -> Value {
        let mut context = self.context.clone().unwrap_or_default();
        context.insert(
            "mcp".to_owned(),
            serde_json::json!({
                "schema_version": 1,
                "tool": purpose,
                "args_hash": args_hash,
                "integration": self.integration.clone().unwrap_or_default(),
            }),
        );
        let mut payload = serde_json::json!({
            "processor": self.processor,
            "action_type": self.action_type,
            "amount_minor": self.amount_minor,
            "currency": self.currency,
            "idempotency_key": self.idempotency_key(purpose, args_hash),
            "subject_reference": self.subject_reference,
            "context": context,
        });
        let Some(object) = payload.as_object_mut() else {
            return Value::Null;
        };
        if let Some(destination) = &self.destination {
            object.insert("destination".to_owned(), Value::String(destination.clone()));
        }
        if let Some(reference) = &self.transaction_reference {
            object.insert(
                "transaction_reference".to_owned(),
                Value::String(reference.clone()),
            );
        }
        for (name, value) in [
            ("trace_id", self.trace_id.as_deref()),
            ("session_id", self.session_id.as_deref()),
            ("workflow_id", self.workflow_id.as_deref()),
        ] {
            if let Some(value) = value {
                object.insert(name.to_owned(), Value::String(value.trim().to_owned()));
            }
        }
        if let Some(approval_id) = approval_id {
            object.insert(
                "approval_id".to_owned(),
                Value::String(approval_id.to_owned()),
            );
        }
        payload
    }

    pub fn verify_payload(&self, token: &str) -> Value {
        let mut payload = serde_json::json!({
            "token": token,
            "processor": self.processor,
            "action_type": self.action_type,
            "amount_minor": self.amount_minor,
            "currency": self.currency,
            "idempotency_key": self.idempotency_key.clone().unwrap_or_default(),
            "subject_reference": self.subject_reference,
            "enforce": true,
        });
        if let Some(object) = payload.as_object_mut() {
            if let Some(destination) = &self.destination {
                object.insert("destination".to_owned(), Value::String(destination.clone()));
            }
            if let Some(reference) = &self.transaction_reference {
                object.insert(
                    "transaction_reference".to_owned(),
                    Value::String(reference.clone()),
                );
            }
        }
        payload
    }

    pub fn consume_payload(&self, token: &str, execution_reference: &str) -> Value {
        serde_json::json!({
            "token": token,
            "processor": self.processor,
            "action_type": self.action_type,
            "execution_reference": execution_reference,
            "transaction_reference": self.transaction_reference,
        })
    }
}

fn trimmed(value: &str, name: &str, min: usize, max: usize) -> AppResult<String> {
    let value = value.trim();
    if value.len() < min || value.len() > max {
        return Err(AppError::Validation(format!(
            "{name} must be between {min} and {max} characters"
        )));
    }
    Ok(value.to_owned())
}

fn optional_trimmed(value: Option<String>, name: &str, max: usize) -> AppResult<Option<String>> {
    value
        .map(|value| {
            let value = value.trim();
            if value.is_empty() {
                Ok(None)
            } else if value.len() > max {
                Err(AppError::Validation(format!(
                    "{name} must be at most {max} characters"
                )))
            } else {
                Ok(Some(value.to_owned()))
            }
        })
        .transpose()
        .map(Option::flatten)
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct AuthorizeActionArgs {
    #[serde(flatten)]
    pub action: ActionArgs,
    #[schemars(description = "Optional HITL approval UUID to resume an approved action.")]
    pub approval_id: Option<String>,
}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct ExecuteActionArgs {
    #[schemars(
        description = "Execution ID returned by prepare_execution, check_permission, or authorize_action."
    )]
    pub execution_id: String,
    #[schemars(
        description = "Optional expected args_hash. Prevents executing a different stored action than the caller reviewed."
    )]
    pub expected_args_hash: Option<String>,
}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct RequestApprovalArgs {
    #[schemars(description = "Execution ID whose action needs human approval.")]
    pub execution_id: String,
    #[schemars(description = "Reason shown to the human reviewer.")]
    pub reason: String,
    #[schemars(description = "Optional reviewer identifier.")]
    pub reviewer: Option<String>,
    #[schemars(description = "Optional non-sensitive metadata for the reviewer.")]
    pub metadata: Option<Map<String, Value>>,
}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct ApprovalStatusArgs {
    #[schemars(description = "Approval/override ID.")]
    pub approval_id: String,
}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct CancelApprovalArgs {
    #[schemars(description = "Approval/override ID to cancel.")]
    pub approval_id: String,
    #[schemars(description = "Reason for cancellation.")]
    pub reason: String,
}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct AbortExecutionArgs {
    #[schemars(description = "Execution ID to abort.")]
    pub execution_id: String,
    #[schemars(description = "Reason for aborting the execution.")]
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct LogEventArgs {
    #[schemars(description = "Event type, for example 'agent.decision' or 'agent.action'.")]
    pub event_type: String,
    #[schemars(description = "Structured event payload. Do not include secrets.")]
    pub data: Map<String, Value>,
    #[schemars(description = "Event source label; defaults to 'mcp'.")]
    pub source: Option<String>,
    #[schemars(
        description = "Optional RFC 3339 timestamp; cannot be in the future by more than a small clock skew."
    )]
    pub timestamp: Option<String>,
    #[schemars(description = "Optional idempotency key (8-128 characters).")]
    pub idempotency_key: Option<String>,
    pub trace_id: Option<String>,
    pub session_id: Option<String>,
    pub workflow_id: Option<String>,
    pub parent_event_id: Option<String>,
    pub root_event_id: Option<String>,
    pub span_id: Option<String>,
    pub causality_type: Option<String>,
    pub agent_type: Option<String>,
    pub agent_id: Option<String>,
    pub agent_metadata: Option<Map<String, Value>>,
}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct LogDecisionArgs {
    #[schemars(description = "Decision label, for example 'approve', 'reject', or 'escalate'.")]
    pub decision: String,
    #[schemars(description = "Human-readable rationale.")]
    pub rationale: Option<String>,
    #[schemars(description = "Optional confidence between 0.0 and 1.0.")]
    pub confidence: Option<f64>,
    #[schemars(description = "Optional non-sensitive decision context.")]
    pub context: Option<Map<String, Value>>,
    pub trace_id: Option<String>,
    pub session_id: Option<String>,
    pub workflow_id: Option<String>,
    pub idempotency_key: Option<String>,
}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct QueryLogsArgs {
    pub event_type: Option<String>,
    pub source: Option<String>,
    pub trace_id: Option<String>,
    pub session_id: Option<String>,
    pub workflow_id: Option<String>,
    pub integrity: Option<String>,
    #[schemars(
        description = "Case-insensitive text query over event type, source, chain hash, and idempotency key."
    )]
    pub query: Option<String>,
    pub from: Option<String>,
    pub to: Option<String>,
    pub cursor: Option<String>,
    #[schemars(description = "Maximum items, 1-500.")]
    pub limit: Option<u32>,
}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct GetExecutionArgs {
    pub execution_id: String,
    pub include_steps: Option<bool>,
    pub include_approvals: Option<bool>,
}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct ListExecutionsArgs {
    pub agent_id: Option<String>,
    pub status: Option<String>,
    pub limit: Option<u32>,
    pub offset: Option<u32>,
}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct GetPolicyViolationsArgs {
    pub agent_id: Option<String>,
    pub from: Option<String>,
    pub to: Option<String>,
    pub limit: Option<u32>,
}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct GetAgentActivityArgs {
    #[schemars(
        description = "Agent identifier recorded on execution records, when present. Gateway-created executions may use principal_id instead."
    )]
    pub agent_id: Option<String>,
    pub principal_id: Option<String>,
    pub status: Option<String>,
    pub from: Option<String>,
    pub to: Option<String>,
    pub limit: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct VerifyReceiptArgs {
    #[schemars(description = "Receipt artifact or an envelope containing a 'receipt' field.")]
    pub receipt: Value,
    #[schemars(description = "Optional Ed25519 public key override (hex or base64).")]
    pub public_key: Option<String>,
    #[schemars(description = "Require a valid Ed25519 signature. Defaults to true.")]
    pub verify_signature: Option<bool>,
    #[schemars(description = "Require a valid Merkle inclusion proof. Defaults to true.")]
    pub verify_merkle: Option<bool>,
}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct GetReceiptArgs {
    pub receipt_id: String,
    #[schemars(description = "Also run independent local verification. Defaults to true.")]
    pub verify: Option<bool>,
}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct SimulatePolicyArgs {
    #[schemars(description = "Execution token ID to replay against alternate scenarios.")]
    pub token_id: String,
    #[schemars(
        description = "Counterfactual scenarios; each has a label and optional request/policy overrides."
    )]
    pub scenarios: Vec<ScenarioArgs>,
}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct ScenarioArgs {
    pub label: String,
    #[serde(default)]
    pub request_overrides: Map<String, Value>,
    #[serde(default)]
    pub policy_overrides: Map<String, Value>,
}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct GetTraceArgs {
    pub trace_id: String,
}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct SessionTimelineArgs {
    pub session_id: String,
    pub cursor: Option<String>,
    pub limit: Option<u32>,
}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct ListTracesArgs {
    #[schemars(description = "Optional trace UUID filter.")]
    pub trace_id: Option<String>,
    #[schemars(description = "Optional session UUID filter.")]
    pub session_id: Option<String>,
    #[schemars(description = "Optional workflow UUID filter.")]
    pub workflow_id: Option<String>,
    #[schemars(description = "Optional event source filter.")]
    pub source: Option<String>,
    #[schemars(description = "Optional event type filter.")]
    pub event_type: Option<String>,
    #[schemars(description = "Optional start timestamp (RFC 3339).")]
    pub from: Option<String>,
    #[schemars(description = "Optional end timestamp (RFC 3339).")]
    pub to: Option<String>,
    #[schemars(description = "Maximum traces to return (1-200, default 50).")]
    pub limit: Option<u32>,
}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct ListPoliciesArgs {}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct ListApprovalsArgs {}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct IssueReceiptArgs {
    #[schemars(description = "Execution ID for which to issue an authoritative receipt.")]
    pub execution_id: String,
    #[schemars(
        description = "Also run independent local verification on the issued receipt. Defaults to true."
    )]
    pub verify: Option<bool>,
}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct EmptyArgs {}
