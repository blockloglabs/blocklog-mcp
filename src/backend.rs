use std::time::Duration;

use futures_util::StreamExt;
use reqwest::{Client, Method, Response, StatusCode};
use serde_json::{json, Value};

use crate::config::Config;
use crate::error::{AppError, AppResult};

#[derive(Clone)]
pub struct BackendClient {
    http: Client,
    base_url: String,
    max_response_bytes: usize,
}

#[derive(Debug, Default)]
pub struct LogQuery<'a> {
    pub event_type: Option<&'a str>,
    pub source: Option<&'a str>,
    pub trace_id: Option<&'a str>,
    pub session_id: Option<&'a str>,
    pub workflow_id: Option<&'a str>,
    pub integrity: Option<&'a str>,
    pub query_text: Option<&'a str>,
    pub from_ts: Option<&'a str>,
    pub to_ts: Option<&'a str>,
    pub limit: Option<usize>,
    pub cursor: Option<&'a str>,
}

#[derive(Debug, Default)]
pub struct TraceQuery<'a> {
    pub trace_id: Option<&'a str>,
    pub session_id: Option<&'a str>,
    pub workflow_id: Option<&'a str>,
    pub source: Option<&'a str>,
    pub event_type: Option<&'a str>,
    pub from_ts: Option<&'a str>,
    pub to_ts: Option<&'a str>,
    pub limit: Option<usize>,
}

impl BackendClient {
    pub fn new(config: &Config) -> AppResult<Self> {
        let http = Client::builder()
            .timeout(config.request_timeout)
            .connect_timeout(Duration::from_secs(5))
            .user_agent(format!("blocklog-mcp/{}", env!("CARGO_PKG_VERSION")))
            .pool_idle_timeout(Duration::from_secs(60))
            .build()
            .map_err(|error| AppError::Internal(format!("failed to build HTTP client: {error}")))?;
        Ok(Self {
            http,
            base_url: config.backend_url.trim_end_matches('/').to_owned(),
            max_response_bytes: config.max_backend_response_bytes,
        })
    }

    fn url(&self, path: &str) -> String {
        if self.base_url.ends_with("/api/v1") {
            format!("{}{}", self.base_url, path)
        } else {
            format!("{}/api/v1{}", self.base_url, path)
        }
    }

    async fn send(
        &self,
        method: Method,
        path: &str,
        api_key: &str,
        query: &[(&str, String)],
        body: Option<&Value>,
    ) -> AppResult<Value> {
        if api_key.trim().is_empty() {
            return Err(AppError::Unauthorized(
                "An API key is required for this operation".to_owned(),
            ));
        }
        let mut request = self
            .http
            .request(method, self.url(path))
            .header("X-API-Key", api_key)
            .header("Accept", "application/json");
        if !query.is_empty() {
            request = request.query(query);
        }
        if let Some(body) = body {
            request = request.json(body);
        }
        let response = request
            .send()
            .await
            .map_err(|error| backend_transport_error(error, path))?;
        self.decode(response).await
    }

    async fn decode(&self, response: Response) -> AppResult<Value> {
        let status = response.status();
        if let Some(length) = response.content_length() {
            if length as usize > self.max_response_bytes {
                return Err(AppError::Backend {
                    status: 502,
                    code: "BACKEND_RESPONSE_TOO_LARGE".to_owned(),
                    message: format!(
                        "Blocklog response exceeded {} bytes",
                        self.max_response_bytes
                    ),
                    retryable: false,
                    details: None,
                });
            }
        }
        let mut stream = response.bytes_stream();
        let mut body = Vec::new();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|error| backend_transport_error(error, "response stream"))?;
            if body.len() + chunk.len() > self.max_response_bytes {
                return Err(AppError::Backend {
                    status: 502,
                    code: "BACKEND_RESPONSE_TOO_LARGE".to_owned(),
                    message: format!(
                        "Blocklog response exceeded {} bytes",
                        self.max_response_bytes
                    ),
                    retryable: false,
                    details: None,
                });
            }
            body.extend_from_slice(&chunk);
        }

        if status.is_success() {
            if status == StatusCode::NO_CONTENT || body.is_empty() {
                return Ok(json!({}));
            }
            return serde_json::from_slice(&body).map_err(|error| AppError::Backend {
                status: 502,
                code: "BACKEND_INVALID_JSON".to_owned(),
                message: format!("Blocklog returned invalid JSON: {error}"),
                retryable: true,
                details: None,
            });
        }

        let detail = serde_json::from_slice::<Value>(&body).unwrap_or_else(|_| {
            json!({
                "detail": String::from_utf8_lossy(&body).chars().take(2000).collect::<String>()
            })
        });
        Err(AppError::backend(status.as_u16(), detail))
    }

    pub async fn authorize(&self, api_key: &str, body: &Value) -> AppResult<Value> {
        self.send(
            Method::POST,
            "/execution/authorize",
            api_key,
            &[],
            Some(body),
        )
        .await
    }

    pub async fn verify(&self, api_key: &str, body: &Value) -> AppResult<Value> {
        self.send(Method::POST, "/execution/verify", api_key, &[], Some(body))
            .await
    }

    pub async fn consume(&self, api_key: &str, body: &Value) -> AppResult<Value> {
        self.send(Method::POST, "/execution/consume", api_key, &[], Some(body))
            .await
    }

    pub async fn record_outcome(
        &self,
        api_key: &str,
        execution_id: &str,
        body: &Value,
    ) -> AppResult<Value> {
        let path = format!(
            "/execution/executions/{}/outcome",
            encode_segment(execution_id)
        );
        self.send(Method::POST, &path, api_key, &[], Some(body))
            .await
    }

    pub async fn simulate(&self, api_key: &str, body: &Value) -> AppResult<Value> {
        self.send(
            Method::POST,
            "/execution/simulations",
            api_key,
            &[],
            Some(body),
        )
        .await
    }

    pub async fn list_policies(&self, api_key: &str) -> AppResult<Value> {
        self.send(Method::GET, "/execution/policies", api_key, &[], None)
            .await
    }

    pub async fn get_execution(
        &self,
        api_key: &str,
        execution_id: &str,
        include_steps: bool,
        include_approvals: bool,
    ) -> AppResult<Value> {
        let path = format!("/executions/{}", encode_segment(execution_id));
        self.send(
            Method::GET,
            &path,
            api_key,
            &[
                ("include_steps", include_steps.to_string()),
                ("include_approvals", include_approvals.to_string()),
            ],
            None,
        )
        .await
    }

    pub async fn list_executions(
        &self,
        api_key: &str,
        agent_id: Option<&str>,
        status: Option<&str>,
        limit: usize,
        offset: usize,
    ) -> AppResult<Value> {
        let mut query = vec![
            ("limit", limit.clamp(1, 500).to_string()),
            ("offset", offset.to_string()),
        ];
        if let Some(agent_id) = agent_id {
            query.push(("agent_id", agent_id.to_owned()));
        }
        if let Some(status) = status {
            query.push(("status", status.to_owned()));
        }
        self.send(Method::GET, "/executions/", api_key, &query, None)
            .await
    }

    pub async fn issue_receipt(&self, api_key: &str, execution_id: &str) -> AppResult<Value> {
        let path = format!(
            "/receipts/executions/{}/issue",
            encode_segment(execution_id)
        );
        self.send(Method::POST, &path, api_key, &[], None).await
    }

    pub async fn export_receipt(&self, api_key: &str, receipt_id: &str) -> AppResult<Value> {
        let path = format!("/receipts/{}/export", encode_segment(receipt_id));
        self.send(Method::GET, &path, api_key, &[], None).await
    }

    pub async fn get_receipt(&self, api_key: &str, receipt_id: &str) -> AppResult<Value> {
        let path = format!("/receipts/{}", encode_segment(receipt_id));
        self.send(Method::GET, &path, api_key, &[], None).await
    }

    pub async fn get_hitl_override(&self, api_key: &str, approval_id: &str) -> AppResult<Value> {
        let path = format!("/hitl/overrides/{}", encode_segment(approval_id));
        self.send(Method::GET, &path, api_key, &[], None).await
    }

    pub async fn list_hitl_overrides(&self, api_key: &str) -> AppResult<Value> {
        self.send(Method::GET, "/hitl/overrides", api_key, &[], None)
            .await
    }

    pub async fn request_hitl(&self, api_key: &str, body: &Value) -> AppResult<Value> {
        self.send(Method::POST, "/hitl/request", api_key, &[], Some(body))
            .await
    }

    pub async fn ingest_log(&self, api_key: &str, body: &Value) -> AppResult<Value> {
        self.send(Method::POST, "/logs", api_key, &[], Some(body))
            .await
    }

    pub async fn get_session_timeline(
        &self,
        api_key: &str,
        path: &str,
        cursor: Option<&str>,
        limit: usize,
    ) -> AppResult<Value> {
        let mut query = vec![("limit", limit.clamp(1, 500).to_string())];
        if let Some(cursor) = cursor.filter(|value| !value.trim().is_empty()) {
            query.push(("cursor", cursor.to_owned()));
        }
        self.send(Method::GET, path, api_key, &query, None).await
    }

    pub async fn list_logs(&self, api_key: &str, filters: &LogQuery<'_>) -> AppResult<Value> {
        let mut query = vec![(
            "limit",
            filters.limit.unwrap_or(100).clamp(1, 500).to_string(),
        )];
        for (name, value) in [
            ("event_type", filters.event_type),
            ("source", filters.source),
            ("trace_id", filters.trace_id),
            ("session_id", filters.session_id),
            ("workflow_id", filters.workflow_id),
            ("integrity", filters.integrity),
            ("q", filters.query_text),
            ("from", filters.from_ts),
            ("to", filters.to_ts),
            ("cursor", filters.cursor),
        ] {
            if let Some(value) = value.filter(|value| !value.trim().is_empty()) {
                query.push((name, value.to_owned()));
            }
        }
        self.send(Method::GET, "/logs", api_key, &query, None).await
    }

    pub async fn list_traces(&self, api_key: &str, filters: &TraceQuery<'_>) -> AppResult<Value> {
        let mut query = vec![(
            "limit",
            filters.limit.unwrap_or(100).clamp(1, 200).to_string(),
        )];
        for (name, value) in [
            ("trace_id", filters.trace_id),
            ("session_id", filters.session_id),
            ("workflow_id", filters.workflow_id),
            ("source", filters.source),
            ("event_type", filters.event_type),
            ("from", filters.from_ts),
            ("to", filters.to_ts),
        ] {
            if let Some(value) = value.filter(|value| !value.trim().is_empty()) {
                query.push((name, value.to_owned()));
            }
        }
        self.send(Method::GET, "/traces", api_key, &query, None)
            .await
    }

    pub async fn get_trace(&self, api_key: &str, trace_id: &str) -> AppResult<Value> {
        let path = format!("/traces/{}", encode_segment(trace_id));
        self.send(Method::GET, &path, api_key, &[], None).await
    }
}

fn backend_transport_error(error: reqwest::Error, context: &str) -> AppError {
    let retryable = error.is_timeout() || error.is_connect() || error.is_request();
    AppError::Backend {
        status: 503,
        code: if error.is_timeout() {
            "BACKEND_TIMEOUT".to_owned()
        } else if error.is_connect() {
            "BACKEND_UNAVAILABLE".to_owned()
        } else {
            "BACKEND_TRANSPORT_ERROR".to_owned()
        },
        message: format!("Blocklog request to {context} failed: {error}"),
        retryable,
        details: None,
    }
}

fn encode_segment(value: &str) -> String {
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
    use super::encode_segment;

    #[test]
    fn encodes_path_segments() {
        assert_eq!(encode_segment("exec_123"), "exec_123");
        assert_eq!(encode_segment("../admin"), "..%2Fadmin");
        assert_eq!(encode_segment("a b"), "a%20b");
    }
}
