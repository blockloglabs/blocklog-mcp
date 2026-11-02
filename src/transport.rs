use std::sync::Arc;

use anyhow::{Context, Result};
use rmcp::transport::streamable_http_server::{
    session::local::LocalSessionManager, StreamableHttpServerConfig, StreamableHttpService,
};
use rmcp::ServiceExt;
use tokio_util::sync::CancellationToken;

use crate::server::BlocklogMcpServer;

pub async fn run_stdio(server: BlocklogMcpServer) -> Result<()> {
    let transport = rmcp::transport::io::stdio_pipes();
    let running = server
        .serve(transport)
        .await
        .context("failed to initialize the MCP stdio server")?;
    running.waiting().await.context("MCP stdio server failed")?;
    Ok(())
}

pub async fn run_http(server: BlocklogMcpServer, cancellation: CancellationToken) -> Result<()> {
    let config = server.config().clone();
    let mut http_config = StreamableHttpServerConfig::default()
        .with_allowed_hosts(config.allowed_hosts.clone())
        .with_allowed_origins(config.allowed_origins.clone())
        .with_legacy_session_mode(true)
        .with_sse_keep_alive(Some(std::time::Duration::from_secs(15)))
        .with_max_request_body_bytes(config.max_argument_bytes.saturating_add(1024 * 1024))
        .with_cancellation_token(cancellation.clone());
    if config.allowed_origins.is_empty() {
        http_config = http_config.enforce_origin_validation();
    }

    let service: StreamableHttpService<BlocklogMcpServer, LocalSessionManager> =
        StreamableHttpService::new(
            move || Ok(server.clone()),
            Arc::new(LocalSessionManager::default()),
            http_config,
        );
    let router = axum::Router::new().nest_service(&config.http_path, service);
    let listener = tokio::net::TcpListener::bind(config.http_bind)
        .await
        .with_context(|| format!("failed to bind HTTP transport to {}", config.http_bind))?;
    let address = listener
        .local_addr()
        .context("failed to read HTTP listener address")?;
    tracing::info!(
        address = %address,
        path = %config.http_path,
        "Blocklog MCP Streamable HTTP transport listening"
    );
    axum::serve(listener, router)
        .with_graceful_shutdown(cancellation.cancelled_owned())
        .await
        .context("MCP HTTP server failed")
}
