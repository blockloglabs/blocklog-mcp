use anyhow::{Context, Result};
use blocklog_mcp::config::{Config, LogFormat, Transport};
use blocklog_mcp::server::BlocklogMcpServer;
use blocklog_mcp::transport::{run_http, run_stdio};
use tokio_util::sync::CancellationToken;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<()> {
    let config = Config::from_env_and_args()?;
    init_tracing(&config);
    let server = BlocklogMcpServer::new(config.clone())?;

    match config.transport {
        Transport::Stdio => {
            tracing::info!("starting Blocklog MCP over stdio");
            run_stdio(server).await
        }
        Transport::Http => {
            tracing::info!("starting Blocklog MCP over Streamable HTTP");
            let cancellation = CancellationToken::new();
            tokio::select! {
                result = run_http(server, cancellation.clone()) => result,
                signal = shutdown_signal() => {
                    signal?;
                    cancellation.cancel();
                    Ok(())
                }
            }
        }
        Transport::Both => {
            tracing::info!("starting Blocklog MCP over stdio and Streamable HTTP");
            let cancellation = CancellationToken::new();
            let http = tokio::spawn(run_http(server.clone(), cancellation.clone()));
            let result = tokio::select! {
                result = run_stdio(server) => result,
                result = http => result.context("HTTP task panicked")?,
                signal = shutdown_signal() => {
                    signal?;
                    Ok(())
                }
            };
            cancellation.cancel();
            result
        }
    }
}

fn init_tracing(config: &Config) {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("blocklog_mcp=info,rmcp=warn"));
    match config.log_format {
        LogFormat::Json => {
            tracing_subscriber::fmt()
                .with_env_filter(filter)
                .with_writer(std::io::stderr)
                .with_ansi(false)
                .json()
                .init();
        }
        LogFormat::Compact => {
            tracing_subscriber::fmt()
                .with_env_filter(filter)
                .with_writer(std::io::stderr)
                .with_ansi(false)
                .init();
        }
    }
}

async fn shutdown_signal() -> Result<()> {
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .context("failed to install SIGTERM handler")?;
        tokio::select! {
            result = tokio::signal::ctrl_c() => result.context("failed to listen for Ctrl-C")?,
            _ = terminate.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c()
            .await
            .context("failed to listen for Ctrl-C")?;
    }
    Ok(())
}
