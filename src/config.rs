use std::collections::{BTreeMap, HashSet};
use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use serde::Deserialize;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Mode {
    Audit,
    Enforce,
}

impl fmt::Display for Mode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Audit => f.write_str("audit"),
            Self::Enforce => f.write_str("enforce"),
        }
    }
}

impl FromStr for Mode {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "audit" => Ok(Self::Audit),
            "enforce" | "enforcement" => Ok(Self::Enforce),
            other => bail!("invalid mode '{other}'; expected audit or enforce"),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Transport {
    Stdio,
    Http,
    Both,
}

impl FromStr for Transport {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "stdio" => Ok(Self::Stdio),
            "http" | "streamable-http" | "streamable_http" => Ok(Self::Http),
            "both" => Ok(Self::Both),
            other => bail!("invalid transport '{other}'; expected stdio, http, or both"),
        }
    }
}

#[derive(Clone)]
pub struct Secret(String);

impl Secret {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn expose(&self) -> &str {
        &self.0
    }

    pub fn is_empty(&self) -> bool {
        self.0.trim().is_empty()
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret([REDACTED])")
    }
}

#[derive(Clone, Debug, Deserialize)]
pub struct TrustRootConfig {
    pub public_key: String,
    #[serde(default = "default_key_status")]
    pub status: String,
    #[serde(default = "default_algorithm")]
    pub algorithm: String,
}

fn default_key_status() -> String {
    "active".to_owned()
}

fn default_algorithm() -> String {
    "ed25519".to_owned()
}

#[derive(Clone, Debug)]
pub struct Config {
    pub backend_url: String,
    pub api_key: Option<Secret>,
    pub mode: Mode,
    pub transport: Transport,
    pub http_bind: SocketAddr,
    pub http_path: String,
    pub allowed_hosts: Vec<String>,
    pub allowed_origins: Vec<String>,
    pub request_timeout: Duration,
    pub max_argument_bytes: usize,
    pub max_backend_response_bytes: usize,
    pub receipt_public_key: Option<String>,
    pub trust_roots: BTreeMap<String, TrustRootConfig>,
    pub witness_trust_roots: BTreeMap<String, String>,
    pub counterparty_trust_roots: BTreeMap<String, String>,
    pub webhook_hosts: HashSet<String>,
    pub allow_insecure_webhooks: bool,
    pub allow_insecure_backend: bool,
    pub log_format: LogFormat,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LogFormat {
    Compact,
    Json,
}

impl FromStr for LogFormat {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "compact" | "text" => Ok(Self::Compact),
            "json" => Ok(Self::Json),
            other => bail!("invalid log format '{other}'; expected compact or json"),
        }
    }
}

impl Config {
    pub fn from_env_and_args() -> Result<Self> {
        let mut transport = env_parse("BLOCKLOG_MCP_TRANSPORT", Transport::Stdio)?;
        let mut mode = env_parse("BLOCKLOG_MCP_MODE", Mode::Enforce)?;

        let mut args = std::env::args().skip(1);
        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--transport" => {
                    let value = args
                        .next()
                        .ok_or_else(|| anyhow!("--transport requires a value"))?;
                    transport = value.parse()?;
                }
                "--mode" => {
                    let value = args
                        .next()
                        .ok_or_else(|| anyhow!("--mode requires a value"))?;
                    mode = value.parse()?;
                }
                "--help" | "-h" => {
                    print_help();
                    std::process::exit(0);
                }
                "--version" | "-V" => {
                    println!("blocklog-mcp {}", env!("CARGO_PKG_VERSION"));
                    std::process::exit(0);
                }
                other => bail!("unknown argument '{other}'; use --help"),
            }
        }

        let backend_url = env_string("BLOCKLOG_BACKEND_URL")
            .or_else(|| env_string("BLOCKLOG_API_URL"))
            .unwrap_or_else(|| "http://127.0.0.1:8000".to_owned())
            .trim_end_matches('/')
            .to_owned();

        let api_key = env_string("BLOCKLOG_API_KEY").map(Secret::new);
        if matches!(transport, Transport::Stdio | Transport::Both)
            && api_key.as_ref().is_none_or(Secret::is_empty)
        {
            bail!("BLOCKLOG_API_KEY is required for the stdio transport");
        }

        let http_bind = env_string("BLOCKLOG_HTTP_BIND")
            .unwrap_or_else(|| "127.0.0.1:8080".to_owned())
            .parse()
            .context("BLOCKLOG_HTTP_BIND must be a socket address")?;
        let http_path =
            normalize_path(env_string("BLOCKLOG_HTTP_PATH").unwrap_or_else(|| "/mcp".to_owned()))?;

        let allowed_hosts = split_list(env_string("BLOCKLOG_HTTP_ALLOWED_HOSTS").as_deref());
        let allowed_hosts = if allowed_hosts.is_empty() {
            vec![
                "localhost".to_owned(),
                "127.0.0.1".to_owned(),
                "::1".to_owned(),
            ]
        } else {
            allowed_hosts
        };
        let allowed_origins = split_list(env_string("BLOCKLOG_HTTP_ALLOWED_ORIGINS").as_deref());

        let request_timeout_secs = env_u64("BLOCKLOG_REQUEST_TIMEOUT_SECS", 15)?;
        if request_timeout_secs == 0 || request_timeout_secs > 300 {
            bail!("BLOCKLOG_REQUEST_TIMEOUT_SECS must be between 1 and 300");
        }
        let max_argument_bytes = env_usize("BLOCKLOG_MAX_ARGUMENT_BYTES", 1_048_576)?;
        if !(1024..=16 * 1024 * 1024).contains(&max_argument_bytes) {
            bail!("BLOCKLOG_MAX_ARGUMENT_BYTES must be between 1024 and 16777216");
        }
        let max_backend_response_bytes = env_usize("BLOCKLOG_MAX_RESPONSE_BYTES", 8 * 1024 * 1024)?;
        if !(4096..=64 * 1024 * 1024).contains(&max_backend_response_bytes) {
            bail!("BLOCKLOG_MAX_RESPONSE_BYTES must be between 4096 and 67108864");
        }

        let receipt_public_key = env_string("BLOCKLOG_RECEIPT_PUBLIC_KEY");
        let trust_roots = parse_json_map::<TrustRootConfig>("BLOCKLOG_TRUST_ROOTS")?;
        let witness_trust_roots = parse_json_map::<String>("BLOCKLOG_WITNESS_TRUST_ROOTS")?;
        let counterparty_trust_roots =
            parse_json_map::<String>("BLOCKLOG_COUNTERPARTY_TRUST_ROOTS")?;

        let webhook_hosts = split_list(env_string("BLOCKLOG_WEBHOOK_ALLOWED_HOSTS").as_deref())
            .into_iter()
            .map(|host| host.to_ascii_lowercase())
            .collect();
        let allow_insecure_webhooks = env_bool("BLOCKLOG_ALLOW_INSECURE_WEBHOOKS", false)?;
        let allow_insecure_backend = env_bool("BLOCKLOG_ALLOW_INSECURE_BACKEND", false)?;
        let log_format = env_parse("BLOCKLOG_LOG_FORMAT", LogFormat::Compact)?;

        let config = Self {
            backend_url,
            api_key,
            mode,
            transport,
            http_bind,
            http_path,
            allowed_hosts,
            allowed_origins,
            request_timeout: Duration::from_secs(request_timeout_secs),
            max_argument_bytes,
            max_backend_response_bytes,
            receipt_public_key,
            trust_roots,
            witness_trust_roots,
            counterparty_trust_roots,
            webhook_hosts,
            allow_insecure_webhooks,
            allow_insecure_backend,
            log_format,
        };
        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> Result<()> {
        let backend = reqwest::Url::parse(&self.backend_url)
            .with_context(|| format!("invalid backend URL '{}'", self.backend_url))?;
        if backend.scheme() != "https" && !self.allow_insecure_backend && !is_loopback_url(&backend)
        {
            bail!(
                "backend URL must use https unless BLOCKLOG_ALLOW_INSECURE_BACKEND=true or the host is loopback"
            );
        }
        if backend.host_str().is_none() {
            bail!("backend URL must include a host");
        }
        if matches!(self.transport, Transport::Http | Transport::Both)
            && !self.http_bind.ip().is_loopback()
        {
            let hosts_set = std::env::var("BLOCKLOG_HTTP_ALLOWED_HOSTS")
                .ok()
                .is_some_and(|value| !value.trim().is_empty());
            if !hosts_set {
                bail!(
                    "refusing to bind the HTTP transport to a non-loopback address without BLOCKLOG_HTTP_ALLOWED_HOSTS"
                );
            }
        }
        if self.mode == Mode::Audit && matches!(self.transport, Transport::Http | Transport::Both) {
            tracing::warn!(
                "audit mode is active; HTTP callers can read evidence but execute_action will not perform side effects"
            );
        }
        Ok(())
    }

    pub fn backend_join(&self, path: &str) -> String {
        format!("{}{}", self.backend_url, path)
    }

    pub fn stdio_api_key(&self) -> Result<&Secret> {
        self.api_key
            .as_ref()
            .filter(|key| !key.is_empty())
            .ok_or_else(|| anyhow!("BLOCKLOG_API_KEY is not configured"))
    }
}

fn is_loopback_url(url: &reqwest::Url) -> bool {
    match url.host_str() {
        Some("localhost") => true,
        Some(host) => host
            .trim_matches(['[', ']'])
            .parse::<IpAddr>()
            .is_ok_and(|ip| ip.is_loopback()),
        None => false,
    }
}

fn normalize_path(value: String) -> Result<String> {
    let path = value.trim();
    if !path.starts_with('/') || path.len() > 128 || path.contains("..") {
        bail!("BLOCKLOG_HTTP_PATH must be an absolute path without '..'");
    }
    let path = path.trim_end_matches('/');
    if path.is_empty() {
        bail!("BLOCKLOG_HTTP_PATH must name a mount path such as /mcp");
    }
    Ok(path.to_owned())
}

fn env_string(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .filter(|value| !value.trim().is_empty())
}

fn env_parse<T>(name: &str, default: T) -> Result<T>
where
    T: FromStr<Err = anyhow::Error>,
{
    match env_string(name) {
        Some(value) => value.parse().with_context(|| format!("invalid {name}")),
        None => Ok(default),
    }
}

fn env_bool(name: &str, default: bool) -> Result<bool> {
    match env_string(name) {
        Some(value) => match value.trim().to_ascii_lowercase().as_str() {
            "1" | "true" | "yes" | "on" => Ok(true),
            "0" | "false" | "no" | "off" => Ok(false),
            _ => bail!("{name} must be true or false"),
        },
        None => Ok(default),
    }
}

fn env_u64(name: &str, default: u64) -> Result<u64> {
    match env_string(name) {
        Some(value) => value
            .parse()
            .with_context(|| format!("{name} must be an integer")),
        None => Ok(default),
    }
}

fn env_usize(name: &str, default: usize) -> Result<usize> {
    match env_string(name) {
        Some(value) => value
            .parse()
            .with_context(|| format!("{name} must be an integer")),
        None => Ok(default),
    }
}

fn split_list(value: Option<&str>) -> Vec<String> {
    value
        .into_iter()
        .flat_map(|value| value.split(','))
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

fn parse_json_map<T>(name: &str) -> Result<BTreeMap<String, T>>
where
    T: for<'de> Deserialize<'de>,
{
    match env_string(name) {
        Some(raw) => serde_json::from_str::<BTreeMap<String, T>>(&raw)
            .with_context(|| format!("{name} must be a JSON object")),
        None => Ok(BTreeMap::new()),
    }
}

fn print_help() {
    println!(
        "blocklog-mcp {}\n\nUSAGE:\n    blocklog-mcp [--transport stdio|http|both] [--mode audit|enforce]\n\nENVIRONMENT:\n    BLOCKLOG_BACKEND_URL\n    BLOCKLOG_API_KEY\n    BLOCKLOG_MCP_MODE\n    BLOCKLOG_MCP_TRANSPORT\n    BLOCKLOG_HTTP_BIND\n    BLOCKLOG_HTTP_PATH\n    BLOCKLOG_HTTP_ALLOWED_HOSTS\n    BLOCKLOG_HTTP_ALLOWED_ORIGINS\n    BLOCKLOG_RECEIPT_PUBLIC_KEY\n    BLOCKLOG_TRUST_ROOTS\n    BLOCKLOG_WITNESS_TRUST_ROOTS\n    BLOCKLOG_COUNTERPARTY_TRUST_ROOTS\n    BLOCKLOG_WEBHOOK_ALLOWED_HOSTS\n    BLOCKLOG_ALLOW_INSECURE_WEBHOOKS\n    BLOCKLOG_ALLOW_INSECURE_BACKEND",
        env!("CARGO_PKG_VERSION")
    );
}
