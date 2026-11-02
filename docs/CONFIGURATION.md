# Blocklog MCP Server Configuration Guide

This document describes all configuration parameters, environment variables, command-line arguments, and security trust roots for the **Blocklog Model Context Protocol (MCP) Server**.

---

## 1. Environment Variables Reference

| Variable | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `BLOCKLOG_BACKEND_URL` | String | `http://127.0.0.1:8000` | Base URL of the Blocklog authoritative control plane. |
| `BLOCKLOG_API_KEY` | String | *None* | Tenant API key. Required when using `stdio` or `both` transport modes. |
| `BLOCKLOG_MCP_MODE` | String | `enforce` | Operating mode: `enforce` (full execution) or `audit` (dry-run simulation). |
| `BLOCKLOG_MCP_TRANSPORT` | String | `stdio` | Transport protocol: `stdio`, `http` (or `streamable-http`), or `both`. |
| `BLOCKLOG_HTTP_BIND` | SocketAddr | `127.0.0.1:8080` | Bind IP and port for the HTTP/SSE transport server. |
| `BLOCKLOG_HTTP_PATH` | String | `/mcp` | Path mount for MCP streamable HTTP endpoints. |
| `BLOCKLOG_HTTP_ALLOWED_HOSTS` | Comma-separated | `localhost,127.0.0.1,::1` | Allowed `Host` headers to prevent DNS rebinding attacks. |
| `BLOCKLOG_HTTP_ALLOWED_ORIGINS`| Comma-separated | *Empty* | Allowed CORS origins for browser-based dashboard clients. |
| `BLOCKLOG_REQUEST_TIMEOUT_SECS`| Integer | `15` | Timeout for outbound HTTP requests to the Blocklog backend (seconds). |
| `BLOCKLOG_MAX_ARGUMENT_BYTES` | Integer | `1048576` (1MB) | Maximum allowed size of incoming tool arguments in bytes. |
| `BLOCKLOG_MAX_RESPONSE_BYTES` | Integer | `8388608` (8MB) | Maximum allowed size of backend responses in bytes. |
| `BLOCKLOG_LOG_FORMAT` | String | `compact` | Logging format: `compact` (ANSI colored) or `json` (structured). |
| `BLOCKLOG_TRUST_ROOTS` | JSON Map | `{}` | Map of authorized Ed25519 root keys for receipt validation. |
| `BLOCKLOG_WITNESS_TRUST_ROOTS` | JSON Map | `{}` | Map of authorized witness notary public keys. |
| `BLOCKLOG_COUNTERPARTY_TRUST_ROOTS` | JSON Map | `{}` | Map of authorized counterparty signature keys. |
| `BLOCKLOG_RECEIPT_PUBLIC_KEY` | Hex / Base64 | *None* | Fallback single public key for ad-hoc receipt validation. |
| `BLOCKLOG_ALLOW_INSECURE_BACKEND` | Boolean | `false` | Allow connecting to `http://` non-loopback backend endpoints (testing only). |

---

## 2. Command-Line Arguments

The `blocklog-mcp` binary accepts CLI flags that override environment variables:

```bash
blocklog-mcp [OPTIONS]
```

### Options:
- `--transport <stdio|http|both>`: Selects the MCP transport protocol.
- `--mode <enforce|audit>`: Selects the runtime enforcement mode.
- `--version`, `-V`: Prints version information and exits.
- `--help`, `-h`: Displays available CLI arguments and usage instructions.

### Example Usage:
```bash
# Run stdio enforcement (standard for Claude Desktop)
./target/release/blocklog-mcp --transport stdio --mode enforce

# Run streamable HTTP on port 8080 for remote agents
BLOCKLOG_HTTP_BIND=0.0.0.0:8080 ./target/release/blocklog-mcp --transport http
```

---

## 3. Cryptographic Trust Roots Configuration

Blocklog receipts use Ed25519 signatures and RFC 6962 Merkle tree proofs. The MCP server validates these independently using trust roots passed via environment variables.

### Primary Trust Roots (`BLOCKLOG_TRUST_ROOTS`)
Pass a JSON map of key IDs to key definitions:
```json
{
  "prod-primary-root": {
    "public_key": "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
    "status": "active",
    "algorithm": "ed25519"
  }
}
```

Set in environment:
```bash
export BLOCKLOG_TRUST_ROOTS='{"prod-primary-root":{"public_key":"d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a","status":"active","algorithm":"ed25519"}}'
```

### Witness & Counterparty Roots
For receipts signed by external witness notaries or counterparties:
```bash
export BLOCKLOG_WITNESS_TRUST_ROOTS='{"witness-notary-1":"4b4b2160938e55e510ee4c32b90b8f44ff53e5fc46bb84128f73b306b3fa2045"}'
export BLOCKLOG_COUNTERPARTY_TRUST_ROOTS='{"stripe-counterparty":"d4f5...b2a1"}'
```

---

## 4. Production Hardening Checklist

1. **Enforce HTTPS**: Ensure `BLOCKLOG_BACKEND_URL` points to `https://` in production. Keep `BLOCKLOG_ALLOW_INSECURE_BACKEND=false`.
2. **Restrict Allowed Hosts**: When running HTTP transport, explicitly define `BLOCKLOG_HTTP_ALLOWED_HOSTS` to your reverse proxy or internal domain names.
3. **Payload Limits**: Tune `BLOCKLOG_MAX_ARGUMENT_BYTES` according to your application requirements to prevent memory exhaustion from oversized agent payloads.
4. **Structured Logging**: Set `BLOCKLOG_LOG_FORMAT=json` when deploying to container clusters (Kubernetes, AWS ECS) for integration with Datadog, Elastic, or CloudWatch.
