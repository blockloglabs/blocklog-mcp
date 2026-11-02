# Blocklog MCP Client Setup Guide

This guide details how to integrate the **Blocklog Model Context Protocol Server** with various AI agent clients, desktop interfaces, and IDEs.

---

## 1. Claude Desktop

### Configuration File Locations
- **macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Windows**: `%APPDATA%\Claude\claude_desktop_config.json`
- **Linux**: `~/.config/Claude/claude_desktop_config.json`

### Stdio Configuration
Add `blocklog` under `mcpServers`:

```json
{
  "mcpServers": {
    "blocklog": {
      "command": "/usr/local/bin/blocklog-mcp",
      "args": ["--transport", "stdio", "--mode", "enforce"],
      "env": {
        "BLOCKLOG_BACKEND_URL": "https://api.blocklogsecurity.com",
        "BLOCKLOG_API_KEY": "blk_live_your_api_key_here",
        "BLOCKLOG_LOG_FORMAT": "compact"
      }
    }
  }
}
```

> **Tip**: Replace `/usr/local/bin/blocklog-mcp` with the absolute path to your compiled binary (`cargo build --release` produces `target/release/blocklog-mcp`).

Restart Claude Desktop. You will see the Blocklog hammer/tool icon indicating that 22 tools and resources are available.

---

## 2. Cursor IDE

Cursor natively supports Model Context Protocol servers in Features > MCP Servers:

1. Open **Cursor Settings** (`Cmd + ,` or `Ctrl + ,`).
2. Navigate to **Features** > **MCP Servers**.
3. Click **Add New MCP Server**.
4. Configure the server:
   - **Name**: `blocklog`
   - **Type**: `command`
   - **Command**: `/path/to/blocklog-mcp --transport stdio`
   - **Environment Variables**:
     - `BLOCKLOG_BACKEND_URL`: `https://api.blocklogsecurity.com`
     - `BLOCKLOG_API_KEY`: `blk_live_your_api_key_here`

Alternatively, add it directly to `.cursor/mcp.json` in your workspace root:

```json
{
  "mcpServers": {
    "blocklog": {
      "command": "/path/to/blocklog-mcp",
      "args": ["--transport", "stdio"],
      "env": {
        "BLOCKLOG_BACKEND_URL": "https://api.blocklogsecurity.com",
        "BLOCKLOG_API_KEY": "blk_live_your_api_key_here"
      }
    }
  }
}
```

---

## 3. Cline / Roo Code (VS Code Extension)

In VS Code with Cline or Roo Code:

1. Click on the Cline settings gear icon.
2. Select **MCP Servers** tab.
3. Edit the `cline_mcp_settings.json`:

```json
{
  "mcpServers": {
    "blocklog": {
      "command": "/path/to/blocklog-mcp",
      "args": ["--transport", "stdio"],
      "env": {
        "BLOCKLOG_BACKEND_URL": "https://api.blocklogsecurity.com",
        "BLOCKLOG_API_KEY": "blk_live_your_api_key_here"
      },
      "disabled": false,
      "autoApprove": [
        "blocklog_check_permission",
        "blocklog_get_approval_status",
        "blocklog_query_logs",
        "blocklog_get_receipt",
        "blocklog_verify_receipt",
        "blocklog_health"
      ]
    }
  }
}
```

---

## 4. Remote Agent Swarms via Streamable HTTP

For multi-tenant agent deployments or Kubernetes clusters, run `blocklog-mcp` as a shared HTTP service:

### Start the Server:
```bash
export BLOCKLOG_MCP_TRANSPORT=http
export BLOCKLOG_HTTP_BIND=0.0.0.0:8080
export BLOCKLOG_BACKEND_URL=https://api.blocklogsecurity.com
./target/release/blocklog-mcp
```

### Connect via HTTP MCP Client:
Clients connect via SSE endpoint:
```
http://<host>:8080/mcp
```

Headers:
- `X-Blocklog-API-Key`: `blk_live_your_api_key_here`
- `Content-Type`: `application/json`

---

## 5. Verifying the Connection

Ask your LLM agent:
> *"Can you check the health of the Blocklog security gateway and verify our active policies?"*

The agent will invoke `blocklog_health` and `blocklog_list_policies`, returning the active gateway status, loaded cryptographic trust roots, and policy definitions.
