#!/usr/bin/env bash
set -euo pipefail

# Test script for connecting to the Blocklog MCP Streamable HTTP server
SERVER_HOST="${1:-127.0.0.1:8080}"
API_KEY="${BLOCKLOG_API_KEY:-blk_test_demo_key}"

echo "==> Testing Blocklog MCP Streamable HTTP transport at http://${SERVER_HOST}/mcp"

# Test health check / SSE stream connection
curl -N -H "Accept: text/event-stream" \
     -H "Host: 127.0.0.1:8080" \
     -H "X-Blocklog-API-Key: ${API_KEY}" \
     "http://${SERVER_HOST}/mcp"
