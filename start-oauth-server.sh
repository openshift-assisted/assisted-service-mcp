#!/bin/bash
set -e

echo "Starting Assisted Service MCP Server with OAuth Authentication..."
echo

# Load OAuth configuration
if [ -f oauth-config.env ]; then
    export $(grep -v '^#' oauth-config.env | xargs)
else
    echo "Error: oauth-config.env not found!"
    exit 1
fi

echo "Configuration:"
echo "  OAuth Enabled: $OAUTH_ENABLED"
echo "  OAuth Client: $OAUTH_CLIENT"
echo "  Server: $MCP_HOST:$MCP_PORT"
echo "  Transport: $TRANSPORT"
echo

echo "OAuth Endpoints:"
echo "  Registration: $SELF_URL/oauth/register"
echo "  Callback: $SELF_URL/oauth/callback"
echo "  Token: $SELF_URL/oauth/token"
echo

echo "MCP Client Configuration:"
echo "  Add this to your Cursor MCP settings:"
echo "  {"
echo "    \"assisted-local-oauth\": {"
echo "      \"transport\": \"streamable-http\","
echo "      \"url\": \"$SELF_URL/mcp\""
echo "    }"
echo "  }"
echo

echo "How it works:"
echo "  1. Cursor connects -> OAuth flow starts automatically"
echo "  2. Browser opens for Red Hat SSO authentication"
echo "  3. After authentication, connection proceeds automatically"
echo "  4. Subsequent connections use cached token"
echo

echo "Starting MCP server..."
echo "Press Ctrl+C to stop"
echo

python -m assisted_service_mcp.src.main
