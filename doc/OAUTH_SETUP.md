# OAuth Authentication Setup

This MCP server supports automatic OAuth authentication with Red Hat SSO for seamless integration with MCP clients.

## Quick Start

1. **Start the OAuth-enabled server**:
   ```bash
   ./start-oauth-server.sh
   ```

2. **Configure your MCP client** (Cursor):
```json
{
   "mcpServers": {
      "assisted-local-oauth": {
         "transport": "streamable-http",
         "url": "http://localhost:8000/mcp"
      }
   }
}
```

3. **Connect from your MCP client** - OAuth flow will start automatically!

## How It Works

1. **Automatic Detection**: When Cursor connects without credentials, the server detects this and initiates OAuth flow
2. **Browser Authentication**: A browser window will open automatically for Red Hat SSO authentication
3. **Token Caching**: After successful authentication, access and refresh tokens are cached for the client
4. **Automatic Refresh**: Expired tokens are automatically refreshed using refresh tokens (5 minutes before expiry)
5. **Seamless Reconnection**: Subsequent connections use cached tokens with transparent refresh

## Configuration

The OAuth configuration is stored in `oauth-config.env`:

```bash
# OAuth Configuration
OAUTH_ENABLED=true
OAUTH_URL=https://sso.redhat.com/auth/realms/redhat-external
OAUTH_CLIENT=ocm-cli
SELF_URL=http://127.0.0.1:8000

# Server Configuration
MCP_HOST=0.0.0.0
MCP_PORT=8000
TRANSPORT="streamable-http"

# Logging
LOGGING_LEVEL=DEBUG
LOG_TO_FILE=false

# Assisted Service API
INVENTORY_URL=https://api.openshift.com/api/assisted-install/v2
SSO_URL=https://sso.redhat.com/auth/realms/redhat-external/protocol/openid-connect/token
```

## Available Endpoints

| Endpoint | Purpose |
|----------|---------|
| `/mcp` | Main MCP endpoint with OAuth middleware |
| `/oauth/register` | OAuth registration for MCP clients |
| `/oauth/callback` | OAuth callback handler |
| `/oauth/token` | Token exchange endpoint |
| `/.well-known/*` | OAuth discovery endpoints |
| `/metrics` | Prometheus metrics |

## Security Features

- **PKCE (Proof Key for Code Exchange)**: Enhanced OAuth security
- **State Parameter**: CSRF protection
- **Token Caching**: Secure in-memory token storage per client
- **Automatic Cleanup**: Expired sessions are cleaned up automatically

## Authentication Priority Order

The server follows this authentication priority:

1. **Authorization Header**: `Bearer <token>` in request headers
2. **OAuth Flow**: Automatic OAuth if enabled and no token found (no fallback to offline token)
3. **Offline Token (Environment)**: `OFFLINE_TOKEN` environment variable (only when OAuth is disabled)

**Important**: When OAuth is enabled, offline token fallback is disabled to ensure consistent OAuth-only authentication.

## Troubleshooting


### Tools Not Loading in Cursor / "Loading Tools" Hangs
**Symptom**: After OAuth authentication completes, Cursor shows "Loading tools..." indefinitely

**Cause**: Cursor's initial MCP connection request gets a 401 (OAuth required), but after OAuth completes, Cursor doesn't automatically retry the connection

**Solution**:
1. **Complete OAuth authentication** in the browser (this works correctly)
2. **Reload the MCP connection** in Cursor:
   - Go to Cursor settings → MCP
   - Disable and re-enable the `assisted-local-oauth` server, OR
   - Restart Cursor
3. **The connection will now work** with your authenticated token

**Alternative**: Use the status endpoint to check authentication:
- GET `http://127.0.0.1:8000/oauth/status?client_id=<your_client_id>`
- Returns authentication status for debugging

### Server Won't Start
- Check if port 8000 is already in use
- Verify all dependencies are installed
- Check `oauth-config.env` file exists and is properly formatted

## Development Notes

- **Client Identification**: Clients are identified by User-Agent + IP address
- **Session Management**: OAuth sessions are stored in memory (not persistent across restarts)
- **Token Expiration**: Tokens are cached until server restart (no automatic refresh yet)
- **Middleware Integration**: OAuth middleware is integrated with FastMCP/Starlette

## Production Considerations

For production deployment:
- Use HTTPS for `SELF_URL`
- Use environment-specific OAuth clients
