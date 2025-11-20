# OAuth Authentication for Assisted Service MCP Server

This document describes the OAuth authentication implementation for the Assisted Service MCP Server.

## Overview

The server supports multiple authorization methods for accessing the Assisted Installer API. The method used depends on the environment variables and headers you provide. The following methods are checked in order of priority; the first one that succeeds will be used, and the rest will be ignored.

## Authentication Priority Order

### 1. Access token in the `Authorization` request header

If the `Authorization` request header contains a bearer token, it will be passed directly to the Assisted Installer API. In this case, the OAuth flow will not be triggered, and any values provided in the `OFFLINE_TOKEN` environment variable or the `OCM-Offline-Token` request header will be ignored.

**Example:**
```http
Authorization: Bearer ACCESS_TOKEN_HERE
```

### 2. OAuth flow

If the `OAUTH_ENABLED` environment variable is set to `true`, the server will use a subset of the OAuth protocol that MCP clients (such as the one in VS Code) use for authentication. When you attempt to connect, the MCP client will open a browser window where you can enter your credentials. The client will then request an access token, which the server will use to authenticate requests to the Assisted Installer API.

When using this authentication method, the `OFFLINE_TOKEN` environment variable and the `OCM-Offline-Token` header will be ignored.

### 3. Offline token via environment variable

If you set the `OFFLINE_TOKEN` environment variable, the server will use this offline token to request an access token, which will then be used to call the Assisted Installer API.

### 4. Offline token via request header

If the `OCM-Offline-Token` request header is set, the server will use it to request an access token, and will then use that access token to call the Assisted Installer API.

## OAuth Configuration

### Environment Variables

You can configure the OAuth authorization server and client identifier using the following environment variables:

| Variable | Default Value | Description |
|----------|---------------|-------------|
| `OAUTH_ENABLED` | `false` | Enable OAuth authentication flow |
| `OAUTH_URL` | `https://sso.redhat.com/auth/realms/redhat-external` | OAuth authorization server URL |
| `OAUTH_CLIENT` | `ocm-cli` | OAuth client identifier |
| `SELF_URL` | `http://localhost:8000` | Base URL that the server uses to construct URLs referencing itself |

### SELF_URL Configuration

The `SELF_URL` environment variable specifies the base URL that the server uses to construct URLs referencing itself. For example, when OAuth is enabled, the server will generate the dynamic client registration URL by appending `/oauth/register` to this base URL.

- **Default:** `http://localhost:8000`
- **Production:** Should be set to the actual URL of the server as accessible to clients

**Examples:**
- Local development: `http://localhost:8000`
- Production with reverse proxy: `https://my.host.com`
- Production with custom port: `https://my.host.com:8443`

## OAuth Endpoints

When OAuth is enabled, the server exposes the following endpoints:

### `/oauth/register` (GET)

Returns OAuth configuration that MCP clients need to initiate the OAuth flow.

**Response:**
```json
{
  "authorization_endpoint": "https://sso.redhat.com/auth/realms/redhat-external/protocol/openid-connect/auth?client_id=cloud-services&...",
  "token_endpoint": "http://localhost:8000/oauth/token",
  "client_id": "cloud-services",
  "redirect_uri": "http://localhost:8000/oauth/callback",
  "state": "random_state_string",
  "response_type": "code",
  "scope": "openid profile email"
}
```

### `/oauth/callback` (GET)

Handles the OAuth callback from the authorization server. This endpoint:
- Receives the authorization code from the OAuth provider
- Exchanges it for an access token
- Displays a success/failure page to the user

**Parameters:**
- `code`: Authorization code from OAuth provider
- `state`: OAuth state parameter for CSRF protection
- `error`: Error code if authentication failed

### `/oauth/token` (POST)

Handles OAuth token requests from MCP clients. This endpoint is used by MCP clients to exchange authorization codes for access tokens.

**Request Body:**
```json
{
  "grant_type": "authorization_code",
  "code": "authorization_code_from_callback",
  "state": "oauth_state_parameter"
}
```

**Response:**
```json
{
  "access_token": "ACCESS_TOKEN_HERE",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "refresh_token_if_available",
  "scope": "openid profile email"
}
```

## OAuth Flow Sequence

1. **Client Registration**: MCP client calls `/oauth/register` to get OAuth configuration
2. **Authorization**: Client redirects user to authorization endpoint with PKCE challenge
3. **User Authentication**: User authenticates with OAuth provider (Red Hat SSO)
4. **Callback**: OAuth provider redirects to `/oauth/callback` with authorization code
5. **Token Exchange**: Client calls `/oauth/token` to exchange code for access token
6. **API Access**: Client uses access token to authenticate API requests

## Security Features

### PKCE (Proof Key for Code Exchange)

The implementation uses PKCE (RFC 7636) for enhanced security:
- Generates cryptographically random code verifier
- Creates SHA256-based code challenge
- Protects against authorization code interception attacks

### State Parameter

Uses OAuth state parameter for CSRF protection:
- Generates cryptographically random state values
- Validates state on callback to prevent CSRF attacks

### Token Storage

- Access tokens are stored temporarily in memory
- Tokens are associated with random identifiers
- No sensitive data is logged

## Usage Examples

### Enable OAuth Authentication

```bash
export OAUTH_ENABLED=true
export OAUTH_URL=https://sso.redhat.com/auth/realms/redhat-external
export OAUTH_CLIENT=cloud-services
export SELF_URL=https://my-mcp-server.com
```

### MCP Client Configuration

When OAuth is enabled, MCP clients should:

1. Call `/oauth/register` to get OAuth configuration
2. Open authorization URL in browser for user authentication
3. Handle the callback and extract authorization code
4. Exchange code for access token via `/oauth/token`
5. Use access token in `Authorization: Bearer <token>` header

### Testing OAuth Flow

You can test the OAuth endpoints manually:

```bash
# Get OAuth configuration
curl http://localhost:8000/oauth/register

# Test callback with error
curl "http://localhost:8000/oauth/callback?error=access_denied"

# Test token endpoint with invalid grant
curl -X POST http://localhost:8000/oauth/token \
  -H "Content-Type: application/json" \
  -d '{"grant_type": "client_credentials", "code": "test", "state": "test"}'
```

## Troubleshooting

### Common Issues

1. **OAuth endpoints return 404**
   - Ensure `OAUTH_ENABLED=true` is set
   - Restart the server after changing environment variables

2. **Invalid OAuth state error**
   - State parameters expire after use
   - Ensure client uses the state from `/oauth/register` response

3. **Token exchange fails**
   - Verify authorization code is valid and not expired
   - Check that redirect_uri matches exactly

4. **SELF_URL misconfiguration**
   - Ensure SELF_URL is accessible from client browsers
   - Include protocol (http/https) and correct port

### Debug Logging

Enable debug logging to troubleshoot OAuth issues:

```bash
export LOGGING_LEVEL=DEBUG
```

Look for log messages with OAuth-related information:
- OAuth registration requests
- Token exchange attempts
- Authentication priority decisions

## Integration with MCP Clients

MCP clients (like VS Code extensions) can integrate with this OAuth implementation by:

1. **Discovery**: Call `/oauth/register` to get OAuth configuration
2. **Browser Flow**: Open authorization URL in system browser
3. **Callback Handling**: Set up local server to handle OAuth callback
4. **Token Management**: Store and refresh access tokens as needed
5. **API Authentication**: Include tokens in `Authorization` header

The server will automatically detect OAuth tokens and use them according to the authentication priority order.
