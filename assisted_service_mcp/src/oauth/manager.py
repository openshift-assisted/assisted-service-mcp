"""OAuth authentication implementation for Assisted Service MCP Server.

Simplified implementation using structured models and centralized token storage.
"""

import base64
import hashlib
import secrets
import time
import urllib.parse
from typing import Any, Dict, Optional

import httpx
from fastapi import HTTPException, Request, Response
from fastapi.responses import HTMLResponse

from assisted_service_mcp.src.logger import log
from assisted_service_mcp.src.oauth.models import OAuthState, OAuthToken
from assisted_service_mcp.src.oauth.store import TokenStore
from assisted_service_mcp.src.oauth.utils import (
    extract_oauth_callback_params,
    get_oauth_success_html,
)
from assisted_service_mcp.src.settings import settings


class OAuthManager:
    """Manages OAuth authentication flow for the MCP server.

    Simplified version using structured models and centralized storage.
    """

    def __init__(self) -> None:
        """Initialize OAuth manager with configuration."""
        self.oauth_url = settings.OAUTH_URL
        self.client_id = settings.OAUTH_CLIENT
        self.self_url = settings.SELF_URL

        # Use configurable redirect URI or construct from SELF_URL
        if settings.OAUTH_REDIRECT_URI:
            self.redirect_uri = settings.OAUTH_REDIRECT_URI
        else:
            # For local development, ensure we use 127.0.0.1 which works better with Red Hat SSO
            self_url_str = str(self.self_url)
            if "localhost" in self_url_str:
                base_url = self_url_str.replace("localhost", "127.0.0.1")
                self.redirect_uri = f"{base_url}/oauth/callback"
            else:
                self.redirect_uri = f"{self_url_str}/oauth/callback"

        # Use centralized token store
        self.token_store = TokenStore()

        # Pending OAuth states (for CSRF protection)
        self._pending_states: Dict[str, OAuthState] = {}

    def generate_pkce_challenge(self) -> tuple[str, str]:
        """Generate PKCE code verifier and challenge.

        Returns:
            Tuple of (code_verifier, code_challenge)
        """
        code_verifier = (
            base64.urlsafe_b64encode(secrets.token_bytes(32))
            .decode("utf-8")
            .rstrip("=")
        )
        code_challenge = (
            base64.urlsafe_b64encode(
                hashlib.sha256(code_verifier.encode("utf-8")).digest()
            )
            .decode("utf-8")
            .rstrip("=")
        )
        return code_verifier, code_challenge

    def create_authorization_url(self, client_id: str) -> tuple[str, str]:
        """Create OAuth authorization URL and state.

        Args:
            client_id: Client identifier for tracking

        Returns:
            Tuple of (authorization_url, state_json)
        """
        code_verifier, code_challenge = self.generate_pkce_challenge()

        # Create structured state
        state = OAuthState(
            session_id=secrets.token_hex(16),
            client_id=client_id,
            timestamp=time.time(),
            code_verifier=code_verifier,
        )

        state_json = state.to_json()

        # Store state for validation
        self._pending_states[state_json] = state

        params = {
            "client_id": self.client_id,
            "response_type": "code",
            "redirect_uri": self.redirect_uri,
            "scope": "openid profile email",
            "state": state_json,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
        }

        auth_url = f"{self.oauth_url}/protocol/openid-connect/auth"
        full_url = f"{auth_url}?{urllib.parse.urlencode(params)}"

        log.debug("Created authorization URL for client %s", client_id)
        return full_url, state_json

    def get_authorization_url(self, state: str) -> str:
        """Generate OAuth authorization URL (backward compatibility method).

        This method maintains compatibility with the old API where state
        was passed in rather than generated internally.

        Args:
            state: OAuth state parameter for CSRF protection

        Returns:
            Authorization URL for the OAuth provider
        """
        code_verifier, code_challenge = self.generate_pkce_challenge()

        # For backward compatibility, create a simple state object
        # Use the provided state as both session_id and a simple client_id
        oauth_state = OAuthState(
            session_id=state,
            client_id=f"legacy_{state[:8]}",
            timestamp=time.time(),
            code_verifier=code_verifier,
        )

        # Store using the original state string as key for backward compatibility
        self._pending_states[state] = oauth_state

        params = {
            "client_id": self.client_id,
            "response_type": "code",
            "redirect_uri": self.redirect_uri,
            "scope": "openid profile email",
            "state": state,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
        }

        auth_url = f"{self.oauth_url}/protocol/openid-connect/auth"
        return f"{auth_url}?{urllib.parse.urlencode(params)}"

    async def exchange_code_for_token(
        self, code: str, state_json: str
    ) -> Optional[OAuthToken]:
        """Exchange authorization code for access token.

        Args:
            code: Authorization code from OAuth provider
            state_json: OAuth state parameter (JSON string or legacy string)

        Returns:
            OAuthToken if successful, None otherwise

        Raises:
            HTTPException: If token exchange fails
        """
        # Try to parse as JSON first (new format), fall back to legacy format
        try:
            state = OAuthState.from_json(state_json)
            state_key = state_json
        except ValueError as exc:
            # Legacy format: plain string state
            if state_json not in self._pending_states:
                log.error("Unknown OAuth state")
                raise HTTPException(
                    status_code=400, detail="Unknown OAuth state"
                ) from exc
            state = self._pending_states[state_json]
            state_key = state_json

        # Check if state exists and is not expired
        if state_key not in self._pending_states:
            log.error("Unknown OAuth state")
            raise HTTPException(status_code=400, detail="Unknown OAuth state")

        stored_state = self._pending_states.pop(state_key)

        if stored_state.is_expired():
            log.error("OAuth state expired")
            raise HTTPException(status_code=400, detail="OAuth state expired")

        # Prepare token exchange request
        data = {
            "grant_type": "authorization_code",
            "client_id": self.client_id,
            "code": code,
            "redirect_uri": self.redirect_uri,
            "code_verifier": state.code_verifier,
        }

        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    f"{self.oauth_url}/protocol/openid-connect/token",
                    data=data,
                    timeout=30.0,
                )
                response.raise_for_status()
                token_data = response.json()

            # Create token object
            token_id = secrets.token_hex(16)
            expires_in = token_data.get("expires_in", 3600)

            token = OAuthToken(
                token_id=token_id,
                client_id=state.client_id,
                access_token=token_data["access_token"],
                refresh_token=token_data.get("refresh_token"),
                expires_at=time.time() + expires_in - 300,  # 5 min safety margin
            )

            # Store token
            self.token_store.store_token(token)

            log.info(
                "Successfully exchanged OAuth code for token (client: %s)",
                state.client_id,
            )
            return token

        except httpx.HTTPError as e:
            log.error("Failed to exchange OAuth code for token: %s", e)
            raise HTTPException(
                status_code=400, detail="Failed to exchange code for token"
            ) from e

    async def get_access_token_by_id(self, token_id: str) -> Optional[str]:
        """Get access token by token ID, refreshing if necessary.

        Args:
            token_id: Token identifier

        Returns:
            Access token if found and valid, None otherwise
        """
        token = self.token_store.get_token_by_id(token_id)
        if not token:
            return None

        # Check if token needs refresh
        if token.is_expired():
            log.info("Token %s is expired, attempting refresh", token_id)
            if await self._refresh_token(token):
                # Get updated token
                token = self.token_store.get_token_by_id(token_id)
                return token.access_token if token else None
            log.warning("Failed to refresh token %s", token_id)
            return None

        return token.access_token

    async def get_stored_access_token(self, token_id: str) -> Optional[str]:
        """Get stored access token by ID (backward compatibility method).

        This is an alias for get_access_token_by_id() to maintain
        backward compatibility with the old API.

        Args:
            token_id: Token identifier

        Returns:
            Access token if found and valid, None otherwise
        """
        return await self.get_access_token_by_id(token_id)

    async def get_access_token_by_client(self, client_id: str) -> Optional[str]:
        """Get access token for a client, refreshing if necessary.

        Args:
            client_id: Client identifier

        Returns:
            Access token if found and valid, None otherwise
        """
        token = self.token_store.get_token_by_client(client_id)
        if not token:
            return None

        # Check if token needs refresh
        if token.is_expired():
            log.info("Token for client %s is expired, attempting refresh", client_id)
            if await self._refresh_token(token):
                # Get updated token
                token = self.token_store.get_token_by_client(client_id)
                return token.access_token if token else None
            log.warning("Failed to refresh token for client %s", client_id)
            return None

        return token.access_token

    async def _refresh_token(self, token: OAuthToken) -> bool:
        """Refresh an access token using the refresh token.

        Args:
            token: Token to refresh

        Returns:
            True if refresh was successful, False otherwise
        """
        if not token.refresh_token:
            log.warning("No refresh token available for token %s", token.token_id)
            return False

        token_url = f"{self.oauth_url}/protocol/openid-connect/token"

        data = {
            "grant_type": "refresh_token",
            "client_id": self.client_id,
            "refresh_token": token.refresh_token,
        }

        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(token_url, data=data, timeout=30.0)
                response.raise_for_status()
                token_data = response.json()

            # Update token in store
            new_access_token = token_data["access_token"]
            new_refresh_token = token_data.get("refresh_token", token.refresh_token)
            expires_in = token_data.get("expires_in", 3600)
            new_expires_at = time.time() + expires_in - 300

            self.token_store.update_token(
                token.token_id, new_access_token, new_refresh_token, new_expires_at
            )

            log.info("Successfully refreshed token %s", token.token_id)
            return True

        except httpx.HTTPError as e:
            log.error("Failed to refresh token %s: %s", token.token_id, e)
            self.token_store.remove_token(token.token_id)
            return False
        except (KeyError, ValueError) as e:
            log.error("Invalid refresh token response for %s: %s", token.token_id, e)
            self.token_store.remove_token(token.token_id)
            return False

    def cleanup_expired_tokens(self) -> None:
        """Clean up expired tokens and states."""
        # Clean up expired tokens
        self.token_store.cleanup_expired_tokens()

        # Clean up expired states
        expired_states = [
            state_json
            for state_json, state in self._pending_states.items()
            if state.is_expired()
        ]
        for state_json in expired_states:
            del self._pending_states[state_json]

        if expired_states:
            log.info("Cleaned up %d expired OAuth states", len(expired_states))


# Global OAuth manager instance
oauth_manager = OAuthManager()


async def oauth_register_handler(_request: Request) -> Dict[str, Any]:
    """Handle OAuth dynamic client registration.

    This endpoint provides the OAuth configuration that MCP clients need
    to initiate the OAuth flow.

    Args:
        request: FastAPI request object

    Returns:
        OAuth registration response
    """
    if not settings.OAUTH_ENABLED:
        raise HTTPException(status_code=404, detail="OAuth not enabled")

    log.info("OAuth registration requested")

    # Generate client ID (simplified - could use request info)
    client_id = f"mcp_client_{secrets.token_hex(8)}"

    # Get authorization URL
    auth_url, state = oauth_manager.create_authorization_url(client_id)

    return {
        "authorization_endpoint": auth_url,
        "token_endpoint": f"{settings.SELF_URL}/oauth/token",
        "client_id": settings.OAUTH_CLIENT,
        "redirect_uri": oauth_manager.redirect_uri,
        "state": state,
        "response_type": "code",
        "scope": "openid profile email",
    }


async def oauth_callback_handler(request: Request) -> Response:
    """Handle OAuth callback from authorization server.

    This handler works for both standard OAuth flows and MCP automatic flows.

    Args:
        request: FastAPI request object containing authorization code

    Returns:
        HTML response indicating success or failure
    """
    if not settings.OAUTH_ENABLED:
        raise HTTPException(status_code=404, detail="OAuth not enabled")

    # Extract parameters from callback
    params = extract_oauth_callback_params(request)
    code, state, error = params["code"], params["state"], params["error"]

    if error:
        log.error("OAuth callback error: %s", error)
        return HTMLResponse(
            content=f"""
            <html>
                <body>
                    <h1>OAuth Authentication Failed</h1>
                    <p>Error: {error}</p>
                    <p>You can close this window.</p>
                </body>
            </html>
            """,
            status_code=400,
        )

    if not code or not state:
        log.error("Missing code or state in OAuth callback")
        return HTMLResponse(
            content="""
            <html>
                <body>
                    <h1>OAuth Authentication Failed</h1>
                    <p>Missing authorization code or state parameter.</p>
                    <p>You can close this window.</p>
                </body>
            </html>
            """,
            status_code=400,
        )

    try:
        # Exchange code for token
        token = await oauth_manager.exchange_code_for_token(code, state)

        if not token:
            raise HTTPException(status_code=500, detail="Failed to create token")

        # Check if this is an MCP flow (state contains mcp_auth in session_id)
        try:
            state_obj = OAuthState.from_json(state)
            is_mcp_flow = state_obj.session_id.startswith("mcp_auth_")
        except ValueError:
            is_mcp_flow = False

        log.info("OAuth authentication successful")

        return HTMLResponse(content=get_oauth_success_html(is_mcp_flow))

    except HTTPException as e:
        log.error("OAuth token exchange failed: %s", e.detail)
        return HTMLResponse(
            content=f"""
            <html>
                <body>
                    <h1>OAuth Authentication Failed</h1>
                    <p>Failed to exchange authorization code for access token.</p>
                    <p>Error: {e.detail}</p>
                    <p>You can close this window.</p>
                </body>
            </html>
            """,
            status_code=e.status_code,
        )


async def oauth_token_handler(request: Request) -> Dict[str, Any]:
    """Handle OAuth token requests from MCP clients.

    This endpoint is used by MCP clients to exchange authorization codes
    for access tokens.

    Args:
        request: FastAPI request object

    Returns:
        Token response
    """
    if not settings.OAUTH_ENABLED:
        raise HTTPException(status_code=404, detail="OAuth not enabled")

    # Parse request body
    content_type = request.headers.get("content-type", "")
    if content_type.startswith("application/json"):
        body = await request.json()
    else:
        form_data = await request.form()
        body = {key: str(value) for key, value in form_data.items()}

    grant_type = body.get("grant_type")
    code = body.get("code")
    state = body.get("state")

    if grant_type != "authorization_code":
        raise HTTPException(status_code=400, detail="Unsupported grant type")

    if not code or not state:
        raise HTTPException(status_code=400, detail="Missing code or state")

    try:
        # Exchange code for token
        token = await oauth_manager.exchange_code_for_token(code, state)

        if not token:
            raise HTTPException(status_code=500, detail="Failed to create token")

        # Handle both OAuthToken objects and dict (for backward compatibility with mocks)
        if isinstance(token, dict):
            return {
                "access_token": token.get("access_token"),
                "token_type": token.get("token_type", "Bearer"),
                "expires_in": token.get("expires_in", 3600),
                "refresh_token": token.get("refresh_token"),
                "scope": token.get("scope", "openid profile email"),
            }
        return {
            "access_token": token.access_token,
            "token_type": "Bearer",
            "expires_in": int(token.expires_at - time.time()),
            "refresh_token": token.refresh_token,
            "scope": "openid profile email",
        }

    except HTTPException:
        raise
    except Exception as e:
        log.error("Unexpected error in OAuth token exchange: %s", e)
        raise HTTPException(status_code=500, detail="Internal server error") from e


def get_oauth_access_token_from_mcp(mcp: Any) -> Optional[str]:
    """Extract OAuth access token from MCP request context.

    This function checks if the current request was authenticated using
    OAuth and returns the access token if available.

    Note: This does not perform token refresh. If the token is expired,
    it will return None and the caller should initiate a new OAuth flow.

    Args:
        mcp: FastMCP instance

    Returns:
        OAuth access token if available and not expired, None otherwise
    """
    if not settings.OAUTH_ENABLED:
        return None

    context = mcp.get_context()
    if not context or not context.request_context:
        return None

    request = context.request_context.request
    if not request:
        return None

    # Check for OAuth token in custom header
    oauth_token_id = request.headers.get("X-OAuth-Token-ID")
    if oauth_token_id:
        # Get token directly from store without refresh (sync context)
        token = oauth_manager.token_store.get_token_by_id(oauth_token_id)
        if token and not token.is_expired():
            return token.access_token

    # Check for OAuth token in Authorization header
    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        # This could be an OAuth token
        return auth_header[7:]  # Remove 'Bearer ' prefix

    return None
