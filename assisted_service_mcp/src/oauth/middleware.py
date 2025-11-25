"""MCP OAuth middleware for automatic authentication flow.

Simplified implementation using structured models and centralized token storage.
"""

import asyncio
from typing import Any, Dict, Optional

from fastapi import Request, Response
from starlette.responses import JSONResponse

from assisted_service_mcp.src.logger import log
from assisted_service_mcp.src.oauth.models import OAuthState
from assisted_service_mcp.src.oauth.manager import oauth_manager
from assisted_service_mcp.src.oauth.utils import open_browser_for_oauth


class MCPOAuthMiddleware:
    """Middleware that handles automatic OAuth flow for MCP clients.

    Simplified version using structured models and centralized storage.
    """

    def __init__(self) -> None:
        """Initialize middleware."""
        # Track pending authentication sessions
        self.pending_auth_sessions: Dict[str, Dict[str, Any]] = {}

    async def handle_mcp_request(self, request: Request, call_next: Any) -> Response:
        """Handle MCP requests and initiate OAuth if needed.

        Args:
            request: FastAPI request
            call_next: Next middleware/handler

        Returns:
            Response from handler or OAuth flow
        """
        # Check if this is an MCP request without authentication
        if not self._is_mcp_request_without_auth(request):
            return await call_next(request)

        client_id = self._get_client_identifier(request)

        # Try to use existing token
        token = oauth_manager.token_store.get_access_token_by_client(client_id)
        if token:
            log.info("Using cached token for client %s", client_id)
            return await self._create_authenticated_request(request, call_next, token)

        # Check if OAuth flow is already in progress
        if self._has_pending_auth(client_id):
            log.info("OAuth flow already in progress for client %s", client_id)
            return await self._wait_for_oauth_completion(request, call_next, client_id)

        # Start new OAuth flow
        return await self._start_new_oauth_flow(request, call_next, client_id)

    def _is_mcp_request_without_auth(self, request: Request) -> bool:
        """Check if this is an MCP request without authentication.

        Args:
            request: FastAPI request

        Returns:
            True if MCP request without auth, False otherwise
        """
        # Check if it's an MCP request
        content_type = request.headers.get("content-type", "")
        is_mcp_request = (
            request.url.path.startswith("/mcp")
            or "mcp" in request.headers.get("user-agent", "").lower()
            or content_type.startswith("application/json")
        )

        # Check if authentication is missing
        has_auth = (
            request.headers.get("authorization")
            or request.headers.get("ocm-offline-token")
            or request.headers.get("x-oauth-token-id")
        )

        return is_mcp_request and not has_auth

    def _get_client_identifier(self, request: Request) -> str:
        """Get a unique identifier for the MCP client.

        Args:
            request: FastAPI request

        Returns:
            Client identifier string
        """
        user_agent = request.headers.get("user-agent", "unknown")
        client_ip = (
            getattr(request.client, "host", "unknown") if request.client else "unknown"
        )
        return f"{user_agent}_{client_ip}"

    def _has_pending_auth(self, client_id: str) -> bool:
        """Check if client has pending authentication.

        Args:
            client_id: Client identifier

        Returns:
            True if auth is pending, False otherwise
        """
        for session_info in self.pending_auth_sessions.values():
            if session_info.get("client_id") == client_id:
                return True
        return False

    async def _start_new_oauth_flow(
        self, request: Request, call_next: Any, client_id: str
    ) -> Response:
        """Start a new OAuth flow for the client.

        Args:
            request: FastAPI request
            call_next: Next middleware/handler
            client_id: Client identifier

        Returns:
            Response (either success or timeout)
        """
        log.info("MCP request detected without authentication, initiating OAuth flow")

        # Create authorization URL using the manager
        auth_url, state_json = oauth_manager.create_authorization_url(client_id)

        # Parse state to get session ID
        try:
            state = OAuthState.from_json(state_json)
            session_id = state.session_id
        except ValueError:
            return JSONResponse(
                {"error": "Failed to create OAuth state"}, status_code=500
            )

        # Store session info
        self.pending_auth_sessions[session_id] = {
            "client_id": client_id,
            "state": state_json,
            "auth_url": auth_url,
            "timestamp": asyncio.get_event_loop().time(),
        }

        # Automatically open browser
        open_browser_for_oauth(auth_url)

        log.info(
            "OAuth flow initiated for client %s, waiting for completion", client_id
        )
        return await self._wait_for_oauth_completion(request, call_next, client_id)

    async def _wait_for_oauth_completion(
        self, request: Request, call_next: Any, client_id: str
    ) -> Response:
        """Wait for OAuth completion and handle the result.

        Args:
            request: FastAPI request
            call_next: Next middleware/handler
            client_id: Client identifier

        Returns:
            Response (either authenticated request or timeout)
        """
        max_wait_time = 60  # 1 minute
        poll_interval = 1  # 1 second
        waited_time = 0

        while waited_time < max_wait_time:
            await asyncio.sleep(poll_interval)
            waited_time += poll_interval

            # Check if OAuth completed (token available for client)
            token = oauth_manager.token_store.get_access_token_by_client(client_id)
            if token:
                log.info(
                    "OAuth completed for client %s, proceeding with request", client_id
                )
                # Clean up pending session
                self._cleanup_client_sessions(client_id)
                return await self._create_authenticated_request(
                    request, call_next, token
                )

        # OAuth timed out
        log.warning("OAuth timed out for client %s", client_id)

        # Get auth URL for error message BEFORE cleanup
        auth_url = None
        for session_info in self.pending_auth_sessions.values():
            if session_info.get("client_id") == client_id:
                auth_url = session_info.get("auth_url")
                break

        # Now clean up the sessions
        self._cleanup_client_sessions(client_id)

        return self._create_timeout_response(auth_url)

    def _cleanup_client_sessions(self, client_id: str) -> None:
        """Clean up all pending sessions for a client.

        Args:
            client_id: Client identifier
        """
        sessions_to_remove = [
            session_id
            for session_id, session_info in self.pending_auth_sessions.items()
            if session_info.get("client_id") == client_id
        ]
        for session_id in sessions_to_remove:
            del self.pending_auth_sessions[session_id]

    async def _create_authenticated_request(
        self, request: Request, call_next: Any, token: str
    ) -> Response:
        """Create a new request with authentication token.

        Args:
            request: Original request
            call_next: Next middleware/handler
            token: Access token

        Returns:
            Response from handler
        """
        # Modify request headers for Starlette
        new_headers = list(request.scope.get("headers", []))
        # Remove any existing authorization header
        new_headers = [(k, v) for k, v in new_headers if k.lower() != b"authorization"]
        # Add the new authorization header
        new_headers.append((b"authorization", f"Bearer {token}".encode()))

        # Create new scope with updated headers
        new_scope = dict(request.scope)
        new_scope["headers"] = new_headers

        # Create new request with updated scope
        from starlette.requests import Request as StarletteRequest

        new_request = StarletteRequest(new_scope, request.receive)
        return await call_next(new_request)

    def _create_timeout_response(self, auth_url: Optional[str] = None) -> JSONResponse:
        """Create timeout response for failed OAuth.

        Args:
            auth_url: Optional auth URL to include in response

        Returns:
            JSON response with timeout error
        """
        if auth_url:
            return JSONResponse(
                {
                    "type": "oauth_timeout",
                    "message": "OAuth authentication timed out or failed",
                    "auth_url": auth_url,
                    "instructions": [
                        "1. Authentication timed out or failed",
                        "2. You can try the authentication URL manually:",
                        f"   {auth_url}",
                        "3. Or reconnect to the MCP server to try again",
                    ],
                },
                status_code=401,
            )
        return JSONResponse(
            {
                "type": "oauth_timeout",
                "message": "OAuth authentication timed out",
                "instructions": [
                    "Authentication took too long or failed",
                    "Please try reconnecting to the MCP server",
                ],
            },
            status_code=401,
        )

    async def handle_oauth_callback(self, request: Request) -> Response:
        """Handle OAuth callback and complete authentication.

        Note: This is now handled by oauth.oauth_callback_handler.
        This method is kept for backward compatibility but delegates to the main handler.

        Args:
            request: FastAPI request

        Returns:
            Response
        """
        from assisted_service_mcp.src.oauth.manager import oauth_callback_handler

        return await oauth_callback_handler(request)

    def cleanup_expired_sessions(self, max_age_seconds: int = 600) -> None:
        """Clean up expired authentication sessions.

        Args:
            max_age_seconds: Maximum session age in seconds (default 10 minutes)
        """
        current_time = asyncio.get_event_loop().time()
        expired_sessions = [
            session_id
            for session_id, info in self.pending_auth_sessions.items()
            if current_time - info["timestamp"] > max_age_seconds
        ]

        for session_id in expired_sessions:
            del self.pending_auth_sessions[session_id]
            log.info("Cleaned up expired OAuth session: %s", session_id)


# Global middleware instance
mcp_oauth_middleware = MCPOAuthMiddleware()
