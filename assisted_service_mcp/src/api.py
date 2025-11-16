"""FastAPI application setup for the Assisted Service MCP server.

This module initializes the FastAPI app and sets up the MCP server
with appropriate transport protocols.
"""

from typing import Awaitable, Callable

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from assisted_service_mcp.src.mcp import AssistedServiceMCPServer
from assisted_service_mcp.src.settings import settings
from assisted_service_mcp.src.logger import log, configure_logging

# Ensure logging is configured before any module-level log usage
configure_logging()

# Initialize the MCP server
server = AssistedServiceMCPServer()

# Choose the appropriate transport protocol based on settings
if settings.TRANSPORT == "streamable-http":
    app = server.mcp.streamable_http_app()
    log.info("Using StreamableHTTP transport (stateless)")
else:
    app = server.mcp.sse_app()
    log.info("Using SSE transport (stateful)")

# Add OAuth endpoints and middleware if OAuth is enabled
if settings.OAUTH_ENABLED:
    from assisted_service_mcp.src.oauth import (
        oauth_register_handler,
        oauth_callback_handler,
        oauth_token_handler,
        mcp_oauth_middleware,
    )

    # Add OAuth middleware to handle authentication during MCP connection
    class OAuthMiddleware(BaseHTTPMiddleware):
        async def dispatch(
            self, request: Request, call_next: Callable[[Request], Awaitable[Response]]
        ) -> Response:
            return await mcp_oauth_middleware.handle_mcp_request(request, call_next)

    app.add_middleware(OAuthMiddleware)

    # OAuth discovery endpoints for better MCP client compatibility

    async def oauth_well_known_openid_handler(_request: Request) -> JSONResponse:
        """OAuth discovery endpoint."""
        return JSONResponse(
            {
                "issuer": settings.SELF_URL,
                "authorization_endpoint": f"{settings.OAUTH_URL}/protocol/openid-connect/auth",
                "token_endpoint": f"{settings.OAUTH_URL}/protocol/openid-connect/token",
                "registration_endpoint": f"{settings.SELF_URL}/oauth/register",
                "userinfo_endpoint": f"{settings.OAUTH_URL}/protocol/openid-connect/userinfo",
                "jwks_uri": f"{settings.OAUTH_URL}/protocol/openid-connect/certs",
                "response_types_supported": ["code"],
                "grant_types_supported": ["authorization_code"],
                "code_challenge_methods_supported": ["S256"],
                "scopes_supported": ["openid", "profile", "email"],
            }
        )

    async def mcp_register_handler(_request: Request) -> JSONResponse:
        """MCP registration endpoint."""
        return JSONResponse(
            {
                "name": "AssistedService",
                "version": "1.0.0",
                "description": "Assisted Service MCP Server with OAuth",
                "oauth": {
                    "authorization_endpoint": f"{settings.OAUTH_URL}/protocol/openid-connect/auth",
                    "token_endpoint": f"{settings.OAUTH_URL}/protocol/openid-connect/token",
                    "client_id": settings.OAUTH_CLIENT,
                    "redirect_uri": f"{settings.SELF_URL}/oauth/callback",
                    "scopes": ["openid", "profile", "email"],
                },
            }
        )

    # Wrapper functions to convert dict responses to JSONResponse for Starlette compatibility
    async def wrapped_oauth_register_handler(request: Request) -> JSONResponse:
        result = await oauth_register_handler(request)
        return JSONResponse(result)

    async def wrapped_oauth_token_handler(request: Request) -> JSONResponse:
        result = await oauth_token_handler(request)
        return JSONResponse(result)

    # Use Starlette's add_route method instead of FastAPI's add_api_route
    app.add_route("/oauth/register", wrapped_oauth_register_handler, methods=["GET"])
    app.add_route(
        "/oauth/callback", oauth_callback_handler, methods=["GET"]
    )  # This one returns Response already
    app.add_route("/oauth/token", wrapped_oauth_token_handler, methods=["POST"])

    # OAuth discovery endpoints - only the standard routes per MCP spec
    app.add_route(
        "/.well-known/openid-configuration/mcp",
        oauth_well_known_openid_handler,
        methods=["GET"],
    )
    app.add_route(
        "/.well-known/openid-configuration",
        oauth_well_known_openid_handler,
        methods=["GET"],
    )

    # OAuth status endpoint for polling
    async def oauth_status_handler(request: Request) -> JSONResponse:
        """Check OAuth authentication status for a client."""
        middleware_instance = mcp_oauth_middleware

        client_id = request.query_params.get("client_id")
        if not client_id:
            return JSONResponse(
                {"error": "client_id parameter required"}, status_code=400
            )

        # Check if client has completed authentication
        from assisted_service_mcp.src.oauth import oauth_manager

        if oauth_manager.token_store.get_token_by_client(client_id):
            return JSONResponse(
                {
                    "status": "authenticated",
                    "message": "OAuth authentication completed successfully",
                }
            )

        # Check if authentication is in progress
        for (
            session_id,
            session_info,
        ) in middleware_instance.pending_auth_sessions.items():
            if session_info.get("client_id") == client_id:
                return JSONResponse(
                    {
                        "status": "pending",
                        "message": "OAuth authentication in progress",
                        "session_id": session_id,
                    }
                )

        return JSONResponse(
            {
                "status": "not_authenticated",
                "message": "No authentication found for this client",
            }
        )

    # MCP registration endpoint
    app.add_route("/register", mcp_register_handler, methods=["POST", "GET"])
    app.add_route("/oauth/status", oauth_status_handler, methods=["GET"])

    log.info(
        "OAuth endpoints and discovery registered: /oauth/*, /.well-known/*, /register, /oauth/status"
    )
else:
    log.info("OAuth is disabled - no OAuth endpoints registered")
