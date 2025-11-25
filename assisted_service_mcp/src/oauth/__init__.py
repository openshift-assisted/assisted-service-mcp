"""OAuth authentication module for Assisted Service MCP Server.

This module provides OAuth2 authentication support with PKCE for the MCP server.
"""

from assisted_service_mcp.src.settings import settings
from assisted_service_mcp.src.oauth.manager import (
    OAuthManager,
    get_oauth_access_token_from_mcp,
    oauth_callback_handler,
    oauth_manager,
    oauth_register_handler,
    oauth_token_handler,
)
from assisted_service_mcp.src.oauth.middleware import (
    MCPOAuthMiddleware,
    mcp_oauth_middleware,
)
from assisted_service_mcp.src.oauth.models import OAuthState, OAuthToken
from assisted_service_mcp.src.oauth.store import TokenStore
from assisted_service_mcp.src.oauth.utils import (
    extract_oauth_callback_params,
    get_oauth_success_html,
    open_browser_for_oauth,
)

__all__ = [
    # Manager
    "OAuthManager",
    "oauth_manager",
    "oauth_register_handler",
    "oauth_callback_handler",
    "oauth_token_handler",
    "get_oauth_access_token_from_mcp",
    # Middleware
    "MCPOAuthMiddleware",
    "mcp_oauth_middleware",
    # Models
    "OAuthToken",
    "OAuthState",
    # Store
    "TokenStore",
    # Utils
    "open_browser_for_oauth",
    "get_oauth_success_html",
    "extract_oauth_callback_params",
    # Settings (for test mocking)
    "settings",
]
