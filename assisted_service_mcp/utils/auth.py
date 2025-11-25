"""Authentication utilities for Assisted Service MCP Server."""

from typing import Any, Callable, Optional

import requests
from assisted_service_mcp.src.logger import log
from assisted_service_mcp.src.settings import get_setting, settings


def get_offline_token(mcp: Any) -> str:
    """
    Retrieve the offline token from environment variables or request headers.

    This function attempts to get the Red Hat OpenShift Cluster Manager (OCM) offline token
    first from the OFFLINE_TOKEN environment variable, then from the OCM-Offline-Token
    request header. The token is required for authenticating with the Red Hat assisted
    installer service.

    Args:
        mcp: The FastMCP instance to get request context from.

    Returns:
        str: The offline token string used for authentication.

    Raises:
        RuntimeError: If no offline token is found in either environment variables
            or request headers.
    """
    log.debug("Attempting to retrieve offline token")
    token = get_setting("OFFLINE_TOKEN")
    if token:
        log.debug("Found offline token in environment variables")
        return token

    context = mcp.get_context()
    if context and context.request_context:
        request = context.request_context.request
        if request is not None:
            token = request.headers.get("OCM-Offline-Token")
            if token:
                log.debug("Found offline token in request headers")
                return token

    log.error("No offline token found in environment or request headers")
    raise RuntimeError("No offline token found in environment or request headers")


def get_access_token(
    mcp: Any,
    oauth_token_func: Callable[[Any], Optional[str]] | None = None,
) -> str:
    """
    Retrieve the access token.

    Authentication methods are checked in the following order of priority:
    1. Access token in the Authorization request header
    2. OAuth flow (if OAUTH_ENABLED is true) - no fallback to offline token
    3. Offline token via environment variable (only if OAuth is disabled)

    When OAuth is enabled, offline token fallback is disabled to ensure consistent
    OAuth-only authentication flow.

    Note: OCM-Offline-Token header support is deprecated but still functional for backward compatibility.

    Args:
        mcp: The FastMCP instance to get request context from.
        oauth_token_func: Optional function to get OAuth token. If not provided,
                         OAuth flow will not be attempted.

    Returns:
        str: The access token.

    Raises:
        RuntimeError: If no valid authentication method is available or authentication fails.
    """
    log.debug("Attempting to retrieve access token using priority order")

    # 1. First try to get the token from the authorization header:
    context = mcp.get_context()
    if context and context.request_context:
        request = context.request_context.request
        if request is not None:
            header = request.headers.get("Authorization")
            if header is not None:
                parts = header.split()
                if len(parts) == 2 and parts[0].lower() == "bearer":
                    log.debug("Found access token in authorization header")
                    return parts[1]

    # 2. Try OAuth flow if enabled
    if settings.OAUTH_ENABLED:
        log.debug("OAuth is enabled, checking for OAuth access token")
        if oauth_token_func:
            oauth_token = oauth_token_func(mcp)
            if oauth_token:
                log.debug("Found OAuth access token (priority 2)")
                return oauth_token
            log.debug(
                "OAuth token function returned None - OAuth flow may be in progress"
            )
        else:
            log.debug(
                "OAuth enabled but no oauth_token_func provided - skipping OAuth priority"
            )

        # When OAuth is enabled, don't fall back to offline token
        log.error(
            "OAuth is enabled but no valid OAuth token found - offline token fallback disabled"
        )
        raise RuntimeError(
            "OAuth authentication is enabled but no valid OAuth token found. "
            "Please complete the OAuth authentication flow."
        )

    # 3. & 4. Try offline token methods (environment variable has priority over header)
    log.debug("Generating new access token from offline token (priority 3 & 4)")

    offline_token = get_offline_token(mcp)

    params = {
        "client_id": "cloud-services",
        "grant_type": "refresh_token",
        "refresh_token": offline_token,
    }
    sso_url = get_setting("SSO_URL")
    if not sso_url:
        log.error("SSO_URL is not configured")
        raise RuntimeError("SSO_URL is not configured")
    try:
        response = requests.post(sso_url, data=params, timeout=30)
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        log.error("Failed to exchange offline token for access token: %s", e)
        raise RuntimeError(f"Failed to obtain access token from SSO: {e}") from e

    try:
        response_data = response.json()
        access_token = response_data["access_token"]
    except (KeyError, ValueError) as e:
        log.error("Invalid SSO response format: %s", e)
        raise RuntimeError(
            "Invalid SSO response: missing or malformed access_token"
        ) from e

    log.debug("Successfully generated new access token from offline token")
    return access_token
