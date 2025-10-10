"""Authentication utilities for Assisted Service MCP Server."""

from typing import Any, Callable

import requests
from assisted_service_mcp.src.logger import log
from assisted_service_mcp.src.settings import get_setting


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
    mcp: Any, offline_token_func: Callable[[], str] | None = None
) -> str:
    """
    Retrieve the access token.

    This function tries to get the Red Hat OpenShift Cluster Manager (OCM) access token. First
    it tries to extract it from the authorization header, and if it isn't there then it tries
    to generate a new one using the offline token.

    Args:
        mcp: The FastMCP instance to get request context from.
        offline_token_func: Optional function to get offline token. If not provided,
                           uses get_offline_token(mcp).

    Returns:
        str: The access token.

    Raises:
        RuntimeError: If it isn't possible to obtain or generate the access token.
    """
    log.debug("Attempting to retrieve access token")
    # First try to get the token from the authorization header:
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

    # Now try to get the offline token, and generate a new access token from it:
    log.debug("Generating new access token from offline token")

    # Use the provided offline token function or default to get_offline_token(mcp)
    if offline_token_func is None:
        offline_token = get_offline_token(mcp)
    else:
        offline_token = offline_token_func()

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

    log.debug("Successfully generated new access token")
    return access_token
