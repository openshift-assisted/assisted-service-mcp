"""Health check tools for Assisted Service MCP Server."""

import json
from typing import Callable

from assisted_service_mcp.src.metrics import track_tool_usage
from assisted_service_mcp.src.settings import get_setting
from assisted_service_mcp.src.logger import log


@track_tool_usage()
async def check_prerequisites(
    get_access_token_func: Callable[[], str],
    ui_supported: bool,
) -> str:
    """Check environment prerequisites for cluster operations.

    Verifies that authentication is configured and the Assisted Installer
    API is reachable. Call this before any cluster operation to confirm
    the environment is ready.

    Returns:
        str: JSON with offline_token_set and api_reachable flags.
    """
    log.info("Checking prerequisites")
    token_set = bool(get_setting("OFFLINE_TOKEN"))

    api_reachable = False
    api_error = None
    if token_set:
        try:
            get_access_token_func()
            api_reachable = True
        except Exception as exc:
            api_error = str(exc)
            log.warning("API not reachable: %s", exc)

    result = {
        "offline_token_set": token_set,
        "api_reachable": api_reachable,
    }
    if api_error:
        result["api_error"] = api_error

    log.info("Prerequisites: token=%s, api=%s", token_set, api_reachable)
    return json.dumps(result)
