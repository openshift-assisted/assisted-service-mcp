"""Version and operator management tools for Assisted Service MCP Server."""

import json
from typing import Callable

from assisted_service_mcp.src.metrics import track_tool_usage
from assisted_service_mcp.src.service_client.assisted_service_api import InventoryClient
from assisted_service_mcp.src.logger import log


@track_tool_usage()
async def list_versions(get_access_token_func: Callable[[], str]) -> str:
    """List all available OpenShift versions for installation.

    Retrieves the latest OpenShift versions that can be installed using the assisted
    installer service, including GA releases and pre-release candidates. Use this
    before creating a cluster to see which versions are currently available.

    Returns:
        str: A JSON string containing available OpenShift versions with metadata
            including version numbers, release dates, and support status.
    """
    log.info("Retrieving available OpenShift versions")
    client = InventoryClient(get_access_token_func())
    try:
        result = await client.get_openshift_versions(True)
        log.info("Successfully retrieved OpenShift versions")
        return json.dumps(result)
    except Exception as e:
        log.error("Failed to retrieve OpenShift versions: %s", str(e))
        raise
