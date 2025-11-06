"""Version and operator management tools for Assisted Service MCP Server."""

from typing import Callable

from assisted_service_mcp.src.metrics import track_tool_usage
from assisted_service_mcp.src.service_client.assisted_service_api import InventoryClient
from assisted_service_mcp.src.logger import log


def format_openshift_version_support_level(support_level: str) -> str:
    match support_level:
        case "production":
            return "Full Support"
        case "maintenance":
            return "Maintenance Support"
        case "end-of-life":
            return "End of Life"
        case "beta":
            return "Release Candidate"
        case "Extended Support":
            return "Extended Support"
        case _:
            return support_level


@track_tool_usage()
async def list_versions(get_access_token_func: Callable[[], str]) -> str:
    """List all available OpenShift versions for installation.

    Retrieves the latest OpenShift versions that can be installed using the assisted
    installer service, including GA releases and pre-release candidates. Use this
    before creating a cluster to see which versions are currently available.

    All available OpenShift versions and their support levels in a formatted table.
    OpenShift Version  | Support Level
    --------------------+---------------
    <openshift_version> | <support_level>
    <openshift_version> | <support_level>
    ...

    Returns:
        str: A table-formatted string containing available OpenShift versions and their support status. Show this as a table to the user if they ask for a list of available versions.
    """
    log.info("Retrieving available OpenShift versions")
    client = InventoryClient(get_access_token_func())
    try:
        result = await client.get_openshift_versions(True)
        log.info("Successfully retrieved OpenShift versions")

        # Build formatted table
        column_width = 30
        header = (
            f"{'OpenShift Version':<{column_width}} | {'Support Level':<{column_width}}"
        )
        separator = f"{'-' * column_width}-+-{'-' * column_width}"
        rows = [
            f"{version.get('display_name', ''):<{column_width}} | {format_openshift_version_support_level(version.get('support_level', '')):<{column_width}}"
            for version in result.values()
        ]
        return_str = f"{header}\n{separator}\n" + "\n".join(rows) + "\n"
        return return_str
    except Exception as e:
        log.error("Failed to retrieve OpenShift versions: %s", str(e))
        raise
