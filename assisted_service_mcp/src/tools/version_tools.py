"""Version and operator management tools for Assisted Service MCP Server."""

from typing import Callable
from assisted_service_client import models

from assisted_service_mcp.src.metrics import track_tool_usage
from assisted_service_mcp.src.service_client.assisted_service_api import InventoryClient
from assisted_service_mcp.src.logger import log


def format_version_list(versions_data: models.OpenshiftVersions) -> str:
    """Format OpenShift versions data as a markdown table.

    Args:
        versions_data: OpenshiftVersions object containing version information from the API

    Returns:
        str: Formatted markdown table with version information
    """
    if not versions_data:
        return "No OpenShift versions available."

    # Support level mapping
    support_level_mapping = {
        "production": "Full Support",
        "maintenance": "Maintenance Support",
        "end-of-life": "End of Life",
        "beta": "Release Candidate",
        "Extended Support": "Extended Support",
    }

    # Start building the markdown table
    markdown_table = (
        "| OpenShift Version | Support Level | Supported CPU Architectures |\n"
    )
    markdown_table += "|---|---|---|\n"

    # Sort versions by display_name for consistent ordering
    sorted_versions = sorted(
        versions_data.items(), key=lambda x: x[1].get("display_name", x[0])
    )

    for version_key, version_info in sorted_versions:
        display_name = version_info.get("display_name", version_key)
        support_level = version_info.get("support_level", "Unknown")
        cpu_arch = version_info.get("cpu_architectures", "Unknown")

        # Map support level using the provided mapping
        mapped_support_level = support_level_mapping.get(support_level, support_level)

        # Handle multiple CPU architectures (if it's a list)
        if isinstance(cpu_arch, list):
            cpu_arch_str = ", ".join(cpu_arch)
        else:
            cpu_arch_str = str(cpu_arch)

        markdown_table += (
            f"| {display_name} | {mapped_support_level} | {cpu_arch_str} |\n"
        )

    return markdown_table


@track_tool_usage()
async def list_versions(get_access_token_func: Callable[[], str]) -> str:
    """List all available OpenShift versions for installation as a formatted markdown table.

    Retrieves the latest OpenShift versions that can be installed using the Red Hat
    Assisted Installer service and returns them in a well-formatted markdown table.

    The output is a ready-to-display markdown table with the following columns:
    - **OpenShift Version**: The version identifier (e.g., "4.18.2", "4.21.0-ec.2-multi")
    - **Support Level**: Mapped support level indicating stability:
      * "Full Support": Production-ready, Generally Available (GA) releases
      * "Release Candidate": Beta/pre-release versions, NOT for production use
      * "Maintenance Support": In maintenance mode, limited updates
      * "End of Life": No longer supported
      * "Extended Support": Extended support lifecycle
    - **Supported CPU Architectures**: Compatible CPU architectures (e.g., x86_64, arm64, s390x, ppc64le)

    IMPORTANT: This tool returns pre-formatted markdown content. Do NOT reformat, restructure,
    or modify the output. Present it exactly as returned to preserve the table formatting.
    The support levels are already properly mapped and the table is ready for display.

    Returns:
        str: A formatted markdown table showing all available OpenShift versions with their
            support levels and supported CPU architectures. The output is ready for direct
            presentation to users without any additional formatting.
    """
    log.info("Retrieving available OpenShift versions")
    client = InventoryClient(get_access_token_func())
    try:
        result = await client.get_openshift_versions(True)
        log.info("Successfully retrieved OpenShift versions")
        return format_version_list(result)
    except Exception as e:
        log.error("Failed to retrieve OpenShift versions: %s", str(e))
        raise
