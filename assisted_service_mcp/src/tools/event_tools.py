"""Event management tools for Assisted Service MCP Server."""

from typing import Annotated
from pydantic import Field

from metrics import track_tool_usage
from assisted_service_mcp.utils.client_factory import InventoryClient
from service_client.logger import log


@track_tool_usage()
async def cluster_events(
    mcp,
    get_access_token_func,
    cluster_id: Annotated[
        str,
        Field(description="The unique identifier of the cluster to get events for."),
    ],
) -> str:
    """Get chronological events for cluster installation progress and diagnostics.

    TOOL_NAME=cluster_events
    DISPLAY_NAME=Cluster Events
    USECASE=Track cluster installation progress, configuration changes, and diagnose issues through event history
    INSTRUCTIONS=1. Get cluster_id from create_cluster or list_clusters, 2. Call function to retrieve events, 3. Review chronological event log for progress and issues
    INPUT_DESCRIPTION=cluster_id (string): cluster UUID
    OUTPUT_DESCRIPTION=JSON string with timestamped events including event types, severity levels, and descriptive messages about cluster activities
    EXAMPLES=cluster_events("cluster-uuid")
    PREREQUISITES=Existing cluster with UUID
    RELATED_TOOLS=cluster_info (current cluster state), host_events (host-specific events), install_cluster (triggers installation events), list_clusters

    I/O-bound operation - uses async def for external API calls.

    Retrieves chronological events related to cluster installation, configuration changes, and status updates.
    Events help track installation progress and diagnose issues.

    Args:
        cluster_id (str): The unique identifier of the cluster to get events for.

    Returns:
        str: JSON string with timestamped cluster events and descriptive messages.
    """
    log.info("Retrieving events for cluster_id: %s", cluster_id)
    client = InventoryClient(get_access_token_func())
    result = await client.get_events(cluster_id=cluster_id)
    log.info("Successfully retrieved events for cluster %s", cluster_id)
    return result


@track_tool_usage()
async def host_events(
    mcp,
    get_access_token_func,
    cluster_id: Annotated[
        str,
        Field(description="The unique identifier of the cluster containing the host."),
    ],
    host_id: Annotated[
        str,
        Field(
            description="The unique identifier of the specific host to get events for."
        ),
    ],
) -> str:
    """Get events specific to a particular host for installation tracking and diagnostics.

    TOOL_NAME=host_events
    DISPLAY_NAME=Host Events
    USECASE=Track host-specific installation progress, hardware validation, and diagnose host issues
    INSTRUCTIONS=1. Get host_id from cluster_info host list, 2. Get cluster_id from create_cluster or list_clusters, 3. Call function to retrieve host events, 4. Review for validation results and issues
    INPUT_DESCRIPTION=cluster_id (string): cluster UUID containing the host, host_id (string): host UUID
    OUTPUT_DESCRIPTION=JSON string with host-specific events including hardware validation results, installation steps, role assignment, and error messages
    EXAMPLES=host_events("cluster-uuid", "host-uuid")
    PREREQUISITES=Existing cluster with discovered hosts
    RELATED_TOOLS=cluster_events (cluster-wide events), cluster_info (get host list), set_host_role (configure host role)

    I/O-bound operation - uses async def for external API calls.

    Retrieves events related to a specific host's installation progress, hardware validation,
    role assignment, and any host-specific issues or status changes.

    Args:
        cluster_id (str): The unique identifier of the cluster containing the host.
        host_id (str): The unique identifier of the specific host to get events for.

    Returns:
        str: JSON string with host-specific events including validation results and installation steps.
    """
    log.info("Retrieving events for host %s in cluster %s", host_id, cluster_id)
    client = InventoryClient(get_access_token_func())
    result = await client.get_events(cluster_id=cluster_id, host_id=host_id)
    log.info(
        "Successfully retrieved events for host %s in cluster %s", host_id, cluster_id
    )
    return result

