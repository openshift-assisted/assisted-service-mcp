"""Event management tools for Assisted Service MCP Server."""

from typing import Annotated, Callable
from pydantic import Field

from assisted_service_mcp.src.metrics import track_tool_usage
from assisted_service_mcp.src.service_client.assisted_service_api import InventoryClient
from assisted_service_mcp.src.logger import log


@track_tool_usage()
async def cluster_events(
    get_access_token_func: Callable[[], str],
    cluster_id: Annotated[
        str,
        Field(description="The unique identifier of the cluster to get events for."),
    ],
) -> str:
    """Get chronological events for cluster installation progress and diagnostics.

    Retrieves timestamped events related to cluster installation, configuration changes,
    and status updates. Use this to track installation progress, understand what actions
    have been taken, and diagnose issues. Events include validation results, configuration
    changes, and error messages.

    Prerequisites:
        - Valid OCM offline token for authentication
        - Existing cluster with UUID (from list_clusters or create_cluster)

    Related tools:
        - cluster_info - Current cluster state and status
        - host_events - Events specific to individual hosts
        - install_cluster - Triggers installation events
        - list_clusters - Get cluster UUIDs

    Returns:
        str: JSON string with timestamped cluster events and descriptive messages.
    """
    log.info("Retrieving events for cluster_id: %s", cluster_id)
    try:
        access_token = get_access_token_func()
        client = InventoryClient(access_token)
        result = await client.get_events(cluster_id=cluster_id)
        log.info("Successfully retrieved events for cluster %s", cluster_id)
        return result
    except Exception as e:
        log.error("Failed to retrieve events for cluster %s: %s", cluster_id, str(e))
        raise


@track_tool_usage()
async def host_events(
    get_access_token_func: Callable[[], str],
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

    Retrieves host-specific events including hardware validation results, installation steps,
    role assignment, and error messages. Use this to diagnose host-specific issues like
    hardware compatibility problems, network configuration issues, or installation failures
    on a particular node.

    Prerequisites:
        - Valid OCM offline token for authentication
        - Existing cluster with discovered hosts
        - Host ID (from cluster_info host list)

    Related tools:
        - cluster_events - Cluster-wide events
        - cluster_info - Get host list and IDs
        - set_host_role - Configure host role assignment

    Returns:
        str: JSON string with host-specific events including validation results and installation steps.
    """
    try:
        log.info("Retrieving events for host %s in cluster %s", host_id, cluster_id)
        client = InventoryClient(get_access_token_func())
        result = await client.get_events(cluster_id=cluster_id, host_id=host_id)
        log.info(
            "Successfully retrieved events for host %s in cluster %s",
            host_id,
            cluster_id,
        )
        return result
    except Exception as e:
        log.error(
            "Failed to retrieve events for host %s in cluster %s: %s",
            host_id,
            cluster_id,
            str(e),
        )
        raise
