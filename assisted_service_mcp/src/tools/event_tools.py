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

    Retrieves timestamped events related to cluster installation, configuration changes,
    and status updates. Use this to track installation progress, understand what actions
    have been taken, and diagnose issues. Events include validation results, configuration
    changes, and error messages.

    Examples:
        - cluster_events("cluster-uuid")
        - Monitor installation progress in real-time
        - Investigate why a cluster installation failed
        - Review configuration changes made to the cluster

    Prerequisites:
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

    Retrieves host-specific events including hardware validation results, installation steps,
    role assignment, and error messages. Use this to diagnose host-specific issues like
    hardware compatibility problems, network configuration issues, or installation failures
    on a particular node.

    Examples:
        - host_events("cluster-uuid", "host-uuid")
        - Debug why a specific host failed validation
        - Monitor installation progress on a particular node
        - Check hardware detection and compatibility results

    Prerequisites:
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
            "Successfully retrieved events for host %s in cluster %s", host_id, cluster_id
        )
        return result
    except Exception as e:
        log.error(
            "Failed to retrieve events for host %s in cluster %s: %s", host_id, cluster_id, str(e))
        raise

