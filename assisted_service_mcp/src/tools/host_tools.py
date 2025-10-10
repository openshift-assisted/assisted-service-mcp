"""Host management tools for Assisted Service MCP Server."""

from typing import Annotated, Callable, Literal
from pydantic import Field

from assisted_service_mcp.src.metrics import track_tool_usage
from assisted_service_mcp.src.service_client.assisted_service_api import InventoryClient
from assisted_service_mcp.src.logger import log
from assisted_service_mcp.src.tools.shared_helpers import _get_cluster_infra_env_id


@track_tool_usage()
async def set_host_role(
    get_access_token_func: Callable[[], str],
    host_id: Annotated[
        str, Field(description="The unique identifier of the host to configure.")
    ],
    cluster_id: Annotated[
        str,
        Field(description="The unique identifier of the cluster containing the host."),
    ],
    role: Annotated[
        Literal["auto-assign", "master", "worker"],
        Field(
            description="The role to assign to the host. Valid options: 'auto-assign' (let installer decide), 'master' (control plane node with API server, etcd, scheduler), 'worker' (compute node for application workloads)."
        ),
    ],
) -> str:
    """Assign a specific role to a discovered host in the cluster.

    Sets whether a host will be a control plane (master) node or worker node. Use 'master'
    for nodes that will run the Kubernetes control plane (API server, etcd, scheduler).
    Use 'worker' for nodes that will only run application workloads. Use 'auto-assign' to
    let the installer choose based on cluster requirements. HA clusters require at least
    3 master nodes.

    Prerequisites:
        - Valid OCM offline token for authentication
        - Discovered host (boot from cluster ISO to discover)
        - Host ID from cluster_info host list
        - Cluster with infrastructure environment

    Related tools:
        - cluster_info - Get list of discovered hosts with their IDs
        - host_events - View host-specific events and validation results
        - cluster_iso_download_url - Get ISO to boot hosts for discovery

    Returns:
        str: Formatted string with updated host configuration showing assigned role.
    """
    log.info("Setting role '%s' for host %s in cluster %s", role, host_id, cluster_id)
    client = InventoryClient(get_access_token_func())

    # Get the InfraEnv ID for the cluster
    infra_env_id = await _get_cluster_infra_env_id(client, cluster_id)

    # Update the host with the specified role
    result = await client.update_host(host_id, infra_env_id, host_role=role)
    log.info("Successfully set role for host %s in cluster %s", host_id, cluster_id)
    return result.to_str()
