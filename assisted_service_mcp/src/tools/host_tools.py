"""Host management tools for Assisted Service MCP Server."""

from typing import Annotated
from pydantic import Field

from metrics import track_tool_usage
from assisted_service_mcp.utils.client_factory import InventoryClient
from service_client.logger import log
from assisted_service_mcp.src.tools.shared_helpers import _get_cluster_infra_env_id


@track_tool_usage()
async def set_host_role(
    mcp,
    get_access_token_func,
    host_id: Annotated[
        str, Field(description="The unique identifier of the host to configure.")
    ],
    cluster_id: Annotated[
        str,
        Field(description="The unique identifier of the cluster containing the host."),
    ],
    role: Annotated[
        str,
        Field(
            description="The role to assign to the host. Valid options are: auto-assign (Let the installer automatically determine the role), master (Control plane node - API server, etcd, scheduler), worker (Compute node for running application workloads)."
        ),
    ],
) -> str:
    """Assign a specific role to a discovered host in the cluster.

    TOOL_NAME=set_host_role
    DISPLAY_NAME=Set Host Role
    USECASE=Configure whether discovered host will be control plane (master) or compute (worker) node
    INSTRUCTIONS=1. Boot hosts with cluster ISO, 2. Get host_id from cluster_info, 3. Get cluster_id, 4. Choose role (auto-assign/master/worker), 5. Receive updated host config
    INPUT_DESCRIPTION=host_id (string): host UUID from discovered hosts, cluster_id (string): cluster UUID, role (string): auto-assign (automatic)/master (control plane)/worker (compute node)
    OUTPUT_DESCRIPTION=Formatted string with updated host configuration showing newly assigned role
    EXAMPLES=set_host_role("host-uuid", "cluster-uuid", "master"), set_host_role("host-uuid", "cluster-uuid", "worker")
    PREREQUISITES=Host discovered after booting from cluster ISO (visible in cluster_info)
    RELATED_TOOLS=cluster_info (get host list and IDs), cluster_iso_download_url (get ISO to boot hosts), host_events (view host-specific events)

    I/O-bound operation - uses async def for external API calls.

    Sets the role for a host that has been discovered through booting from the cluster ISO.
    The role determines the host's function in the OpenShift cluster.

    Args:
        host_id (str): The unique identifier of the host to configure.
        cluster_id (str): The unique identifier of the cluster containing the host.
        role (str): auto-assign, master (control plane), or worker (compute).

    Returns:
        str: Formatted string with updated host configuration showing assigned role.
    """
    log.info("Setting role '%s' for host %s in cluster %s", role, host_id, cluster_id)
    client = InventoryClient(get_access_token_func())

    # Get the InfraEnv ID for the cluster
    infra_env_id = await _get_cluster_infra_env_id(client, cluster_id)

    # Update the host with the specified role
    result = await client.update_host(host_id, infra_env_id, host_role=role)
    log.info(
        "Successfully set role '%s' for host %s in cluster %s",
        role,
        host_id,
        cluster_id,
    )
    return result.to_str()

