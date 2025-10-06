"""Shared helper functions used across multiple tool modules."""

from assisted_service_mcp.utils.client_factory import InventoryClient
from service_client.logger import log


async def _get_cluster_infra_env_id(client: InventoryClient, cluster_id: str) -> str:
    """
    Get the InfraEnv ID for a cluster (expecting a single InfraEnv).

    This is shared code used by both set_host_role and set_cluster_ssh_key.

    Args:
        client: The InventoryClient instance.
        cluster_id: The cluster ID to get InfraEnv ID for.

    Returns:
        str: The InfraEnv ID (first valid one if multiple exist).

    Raises:
        ValueError: If no InfraEnv is found or InfraEnv doesn't have a valid ID.
    """
    log.info("Getting InfraEnv for cluster %s", cluster_id)
    infra_envs = await client.list_infra_envs(cluster_id)

    if not infra_envs:
        raise ValueError(f"No InfraEnv found for cluster {cluster_id}")

    if len(infra_envs) > 1:
        log.warning(
            "Found %d InfraEnvs for cluster %s, using the first valid one",
            len(infra_envs),
            cluster_id,
        )

    infra_env_id = infra_envs[0].get("id")
    if not infra_env_id:
        raise ValueError(f"No InfraEnv with valid ID found for cluster {cluster_id}")

    log.info("Using InfraEnv %s for cluster %s", infra_env_id, cluster_id)
    return infra_env_id

