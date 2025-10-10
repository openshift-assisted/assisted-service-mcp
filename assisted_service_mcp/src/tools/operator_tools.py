"""Version and operator management tools for Assisted Service MCP Server."""

import json
from typing import Annotated, Callable
from pydantic import Field

from assisted_service_mcp.src.metrics import track_tool_usage
from assisted_service_mcp.src.service_client.assisted_service_api import InventoryClient
from assisted_service_mcp.src.logger import log


@track_tool_usage()
async def list_operator_bundles(get_access_token_func: Callable[[], str]) -> str:
    """List available operator bundles that can be added to clusters.

    Retrieves operator bundles that extend OpenShift cluster functionality with additional
    capabilities like virtualization, AI/ML, monitoring, and storage. These bundles are
    automatically installed during cluster deployment if added before installation.

    Prerequisites:
        - Valid OCM offline token for authentication

    Related tools:
        - add_operator_bundle_to_cluster - Add bundles from this list to a cluster
        - create_cluster - Operator bundles can be added to new clusters
        - list_versions - See compatible OpenShift versions

    Returns:
        str: A JSON string containing available operator bundles with metadata
            including bundle names, descriptions, and operator details.
    """
    log.info("Retrieving available operator bundles")
    client = InventoryClient(get_access_token_func())
    try:
        result = await client.get_operator_bundles()
        log.info("Successfully retrieved %s operator bundles", len(result))
        return json.dumps(result)
    except Exception as e:
        log.error("Failed to retrieve operator bundles: %s", str(e))
        raise


@track_tool_usage()
async def add_operator_bundle_to_cluster(
    get_access_token_func: Callable[[], str],
    cluster_id: Annotated[
        str, Field(description="The unique identifier of the cluster to configure.")
    ],
    bundle_name: Annotated[
        str,
        Field(
            description="The name of the operator bundle to add. Use list_operator_bundles to see available bundles. Common bundles: 'virtualization', 'openshift-ai'."
        ),
    ],
) -> str:
    """Add an operator bundle to be automatically installed with the cluster.

    Configures the specified operator bundle to be installed during cluster deployment.
    The operator will be installed automatically after the cluster installation completes.
    Bundle must be from the list returned by list_operator_bundles(). Add operator bundles
    before starting cluster installation.

    Prerequisites:
        - Valid OCM offline token for authentication
        - Existing cluster (from create_cluster)
        - Cluster not yet installed (check with cluster_info)
        - Bundle name from list_operator_bundles

    Related tools:
        - list_operator_bundles - Get available operator bundle names
        - cluster_info - Verify cluster state and installed operators
        - create_cluster - Create cluster first
        - install_cluster - Start installation after adding bundles

    Returns:
        str: A formatted string containing the updated cluster configuration
            showing the newly added operator bundle.
    """
    log.info("Adding operator bundle '%s' to cluster %s", bundle_name, cluster_id)
    client = InventoryClient(get_access_token_func())
    try:
        result = await client.add_operator_bundle_to_cluster(cluster_id, bundle_name)
        log.info(
            "Successfully added operator bundle '%s' to cluster %s",
            bundle_name,
            cluster_id,
        )
        return result.to_str()
    except Exception as e:
        log.error(
            "Failed to add operator bundle '%s' to cluster %s: %s",
            bundle_name,
            cluster_id,
            str(e),
        )
        raise
