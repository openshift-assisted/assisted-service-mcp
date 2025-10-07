"""Version and operator management tools for Assisted Service MCP Server."""

import json
from typing import Annotated
from pydantic import Field

from metrics import track_tool_usage
from assisted_service_mcp.utils.client_factory import InventoryClient
from service_client.logger import log


@track_tool_usage()
async def list_versions(mcp, get_access_token_func) -> str:
    """List all available OpenShift versions for installation.

    Retrieves the complete list of OpenShift versions that can be installed using the
    assisted installer service, including GA releases and pre-release candidates. Use
    this before creating a cluster to see which versions are available.

    Examples:
        - list_versions()
        - Check available versions before creating a new cluster
        - See if a specific OpenShift version is available
        - Find the latest stable release

    Prerequisites:
        - Valid OCM offline token for authentication

    Related tools:
        - create_cluster - Uses version from this list
        - list_operator_bundles - See available operators for each version

    Returns:
        str: A JSON string containing available OpenShift versions with metadata
            including version numbers, release dates, and support status.
    """
    log.info("Retrieving available OpenShift versions")
    client = InventoryClient(get_access_token_func())
    result = await client.get_openshift_versions(True)
    log.info("Successfully retrieved OpenShift versions")
    return json.dumps(result)


@track_tool_usage()
async def list_operator_bundles(mcp, get_access_token_func) -> str:
    """List available operator bundles that can be added to clusters.

    Retrieves operator bundles that extend OpenShift cluster functionality with additional
    capabilities like virtualization, AI/ML, monitoring, and storage. These bundles are
    automatically installed during cluster deployment if added before installation.

    Examples:
        - list_operator_bundles()
        - See available operators before creating a cluster
        - Check if a specific operator bundle is available
        - Find operators for a specific use case (e.g., virtualization, AI)

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
    result = await client.get_operator_bundles()
    log.info("Successfully retrieved %s operator bundles", len(result))
    return json.dumps(result)


@track_tool_usage()
async def add_operator_bundle_to_cluster(
    mcp,
    get_access_token_func,
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

    Examples:
        - add_operator_bundle_to_cluster("cluster-uuid", "virtualization")
        - add_operator_bundle_to_cluster("cluster-uuid", "openshift-ai")

    Prerequisites:
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
    result = await client.add_operator_bundle_to_cluster(cluster_id, bundle_name)
    log.info(
        "Successfully added operator bundle '%s' to cluster %s", bundle_name, cluster_id
    )
    return result.to_str()

