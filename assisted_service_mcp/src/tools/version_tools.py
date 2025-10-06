"""Version and operator management tools for Assisted Service MCP Server."""

import json
from typing import Annotated
from pydantic import Field

from metrics import track_tool_usage
from assisted_service_mcp.utils.client_factory import InventoryClient
from service_client.logger import log


@track_tool_usage()
async def list_versions(mcp, get_access_token_func) -> str:
    """List all available OpenShift versions for installation with comprehensive metadata.

    TOOL_NAME=list_versions
    DISPLAY_NAME=OpenShift Version List
    USECASE=Retrieve available OpenShift versions that can be installed using the assisted installer
    INSTRUCTIONS=1. Call function without parameters, 2. Receive list of available versions
    INPUT_DESCRIPTION=No parameters required
    OUTPUT_DESCRIPTION=JSON string with available OpenShift versions including version numbers, release dates, and support status
    EXAMPLES=list_versions()
    PREREQUISITES=Valid OCM offline token for authentication
    RELATED_TOOLS=create_cluster (uses version from this list), list_operator_bundles

    I/O-bound operation - uses async def for external API calls.

    Retrieves the complete list of OpenShift versions that can be installed
    using the assisted installer service, including release versions and
    pre-release candidates.

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
    """List available operator bundles for cluster installation with comprehensive metadata.

    TOOL_NAME=list_operator_bundles
    DISPLAY_NAME=Operator Bundle List
    USECASE=Retrieve available operator bundles that extend OpenShift cluster functionality
    INSTRUCTIONS=1. Call function without parameters, 2. Receive list of available operator bundles
    INPUT_DESCRIPTION=No parameters required
    OUTPUT_DESCRIPTION=JSON string with available operator bundles including bundle names, descriptions, and operator details
    EXAMPLES=list_operator_bundles()
    PREREQUISITES=Valid OCM offline token for authentication
    RELATED_TOOLS=add_operator_bundle_to_cluster (adds bundles from this list), create_cluster

    I/O-bound operation - uses async def for external API calls.

    Retrieves details about operator bundles that can be optionally installed
    during cluster deployment.

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
            description="The name of the operator bundle to add. The available operator bundle names are 'virtualization' and 'openshift-ai'"
        ),
    ],
) -> str:
    """Add an operator bundle to be installed with the cluster with comprehensive metadata.

    TOOL_NAME=add_operator_bundle_to_cluster
    DISPLAY_NAME=Add Operator Bundle
    USECASE=Add operator bundles to extend cluster functionality with virtualization, AI, and other capabilities
    INSTRUCTIONS=1. Get bundle name from list_operator_bundles, 2. Provide cluster_id and bundle_name, 3. Receive updated cluster configuration
    INPUT_DESCRIPTION=cluster_id (string): cluster UUID, bundle_name (string): operator bundle name ('virtualization' or 'openshift-ai')
    OUTPUT_DESCRIPTION=Formatted string with updated cluster configuration showing added operator bundle
    EXAMPLES=add_operator_bundle_to_cluster("cluster-uuid", "virtualization")
    PREREQUISITES=Valid cluster with status allowing operator addition, bundle name from list_operator_bundles
    RELATED_TOOLS=list_operator_bundles (get available bundles), cluster_info (verify cluster state), create_cluster

    I/O-bound operation - uses async def for external API calls.

    Configures the specified operator bundle to be automatically installed
    during cluster deployment. The bundle must be from the list of available
    bundles returned by list_operator_bundles().

    Args:
        cluster_id (str): The unique identifier of the cluster to configure.
        bundle_name (str): The name of the operator bundle to add.
            The available operator bundle names are "virtualization" and "openshift-ai"

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

