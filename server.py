"""
MCP server for Red Hat Assisted Service API.

This module provides Model Context Protocol (MCP) tools for interacting with
Red Hat's Assisted Service API to manage OpenShift cluster installations.
"""

import json
import os
import asyncio
from typing import Any, Annotated

from jinja2 import TemplateError
import requests
import uvicorn
from pydantic import Field
from assisted_service_client import models
from mcp.server.fastmcp import FastMCP
from log_analyzer.main import analyze_cluster

from metrics import metrics, track_tool_usage, initiate_metrics
from service_client import InventoryClient
from service_client.helpers import Helpers
from service_client.logger import log
from static_net import (
    NMStateTemplateParams,
    add_or_replace_static_host_config_yaml,
    generate_nmstate_from_template,
    remove_static_host_config_by_index,
    validate_and_parse_nmstate,
)


transport_type = os.environ.get("TRANSPORT", "sse").lower()
use_stateless_http = transport_type == "streamable-http"

mcp = FastMCP("AssistedService", host="0.0.0.0", stateless_http=use_stateless_http)


TROUBLESHOOTING_ENABLED = (
    os.environ.get("ENABLE_TROUBLESHOOTING_TOOLS", "0").lower() == "1"
)


def format_presigned_url(presigned_url: models.PresignedUrl) -> dict[str, Any]:
    r"""
    Format a presigned URL object into a readable string.

    Args:
        access_token: The access token for authentication.
        
    Returns:
        InventoryClient instance.
    
    Tests can patch this function to return a mock client.
    """
    return client_factory.InventoryClient(access_token)

# Import all tool modules for re-export
from assisted_service_mcp.src.tools import (
    cluster_tools,
    event_tools,
    download_tools,
    version_tools,
    host_tools,
    network_tools,
)

# For backwards compatibility with tests, create a module-level mcp instance
_server = AssistedServiceMCPServer()
mcp = _server.mcp

# Re-export auth helpers with wrappers that match the old signature
def get_offline_token() -> str:
    """Wrapper for backwards compatibility."""
    return _auth_module.get_offline_token(mcp)


def get_access_token() -> str:
    """Wrapper for backwards compatibility."""
    # Pass get_offline_token as a callback to break the dependency
    return _auth_module.get_access_token(mcp, offline_token_func=get_offline_token)


# Re-export all tool functions for backwards compatibility with tests
# These wrappers inject the mcp instance and auth function automatically

async def cluster_info(cluster_id: str) -> str:
    """Get comprehensive information about a specific cluster.
    
    Args:
        cluster_id: The unique identifier of the cluster.
        
    Returns:
        str: Formatted cluster information.
    """
    return await cluster_tools.cluster_info(mcp, get_access_token, cluster_id)


async def list_clusters() -> str:
    """List all clusters for the current user.
    
    Returns:
        str: JSON string containing list of clusters.
    """
    return await cluster_tools.list_clusters(mcp, get_access_token)


async def create_cluster(
    name: str,
    version: str,
    base_domain: str,
    *args: Any,
    **kwargs: Any
) -> str:
    """Create a new OpenShift cluster.
    
    Args:
        name: The name of the new cluster.
        version: The OpenShift version to install.
        base_domain: The base DNS domain for the cluster.
        *args: Additional positional arguments.
        **kwargs: Additional keyword arguments (e.g., ssh_public_key, cpu_architecture, platform).
        
    Returns:
        str: Formatted cluster information.
    """
    return await cluster_tools.create_cluster(mcp, get_access_token, name, version, base_domain, *args, **kwargs)


async def set_cluster_vips(
    cluster_id: str,
    api_vip: str,
    ingress_vip: str
) -> str:
    """Set the VIPs (Virtual IPs) for a cluster.
    
    Args:
        cluster_id: The unique identifier of the cluster.
        api_vip: The IP address for the cluster API endpoint.
        ingress_vip: The IP address for the cluster ingress endpoint.
        
    Returns:
        str: Formatted cluster information.
    """
    return await cluster_tools.set_cluster_vips(mcp, get_access_token, cluster_id, api_vip, ingress_vip)


async def set_cluster_platform(cluster_id: str, platform: str) -> str:
    """Set the platform for a cluster.
    
    Args:
        cluster_id: The unique identifier of the cluster.
        platform: The platform type (e.g., 'baremetal', 'vsphere', 'none').
        
    Returns:
        str: Formatted cluster information.
    """
    return await cluster_tools.set_cluster_platform(mcp, get_access_token, cluster_id, platform)


async def install_cluster(cluster_id: str) -> str:
    """Start the installation process for a cluster.
    
    Args:
        cluster_id: The unique identifier of the cluster.
        
    Returns:
        str: Formatted cluster information.
    """
    return await cluster_tools.install_cluster(mcp, get_access_token, cluster_id)


async def set_cluster_ssh_key(cluster_id: str, ssh_public_key: str) -> str:
    """Set the SSH public key for a cluster.
    
    Args:
        cluster_id: The unique identifier of the cluster.
        ssh_public_key: The SSH public key to add.
        
    Returns:
        str: Formatted cluster information or error message.
    """
    return await cluster_tools.set_cluster_ssh_key(mcp, get_access_token, cluster_id, ssh_public_key)


async def cluster_events(cluster_id: str) -> str:
    """Get events for a cluster.
    
    Args:
        cluster_id: The unique identifier of the cluster.
        
    Returns:
        str: JSON string containing cluster events.
    """
    return await event_tools.cluster_events(mcp, get_access_token, cluster_id)


async def host_events(host_id: str, cluster_id: str) -> str:
    """Get events for a specific host.
    
    Args:
        host_id: The unique identifier of the host.
        cluster_id: The unique identifier of the cluster containing the host.
        
    Returns:
        str: JSON string containing host events.
    """
    return await event_tools.host_events(mcp, get_access_token, host_id, cluster_id)


async def cluster_iso_download_url(cluster_id: str) -> str:
    """Get ISO download URL for a cluster.
    
    Args:
        cluster_id: The unique identifier of the cluster.
        
    Returns:
        str: JSON string containing URL and optional expiration.
    """
    return await download_tools.cluster_iso_download_url(mcp, get_access_token, cluster_id)


async def cluster_credentials_download_url(cluster_id: str, file_name: str) -> str:
    """Get credentials download URL for a cluster.
    
    Args:
        cluster_id: The unique identifier of the cluster.
        file_name: The name of the credentials file to download.
        
    Returns:
        str: JSON string containing URL and optional expiration.
    """
    return await download_tools.cluster_credentials_download_url(mcp, get_access_token, cluster_id, file_name)


async def list_versions() -> str:
    """List all available OpenShift versions.
    
    Returns:
        str: JSON string containing available versions.
    """
    return await version_tools.list_versions(mcp, get_access_token)


async def list_operator_bundles() -> str:
    """List all available operator bundles.
    
    Returns:
        str: JSON string containing available operator bundles.
    """
    return await version_tools.list_operator_bundles(mcp, get_access_token)


async def add_operator_bundle_to_cluster(cluster_id: str, bundle_name: str) -> str:
    """Add an operator bundle to a cluster.
    
    Args:
        cluster_id: The unique identifier of the cluster.
        bundle_name: The name of the operator bundle to add.
        
    Returns:
        str: Formatted cluster information.
    """
    return await version_tools.add_operator_bundle_to_cluster(mcp, get_access_token, cluster_id, bundle_name)


async def set_host_role(host_id: str, cluster_id: str, role: str) -> str:
    """Set the role for a host.
    
    Args:
        host_id: The unique identifier of the host.
        cluster_id: The unique identifier of the cluster.
        role: The role to assign (e.g., 'master', 'worker', 'auto-assign').
        
    Returns:
        str: A JSON containing the presigned URL and optional
            expiration time. The response format is:
            {
                url: <presigned-download-url>
                expires_at: <expiration-timestamp> (if available)
            }
    """
    log.info(
        "Getting presigned URL for cluster %s credentials file %s",
        cluster_id,
        file_name,
    )
    client = InventoryClient(get_access_token())
    result = await client.get_presigned_for_cluster_credentials(cluster_id, file_name)
    log.info(
        "Successfully retrieved presigned URL for cluster %s credentials file %s - %s",
        cluster_id,
        file_name,
        result,
    )

    return json.dumps(format_presigned_url(result))


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


@mcp.tool()
@track_tool_usage()
async def set_host_role(
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
    """
    Assign a specific role to a discovered host in the cluster.

    Sets the role for a host that has been discovered through the cluster's hosts boot process.
    The role determines the host's function in the OpenShift cluster.

    Args:
        host_id (str): The unique identifier of the host to configure.
        cluster_id (str): The unique identifier of the cluster containing the host.
        role (str): The role to assign to the host. Valid options are:
            - 'auto-assign': Let the installer automatically determine the role
            - 'master': Control plane node (API server, etcd, scheduler)
            - 'worker': Compute node for running application workloads

    Returns:
        str: A formatted string containing the updated host configuration
            showing the newly assigned role.
    """
    log.info("Setting role '%s' for host %s in cluster %s", role, host_id, cluster_id)
    client = InventoryClient(get_access_token())

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


@mcp.tool()
@track_tool_usage()
async def set_cluster_ssh_key(
    cluster_id: Annotated[
        str, Field(description="The unique identifier of the cluster to update.")
    ],
    ssh_public_key: Annotated[
        str,
        Field(
            description="The SSH public key to set for the cluster. This should be a valid SSH public key in OpenSSH format."
        ),
    ],
) -> str:
    """
    Set or update the SSH public key for a cluster.

    This allows SSH access to cluster nodes during and after installation.
    Only ISO images downloaded after the update will include the updated key.
    Discovered hosts should be booted with a new ISO in order to get the new key.

    Args:
        cluster_id (str): The unique identifier of the cluster to update.
        ssh_public_key (str): The SSH public key to set for the cluster.
            This should be a valid SSH public key in OpenSSH format
            (e.g., 'ssh-rsa AAAAB3NzaC1yc2E... user@host').

    Returns:
        str: A formatted string containing the updated cluster configuration.
    """
    log.info("Setting SSH public key for cluster %s", cluster_id)
    client = InventoryClient(get_access_token())

    # Update the cluster with the new SSH public key
    result = await client.update_cluster(cluster_id, ssh_public_key=ssh_public_key)
    log.info("Successfully updated cluster %s with new SSH key", cluster_id)

    # Get the InfraEnv ID and update it
    try:
        infra_env_id = await _get_cluster_infra_env_id(client, cluster_id)
    except ValueError as e:
        log.error("Failed to get InfraEnv ID: %s", str(e))
        return f"Cluster key updated, but failed to get InfraEnv ID: {str(e)}. New cluster: {result.to_str()}"

    try:
        await client.update_infra_env(infra_env_id, ssh_authorized_key=ssh_public_key)
        log.info("Successfully updated InfraEnv %s with new SSH key", infra_env_id)
    except Exception as e:
        log.error("Failed to update InfraEnv %s: %s", infra_env_id, str(e))
        return f"Cluster key updated, but boot image key update failed. New cluster: {result.to_str()}"

    log.info(
        "Successfully updated SSH key for cluster %s and its InfraEnvs", cluster_id
    )
    return result.to_str()


@track_tool_usage()
async def analyze_cluster_logs(
    cluster_id: Annotated[str, Field(description="The ID of the cluster")],
) -> str:
    """
    Analyze the cluster logs for the given cluster_id and return the results.
    """
    client = InventoryClient(get_access_token())
    results = await analyze_cluster(cluster_id=cluster_id, api_client=client)
    return "\n\n".join([str(r) for r in results])


def list_tools() -> list[str]:
    """List all MCP tools."""

    async def mcp_list_tools() -> list[str]:
        return [t.name for t in await mcp.list_tools()]

    return asyncio.run(mcp_list_tools())


if __name__ == "__main__":
    if transport_type == "streamable-http":
        app = mcp.streamable_http_app()
        log.info("Using StreamableHTTP transport (stateless)")
    else:
        app = mcp.sse_app()
        log.info("Using SSE transport (stateful)")

    if TROUBLESHOOTING_ENABLED:
        mcp.add_tool(analyze_cluster_logs)

    initiate_metrics(list_tools())
    app.add_route("/metrics", metrics)
    uvicorn.run(app, host="0.0.0.0")
