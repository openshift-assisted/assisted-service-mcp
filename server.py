"""
MCP server for Red Hat Assisted Service API.

This module provides Model Context Protocol (MCP) tools for interacting with
Red Hat's Assisted Service API to manage OpenShift cluster installations.
"""

import json
import os
import asyncio
from typing import Optional, Any

import requests
import uvicorn
from assisted_service_client import models
from mcp.server.fastmcp import FastMCP


from service_client import InventoryClient, metrics, track_tool_usage, initiate_metrics
from service_client.logger import log


transport_type = os.environ.get("TRANSPORT", "sse").lower()
use_stateless_http = transport_type == "streamable-http"

mcp = FastMCP("AssistedService", host="0.0.0.0", stateless_http=use_stateless_http)


def format_presigned_url(presigned_url: models.PresignedUrl) -> dict[str, Any]:
    r"""
    Format a presigned URL object into a readable string.

    Args:
        presigned_url: A PresignedUrl object with url and optional expires_at attributes.

    Returns:
        dict: A dict containing URL and optional expiration time.
            Format:
                {
                    url: <url>
                    expires_at: <expiration> (if expiration exists)
                }
    """
    presigned_url_dict = {
        "url": presigned_url.url,
    }

    # Only include expiration time if it's a meaningful date (not a zero/default value)
    if presigned_url.expires_at and not str(presigned_url.expires_at).startswith(
        "0001-01-01"
    ):
        presigned_url_dict["expires_at"] = presigned_url.expires_at.isoformat().replace(
            "+00:00", "Z"
        )

    return presigned_url_dict


def get_offline_token() -> str:
    """
    Retrieve the offline token from environment variables or request headers.

    This function attempts to get the Red Hat OpenShift Cluster Manager (OCM) offline token
    first from the OFFLINE_TOKEN environment variable, then from the OCM-Offline-Token
    request header. The token is required for authenticating with the Red Hat assisted
    installer service.

    Returns:
        str: The offline token string used for authentication.

    Raises:
        RuntimeError: If no offline token is found in either environment variables
            or request headers.
    """
    log.debug("Attempting to retrieve offline token")
    token = os.environ.get("OFFLINE_TOKEN")
    if token:
        log.debug("Found offline token in environment variables")
        return token

    request = mcp.get_context().request_context.request
    if request is not None:
        token = request.headers.get("OCM-Offline-Token")
        if token:
            log.debug("Found offline token in request headers")
            return token

    log.error("No offline token found in environment or request headers")
    raise RuntimeError("No offline token found in environment or request headers")


def get_access_token() -> str:
    """
    Retrieve the access token.

    This function tries to get the Red Hat OpenShift Cluster Manager (OCM) access token. First
    it tries to extract it from the authorization header, and if it isn't there then it tries
    to generate a new one using the offline token.

    Returns:
        str: The access token.

    Raises:
        RuntimeError: If it isn't possible to obtain or generate the access token.
    """
    log.debug("Attempting to retrieve access token")
    # First try to get the token from the authorization header:
    request = mcp.get_context().request_context.request
    if request is not None:
        header = request.headers.get("Authorization")
        if header is not None:
            parts = header.split()
            if len(parts) == 2 and parts[0].lower() == "bearer":
                log.debug("Found access token in authorization header")
                return parts[1]

    # Now try to get the offline token, and generate a new access token from it:
    log.debug("Generating new access token from offline token")
    params = {
        "client_id": "cloud-services",
        "grant_type": "refresh_token",
        "refresh_token": get_offline_token(),
    }
    sso_url = os.environ.get(
        "SSO_URL",
        "https://sso.redhat.com/auth/realms/redhat-external/protocol/openid-connect/token",
    )
    response = requests.post(sso_url, data=params, timeout=30)
    response.raise_for_status()
    log.debug("Successfully generated new access token")
    return response.json()["access_token"]


@mcp.tool()
@track_tool_usage()
async def cluster_info(cluster_id: str) -> str:
    """
    Get comprehensive information about a specific assisted installer cluster.

    Retrieves detailed cluster information including configuration, status, hosts,
    network settings, and installation progress for the specified cluster ID.

    Args:
        cluster_id (str): The unique identifier of the cluster to retrieve information for.
            This is typically a UUID string.

    Returns:
        str: A formatted string containing detailed cluster information including:
            - Cluster name, ID, and OpenShift version
            - Installation status and progress
            - Network configuration (VIPs, subnets)
            - Host information and roles
    """
    log.info("Retrieving cluster information for cluster_id: %s", cluster_id)
    client = InventoryClient(get_access_token())
    result = await client.get_cluster(cluster_id=cluster_id)
    log.info("Successfully retrieved cluster information for %s", cluster_id)
    return result.to_str()


@mcp.tool()
@track_tool_usage()
async def list_clusters() -> str:
    """
    List all assisted installer clusters for the current user.

    Retrieves a summary of all clusters associated with the current user's account.
    This provides basic information about each cluster without detailed configuration.
    Use cluster_info() to get comprehensive details about a specific cluster.

    Returns:
        str: A JSON-formatted string containing an array of cluster objects.
            Each cluster object includes:
            - name (str): The cluster name
            - id (str): The unique cluster identifier
            - openshift_version (str): The OpenShift version being installed
            - status (str): Current cluster status (e.g., 'ready', 'installing', 'error')
    """
    log.info("Retrieving list of all clusters")
    client = InventoryClient(get_access_token())
    clusters = await client.list_clusters()
    resp = [
        {
            "name": cluster["name"],
            "id": cluster["id"],
            "openshift_version": cluster["openshift_version"],
            "status": cluster["status"],
        }
        for cluster in clusters
    ]
    log.info("Successfully retrieved %s clusters", len(resp))
    return json.dumps(resp)


@mcp.tool()
@track_tool_usage()
async def cluster_events(cluster_id: str) -> str:
    """
    Get the events related to a cluster with the given cluster id.

    Retrieves chronological events related to cluster installation, configuration
    changes, and status updates. These events help track installation progress
    and diagnose issues.

    Args:
        cluster_id (str): The unique identifier of the cluster to get events for.

    Returns:
        str: A JSON-formatted string containing cluster events with timestamps,
            event types, and descriptive messages about cluster activities.
    """
    log.info("Retrieving events for cluster_id: %s", cluster_id)
    client = InventoryClient(get_access_token())
    result = await client.get_events(cluster_id=cluster_id)
    log.info("Successfully retrieved events for cluster %s", cluster_id)
    return result


@mcp.tool()
@track_tool_usage()
async def host_events(cluster_id: str, host_id: str) -> str:
    """
    Get events specific to a particular host within a cluster.

    Retrieves events related to a specific host's installation progress, hardware
    validation, role assignment, and any host-specific issues or status changes.

    Args:
        cluster_id (str): The unique identifier of the cluster containing the host.
        host_id (str): The unique identifier of the specific host to get events for.

    Returns:
        str: A JSON-formatted string containing host-specific events including
            hardware validation results, installation steps, and error messages.
    """
    log.info("Retrieving events for host %s in cluster %s", host_id, cluster_id)
    client = InventoryClient(get_access_token())
    result = await client.get_events(cluster_id=cluster_id, host_id=host_id)
    log.info(
        "Successfully retrieved events for host %s in cluster %s", host_id, cluster_id
    )
    return result


@mcp.tool()
@track_tool_usage()
async def cluster_iso_download_url(cluster_id: str) -> str:
    """
    Get ISO download URL(s) for a cluster.

    Args:
        cluster_id (str): The unique identifier of the cluster.

    Returns:
        dict: A JSON containing ISO download URLs and optional
            expiration times. Each ISO's information is formatted as:
            [{
                url: <download-url>
                expires_at: <expiration-timestamp> (if available)
            }]
    """
    log.info("Retrieving InfraEnv ISO URLs for cluster_id: %s", cluster_id)
    client = InventoryClient(get_access_token())
    infra_envs = await client.list_infra_envs(cluster_id)

    if not infra_envs:
        log.info("No infrastructure environments found for cluster %s", cluster_id)
        return "No ISO download URLs found for this cluster."

    log.info(
        "Found %d infrastructure environments for cluster %s",
        len(infra_envs),
        cluster_id,
    )

    # Get presigned URLs for each infra env
    iso_info = []
    for infra_env in infra_envs:
        infra_env_id = infra_env.get("id", "unknown")

        # Use the new get_infra_env_download_url method
        presigned_url = await client.get_infra_env_download_url(infra_env_id)

        if presigned_url.url:
            iso_info.append(format_presigned_url(presigned_url))
        else:
            log.warning(
                "No ISO download URL found for infra env %s",
                infra_env_id,
            )

    if not iso_info:
        log.info(
            "No ISO download URLs found in infrastructure environments for cluster %s",
            cluster_id,
        )
        return "No ISO download URLs found for this cluster."

    log.info("Returning %d ISO URLs for cluster %s", len(iso_info), cluster_id)
    return json.dumps(iso_info)


@mcp.tool()
@track_tool_usage()
async def create_cluster(  # pylint: disable=too-many-arguments,too-many-positional-arguments
    name: str,
    version: str,
    base_domain: str,
    single_node: bool,
    ssh_public_key: Optional[str] = None,
    cpu_architecture: Optional[str] = "x86_64",
) -> str:
    """
    Create a new OpenShift cluster.

    Creates a cluster definition. The cluster can be configured for high availability
    (multi-node) or single-node deployment.

    Args:
        name (str): The name for the new cluster. The cluster name must meet the
            following requirements, refuse to accept cluster names that fail any of these:
              - Be between 1 and 54 characters
              - Use only lowercase alphanumeric characters or the hyphen (-)
              - Start and end with a lowercase letter or number
            Strictly adhere to these rules, check every cluster name carefully.
        version (str): The OpenShift version to install (e.g., "4.18.2", "4.17.1").
            Use list_versions() to see available versions.
        base_domain (str): The base DNS domain for the cluster (e.g., "example.com").
            The cluster will be accessible at api.{name}.{base_domain}.
        single_node (bool): Whether to create a single-node cluster. Set to True for
            edge deployments or resource-constrained environments. Set to False for
            production high-availability clusters with multiple control plane nodes.
        ssh_public_key (str, optional): SSH public key for accessing cluster nodes.
            Providing this key will allow ssh acces to the nodes during and after
            cluster installation.
        cpu_architecture (str, optional): The CPU architecture for the cluster.
            Valid options are:
              - 'x86_64': Intel/AMD 64-bit processors (default)
              - 'aarch64': ARM 64-bit processors
              - 'arm64': ARM 64-bit processors (alias for aarch64)
              - 'ppc64le': IBM POWER little-endian 64-bit processors
              - 's390x': IBM System z mainframe processors
            Defaults to 'x86_64' if not specified.

    Returns:
        str: The created cluster's id
    """
    log.info(
        "Creating cluster: name=%s, version=%s, base_domain=%s, single_node=%s, cpu_architecture=%s, ssh_key_provided=%s",
        name,
        version,
        base_domain,
        single_node,
        cpu_architecture,
        ssh_public_key is not None,
    )
    client = InventoryClient(get_access_token())

    # Prepare cluster parameters
    cluster_params = {
        "base_dns_domain": base_domain,
        "tags": "chatbot",
        "cpu_architecture": cpu_architecture,
    }
    if ssh_public_key:
        cluster_params["ssh_public_key"] = ssh_public_key

    cluster = await client.create_cluster(name, version, single_node, **cluster_params)
    if cluster.id is None:
        log.error("Failed to create cluster %s: cluster ID is unset", name)
        return f"Failed to create cluster {name}: cluster ID is unset"

    log.info("Successfully created cluster %s with ID: %s", name, cluster.id)

    # Prepare infra env parameters
    infraenv_params = {
        "cluster_id": cluster.id,
        "openshift_version": cluster.openshift_version,
        "cpu_architecture": cpu_architecture,
    }
    if ssh_public_key:
        infraenv_params["ssh_authorized_key"] = ssh_public_key

    infraenv = await client.create_infra_env(name, **infraenv_params)
    log.info(
        "Successfully created InfraEnv for cluster %s with ID: %s",
        cluster.id,
        infraenv.id,
    )
    return cluster.id


@mcp.tool()
@track_tool_usage()
async def set_cluster_vips(cluster_id: str, api_vip: str, ingress_vip: str) -> str:
    """
    Configure the virtual IP addresses (VIPs) for cluster API and ingress traffic.

    Sets the API VIP (for cluster management) and Ingress VIP (for application traffic)
    for the specified cluster. These VIPs must be available IP addresses within the
    cluster's network subnet.

    Args:
        cluster_id (str): The unique identifier of the cluster to configure.
        api_vip (str): The IP address for the cluster API endpoint. This is where
            kubectl and other management tools will connect.
        ingress_vip (str): The IP address for ingress traffic to applications
            running in the cluster.

    Returns:
        str: A formatted string containing the updated cluster configuration
            showing the newly set VIP addresses.
    """
    log.info(
        "Setting VIPs for cluster %s: api_vip=%s, ingress_vip=%s",
        cluster_id,
        api_vip,
        ingress_vip,
    )
    client = InventoryClient(get_access_token())
    result = await client.update_cluster(
        cluster_id, api_vip=api_vip, ingress_vip=ingress_vip
    )
    log.info("Successfully set VIPs for cluster %s", cluster_id)
    return result.to_str()


@mcp.tool()
@track_tool_usage()
async def install_cluster(cluster_id: str) -> str:
    """
    Trigger the installation process for a prepared cluster.

    Initiates the OpenShift installation on all discovered and validated hosts.
    The cluster must have all prerequisites met including sufficient hosts,
    network configuration, and any required validations.

    Args:
        cluster_id (str): The unique identifier of the cluster to install.

    Returns:
        str: A formatted string containing the cluster status after installation
            has been triggered, including installation progress information.

    Note:
        Before calling this function, ensure:
        - All required hosts are discovered and ready
        - Network configuration is complete (VIPs set if required)
        - All cluster validations pass
    """
    log.info("Initiating installation for cluster_id: %s", cluster_id)
    client = InventoryClient(get_access_token())
    result = await client.install_cluster(cluster_id)
    log.info("Successfully triggered installation for cluster %s", cluster_id)
    return result.to_str()


@mcp.tool()
@track_tool_usage()
async def list_versions() -> str:
    """
    List all available OpenShift versions for installation.

    Retrieves the complete list of OpenShift versions that can be installed
    using the assisted installer service, including release versions and
    pre-release candidates.

    Returns:
        str: A JSON string containing available OpenShift versions with metadata
            including version numbers, release dates, and support status.
    """
    log.info("Retrieving available OpenShift versions")
    client = InventoryClient(get_access_token())
    result = await client.get_openshift_versions(True)
    log.info("Successfully retrieved OpenShift versions")
    return json.dumps(result)


@mcp.tool()
@track_tool_usage()
async def list_operator_bundles() -> str:
    """
    List available operator bundles for cluster installation.

    Retrieves operator bundles that can be optionally installed during cluster
    deployment. These include Red Hat and certified partner operators for
    various functionalities like storage, networking, and monitoring.

    Returns:
        str: A JSON string containing available operator bundles with metadata
            including bundle names, descriptions, and operator details.
    """
    log.info("Retrieving available operator bundles")
    client = InventoryClient(get_access_token())
    result = await client.get_operator_bundles()
    log.info("Successfully retrieved %s operator bundles", len(result))
    return json.dumps(result)


@mcp.tool()
@track_tool_usage()
async def add_operator_bundle_to_cluster(cluster_id: str, bundle_name: str) -> str:
    """
    Add an operator bundle to be installed with the cluster.

    Configures the specified operator bundle to be automatically installed
    during cluster deployment. The bundle must be from the list of available
    bundles returned by list_operator_bundles().

    Args:
        cluster_id (str): The unique identifier of the cluster to configure.
        bundle_name (str): The name of the operator bundle to add. Use
            list_operator_bundles() to see available bundle names.

    Returns:
        str: A formatted string containing the updated cluster configuration
            showing the newly added operator bundle.
    """
    log.info("Adding operator bundle '%s' to cluster %s", bundle_name, cluster_id)
    client = InventoryClient(get_access_token())
    result = await client.add_operator_bundle_to_cluster(cluster_id, bundle_name)
    log.info(
        "Successfully added operator bundle '%s' to cluster %s", bundle_name, cluster_id
    )
    return result.to_str()


@mcp.tool()
@track_tool_usage()
async def cluster_credentials_download_url(cluster_id: str, file_name: str) -> str:
    """
    Get presigned download URL for cluster credential files.

    Retrieves a presigned URL for downloading cluster credential files such as
    kubeconfig, kubeadmin password, or kubeconfig without ingress configuration.
    For a successfully installed cluster the kubeconfig file should always be used
    over the kubeconfig-noingress file.
    The URL is time-limited and provides secure access to sensitive cluster files.
    Whenever a URL is returned provide the user with information on the expiration
    of that URL if possible.

    Args:
        cluster_id (str): The unique identifier of the cluster to get credentials for.
        file_name (str): The type of credential file to download. Valid options are:
            - "kubeconfig": Standard kubeconfig file for cluster access
            - "kubeconfig-noingress": Kubeconfig without ingress configuration
            - "kubeadmin-password": The kubeadmin user password file

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


@mcp.tool()
@track_tool_usage()
async def set_host_role(host_id: str, infraenv_id: str, role: str) -> str:
    """
    Assign a specific role to a discovered host in the cluster.

    Sets the role for a host that has been discovered through the InfraEnv boot process.
    The role determines the host's function in the OpenShift cluster.

    Args:
        host_id (str): The unique identifier of the host to configure.
        infraenv_id (str): The unique identifier of the InfraEnv containing the host.
        role (str): The role to assign to the host. Valid options are:
            - 'auto-assign': Let the installer automatically determine the role
            - 'master': Control plane node (API server, etcd, scheduler)
            - 'worker': Compute node for running application workloads

    Returns:
        str: A formatted string containing the updated host configuration
            showing the newly assigned role.
    """
    log.info("Setting role '%s' for host %s in InfraEnv %s", role, host_id, infraenv_id)
    client = InventoryClient(get_access_token())
    result = await client.update_host(host_id, infraenv_id, host_role=role)
    log.info("Successfully set role '%s' for host %s", role, host_id)
    return result.to_str()


@mcp.tool()
@track_tool_usage()
async def set_cluster_ssh_key(cluster_id: str, ssh_public_key: str) -> str:
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

    # Get existing InfraEnvs and update them
    infra_envs = await client.list_infra_envs(cluster_id)
    log.info("Found %d InfraEnvs for cluster %s", len(infra_envs), cluster_id)

    update_failed = False
    for infra_env in infra_envs:
        infra_env_id = infra_env.get("id")
        if not infra_env_id:
            log.warning("Skipping InfraEnv without ID: %s", infra_env)
            continue

        try:
            await client.update_infra_env(
                infra_env_id, ssh_authorized_key=ssh_public_key
            )
            log.info("Successfully updated InfraEnv %s with new SSH key", infra_env_id)
        except Exception as e:
            update_failed = True
            log.error("Failed to update InfraEnv %s: %s", infra_env_id, str(e))

    if update_failed:
        return f"Cluster key updated, but boot image key update failed. New cluster: {result.to_str()}"

    log.info(
        "Successfully updated SSH key for cluster %s and its InfraEnvs", cluster_id
    )
    return result.to_str()


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

    initiate_metrics(list_tools())
    app.add_route("/metrics", metrics)
    uvicorn.run(app, host="0.0.0.0")
