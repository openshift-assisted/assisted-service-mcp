"""
MCP server for Red Hat Assisted Service API.

This module provides Model Context Protocol (MCP) tools for interacting with
Red Hat's Assisted Service API to manage OpenShift cluster installations.
"""

import json
import os

import requests
from mcp.server.fastmcp import FastMCP

from service_client import InventoryClient
from service_client.logger import log

mcp = FastMCP("AssistedService", host="0.0.0.0")


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
async def infraenv_info(infraenv_id: str) -> str:
    """
    Get detailed information about an infrastructure environment (InfraEnv).

    An InfraEnv contains the configuration and resources needed to boot and discover
    hosts for cluster installation, including the discovery ISO image and network
    configuration.

    Args:
        infraenv_id (str): The unique identifier of the infrastructure environment.

    Returns:
        str: A formatted string containing comprehensive InfraEnv information including:
            - ISO download URL for host discovery
            - Network configuration and proxy settings
            - SSH public key for host access
            - Associated cluster information
            - Static network configuration if applicable
    """
    log.info("Retrieving InfraEnv information for infraenv_id: %s", infraenv_id)
    client = InventoryClient(get_access_token())
    result = await client.get_infra_env(infraenv_id)
    log.info("Successfully retrieved InfraEnv information for %s", infraenv_id)
    return result.to_str()


@mcp.tool()
async def create_cluster(
    name: str, version: str, base_domain: str, single_node: bool
) -> str:
    """
    Create a new OpenShift cluster and associated infrastructure environment.

    Creates both a cluster definition and an InfraEnv for host discovery. The cluster
    can be configured for high availability (multi-node) or single-node deployment.

    Args:
        name (str): The name for the new cluster. Must be unique within your account.
        version (str): The OpenShift version to install (e.g., "4.18.2", "4.17.1").
            Use list_versions() to see available versions.
        base_domain (str): The base DNS domain for the cluster (e.g., "example.com").
            The cluster will be accessible at api.{name}.{base_domain}.
        single_node (bool): Whether to create a single-node cluster. Set to True for
            edge deployments or resource-constrained environments. Set to False for
            production high-availability clusters with multiple control plane nodes.

    Returns:
        str: A JSON string containing the created cluster and InfraEnv IDs:
            - cluster_id (str): The unique identifier of the created cluster
            - infraenv_id (str): The unique identifier of the created InfraEnv
    """
    log.info(
        "Creating cluster: name=%s, version=%s, base_domain=%s, single_node=%s",
        name,
        version,
        base_domain,
        single_node,
    )
    client = InventoryClient(get_access_token())
    cluster = await client.create_cluster(
        name, version, single_node, base_dns_domain=base_domain, tags="chatbot"
    )
    log.info("Successfully created cluster %s with ID: %s", name, cluster.id)
    infraenv = await client.create_infra_env(
        name, cluster_id=cluster.id, openshift_version=cluster.openshift_version
    )
    log.info(
        "Successfully created InfraEnv for cluster %s with ID: %s",
        cluster.id,
        infraenv.id,
    )
    return json.dumps({"cluster_id": cluster.id, "infraenv_id": infraenv.id})


@mcp.tool()
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


if __name__ == "__main__":
    mcp.run(transport="sse")
