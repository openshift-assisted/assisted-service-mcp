"""Cluster management tools for Assisted Service MCP Server."""

import json
from typing import Annotated
from pydantic import Field

from metrics import track_tool_usage
from assisted_service_mcp.utils.client_factory import InventoryClient
from service_client.helpers import Helpers
from service_client.logger import log


@track_tool_usage()
async def cluster_info(
    mcp,  # FastMCP instance passed from mcp.py
    get_access_token_func,  # Auth function passed from mcp.py
    cluster_id: Annotated[
        str,
        Field(
            description="The unique identifier of the cluster to retrieve information for. This is typically a UUID string."
        ),
    ],
) -> str:
    """Get comprehensive information about a specific cluster.

    Retrieves detailed cluster information including configuration, status, network settings,
    installation progress, and host information. Use this to check cluster state, verify
    configuration, or monitor installation progress.

    Examples:
        - cluster_info("550e8400-e29b-41d4-a716-446655440000")
        - After creating a cluster, use this to verify the configuration
        - During installation, use this to check current status and progress

    Prerequisites:
        - Valid cluster UUID (from list_clusters or create_cluster)
        - OCM offline token for authentication

    Related tools:
        - list_clusters - Get cluster IDs
        - cluster_events - View cluster installation history
        - install_cluster - Start cluster installation
        - set_cluster_vips - Configure network VIPs

    Returns:
        str: A formatted string containing detailed cluster information including:
            - Cluster name, ID, and OpenShift version
            - Installation status and progress
            - Network configuration (VIPs, subnets)
            - Host information and roles
    """
    log.info("Retrieving cluster information for cluster_id: %s", cluster_id)
    client = InventoryClient(get_access_token_func())
    result = await client.get_cluster(cluster_id=cluster_id)
    log.info("Successfully retrieved cluster information for %s", cluster_id)
    return result.to_str()


@track_tool_usage()
async def list_clusters(
    mcp, get_access_token_func  # Positional args for consistency
) -> str:
    """List all clusters for the current user.

    Retrieves a summary of all OpenShift clusters associated with your account. This provides
    basic information about each cluster (name, ID, version, status) without detailed
    configuration. Use cluster_info() to get comprehensive details about a specific cluster.

    Examples:
        - list_clusters()
        - Use at the start of a session to see all available clusters
        - Check status of multiple clusters at once

    Prerequisites:
        - Valid OCM offline token for authentication

    Related tools:
        - cluster_info - Get detailed information for a specific cluster
        - create_cluster - Create a new cluster
        - cluster_events - View installation history for a cluster

    Returns:
        str: A JSON-formatted string containing an array of cluster objects.
            Each cluster object includes:
            - name (str): The cluster name
            - id (str): The unique cluster identifier
            - openshift_version (str): The OpenShift version being installed
            - status (str): Current cluster status (e.g., 'ready', 'installing', 'error')
    """
    log.info("Retrieving list of all clusters")
    client = InventoryClient(get_access_token_func())
    clusters = await client.list_clusters()
    resp = [
        {
            "name": cluster["name"],
            "id": cluster["id"],
            "openshift_version": cluster.get("openshift_version", "Unknown"),
            "status": cluster["status"],
        }
        for cluster in clusters
    ]
    log.info("Successfully retrieved %s clusters", len(resp))
    return json.dumps(resp)


@track_tool_usage()
async def create_cluster(  # pylint: disable=too-many-arguments,too-many-positional-arguments
    mcp,
    get_access_token_func,
    name: Annotated[str, Field(description="The name of the new cluster.")],
    version: Annotated[
        str,
        Field(
            description="The OpenShift version to install (e.g., '4.18.2', '4.17.1'). Use list_versions to see available versions."
        ),
    ],
    base_domain: Annotated[
        str,
        Field(
            description="The base DNS domain for the cluster (e.g., 'example.com'). The cluster will be accessible at api.<name>.<base_domain>."
        ),
    ],
    single_node: Annotated[
        bool,
        Field(
            description="Whether to create a single-node cluster. Set to True for edge deployments or resource-constrained environments. Set to False for production high-availability clusters with multiple control plane nodes."
        ),
    ],
    ssh_public_key: Annotated[
        str | None,
        Field(default=None, description="SSH public key for accessing cluster nodes. Allows SSH access to nodes during and after installation."),
    ] = None,
    cpu_architecture: Annotated[
        str,
        Field(
            default="x86_64",
            description="CPU architecture for the cluster. Valid options: x86_64 (default), aarch64, arm64, ppc64le, s390x.",
        ),
    ] = "x86_64",
    platform: Annotated[
        Helpers.VALID_PLATFORMS | None,
        Field(
            default=None,
            description="Infrastructure platform. For multi-node: baremetal (default), vsphere, oci, nutanix, none. For single-node: must be 'none'. Auto-selected based on single_node if not specified.",
        ),
    ] = None,
) -> str:
    """Create a new OpenShift cluster.

    Creates a cluster definition and infrastructure environment for either high-availability
    (multi-node) or single-node (SNO) deployment. For single-node clusters, platform must be
    'none'. For multi-node clusters, platform defaults to 'baremetal' but can be vsphere,
    oci, or nutanix. This creates the cluster configuration only; use install_cluster to
    start the actual installation.

    Examples:
        - create_cluster("prod-cluster", "4.18.2", "example.com", False, ssh_public_key="ssh-rsa AAAA...", platform="baremetal")
        - create_cluster("edge-cluster", "4.17.1", "edge.local", True)  # Single-node, platform='none' auto-selected
        - create_cluster("vsphere-cluster", "4.18.2", "vsphere.com", False, platform="vsphere", cpu_architecture="x86_64")

    Prerequisites:
        - Valid OCM offline token for authentication
        - OpenShift version from list_versions
        - Configured DNS domain

    Related tools:
        - list_versions - Get available OpenShift versions
        - cluster_info - View created cluster details
        - set_cluster_vips - Configure VIPs (required for HA baremetal/vsphere/nutanix)
        - install_cluster - Start the installation process

    Returns:
        str: The created cluster's UUID.
    """
    log.info(
        "Creating cluster: name=%s, version=%s, base_domain=%s, single_node=%s, cpu_architecture=%s, ssh_key_provided=%s, platform=%s",
        name,
        version,
        base_domain,
        single_node,
        cpu_architecture,
        ssh_public_key is not None,
        platform,
    )

    if platform:
        # Check for invalid combination: single_node = true and platform is specified and not "none"
        if single_node is True and platform != "none":
            return "Platform must be set to 'none' for single-node clusters"
    else:
        platform = "baremetal"
        if single_node is True:
            platform = "none"

    client = InventoryClient(get_access_token_func())

    # Prepare cluster parameters
    cluster_params = {
        "base_dns_domain": base_domain,
        "tags": "chatbot",
        "cpu_architecture": cpu_architecture,
        "platform": platform,
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


@track_tool_usage()
async def set_cluster_vips(
    mcp,
    get_access_token_func,
    cluster_id: Annotated[
        str, Field(description="The unique identifier of the cluster to configure.")
    ],
    api_vip: Annotated[
        str,
        Field(
            description="The IP address for the cluster API endpoint. This is where kubectl and other management tools will connect."
        ),
    ],
    ingress_vip: Annotated[
        str,
        Field(
            description="The IP address for ingress traffic to applications running in the cluster."
        ),
    ],
) -> str:
    """Configure virtual IP addresses (VIPs) for cluster API and ingress traffic.

    Sets the API and ingress VIPs required for HA clusters on baremetal, vsphere, and nutanix
    platforms. VIPs are NOT needed for single-node clusters or clusters on 'none' or 'oci'
    platforms. The IP addresses must be within the cluster's network subnet, not assigned to
    any physical host, and reachable from all cluster nodes.

    Examples:
        - set_cluster_vips("cluster-uuid", "192.168.1.100", "192.168.1.101")
        - After creating an HA baremetal cluster, set VIPs before installation
        - Use consecutive IPs from your cluster subnet

    Prerequisites:
        - Multi-node cluster on baremetal, vsphere, or nutanix platform
        - Two unused IP addresses within the cluster subnet
        - IPs must be reachable from all cluster nodes

    Related tools:
        - create_cluster - Create the cluster first
        - cluster_info - Verify VIP configuration
        - install_cluster - Install after VIPs are configured

    Returns:
        str: Formatted string with updated cluster configuration including VIP addresses.
    """
    log.info(
        "Setting VIPs for cluster %s: API VIP=%s, Ingress VIP=%s",
        cluster_id,
        api_vip,
        ingress_vip,
    )
    client = InventoryClient(get_access_token_func())
    result = await client.update_cluster(
        cluster_id, api_vip=api_vip, ingress_vip=ingress_vip
    )
    log.info("Successfully set VIPs for cluster %s", cluster_id)
    return result.to_str()


@track_tool_usage()
async def set_cluster_platform(
    mcp,
    get_access_token_func,
    cluster_id: Annotated[
        str, Field(description="The unique identifier of the cluster to configure.")
    ],
    platform: Annotated[
        Helpers.VALID_PLATFORMS,
        Field(
            description="The platform to set for the cluster. Valid options: baremetal, vsphere, oci, nutanix, none."
        ),
    ],
) -> str:
    """Set or update the infrastructure platform type for a cluster.

    Changes the platform type which determines deployment method and available infrastructure
    features. Single-node clusters require platform 'none'. Multi-node clusters can use
    baremetal, vsphere, oci, or nutanix. Changing the platform may require reconfiguration
    of network settings (VIPs) and other platform-specific parameters.

    Examples:
        - set_cluster_platform("cluster-uuid", "vsphere")  # Change to vSphere deployment
        - set_cluster_platform("cluster-uuid", "none")  # Set for single-node or platformless
        - set_cluster_platform("cluster-uuid", "baremetal")  # Standard baremetal deployment

    Prerequisites:
        - Existing cluster (from create_cluster)
        - Compatible platform choice for cluster type (single-node requires 'none')

    Related tools:
        - create_cluster - Creates cluster with default platform
        - set_cluster_vips - Configure VIPs (required for baremetal/vsphere/nutanix)
        - cluster_info - Verify platform configuration

    Returns:
        str: Formatted string with updated cluster configuration and new platform setting.
    """
    log.info("Setting platform '%s' for cluster %s", platform, cluster_id)
    client = InventoryClient(get_access_token_func())
    result = await client.update_cluster(cluster_id, platform=platform)
    log.info("Successfully set platform for cluster %s", cluster_id)
    return result.to_str()


@track_tool_usage()
async def install_cluster(
    mcp,
    get_access_token_func,
    cluster_id: Annotated[
        str, Field(description="The unique identifier of the cluster to install.")
    ],
) -> str:
    """Start the OpenShift installation process for a prepared cluster.

    Initiates installation on all discovered and validated hosts. The cluster must have all
    prerequisites met: required number of hosts discovered and ready, network configuration
    complete (VIPs set if required), and all validations passing. This operation returns
    immediately; use cluster_info and cluster_events to monitor installation progress.

    Examples:
        - install_cluster("cluster-uuid")
        - After all hosts are discovered and validated, trigger installation
        - VIPs must be configured first for HA baremetal/vsphere/nutanix clusters

    Prerequisites:
        - All required hosts discovered and in 'ready' state
        - Network configuration complete (VIPs set if required by platform)
        - All cluster validations passing (check with cluster_info)
        - For HA: minimum 3 master nodes, VIPs configured
        - For SNO: 1 node with sufficient resources

    Related tools:
        - create_cluster - Create cluster first
        - cluster_info - Check readiness and monitor installation progress
        - cluster_events - View detailed installation events and logs
        - set_cluster_vips - Configure VIPs before installation (HA clusters)

    Returns:
        str: Formatted string with cluster status and installation progress information.
    """
    log.info("Initiating installation for cluster_id: %s", cluster_id)
    client = InventoryClient(get_access_token_func())
    result = await client.install_cluster(cluster_id)
    log.info("Successfully triggered installation for cluster %s", cluster_id)
    return result.to_str()


@track_tool_usage()
async def set_cluster_ssh_key(
    mcp,
    get_access_token_func,
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
    """Set or update the SSH public key for a cluster.

    Updates both the cluster configuration and boot images with the SSH public key, enabling
    SSH access to cluster nodes during and after installation. Only ISO images downloaded after
    this update will include the new key. Hosts already booted need to be rebooted with a new
    ISO to get the updated key.

    Examples:
        - set_cluster_ssh_key("cluster-uuid", "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC... user@host")
        - Add SSH key to existing cluster that was created without one
        - Update SSH key if the old key is compromised

    Prerequisites:
        - Existing cluster (from create_cluster)
        - Valid SSH public key in OpenSSH format (starts with ssh-rsa, ssh-ed25519, etc.)

    Related tools:
        - create_cluster - Can set SSH key at creation time
        - cluster_iso_download_url - Download new ISO with updated key
        - cluster_info - Verify SSH key configuration

    Returns:
        str: Formatted string with updated cluster configuration, or error message if boot image update fails.
    """
    log.info("Setting SSH public key for cluster %s", cluster_id)
    client = InventoryClient(get_access_token_func())

    # Import helper function here to avoid circular imports
    from assisted_service_mcp.src.tools.shared_helpers import _get_cluster_infra_env_id

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

