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
    """Get comprehensive information about a specific assisted installer cluster with comprehensive metadata.

    TOOL_NAME=cluster_info
    DISPLAY_NAME=Cluster Information
    USECASE=Retrieve detailed configuration, status, network settings, and installation progress for a specific cluster
    INSTRUCTIONS=1. Obtain cluster_id from list_clusters or previous cluster operations, 2. Call function with cluster_id, 3. Receive detailed cluster information
    INPUT_DESCRIPTION=cluster_id (string): cluster UUID obtained from list_clusters or cluster creation
    OUTPUT_DESCRIPTION=Formatted string with cluster name, ID, OpenShift version, installation status/progress, network configuration (VIPs, subnets), and host information/roles
    EXAMPLES=cluster_info("550e8400-e29b-41d4-a716-446655440000")
    PREREQUISITES=Valid cluster_id, OCM offline token for authentication
    RELATED_TOOLS=list_clusters (get cluster IDs), cluster_events (view cluster history), install_cluster, set_cluster_vips

    I/O-bound operation - uses async def for external API calls.

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
    client = InventoryClient(get_access_token_func())
    result = await client.get_cluster(cluster_id=cluster_id)
    log.info("Successfully retrieved cluster information for %s", cluster_id)
    return result.to_str()


@track_tool_usage()
async def list_clusters(
    mcp, get_access_token_func  # Positional args for consistency
) -> str:
    """List all assisted installer clusters for the current user with comprehensive metadata.

    TOOL_NAME=list_clusters
    DISPLAY_NAME=List Clusters
    USECASE=Retrieve summary of all OpenShift clusters associated with the current user's account
    INSTRUCTIONS=1. Call function without parameters, 2. Receive list of cluster summaries
    INPUT_DESCRIPTION=No parameters required
    OUTPUT_DESCRIPTION=JSON array with cluster objects containing name, id, openshift_version, and status (e.g., 'ready', 'installing', 'error')
    EXAMPLES=list_clusters()
    PREREQUISITES=Valid OCM offline token for authentication
    RELATED_TOOLS=cluster_info (get detailed cluster information), create_cluster (create new cluster), cluster_events (view cluster history)

    I/O-bound operation - uses async def for external API calls.

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
            description="The OpenShift version to install (e.g., '4.18.2', '4.17.1')."
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
            description="Whether to create a single-node cluster.Set to True for edge deployments or resource-constrained environments. Set to False for  production high-availability clusters with multiple control plane nodes."
        ),
    ],
    ssh_public_key: Annotated[
        str | None,
        Field(default=None, description="SSH public key for accessing cluster nodes."),
    ] = None,
    cpu_architecture: Annotated[
        str,
        Field(
            default="x86_64",
            description="The CPU architecture for the cluster. Defaults to 'x86_64' if not specified. Valid options are: x86_64, aarch64, arm64, ppc64le, s390x.",
        ),
    ] = "x86_64",
    platform: Annotated[
        Helpers.VALID_PLATFORMS | None,
        Field(
            default=None,
            description="The platform of the cluster. Defaults to 'baremetal' if not specified and single_node is false, or 'none' if not specified and single_node is true. Valid options: baremetal, vsphere, oci, nutanix, none.",
        ),
    ] = None,
) -> str:
    """Create a new OpenShift cluster with comprehensive configuration options.

    TOOL_NAME=create_cluster
    DISPLAY_NAME=Create OpenShift Cluster
    USECASE=Create new OpenShift cluster for production HA or single-node edge deployments
    INSTRUCTIONS=1. Get version from list_versions, 2. Choose single_node (True/False) and platform, 3. Provide name/domain/architecture, 4. Optionally add SSH key, 5. Receive cluster ID
    INPUT_DESCRIPTION=name (string): cluster name, version (string): OpenShift version from list_versions, base_domain (string): DNS domain (e.g. 'example.com'), single_node (boolean): True for SNO/False for HA, ssh_public_key (string, optional): SSH public key, cpu_architecture (string, optional): x86_64/aarch64/arm64/ppc64le/s390x (default: x86_64), platform (string, optional): baremetal/vsphere/oci/nutanix/none (auto-selected based on single_node if not specified)
    OUTPUT_DESCRIPTION=String containing the created cluster's UUID for use in subsequent operations
    EXAMPLES=create_cluster("my-cluster", "4.18.2", "example.com", False, ssh_public_key="ssh-rsa AAAA...", platform="baremetal"), create_cluster("edge-cluster", "4.17.1", "edge.example.com", True)
    PREREQUISITES=Valid OCM offline token, OpenShift version from list_versions, DNS domain configured
    RELATED_TOOLS=list_versions (get available versions), cluster_info (view created cluster), set_cluster_vips (configure VIPs for HA clusters), install_cluster (start installation)

    I/O-bound operation - uses async def for external API calls.

    Creates a cluster definition and associated infrastructure environment. The cluster can be configured 
    for high availability (multi-node) or single-node deployment (SNO). For single-node clusters, platform 
    must be 'none'. For multi-node clusters, platform defaults to 'baremetal' but can be set to vsphere, 
    oci, or nutanix.

    Args:
        name (str): The name for the new cluster.
        version (str): The OpenShift version to install (e.g., "4.18.2", "4.17.1").
            Use list_versions() to see available versions.
        base_domain (str): The base DNS domain for the cluster (e.g., "example.com").
            The cluster will be accessible at api.{name}.{base_domain}.
        single_node (bool): Whether to create a single-node cluster. Set to True for
            edge deployments or resource-constrained environments. Set to False for
            production high-availability clusters with multiple control plane nodes.
        ssh_public_key (str, optional): SSH public key for accessing cluster nodes.
            Providing this key will allow SSH access to the nodes during and after
            cluster installation.
        cpu_architecture (str, optional): The CPU architecture for the cluster.
            Valid options: x86_64 (default), aarch64, arm64, ppc64le, s390x.
        platform (str, optional): The platform of the cluster.
            For multi-node: baremetal (default), vsphere, oci, nutanix, none.
            For single-node: must be 'none'.
            Auto-selected if not specified.

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

    TOOL_NAME=set_cluster_vips
    DISPLAY_NAME=Configure Cluster VIPs
    USECASE=Configure virtual IPs for high-availability cluster API and ingress endpoints
    INSTRUCTIONS=1. Get cluster_id from create_cluster, 2. Ensure platform is baremetal/vsphere/nutanix, 3. Provide two unused IPs from cluster subnet, 4. Receive updated cluster config
    INPUT_DESCRIPTION=cluster_id (string): cluster UUID, api_vip (string): IP for API endpoint (kubectl/management tools), ingress_vip (string): IP for application ingress traffic
    OUTPUT_DESCRIPTION=Formatted string with updated cluster configuration showing configured VIP addresses
    EXAMPLES=set_cluster_vips("cluster-uuid", "192.168.1.100", "192.168.1.101")
    PREREQUISITES=Multi-node cluster on baremetal/vsphere/nutanix platform, IPs within cluster subnet and not assigned to any host, reachable from all cluster nodes
    RELATED_TOOLS=create_cluster (create cluster first), cluster_info (verify VIP configuration), install_cluster

    I/O-bound operation - uses async def for external API calls.

    VIPs are only required for clusters on baremetal, vsphere, and nutanix platforms.
    Do NOT set VIPs for clusters on 'none' or 'oci' platforms.
    
    The IP addresses must be within the cluster's network subnet, not assigned to any physical host,
    and reachable from all cluster nodes.

    Args:
        cluster_id (str): The unique identifier of the cluster to configure.
        api_vip (str): The IP address for the cluster API endpoint where kubectl connects.
        ingress_vip (str): The IP address for ingress traffic to applications.

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
    """Set or update the platform type for a cluster.

    TOOL_NAME=set_cluster_platform
    DISPLAY_NAME=Set Cluster Platform
    USECASE=Configure or change the infrastructure platform type for cluster deployment
    INSTRUCTIONS=1. Get cluster_id from create_cluster, 2. Choose platform type based on infrastructure, 3. Receive updated cluster config, 4. May need to reconfigure network settings
    INPUT_DESCRIPTION=cluster_id (string): cluster UUID, platform (string): baremetal/vsphere/oci/nutanix/none
    OUTPUT_DESCRIPTION=Formatted string with updated cluster configuration showing new platform setting
    EXAMPLES=set_cluster_platform("cluster-uuid", "vsphere"), set_cluster_platform("cluster-uuid", "none")
    PREREQUISITES=Existing cluster, compatible platform choice for cluster type (single-node clusters require 'none')
    RELATED_TOOLS=create_cluster (creates with default platform), set_cluster_vips (VIP configuration depends on platform), cluster_info

    I/O-bound operation - uses async def for external API calls.

    The platform type determines how the cluster will be deployed and what infrastructure-specific
    features are available. Changing the platform may require reconfiguration of network settings
    and other platform-specific parameters.

    Args:
        cluster_id (str): The unique identifier of the cluster to configure.
        platform (str): baremetal, vsphere, oci, nutanix, or none.

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
    """Trigger the installation process for a prepared cluster.

    TOOL_NAME=install_cluster
    DISPLAY_NAME=Install Cluster
    USECASE=Start OpenShift installation on validated and prepared cluster
    INSTRUCTIONS=1. Ensure all hosts discovered and validated, 2. Verify network config complete (VIPs if needed), 3. Check validations pass, 4. Call with cluster_id, 5. Monitor via cluster_info/cluster_events
    INPUT_DESCRIPTION=cluster_id (string): cluster UUID ready for installation
    OUTPUT_DESCRIPTION=Formatted string with cluster status after installation triggered, includes progress information
    EXAMPLES=install_cluster("cluster-uuid")
    PREREQUISITES=All required hosts discovered and ready, network configuration complete (VIPs set if required), all cluster validations passing
    RELATED_TOOLS=create_cluster (create first), cluster_info (check readiness and monitor progress), cluster_events (monitor installation), set_cluster_vips (configure network)

    I/O-bound operation - uses async def for external API calls.

    Initiates the OpenShift installation on all discovered and validated hosts. The cluster must
    have all prerequisites met before installation can begin. Returns immediately - use cluster_info
    and cluster_events to monitor progress.

    Args:
        cluster_id (str): The unique identifier of the cluster to install.

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
    """Set or update the SSH public key for a cluster and its boot images.

    TOOL_NAME=set_cluster_ssh_key
    DISPLAY_NAME=Set Cluster SSH Key
    USECASE=Configure SSH access to cluster nodes during and after installation
    INSTRUCTIONS=1. Get cluster_id from create_cluster, 2. Provide SSH public key in OpenSSH format, 3. Download new ISO after update, 4. Boot/reboot hosts with new ISO to apply key
    INPUT_DESCRIPTION=cluster_id (string): cluster UUID, ssh_public_key (string): SSH public key in OpenSSH format (e.g., 'ssh-rsa AAAAB3...')
    OUTPUT_DESCRIPTION=Formatted string with updated cluster configuration, or partial success message if boot image update fails
    EXAMPLES=set_cluster_ssh_key("cluster-uuid", "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC... user@host")
    PREREQUISITES=Existing cluster, valid SSH public key in OpenSSH format
    RELATED_TOOLS=create_cluster (can set SSH key at creation), cluster_iso_download_url (get new ISO with updated key), cluster_info

    I/O-bound operation - uses async def for external API calls.

    Updates both the cluster configuration and associated infrastructure environment boot images
    with the SSH public key. Only ISO images downloaded after this update will include the new key.
    Discovered hosts must be booted with a new ISO to get the updated key.

    Args:
        cluster_id (str): The unique identifier of the cluster to update.
        ssh_public_key (str): SSH public key in OpenSSH format (e.g., 'ssh-rsa AAAAB3...').

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

