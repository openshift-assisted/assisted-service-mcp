"""Cluster management tools for Assisted Service MCP Server."""

import json
from typing import Annotated, Callable
from pydantic import Field

from assisted_service_mcp.src.metrics import track_tool_usage
from assisted_service_mcp.src.service_client.assisted_service_api import InventoryClient
from assisted_service_mcp.src.service_client.helpers import Helpers
from assisted_service_mcp.src.logger import log
from assisted_service_mcp.src.utils.log_analyzer.main import analyze_cluster


@track_tool_usage()
async def cluster_info(
    get_access_token_func: Callable[[], str],
    cluster_id: Annotated[
        str,
        Field(
            description="The unique identifier of the cluster to retrieve information for."
        ),
    ],
) -> str:
    """Get comprehensive information about a specific cluster.

    Retrieves detailed cluster information including configuration, status, network settings,
    installation progress, and host information. Use this to check cluster state, verify
    configuration, or monitor installation progress.

    Prerequisites:
        - Valid cluster UUID (from list_clusters or create_cluster)

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
async def list_clusters(get_access_token_func: Callable[[], str]) -> str:
    """List all clusters for the current user.

    Retrieves a summary of all OpenShift clusters associated with your account. This provides
    basic information about each cluster (name, ID, version, status) without detailed
    configuration. Use cluster_info() to get comprehensive details about a specific cluster.

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
    get_access_token_func: Callable[[], str],
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
        Field(
            default=None,
            description="SSH public key for accessing cluster nodes. Allows SSH access to nodes during and after installation.",
        ),
    ] = None,
    cpu_architecture: Annotated[
        Helpers.VALID_CPU_ARCHITECTURES | None,
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
    start the actual installation. Optional parameters: ssh_public_key, cpu_architecture, platform.

    Examples:
        - create_cluster("prod-cluster", "4.18.2", "example.com", False, ssh_public_key="ssh-rsa AAAA...", platform="baremetal")
        - create_cluster("edge-cluster", "4.17.1", "edge.local", True)  # Single-node, platform='none' auto-selected
        - create_cluster("vsphere-cluster", "4.18.2", "vsphere.com", False, platform="vsphere", cpu_architecture="x86_64")

    Prerequisites:
        - OpenShift version from list_versions

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

    # Set default cpu_architecture if not provided
    if cpu_architecture is None:
        cpu_architecture = "x86_64"

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
    get_access_token_func: Callable[[], str],
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
    platforms. The IP addresses must be within the cluster's machine network subnet, not assigned
    to any physical host, and reachable from all cluster nodes.

    Prerequisites:
        - Multi-node cluster on baremetal, vsphere, or nutanix platform
        - Two unused IP addresses within the cluster subnet

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
    get_access_token_func: Callable[[], str],
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

    Prerequisites:
        - Existing cluster (from create_cluster)
        - Compatible platform choice for cluster type (single-node requires 'none')

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
    get_access_token_func: Callable[[], str],
    cluster_id: Annotated[
        str, Field(description="The unique identifier of the cluster to install.")
    ],
) -> str:
    """Start the OpenShift installation process for a prepared cluster.

    Initiates installation on all discovered and validated hosts. The cluster must have all
    prerequisites met: required number of hosts discovered and ready, network configuration
    complete (VIPs set if required), and all validations passing. This operation returns
    immediately; use cluster_info and cluster_events to monitor installation progress.

    Prerequisites:
        - All required hosts discovered and in 'ready' state
        - Network configuration complete (VIPs set if required by platform)
        - All cluster validations passing (check with cluster_info)
        - For SNO: 1 node with sufficient resources

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
    get_access_token_func: Callable[[], str],
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

    Prerequisites:
        - Existing cluster (from create_cluster)
        - Valid SSH public key in OpenSSH format (starts with ssh-rsa, ssh-ed25519, etc.)

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


@track_tool_usage()
async def analyze_cluster_logs(
    get_access_token_func: Callable[[], str],
    cluster_id: Annotated[str, Field(description="The ID of the cluster")],
) -> str:
    """Analyze Assisted Installer logs for a cluster and summarize findings.

    Runs a set of built‑in log analysis signatures against the cluster’s collected
    logs (controller logs, bootstrap/control‑plane logs, and must‑gather content
    when available). The results highlight common misconfigurations and known
    error patterns to speed up triage of failed or degraded installations.

    Prerequisites:
        - Logs are available for the target cluster (downloadable via the API)

    Returns:
        str: Human‑readable report of signature results. Returns an empty
            string if no issues were found by the analyzer.
    """
    client = InventoryClient(get_access_token_func())
    results = await analyze_cluster(cluster_id=cluster_id, api_client=client)
    return "\n\n".join([str(r) for r in results])
