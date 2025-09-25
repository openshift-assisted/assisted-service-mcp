# pylint: disable=too-many-lines
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
async def cluster_info(
    cluster_id: Annotated[
        str,
        Field(
            description="The unique identifier of the cluster to retrieve information for. This is typically a UUID string."
        ),
    ],
) -> str:
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
async def cluster_events(
    cluster_id: Annotated[
        str,
        Field(description="The unique identifier of the cluster to get events for."),
    ],
) -> str:
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
async def host_events(
    cluster_id: Annotated[
        str,
        Field(description="The unique identifier of the cluster containing the host."),
    ],
    host_id: Annotated[
        str,
        Field(
            description="The unique identifier of the specific host to get events for."
        ),
    ],
) -> str:
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
async def cluster_iso_download_url(
    cluster_id: Annotated[
        str,
        Field(
            description="The unique identifier of the cluster, whose ISO image URL has to be retrieved."
        ),
    ],
) -> str:
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
    """
    Create a new OpenShift cluster.

    Creates a cluster definition. The cluster can be configured for high availability
    (multi-node) or single-node deployment.

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
        platform (str, optional): The platform of the cluster.
            Valid options for multi-node clusters are:
              - 'baremetal': Bare metal platform
              - 'vsphere': VMware vSphere platform
              - 'oci': Oracle Cloud Infrastructure platform
              - 'nutanix': Nutanix platform
              - 'none': No platform
            Valid options for single-node clusters are:
              - 'none': No platform
            Defaults to 'baremetal' if not specified and single_node is false or none if not specified and single_node is true.
    Returns:
        str: The created cluster's id
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

    client = InventoryClient(get_access_token())

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


@mcp.tool()
@track_tool_usage()
async def validate_nmstate_yaml(nmstate_yaml: str) -> str:
    """
    Validate an nmstate yaml document.

    The yaml should always be validated before submitted to the cluster.
    """
    validate_and_parse_nmstate(nmstate_yaml)
    return "YAML is valid"


@mcp.tool(
    description=f"""
    Generate an initial nmstate yaml.

    You should call this after gathering information from the user to generate the initial nmstate
    yaml. Then you can tweak it as needed. Do not generate nmstate yaml from scratch without calling
    this tool.

    Returns: the generated nmstate yaml

    Input param schema:
    {NMStateTemplateParams.model_json_schema()}
"""
)
@track_tool_usage()
async def generate_nmstate_yaml(params: NMStateTemplateParams) -> str:
    """
    Generate an initial nmstate yaml.

    See the mcp.tool description for more details (we have to use it since we dynamically generate
    the input schema for the params).
    """
    log.info("Generate nmstate yaml with params: %s", params.model_dump_json(indent=2))
    try:
        generated = generate_nmstate_from_template(params)
        log.debug("Generated yaml: %s", generated)
        return generated
    except TemplateError as e:
        log.error("Failed to render nmstate template", exc_info=e)
        return "ERROR: Failed to generate nmstate yaml"
    except Exception as e:
        log.error("Exception generating nmstate yaml", exc_info=e)
        return "ERROR: Unknown error"


@mcp.tool()
@track_tool_usage()
async def alter_static_network_config_nmstate_for_host(
    cluster_id: str, index: int | None, new_nmstate_yaml: str | None
) -> str:
    """
    Add, replace, or delete the nmstate yaml for a single host.

    To add a new host, set index to None and the given config will be appended to the end of the
    static network configs for the given cluster.

    To remove a host's config at a particular index, set new_nmstate_yaml to None.

    Args:
        cluster_id (str): The unique identifier of the cluster
        index (int | None): The index of the host in the existing static config to replace, or None to append a new host to the end of the config.
        new_nmstate_yaml (str): The new nmstate YAML for a host. Leave this None to delete the config at the given index.

    Returns: the updated infra env with the new static network config
    """
    client = InventoryClient(get_access_token())
    infra_env_id = await _get_cluster_infra_env_id(client, cluster_id)
    infra_env = await client.get_infra_env(infra_env_id)

    if new_nmstate_yaml is None:
        if index is None:
            raise ValueError("index cannot be null when removing a host yaml")
        if not infra_env.static_network_config:
            raise ValueError(
                "cannot remove host yaml with empty existing static network config"
            )
        static_network_config = remove_static_host_config_by_index(
            existing_static_network_config=infra_env.static_network_config, index=index
        )
    else:
        static_network_config = add_or_replace_static_host_config_yaml(
            existing_static_network_config=infra_env.static_network_config,
            index=index,
            new_nmstate_yaml=new_nmstate_yaml,
        )

    result = await client.update_infra_env(
        infra_env_id, static_network_config=static_network_config
    )
    return result.to_str()


@mcp.tool()
@track_tool_usage()
async def list_static_network_config(cluster_id: str) -> str:
    """
    List all of the host static network config associated with the given cluster_id.

    Args:
        cluster_id (str): The unique identifier of the cluster to configure.

    Returns:
        str: A JSON-formatted list of static network config or an error string
    """
    client = InventoryClient(get_access_token())
    infra_envs = await client.list_infra_envs(cluster_id)
    log.info("Found %d InfraEnvs for cluster %s", len(infra_envs), cluster_id)

    if len(infra_envs) != 1:
        log.warning(
            "cluster %s has %d infra_envs, expected 1", cluster_id, len(infra_envs)
        )
        return "ERROR: this cluster doesn't have exactly 1 infra env, cannot manage static network config"

    return json.dumps(infra_envs[0].get("static_network_config", []))


@mcp.tool()
@track_tool_usage()
async def set_cluster_vips(
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
    """
    Configure the virtual IP addresses (VIPs) for cluster API and ingress traffic.

    VIPs are only required for clusters in the following platforms: baremetal, vsphere, nutanix.
    Do not set VIPs for clusters in the following platforms: none, oci.

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
async def set_cluster_platform(
    cluster_id: Annotated[
        str, Field(description="The unique identifier of the cluster to configure.")
    ],
    platform: Annotated[
        Helpers.VALID_PLATFORMS,
        Field(
            description="The platform for the cluster. Valid options are: baremetal, vsphere, oci, nutanix, or none."
        ),
    ],
) -> str:
    """
    Set the platform for a cluster.

    Args:
        cluster_id (str): The unique identifier of the cluster to configure.
        platform (str): The platform for the cluster.
            Valid options are:
              - 'baremetal': Bare metal platform
              - 'vsphere': VMware vSphere platform
              - 'oci': Oracle Cloud Infrastructure platform
              - 'nutanix': Nutanix platform
              - 'none': No platform

    Returns:
        str: A formatted string containing the updated cluster configuration
            showing the newly set platform.
    """
    log.info(
        "Setting platform for cluster %s: platform=%s",
        cluster_id,
        platform,
    )
    client = InventoryClient(get_access_token())
    result = await client.update_cluster(cluster_id, platform=platform)
    log.info("Successfully set platform for cluster %s", cluster_id)
    return result.to_str()


@mcp.tool()
@track_tool_usage()
async def install_cluster(
    cluster_id: Annotated[
        str, Field(description="The unique identifier of the cluster to install.")
    ],
) -> str:
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

    Retrieves details about operator bundles that can be optionally installed
    during cluster deployment.

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
async def add_operator_bundle_to_cluster(
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
    """
    Add an operator bundle to be installed with the cluster.

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
    client = InventoryClient(get_access_token())
    result = await client.add_operator_bundle_to_cluster(cluster_id, bundle_name)
    log.info(
        "Successfully added operator bundle '%s' to cluster %s", bundle_name, cluster_id
    )
    return result.to_str()


@mcp.tool()
@track_tool_usage()
async def cluster_credentials_download_url(
    cluster_id: Annotated[
        str,
        Field(
            description="The unique identifier of the cluster to get credentials for."
        ),
    ],
    file_name: Annotated[
        str,
        Field(
            description="The type of credential file to download. Valid options are: kubeconfig (Standard kubeconfig file for cluster access), kubeconfig-noingress (Kubeconfig without ingress configuration), kubeadmin-password (The kubeadmin user password file)."
        ),
    ],
) -> str:
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
