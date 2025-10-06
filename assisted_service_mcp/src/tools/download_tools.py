"""Download URL tools for Assisted Service MCP Server."""

import json
from typing import Annotated
from pydantic import Field

from metrics import track_tool_usage
from assisted_service_mcp.utils.client_factory import InventoryClient
from service_client.logger import log
from assisted_service_mcp.utils.helpers import format_presigned_url


@track_tool_usage()
async def cluster_iso_download_url(
    mcp,
    get_access_token_func,
    cluster_id: Annotated[
        str,
        Field(
            description="The unique identifier of the cluster, whose ISO image URL has to be retrieved."
        ),
    ],
) -> str:
    """Get ISO download URL(s) for cluster boot images.

    TOOL_NAME=cluster_iso_download_url
    DISPLAY_NAME=Cluster ISO Download URL
    USECASE=Get presigned URLs to download bootable ISO images for cluster host discovery and installation
    INSTRUCTIONS=1. Get cluster_id from create_cluster, 2. Call function to get ISO URLs, 3. Download ISO from returned URL(s), 4. Boot hosts from ISO for discovery
    INPUT_DESCRIPTION=cluster_id (string): cluster UUID
    OUTPUT_DESCRIPTION=JSON array with ISO download information including presigned URLs and optional expiration timestamps for each infrastructure environment
    EXAMPLES=cluster_iso_download_url("cluster-uuid")
    PREREQUISITES=Cluster with created infrastructure environments
    RELATED_TOOLS=create_cluster (creates cluster and infra env), set_cluster_ssh_key (update SSH key, requires new ISO download), cluster_info

    I/O-bound operation - uses async def for external API calls.

    Retrieves presigned download URLs for all infrastructure environment ISOs associated with the cluster.
    These ISOs are used to boot hosts for discovery and installation. URLs are time-limited for security.

    Args:
        cluster_id (str): The unique identifier of the cluster.

    Returns:
        str: JSON array with ISO URLs and optional expiration times, or message if no ISOs found.
    """
    log.info("Retrieving InfraEnv ISO URLs for cluster_id: %s", cluster_id)
    client = InventoryClient(get_access_token_func())
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


@track_tool_usage()
async def cluster_credentials_download_url(
    mcp,
    get_access_token_func,
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
    """Get presigned download URL for cluster credential files after successful installation.

    TOOL_NAME=cluster_credentials_download_url
    DISPLAY_NAME=Cluster Credentials Download URL
    USECASE=Get secure presigned URLs to download kubeconfig and kubeadmin password after cluster installation completes
    INSTRUCTIONS=1. Ensure cluster installation completed successfully, 2. Get cluster_id, 3. Choose file_name (kubeconfig recommended), 4. Download credentials from returned URL before expiration
    INPUT_DESCRIPTION=cluster_id (string): cluster UUID, file_name (string): kubeconfig (standard, use this)/kubeconfig-noingress (without ingress)/kubeadmin-password (admin password)
    OUTPUT_DESCRIPTION=JSON object with presigned download URL and optional expiration timestamp for secure credential file access
    EXAMPLES=cluster_credentials_download_url("cluster-uuid", "kubeconfig"), cluster_credentials_download_url("cluster-uuid", "kubeadmin-password")
    PREREQUISITES=Successfully installed cluster (check with cluster_info)
    RELATED_TOOLS=cluster_info (verify installation complete), install_cluster (start installation), cluster_events (monitor installation progress)

    I/O-bound operation - uses async def for external API calls.

    Retrieves a time-limited presigned URL for downloading cluster credential files. For successfully
    installed clusters, always use "kubeconfig" over "kubeconfig-noingress". URLs expire for security.

    Args:
        cluster_id (str): The unique identifier of the cluster to get credentials for.
        file_name (str): kubeconfig, kubeconfig-noingress, or kubeadmin-password.

    Returns:
        str: JSON with presigned URL and optional expiration timestamp.
    """
    log.info(
        "Getting presigned URL for cluster %s credentials file %s",
        cluster_id,
        file_name,
    )
    client = InventoryClient(get_access_token_func())
    result = await client.get_presigned_for_cluster_credentials(cluster_id, file_name)
    log.info(
        "Successfully retrieved presigned URL for cluster %s credentials file %s - %s",
        cluster_id,
        file_name,
        result,
    )

    return json.dumps(format_presigned_url(result))

