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
            description="The unique identifier of the cluster whose ISO image URL will be retrieved."
        ),
    ],
) -> str:
    """Get ISO download URL(s) for cluster boot images.

    Retrieves time-limited download URLs for all infrastructure environment ISOs
    associated with the cluster. These bootable ISOs are used to boot hosts for automatic
    discovery and installation. Download the ISO and boot your hosts from it (USB, virtual
    media, PXE) to add them to the cluster. URLs are time-limited for security and will
    expire after a period.

    Examples:
        - cluster_iso_download_url("cluster-uuid")
        - After creating a cluster, get the ISO URL to boot your first host
        - If you updated SSH key, download a new ISO with the updated key

    Prerequisites:
        - Cluster with created infrastructure environment (automatically created by create_cluster)

    Related tools:
        - create_cluster - Creates cluster and infrastructure environment
        - set_cluster_ssh_key - Update SSH key (requires new ISO download)
        - cluster_info - View cluster and infrastructure environment details

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
            description="The type of credential file to download. Valid options: 'kubeconfig' (standard kubeconfig for cluster access - use this), 'kubeconfig-noingress' (kubeconfig without ingress), 'kubeadmin-password' (the kubeadmin user password)."
        ),
    ],
) -> str:
    """Get presigned download URL for cluster credentials after installation completes.

    Retrieves a presigned URL for downloading cluster credential files such as
    kubeconfig, kubeadmin password, or kubeconfig without ingress configuration.
    For a successfully installed cluster the kubeconfig file should always be used
    over the kubeconfig-noingress file.
    The URL is time-limited and provides secure access to sensitive cluster files.
    Whenever a URL is returned provide the user with information on the expiration
    of that URL if possible.
    
    Examples:
        - cluster_credentials_download_url("cluster-uuid", "kubeconfig")
        - cluster_credentials_download_url("cluster-uuid", "kubeadmin-password")
        - After installation completes, get kubeconfig to start using the cluster
        - Get admin password if you need to log into the web console

    Prerequisites:
        - Successfully completed cluster installation (check status with cluster_info)

    Related tools:
        - cluster_info - Verify installation is complete
        - install_cluster - Start the installation
        - cluster_events - Monitor installation progress

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

