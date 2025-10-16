"""Download URL tools for Assisted Service MCP Server."""

import json
from datetime import datetime, timezone
from typing import Annotated, Callable, Any
from pydantic import Field

from assisted_service_client import models
from assisted_service_mcp.src.metrics import track_tool_usage
from assisted_service_mcp.src.service_client.assisted_service_api import InventoryClient
from assisted_service_mcp.src.logger import log

# Define a constant for zero datetime
ZERO_DATETIME = datetime(1, 1, 1, tzinfo=timezone.utc)


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
    if presigned_url.expires_at and presigned_url.expires_at != ZERO_DATETIME:
        presigned_url_dict["expires_at"] = presigned_url.expires_at.isoformat().replace(
            "+00:00", "Z"
        )

    return presigned_url_dict


@track_tool_usage()
async def cluster_iso_download_url(
    get_access_token_func: Callable[[], str],
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
    media) to add them to the cluster. URLs are time-limited for security and will
    expire after a period.

    Prerequisites:
        - Cluster with created infrastructure environment (automatically created by create_cluster)

    Returns:
        str: JSON array with ISO URLs and optional expiration times, or message if no ISOs found.
    """
    log.info("Retrieving InfraEnv ISO URLs for cluster_id: %s", cluster_id)
    try:
        token = get_access_token_func()
        client = InventoryClient(token)
        infra_envs = await client.list_infra_envs(cluster_id)
    except Exception as e:
        log.error("Failed to retrieve infrastructure environments: %s", e)
        return f"Error retrieving ISO URLs: {str(e)}"

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

        try:
            presigned_url = await client.get_infra_env_download_url(infra_env_id)
        except Exception as e:
            log.error(
                "Failed to get download URL for infra env %s: %s", infra_env_id, e
            )
            continue

        if presigned_url and presigned_url.url:
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
    get_access_token_func: Callable[[], str],
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

    Prerequisites:
        - Successfully completed cluster installation (check status with cluster_info)

    Returns:
        str: JSON with presigned URL and optional expiration timestamp.
    """
    log.info(
        "Getting presigned URL for cluster %s credentials file %s",
        cluster_id,
        file_name,
    )
    try:
        client = InventoryClient(get_access_token_func())
        result = await client.get_presigned_for_cluster_credentials(
            cluster_id, file_name
        )
    except Exception as e:
        log.error("Failed to retrieve credentials URL: %s", e)
        return json.dumps({"error": f"Failed to retrieve credentials URL: {str(e)}"})

    if not result:
        log.warning(
            "No presigned URL returned for cluster %s file %s", cluster_id, file_name
        )
        return json.dumps({"error": "No credentials URL available"})

    log.info(
        "Successfully retrieved presigned URL for cluster %s credentials file %s",
        cluster_id,
        file_name,
    )

    return json.dumps(format_presigned_url(result))
