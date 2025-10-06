"""Helper utilities for Assisted Service MCP Server."""

from typing import Any
from assisted_service_client import models


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

