"""Unit tests for the cluster_credentials_download_url tool.

The Assisted Service client is mocked. These tests call the tool function
directly and do not start the MCP server.
"""

import json
from datetime import datetime
from unittest.mock import AsyncMock, Mock, patch

import pytest

from assisted_service_mcp.src.service_client.exceptions import AssistedServiceAPIError
from assisted_service_mcp.src.tools import download_tools

TOKEN = "test-access-token"
CLUSTER_ID = "cid"
FILE_NAME = "kubeconfig"


class _PresignedUrl:
    def __init__(self, url: str, expires_at: datetime | None) -> None:
        self.url = url
        self.expires_at = expires_at


def _token() -> str:
    return TOKEN


def _client(result: object) -> Mock:
    client = Mock()
    client.get_presigned_for_cluster_credentials = AsyncMock(return_value=result)
    return client


async def _invoke(
    client: Mock,
    *,
    cluster_id: str = CLUSTER_ID,
    file_name: str = FILE_NAME,
) -> tuple[str, Mock]:
    with patch(
        "assisted_service_mcp.src.tools.download_tools.InventoryClient",
        return_value=client,
    ) as inventory_client:
        result = await download_tools.cluster_credentials_download_url(
            _token, cluster_id, file_name
        )
    return result, inventory_client


@pytest.mark.asyncio
async def test_cluster_credentials_download_url_returns_url_without_expiration() -> (
    None
):
    client = _client(_PresignedUrl("https://u/kubeconfig", None))

    result, inventory_client = await _invoke(client)

    assert json.loads(result) == {"url": "https://u/kubeconfig"}
    inventory_client.assert_called_once_with(TOKEN)
    client.get_presigned_for_cluster_credentials.assert_awaited_once_with(
        CLUSTER_ID, FILE_NAME
    )


@pytest.mark.asyncio
async def test_cluster_credentials_download_url_includes_expiration() -> None:
    client = _client(
        _PresignedUrl(
            "https://u/kubeconfig",
            datetime.fromisoformat("2025-01-01T00:00:00+00:00"),
        )
    )

    result, _inventory_client = await _invoke(client)

    assert json.loads(result) == {
        "url": "https://u/kubeconfig",
        "expires_at": "2025-01-01T00:00:00Z",
    }


@pytest.mark.asyncio
async def test_cluster_credentials_download_url_api_error_returns_json() -> None:
    client = _client(None)
    client.get_presigned_for_cluster_credentials.side_effect = AssistedServiceAPIError(
        "boom"
    )

    result, _inventory_client = await _invoke(client)

    assert json.loads(result) == {"error": "Failed to retrieve credentials URL: boom"}


@pytest.mark.asyncio
async def test_cluster_credentials_download_url_missing_url_returns_json() -> None:
    client = _client(None)

    result, _inventory_client = await _invoke(client)

    assert json.loads(result) == {"error": "No credentials URL available"}
