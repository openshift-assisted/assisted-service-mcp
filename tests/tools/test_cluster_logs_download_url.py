"""Unit tests for the cluster_logs_download_url tool.

The Assisted Service client is mocked. These tests call the tool function
directly and do not start the MCP server.
"""

import json
from unittest.mock import AsyncMock, Mock

import pytest

from assisted_service_mcp.src.service_client.exceptions import AssistedServiceAPIError
from assisted_service_mcp.src.tools import download_tools
from tests.tools.tool_test_helpers import TEST_TOKEN, invoke_with_client, test_token

DOWNLOAD_TOOLS_CLIENT = "assisted_service_mcp.src.tools.download_tools.InventoryClient"
CLUSTER_ID = "cid"
LOGS_URL = "https://u/cluster-logs"


def _client(logs_url: str | None) -> Mock:
    client = Mock()
    client.get_presigned_cluster_logs_url = AsyncMock(return_value=logs_url)
    return client


async def _invoke(client: Mock) -> tuple[str, Mock]:
    return await invoke_with_client(
        DOWNLOAD_TOOLS_CLIENT,
        client,
        download_tools.cluster_logs_download_url(test_token, CLUSTER_ID),
    )


@pytest.mark.asyncio
async def test_cluster_logs_download_url_returns_url() -> None:
    client = _client(LOGS_URL)

    result, inventory_client = await _invoke(client)

    assert json.loads(result) == {"url": LOGS_URL}
    inventory_client.assert_called_once_with(TEST_TOKEN)
    client.get_presigned_cluster_logs_url.assert_awaited_once_with(CLUSTER_ID)


@pytest.mark.asyncio
async def test_cluster_logs_download_url_api_error_returns_json() -> None:
    client = _client(None)
    client.get_presigned_cluster_logs_url.side_effect = AssistedServiceAPIError("boom")

    result, _inventory_client = await _invoke(client)

    assert json.loads(result) == {
        "error": f"Failed to retrieve logs URL for cluster {CLUSTER_ID}: boom"
    }
    client.get_presigned_cluster_logs_url.assert_awaited_once_with(CLUSTER_ID)


@pytest.mark.asyncio
async def test_cluster_logs_download_url_missing_url_returns_json() -> None:
    client = _client(None)

    result, _inventory_client = await _invoke(client)

    assert json.loads(result) == {
        "error": f"No logs URL available for cluster {CLUSTER_ID}"
    }
    client.get_presigned_cluster_logs_url.assert_awaited_once_with(CLUSTER_ID)
