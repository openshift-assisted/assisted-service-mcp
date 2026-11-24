"""Unit tests for the set_cluster_platform tool.

The Assisted Service client is mocked. These tests call the tool function
directly and do not start the MCP server.
"""

from unittest.mock import AsyncMock, Mock, patch

import pytest

from assisted_service_mcp.src.service_client.exceptions import AssistedServiceAPIError
from assisted_service_mcp.src.service_client.helpers import Helpers
from assisted_service_mcp.src.tools import cluster_tools

TOKEN = "test-access-token"
CLUSTER_ID = "cid"
PLATFORM: Helpers.VALID_PLATFORMS = "vsphere"


def _token() -> str:
    return TOKEN


def _client(text: str = "UPDATED") -> Mock:
    updated = Mock()
    updated.to_str.return_value = text
    client = Mock()
    client.update_cluster = AsyncMock(return_value=updated)
    return client


async def _invoke(
    client: Mock,
    *,
    cluster_id: str = CLUSTER_ID,
    platform: Helpers.VALID_PLATFORMS = PLATFORM,
) -> tuple[str, Mock]:
    with patch(
        "assisted_service_mcp.src.tools.cluster_tools.InventoryClient",
        return_value=client,
    ) as inventory_client:
        result = await cluster_tools.set_cluster_platform(_token, cluster_id, platform)
    return result, inventory_client


@pytest.mark.asyncio
async def test_set_cluster_platform_returns_updated_cluster_text() -> None:
    client = _client()

    result, inventory_client = await _invoke(client)

    assert result == "UPDATED"
    inventory_client.assert_called_once_with(TOKEN)
    client.update_cluster.assert_awaited_once_with(CLUSTER_ID, platform=PLATFORM)


@pytest.mark.asyncio
async def test_set_cluster_platform_api_error_propagates() -> None:
    client = _client()
    client.update_cluster.side_effect = AssistedServiceAPIError(
        "platform update failed"
    )

    with pytest.raises(AssistedServiceAPIError, match="platform update failed"):
        await _invoke(client)

    client.update_cluster.assert_awaited_once_with(CLUSTER_ID, platform=PLATFORM)
