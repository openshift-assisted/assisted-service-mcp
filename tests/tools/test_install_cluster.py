"""Unit tests for the install_cluster tool.

The Assisted Service client is mocked. These tests call the tool function
directly and do not start the MCP server.
"""

from unittest.mock import AsyncMock, Mock, patch

import pytest

from assisted_service_mcp.src.service_client.exceptions import AssistedServiceAPIError
from assisted_service_mcp.src.tools import cluster_tools

TOKEN = "test-access-token"
CLUSTER_ID = "cid"


def _token() -> str:
    return TOKEN


def _client(text: str = "INSTALL-TRIGGERED") -> Mock:
    installing = Mock()
    installing.to_str.return_value = text
    client = Mock()
    client.install_cluster = AsyncMock(return_value=installing)
    return client


async def _invoke(client: Mock, *, cluster_id: str = CLUSTER_ID) -> tuple[str, Mock]:
    with patch(
        "assisted_service_mcp.src.tools.cluster_tools.InventoryClient",
        return_value=client,
    ) as inventory_client:
        result = await cluster_tools.install_cluster(_token, cluster_id)
    return result, inventory_client


@pytest.mark.asyncio
async def test_install_cluster_returns_triggered_cluster_text() -> None:
    client = _client()

    result, inventory_client = await _invoke(client)

    assert result == "INSTALL-TRIGGERED"
    inventory_client.assert_called_once_with(TOKEN)
    client.install_cluster.assert_awaited_once_with(CLUSTER_ID)


@pytest.mark.asyncio
async def test_install_cluster_api_error_propagates() -> None:
    client = _client()
    client.install_cluster.side_effect = AssistedServiceAPIError("install failed")

    with pytest.raises(AssistedServiceAPIError, match="install failed"):
        await _invoke(client)

    client.install_cluster.assert_awaited_once_with(CLUSTER_ID)
