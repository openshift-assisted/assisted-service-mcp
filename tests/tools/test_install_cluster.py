"""Unit tests for the install_cluster tool.

The Assisted Service client is mocked. These tests call the tool function
directly and do not start the MCP server.
"""

from unittest.mock import AsyncMock, Mock

import pytest

from assisted_service_mcp.src.service_client.exceptions import AssistedServiceAPIError
from assisted_service_mcp.src.tools import cluster_tools
from tests.tools.tool_test_helpers import (
    TEST_TOKEN,
    invoke_with_client,
    mock_to_str_result,
    test_token,
)

CLUSTER_TOOLS_CLIENT = "assisted_service_mcp.src.tools.cluster_tools.InventoryClient"
CLUSTER_ID = "cid"


def _client(text: str = "INSTALL-TRIGGERED") -> Mock:
    client = Mock()
    client.install_cluster = AsyncMock(return_value=mock_to_str_result(text))
    return client


async def _invoke(client: Mock, *, cluster_id: str = CLUSTER_ID) -> tuple[str, Mock]:
    return await invoke_with_client(
        CLUSTER_TOOLS_CLIENT,
        client,
        cluster_tools.install_cluster(test_token, cluster_id),
    )


@pytest.mark.asyncio
async def test_install_cluster_returns_triggered_cluster_text() -> None:
    client = _client()

    result, inventory_client = await _invoke(client)

    assert result == "INSTALL-TRIGGERED"
    inventory_client.assert_called_once_with(TEST_TOKEN)
    client.install_cluster.assert_awaited_once_with(CLUSTER_ID)


@pytest.mark.asyncio
async def test_install_cluster_api_error_propagates() -> None:
    client = _client()
    client.install_cluster.side_effect = AssistedServiceAPIError("install failed")

    with pytest.raises(AssistedServiceAPIError, match="install failed"):
        await _invoke(client)

    client.install_cluster.assert_awaited_once_with(CLUSTER_ID)
