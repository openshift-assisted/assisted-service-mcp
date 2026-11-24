"""Unit tests for the list_operator_bundles tool.

The Assisted Service client is mocked. These tests call the tool function
directly and do not start the MCP server.
"""

import json
from unittest.mock import AsyncMock, Mock, patch

import pytest

from assisted_service_mcp.src.service_client.exceptions import AssistedServiceAPIError
from assisted_service_mcp.src.tools import operator_tools

TOKEN = "test-access-token"


def _token() -> str:
    return TOKEN


def _client(bundles: list[dict[str, str]]) -> Mock:
    client = Mock()
    client.get_operator_bundles = AsyncMock(return_value=bundles)
    return client


async def _invoke(client: Mock) -> tuple[str, Mock]:
    with patch(
        "assisted_service_mcp.src.tools.operator_tools.InventoryClient",
        return_value=client,
    ) as inventory_client:
        result = await operator_tools.list_operator_bundles(_token)
    return result, inventory_client


@pytest.mark.asyncio
async def test_list_operator_bundles_returns_json() -> None:
    bundles = [{"name": "virtualization"}]
    client = _client(bundles)

    result, inventory_client = await _invoke(client)

    assert json.loads(result) == bundles
    inventory_client.assert_called_once_with(TOKEN)
    client.get_operator_bundles.assert_awaited_once_with()


@pytest.mark.asyncio
async def test_list_operator_bundles_api_error_propagates() -> None:
    client = _client([])
    client.get_operator_bundles.side_effect = AssistedServiceAPIError("boom2")

    with pytest.raises(AssistedServiceAPIError, match="boom2"):
        await _invoke(client)

    client.get_operator_bundles.assert_awaited_once_with()
