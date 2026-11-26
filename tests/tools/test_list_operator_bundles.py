"""Unit tests for the list_operator_bundles tool.

The Assisted Service client is mocked. These tests call the tool function
directly and do not start the MCP server.
"""

import json
from unittest.mock import AsyncMock, Mock

import pytest

from assisted_service_mcp.src.service_client.exceptions import AssistedServiceAPIError
from assisted_service_mcp.src.tools import operator_tools
from tests.tools.tool_test_helpers import TEST_TOKEN, invoke_with_client, test_token

OPERATOR_TOOLS_CLIENT = "assisted_service_mcp.src.tools.operator_tools.InventoryClient"


def _client(bundles: list[dict[str, str]]) -> Mock:
    client = Mock()
    client.get_operator_bundles = AsyncMock(return_value=bundles)
    return client


async def _invoke(client: Mock) -> tuple[str, Mock]:
    return await invoke_with_client(
        OPERATOR_TOOLS_CLIENT,
        client,
        operator_tools.list_operator_bundles(test_token),
    )


@pytest.mark.asyncio
async def test_list_operator_bundles_returns_json() -> None:
    bundles = [{"name": "virtualization"}]
    client = _client(bundles)

    result, inventory_client = await _invoke(client)

    assert json.loads(result) == bundles
    inventory_client.assert_called_once_with(TEST_TOKEN)
    client.get_operator_bundles.assert_awaited_once_with()


@pytest.mark.asyncio
async def test_list_operator_bundles_api_error_propagates() -> None:
    client = _client([])
    client.get_operator_bundles.side_effect = AssistedServiceAPIError("boom2")

    with pytest.raises(AssistedServiceAPIError, match="boom2"):
        await _invoke(client)

    client.get_operator_bundles.assert_awaited_once_with()
