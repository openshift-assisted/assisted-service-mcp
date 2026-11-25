"""Unit tests for the add_operator_bundle_to_cluster tool.

The Assisted Service client is mocked. These tests call the tool function
directly and do not start the MCP server.
"""

from unittest.mock import AsyncMock, Mock

import pytest

from assisted_service_mcp.src.service_client.exceptions import AssistedServiceAPIError
from assisted_service_mcp.src.tools import operator_tools
from tests.tools.tool_test_helpers import (
    TEST_TOKEN,
    invoke_with_client,
    mock_to_str_result,
    test_token,
)

OPERATOR_TOOLS_CLIENT = "assisted_service_mcp.src.tools.operator_tools.InventoryClient"
CLUSTER_ID = "cid"
BUNDLE_NAME = "virtualization"


def _client(text: str = "OP-ADDED") -> Mock:
    client = Mock()
    client.add_operator_bundle_to_cluster = AsyncMock(
        return_value=mock_to_str_result(text)
    )
    return client


async def _invoke(
    client: Mock,
    *,
    cluster_id: str = CLUSTER_ID,
    bundle_name: str = BUNDLE_NAME,
) -> tuple[str, Mock]:
    return await invoke_with_client(
        OPERATOR_TOOLS_CLIENT,
        client,
        operator_tools.add_operator_bundle_to_cluster(
            test_token, cluster_id, bundle_name
        ),
    )


@pytest.mark.asyncio
async def test_add_operator_bundle_to_cluster_returns_updated_cluster_text() -> None:
    client = _client()

    result, inventory_client = await _invoke(client)

    assert result == "OP-ADDED"
    inventory_client.assert_called_once_with(TEST_TOKEN)
    client.add_operator_bundle_to_cluster.assert_awaited_once_with(
        CLUSTER_ID, BUNDLE_NAME
    )


@pytest.mark.asyncio
async def test_add_operator_bundle_to_cluster_api_error_propagates() -> None:
    client = _client()
    client.add_operator_bundle_to_cluster.side_effect = AssistedServiceAPIError(
        "bundle failed"
    )

    with pytest.raises(AssistedServiceAPIError, match="bundle failed"):
        await _invoke(client)

    client.add_operator_bundle_to_cluster.assert_awaited_once_with(
        CLUSTER_ID, BUNDLE_NAME
    )
