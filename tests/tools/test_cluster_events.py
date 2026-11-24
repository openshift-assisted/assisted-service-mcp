"""Unit tests for the cluster_events tool.

The Assisted Service client is mocked. These tests call the tool function
directly and do not start the MCP server.
"""

import json
from unittest.mock import AsyncMock, Mock, patch

import pytest

from assisted_service_mcp.src.service_client.exceptions import AssistedServiceAPIError
from assisted_service_mcp.src.tools import event_tools

TOKEN = "test-access-token"
CLUSTER_ID = "cid"
EVENTS = '{"events": ["e1", "e2"]}'


def _token() -> str:
    return TOKEN


def _client(events: str = EVENTS) -> Mock:
    client = Mock()
    client.get_events = AsyncMock(return_value=events)
    return client


async def _invoke(client: Mock, *, cluster_id: str = CLUSTER_ID) -> tuple[str, Mock]:
    with patch(
        "assisted_service_mcp.src.tools.event_tools.InventoryClient",
        return_value=client,
    ) as inventory_client:
        result = await event_tools.cluster_events(_token, cluster_id)
    return result, inventory_client


@pytest.mark.asyncio
async def test_cluster_events_returns_event_json() -> None:
    client = _client()

    result, inventory_client = await _invoke(client)

    assert result == EVENTS
    assert json.loads(result)["events"] == ["e1", "e2"]
    inventory_client.assert_called_once_with(TOKEN)
    client.get_events.assert_awaited_once_with(cluster_id=CLUSTER_ID)


@pytest.mark.asyncio
async def test_cluster_events_api_error_propagates() -> None:
    client = _client()
    client.get_events.side_effect = AssistedServiceAPIError("events failed")

    with pytest.raises(AssistedServiceAPIError, match="events failed"):
        await _invoke(client)

    client.get_events.assert_awaited_once_with(cluster_id=CLUSTER_ID)
