"""Unit tests for the cluster_events tool.

The Assisted Service client is mocked. These tests call the tool function
directly and do not start the MCP server.
"""

import json
from unittest.mock import Mock

import pytest

from assisted_service_mcp.src.service_client.exceptions import AssistedServiceAPIError
from assisted_service_mcp.src.tools import event_tools
from tests.tools.tool_test_helpers import (
    TEST_TOKEN,
    events_client,
    invoke_with_client,
    test_token,
)

EVENT_TOOLS_CLIENT = "assisted_service_mcp.src.tools.event_tools.InventoryClient"
CLUSTER_ID = "cid"
EVENTS = '{"events": ["e1", "e2"]}'


async def _invoke(client: Mock, *, cluster_id: str = CLUSTER_ID) -> tuple[str, Mock]:
    return await invoke_with_client(
        EVENT_TOOLS_CLIENT,
        client,
        event_tools.cluster_events(test_token, cluster_id),
    )


@pytest.mark.asyncio
async def test_cluster_events_returns_event_json() -> None:
    client = events_client(EVENTS)

    result, inventory_client = await _invoke(client)

    assert result == EVENTS
    assert json.loads(result)["events"] == ["e1", "e2"]
    inventory_client.assert_called_once_with(TEST_TOKEN)
    client.get_events.assert_awaited_once_with(cluster_id=CLUSTER_ID)


@pytest.mark.asyncio
async def test_cluster_events_api_error_propagates() -> None:
    client = events_client(EVENTS)
    client.get_events.side_effect = AssistedServiceAPIError("events failed")

    with pytest.raises(AssistedServiceAPIError, match="events failed"):
        await _invoke(client)

    client.get_events.assert_awaited_once_with(cluster_id=CLUSTER_ID)
