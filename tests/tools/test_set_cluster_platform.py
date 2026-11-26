"""Unit tests for the set_cluster_platform tool.

The Assisted Service client is mocked. These tests call the tool function
directly and do not start the MCP server.
"""

from unittest.mock import Mock

import pytest

from assisted_service_mcp.src.service_client.exceptions import AssistedServiceAPIError
from assisted_service_mcp.src.service_client.helpers import Helpers
from assisted_service_mcp.src.tools import cluster_tools
from tests.tools.tool_test_helpers import (
    TEST_TOKEN,
    invoke_with_client,
    test_token,
    update_cluster_client,
)

CLUSTER_TOOLS_CLIENT = "assisted_service_mcp.src.tools.cluster_tools.InventoryClient"
CLUSTER_ID = "cid"
PLATFORM: Helpers.VALID_PLATFORMS = "vsphere"


async def _invoke(
    client: Mock,
    *,
    cluster_id: str = CLUSTER_ID,
    platform: Helpers.VALID_PLATFORMS = PLATFORM,
) -> tuple[str, Mock]:
    return await invoke_with_client(
        CLUSTER_TOOLS_CLIENT,
        client,
        cluster_tools.set_cluster_platform(test_token, cluster_id, platform),
    )


@pytest.mark.asyncio
async def test_set_cluster_platform_returns_updated_cluster_text() -> None:
    client = update_cluster_client()

    result, inventory_client = await _invoke(client)

    assert result == "UPDATED"
    inventory_client.assert_called_once_with(TEST_TOKEN)
    client.update_cluster.assert_awaited_once_with(CLUSTER_ID, platform=PLATFORM)


@pytest.mark.asyncio
async def test_set_cluster_platform_api_error_propagates() -> None:
    client = update_cluster_client()
    client.update_cluster.side_effect = AssistedServiceAPIError(
        "platform update failed"
    )

    with pytest.raises(AssistedServiceAPIError, match="platform update failed"):
        await _invoke(client)

    client.update_cluster.assert_awaited_once_with(CLUSTER_ID, platform=PLATFORM)
