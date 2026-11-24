"""Unit tests for the set_cluster_vips tool.

The Assisted Service client is mocked. These tests call the tool function
directly and do not start the MCP server.
"""

from unittest.mock import AsyncMock, Mock, patch

import pytest

from assisted_service_mcp.src.service_client.exceptions import AssistedServiceAPIError
from assisted_service_mcp.src.tools import cluster_tools

TOKEN = "test-access-token"
CLUSTER_ID = "cid"
API_VIP = "10.0.0.2"
INGRESS_VIP = "10.0.0.3"


def _token() -> str:
    return TOKEN


def _client(text: str = "VIPS-UPDATED") -> Mock:
    updated = Mock()
    updated.to_str.return_value = text
    client = Mock()
    client.update_cluster = AsyncMock(return_value=updated)
    return client


async def _invoke(
    client: Mock,
    *,
    cluster_id: str = CLUSTER_ID,
    api_vip: str = API_VIP,
    ingress_vip: str = INGRESS_VIP,
) -> tuple[str, Mock]:
    with patch(
        "assisted_service_mcp.src.tools.cluster_tools.InventoryClient",
        return_value=client,
    ) as inventory_client:
        result = await cluster_tools.set_cluster_vips(
            _token, cluster_id, api_vip, ingress_vip
        )
    return result, inventory_client


@pytest.mark.asyncio
async def test_set_cluster_vips_returns_updated_cluster_text() -> None:
    client = _client()

    result, inventory_client = await _invoke(client)

    assert result == "VIPS-UPDATED"
    inventory_client.assert_called_once_with(TOKEN)
    client.update_cluster.assert_awaited_once_with(
        CLUSTER_ID, api_vip=API_VIP, ingress_vip=INGRESS_VIP
    )


@pytest.mark.asyncio
async def test_set_cluster_vips_api_error_propagates() -> None:
    client = _client()
    client.update_cluster.side_effect = AssistedServiceAPIError("vip update failed")

    with pytest.raises(AssistedServiceAPIError, match="vip update failed"):
        await _invoke(client)

    client.update_cluster.assert_awaited_once_with(
        CLUSTER_ID, api_vip=API_VIP, ingress_vip=INGRESS_VIP
    )
