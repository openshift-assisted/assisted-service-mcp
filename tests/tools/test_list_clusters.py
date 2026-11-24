"""Unit tests for the list_clusters tool.

The Assisted Service client is mocked. These tests call the tool function
directly and do not start the MCP server.
"""

from unittest.mock import AsyncMock, Mock, patch

import pytest

from assisted_service_mcp.src.service_client.exceptions import AssistedServiceAPIError
from assisted_service_mcp.src.tools import cluster_tools

TOKEN = "test-access-token"


def _token() -> str:
    return TOKEN


def _client(clusters: list[dict[str, str]]) -> Mock:
    client = Mock()
    client.list_clusters = AsyncMock(return_value=clusters)
    return client


async def _invoke(client: Mock) -> tuple[str, Mock]:
    with patch(
        "assisted_service_mcp.src.tools.cluster_tools.InventoryClient",
        return_value=client,
    ) as inventory_client:
        result = await cluster_tools.list_clusters(_token)
    return result, inventory_client


@pytest.mark.asyncio
async def test_list_clusters_formats_fields_and_defaults_missing_version() -> None:
    client = _client(
        [
            {
                "name": "cluster1",
                "id": "id1",
                "openshift_version": "4.18.2",
                "status": "ready",
            },
            {
                "name": "cluster2",
                "id": "id2",
                "openshift_version": "4.17.1",
                "status": "installing",
            },
            {"name": "cluster3", "id": "id3", "status": "installing"},
        ]
    )

    result, inventory_client = await _invoke(client)

    assert result == (
        "cluster1\n"
        "- ID: id1\n"
        "- Openshift version: 4.18.2\n"
        "- Status: ready\n"
        "\n"
        "cluster2\n"
        "- ID: id2\n"
        "- Openshift version: 4.17.1\n"
        "- Status: installing\n"
        "\n"
        "cluster3\n"
        "- ID: id3\n"
        "- Openshift version: Unknown\n"
        "- Status: installing\n"
        "\n"
    )
    inventory_client.assert_called_once_with(TOKEN)
    client.list_clusters.assert_awaited_once_with()


@pytest.mark.asyncio
async def test_list_clusters_empty_returns_message() -> None:
    client = _client([])

    result, inventory_client = await _invoke(client)

    assert result == "No clusters found."
    inventory_client.assert_called_once_with(TOKEN)
    client.list_clusters.assert_awaited_once_with()


@pytest.mark.asyncio
async def test_list_clusters_api_error_propagates() -> None:
    client = _client([])
    client.list_clusters.side_effect = AssistedServiceAPIError("list failed")

    with pytest.raises(AssistedServiceAPIError, match="list failed"):
        await _invoke(client)

    client.list_clusters.assert_awaited_once_with()
