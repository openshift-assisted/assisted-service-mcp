"""Unit tests for the list_clusters tool.

The Assisted Service client is mocked. These tests call the tool function
directly and do not start the MCP server.
"""

from unittest.mock import AsyncMock, Mock

import pytest

from assisted_service_mcp.src.service_client.exceptions import AssistedServiceAPIError
from assisted_service_mcp.src.tools import cluster_tools
from tests.tools.tool_test_helpers import TEST_TOKEN, invoke_with_client, test_token

CLUSTER_TOOLS_CLIENT = "assisted_service_mcp.src.tools.cluster_tools.InventoryClient"


def _client(clusters: list[dict[str, str]]) -> Mock:
    client = Mock()
    client.list_clusters = AsyncMock(return_value=clusters)
    return client


async def _invoke(client: Mock) -> tuple[str, Mock]:
    return await invoke_with_client(
        CLUSTER_TOOLS_CLIENT,
        client,
        cluster_tools.list_clusters(test_token),
    )


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
    inventory_client.assert_called_once_with(TEST_TOKEN)
    client.list_clusters.assert_awaited_once_with()


@pytest.mark.asyncio
async def test_list_clusters_empty_returns_message() -> None:
    client = _client([])

    result, inventory_client = await _invoke(client)

    assert result == "No clusters found."
    inventory_client.assert_called_once_with(TEST_TOKEN)
    client.list_clusters.assert_awaited_once_with()


@pytest.mark.asyncio
async def test_list_clusters_api_error_propagates() -> None:
    client = _client([])
    client.list_clusters.side_effect = AssistedServiceAPIError("list failed")

    with pytest.raises(AssistedServiceAPIError, match="list failed"):
        await _invoke(client)

    client.list_clusters.assert_awaited_once_with()
