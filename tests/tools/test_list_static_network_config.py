"""Unit tests for the list_static_network_config tool.

The Assisted Service client is mocked. These tests call the tool function
directly and do not start the MCP server.
"""

import json
from unittest.mock import AsyncMock, Mock, patch

import pytest

from assisted_service_mcp.src.service_client.exceptions import AssistedServiceAPIError
from assisted_service_mcp.src.tools import network_tools

TOKEN = "test-access-token"
CLUSTER_ID = "cid"
INFRA_ENV_ERROR = (
    "ERROR: this cluster doesn't have exactly 1 infra env, "
    "cannot manage static network config"
)


def _token() -> str:
    return TOKEN


def _client(infra_envs: list[dict[str, object]]) -> Mock:
    client = Mock()
    client.list_infra_envs = AsyncMock(return_value=infra_envs)
    return client


async def _invoke(client: Mock) -> tuple[str, Mock]:
    with patch(
        "assisted_service_mcp.src.tools.network_tools.InventoryClient",
        return_value=client,
    ) as inventory_client:
        result = await network_tools.list_static_network_config(_token, CLUSTER_ID)
    return result, inventory_client


@pytest.mark.asyncio
async def test_list_static_network_config_returns_configs() -> None:
    client = _client([{"static_network_config": ["cfg1", "cfg2"]}])

    result, inventory_client = await _invoke(client)

    assert json.loads(result) == ["cfg1", "cfg2"]
    inventory_client.assert_called_once_with(TOKEN)
    client.list_infra_envs.assert_awaited_once_with(CLUSTER_ID)


@pytest.mark.asyncio
async def test_list_static_network_config_missing_config_returns_empty_list() -> None:
    client = _client([{"id": "ie1"}])

    result, _inventory_client = await _invoke(client)

    assert json.loads(result) == []


@pytest.mark.asyncio
async def test_list_static_network_config_wrong_infra_env_count_returns_error() -> None:
    client = _client([{"id": "a"}, {"id": "b"}])

    result, _inventory_client = await _invoke(client)

    assert result == INFRA_ENV_ERROR


@pytest.mark.asyncio
async def test_list_static_network_config_api_error_propagates() -> None:
    client = _client([])
    client.list_infra_envs.side_effect = AssistedServiceAPIError("list failed")

    with pytest.raises(AssistedServiceAPIError, match="list failed"):
        await _invoke(client)
