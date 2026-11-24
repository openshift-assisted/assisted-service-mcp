"""Unit tests for the alter_static_network_config_nmstate_for_host tool.

The Assisted Service client and static-network helpers are mocked. These tests
call the tool directly and do not start the MCP server.
"""

from unittest.mock import AsyncMock, Mock, patch

import pytest

from assisted_service_mcp.src.service_client.exceptions import AssistedServiceAPIError
from assisted_service_mcp.src.tools import network_tools

TOKEN = "test-access-token"
CLUSTER_ID = "cid"
INFRA_ENV_ID = "ie1"
NMSTATE_YAML = "interfaces: []\n"
EMPTY_CONFIG_JSON = "[]"
EXISTING_CONFIG_JSON = (
    '[{"mac_interface_map": [{"logical_nic_name": "eth0", '
    '"mac_address": "00:11:22:33:44:55"}], "network_yaml": "old"}]'
)
NEW_HOST_CONFIGS = [
    {
        "mac_interface_map": [
            {"logical_nic_name": "eth0", "mac_address": "00:11:22:33:44:55"}
        ],
        "network_yaml": NMSTATE_YAML,
    }
]
AFTER_REMOVE_CONFIGS: list[dict[str, object]] = []


def _token() -> str:
    return TOKEN


def _client(static_network_config: object) -> Mock:
    infra_env = Mock()
    infra_env.static_network_config = static_network_config
    updated = Mock()
    updated.to_str.return_value = "UPDATED-INFRA"
    client = Mock()
    client.get_infra_env = AsyncMock(return_value=infra_env)
    client.update_infra_env = AsyncMock(return_value=updated)
    return client


@pytest.mark.asyncio
async def test_alter_static_network_adds_or_replaces_host_config() -> None:
    client = _client(EMPTY_CONFIG_JSON)
    infra_env_lookup = AsyncMock(return_value=INFRA_ENV_ID)
    with (
        patch(
            "assisted_service_mcp.src.tools.network_tools._get_cluster_infra_env_id",
            new=infra_env_lookup,
        ),
        patch(
            "assisted_service_mcp.src.tools.network_tools.add_or_replace_static_host_config_yaml",
            return_value=NEW_HOST_CONFIGS,
        ) as add_or_replace,
        patch(
            "assisted_service_mcp.src.tools.network_tools.InventoryClient",
            return_value=client,
        ) as inventory_client,
    ):
        result = await network_tools.alter_static_network_config_nmstate_for_host(
            _token, CLUSTER_ID, None, NMSTATE_YAML
        )

    assert result == "UPDATED-INFRA"
    inventory_client.assert_called_once_with(TOKEN)
    infra_env_lookup.assert_awaited_once_with(client, CLUSTER_ID)
    client.get_infra_env.assert_awaited_once_with(INFRA_ENV_ID)
    add_or_replace.assert_called_once_with(
        existing_static_network_config=EMPTY_CONFIG_JSON,
        index=None,
        new_nmstate_yaml=NMSTATE_YAML,
    )
    client.update_infra_env.assert_awaited_once_with(
        INFRA_ENV_ID, static_network_config=NEW_HOST_CONFIGS
    )


@pytest.mark.asyncio
async def test_alter_static_network_removes_host_config() -> None:
    client = _client(EXISTING_CONFIG_JSON)
    infra_env_lookup = AsyncMock(return_value=INFRA_ENV_ID)
    with (
        patch(
            "assisted_service_mcp.src.tools.network_tools._get_cluster_infra_env_id",
            new=infra_env_lookup,
        ),
        patch(
            "assisted_service_mcp.src.tools.network_tools.remove_static_host_config_by_index",
            return_value=AFTER_REMOVE_CONFIGS,
        ) as remove_config,
        patch(
            "assisted_service_mcp.src.tools.network_tools.InventoryClient",
            return_value=client,
        ),
    ):
        result = await network_tools.alter_static_network_config_nmstate_for_host(
            _token, CLUSTER_ID, 0, None
        )

    assert result == "UPDATED-INFRA"
    infra_env_lookup.assert_awaited_once_with(client, CLUSTER_ID)
    remove_config.assert_called_once_with(
        existing_static_network_config=EXISTING_CONFIG_JSON, index=0
    )
    client.update_infra_env.assert_awaited_once_with(
        INFRA_ENV_ID, static_network_config=AFTER_REMOVE_CONFIGS
    )


@pytest.mark.asyncio
async def test_alter_static_network_remove_with_none_index_raises() -> None:
    client = _client(EMPTY_CONFIG_JSON)
    with (
        patch(
            "assisted_service_mcp.src.tools.network_tools._get_cluster_infra_env_id",
            new=AsyncMock(return_value=INFRA_ENV_ID),
        ),
        patch(
            "assisted_service_mcp.src.tools.network_tools.InventoryClient",
            return_value=client,
        ),
        pytest.raises(ValueError, match="index cannot be null"),
    ):
        await network_tools.alter_static_network_config_nmstate_for_host(
            _token, CLUSTER_ID, None, None
        )

    client.update_infra_env.assert_not_called()


@pytest.mark.asyncio
async def test_alter_static_network_remove_with_empty_existing_raises() -> None:
    client = _client(None)
    with (
        patch(
            "assisted_service_mcp.src.tools.network_tools._get_cluster_infra_env_id",
            new=AsyncMock(return_value=INFRA_ENV_ID),
        ),
        patch(
            "assisted_service_mcp.src.tools.network_tools.InventoryClient",
            return_value=client,
        ),
        pytest.raises(ValueError, match="empty existing static network config"),
    ):
        await network_tools.alter_static_network_config_nmstate_for_host(
            _token, CLUSTER_ID, 0, None
        )

    client.update_infra_env.assert_not_called()


@pytest.mark.asyncio
async def test_alter_static_network_update_error_propagates() -> None:
    client = _client(EMPTY_CONFIG_JSON)
    client.update_infra_env.side_effect = AssistedServiceAPIError("update failed")
    with (
        patch(
            "assisted_service_mcp.src.tools.network_tools._get_cluster_infra_env_id",
            new=AsyncMock(return_value=INFRA_ENV_ID),
        ),
        patch(
            "assisted_service_mcp.src.tools.network_tools.add_or_replace_static_host_config_yaml",
            return_value=NEW_HOST_CONFIGS,
        ),
        patch(
            "assisted_service_mcp.src.tools.network_tools.InventoryClient",
            return_value=client,
        ),
        pytest.raises(AssistedServiceAPIError, match="update failed"),
    ):
        await network_tools.alter_static_network_config_nmstate_for_host(
            _token, CLUSTER_ID, None, NMSTATE_YAML
        )
