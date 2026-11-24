"""Unit tests for the set_host_role tool.

The Assisted Service client is mocked. These tests call the tool function
directly and do not start the MCP server.
"""

from typing import Literal
from unittest.mock import AsyncMock, Mock, patch

import pytest

from assisted_service_mcp.src.service_client.exceptions import AssistedServiceAPIError
from assisted_service_mcp.src.tools import host_tools

TOKEN = "test-access-token"
HOST_ID = "hid"
CLUSTER_ID = "cid"
INFRA_ENV_ID = "ie1"
ROLE: Literal["auto-assign", "master", "worker"] = "worker"


def _token() -> str:
    return TOKEN


def _client(text: str = "HOST-UPDATED") -> Mock:
    updated = Mock()
    updated.to_str.return_value = text
    client = Mock()
    client.update_host = AsyncMock(return_value=updated)
    return client


async def _invoke(
    client: Mock,
    *,
    infra_env_id: str | None = INFRA_ENV_ID,
    infra_env_error: Exception | None = None,
) -> tuple[str, Mock, AsyncMock]:
    lookup = AsyncMock(return_value=infra_env_id)
    if infra_env_error is not None:
        lookup = AsyncMock(side_effect=infra_env_error)
    with (
        patch(
            "assisted_service_mcp.src.tools.host_tools._get_cluster_infra_env_id",
            new=lookup,
        ),
        patch(
            "assisted_service_mcp.src.tools.host_tools.InventoryClient",
            return_value=client,
        ) as inventory_client,
    ):
        result = await host_tools.set_host_role(_token, HOST_ID, CLUSTER_ID, ROLE)
    return result, inventory_client, lookup


@pytest.mark.asyncio
async def test_set_host_role_returns_updated_host_text() -> None:
    client = _client()

    result, inventory_client, infra_env_lookup = await _invoke(client)

    assert result == "HOST-UPDATED"
    inventory_client.assert_called_once_with(TOKEN)
    infra_env_lookup.assert_awaited_once_with(client, CLUSTER_ID)
    client.update_host.assert_awaited_once_with(HOST_ID, INFRA_ENV_ID, host_role=ROLE)


@pytest.mark.asyncio
async def test_set_host_role_missing_infra_env_propagates() -> None:
    client = _client()

    with pytest.raises(ValueError, match="No InfraEnv found for cluster cid"):
        await _invoke(
            client,
            infra_env_error=ValueError("No InfraEnv found for cluster cid"),
        )

    client.update_host.assert_not_called()


@pytest.mark.asyncio
async def test_set_host_role_api_error_propagates() -> None:
    client = _client()
    client.update_host.side_effect = AssistedServiceAPIError("role update failed")

    with pytest.raises(AssistedServiceAPIError, match="role update failed"):
        await _invoke(client)

    client.update_host.assert_awaited_once_with(HOST_ID, INFRA_ENV_ID, host_role=ROLE)
