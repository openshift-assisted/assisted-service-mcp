"""Unit tests for the cluster_iso_download_url tool.

The Assisted Service client is mocked. These tests call the tool function
directly and do not start the MCP server.
"""

import json
from datetime import UTC, datetime
from unittest.mock import AsyncMock, Mock, call, patch

import pytest

from assisted_service_mcp.src.service_client.exceptions import AssistedServiceAPIError
from assisted_service_mcp.src.tools import download_tools

TOKEN = "test-access-token"
CLUSTER_ID = "cid"
NO_URLS = "No ISO download URLs found for this cluster."


class _PresignedUrl:
    def __init__(self, url: str | None, expires_at: datetime | None) -> None:
        self.url = url
        self.expires_at = expires_at


def _token() -> str:
    return TOKEN


def _client(
    infra_envs: list[dict[str, str]],
    downloads: object,
) -> Mock:
    client = Mock()
    client.list_infra_envs = AsyncMock(return_value=infra_envs)
    client.get_infra_env_download_url = AsyncMock(side_effect=downloads)
    return client


async def _invoke(client: Mock) -> tuple[str, Mock]:
    with patch(
        "assisted_service_mcp.src.tools.download_tools.InventoryClient",
        return_value=client,
    ) as inventory_client:
        result = await download_tools.cluster_iso_download_url(_token, CLUSTER_ID)
    return result, inventory_client


@pytest.mark.asyncio
async def test_cluster_iso_download_url_includes_expiration() -> None:
    expires_at = datetime.fromisoformat("2025-01-01T00:00:00+00:00")
    client = _client(
        [{"id": "ie1"}],
        [_PresignedUrl("https://u/iso", expires_at)],
    )

    result, inventory_client = await _invoke(client)

    assert json.loads(result) == [
        {"url": "https://u/iso", "expires_at": "2025-01-01T00:00:00Z"}
    ]
    inventory_client.assert_called_once_with(TOKEN)
    client.list_infra_envs.assert_awaited_once_with(CLUSTER_ID)
    client.get_infra_env_download_url.assert_awaited_once_with("ie1")


@pytest.mark.asyncio
async def test_cluster_iso_download_url_omits_zero_expiration() -> None:
    client = _client(
        [{"id": "ie1"}, {"id": "ie2"}],
        [
            _PresignedUrl("https://u/iso1", datetime(1, 1, 1, tzinfo=UTC)),
            _PresignedUrl(
                "https://u/iso2",
                datetime.fromisoformat("2025-01-15T12:00:00+00:00"),
            ),
        ],
    )

    result, _inventory_client = await _invoke(client)

    data = json.loads(result)
    assert data[0] == {"url": "https://u/iso1"}
    assert data[1]["url"] == "https://u/iso2"
    assert data[1]["expires_at"].startswith("2025-01-15T12:00:00")
    assert client.get_infra_env_download_url.await_args_list == [
        call("ie1"),
        call("ie2"),
    ]


@pytest.mark.asyncio
async def test_cluster_iso_download_url_no_infra_envs_returns_message() -> None:
    client = _client([], [])

    result, _inventory_client = await _invoke(client)

    assert result == NO_URLS
    client.get_infra_env_download_url.assert_not_called()


@pytest.mark.asyncio
async def test_cluster_iso_download_url_lookup_error_returns_message() -> None:
    client = _client([], [])
    client.list_infra_envs.side_effect = AssistedServiceAPIError("list failed")

    result, _inventory_client = await _invoke(client)

    assert result == "Error retrieving ISO URLs: list failed"
    client.get_infra_env_download_url.assert_not_called()


@pytest.mark.asyncio
async def test_cluster_iso_download_url_skips_failed_infra_env() -> None:
    client = _client(
        [{"id": "ie1"}, {"id": "ie2"}],
        [
            AssistedServiceAPIError("iso failed"),
            _PresignedUrl("https://u/iso2", None),
        ],
    )

    result, _inventory_client = await _invoke(client)

    assert json.loads(result) == [{"url": "https://u/iso2"}]
    assert client.get_infra_env_download_url.await_args_list == [
        call("ie1"),
        call("ie2"),
    ]


@pytest.mark.asyncio
async def test_cluster_iso_download_url_missing_url_returns_message() -> None:
    client = _client(
        [{"id": "ie1"}],
        [_PresignedUrl(None, None)],
    )

    result, _inventory_client = await _invoke(client)

    assert result == NO_URLS


@pytest.mark.asyncio
async def test_cluster_iso_download_url_missing_infra_env_id_uses_unknown() -> None:
    client = _client(
        [{}],
        [_PresignedUrl("https://u/iso", None)],
    )

    result, _inventory_client = await _invoke(client)

    assert json.loads(result) == [{"url": "https://u/iso"}]
    client.get_infra_env_download_url.assert_awaited_once_with("unknown")
