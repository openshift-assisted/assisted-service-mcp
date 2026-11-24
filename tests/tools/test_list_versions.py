"""Unit tests for the list_versions tool.

The Assisted Service client is mocked. These tests call the tool function
directly and do not start the MCP server.
"""

from typing import cast
from unittest.mock import AsyncMock, Mock, patch

import pytest
from assisted_service_client import models

from assisted_service_mcp.src.service_client.exceptions import AssistedServiceAPIError
from assisted_service_mcp.src.tools import version_tools

TOKEN = "test-access-token"


def _token() -> str:
    return TOKEN


def _client(versions: object) -> Mock:
    client = Mock()
    client.get_openshift_versions = AsyncMock(return_value=versions)
    return client


async def _invoke(client: Mock) -> tuple[str, Mock]:
    with patch(
        "assisted_service_mcp.src.tools.version_tools.InventoryClient",
        return_value=client,
    ) as inventory_client:
        result = await version_tools.list_versions(_token)
    return result, inventory_client


@pytest.mark.asyncio
async def test_list_versions_formats_support_levels_architectures_and_sorts() -> None:
    client = _client(
        cast(
            models.OpenshiftVersions,
            {
                "4.19.0": {
                    "display_name": "4.19.0",
                    "support_level": "beta",
                    "cpu_architectures": "x86_64",
                },
                "4.18.1": {
                    "display_name": "4.18.1",
                    "support_level": "production",
                    "cpu_architectures": ["x86_64", "arm64"],
                },
                "4.17": {"support_level": "custom-level"},
            },
        )
    )

    result, inventory_client = await _invoke(client)

    assert result == (
        "Available OpenShift versions:\n"
        "\n"
        "| OpenShift Version | Support Level | Supported CPU Architectures |\n"
        "|---|---|---|\n"
        "| 4.17 | custom-level | Unknown |\n"
        "| 4.18.1 | Full Support | x86_64, arm64 |\n"
        "| 4.19.0 | Release Candidate | x86_64 |\n"
    )
    inventory_client.assert_called_once_with(TOKEN)
    client.get_openshift_versions.assert_awaited_once_with(True)


@pytest.mark.asyncio
async def test_list_versions_empty_returns_message() -> None:
    client = _client(cast(models.OpenshiftVersions, {}))

    result, _inventory_client = await _invoke(client)

    assert result == "No OpenShift versions available."


@pytest.mark.asyncio
async def test_list_versions_api_error_propagates() -> None:
    client = _client(cast(models.OpenshiftVersions, {}))
    client.get_openshift_versions.side_effect = AssistedServiceAPIError("boom")

    with pytest.raises(AssistedServiceAPIError, match="boom"):
        await _invoke(client)

    client.get_openshift_versions.assert_awaited_once_with(True)
