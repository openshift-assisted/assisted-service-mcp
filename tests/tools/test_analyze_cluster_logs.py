"""Unit tests for the analyze_cluster_logs tool.

The Assisted Service client and log analyzer are mocked. These tests call
the tool function directly and do not start the MCP server.
"""

from unittest.mock import AsyncMock, Mock, patch

import pytest

from assisted_service_mcp.src.mcp import AssistedServiceMCPServer
from assisted_service_mcp.src.settings import settings
from assisted_service_mcp.src.tools import cluster_tools

TOKEN = "test-access-token"
CLUSTER_ID = "cid"


def _token() -> str:
    return TOKEN


async def _invoke(client: Mock, analyze: AsyncMock) -> tuple[str, Mock]:
    with (
        patch(
            "assisted_service_mcp.src.tools.cluster_tools.InventoryClient",
            return_value=client,
        ) as inventory_client,
        patch(
            "assisted_service_mcp.src.tools.cluster_tools.runner.analyze_cluster",
            new=analyze,
        ),
    ):
        result = await cluster_tools.analyze_cluster_logs(_token, CLUSTER_ID)
    return result, inventory_client


@pytest.mark.asyncio
async def test_analyze_cluster_logs_joins_findings() -> None:
    client = Mock()
    analyze = AsyncMock(return_value=["first finding", "second finding"])

    result, inventory_client = await _invoke(client, analyze)

    assert result == "first finding\n\nsecond finding"
    inventory_client.assert_called_once_with(TOKEN)
    analyze.assert_awaited_once_with(cluster_id=CLUSTER_ID, api_client=client)


@pytest.mark.asyncio
async def test_analyze_cluster_logs_empty_results_return_empty_string() -> None:
    client = Mock()
    analyze = AsyncMock(return_value=[])

    result, _inventory_client = await _invoke(client, analyze)

    assert result == ""
    analyze.assert_awaited_once_with(cluster_id=CLUSTER_ID, api_client=client)


@pytest.mark.asyncio
async def test_analyze_cluster_logs_analyzer_error_propagates() -> None:
    client = Mock()
    analyze = AsyncMock(side_effect=RuntimeError("logs unavailable"))

    with pytest.raises(RuntimeError, match="logs unavailable"):
        await _invoke(client, analyze)


@pytest.mark.parametrize(
    ("enabled", "registered"),
    [(1, True), (0, False)],
)
def test_analyze_cluster_logs_registration_follows_troubleshooting_flag(
    enabled: int, registered: bool
) -> None:
    with patch.object(settings, "ENABLE_TROUBLESHOOTING_TOOLS", enabled):
        tool_names = AssistedServiceMCPServer().list_tools_sync()

    assert ("analyze_cluster_logs" in tool_names) is registered
