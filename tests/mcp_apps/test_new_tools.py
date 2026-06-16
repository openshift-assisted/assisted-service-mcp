"""Unit tests for new MCP Apps tools."""

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from assisted_service_mcp.src.tools.host_tools import get_cluster_hosts
from assisted_service_mcp.src.tools.cluster_tools import (
    get_installation_progress,
    open_cluster_creator,
)
from assisted_service_mcp.src.tools.health_tools import check_prerequisites


def _mock_token() -> str:
    return "mock-access-token"


class TestGetClusterHosts:
    """Tests for get_cluster_hosts tool."""

    @pytest.mark.asyncio
    async def test_returns_json_with_hosts_and_iso(self) -> None:
        mock_host = MagicMock()
        mock_host.id = "host-1"
        mock_host.requested_hostname = "master-0"
        mock_host.hostname = "localhost"
        mock_host.status = "known"
        mock_host.role = "master"

        mock_cluster = MagicMock()
        mock_cluster.hosts = [mock_host]
        mock_cluster.status = "pending-for-input"

        mock_presigned = MagicMock()
        mock_presigned.url = "https://example.com/iso.iso"

        with patch(
            "assisted_service_mcp.src.tools.host_tools.InventoryClient"
        ) as MockClient:
            client = MockClient.return_value
            client.get_cluster = AsyncMock(return_value=mock_cluster)
            client.list_infra_envs = AsyncMock(
                return_value=[{"id": "infra-1"}]
            )
            client.get_infra_env_download_url = AsyncMock(
                return_value=mock_presigned
            )

            result = await get_cluster_hosts(_mock_token, True, "cluster-1")

        data = json.loads(result)
        assert len(data["hosts"]) == 1
        assert data["hosts"][0]["id"] == "host-1"
        assert data["hosts"][0]["hostname"] == "master-0"
        assert data["hosts"][0]["role"] == "master"
        assert data["discovery_iso_url"] == "https://example.com/iso.iso"

    @pytest.mark.asyncio
    async def test_returns_empty_hosts_when_none(self) -> None:
        mock_cluster = MagicMock()
        mock_cluster.hosts = []
        mock_cluster.status = "pending-for-input"

        with patch(
            "assisted_service_mcp.src.tools.host_tools.InventoryClient"
        ) as MockClient:
            client = MockClient.return_value
            client.get_cluster = AsyncMock(return_value=mock_cluster)
            client.list_infra_envs = AsyncMock(return_value=[])

            result = await get_cluster_hosts(_mock_token, True, "cluster-1")

        data = json.loads(result)
        assert data["hosts"] == []
        assert data["discovery_iso_url"] == ""


class TestGetInstallationProgress:
    """Tests for get_installation_progress tool."""

    @pytest.mark.asyncio
    async def test_returns_progress_json(self) -> None:
        mock_progress = MagicMock()
        mock_progress.total_percentage = 65

        mock_cluster = MagicMock()
        mock_cluster.status = "installing"
        mock_cluster.progress = mock_progress
        mock_cluster.status_info = "Bootstrap complete"

        with patch(
            "assisted_service_mcp.src.tools.cluster_tools.InventoryClient"
        ) as MockClient:
            client = MockClient.return_value
            client.get_cluster = AsyncMock(return_value=mock_cluster)

            result = await get_installation_progress(_mock_token, True, "cluster-1")

        data = json.loads(result)
        assert data["status"] == "installing"
        assert data["progress"] == 65
        assert data["status_info"] == "Bootstrap complete"

    @pytest.mark.asyncio
    async def test_returns_zero_progress_when_no_progress_attr(self) -> None:
        mock_cluster = MagicMock()
        mock_cluster.status = "pending-for-input"
        mock_cluster.progress = None
        mock_cluster.status_info = ""

        with patch(
            "assisted_service_mcp.src.tools.cluster_tools.InventoryClient"
        ) as MockClient:
            client = MockClient.return_value
            client.get_cluster = AsyncMock(return_value=mock_cluster)

            result = await get_installation_progress(_mock_token, True, "cluster-1")

        data = json.loads(result)
        assert data["status"] == "pending-for-input"
        assert data["progress"] == 0


class TestCheckPrerequisites:
    """Tests for check_prerequisites tool."""

    @pytest.mark.asyncio
    async def test_token_set_and_api_reachable(self) -> None:
        with patch(
            "assisted_service_mcp.src.tools.health_tools.get_setting",
            return_value="some-token",
        ):
            result = await check_prerequisites(_mock_token, True)

        data = json.loads(result)
        assert data["offline_token_set"] is True
        assert data["api_reachable"] is True

    @pytest.mark.asyncio
    async def test_token_not_set(self) -> None:
        with patch(
            "assisted_service_mcp.src.tools.health_tools.get_setting",
            return_value=None,
        ):
            result = await check_prerequisites(_mock_token, True)

        data = json.loads(result)
        assert data["offline_token_set"] is False
        assert data["api_reachable"] is False

    @pytest.mark.asyncio
    async def test_token_set_but_api_unreachable(self) -> None:
        def failing_token() -> str:
            raise RuntimeError("SSO unreachable")

        with patch(
            "assisted_service_mcp.src.tools.health_tools.get_setting",
            return_value="some-token",
        ):
            result = await check_prerequisites(failing_token, True)

        data = json.loads(result)
        assert data["offline_token_set"] is True
        assert data["api_reachable"] is False
        assert "SSO unreachable" in data["api_error"]


class TestOpenClusterCreator:
    """Tests for open_cluster_creator tool."""

    @pytest.mark.asyncio
    async def test_ui_supported_returns_dashboard_loaded(self) -> None:
        result = await open_cluster_creator(_mock_token, True)
        assert "dashboard loaded" in result.lower()

    @pytest.mark.asyncio
    async def test_text_only_also_returns_dashboard_loaded(self) -> None:
        result = await open_cluster_creator(_mock_token, False)
        assert "dashboard loaded" in result.lower()
