"""Tests for MCP Apps UI resource registration."""

import pytest

from assisted_service_mcp.src.mcp import (
    INVENTORY_HTML,
    CREATOR_HTML,
    SETUP_HTML,
    INVENTORY_RESOURCE_URI,
    CREATOR_RESOURCE_URI,
    SETUP_RESOURCE_URI,
    AssistedServiceMCPServer,
)


class TestHtmlLoading:
    """Verify HTML dashboard files load correctly at import time."""

    def test_inventory_html_is_loaded(self) -> None:
        assert len(INVENTORY_HTML) > 100
        assert "<!DOCTYPE html>" in INVENTORY_HTML or "<html" in INVENTORY_HTML

    def test_creator_html_is_loaded(self) -> None:
        assert len(CREATOR_HTML) > 100
        assert "<!DOCTYPE html>" in CREATOR_HTML or "<html" in CREATOR_HTML

    def test_setup_html_is_loaded(self) -> None:
        assert len(SETUP_HTML) > 100
        assert "<!DOCTYPE html>" in SETUP_HTML or "<html" in SETUP_HTML


class TestResourceUris:
    """Verify resource URI constants follow expected naming."""

    def test_inventory_uri(self) -> None:
        assert INVENTORY_RESOURCE_URI == "ui://cluster-inventory"

    def test_creator_uri(self) -> None:
        assert CREATOR_RESOURCE_URI == "ui://cluster-creator"

    def test_setup_uri(self) -> None:
        assert SETUP_RESOURCE_URI == "ui://cluster-setup"


class TestHtmlContent:
    """Verify HTML dashboards contain MCP Apps SDK and correct tool calls."""

    def test_inventory_has_mcp_sdk(self) -> None:
        assert "unpkg.com/@modelcontextprotocol/ext-apps" in INVENTORY_HTML

    def test_creator_has_mcp_sdk(self) -> None:
        assert "unpkg.com/@modelcontextprotocol/ext-apps" in CREATOR_HTML

    def test_setup_has_mcp_sdk(self) -> None:
        assert "unpkg.com/@modelcontextprotocol/ext-apps" in SETUP_HTML

    def test_inventory_calls_list_clusters(self) -> None:
        assert "list_clusters" in INVENTORY_HTML

    def test_inventory_calls_cluster_info(self) -> None:
        assert "cluster_info" in INVENTORY_HTML

    def test_creator_calls_create_cluster(self) -> None:
        assert "create_cluster" in CREATOR_HTML

    def test_setup_calls_get_cluster_hosts(self) -> None:
        assert "get_cluster_hosts" in SETUP_HTML

    def test_setup_calls_set_host_role(self) -> None:
        assert "set_host_role" in SETUP_HTML

    def test_setup_calls_install_cluster(self) -> None:
        assert "install_cluster" in SETUP_HTML

    def test_inventory_has_send_message(self) -> None:
        assert "sendMessage" in INVENTORY_HTML

    def test_creator_has_send_message(self) -> None:
        assert "sendMessage" in CREATOR_HTML
