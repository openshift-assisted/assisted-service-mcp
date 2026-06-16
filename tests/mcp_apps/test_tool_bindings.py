"""Tests for tool-to-UI resource bindings via AppConfig."""

import pytest

from assisted_service_mcp.src.mcp import AssistedServiceMCPServer


@pytest.fixture(scope="module")
def server() -> AssistedServiceMCPServer:
    return AssistedServiceMCPServer()


@pytest.fixture(scope="module")
def tool_names(server: AssistedServiceMCPServer) -> list[str]:
    return server.list_tools_sync()


class TestToolRegistration:
    """Verify all expected tools are registered."""

    EXPECTED_ORIGINAL_TOOLS = {
        "cluster_info",
        "list_clusters",
        "create_cluster",
        "set_cluster_vips",
        "set_cluster_platform",
        "install_cluster",
        "set_cluster_ssh_key",
        "cluster_events",
        "host_events",
        "cluster_iso_download_url",
        "cluster_credentials_download_url",
        "cluster_logs_download_url",
        "list_versions",
        "list_operator_bundles",
        "add_operator_bundle_to_cluster",
        "set_host_role",
        "validate_nmstate_yaml",
        "generate_nmstate_yaml",
        "alter_static_network_config_nmstate_for_host",
        "list_static_network_config",
    }

    EXPECTED_NEW_TOOLS = {
        "get_cluster_hosts",
        "get_installation_progress",
        "check_prerequisites",
    }

    def test_all_original_tools_registered(self, tool_names: list[str]) -> None:
        names_set = set(tool_names)
        missing = self.EXPECTED_ORIGINAL_TOOLS - names_set
        assert not missing, f"Missing original tools: {missing}"

    def test_all_new_tools_registered(self, tool_names: list[str]) -> None:
        names_set = set(tool_names)
        missing = self.EXPECTED_NEW_TOOLS - names_set
        assert not missing, f"Missing new tools: {missing}"

    def test_total_tool_count(self, tool_names: list[str]) -> None:
        expected_min = len(self.EXPECTED_ORIGINAL_TOOLS) + len(
            self.EXPECTED_NEW_TOOLS
        )
        assert len(tool_names) >= expected_min, (
            f"Expected at least {expected_min} tools, got {len(tool_names)}"
        )
