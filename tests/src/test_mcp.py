import importlib


def test_mcp_registers_tools_and_auth_closures() -> None:
    mod = importlib.import_module("assisted_service_mcp.src.mcp")
    server = mod.AssistedServiceMCPServer()

    # Check closures exist
    assert hasattr(server, "_get_access_token")

    # List tools
    tool_names = server.list_tools_sync()
    assert isinstance(tool_names, list)
    # Expect at least all core tools
    expected = {
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
        "list_versions",
        "list_operator_bundles",
        "add_operator_bundle_to_cluster",
        "set_host_role",
        "validate_nmstate_yaml",
        "generate_nmstate_yaml",
        "alter_static_network_config_nmstate_for_host",
        "list_static_network_config",
    }
    assert expected.issubset(set(tool_names))
