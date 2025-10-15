import asyncio
import json
import datetime as _dt
from unittest.mock import patch, Mock, MagicMock, AsyncMock
import pytest

from assisted_service_mcp.src.tools.version_tools import list_versions
from assisted_service_mcp.src.tools.operator_tools import (
    list_operator_bundles,
    add_operator_bundle_to_cluster,
)


@pytest.mark.asyncio
async def test_tool_set_cluster_platform_module() -> None:
    from assisted_service_mcp.src.tools import cluster_tools
    from assisted_service_mcp.src.mcp import AssistedServiceMCPServer

    mock_client = Mock()
    mock_client.update_cluster = AsyncMock(
        return_value=type("_R", (), {"to_str": lambda self=None: "UPDATED"})()
    )

    AssistedServiceMCPServer()
    with (
        patch(
            "assisted_service_mcp.src.tools.cluster_tools.InventoryClient",
            return_value=mock_client,
        ),
        patch(
            "assisted_service_mcp.utils.auth.get_access_token",
            return_value="test-access-token",
        ),
    ):
        resp = await cluster_tools.set_cluster_platform(
            lambda: "test-access-token", "cid", "vsphere"
        )
        assert resp == "UPDATED"


@pytest.mark.asyncio
async def test_tool_set_cluster_vips_module() -> None:
    from assisted_service_mcp.src.tools import cluster_tools
    from assisted_service_mcp.src.mcp import AssistedServiceMCPServer

    mock_client = Mock()
    mock_client.update_cluster = AsyncMock(
        return_value=type("_R", (), {"to_str": lambda self=None: "VIPS-UPDATED"})()
    )

    AssistedServiceMCPServer()
    with (
        patch(
            "assisted_service_mcp.src.tools.cluster_tools.InventoryClient",
            return_value=mock_client,
        ),
        patch(
            "assisted_service_mcp.utils.auth.get_access_token",
            return_value="test-access-token",
        ),
    ):
        resp = await cluster_tools.set_cluster_vips(
            lambda: "test-access-token", "cid", "10.0.0.2", "10.0.0.3"
        )
        assert resp == "VIPS-UPDATED"


@pytest.mark.asyncio
async def test_create_cluster_invalid_platform_for_sno_returns_message() -> None:
    from assisted_service_mcp.src.tools import cluster_tools
    from assisted_service_mcp.src.mcp import AssistedServiceMCPServer

    AssistedServiceMCPServer()
    resp = await cluster_tools.create_cluster(
        lambda: "t",
        name="n",
        version="4.18.0",
        base_domain="example.com",
        single_node=True,
        ssh_public_key=None,
        cpu_architecture="x86_64",
        platform="baremetal",
    )
    assert resp == "Platform must be set to 'none' for single-node clusters"


@pytest.mark.asyncio
async def test_tool_install_cluster_module() -> None:
    from assisted_service_mcp.src.tools import cluster_tools
    from assisted_service_mcp.src.mcp import AssistedServiceMCPServer

    mock_client = Mock()
    mock_client.install_cluster = AsyncMock(
        return_value=type("_R", (), {"to_str": lambda self=None: "INSTALL-TRIGGERED"})()
    )

    AssistedServiceMCPServer()
    with (
        patch(
            "assisted_service_mcp.src.tools.cluster_tools.InventoryClient",
            return_value=mock_client,
        ),
        patch(
            "assisted_service_mcp.utils.auth.get_access_token",
            return_value="test-access-token",
        ),
    ):
        resp = await cluster_tools.install_cluster(lambda: "test-access-token", "cid")
        assert resp == "INSTALL-TRIGGERED"


@pytest.mark.asyncio
async def test_tool_cluster_events_module() -> None:
    from assisted_service_mcp.src.tools import event_tools
    from assisted_service_mcp.src.mcp import AssistedServiceMCPServer

    mock_client = Mock()
    mock_client.get_events = AsyncMock(return_value='{"events": ["e1", "e2"]}')

    AssistedServiceMCPServer()
    with (
        patch(
            "assisted_service_mcp.src.tools.event_tools.InventoryClient",
            return_value=mock_client,
        ),
        patch(
            "assisted_service_mcp.utils.auth.get_access_token",
            return_value="test-access-token",
        ),
    ):
        resp = await event_tools.cluster_events(lambda: "test-access-token", "cid")
        assert json.loads(resp)["events"] == ["e1", "e2"]


@pytest.mark.asyncio
async def test_tool_host_events_module() -> None:
    from assisted_service_mcp.src.tools import event_tools
    from assisted_service_mcp.src.mcp import AssistedServiceMCPServer

    mock_client = Mock()
    mock_client.get_events = AsyncMock(return_value='{"events": ["h1"]}')

    AssistedServiceMCPServer()
    with (
        patch(
            "assisted_service_mcp.src.tools.event_tools.InventoryClient",
            return_value=mock_client,
        ),
        patch(
            "assisted_service_mcp.utils.auth.get_access_token",
            return_value="test-access-token",
        ),
    ):
        resp = await event_tools.host_events(lambda: "test-access-token", "cid", "hid")
        assert json.loads(resp)["events"] == ["h1"]


@pytest.mark.asyncio
async def test_tool_cluster_iso_download_url_module() -> None:
    from assisted_service_mcp.src.tools import download_tools
    from assisted_service_mcp.src.mcp import AssistedServiceMCPServer

    class _Presigned:
        def __init__(self, url: str, expires_at: str | None = None) -> None:
            self.url = url
            self.expires_at = (
                _dt.datetime.fromisoformat("2025-01-01T00:00:00+00:00")
                if expires_at
                else None
            )

    mock_client = Mock()
    mock_client.list_infra_envs = AsyncMock(return_value=[{"id": "ie1"}])
    mock_client.get_infra_env_download_url = AsyncMock(
        return_value=_Presigned("https://u/iso", "2025-01-01T00:00:00Z")
    )

    AssistedServiceMCPServer()
    with (
        patch(
            "assisted_service_mcp.src.tools.download_tools.InventoryClient",
            return_value=mock_client,
        ),
        patch(
            "assisted_service_mcp.utils.auth.get_access_token",
            return_value="test-access-token",
        ),
    ):
        resp = await download_tools.cluster_iso_download_url(
            lambda: "test-access-token", "cid"
        )
        data = json.loads(resp)
        assert data[0]["url"] == "https://u/iso"
        assert data[0]["expires_at"] == "2025-01-01T00:00:00Z"


@pytest.mark.asyncio
async def test_tool_cluster_credentials_download_url_module() -> None:
    from assisted_service_mcp.src.tools import download_tools
    from assisted_service_mcp.src.mcp import AssistedServiceMCPServer

    class _Presigned:
        def __init__(self, url: str, expires_at: str | None = None) -> None:
            self.url = url
            self.expires_at = expires_at

    mock_client = Mock()
    mock_client.get_presigned_for_cluster_credentials = AsyncMock(
        return_value=_Presigned("https://u/kubeconfig", None)
    )

    AssistedServiceMCPServer()
    with (
        patch(
            "assisted_service_mcp.src.tools.download_tools.InventoryClient",
            return_value=mock_client,
        ),
        patch(
            "assisted_service_mcp.utils.auth.get_access_token",
            return_value="test-access-token",
        ),
    ):
        resp = await download_tools.cluster_credentials_download_url(
            lambda: "test-access-token", "cid", "kubeconfig"
        )
        data = json.loads(resp)
        assert data["url"] == "https://u/kubeconfig"


@pytest.mark.asyncio
async def test_tool_set_host_role_module() -> None:
    from assisted_service_mcp.src.tools import host_tools
    from assisted_service_mcp.src.mcp import AssistedServiceMCPServer

    mock_client = Mock()
    mock_client.update_host = AsyncMock(
        return_value=type("_R", (), {"to_str": lambda self=None: "HOST-UPDATED"})()
    )

    AssistedServiceMCPServer()
    with (
        patch(
            "assisted_service_mcp.src.tools.host_tools._get_cluster_infra_env_id",
            new=AsyncMock(return_value="ie1"),
        ),
        patch(
            "assisted_service_mcp.src.tools.host_tools.InventoryClient",
            return_value=mock_client,
        ),
        patch(
            "assisted_service_mcp.utils.auth.get_access_token",
            return_value="test-access-token",
        ),
    ):
        resp = await host_tools.set_host_role(
            lambda: "test-access-token", "hid", "cid", "worker"
        )
        assert resp == "HOST-UPDATED"


@pytest.mark.asyncio
async def test_tool_add_operator_bundle_module() -> None:
    from assisted_service_mcp.src.tools import operator_tools
    from assisted_service_mcp.src.mcp import AssistedServiceMCPServer

    mock_client = Mock()
    mock_client.add_operator_bundle_to_cluster = AsyncMock(
        return_value=type("_R", (), {"to_str": lambda self=None: "OP-ADDED"})()
    )

    AssistedServiceMCPServer()
    with (
        patch(
            "assisted_service_mcp.src.tools.operator_tools.InventoryClient",
            return_value=mock_client,
        ),
        patch(
            "assisted_service_mcp.utils.auth.get_access_token",
            return_value="test-access-token",
        ),
    ):
        resp = await operator_tools.add_operator_bundle_to_cluster(
            lambda: "test-access-token", "cid", "virtualization"
        )
        assert resp == "OP-ADDED"


@pytest.mark.asyncio
async def test_tool_list_operator_bundles_module() -> None:
    from assisted_service_mcp.src.tools import operator_tools
    from assisted_service_mcp.src.mcp import AssistedServiceMCPServer

    bundles = [{"name": "virtualization"}]
    mock_client = Mock()
    mock_client.get_operator_bundles = AsyncMock(return_value=bundles)

    AssistedServiceMCPServer()
    with (
        patch(
            "assisted_service_mcp.src.tools.operator_tools.InventoryClient",
            return_value=mock_client,
        ),
        patch(
            "assisted_service_mcp.utils.auth.get_access_token",
            return_value="test-access-token",
        ),
    ):
        resp = await operator_tools.list_operator_bundles(lambda: "test-access-token")
        assert json.loads(resp) == bundles


@pytest.mark.asyncio
async def test_tool_network_validate_nmstate_yaml_module() -> None:
    from assisted_service_mcp.src.tools import network_tools
    from assisted_service_mcp.src.mcp import AssistedServiceMCPServer

    with patch(
        "assisted_service_mcp.src.tools.network_tools.validate_and_parse_nmstate"
    ):
        AssistedServiceMCPServer()
        resp = await network_tools.validate_nmstate_yaml(
            lambda: "test-access-token", "interfaces: []\n"
        )
        assert resp == "YAML is valid"


@pytest.mark.asyncio
async def test_alter_static_network_remove_with_none_index_raises() -> None:
    from assisted_service_mcp.src.tools import network_tools
    from assisted_service_mcp.src.mcp import AssistedServiceMCPServer

    AssistedServiceMCPServer()
    mock_client = Mock()
    mock_client.get_infra_env = AsyncMock(
        return_value=type("_I", (), {"static_network_config": "[]"})()
    )
    with (
        patch(
            "assisted_service_mcp.src.tools.network_tools.InventoryClient",
            return_value=mock_client,
        ),
        patch(
            "assisted_service_mcp.src.tools.network_tools._get_cluster_infra_env_id",
            new=AsyncMock(return_value="ie1"),
        ),
    ):
        with pytest.raises(ValueError, match="index cannot be null"):
            await network_tools.alter_static_network_config_nmstate_for_host(
                lambda: "t", "cid", None, None
            )


@pytest.mark.asyncio
async def test_alter_static_network_remove_with_empty_existing_raises() -> None:
    from assisted_service_mcp.src.tools import network_tools
    from assisted_service_mcp.src.mcp import AssistedServiceMCPServer

    AssistedServiceMCPServer()
    mock_client = Mock()
    mock_client.get_infra_env = AsyncMock(
        return_value=type("_I", (), {"static_network_config": None})()
    )
    with (
        patch(
            "assisted_service_mcp.src.tools.network_tools.InventoryClient",
            return_value=mock_client,
        ),
        patch(
            "assisted_service_mcp.src.tools.network_tools._get_cluster_infra_env_id",
            new=AsyncMock(return_value="ie1"),
        ),
    ):
        with pytest.raises(ValueError, match="empty existing static network config"):
            await network_tools.alter_static_network_config_nmstate_for_host(
                lambda: "t", "cid", 0, None
            )


@pytest.mark.asyncio
async def test_list_static_network_config_invalid_infraenv_count() -> None:
    from assisted_service_mcp.src.tools import network_tools
    from assisted_service_mcp.src.mcp import AssistedServiceMCPServer

    AssistedServiceMCPServer()
    mock_client = Mock()
    mock_client.list_infra_envs = AsyncMock(return_value=[{"id": "a"}, {"id": "b"}])
    with patch(
        "assisted_service_mcp.src.tools.network_tools.InventoryClient",
        return_value=mock_client,
    ):
        resp = await network_tools.list_static_network_config(lambda: "t", "cid")
        assert resp.startswith("ERROR:")


@pytest.mark.asyncio
async def test_list_versions_happy_path() -> None:
    from assisted_service_mcp.src.tools import version_tools
    from assisted_service_mcp.src.mcp import AssistedServiceMCPServer

    AssistedServiceMCPServer()
    mock_client = Mock()
    mock_client.get_openshift_versions = AsyncMock(return_value=[{"version": "4.18.1"}])
    with patch(
        "assisted_service_mcp.src.tools.version_tools.InventoryClient",
        return_value=mock_client,
    ):
        resp = await version_tools.list_versions(lambda: "t")
        assert json.loads(resp)[0]["version"] == "4.18.1"


@pytest.mark.asyncio
async def test_tool_network_generate_nmstate_yaml_module() -> None:
    from assisted_service_mcp.src.tools import network_tools
    from assisted_service_mcp.src.utils.static_net.template import (
        NMStateTemplateParams,
        EthernetInterfaceParams,
    )
    from assisted_service_mcp.src.mcp import AssistedServiceMCPServer

    params = NMStateTemplateParams(
        routes=None,
        bond_ifaces=None,
        vlan_ifaces=None,
        ethernet_ifaces=[
            EthernetInterfaceParams(mac_address="00:11:22:33:44:55", name="eth0")
        ],
    )
    AssistedServiceMCPServer()
    with patch(
        "assisted_service_mcp.src.tools.network_tools.generate_nmstate_from_template",
        return_value="yaml",
    ):
        resp = await network_tools.generate_nmstate_yaml(
            lambda: "test-access-token", params
        )
        assert resp == "yaml"


@pytest.mark.asyncio
async def test_tool_create_cluster_module() -> None:
    from assisted_service_mcp.src.tools import cluster_tools
    from assisted_service_mcp.src.mcp import AssistedServiceMCPServer

    # Simulate returned API objects' to_str() and attributes
    class _Cluster:
        def __init__(self, cid: str, ver: str) -> None:
            self.id = cid
            self.openshift_version = ver

        def to_str(self) -> str:
            return f"CLUSTER:{self.id}:{self.openshift_version}"

    class _Infra:
        def __init__(self, iid: str) -> None:
            self.id = iid

    mock_client = Mock()
    mock_client.create_cluster = AsyncMock(return_value=_Cluster("cid-1", "4.18.2"))
    mock_client.create_infra_env = AsyncMock(return_value=_Infra("ie-1"))

    AssistedServiceMCPServer()
    with (
        patch(
            "assisted_service_mcp.src.tools.cluster_tools.InventoryClient",
            return_value=mock_client,
        ),
        patch(
            "assisted_service_mcp.utils.auth.get_access_token",
            return_value="test-access-token",
        ),
    ):
        resp = await cluster_tools.create_cluster(
            lambda: "test-access-token",
            name="n",
            version="4.18.2",
            base_domain="example.com",
            single_node=False,
            ssh_public_key=None,
            cpu_architecture="x86_64",
            platform="baremetal",
        )
        assert resp == "cid-1"


@pytest.mark.asyncio
async def test_tool_set_cluster_ssh_key_partial_failure_module() -> None:
    from assisted_service_mcp.src.tools import cluster_tools
    from assisted_service_mcp.src.mcp import AssistedServiceMCPServer

    class _Cluster:
        def __init__(self, cid: str) -> None:
            self.id = cid

        def to_str(self) -> str:
            return f"CLUSTER:{self.id}"

    mock_client = Mock()
    mock_client.update_cluster = AsyncMock(return_value=_Cluster("cid"))
    mock_client.list_infra_envs = AsyncMock(return_value=[{"id": "infraenv-id"}])
    mock_client.update_infra_env = AsyncMock(side_effect=Exception("Update failed"))

    AssistedServiceMCPServer()
    with (
        patch(
            "assisted_service_mcp.src.tools.shared_helpers._get_cluster_infra_env_id",
            new=AsyncMock(return_value="infraenv-id"),
        ),
        patch(
            "assisted_service_mcp.src.tools.cluster_tools.InventoryClient",
            return_value=mock_client,
        ),
        patch(
            "assisted_service_mcp.utils.auth.get_access_token",
            return_value="test-access-token",
        ),
    ):
        resp = await cluster_tools.set_cluster_ssh_key(
            lambda: "test-access-token", "cid", "ssh-rsa AAAA"
        )
        assert "Cluster key updated, but boot image key update failed" in resp


def test_list_versions_error_branch() -> None:  # type: ignore[no-untyped-def]
    async def run() -> None:
        with patch(
            "assisted_service_mcp.src.service_client.assisted_service_api.InventoryClient.get_openshift_versions",
            side_effect=Exception("boom"),
        ):
            try:
                await list_versions(lambda: "token")
            except Exception as e:  # noqa: BLE001
                assert "boom" in str(e)

    asyncio.run(run())


def test_list_operator_bundles_error_branch() -> None:  # type: ignore[no-untyped-def]
    async def run() -> None:
        with patch(
            "assisted_service_mcp.src.service_client.assisted_service_api.InventoryClient.get_operator_bundles",
            side_effect=Exception("boom2"),
        ):
            try:
                await list_operator_bundles(lambda: "token")
            except Exception as e:  # noqa: BLE001
                assert "boom2" in str(e)

    asyncio.run(run())


def test_add_operator_bundle_to_cluster_happy() -> None:  # type: ignore[no-untyped-def]
    async def run() -> None:
        mock_client = MagicMock()
        mock_cluster = MagicMock()
        mock_client.add_operator_bundle_to_cluster = AsyncMock(
            return_value=mock_cluster
        )
        mock_cluster.to_str.return_value = "cluster-str"
        # Patch where it's used: operator_tools imports InventoryClient into its namespace
        with patch(
            "assisted_service_mcp.src.tools.operator_tools.InventoryClient",
            return_value=mock_client,
        ):
            s = await add_operator_bundle_to_cluster(lambda: "token", "cid", "bundle")
            assert s == "cluster-str"

    asyncio.run(run())
