"""Unit tests for the create_cluster tool.

The Assisted Service client is mocked. These tests call the tool function
directly and do not start the MCP server.
"""

from typing import cast
from unittest.mock import AsyncMock, Mock, patch

import pytest

from assisted_service_mcp.src.service_client.helpers import Helpers
from assisted_service_mcp.src.tools import cluster_tools
from tests.create_objects_helpers import create_test_cluster, create_test_infra_env

TOKEN = "test-access-token"
NAME = "test-cluster"
VERSION = "4.18.2"
BASE_DOMAIN = "example.com"
VALID_SSH_KEY = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCtest user@example.com"
SNO_PLATFORM_MESSAGE = "Platform must be set to 'none' for single-node clusters"


class _UnsetClusterId:
    """Cluster response whose id was not set by the API."""

    id = None
    openshift_version = VERSION


def _token() -> str:
    return TOKEN


def _client(cluster_id: str = "cid-1", openshift_version: str = VERSION) -> Mock:
    client = Mock()
    client.create_cluster = AsyncMock(
        return_value=create_test_cluster(
            cluster_id=cluster_id,
            name=NAME,
            openshift_version=openshift_version,
        )
    )
    client.create_infra_env = AsyncMock(
        return_value=create_test_infra_env(
            infra_env_id="ie-1",
            name=NAME,
            cluster_id=cluster_id,
        )
    )
    return client


async def _invoke(  # pylint: disable=too-many-arguments,too-many-positional-arguments
    client: Mock,
    *,
    name: str = NAME,
    version: str = VERSION,
    base_domain: str = BASE_DOMAIN,
    single_node: bool = False,
    ssh_public_key: str | None = None,
    cpu_architecture: Helpers.VALID_CPU_ARCHITECTURES | None = "x86_64",
    platform: Helpers.VALID_PLATFORMS | None = "baremetal",
) -> tuple[str, Mock]:
    with patch(
        "assisted_service_mcp.src.tools.cluster_tools.InventoryClient",
        return_value=client,
    ) as inventory_client:
        result = await cluster_tools.create_cluster(
            _token,
            name=name,
            version=version,
            base_domain=base_domain,
            single_node=single_node,
            ssh_public_key=ssh_public_key,
            cpu_architecture=cpu_architecture,
            platform=platform,
        )
    return result, inventory_client


def _assert_api_calls(  # pylint: disable=too-many-arguments,too-many-positional-arguments
    client: Mock,
    *,
    name: str,
    version: str,
    single_node: bool,
    base_domain: str,
    platform: str,
    cpu_architecture: str,
    ssh_public_key: str | None,
    cluster_id: str,
    openshift_version: str,
) -> None:
    if ssh_public_key is None:
        client.create_cluster.assert_awaited_once_with(
            name,
            version,
            single_node,
            base_dns_domain=base_domain,
            tags="chatbot",
            cpu_architecture=cpu_architecture,
            platform=platform,
        )
        client.create_infra_env.assert_awaited_once_with(
            name,
            cluster_id=cluster_id,
            openshift_version=openshift_version,
            cpu_architecture=cpu_architecture,
        )
        return

    client.create_cluster.assert_awaited_once_with(
        name,
        version,
        single_node,
        base_dns_domain=base_domain,
        tags="chatbot",
        cpu_architecture=cpu_architecture,
        platform=platform,
        ssh_public_key=ssh_public_key,
    )
    client.create_infra_env.assert_awaited_once_with(
        name,
        cluster_id=cluster_id,
        openshift_version=openshift_version,
        cpu_architecture=cpu_architecture,
        ssh_authorized_key=ssh_public_key,
    )


@pytest.mark.asyncio
async def test_create_cluster_multi_node_baremetal_returns_id_and_forwards_params() -> (
    None
):
    client = _client()

    result, inventory_client = await _invoke(client)

    assert result == "cid-1"
    inventory_client.assert_called_once_with(TOKEN)
    _assert_api_calls(
        client,
        name=NAME,
        version=VERSION,
        single_node=False,
        base_domain=BASE_DOMAIN,
        platform="baremetal",
        cpu_architecture="x86_64",
        ssh_public_key=None,
        cluster_id="cid-1",
        openshift_version=VERSION,
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("single_node", "expected_platform"),
    [(False, "baremetal"), (True, "none")],
)
async def test_create_cluster_omitted_platform_defaults(
    single_node: bool, expected_platform: str
) -> None:
    client = _client()

    result, inventory_client = await _invoke(
        client, single_node=single_node, platform=None
    )

    assert result == "cid-1"
    inventory_client.assert_called_once_with(TOKEN)
    _assert_api_calls(
        client,
        name=NAME,
        version=VERSION,
        single_node=single_node,
        base_domain=BASE_DOMAIN,
        platform=expected_platform,
        cpu_architecture="x86_64",
        ssh_public_key=None,
        cluster_id="cid-1",
        openshift_version=VERSION,
    )


@pytest.mark.asyncio
async def test_create_cluster_single_node_explicit_none_platform() -> None:
    client = _client()

    result, _inventory_client = await _invoke(client, single_node=True, platform="none")

    assert result == "cid-1"
    _assert_api_calls(
        client,
        name=NAME,
        version=VERSION,
        single_node=True,
        base_domain=BASE_DOMAIN,
        platform="none",
        cpu_architecture="x86_64",
        ssh_public_key=None,
        cluster_id="cid-1",
        openshift_version=VERSION,
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("platform", ["vsphere", "oci", "nutanix"])
async def test_create_cluster_forwards_multi_node_platform(platform: str) -> None:
    client = _client()
    typed_platform = cast(Helpers.VALID_PLATFORMS, platform)

    result, _inventory_client = await _invoke(
        client, single_node=False, platform=typed_platform
    )

    assert result == "cid-1"
    _assert_api_calls(
        client,
        name=NAME,
        version=VERSION,
        single_node=False,
        base_domain=BASE_DOMAIN,
        platform=platform,
        cpu_architecture="x86_64",
        ssh_public_key=None,
        cluster_id="cid-1",
        openshift_version=VERSION,
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("cpu_architecture", ["aarch64", "arm64", "ppc64le", "s390x"])
async def test_create_cluster_forwards_cpu_architecture(cpu_architecture: str) -> None:
    client = _client()
    typed_cpu = cast(Helpers.VALID_CPU_ARCHITECTURES, cpu_architecture)

    result, _inventory_client = await _invoke(client, cpu_architecture=typed_cpu)

    assert result == "cid-1"
    _assert_api_calls(
        client,
        name=NAME,
        version=VERSION,
        single_node=False,
        base_domain=BASE_DOMAIN,
        platform="baremetal",
        cpu_architecture=cpu_architecture,
        ssh_public_key=None,
        cluster_id="cid-1",
        openshift_version=VERSION,
    )


@pytest.mark.asyncio
async def test_create_cluster_none_cpu_architecture_defaults_to_x86_64() -> None:
    client = _client(cluster_id="cid-2", openshift_version="4.19.0")

    result, _inventory_client = await _invoke(
        client,
        name=NAME,
        version="4.19.0",
        single_node=True,
        ssh_public_key=None,
        cpu_architecture=None,
        platform=None,
    )

    assert result == "cid-2"
    _assert_api_calls(
        client,
        name=NAME,
        version="4.19.0",
        single_node=True,
        base_domain=BASE_DOMAIN,
        platform="none",
        cpu_architecture="x86_64",
        ssh_public_key=None,
        cluster_id="cid-2",
        openshift_version="4.19.0",
    )


@pytest.mark.asyncio
async def test_create_cluster_sanitizes_ssh_key_for_cluster_and_infra_env() -> None:
    client = _client()
    quoted_key = f'  "{VALID_SSH_KEY}"  '

    result, _inventory_client = await _invoke(client, ssh_public_key=quoted_key)

    assert result == "cid-1"
    _assert_api_calls(
        client,
        name=NAME,
        version=VERSION,
        single_node=False,
        base_domain=BASE_DOMAIN,
        platform="baremetal",
        cpu_architecture="x86_64",
        ssh_public_key=VALID_SSH_KEY,
        cluster_id="cid-1",
        openshift_version=VERSION,
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("platform", ["baremetal", "vsphere", "oci", "nutanix"])
async def test_create_cluster_invalid_platform_for_sno_returns_message(
    platform: str,
) -> None:
    client = _client()
    typed_platform = cast(Helpers.VALID_PLATFORMS, platform)

    result, inventory_client = await _invoke(
        client, single_node=True, platform=typed_platform
    )

    assert result == SNO_PLATFORM_MESSAGE
    inventory_client.assert_not_called()
    client.create_cluster.assert_not_called()
    client.create_infra_env.assert_not_called()


@pytest.mark.asyncio
async def test_create_cluster_invalid_ssh_key_returns_message_without_api_call() -> (
    None
):
    client = _client()

    result, inventory_client = await _invoke(client, ssh_public_key="not-a-key")

    assert result.startswith("SSH key validation failed:")
    inventory_client.assert_not_called()
    client.create_cluster.assert_not_called()
    client.create_infra_env.assert_not_called()


@pytest.mark.asyncio
async def test_create_cluster_unset_id_returns_message_without_infra_env() -> None:
    client = _client()
    client.create_cluster.return_value = _UnsetClusterId()

    result, inventory_client = await _invoke(client, name="edge")

    assert result == "Failed to create cluster edge: cluster ID is unset"
    inventory_client.assert_called_once_with(TOKEN)
    client.create_infra_env.assert_not_called()


@pytest.mark.asyncio
async def test_create_cluster_api_error_propagates() -> None:
    client = _client()
    client.create_cluster.side_effect = RuntimeError("api down")

    with pytest.raises(RuntimeError, match="api down"):
        await _invoke(client)

    client.create_infra_env.assert_not_called()


@pytest.mark.asyncio
async def test_create_cluster_infra_env_error_propagates() -> None:
    client = _client()
    client.create_infra_env.side_effect = RuntimeError("infra failed")

    with pytest.raises(RuntimeError, match="infra failed"):
        await _invoke(client)

    client.create_cluster.assert_awaited_once()
