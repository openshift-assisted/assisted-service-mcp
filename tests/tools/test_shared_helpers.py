from unittest.mock import AsyncMock
import pytest

from assisted_service_mcp.src.tools.shared_helpers import _get_cluster_infra_env_id


@pytest.mark.asyncio
async def test_get_cluster_infra_env_id_success() -> None:
    client = AsyncMock()
    client.list_infra_envs.return_value = [{"id": "ie-1"}]
    res = await _get_cluster_infra_env_id(client, "cid")
    assert res == "ie-1"


@pytest.mark.asyncio
async def test_get_cluster_infra_env_id_no_infra_envs() -> None:
    client = AsyncMock()
    client.list_infra_envs.return_value = []
    with pytest.raises(ValueError):
        await _get_cluster_infra_env_id(client, "cid")


@pytest.mark.asyncio
async def test_get_cluster_infra_env_id_missing_id() -> None:
    client = AsyncMock()
    client.list_infra_envs.return_value = [{}]
    with pytest.raises(ValueError):
        await _get_cluster_infra_env_id(client, "cid")
