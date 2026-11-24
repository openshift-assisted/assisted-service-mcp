"""Unit tests for the set_cluster_ssh_key tool and its SSH-key validation.

The Assisted Service client is mocked. These tests call the tool function
directly and do not start the MCP server.
"""

from unittest.mock import AsyncMock, Mock, patch

import pytest

from assisted_service_mcp.src.service_client.exceptions import AssistedServiceAPIError
from assisted_service_mcp.src.tools import cluster_tools
from assisted_service_mcp.src.tools.cluster_tools import _validate_ssh_key
from tests.create_objects_helpers import create_test_cluster

TOKEN = "test-access-token"
CLUSTER_ID = "cid"
VALID_SSH_KEY = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCtest user@example.com"
SHORT_VALID_SSH_KEY = "ssh-rsa AAAA"


def _token() -> str:
    return TOKEN


def _client() -> Mock:
    client = Mock()
    client.update_cluster = AsyncMock(
        return_value=create_test_cluster(cluster_id=CLUSTER_ID)
    )
    client.update_infra_env = AsyncMock(return_value=None)
    return client


async def _invoke(
    client: Mock,
    ssh_public_key: str,
    *,
    infra_env_id: str | None = "ie1",
    infra_env_error: Exception | None = None,
) -> tuple[str, Mock]:
    infra_env_lookup = AsyncMock(return_value=infra_env_id)
    if infra_env_error is not None:
        infra_env_lookup = AsyncMock(side_effect=infra_env_error)
    with (
        patch(
            "assisted_service_mcp.src.tools.shared_helpers._get_cluster_infra_env_id",
            new=infra_env_lookup,
        ),
        patch(
            "assisted_service_mcp.src.tools.cluster_tools.InventoryClient",
            return_value=client,
        ) as inventory_client,
    ):
        result = await cluster_tools.set_cluster_ssh_key(
            _token, CLUSTER_ID, ssh_public_key
        )
    return result, inventory_client


@pytest.mark.asyncio
async def test_set_cluster_ssh_key_updates_cluster_and_infra_env() -> None:
    client = _client()
    cluster = client.update_cluster.return_value

    result, inventory_client = await _invoke(client, VALID_SSH_KEY)

    assert result == cluster.to_str()
    inventory_client.assert_called_once_with(TOKEN)
    client.update_cluster.assert_awaited_once_with(
        CLUSTER_ID, ssh_public_key=VALID_SSH_KEY
    )
    client.update_infra_env.assert_awaited_once_with(
        "ie1", ssh_authorized_key=VALID_SSH_KEY
    )


@pytest.mark.asyncio
async def test_set_cluster_ssh_key_strips_quotes() -> None:
    client = _client()
    quoted_key = f'"{VALID_SSH_KEY}"'

    await _invoke(client, quoted_key)

    assert client.update_cluster.await_args is not None
    stored_key = client.update_cluster.await_args.kwargs["ssh_public_key"]
    assert stored_key == VALID_SSH_KEY
    assert '"' not in stored_key
    assert client.update_infra_env.await_args is not None
    infra_env_key = client.update_infra_env.await_args.kwargs["ssh_authorized_key"]
    assert infra_env_key == VALID_SSH_KEY
    assert '"' not in infra_env_key


@pytest.mark.asyncio
async def test_set_cluster_ssh_key_validation_failure_skips_api() -> None:
    with patch(
        "assisted_service_mcp.src.tools.cluster_tools.InventoryClient"
    ) as inventory_client:
        result = await cluster_tools.set_cluster_ssh_key(
            _token, CLUSTER_ID, "invalid-key"
        )

    inventory_client.assert_not_called()
    assert result.startswith("SSH key validation failed:")
    assert "Invalid SSH key format" in result


@pytest.mark.asyncio
async def test_set_cluster_ssh_key_missing_infra_env_returns_partial_update() -> None:
    client = _client()
    cluster = client.update_cluster.return_value

    result, _inventory_client = await _invoke(
        client,
        SHORT_VALID_SSH_KEY,
        infra_env_error=ValueError("No InfraEnv found for cluster cid"),
    )

    assert result == (
        "Cluster key updated, but failed to get InfraEnv ID: "
        f"No InfraEnv found for cluster cid. New cluster: {cluster.to_str()}"
    )
    client.update_cluster.assert_awaited_once()
    client.update_infra_env.assert_not_called()


@pytest.mark.asyncio
async def test_set_cluster_ssh_key_infra_env_update_failure_returns_partial_update() -> (
    None
):
    client = _client()
    client.update_infra_env.side_effect = AssistedServiceAPIError("Update failed")
    cluster = client.update_cluster.return_value

    result, _inventory_client = await _invoke(client, SHORT_VALID_SSH_KEY)

    assert result == (
        "Cluster key updated, but boot image key update failed. "
        f"New cluster: {cluster.to_str()}"
    )
    client.update_cluster.assert_awaited_once_with(
        CLUSTER_ID, ssh_public_key=SHORT_VALID_SSH_KEY
    )


@pytest.mark.asyncio
async def test_set_cluster_ssh_key_cluster_update_error_propagates() -> None:
    client = _client()
    client.update_cluster.side_effect = AssistedServiceAPIError("cluster update failed")

    with pytest.raises(AssistedServiceAPIError, match="cluster update failed"):
        await _invoke(client, VALID_SSH_KEY)

    client.update_infra_env.assert_not_called()


@pytest.mark.asyncio
async def test_validate_ssh_key_valid_keys() -> None:
    """Test _validate_ssh_key with various valid SSH key formats."""
    valid_with_comment = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCtest user@example.com"
    result = _validate_ssh_key(valid_with_comment)
    assert result == "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCtest user@example.com"

    valid_no_comment = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCtest"
    result = _validate_ssh_key(valid_no_comment)
    assert result == "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCtest"

    valid_multiword = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAtest my test key"
    result = _validate_ssh_key(valid_multiword)
    assert result == "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAtest my test key"

    valid_special_comment = "ssh-rsa AAAAB3NzaC1yc2EAAAAtest user+lab:ops@example.com"
    result = _validate_ssh_key(valid_special_comment)
    assert result == valid_special_comment


@pytest.mark.asyncio
async def test_validate_ssh_key_invalid_format() -> None:
    """Test _validate_ssh_key rejects keys with invalid format."""
    with pytest.raises(ValueError, match="Invalid SSH key format"):
        _validate_ssh_key("ssh-rsa")

    with pytest.raises(ValueError, match="Invalid SSH key format"):
        _validate_ssh_key("")

    with pytest.raises(ValueError, match="Invalid SSH key format"):
        _validate_ssh_key("ssh-rsa ")


@pytest.mark.asyncio
async def test_validate_ssh_key_invalid_characters() -> None:
    """Test _validate_ssh_key rejects keys with invalid characters."""
    with pytest.raises(ValueError, match="SSH key data contains invalid characters"):
        _validate_ssh_key("ssh-rsa AAAA$INVALID user@example.com")

    with pytest.raises(ValueError, match="SSH key data contains invalid characters"):
        _validate_ssh_key("ssh-rsa AAAA;echo user@example.com")


@pytest.mark.asyncio
async def test_validate_ssh_key_unsafe_comment() -> None:
    """Test _validate_ssh_key rejects keys with unsafe characters in comment."""
    with pytest.raises(ValueError, match="SSH key comment contains unsafe characters"):
        _validate_ssh_key("ssh-rsa AAAAB3NzaC1yc2EAAAAtest user;rm -rf /")

    with pytest.raises(ValueError, match="SSH key comment contains unsafe characters"):
        _validate_ssh_key("ssh-rsa AAAAB3NzaC1yc2EAAAAtest user|cat /etc/passwd")

    with pytest.raises(ValueError, match="SSH key comment contains unsafe characters"):
        _validate_ssh_key("ssh-rsa AAAAB3NzaC1yc2EAAAAtest user$(whoami)")

    with pytest.raises(ValueError, match="SSH key comment contains unsafe characters"):
        _validate_ssh_key("ssh-rsa AAAAB3NzaC1yc2EAAAAtest user`id`")


@pytest.mark.asyncio
async def test_validate_ssh_key_invalid_key_type() -> None:
    """Test _validate_ssh_key rejects invalid SSH key types."""
    with pytest.raises(ValueError, match="Invalid SSH key type 'foo'"):
        _validate_ssh_key("foo AAAAB3NzaC1yc2EAAAAtest user@example.com")

    with pytest.raises(ValueError, match="Invalid SSH key type 'random-type'"):
        _validate_ssh_key("random-type AAAAB3NzaC1yc2EAAAAtest user@example.com")

    with pytest.raises(ValueError, match="Invalid SSH key type 'ssh-rssa'"):
        _validate_ssh_key("ssh-rssa AAAAB3NzaC1yc2EAAAAtest user@example.com")

    with pytest.raises(ValueError, match="Invalid SSH key type 'SSH-RSA'"):
        _validate_ssh_key("SSH-RSA AAAAB3NzaC1yc2EAAAAtest user@example.com")


@pytest.mark.asyncio
async def test_validate_ssh_key_strips_quotes() -> None:
    """Test _validate_ssh_key strips surrounding quotes."""
    quoted_single = "'ssh-rsa AAAAB3NzaC1yc2EAAAAtest user@example.com'"
    result = _validate_ssh_key(quoted_single)
    assert result == "ssh-rsa AAAAB3NzaC1yc2EAAAAtest user@example.com"
    assert "'" not in result

    quoted_double = '"ssh-rsa AAAAB3NzaC1yc2EAAAAtest user@example.com"'
    result = _validate_ssh_key(quoted_double)
    assert result == "ssh-rsa AAAAB3NzaC1yc2EAAAAtest user@example.com"
    assert '"' not in result


@pytest.mark.asyncio
async def test_validate_ssh_key_normalizes_whitespace() -> None:
    """Test _validate_ssh_key normalizes excessive whitespace."""
    excessive_spaces = "ssh-rsa    AAAAB3NzaC1yc2EAAAAtest    user@example.com"
    result = _validate_ssh_key(excessive_spaces)
    assert result == "ssh-rsa AAAAB3NzaC1yc2EAAAAtest user@example.com"

    mixed_whitespace = "ssh-rsa\t\tAAAAB3NzaC1yc2EAAAAtest\t  user@example.com"
    result = _validate_ssh_key(mixed_whitespace)
    assert result == "ssh-rsa AAAAB3NzaC1yc2EAAAAtest user@example.com"
