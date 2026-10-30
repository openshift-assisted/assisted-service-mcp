"""Tests for SSH key validation and cluster SSH-key updates."""

from unittest.mock import AsyncMock, Mock, patch

import pytest


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
    mock_client.update_infra_env = AsyncMock(
        side_effect=cluster_tools.AssistedServiceAPIError("Update failed")
    )

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
    ):
        resp = await cluster_tools.set_cluster_ssh_key(
            lambda: "test-access-token", "cid", "ssh-rsa AAAA"
        )
        assert "Cluster key updated, but boot image key update failed" in resp


@pytest.mark.asyncio
async def test_tool_set_cluster_ssh_key_success_path() -> None:
    from assisted_service_mcp.src.tools import cluster_tools
    from assisted_service_mcp.src.mcp import AssistedServiceMCPServer
    from tests.test_utils import create_test_cluster

    cluster = create_test_cluster(cluster_id="cid")
    mock_client = Mock()
    mock_client.update_cluster = AsyncMock(return_value=cluster)
    mock_client.update_infra_env = AsyncMock(return_value=None)

    AssistedServiceMCPServer()
    with (
        patch(
            "assisted_service_mcp.src.tools.shared_helpers._get_cluster_infra_env_id",
            new=AsyncMock(return_value="ie1"),
        ),
        patch(
            "assisted_service_mcp.src.tools.cluster_tools.InventoryClient",
            return_value=mock_client,
        ),
    ):
        resp = await cluster_tools.set_cluster_ssh_key(
            lambda: "t",
            "cid",
            "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCtest user@example.com",
        )
        assert resp == cluster.to_str()


@pytest.mark.asyncio
async def test_tool_set_cluster_ssh_key_strips_quotes() -> None:
    """Test that set_cluster_ssh_key strips quotes from input and stores unquoted value."""
    from assisted_service_mcp.src.tools import cluster_tools
    from assisted_service_mcp.src.mcp import AssistedServiceMCPServer
    from tests.test_utils import create_test_cluster

    cluster = create_test_cluster(cluster_id="cid")
    mock_client = Mock()
    mock_client.update_cluster = AsyncMock(return_value=cluster)
    mock_client.update_infra_env = AsyncMock(return_value=None)

    AssistedServiceMCPServer()
    with (
        patch(
            "assisted_service_mcp.src.tools.shared_helpers._get_cluster_infra_env_id",
            new=AsyncMock(return_value="ie1"),
        ),
        patch(
            "assisted_service_mcp.src.tools.cluster_tools.InventoryClient",
            return_value=mock_client,
        ),
    ):
        # Input with double quotes
        quoted_key = '"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCtest user@example.com"'
        await cluster_tools.set_cluster_ssh_key(lambda: "t", "cid", quoted_key)

        # Verify the stored value has quotes stripped
        update_cluster_call = mock_client.update_cluster.call_args
        stored_key = update_cluster_call[1]["ssh_public_key"]
        assert (
            stored_key == "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCtest user@example.com"
        )
        assert '"' not in stored_key

        # Also verify infra_env gets the unquoted value
        update_infra_env_call = mock_client.update_infra_env.call_args
        infra_env_key = update_infra_env_call[1]["ssh_authorized_key"]
        assert (
            infra_env_key
            == "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCtest user@example.com"
        )
        assert '"' not in infra_env_key


@pytest.mark.asyncio
async def test_validate_ssh_key_valid_keys() -> None:
    """Test _validate_ssh_key with various valid SSH key formats."""
    from assisted_service_mcp.src.tools.cluster_tools import _validate_ssh_key

    # Valid key with comment
    valid_with_comment = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCtest user@example.com"
    result = _validate_ssh_key(valid_with_comment)
    assert result == "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCtest user@example.com"

    # Valid key without comment
    valid_no_comment = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCtest"
    result = _validate_ssh_key(valid_no_comment)
    assert result == "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCtest"

    # Valid key with multi-word comment
    valid_multiword = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAtest my test key"
    result = _validate_ssh_key(valid_multiword)
    assert result == "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAtest my test key"

    # Valid key with special chars in comment
    valid_special_comment = (
        "ssh-rsa AAAAB3NzaC1yc2EAAAAtest user@host.example-domain.com"
    )
    result = _validate_ssh_key(valid_special_comment)
    assert result == "ssh-rsa AAAAB3NzaC1yc2EAAAAtest user@host.example-domain.com"


@pytest.mark.asyncio
async def test_validate_ssh_key_invalid_format() -> None:
    """Test _validate_ssh_key rejects keys with invalid format."""
    from assisted_service_mcp.src.tools.cluster_tools import _validate_ssh_key

    # Missing key data
    with pytest.raises(ValueError, match="Invalid SSH key format"):
        _validate_ssh_key("ssh-rsa")

    # Empty string
    with pytest.raises(ValueError, match="Invalid SSH key format"):
        _validate_ssh_key("")

    # Just a type
    with pytest.raises(ValueError, match="Invalid SSH key format"):
        _validate_ssh_key("ssh-rsa ")


@pytest.mark.asyncio
async def test_validate_ssh_key_invalid_characters() -> None:
    """Test _validate_ssh_key rejects keys with invalid characters."""
    from assisted_service_mcp.src.tools.cluster_tools import _validate_ssh_key

    # Invalid characters in key data
    with pytest.raises(ValueError, match="SSH key data contains invalid characters"):
        _validate_ssh_key("ssh-rsa AAAA$INVALID user@example.com")

    # Invalid characters in key data (special chars)
    with pytest.raises(ValueError, match="SSH key data contains invalid characters"):
        _validate_ssh_key("ssh-rsa AAAA;echo user@example.com")


@pytest.mark.asyncio
async def test_validate_ssh_key_unsafe_comment() -> None:
    """Test _validate_ssh_key rejects keys with unsafe characters in comment."""
    from assisted_service_mcp.src.tools.cluster_tools import _validate_ssh_key

    # Semicolon in comment (command injection attempt)
    with pytest.raises(ValueError, match="SSH key comment contains unsafe characters"):
        _validate_ssh_key("ssh-rsa AAAAB3NzaC1yc2EAAAAtest user;rm -rf /")

    # Pipe in comment
    with pytest.raises(ValueError, match="SSH key comment contains unsafe characters"):
        _validate_ssh_key("ssh-rsa AAAAB3NzaC1yc2EAAAAtest user|cat /etc/passwd")

    # Dollar sign in comment
    with pytest.raises(ValueError, match="SSH key comment contains unsafe characters"):
        _validate_ssh_key("ssh-rsa AAAAB3NzaC1yc2EAAAAtest user$(whoami)")

    # Backtick in comment
    with pytest.raises(ValueError, match="SSH key comment contains unsafe characters"):
        _validate_ssh_key("ssh-rsa AAAAB3NzaC1yc2EAAAAtest user`id`")


@pytest.mark.asyncio
async def test_validate_ssh_key_invalid_key_type() -> None:
    """Test _validate_ssh_key rejects invalid SSH key types."""
    from assisted_service_mcp.src.tools.cluster_tools import _validate_ssh_key

    # Invalid key type "foo"
    with pytest.raises(ValueError, match="Invalid SSH key type 'foo'"):
        _validate_ssh_key("foo AAAAB3NzaC1yc2EAAAAtest user@example.com")

    # Invalid key type "random-type"
    with pytest.raises(ValueError, match="Invalid SSH key type 'random-type'"):
        _validate_ssh_key("random-type AAAAB3NzaC1yc2EAAAAtest user@example.com")

    # Typo in key type
    with pytest.raises(ValueError, match="Invalid SSH key type 'ssh-rssa'"):
        _validate_ssh_key("ssh-rssa AAAAB3NzaC1yc2EAAAAtest user@example.com")

    # Case-sensitive check - uppercase should fail
    with pytest.raises(ValueError, match="Invalid SSH key type 'SSH-RSA'"):
        _validate_ssh_key("SSH-RSA AAAAB3NzaC1yc2EAAAAtest user@example.com")


@pytest.mark.asyncio
async def test_validate_ssh_key_strips_quotes() -> None:
    """Test _validate_ssh_key strips surrounding quotes."""
    from assisted_service_mcp.src.tools.cluster_tools import _validate_ssh_key

    # Single quotes
    quoted_single = "'ssh-rsa AAAAB3NzaC1yc2EAAAAtest user@example.com'"
    result = _validate_ssh_key(quoted_single)
    assert result == "ssh-rsa AAAAB3NzaC1yc2EAAAAtest user@example.com"
    assert "'" not in result

    # Double quotes
    quoted_double = '"ssh-rsa AAAAB3NzaC1yc2EAAAAtest user@example.com"'
    result = _validate_ssh_key(quoted_double)
    assert result == "ssh-rsa AAAAB3NzaC1yc2EAAAAtest user@example.com"
    assert '"' not in result


@pytest.mark.asyncio
async def test_validate_ssh_key_normalizes_whitespace() -> None:
    """Test _validate_ssh_key normalizes excessive whitespace."""
    from assisted_service_mcp.src.tools.cluster_tools import _validate_ssh_key

    # Multiple spaces between parts
    excessive_spaces = "ssh-rsa    AAAAB3NzaC1yc2EAAAAtest    user@example.com"
    result = _validate_ssh_key(excessive_spaces)
    assert result == "ssh-rsa AAAAB3NzaC1yc2EAAAAtest user@example.com"

    # Tabs and mixed whitespace
    mixed_whitespace = "ssh-rsa\t\tAAAAB3NzaC1yc2EAAAAtest\t  user@example.com"
    result = _validate_ssh_key(mixed_whitespace)
    assert result == "ssh-rsa AAAAB3NzaC1yc2EAAAAtest user@example.com"


@pytest.mark.asyncio
async def test_set_cluster_ssh_key_validation_failure() -> None:
    """Test set_cluster_ssh_key returns error message when validation fails."""
    from assisted_service_mcp.src.tools import cluster_tools
    from assisted_service_mcp.src.mcp import AssistedServiceMCPServer

    AssistedServiceMCPServer()

    # Invalid SSH key should return error without creating an API client.
    with patch(
        "assisted_service_mcp.src.tools.cluster_tools.InventoryClient"
    ) as mock_inventory_client:
        resp = await cluster_tools.set_cluster_ssh_key(
            lambda: "t", "cid", "invalid-key"
        )

    mock_inventory_client.assert_not_called()
    assert "SSH key validation failed" in resp
    assert "Invalid SSH key format" in resp
