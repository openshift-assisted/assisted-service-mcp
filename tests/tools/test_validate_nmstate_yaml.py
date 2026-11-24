"""Unit tests for the validate_nmstate_yaml tool.

These tests call the tool function directly and do not start the MCP server.
YAML parsing is covered in the static-network tests; these tests cover how the
tool reports that result.
"""

import pytest

from assisted_service_mcp.src.tools import network_tools

TOKEN = "test-access-token"


def _token() -> str:
    return TOKEN


@pytest.mark.asyncio
async def test_validate_nmstate_yaml_returns_valid() -> None:
    result = await network_tools.validate_nmstate_yaml(_token, "interfaces: []\n")

    assert result == "YAML is valid"


@pytest.mark.asyncio
async def test_validate_nmstate_yaml_invalid_yaml_propagates() -> None:
    invalid_yaml = "interfaces:\n- name: eth0\n    bad:\n"

    with pytest.raises(ValueError, match="Invalid YAML"):
        await network_tools.validate_nmstate_yaml(_token, invalid_yaml)


@pytest.mark.asyncio
async def test_validate_nmstate_yaml_empty_document_returns_valid() -> None:
    result = await network_tools.validate_nmstate_yaml(_token, "")

    assert result == "YAML is valid"
