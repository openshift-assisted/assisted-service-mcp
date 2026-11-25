"""Unit tests for the validate_nmstate_yaml tool.

These tests call the tool function directly and do not start the MCP server.
YAML parsing is covered in the static-network tests; these tests cover how the
tool reports that result.
"""

import pytest

from assisted_service_mcp.src.tools import network_tools
from tests.tools.tool_test_helpers import test_token


@pytest.mark.asyncio
async def test_validate_nmstate_yaml_returns_valid() -> None:
    result = await network_tools.validate_nmstate_yaml(test_token, "interfaces: []\n")

    assert result == "YAML is valid"


@pytest.mark.asyncio
async def test_validate_nmstate_yaml_invalid_yaml_propagates() -> None:
    invalid_yaml = "interfaces:\n- name: eth0\n    bad:\n"

    with pytest.raises(ValueError, match="Invalid YAML"):
        await network_tools.validate_nmstate_yaml(test_token, invalid_yaml)


@pytest.mark.asyncio
async def test_validate_nmstate_yaml_empty_document_returns_valid() -> None:
    result = await network_tools.validate_nmstate_yaml(test_token, "")

    assert result == "YAML is valid"
