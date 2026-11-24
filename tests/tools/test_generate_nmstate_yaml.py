"""Unit tests for the generate_nmstate_yaml tool.

Template rendering is covered by the static-network tests. These tests call
the tool directly and do not start the MCP server.
"""

from unittest.mock import patch

import pytest
import yaml
from jinja2 import TemplateError

from assisted_service_mcp.src.tools import network_tools
from assisted_service_mcp.src.utils.static_network.template import (
    EthernetInterfaceParams,
    NMStateTemplateParams,
)

TOKEN = "test-access-token"


def _token() -> str:
    return TOKEN


def _params() -> NMStateTemplateParams:
    return NMStateTemplateParams(
        routes=None,
        bond_ifaces=None,
        vlan_ifaces=None,
        ethernet_ifaces=[
            EthernetInterfaceParams(mac_address="00:11:22:33:44:55", name="eth0")
        ],
    )


@pytest.mark.asyncio
async def test_generate_nmstate_yaml_returns_generated_yaml() -> None:
    params = _params()
    with patch(
        "assisted_service_mcp.src.tools.network_tools.generate_nmstate_from_template",
        return_value="yaml",
    ) as generate:
        result = await network_tools.generate_nmstate_yaml(_token, params)

    assert result == "yaml"
    generate.assert_called_once_with(params)


@pytest.mark.asyncio
async def test_generate_nmstate_yaml_template_error_returns_message() -> None:
    with patch(
        "assisted_service_mcp.src.tools.network_tools.generate_nmstate_from_template",
        side_effect=TemplateError("bad template"),
    ):
        result = await network_tools.generate_nmstate_yaml(_token, _params())

    assert result == "ERROR: Failed to generate nmstate yaml: bad template"


@pytest.mark.asyncio
async def test_generate_nmstate_yaml_invalid_yaml_returns_message() -> None:
    with patch(
        "assisted_service_mcp.src.tools.network_tools.generate_nmstate_from_template",
        side_effect=yaml.YAMLError("bad yaml"),
    ):
        result = await network_tools.generate_nmstate_yaml(_token, _params())

    assert result == "ERROR: Failed to generate nmstate yaml: bad yaml"
