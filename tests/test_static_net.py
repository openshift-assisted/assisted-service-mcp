# type: ignore
"""
Unit tests for the static_net module.
"""

import json
from ipaddress import IPv4Address

import pytest
import yaml

from static_net import (
    remove_static_host_config_by_index,
    add_or_replace_static_host_config_yaml,
    validate_and_parse_nmstate,
    generate_nmstate_from_template,
    NMStateTemplateParams,
)

from static_net.template import (
    EthernetInterfaceParams,
    IPV4AddressWithSubnet,
    RouteParams,
    DNSParams,
    BondInterfaceParams,
    VLANInterfaceParams,
)


class TestRemoveStaticHostConfigByIndex:
    """Test the remove_static_host_config_by_index function."""

    def test_remove_valid_index(self):
        """Test removing a host config at a valid index."""
        config_data = [
            {
                "mac_interface_map": [
                    {"logical_nic_name": "eth0", "mac_address": "00:11:22:33:44:55"}
                ],
                "network_yaml": "interfaces:\n- name: eth0\n  type: ethernet",
            },
            {
                "mac_interface_map": [
                    {"logical_nic_name": "eth1", "mac_address": "00:11:22:33:44:66"}
                ],
                "network_yaml": "interfaces:\n- name: eth1\n  type: ethernet",
            },
        ]
        existing_config = json.dumps(config_data)

        result = remove_static_host_config_by_index(existing_config, 0)

        assert len(result) == 1
        assert result[0]["mac_interface_map"][0]["logical_nic_name"] == "eth1"

    def test_remove_last_item(self):
        """Test removing the last item in the config."""
        config_data = [
            {
                "mac_interface_map": [
                    {"logical_nic_name": "eth0", "mac_address": "00:11:22:33:44:55"}
                ],
                "network_yaml": "interfaces:\n- name: eth0\n  type: ethernet",
            }
        ]
        existing_config = json.dumps(config_data)

        result = remove_static_host_config_by_index(existing_config, 0)

        assert len(result) == 0

    def test_remove_invalid_index_too_high(self):
        """Test removing with an index that's too high."""
        config_data = [
            {
                "mac_interface_map": [
                    {"logical_nic_name": "eth0", "mac_address": "00:11:22:33:44:55"}
                ],
                "network_yaml": "interfaces:\n- name: eth0\n  type: ethernet",
            }
        ]
        existing_config = json.dumps(config_data)

        with pytest.raises(
            ValueError,
            match="static network config only has 1 elements, cannot delete index 5",
        ):
            remove_static_host_config_by_index(existing_config, 5)

    def test_remove_from_empty_config(self):
        """Test removing from an empty config."""
        existing_config = json.dumps([])

        with pytest.raises(
            ValueError,
            match="static network config only has 0 elements, cannot delete index 0",
        ):
            remove_static_host_config_by_index(existing_config, 0)


class TestAddOrReplaceStaticHostConfigYaml:
    """Test the add_or_replace_static_host_config_yaml function."""

    @pytest.fixture
    def valid_nmstate_yaml(self):
        """Fixture providing a valid nmstate YAML configuration."""
        return """
            interfaces:
            - name: eth0
              type: ethernet
              state: up
              mac-address: "00:11:22:33:44:55"
              ipv4:
                enabled: true
                address:
                - ip: 192.168.1.10
                  prefix-length: 24
            """

    def test_add_to_empty_config(self, valid_nmstate_yaml):
        """Test adding a config to an empty existing config."""
        result = add_or_replace_static_host_config_yaml(None, None, valid_nmstate_yaml)

        assert len(result) == 1
        assert result[0]["mac_interface_map"][0]["logical_nic_name"] == "eth0"
        assert result[0]["mac_interface_map"][0]["mac_address"] == "00:11:22:33:44:55"
        assert result[0]["network_yaml"] == valid_nmstate_yaml

    def test_add_to_existing_config(self, valid_nmstate_yaml):
        """Test adding a config to an existing config."""
        existing_data = [
            {
                "mac_interface_map": [
                    {"logical_nic_name": "eth1", "mac_address": "00:11:22:33:44:66"}
                ],
                "network_yaml": "interfaces:\n- name: eth1\n  type: ethernet",
            }
        ]
        existing_config = json.dumps(existing_data)

        result = add_or_replace_static_host_config_yaml(
            existing_config, None, valid_nmstate_yaml
        )

        assert len(result) == 2
        assert result[0]["mac_interface_map"][0]["logical_nic_name"] == "eth1"
        assert result[1]["mac_interface_map"][0]["logical_nic_name"] == "eth0"

    def test_replace_at_index(self, valid_nmstate_yaml):
        """Test replacing a config at a specific index."""
        existing_data = [
            {
                "mac_interface_map": [
                    {"logical_nic_name": "eth1", "mac_address": "00:11:22:33:44:66"}
                ],
                "network_yaml": "interfaces:\n- name: eth1\n  type: ethernet",
            }
        ]
        existing_config = json.dumps(existing_data)

        result = add_or_replace_static_host_config_yaml(
            existing_config, 0, valid_nmstate_yaml
        )

        assert len(result) == 1
        assert result[0]["mac_interface_map"][0]["logical_nic_name"] == "eth0"
        assert result[0]["mac_interface_map"][0]["mac_address"] == "00:11:22:33:44:55"

    def test_replace_invalid_index(self, valid_nmstate_yaml):
        """Test replacing with an invalid index."""
        existing_data = [
            {
                "mac_interface_map": [
                    {"logical_nic_name": "eth1", "mac_address": "00:11:22:33:44:66"}
                ],
                "network_yaml": "interfaces:\n- name: eth1\n  type: ethernet",
            }
        ]
        existing_config = json.dumps(existing_data)

        with pytest.raises(IndexError):
            add_or_replace_static_host_config_yaml(
                existing_config, 5, valid_nmstate_yaml
            )

    def test_nmstate_without_mac_addresses(self):
        """Test with nmstate YAML that has no MAC addresses."""
        nmstate_yaml = """
            interfaces:
            - name: eth0
              type: ethernet
              state: up
              ipv4:
                enabled: true
                address:
                - ip: 192.168.1.10
                  prefix-length: 24
            """

        with pytest.raises(
            ValueError,
            match="At least one interface must be associated to a MAC Address",
        ):
            add_or_replace_static_host_config_yaml(None, None, nmstate_yaml)


class TestValidateAndParseNmstate:
    """Test the validate_and_parse_nmstate function."""

    def test_valid_yaml(self):
        """Test parsing valid YAML."""
        valid_yaml = """
            interfaces:
            - name: eth0
              type: ethernet
              state: up
            """
        result = validate_and_parse_nmstate(valid_yaml)

        assert isinstance(result, dict)
        assert "interfaces" in result
        assert result["interfaces"][0]["name"] == "eth0"

    def test_invalid_yaml(self):
        """Test parsing invalid YAML."""
        invalid_yaml = """
            interfaces:
            - name: eth0
              type: ethernet
              state: up
                      invalid_indentation:
            """
        with pytest.raises(ValueError):
            validate_and_parse_nmstate(invalid_yaml)

    def test_empty_yaml(self):
        """Test parsing empty YAML."""
        result = validate_and_parse_nmstate("")
        assert result is None

    def test_yaml_with_complex_structure(self):
        """Test parsing YAML with complex nested structure."""
        complex_yaml = """
            dns-resolver:
              config:
                server:
                - 8.8.8.8
                - 1.1.1.1
                search:
                - example.com
            routes:
              config:
              - destination: 0.0.0.0/0
                next-hop-address: 192.168.1.1
                next-hop-interface: eth0
                table-id: 254
            interfaces:
            - name: eth0
              type: ethernet
              state: up
              mac-address: "00:11:22:33:44:55"
            """
        result = validate_and_parse_nmstate(complex_yaml)

        assert "dns-resolver" in result
        assert "routes" in result
        assert "interfaces" in result
        assert len(result["dns-resolver"]["config"]["server"]) == 2
        assert result["routes"]["config"][0]["destination"] == "0.0.0.0/0"


class TestGenerateNmstateFromTemplate:
    """Test the generate_nmstate_from_template function."""

    def test_minimal_ethernet_config(self):
        """Test generating nmstate with minimal ethernet configuration."""
        params = NMStateTemplateParams(
            ethernet_ifaces=[
                EthernetInterfaceParams(
                    name="eth0",
                    mac_address="00:11:22:33:44:55",
                    ipv4_address=IPV4AddressWithSubnet(
                        address=IPv4Address("192.168.1.10"), cidr_length=24
                    ),
                )
            ]
        )

        result = generate_nmstate_from_template(params)

        assert "interfaces:" in result
        assert "name: eth0" in result
        assert "type: ethernet" in result
        assert "mac-address: 00:11:22:33:44:55" in result
        assert "ip: 192.168.1.10" in result
        assert "prefix-length: 24" in result

        # Verify the generated YAML is valid
        yaml.safe_load(result)

    def test_ethernet_without_ip(self):
        """Test generating nmstate with ethernet interface without IP."""
        params = NMStateTemplateParams(
            ethernet_ifaces=[
                EthernetInterfaceParams(
                    name="eth0", mac_address="00:11:22:33:44:55", ipv4_address=None
                )
            ]
        )

        result = generate_nmstate_from_template(params)

        assert "enabled: false" in result
        assert "dhcp: false" in result

        # Verify the generated YAML is valid
        yaml.safe_load(result)

    def test_with_dns_config(self):
        """Test generating nmstate with DNS configuration."""
        params = NMStateTemplateParams(
            dns=DNSParams(
                dns_servers=["8.8.8.8", "1.1.1.1"],
                dns_search_domains=["example.com", "test.com"],
            ),
            ethernet_ifaces=[
                EthernetInterfaceParams(
                    name="eth0", mac_address="00:11:22:33:44:55", ipv4_address=None
                )
            ],
        )

        result = generate_nmstate_from_template(params)

        assert "dns-resolver:" in result
        assert "- 8.8.8.8" in result
        assert "- 1.1.1.1" in result
        assert "- example.com" in result
        assert "- test.com" in result

    def test_with_routes(self):
        """Test generating nmstate with routing configuration."""
        params = NMStateTemplateParams(
            routes=[
                RouteParams(
                    destination="0.0.0.0/0",
                    next_hop_address="192.168.1.1",
                    next_hop_interface="eth0",
                    table_id=254,
                    metric=50,
                )
            ],
            ethernet_ifaces=[
                EthernetInterfaceParams(
                    name="eth0", mac_address="00:11:22:33:44:55", ipv4_address=None
                )
            ],
        )

        result = generate_nmstate_from_template(params)

        assert "routes:" in result
        assert "destination: 0.0.0.0/0" in result
        assert "next-hop-address: 192.168.1.1" in result
        assert "next-hop-interface: eth0" in result
        assert "table-id: 254" in result
        assert "metric: 50" in result

        # Verify the generated YAML is valid
        yaml.safe_load(result)

    def test_with_vlan_interfaces(self):
        """Test generating nmstate with VLAN interfaces."""
        params = NMStateTemplateParams(
            ethernet_ifaces=[
                EthernetInterfaceParams(
                    name="eth0", mac_address="00:11:22:33:44:55", ipv4_address=None
                )
            ],
            vlan_ifaces=[
                VLANInterfaceParams(
                    name="vlan100",
                    vlan_id=100,
                    base_interface_name="eth0",
                    ipv4_address=IPV4AddressWithSubnet(
                        address=IPv4Address("192.168.100.10"), cidr_length=24
                    ),
                )
            ],
        )

        result = generate_nmstate_from_template(params)

        assert "name: vlan100" in result
        assert "type: vlan" in result
        assert "base-iface: eth0" in result
        assert "id: 100" in result
        assert "ip: 192.168.100.10" in result

        # Verify the generated YAML is valid
        yaml.safe_load(result)

    def test_with_bond_interfaces(self):
        """Test generating nmstate with bond interfaces."""
        params = NMStateTemplateParams(
            ethernet_ifaces=[
                EthernetInterfaceParams(
                    name="eth0", mac_address="00:11:22:33:44:55", ipv4_address=None
                ),
                EthernetInterfaceParams(
                    name="eth1", mac_address="00:11:22:33:44:66", ipv4_address=None
                ),
            ],
            bond_ifaces=[
                BondInterfaceParams(
                    name="bond0",
                    mode="active-backup",
                    port_interface_names=["eth0", "eth1"],
                )
            ],
        )

        result = generate_nmstate_from_template(params)

        assert "name: bond0" in result
        assert "type: bond" in result
        assert "mode: active-backup" in result
        assert "- eth0" in result
        assert "- eth1" in result

        # Verify the generated YAML is valid
        yaml.safe_load(result)

    def test_complex_configuration(self):
        """Test generating nmstate with all components."""
        params = NMStateTemplateParams(
            dns=DNSParams(dns_servers=["8.8.8.8"], dns_search_domains=["example.com"]),
            routes=[
                RouteParams(
                    destination="10.0.0.0/8",
                    next_hop_address="192.168.1.1",
                    next_hop_interface="eth0",
                )
            ],
            ethernet_ifaces=[
                EthernetInterfaceParams(
                    name="eth0",
                    mac_address="00:11:22:33:44:55",
                    ipv4_address=IPV4AddressWithSubnet(
                        address=IPv4Address("192.168.1.10"), cidr_length=24
                    ),
                )
            ],
            vlan_ifaces=[
                VLANInterfaceParams(
                    name="vlan200",
                    vlan_id=200,
                    base_interface_name="eth0",
                    ipv4_address=IPV4AddressWithSubnet(
                        address=IPv4Address("192.168.200.10"), cidr_length=24
                    ),
                )
            ],
        )

        result = generate_nmstate_from_template(params)

        # Verify all components are present
        assert "dns-resolver:" in result
        assert "routes:" in result
        assert "interfaces:" in result
        assert "name: eth0" in result
        assert "name: vlan200" in result

        # Verify the generated YAML is valid
        yaml.safe_load(result)
